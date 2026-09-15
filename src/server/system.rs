/*
 * Isabelle project
 *
 * Copyright 2023-2026 Maxim Menshikov
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
//! `/system/` — what the server is, rather than what is in it.
//!
//! The collections hold a deployment's data; these endpoints hold the
//! deployment itself: how it sends mail, when it updates itself. Each one is
//! administrator-only and each owns its own corner of the configuration —
//! knowing, unlike a generic writer, what a usable value looks like and where
//! it belongs. That division is why the secret store keeps a `global.` name
//! space these write and nothing else does.
//!
//! Secrets never come back out. A screen that shows what is configured shows
//! that something is, not what it is.
use crate::server::user_control::*;

use crate::server::reply;
use crate::server::secret::ensure_admin;
use crate::state::state::*;
use crate::state::store::Store;
use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use log::{error, info};
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;

/// What a client sends instead of a secret it was never given.
///
/// The same word the secret store itself uses, so a screen that read the
/// configuration back and posted it unchanged leaves the password alone
/// rather than overwriting it with a placeholder.
const UNCHANGED: &str = "<hidden>";

/// Whether this is a client saying "leave the password as it is".
///
/// Two ways of saying it, and no third. An empty field is one nobody typed
/// in; the placeholder is what a screen posts back after reading the
/// configuration, because it was never given the password to post. Anything
/// else is a new password, including a word that merely looks like the
/// placeholder.
fn keeps_existing(password: &str) -> bool {
    password.is_empty() || password == UNCHANGED
}

#[derive(Debug, Deserialize)]
pub struct MailConfig {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub login: String,
    /// Empty or `<hidden>` leaves whatever is stored alone. There is no other
    /// way to say "keep it": the client was never told what it is.
    #[serde(default)]
    pub password: String,
}

/// What is configured, without saying what the secret is.
pub async fn system_mail(user: Identity, data: web::Data<State>) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let srv: &crate::state::data::Data = &data.server;
    let settings = srv.rw.get_settings().await.clone();
    let stored = {
        let guard = srv.secrets.lock();
        guard
            .as_ref()
            .and_then(|s| s.get_by_name(crate::notif::email::SMTP_SECRET))
    };
    let (login, has_password) = match &stored {
        Some(i) => (
            i.safe_str("login", ""),
            !i.safe_str("password", "").is_empty(),
        ),
        None => (settings.safe_str("smtp_login", ""), false),
    };

    let mut out: HashMap<String, String> = HashMap::new();
    out.insert("server".into(), settings.safe_str("smtp_server", ""));
    out.insert("from".into(), settings.safe_str("smtp_from", ""));
    out.insert("login".into(), login);
    // Whether there is one, never which. A screen shows that mail is set up.
    out.insert("password_set".into(), has_password.to_string());
    reply::ok_with(out)
}

/// Configure the mail server.
///
/// The address and the host go to the settings — neither is a secret — and
/// the credentials to the store, which is encrypted at rest under a key of
/// its own. Writing them here rather than through the generic secret endpoint
/// is what lets that endpoint keep the whole `global.` space closed.
pub async fn system_mail_save(
    user: Identity,
    data: web::Data<State>,
    cfg: web::Json<MailConfig>,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let srv: &crate::state::data::Data = &data.server;
    let cfg = cfg.into_inner();

    let from = cfg.from.trim().to_string();
    // Checked here, where somebody is looking at a form and can fix it. The
    // sender is used for every message this deployment ever sends, and a bad
    // one is discovered later, silently, by mail that does not arrive.
    if !from.is_empty() && from.parse::<lettre::message::Mailbox>().is_err() {
        return reply::err(format!("'{from}' is not an address mail can be sent from."));
    }

    let mut upd = srv.rw.get_settings().await.clone();
    upd.set_str("smtp_server", cfg.server.trim());
    upd.set_str("smtp_from", &from);
    // The credentials live in the store now. Left here they would stay in
    // every backup of the settings, which is the thing this moved away from.
    upd.strs.remove("smtp_login");
    upd.strs.remove("smtp_password");
    if !srv.rw.set_settings(upd).await {
        return reply::err("The settings could not be written.");
    }

    let mut secrets = srv.secrets.lock();
    let store = match secrets.as_mut() {
        Some(s) => s,
        None => return reply::err("The secret store is not available."),
    };
    let name = crate::notif::email::SMTP_SECRET;
    let existing = store.get_by_name(name);
    let mut itm = Item::new();
    itm.id = existing.as_ref().map(|i| i.id).unwrap_or(u64::MAX);
    itm.set_str("name", name);
    itm.set_str("login", cfg.login.trim());
    let password = cfg.password.trim();
    if keeps_existing(password) {
        // Keep what is there. An empty field is a field nobody typed in, and
        // the client could not have typed the password back because it was
        // never given it.
        if let Some(prev) = existing.as_ref().map(|i| i.safe_str("password", "")) {
            itm.set_str("password", &prev);
        }
    } else {
        itm.set_str("password", password);
    }
    match store.set(&itm, false) {
        Ok(_) => {
            info!("Mail: configuration stored");
            reply::ok()
        }
        Err(e) => reply::err(format!("The credentials could not be stored: {e}")),
    }
}

/// Forget the mail configuration entirely.
pub async fn system_mail_forget(user: Identity, data: web::Data<State>) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let srv: &crate::state::data::Data = &data.server;
    let mut upd = srv.rw.get_settings().await.clone();
    upd.set_str("smtp_server", "");
    upd.set_str("smtp_from", "");
    upd.strs.remove("smtp_login");
    upd.strs.remove("smtp_password");
    let _ = srv.rw.set_settings(upd).await;

    let mut secrets = srv.secrets.lock();
    if let Some(store) = secrets.as_mut() {
        if let Some(existing) = store.get_by_name(crate::notif::email::SMTP_SECRET) {
            if let Err(e) = store.del(existing.id) {
                return reply::err(format!("The credentials could not be removed: {e}"));
            }
        }
    }
    info!("Mail: configuration forgotten");
    reply::ok()
}

pub async fn system_update(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let usr = get_user(srv, principal(&user)).await;

    if !check_role(srv, &usr, "admin").await {
        return HttpResponse::Forbidden().into();
    }

    let script = srv.update_script.lock().clone();
    if script.is_empty() {
        return HttpResponse::Ok().body(
            serde_json::to_string(&ProcessResult {
                succeeded: false,
                error: "update script is not configured".to_string(),
                data: HashMap::new(),
            })
            .unwrap(),
        );
    }

    info!("System update: invoking {}", script);

    let parts: Vec<&str> = script.split_whitespace().collect();
    let (program, args) = match parts.split_first() {
        Some((p, a)) => (*p, a),
        None => {
            return HttpResponse::Ok().body(
                serde_json::to_string(&ProcessResult {
                    succeeded: false,
                    error: "update script is not configured".to_string(),
                    data: HashMap::new(),
                })
                .unwrap(),
            );
        }
    };
    let output = Command::new(program).args(args).output();
    match output {
        Ok(out) => {
            let mut data_map: HashMap<String, String> = HashMap::new();
            data_map.insert(
                "stdout".to_string(),
                String::from_utf8_lossy(&out.stdout).to_string(),
            );
            data_map.insert(
                "stderr".to_string(),
                String::from_utf8_lossy(&out.stderr).to_string(),
            );
            data_map.insert(
                "exit_code".to_string(),
                out.status.code().map(|c| c.to_string()).unwrap_or_default(),
            );

            HttpResponse::Ok().body(
                serde_json::to_string(&ProcessResult {
                    succeeded: out.status.success(),
                    error: if out.status.success() {
                        "".to_string()
                    } else {
                        format!("update script exited with status {}", out.status)
                    },
                    data: data_map,
                })
                .unwrap(),
            )
        }
        Err(e) => {
            error!("System update: failed to run {}: {}", script, e);
            HttpResponse::Ok().body(
                serde_json::to_string(&ProcessResult {
                    succeeded: false,
                    error: format!("failed to run update script: {}", e),
                    data: HashMap::new(),
                })
                .unwrap(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A screen shows that mail is configured, never what with. The word a
    /// client sends back instead of a password it was never given is the
    /// store's own, so posting an unchanged form leaves the password alone.
    #[test]
    fn the_placeholder_is_the_stores_own_word() {
        assert_eq!(UNCHANGED, "<hidden>");
    }

    /// Empty and the placeholder both mean "leave it", and nothing else
    /// does. There is no third way to say it: the client was never told what
    /// the password is, so it cannot type it back.
    #[test]
    fn only_two_things_mean_leave_it_alone() {
        assert!(keeps_existing(""));
        assert!(keeps_existing(UNCHANGED));

        // A new password, including one that merely looks like the word.
        assert!(!keeps_existing("s3cret"));
        assert!(!keeps_existing("hidden"));
        assert!(!keeps_existing("<hidden"));
        assert!(!keeps_existing("<HIDDEN>"));
    }

    /// A body with nothing in it is a body that clears the host and the
    /// sender and keeps the password — not one that fails to parse.
    #[test]
    fn a_partial_body_is_read() {
        let cfg: MailConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.server, "");
        assert_eq!(cfg.from, "");
        assert_eq!(cfg.login, "");
        assert_eq!(cfg.password, "");

        let cfg: MailConfig =
            serde_json::from_str(r#"{"server":"smtp.example.com","from":"Proteos <p@e.dev>"}"#)
                .unwrap();
        assert_eq!(cfg.server, "smtp.example.com");
        assert_eq!(cfg.from, "Proteos <p@e.dev>");
    }

    /// The sender is checked where somebody is looking at a form and can fix
    /// it. Left to the send itself, a bad one is found later and silently, by
    /// mail that does not arrive.
    #[test]
    fn the_sender_is_checked_before_it_is_stored() {
        for good in ["p@e.dev", "Proteos <p@e.dev>"] {
            assert!(good.parse::<lettre::message::Mailbox>().is_ok(), "{good}");
        }
        for bad in ["nonsense", "a@b@c", "@e.dev"] {
            assert!(bad.parse::<lettre::message::Mailbox>().is_err(), "{bad}");
        }
    }

    /// The credentials live in the store, and the endpoint that writes them
    /// is the one that owns them — which is what lets the generic secret
    /// endpoint keep the whole reserved space closed.
    #[test]
    fn the_entry_written_is_the_reserved_one() {
        assert!(crate::state::secrets::is_global_name(
            crate::notif::email::SMTP_SECRET
        ));
        assert_eq!(crate::notif::email::SMTP_SECRET, "global.smtp");
    }
}
