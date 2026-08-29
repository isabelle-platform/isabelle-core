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
//! Configuring the ways in.
//!
//! One screen's worth of API for every way of signing in that is not a local
//! password: the identity providers, which are a redirect flow, and the
//! directory, which is a bind. They have almost nothing in common as
//! protocols and everything in common as a thing an administrator sets up
//! once, so they are configured together and stored the same way — one
//! encrypted secret-store entry each, whose presence is what enables them.
//!
//! Two rules run through all of it. Nothing that was written as a secret is
//! ever read back, so what comes out says only whether there is one. And an
//! empty secret in what goes in means "leave it alone", because a form that
//! was never allowed to show a value must not be able to erase it by being
//! saved; removing something is `/auth/config/forget`, which says so.

use crate::server::secret::ensure_admin;
use crate::server::signin::{ldap_config, LDAP_SECRET};
use crate::state::state::*;
use crate::util::ldap::LdapConfig;
use crate::util::multipart::{read_json_body, Limits};
use crate::util::oidc::{self, Provider, ProviderConfig};
use actix_identity::Identity;
use actix_web::{web, HttpResponse};
use isabelle_dm::data_model::item::Item;
use log::{error, info};
use serde::Deserialize;
use std::collections::HashMap;

/// One provider as an administrator sees it.
///
/// The secret store masks everything it is not told is metadata, which is the
/// right default for a store of secrets but leaves a configuration screen
/// unable to show a client id — a value that is in the address bar of every
/// person who ever signs in. Rather than widening that allowlist for every
/// secret in the deployment, the decision about which of *these* fields are
/// public is made here, where what each one is for is known.
fn admin_view(srv: &crate::state::data::Data, provider: Provider) -> serde_json::Value {
    let stored = crate::server::oauth::provider_config(srv, provider);
    let cfg = stored.clone().unwrap_or_default();
    let problem = match &stored {
        None => String::new(),
        Some(c) => oidc::validate(provider, c).err().unwrap_or_default(),
    };
    // Never the client secret and never the key — only whether there is one,
    // which is what a form needs to say "leave blank to keep".
    let has_secret = match provider {
        Provider::Google => !cfg.client_secret.trim().is_empty(),
        Provider::Apple => !cfg.private_key.trim().is_empty(),
    };
    serde_json::json!({
        "id": provider.id(),
        "name": provider.display_name(),
        "configured": stored.is_some() && problem.is_empty(),
        "problem": problem,
        "client_id": cfg.client_id,
        "team_id": cfg.team_id,
        "key_id": cfg.key_id,
        "redirect_uri": stored_redirect_uri(srv, provider),
        "effective_redirect_uri": crate::server::oauth::redirect_uri(srv, provider),
        "has_secret": has_secret,
    })
}

/// The redirect URI an operator set, as opposed to the one in use.
fn stored_redirect_uri(srv: &crate::state::data::Data, provider: Provider) -> String {
    srv.secrets
        .lock()
        .as_ref()
        .and_then(|s| s.get_by_name(provider.secret_name()))
        .map(|i| i.safe_str("redirect_uri", ""))
        .unwrap_or_default()
}

/// The directory as an administrator sees it.
///
/// Kept out of `providers` deliberately: those are things a login screen puts
/// a button on, and this is not one. Signing in against a directory happens
/// through the ordinary form, so a screen that offered a "Continue with LDAP"
/// button would be offering something that does not exist.
fn ldap_admin_view(srv: &crate::state::data::Data) -> serde_json::Value {
    let stored = ldap_config(srv);
    let cfg = stored.clone().unwrap_or_default();
    let problem = match &stored {
        None => String::new(),
        Some(c) => crate::util::ldap::validate(c).err().unwrap_or_default(),
    };
    serde_json::json!({
        "configured": stored.is_some() && problem.is_empty(),
        "problem": problem,
        "url": cfg.url,
        "bind_dn": cfg.bind_dn,
        "base_dn": cfg.base_dn,
        "user_filter": cfg.user_filter,
        "user_dn_template": cfg.user_dn_template,
        "email_attribute": cfg.email_attribute,
        "name_attribute": cfg.name_attribute,
        "allow_plaintext": cfg.allow_plaintext,
        // The service account's password, like every other secret here, is
        // acknowledged and never returned.
        "has_secret": !cfg.bind_password.trim().is_empty(),
    })
}

/// What is configured, for the screen that configures it.
pub async fn auth_config(user: Identity, data: web::Data<State>) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let srv: &crate::state::data::Data = &data.server;
    HttpResponse::Ok().json(serde_json::json!({
        "providers": [
            admin_view(srv, Provider::Google),
            admin_view(srv, Provider::Apple),
        ],
        "ldap": ldap_admin_view(srv),
    }))
}

/// One provider's settings, as a form submits them.
///
/// Every field is optional and absent means "leave alone", so a form can send
/// only what changed. For the two that can never be read back — the client
/// secret and the private key — an empty string means the same thing, because
/// an empty box on a screen that cannot show them means "unchanged", not
/// "delete". Removing a provider is `/auth/config/forget`, which says so.
#[derive(Debug, Default, Deserialize)]
struct ConfigUpdate {
    provider: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,

    // The directory's own settings. Absent for a provider, and vice versa.
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    bind_dn: Option<String>,
    #[serde(default)]
    bind_password: Option<String>,
    #[serde(default)]
    base_dn: Option<String>,
    #[serde(default)]
    user_filter: Option<String>,
    #[serde(default)]
    user_dn_template: Option<String>,
    #[serde(default)]
    email_attribute: Option<String>,
    #[serde(default)]
    name_attribute: Option<String>,
    #[serde(default)]
    allow_plaintext: Option<bool>,
}

/// Fold a submitted form onto the directory settings already stored, by the
/// same rule: an absent field is left alone, and so is a blank password,
/// which is the one value the screen was never allowed to show.
fn apply_ldap_update(current: &LdapConfig, update: &ConfigUpdate) -> LdapConfig {
    let plain = |field: &Option<String>, existing: &str| -> String {
        field
            .as_ref()
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|| existing.to_string())
    };
    LdapConfig {
        url: plain(&update.url, &current.url),
        bind_dn: plain(&update.bind_dn, &current.bind_dn),
        bind_password: match update.bind_password.as_ref().map(|v| v.trim()) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => current.bind_password.clone(),
        },
        base_dn: plain(&update.base_dn, &current.base_dn),
        user_filter: plain(&update.user_filter, &current.user_filter),
        user_dn_template: plain(&update.user_dn_template, &current.user_dn_template),
        email_attribute: plain(&update.email_attribute, &current.email_attribute),
        name_attribute: plain(&update.name_attribute, &current.name_attribute),
        allow_plaintext: update.allow_plaintext.unwrap_or(current.allow_plaintext),
    }
}

/// Fold a submitted form onto what is already stored.
///
/// Separated from the writing so the "empty means unchanged" rule — the one
/// that decides whether a saved form can wipe a secret it was never shown —
/// can be stated as a test.
fn apply_update(current: &ProviderConfig, update: &ConfigUpdate) -> ProviderConfig {
    let plain = |field: &Option<String>, existing: &str| -> String {
        field
            .as_ref()
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|| existing.to_string())
    };
    let secret = |field: &Option<String>, existing: &str| -> String {
        match field.as_ref().map(|v| v.trim()) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => existing.to_string(),
        }
    };
    ProviderConfig {
        client_id: plain(&update.client_id, &current.client_id),
        client_secret: secret(&update.client_secret, &current.client_secret),
        team_id: plain(&update.team_id, &current.team_id),
        key_id: plain(&update.key_id, &current.key_id),
        private_key: secret(&update.private_key, &current.private_key),
    }
}

fn config_err(msg: impl Into<String>) -> HttpResponse {
    HttpResponse::Ok().json(isabelle_dm::data_model::process_result::ProcessResult {
        succeeded: false,
        error: msg.into(),
        data: HashMap::new(),
    })
}

fn config_ok() -> HttpResponse {
    HttpResponse::Ok().json(isabelle_dm::data_model::process_result::ProcessResult {
        succeeded: true,
        error: String::new(),
        data: HashMap::new(),
    })
}

/// Configure one provider.
pub async fn auth_config_save(
    user: Identity,
    data: web::Data<State>,
    mut payload: web::Payload,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let limits = Limits::from_data(&data.server);
    let update: ConfigUpdate = match read_json_body(&mut payload, limits).await {
        Ok(v) => v,
        Err(e) => {
            error!("Could not read the sign-in configuration: {}", e);
            return HttpResponse::build(e.status()).finish();
        }
    };
    let srv: &crate::state::data::Data = &data.server;
    if update.provider.trim() == "ldap" {
        return save_ldap(srv, &update);
    }
    let provider = match Provider::from_id(update.provider.trim()) {
        Some(p) => p,
        None => return config_err("There is no such provider."),
    };

    let merged = apply_update(
        &crate::server::oauth::provider_config(srv, provider).unwrap_or_default(),
        &update,
    );
    // Checked before it is stored, not when somebody first tries to sign in:
    // a private key that cannot be read is a setting that is wrong now.
    if let Err(e) = oidc::validate(provider, &merged) {
        return config_err(format!(
            "{} cannot be used yet: {}",
            provider.display_name(),
            e
        ));
    }
    let uri = update
        .redirect_uri
        .clone()
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| stored_redirect_uri(srv, provider));
    if !uri.is_empty() && !oidc::redirect_uri_is_usable(&uri) {
        return config_err(
            "The redirect URI has to be a full address, starting with http:// or https://.",
        );
    }

    let mut secrets = srv.secrets.lock();
    let store = match secrets.as_mut() {
        Some(s) => s,
        None => return config_err("The secret store is not available."),
    };
    let mut itm = Item::new();
    itm.id = store
        .get_by_name(provider.secret_name())
        .map(|i| i.id)
        .unwrap_or(u64::MAX);
    itm.set_str("name", provider.secret_name());
    itm.set_str("client_id", merged.client_id.trim());
    itm.set_str("client_secret", merged.client_secret.trim());
    itm.set_str("team_id", merged.team_id.trim());
    itm.set_str("key_id", merged.key_id.trim());
    itm.set_str("private_key", merged.private_key.trim());
    itm.set_str("redirect_uri", &uri);
    match store.set(&itm, true) {
        Ok(_) => {
            info!("Sign-in with {} was configured", provider.display_name());
            config_ok()
        }
        Err(e) => config_err(format!("The configuration could not be stored: {}", e)),
    }
}

/// Store the directory settings, once they are known to be usable.
fn save_ldap(srv: &crate::state::data::Data, update: &ConfigUpdate) -> HttpResponse {
    let merged = apply_ldap_update(&ldap_config(srv).unwrap_or_default(), update);
    // Checked before storing, like the providers: a filter with no `%u` in it
    // matches the same person whatever is typed, which is worse than a
    // setting that plainly does not work.
    if let Err(e) = crate::util::ldap::validate(&merged) {
        return config_err(format!("The directory cannot be used yet: {}", e));
    }

    let mut secrets = srv.secrets.lock();
    let store = match secrets.as_mut() {
        Some(s) => s,
        None => return config_err("The secret store is not available."),
    };
    let mut itm = Item::new();
    itm.id = store
        .get_by_name(LDAP_SECRET)
        .map(|i| i.id)
        .unwrap_or(u64::MAX);
    itm.set_str("name", LDAP_SECRET);
    itm.set_str("url", merged.url.trim());
    itm.set_str("bind_dn", merged.bind_dn.trim());
    itm.set_str("bind_password", merged.bind_password.trim());
    itm.set_str("base_dn", merged.base_dn.trim());
    itm.set_str("user_filter", merged.user_filter.trim());
    itm.set_str("user_dn_template", merged.user_dn_template.trim());
    itm.set_str("email_attribute", merged.email_attribute.trim());
    itm.set_str("name_attribute", merged.name_attribute.trim());
    itm.set_bool("allow_plaintext", merged.allow_plaintext);
    match store.set(&itm, true) {
        Ok(_) => {
            info!("Sign-in against the directory was configured");
            config_ok()
        }
        Err(e) => config_err(format!("The configuration could not be stored: {}", e)),
    }
}

#[derive(Debug, Deserialize)]
struct ForgetRequest {
    provider: String,
}

/// Remove a provider's configuration, which is also how it is switched off.
pub async fn auth_config_forget(
    user: Identity,
    data: web::Data<State>,
    mut payload: web::Payload,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let limits = Limits::from_data(&data.server);
    let req: ForgetRequest = match read_json_body(&mut payload, limits).await {
        Ok(v) => v,
        Err(e) => return HttpResponse::build(e.status()).finish(),
    };
    let srv: &crate::state::data::Data = &data.server;
    let name = if req.provider.trim() == "ldap" {
        LDAP_SECRET
    } else {
        match Provider::from_id(req.provider.trim()) {
            Some(p) => p.secret_name(),
            None => return config_err("There is no such provider."),
        }
    };
    let mut secrets = srv.secrets.lock();
    let store = match secrets.as_mut() {
        Some(s) => s,
        None => return config_err("The secret store is not available."),
    };
    let id = match store.get_by_name(name) {
        Some(i) => i.id,
        // Already absent is the state that was asked for.
        None => return config_ok(),
    };
    match store.del(id) {
        Ok(_) => {
            info!("Sign-in configuration '{}' was removed", name);
            config_ok()
        }
        Err(e) => config_err(format!("The configuration could not be removed: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule that decides whether saving a form can wipe a secret the
    /// form was never allowed to show.
    #[test]
    fn a_blank_secret_box_means_unchanged_rather_than_delete() {
        let current = ProviderConfig {
            client_id: "old-id".into(),
            client_secret: "kept".into(),
            ..Default::default()
        };
        let update = ConfigUpdate {
            provider: "google".into(),
            client_id: Some("new-id".into()),
            client_secret: Some(String::new()),
            ..Default::default()
        };
        let merged = apply_update(&current, &update);
        assert_eq!(merged.client_id, "new-id");
        assert_eq!(merged.client_secret, "kept");
    }

    #[test]
    fn a_secret_that_was_typed_replaces_the_one_stored() {
        let current = ProviderConfig {
            client_secret: "old".into(),
            ..Default::default()
        };
        let update = ConfigUpdate {
            provider: "google".into(),
            client_secret: Some("  new  ".into()),
            ..Default::default()
        };
        // Trimmed on the way in: a value pasted with a newline would
        // otherwise be a secret that is subtly not the one issued.
        assert_eq!(apply_update(&current, &update).client_secret, "new");
    }

    /// A field the form did not send is a field the form was not editing.
    #[test]
    fn what_a_form_leaves_out_it_leaves_alone() {
        let current = ProviderConfig {
            client_id: "id".into(),
            client_secret: "shh".into(),
            team_id: "T".into(),
            key_id: "K".into(),
            private_key: "PEM".into(),
        };
        let update = ConfigUpdate {
            provider: "apple".into(),
            ..Default::default()
        };
        assert_eq!(apply_update(&current, &update), current);
    }

    /// A non-secret field, on the other hand, can be cleared — it is on the
    /// screen, so an empty box is a decision.
    #[test]
    fn clearing_a_visible_field_clears_it() {
        let current = ProviderConfig {
            client_id: "id".into(),
            team_id: "T".into(),
            ..Default::default()
        };
        let update = ConfigUpdate {
            provider: "apple".into(),
            team_id: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(apply_update(&current, &update).team_id, "");
    }

    fn ldap_update(over: fn(&mut ConfigUpdate)) -> ConfigUpdate {
        let mut u = ConfigUpdate {
            provider: "ldap".into(),
            client_id: None,
            client_secret: None,
            team_id: None,
            key_id: None,
            private_key: None,
            redirect_uri: None,
            url: None,
            bind_dn: None,
            bind_password: None,
            base_dn: None,
            user_filter: None,
            user_dn_template: None,
            email_attribute: None,
            name_attribute: None,
            allow_plaintext: None,
        };
        over(&mut u);
        u
    }

    /// The same rule as for a client secret, and for the same reason: the
    /// screen was never shown the service account's password.
    #[test]
    fn a_blank_service_password_leaves_the_stored_one_alone() {
        let current = LdapConfig {
            url: "ldaps://old.example.com".into(),
            bind_password: "kept".into(),
            ..Default::default()
        };
        let merged = apply_ldap_update(
            &current,
            &ldap_update(|u| {
                u.url = Some("ldaps://new.example.com".into());
                u.bind_password = Some(String::new());
            }),
        );
        assert_eq!(merged.url, "ldaps://new.example.com");
        assert_eq!(merged.bind_password, "kept");
    }

    /// A checkbox that was not sent is a checkbox nobody touched — and this
    /// particular one is what stands between a password and the network.
    #[test]
    fn the_plaintext_decision_is_not_reset_by_a_form_that_omits_it() {
        let current = LdapConfig {
            allow_plaintext: true,
            ..Default::default()
        };
        assert!(apply_ldap_update(&current, &ldap_update(|_| {})).allow_plaintext);
        assert!(
            !apply_ldap_update(&current, &ldap_update(|u| u.allow_plaintext = Some(false)))
                .allow_plaintext
        );
    }

    #[test]
    fn a_typed_service_password_replaces_the_stored_one() {
        let current = LdapConfig {
            bind_password: "old".into(),
            ..Default::default()
        };
        let merged = apply_ldap_update(
            &current,
            &ldap_update(|u| u.bind_password = Some("  new  ".into())),
        );
        assert_eq!(merged.bind_password, "new");
    }
}
