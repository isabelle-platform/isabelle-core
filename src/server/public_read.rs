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

//! Reading without an account, on an instance that says it is public.
//!
//! An administrator makes an instance public with the `instance_public`
//! setting. What that opens is decided in two places, and both have to agree:
//!
//! * here, which collections an anonymous caller may list at all — the ones
//!   the flavour names in `internals.public_read_collections`, and never
//!   `user` or the API tokens, whatever that says;
//! * in the plugins, what of those collections such a caller may see: their
//!   list hooks and route guards are called with no user, exactly as for an
//!   account that has no rights, and narrow from there.
//!
//! Nothing here opens a write. `itm/edit`, `itm/del`, the settings and every
//! POST route still take a session.
//!
//! An instance several customers share (the `shared_instance` feature) is
//! never public, whatever the setting says: opening it would show each of
//! them what the others keep there.
//!
//! A visitor asking for a collection that is not opened gets an empty list
//! rather than a refusal. Nothing is disclosed either way, and the screens a
//! visitor may open read such collections on the side — the users behind the
//! runs, the nodes behind the projects — and would otherwise fail whole.

use crate::state::data::Data;

/// The setting that makes an instance public.
pub const SETTING_PUBLIC: &str = "instance_public";
/// The internals entry naming the collections anonymous callers may list.
pub const INTERNALS_COLLECTIONS: &str = "public_read_collections";

/// The internals entry naming the settings anybody who may read may see.
pub const INTERNALS_SETTINGS: &str = "public_settings";
/// The feature of an instance several customers share.
pub const FEATURE_SHARED: &str = "shared_instance";

/// Collections no configuration opens to an anonymous caller.
const NEVER: [&str; 2] = ["user", crate::server::api_token::COLLECTION];

pub async fn is_public(srv: &Data) -> bool {
    !srv.features().has(FEATURE_SHARED)
        && srv.rw.get_settings().await.safe_bool(SETTING_PUBLIC, false)
}

/// The settings a reader who is not an administrator is given: only the keys
/// the flavour names in `internals.public_settings` — the site's name and
/// look, which sections it shows, where its Bublik is. Never the rest, which
/// holds API keys and passwords.
pub async fn public_settings(srv: &Data) -> isabelle_dm::data_model::item::Item {
    let all = srv.rw.get_settings().await;
    let internals = srv.rw.get_internals().await;
    let mut out = isabelle_dm::data_model::item::Item::new();
    out.id = all.id;
    let Some(keys) = internals.strstrs.get(INTERNALS_SETTINGS) else {
        return out;
    };
    for key in keys.values() {
        if let Some(v) = all.strs.get(key) {
            out.strs.insert(key.clone(), v.clone());
        }
        if let Some(v) = all.bools.get(key) {
            out.bools.insert(key.clone(), *v);
        }
        if let Some(v) = all.u64s.get(key) {
            out.u64s.insert(key.clone(), *v);
        }
    }
    out
}

/// Whether a caller with no session may list `collection`.
pub async fn anonymous_may_list(srv: &Data, collection: &str) -> bool {
    if NEVER.contains(&collection) || !is_public(srv).await {
        return false;
    }
    srv.rw
        .get_internals()
        .await
        .strstrs
        .get(INTERNALS_COLLECTIONS)
        .is_some_and(|m| m.values().any(|c| c == collection))
}

#[cfg(test)]
mod tests {
    use crate::server::itm::itm_list;
    use crate::server::login::{is_logged_in, login};
    use crate::server::setting::setting_list;
    use crate::state::data::Data;
    use crate::state::features::Features;
    use crate::state::state::State;
    use crate::state::store_memory::StoreMemory;
    use crate::util::crypto::{get_new_salt, get_password_hash};
    use actix_web::http::StatusCode;
    use actix_web::{test, web, App};
    use isabelle_dm::data_model::item::Item;
    use std::collections::{BTreeMap, HashMap};

    fn item(id: u64, name: &str) -> Item {
        let mut it = Item::new();
        it.id = id;
        it.set_str("name", name);
        it
    }

    fn names(values: &[&str]) -> HashMap<String, String> {
        values
            .iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v.to_string()))
            .collect()
    }

    async fn state(public: bool, shared: bool) -> web::Data<State> {
        let store = StoreMemory::with_collections(&["user", "workspace", "node"]);
        let mut admin = item(1, "admin");
        admin.set_str("login", "admin");
        admin.set_str("email", "admin@example.org");
        admin.set_str("password", &get_password_hash("hunter2", &get_new_salt()));
        admin.set_bool("role_is_active", true);
        admin.set_bool("role_is_admin", true);
        store.seed("user", admin);
        store.seed("workspace", item(5, "wifi"));
        store.seed("node", item(6, "lab"));
        let mut internals = Item::new();
        // "user" named here by mistake; it must stay closed anyway.
        internals.strstrs.insert(
            super::INTERNALS_COLLECTIONS.to_string(),
            names(&["workspace", "user"]),
        );
        internals.strstrs.insert(
            super::INTERNALS_SETTINGS.to_string(),
            names(&["site_name", "instance_public"]),
        );
        store.set_internals(internals);
        let mut settings = Item::new();
        settings.set_bool(super::SETTING_PUBLIC, public);
        settings.set_str("site_name", "Lab");
        settings.set_str("ai_claude_api_key", "sk-secret");
        let mut data = Data::new();
        data.rw = Box::new(store);
        data.rw.set_settings(settings).await;
        if shared {
            let mut declared = BTreeMap::new();
            declared.insert(super::FEATURE_SHARED.to_string(), serde_json::Value::Null);
            *data.features.lock() = std::sync::Arc::new(Features::from_map(declared));
        }
        web::Data::new(State::from_data(data))
    }

    macro_rules! app {
        ($state:expr) => {
            test::init_service(
                App::new()
                    .app_data($state)
                    .wrap(actix_identity::IdentityMiddleware::default())
                    .wrap(
                        actix_session::SessionMiddleware::builder(
                            actix_session::storage::CookieSessionStore::default(),
                            actix_web::cookie::Key::from(&[0u8; 64]),
                        )
                        .cookie_secure(false)
                        .build(),
                    )
                    .route("/login", web::post().to(login))
                    .route("/is_logged_in", web::get().to(is_logged_in))
                    .route("/setting/list", web::get().to(setting_list))
                    .route("/itm/list", web::get().to(itm_list)),
            )
            .await
        };
    }

    macro_rules! get {
        ($app:expr, $uri:expr) => {{
            let res =
                test::call_service(&$app, test::TestRequest::get().uri($uri).to_request()).await;
            let status = res.status();
            let body = String::from_utf8_lossy(&test::read_body(res).await).to_string();
            (status, body)
        }};
    }

    #[actix_web::test]
    async fn a_private_instance_lists_nothing_anonymously() {
        let app = app!(state(false, false).await);
        let (status, _) = get!(app, "/itm/list?collection=workspace&context=list&id=5");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = get!(app, "/setting/list");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn a_public_instance_lists_what_the_flavour_opened_and_nothing_else() {
        let app = app!(state(true, false).await);
        let (status, body) = get!(app, "/itm/list?collection=workspace&context=list&id=5");
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("wifi"));
        // Not named, or named but never open: an empty answer, not a refusal
        // that would fail a page reading them on the side.
        for uri in [
            "/itm/list?collection=node&context=list&id=6",
            "/itm/list?collection=user&context=list&id=1",
        ] {
            let (status, body) = get!(app, uri);
            assert_eq!(status, StatusCode::OK, "{}", uri);
            assert!(
                !body.contains("lab") && !body.contains("admin"),
                "{}: {}",
                uri,
                body
            );
            assert!(body.contains("\"total_count\":0"), "{}: {}", uri, body);
        }
    }

    #[actix_web::test]
    async fn a_visitor_is_told_the_settings_the_flavour_named_and_no_secret() {
        let app = app!(state(true, false).await);
        let (status, body) = get!(app, "/setting/list");
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Lab"));
        assert!(body.contains("instance_public"));
        assert!(!body.contains("sk-secret"), "{}", body);
    }

    /// An instance several customers share is never public: the setting
    /// changes nothing, and the UI is told so.
    #[actix_web::test]
    async fn a_shared_instance_is_never_public() {
        let app = app!(state(true, true).await);
        let (status, _) = get!(app, "/itm/list?collection=workspace&context=list&id=5");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = get!(app, "/setting/list");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (_, body) = get!(app, "/is_logged_in");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["params"]["public"], "false");
    }

    #[actix_web::test]
    async fn the_session_check_says_whether_the_instance_is_public() {
        for public in [false, true] {
            let app = app!(state(public, false).await);
            let (_, body) = get!(app, "/is_logged_in");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["params"]["public"], public.to_string());
        }
    }
}
