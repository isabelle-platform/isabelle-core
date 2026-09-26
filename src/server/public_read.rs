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

use crate::state::data::Data;

/// The setting that makes an instance public.
pub const SETTING_PUBLIC: &str = "instance_public";
/// The internals entry naming the collections anonymous callers may list.
pub const INTERNALS_COLLECTIONS: &str = "public_read_collections";

/// Collections no configuration opens to an anonymous caller.
const NEVER: [&str; 2] = ["user", crate::server::api_token::COLLECTION];

pub async fn is_public(srv: &Data) -> bool {
    srv.rw.get_settings().await.safe_bool(SETTING_PUBLIC, false)
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
    use crate::state::data::Data;
    use crate::state::state::State;
    use crate::state::store_memory::StoreMemory;
    use crate::util::crypto::{get_new_salt, get_password_hash};
    use actix_web::http::StatusCode;
    use actix_web::{test, web, App};
    use isabelle_dm::data_model::item::Item;
    use std::collections::HashMap;

    fn item(id: u64, name: &str) -> Item {
        let mut it = Item::new();
        it.id = id;
        it.set_str("name", name);
        it
    }

    async fn state(public: bool) -> web::Data<State> {
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
        let mut open = HashMap::new();
        open.insert("1".to_string(), "workspace".to_string());
        // Named here by mistake; it must stay closed anyway.
        open.insert("2".to_string(), "user".to_string());
        internals
            .strstrs
            .insert(super::INTERNALS_COLLECTIONS.to_string(), open);
        store.set_internals(internals);
        let mut settings = Item::new();
        settings.set_bool(super::SETTING_PUBLIC, public);
        let mut data = Data::new();
        data.rw = Box::new(store);
        data.rw.set_settings(settings).await;
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
                    .route("/itm/list", web::get().to(itm_list)),
            )
            .await
        };
    }

    macro_rules! status {
        ($app:expr, $uri:expr) => {
            test::call_service(&$app, test::TestRequest::get().uri($uri).to_request())
                .await
                .status()
        };
    }

    #[actix_web::test]
    async fn a_private_instance_lists_nothing_anonymously() {
        let app = app!(state(false).await);
        assert_eq!(
            status!(app, "/itm/list?collection=workspace&context=list"),
            StatusCode::UNAUTHORIZED
        );
    }

    #[actix_web::test]
    async fn a_public_instance_lists_what_the_flavour_opened_and_nothing_else() {
        let app = app!(state(true).await);
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/itm/list?collection=workspace&context=list&id=5")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = test::read_body(res).await;
        assert!(String::from_utf8_lossy(&body).contains("wifi"));
        // Not named: closed.
        assert_eq!(
            status!(app, "/itm/list?collection=node&context=list&id=6"),
            StatusCode::UNAUTHORIZED
        );
        // Named, but never open.
        assert_eq!(
            status!(app, "/itm/list?collection=user&context=list&id=1"),
            StatusCode::UNAUTHORIZED
        );
    }

    #[actix_web::test]
    async fn the_session_check_says_whether_the_instance_is_public() {
        for public in [false, true] {
            let app = app!(state(public).await);
            let res = test::call_service(
                &app,
                test::TestRequest::get().uri("/is_logged_in").to_request(),
            )
            .await;
            let v: serde_json::Value = serde_json::from_slice(&test::read_body(res).await).unwrap();
            assert_eq!(v["params"]["public"], public.to_string());
        }
    }
}
