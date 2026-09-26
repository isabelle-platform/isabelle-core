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

//! The feature list, over HTTP.
//!
//! One endpoint, and it is a read. `features.js` is edited on disk and
//! nowhere else — there is no `/feature/edit` to match `/setting/edit`, and
//! its absence is the guarantee, not a gap. A deployment's feature set is
//! decided by whoever installs it, so no session, no token and no plugin can
//! widen it from inside the running server.
//!
//! What goes out is the names alone. The descriptor beside each name is for
//! the code that implements the feature — it can hold limits, quotas, keys
//! into somebody's licence, internal names of things — and a browser needs
//! none of that to decide what to render. Plugins read the full document
//! through `Data::features()`, which stays on this side of the wire.

use crate::state::state::*;
use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};

/// `GET /feature/list` — what this deployment may do, by name.
///
/// Any signed-in caller, not only an administrator: the UI a normal user
/// looks at is the main thing that has to know which features exist, and an
/// admin-only answer would leave it guessing. It says nothing about the
/// caller, so it discloses nothing one account could not learn from another.
pub async fn feature_list(
    user: Option<Identity>,
    data: web::Data<State>,
    _req: HttpRequest,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    // What the deployment can do decides what a public instance shows its
    // anonymous readers, so they are told too; nobody else is.
    if user.is_none() && !crate::server::public_read::is_public(srv).await {
        return HttpResponse::Unauthorized().into();
    }
    let features = srv.features();
    HttpResponse::Ok().json(features.names())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::login::login;
    use crate::state::data::Data;
    use crate::state::features::Features;
    use crate::state::store_memory::StoreMemory;
    use crate::util::crypto::{get_new_salt, get_password_hash};
    use actix_web::{test, App};
    use isabelle_dm::data_model::item::Item;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    const BOUNDARY: &str = "----isabelletestboundary";

    /// The same middleware stack the server builds, so `Identity` is a real
    /// extractor rather than something that panics for want of one, and a
    /// session cookie is obtained the way a client obtains it.
    macro_rules! app_with {
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
                    .route("/feature/list", web::get().to(feature_list)),
            )
            .await
        };
    }

    fn account_with_password(pw: &str) -> Item {
        let mut itm = Item::new();
        itm.id = 1;
        itm.set_str("login", "alice");
        itm.set_str("email", "alice@example.org");
        itm.set_str("password", &get_password_hash(pw, &get_new_salt()));
        itm.set_bool("role_is_active", true);
        itm
    }

    fn multipart_body(fields: &[(&str, &str)]) -> String {
        let mut body = String::new();
        for (name, value) in fields {
            body.push_str(&format!("--{}\r\n", BOUNDARY));
            body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
                name
            ));
            body.push_str(value);
            body.push_str("\r\n");
        }
        body.push_str(&format!("--{}--\r\n", BOUNDARY));
        body
    }

    /// A deployment holding one account and whatever feature set is given.
    fn state_with(features: Features) -> web::Data<State> {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", account_with_password("hunter2"));
        let mut data = Data::new();
        data.rw = Box::new(store);
        let state = State::from_data(data);
        *state.server.features.lock() = Arc::new(features);
        web::Data::new(state)
    }

    /// Three features, two of them with descriptors that must never leave
    /// the server.
    fn declared() -> Features {
        let mut map = BTreeMap::new();
        map.insert(
            "reports".to_string(),
            json!({ "formats": ["pdf"], "internal_quota_key": "quota-7731" }),
        );
        map.insert("sso".to_string(), json!({ "tenant": "acme-internal" }));
        map.insert("beta_ui".to_string(), json!(null));
        Features::from_map(map)
    }

    /// Sign in and return the session cookie, the way a client would.
    macro_rules! session_cookie {
        ($app:expr) => {{
            let res = test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/login")
                    .insert_header((
                        "content-type",
                        format!("multipart/form-data; boundary={}", BOUNDARY),
                    ))
                    .set_payload(multipart_body(&[
                        ("username", "alice"),
                        ("password", "hunter2"),
                    ]))
                    .to_request(),
            )
            .await;
            res.response()
                .cookies()
                .next()
                .expect("login issued no session cookie")
                .into_owned()
        }};
    }

    /// The names, and nothing else. The descriptor is the part a browser
    /// must not receive: it can carry quotas, tenant names and licence
    /// detail that the feature's own code needs and a UI does not.
    #[actix_web::test]
    async fn the_list_is_names_without_descriptors() {
        let app = app_with!(state_with(declared()));
        let cookie = session_cookie!(app);

        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/feature/list")
                .cookie(cookie)
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), actix_web::http::StatusCode::OK);

        let body = test::read_body(res).await;
        let text = String::from_utf8_lossy(&body);

        let names: Vec<String> = serde_json::from_slice(&body).expect("not a JSON array");
        assert_eq!(names, vec!["beta_ui", "reports", "sso"]);

        for leaked in [
            "formats",
            "pdf",
            "internal_quota_key",
            "quota-7731",
            "acme-internal",
        ] {
            assert!(
                !text.contains(leaked),
                "the response carried a descriptor: {} in {}",
                leaked,
                text
            );
        }
    }

    /// Reading the list takes a session. It is not secret, but it is not
    /// part of what an anonymous caller is told about a deployment either —
    /// `/is_logged_in` is the endpoint that exists for that.
    #[actix_web::test]
    async fn no_session_reads_nothing() {
        let app = app_with!(state_with(declared()));
        let res = test::call_service(
            &app,
            test::TestRequest::get().uri("/feature/list").to_request(),
        )
        .await;
        assert_eq!(res.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    /// A deployment with no usable `features.js` answers an empty list, not
    /// an error and not a missing endpoint. The client's question — "may I
    /// show this?" — has an answer in that case too, and it is "no".
    #[actix_web::test]
    async fn a_deployment_without_features_answers_an_empty_list() {
        let app = app_with!(state_with(Features::new()));
        let cookie = session_cookie!(app);

        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/feature/list")
                .cookie(cookie)
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), actix_web::http::StatusCode::OK);
        let names: Vec<String> = serde_json::from_slice(&test::read_body(res).await).unwrap();
        assert!(names.is_empty(), "{:?}", names);
    }
}
