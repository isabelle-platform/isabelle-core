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

//! Request-level guards that apply to every route.
//!
//! These are the checks that cannot live in a handler, because a handler only
//! runs once routing has already decided the request is well formed and the
//! caller is who the cookie says.

use crate::server::user_control::{get_user, session_generation};
use crate::state::state::State;
use actix_identity::IdentityExt;
use actix_session::SessionExt;
use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::middleware::Next;
use actix_web::{Error, HttpResponse};
use log::{info, warn};

/// Key the session generation is stored under in the cookie.
pub const SESSION_GEN_KEY: &str = "sgen";

/// Refuse a request that frames its body two ways at once.
///
/// RFC 9112 §6.1: a message with both `Content-Length` and `Transfer-Encoding`
/// must be rejected, or the `Content-Length` removed before it is forwarded.
/// Accepting it is what turns one request into two when something in front of
/// this server resolves the ambiguity the other way — the front end reads one
/// framing, the back end the other, and the bytes left over in the connection
/// become a request nobody authenticated. Harmless while nothing proxies this
/// service, and the whole ballgame the moment something does.
pub async fn reject_ambiguous_framing(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let headers = req.headers();
    if headers.contains_key(header::CONTENT_LENGTH)
        && headers.contains_key(header::TRANSFER_ENCODING)
    {
        warn!(
            "Refusing {} {}: both Content-Length and Transfer-Encoding",
            req.method(),
            req.path()
        );
        return Ok(req.into_response(HttpResponse::BadRequest().finish().map_into_right_body()));
    }
    next.call(req).await.map(|res| res.map_into_left_body())
}

/// Refuse a session whose account has moved on since it was issued.
///
/// The session lives entirely in the cookie, so `/logout` only asks the
/// browser to forget it: a copy taken beforehand kept working, and a revoked
/// role or a changed password left every session opened under the old state
/// running. The generation stamped into the session at login is compared here
/// against the one on the record, and a mismatch ends the session.
///
/// Unauthenticated requests cost nothing — no identity, no lookup. An
/// authenticated one costs the same `get_user` every handler already does,
/// which the Mongo store answers from an indexed query behind a short-lived
/// cache.
///
/// A revoked session is **purged and the request continues as anonymous**,
/// rather than being answered 401 here. The outcome a caller sees is the same
/// wherever it matters — every protected route already refuses an
/// unauthenticated caller with 401 — but it leaves the recovery paths open. A
/// blanket 401 from this layer would also hit `/login`, so a browser holding a
/// cookie that had just been revoked could not log in again to replace it.
///
/// A session naming an account that no longer resolves is left alone: that is
/// the handlers' existing behaviour (`is_logged_in` answers with an empty
/// user, protected routes refuse on their own), and second-guessing it here
/// would change what an unauthenticated probe returns.
pub async fn enforce_session_generation(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let principal = req.get_identity().ok().and_then(|i| i.id().ok());

    if let (Some(principal), Some(state)) = (
        principal,
        req.app_data::<actix_web::web::Data<State>>().cloned(),
    ) {
        let srv: &crate::state::data::Data = &state.server;
        if let Some(usr) = get_user(srv, principal.clone()).await {
            // A session issued before this check existed carries no stamp and
            // reads as generation 0 — the same value a record that has never
            // been revoked holds, so the upgrade logs nobody out.
            let presented = req
                .get_session()
                .get::<u64>(SESSION_GEN_KEY)
                .ok()
                .flatten()
                .unwrap_or(0);
            let current = session_generation(&usr);
            if presented != current {
                info!(
                    "Dropping revoked session for {} (presented {}, current {})",
                    principal, presented, current
                );
                // `clear`, not `purge`: both empty the session so the
                // `Identity` extractor in the handler finds nothing and the
                // request is served as if no cookie had been sent, but `purge`
                // is terminal for the request — anything the handler writes to
                // the session afterwards is discarded. That would break the
                // one request this design exists to keep working, `/login`:
                // the caller would be told it logged in and get no usable
                // session back.
                req.get_session().clear();
            }
        }
    }

    next.call(req).await.map(|res| res.map_into_left_body())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{middleware::from_fn, test, web, App, HttpResponse as Resp};

    /// Both framings at once is the ambiguity; either one alone is an
    /// ordinary request and must still be served.
    #[actix_web::test]
    async fn one_framing_is_fine_and_two_are_not() {
        let app = test::init_service(
            App::new()
                .wrap(from_fn(reject_ambiguous_framing))
                .route("/probe", web::post().to(|| async { Resp::Ok().finish() })),
        )
        .await;

        let plain = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/probe")
                .set_payload("hello")
                .to_request(),
        )
        .await;
        assert!(plain.status().is_success(), "a normal body was refused");

        let chunked = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/probe")
                .insert_header((header::TRANSFER_ENCODING, "chunked"))
                .to_request(),
        )
        .await;
        assert!(chunked.status().is_success(), "chunked alone was refused");

        let both = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/probe")
                .insert_header((header::CONTENT_LENGTH, "5"))
                .insert_header((header::TRANSFER_ENCODING, "chunked"))
                .set_payload("hello")
                .to_request(),
        )
        .await;
        assert_eq!(
            both.status(),
            actix_web::http::StatusCode::BAD_REQUEST,
            "a request smuggling two framings was accepted"
        );
    }

    /// A request with no session at all must not pay for a user lookup, and
    /// must not be turned away — this is every unauthenticated route.
    #[actix_web::test]
    async fn requests_without_a_session_pass_through() {
        let app = test::init_service(
            App::new()
                .wrap(from_fn(enforce_session_generation))
                .wrap(actix_identity::IdentityMiddleware::default())
                .wrap(
                    actix_session::SessionMiddleware::builder(
                        actix_session::storage::CookieSessionStore::default(),
                        actix_web::cookie::Key::from(&[0u8; 64]),
                    )
                    .cookie_secure(false)
                    .build(),
                )
                .route("/probe", web::get().to(|| async { Resp::Ok().finish() })),
        )
        .await;

        let res =
            test::call_service(&app, test::TestRequest::get().uri("/probe").to_request()).await;
        assert!(res.status().is_success());
    }
}

/// The revocation itself, end to end: log in, keep a copy of the cookie, log
/// out, and try the copy again. Before the generation check the copy kept
/// working — there was no server-side record to invalidate — and a
/// `BrowserSession` cookie never expires on a clock, so "until it expires on
/// its own" meant "forever".
#[cfg(test)]
mod revocation_tests {
    use super::*;
    use crate::server::login::{login, logout};
    use crate::state::data::Data;
    use crate::state::store_memory::StoreMemory;
    use crate::util::crypto::{get_new_salt, get_password_hash};
    use actix_web::cookie::Cookie;
    use actix_web::{middleware::from_fn, test, web, App, HttpResponse as Resp};
    use isabelle_dm::data_model::item::Item;

    const BOUNDARY: &str = "----isabelletestboundary";

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

    fn account_with_password(pw: &str) -> Item {
        let mut itm = Item::new();
        itm.id = 1;
        itm.set_str("login", "alice");
        itm.set_str("email", "alice@example.org");
        itm.set_str("password", &get_password_hash(pw, &get_new_salt()));
        itm.set_bool("role_is_active", true);
        itm
    }

    macro_rules! app_with {
        ($state:expr) => {
            test::init_service(
                App::new()
                    .app_data($state)
                    .wrap(from_fn(enforce_session_generation))
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
                    .route("/logout", web::post().to(logout))
                    // Stands in for every protected route: the `Identity`
                    // extractor is what refuses an anonymous caller with 401,
                    // and a purged session is exactly an anonymous caller.
                    .route(
                        "/probe",
                        web::get().to(|_: actix_identity::Identity| async { Resp::Ok().finish() }),
                    ),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn a_cookie_copied_before_logout_stops_working() {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", account_with_password("hunter2"));
        let mut data = Data::new();
        data.rw = Box::new(store.clone());
        let state = web::Data::new(State::from_data(data));
        let app = app_with!(state);

        // Log in and keep the cookie, exactly as a thief would.
        let res = test::call_service(
            &app,
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
        assert!(res.status().is_success());
        let raw = res
            .response()
            .cookies()
            .find(|c| c.name() == "id")
            .expect("no session cookie was issued");
        let stolen = Cookie::new(raw.name().to_string(), raw.value().to_string());

        // It works while the session is current.
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/probe")
                .cookie(stolen.clone())
                .to_request(),
        )
        .await;
        assert!(res.status().is_success(), "a valid session was refused");

        // The legitimate user logs out.
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/logout")
                .cookie(stolen.clone())
                .to_request(),
        )
        .await;
        assert!(res.status().is_success());

        // The copy taken beforehand must now be worthless.
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/probe")
                .cookie(stolen)
                .to_request(),
        )
        .await;
        assert_eq!(
            res.status(),
            actix_web::http::StatusCode::UNAUTHORIZED,
            "a session copied before logout still works"
        );
    }

    /// The recovery path the purge-and-continue design exists to protect: a
    /// browser holding a just-revoked cookie has to be able to log in again.
    /// A blanket 401 from the guard would refuse `/login` too, leaving the
    /// user with no way back in short of clearing cookies by hand.
    #[actix_web::test]
    async fn a_revoked_session_can_still_log_in_again() {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", account_with_password("hunter2"));
        let mut data = Data::new();
        data.rw = Box::new(store.clone());
        let state = web::Data::new(State::from_data(data));
        let app = app_with!(state);

        let credentials = || {
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
        };

        let res = test::call_service(&app, credentials().to_request()).await;
        let raw = res.response().cookies().find(|c| c.name() == "id").unwrap();
        let stale = Cookie::new(raw.name().to_string(), raw.value().to_string());

        let mut bumped = store.peek("user", 1).unwrap();
        bumped.set_u64("session_gen", 9);
        store.seed("user", bumped);

        // Same browser, same stale cookie, correct password.
        let res = test::call_service(&app, credentials().cookie(stale).to_request()).await;
        assert!(
            res.status().is_success(),
            "a revoked session could not log in again"
        );

        // And the session it got back is usable.
        let raw = res
            .response()
            .cookies()
            .find(|c| c.name() == "id")
            .expect("logging in again issued no session");
        let fresh = Cookie::new(raw.name().to_string(), raw.value().to_string());
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/probe")
                .cookie(fresh)
                .to_request(),
        )
        .await;
        assert!(res.status().is_success(), "the new session was refused too");
    }

    /// Revocation is per account, not per cookie: raising the generation on
    /// the record — what a role change or a password change does — has to end
    /// sessions on every device at once, which is the case no cookie-side fix
    /// can reach.
    #[actix_web::test]
    async fn raising_the_generation_ends_sessions_on_every_device() {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", account_with_password("hunter2"));
        let mut data = Data::new();
        data.rw = Box::new(store.clone());
        let state = web::Data::new(State::from_data(data));
        let app = app_with!(state);

        let res = test::call_service(
            &app,
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
        let raw = res.response().cookies().find(|c| c.name() == "id").unwrap();
        let cookie = Cookie::new(raw.name().to_string(), raw.value().to_string());

        // An administrator revokes the account's roles out of band.
        let mut bumped = store.peek("user", 1).unwrap();
        bumped.set_u64("session_gen", 1);
        store.seed("user", bumped);

        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/probe")
                .cookie(cookie)
                .to_request(),
        )
        .await;
        assert_eq!(
            res.status(),
            actix_web::http::StatusCode::UNAUTHORIZED,
            "a session outlived the revocation of its account"
        );
    }
}
