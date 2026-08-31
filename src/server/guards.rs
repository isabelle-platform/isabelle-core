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

use crate::server::user_control::{lookup_user, session_generation};
use crate::state::state::State;
use crate::state::store::UserLookup;
use actix_identity::IdentityExt;
use actix_session::SessionExt;
use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::middleware::Next;
use actix_web::{Error, HttpMessage, HttpResponse};
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
/// A session naming an account that no longer exists is dropped too, but only
/// when it carries a stamp. A stamped session was issued by this build, so its
/// account resolving to nothing means the account is gone. An unstamped one
/// predates the check and is left alone, which is what keeps the upgrade from
/// logging out everybody whose account merely fails to resolve for some other
/// reason.
///
/// "Resolving to nothing" has to mean the store *answered* and had no such
/// record. A store that could not be asked establishes nothing, and the
/// request passes untouched: a lookup that fails during a database hiccup
/// would otherwise revoke every session in the deployment at once, and because
/// the session lives in the cookie, revoking it rewrites what the browser
/// holds — so the damage would outlast the hiccup by exactly as long as it
/// takes every user to log in again. The narrow cost of passing instead is
/// that during an outage a session already revoked out of band stays usable;
/// the handler behind it still cannot resolve a user, so it can do no more
/// than an anonymous caller.
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
        // `None` here means the session predates this check — it carries no
        // stamp, and reads as generation 0, which is what a record that has
        // never been revoked holds. So the upgrade logs nobody out.
        let presented = req.get_session().get::<u64>(SESSION_GEN_KEY).ok().flatten();
        let stale = match lookup_user(srv, principal.clone()).await {
            UserLookup::Found(usr) => {
                let current = session_generation(&usr);
                presented.unwrap_or(0) != current
            }
            // The account is gone. Its sessions should go with it.
            UserLookup::Absent => presented.is_some(),
            // Nothing was established, so nothing is revoked. See above.
            UserLookup::Unavailable => {
                warn!(
                    "Passing {} {} unchecked: the user store did not answer for {}",
                    req.method(),
                    req.path(),
                    principal
                );
                false
            }
        };

        if stale {
            info!(
                "Dropping revoked session for {} (presented {:?})",
                principal, presented
            );
            // `clear`, not `purge`: both empty the session so the `Identity`
            // extractor in the handler finds nothing and the request is served
            // as if no cookie had been sent, but `purge` is terminal for the
            // request — anything the handler writes to the session afterwards
            // is discarded. That would break the one request this design
            // exists to keep working, `/login`: the caller would be told it
            // logged in and get no usable session back.
            req.get_session().clear();
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
                    // The same order as the server builds: a token becomes an
                    // identity innermost, after everything outside has decided
                    // the request carries no session.
                    .wrap(from_fn(accept_api_token))
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

    /// A token is good for the request it was sent with, and for nothing
    /// after it.
    ///
    /// The session store here is the cookie itself, so writing the identity
    /// into the session to tell the handler who is calling would otherwise
    /// hand the caller a *session* — one that outlives the token, ignores its
    /// scopes, and cannot be taken back by revoking it. This asserts the
    /// answer carries no such thing.
    #[actix_web::test]
    async fn a_token_does_not_leave_a_session_behind() {
        let store = StoreMemory::with_collections(&["user", "api_token"]);
        store.seed("user", account_with_password("hunter2"));

        let secret = crate::server::api_token::generate_secret();
        let mut token = Item::new();
        token.id = 1;
        token.set_id("user", 1);
        token.set_str("hash", &crate::server::api_token::hash(&secret));
        token.set_str("scopes", r#"["read"]"#);
        store.seed("api_token", token);

        // The probe route has to be in a scope, or the token is refused for
        // the right reason and the test learns nothing about sessions. This
        // is the same declaration a flavour makes in `internals.js`.
        let mut internals = Item::new();
        let mut scopes = std::collections::HashMap::new();
        scopes.insert("1".to_string(), "/probe:read".to_string());
        internals.set_strstr("route_scope", &scopes);
        store.set_internals(internals);

        let mut data = Data::new();
        data.rw = Box::new(store.clone());
        data.rebuild_route_cache().await;
        let state = web::Data::new(State::from_data(data));
        let app = app_with!(state.clone());

        let whole = crate::server::api_token::assemble(1, &secret);
        let answered = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/probe")
                .insert_header((header::AUTHORIZATION, format!("Bearer {}", whole)))
                .to_request(),
        )
        .await;
        assert!(
            answered.status().is_success(),
            "the token was refused: {}",
            answered.status()
        );

        // Whatever the answer sets, it must not be a usable session. A
        // removal is fine — that is what purging looks like on the wire — and
        // so is nothing at all; a session cookie with a value is not.
        let handed_back: Vec<String> = answered
            .response()
            .headers()
            .get_all(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap_or_default().to_string())
            .filter(|c| c.starts_with("id=") || c.contains("isabelle-cookie="))
            .collect();
        for cookie in &handed_back {
            let value = cookie
                .split(';')
                .next()
                .and_then(|kv| kv.split_once('='))
                .map(|(_, v)| v)
                .unwrap_or("");
            assert!(
                value.is_empty(),
                "a token request was answered with a session cookie: {cookie}"
            );
        }

        // And the same request without the token is anonymous, which is what
        // replaying anything the answer carried would amount to.
        let replayed =
            test::call_service(&app, test::TestRequest::get().uri("/probe").to_request()).await;
        assert_eq!(
            replayed.status(),
            actix_web::http::StatusCode::UNAUTHORIZED,
            "a request with no credential at all was served"
        );
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

    /// Deleting an account has to take its sessions with it. The record is
    /// gone, so there is no generation left to compare against — the fact
    /// that the session carries a stamp at all is what says it was issued by
    /// a build that would have kept one.
    #[actix_web::test]
    async fn deleting_an_account_ends_its_session() {
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

        crate::state::store::Store::del_item(&store, "user", 1).await;

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
            "a deleted account kept a working session"
        );
    }

    /// A database that does not answer is not a database that says the
    /// account is gone. Conflating the two revokes every session in the
    /// deployment during any lookup failure — and because the session lives
    /// in the cookie, revoking it rewrites what the browser holds, so the
    /// outage outlasts itself: everyone has to log in again once the store
    /// recovers.
    #[actix_web::test]
    async fn a_store_that_cannot_answer_does_not_revoke_anything() {
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

        store.set_unreachable(true);
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/probe")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert!(
            res.status().is_success(),
            "a database hiccup logged a live session out"
        );
        // The guard must not have written a cleared session back to the
        // browser either — that is what would make the logout permanent.
        assert!(
            res.response().cookies().all(|c| c.name() != "id"),
            "the session cookie was rewritten during an outage"
        );

        // And the same cookie keeps working once the store recovers.
        store.set_unreachable(false);
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/probe")
                .cookie(cookie)
                .to_request(),
        )
        .await;
        assert!(
            res.status().is_success(),
            "the session did not survive the outage"
        );
    }

    /// The outage exemption must not become a way to keep a revoked session:
    /// the moment the store answers again, the generation check applies.
    #[actix_web::test]
    async fn recovery_re_applies_a_revocation_made_during_the_outage() {
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

        let mut bumped = store.peek("user", 1).unwrap();
        bumped.set_u64("session_gen", 4);
        store.seed("user", bumped);

        store.set_unreachable(true);
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/probe")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert!(
            res.status().is_success(),
            "the outage exemption did not hold"
        );

        store.set_unreachable(false);
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
            "a revocation was lost because it happened during an outage"
        );
    }

    /// Logging out is deliberately account-wide, not device-wide.
    ///
    /// With `CookieSessionStore` the whole session is the cookie, so there is
    /// nothing per-device to invalidate: the generation on the record is the
    /// only handle the server has, and it names the account. Ending one
    /// device's session therefore ends them all. That is the safe direction
    /// for the case this exists for — a copied cookie — but it is a visible
    /// product decision, so it is pinned here rather than left to be
    /// rediscovered. Per-device logout would need server-side session state,
    /// which this design does not have.
    #[actix_web::test]
    async fn logging_out_on_one_device_ends_the_session_on_the_others() {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", account_with_password("hunter2"));
        let mut data = Data::new();
        data.rw = Box::new(store.clone());
        let state = web::Data::new(State::from_data(data));
        let app = app_with!(state);

        let sign_in = || {
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

        let laptop = {
            let res = test::call_service(&app, sign_in().to_request()).await;
            let raw = res.response().cookies().find(|c| c.name() == "id").unwrap();
            Cookie::new(raw.name().to_string(), raw.value().to_string())
        };
        let phone = {
            let res = test::call_service(&app, sign_in().to_request()).await;
            let raw = res.response().cookies().find(|c| c.name() == "id").unwrap();
            Cookie::new(raw.name().to_string(), raw.value().to_string())
        };

        // The laptop logs out.
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/logout")
                .cookie(laptop)
                .to_request(),
        )
        .await;
        assert!(res.status().is_success());

        // The phone's session goes with it.
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/probe")
                .cookie(phone)
                .to_request(),
        )
        .await;
        assert_eq!(
            res.status(),
            actix_web::http::StatusCode::UNAUTHORIZED,
            "logout is documented as account-wide but left another device signed in"
        );
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

/// Accept an API token in place of a session cookie.
///
/// This runs before the `Identity` extractor gets its hands on the request,
/// which is the only place it can run: the extractor answers 401 for anything
/// without a session, inside a crate we do not own, before any handler is
/// reached. So a token is turned into an ordinary identity here, and
/// everything downstream — every handler, every plugin, every permission
/// check — sees exactly what a browser's cookie would have produced and needs
/// to know nothing about tokens.
///
/// Three things are decided here and nowhere else:
///
/// * **A request with no bearer token passes untouched.** Cookies keep
///   working, and a header meant for something else in front of us is not our
///   business.
/// * **A token that fails is 401 and the request stops.** It is deliberately
///   not "continue as anonymous": a caller who presented a credential wants to
///   know it was refused, and letting it fall through would answer some
///   requests successfully as nobody, which is a far more confusing thing to
///   debug than a 401.
/// * **A token outside its scopes is 403.** Different from 401 on purpose: the
///   credential is good, the request is not.
pub async fn accept_api_token(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::server::api_token::from_header);

    let Some(presented) = presented else {
        return next.call(req).await.map(|res| res.map_into_left_body());
    };

    // Whether the caller was already signed in before the token was looked
    // at. It decides what happens to the session afterwards: one this
    // middleware created has to go, and one the caller brought is theirs.
    let had_session = req.get_identity().is_ok();

    let Some(state) = req.app_data::<actix_web::web::Data<State>>().cloned() else {
        // Nothing to check against. Refusing is the only safe answer: passing
        // would serve a credentialed request as anonymous.
        return Ok(refuse(
            req,
            HttpResponse::Unauthorized(),
            "server state is unavailable",
        ));
    };
    let srv: &crate::state::data::Data = &state.server;

    let record = match crate::server::api_token::resolve(srv, &presented).await {
        Ok(r) => r,
        Err(e) => {
            // The reason goes to the log, never to the caller: telling one
            // apart from another turns a 401 into an oracle for guessing
            // identifiers.
            warn!(
                "Refusing token {} on {} {}: {}",
                presented.id,
                req.method(),
                req.path(),
                e.reason()
            );
            return Ok(refuse(req, HttpResponse::Unauthorized(), "invalid token"));
        }
    };

    let owner_id = record.safe_id(crate::server::api_token::FIELD_USER, u64::MAX);
    let owner = match srv.rw.get_item("user", owner_id).await {
        Some(u) if u.safe_bool("role_is_active", false) => u,
        _ => {
            warn!(
                "Refusing token {}: {}",
                presented.id,
                crate::server::api_token::Rejected::OwnerInactive.reason()
            );
            return Ok(refuse(req, HttpResponse::Unauthorized(), "invalid token"));
        }
    };

    // Which scope this request needs, out of whichever table answers for it.
    //
    // A plugin route is one thing, so its scope is named after the route. The
    // generic item routes are every collection at once, so theirs is named
    // after the collection in the query — otherwise `/itm/edit` would be a
    // single permission covering a test run and the project it belongs to.
    let declared = {
        let cache = srv.route_cache.lock().clone();
        match crate::server::api_token::item_route_verb(req.path()) {
            Some(verb) => {
                crate::server::api_token::collection_of(req.query_string()).and_then(|c| {
                    cache
                        .collection_scopes
                        .get(&format!("{}:{}", c, verb))
                        .cloned()
                })
            }
            None => cache.route_scopes.get(req.path()).cloned(),
        }
    };
    let granted = crate::server::api_token::scopes_of(&record);
    if let Err(why) =
        crate::server::api_token::scope_allows(req.path(), &granted, declared.as_deref())
    {
        warn!("Refusing token {}: {}", presented.id, why);
        return Ok(refuse(req, HttpResponse::Forbidden(), &why));
    }

    // From here the handler sees what a signed-in caller would. The identity
    // has to go through the session, because that is where the `Identity`
    // extractor every handler uses will look for it.
    let principal = owner.safe_str("email", "");
    // The borrow has to end before `req` can be moved into a refusal.
    let attached = {
        let extensions = req.extensions();
        actix_identity::Identity::login(&extensions, principal.clone()).err()
    };
    if let Some(e) = attached {
        warn!(
            "Could not attach an identity for token {}: {}",
            presented.id, e
        );
        return Ok(refuse(req, HttpResponse::Unauthorized(), "invalid token"));
    }
    // The session-generation check runs after this one and would otherwise
    // find a session with no stamp and read it as generation zero. Stamping it
    // keeps a token honest about revocation: bump the account's generation and
    // its tokens stop working with its cookies.
    let _ = req
        .get_session()
        .insert(SESSION_GEN_KEY, session_generation(&owner));

    crate::server::api_token::touch(srv, &record).await;

    let res = next.call(req).await?;

    // And it ends with the request.
    //
    // Writing the identity into the session is how the handler is told who is
    // calling; letting that session *survive* would hand the caller a cookie
    // worth more than the token that produced it. The session store is the
    // cookie itself, so without this the answer to a read-scoped request
    // carries a full session: replay it without the token and every scope is
    // gone, `NEVER` with it — the holder of a token that may only read runs
    // could mint itself another token. Revoking the token would not help,
    // because the cookie is no longer a token.
    //
    // Purging leaves the response asking the client to drop the cookie rather
    // than to keep it, which is the only shape that says "this credential was
    // good for one request".
    //
    // Only a session this middleware made, though. A caller who sent a cookie
    // *and* a token gets the token's limits applied to that request — they
    // presented a credential, so it counts — but their browser session is
    // theirs and is not something a stray `Authorization` header should end.
    if !had_session {
        res.request().get_session().purge();
    }

    Ok(res.map_into_left_body())
}

/// End the request here, with a body the caller can read.
fn refuse<B: MessageBody + 'static>(
    req: ServiceRequest,
    mut status: actix_web::HttpResponseBuilder,
    message: &str,
) -> ServiceResponse<EitherBody<B>> {
    let body = serde_json::json!({"succeeded": false, "error": message}).to_string();
    req.into_response(status.content_type("application/json").body(body))
        .map_into_right_body()
}
