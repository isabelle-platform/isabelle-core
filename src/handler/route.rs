/*
 * Isabelle project
 *
 * Copyright 2023-2025 Maxim Menshikov
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
use crate::handler::route_call::*;
use crate::handler::web_response::conv_response;
use crate::util::multipart::{with_deadline, Limits, ReadError};
use crate::State;
use actix_identity::Identity;
use actix_multipart::Multipart;
use actix_web::web;
use actix_web::HttpMessage;
use actix_web::{HttpRequest, HttpResponse};
use futures_util::StreamExt;
use isabelle_plugin_api::api::WebResponse;
use log::trace;
use std::collections::HashMap;

/// Call HTTP URL hooks. This function checks actual location from request
/// first.
pub async fn url_route(
    user: Identity,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let cache = srv.route_cache.lock().clone();

    trace!("Custom URL: {}", req.path());

    if let Some(handler) = cache.url_routes.get(req.path()) {
        trace!("Call custom route {}", handler);
        return call_url_route(srv, user, handler, req.query_string()).await;
    }

    HttpResponse::NotFound().into()
}

/// Call URL POST route that requires authenticated user.
/// This function also checks the actual location in the request.
pub async fn url_post_route(
    user: Identity,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
    payload: Multipart,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let cache = srv.route_cache.lock().clone();

    trace!("Custom post URL: {}", req.path());

    if let Some(handler) = cache.url_routes.get(req.path()) {
        trace!("Call custom route {}", handler);
        return call_url_post_route(srv, user, handler, req.query_string(), payload).await;
    }

    HttpResponse::NotFound().into()
}

/// Call URL route that doesn't require authenticated user.
/// This function also checks the actual location in the request.
pub async fn url_unprotected_route(
    user: Option<Identity>,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let cache = srv.route_cache.lock().clone();

    trace!("Custom unprotected URL: {}", req.path());

    if let Some(handler) = cache.unprotected_url_routes.get(req.path()) {
        trace!("Call custom route {}", handler);
        return call_url_unprotected_route(srv, user, handler, req.query_string()).await;
    }

    HttpResponse::NotFound().into()
}

/// Call URL POST route that doesn't require authenticated user.
/// This function also checks the actual location in the request.
pub async fn url_unprotected_post_route(
    user: Option<Identity>,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
    payload: Multipart,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let cache = srv.route_cache.lock().clone();

    trace!("Custom unprotected post URL: {}", req.path());

    if let Some(handler) = cache.unprotected_url_routes.get(req.path()) {
        trace!("Call custom route {}", handler);
        return call_url_unprotected_post_route(srv, user, handler, req.query_string(), payload)
            .await;
    }

    HttpResponse::NotFound().into()
}

/// Request headers as a plugin hook sees them: names lowercased, and the ones
/// that carry credentials left behind.
///
/// A hook needs headers for one reason — a caller that signs its request, of
/// which a payment provider's webhook is the usual example — and that never
/// involves the session cookie or an `Authorization` header. Those are dropped
/// here rather than trusted not to be read: the hook is already told who the
/// user is through `user`, and a raw credential is the one thing it could do
/// more with than that.
///
/// A repeated header name collapses to the last value. No signing scheme sends
/// its signature twice, and a hook that needs every value of a repeated header
/// wants a different shape than this one.
fn plugin_headers(req: &HttpRequest) -> HashMap<String, String> {
    const WITHHELD: [&str; 3] = ["cookie", "authorization", "proxy-authorization"];
    req.headers()
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            if WITHHELD.contains(&name.as_str()) {
                return None;
            }
            // A header that is not valid UTF-8 cannot be handed over as a
            // String. Dropping it beats refusing the whole request: it is
            // never the signature, which is hex or base64 by construction.
            value.to_str().ok().map(|v| (name, v.to_string()))
        })
        .collect()
}

/// Call URL REST hook with the payload
pub async fn url_generic_rest_route(
    user: Option<Identity>,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
    payload: &mut web::Payload,
    method: &str,
) -> HttpResponse {
    let limits = {
        let srv: &crate::state::data::Data = &data.server;
        Limits::from_data(srv)
    };
    // A body with no deadline is a parked request: the headers are complete,
    // so actix's header timeout has already passed, and nothing else was
    // watching. `chunk` is matched rather than unwrapped for the same reason
    // the query parses are — a panicking handler drops the connection with no
    // status, which a client cannot tell apart from a network failure.
    let read = with_deadline(limits, async {
        let mut body = web::BytesMut::new();
        while let Some(chunk) = payload.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => return Err(ReadError::Malformed(e.to_string())),
            };
            // limit max size of in-memory payload
            if (body.len() + chunk.len()) > limits.max_bytes {
                return Err(ReadError::TooLarge(body.len() + chunk.len()));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    })
    .await;
    let body = match read {
        Ok(b) => b,
        Err(e) => {
            trace!("Could not read the REST body: {}", e);
            return HttpResponse::build(e.status()).into();
        }
    };

    let body = std::str::from_utf8(&body);
    if !body.is_ok() {
        return HttpResponse::BadRequest().into();
    }

    let body = body.unwrap();

    let srv: &crate::state::data::Data = &data.server;
    let cache = srv.route_cache.lock().clone();

    if let Some(handler) = cache.rest_routes.get(req.path()) {
        trace!("Call custom route {}", handler);
        let resp = call_url_rest_route(
            srv,
            user,
            handler,
            method,
            req.query_string(),
            body,
            plugin_headers(&req),
        )
        .await;
        match &resp {
            WebResponse::Login(email) => {
                // A plugin route asked for a session. If one cannot be
                // attached, say so rather than panicking — the caller would
                // otherwise see the connection drop with no status and no way
                // to tell it apart from a network fault.
                if let Err(e) = Identity::login(&req.extensions(), email.to_string()) {
                    trace!("Could not establish a session from a plugin route: {}", e);
                    return HttpResponse::InternalServerError().into();
                }
            }
            WebResponse::Logout => { /* FIXME */ }
            _ => {}
        }
        return conv_response(resp).await;
    }

    HttpResponse::NotFound().into()
}

/// Call URL rest hooks. This function checks actual location from request
/// first.
pub async fn url_rest_route(
    user: Option<Identity>,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse {
    return url_generic_rest_route(user, data, req, &mut payload, "GET").await;
}

/// Call URL rest hooks. This function checks actual location from request
/// first.
pub async fn url_post_rest_route(
    user: Option<Identity>,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse {
    return url_generic_rest_route(user, data, req, &mut payload, "POST").await;
}

#[cfg(test)]
mod header_tests {
    use super::*;
    use actix_web::test::TestRequest;

    fn headers_of(req: TestRequest) -> HashMap<String, String> {
        plugin_headers(&req.to_http_request())
    }

    /// What the whole change exists for: a signature travels in a header, and
    /// it has to arrive spelled the way the hook will look it up.
    #[test]
    fn a_signature_survives_with_its_name_folded() {
        let h = headers_of(TestRequest::post().insert_header(("Stripe-Signature", "t=1,v1=ab")));
        assert_eq!(
            h.get("stripe-signature").map(String::as_str),
            Some("t=1,v1=ab")
        );
    }

    /// A plugin is told who the caller is through `user`. Handing it the raw
    /// session cookie as well would let it be somebody else.
    #[test]
    fn credentials_are_withheld() {
        let h = headers_of(
            TestRequest::post()
                .insert_header(("Cookie", "id=secret"))
                .insert_header(("Authorization", "Bearer secret"))
                .insert_header(("Proxy-Authorization", "Basic secret"))
                .insert_header(("Content-Type", "application/json")),
        );
        assert!(!h.contains_key("cookie"), "{h:?}");
        assert!(!h.contains_key("authorization"), "{h:?}");
        assert!(!h.contains_key("proxy-authorization"), "{h:?}");
        // …and the ordinary ones still come through, or the filter is a wall.
        assert_eq!(
            h.get("content-type").map(String::as_str),
            Some("application/json")
        );
    }
}

/// The webhook path, end to end: a signed JSON body posted to a REST route has
/// to reach the plugin hook byte-for-byte, with its signature header intact.
///
/// This is what the multipart routes cannot do — they re-parse the body into an
/// `Item` and never look at a header — and it is the whole reason `RouteRest`
/// grew a `headers` field.
#[cfg(test)]
mod rest_delivery_tests {
    use super::*;
    use crate::state::data::Data;
    use crate::state::route_cache::RouteCache;
    use actix_web::test::TestRequest;
    use actix_web::{test, web, App};
    use isabelle_dm::data_model::item::Item;
    use isabelle_plugin_api::actor::{PluginHookMessage, PluginRegistry};
    use std::sync::Arc;

    const PATH: &str = "/proteos/webhooks/stripe";
    const HANDLER: &str = "proteos_stripe_webhook";
    // Deliberately awkward: whitespace and a non-ASCII character, because HMAC
    // is over the exact bytes and any re-encoding on the way in breaks it.
    const BODY: &str = "{\n  \"id\": \"evt_1\",\n  \"note\": \"счёт\"\n}";
    const SIG: &str = "t=1700000000,v1=deadbeef";

    #[actix_web::test]
    async fn a_signed_body_reaches_the_hook_intact() {
        let mut internals = Item::new();
        internals.set_strstr(
            "extra_rest_route",
            &[("1".to_string(), format!("{PATH}:post:{HANDLER}"))]
                .into_iter()
                .collect(),
        );

        let data = Data::new();
        *data.route_cache.lock() = Arc::new(RouteCache::from_internals(&internals));

        // A plugin that does nothing but record what it was handed.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<PluginHookMessage>(4);
        let mut registry = PluginRegistry::new();
        registry.add("recorder", tx);
        data.set_plugin_registry(registry).ok().unwrap();

        let seen = Arc::new(std::sync::Mutex::new(None));
        {
            let seen = seen.clone();
            actix_rt::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    if let PluginHookMessage::RouteRest {
                        hndl,
                        payload,
                        headers,
                        reply,
                        ..
                    } = msg
                    {
                        *seen.lock().unwrap() = Some((hndl, payload, headers));
                        let _ = reply.send(isabelle_plugin_api::api::WebResponse::Ok);
                    }
                }
            });
        }

        let state = web::Data::new(crate::State::from_data(data));
        // The identity machinery has to be mounted even though the caller is
        // anonymous: `Option<Identity>` panics without it.
        let app = test::init_service(
            App::new()
                .app_data(state)
                .wrap(actix_identity::IdentityMiddleware::default())
                .wrap(
                    actix_session::SessionMiddleware::builder(
                        actix_session::storage::CookieSessionStore::default(),
                        actix_web::cookie::Key::from(&[0u8; 64]),
                    )
                    .cookie_secure(false)
                    .build(),
                )
                .route(PATH, web::post().to(url_post_rest_route)),
        )
        .await;

        let res = test::call_service(
            &app,
            TestRequest::post()
                .uri(PATH)
                .insert_header(("Content-Type", "application/json"))
                .insert_header(("Stripe-Signature", SIG))
                // The credential a plugin has no business seeing.
                .insert_header(("Cookie", "id=session-secret"))
                .set_payload(BODY)
                .to_request(),
        )
        .await;
        assert!(res.status().is_success(), "status {}", res.status());

        let seen = seen.lock().unwrap().clone();
        let (hndl, payload, headers) = seen.expect("the hook was never called");
        assert_eq!(hndl, HANDLER);
        // Byte-for-byte: this is what the HMAC is computed over.
        assert_eq!(payload, BODY);
        assert_eq!(
            headers.get("stripe-signature").map(String::as_str),
            Some(SIG)
        );
        assert!(!headers.contains_key("cookie"), "{headers:?}");
    }
}
