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
        let resp = call_url_rest_route(srv, user, handler, method, req.query_string(), body).await;
        match &resp {
            WebResponse::Login(email) => {
                Identity::login(&req.extensions(), email.to_string()).unwrap();
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
