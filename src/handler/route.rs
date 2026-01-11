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
use crate::state::store::Store;
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
    let srv_lock = data.server.lock();
    let mut srv = unsafe { &mut (*srv_lock.as_ptr()) };
    let routes = srv
        .rw
        .get_internals()
        .await
        .safe_strstr("extra_route", &HashMap::new());

    trace!("Custom URL: {}", req.path());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            trace!("Call custom route {}", parts[2]);
            return call_url_route(&mut srv, user, parts[2], req.query_string()).await;
        }
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
    let srv_lock = data.server.lock();
    let mut srv = unsafe { &mut (*srv_lock.as_ptr()) };

    let routes = srv
        .rw
        .get_internals()
        .await
        .safe_strstr("extra_route", &HashMap::new());

    trace!("Custom post URL: {}", req.path());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            trace!("Call custom route {}", parts[2]);
            return call_url_post_route(&mut srv, user, parts[2], req.query_string(), payload)
                .await;
        }
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
    let srv_lock = data.server.lock();
    let mut srv = unsafe { &mut (*srv_lock.as_ptr()) };
    let routes = srv
        .rw
        .get_internals()
        .await
        .safe_strstr("extra_unprotected_route", &HashMap::new());

    trace!("Custom unprotected URL: {}", req.path());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            trace!("Call custom route {}", parts[2]);
            return call_url_unprotected_route(&mut srv, user, parts[2], req.query_string()).await;
        }
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
    let srv_lock = data.server.lock();
    let mut srv = unsafe { &mut (*srv_lock.as_ptr()) };

    let routes = srv
        .rw
        .get_internals()
        .await
        .safe_strstr("extra_unprotected_route", &HashMap::new());

    trace!("Custom unprotected post URL: {}", req.path());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            trace!("Call custom route {}", parts[2]);
            return call_url_unprotected_post_route(
                &mut srv,
                user,
                parts[2],
                req.query_string(),
                payload,
            )
            .await;
        }
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
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.unwrap();
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > 20 * 1024 * 1024 {
            return HttpResponse::BadRequest().into();
        }
        body.extend_from_slice(&chunk);
    }

    let body = std::str::from_utf8(&body);
    if !body.is_ok() {
        return HttpResponse::BadRequest().into();
    }

    let body = body.unwrap();

    let srv_lock = data.server.lock();
    let mut srv = unsafe { &mut (*srv_lock.as_ptr()) };
    let routes = srv
        .rw
        .get_internals()
        .await
        .safe_strstr("extra_rest_route", &HashMap::new());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            trace!("Call custom route {}", parts[2]);
            let resp =
                call_url_rest_route(&mut srv, user, parts[2], method, req.query_string(), body)
                    .await;
            match &resp {
                WebResponse::Login(email) => {
                    Identity::login(&req.extensions(), email.to_string()).unwrap();
                }
                WebResponse::Logout => { /* FIXME */ }
                _ => {}
            }
            return conv_response(resp).await;
        }
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
