/*
 * Isabelle project
 *
 * Copyright 2023-2024 Maxim Menshikov
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
use crate::server::user_control::*;
use crate::state::store::Store;
use crate::State;
use actix_identity::Identity;
use actix_multipart::Multipart;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use futures_util::TryStreamExt;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use isabelle_plugin_api::api::WebResponse;
use log::info;
use std::collections::HashMap;

/// Convert internal Web response to proper HttpResponse
fn conv_response(resp: WebResponse) -> HttpResponse {
    match resp {
        WebResponse::Ok => {
            return HttpResponse::Ok().into();
        }
        WebResponse::OkData(text) => {
            return HttpResponse::Ok().body(text);
        }
        WebResponse::NotFound => {
            return HttpResponse::NotFound().into();
        }
        WebResponse::Unauthorized => {
            return HttpResponse::Unauthorized().into();
        }
        WebResponse::BadRequest => {
            return HttpResponse::BadRequest().into();
        }
        WebResponse::Forbidden => {
            return HttpResponse::Forbidden().into();
        }
        WebResponse::NotImplemented => todo!(),
    }
}

/// Call hook associated with pre-editing of item data.
pub async fn call_item_pre_edit_hook(
    srv: &mut crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    old_itm: Option<Item>,
    itm: &mut Item,
    del: bool,
    merge: bool,
) -> ProcessResult {
    for plugin in &mut srv.plugin_pool.plugins {
        let r = plugin.item_pre_edit_hook(
            &srv.plugin_api,
            hndl,
            user,
            collection,
            old_itm.clone(),
            itm,
            del,
            merge,
        );
        if !r.succeeded && r.error != "not implemented" {
            return r;
        }
    }

    match hndl {
        &_ => {
            return ProcessResult {
                succeeded: true,
                error: "".to_string(),
            };
        }
    }
}

/// Call hook associated with post-editing of item data.
pub async fn call_item_post_edit_hook(
    srv: &mut crate::state::data::Data,
    hndl: &str,
    collection: &str,
    id: u64,
    del: bool,
) {
    for plugin in &mut srv.plugin_pool.plugins {
        plugin.item_post_edit_hook(&srv.plugin_api, hndl, collection, id, del);
    }

    match hndl {
        &_ => {}
    }
}

/// Call item action authorization hook that can prohibit editing or removal
pub async fn call_itm_auth_hook(
    srv: &mut crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    id: u64,
    new_item: Option<Item>,
    del: bool,
) -> bool {
    for plugin in &mut srv.plugin_pool.plugins {
        plugin.item_auth_hook(
            &srv.plugin_api,
            hndl,
            user,
            collection,
            id,
            new_item.clone(),
            del,
        );
    }

    match hndl {
        &_ => return false,
    }
}

/// Call list filter hook, allowing for hiding specific list items
pub async fn call_itm_list_filter_hook(
    srv: &mut crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    context: &str,
    map: &mut HashMap<u64, Item>,
) {
    for plugin in &mut srv.plugin_pool.plugins {
        plugin.item_list_filter_hook(&srv.plugin_api, hndl, user, collection, context, map);
    }

    match hndl {
        &_ => {}
    }
}

/// Call HTTP url hook, allowing for responses to web requests.
pub async fn call_url_route(
    srv: &mut crate::state::data::Data,
    user: Identity,
    hndl: &str,
    query: &str,
) -> HttpResponse {
    let usr: Option<Item> = get_user(srv, user.id().unwrap()).await;

    for plugin in &mut srv.plugin_pool.plugins {
        let wr = plugin.route_url_hook(&srv.plugin_api, hndl, &usr, query);
        match wr {
            WebResponse::NotImplemented => {
                continue;
            }
            _ => {
                return conv_response(wr);
            }
        }
    }

    match hndl {
        &_ => {
            return HttpResponse::NotFound().into();
        }
    }
}

/// Call HTTP URL hooks. This function checks actual location from request
/// first.
pub async fn url_route(
    user: Identity,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
) -> HttpResponse {
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    let routes = srv
        .rw
        .get_internals()
        .await
        .safe_strstr("extra_route", &HashMap::new());

    info!("Custom URL: {}", req.path());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            info!("Call custom route {}", parts[2]);
            return call_url_route(&mut srv, user, parts[2], req.query_string()).await;
        }
    }

    HttpResponse::NotFound().into()
}

/// Call URL POST route that requires authenticated user.
pub async fn call_url_post_route(
    mut srv: &mut crate::state::data::Data,
    user: Identity,
    hndl: &str,
    query: &str,
    mut payload: Multipart,
) -> HttpResponse {
    let usr: Option<Item>;

    usr = get_user(&mut srv, user.id().unwrap()).await;

    let mut post_itm = Item::new();
    while let Ok(Some(mut field)) = payload.try_next().await {
        while let Ok(Some(chunk)) = field.try_next().await {
            let data = chunk;

            if field.name() == "item" {
                let v = &data.to_vec();
                let strv = std::str::from_utf8(v).unwrap_or("{}");
                let new_itm: Item = serde_json::from_str(strv).unwrap_or(Item::new());
                post_itm.merge(&new_itm);
            }
        }
    }

    for plugin in &mut srv.plugin_pool.plugins {
        let wr = plugin.route_url_post_hook(&srv.plugin_api, hndl, &usr, query, &post_itm);
        match wr {
            WebResponse::NotImplemented => {
                continue;
            }
            _ => {
                return conv_response(wr);
            }
        }
    }

    match hndl {
        &_ => {
            return HttpResponse::NotFound().into();
        }
    }
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
    let mut srv = srv_lock.borrow_mut();

    let routes = srv
        .rw
        .get_internals()
        .await
        .safe_strstr("extra_route", &HashMap::new());

    info!("Custom post URL: {}", req.path());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            info!("Call custom route {}", parts[2]);
            return call_url_post_route(&mut srv, user, parts[2], req.query_string(), payload)
                .await;
        }
    }

    HttpResponse::NotFound().into()
}

/// Call URL route that doesn't require authenticated user.
pub async fn call_url_unprotected_route(
    srv: &mut crate::state::data::Data,
    user: Option<Identity>,
    hndl: &str,
    query: &str,
) -> HttpResponse {
    let mut usr: Option<Item> = None;

    if !user.is_none() {
        usr = get_user(srv, user.unwrap().id().unwrap()).await;
    }

    for plugin in &mut srv.plugin_pool.plugins {
        let wr = plugin.route_unprotected_url_hook(&srv.plugin_api, hndl, &usr, query);
        match wr {
            WebResponse::NotImplemented => {
                continue;
            }
            _ => {
                return conv_response(wr);
            }
        }
    }

    match hndl {
        &_ => {
            return HttpResponse::NotFound().into();
        }
    }
}

/// Call URL POST route that doesn't require authenticated user.
pub async fn call_url_unprotected_post_route(
    mut srv: &mut crate::state::data::Data,
    user: Option<Identity>,
    hndl: &str,
    query: &str,
    mut payload: Multipart,
) -> HttpResponse {
    let mut usr: Option<Item> = None;

    if !user.is_none() {
        usr = get_user(&mut srv, user.unwrap().id().unwrap()).await;
    }

    let mut post_itm = Item::new();
    while let Ok(Some(mut field)) = payload.try_next().await {
        while let Ok(Some(chunk)) = field.try_next().await {
            let data = chunk;

            if field.name() == "item" {
                let v = &data.to_vec();
                let strv = std::str::from_utf8(v).unwrap_or("{}");
                let new_itm: Item = serde_json::from_str(strv).unwrap_or(Item::new());
                post_itm.merge(&new_itm);
            }
        }
    }

    for plugin in &mut srv.plugin_pool.plugins {
        let wr =
            plugin.route_unprotected_url_post_hook(&srv.plugin_api, hndl, &usr, query, &post_itm);
        match wr {
            WebResponse::NotImplemented => {
                continue;
            }
            _ => {
                return conv_response(wr);
            }
        }
    }

    match hndl {
        &_ => {
            return HttpResponse::NotFound().into();
        }
    }
}

/// Call URL route that doesn't require authenticated user.
/// This function also checks the actual location in the request.
pub async fn url_unprotected_route(
    user: Option<Identity>,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
) -> HttpResponse {
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    let routes = srv
        .rw
        .get_internals()
        .await
        .safe_strstr("extra_unprotected_route", &HashMap::new());

    info!("Custom unprotected URL: {}", req.path());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            info!("Call custom route {}", parts[2]);
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
    let mut srv = srv_lock.borrow_mut();

    let routes = srv
        .rw
        .get_internals()
        .await
        .safe_strstr("extra_unprotected_route", &HashMap::new());

    info!("Custom unprotected post URL: {}", req.path());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            info!("Call custom route {}", parts[2]);
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

/// Call collection read hook that can actually filter out particular item
pub async fn call_collection_read_hook(
    data: &mut crate::state::data::Data,
    hndl: &str,
    collection: &str,
    itm: &mut Item,
) -> bool {
    for plugin in &mut data.plugin_pool.plugins {
        info!("Call collection read hook {}", hndl);
        if plugin.collection_read_hook(&data.plugin_api, hndl, collection, itm) {
            return true;
        }
    }

    match hndl {
        _ => {
            return false;
        }
    }
}

/// Call One-Time Password hook
pub async fn call_otp_hook(srv: &mut crate::state::data::Data, hndl: &str, itm: Item) {
    for plugin in &mut srv.plugin_pool.plugins {
        plugin.call_otp_hook(&srv.plugin_api, hndl, &itm);
    }

    match hndl {
        _ => {}
    }
}

/// Call Periodic Job hook
pub async fn call_periodic_job_hook(srv: &mut crate::state::data::Data, timing: &str) {
    for plugin in &mut srv.plugin_pool.plugins {
        plugin.call_periodic_job_hook(&srv.plugin_api, timing);
    }
}
