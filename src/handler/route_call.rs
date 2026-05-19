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

//! Hook dispatchers used by HTTP handlers. Every hook goes through the
//! actor pipeline (`plugin_registry`) — trait-mode (`plugin_pool`) was
//! removed when all in-tree plugins migrated to actor-mode. The signatures
//! here are kept stable so server-side call sites (itm, login, route) did
//! not need to change.

use crate::handler::route_call_actor::*;
use crate::handler::web_response::*;
use crate::server::user_control::*;
use actix_identity::Identity;
use actix_multipart::Multipart;
use actix_web::HttpResponse;
use futures_util::TryStreamExt;
use isabelle_dm::data_model::data_object_action::DataObjectAction;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use isabelle_plugin_api::api::WebResponse;
use log::{error, info};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

pub async fn call_item_pre_edit_hook(
    srv: &crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    old_itm: Option<Item>,
    itm: &mut Item,
    action: DataObjectAction,
    merge: bool,
) -> ProcessResult {
    call_item_pre_edit_hook_actor(srv, hndl, user, collection, old_itm, itm, action, merge).await
}

pub async fn call_item_post_edit_hook(
    srv: &crate::state::data::Data,
    hndl: &str,
    collection: &str,
    old_itm: Option<Item>,
    id: u64,
    action: DataObjectAction,
) {
    call_item_post_edit_hook_actor(srv, hndl, collection, old_itm, id, action).await;
}

pub async fn call_item_auth_hook(
    srv: &crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    id: u64,
    new_item: Option<Item>,
    del: bool,
) -> bool {
    call_item_auth_hook_actor(srv, hndl, user, collection, id, new_item, del).await
}

pub async fn call_item_list_filter_hook(
    srv: &crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    context: &str,
    map: &mut HashMap<u64, Item>,
) {
    call_item_list_filter_hook_actor(srv, hndl, user, collection, context, map).await;
}

pub async fn call_item_list_db_filter_hook(
    srv: &crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    context: &str,
    filter_type: &str,
) -> Vec<String> {
    call_item_list_db_filter_hook_actor(srv, hndl, user, collection, context, filter_type).await
}

pub async fn call_url_route(
    srv: &crate::state::data::Data,
    user: Identity,
    hndl: &str,
    query: &str,
) -> HttpResponse {
    let usr: Option<Item> = get_user(srv, user.id().unwrap()).await;
    let wr = call_url_route_actor(srv, hndl, &usr, query).await;
    if matches!(wr, WebResponse::NotImplemented) {
        return HttpResponse::NotFound().into();
    }
    conv_response(wr).await
}

pub async fn handle_item_files(mut payload: Multipart) -> (Item, HashMap<String, String>) {
    let mut post_itm = Item::new();
    let mut files: HashMap<String, String> = HashMap::new();
    let mut files_count = 0;
    let path = Path::new("./tmp");

    if let Err(e) = fs::create_dir_all(&path) {
        error!("Failed to create directory: {}", e);
    }

    while let Ok(Some(mut field)) = payload.try_next().await {
        if field.name() == "item" {
            let mut field_data: Vec<u8> = Vec::new();
            while let Ok(Some(chunk)) = field.try_next().await {
                field_data.extend_from_slice(&chunk);
            }
            let strv = std::str::from_utf8(&field_data).unwrap_or("{}");
            let new_itm: Item = serde_json::from_str(strv).unwrap_or_else(|e| {
                log::error!("Failed to parse item JSON: {:?}", e);
                Item::new()
            });
            post_itm.id = new_itm.id;
            post_itm.merge(&new_itm);
        } else {
            let cd = field.content_disposition();
            let filename = cd
                .get_filename()
                .map_or_else(|| Uuid::new_v4().to_string(), sanitize_filename::sanitize);
            let filepath = format!("./tmp/{filename}");
            let f = std::fs::File::create(filepath.clone());

            info!("Created file {}", filepath);
            files.insert(files_count.to_string(), filepath);
            files_count = files_count + 1;

            if let Ok(mut file) = f {
                while let Ok(Some(chunk)) = field.try_next().await {
                    let _ = file.write_all(&chunk);
                }
            } else {
                error!("Failed to open file");
            }
        }
    }

    if files_count > 0 {
        post_itm.set_strstr("multipart-files", &files);
    }

    return (post_itm, files);
}

pub async fn handle_file_cleanup(files: &HashMap<String, String>) {
    for file in files {
        info!("Removed file {}", file.1);
        let _ = std::fs::remove_file(file.1);
    }
}

pub async fn call_url_post_route(
    srv: &crate::state::data::Data,
    user: Identity,
    hndl: &str,
    query: &str,
    payload: Multipart,
) -> HttpResponse {
    let usr = get_user(srv, user.id().unwrap()).await;
    let (post_itm, files) = handle_item_files(payload).await;

    let wr = call_url_post_route_actor(srv, hndl, &usr, query, &post_itm).await;
    let response = if matches!(wr, WebResponse::NotImplemented) {
        WebResponse::Ok
    } else {
        wr
    };

    handle_file_cleanup(&files).await;
    conv_response(response).await
}

pub async fn call_url_unprotected_route(
    srv: &crate::state::data::Data,
    user: Option<Identity>,
    hndl: &str,
    query: &str,
) -> HttpResponse {
    let mut usr: Option<Item> = None;
    if let Some(u) = user {
        usr = get_user(srv, u.id().unwrap()).await;
    }

    let wr = call_url_unprotected_route_actor(srv, hndl, &usr, query).await;
    if matches!(wr, WebResponse::NotImplemented) {
        return HttpResponse::NotFound().into();
    }
    conv_response(wr).await
}

pub async fn call_url_unprotected_post_route(
    srv: &crate::state::data::Data,
    user: Option<Identity>,
    hndl: &str,
    query: &str,
    payload: Multipart,
) -> HttpResponse {
    let mut usr: Option<Item> = None;
    if let Some(u) = user {
        usr = get_user(srv, u.id().unwrap()).await;
    }

    let (post_itm, files) = handle_item_files(payload).await;

    let wr = call_url_unprotected_post_route_actor(srv, hndl, &usr, query, &post_itm).await;
    let response = if matches!(wr, WebResponse::NotImplemented) {
        WebResponse::Ok
    } else {
        wr
    };

    handle_file_cleanup(&files).await;
    conv_response(response).await
}

pub async fn call_url_rest_route(
    srv: &crate::state::data::Data,
    user: Option<Identity>,
    hndl: &str,
    method: &str,
    query: &str,
    payload: &str,
) -> WebResponse {
    let mut usr: Option<Item> = None;
    if let Some(u) = user {
        usr = get_user(srv, u.id().unwrap()).await;
    }

    let wr = call_url_rest_route_actor(srv, hndl, method, &usr, query, payload).await;
    if matches!(wr, WebResponse::NotImplemented) {
        WebResponse::Ok
    } else {
        wr
    }
}

pub async fn call_collection_read_hook(
    data: &crate::state::data::Data,
    hndl: &str,
    collection: &str,
    itm: &mut Item,
) -> bool {
    call_collection_read_hook_actor(data, hndl, collection, itm).await
}

pub async fn call_otp_hook(srv: &crate::state::data::Data, hndl: &str, itm: Item) {
    call_otp_hook_actor(srv, hndl, itm).await;
}

/// Periodic tick from the `thread::spawn` loop in main.rs. No tokio runtime
/// context — we use `mpsc::Sender::try_send`, which is a sync method. If a
/// plugin's mailbox is full we drop the tick (idempotent — next tick catches up).
pub fn call_periodic_job_hook(srv: &crate::state::data::Data, timing: &str) {
    for sender in srv.plugin_registry.senders() {
        let msg = isabelle_plugin_api::actor::PluginHookMessage::PeriodicJob {
            timing: timing.to_string(),
        };
        if let Err(e) = sender.try_send(msg) {
            log::trace!(target: "core::periodic",
                "actor periodic tick dropped ({}): {}", timing, e);
        }
    }
}
