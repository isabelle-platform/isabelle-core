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

/// Call hook associated with pre-editing of item data.
pub async fn call_item_pre_edit_hook(
    srv: &mut crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    old_itm: Option<Item>,
    itm: &mut Item,
    action: DataObjectAction,
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
            action.clone(),
            merge,
        );
        if !r.succeeded && r.error != "not implemented" {
            return r;
        }
    }

    return ProcessResult {
        succeeded: true,
        error: "".to_string(),
        data: HashMap::new(),
    };
}

/// Call hook associated with post-editing of item data.
pub async fn call_item_post_edit_hook(
    srv: &mut crate::state::data::Data,
    hndl: &str,
    collection: &str,
    old_itm: Option<Item>,
    id: u64,
    action: DataObjectAction,
) {
    for plugin in &mut srv.plugin_pool.plugins {
        plugin.item_post_edit_hook(
            &srv.plugin_api,
            hndl,
            collection,
            old_itm.clone(),
            id,
            action.clone(),
        );
    }
}

/// Call item action authorization hook that can prohibit editing or removal
pub async fn call_item_auth_hook(
    srv: &mut crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    id: u64,
    new_item: Option<Item>,
    del: bool,
) -> bool {
    for plugin in &mut srv.plugin_pool.plugins {
        let res = plugin.item_auth_hook(
            &srv.plugin_api,
            hndl,
            user,
            collection,
            id,
            new_item.clone(),
            del,
        );
        if !res {
            return res;
        }
    }

    return true;
}

/// Call list filter hook, allowing for hiding specific list items
pub async fn call_item_list_filter_hook(
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
}

pub async fn call_item_list_db_filter_hook(
    srv: &mut crate::state::data::Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    context: &str,
    filter_type: &str,
) -> Vec<String> {
    let mut filters = Vec::new();
    for plugin in &mut srv.plugin_pool.plugins {
        let filter = plugin.item_list_db_filter_hook(
            &srv.plugin_api,
            hndl,
            user,
            collection,
            context,
            filter_type,
        );
        if filter != "" {
            filters.push(filter);
        }
    }
    return filters;
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
                return conv_response(wr).await;
            }
        }
    }

    return HttpResponse::NotFound().into();
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
            while let Ok(Some(chunk)) = field.try_next().await {
                let data = chunk;
                let v = &data.to_vec();
                let strv = std::str::from_utf8(v).unwrap_or("{}");
                let new_itm: Item = serde_json::from_str(strv).unwrap_or(Item::new());
                post_itm.id = new_itm.id;
                post_itm.merge(&new_itm);
            }
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

/// Call URL POST route that requires authenticated user.
pub async fn call_url_post_route(
    mut srv: &mut crate::state::data::Data,
    user: Identity,
    hndl: &str,
    query: &str,
    payload: Multipart,
) -> HttpResponse {
    let usr: Option<Item>;

    usr = get_user(&mut srv, user.id().unwrap()).await;

    let (post_itm, files) = handle_item_files(payload).await;

    let mut response: WebResponse = WebResponse::Ok;
    for plugin in &mut srv.plugin_pool.plugins {
        let wr = plugin.route_url_post_hook(&srv.plugin_api, hndl, &usr, query, &post_itm);
        match wr {
            WebResponse::NotImplemented => {
                continue;
            }
            _ => {
                response = wr;
            }
        }
    }

    handle_file_cleanup(&files).await;
    return conv_response(response).await;
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
                return conv_response(wr).await;
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
    payload: Multipart,
) -> HttpResponse {
    let mut usr: Option<Item> = None;

    if !user.is_none() {
        usr = get_user(&mut srv, user.unwrap().id().unwrap()).await;
    }

    let (post_itm, files) = handle_item_files(payload).await;
    let mut response: WebResponse = WebResponse::Ok;

    for plugin in &mut srv.plugin_pool.plugins {
        let wr =
            plugin.route_unprotected_url_post_hook(&srv.plugin_api, hndl, &usr, query, &post_itm);
        match wr {
            WebResponse::NotImplemented => {
                continue;
            }
            _ => {
                response = wr;
            }
        }
    }

    handle_file_cleanup(&files).await;

    return conv_response(response).await;
}

/// Call URL REST route.
pub async fn call_url_rest_route(
    mut srv: &mut crate::state::data::Data,
    user: Option<Identity>,
    hndl: &str,
    method: &str,
    query: &str,
    payload: &str,
) -> WebResponse {
    let mut usr: Option<Item> = None;

    if !user.is_none() {
        usr = get_user(&mut srv, user.unwrap().id().unwrap()).await;
    }

    let mut response: WebResponse = WebResponse::Ok;

    for plugin in &mut srv.plugin_pool.plugins {
        let wr = plugin.route_rest_hook(&srv.plugin_api, hndl, method, &usr, query, payload);
        match wr {
            WebResponse::NotImplemented => {
                continue;
            }
            _ => {
                response = wr;
            }
        }
    }

    return response;
}

/// Call collection read hook that can actually filter out particular item
pub async fn call_collection_read_hook(
    data: &mut crate::state::data::Data,
    hndl: &str,
    collection: &str,
    itm: &mut Item,
) -> bool {
    for plugin in &mut data.plugin_pool.plugins {
        if plugin.collection_read_hook(&data.plugin_api, hndl, collection, itm) {
            return true;
        }
    }

    return false;
}

/// Call One-Time Password hook
pub async fn call_otp_hook(srv: &mut crate::state::data::Data, hndl: &str, itm: Item) {
    for plugin in &mut srv.plugin_pool.plugins {
        plugin.call_otp_hook(&srv.plugin_api, hndl, &itm);
    }
}

/// Call Periodic Job hook
pub fn call_periodic_job_hook(srv: &mut crate::state::data::Data, timing: &str) {
    for plugin in &mut srv.plugin_pool.plugins {
        plugin.call_periodic_job_hook(&srv.plugin_api, timing);
    }
}
