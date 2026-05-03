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
use crate::server::user_control::*;
use crate::state::state::*;
use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct SecretIdReq {
    pub id: u64,
}

#[derive(Serialize)]
struct SecretRef {
    id: u64,
    name: String,
}

async fn ensure_admin(data: &web::Data<State>, user: &Identity) -> Result<(), HttpResponse> {
    let srv_lock = data.server.lock();
    let srv = unsafe { &mut (*srv_lock.as_ptr()) };
    let usr = get_user(srv, user.id().unwrap()).await;
    if !check_role(srv, &usr, "admin").await {
        return Err(HttpResponse::Forbidden().into());
    }
    Ok(())
}

fn proc_err(msg: impl Into<String>) -> HttpResponse {
    HttpResponse::Ok().body(
        serde_json::to_string(&ProcessResult {
            succeeded: false,
            error: msg.into(),
            data: HashMap::new(),
        })
        .unwrap(),
    )
}

fn proc_ok_with_id(id: u64) -> HttpResponse {
    let mut data_map: HashMap<String, String> = HashMap::new();
    data_map.insert("id".to_string(), id.to_string());
    HttpResponse::Ok().body(
        serde_json::to_string(&ProcessResult {
            succeeded: true,
            error: "".to_string(),
            data: data_map,
        })
        .unwrap(),
    )
}

fn proc_ok() -> HttpResponse {
    HttpResponse::Ok().body(
        serde_json::to_string(&ProcessResult {
            succeeded: true,
            error: "".to_string(),
            data: HashMap::new(),
        })
        .unwrap(),
    )
}

pub async fn secret_edit(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
    body: web::Json<Item>,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let srv_lock = data.server.lock();
    let srv = unsafe { &mut (*srv_lock.as_ptr()) };
    let store = match srv.secrets.as_mut() {
        Some(s) => s,
        None => return proc_err("secret store is not initialized"),
    };
    // Default to merge semantics: external clients cannot read raw values,
    // so a fresh PUT of a partial Item must not silently wipe fields the
    // caller didn't include. Together with the "<hidden>" placeholder rule
    // in SecretStore::set, this lets a client round-trip a masked Item.
    match store.set(&body, true) {
        Ok(id) => proc_ok_with_id(id),
        Err(e) => proc_err(format!("failed to write secret: {}", e)),
    }
}

pub async fn secret_get(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
    body: web::Json<SecretIdReq>,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let srv_lock = data.server.lock();
    let srv = unsafe { &mut (*srv_lock.as_ptr()) };
    let store = match srv.secrets.as_ref() {
        Some(s) => s,
        None => return proc_err("secret store is not initialized"),
    };
    match store.get_masked(body.id) {
        Some(item) => HttpResponse::Ok().body(serde_json::to_string(&item).unwrap()),
        None => HttpResponse::NotFound().into(),
    }
}

pub async fn secret_del(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
    body: web::Json<SecretIdReq>,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let srv_lock = data.server.lock();
    let srv = unsafe { &mut (*srv_lock.as_ptr()) };
    let store = match srv.secrets.as_mut() {
        Some(s) => s,
        None => return proc_err("secret store is not initialized"),
    };
    match store.del(body.id) {
        Ok(_) => proc_ok(),
        Err(e) => proc_err(format!("failed to delete secret: {}", e)),
    }
}

pub async fn secret_list(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let srv_lock = data.server.lock();
    let srv = unsafe { &mut (*srv_lock.as_ptr()) };
    let refs: Vec<SecretRef> = match srv.secrets.as_ref() {
        Some(s) => s
            .list()
            .into_iter()
            .map(|(id, name)| SecretRef { id, name })
            .collect(),
        None => return proc_err("secret store is not initialized"),
    };
    HttpResponse::Ok().body(serde_json::to_string(&refs).unwrap())
}
