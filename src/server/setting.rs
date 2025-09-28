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
use crate::notif::gcal::*;
use crate::server::user_control::*;
use crate::state::state::*;
use crate::state::store::Store;
use actix_identity::Identity;
use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use log::info;
use serde::{Deserialize, Serialize};
use serde_qs;
use serde_qs::Config;
use std::collections::HashMap;

pub async fn setting_edit(
    user: Identity,
    data: web::Data<State>,
    req: HttpRequest,
    mut payload: Multipart,
) -> HttpResponse {
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    let usr = get_user(&mut srv, user.id().unwrap()).await;

    // Settings can't be edited by non-admins.
    if !check_role(&mut srv, &usr, "admin").await {
        return HttpResponse::Forbidden().into();
    }

    // Merge settings from multipart data
    let mut itm = serde_qs::from_str::<Item>(&req.query_string()).unwrap();
    while let Ok(Some(mut field)) = payload.try_next().await {
        while let Ok(Some(chunk)) = field.try_next().await {
            let data = chunk;

            if field.name() == "item" {
                let v = &data.to_vec();
                let strv = std::str::from_utf8(v).unwrap_or("{}");
                let new_itm: Item = serde_json::from_str(strv).unwrap_or(Item::new());
                itm.merge(&new_itm);
            }
        }
    }

    info!("Settings edited");

    // Set settings
    srv.rw.set_settings(itm.clone()).await;

    return HttpResponse::Ok().body(
        serde_json::to_string(&ProcessResult {
            succeeded: true,
            error: "".to_string(),
            data: HashMap::new(),
        })
        .unwrap(),
    );
}

pub async fn setting_list(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
) -> HttpResponse {
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    let usr = get_user(&mut srv, user.id().unwrap()).await;

    // Non-admins can't list settings
    if !check_role(&mut srv, &usr, "admin").await {
        return HttpResponse::Forbidden().into();
    }

    // Return settings finally
    let st = srv.rw.get_settings().await.clone();

    HttpResponse::Ok()
        .body(serde_json::to_string(&st).unwrap())
        .into()
}

pub async fn setting_gcal_auth(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
) -> HttpResponse {
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    let usr = get_user(&mut srv, user.id().unwrap()).await;

    // Non-admins can't authenticate with Google Calendar
    if !check_role(&mut srv, &usr, "admin").await {
        return HttpResponse::Forbidden().into();
    }

    // Start authentication
    HttpResponse::Ok().body(auth_google(&mut srv).await).into()
}

pub async fn setting_gcal_auth_end(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
) -> HttpResponse {
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    let usr = get_user(&mut srv, user.id().unwrap()).await;

    // Non-admins can't finish Google Authentication
    if !check_role(&mut srv, &usr, "admin").await {
        return HttpResponse::Forbidden().into();
    }

    // Take authentication data from query
    info!("Auth end");
    #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
    pub struct AuthEndData {
        pub state: String,
        pub code: String,
        pub scope: String,
    }

    let config = Config::new(10, false);
    let data: AuthEndData = config.deserialize_str(&_req.query_string()).unwrap();

    // Finish authentication
    let public_url = srv.public_url.clone();
    HttpResponse::Ok()
        .body(
            auth_google_end(
                &mut srv,
                public_url + "/?" + _req.query_string(),
                data.state,
                data.code,
            )
            .await,
        )
        .into()
}
