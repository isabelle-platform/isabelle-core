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
//! The routes of the maintenance state: see `crate::state::maintenance`.
//!
//! - `GET /maintenance` — anybody, signed in or not: whether the
//!   installation is closed and when it reopens, which is what a page needs
//!   to say "back in a few minutes". An administrator is also told who
//!   asked, why, and what is running.
//! - `POST /maintenance/set?action=ask|close|reopen` — an administrator.
//!   `ask` closes at the next moment nothing is running, `close` closes now,
//!   `reopen` reopens and drops a request that is waiting. `minutes` and
//!   `wait_hours` override the installation's settings for this one request.

use crate::server::user_control::*;
use crate::state::maintenance;
use crate::state::state::*;
use crate::state::store::Store;
use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use isabelle_plugin_api::actor::MaintenanceInfo;
use serde::Deserialize;

/// The installation's own numbers, read again: an administrator who has
/// just changed them expects the next request to use them.
pub async fn refresh_defaults(srv: &crate::state::data::Data) {
    let s = srv.rw.get_settings().await;
    let num = |k: &str| s.safe_str(k, "").trim().parse::<u64>().ok();
    maintenance::set_defaults(
        num(maintenance::MINUTES_SETTING),
        num(maintenance::WAIT_HOURS_SETTING),
    );
}

/// What an administrator is told.
pub fn full(i: &MaintenanceInfo) -> serde_json::Value {
    serde_json::json!({
        "state": i.state,
        "asked_by": i.asked_by,
        "reason": i.reason,
        "wait_until": i.wait_until,
        "reopen_at": i.reopen_at,
        "note": i.note,
        "running": i.running.len(),
        "running_titles": i.running,
    })
}

/// What anybody is told. `waiting` reads as `open`: nothing has changed for
/// anybody yet, and that an update is coming is not everybody's to know.
fn public(i: &MaintenanceInfo) -> serde_json::Value {
    let closed = i.is_closed();
    serde_json::json!({
        "state": if closed { "closed" } else { "open" },
        "reopen_at": if closed { i.reopen_at.as_str() } else { "" },
    })
}

pub async fn maintenance_get(user: Option<Identity>, data: web::Data<State>) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let usr = match &user {
        Some(u) => get_user(srv, principal(u)).await,
        None => None,
    };
    let i = maintenance::info();
    let body = if check_role(srv, &usr, "admin").await {
        full(&i)
    } else {
        public(&i)
    };
    HttpResponse::Ok()
        .content_type("application/json")
        .body(body.to_string())
}

#[derive(Debug, Deserialize)]
struct SetQuery {
    #[serde(default)]
    action: String,
    #[serde(default)]
    minutes: Option<u64>,
    #[serde(default)]
    wait_hours: Option<u64>,
    #[serde(default)]
    reason: String,
}

pub async fn maintenance_set(
    user: Identity,
    data: web::Data<State>,
    req: HttpRequest,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let usr = get_user(srv, principal(&user)).await;
    if !check_role(srv, &usr, "admin").await {
        return HttpResponse::Forbidden().into();
    }
    let q: SetQuery = match serde_qs::from_str(req.query_string()) {
        Ok(q) => q,
        Err(_) => return HttpResponse::BadRequest().into(),
    };
    let by = usr
        .as_ref()
        .map(|u| u.safe_str("login", ""))
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "an administrator".to_string());
    refresh_defaults(srv).await;
    let i = match q.action.as_str() {
        "ask" => maintenance::ask(&by, &q.reason, q.minutes, q.wait_hours),
        "close" => maintenance::close_now(&by, &q.reason, q.minutes),
        "reopen" => maintenance::reopen(&by),
        _ => {
            return HttpResponse::Ok().content_type("application/json").body(
                serde_json::json!({
                    "succeeded": false,
                    "error": "Say what to do: ask, close or reopen.",
                })
                .to_string(),
            )
        }
    };
    HttpResponse::Ok().content_type("application/json").body(
        serde_json::json!({
            "succeeded": true,
            "error": "",
            "maintenance": full(&i),
        })
        .to_string(),
    )
}
