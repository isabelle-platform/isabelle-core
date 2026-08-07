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
use crate::util::multipart::{read_json_body, Limits};
use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use log::error;
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

/// Refuse anyone who is not an administrator.
///
/// Shared with `server::openapi`, which gates on exactly the same thing: the
/// API description names every plugin route and every collection this
/// deployment has.
pub(crate) async fn ensure_admin(
    data: &web::Data<State>,
    user: &Identity,
) -> Result<(), HttpResponse> {
    let srv: &crate::state::data::Data = &data.server;
    let usr = get_user(srv, principal(user)).await;
    if !check_role(srv, &usr, "admin").await {
        return Err(HttpResponse::Forbidden().into());
    }
    Ok(())
}

fn proc_err(msg: impl Into<String>) -> HttpResponse {
    proc_err_status(actix_web::http::StatusCode::OK, msg)
}

/// A failure envelope at a chosen status.
///
/// Every other answer from these endpoints is a `ProcessResult` document, and
/// clients parse the body before they look at the status. A bare
/// `HttpResponse::NotFound()` sends no body at all, so the one answer that
/// carries a distinct status was also the one that made `resp.json()` throw.
fn proc_err_status(status: actix_web::http::StatusCode, msg: impl Into<String>) -> HttpResponse {
    HttpResponse::build(status).body(
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

/// Read this request's JSON body under the deployment's size and time limits.
///
/// These endpoints used the `web::Json<T>` extractor, which honours the
/// configured maximum size but has no deadline — so a trickled body held the
/// connection open indefinitely, the same defect the multipart handlers had.
async fn body_json<T: serde::de::DeserializeOwned>(
    data: &web::Data<State>,
    payload: &mut web::Payload,
) -> Result<T, HttpResponse> {
    let limits = Limits::from_data(&data.server);
    read_json_body::<T>(payload, limits).await.map_err(|e| {
        error!("Could not read the secret request body: {}", e);
        HttpResponse::build(e.status()).finish()
    })
}

pub async fn secret_edit(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let body: Item = match body_json(&data, &mut payload).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let srv: &crate::state::data::Data = &data.server;
    let mut secrets = srv.secrets.lock();
    let store = match secrets.as_mut() {
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
    mut payload: web::Payload,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let body: SecretIdReq = match body_json(&data, &mut payload).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let srv: &crate::state::data::Data = &data.server;
    let secrets = srv.secrets.lock();
    let store = match secrets.as_ref() {
        Some(s) => s,
        None => return proc_err("secret store is not initialized"),
    };
    match store.get_masked(body.id) {
        Some(item) => HttpResponse::Ok().body(serde_json::to_string(&item).unwrap()),
        None => proc_err_status(
            actix_web::http::StatusCode::NOT_FOUND,
            "no such secret".to_string(),
        ),
    }
}

pub async fn secret_del(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let body: SecretIdReq = match body_json(&data, &mut payload).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let srv: &crate::state::data::Data = &data.server;
    let mut secrets = srv.secrets.lock();
    let store = match secrets.as_mut() {
        Some(s) => s,
        None => return proc_err("secret store is not initialized"),
    };
    // `del` reports whether anything was actually removed. Mapping every `Ok`
    // to success left a client unable to tell a deletion from a no-op — the
    // one thing this call exists to confirm.
    match store.del(body.id) {
        Ok(true) => proc_ok(),
        Ok(false) => proc_err_status(
            actix_web::http::StatusCode::NOT_FOUND,
            "no such secret".to_string(),
        ),
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
    let srv: &crate::state::data::Data = &data.server;
    let secrets = srv.secrets.lock();
    let refs: Vec<SecretRef> = match secrets.as_ref() {
        Some(s) => s
            .list()
            .into_iter()
            .map(|(id, name)| SecretRef { id, name })
            .collect(),
        None => return proc_err("secret store is not initialized"),
    };
    HttpResponse::Ok().body(serde_json::to_string(&refs).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::MessageBody;
    use actix_web::http::StatusCode;

    fn parse(resp: HttpResponse) -> (StatusCode, ProcessResult) {
        let status = resp.status();
        let bytes = resp.into_body().try_into_bytes().unwrap();
        let parsed: ProcessResult = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("body was not a ProcessResult: {} ({:?})", e, bytes));
        (status, parsed)
    }

    /// Every answer these endpoints give is a `ProcessResult` document, and
    /// clients parse the body before looking at the status. Deleting a secret
    /// that is not there answers 404, and that answer used to carry no body
    /// at all — the one status a client would want to branch on was the one
    /// that broke its parser.
    #[test]
    fn a_missing_secret_answers_404_with_a_parseable_body() {
        let (status, result) = parse(proc_err_status(StatusCode::NOT_FOUND, "no such secret"));
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!result.succeeded);
        assert_eq!(result.error, "no such secret");
    }

    /// The ordinary failure envelope keeps its 200: clients already read
    /// `succeeded` for those, and moving them would be a separate, breaking
    /// change.
    #[test]
    fn an_ordinary_failure_still_answers_200() {
        let (status, result) = parse(proc_err("secret store is not initialized"));
        assert_eq!(status, StatusCode::OK);
        assert!(!result.succeeded);
        assert_eq!(result.error, "secret store is not initialized");
    }

    #[test]
    fn success_is_reported_as_success() {
        let (status, result) = parse(proc_ok());
        assert_eq!(status, StatusCode::OK);
        assert!(result.succeeded);
        assert_eq!(result.error, "");
    }
}
