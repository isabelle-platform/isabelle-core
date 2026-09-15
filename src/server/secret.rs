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
use crate::server::reply;
use crate::server::user_control::*;
use crate::state::state::*;
use crate::util::multipart::{read_json_body, Limits};
use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use isabelle_dm::data_model::item::Item;
use log::error;
use serde::{Deserialize, Serialize};

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

/// Why the reserved space is not editable here.
///
/// These entries are the application's own configuration — how it sends
/// mail, who it trusts to sign people in — and each is written by the screen
/// that owns it, which knows what a valid one looks like. Reached through
/// this endpoint instead, they can be half-written, renamed, or created by
/// somebody who only meant to save a password of their own and picked a name
/// that collided. So the space is closed here to everybody, administrators
/// included: the way to change one is the screen it belongs to.
fn reserved(name: &str) -> HttpResponse {
    reply::err(format!(
        "'{name}' is in the reserved '{}' name space, which holds this server's own \
         configuration. Change it on the screen it belongs to; secrets of your own can have \
         any other name.",
        crate::state::secrets::GLOBAL_PREFIX
    ))
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
    // Refused on the name that was sent and again on the one it would be
    // changing: a request may not create an entry in the reserved space, and
    // it may not reach into one by id either.
    let wanted = body.safe_str("name", "");
    if crate::state::secrets::is_global_name(&wanted) {
        return reserved(&wanted);
    }
    let mut secrets = srv.secrets.lock();
    let store = match secrets.as_mut() {
        Some(s) => s,
        None => return reply::err("secret store is not initialized"),
    };
    if body.id != u64::MAX {
        if let Some(existing) = store.get(body.id) {
            let current = existing.safe_str("name", "");
            if crate::state::secrets::is_global_name(&current) {
                return reserved(&current);
            }
        }
    }
    // Default to merge semantics: external clients cannot read raw values,
    // so a fresh PUT of a partial Item must not silently wipe fields the
    // caller didn't include. Together with the "<hidden>" placeholder rule
    // in SecretStore::set, this lets a client round-trip a masked Item.
    match store.set(&body, true) {
        Ok(id) => reply::ok_with_id(id),
        Err(e) => reply::err(format!("failed to write secret: {}", e)),
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
        None => return reply::err("secret store is not initialized"),
    };
    match store.get_masked(body.id) {
        Some(item) => HttpResponse::Ok().body(serde_json::to_string(&item).unwrap()),
        None => reply::err_status(
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
        None => return reply::err("secret store is not initialized"),
    };
    // Closed the same way editing is, and for the same reason: an entry in
    // the reserved space is configuration the server needs to work, and
    // removing it from here would leave the screen that owns it describing
    // something that is no longer there.
    if let Some(existing) = store.get(body.id) {
        let name = existing.safe_str("name", "");
        if crate::state::secrets::is_global_name(&name) {
            return reserved(&name);
        }
    }
    // `del` reports whether anything was actually removed. Mapping every `Ok`
    // to success left a client unable to tell a deletion from a no-op — the
    // one thing this call exists to confirm.
    match store.del(body.id) {
        Ok(true) => reply::ok(),
        Ok(false) => reply::err_status(
            actix_web::http::StatusCode::NOT_FOUND,
            "no such secret".to_string(),
        ),
        Err(e) => reply::err(format!("failed to delete secret: {}", e)),
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
        None => return reply::err("secret store is not initialized"),
    };
    HttpResponse::Ok().body(serde_json::to_string(&refs).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::MessageBody;
    use actix_web::http::StatusCode;
    use isabelle_dm::data_model::process_result::ProcessResult;

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
        let (status, result) = parse(reply::err_status(StatusCode::NOT_FOUND, "no such secret"));
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!result.succeeded);
        assert_eq!(result.error, "no such secret");
    }

    /// The ordinary failure envelope keeps its 200: clients already read
    /// `succeeded` for those, and moving them would be a separate, breaking
    /// change.
    #[test]
    fn an_ordinary_failure_still_answers_200() {
        let (status, result) = parse(reply::err("secret store is not initialized"));
        assert_eq!(status, StatusCode::OK);
        assert!(!result.succeeded);
        assert_eq!(result.error, "secret store is not initialized");
    }

    #[test]
    fn success_is_reported_as_success() {
        let (status, result) = parse(reply::ok());
        assert_eq!(status, StatusCode::OK);
        assert!(result.succeeded);
        assert_eq!(result.error, "");
    }
}
