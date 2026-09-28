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

/// Who is asking, as far as secrets are concerned.
///
/// Anybody with an active account may keep secrets: a person connecting a
/// node of their own needs somewhere to put its password. Each secret belongs
/// to whoever stored it (`owner::FIELD_OWNER`), and only its owner and the
/// administrators see or change it. Entries stored before secrets had owners
/// have none, and are the administrators'.
struct Caller {
    id: u64,
    admin: bool,
}

impl Caller {
    fn may_touch(&self, secret: &Item) -> bool {
        crate::server::owner::may_touch(secret, self.id, self.admin)
    }
}

async fn caller(data: &web::Data<State>, user: &Identity) -> Result<Caller, HttpResponse> {
    let srv: &crate::state::data::Data = &data.server;
    let usr = get_user(srv, principal(user)).await;
    if !check_role(srv, &usr, "active").await {
        return Err(HttpResponse::Forbidden().into());
    }
    let admin = check_role(srv, &usr, "admin").await;
    match usr {
        Some(u) => Ok(Caller { id: u.id, admin }),
        None => Err(HttpResponse::Forbidden().into()),
    }
}

/// The answer for a secret the caller may not see: the same as for one that
/// is not there, so that asking discloses nothing.
fn no_such_secret() -> HttpResponse {
    reply::err_status(
        actix_web::http::StatusCode::NOT_FOUND,
        "no such secret".to_string(),
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
    let me = match caller(&data, &user).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut body: Item = match body_json(&data, &mut payload).await {
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
    let existing = if body.id != u64::MAX {
        store.get(body.id)
    } else {
        None
    };
    if let Some(existing) = &existing {
        if !me.may_touch(existing) {
            return no_such_secret();
        }
        let current = existing.safe_str("name", "");
        if crate::state::secrets::is_global_name(&current) {
            return reserved(&current);
        }
    }
    crate::server::owner::stamp(&mut body, existing.as_ref(), me.id);
    // Default to merge semantics: external clients cannot read raw values,
    // so a fresh PUT of a partial Item must not silently wipe fields the
    // caller didn't include. Together with the "<hidden>" placeholder rule
    // in SecretStore::set, this lets a client round-trip a masked Item.
    match store.set(&body, true) {
        Ok(id) => reply::ok_with_id(id),
        // Names are unique across the store, so a taken one may be somebody
        // else's: say that it is taken, not whose it is.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && !me.admin => reply::err(
            format!("a secret named '{wanted}' already exists; choose another name"),
        ),
        Err(e) => reply::err(format!("failed to write secret: {}", e)),
    }
}

pub async fn secret_get(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse {
    let me = match caller(&data, &user).await {
        Ok(c) => c,
        Err(r) => return r,
    };
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
        Some(item) if me.may_touch(&item) => {
            HttpResponse::Ok().body(serde_json::to_string(&item).unwrap())
        }
        _ => no_such_secret(),
    }
}

pub async fn secret_del(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse {
    let me = match caller(&data, &user).await {
        Ok(c) => c,
        Err(r) => return r,
    };
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
        if !me.may_touch(&existing) {
            return no_such_secret();
        }
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
        Ok(false) => no_such_secret(),
        Err(e) => reply::err(format!("failed to delete secret: {}", e)),
    }
}

pub async fn secret_list(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
) -> HttpResponse {
    let me = match caller(&data, &user).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let srv: &crate::state::data::Data = &data.server;
    let secrets = srv.secrets.lock();
    let refs: Vec<SecretRef> = match secrets.as_ref() {
        Some(s) => s
            .list()
            .into_iter()
            .filter(|(id, _)| s.get(*id).map_or(false, |it| me.may_touch(&it)))
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

/// Whose secrets are whose, through a real app.
#[cfg(test)]
mod owner_tests {
    use super::*;
    use crate::server::login::login;
    use crate::state::data::Data;
    use crate::state::store_memory::StoreMemory;
    use crate::util::crypto::{get_new_salt, get_password_hash};
    use actix_web::cookie::Cookie;
    use actix_web::{test, App};
    use serde_json::{json, Value};

    const BOUNDARY: &str = "----isabelletestboundary";

    fn account(id: u64, login: &str, admin: bool, active: bool) -> Item {
        let mut itm = Item::new();
        itm.id = id;
        itm.set_str("login", login);
        itm.set_str("email", &format!("{}@example.org", login));
        itm.set_str("password", &get_password_hash("hunter2", &get_new_salt()));
        itm.set_bool("role_is_active", active);
        if admin {
            itm.set_bool("role_is_admin", true);
        }
        itm
    }

    fn state(dir: &tempfile::TempDir) -> web::Data<State> {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", account(1, "admin", true, true));
        store.seed("user", account(2, "bob", false, true));
        store.seed("user", account(3, "carol", false, true));
        store.seed("user", account(4, "dave", false, false));
        let mut data = Data::new();
        data.rw = Box::new(store);
        let mut secrets = crate::state::secrets::SecretStore::open(
            &dir.path().join("key"),
            &dir.path().join("store"),
        )
        .unwrap();
        // Stored before secrets had owners.
        let mut legacy = Item::new();
        legacy.set_str("name", "legacy");
        legacy.set_str("secret_value", "old");
        secrets.set(&legacy, false).unwrap();
        *data.secrets.lock() = Some(secrets);
        web::Data::new(State::from_data(data))
    }

    macro_rules! app_with {
        ($state:expr) => {
            test::init_service(
                App::new()
                    .app_data($state)
                    .wrap(actix_identity::IdentityMiddleware::default())
                    .wrap(
                        actix_session::SessionMiddleware::builder(
                            actix_session::storage::CookieSessionStore::default(),
                            actix_web::cookie::Key::from(&[0u8; 64]),
                        )
                        .cookie_secure(false)
                        .build(),
                    )
                    .route("/login", web::post().to(login))
                    .route("/secret/edit", web::post().to(secret_edit))
                    .route("/secret/del", web::post().to(secret_del))
                    .route("/secret/list", web::get().to(secret_list))
                    .route("/secret/get", web::post().to(secret_get)),
            )
            .await
        };
    }

    macro_rules! sign_in {
        ($app:expr, $username:expr) => {{
            let body = format!(
                "--{b}\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n{u}\r\n\
                 --{b}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n\
                 --{b}--\r\n",
                b = BOUNDARY,
                u = $username
            );
            let res = test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/login")
                    .insert_header((
                        "content-type",
                        format!("multipart/form-data; boundary={}", BOUNDARY),
                    ))
                    .set_payload(body)
                    .to_request(),
            )
            .await;
            let raw = res
                .response()
                .cookies()
                .find(|c| c.name() == "id")
                .expect("no session cookie was issued");
            Cookie::new(raw.name().to_string(), raw.value().to_string())
        }};
    }

    macro_rules! post {
        ($app:expr, $who:expr, $path:expr, $body:expr) => {{
            let res = test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri($path)
                    .cookie($who.clone())
                    .insert_header(("content-type", "application/json"))
                    .set_payload($body.to_string())
                    .to_request(),
            )
            .await;
            let status = res.status();
            let body = test::read_body(res).await;
            (
                status,
                serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
            )
        }};
    }

    macro_rules! names {
        ($app:expr, $who:expr) => {{
            let body = test::call_and_read_body(
                &$app,
                test::TestRequest::get()
                    .uri("/secret/list")
                    .cookie($who.clone())
                    .to_request(),
            )
            .await;
            let refs: Vec<Value> = serde_json::from_slice(&body).unwrap();
            let mut n: Vec<String> = refs
                .iter()
                .map(|r| r["name"].as_str().unwrap().to_string())
                .collect();
            n.sort();
            n
        }};
    }

    fn secret(name: &str) -> Value {
        json!({ "id": u64::MAX, "strs": { "name": name, "secret_value": "s3cret" } })
    }

    #[actix_web::test]
    async fn everybody_keeps_their_own_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_with!(state(&dir));
        let admin = sign_in!(app, "admin");
        let bob = sign_in!(app, "bob");
        let carol = sign_in!(app, "carol");

        let (_, r) = post!(app, bob, "/secret/edit", secret("bob ssh"));
        assert_eq!(r["succeeded"], true, "{r}");
        let bobs: u64 = r["data"]["id"].as_str().unwrap().parse().unwrap();
        let (_, r) = post!(app, carol, "/secret/edit", secret("carol ssh"));
        assert_eq!(r["succeeded"], true, "{r}");

        assert_eq!(names!(app, bob), vec!["bob ssh"]);
        assert_eq!(names!(app, carol), vec!["carol ssh"]);
        assert_eq!(names!(app, admin), vec!["bob ssh", "carol ssh", "legacy"]);

        // Carol cannot read, change or delete Bob's; it answers as if absent.
        let (st, _) = post!(app, carol, "/secret/get", json!({ "id": bobs }));
        assert_eq!(st, actix_web::http::StatusCode::NOT_FOUND);
        let (st, _) = post!(
            app,
            carol,
            "/secret/edit",
            json!({ "id": bobs, "strs": { "name": "bob ssh", "secret_value": "mine" } })
        );
        assert_eq!(st, actix_web::http::StatusCode::NOT_FOUND);
        let (st, _) = post!(app, carol, "/secret/del", json!({ "id": bobs }));
        assert_eq!(st, actix_web::http::StatusCode::NOT_FOUND);

        // Nor can she take it over by claiming it on a new one.
        let (_, r) = post!(
            app,
            carol,
            "/secret/edit",
            json!({ "id": u64::MAX, "ids": { "owner": 2 }, "strs": { "name": "planted" } })
        );
        assert_eq!(r["succeeded"], true, "{r}");
        assert!(!names!(app, bob).contains(&"planted".to_string()));

        // A taken name does not say whose it is.
        let (_, r) = post!(app, carol, "/secret/edit", secret("bob ssh"));
        assert_eq!(r["succeeded"], false);
        assert!(!r["error"].as_str().unwrap().contains("by id"), "{r}");

        // Bob edits his own and keeps it.
        let (_, r) = post!(
            app,
            bob,
            "/secret/edit",
            json!({ "id": bobs, "ids": { "owner": 3 }, "strs": { "description": "lab" } })
        );
        assert_eq!(r["succeeded"], true, "{r}");
        let (_, got) = post!(app, bob, "/secret/get", json!({ "id": bobs }));
        assert_eq!(got["ids"]["owner"], 2);
        assert_eq!(got["strs"]["description"], "lab");

        // The administrator reaches everybody's, and Bob his own.
        let (st, _) = post!(app, admin, "/secret/get", json!({ "id": bobs }));
        assert!(st.is_success());
        let (_, r) = post!(app, bob, "/secret/del", json!({ "id": bobs }));
        assert_eq!(r["succeeded"], true, "{r}");
    }

    #[actix_web::test]
    async fn an_unowned_secret_is_the_administrators() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_with!(state(&dir));
        let bob = sign_in!(app, "bob");
        let admin = sign_in!(app, "admin");
        let (st, _) = post!(app, bob, "/secret/get", json!({ "id": 0 }));
        assert_eq!(st, actix_web::http::StatusCode::NOT_FOUND);
        let (st, _) = post!(app, admin, "/secret/get", json!({ "id": 0 }));
        assert!(st.is_success());
    }
}
