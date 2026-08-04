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
use crate::util::multipart::{with_deadline, Limits, ReadError};
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
    let usr: Option<Item> = get_user(srv, principal(&user)).await;
    let wr = call_url_route_actor(srv, hndl, &usr, query).await;
    if matches!(wr, WebResponse::NotImplemented) {
        return HttpResponse::NotFound().into();
    }
    conv_response(wr).await
}

/// Read a plugin route's multipart body: an optional `item` JSON field plus
/// any number of uploads, which are streamed to a directory of their own
/// under `./tmp`.
///
/// Bounded the same way core's own handlers are — see `util::multipart`. This
/// one matters more than most: without a deadline an unfinished part parks the
/// request forever, and without a byte cap the uploads land on disk unbounded.
/// Any file already written is removed before the error is returned, so a
/// refused request leaves nothing behind.
///
/// The per-request directory is what keeps concurrent uploads apart. Files
/// used to be written to `./tmp/{name the client chose}`, so two callers
/// uploading `photo.jpg` at the same time wrote to one path — the second
/// overwrote the first's content, and whichever finished first deleted the
/// file out from under the other during cleanup. The name is still sanitised;
/// the directory is what makes it unambiguous.
///
/// It is created only once a file field actually turns up. Creating it up
/// front leaked one empty directory per request for every caller that sent no
/// uploads — which is most of them, and `call_url_unprotected_post_route`
/// reaches this without authenticating, so the leak was an anonymous client's
/// to drive until the filesystem ran out of inodes. `handle_file_cleanup`
/// removes the directory along with the files, and it can only find it
/// through them.
pub async fn handle_item_files(
    payload: Option<Multipart>,
    limits: Limits,
) -> Result<(Item, HashMap<String, String>), (ReadError, HashMap<String, String>)> {
    let mut post_itm = Item::new();
    let mut files: HashMap<String, String> = HashMap::new();
    let mut files_count = 0;
    let mut total: usize = 0;
    let req_dir = format!("{}/{}", upload_root(), Uuid::new_v4());
    let mut dir_ready = false;

    // No multipart body at all, which is normal: plenty of action endpoints
    // take everything in the query string and post nothing. They get an empty
    // Item, exactly as if the body had been an empty form. Demanding a
    // multipart envelope from them made actix fail extraction before the route
    // ever ran, and all the caller saw was
    //   Could not read the request body: malformed multipart body:
    //   Multipart boundary is not found
    // with no hint of which endpoint or why.
    let mut payload = match payload {
        Some(p) => p,
        None => return Ok((post_itm, files)),
    };

    let outcome = with_deadline(limits, async {
        loop {
            let mut field = match payload.try_next().await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => return Err(ReadError::Malformed(e.to_string())),
            };

            if field.name() == "item" {
                let mut field_data: Vec<u8> = Vec::new();
                loop {
                    match field.try_next().await {
                        Ok(Some(chunk)) => {
                            total = total.saturating_add(chunk.len());
                            if total > limits.max_bytes {
                                return Err(ReadError::TooLarge(total));
                            }
                            field_data.extend_from_slice(&chunk);
                        }
                        Ok(None) => break,
                        Err(e) => return Err(ReadError::Malformed(e.to_string())),
                    }
                }
                let strv = std::str::from_utf8(&field_data).unwrap_or("{}");
                let new_itm: Item = serde_json::from_str(strv).unwrap_or_else(|e| {
                    log::error!("Failed to parse item JSON: {:?}", e);
                    Item::new()
                });
                post_itm.id = new_itm.id;
                post_itm.merge(&new_itm);
            } else {
                // First upload of this request: now the directory is worth
                // creating.
                if !dir_ready {
                    if let Err(e) = fs::create_dir_all(Path::new(&req_dir)) {
                        error!("Failed to create directory {}: {}", req_dir, e);
                    }
                    dir_ready = true;
                }

                let cd = field.content_disposition();
                let filename = cd
                    .get_filename()
                    .map_or_else(|| Uuid::new_v4().to_string(), sanitize_filename::sanitize);
                let filepath = format!("{req_dir}/{filename}");
                let f = std::fs::File::create(filepath.clone());

                info!("Created file {}", filepath);
                files.insert(files_count.to_string(), filepath);
                files_count = files_count + 1;

                match f {
                    Ok(mut file) => loop {
                        match field.try_next().await {
                            Ok(Some(chunk)) => {
                                total = total.saturating_add(chunk.len());
                                if total > limits.max_bytes {
                                    return Err(ReadError::TooLarge(total));
                                }
                                let _ = file.write_all(&chunk);
                            }
                            Ok(None) => break,
                            Err(e) => return Err(ReadError::Malformed(e.to_string())),
                        }
                    },
                    Err(_) => error!("Failed to open file"),
                }
            }
        }
        Ok(())
    })
    .await;

    if let Err(e) = outcome {
        return Err((e, files));
    }

    if files_count > 0 {
        post_itm.set_strstr("multipart-files", &files);
    }

    Ok((post_itm, files))
}

/// Directory the per-request upload directories are created under.
#[cfg(not(test))]
fn upload_root() -> String {
    "./tmp".to_string()
}

/// Under test the root is redirected into a temporary directory, so that
/// asserting on what was and was not created does not depend on — or litter —
/// the working tree.
#[cfg(test)]
fn upload_root() -> String {
    tests::upload_root()
}

pub async fn handle_file_cleanup(files: &HashMap<String, String>) {
    let mut dirs: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();
    for file in files {
        info!("Removed file {}", file.1);
        if let Some(parent) = Path::new(file.1).parent() {
            dirs.insert(parent.to_path_buf());
        }
        let _ = std::fs::remove_file(file.1);
    }
    // Non-recursive on purpose: this succeeds only once the directory is
    // empty, so it can never take out anything this request did not put there.
    for dir in dirs {
        let _ = std::fs::remove_dir(dir);
    }
}

pub async fn call_url_post_route(
    srv: &crate::state::data::Data,
    user: Identity,
    hndl: &str,
    query: &str,
    payload: Option<Multipart>,
) -> HttpResponse {
    let usr = get_user(srv, principal(&user)).await;
    let (post_itm, files) = match handle_item_files(payload, Limits::from_data(srv)).await {
        Ok(v) => v,
        Err((e, partial)) => {
            error!("Could not read the request body: {}", e);
            handle_file_cleanup(&partial).await;
            return HttpResponse::build(e.status()).into();
        }
    };

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
        usr = get_user(srv, principal(&u)).await;
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
    payload: Option<Multipart>,
) -> HttpResponse {
    let mut usr: Option<Item> = None;
    if let Some(u) = user {
        usr = get_user(srv, principal(&u)).await;
    }

    let (post_itm, files) = match handle_item_files(payload, Limits::from_data(srv)).await {
        Ok(v) => v,
        Err((e, partial)) => {
            error!("Could not read the request body: {}", e);
            handle_file_cleanup(&partial).await;
            return HttpResponse::build(e.status()).into();
        }
    };

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
        usr = get_user(srv, principal(&u)).await;
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
    for sender in srv.plugin_registry().senders() {
        let msg = isabelle_plugin_api::actor::PluginHookMessage::PeriodicJob {
            timing: timing.to_string(),
        };
        if let Err(e) = sender.try_send(msg) {
            log::trace!(target: "core::periodic",
                "actor periodic tick dropped ({}): {}", timing, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{web, App, HttpResponse};
    use parking_lot::Mutex;
    use std::sync::OnceLock;
    use std::time::Duration;

    const BOUNDARY: &str = "----isabelletestboundary";

    /// The redirected upload root. `handle_item_files` writes into whatever
    /// this holds, so a test that wants to look at the directory tree points
    /// it at a `tempdir` first.
    fn root_cell() -> &'static Mutex<String> {
        static ROOT: OnceLock<Mutex<String>> = OnceLock::new();
        ROOT.get_or_init(|| Mutex::new("./tmp".to_string()))
    }

    /// Serialises the tests that redirect the root, since it is global.
    fn root_guard() -> &'static Mutex<()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD.get_or_init(|| Mutex::new(()))
    }

    pub(super) fn upload_root() -> String {
        root_cell().lock().clone()
    }

    /// A multipart body with an `item` field and zero or more file parts.
    fn body(item: Option<&str>, files: &[(&str, &str)]) -> String {
        let mut out = String::new();
        if let Some(json) = item {
            out.push_str(&format!("--{}\r\n", BOUNDARY));
            out.push_str("Content-Disposition: form-data; name=\"item\"\r\n\r\n");
            out.push_str(json);
            out.push_str("\r\n");
        }
        for (name, content) in files {
            out.push_str(&format!("--{}\r\n", BOUNDARY));
            out.push_str(&format!(
                "Content-Disposition: form-data; name=\"upload\"; filename=\"{}\"\r\n\r\n",
                name
            ));
            out.push_str(content);
            out.push_str("\r\n");
        }
        out.push_str(&format!("--{}--\r\n", BOUNDARY));
        out
    }

    type Outcome = Result<(Item, HashMap<String, String>), (ReadError, HashMap<String, String>)>;

    /// Drive a real multipart body through the real extractor into
    /// `handle_item_files`, and hand back what it made of it.
    async fn run(payload: String, limits: Limits) -> Outcome {
        let sink: std::sync::Arc<Mutex<Option<Outcome>>> = std::sync::Arc::new(Mutex::new(None));
        let into = sink.clone();

        let app = actix_web::test::init_service(App::new().route(
            "/probe",
            web::post().to(move |mp: Multipart| {
                let into = into.clone();
                async move {
                    *into.lock() = Some(handle_item_files(Some(mp), limits).await);
                    HttpResponse::Ok().finish()
                }
            }),
        ))
        .await;

        let req = actix_web::test::TestRequest::post()
            .uri("/probe")
            .insert_header((
                "content-type",
                format!("multipart/form-data; boundary={}", BOUNDARY),
            ))
            .set_payload(payload)
            .to_request();
        let _ = actix_web::test::call_service(&app, req).await;

        let taken = sink.lock().take();
        taken.expect("handler did not run")
    }

    fn generous() -> Limits {
        Limits {
            deadline: Duration::from_secs(5),
            max_bytes: 1024 * 1024,
        }
    }

    fn entries(root: &Path) -> Vec<String> {
        match std::fs::read_dir(root) {
            Ok(rd) => rd
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Point the upload root at a fresh temporary directory for the duration
    /// of one test.
    fn with_root<T>(f: impl FnOnce(&Path) -> T) -> T {
        let _serialised = root_guard().lock();
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("tmp");
        std::fs::create_dir_all(&root).unwrap();
        *root_cell().lock() = root.to_string_lossy().into_owned();
        let out = f(dir.path());
        *root_cell().lock() = "./tmp".to_string();
        out
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// A POST with no multipart body at all is legitimate: action routes take
    /// their arguments in the query string and send nothing. Extraction used
    /// to fail on them before the route ran, and the caller was told only
    /// "Multipart boundary is not found" — which is how the portal's
    /// channel-planning buttons failed silently for months.
    #[test]
    fn a_request_without_a_body_is_accepted() {
        with_root(|base| {
            let root = base.join("tmp");
            let (itm, files) = rt()
                .block_on(handle_item_files(None, generous()))
                .expect("a body-less POST must not be refused");

            assert!(itm.strs.is_empty(), "nothing was posted");
            assert!(files.is_empty());
            assert!(
                entries(&root).is_empty(),
                "left behind {:?}",
                entries(&root)
            );
        });
    }

    /// A request that uploads nothing must leave nothing behind. The
    /// directory used to be created before the body was even looked at, so
    /// every plugin POST that carried only an `item` field — and every
    /// anonymous call to an unprotected POST route — leaked one empty
    /// directory that no cleanup path could ever find again.
    #[test]
    fn a_request_without_uploads_creates_no_directory() {
        with_root(|base| {
            let root = base.join("tmp");
            let (itm, files) = rt()
                .block_on(run(body(Some("{\"id\":7}"), &[]), generous()))
                .expect("a well-formed body was rejected");

            assert_eq!(itm.id, 7, "the item field was not read");
            assert!(files.is_empty());
            assert!(
                entries(&root).is_empty(),
                "left behind {:?}",
                entries(&root)
            );
        });
    }

    /// A body that is refused before any upload arrives must not leak one
    /// either — this is the same path, reached by the client that costs the
    /// least to be.
    #[test]
    fn a_refused_body_without_uploads_creates_no_directory() {
        with_root(|base| {
            let root = base.join("tmp");
            let limits = Limits {
                deadline: Duration::from_secs(5),
                max_bytes: 8,
            };
            let (err, files) = rt()
                .block_on(run(body(Some(&"x".repeat(64)), &[]), limits))
                .expect_err("an oversized body was accepted");

            assert_eq!(err, ReadError::TooLarge(64));
            assert!(files.is_empty());
            assert!(
                entries(&root).is_empty(),
                "left behind {:?}",
                entries(&root)
            );
        });
    }

    /// The directory still has to exist when there *is* something to put in
    /// it, and cleanup still has to take it away afterwards.
    #[test]
    fn uploads_get_a_directory_that_cleanup_removes() {
        with_root(|base| {
            let root = base.join("tmp");
            let (_itm, files) = rt()
                .block_on(run(
                    body(Some("{\"id\":1}"), &[("a.txt", "alpha"), ("b.txt", "beta")]),
                    generous(),
                ))
                .expect("an upload was rejected");

            assert_eq!(files.len(), 2);
            assert_eq!(entries(&root).len(), 1, "uploads did not get a directory");
            for path in files.values() {
                assert!(Path::new(path).is_file(), "{} was not written", path);
            }

            rt().block_on(handle_file_cleanup(&files));
            assert!(
                entries(&root).is_empty(),
                "cleanup left {:?}",
                entries(&root)
            );
        });
    }

    /// Two requests uploading the same filename must not share a path — the
    /// defect the per-request directory exists to fix. Asserted here so that
    /// making the directory lazy cannot quietly undo it.
    #[test]
    fn concurrent_uploads_of_one_name_do_not_collide() {
        with_root(|base| {
            let root = base.join("tmp");
            let rt = rt();
            let (_, first) = rt
                .block_on(run(body(None, &[("photo.jpg", "first")]), generous()))
                .unwrap();
            let (_, second) = rt
                .block_on(run(body(None, &[("photo.jpg", "second")]), generous()))
                .unwrap();

            let a = first.values().next().unwrap();
            let b = second.values().next().unwrap();
            assert_ne!(a, b, "two requests shared one upload path");
            assert_eq!(std::fs::read_to_string(a).unwrap(), "first");
            assert_eq!(std::fs::read_to_string(b).unwrap(), "second");
            assert_eq!(entries(&root).len(), 2);

            rt.block_on(handle_file_cleanup(&first));
            // The other request's file must survive its neighbour's cleanup.
            assert!(
                Path::new(b).is_file(),
                "cleanup reached into another request"
            );
            rt.block_on(handle_file_cleanup(&second));
            assert!(entries(&root).is_empty());
        });
    }
}
