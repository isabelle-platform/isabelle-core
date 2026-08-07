/*
 * Isabelle project
 *
 * Copyright 2023-2026 Maxim Menshikov
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 */

// No `unsafe` anywhere in this crate, enforced by the compiler rather than
// by review: `forbid` cannot be lifted by a local `allow`, so the aliasing
// cast this startup path used to rely on cannot come back unnoticed.
#![forbid(unsafe_code)]

//! Isabelle core library entry point.
//!
//! Per-deployment binaries call [`run`] with a `setup` closure that
//! registers the plugins for that flavour. Core itself has no plugin
//! dependencies — each shell binary picks them. Typical use:
//!
//! ```ignore
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     isabelle_core::run(|reg, core| {
//!         isabelle_plugin_security::register_actor(reg, core.clone());
//!         isabelle_plugin_midair::register_actor(reg, core.clone());
//!     }).await
//! }
//! ```

use crate::args::Args;
use chrono::Timelike;
use chrono::{FixedOffset, Local};
use cron::Schedule;
use std::{str::FromStr, time::Duration};

#[cfg(not(feature = "full_file_database"))]
use crate::state::merger::merge_database;
use crate::state::store::Store;

pub mod args;
pub mod handler;
pub mod notif;
#[cfg(feature = "actor-demo")]
pub mod plugin_actor_demo;
pub mod server;
pub mod state;
pub mod util;

use crate::handler::route::url_post_rest_route;
use crate::handler::route::url_post_route;
use crate::handler::route::url_rest_route;
use crate::handler::route::url_route;
use crate::handler::route::url_unprotected_post_route;
use crate::handler::route::url_unprotected_route;
use crate::handler::route_call::call_periodic_job_hook;
use crate::notif::gcal::*;
use crate::server::guards::{enforce_session_generation, reject_ambiguous_framing};
use crate::server::itm::*;
use crate::server::login::*;
use crate::server::openapi::{openapi_docs, openapi_json, DOCS_PATH, OPENAPI_PATH};
use std::collections::HashMap;

use crate::server::secret::*;
use crate::server::setting::*;
use crate::server::system::*;

use crate::state::state::*;
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_session::config::{BrowserSession, CookieContentSecurity};
use actix_session::storage::CookieSessionStore;
use actix_session::SessionMiddleware;
use actix_web::middleware::from_fn;
use actix_web::web::Data;
use actix_web::{cookie::Key, cookie::SameSite, rt, web, App, HttpServer};
use clap::Parser;
use log::info;
use std::thread;

/// Re-exported actor-mode types so shell binaries don't have to add their
/// own `isabelle-plugin-api` dependency just for the closure signature.
pub use isabelle_plugin_api::actor::{CoreHandle, PluginRegistry};

/// Session middleware based on cookies.
///
/// `key` signs and encrypts the session cookie, so it must be a persisted
/// random secret — see `load_or_create_session_key`. It is passed in rather
/// than derived here because `HttpServer::new`'s factory runs once per worker
/// and every worker must use the same key.
///
/// The session cookie is `SameSite=Lax`, which is what stops cross-site
/// request forgery here: no endpoint carries a CSRF token, so if the browser
/// attached this cookie to a cross-site POST, any page an authenticated user
/// visited could act as them. It used to be `SameSite=None` whenever the
/// cookie was `Secure` — i.e. in every production deployment — which made a
/// plain `<form method=post>` on an attacker's page enough to invoke
/// `/system/update` (running the configured update script server-side) or
/// `/itm/edit` as a logged-in admin, no JavaScript and no CORS involved.
///
/// `Lax` is compatible with how this application is deployed: production
/// serves the UI and the API from one origin (the API under `/api` behind the
/// reverse proxy), and local development serves the UI on one port and the
/// backend on another — a different *origin*, but the same *site*, which is
/// what `SameSite` is about. A deployment that genuinely splits UI and API
/// across registrable domains would need real CSRF tokens; loosening this back
/// to `None` would only restore the hole.
fn session_middleware(
    _pub_fqdn: String,
    cookie_http_insecure: bool,
    key: Key,
) -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(CookieSessionStore::default(), key)
        .session_lifecycle(BrowserSession::default())
        .cookie_same_site(SameSite::Lax)
        .cookie_path("/".into())
        .cookie_name(String::from("isabelle-cookie"))
        .cookie_content_security(CookieContentSecurity::Private)
        .cookie_http_only(true)
        .cookie_secure(!cookie_http_insecure)
        .build()
}

/// Reduce an origin-ish configuration value to the exact form a browser sends
/// in the `Origin` header: scheme, host and (only when non-default) port, with
/// no trailing slash and no path.
///
/// Operators write `--pub-url` as a URL, sometimes with a trailing slash or a
/// path, but `Origin` never has either, and the allowlist is compared byte for
/// byte.
fn normalize_origin(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, r)) if !s.is_empty() => (s, r),
        _ => return None,
    };
    // Cut off path, query and fragment; keep host[:port].
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('.');
    if authority.is_empty() {
        return None;
    }
    Some(format!("{}://{}", scheme.to_lowercase(), authority))
}

/// Cross-origin policy.
///
/// This used to be `Cors::permissive()`, which reflects any `Origin` back and
/// sets `Access-Control-Allow-Credentials: true` — the "reflect origin + allow
/// credentials" combination that lets any page read authenticated responses
/// from this API. The allowlist is built from `--pub-url` (where the UI is
/// served from) plus any `--cors-origin` entries.
///
/// `block_on_origin_mismatch(false)` is deliberate: an unlisted `Origin` gets
/// no CORS headers, and the browser refuses the read — enforcement stays where
/// it belongs. Blocking server-side instead would reject same-origin POSTs
/// too, because browsers send `Origin` on those as well, so a `--pub-url` that
/// merely disagreed about a trailing slash would break the whole UI.
/// True for an origin that can only be a developer's own machine:
/// `localhost`, `127.0.0.1` or `[::1]`, on any port and either scheme.
///
/// A loopback origin cannot be reached by a third-party page, so allowing the
/// whole family costs nothing while removing a class of self-inflicted CORS
/// failures — `--pub-url` names exactly one of these spellings, and a browser
/// opened on any of the others is refused even though it is the same machine.
fn is_loopback_origin(origin: &str) -> bool {
    let host = match origin.split_once("://") {
        Some((scheme, rest)) if scheme == "http" || scheme == "https" => rest,
        _ => return false,
    };
    let host = host.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

/// `dev_mode` mirrors `--cookie-http-insecure`: the flag that already says
/// "this is a local development run".
fn cors_middleware(pub_url: &str, extra_origins: &[String], dev_mode: bool) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "HEAD", "OPTIONS"])
        .allow_any_header()
        .supports_credentials()
        .block_on_origin_mismatch(false)
        .max_age(3600);

    if dev_mode {
        info!("CORS: development run — allowing any loopback origin");
        cors = cors.allowed_origin_fn(|origin, _req| {
            let ok = origin.to_str().map(is_loopback_origin).unwrap_or(false);
            if !ok {
                // Without this line a rejected origin is invisible server-side:
                // the browser reports "CORS error" and the log shows a normal
                // 200, which is a genuinely confusing pair to debug.
                log::warn!(
                    "CORS: origin {:?} is not allowed — pass it with --cors-origin \
                     (or point --pub-url at it)",
                    origin.to_str().unwrap_or("<unprintable>")
                );
            }
            ok
        });
    }

    for raw in std::iter::once(pub_url).chain(extra_origins.iter().map(|s| s.as_str())) {
        match normalize_origin(raw) {
            Some(origin) => {
                info!("CORS: allowing origin {}", origin);
                cors = cors.allowed_origin(&origin);
            }
            None if raw.trim().is_empty() => {}
            None => log::warn!("CORS: ignoring malformed origin {:?}", raw),
        }
    }

    cors
}

/// Run the Isabelle core HTTP server. The `setup` closure is invoked once
/// during startup, after `CoreHandle` is available but before the HTTP
/// server starts accepting requests, so per-deployment shell binaries can
/// register the plugins they need. Pass an empty closure if you want core
/// with no plugins (dev / smoke tests).
pub async fn run<F>(setup: F) -> std::io::Result<()>
where
    F: FnOnce(&mut PluginRegistry, &CoreHandle),
{
    let args = Args::parse();

    env_logger::init();

    // Routes: they must be collected here in order to be set up in Actix
    let mut new_routes: HashMap<String, String> = HashMap::new();
    let mut new_unprotected_routes: HashMap<String, String> = HashMap::new();
    let mut new_rest_routes: HashMap<String, String> = HashMap::new();

    // Startup runs in two phases, and the split is what keeps this code free
    // of aliasing tricks.
    //
    // Phase one builds `Data` while this function still owns it outright.
    // Connecting the stores needs `&mut`, and here that is simply what an
    // owned local gives you. The previous arrangement created the value inside
    // a global `Arc` first and then cast `&Data` back to `&mut Data` to finish
    // initialising it, which is undefined behaviour no matter how single-
    // threaded the moment is: `&T` tells the compiler the pointee is not
    // written through, and it optimises on that promise.
    //
    // Phase two publishes the value into an `Arc` and never takes `&mut`
    // again. Only two fields cannot be filled before publication — the core
    // task handle and the plugin registry, both of which need the `Arc` to
    // exist first — and those are `OnceLock`s, written through `&Data`.
    let mut data = crate::state::data::Data::new();

    {
        let srv: &crate::state::data::Data = &data;

        *srv.gc_path.lock() = args.gc_path.to_string();
        *srv.py_path.lock() = args.py_path.to_string();
        *srv.data_path.lock() = args.data_path.to_string();
        *srv.public_url.lock() = args.pub_url.to_string();
        srv.port
            .store(args.bind_port, std::sync::atomic::Ordering::Relaxed);
        srv.max_payload_bytes
            .store(args.max_payload_bytes, std::sync::atomic::Ordering::Relaxed);
        srv.body_timeout_secs
            .store(args.body_timeout_secs, std::sync::atomic::Ordering::Relaxed);
        *srv.update_script.lock() = args.update_script.to_string();

        // Initialize the encrypted secret store. The master key file
        // defaults to ${data_path}/.secret-key when not specified.
        let key_file = if args.secret_key_file.is_empty() {
            std::path::PathBuf::from(&args.data_path).join(".secret-key")
        } else {
            std::path::PathBuf::from(&args.secret_key_file)
        };
        let store_file = std::path::PathBuf::from(&args.data_path).join("secrets.enc");
        if let Some(parent) = key_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match crate::state::secrets::SecretStore::open(&key_file, &store_file) {
            Ok(s) => {
                info!("Secret store: opened ({} entries)", s.list().len());
                *srv.secrets.lock() = Some(s);
            }
            Err(e) => {
                log::error!("Secret store: failed to open: {}", e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("secret store init failed: {}", e),
                ));
            }
        }
    }

    info!("Data storage: connecting");
    // Put options to internal structures and connect to database.
    // `data` is still an owned local here, so these `&mut` borrows are the
    // ordinary kind the compiler checks.
    #[cfg(not(feature = "full_file_database"))]
    {
        data.file_rw.connect(&args.data_path, "").await;
        data.rw.set_database_name(&args.db_name);
        data.rw.connect(&args.db_url, &args.data_path).await;

        // First-run autodetect: seed from the file-backed store when the
        // database holds no data yet. We must check for *items*, not
        // collections: connect() above pre-creates the declared (but empty)
        // collections from internals.js, so get_collections() is never empty
        // here. Idempotent across restarts: once seeded, this is a no-op.
        let mut has_data = false;
        for coll in data.rw.get_collections().await {
            if data
                .rw
                .get_items(&coll, u64::MAX, u64::MAX, "", "", 0, 1)
                .await
                .total_count
                > 0
            {
                has_data = true;
                break;
            }
        }
        if !has_data {
            info!("Flow: empty database detected, seeding from file store");
            merge_database(&mut data.file_rw, &mut *data.rw).await;
            info!("Flow: seeding complete");
        }
    }

    #[cfg(feature = "full_file_database")]
    {
        data.rw.connect(&args.data_path, "").await;
    }

    info!("Data storage: connected");

    // Phase two: publish. `data` is moved behind an `Arc` and from here on is
    // only ever reached through `&`.
    let state = State::from_data(data);

    {
        let srv: &crate::state::data::Data = &state.server;

        // Spawn the core processing task — it owns the inbox for the new
        // actor-model `CoreMessage`s and processes them against `Data`.
        // The returned `CoreHandle` is published on `srv` so the caller's
        // setup closure (and the plugins it registers) can clone it.
        let core_handle = crate::state::core_task::spawn_core_task(state.clone());
        if srv.set_core_handle(core_handle.clone()).is_err() {
            log::warn!("Core handle was already published; ignoring");
        }

        // Hand control to the deployment-specific shell binary so it can
        // register whichever plugins it links against. The registry is built
        // here, as an owned value, and published once it is complete.
        info!("Plugins: registering");
        let mut registry = PluginRegistry::new();
        setup(&mut registry, &core_handle);
        let plugin_count = registry.len();
        if srv.set_plugin_registry(registry).is_err() {
            log::warn!("Plugin registry was already published; ignoring");
        }
        info!("Plugins: {} registered", plugin_count);

        // Perform initialization checks, etc.
        info!("Flow: performing initialization checks");
        srv.init_checks().await;
        info!("Flow: performed initialization checks");

        // Pre-parse routing tables from internals.js so request handlers
        // can do O(1) lookups instead of re-splitting "path:method:handler"
        // strings on every request.
        srv.rebuild_route_cache().await;

        // Initialize Google Calendar
        info!("Flow: initializing Google Calendar");
        init_google(srv).await;
        info!("Flow: initialized Google Calendar");

        // Get all extra routes and put them to map
        {
            let routes = srv
                .rw
                .get_internals()
                .await
                .safe_strstr("extra_route", &HashMap::new());
            for route in routes {
                let parts: Vec<&str> = route.1.split(":").collect();
                new_routes.insert(parts[0].to_string(), parts[1].to_string());
                info!("Adding route: {} : {}", parts[0], parts[1]);
            }
        }
        {
            let routes = srv
                .rw
                .get_internals()
                .await
                .safe_strstr("extra_unprotected_route", &HashMap::new());
            for route in routes {
                let parts: Vec<&str> = route.1.split(":").collect();
                new_unprotected_routes.insert(parts[0].to_string(), parts[1].to_string());
                info!("Adding unprotected route: {} : {}", parts[0], parts[1]);
            }
        }
        {
            let routes = srv
                .rw
                .get_internals()
                .await
                .safe_strstr("extra_rest_route", &HashMap::new());
            for route in routes {
                let parts: Vec<&str> = route.1.split(":").collect();
                new_rest_routes.insert(parts[0].to_string(), parts[1].to_string());
                info!("Adding rest route: {} : {}", parts[0], parts[1]);
            }
        }
    }

    // Session cookie key: a persisted random secret, generated on first run.
    // Never a constant — a fixed key lets anyone forge a session cookie for
    // any identity, including admin.
    let session_key = {
        let key_file = if args.session_key_file.is_empty() {
            std::path::PathBuf::from(&args.data_path).join(".session-key")
        } else {
            std::path::PathBuf::from(&args.session_key_file)
        };
        let existed = key_file.exists();
        match crate::state::secrets::load_or_create_session_key(&key_file) {
            Ok(bytes) => {
                if existed {
                    info!("Session key: loaded from {}", key_file.display());
                } else {
                    info!(
                        "Session key: generated a new one at {} (existing sessions are invalidated)",
                        key_file.display()
                    );
                }
                Key::from(&bytes)
            }
            Err(e) => {
                log::error!("Session key: failed to load/create: {}", e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("session key init failed: {}", e),
                ));
            }
        }
    };

    let data = Data::new(state.clone());
    let data_clone = data.clone();

    {
        let srv: &crate::state::data::Data = &state.server;
        srv.init_data_path().await;
    }

    info!("Flow: Starting server");

    // periodic tasks
    thread::spawn(move || {
        let expression = "*   *   *     *       *  *  *";
        let schedule = Schedule::from_str(expression).unwrap();
        let offset = Some(FixedOffset::east_opt(0)).unwrap();
        loop {
            let mut upcoming = schedule.upcoming(offset.unwrap()).take(1);
            thread::sleep(Duration::from_millis(500));

            let local = Local::now();

            if let Some(datetime) = upcoming.next() {
                if datetime.timestamp() <= local.timestamp() {
                    let srv: &crate::state::data::Data = &data_clone.server;
                    if local.time().second() == 0 {
                        call_periodic_job_hook(srv, "min");
                    }
                    call_periodic_job_hook(srv, "sec");
                }
            }
        }
    });

    let srv = HttpServer::new(move || {
        // Set up all generic routes
        // Wrap order is inside-out: the last `.wrap` is the outermost layer.
        // `enforce_session_generation` therefore has to be registered first,
        // so that it runs *after* the session and identity middleware have
        // populated what it reads. `reject_ambiguous_framing` is a pure
        // header check and does not care where it sits.
        let mut app = App::new()
            .app_data(data.clone())
            .app_data(web::PayloadConfig::new(args.max_payload_bytes))
            .wrap(from_fn(enforce_session_generation))
            .wrap(from_fn(reject_ambiguous_framing))
            .wrap(cors_middleware(
                &args.pub_url,
                &args.cors_origin,
                args.cookie_http_insecure,
            ))
            .wrap(IdentityMiddleware::default())
            .wrap(session_middleware(
                args.pub_fqdn.clone(),
                args.cookie_http_insecure,
                session_key.clone(),
            ))
            .route("/itm/edit", web::post().to(itm_edit))
            .route("/itm/del", web::post().to(itm_del))
            .route("/itm/list", web::get().to(itm_list))
            .route("/login", web::post().to(login))
            .route("/register", web::post().to(register))
            .route("/gen_otp", web::post().to(gen_otp))
            .route("/logout", web::post().to(logout))
            .route("/is_logged_in", web::get().to(is_logged_in))
            .route("/setting/edit", web::post().to(setting_edit))
            .route("/setting/list", web::get().to(setting_list))
            .route("/setting/gcal_auth", web::post().to(setting_gcal_auth))
            .route(
                "/setting/gcal_auth_end",
                web::post().to(setting_gcal_auth_end),
            )
            .route("/system/update", web::post().to(system_update))
            .route("/secret/edit", web::post().to(secret_edit))
            .route("/secret/del", web::post().to(secret_del))
            .route("/secret/list", web::get().to(secret_list))
            .route("/secret/get", web::post().to(secret_get))
            // Registered before the plugin routes below, so a plugin cannot
            // shadow the description of the very surface it is part of.
            .route(OPENAPI_PATH, web::get().to(openapi_json))
            .route(DOCS_PATH, web::get().to(openapi_docs));
        // Set up extra protected routes
        for route in &new_routes {
            if route.1 == "post" {
                app = app.route(route.0, web::post().to(url_post_route))
            } else if route.1 == "get" {
                app = app.route(route.0, web::get().to(url_route))
            }
        }
        // Set up extra unprotected routes
        for route in &new_unprotected_routes {
            if route.1 == "post" {
                app = app.route(route.0, web::post().to(url_unprotected_post_route))
            } else if route.1 == "get" {
                app = app.route(route.0, web::get().to(url_unprotected_route))
            }
        }
        // Set up rest routes
        for route in &new_rest_routes {
            if route.1 == "post" {
                app = app.route(route.0, web::post().to(url_post_rest_route))
            } else if route.1 == "get" {
                app = app.route(route.0, web::get().to(url_rest_route))
            }
        }
        app
    })
    .bind((args.bind_addr, args.bind_port))?
    .run();
    let th = rt::spawn(srv);
    let _ = th.await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `Origin` header carries scheme, host and port — never a path and
    /// never a trailing slash — so configuration written as a URL has to be
    /// reduced to that form before it can be compared.
    #[test]
    fn origins_are_normalized_to_header_form() {
        assert_eq!(
            normalize_origin("https://app.example.com/"),
            Some("https://app.example.com".to_string())
        );
        assert_eq!(
            normalize_origin("https://app.example.com/ui/index.html"),
            Some("https://app.example.com".to_string())
        );
        assert_eq!(
            normalize_origin("  http://localhost:8081  "),
            Some("http://localhost:8081".to_string())
        );
        assert_eq!(
            normalize_origin("HTTPS://app.example.com"),
            Some("https://app.example.com".to_string())
        );
        assert_eq!(
            normalize_origin("https://app.example.com?a=b"),
            Some("https://app.example.com".to_string())
        );
    }

    /// The dev setup: UI on :8081, backend on :8090. Different origin, so the
    /// UI's origin must survive normalization intact — including its port.
    #[test]
    fn dev_ui_origin_survives() {
        assert_eq!(
            normalize_origin("http://localhost:8081"),
            Some("http://localhost:8081".to_string())
        );
    }

    #[test]
    fn malformed_origins_are_dropped() {
        assert_eq!(normalize_origin(""), None);
        assert_eq!(normalize_origin("localhost:8081"), None);
        assert_eq!(normalize_origin("https://"), None);
        assert_eq!(normalize_origin("://host"), None);
    }

    // The session cookie's attributes are the CSRF defence — there is no
    // token anywhere — so they are asserted against the real middleware
    // rather than left to a doc comment. Flipping `SameSite` back to `None`
    // must fail a test, not merely contradict a paragraph.

    /// Drive a request through `session_middleware` that writes to the
    /// session, and return the `Set-Cookie` header it emits.
    async fn set_cookie_header(cookie_http_insecure: bool) -> String {
        async fn touch(session: actix_session::Session) -> actix_web::HttpResponse {
            // The cookie is only emitted once the session is non-empty.
            session.insert("probe", "1").unwrap();
            actix_web::HttpResponse::Ok().finish()
        }

        let app = actix_web::test::init_service(
            App::new()
                .wrap(session_middleware(
                    "localhost".to_string(),
                    cookie_http_insecure,
                    Key::from(&[0u8; 64]),
                ))
                .route("/touch", web::get().to(touch)),
        )
        .await;

        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/touch")
                .to_request(),
        )
        .await;

        res.headers()
            .get("set-cookie")
            .expect("session middleware emitted no Set-Cookie")
            .to_str()
            .unwrap()
            .to_string()
    }

    /// `SameSite=Lax` is what stops a cross-site POST from carrying the
    /// session. With `None` — the previous value in every production
    /// deployment — a form on any page could invoke `/system/update` or
    /// `/itm/edit` as a logged-in admin.
    #[actix_web::test]
    async fn session_cookie_is_same_site_lax() {
        let header = set_cookie_header(false).await;
        assert!(
            header.contains("SameSite=Lax"),
            "expected SameSite=Lax, got: {}",
            header
        );
        assert!(
            !header.contains("SameSite=None"),
            "SameSite=None re-opens cross-site request forgery: {}",
            header
        );
    }

    /// `HttpOnly` keeps the cookie away from JavaScript, so an XSS bug cannot
    /// be escalated into session theft.
    #[actix_web::test]
    async fn session_cookie_is_http_only() {
        let header = set_cookie_header(false).await;
        assert!(header.contains("HttpOnly"), "got: {}", header);
    }

    /// `Secure` is tied to the deployment flag: set by default, dropped only
    /// when the operator explicitly asks for plain HTTP.
    #[actix_web::test]
    async fn session_cookie_is_secure_unless_explicitly_disabled() {
        let secure = set_cookie_header(false).await;
        assert!(secure.contains("Secure"), "got: {}", secure);

        let insecure = set_cookie_header(true).await;
        assert!(
            !insecure.contains("Secure"),
            "--cookie-http-insecure must drop Secure, got: {}",
            insecure
        );
        // Relaxing transport security must not silently relax CSRF too.
        assert!(insecure.contains("SameSite=Lax"), "got: {}", insecure);
    }

    /// Name and path are part of the contract with the frontend; the cookie
    /// has to be sent for every route, not just the one that set it.
    #[actix_web::test]
    async fn session_cookie_keeps_its_name_and_scope() {
        let header = set_cookie_header(false).await;
        assert!(header.starts_with("isabelle-cookie="), "got: {}", header);
        assert!(header.contains("Path=/"), "got: {}", header);
    }

    /// A browser session cookie carries no expiry — closing the browser ends
    /// it. `Max-Age`/`Expires` would turn it into a persistent credential on
    /// disk.
    #[actix_web::test]
    async fn session_cookie_is_not_persistent() {
        let header = set_cookie_header(false).await;
        assert!(!header.contains("Max-Age"), "got: {}", header);
        assert!(!header.contains("Expires"), "got: {}", header);
    }

    // The CORS behaviour below is what the app's availability rides on, so it
    // is exercised against the real middleware rather than reasoned about.

    type ProbeResponse =
        actix_web::dev::ServiceResponse<actix_web::body::EitherBody<actix_web::body::BoxBody>>;

    #[test]
    fn loopback_origins_are_recognised() {
        for o in [
            "http://localhost:8080",
            "http://localhost",
            "https://localhost:3000",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(is_loopback_origin(o), "{o} should be loopback");
        }
    }

    /// A name that merely contains "localhost", or any real host, must not be
    /// mistaken for the developer's own machine.
    #[test]
    fn non_loopback_origins_are_rejected() {
        for o in [
            "http://localhost.evil.com",
            "http://notlocalhost:8080",
            "http://isabelle.dev.:8080",
            "https://app.example.com",
            "file:///etc/passwd",
            "",
        ] {
            assert!(!is_loopback_origin(o), "{o} must not be loopback");
        }
    }

    async fn probe(origin: Option<&str>) -> ProbeResponse {
        let app = actix_web::test::init_service(
            App::new()
                .wrap(cors_middleware(
                    "http://localhost:8081/",
                    &["https://app.example.com".to_string()],
                    false,
                ))
                .route("/probe", web::post().to(actix_web::HttpResponse::Ok)),
        )
        .await;

        let mut req = actix_web::test::TestRequest::post().uri("/probe");
        if let Some(origin) = origin {
            req = req.insert_header(("Origin", origin));
        }
        actix_web::test::call_service(&app, req.to_request()).await
    }

    fn allow_origin(res: &ProbeResponse) -> Option<String> {
        res.headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap().to_string())
    }

    /// A same-origin request carries no `Origin` at all, or carries the
    /// deployment's own. Neither may be turned away — this is every request
    /// the UI makes.
    #[actix_web::test]
    async fn same_origin_requests_are_served() {
        let res = probe(None).await;
        assert!(res.status().is_success());

        let res = probe(Some("http://localhost:8081")).await;
        assert!(res.status().is_success());
        assert_eq!(allow_origin(&res).as_deref(), Some("http://localhost:8081"));
    }

    #[actix_web::test]
    async fn configured_extra_origin_is_allowed() {
        let res = probe(Some("https://app.example.com")).await;
        assert!(res.status().is_success());
        assert_eq!(
            allow_origin(&res).as_deref(),
            Some("https://app.example.com")
        );
    }

    /// The UI fetches with `credentials: "include"`. Without this header the
    /// browser discards the response, so the cross-origin dev setup (UI on
    /// :8081, backend on :8090) would stop working entirely.
    #[actix_web::test]
    async fn allowed_origins_may_send_credentials() {
        let res = probe(Some("http://localhost:8081")).await;
        assert_eq!(
            res.headers()
                .get("access-control-allow-credentials")
                .map(|v| v.to_str().unwrap()),
            Some("true")
        );
    }

    /// An attacker's page gets no `Access-Control-Allow-Origin`, so the
    /// browser refuses to hand it the response body. The request itself is
    /// still served: blocking it server-side would also reject same-origin
    /// POSTs, which browsers stamp with `Origin` too.
    #[actix_web::test]
    async fn unknown_origin_gets_no_cors_headers() {
        let res = probe(Some("https://evil.example.net")).await;
        assert!(res.status().is_success());
        assert_eq!(allow_origin(&res), None);
    }

    /// The old `Cors::permissive()` reflected whatever origin asked. If this
    /// ever regresses, the credentialed cross-origin read comes back.
    #[actix_web::test]
    async fn origins_are_not_reflected_blindly() {
        for origin in [
            "https://evil.example.net",
            "http://localhost:9999",
            "null",
            "http://app.example.com",
        ] {
            let res = probe(Some(origin)).await;
            assert_eq!(allow_origin(&res), None, "{} must not be reflected", origin);
        }
    }
}
