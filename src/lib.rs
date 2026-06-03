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

#[macro_use]
extern crate lazy_static;

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
use crate::server::itm::*;
use crate::server::login::*;
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
use actix_web::web::Data;
use actix_web::{cookie::Key, cookie::SameSite, rt, web, App, HttpServer};
use clap::Parser;
use log::info;
use std::thread;

/// Re-exported actor-mode types so shell binaries don't have to add their
/// own `isabelle-plugin-api` dependency just for the closure signature.
pub use isabelle_plugin_api::actor::{CoreHandle, PluginRegistry};

/// Session middleware based on cookies
fn session_middleware(
    _pub_fqdn: String,
    cookie_http_insecure: bool,
) -> SessionMiddleware<CookieSessionStore> {
    let same_site = if cookie_http_insecure {
        SameSite::Lax
    } else {
        SameSite::None
    };
    SessionMiddleware::builder(CookieSessionStore::default(), Key::from(&[0; 64]))
        .session_lifecycle(BrowserSession::default())
        .cookie_same_site(same_site)
        .cookie_path("/".into())
        .cookie_name(String::from("isabelle-cookie"))
        .cookie_content_security(CookieContentSecurity::Private)
        .cookie_http_only(true)
        .cookie_secure(!cookie_http_insecure)
        .build()
}

lazy_static! {
    /// Global state
    pub(crate) static ref G_STATE: State = State::new();
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

    {
        let srv: &crate::state::data::Data = &G_STATE.server;
        // SAFETY: this is the single-threaded startup phase. No other code
        // observes `Data` yet — actix HTTP workers and core_task haven't
        // started. We mutate the remaining `&mut`-only fields (`file_rw`,
        // `rw.database_name`, `rw.connect`'s internals, `core_handle`)
        // through a raw pointer aliasing the Arc<Data>'s payload.
        #[allow(invalid_reference_casting)]
        let srv_mut: &mut crate::state::data::Data = unsafe {
            &mut *(srv as *const crate::state::data::Data as *mut crate::state::data::Data)
        };

        *srv.gc_path.lock() = args.gc_path.to_string();
        *srv.py_path.lock() = args.py_path.to_string();
        *srv.data_path.lock() = args.data_path.to_string();
        *srv.public_url.lock() = args.pub_url.to_string();
        srv.port
            .store(args.bind_port, std::sync::atomic::Ordering::Relaxed);
        srv.max_payload_bytes
            .store(args.max_payload_bytes, std::sync::atomic::Ordering::Relaxed);
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

        info!("Data storage: connecting");
        // Put options to internal structures and connect to database
        #[cfg(not(feature = "full_file_database"))]
        {
            srv_mut.file_rw.connect(&args.data_path, "").await;
            srv_mut.rw.database_name = args.db_name.clone();
            srv_mut.rw.connect(&args.db_url, &args.data_path).await;

            // First-run autodetect: seed from the file-backed store when the
            // database holds no data yet. We must check for *items*, not
            // collections: connect() above pre-creates the declared (but empty)
            // collections from internals.js, so get_collections() is never empty
            // here. Idempotent across restarts: once seeded, this is a no-op.
            let mut has_data = false;
            for coll in srv.rw.get_collections().await {
                if srv
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
                merge_database(&mut srv_mut.file_rw, &mut srv_mut.rw).await;
                info!("Flow: seeding complete");
            }
        }

        info!("Data storage: connected");

        #[cfg(feature = "full_file_database")]
        {
            srv_mut.rw.connect(&args.data_path, "").await;
        }

        // Spawn the core processing task — it owns the inbox for the new
        // actor-model `CoreMessage`s and processes them against `Data`.
        // The returned `CoreHandle` is stored on `srv` so the caller's
        // setup closure (and the plugins it registers) can clone it.
        let core_handle = crate::state::core_task::spawn_core_task(G_STATE.clone());
        srv_mut.core_handle = Some(core_handle.clone());

        // Hand control to the deployment-specific shell binary so it can
        // register whichever plugins it links against.
        info!("Plugins: registering");
        setup(&mut srv_mut.plugin_registry, &core_handle);
        info!("Plugins: {} registered", srv_mut.plugin_registry.len());

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

    let data = Data::new(G_STATE.clone());
    let data_clone = data.clone();

    {
        let srv: &crate::state::data::Data = &G_STATE.server;
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
        let mut app = App::new()
            .app_data(data.clone())
            .app_data(web::PayloadConfig::new(args.max_payload_bytes))
            .wrap(Cors::permissive())
            .wrap(IdentityMiddleware::default())
            .wrap(session_middleware(
                args.pub_fqdn.clone(),
                args.cookie_http_insecure,
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
            .route("/secret/get", web::post().to(secret_get));
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
