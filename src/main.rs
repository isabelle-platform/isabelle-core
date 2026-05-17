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
use crate::args::Args;
use chrono::Timelike;
#[macro_use]
extern crate lazy_static;
use crate::util::crypto::*;
use chrono::{FixedOffset, Local};
use cron::Schedule;
use std::{str::FromStr, time::Duration};

use crate::notif::email::send_email;

#[cfg(not(feature = "full_file_database"))]
use crate::state::merger::merge_database;
use crate::state::store::Store;

mod args;
mod handler;
mod notif;
#[cfg(feature = "actor-demo")]
mod plugin_actor_demo;
mod server;
mod state;
mod util;

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
use crate::server::user_control::*;
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
use std::ops::DerefMut;
use std::thread;

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
    static ref G_STATE : State = State::new();
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    env_logger::init();

    // Routes: they must be collected here in order to be set up in Actix
    let mut new_routes: HashMap<String, String> = HashMap::new();
    let mut new_unprotected_routes: HashMap<String, String> = HashMap::new();
    let mut new_rest_routes: HashMap<String, String> = HashMap::new();

    {
        let srv_lock = G_STATE.server.lock();
        let mut srv_mut = srv_lock.borrow_mut();
        let mut srv = srv_mut.deref_mut();

        srv.gc_path = args.gc_path.to_string();
        srv.py_path = args.py_path.to_string();
        srv.data_path = args.data_path.to_string();
        srv.public_url = args.pub_url.to_string();
        srv.port = args.bind_port;
        srv.max_payload_bytes = args.max_payload_bytes;
        srv.update_script = args.update_script.to_string();

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
                srv.secrets = Some(s);
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
            srv.file_rw.connect(&args.data_path, "").await;
            srv.rw.database_name = args.db_name.clone();
            srv.rw.connect(&args.db_url, &args.data_path).await;

            // First-run autodetect: if the target database has no collections,
            // seed it from the file-backed store. Idempotent across restarts:
            // once seeded, the database is non-empty and this is a no-op.
            if srv.rw.get_collections().await.is_empty() {
                info!("Flow: empty database detected, seeding from file store");
                merge_database(&mut srv.file_rw, &mut srv.rw).await;
                info!("Flow: seeding complete");
            }
        }

        info!("Data storage: connected");

        #[cfg(feature = "full_file_database")]
        {
            srv.rw.connect(&args.data_path, "").await;
        }

        // Spawn the core processing task — it owns the inbox for the new
        // actor-model `CoreMessage`s and processes them against `Data`.
        // The returned `CoreHandle` is stored on `srv` so actor plugins
        // (registered below) can clone it at register time.
        srv.core_handle = Some(crate::state::core_task::spawn_core_task(G_STATE.clone()));

        // Register statically-linked plugins. Each plugin's `register` is
        // compiled into the core binary; which ones are included is decided
        // at build time via cargo features (see Cargo.toml `[features]`).
        info!("Plugins: registering");
        {
            let s = &mut srv;
            let before = s.plugin_pool.plugins.len();
            // Security registers either via trait (default) or actor mode,
            // controlled by mutually-exclusive features. Both wired off the
            // same dep so there's no double-link.
            #[cfg(all(feature = "plugin-security", not(feature = "plugin-security-actor")))]
            isabelle_plugin_security::register(&mut s.plugin_pool);
            #[cfg(feature = "plugin-security-actor")]
            {
                if let Some(core) = s.core_handle.clone() {
                    isabelle_plugin_security::register_actor(&mut s.plugin_registry, core);
                }
            }
            #[cfg(feature = "plugin-midair")]
            isabelle_plugin_midair::register(&mut s.plugin_pool);

            // Phase 3 pilot: register the actor-mode demo plugin.
            #[cfg(feature = "actor-demo")]
            {
                if let Some(core) = s.core_handle.clone() {
                    let _stats = crate::plugin_actor_demo::register_demo(
                        &mut s.plugin_registry,
                        core,
                    );
                    // We drop _stats — the demo plugin keeps the Arc'd
                    // counters; nobody is reading them from production. The
                    // tests instantiate their own demo and keep the handle.
                }
            }

            let registered = s.plugin_pool.plugins.len() - before;
            info!(
                "Plugins: {} registered (trait), {} registered (actor)",
                registered,
                s.plugin_registry.len()
            );
            info!("Plugins: ensuring operation");
            s.plugin_pool.ping_plugins();
        }
        info!("Plugins: loaded");

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
        init_google(&mut srv).await;
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
        let srv_lock = G_STATE.server.lock();
        let mut srv_mut = srv_lock.borrow_mut();
        let srv = srv_mut.deref_mut();
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
                    let srv_lock = data_clone.server.lock();
                    let mut srv = srv_lock.borrow_mut();
                    if local.time().second() == 0 {
                        call_periodic_job_hook(&mut srv, "min");
                    }
                    call_periodic_job_hook(&mut srv, "sec");
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
