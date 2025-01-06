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
mod server;
mod state;
mod util;

use crate::handler::route::url_post_route;
use crate::handler::route::url_route;
use crate::handler::route::url_unprotected_post_route;
use crate::handler::route::url_unprotected_route;
use crate::handler::route_call::call_periodic_job_hook;
use crate::notif::gcal::*;
use crate::server::itm::*;
use crate::server::login::*;
use crate::server::user_control::*;
use std::collections::HashMap;

use crate::server::setting::*;

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

    {
        let srv_lock = G_STATE.server.lock();
        let mut srv_mut = srv_lock.borrow_mut();
        let mut srv = srv_mut.deref_mut();

        srv.gc_path = args.gc_path.to_string();
        srv.py_path = args.py_path.to_string();
        srv.data_path = args.data_path.to_string();
        srv.public_url = args.pub_url.to_string();
        srv.port = args.bind_port;

        info!("Data storage: connecting");
        // Put options to internal structures and connect to database
        #[cfg(not(feature = "full_file_database"))]
        {
            srv.file_rw.connect(&args.data_path, "").await;
            srv.rw.database_name = args.db_name.clone();
            srv.rw.connect(&args.db_url, &args.data_path).await;
        }

        info!("Data storage: connected");

        #[cfg(feature = "full_file_database")]
        {
            info!(
                "Database url {} name {} unused",
                database_name.clone(),
                db_url.clone()
            );
            srv.rw.connect(&data_path, "").await;
        }

        // Load plugins
        info!("Plugins: loading");
        {
            let s = &mut srv;
            s.plugin_pool.load_plugins(&args.plugin_dir);
            info!("Plugins: ensuring operation");
            s.plugin_pool.ping_plugins();
        }
        info!("Plugins: loaded");

        // Perform initialization checks, etc.
        info!("Flow: performing initialization checks");
        srv.init_checks().await;
        info!("Flow: performed initialization checks");

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

        // If it is a first run, merge database.
        #[cfg(not(feature = "full_file_database"))]
        if args.first_run {
            let m = &mut srv;
            info!("Flow: first run - merge database and exit");
            merge_database(&mut m.file_rw, &mut m.rw).await;
        }
    }

    // If it is first run, don't do anything else
    if args.first_run {
        return Ok(());
    }

    let data = Data::new(G_STATE.clone());
    let data_clone = data.clone();
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
            .route("/gen_otp", web::post().to(gen_otp))
            .route("/logout", web::post().to(logout))
            .route("/is_logged_in", web::get().to(is_logged_in))
            .route("/setting/edit", web::post().to(setting_edit))
            .route("/setting/list", web::get().to(setting_list))
            .route("/setting/gcal_auth", web::post().to(setting_gcal_auth))
            .route(
                "/setting/gcal_auth_end",
                web::post().to(setting_gcal_auth_end),
            );
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
        app
    })
    .bind((args.bind_addr, args.bind_port))?
    .run();
    let th = rt::spawn(srv);
    let _ = th.await;

    Ok(())
}
