mod handler;
mod notif;
mod server;
mod state;

use crate::handler::route::url_route;
use std::collections::HashMap;
use crate::notif::gcal::init_google;
use crate::server::itm::*;
use crate::server::login::*;

use crate::server::setting::*;
use crate::state::data_rw::*;
use crate::state::state::*;
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_session::config::{BrowserSession, CookieContentSecurity};
use actix_session::storage::CookieSessionStore;
use actix_session::SessionMiddleware;
use actix_web::web::Data;
use actix_web::{cookie::Key, cookie::SameSite, web, App, HttpServer};
use log::info;
use std::env;
use std::ops::DerefMut;

fn session_middleware() -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(CookieSessionStore::default(), Key::from(&[0; 64]))
        .session_lifecycle(BrowserSession::default())
        .cookie_same_site(SameSite::None)
        .cookie_path("/".into())
        .cookie_name(String::from("isabelle-cookie"))
        .cookie_domain(Some("localhost".into()))
        .cookie_content_security(CookieContentSecurity::Private)
        .cookie_http_only(true)
        .cookie_secure(true)
        .build()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut gc_path: String = "".to_string();
    let mut py_path: String = "".to_string();
    let mut data_path: String = "sample-data".to_string();
    let mut pub_path: String = "http://localhost:8081".to_string();
    let mut port: u16 = 8090;
    let mut gc_next = false;
    let mut py_next = false;
    let mut data_next = false;
    let mut pub_next = false;
    let mut port_next = false;

    for arg in args {
        if gc_next {
            gc_path = arg.clone();
            gc_next = false;
        } else if py_next {
            py_path = arg.clone();
            py_next = false;
        } else if data_next {
            data_path = arg.clone();
            data_next = false;
        } else if pub_next {
            pub_path = arg.clone();
            pub_next = false;
        } else if port_next {
            port = arg.parse().unwrap();
            port_next = false;
        }

        if arg == "--gc-path" {
            gc_next = true;
        } else if arg == "--py-path" {
            py_next = true;
        } else if arg == "--data-path" {
            data_next = true;
        } else if arg == "--pub-url" {
            pub_next = true;
        }
    }

    env_logger::init();

    let mut new_routes : HashMap<String, String> = HashMap::new();
    let state = State::new();
    {
        let mut srv = state.server.lock().unwrap();
        {
            *srv.deref_mut() = read_data(&data_path);
            (*srv.deref_mut()).gc_path = gc_path.to_string();
            (*srv.deref_mut()).py_path = py_path.to_string();
            (*srv.deref_mut()).data_path = data_path.to_string();
            (*srv.deref_mut()).public_url = pub_path.to_string();
            (*srv.deref_mut()).port = port;

            info!("Initializing google!");
            let res = init_google(srv.deref_mut());
            info!("Result: {}", res);

            let routes = (*srv.deref_mut()).internals.safe_strstr("extra_route", &HashMap::new());
            for route in routes {
                let parts: Vec<&str> = route.1.split(":").collect();
                new_routes.insert(parts[0].to_string(), parts[1].to_string());
                info!("Route: {} : {}", parts[0], parts[1]);
            }
        }
    }

    let data = Data::new(state);
    info!("Starting server");
    HttpServer::new(move || {
        let mut app = App::new()
            .app_data(data.clone())
            .wrap(Cors::permissive())
            .wrap(IdentityMiddleware::default())
            .wrap(session_middleware())
            .route("/itm/edit", web::post().to(itm_edit))
            .route("/itm/del", web::post().to(itm_del))
            .route("/itm/list", web::get().to(itm_list))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/is_logged_in", web::get().to(is_logged_in))
            .route("/setting/edit", web::post().to(setting_edit))
            .route("/setting/list", web::get().to(setting_list))
            .route("/setting/gcal_auth", web::post().to(setting_gcal_auth))
            .route(
                "/setting/gcal_auth_end",
                web::post().to(setting_gcal_auth_end),
            );
        for route in &new_routes {
            if route.1 == "post" {
                app = app.route(route.0, web::post().to(url_route))
            } else if route.1 == "get" {
                app = app.route(route.0, web::get().to(url_route))
            }
        }
        app
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
