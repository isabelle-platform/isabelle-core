use crate::server::user_control::*;
use crate::state::state::*;
use actix_identity::Identity;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use isabelle_dm::data_model::login_user::LoginUser;
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_qs;

pub async fn login(
    _user: Option<Identity>,
    data: web::Data<State>,
    req: HttpRequest,
) -> impl Responder {
    let srv = data.server.lock().unwrap();
    let lu = serde_qs::from_str::<LoginUser>(&req.query_string()).unwrap();
    let usr = get_user(&srv, lu.username.clone());

    if usr == None {
        info!("No user found, couldn't log in");
    } else {
        let itm_real = usr.unwrap();

        if itm_real.strs.contains_key("password")
            && itm_real.safe_str("password", "") == lu.password
        {
            Identity::login(&req.extensions(), lu.username.clone()).unwrap();
            info!("Logged in as {}", lu.username);
        } else {
            error!("Invalid password for {}", lu.username);
        }
    }

    HttpResponse::Ok()
}

pub async fn logout(
    _user: Identity,
    _data: web::Data<State>,
    _request: HttpRequest,
) -> impl Responder {
    _user.logout();
    info!("Logged out");

    HttpResponse::Ok()
}

pub async fn is_logged_in(_user: Option<Identity>, data: web::Data<State>) -> impl Responder {
    let srv = data.server.lock().unwrap();

    #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
    pub struct LoginUser {
        pub username: String,
        pub id: u64,
        pub role: Vec<String>,
        pub site_name: String,
        pub site_logo: String,
        pub licensed_to: String,
    }

    let mut user: LoginUser = LoginUser {
        username: "".to_string(),
        id: 0,
        role: Vec::new(),
        site_name: "".to_string(),
        site_logo: "".to_string(),
        licensed_to: "".to_string(),
    };

    user.site_name = srv.settings.clone().safe_str("site_name",
        &srv.internals.safe_str("default_site_name", "Isabelle"));

    user.site_logo = srv.settings.clone().safe_str("site_logo",
        &srv.internals.safe_str("default_site_logo", "logo.png"));

    user.licensed_to = srv.settings.clone().safe_str("licensed_to",
        &srv.internals.safe_str("default_licensed_to", "end user"));

    if _user.is_none() || !srv.itm.contains_key("user") {
        info!("No user or user database");
        return web::Json(user);
    }

    for item in srv.itm["user"].get_all() {
        if item.1.strs.contains_key("login")
            && item.1.strs["login"] == _user.as_ref().unwrap().id().unwrap()
        {
            user.username = _user.as_ref().unwrap().id().unwrap();
            user.id = *item.0;
            for bp in &item.1.bools {
                if bp.0.starts_with("role_is_") {
                    user.role.push(bp.0[8..].to_string());
                }
            }
            break;
        }
    }

    web::Json(user)
}