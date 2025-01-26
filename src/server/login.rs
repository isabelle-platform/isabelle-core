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
use isabelle_dm::data_model::item::Item;
use crate::handler::route_call::*;
use crate::server::user_control::*;
use crate::state::state::*;
use crate::state::store::Store;
use crate::util::crypto::get_otp_code;
use crate::util::crypto::verify_password;
use actix_identity::Identity;
use actix_multipart::Multipart;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use futures_util::TryStreamExt;
use isabelle_dm::data_model::process_result::ProcessResult;
use isabelle_dm::transfer_model::detailed_login_user::DetailedLoginUser;
use isabelle_dm::transfer_model::login_user::LoginUser;
use log::{error, info};
use std::collections::HashMap;

/// Generate one-time password for the user.
pub async fn gen_otp(
    _user: Option<Identity>,
    data: web::Data<State>,
    mut payload: Multipart,
    _req: HttpRequest,
) -> impl Responder {
    let mut lu = LoginUser {
        username: "".to_string(),
        password: "".to_string(),
    };

    while let Ok(Some(mut field)) = payload.try_next().await {
        while let Ok(Some(chunk)) = field.try_next().await {
            let data = chunk;

            if field.name() == "username" {
                lu.username = std::str::from_utf8(&data.to_vec()).unwrap().to_string();
            }
        }
    }

    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    info!("User name: {}", lu.username.clone());
    let usr = get_user(&mut srv, lu.username.clone()).await;

    if usr == None {
        info!("No user {} found, couldn't otp", lu.username.clone());
        return web::Json(ProcessResult {
            succeeded: false,
            error: "Invalid login".to_string(),
        });
    } else {
        let mut new_usr_itm = srv
            .rw
            .get_item("user", usr.clone().unwrap().id)
            .await
            .unwrap();
        new_usr_itm.set_str("otp", &get_otp_code());
        srv.rw.set_item("user", &new_usr_itm, false).await;

        let routes = srv
            .rw
            .get_internals()
            .await
            .safe_strstr("otp_hook", &HashMap::new());
        for route in routes {
            call_otp_hook(&mut srv, &route.1, new_usr_itm.clone()).await;
        }
    }

    return web::Json(ProcessResult {
        succeeded: true,
        error: "".to_string(),
    });
}

/// Log in into the system using username/password pair provided inside the
/// POST data.
pub async fn register(
    _user: Option<Identity>,
    data: web::Data<State>,
    mut payload: Multipart,
    _req: HttpRequest,
) -> impl Responder {
    let mut login : String = "".to_string();
    let mut email : String = "".to_string();
    let mut dry : String = "".to_string();

    // Take the username/password from POST data
    while let Ok(Some(mut field)) = payload.try_next().await {
        while let Ok(Some(chunk)) = field.try_next().await {
            let data = chunk;

            if field.name() == "login" {
                login = std::str::from_utf8(&data.to_vec()).unwrap().to_string();
            } else if field.name() == "email" {
                email = std::str::from_utf8(&data.to_vec()).unwrap().to_string();
            } else if field.name() == "dry" {
                dry = std::str::from_utf8(&data.to_vec()).unwrap().to_string();
            }
        }
    }

    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    info!("User name: {}", login);
    let mut usr = get_user(&mut srv, login.clone()).await;

    if usr.is_some() {
        if usr.unwrap().safe_bool("logged_once", false) {
            return web::Json(ProcessResult {
                succeeded: false,
                error: "Login is already used".to_string(),
            });
        }
    }

    usr = get_user(&mut srv, email.clone()).await;
    if usr.is_some() {
        if usr.unwrap().safe_bool("logged_once", false) {
            return web::Json(ProcessResult {
                succeeded: false,
                error: "Email is already used".to_string(),
            });
        }
    }

    if dry != "true" {
        let mut itm = Item::new();

        itm.set_str("name", &login);
        itm.set_str("login", &login);
        itm.set_str("email", &email);
        itm.set_bool("role_is_active", true);

        srv.rw.set_item("user", &itm, false).await;
    }

    return web::Json(ProcessResult {
        succeeded: true,
        error: "".to_string(),
    });
}

/// Log in into the system using username/password pair provided inside the
/// POST data.
pub async fn login(
    _user: Option<Identity>,
    data: web::Data<State>,
    mut payload: Multipart,
    req: HttpRequest,
) -> impl Responder {
    let mut lu = LoginUser {
        username: "".to_string(),
        password: "".to_string(),
    };

    // Take the username/password from POST data
    while let Ok(Some(mut field)) = payload.try_next().await {
        while let Ok(Some(chunk)) = field.try_next().await {
            let data = chunk;

            if field.name() == "username" {
                lu.username = std::str::from_utf8(&data.to_vec()).unwrap().to_string();
            } else if field.name() == "password" {
                lu.password = std::str::from_utf8(&data.to_vec()).unwrap().to_string();
            }
        }
    }

    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    info!("User name: {}", lu.username.clone());

    // Find the user in the database
    let usr = get_user(&mut srv, lu.username.clone()).await;

    if usr == None {
        // Not found - error out.
        info!("No user {} found, couldn't log in", lu.username.clone());
        return web::Json(ProcessResult {
            succeeded: false,
            error: "Invalid login/password".to_string(),
        });
    } else {
        let itm_real = usr.unwrap();

        // Clear the OTP data - it is no longer needed
        clear_otp(&mut srv, lu.username.clone()).await;

        // Don't let inactive users log in.
        if itm_real.safe_bool("role_is_active", false) == false {
            info!("User {} is inactive, couldn't log in", lu.username.clone());
            return web::Json(ProcessResult {
                succeeded: false,
                error: "User is inactive".to_string(),
            });
        }

        // Verify password/otp
        let pw = itm_real.safe_str("password", "");
        let otp = itm_real.safe_str("otp", "");
        if (pw != "" && verify_password(&lu.password, &pw)) || (otp != "" && lu.password == otp) {
            // Password matches - log in.
            Identity::login(&req.extensions(), itm_real.safe_str("email", "")).unwrap();

            let mut logged = Item::new();
            logged.id = itm_real.id;
            logged.set_bool("logged_once", true);
            srv.rw.set_item("user", &logged, true).await;
            info!("Logged in as {}", lu.username);
        } else {
            // Password doesn't match - error out.
            error!("Invalid password for {}", lu.username);
            return web::Json(ProcessResult {
                succeeded: false,
                error: "Invalid login/password".to_string(),
            });
        }
    }

    return web::Json(ProcessResult {
        succeeded: true,
        error: "".to_string(),
    });
}

/// Log the user out.
pub async fn logout(
    _user: Identity,
    _data: web::Data<State>,
    _request: HttpRequest,
) -> impl Responder {
    _user.logout();
    info!("Logged out");

    HttpResponse::Ok()
}

/// Check if the user is logged in. Additionally, this function returns a json
/// with a few more basic site settings and user roles.
pub async fn is_logged_in(_user: Option<Identity>, data: web::Data<State>) -> impl Responder {
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();

    let mut user: DetailedLoginUser = DetailedLoginUser {
        username: "".to_string(),
        id: 0,
        role: Vec::new(),
        site_name: "".to_string(),
        site_logo: "".to_string(),
        licensed_to: "".to_string(),
    };

    user.site_name = srv
        .rw
        .get_settings()
        .await
        .clone()
        .safe_str("site_name", "");
    if user.site_name == "" {
        user.site_name = srv
            .rw
            .get_internals()
            .await
            .safe_str("default_site_name", "Isabelle");
    }

    user.site_logo = srv
        .rw
        .get_settings()
        .await
        .clone()
        .safe_str("site_logo", "");
    if user.site_logo == "" {
        user.site_logo = srv
            .rw
            .get_internals()
            .await
            .safe_str("default_site_logo", "/logo.png");
    }
    info!("Site logo: {}", user.site_logo);

    user.licensed_to = srv
        .rw
        .get_settings()
        .await
        .clone()
        .safe_str("licensed_to", "");
    if user.licensed_to == "" {
        user.licensed_to = srv
            .rw
            .get_internals()
            .await
            .safe_str("default_licensed_to", "end user");
    }

    if _user.is_none() || !srv.has_collection("user") {
        info!("No user or user database");
        return web::Json(user);
    }

    let role_is = srv
        .rw
        .get_internals()
        .await
        .safe_str("user_role_prefix", "role_is_");
    let email = _user.as_ref().unwrap().id().unwrap();
    if !login_has_bad_symbols(&email) {
        let filter = "{ \"strs.email\": \"".to_owned() + &email + "\" }";
        let all_users = srv.rw.get_all_items("user", "name", &filter).await;
        for item in &all_users.map {
            if item.1.strs.contains_key("email") && item.1.strs["email"] == email {
                user.username = _user.as_ref().unwrap().id().unwrap();
                user.id = *item.0;
                for bp in &item.1.bools {
                    if bp.0.starts_with(&role_is) {
                        user.role.push(bp.0[8..].to_string());
                    }
                }
                break;
            }
        }
    }

    web::Json(user)
}
