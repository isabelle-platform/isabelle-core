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
use isabelle_dm::data_model::item::Item;
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
        let field_name = field.name().to_string();
        let mut field_data: Vec<u8> = Vec::new();
        while let Ok(Some(chunk)) = field.try_next().await {
            field_data.extend_from_slice(&chunk);
        }

        if field_name == "username" {
            lu.username = std::str::from_utf8(&field_data).unwrap_or("").to_string();
        }
    }

    let srv: &crate::state::data::Data = &data.server;
    info!("User name: {}", lu.username.clone());
    let usr = get_user(srv, lu.username.clone()).await;

    if usr == None {
        info!("No user {} found, couldn't otp", lu.username.clone());
        return web::Json(ProcessResult {
            succeeded: false,
            error: "Invalid login".to_string(),
            data: HashMap::new(),
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
            call_otp_hook(srv, &route.1, new_usr_itm.clone()).await;
        }
    }

    return web::Json(ProcessResult {
        succeeded: true,
        error: "".to_string(),
        data: HashMap::new(),
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
    let mut login: String = "".to_string();
    let mut email: String = "".to_string();
    let mut dry: String = "".to_string();

    // Take the username/password from POST data
    while let Ok(Some(mut field)) = payload.try_next().await {
        let field_name = field.name().to_string();
        let mut field_data: Vec<u8> = Vec::new();
        while let Ok(Some(chunk)) = field.try_next().await {
            field_data.extend_from_slice(&chunk);
        }

        if field_name == "login" {
            login = std::str::from_utf8(&field_data).unwrap_or("").to_string();
        } else if field_name == "email" {
            email = std::str::from_utf8(&field_data).unwrap_or("").to_string();
        } else if field_name == "dry" {
            dry = std::str::from_utf8(&field_data).unwrap_or("").to_string();
        }
    }

    let srv: &crate::state::data::Data = &data.server;
    info!("User name: {}", login);
    let usr_by_login = get_user(srv, login.clone()).await;

    if let Some(ref existing) = usr_by_login {
        if existing.safe_bool("logged_once", false) {
            return web::Json(ProcessResult {
                succeeded: false,
                error: "Login is already used".to_string(),
                data: HashMap::new(),
            });
        }
    }

    let usr_by_email = get_user(srv, email.clone()).await;
    if let Some(ref existing) = usr_by_email {
        if existing.safe_bool("logged_once", false) {
            return web::Json(ProcessResult {
                succeeded: false,
                error: "Email is already used".to_string(),
                data: HashMap::new(),
            });
        }
    }

    if dry != "true" {
        // Reuse an existing pending record (logged_once == false) to avoid
        // creating a duplicate user if registration was already started once.
        let mut itm = usr_by_login.or(usr_by_email).unwrap_or_else(Item::new);

        itm.set_str("name", &login);
        itm.set_str("login", &login);
        itm.set_str("email", &email);
        itm.set_bool("role_is_active", true);

        srv.rw.set_item("user", &itm, false).await;
    }

    return web::Json(ProcessResult {
        succeeded: true,
        error: "".to_string(),
        data: HashMap::new(),
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
        let field_name = field.name().to_string();
        let mut field_data: Vec<u8> = Vec::new();
        while let Ok(Some(chunk)) = field.try_next().await {
            field_data.extend_from_slice(&chunk);
        }

        if field_name == "username" {
            lu.username = std::str::from_utf8(&field_data).unwrap_or("").to_string();
        } else if field_name == "password" {
            lu.password = std::str::from_utf8(&field_data).unwrap_or("").to_string();
        }
    }

    let srv: &crate::state::data::Data = &data.server;
    info!("User name: {}", lu.username.clone());

    // Find the user in the database
    let usr = get_user(srv, lu.username.clone()).await;

    if usr == None {
        // Not found - error out.
        info!("No user {} found, couldn't log in", lu.username.clone());
        return web::Json(ProcessResult {
            succeeded: false,
            error: "Invalid login/password".to_string(),
            data: HashMap::new(),
        });
    } else {
        let itm_real = usr.unwrap();

        // Clear the OTP data - it is no longer needed
        clear_otp(srv, lu.username.clone()).await;

        // Don't let inactive users log in.
        if itm_real.safe_bool("role_is_active", false) == false {
            info!("User {} is inactive, couldn't log in", lu.username.clone());
            return web::Json(ProcessResult {
                succeeded: false,
                error: "User is inactive".to_string(),
                data: HashMap::new(),
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
                data: HashMap::new(),
            });
        }
    }

    return web::Json(ProcessResult {
        succeeded: true,
        error: "".to_string(),
        data: HashMap::new(),
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
///
/// Lock-discipline note: this handler used to hold the global
/// `parking_lot::ReentrantMutex` across the Mongo round-trip in
/// `get_all_items("user", …)`, which serialised every concurrent request on
/// that one mutex. The body now follows a two-phase pattern:
///
///   1. Brief locked phase — read cached settings/internals (all in-memory,
///      no real awaits), compute defaults, and clone out the Mongo handle.
///   2. Lock-free phase — do the user lookup directly on the cloned Mongo
///      collection, which holds its own internal Arc to the connection pool.
///
/// Multiple concurrent `/is_logged_in` requests now overlap on Mongo I/O
/// instead of queuing on the mutex. The same pattern can (and should) be
/// applied to other read-heavy handlers in subsequent passes.
pub async fn is_logged_in(_user: Option<Identity>, data: web::Data<State>) -> impl Responder {
    let mut user = DetailedLoginUser {
        username: "".to_string(),
        id: 0,
        role: Vec::new(),
        site_name: "".to_string(),
        site_logo: "".to_string(),
        licensed_to: "".to_string(),
        params: HashMap::new(),
    };

    // Phase 1: under the lock, read in-memory caches and clone the Mongo
    // handles we'll need. No real awaits here — `get_settings`/`get_internals`
    // are sync I/O wrapped in async-trait, and Client::clone is just an
    // Arc bump. The lock guard is dropped at the end of this block.
    #[cfg(not(feature = "full_file_database"))]
    let mongo_view: Option<(mongodb::Client, String, String)> = {
        let srv: &crate::state::data::Data = &data.server;

        let settings = srv.rw.get_settings().await;
        let internals = srv.rw.get_internals().await;

        let pick = |key: &str, default_key: &str, default_value: &str| {
            let s = settings.safe_str(key, "");
            if s.is_empty() {
                internals.safe_str(default_key, default_value)
            } else {
                s
            }
        };
        user.site_name = pick("site_name", "default_site_name", "Isabelle");
        user.site_logo = pick("site_logo", "default_site_logo", "/logo.png");
        user.licensed_to = pick("licensed_to", "default_licensed_to", "end user");
        let language = pick("language", "default_language", "en");
        user.params.insert("language".to_string(), language);

        info!("Site logo: {}", user.site_logo);

        if _user.is_none() || !srv.has_collection("user") {
            info!("No user or user database");
            None
        } else {
            let role_is = internals.safe_str("user_role_prefix", "role_is_");
            match srv.rw.client.as_ref() {
                Some(c) => Some((c.clone(), srv.rw.database_name.clone(), role_is)),
                None => None,
            }
        }
    }; // ← lock released here

    #[cfg(feature = "full_file_database")]
    let _ = data;

    // Phase 2: lock-free Mongo lookup. Concurrent requests parallelise here.
    #[cfg(not(feature = "full_file_database"))]
    if let Some((client, db_name, role_is)) = mongo_view {
        let email = _user.as_ref().unwrap().id().unwrap();
        if !login_has_bad_symbols(&email) {
            let coll: mongodb::Collection<crate::util::bson_wrapper::BsonItem> =
                client.database(&db_name).collection("user");
            let filter = mongodb::bson::doc! { "strs.email": &email };
            if let Ok(Some(bson_item)) = coll.find_one(filter).await {
                let item: Item = bson_item.into();
                if item.strs.get("email").map(String::as_str) == Some(email.as_str()) {
                    user.username = email.clone();
                    user.id = item.id;
                    // Derive roles from bool flags with prefix `role_is_...`.
                    //
                    // Important: avoid granting "admin" unless role_is_admin
                    // is explicitly true. Previously we pushed every role
                    // key regardless of its boolean value, which caused
                    // non-admin users (role_is_admin=false) to still receive
                    // "admin" in /is_logged_in payload, leading to incorrect
                    // UI gating.
                    for bp in &item.bools {
                        if bp.0.starts_with(&role_is) {
                            if bp.0 == "role_is_admin" && !*bp.1 {
                                continue;
                            }
                            if *bp.1 {
                                user.role.push(bp.0[8..].to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    // File-store path: fall back to the original lock-held flow. StoreLocal
    // doesn't speak Mongo so we can't split the same way. Same correctness,
    // unchanged perf — this feature is sample/test only.
    #[cfg(feature = "full_file_database")]
    {
        let srv: &crate::state::data::Data = &data.server;
        let settings = srv.rw.get_settings().await;
        let internals = srv.rw.get_internals().await;
        let pick = |key: &str, default_key: &str, default_value: &str| {
            let s = settings.safe_str(key, "");
            if s.is_empty() {
                internals.safe_str(default_key, default_value)
            } else {
                s
            }
        };
        user.site_name = pick("site_name", "default_site_name", "Isabelle");
        user.site_logo = pick("site_logo", "default_site_logo", "/logo.png");
        user.licensed_to = pick("licensed_to", "default_licensed_to", "end user");
        let language = pick("language", "default_language", "en");
        user.params.insert("language".to_string(), language);
        if _user.is_some() && srv.has_collection("user") {
            let role_is = internals.safe_str("user_role_prefix", "role_is_");
            let email = _user.as_ref().unwrap().id().unwrap();
            if !login_has_bad_symbols(&email) {
                let filter =
                    "{ \"strs.email\": \"".to_owned() + &email + "\" }";
                let all_users =
                    srv.rw.get_all_items("user", "name", &filter).await;
                for item in &all_users.map {
                    if item.1.strs.get("email").map(String::as_str)
                        == Some(email.as_str())
                    {
                        user.username = email.clone();
                        user.id = *item.0;
                        for bp in &item.1.bools {
                            if bp.0.starts_with(&role_is) {
                                if bp.0 == "role_is_admin" && !*bp.1 {
                                    continue;
                                }
                                if *bp.1 {
                                    user.role.push(bp.0[8..].to_string());
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    web::Json(user)
}
