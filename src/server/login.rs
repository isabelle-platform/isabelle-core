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
use crate::server::guards::SESSION_GEN_KEY;
use crate::server::user_control::*;
use crate::state::state::*;
use crate::state::store::Store;
use crate::util::crypto::constant_time_eq;
use crate::util::crypto::get_otp_code;
use crate::util::crypto::verify_password;
use crate::util::multipart::{field_str, read_fields, Limits};
use actix_identity::Identity;
use actix_multipart::Multipart;
use actix_session::SessionExt;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use isabelle_dm::transfer_model::detailed_login_user::DetailedLoginUser;
use isabelle_dm::transfer_model::login_user::LoginUser;
use log::{error, info};
use std::collections::HashMap;

/// The JSON envelope these endpoints answer with, at a chosen status.
///
/// A body that could not be read is the request's own fault and gets a 4xx;
/// everything else keeps the 200-with-`succeeded:false` shape clients already
/// parse, so a rejected login still reads the same as before.
fn result_json(status: actix_web::http::StatusCode, succeeded: bool, error: &str) -> HttpResponse {
    HttpResponse::build(status).json(ProcessResult {
        succeeded,
        error: error.to_string(),
        data: HashMap::new(),
    })
}

fn ok_json(succeeded: bool, error: &str) -> HttpResponse {
    result_json(actix_web::http::StatusCode::OK, succeeded, error)
}

/// Generate one-time password for the user.
pub async fn gen_otp(
    _user: Option<Identity>,
    data: web::Data<State>,
    mut payload: Multipart,
    _req: HttpRequest,
) -> impl Responder {
    let srv: &crate::state::data::Data = &data.server;
    let fields = match read_fields(&mut payload, Limits::from_data(srv)).await {
        Ok(f) => f,
        Err(e) => {
            error!("Could not read the gen_otp body: {}", e);
            return result_json(e.status(), false, "Malformed request");
        }
    };
    let lu = LoginUser {
        username: field_str(&fields, "username"),
        password: "".to_string(),
    };

    info!("User name: {}", lu.username.clone());
    let usr = get_user(srv, lu.username.clone()).await;

    // Everything below is silent about its outcome: the response is identical
    // whether or not the account exists, is active, or is being throttled.
    // Otherwise this endpoint is a free oracle for enumerating logins.
    if let Some(usr) = usr {
        let now = now_ts();
        // An inactive account — one an operator provisioned but never
        // activated — has no OTP path at all: the code would be a credential
        // for an account its owner has never touched. The throttle bounds both
        // mail-bombing and repeated re-rolls of a code being brute-forced.
        if !otp_may_be_issued(&usr, now) {
            info!("OTP not issued for {}", lu.username);
        } else if let Some(mut new_usr_itm) = srv.rw.get_item("user", usr.id).await {
            new_usr_itm.set_str("otp", &get_otp_code());
            new_usr_itm.set_u64("otp_issued_at", now);
            new_usr_itm.set_u64("otp_expires_at", now + OTP_TTL_SECS);
            new_usr_itm.set_u64("otp_attempts", 0);
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
    } else {
        info!("No user {} found, couldn't otp", lu.username.clone());
    }

    return ok_json(true, "");
}

/// Log in into the system using username/password pair provided inside the
/// POST data.
pub async fn register(
    _user: Option<Identity>,
    data: web::Data<State>,
    mut payload: Multipart,
    _req: HttpRequest,
) -> impl Responder {
    let srv: &crate::state::data::Data = &data.server;

    // Take the registration details from POST data
    let fields = match read_fields(&mut payload, Limits::from_data(srv)).await {
        Ok(f) => f,
        Err(e) => {
            error!("Could not read the register body: {}", e);
            return result_json(e.status(), false, "Malformed request");
        }
    };
    let login = field_str(&fields, "login");
    let email = field_str(&fields, "email");
    let dry = field_str(&fields, "dry");

    info!("User name: {}", login);

    // Reject logins/emails that `get_user` cannot look up. Without this a
    // login containing `$` or `{` reports as free (the lookup returns None),
    // creating a record that no later lookup can ever find again.
    if !login_is_acceptable(&login) || !login_is_acceptable(&email) {
        return ok_json(false, "Invalid login or email");
    }

    if !srv
        .rw
        .get_internals()
        .await
        .safe_bool("allow_self_registration", true)
    {
        info!("Self-registration is disabled, rejecting {}", login);
        return ok_json(false, "Registration is disabled");
    }

    let usr_by_login = get_user(srv, login.clone()).await;
    let usr_by_email = get_user(srv, email.clone()).await;

    let target = registration_target(&usr_by_login, &usr_by_email);
    if target == RegistrationTarget::Taken {
        info!("Login or email is already taken: {}", login);
        return ok_json(false, "Login is already used");
    }

    // Only ever create. A `Resume` is an exact re-submit of a registration
    // that is already on disk, so there is nothing left to write.
    if dry != "true" && target == RegistrationTarget::Create {
        let mut itm = Item::new();

        itm.set_str("name", &login);
        itm.set_str("login", &login);
        itm.set_str("email", &email);
        itm.set_bool("self_registered", true);
        itm.set_bool("role_is_active", true);

        srv.rw.set_item("user", &itm, false).await;
    }

    return ok_json(true, "");
}

/// Log in into the system using username/password pair provided inside the
/// POST data.
pub async fn login(
    _user: Option<Identity>,
    data: web::Data<State>,
    mut payload: Multipart,
    req: HttpRequest,
) -> impl Responder {
    let srv: &crate::state::data::Data = &data.server;

    // Take the username/password from POST data
    let fields = match read_fields(&mut payload, Limits::from_data(srv)).await {
        Ok(f) => f,
        Err(e) => {
            error!("Could not read the login body: {}", e);
            return result_json(e.status(), false, "Malformed request");
        }
    };
    let lu = LoginUser {
        username: field_str(&fields, "username"),
        password: field_str(&fields, "password"),
    };

    info!("User name: {}", lu.username.clone());

    // Find the user in the database
    let usr = get_user(srv, lu.username.clone()).await;

    if usr == None {
        // Not found - error out.
        info!("No user {} found, couldn't log in", lu.username.clone());
        return ok_json(false, "Invalid login/password");
    } else {
        let itm_real = usr.unwrap();

        // Don't let inactive users log in.
        if itm_real.safe_bool("role_is_active", false) == false {
            info!("User {} is inactive, couldn't log in", lu.username.clone());
            return ok_json(false, "User is inactive");
        }

        // Verify password/otp
        let pw = itm_real.safe_str("password", "");
        let otp = itm_real.safe_str("otp", "");
        let attempts = itm_real.safe_u64("otp_attempts", 0);

        // An OTP is only a credential while it is fresh and unexhausted.
        let otp_live = otp_is_live(&itm_real, now_ts());
        let otp_ok = otp_live && constant_time_eq(otp.as_bytes(), lu.password.as_bytes());
        let pw_ok = pw != "" && verify_password(&lu.password, &pw);

        if pw_ok || otp_ok {
            // Password matches - log in.
            Identity::login(&req.extensions(), itm_real.safe_str("email", "")).unwrap();

            // Stamp the session with the generation in force right now. The
            // guard middleware compares it on every later request, so bumping
            // the number on the record — at logout, on a password change, on a
            // role change — stops this cookie being accepted, which is the
            // only revocation available when the whole session lives in it.
            if let Err(e) = req
                .get_session()
                .insert(SESSION_GEN_KEY, session_generation(&itm_real))
            {
                error!("Could not stamp the session generation: {}", e);
            }

            // Burn the OTP on any successful login, addressed by id. The old
            // `clear_otp(login)` matched only records whose `login` and
            // `email` were both equal to the submitted string — never true for
            // a normal account — so codes were in practice never invalidated
            // and stayed usable forever as a second password. It also ran
            // before verification, which would have burned a code the
            // legitimate user was still typing in.
            let mut logged = Item::new();
            logged.id = itm_real.id;
            logged.set_bool("logged_once", true);
            logged.set_str("otp", "");
            logged.set_u64("otp_expires_at", 0);
            logged.set_u64("otp_attempts", 0);
            srv.rw.set_item("user", &logged, true).await;
            info!("Logged in as {}", lu.username);
        } else {
            // Password doesn't match - error out.
            if otp_live {
                bump_otp_attempts(srv, itm_real.id, attempts).await;
            }
            error!("Invalid password for {}", lu.username);
            return ok_json(false, "Invalid login/password");
        }
    }

    return ok_json(true, "");
}

/// Log the user out.
///
/// Dropping the cookie is only half of it: the session lives entirely inside
/// that cookie, so a copy taken before this call would otherwise keep working
/// forever — a `BrowserSession` cookie has no expiry to run out. Bumping the
/// account's session generation is what actually revokes it, here and on every
/// other device.
pub async fn logout(
    _user: Identity,
    _data: web::Data<State>,
    _request: HttpRequest,
) -> impl Responder {
    let srv: &crate::state::data::Data = &_data.server;
    if let Ok(principal) = _user.id() {
        if let Some(usr) = get_user(srv, principal).await {
            bump_session_generation(srv, &usr).await;
        }
    }
    _user.logout();
    info!("Logged out");

    HttpResponse::Ok()
}

/// Check if the user is logged in. Additionally, this function returns a json
/// with a few more basic site settings and user roles.
///
/// This used to exist in two copies — one reaching into `StoreMongo`'s client
/// and database name to issue a `find_one` by hand, the other scanning the
/// whole `user` collection under `full_file_database` — because the store was
/// a concrete type and there was no lookup on the trait to call. Both are now
/// the single `get_user` path every other handler already uses, which on the
/// Mongo backend answers from an indexed query behind a short-TTL cache
/// rather than an uncached hand-built one.
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

    let identity = match _user.as_ref().and_then(|i| i.id().ok()) {
        Some(email) if srv.has_collection("user") => email,
        _ => {
            info!("No user or user database");
            return web::Json(user);
        }
    };

    let role_is = internals.safe_str("user_role_prefix", "role_is_");
    let found = match get_user(srv, identity.clone()).await {
        Some(found) => found,
        None => return web::Json(user),
    };

    // The session principal is an email (that is what `login` stores), while
    // `get_user` resolves either a login or an email. Confirm the record we
    // got is the one the session names, so a login that happens to equal
    // somebody else's email cannot borrow their roles.
    if found.strs.get("email").map(String::as_str) != Some(identity.as_str()) {
        return web::Json(user);
    }

    user.username = identity;
    user.id = found.id;

    // Roles are the `role_is_*` bool flags that are actually set. Only true
    // flags count: reading the key alone once handed "admin" to every user
    // carrying an explicit `role_is_admin: false`.
    for (key, value) in &found.bools {
        if *value {
            if let Some(role) = key.strip_prefix(role_is.as_str()) {
                if !role.is_empty() {
                    user.role.push(role.to_string());
                }
            }
        }
    }

    web::Json(user)
}

/// Handler-level tests for the authentication endpoints.
///
/// These reach the real `register` / `gen_otp` / `login` functions through a
/// real actix app, with an in-memory store behind `Data::rw`. The unit tests
/// in `user_control` prove the decision functions are right; these prove the
/// handlers actually consult them, which is the half that a refactor can
/// silently drop.
#[cfg(test)]
mod handler_tests {
    use super::*;
    use crate::state::data::Data;
    use crate::state::store_memory::StoreMemory;
    use actix_web::{test, App};

    const BOUNDARY: &str = "----isabelletestboundary";

    fn multipart_body(fields: &[(&str, &str)]) -> String {
        let mut body = String::new();
        for (name, value) in fields {
            body.push_str(&format!("--{}\r\n", BOUNDARY));
            body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
                name
            ));
            body.push_str(value);
            body.push_str("\r\n");
        }
        body.push_str(&format!("--{}--\r\n", BOUNDARY));
        body
    }

    fn state_with(store: StoreMemory) -> web::Data<State> {
        let mut data = Data::new();
        data.rw = Box::new(store);
        web::Data::new(crate::state::state::State::from_data(data))
    }

    /// An account an operator provisioned: real login and email, never
    /// logged in, no self-registration marker.
    fn provisioned_admin() -> Item {
        let mut itm = Item::new();
        itm.id = 1;
        itm.set_str("name", "admin");
        itm.set_str("login", "admin");
        itm.set_str("email", "admin@example.org");
        itm.set_bool("role_is_admin", true);
        itm.set_bool("role_is_active", true);
        itm
    }

    /// Drive one multipart POST through a real app and return the decoded
    /// `ProcessResult`.
    async fn call(
        state: web::Data<State>,
        route: &str,
        handler: actix_web::Route,
        fields: &[(&str, &str)],
    ) -> ProcessResult {
        // `Option<Identity>` is an extractor, not a plain argument: without
        // `IdentityMiddleware` installed it panics rather than yielding
        // `None`. The app therefore carries the same middleware stack the
        // real server does.
        let app = test::init_service(
            App::new()
                .app_data(state)
                .wrap(actix_identity::IdentityMiddleware::default())
                .wrap(
                    actix_session::SessionMiddleware::builder(
                        actix_session::storage::CookieSessionStore::default(),
                        actix_web::cookie::Key::from(&[0u8; 64]),
                    )
                    .cookie_secure(false)
                    .build(),
                )
                .route(route, handler),
        )
        .await;
        let req = test::TestRequest::post()
            .uri(route)
            .insert_header((
                "content-type",
                format!("multipart/form-data; boundary={}", BOUNDARY),
            ))
            .set_payload(multipart_body(fields))
            .to_request();
        let body = test::call_and_read_body(&app, req).await;
        serde_json::from_slice(&body).expect("handler returned non-JSON")
    }

    /// The account takeover, end to end: guess the login of a provisioned
    /// account and submit your own email. The handler must refuse, and — the
    /// part that actually mattered — must leave the stored email alone.
    #[actix_web::test]
    async fn register_cannot_repoint_a_provisioned_account() {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", provisioned_admin());
        let state = state_with(store.clone());

        let result = call(
            state,
            "/register",
            web::post().to(register),
            &[
                ("login", "admin"),
                ("email", "attacker@evil.example"),
                ("dry", "false"),
            ],
        )
        .await;

        assert!(!result.succeeded, "registration on a taken login succeeded");
        let stored = store.peek("user", 1).unwrap();
        assert_eq!(
            stored.safe_str("email", ""),
            "admin@example.org",
            "the victim's email was rewritten"
        );
        assert_eq!(store.count("user"), 1, "a duplicate record was created");
    }

    /// The mirror image: keep your own login, submit the victim's email.
    #[actix_web::test]
    async fn register_cannot_claim_a_taken_email() {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", provisioned_admin());
        let state = state_with(store.clone());

        let result = call(
            state,
            "/register",
            web::post().to(register),
            &[
                ("login", "newcomer"),
                ("email", "admin@example.org"),
                ("dry", "false"),
            ],
        )
        .await;

        assert!(!result.succeeded);
        assert_eq!(store.count("user"), 1);
        assert_eq!(
            store.peek("user", 1).unwrap().safe_str("login", ""),
            "admin"
        );
    }

    /// The legitimate path still works, and marks the record as
    /// self-registered so a later re-submit can be told apart from an
    /// operator-provisioned account.
    #[actix_web::test]
    async fn register_creates_a_marked_active_account() {
        let store = StoreMemory::with_collections(&["user"]);
        let state = state_with(store.clone());

        let result = call(
            state,
            "/register",
            web::post().to(register),
            &[
                ("login", "bob"),
                ("email", "bob@example.org"),
                ("dry", "false"),
            ],
        )
        .await;

        assert!(result.succeeded, "{}", result.error);
        assert_eq!(store.count("user"), 1);
        let created = store.peek("user", 1).unwrap();
        assert_eq!(created.safe_str("login", ""), "bob");
        assert_eq!(created.safe_str("email", ""), "bob@example.org");
        assert!(created.safe_bool("self_registered", false));
        assert!(created.safe_bool("role_is_active", false));
    }

    /// A login that `get_user` cannot look up must be refused, not stored:
    /// the lookup returns `None` for these, so such a record would report as
    /// free forever and be unfindable afterwards.
    #[actix_web::test]
    async fn register_refuses_logins_it_could_never_find_again() {
        let store = StoreMemory::with_collections(&["user"]);
        let state = state_with(store.clone());

        let result = call(
            state,
            "/register",
            web::post().to(register),
            &[
                ("login", "bob$"),
                ("email", "bob@example.org"),
                ("dry", "false"),
            ],
        )
        .await;

        assert!(!result.succeeded);
        assert_eq!(store.count("user"), 0);
    }

    /// `/gen_otp` must answer identically whether or not the account exists,
    /// otherwise it enumerates logins for anyone who asks.
    #[actix_web::test]
    async fn gen_otp_does_not_reveal_whether_an_account_exists() {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", provisioned_admin());

        let existing = call(
            state_with(store.clone()),
            "/gen_otp",
            web::post().to(gen_otp),
            &[("username", "admin")],
        )
        .await;
        let missing = call(
            state_with(store.clone()),
            "/gen_otp",
            web::post().to(gen_otp),
            &[("username", "nobody")],
        )
        .await;

        assert_eq!(existing.succeeded, missing.succeeded);
        assert_eq!(existing.error, missing.error);
    }

    /// The code itself must be issued only to the account that exists, and
    /// must carry an expiry — a code without one is a permanent password.
    #[actix_web::test]
    async fn gen_otp_issues_a_code_with_an_expiry() {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", provisioned_admin());
        let state = state_with(store.clone());

        call(
            state,
            "/gen_otp",
            web::post().to(gen_otp),
            &[("username", "admin")],
        )
        .await;

        let stored = store.peek("user", 1).unwrap();
        assert_ne!(stored.safe_str("otp", ""), "", "no code was issued");
        assert!(
            stored.safe_u64("otp_expires_at", 0) > now_ts(),
            "code was issued without a future expiry"
        );
        assert_eq!(stored.safe_u64("otp_attempts", u64::MAX), 0);
    }

    /// An account an operator has not activated has no OTP path at all: the
    /// code would be a credential for an account nobody has ever used.
    #[actix_web::test]
    async fn gen_otp_refuses_inactive_accounts() {
        let store = StoreMemory::with_collections(&["user"]);
        let mut inactive = provisioned_admin();
        inactive.set_bool("role_is_active", false);
        store.seed("user", inactive);
        let state = state_with(store.clone());

        let result = call(
            state,
            "/gen_otp",
            web::post().to(gen_otp),
            &[("username", "admin")],
        )
        .await;

        assert!(result.succeeded, "the refusal must not be visible");
        assert_eq!(
            store.peek("user", 1).unwrap().safe_str("otp", ""),
            "",
            "a code was issued to an inactive account"
        );
    }

    /// A second request inside the resend window must not roll a new code —
    /// otherwise the endpoint is both a mail cannon and a way to keep
    /// re-rolling a code that is being guessed.
    #[actix_web::test]
    async fn gen_otp_is_throttled() {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", provisioned_admin());

        call(
            state_with(store.clone()),
            "/gen_otp",
            web::post().to(gen_otp),
            &[("username", "admin")],
        )
        .await;
        let first = store.peek("user", 1).unwrap().safe_str("otp", "");

        call(
            state_with(store.clone()),
            "/gen_otp",
            web::post().to(gen_otp),
            &[("username", "admin")],
        )
        .await;
        let second = store.peek("user", 1).unwrap().safe_str("otp", "");

        assert_eq!(first, second, "throttle did not hold");
    }
}
