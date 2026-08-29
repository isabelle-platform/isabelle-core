/*
 * Isabelle project
 *
 * Copyright 2023-2026 Maxim Menshikov
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
//! Signing in with an identity provider.
//!
//! Three endpoints, and the browser walks between them: `/auth/providers`
//! says which are configured, `/auth/{provider}/start` sends the browser to
//! the provider, and `/auth/{provider}/callback` receives it back with a code
//! and turns that into a session. Nothing here is a fetch — every step is a
//! navigation, because the provider will only talk to a browser.
//!
//! **Where the flow lives.** Between start and callback there is state to
//! keep: the nonce the identity token must echo, the PKCE verifier, and where
//! the user was going. It is kept here, in this process, keyed by the `state`
//! parameter — not in the session cookie. Apple answers by POSTing the form
//! back, and a `SameSite=Lax` cookie is not sent on a cross-site POST, so a
//! cookie-carried flow would work for Google and fail for Apple. Single-use
//! server-side state is also what the OAuth specification asks for. The cost
//! is that a deployment running several cores behind one address would have
//! to make the callback land on the core that started the flow; Isabelle
//! deployments run one.
//!
//! **What a provider is trusted for.** The identity, and nothing else. It
//! says who the account is (`sub`) and what address it has, and whether it
//! vouches for that address. Roles, activity and everything else belong to
//! the record here, so a provider cannot make anybody an administrator.

use crate::server::secret::ensure_admin;
use crate::server::user_control::*;
use crate::state::state::*;
use crate::util::multipart::{read_body, read_json_body, Limits};
use crate::util::oidc::{self, Provider, ProviderConfig};
use actix_identity::Identity;
use actix_session::SessionExt;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use base64::Engine;
use isabelle_dm::data_model::item::Item;
use log::{error, info, warn};
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;

/// How long a started sign-in may take to come back.
///
/// Long enough for a password manager, a second factor and a consent screen;
/// short enough that an intercepted link is stale by the time it is used.
const FLOW_TTL_SECS: u64 = 600;

/// How many sign-ins may be in flight at once.
///
/// Anyone can start one — `/start` is unauthenticated by necessity — so this
/// is the bound on what an unauthenticated caller can make this process hold.
const MAX_FLOWS: usize = 512;

/// The cookie that ties a callback to the browser that started the flow.
const FLOW_COOKIE: &str = "isabelle-oauth";

/// A sign-in that has been started and not yet come back.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingFlow {
    pub provider: Provider,
    /// Echoed in the identity token; proves the token answers this request.
    pub nonce: String,
    pub verifier: String,
    /// Where to send the browser once it is signed in.
    pub next: String,
    /// Matched against the flow cookie, so a callback delivered to somebody
    /// else's browser cannot sign them in as us.
    pub binding: String,
    pub started_at: u64,
}

/// The sign-ins in flight, keyed by their `state` parameter.
#[derive(Debug, Default)]
pub struct PendingFlows {
    map: HashMap<String, PendingFlow>,
}

impl PendingFlows {
    pub fn insert(&mut self, state: String, flow: PendingFlow, now: u64) {
        self.prune(now);
        // Still full after pruning means flows are being started faster than
        // they finish. Dropping the oldest keeps the newest — the one a person
        // is most likely waiting on — rather than refusing everyone.
        while self.map.len() >= MAX_FLOWS {
            let oldest = self
                .map
                .iter()
                .min_by_key(|(_, f)| f.started_at)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.map.remove(&k);
                }
                None => break,
            }
        }
        self.map.insert(state, flow);
    }

    /// Take a flow out. Single use: a code replayed against a state that has
    /// already been spent finds nothing.
    pub fn take(&mut self, state: &str, now: u64) -> Option<PendingFlow> {
        self.prune(now);
        self.map.remove(state)
    }

    fn prune(&mut self, now: u64) {
        self.map
            .retain(|_, f| now.saturating_sub(f.started_at) < FLOW_TTL_SECS);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// A URL-safe random string of `bytes` bytes of entropy.
fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Reduce a caller-supplied `next` to a path on this site.
///
/// It ends up in a `Location` header after a successful sign-in, which makes
/// it an open redirect if taken at face value — the most convincing kind,
/// because the user really did just authenticate. Only a path is allowed, and
/// `//host` is a URL with the scheme left off, not a path.
pub fn safe_next(next: &str) -> String {
    let n = next.trim();
    let acceptable = n.starts_with('/')
        && !n.starts_with("//")
        && !n.starts_with("/\\")
        && !n.contains('\\')
        && !n.chars().any(|c| c.is_control());
    if acceptable {
        n.to_string()
    } else {
        "/".to_string()
    }
}

/// Why a sign-in was refused, as the browser is told.
///
/// A slug rather than a sentence: this travels in a URL the user can read and
/// forward, and the detail behind it — which record, which provider, which
/// mismatch — belongs in the log, not in an address bar.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Refusal {
    /// The user said no at the provider, or the provider gave up.
    Denied,
    /// The provider will not vouch for the address.
    Unverified,
    /// No account, and this deployment does not accept new ones.
    RegistrationClosed,
    /// There is an account and it is switched off.
    Inactive,
    /// The address belongs to an account already tied to a different one at
    /// this provider.
    Mismatched,
    /// Anything that went wrong on the way.
    Failed,
}

impl Refusal {
    pub fn slug(self) -> &'static str {
        match self {
            Refusal::Denied => "denied",
            Refusal::Unverified => "unverified",
            Refusal::RegistrationClosed => "registration_closed",
            Refusal::Inactive => "inactive",
            Refusal::Mismatched => "mismatched",
            Refusal::Failed => "failed",
        }
    }
}

/// What signing in with this identity should do.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolution {
    /// Sign in as the record with this id, recording the provider subject.
    SignIn(u64),
    /// There is no such account and one may be made.
    Create,
    Refuse(Refusal),
}

/// The `strs` key under which a provider's subject is remembered.
pub fn subject_key(provider: Provider) -> String {
    format!("oauth_{}_subject", provider.id())
}

/// Decide what an authenticated identity means for this deployment.
///
/// Kept apart from the request handling because this is the part with the
/// security argument in it, and it is worth being able to state that argument
/// as tests rather than as a comment.
///
/// The address is the key. It is what the rest of this core already treats as
/// the principal — a session is stamped with an email — so keying a provider
/// sign-in on anything else would create a second kind of account that could
/// not log in the ordinary way. What guards it is that the provider must
/// vouch for the address, and that once a record has been signed into with
/// one provider account it will not accept another: an address that changes
/// hands at the provider cannot pick up the record that was left behind.
pub fn resolve(
    existing: Option<&Item>,
    identity: &oidc::Identity,
    provider: Provider,
    allow_self_registration: bool,
) -> Resolution {
    if identity.email.trim().is_empty() {
        return Resolution::Refuse(Refusal::Unverified);
    }
    if !identity.email_verified {
        return Resolution::Refuse(Refusal::Unverified);
    }
    let existing = match existing {
        None => {
            return if allow_self_registration {
                Resolution::Create
            } else {
                Resolution::Refuse(Refusal::RegistrationClosed)
            }
        }
        Some(u) => u,
    };
    // The lookup that found this record matches a login *or* an email, which
    // is right for a password sign-in — people type either — but not here.
    // What the provider vouched for is an address, so an account is only the
    // right one if that is the address it holds; otherwise an account whose
    // login happened to be somebody else's email address could be signed
    // into by that somebody else.
    if !existing
        .safe_str("email", "")
        .trim()
        .eq_ignore_ascii_case(identity.email.trim())
    {
        return Resolution::Refuse(Refusal::Mismatched);
    }
    if !existing.safe_bool("role_is_active", false) {
        return Resolution::Refuse(Refusal::Inactive);
    }
    let known = existing.safe_str(&subject_key(provider), "");
    if !known.is_empty() && known != identity.subject {
        return Resolution::Refuse(Refusal::Mismatched);
    }
    Resolution::SignIn(existing.id)
}

/// Read a provider's configuration out of the encrypted secret store.
///
/// Presence is the switch: a provider with no entry is not offered and cannot
/// be started. There is no second flag to leave in the wrong position, and
/// nothing about it sits in the settings document that plugins and admins
/// read for other reasons.
pub fn provider_config(
    srv: &crate::state::data::Data,
    provider: Provider,
) -> Option<ProviderConfig> {
    let guard = srv.secrets.lock();
    let store = guard.as_ref()?;
    let item = store.get_by_name(provider.secret_name())?;
    Some(ProviderConfig {
        client_id: item.safe_str("client_id", ""),
        client_secret: item.safe_str("client_secret", ""),
        team_id: item.safe_str("team_id", ""),
        key_id: item.safe_str("key_id", ""),
        private_key: item.safe_str("private_key", ""),
    })
}

/// Where the provider sends the browser back to.
///
/// An operator registers this string with the provider, so it can also be
/// stored beside the credentials and used verbatim — that is the only way to
/// be certain the two match. The default is where a stock Isabelle deployment
/// puts the core: the shipped nginx configuration serves it under `/api`, and
/// the provider needs the address the *browser* uses, not the one the proxy
/// forwards to.
fn redirect_uri(srv: &crate::state::data::Data, provider: Provider) -> String {
    if let Some(cfg) = srv.secrets.lock().as_ref() {
        if let Some(item) = cfg.get_by_name(provider.secret_name()) {
            let explicit = item.safe_str("redirect_uri", "");
            if !explicit.trim().is_empty() {
                return explicit.trim().to_string();
            }
        }
    }
    format!(
        "{}/api/auth/{}/callback",
        srv.public_url.lock().trim_end_matches('/'),
        provider.id()
    )
}

/// One provider as an administrator sees it.
///
/// The secret store masks everything it is not told is metadata, which is the
/// right default for a store of secrets but leaves a configuration screen
/// unable to show a client id — a value that is in the address bar of every
/// person who ever signs in. Rather than widening that allowlist for every
/// secret in the deployment, the decision about which of *these* fields are
/// public is made here, where what each one is for is known.
fn admin_view(srv: &crate::state::data::Data, provider: Provider) -> serde_json::Value {
    let stored = provider_config(srv, provider);
    let cfg = stored.clone().unwrap_or_default();
    let problem = match &stored {
        None => String::new(),
        Some(c) => oidc::validate(provider, c).err().unwrap_or_default(),
    };
    // Never the client secret and never the key — only whether there is one,
    // which is what a form needs to say "leave blank to keep".
    let has_secret = match provider {
        Provider::Google => !cfg.client_secret.trim().is_empty(),
        Provider::Apple => !cfg.private_key.trim().is_empty(),
    };
    serde_json::json!({
        "id": provider.id(),
        "name": provider.display_name(),
        "configured": stored.is_some() && problem.is_empty(),
        "problem": problem,
        "client_id": cfg.client_id,
        "team_id": cfg.team_id,
        "key_id": cfg.key_id,
        "redirect_uri": stored_redirect_uri(srv, provider),
        "effective_redirect_uri": redirect_uri(srv, provider),
        "has_secret": has_secret,
    })
}

/// The redirect URI an operator set, as opposed to the one in use.
fn stored_redirect_uri(srv: &crate::state::data::Data, provider: Provider) -> String {
    srv.secrets
        .lock()
        .as_ref()
        .and_then(|s| s.get_by_name(provider.secret_name()))
        .map(|i| i.safe_str("redirect_uri", ""))
        .unwrap_or_default()
}

/// What is configured, for the screen that configures it.
pub async fn auth_config(user: Identity, data: web::Data<State>) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let srv: &crate::state::data::Data = &data.server;
    HttpResponse::Ok().json(serde_json::json!({
        "providers": [
            admin_view(srv, Provider::Google),
            admin_view(srv, Provider::Apple),
        ],
    }))
}

/// One provider's settings, as a form submits them.
///
/// Every field is optional and absent means "leave alone", so a form can send
/// only what changed. For the two that can never be read back — the client
/// secret and the private key — an empty string means the same thing, because
/// an empty box on a screen that cannot show them means "unchanged", not
/// "delete". Removing a provider is `/auth/config/forget`, which says so.
#[derive(Debug, Deserialize)]
struct ConfigUpdate {
    provider: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
}

/// Fold a submitted form onto what is already stored.
///
/// Separated from the writing so the "empty means unchanged" rule — the one
/// that decides whether a saved form can wipe a secret it was never shown —
/// can be stated as a test.
fn apply_update(current: &ProviderConfig, update: &ConfigUpdate) -> ProviderConfig {
    let plain = |field: &Option<String>, existing: &str| -> String {
        field
            .as_ref()
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|| existing.to_string())
    };
    let secret = |field: &Option<String>, existing: &str| -> String {
        match field.as_ref().map(|v| v.trim()) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => existing.to_string(),
        }
    };
    ProviderConfig {
        client_id: plain(&update.client_id, &current.client_id),
        client_secret: secret(&update.client_secret, &current.client_secret),
        team_id: plain(&update.team_id, &current.team_id),
        key_id: plain(&update.key_id, &current.key_id),
        private_key: secret(&update.private_key, &current.private_key),
    }
}

fn config_err(msg: impl Into<String>) -> HttpResponse {
    HttpResponse::Ok().json(isabelle_dm::data_model::process_result::ProcessResult {
        succeeded: false,
        error: msg.into(),
        data: HashMap::new(),
    })
}

fn config_ok() -> HttpResponse {
    HttpResponse::Ok().json(isabelle_dm::data_model::process_result::ProcessResult {
        succeeded: true,
        error: String::new(),
        data: HashMap::new(),
    })
}

/// Configure one provider.
pub async fn auth_config_save(
    user: Identity,
    data: web::Data<State>,
    mut payload: web::Payload,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let limits = Limits::from_data(&data.server);
    let update: ConfigUpdate = match read_json_body(&mut payload, limits).await {
        Ok(v) => v,
        Err(e) => {
            error!("Could not read the sign-in configuration: {}", e);
            return HttpResponse::build(e.status()).finish();
        }
    };
    let provider = match Provider::from_id(update.provider.trim()) {
        Some(p) => p,
        None => return config_err("There is no such provider."),
    };
    let srv: &crate::state::data::Data = &data.server;

    let merged = apply_update(&provider_config(srv, provider).unwrap_or_default(), &update);
    // Checked before it is stored, not when somebody first tries to sign in:
    // a private key that cannot be read is a setting that is wrong now.
    if let Err(e) = oidc::validate(provider, &merged) {
        return config_err(format!(
            "{} cannot be used yet: {}",
            provider.display_name(),
            e
        ));
    }
    let uri = update
        .redirect_uri
        .clone()
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| stored_redirect_uri(srv, provider));
    if !uri.is_empty() && !oidc::redirect_uri_is_usable(&uri) {
        return config_err(
            "The redirect URI has to be a full address, starting with http:// or https://.",
        );
    }

    let mut secrets = srv.secrets.lock();
    let store = match secrets.as_mut() {
        Some(s) => s,
        None => return config_err("The secret store is not available."),
    };
    let mut itm = Item::new();
    itm.id = store
        .get_by_name(provider.secret_name())
        .map(|i| i.id)
        .unwrap_or(u64::MAX);
    itm.set_str("name", provider.secret_name());
    itm.set_str("client_id", merged.client_id.trim());
    itm.set_str("client_secret", merged.client_secret.trim());
    itm.set_str("team_id", merged.team_id.trim());
    itm.set_str("key_id", merged.key_id.trim());
    itm.set_str("private_key", merged.private_key.trim());
    itm.set_str("redirect_uri", &uri);
    match store.set(&itm, true) {
        Ok(_) => {
            info!("Sign-in with {} was configured", provider.display_name());
            config_ok()
        }
        Err(e) => config_err(format!("The configuration could not be stored: {}", e)),
    }
}

#[derive(Debug, Deserialize)]
struct ForgetRequest {
    provider: String,
}

/// Remove a provider's configuration, which is also how it is switched off.
pub async fn auth_config_forget(
    user: Identity,
    data: web::Data<State>,
    mut payload: web::Payload,
) -> HttpResponse {
    if let Err(r) = ensure_admin(&data, &user).await {
        return r;
    }
    let limits = Limits::from_data(&data.server);
    let req: ForgetRequest = match read_json_body(&mut payload, limits).await {
        Ok(v) => v,
        Err(e) => return HttpResponse::build(e.status()).finish(),
    };
    let provider = match Provider::from_id(req.provider.trim()) {
        Some(p) => p,
        None => return config_err("There is no such provider."),
    };
    let srv: &crate::state::data::Data = &data.server;
    let mut secrets = srv.secrets.lock();
    let store = match secrets.as_mut() {
        Some(s) => s,
        None => return config_err("The secret store is not available."),
    };
    let id = match store.get_by_name(provider.secret_name()) {
        Some(i) => i.id,
        // Already absent is the state that was asked for.
        None => return config_ok(),
    };
    match store.del(id) {
        Ok(_) => {
            info!("Sign-in with {} was removed", provider.display_name());
            config_ok()
        }
        Err(e) => config_err(format!("The configuration could not be removed: {}", e)),
    }
}

/// Which providers this deployment can sign in with.
///
/// Unauthenticated on purpose: it is read by a login screen, which by
/// definition has nobody signed in. It says only that a provider is
/// configured — never with what.
pub async fn auth_providers(data: web::Data<State>) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let mut out: Vec<serde_json::Value> = Vec::new();
    for provider in [Provider::Google, Provider::Apple] {
        if let Some(cfg) = provider_config(srv, provider) {
            if cfg.check(provider).is_ok() {
                out.push(serde_json::json!({
                    "id": provider.id(),
                    "name": provider.display_name(),
                }));
            }
        }
    }
    HttpResponse::Ok().json(serde_json::json!({ "providers": out }))
}

/// Send the browser to the provider.
pub async fn auth_start(
    data: web::Data<State>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let provider = match Provider::from_id(&path.into_inner()) {
        Some(p) => p,
        None => return HttpResponse::NotFound().finish(),
    };

    #[derive(Debug, Deserialize, Default)]
    struct Q {
        #[serde(default)]
        next: String,
    }
    let q: Q = serde_qs::from_str(req.query_string()).unwrap_or_default();
    let next = safe_next(&q.next);

    let cfg = match provider_config(srv, provider) {
        Some(c) => c,
        None => {
            warn!("Sign-in with {} is not configured", provider.display_name());
            return refuse(srv, &next, Refusal::Failed);
        }
    };
    if let Err(e) = cfg.check(provider) {
        error!(
            "Sign-in with {} is configured but unusable: {}",
            provider.display_name(),
            e
        );
        return refuse(srv, &next, Refusal::Failed);
    }

    let state = random_token(32);
    let nonce = random_token(32);
    let verifier = random_token(32);
    let binding = random_token(32);
    let uri = redirect_uri(srv, provider);

    srv.oauth_flows.lock().insert(
        state.clone(),
        PendingFlow {
            provider,
            nonce: nonce.clone(),
            verifier: verifier.clone(),
            next,
            binding: binding.clone(),
            started_at: now_ts(),
        },
        now_ts(),
    );

    let url = oidc::authorize_url(
        provider,
        &cfg,
        &uri,
        &state,
        &nonce,
        &oidc::pkce_challenge(&verifier),
    );
    info!(
        "Starting {} sign-in, returning to {}",
        provider.display_name(),
        uri
    );
    HttpResponse::Found()
        .cookie(flow_cookie(srv, &binding))
        .append_header(("Location", url))
        .finish()
}

/// The cookie that proves the callback reached the browser that started.
///
/// `SameSite=None` where it can be: Apple posts the callback from its own
/// origin, and `Lax` withholds a cookie on a cross-site POST, which would
/// leave the Apple flow with no binding at all. `None` requires `Secure`, so
/// an insecure development run falls back to `Lax` — where Apple does not
/// work regardless, since it will not register an `http://` redirect.
fn flow_cookie<'a>(srv: &crate::state::data::Data, binding: &'a str) -> Cookie<'a> {
    let secure = !*srv.cookie_http_insecure.lock();
    Cookie::build(FLOW_COOKIE, binding)
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(if secure {
            SameSite::None
        } else {
            SameSite::Lax
        })
        .max_age(actix_web::cookie::time::Duration::seconds(
            FLOW_TTL_SECS as i64,
        ))
        .finish()
}

/// What a provider sends back, however it sends it.
#[derive(Debug, Deserialize, Default)]
struct Callback {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: String,
}

/// Google's callback: a redirect, so the answer is in the query.
pub async fn auth_callback_get(
    data: web::Data<State>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let cb: Callback = serde_qs::from_str(req.query_string()).unwrap_or_default();
    finish(data, path.into_inner(), cb, req).await
}

/// Apple's callback: a form POST from appleid.apple.com.
pub async fn auth_callback_post(
    data: web::Data<State>,
    path: web::Path<String>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse {
    let limits = Limits::from_data(&data.server);
    let body = match read_body(&mut payload, limits).await {
        Ok(b) => b,
        Err(e) => {
            error!("Could not read the OAuth callback body: {}", e);
            return HttpResponse::build(e.status()).finish();
        }
    };
    let cb: Callback = serde_qs::from_str(&String::from_utf8_lossy(&body)).unwrap_or_default();
    finish(data, path.into_inner(), cb, req).await
}

/// Turn a callback into a session, or into a refusal.
async fn finish(
    data: web::Data<State>,
    provider_id: String,
    cb: Callback,
    req: HttpRequest,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let provider = match Provider::from_id(&provider_id) {
        Some(p) => p,
        None => return HttpResponse::NotFound().finish(),
    };

    // Taken first and unconditionally: a state is spent whether or not the
    // rest of the callback is any good, so a failed attempt cannot be retried
    // against the same nonce.
    let flow = srv.oauth_flows.lock().take(&cb.state, now_ts());
    let flow = match flow {
        Some(f) if f.provider == provider => f,
        _ => {
            warn!(
                "Discarding a callback from {} with no matching sign-in in flight",
                provider.display_name()
            );
            return refuse(srv, "/", Refusal::Failed);
        }
    };

    let presented = req
        .cookie(FLOW_COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    if !crate::util::crypto::constant_time_eq(presented.as_bytes(), flow.binding.as_bytes()) {
        // Either the browser finishing this is not the one that started it —
        // which is how a stranger signs somebody into an account of the
        // stranger's choosing — or the cookie did not survive the round trip.
        warn!(
            "Discarding a callback from {} delivered to a browser that did not start it",
            provider.display_name()
        );
        return refuse(srv, &flow.next, Refusal::Failed);
    }

    if !cb.error.is_empty() {
        info!(
            "{} declined the sign-in: {}",
            provider.display_name(),
            cb.error
        );
        return refuse(srv, &flow.next, Refusal::Denied);
    }
    if cb.code.is_empty() {
        return refuse(srv, &flow.next, Refusal::Failed);
    }

    let cfg = match provider_config(srv, provider) {
        Some(c) => c,
        None => return refuse(srv, &flow.next, Refusal::Failed),
    };
    let uri = redirect_uri(srv, provider);
    let tokens =
        match oidc::exchange_code(provider, &cfg, &uri, &cb.code, &flow.verifier, now_ts()).await {
            Ok(t) => t,
            Err(e) => {
                error!("Could not exchange the authorization code: {}", e);
                return refuse(srv, &flow.next, Refusal::Failed);
            }
        };
    let identity = match oidc::verify_id_token(provider, &cfg, &tokens.id_token, &flow.nonce).await
    {
        Ok(i) => i,
        Err(e) => {
            error!("Could not accept the identity token: {}", e);
            return refuse(srv, &flow.next, Refusal::Failed);
        }
    };

    let existing = get_user(srv, identity.email.clone()).await;
    let allow_registration = srv
        .rw
        .get_internals()
        .await
        .safe_bool("allow_self_registration", true);
    let resolution = resolve(existing.as_ref(), &identity, provider, allow_registration);

    let record = match resolution {
        Resolution::Refuse(r) => {
            info!(
                "Refusing a {} sign-in for {}: {}",
                provider.display_name(),
                identity.email,
                r.slug()
            );
            return refuse(srv, &flow.next, r);
        }
        Resolution::SignIn(id) => {
            let mut itm = Item::new();
            itm.id = id;
            itm.set_str(&subject_key(provider), &identity.subject);
            itm.set_bool("logged_once", true);
            srv.rw.set_item("user", &itm, true).await;
            info!(
                "Signed in {} with {}",
                identity.email,
                provider.display_name()
            );
            existing
        }
        Resolution::Create => {
            if !login_is_acceptable(&identity.email) {
                return refuse(srv, &flow.next, Refusal::Failed);
            }
            let mut itm = Item::new();
            itm.set_str("login", &identity.email);
            itm.set_str("email", &identity.email);
            itm.set_str(
                "name",
                if identity.name.trim().is_empty() {
                    &identity.email
                } else {
                    identity.name.trim()
                },
            );
            itm.set_str(&subject_key(provider), &identity.subject);
            itm.set_bool("self_registered", true);
            itm.set_bool("role_is_active", true);
            itm.set_bool("logged_once", true);
            let id = srv.rw.set_item("user", &itm, false).await;
            info!(
                "Registered {} through {} as id {}",
                identity.email,
                provider.display_name(),
                id
            );
            srv.rw.get_item("user", id).await
        }
    };

    // The session is stamped with the record as it stands after the write, so
    // a generation bumped by that write does not immediately invalidate the
    // session it just created.
    if let Err(e) = actix_identity::Identity::login(&req.extensions(), identity.email.clone()) {
        error!(
            "Could not establish a session for {}: {}",
            identity.email, e
        );
        return refuse(srv, &flow.next, Refusal::Failed);
    }
    let generation = record.as_ref().map(session_generation).unwrap_or(0);
    if let Err(e) = req
        .get_session()
        .insert(crate::server::guards::SESSION_GEN_KEY, generation)
    {
        error!("Could not stamp the session generation: {}", e);
    }

    HttpResponse::Found()
        .cookie(expired_flow_cookie(srv))
        .append_header(("Location", site_url(srv, &flow.next)))
        .finish()
}

/// Send the browser back where it came from, carrying why it did not work.
fn refuse(srv: &crate::state::data::Data, next: &str, why: Refusal) -> HttpResponse {
    let target = safe_next(next);
    let separator = if target.contains('?') { '&' } else { '?' };
    HttpResponse::Found()
        .cookie(expired_flow_cookie(srv))
        .append_header((
            "Location",
            format!(
                "{}{}auth_error={}",
                site_url(srv, &target),
                separator,
                why.slug()
            ),
        ))
        .finish()
}

/// A path on this site, as an address the browser can be sent to.
///
/// The site is where `--pub-url` says it is, and that is not always where
/// this process is: a development frontend is served from its own port and
/// talks to the core on another, so a bare path in a `Location` would resolve
/// against the core and land nowhere. In a deployment the two are one origin
/// and this changes nothing. It is not an open redirect — the host comes from
/// the operator's own configuration, and only the path from the caller.
fn site_url(srv: &crate::state::data::Data, path: &str) -> String {
    format!(
        "{}{}",
        srv.public_url.lock().trim_end_matches('/'),
        safe_next(path)
    )
}

fn expired_flow_cookie(srv: &crate::state::data::Data) -> Cookie<'static> {
    let mut c = flow_cookie(srv, "");
    c.make_removal();
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(email: &str, verified: bool, subject: &str) -> oidc::Identity {
        oidc::Identity {
            subject: subject.to_string(),
            email: email.to_string(),
            email_verified: verified,
            name: "Someone".to_string(),
        }
    }

    fn account(id: u64, active: bool, subject: Option<&str>) -> Item {
        let mut itm = Item::new();
        itm.id = id;
        itm.set_str("email", "someone@example.com");
        itm.set_bool("role_is_active", active);
        if let Some(s) = subject {
            itm.set_str(&subject_key(Provider::Google), s);
        }
        itm
    }

    /// It ends up in a `Location` after a successful sign-in, which is the
    /// most convincing possible open redirect.
    #[test]
    fn a_destination_is_reduced_to_somewhere_on_this_site() {
        assert_eq!(safe_next("/products"), "/products");
        assert_eq!(safe_next("/a?b=c"), "/a?b=c");
        assert_eq!(safe_next(""), "/");
        assert_eq!(safe_next("https://evil.test/"), "/");
        // A scheme-relative URL is not a path, however much it looks like one.
        assert_eq!(safe_next("//evil.test/"), "/");
        assert_eq!(safe_next("/\\evil.test/"), "/");
        assert_eq!(safe_next("/a\\b"), "/");
        assert_eq!(safe_next("/a\nSet-Cookie: x=y"), "/");
    }

    #[test]
    fn an_address_the_provider_will_not_vouch_for_is_not_an_identity() {
        assert_eq!(
            resolve(
                None,
                &identity("someone@example.com", false, "sub-1"),
                Provider::Google,
                true
            ),
            Resolution::Refuse(Refusal::Unverified)
        );
        assert_eq!(
            resolve(None, &identity("", true, "sub-1"), Provider::Google, true),
            Resolution::Refuse(Refusal::Unverified)
        );
    }

    #[test]
    fn an_unknown_address_registers_only_where_registration_is_open() {
        let id = identity("someone@example.com", true, "sub-1");
        assert_eq!(
            resolve(None, &id, Provider::Google, true),
            Resolution::Create
        );
        assert_eq!(
            resolve(None, &id, Provider::Google, false),
            Resolution::Refuse(Refusal::RegistrationClosed)
        );
    }

    /// The record decides, not the provider: an account switched off here
    /// stays off however convincingly Google vouches for its owner.
    #[test]
    fn a_deactivated_account_cannot_be_signed_into() {
        let usr = account(7, false, None);
        assert_eq!(
            resolve(
                Some(&usr),
                &identity("someone@example.com", true, "sub-1"),
                Provider::Google,
                true
            ),
            Resolution::Refuse(Refusal::Inactive)
        );
    }

    /// The chosen policy: a verified address signs into the account that
    /// already holds it, password or no password.
    #[test]
    fn a_verified_address_signs_into_the_account_that_owns_it() {
        let usr = account(7, true, None);
        assert_eq!(
            resolve(
                Some(&usr),
                &identity("someone@example.com", true, "sub-1"),
                Provider::Google,
                true
            ),
            Resolution::SignIn(7)
        );
    }

    /// The guard on that policy. Once a record has been signed into with one
    /// provider account, an address that later changes hands at the provider
    /// cannot pick the record up.
    #[test]
    fn an_address_that_changed_hands_at_the_provider_cannot_take_the_record() {
        let usr = account(7, true, Some("sub-1"));
        assert_eq!(
            resolve(
                Some(&usr),
                &identity("someone@example.com", true, "sub-1"),
                Provider::Google,
                true
            ),
            Resolution::SignIn(7)
        );
        assert_eq!(
            resolve(
                Some(&usr),
                &identity("someone@example.com", true, "sub-2"),
                Provider::Google,
                true
            ),
            Resolution::Refuse(Refusal::Mismatched)
        );
    }

    /// A record is found by login or by email, because that is what a typed
    /// sign-in needs. A provider vouches for an address and nothing else, so
    /// an account whose *login* is somebody else's address is not a match.
    #[test]
    fn an_account_whose_login_is_someone_elses_address_is_not_that_someone() {
        let mut usr = Item::new();
        usr.id = 9;
        usr.set_str("login", "someone@example.com");
        usr.set_str("email", "impostor@example.net");
        usr.set_bool("role_is_active", true);
        assert_eq!(
            resolve(
                Some(&usr),
                &identity("someone@example.com", true, "sub-1"),
                Provider::Google,
                true
            ),
            Resolution::Refuse(Refusal::Mismatched)
        );
    }

    /// The address is compared as addresses are, not byte for byte.
    #[test]
    fn a_record_written_in_mixed_case_is_still_the_same_account() {
        let mut usr = account(7, true, None);
        usr.set_str("email", "SomeOne@Example.COM");
        assert_eq!(
            resolve(
                Some(&usr),
                &identity("someone@example.com", true, "sub-1"),
                Provider::Google,
                true
            ),
            Resolution::SignIn(7)
        );
    }

    /// Subjects are remembered per provider, so signing in with Apple to an
    /// account that has only ever used Google is a first link, not a clash.
    #[test]
    fn each_provider_is_remembered_separately() {
        let usr = account(7, true, Some("google-sub"));
        assert_eq!(
            resolve(
                Some(&usr),
                &identity("someone@example.com", true, "apple-sub"),
                Provider::Apple,
                true
            ),
            Resolution::SignIn(7)
        );
    }

    /// The rule that decides whether saving a form can wipe a secret the
    /// form was never allowed to show.
    #[test]
    fn a_blank_secret_box_means_unchanged_rather_than_delete() {
        let current = ProviderConfig {
            client_id: "old-id".into(),
            client_secret: "kept".into(),
            ..Default::default()
        };
        let update = ConfigUpdate {
            provider: "google".into(),
            client_id: Some("new-id".into()),
            client_secret: Some(String::new()),
            team_id: None,
            key_id: None,
            private_key: None,
            redirect_uri: None,
        };
        let merged = apply_update(&current, &update);
        assert_eq!(merged.client_id, "new-id");
        assert_eq!(merged.client_secret, "kept");
    }

    #[test]
    fn a_secret_that_was_typed_replaces_the_one_stored() {
        let current = ProviderConfig {
            client_secret: "old".into(),
            ..Default::default()
        };
        let update = ConfigUpdate {
            provider: "google".into(),
            client_id: None,
            client_secret: Some("  new  ".into()),
            team_id: None,
            key_id: None,
            private_key: None,
            redirect_uri: None,
        };
        // Trimmed on the way in: a value pasted with a newline would
        // otherwise be a secret that is subtly not the one issued.
        assert_eq!(apply_update(&current, &update).client_secret, "new");
    }

    /// A field the form did not send is a field the form was not editing.
    #[test]
    fn what_a_form_leaves_out_it_leaves_alone() {
        let current = ProviderConfig {
            client_id: "id".into(),
            client_secret: "shh".into(),
            team_id: "T".into(),
            key_id: "K".into(),
            private_key: "PEM".into(),
        };
        let update = ConfigUpdate {
            provider: "apple".into(),
            client_id: None,
            client_secret: None,
            team_id: None,
            key_id: None,
            private_key: None,
            redirect_uri: None,
        };
        assert_eq!(apply_update(&current, &update), current);
    }

    /// A non-secret field, on the other hand, can be cleared — it is on the
    /// screen, so an empty box is a decision.
    #[test]
    fn clearing_a_visible_field_clears_it() {
        let current = ProviderConfig {
            client_id: "id".into(),
            team_id: "T".into(),
            ..Default::default()
        };
        let update = ConfigUpdate {
            provider: "apple".into(),
            client_id: None,
            client_secret: None,
            team_id: Some(String::new()),
            key_id: None,
            private_key: None,
            redirect_uri: None,
        };
        assert_eq!(apply_update(&current, &update).team_id, "");
    }

    fn flow(started_at: u64) -> PendingFlow {
        PendingFlow {
            provider: Provider::Google,
            nonce: "n".into(),
            verifier: "v".into(),
            next: "/".into(),
            binding: "b".into(),
            started_at,
        }
    }

    /// A code is worth one exchange. Replaying it finds no flow, so it cannot
    /// be redeemed a second time against the same nonce.
    #[test]
    fn a_state_can_only_be_spent_once() {
        let mut flows = PendingFlows::default();
        flows.insert("st".into(), flow(100), 100);
        assert!(flows.take("st", 100).is_some());
        assert!(flows.take("st", 100).is_none());
    }

    #[test]
    fn a_sign_in_left_unfinished_expires() {
        let mut flows = PendingFlows::default();
        flows.insert("st".into(), flow(100), 100);
        assert!(flows.take("st", 100 + FLOW_TTL_SECS - 1).is_some());

        flows.insert("st2".into(), flow(100), 100);
        assert!(flows.take("st2", 100 + FLOW_TTL_SECS).is_none());
    }

    /// `/start` is unauthenticated by necessity, so what it can be made to
    /// hold has to be bounded.
    #[test]
    fn flows_in_flight_are_bounded() {
        let mut flows = PendingFlows::default();
        // All still well inside the expiry, so what is measured here is the
        // cap and not the pruning.
        let total = MAX_FLOWS + 50;
        let now = 100 + total as u64;
        for i in 0..total {
            flows.insert(format!("st{}", i), flow(100 + i as u64), now);
        }
        assert!(flows.len() <= MAX_FLOWS, "{}", flows.len());
        // The newest survived; the oldest is what gave way.
        assert!(flows.take(&format!("st{}", total - 1), now).is_some());
        assert!(flows.take("st0", now).is_none());
    }

    /// Expiry alone clears the table when flows are merely abandoned.
    #[test]
    fn abandoned_flows_do_not_accumulate() {
        let mut flows = PendingFlows::default();
        for i in 0..10 {
            flows.insert(format!("st{}", i), flow(100), 100);
        }
        flows.insert(
            "fresh".into(),
            flow(100 + FLOW_TTL_SECS),
            100 + FLOW_TTL_SECS,
        );
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn every_refusal_has_something_to_say() {
        for r in [
            Refusal::Denied,
            Refusal::Unverified,
            Refusal::RegistrationClosed,
            Refusal::Inactive,
            Refusal::Mismatched,
            Refusal::Failed,
        ] {
            assert!(!r.slug().is_empty());
            assert!(r.slug().chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }
}
