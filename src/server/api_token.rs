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

//! API tokens: proving who you are without a browser.
//!
//! Everything else in this server authenticates with the session cookie, which
//! is exactly right for a person at a keyboard and useless for the callers
//! that actually need an API — a CI job, a deployment script, another service.
//! Those either could not call the API at all or grew their own arrangements
//! beside it, and the two that exist are cautionary: one compares a secret in
//! plain text by scanning every device on every request and enrols a stranger
//! rather than refusing them; the other keeps its tokens in a settings field.
//!
//! A token here is the *same* identity as a login, reached another way. It
//! belongs to one account, it acts with that account's permissions and never
//! more, and every rule that already governs that account — seats, teams,
//! project scoping — applies unchanged, because by the time a request reaches
//! anything that decides such matters, a token has become the ordinary
//! `Option<Item>` a cookie would have produced.
//!
//! What a token adds is a *narrowing*. It is issued for a named set of scopes,
//! and a request outside them is refused before the handler runs, so a token
//! left in a CI variable is worth less than the password it stands in for.
//!
//! ## Shape
//!
//! ```text
//! mid_<id>_<43 characters of base64url>
//!     └id┘ └──────── the secret ───────┘
//! ```
//!
//! The identifier is in front so that verifying costs one lookup. The
//! alternative — a bare secret compared against every stored token — is how
//! the delta agent's tokens work today, and it is both slow and a timing
//! oracle. Only the hash of the secret is stored, so the store cannot give a
//! token back to anybody, including us: it is shown once, when it is made.

use crate::server::user_control::{check_role, get_user, principal};
use crate::state::data::Data;
use crate::state::state::State;
use crate::util::crypto::constant_time_eq;
use crate::util::multipart::{read_json_body, Limits};
use actix_identity::Identity;
use actix_web::{web, HttpResponse};
use isabelle_dm::data_model::item::Item;
use sha2::{Digest, Sha256};

/// The collection tokens live in.
pub const COLLECTION: &str = "api_token";

/// Everything before the identifier, so that a token found in a log or a
/// pasted config is recognisable as one.
const PREFIX: &str = "mid_";

/// Fields on a token record.
pub const FIELD_USER: &str = "user";
pub const FIELD_NAME: &str = "name";
pub const FIELD_HASH: &str = "hash";
pub const FIELD_SHOWN: &str = "shown";
pub const FIELD_SCOPES: &str = "scopes";
pub const FIELD_CREATED: &str = "created";
pub const FIELD_EXPIRES: &str = "expires";
pub const FIELD_LAST_USED: &str = "last_used";
pub const FIELD_REVOKED: &str = "revoked";

/// Every scope this instance's own routes name, for tests that need a token
/// that holds everything there is to hold.
#[cfg(test)]
const PROVIDERS_SCOPES: [&str; 3] = ["read", "write", "admin"];

/// How many bytes of randomness the secret carries.
///
/// 32 bytes is far past guessing, which is why the stored hash can be a plain
/// SHA-256 rather than a password hash: there is no low-entropy secret to make
/// expensive. Argon2 on every request would only be an invitation to exhaust
/// the server's CPU with wrong tokens.
const SECRET_BYTES: usize = 32;

/// Whether the generic item API may touch a collection at all.
///
/// It may not touch this one, and that is enforced here rather than in a
/// plugin because the collection and the endpoints that maintain it are the
/// core's own. A rule that lived in a plugin would hold only for the
/// deployments that load it, and a token record is a *credential*: whoever
/// can write one chooses both the owner and the hash, which is to say mints a
/// working credential for somebody else's account. Whoever can read one is
/// handed the verifier every presented token is measured against.
///
/// Tokens are made by `/api_token/issue`, ended by `/api_token/revoke`, and
/// listed by `/api_token/list`, which returns what a person needs to manage
/// them and never the hash.
pub fn hidden_from_item_api(collection: &str) -> bool {
    collection == COLLECTION
}

/// A token as presented by a caller, split into the part that finds the record
/// and the part that proves it.
#[derive(Debug, PartialEq, Eq)]
pub struct Presented {
    pub id: u64,
    pub secret: String,
}

/// Read `mid_<id>_<secret>`, or decide this is not one of ours.
///
/// Anything unrecognised returns `None` rather than an error: a deployment may
/// well sit behind a proxy that sets `Authorization` for its own reasons, and
/// a header we do not understand must leave the request exactly as it was
/// rather than fail it.
pub fn parse(presented: &str) -> Option<Presented> {
    let rest = presented.trim().strip_prefix(PREFIX)?;
    let (id, secret) = rest.split_once('_')?;
    if secret.is_empty() {
        return None;
    }
    Some(Presented {
        id: id.parse::<u64>().ok()?,
        secret: secret.to_string(),
    })
}

/// The credential out of an `Authorization` header, if it carries a bearer one.
pub fn from_header(header: &str) -> Option<Presented> {
    // Case-insensitively, because the scheme is a keyword rather than a value
    // and clients spell it as they please.
    let (scheme, value) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    parse(value)
}

/// What is stored for a secret, and what a presented one is measured against.
pub fn hash(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Mint a new secret.
pub fn generate_secret() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The whole token as it is handed to its owner, once.
pub fn assemble(id: u64, secret: &str) -> String {
    format!("{}{}_{}", PREFIX, id, secret)
}

/// The opening characters of a secret, kept on the record so that a person
/// with several tokens can tell which is which without being shown any of
/// them in full.
pub fn shown_part(secret: &str) -> String {
    secret.chars().take(6).collect()
}

/// Why a presented token was not accepted.
///
/// Deliberately not reported to the caller in this detail — every failure
/// answers the same 401 — but the distinction is what makes the server log
/// worth reading when a CI job stops working at three in the morning.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejected {
    /// No such token. Also what a guessed identifier gets.
    Unknown,
    /// The identifier exists and the secret does not match it.
    WrongSecret,
    Revoked,
    Expired,
    /// The account it belongs to is gone or is not allowed to sign in.
    OwnerInactive,
}

impl Rejected {
    pub fn reason(&self) -> &'static str {
        match self {
            Rejected::Unknown => "no such token",
            Rejected::WrongSecret => "secret does not match",
            Rejected::Revoked => "token was revoked",
            Rejected::Expired => "token has expired",
            Rejected::OwnerInactive => "owner is inactive or gone",
        }
    }
}

/// Check a stored record against a presented secret and a clock.
///
/// Separated from the lookup so that it can be tested without a store: this is
/// the part where being wrong is expensive.
pub fn check(record: &Item, secret: &str, now: u64) -> Result<(), Rejected> {
    if record.safe_bool(FIELD_REVOKED, false) {
        return Err(Rejected::Revoked);
    }
    // Zero means it does not expire. A token issued without an end date is a
    // deliberate choice a person can make; a token whose end date has passed
    // is not.
    let expires = record.safe_u64(FIELD_EXPIRES, 0);
    if expires != 0 && now >= expires {
        return Err(Rejected::Expired);
    }
    // Constant time, because the stored value is a hash of a secret and the
    // comparison runs on attacker-supplied input. The lengths are equal for
    // any two SHA-256 hex digests, so nothing leaks from the length check.
    if !constant_time_eq(
        record.safe_str(FIELD_HASH, "").as_bytes(),
        hash(secret).as_bytes(),
    ) {
        return Err(Rejected::WrongSecret);
    }
    Ok(())
}

/// The scopes a record grants, as written when it was issued.
pub fn scopes_of(record: &Item) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(&record.safe_str(FIELD_SCOPES, "[]")).unwrap_or_default()
}

/// Seconds since the epoch, for the fields that hold a time.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Find the record a presented token names, and check it.
pub async fn resolve(srv: &Data, presented: &Presented) -> Result<Item, Rejected> {
    let record = match srv.rw.get_item(COLLECTION, presented.id).await {
        Some(r) => r,
        None => return Err(Rejected::Unknown),
    };
    check(&record, &presented.secret, now())?;
    Ok(record)
}

/// Routes no token may reach, whatever it was issued for.
///
/// These are the ways a caller stops being a caller and becomes a resident:
/// reading the credential store, rewriting the instance's settings, editing
/// accounts, minting further tokens, updating the server. A token is meant to
/// be pasted into a CI variable and forgotten, and the damage from losing one
/// has to stay bounded by what it can do — so the answer to "can this token
/// grant itself more" is no, and it is no in one place rather than per scope.
///
/// A person at a browser can still do all of it. That is the difference
/// between an authenticated session and a credential in a file.
const NEVER: [&str; 6] = [
    "/secret/",
    "/setting/edit",
    "/setting/gcal_auth",
    "/api_token/",
    "/system/update",
    "/user/pwd",
];

/// The scopes core's own routes belong to.
///
/// Plugin routes name their scope in `internals.js`, beside the route itself,
/// because which scope a route belongs to is a statement about that route and
/// core has no business guessing it. This one is core's own and names no
/// collection, so core is the one place that can say.
const CORE_SCOPES: [(&str, &str); 1] = [("/setting/list", "read")];

/// The generic item routes, and what each of them does.
///
/// These are the routes a scope cannot be named after: one path serves every
/// collection there is, so `/itm/edit` would otherwise be a single permission
/// covering a test run and a project alike. What they are doing it *to* is in
/// the query string, and that is what the scope is named after instead.
pub fn item_route_verb(path: &str) -> Option<&'static str> {
    match path {
        "/itm/list" => Some("read"),
        "/itm/edit" | "/itm/del" => Some("write"),
        _ => None,
    }
}

/// The collection a request names, out of its query string.
///
/// Read the same way the handler reads it, so that the scope check and the
/// write it guards can never disagree about which collection is meant.
pub fn collection_of(query: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Coll {
        collection: String,
    }
    serde_qs::from_str::<Coll>(query)
        .ok()
        .map(|c| c.collection)
        .filter(|c| !c.is_empty())
}

/// Whether a request is inside what a token was issued for.
///
/// `route_scope` is the scope declared for the handler this path resolves to,
/// or `None` when nothing declares one.
pub fn scope_allows(path: &str, granted: &[String], declared: Option<&str>) -> Result<(), String> {
    // Whichever table answered for this path: the route's own scope, or the
    // one named for the collection it acts on. The caller resolves it,
    // because the caller is the one holding the tables.
    let route_scope = declared;
    if NEVER.iter().any(|p| path.starts_with(p)) {
        return Err(format!("{} is never reachable with a token", path));
    }

    let needed = match CORE_SCOPES.iter().find(|(p, _)| *p == path) {
        Some((_, scope)) => Some(*scope),
        None => route_scope,
    };

    // Fail closed. A route nobody has placed in a scope is not reachable with
    // a token — which means a route added tomorrow is unreachable until
    // somebody says where it belongs, rather than quietly inheriting whatever
    // the broadest existing token happens to hold.
    let needed = match needed {
        Some(s) => s,
        None => return Err(format!("{} is in no scope, so no token covers it", path)),
    };

    if granted.iter().any(|g| g == needed) {
        Ok(())
    } else {
        Err(format!("{} needs the '{}' scope", path, needed))
    }
}

/// How stale the "last used" mark is allowed to be.
///
/// A token in a build loop is presented many times a minute, and writing the
/// record on each of them would turn every read of the API into a write to the
/// database. The mark exists so that a person looking at a list of tokens can
/// tell which are still in use and which can be revoked; for that, a minute is
/// as good as a millisecond.
const TOUCH_INTERVAL_SECS: u64 = 60;

/// Note that a token was used, if it has not been noted recently.
pub async fn touch(srv: &Data, record: &Item) {
    let now = now();
    if now.saturating_sub(record.safe_u64(FIELD_LAST_USED, 0)) < TOUCH_INTERVAL_SECS {
        return;
    }
    let mut itm = Item::new();
    itm.id = record.id;
    itm.set_u64(FIELD_LAST_USED, now);
    srv.rw.set_item(COLLECTION, &itm, true).await;
}

// ── The endpoints that manage tokens ────────────────────────────────────────
//
// All three need a session: they are in `NEVER`, so a token cannot reach them.
// That is the rule that keeps a leaked token from renewing itself — whoever
// holds one can use the API, but making another one takes the password.

/// What a caller sends to make a token.
#[derive(serde::Deserialize)]
pub struct IssueRequest {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Days until it stops working; 0 or absent means it does not expire.
    #[serde(default)]
    pub expires_days: u64,
}

/// One token as its owner sees it afterwards — never the secret.
#[derive(serde::Serialize)]
pub struct TokenView {
    pub id: u64,
    pub name: String,
    pub shown: String,
    pub scopes: Vec<String>,
    pub created: u64,
    pub expires: u64,
    pub last_used: u64,
    pub revoked: bool,
}

impl TokenView {
    pub fn of(record: &Item) -> Self {
        TokenView {
            id: record.id,
            name: record.safe_str(FIELD_NAME, ""),
            shown: record.safe_str(FIELD_SHOWN, ""),
            scopes: scopes_of(record),
            created: record.safe_u64(FIELD_CREATED, 0),
            expires: record.safe_u64(FIELD_EXPIRES, 0),
            last_used: record.safe_u64(FIELD_LAST_USED, 0),
            revoked: record.safe_bool(FIELD_REVOKED, false),
        }
    }
}

/// Write a new token for `owner` and return it assembled, once.
pub async fn issue(srv: &Data, owner: u64, req: &IssueRequest) -> Result<(u64, String), String> {
    if req.name.trim().is_empty() {
        return Err("a token needs a name, so that it can be told from the others".to_string());
    }
    if req.scopes.is_empty() {
        return Err("a token with no scopes could not be used for anything".to_string());
    }

    let secret = generate_secret();
    let now = now();

    let mut itm = Item::new();
    itm.id = u64::MAX;
    itm.set_id(FIELD_USER, owner);
    itm.set_str(FIELD_NAME, req.name.trim());
    itm.set_str(FIELD_HASH, &hash(&secret));
    itm.set_str(FIELD_SHOWN, &shown_part(&secret));
    itm.set_str(
        FIELD_SCOPES,
        &serde_json::to_string(&req.scopes).unwrap_or_else(|_| "[]".to_string()),
    );
    itm.set_u64(FIELD_CREATED, now);
    itm.set_u64(
        FIELD_EXPIRES,
        if req.expires_days == 0 {
            0
        } else {
            now.saturating_add(req.expires_days.saturating_mul(86_400))
        },
    );
    itm.set_bool(FIELD_REVOKED, false);

    let id = srv.rw.set_item(COLLECTION, &itm, false).await;
    Ok((id, assemble(id, &secret)))
}

/// Every token belonging to one account, newest first.
pub async fn list_of(srv: &Data, owner: u64) -> Vec<TokenView> {
    let all = srv.rw.get_all_items(COLLECTION, "id", "").await;
    let mut mine: Vec<TokenView> = all
        .map
        .values()
        .filter(|r| r.safe_id(FIELD_USER, u64::MAX) == owner)
        .map(TokenView::of)
        .collect();
    mine.sort_by(|a, b| b.created.cmp(&a.created));
    mine
}

/// Stop a token working, without losing the record of it having existed.
pub async fn revoke(srv: &Data, id: u64) -> bool {
    let mut itm = Item::new();
    itm.id = id;
    itm.set_bool(FIELD_REVOKED, true);
    srv.rw.set_item(COLLECTION, &itm, true).await;
    true
}

/// Answer shapes for the three endpoints.
#[derive(serde::Serialize)]
struct Answer<T: serde::Serialize> {
    succeeded: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    error: String,
    #[serde(flatten)]
    data: T,
}

fn failed(message: &str) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"succeeded": false, "error": message}))
}

/// The account a request is being made for.
///
/// A person manages their own tokens; an administrator may also manage
/// somebody else's, which is what makes revoking a departed colleague's CI
/// token possible without their password.
async fn subject(
    data: &web::Data<State>,
    user: &Identity,
    asked_for: Option<u64>,
) -> Result<u64, HttpResponse> {
    let srv: &Data = &data.server;
    let me = match get_user(srv, principal(user)).await {
        Some(u) => u,
        None => return Err(failed("no such account")),
    };
    match asked_for {
        None => Ok(me.id),
        Some(id) if id == me.id => Ok(me.id),
        Some(id) => {
            if check_role(srv, &Some(me), "admin").await {
                Ok(id)
            } else {
                Err(failed("that is somebody else's token"))
            }
        }
    }
}

pub async fn api_token_issue(
    user: Identity,
    data: web::Data<State>,
    mut payload: web::Payload,
) -> HttpResponse {
    let limits = Limits::from_data(&data.server);
    let body: IssueRequest = match read_json_body::<IssueRequest>(&mut payload, limits).await {
        Ok(v) => v,
        Err(e) => return HttpResponse::build(e.status()).finish(),
    };
    // Deliberately the caller's own account only: a token is a credential, and
    // handing somebody a credential for an account they do not control is not
    // administration, it is impersonation.
    let owner = match subject(&data, &user, None).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    match issue(&data.server, owner, &body).await {
        Ok((id, whole)) => {
            log::info!("Issued API token {} for user {} ({})", id, owner, body.name);
            HttpResponse::Ok().json(Answer {
                succeeded: true,
                error: String::new(),
                // The one and only time this value exists outside the caller's
                // hands: the store keeps a hash and can never show it again.
                data: serde_json::json!({"id": id, "token": whole}),
            })
        }
        Err(e) => failed(&e),
    }
}

#[derive(serde::Deserialize)]
pub struct OwnerQuery {
    #[serde(default)]
    pub user: Option<u64>,
}

pub async fn api_token_list(
    user: Identity,
    data: web::Data<State>,
    query: web::Query<OwnerQuery>,
) -> HttpResponse {
    let owner = match subject(&data, &user, query.user).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    HttpResponse::Ok().json(Answer {
        succeeded: true,
        error: String::new(),
        data: serde_json::json!({"tokens": list_of(&data.server, owner).await}),
    })
}

#[derive(serde::Deserialize)]
pub struct RevokeRequest {
    pub id: u64,
}

pub async fn api_token_revoke(
    user: Identity,
    data: web::Data<State>,
    mut payload: web::Payload,
) -> HttpResponse {
    let limits = Limits::from_data(&data.server);
    let body: RevokeRequest = match read_json_body::<RevokeRequest>(&mut payload, limits).await {
        Ok(v) => v,
        Err(e) => return HttpResponse::build(e.status()).finish(),
    };
    let record = match data.server.rw.get_item(COLLECTION, body.id).await {
        Some(r) => r,
        None => return failed("no such token"),
    };
    // Whose it is decides who may revoke it. Asking for the owner rather than
    // trusting the request is the difference between revoking your own token
    // and revoking anybody's by guessing an identifier.
    if let Err(r) = subject(&data, &user, Some(record.safe_id(FIELD_USER, u64::MAX))).await {
        return r;
    }
    revoke(&data.server, body.id).await;
    log::info!("Revoked API token {}", body.id);
    HttpResponse::Ok().json(serde_json::json!({"succeeded": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(secret: &str) -> Item {
        let mut itm = Item::new();
        itm.id = 7;
        itm.set_str(FIELD_HASH, &hash(secret));
        itm.set_id(FIELD_USER, 2);
        itm
    }

    #[test]
    fn a_token_survives_the_round_trip_it_is_made_for() {
        let secret = generate_secret();
        let whole = assemble(7, &secret);
        let read = parse(&whole).expect("a token we just made must parse");
        assert_eq!(read.id, 7);
        assert_eq!(read.secret, secret);
    }

    #[test]
    fn two_secrets_are_never_the_same() {
        // Not a test of randomness, which cannot be tested here — a test that
        // the generator is called per token rather than once and cached.
        let a = generate_secret();
        let b = generate_secret();
        assert_ne!(a, b);
        assert!(a.len() >= 40, "a secret shorter than this is guessable");
    }

    #[test]
    fn anything_that_is_not_ours_is_left_alone() {
        // A deployment behind a proxy may carry an Authorization header that
        // has nothing to do with us. Every one of these must read as "no
        // token presented" rather than as a bad one, or the proxy's own
        // header would start failing requests.
        for other in [
            "",
            "mid_",
            "mid_7",
            "mid_7_",
            "mid_seven_abc",
            "ghp_realtokenbutnotours",
            "Bearer something",
        ] {
            assert_eq!(parse(other), None, "{other:?} was read as a token");
        }
    }

    #[test]
    fn the_scheme_is_read_case_insensitively_and_nothing_else_is() {
        let secret = "abc";
        let whole = assemble(3, secret);
        for spelling in ["Bearer", "bearer", "BEARER"] {
            let got = from_header(&format!("{spelling} {whole}"));
            assert_eq!(got.map(|p| p.id), Some(3), "{spelling} was not accepted");
        }
        assert_eq!(from_header(&format!("Basic {whole}")), None);
        assert_eq!(from_header(&whole), None, "a bare token is not a header");
    }

    #[test]
    fn a_good_secret_passes_and_a_wrong_one_does_not() {
        let record = stored("right");
        assert_eq!(check(&record, "right", 1_000), Ok(()));
        assert_eq!(check(&record, "wrong", 1_000), Err(Rejected::WrongSecret));
        // The empty string is the value a misconfigured client sends, and it
        // must not match a record whose hash field is somehow empty either.
        assert_eq!(check(&Item::new(), "", 1_000), Err(Rejected::WrongSecret));
    }

    #[test]
    fn a_revoked_token_is_refused_before_its_secret_is_even_read() {
        let mut record = stored("right");
        record.set_bool(FIELD_REVOKED, true);
        // The right secret, and still no.
        assert_eq!(check(&record, "right", 1_000), Err(Rejected::Revoked));
    }

    #[test]
    fn expiry_is_a_moment_not_a_suggestion() {
        let mut record = stored("right");
        record.set_u64(FIELD_EXPIRES, 1_000);
        assert_eq!(check(&record, "right", 999), Ok(()));
        // At the stated second it is over: an expiry that still worked during
        // its final second would be an off-by-one nobody would ever notice.
        assert_eq!(check(&record, "right", 1_000), Err(Rejected::Expired));
        assert_eq!(check(&record, "right", 1_001), Err(Rejected::Expired));
    }

    #[test]
    fn no_expiry_means_no_expiry() {
        let record = stored("right");
        assert_eq!(check(&record, "right", u64::MAX), Ok(()));
    }

    #[test]
    fn a_scope_is_needed_and_the_right_one() {
        let granted = vec!["read".to_string()];
        assert_eq!(
            scope_allows("/test/run", &granted, Some("read")),
            Ok(()),
            "a route declaring a scope the token holds"
        );
        assert!(scope_allows("/test/run", &granted, Some("runs")).is_err());
    }

    #[test]
    fn the_item_routes_are_named_by_what_they_do_not_by_their_path() {
        // One path, every collection: `/itm/edit` is a write to a test run
        // and a write to the project it belongs to, and those are not the
        // same permission. So these carry no scope of their own.
        assert_eq!(item_route_verb("/itm/list"), Some("read"));
        assert_eq!(item_route_verb("/itm/edit"), Some("write"));
        assert_eq!(item_route_verb("/itm/del"), Some("write"));
        assert_eq!(item_route_verb("/test/run"), None);

        // And with nothing declared for the collection, nothing is allowed —
        // the same fail-closed rule as for a route.
        let everything = vec!["read".to_string(), "write".to_string()];
        assert!(scope_allows("/itm/edit", &everything, None).is_err());
    }

    #[test]
    fn the_collection_is_read_the_way_the_handler_reads_it() {
        assert_eq!(
            collection_of("collection=test&sort_key=id").as_deref(),
            Some("test")
        );
        assert_eq!(
            collection_of("id=1&collection=analysis").as_deref(),
            Some("analysis")
        );
        // Nothing to name a scope after: refusing is then the only safe
        // answer, and `scope_allows` gets `None` and gives it.
        assert_eq!(collection_of("sort_key=id"), None);
        assert_eq!(collection_of("collection="), None);
        assert_eq!(collection_of(""), None);
    }

    /// A scope nobody declared grants nothing, and cannot be talked into
    /// granting something by being named after one.
    ///
    /// Issuing does not check the vocabulary — core does not own it, the
    /// flavour declares it — so a token can be made with any word in it. That
    /// is only safe because the word has to appear in a table on the way out
    /// as well, and this is the test that says so.
    /// The collection is not an item collection, and core says so itself.
    ///
    /// This lived in one plugin's authorization rules first, which was the
    /// wrong place twice over: a deployment loading a different plugin set
    /// had no rule at all, and the collection belongs to core rather than to
    /// any plugin. Whoever can write a token record chooses its owner and its
    /// hash — that is a working credential for somebody else's account.
    #[test]
    fn the_token_collection_is_not_reachable_as_items() {
        assert!(hidden_from_item_api(COLLECTION));
        // And nothing else is swept up with it: the rule is about this one
        // collection, not about anything whose name resembles it.
        for other in ["user", "note", "api_tokens", "api_token_x", "", "token"] {
            assert!(!hidden_from_item_api(other), "{other} was hidden too");
        }
    }

    #[test]
    fn an_invented_scope_opens_nothing() {
        let invented = vec![
            "wat".to_string(),
            "*".to_string(),
            "admin".to_string(),
            // The words the refusals are written with, in case one of them
            // were ever compared against a scope by accident.
            "never".to_string(),
            String::new(),
        ];
        assert!(scope_allows("/secret/list", &invented, None).is_err());
        assert!(scope_allows("/anything", &invented, None).is_err());
        assert!(scope_allows("/anything", &invented, Some("read")).is_err());
        // And an empty granted list is not a wildcard either.
        assert!(scope_allows("/anything", &[], Some("read")).is_err());
    }

    /// The forbidden list is about the route, not about who is asking.
    ///
    /// An administrator's token carries an administrator's permissions —
    /// that is the point of it — but the routes that mint credentials stay
    /// shut, or a leaked token would be a way to make more of itself.
    #[test]
    fn the_forbidden_list_does_not_bend_for_a_powerful_owner() {
        let everything: Vec<String> = PROVIDERS_SCOPES.iter().map(|s| s.to_string()).collect();
        for path in ["/secret/list", "/api_token/issue", "/system/update"] {
            assert!(
                scope_allows(path, &everything, Some("read")).is_err(),
                "{path} was reachable"
            );
        }
    }

    #[test]
    fn a_route_in_no_scope_is_reachable_by_no_token() {
        // The whole point of failing closed: a route added tomorrow must not
        // be quietly covered by a token issued today.
        let everything = vec!["read".to_string(), "write".to_string(), "runs".to_string()];
        assert!(scope_allows("/something/new", &everything, None).is_err());
    }

    #[test]
    fn the_forbidden_routes_are_forbidden_to_every_token() {
        let everything = vec!["read".to_string(), "write".to_string(), "admin".to_string()];
        for path in [
            "/secret/list",
            "/secret/get",
            "/setting/edit",
            "/api_token/issue",
            "/system/update",
            "/user/pwd",
        ] {
            let refused = scope_allows(path, &everything, Some("read"));
            assert!(refused.is_err(), "{path} was reachable with a token");
            assert!(
                refused.unwrap_err().contains("never"),
                "{path} was refused for the wrong reason"
            );
        }
    }

    #[test]
    fn scopes_are_read_off_the_record_and_a_broken_list_grants_nothing() {
        let mut record = Item::new();
        record.set_str(FIELD_SCOPES, r#"["read","runs"]"#);
        assert_eq!(scopes_of(&record), vec!["read", "runs"]);

        // Anything unreadable grants nothing, rather than everything.
        record.set_str(FIELD_SCOPES, "not json at all");
        assert!(scopes_of(&record).is_empty());
        assert!(scopes_of(&Item::new()).is_empty());
    }

    #[test]
    fn only_the_opening_of_a_secret_is_ever_kept_for_display() {
        let secret = generate_secret();
        let shown = shown_part(&secret);
        assert_eq!(shown.chars().count(), 6);
        assert!(secret.starts_with(&shown));
        assert!(
            shown.len() < secret.len() / 4,
            "too much of it is on screen"
        );
    }
}
