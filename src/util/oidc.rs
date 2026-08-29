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
//! OpenID Connect — as much of it as signing in needs.
//!
//! Both providers here speak the same authorization-code flow, so the parts
//! that differ are named rather than branched around: what each one calls
//! things, whether it will take a PKCE challenge, and how it wants to be paid
//! for the code. Everything else — building the authorization URL, exchanging
//! the code, checking the identity token that comes back — is one path.
//!
//! The identity token is the whole point. The token endpoint is reached over
//! TLS and answers only us, but the claims inside are what decide who is
//! logged in, so they are verified against the provider's published keys
//! rather than trusted for having arrived: signature, issuer, audience,
//! expiry, and the nonce that ties the answer to the request we started.

use base64::Engine;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a provider's signing keys are reused before being fetched again.
///
/// Providers rotate these on their own schedule and publish the new key before
/// they sign with it, so an hour-old copy verifies today's tokens. A lookup
/// that misses the key it needs refetches immediately regardless.
const JWKS_CACHE_FOR: Duration = Duration::from_secs(3600);

/// The identity providers this core can sign a user in with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
    Apple,
}

impl Provider {
    pub fn from_id(id: &str) -> Option<Provider> {
        match id {
            "google" => Some(Provider::Google),
            "apple" => Some(Provider::Apple),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::Apple => "apple",
        }
    }

    /// What a sign-in button should say.
    pub fn display_name(self) -> &'static str {
        match self {
            Provider::Google => "Google",
            Provider::Apple => "Apple",
        }
    }

    /// The name of the secret-store entry that configures this provider.
    /// Its presence is what enables the provider — there is no separate
    /// switch to leave in the wrong position.
    pub fn secret_name(self) -> &'static str {
        match self {
            Provider::Google => "oauth_google",
            Provider::Apple => "oauth_apple",
        }
    }

    /// The `iss` an identity token from this provider must carry.
    pub fn issuer(self) -> &'static str {
        match self {
            Provider::Google => "https://accounts.google.com",
            Provider::Apple => "https://appleid.apple.com",
        }
    }

    pub fn authorize_endpoint(self) -> &'static str {
        match self {
            Provider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            Provider::Apple => "https://appleid.apple.com/auth/authorize",
        }
    }

    pub fn token_endpoint(self) -> &'static str {
        match self {
            Provider::Google => "https://oauth2.googleapis.com/token",
            Provider::Apple => "https://appleid.apple.com/auth/token",
        }
    }

    pub fn jwks_uri(self) -> &'static str {
        match self {
            Provider::Google => "https://www.googleapis.com/oauth2/v3/certs",
            Provider::Apple => "https://appleid.apple.com/auth/keys",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Provider::Google => "openid email profile",
            Provider::Apple => "email name",
        }
    }

    /// Whether the authorization request carries a PKCE challenge.
    ///
    /// Google takes one and it costs nothing to send. Apple does not document
    /// support, and it is not needed there: Apple authenticates the token
    /// request with a signed client secret that only the holder of the
    /// registered private key can produce.
    pub fn uses_pkce(self) -> bool {
        matches!(self, Provider::Google)
    }

    /// Whether the provider answers by POSTing a form back to us.
    ///
    /// Apple requires it whenever any scope is requested, and the email is a
    /// scope, so there is no version of this flow where Apple comes back as a
    /// GET. It decides how the callback is routed and how the browser must be
    /// asked to return the flow's cookie.
    pub fn uses_form_post(self) -> bool {
        matches!(self, Provider::Apple)
    }
}

/// What an operator configured for one provider.
///
/// Google needs a client secret. Apple needs a key it can be asked to sign
/// with — the "secret" it wants is a fresh JWT, so the material is a private
/// key and the identifiers naming it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub team_id: String,
    pub key_id: String,
    pub private_key: String,
}

impl ProviderConfig {
    /// Whether this is enough to start a flow, and what is missing if not.
    pub fn check(&self, provider: Provider) -> Result<(), String> {
        if self.client_id.trim().is_empty() {
            return Err("client_id is not set".to_string());
        }
        match provider {
            Provider::Google => {
                if self.client_secret.trim().is_empty() {
                    return Err("client_secret is not set".to_string());
                }
            }
            Provider::Apple => {
                for (name, value) in [
                    ("team_id", &self.team_id),
                    ("key_id", &self.key_id),
                    ("private_key", &self.private_key),
                ] {
                    if value.trim().is_empty() {
                        return Err(format!("{} is not set", name));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Everything `check` asks for, plus the things that are only wrong once
/// something tries to use them.
///
/// Run when an operator saves the configuration rather than only when
/// somebody tries to sign in: an unreadable `.p8` is otherwise a silent
/// setting that fails weeks later, at a token endpoint, as somebody else's
/// problem.
pub fn validate(provider: Provider, cfg: &ProviderConfig) -> Result<(), String> {
    cfg.check(provider)?;
    if provider == Provider::Apple {
        jsonwebtoken::EncodingKey::from_ec_pem(cfg.private_key.trim().as_bytes())
            .map_err(|e| format!("the private key could not be read as an EC key: {}", e))?;
    }
    Ok(())
}

/// Whether a redirect URI is one a provider could be given.
///
/// It has to be absolute — the provider sends a browser there from its own
/// site — and a stray space in a pasted value is a mismatch that reports
/// itself only as an opaque refusal at the far end.
pub fn redirect_uri_is_usable(uri: &str) -> bool {
    let u = uri.trim();
    (u.starts_with("http://") || u.starts_with("https://"))
        && !u.chars().any(|c| c.is_whitespace())
        && u.len() > "https://".len()
}

/// Where the browser is sent to authenticate.
pub fn authorize_url(
    provider: Provider,
    cfg: &ProviderConfig,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    pkce_challenge: &str,
) -> String {
    let mut params: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", cfg.client_id.trim()),
        ("redirect_uri", redirect_uri),
        ("scope", provider.scope()),
        ("state", state),
        ("nonce", nonce),
    ];
    if provider.uses_form_post() {
        params.push(("response_mode", "form_post"));
    }
    if provider.uses_pkce() {
        params.push(("code_challenge", pkce_challenge));
        params.push(("code_challenge_method", "S256"));
    }
    // Built through a URL type rather than by hand: every one of these values
    // is either operator-supplied or random, and a stray `&` in one of them
    // would otherwise become a parameter of its own.
    match reqwest::Url::parse_with_params(provider.authorize_endpoint(), &params) {
        Ok(u) => u.to_string(),
        Err(_) => provider.authorize_endpoint().to_string(),
    }
}

/// The verifier a PKCE challenge is derived from.
pub fn pkce_challenge(verifier: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[derive(Debug, Serialize, Deserialize)]
struct AppleSecretClaims {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
    sub: String,
}

/// The string that goes in the `client_secret` parameter.
///
/// For Google it is the secret itself. Apple does not issue one: it asks for a
/// short-lived JWT signed with the private key of a registered key pair, so
/// what an operator stores is the key, and the secret is minted per request.
pub fn client_secret(provider: Provider, cfg: &ProviderConfig, now: u64) -> Result<String, String> {
    match provider {
        Provider::Google => Ok(cfg.client_secret.clone()),
        Provider::Apple => {
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
            header.kid = Some(cfg.key_id.trim().to_string());
            let claims = AppleSecretClaims {
                iss: cfg.team_id.trim().to_string(),
                iat: now,
                // Apple allows up to six months. Minutes is all a token
                // exchange needs, and a secret that cannot be revoked should
                // not outlive its use.
                exp: now + 300,
                aud: Provider::Apple.issuer().to_string(),
                sub: cfg.client_id.trim().to_string(),
            };
            let key = jsonwebtoken::EncodingKey::from_ec_pem(cfg.private_key.trim().as_bytes())
                .map_err(|e| format!("the Apple signing key could not be read: {}", e))?;
            jsonwebtoken::encode(&header, &claims, &key)
                .map_err(|e| format!("the Apple client secret could not be signed: {}", e))
        }
    }
}

/// What an identity token has to satisfy before its claims mean anything.
fn id_token_validation(
    provider: Provider,
    cfg: &ProviderConfig,
    alg: jsonwebtoken::Algorithm,
) -> jsonwebtoken::Validation {
    let mut validation = jsonwebtoken::Validation::new(alg);
    // Without the audience, a token minted for someone else's application —
    // by the same provider, with a valid signature — would be accepted here.
    validation.set_audience(&[cfg.client_id.trim()]);
    validation.set_issuer(&[provider.issuer()]);
    validation.validate_exp = true;
    // Naming them required is not the same as comparing them. `set_audience`
    // checks an audience the token carries and says nothing about one that is
    // absent, so without this a token with no `aud` at all — minted for
    // nothing in particular — passes the comparison by having nothing to
    // compare. The same goes for the issuer.
    validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
    validation
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    #[serde(default)]
    pub id_token: String,
}

/// Trade the authorization code for the identity token.
pub async fn exchange_code(
    provider: Provider,
    cfg: &ProviderConfig,
    redirect_uri: &str,
    code: &str,
    pkce_verifier: &str,
    now: u64,
) -> Result<TokenResponse, String> {
    let secret = client_secret(provider, cfg, now)?;
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", cfg.client_id.trim()),
        ("client_secret", &secret),
    ];
    if provider.uses_pkce() {
        form.push(("code_verifier", pkce_verifier));
    }

    let client = http_client()?;
    let resp = client
        .post(provider.token_endpoint())
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("reaching {}: {}", provider.display_name(), e))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        // The body carries `error_description`, which is the only thing that
        // ever says which of a dozen registration details is wrong.
        return Err(format!(
            "{} refused the authorization code ({}): {}",
            provider.display_name(),
            status.as_u16(),
            body.chars().take(300).collect::<String>()
        ));
    }
    let parsed: TokenResponse = serde_json::from_str(&body)
        .map_err(|e| format!("{} answered unreadably: {}", provider.display_name(), e))?;
    if parsed.id_token.is_empty() {
        return Err(format!(
            "{} returned no identity token",
            provider.display_name()
        ));
    }
    Ok(parsed)
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("building an HTTP client: {}", e))
}

/// Who the provider says this is.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    /// The provider's own immutable identifier for the account.
    pub subject: String,
    pub email: String,
    /// Whether the provider vouches for the address. An unverified one is not
    /// an identity — anyone can put anyone's address in a profile.
    pub email_verified: bool,
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    email: String,
    /// Google sends a JSON boolean here; Apple sends the string "true". Both
    /// mean the same thing, and refusing one of them would refuse every Apple
    /// sign-in.
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    nonce: String,
}

fn claimed_verified(v: &Option<serde_json::Value>) -> bool {
    match v {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s == "true",
        _ => false,
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    #[serde(default)]
    keys: Vec<Jwk>,
}

impl Jwk {
    fn decoding_key(&self) -> Result<jsonwebtoken::DecodingKey, String> {
        match self.kty.as_str() {
            "RSA" => jsonwebtoken::DecodingKey::from_rsa_components(&self.n, &self.e)
                .map_err(|e| format!("unusable RSA key {}: {}", self.kid, e)),
            "EC" => jsonwebtoken::DecodingKey::from_ec_components(&self.x, &self.y)
                .map_err(|e| format!("unusable EC key {}: {}", self.kid, e)),
            other => Err(format!("unsupported key type {}", other)),
        }
    }
}

static JWKS_CACHE: Mutex<Option<HashMap<String, (Jwks, Instant)>>> = Mutex::new(None);

async fn signing_keys(provider: Provider, force: bool) -> Result<Jwks, String> {
    let uri = provider.jwks_uri();
    if !force {
        let cache = JWKS_CACHE.lock();
        if let Some(map) = cache.as_ref() {
            if let Some((jwks, fetched)) = map.get(uri) {
                if fetched.elapsed() < JWKS_CACHE_FOR {
                    return Ok(jwks.clone());
                }
            }
        }
    }

    let client = http_client()?;
    let jwks: Jwks = client
        .get(uri)
        .send()
        .await
        .map_err(|e| format!("fetching {}'s signing keys: {}", provider.display_name(), e))?
        .json()
        .await
        .map_err(|e| format!("reading {}'s signing keys: {}", provider.display_name(), e))?;

    JWKS_CACHE
        .lock()
        .get_or_insert_with(HashMap::new)
        .insert(uri.to_string(), (jwks.clone(), Instant::now()));
    Ok(jwks)
}

/// Check an identity token and read who it says signed in.
///
/// Every check here is load-bearing. Without the signature the token is a
/// string the browser handed us; without `aud` a token minted for a different
/// application would be accepted; without the nonce a token captured from
/// somewhere else could be replayed into a flow we started.
pub async fn verify_id_token(
    provider: Provider,
    cfg: &ProviderConfig,
    id_token: &str,
    nonce: &str,
) -> Result<Identity, String> {
    let header = jsonwebtoken::decode_header(id_token)
        .map_err(|e| format!("the identity token is not a token: {}", e))?;
    let kid = header.kid.clone().unwrap_or_default();

    let validation = id_token_validation(provider, cfg, header.alg);

    // A key we do not know is the ordinary shape of a rotation: fetch again
    // before deciding the token is bad.
    let mut jwks = signing_keys(provider, false).await?;
    if !jwks.keys.iter().any(|k| k.kid == kid) {
        jwks = signing_keys(provider, true).await?;
    }
    check_id_token(provider, id_token, nonce, &kid, &validation, &jwks)
}

/// The verification itself, with the provider's keys already in hand.
///
/// Split out from fetching them so that what the checks actually accept and
/// reject can be stated as tests against a token this process minted, rather
/// than only against whatever a provider happens to send.
fn check_id_token(
    provider: Provider,
    id_token: &str,
    nonce: &str,
    kid: &str,
    validation: &jsonwebtoken::Validation,
    jwks: &Jwks,
) -> Result<Identity, String> {
    let jwk = jwks.keys.iter().find(|k| k.kid == kid).ok_or_else(|| {
        format!(
            "{} signed with a key it does not publish ({})",
            provider.display_name(),
            kid
        )
    })?;

    let claims = jsonwebtoken::decode::<IdTokenClaims>(id_token, &jwk.decoding_key()?, validation)
        .map_err(|e| format!("the identity token did not check out: {}", e))?
        .claims;

    if claims.nonce != nonce {
        return Err("the identity token answers a different sign-in".to_string());
    }
    if claims.sub.trim().is_empty() {
        return Err("the identity token names no account".to_string());
    }

    Ok(Identity {
        subject: claims.sub,
        email: claims.email.trim().to_lowercase(),
        email_verified: claimed_verified(&claims.email_verified),
        name: claims.name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_ids_round_trip_and_nothing_else_is_a_provider() {
        assert_eq!(Provider::from_id("google"), Some(Provider::Google));
        assert_eq!(Provider::from_id("apple"), Some(Provider::Apple));
        assert_eq!(Provider::from_id("facebook"), None);
        assert_eq!(Provider::from_id("Google"), None);
        assert_eq!(Provider::Google.id(), "google");
    }

    /// Apple will not answer with a GET once a scope is asked for, and the
    /// email is a scope — so the callback has to be prepared for a POST.
    #[test]
    fn apple_comes_back_as_a_post_and_google_does_not() {
        assert!(Provider::Apple.uses_form_post());
        assert!(!Provider::Google.uses_form_post());
        assert!(Provider::Google.uses_pkce());
        assert!(!Provider::Apple.uses_pkce());
    }

    #[test]
    fn the_authorization_url_carries_what_the_flow_is_bound_to() {
        let cfg = ProviderConfig {
            client_id: "cid".into(),
            ..Default::default()
        };
        let url = authorize_url(
            Provider::Google,
            &cfg,
            "https://example.test/auth/google/callback",
            "st",
            "no",
            "ch",
        );
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("state=st"));
        assert!(url.contains("nonce=no"));
        assert!(url.contains("code_challenge=ch"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.test%2Fauth%2Fgoogle%2Fcallback"));
        assert!(!url.contains("response_mode"));
    }

    #[test]
    fn apple_is_asked_to_post_its_answer_and_is_sent_no_challenge() {
        let cfg = ProviderConfig {
            client_id: "cid".into(),
            ..Default::default()
        };
        let url = authorize_url(Provider::Apple, &cfg, "https://e.test/cb", "st", "no", "ch");
        assert!(url.contains("response_mode=form_post"));
        assert!(!url.contains("code_challenge"));
    }

    /// A client id with a reserved character in it must not become two
    /// parameters.
    #[test]
    fn a_value_cannot_smuggle_a_parameter_into_the_url() {
        let cfg = ProviderConfig {
            client_id: "cid&scope=evil".into(),
            ..Default::default()
        };
        let url = authorize_url(Provider::Google, &cfg, "https://e.test/cb", "s", "n", "c");
        assert!(url.contains("client_id=cid%26scope%3Devil"), "{url}");
        assert_eq!(url.matches("scope=").count(), 1, "{url}");
    }

    /// RFC 7636's own example, so the derivation is checked against the
    /// specification rather than against itself.
    #[test]
    fn the_pkce_challenge_is_the_digest_of_the_verifier() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_provider_missing_its_credentials_says_which_one() {
        let empty = ProviderConfig::default();
        assert_eq!(
            empty.check(Provider::Google),
            Err("client_id is not set".to_string())
        );
        let no_secret = ProviderConfig {
            client_id: "cid".into(),
            ..Default::default()
        };
        assert_eq!(
            no_secret.check(Provider::Google),
            Err("client_secret is not set".to_string())
        );
        // Apple asks for different things, and says so.
        assert_eq!(
            no_secret.check(Provider::Apple),
            Err("team_id is not set".to_string())
        );
        let apple = ProviderConfig {
            client_id: "cid".into(),
            team_id: "T".into(),
            key_id: "K".into(),
            private_key: "PEM".into(),
            ..Default::default()
        };
        assert_eq!(apple.check(Provider::Apple), Ok(()));
    }

    /// Google's secret is a stored string; Apple's is minted, and unreadable
    /// key material must fail here rather than at the token endpoint.
    #[test]
    fn googles_secret_is_the_stored_one_and_apples_is_signed() {
        let google = ProviderConfig {
            client_id: "cid".into(),
            client_secret: "shh".into(),
            ..Default::default()
        };
        assert_eq!(
            client_secret(Provider::Google, &google, 1_000).unwrap(),
            "shh"
        );

        let apple = ProviderConfig {
            client_id: "cid".into(),
            team_id: "T".into(),
            key_id: "K".into(),
            private_key: "not a key".into(),
            ..Default::default()
        };
        let err = client_secret(Provider::Apple, &apple, 1_000).unwrap_err();
        assert!(err.contains("Apple signing key"), "{err}");
    }

    /// A real ES256 key, so the minted secret is checked as a token and not
    /// just as a non-empty string.
    #[test]
    fn the_apple_secret_says_who_is_asking_and_for_how_long() {
        // Generated for this test alone; it authenticates nothing.
        let pem = "-----BEGIN PRIVATE KEY-----\n\
             MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
             OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
             1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
             -----END PRIVATE KEY-----";
        let cfg = ProviderConfig {
            client_id: "io.example.web".into(),
            team_id: "TEAM123456".into(),
            key_id: "KEY1234567".into(),
            private_key: pem.into(),
            ..Default::default()
        };
        let token = client_secret(Provider::Apple, &cfg, 1_000_000).unwrap();

        let mut parts = token.split('.');
        let dec = |s: &str| {
            String::from_utf8(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(s)
                    .unwrap(),
            )
            .unwrap()
        };
        let header: serde_json::Value = serde_json::from_str(&dec(parts.next().unwrap())).unwrap();
        let claims: AppleSecretClaims = serde_json::from_str(&dec(parts.next().unwrap())).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY1234567");
        assert_eq!(claims.iss, "TEAM123456");
        assert_eq!(claims.sub, "io.example.web");
        assert_eq!(claims.aud, "https://appleid.apple.com");
        assert_eq!(claims.exp, 1_000_300, "a mintable secret should be short");
    }

    /// Apple sends the string "true" where Google sends a boolean. Reading
    /// only one of them would reject every Apple sign-in.
    #[test]
    fn both_spellings_of_a_verified_address_are_understood() {
        assert!(claimed_verified(&Some(serde_json::json!(true))));
        assert!(claimed_verified(&Some(serde_json::json!("true"))));
        assert!(!claimed_verified(&Some(serde_json::json!(false))));
        assert!(!claimed_verified(&Some(serde_json::json!("false"))));
        assert!(!claimed_verified(&None));
    }

    // ---- Identity-token verification -----------------------------------
    //
    // Every check below is what stands between a string the browser handed us
    // and a session. They are exercised against a token this test mints, so
    // each one can be broken deliberately and seen to be caught.

    /// The key pair used to mint test tokens. Generated for these tests
    /// alone; it authenticates nothing.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
         MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
         OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
         1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
         -----END PRIVATE KEY-----";

    /// The same key as the provider would publish it.
    fn test_jwks(kid: &str) -> Jwks {
        Jwks {
            keys: vec![Jwk {
                kid: kid.to_string(),
                kty: "EC".to_string(),
                n: String::new(),
                e: String::new(),
                x: "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84".to_string(),
                y: "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY".to_string(),
            }],
        }
    }

    fn mint(claims: serde_json::Value, kid: &str) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(kid.to_string());
        let key = jsonwebtoken::EncodingKey::from_ec_pem(TEST_KEY_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    fn in_an_hour() -> u64 {
        (chrono::Utc::now().timestamp() as u64) + 3600
    }

    fn good_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": Provider::Apple.issuer(),
            "aud": "io.example.web",
            "sub": "001122.abc",
            "exp": in_an_hour(),
            "email": "Someone@Example.COM",
            "email_verified": "true",
            "nonce": "the-nonce",
            "name": "Someone",
        })
    }

    fn test_cfg() -> ProviderConfig {
        ProviderConfig {
            client_id: "io.example.web".into(),
            ..Default::default()
        }
    }

    fn check(claims: serde_json::Value, kid: &str, nonce: &str) -> Result<Identity, String> {
        let cfg = test_cfg();
        let token = mint(claims, kid);
        let validation = id_token_validation(Provider::Apple, &cfg, jsonwebtoken::Algorithm::ES256);
        check_id_token(
            Provider::Apple,
            &token,
            nonce,
            kid,
            &validation,
            &test_jwks("k1"),
        )
    }

    #[test]
    fn a_good_token_yields_the_identity_inside_it() {
        let id = check(good_claims(), "k1", "the-nonce").unwrap();
        assert_eq!(id.subject, "001122.abc");
        // Addresses are compared elsewhere against records written in lower
        // case, so they are folded here rather than at each use.
        assert_eq!(id.email, "someone@example.com");
        assert!(id.email_verified);
        assert_eq!(id.name, "Someone");
    }

    /// Without this, a token the provider minted for a different application
    /// would sign its holder into this one.
    #[test]
    fn a_token_for_another_application_is_refused() {
        let mut claims = good_claims();
        claims["aud"] = serde_json::json!("io.somebody-else.web");
        assert!(check(claims, "k1", "the-nonce").is_err());
    }

    /// Without this, a token from any issuer whose key we happen to hold
    /// would do.
    #[test]
    fn a_token_from_another_issuer_is_refused() {
        let mut claims = good_claims();
        claims["iss"] = serde_json::json!("https://accounts.google.com");
        assert!(check(claims, "k1", "the-nonce").is_err());
    }

    #[test]
    fn an_expired_token_is_refused() {
        let mut claims = good_claims();
        claims["exp"] = serde_json::json!(1_000_000);
        assert!(check(claims, "k1", "the-nonce").is_err());
    }

    /// The nonce is what ties the answer to the request we started, so a
    /// token captured from another sign-in cannot be replayed into ours.
    #[test]
    fn a_token_answering_a_different_sign_in_is_refused() {
        let err = check(good_claims(), "k1", "a-different-nonce").unwrap_err();
        assert!(err.contains("different sign-in"), "{err}");
    }

    /// The signature is the only reason to believe any of the rest.
    #[test]
    fn a_tampered_token_is_refused() {
        let cfg = test_cfg();
        let token = mint(good_claims(), "k1");
        // Rewrite one character of the payload, leaving the signature behind.
        let mut parts: Vec<String> = token.split('.').map(|s| s.to_string()).collect();
        let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&parts[1])
            .unwrap();
        let body = String::from_utf8(raw.clone()).unwrap();
        raw = body.replace("001122.abc", "001122.xyz").as_bytes().to_vec();
        parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let forged = parts.join(".");

        let validation = id_token_validation(Provider::Apple, &cfg, jsonwebtoken::Algorithm::ES256);
        assert!(check_id_token(
            Provider::Apple,
            &forged,
            "the-nonce",
            "k1",
            &validation,
            &test_jwks("k1")
        )
        .is_err());
    }

    /// A token signed with a key the provider does not publish is refused —
    /// which is also what a rotation looks like before the keys are refetched.
    #[test]
    fn a_token_signed_with_an_unpublished_key_is_refused() {
        let err = check(good_claims(), "k2", "the-nonce").unwrap_err();
        assert!(err.contains("does not publish"), "{err}");
    }

    /// An identity with no subject is not an identity, however well signed.
    #[test]
    fn a_token_naming_no_account_is_refused() {
        let mut claims = good_claims();
        claims["sub"] = serde_json::json!("");
        let err = check(claims, "k1", "the-nonce").unwrap_err();
        assert!(err.contains("names no account"), "{err}");
    }

    /// Verification does not judge the address — that is the sign-in policy's
    /// job — but it must report faithfully what the provider claimed.
    #[test]
    fn an_unverified_address_is_reported_as_unverified() {
        let mut claims = good_claims();
        claims["email_verified"] = serde_json::json!(false);
        assert!(!check(claims, "k1", "the-nonce").unwrap().email_verified);
    }

    /// A key that cannot be read is the difference between a setting that is
    /// wrong now and one that fails at a token endpoint next month.
    #[test]
    fn an_unreadable_apple_key_is_caught_when_it_is_saved() {
        let mut cfg = ProviderConfig {
            client_id: "cid".into(),
            team_id: "T".into(),
            key_id: "K".into(),
            private_key: "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----".into(),
            ..Default::default()
        };
        assert!(validate(Provider::Apple, &cfg).is_err());
        cfg.private_key = TEST_KEY_PEM.to_string();
        assert_eq!(validate(Provider::Apple, &cfg), Ok(()));
    }

    /// Google has no key to check, so validation is presence and no more.
    #[test]
    fn google_is_valid_once_it_has_both_halves() {
        let cfg = ProviderConfig {
            client_id: "cid".into(),
            client_secret: "shh".into(),
            ..Default::default()
        };
        assert_eq!(validate(Provider::Google, &cfg), Ok(()));
    }

    #[test]
    fn a_redirect_uri_has_to_be_somewhere_a_browser_could_be_sent() {
        assert!(redirect_uri_is_usable(
            "https://example.test/api/auth/google/callback"
        ));
        assert!(redirect_uri_is_usable(
            "http://localhost:8090/auth/google/callback"
        ));
        assert!(!redirect_uri_is_usable("/auth/google/callback"));
        assert!(!redirect_uri_is_usable("example.test/callback"));
        // Pasted with a newline on the end — trimmed, and stored trimmed.
        assert!(redirect_uri_is_usable("https://example.test/cb\n"));
        // Whitespace in the middle is a different address, not a stray one.
        assert!(!redirect_uri_is_usable("https://example.test/c b"));
        assert!(!redirect_uri_is_usable("https://"));
    }

    /// Algorithm confusion: a token that names a symmetric algorithm, signed
    /// with the provider's *public* key as if it were a shared secret. The
    /// validation is built from the token's own header, so this is the shape
    /// that has to be refused by the key rather than by the header.
    #[test]
    fn a_token_that_chooses_its_own_algorithm_is_refused() {
        let public_key_as_secret = b"EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84";
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("k1".to_string());
        let forged = jsonwebtoken::encode(
            &header,
            &good_claims(),
            &jsonwebtoken::EncodingKey::from_secret(public_key_as_secret),
        )
        .unwrap();

        let cfg = test_cfg();
        let validation = id_token_validation(Provider::Apple, &cfg, jsonwebtoken::Algorithm::HS256);
        let outcome = check_id_token(
            Provider::Apple,
            &forged,
            "the-nonce",
            "k1",
            &validation,
            &test_jwks("k1"),
        );
        assert!(outcome.is_err(), "an HS256 token was accepted: {outcome:?}");
    }

    /// The same shape reached the way the real code reaches it — the
    /// algorithm taken from the header — so the refusal does not depend on
    /// the caller having guessed right.
    #[test]
    fn the_algorithm_in_the_header_cannot_pick_a_key_that_does_not_fit_it() {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("k1".to_string());
        let forged = jsonwebtoken::encode(
            &header,
            &good_claims(),
            &jsonwebtoken::EncodingKey::from_secret(b"anything at all"),
        )
        .unwrap();

        let parsed = jsonwebtoken::decode_header(&forged).unwrap();
        assert_eq!(parsed.alg, jsonwebtoken::Algorithm::HS256);
        let cfg = test_cfg();
        let validation = id_token_validation(Provider::Apple, &cfg, parsed.alg);
        assert!(check_id_token(
            Provider::Apple,
            &forged,
            "the-nonce",
            "k1",
            &validation,
            &test_jwks("k1")
        )
        .is_err());
    }

    /// An unsigned token — the other half of the same family.
    #[test]
    fn an_unsigned_token_is_not_a_token() {
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(good_claims().to_string());
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"k1"}"#);
        let unsigned = format!("{}.{}.", header, payload);
        // It does not even parse as a token this crate will consider.
        assert!(jsonwebtoken::decode_header(&unsigned).is_err());
    }

    /// A token with no `kid` cannot name a key, and must not fall through to
    /// whichever key happens to be first.
    #[test]
    fn a_token_naming_no_key_is_refused() {
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        let key = jsonwebtoken::EncodingKey::from_ec_pem(TEST_KEY_PEM.as_bytes()).unwrap();
        let token = jsonwebtoken::encode(&header, &good_claims(), &key).unwrap();
        assert!(jsonwebtoken::decode_header(&token).unwrap().kid.is_none());

        let cfg = test_cfg();
        let validation = id_token_validation(Provider::Apple, &cfg, jsonwebtoken::Algorithm::ES256);
        let err = check_id_token(
            Provider::Apple,
            &token,
            "the-nonce",
            "",
            &validation,
            &test_jwks("k1"),
        )
        .unwrap_err();
        assert!(err.contains("does not publish"), "{err}");
    }

    /// A key the provider publishes but which is not the sort it says it is.
    #[test]
    fn a_key_of_an_unusable_kind_is_refused_rather_than_guessed_at() {
        let jwks = Jwks {
            keys: vec![Jwk {
                kid: "k1".to_string(),
                kty: "OKP".to_string(),
                ..test_jwks("k1").keys[0].clone()
            }],
        };
        let cfg = test_cfg();
        let validation = id_token_validation(Provider::Apple, &cfg, jsonwebtoken::Algorithm::ES256);
        let err = check_id_token(
            Provider::Apple,
            &mint(good_claims(), "k1"),
            "the-nonce",
            "k1",
            &validation,
            &jwks,
        )
        .unwrap_err();
        assert!(err.contains("unsupported key type"), "{err}");
    }

    /// The audience may be a list, and this application being one of several
    /// named is still this application being named.
    #[test]
    fn an_audience_list_containing_us_is_accepted() {
        let mut claims = good_claims();
        claims["aud"] = serde_json::json!(["io.example.web", "io.example.ios"]);
        assert!(check(claims, "k1", "the-nonce").is_ok());
    }

    /// …and one that does not name us is not.
    #[test]
    fn an_audience_list_without_us_is_refused() {
        let mut claims = good_claims();
        claims["aud"] = serde_json::json!(["io.somebody.web", "io.somebody.ios"]);
        assert!(check(claims, "k1", "the-nonce").is_err());
    }

    /// A token with no audience at all names nobody, so it names not us.
    #[test]
    fn a_token_with_no_audience_is_refused() {
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("aud");
        assert!(check(claims, "k1", "the-nonce").is_err());
    }

    #[test]
    fn a_token_with_no_expiry_is_refused() {
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("exp");
        assert!(check(claims, "k1", "the-nonce").is_err());
    }

    /// A token that carries no nonce cannot be answering the sign-in we
    /// started, whatever else is right about it.
    #[test]
    fn a_token_with_no_nonce_is_refused() {
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("nonce");
        let err = check(claims, "k1", "the-nonce").unwrap_err();
        assert!(err.contains("different sign-in"), "{err}");
    }

    /// Garbage in the token position is a refusal, not a panic.
    #[test]
    fn something_that_is_not_a_token_at_all_is_refused() {
        let cfg = test_cfg();
        let validation = id_token_validation(Provider::Apple, &cfg, jsonwebtoken::Algorithm::ES256);
        for junk in ["", "....", "not.a.token", "a.b", "eyJhbGciOiJFUzI1NiJ9"] {
            assert!(
                check_id_token(
                    Provider::Apple,
                    junk,
                    "the-nonce",
                    "k1",
                    &validation,
                    &test_jwks("k1")
                )
                .is_err(),
                "{junk:?}"
            );
        }
    }

    /// The subject is what identifies the account for good, so it must be
    /// carried through exactly rather than trimmed or folded like the
    /// address is.
    #[test]
    fn the_subject_is_carried_through_untouched() {
        let mut claims = good_claims();
        claims["sub"] = serde_json::json!("001122.AbCdEf.3344");
        assert_eq!(
            check(claims, "k1", "the-nonce").unwrap().subject,
            "001122.AbCdEf.3344"
        );
    }

    /// A whitespace-only subject names nobody either.
    #[test]
    fn a_blank_subject_names_no_account() {
        let mut claims = good_claims();
        claims["sub"] = serde_json::json!("   ");
        assert!(check(claims, "k1", "the-nonce")
            .unwrap_err()
            .contains("names no account"));
    }

    /// An entry with no name is not an error; the address is what an account
    /// is made from.
    #[test]
    fn a_token_without_a_name_still_identifies_somebody() {
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("name");
        let id = check(claims, "k1", "the-nonce").unwrap();
        assert_eq!(id.name, "");
        assert_eq!(id.email, "someone@example.com");
    }
}
