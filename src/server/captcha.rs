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
//! A check that the person at a sign-in form is a person.
//!
//! The forms nobody is signed in for — signing in, asking for a one-time
//! code, making an account — are the ones a script can hammer: to guess
//! passwords, to send mail to addresses that never asked for it, to fill the
//! user list. reCAPTCHA v3 scores each submission without showing anybody a
//! puzzle; the browser gets a token from Google and sends it with the form,
//! and this module asks Google what the token is worth.
//!
//! Off by default. It is made only when an administrator has switched it on
//! in the settings (`captcha_enabled`) and both keys are in the environment,
//! so a deployment that never asked for it behaves exactly as before, and one
//! that did can switch it off again without a shell on the server:
//!
//!   RECAPTCHA_SITE_KEY     the public key, handed to the sign-in screens
//!   RECAPTCHA_SECRET_KEY   the secret key, which never leaves this process
//!   RECAPTCHA_MIN_SCORE    lowest score let through, 0.0 to 1.0 (default 0.5)
//!   RECAPTCHA_VERIFY_URL   where to ask, for a test stand (default Google)
//!
//! Two rules decide every case. A submission Google calls a robot, or one
//! with no usable token, is refused. A check that could not be made — Google
//! not answering, or answering that our own key is wrong — lets the
//! submission through and says so in the log: the alternative is that an
//! outage somewhere else, or one mistyped key, locks every user and every
//! administrator out of the deployment, with no way in to correct it.

use log::{error, info, warn};
use serde::Deserialize;
use std::time::Duration;

const SITE_KEY_VAR: &str = "RECAPTCHA_SITE_KEY";
const SECRET_KEY_VAR: &str = "RECAPTCHA_SECRET_KEY";
const MIN_SCORE_VAR: &str = "RECAPTCHA_MIN_SCORE";
const VERIFY_URL_VAR: &str = "RECAPTCHA_VERIFY_URL";

const VERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";
const MIN_SCORE: f64 = 0.5;

/// How long a sign-in waits for Google before going on without it.
const WAIT_FOR: Duration = Duration::from_secs(5);

/// What a refused person is told. One sentence for every reason: which of
/// them it was is for the log, and of no use to a robot.
pub const REFUSED: &str =
    "We could not confirm that you are not a robot. Reload the page and try again.";

/// The form field the token travels in.
pub const FIELD: &str = "captcha";

/// The check as this deployment is set up to make it.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub site_key: String,
    secret: String,
    min_score: f64,
    verify_url: String,
}

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The setting that switches the check on. Absent is off.
pub const ENABLED: &str = "captcha_enabled";

/// The check, when an administrator has switched it on and it can be made.
pub async fn active(srv: &crate::state::data::Data) -> Option<Config> {
    use crate::state::store::Store;
    let on = srv
        .rw
        .get_settings()
        .await
        .bools
        .get(ENABLED)
        .copied()
        .unwrap_or(false);
    if on {
        config()
    } else {
        None
    }
}

/// The check as the environment describes it, switched on or not.
pub fn config() -> Option<Config> {
    config_from(
        env_opt(SITE_KEY_VAR),
        env_opt(SECRET_KEY_VAR),
        env_opt(MIN_SCORE_VAR),
        env_opt(VERIFY_URL_VAR),
    )
}

/// Half a pair is not a check: a site key alone would make every browser ask
/// Google for a token nobody verifies, and a secret alone would refuse every
/// form, since no browser was told to bring one.
fn config_from(
    site_key: Option<String>,
    secret: Option<String>,
    min_score: Option<String>,
    verify_url: Option<String>,
) -> Option<Config> {
    let (site_key, secret) = match (site_key, secret) {
        (Some(k), Some(s)) => (k, s),
        (None, None) => return None,
        (k, _) => {
            warn!(
                "{} is set and {} is not: the sign-in check stays off until both are",
                if k.is_some() {
                    SITE_KEY_VAR
                } else {
                    SECRET_KEY_VAR
                },
                if k.is_some() {
                    SECRET_KEY_VAR
                } else {
                    SITE_KEY_VAR
                },
            );
            return None;
        }
    };
    let min_score = min_score
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| (0.0..=1.0).contains(v))
        .unwrap_or(MIN_SCORE);
    Some(Config {
        site_key,
        secret,
        min_score,
        verify_url: verify_url.unwrap_or_else(|| VERIFY_URL.to_string()),
    })
}

/// What the sign-in screens are told: which key to ask Google with, or
/// nothing when the check is off.
pub async fn public_view(srv: &crate::state::data::Data) -> serde_json::Value {
    match active(srv).await {
        Some(c) => serde_json::json!({ "provider": "recaptcha", "site_key": c.site_key }),
        None => serde_json::Value::Null,
    }
}

/// Google's answer about one token.
#[derive(Debug, Default, Deserialize)]
struct Answer {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    action: Option<String>,
    #[serde(rename = "error-codes", default)]
    error_codes: Vec<String>,
}

/// What an answer means for the submission it came with.
#[derive(Debug, PartialEq)]
enum Judgement {
    /// A person, as far as Google can tell.
    Person,
    /// Refused, and why — for the log.
    Robot(String),
    /// The check itself is broken on our side, and why.
    Broken(String),
}

fn judge(answer: &Answer, action: &str, min_score: f64) -> Judgement {
    if !answer.success {
        // Google names the secret when the secret is what is wrong. That is
        // this deployment's mistake and not the visitor's.
        if answer.error_codes.iter().any(|c| c.contains("secret")) {
            return Judgement::Broken(format!(
                "the secret key was not accepted ({})",
                answer.error_codes.join(", ")
            ));
        }
        return Judgement::Robot(format!(
            "the token was not accepted ({})",
            answer.error_codes.join(", ")
        ));
    }
    // A token is issued for one form. One taken from a different form — or
    // from a different page of the same site — proves nothing about this one.
    match answer.action.as_deref() {
        Some(a) if a == action => {}
        other => {
            return Judgement::Robot(format!(
                "the token is for {:?}, not for {:?}",
                other.unwrap_or(""),
                action
            ))
        }
    }
    match answer.score {
        Some(s) if s >= min_score => Judgement::Person,
        Some(s) => Judgement::Robot(format!("score {} is below {}", s, min_score)),
        // No score means these are not v3 keys; a v2 answer carries none.
        None => Judgement::Broken("the answer has no score: the keys are not reCAPTCHA v3".into()),
    }
}

/// Whether the submission that brought `token` may go on. `Err` is what to
/// tell the person; with the check off, everything may.
pub async fn check(
    srv: &crate::state::data::Data,
    token: &str,
    action: &str,
) -> Result<(), &'static str> {
    check_with(active(srv).await, token, action).await
}

async fn check_with(cfg: Option<Config>, token: &str, action: &str) -> Result<(), &'static str> {
    let cfg = match cfg {
        Some(c) => c,
        None => return Ok(()),
    };
    let token = token.trim();
    if token.is_empty() {
        info!("captcha: {} refused: no token", action);
        return Err(REFUSED);
    }
    let answer = match ask(&cfg, token).await {
        Ok(a) => a,
        Err(e) => {
            warn!(
                "captcha: could not be checked ({}), letting the {} through",
                e, action
            );
            return Ok(());
        }
    };
    match judge(&answer, action, cfg.min_score) {
        Judgement::Person => Ok(()),
        Judgement::Robot(why) => {
            info!("captcha: {} refused: {}", action, why);
            Err(REFUSED)
        }
        Judgement::Broken(why) => {
            error!(
                "captcha: the check is not working — {}; letting the {} through",
                why, action
            );
            Ok(())
        }
    }
}

async fn ask(cfg: &Config, token: &str) -> Result<Answer, String> {
    let client = reqwest::Client::builder()
        .timeout(WAIT_FOR)
        .build()
        .map_err(|e| format!("building an HTTP client: {}", e))?;
    let resp = client
        .post(&cfg.verify_url)
        .form(&[("secret", cfg.secret.as_str()), ("response", token)])
        .send()
        .await
        // Without the address: the secret is in the body, not there, but an
        // error that prints a URL invites one that some day prints more.
        .map_err(|e| format!("asking: {}", e.without_url()))?;
    if !resp.status().is_success() {
        return Err(format!("the answer was HTTP {}", resp.status().as_u16()));
    }
    resp.json::<Answer>()
        .await
        .map_err(|e| format!("reading the answer: {}", e.without_url()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(json: &str) -> Answer {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_person_at_the_right_form_goes_on() {
        let a = answer(r#"{"success":true,"score":0.9,"action":"login","hostname":"x"}"#);
        assert_eq!(judge(&a, "login", 0.5), Judgement::Person);
        // The threshold itself is let through.
        let a = answer(r#"{"success":true,"score":0.5,"action":"login"}"#);
        assert_eq!(judge(&a, "login", 0.5), Judgement::Person);
    }

    #[test]
    fn a_low_score_is_a_robot() {
        let a = answer(r#"{"success":true,"score":0.1,"action":"login"}"#);
        assert!(matches!(judge(&a, "login", 0.5), Judgement::Robot(_)));
        // The same answer under a threshold it clears.
        assert_eq!(judge(&a, "login", 0.1), Judgement::Person);
    }

    #[test]
    fn a_token_from_another_form_is_a_robot() {
        let a = answer(r#"{"success":true,"score":0.9,"action":"waitlist"}"#);
        assert!(matches!(judge(&a, "login", 0.5), Judgement::Robot(_)));
        let a = answer(r#"{"success":true,"score":0.9}"#);
        assert!(matches!(judge(&a, "login", 0.5), Judgement::Robot(_)));
    }

    #[test]
    fn a_spent_or_made_up_token_is_a_robot() {
        for code in ["timeout-or-duplicate", "invalid-input-response"] {
            let a = answer(&format!(r#"{{"success":false,"error-codes":["{code}"]}}"#));
            assert!(
                matches!(judge(&a, "login", 0.5), Judgement::Robot(_)),
                "{code}"
            );
        }
        // Said nothing at all about why: still not a person.
        let a = answer(r#"{"success":false}"#);
        assert!(matches!(judge(&a, "login", 0.5), Judgement::Robot(_)));
    }

    #[test]
    fn a_wrong_secret_is_our_fault_not_the_visitors() {
        for code in ["invalid-input-secret", "missing-input-secret"] {
            let a = answer(&format!(r#"{{"success":false,"error-codes":["{code}"]}}"#));
            assert!(
                matches!(judge(&a, "login", 0.5), Judgement::Broken(_)),
                "{code}"
            );
        }
    }

    #[test]
    fn keys_of_the_wrong_kind_are_our_fault() {
        let a = answer(r#"{"success":true,"action":"login"}"#);
        assert!(matches!(judge(&a, "login", 0.5), Judgement::Broken(_)));
    }

    #[test]
    fn the_check_needs_both_keys() {
        let s = |v: &str| Some(v.to_string());
        assert!(config_from(None, None, None, None).is_none());
        assert!(config_from(s("site"), None, None, None).is_none());
        assert!(config_from(None, s("secret"), None, None).is_none());
        let c = config_from(s("site"), s("secret"), None, None).unwrap();
        assert_eq!(c.site_key, "site");
        assert_eq!(c.min_score, MIN_SCORE);
        assert_eq!(c.verify_url, VERIFY_URL);
    }

    #[test]
    fn a_threshold_that_is_not_one_falls_back() {
        let s = |v: &str| Some(v.to_string());
        let with = |score: &str| {
            config_from(s("site"), s("secret"), s(score), None)
                .unwrap()
                .min_score
        };
        assert_eq!(with("0.7"), 0.7);
        assert_eq!(with("0"), 0.0);
        assert_eq!(with("7"), MIN_SCORE);
        assert_eq!(with("-1"), MIN_SCORE);
        assert_eq!(with("high"), MIN_SCORE);
    }

    /// A stand-in for Google: answers every request with `body`, and says
    /// where it listens.
    fn stand_in(body: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });
        format!("http://{}/siteverify", addr)
    }

    fn asking(url: String) -> Option<Config> {
        Some(Config {
            site_key: "site".into(),
            secret: "secret".into(),
            min_score: MIN_SCORE,
            verify_url: url,
        })
    }

    #[actix_web::test]
    async fn switched_off_it_asks_for_nothing() {
        assert_eq!(check_with(None, "", "login").await, Ok(()));
    }

    #[actix_web::test]
    async fn a_form_without_a_token_is_refused_unasked() {
        // The address answers nobody: had it been asked, the check would have
        // been "not made" and the form let through.
        let cfg = asking("http://127.0.0.1:1/siteverify".into());
        assert_eq!(check_with(cfg.clone(), "", "login").await, Err(REFUSED));
        assert_eq!(check_with(cfg, "   ", "login").await, Err(REFUSED));
    }

    #[actix_web::test]
    async fn a_person_is_let_in_and_a_robot_is_not() {
        let person = stand_in(r#"{"success":true,"score":0.9,"action":"login"}"#);
        assert_eq!(
            check_with(asking(person.clone()), "tok", "login").await,
            Ok(())
        );
        // The same good token, brought to a different form.
        assert_eq!(
            check_with(asking(person), "tok", "register").await,
            Err(REFUSED)
        );
        let robot = stand_in(r#"{"success":true,"score":0.1,"action":"login"}"#);
        assert_eq!(
            check_with(asking(robot), "tok", "login").await,
            Err(REFUSED)
        );
    }

    #[actix_web::test]
    async fn a_check_that_cannot_be_made_locks_nobody_out() {
        // Nothing listens there.
        let down = asking("http://127.0.0.1:1/siteverify".into());
        assert_eq!(check_with(down, "tok", "login").await, Ok(()));
        // It answers, and what it says is that our key is wrong.
        let wrong_key = stand_in(r#"{"success":false,"error-codes":["invalid-input-secret"]}"#);
        assert_eq!(check_with(asking(wrong_key), "tok", "login").await, Ok(()));
        // It answers something that is not an answer.
        let nonsense = stand_in("<html>");
        assert_eq!(check_with(asking(nonsense), "tok", "login").await, Ok(()));
    }

    #[test]
    fn the_refusal_names_no_reason() {
        assert!(!REFUSED.contains("score"));
        assert!(!REFUSED.contains("token"));
    }
}
