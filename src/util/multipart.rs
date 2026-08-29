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

//! Bounded reading of `multipart/form-data` request bodies.
//!
//! Every handler that accepts a multipart body used to spell out the same
//! two nested loops:
//!
//! ```ignore
//! while let Ok(Some(mut field)) = payload.try_next().await {
//!     while let Ok(Some(chunk)) = field.try_next().await { … }
//! }
//! ```
//!
//! which has two problems that no amount of care at the call site can fix.
//!
//! It has no deadline. A body whose framing is correct — `Content-Length`
//! matches, boundary matches the header — but whose multipart structure is
//! left unfinished never yields another field and never ends, so the request
//! is never answered and the connection is pinned for as long as the client
//! cares to wait. The same holds for a complete body delivered one byte every
//! few seconds: actix times out incomplete *headers*, but nothing times out a
//! body. Either way an unauthenticated client can park an unbounded number of
//! requests, each costing a socket and a task.
//!
//! It has no size limit. `web::PayloadConfig` is consulted by the `Json` and
//! `Bytes` extractors, but `actix_multipart::Multipart` reads the stream
//! itself and never sees it — so the one family of endpoints that exists to
//! accept uploads was the one family the configured maximum did not cover.
//!
//! [`read_fields`] applies both bounds while it reads, and reports which one
//! it hit so the caller can answer 400 or 413 rather than hang.

use actix_multipart::Multipart;
use actix_web::rt::time::timeout;
use futures_util::TryStreamExt;
use std::collections::HashMap;
use std::time::Duration;

/// Why a multipart body could not be read in full.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The deadline expired with the body still unfinished. Covers both the
    /// never-closed part and the byte-per-second trickle.
    Timeout,
    /// The body is larger than the configured maximum. Carries how far it had
    /// got when the count was exceeded, for the log.
    TooLarge(usize),
    /// The stream itself is malformed — bad framing, a truncated part header.
    Malformed(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Timeout => write!(f, "timed out while reading the body"),
            ReadError::TooLarge(n) => write!(f, "body exceeds the maximum size ({} bytes read)", n),
            ReadError::Malformed(e) => write!(f, "malformed multipart body: {}", e),
        }
    }
}

impl ReadError {
    /// The status a client should be told. A body too large is 413 — a
    /// distinct outcome the caller can act on — and everything else is the
    /// client's own framing, so 400. What none of them is, is silence.
    pub fn status(&self) -> actix_web::http::StatusCode {
        match self {
            ReadError::TooLarge(_) => actix_web::http::StatusCode::PAYLOAD_TOO_LARGE,
            _ => actix_web::http::StatusCode::BAD_REQUEST,
        }
    }
}

/// The bounds a single request's body is read under.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Wall-clock deadline for reading the entire body.
    pub deadline: Duration,
    /// Maximum number of body bytes accepted, summed across all fields.
    pub max_bytes: usize,
}

impl Limits {
    /// The bounds configured for this deployment (`--max-payload` and
    /// `--body-timeout`).
    pub fn from_data(srv: &crate::state::data::Data) -> Self {
        use std::sync::atomic::Ordering;
        Self {
            deadline: Duration::from_secs(srv.body_timeout_secs.load(Ordering::Relaxed)),
            max_bytes: srv.max_payload_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Read a whole multipart body into `field name -> bytes`, under `limits`.
///
/// Later fields of the same name overwrite earlier ones, matching what the
/// hand-rolled loops did. On any error the partially read data is dropped:
/// no handler wants half a body, and acting on one is how a truncated upload
/// becomes a silently truncated record.
pub async fn read_fields(
    payload: &mut Multipart,
    limits: Limits,
) -> Result<HashMap<String, Vec<u8>>, ReadError> {
    with_deadline(limits, read_all(payload, limits.max_bytes)).await
}

/// Run a body-reading future under the configured deadline.
///
/// For readers that cannot use [`read_fields`] because they do something other
/// than buffer every field — streaming an upload to disk, say — but need the
/// same guarantee that the request eventually gets answered.
pub async fn with_deadline<F, T>(limits: Limits, fut: F) -> Result<T, ReadError>
where
    F: std::future::Future<Output = Result<T, ReadError>>,
{
    match timeout(limits.deadline, fut).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ReadError::Timeout),
    }
}

/// Read a whole request body under `limits` and parse it as JSON.
///
/// The `web::Json<T>` extractor honours `PayloadConfig`'s size limit but has
/// no deadline of its own, so a JSON endpoint could be held open by a trickle
/// exactly the way the multipart ones were. This is the same bounded read,
/// spelled for a body that is one document rather than a set of fields.
pub async fn read_json_body<T: serde::de::DeserializeOwned>(
    payload: &mut actix_web::web::Payload,
    limits: Limits,
) -> Result<T, ReadError> {
    let body = read_body(payload, limits).await?;
    serde_json::from_slice(&body).map_err(|e| ReadError::Malformed(e.to_string()))
}

/// Read a whole request body under `limits`, without deciding what it is.
///
/// The bounded read itself is the same for every body shape; only the parse
/// after it differs. Form-encoded bodies — a provider POSTing an OAuth
/// callback back to us — need exactly this and no JSON.
pub async fn read_body(
    payload: &mut actix_web::web::Payload,
    limits: Limits,
) -> Result<actix_web::web::BytesMut, ReadError> {
    use futures_util::StreamExt;

    with_deadline(limits, async {
        let mut body = actix_web::web::BytesMut::new();
        while let Some(chunk) = payload.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => return Err(ReadError::Malformed(e.to_string())),
            };
            if body.len() + chunk.len() > limits.max_bytes {
                return Err(ReadError::TooLarge(body.len() + chunk.len()));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    })
    .await
}

/// Convenience for the common case: one named field, as UTF-8.
pub fn field_str(fields: &HashMap<String, Vec<u8>>, name: &str) -> String {
    fields
        .get(name)
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

async fn read_all(
    payload: &mut Multipart,
    max_bytes: usize,
) -> Result<HashMap<String, Vec<u8>>, ReadError> {
    let mut fields: HashMap<String, Vec<u8>> = HashMap::new();
    let mut total: usize = 0;

    loop {
        let mut field = match payload.try_next().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return Err(ReadError::Malformed(e.to_string())),
        };
        let name = field.name().to_string();
        let mut data: Vec<u8> = Vec::new();

        loop {
            match field.try_next().await {
                Ok(Some(chunk)) => {
                    // Counted before the copy, so an oversized body is
                    // refused rather than buffered first and refused after.
                    total = total.saturating_add(chunk.len());
                    if total > max_bytes {
                        return Err(ReadError::TooLarge(total));
                    }
                    data.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => return Err(ReadError::Malformed(e.to_string())),
            }
        }

        fields.insert(name, data);
    }

    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{web, App, HttpResponse};

    const BOUNDARY: &str = "----isabelletestboundary";

    fn body(fields: &[(&str, &str)], terminate: bool) -> String {
        let mut out = String::new();
        for (name, value) in fields {
            out.push_str(&format!("--{}\r\n", BOUNDARY));
            out.push_str(&format!(
                "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
                name
            ));
            out.push_str(value);
            out.push_str("\r\n");
        }
        if terminate {
            out.push_str(&format!("--{}--\r\n", BOUNDARY));
        }
        out
    }

    /// Drive a real multipart body through the real extractor and report what
    /// `read_fields` made of it.
    async fn probe(payload: String, limits: Limits) -> Result<HashMap<String, Vec<u8>>, String> {
        let outcome: std::sync::Arc<parking_lot::Mutex<Option<Result<_, String>>>> =
            std::sync::Arc::new(parking_lot::Mutex::new(None));
        let sink = outcome.clone();

        let app = actix_web::test::init_service(App::new().route(
            "/probe",
            web::post().to(move |mut mp: Multipart| {
                let sink = sink.clone();
                async move {
                    let r = read_fields(&mut mp, limits)
                        .await
                        .map_err(|e| e.to_string());
                    *sink.lock() = Some(r);
                    HttpResponse::Ok().finish()
                }
            }),
        ))
        .await;

        let req = actix_web::test::TestRequest::post()
            .uri("/probe")
            .insert_header((
                "content-type",
                format!("multipart/form-data; boundary={}", BOUNDARY),
            ))
            .set_payload(payload)
            .to_request();
        let _ = actix_web::test::call_service(&app, req).await;

        let taken = outcome.lock().take();
        taken.expect("handler did not run")
    }

    fn generous() -> Limits {
        Limits {
            deadline: Duration::from_secs(5),
            max_bytes: 1024 * 1024,
        }
    }

    #[actix_web::test]
    async fn a_well_formed_body_yields_its_fields() {
        let got = probe(
            body(&[("username", "alice"), ("password", "s3cr3t")], true),
            generous(),
        )
        .await
        .expect("well-formed body rejected");
        assert_eq!(field_str(&got, "username"), "alice");
        assert_eq!(field_str(&got, "password"), "s3cr3t");
        assert_eq!(field_str(&got, "absent"), "");
    }

    /// The availability bug in one test: a body that opens a part and never
    /// closes it. The stream yields no further field and never ends, so
    /// without the deadline this request is simply never answered.
    #[actix_web::test]
    async fn an_unterminated_body_is_given_up_on() {
        let limits = Limits {
            deadline: Duration::from_millis(200),
            max_bytes: 1024 * 1024,
        };
        let err = probe(body(&[("item", "{")], false), limits)
            .await
            .expect_err("an unfinished body was accepted as complete");
        assert!(err.contains("timed out"), "{}", err);
    }

    /// `web::PayloadConfig` never reaches the multipart extractor, so the
    /// limit has to be counted here or uploads are unbounded.
    #[actix_web::test]
    async fn an_oversized_body_is_refused() {
        let limits = Limits {
            deadline: Duration::from_secs(5),
            max_bytes: 16,
        };
        let big = "x".repeat(1024);
        let err = probe(body(&[("item", &big)], true), limits)
            .await
            .expect_err("the payload limit did not cover multipart");
        assert!(err.contains("exceeds the maximum size"), "{}", err);
    }

    /// The limit is on the body, not on any one field: several small parts
    /// must not add up to more than the maximum either.
    #[actix_web::test]
    async fn the_limit_is_summed_across_fields() {
        let limits = Limits {
            deadline: Duration::from_secs(5),
            max_bytes: 20,
        };
        let part = "x".repeat(15);
        let err = probe(body(&[("a", &part), ("b", &part)], true), limits)
            .await
            .expect_err("per-field accounting let the body through");
        assert!(err.contains("exceeds the maximum size"), "{}", err);
    }

    /// Garbage still gets an answer — the caller turns this into a 400. What
    /// it must not do is look like a successfully read empty body, which is
    /// how the old `while let Ok(Some(_))` loops reported it.
    #[actix_web::test]
    async fn broken_framing_is_reported_rather_than_silently_empty() {
        let err = probe("not a multipart body at all".to_string(), generous())
            .await
            .expect_err("malformed framing was reported as an empty body");
        assert!(err.contains("malformed"), "{}", err);
    }
}
