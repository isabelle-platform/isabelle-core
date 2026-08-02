/*
 * Isabelle project
 *
 * Copyright 2023-2025 Maxim Menshikov
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
use clap::Parser;

pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024 * 1024 * 1024; // ~1 GiB

/// How long a handler will keep reading a request body before giving up.
///
/// actix already times out incomplete *headers* (~12 s); a body that arrives
/// one byte at a time, or a multipart part that is opened and never closed,
/// had no such deadline and pinned a connection and a task for as long as the
/// client cared to wait. This is the matching bound for the body, set in the
/// same range as the header timeout so the two defences behave alike.
///
/// It is a *total* deadline, not an idle one: a trickle that sends a byte
/// every few seconds keeps an idle timer happy forever, and total elapsed time
/// is the only thing that actually separates it from a real upload. The
/// consequence is that a genuinely slow client uploading a large file can be
/// cut off — an operator who expects that should raise `--body-timeout`, and
/// should look at `--max-payload` at the same time, since the two together are
/// what set the slowest upload the server will sit through.
pub const DEFAULT_BODY_TIMEOUT_SECS: u64 = 15;

/// Isabelle - high-performant server for web applications
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Data path
    #[arg(long, default_value("sample-data"))]
    pub data_path: String,

    /// Public URL
    #[arg(long, default_value("http://localhost:8081"))]
    pub pub_url: String,

    /// Public FQDN
    #[arg(long, default_value("localhost"))]
    pub pub_fqdn: String,

    /// Database URL
    #[arg(long, default_value("mongodb://127.0.0.1:27017"))]
    pub db_url: String,

    /// Database name
    #[arg(long, default_value("isabelle"), visible_alias("database"))]
    pub db_name: String,

    /// Google Calendar path
    #[arg(long, default_value(""))]
    pub gc_path: String,

    /// Python path
    #[arg(long, default_value(""))]
    pub py_path: String,

    /// Port number
    #[arg(long, default_value("0.0.0.0"))]
    pub bind_addr: String,

    /// Port number
    #[arg(long, visible_alias("port"))]
    pub bind_port: u16,

    /// Max request payload size in bytes
    #[arg(long, default_value_t = DEFAULT_MAX_PAYLOAD_BYTES, visible_alias("max-payload"))]
    pub max_payload_bytes: usize,

    /// Deadline, in seconds, for reading a whole request body. A body that is
    /// still incomplete when it expires is answered 400 and dropped.
    #[arg(long, default_value_t = DEFAULT_BODY_TIMEOUT_SECS, visible_alias("body-timeout"))]
    pub body_timeout_secs: u64,

    /// Set http-secure on cookies to false
    #[arg(long, default_value_t = false)]
    pub cookie_http_insecure: bool,

    /// Extra origin allowed to call this API cross-origin, e.g.
    /// `https://app.example.com`. Repeat for several. The origin derived from
    /// `--pub-url` is always allowed; same-origin deployments need nothing
    /// here. Anything not listed gets no CORS headers, so browsers refuse to
    /// let a page read the response.
    #[arg(long = "cors-origin")]
    pub cors_origin: Vec<String>,

    /// Path to update script invoked by POST /system/update
    #[arg(long, default_value(""))]
    pub update_script: String,

    /// Path to the master key file used to encrypt the secret store.
    /// If empty, defaults to ${data_path}/.secret-key. Auto-generated on
    /// first run if missing.
    #[arg(long, default_value(""))]
    pub secret_key_file: String,

    /// Path to the 64-byte key that signs and encrypts session cookies.
    /// If empty, defaults to ${data_path}/.session-key. Auto-generated on
    /// first run if missing; deleting it invalidates all live sessions.
    #[arg(long, default_value(""))]
    pub session_key_file: String,
}
