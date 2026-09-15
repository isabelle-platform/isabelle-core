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
pub mod api_token;
pub mod auth_config;
pub mod feature;
pub mod guards;
pub mod itm;
pub mod list_filter;
pub mod login;
pub mod oauth;
pub mod openapi;
pub mod secret;
pub mod setting;
pub mod signin;
pub mod system;
pub mod user_control;

/// The answer shape every one of these endpoints gives.
///
/// A `ProcessResult` document, always, whatever the status — clients here
/// parse the body before they look at the status line, so an answer with no
/// body is the one that makes `resp.json()` throw.
pub(crate) mod reply {
    use actix_web::HttpResponse;
    use isabelle_dm::data_model::process_result::ProcessResult;
    use std::collections::HashMap;

    pub(crate) fn ok() -> HttpResponse {
        ok_with(HashMap::new())
    }

    pub(crate) fn ok_with(data: HashMap<String, String>) -> HttpResponse {
        HttpResponse::Ok().body(
            serde_json::to_string(&ProcessResult {
                succeeded: true,
                error: String::new(),
                data,
            })
            .unwrap(),
        )
    }

    /// A success that names the id it just wrote.
    pub(crate) fn ok_with_id(id: u64) -> HttpResponse {
        let mut data = HashMap::new();
        data.insert("id".to_string(), id.to_string());
        ok_with(data)
    }

    pub(crate) fn err(msg: impl Into<String>) -> HttpResponse {
        err_status(actix_web::http::StatusCode::OK, msg)
    }

    pub(crate) fn err_status(
        status: actix_web::http::StatusCode,
        msg: impl Into<String>,
    ) -> HttpResponse {
        HttpResponse::build(status).body(
            serde_json::to_string(&ProcessResult {
                succeeded: false,
                error: msg.into(),
                data: HashMap::new(),
            })
            .unwrap(),
        )
    }
}
