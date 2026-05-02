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
use crate::server::user_control::*;
use crate::state::state::*;
use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use isabelle_dm::data_model::process_result::ProcessResult;
use log::{error, info};
use std::collections::HashMap;
use std::process::Command;

pub async fn system_update(
    user: Identity,
    data: web::Data<State>,
    _req: HttpRequest,
) -> HttpResponse {
    let srv_lock = data.server.lock();
    let srv = unsafe { &mut (*srv_lock.as_ptr()) };
    let usr = get_user(srv, user.id().unwrap()).await;

    if !check_role(srv, &usr, "admin").await {
        return HttpResponse::Forbidden().into();
    }

    let script = srv.update_script.clone();
    if script.is_empty() {
        return HttpResponse::Ok().body(
            serde_json::to_string(&ProcessResult {
                succeeded: false,
                error: "update script is not configured".to_string(),
                data: HashMap::new(),
            })
            .unwrap(),
        );
    }

    info!("System update: invoking {}", script);

    let parts: Vec<&str> = script.split_whitespace().collect();
    let (program, args) = match parts.split_first() {
        Some((p, a)) => (*p, a),
        None => {
            return HttpResponse::Ok().body(
                serde_json::to_string(&ProcessResult {
                    succeeded: false,
                    error: "update script is not configured".to_string(),
                    data: HashMap::new(),
                })
                .unwrap(),
            );
        }
    };
    let output = Command::new(program).args(args).output();
    match output {
        Ok(out) => {
            let mut data_map: HashMap<String, String> = HashMap::new();
            data_map.insert(
                "stdout".to_string(),
                String::from_utf8_lossy(&out.stdout).to_string(),
            );
            data_map.insert(
                "stderr".to_string(),
                String::from_utf8_lossy(&out.stderr).to_string(),
            );
            data_map.insert(
                "exit_code".to_string(),
                out.status.code().map(|c| c.to_string()).unwrap_or_default(),
            );

            HttpResponse::Ok().body(
                serde_json::to_string(&ProcessResult {
                    succeeded: out.status.success(),
                    error: if out.status.success() {
                        "".to_string()
                    } else {
                        format!("update script exited with status {}", out.status)
                    },
                    data: data_map,
                })
                .unwrap(),
            )
        }
        Err(e) => {
            error!("System update: failed to run {}: {}", script, e);
            HttpResponse::Ok().body(
                serde_json::to_string(&ProcessResult {
                    succeeded: false,
                    error: format!("failed to run update script: {}", e),
                    data: HashMap::new(),
                })
                .unwrap(),
            )
        }
    }
}
