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
use actix_web::http::header::{
    self, Charset, ContentDisposition, DispositionParam, DispositionType, ExtendedValue,
};
use actix_web::HttpResponse;
use isabelle_plugin_api::api::WebResponse;
use std::path::Path;

/// `Content-Disposition: attachment` under `name`. A plain `filename` for
/// browsers that read only that, with any character it cannot carry replaced;
/// the exact name in `filename*` (RFC 6266) when it is not plain ASCII.
fn attachment_named(name: &str) -> ContentDisposition {
    let plain: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut parameters = vec![DispositionParam::Filename(plain)];
    if !name.is_ascii() {
        parameters.push(DispositionParam::FilenameExt(ExtendedValue {
            charset: Charset::Ext("UTF-8".to_string()),
            language_tag: None,
            value: name.as_bytes().to_vec(),
        }));
    }
    ContentDisposition {
        disposition: DispositionType::Attachment,
        parameters,
    }
}

/// Convert internal Web response to proper HttpResponse
pub async fn conv_response(resp: WebResponse) -> HttpResponse {
    match resp {
        WebResponse::Ok | WebResponse::Logout => {
            return HttpResponse::Ok().into();
        }
        WebResponse::Login(_email) => {
            return HttpResponse::Ok().into();
        }
        WebResponse::OkData(text) => {
            let trimmed = text.trim_start();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                return HttpResponse::Ok()
                    .content_type("application/json")
                    .body(text);
            }
            return HttpResponse::Ok().body(text);
        }
        WebResponse::OkFile(name, data) => {
            // Serve the in-memory bytes with a content-type guessed from the name's
            // extension (was a stub that dropped the body -> empty 200).
            let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
            let content_type = match ext.as_str() {
                "png" => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "webp" => "image/webp",
                "gif" => "image/gif",
                "svg" => "image/svg+xml",
                "html" | "htm" => "text/html; charset=utf-8",
                "txt" => "text/plain; charset=utf-8",
                "json" => "application/json",
                _ => "application/octet-stream",
            };
            return HttpResponse::Ok().content_type(content_type).body(data);
        }
        WebResponse::OkFilePath(name, p) => {
            // Opened, not checked for and then opened: a file that goes away in
            // between is a 404, not a panic.
            let file = match actix_files::NamedFile::open_async(Path::new(&p)).await {
                Ok(f) => f,
                Err(_) => return HttpResponse::NotFound().into(),
            };
            // Always a download, under the name the plugin gave it. Served
            // inline, a file with an HTML or SVG type would run as a page of
            // this origin, with the session of whoever opened it — and plugins
            // serve files whose contents they do not control (uploaded avatars,
            // a test run's artifacts). An <img> still shows an attachment.
            let file = file.set_content_disposition(attachment_named(&name));
            let req = actix_web::test::TestRequest::default().to_http_request();
            let mut resp = file.into_response(&req);
            resp.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                header::HeaderValue::from_static("nosniff"),
            );
            return resp;
        }
        WebResponse::NotFound => {
            return HttpResponse::NotFound().into();
        }
        WebResponse::Unauthorized => {
            return HttpResponse::Unauthorized().into();
        }
        WebResponse::BadRequest => {
            return HttpResponse::BadRequest().into();
        }
        WebResponse::Forbidden => {
            return HttpResponse::Forbidden().into();
        }
        WebResponse::NotImplemented => todo!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(resp: &HttpResponse, name: header::HeaderName) -> String {
        resp.headers()
            .get(name)
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default()
    }

    #[actix_web::test]
    async fn a_served_file_is_a_named_download() {
        let dir =
            std::env::temp_dir().join(format!("isabelle-web-response-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.html");
        std::fs::write(&path, "<script>alert(1)</script>").unwrap();

        let resp = conv_response(WebResponse::OkFilePath(
            "report.html".to_string(),
            path.to_string_lossy().into_owned(),
        ))
        .await;
        assert_eq!(resp.status(), 200);
        let cd = header(&resp, header::CONTENT_DISPOSITION);
        assert!(cd.starts_with("attachment"), "got {}", cd);
        assert!(cd.contains("filename=\"report.html\""), "got {}", cd);
        assert_eq!(header(&resp, header::X_CONTENT_TYPE_OPTIONS), "nosniff");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[actix_web::test]
    async fn a_missing_file_is_not_found() {
        let resp = conv_response(WebResponse::OkFilePath(
            "gone.txt".to_string(),
            "/nonexistent/isabelle/gone.txt".to_string(),
        ))
        .await;
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn a_name_that_is_not_plain_ascii_keeps_its_exact_form() {
        let cd = attachment_named("отчёт \"1\".txt");
        let params = &cd.parameters;
        assert!(matches!(&params[0], DispositionParam::Filename(f) if f == "_____ _1_.txt"));
        assert!(matches!(&params[1], DispositionParam::FilenameExt(_)));
    }
}
