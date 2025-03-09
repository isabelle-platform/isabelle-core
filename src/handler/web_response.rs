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
use actix_web::HttpResponse;
use isabelle_plugin_api::api::WebResponse;
use std::path::Path;

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
            return HttpResponse::Ok().body(text);
        }
        WebResponse::OkFile(_name, _data) => {
            return HttpResponse::Ok().into();
        }
        WebResponse::OkFilePath(_name, p) => {
            let path = Path::new(&p);
            if Path::exists(&path) {
                let file = actix_files::NamedFile::open_async(path).await.unwrap();
                let req = actix_web::test::TestRequest::default().to_http_request();
                return file.into_response(&req);
            } else {
                return HttpResponse::NotFound().into();
            }
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
