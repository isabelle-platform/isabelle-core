use isabelle_plugin_api::api::WebResponse;
use actix_web::HttpResponse;

/// Convert internal Web response to proper HttpResponse
pub fn conv_response(resp: WebResponse) -> HttpResponse {
    match resp {
        WebResponse::Ok => {
            return HttpResponse::Ok().into();
        }
        WebResponse::OkData(text) => {
            return HttpResponse::Ok().body(text);
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
