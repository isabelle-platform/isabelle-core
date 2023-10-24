use crate::handler::equestrian::*;
use crate::State;
use actix_identity::Identity;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use log::info;
use std::collections::HashMap;

pub fn call_item_route(
    srv: &mut crate::state::data::Data,
    hndl: &str,
    collection: &str,
    id: u64,
    del: bool,
) {
    match hndl {
        "equestrian_job_sync" => equestrian_job_sync(srv, collection, id, del),
        &_ => {}
    }
}

pub fn call_url_route(
    srv: &mut crate::state::data::Data,
    user: Identity,
    hndl: &str,
    query: &str,
) -> HttpResponse {
    match hndl {
        "equestrian_schedule_materialize" => {
            return equestrian_schedule_materialize(srv, user, query);
        }
        "pay_find_broken_payments" => {
            return equestrian_pay_find_broken_payments(srv, user, query);
        }
        &_ => {
            return HttpResponse::NotFound().into();
        }
    }
}

pub async fn url_route(
    user: Identity,
    data: actix_web::web::Data<State>,
    req: HttpRequest,
) -> HttpResponse {
    let mut srv = data.server.lock().unwrap();
    let routes = srv.internals.safe_strstr("extra_route", &HashMap::new());

    info!("Custom URL: {}", req.path());

    for route in routes {
        let parts: Vec<&str> = route.1.split(":").collect();
        if parts[0] == req.path() {
            info!("Call custom route {}", parts[2]);
            return call_url_route(&mut srv, user, parts[2], req.query_string());
        }
    }

    HttpResponse::NotFound().into()
}