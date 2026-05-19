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
use crate::handler::route_call::*;
use crate::server::user_control::*;
use crate::state::state::*;
use crate::state::store::Store;
use actix_identity::Identity;
use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use isabelle_dm::data_model::data_object_action::DataObjectAction;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::list_query::ListQuery;
use isabelle_dm::data_model::list_result::ListResult;
use isabelle_dm::data_model::merge_coll::MergeColl;
use isabelle_dm::data_model::process_result::ProcessResult;
use log::{error, info};
use serde_qs;
use std::collections::HashMap;

/// Action that is called on editing items. This function unrolls the
/// multipart data, all needed hooks, and eventually prepare response.
pub async fn itm_edit(
    user: Identity,
    data: web::Data<State>,
    req: HttpRequest,
    mut payload: Multipart,
) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let usr = get_user(srv, user.id().unwrap()).await;

    let mc = serde_qs::from_str::<MergeColl>(&req.query_string()).unwrap();
    let mut itm = serde_qs::from_str::<Item>(&req.query_string()).unwrap();

    while let Ok(Some(mut field)) = payload.try_next().await {
        let field_name = field.name().to_string();
        let mut field_data: Vec<u8> = Vec::new();
        while let Ok(Some(chunk)) = field.try_next().await {
            field_data.extend_from_slice(&chunk);
        }

        if field_name == "item" {
            let strv = std::str::from_utf8(&field_data).unwrap_or("{}");
            let new_itm: Item = serde_json::from_str(strv).unwrap_or_else(|e| {
                log::error!("Failed to parse item JSON: {:?}", e);
                Item::new()
            });
            itm.merge(&new_itm);
        }
    }

    // `itm_auth_hook` is a flat handler list with no ":"-split, so it's still
    // read straight from the cached internals. Pre-/post-edit hooks are read
    // from the pre-parsed route cache below.
    let internals = srv.rw.get_internals().await;
    let cache = srv.route_cache.lock().clone();

    /* call auth hooks */
    if let Some(routes) = internals.strstrs.get("itm_auth_hook") {
        for route in routes {
            if !call_item_auth_hook(
                srv,
                route.1,
                &usr,
                &mc.collection,
                itm.id,
                Some(itm.clone()),
                false,
            )
            .await
            {
                return HttpResponse::Forbidden().into();
            }
        }
    }

    itm.normalize_negated();

    if srv.has_collection(&mc.collection) {
        let mut itm_clone = itm.clone();

        let old_itm = srv.rw.get_item(&mc.collection, itm.id).await;
        /* call pre edit hooks */
        {
            let specific = cache.item_pre_edit.get(&mc.collection);
            for handler in specific
                .into_iter()
                .flatten()
                .chain(cache.item_pre_edit_wildcard.iter())
            {
                let res = call_item_pre_edit_hook(
                    srv,
                    handler,
                    &usr,
                    &mc.collection,
                    old_itm.clone(),
                    &mut itm_clone,
                    if old_itm.is_some() {
                        DataObjectAction::Modify
                    } else {
                        DataObjectAction::Create
                    },
                    mc.merge,
                )
                .await;
                if !res.succeeded {
                    info!("Item pre edit hook failed: {} - {}", handler, res.error);
                    let s = serde_json::to_string(&res);
                    return HttpResponse::Ok().body(s.unwrap_or("{}".to_string()));
                }
            }
        }

        let r = srv.rw.set_item(&mc.collection, &itm_clone, mc.merge).await;
        info!("Collection {} element {} set", mc.collection, itm.id);

        /* call post edit hooks */
        {
            let specific = cache.item_post_edit.get(&mc.collection);
            for handler in specific
                .into_iter()
                .flatten()
                .chain(cache.item_post_edit_wildcard.iter())
            {
                call_item_post_edit_hook(
                    srv,
                    handler,
                    &mc.collection,
                    old_itm.clone(),
                    itm.id,
                    if old_itm.is_some() {
                        DataObjectAction::Modify
                    } else {
                        DataObjectAction::Create
                    },
                )
                .await;
            }
        }

        let mut map = HashMap::new();
        map.insert("id".to_string(), r.to_string());
        return HttpResponse::Ok().body(
            serde_json::to_string(&ProcessResult {
                succeeded: true,
                error: "".to_string(),
                data: map,
            })
            .unwrap(),
        );
    } else {
        error!("Collection {} doesn't exist", mc.collection);
    }

    return HttpResponse::BadRequest().into();
}

/// Action that is called on removing the item. This function calls
/// all necessary hooks and actually performs removal.
pub async fn itm_del(user: Identity, data: web::Data<State>, req: HttpRequest) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let usr = get_user(srv, user.id().unwrap()).await;

    let mc = serde_qs::from_str::<MergeColl>(&req.query_string()).unwrap();
    let itm = serde_qs::from_str::<Item>(&req.query_string()).unwrap();

    // See itm_edit for the cache/internals split rationale.
    let internals = srv.rw.get_internals().await;
    let cache = srv.route_cache.lock().clone();

    /* call auth hooks */
    if let Some(routes) = internals.strstrs.get("itm_auth_hook") {
        for route in routes {
            if !call_item_auth_hook(srv, route.1, &usr, &mc.collection, itm.id, None, true).await
            {
                return HttpResponse::Forbidden().into();
            }
        }
    }

    if srv.has_collection(&mc.collection) {
        let old_itm = srv.rw.get_item(&mc.collection, itm.id).await;
        let mut new_itm = Item::new();

        /* call pre edit hooks before removal */
        {
            let specific = cache.item_pre_edit.get(&mc.collection);
            for handler in specific
                .into_iter()
                .flatten()
                .chain(cache.item_pre_edit_wildcard.iter())
            {
                let res = call_item_pre_edit_hook(
                    srv,
                    handler,
                    &usr,
                    &mc.collection,
                    old_itm.clone(),
                    &mut new_itm,
                    DataObjectAction::Delete,
                    mc.merge,
                )
                .await;
                if !res.succeeded {
                    info!("Item pre edit hook failed: {} - {}", handler, res.error);
                    let s = serde_json::to_string(&res);
                    return HttpResponse::Ok().body(s.unwrap_or("{}".to_string()));
                }
            }
        }

        if srv.rw.del_item(&mc.collection, itm.id).await {
            info!("Collection {} element {} removed", mc.collection, itm.id);
        }

        /* call post edit hooks */
        {
            let specific = cache.item_post_edit.get(&mc.collection);
            for handler in specific
                .into_iter()
                .flatten()
                .chain(cache.item_post_edit_wildcard.iter())
            {
                call_item_post_edit_hook(
                    srv,
                    handler,
                    &mc.collection,
                    old_itm.clone(),
                    itm.id,
                    DataObjectAction::Delete,
                )
                .await;
            }
        }

        return HttpResponse::Ok().into();
    } else {
        error!("Collection {} doesn't exist", mc.collection);
    }

    return HttpResponse::BadRequest().into();
}

/// Action that is called on any attempt to list database items.
/// This function invokes all necessary hooks before giving away the list
/// in form of json array.
pub async fn itm_list(user: Identity, data: web::Data<State>, req: HttpRequest) -> HttpResponse {
    let srv: &crate::state::data::Data = &data.server;
    let usr = get_user(srv, user.id().unwrap()).await;

    let mut lq = match serde_qs::from_str::<ListQuery>(&req.query_string()) {
        Ok(v) => v,
        Err(e) => {
            error!("Malformed list query: {}", e);
            return HttpResponse::BadRequest().into();
        }
    };

    if !srv.has_collection(&lq.collection) {
        error!("Collection {} doesn't exist", lq.collection);
        return HttpResponse::BadRequest().into();
    }

    // A single-id get is semantically a "view this one item in full" — the
    // listing-style trim plugins do via `item_list_filter_hook` (e.g. midair's
    // `reduce_test` that drops processed_mi*/ai_review for compactness) is
    // not what the caller wants. Force `context=full` so plugins skip the
    // trim, unless the caller explicitly overrode it.
    if lq.id != u64::MAX && lq.context.is_empty() {
        lq.context = "full".to_string();
    }

    let mut lr = ListResult {
        map: HashMap::new(),
        total_count: 0,
    };

    // Cache internals once per request to avoid repeated disk reads.
    let internals = srv.rw.get_internals().await;

    if lq.id != u64::MAX {
        let res = srv.rw.get_item(&lq.collection, lq.id).await;
        if res == None {
            error!(
                "Collection {} requested element {} doesn't exist",
                lq.collection, lq.id
            );
            return HttpResponse::BadRequest().into();
        }

        lr.map.insert(lq.id, res.unwrap());
        lr.total_count = 1;
        info!("Collection {} requested element {}", lq.collection, lq.id);
    } else if lq.id_min != u64::MAX || lq.id_max != u64::MAX || lq.sort_key != "" || lq.filter != ""
    {
        info!(
            "Collection {} requested range {} - {} sort {} skip {} limit {} filter {}",
            lq.collection, lq.id_min, lq.id_max, lq.sort_key, lq.skip, lq.limit, lq.filter
        );

        let mut filters: Vec<String> = Vec::new();
        let mut final_filter: String = "".to_string();

        if lq.filter != "" {
            filters.push(lq.filter.to_string());
        }

        if let Some(db_filter_routes) = internals.strstrs.get("itm_list_db_filter_hook") {
            for route in db_filter_routes {
                let new_filters = call_item_list_db_filter_hook(
                    srv,
                    route.1,
                    &usr,
                    &lq.collection,
                    &lq.context,
                    "mongo",
                )
                .await;
                filters.extend(new_filters);
            }
        }

        for filt in filters {
            if final_filter == "" {
                final_filter = filt;
            } else {
                final_filter = "{ \"$and\": [".to_owned() + &final_filter + ", " + &filt + "]}";
            }
        }

        lr = srv
            .rw
            .get_items(
                &lq.collection,
                lq.id_min,
                lq.id_max,
                &lq.sort_key,
                &final_filter,
                lq.skip,
                lq.limit,
            )
            .await;
    } else if !lq.id_list.is_empty() {
        // Fetch all requested ids, then paginate deterministically.
        // total_count reflects how many of the requested ids actually exist.
        let mut found: Vec<(u64, Item)> = Vec::new();
        for id in &lq.id_list {
            if let Some(itm) = srv.rw.get_item(&lq.collection, *id).await {
                found.push((*id, itm));
            }
        }
        found.sort_by_key(|(id, _)| *id);
        lr.total_count = found.len() as u64;

        let skip = if lq.skip == u64::MAX { 0 } else { lq.skip } as usize;
        let limit = if lq.limit == u64::MAX {
            usize::MAX
        } else {
            lq.limit as usize
        };
        for (id, item) in found.into_iter().skip(skip).take(limit) {
            lr.map.insert(id, item);
        }
        info!(
            "Collection {} requested list of IDs: {} matched, skip {} limit {}",
            lq.collection, lr.total_count, lq.skip, lq.limit
        );
    } else {
        info!("Collection {} unknown filter", lq.collection);
    }

    /* itm filter hooks. NOTE: these run after pagination and may mutate
     * (or remove) items on the current page. They do not affect total_count
     * — for cross-page filtering use itm_list_db_filter_hook instead, which
     * is pushed down into the database query. */
    if let Some(routes) = internals.strstrs.get("itm_list_filter_hook") {
        let mut sorted_routes: Vec<_> = routes.iter().collect();
        sorted_routes.sort_by(|a, b| a.0.cmp(b.0));
        for route in sorted_routes {
            call_item_list_filter_hook(
                srv,
                route.1,
                &usr,
                &lq.collection,
                &lq.context,
                &mut lr.map,
            )
            .await;
        }
    }

    HttpResponse::Ok().body(serde_json::to_string(&lr).unwrap())
}
