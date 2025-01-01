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
use std::ops::DerefMut;

/// Action that is called on editing items. This function unrolls the
/// multipart data, all needed hooks, and eventually prepare response.
pub async fn itm_edit(
    user: Identity,
    data: web::Data<State>,
    req: HttpRequest,
    mut payload: Multipart,
) -> HttpResponse {
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    let usr = get_user(&mut srv, user.id().unwrap()).await;

    let mc = serde_qs::from_str::<MergeColl>(&req.query_string()).unwrap();
    let mut itm = serde_qs::from_str::<Item>(&req.query_string()).unwrap();

    while let Ok(Some(mut field)) = payload.try_next().await {
        while let Ok(Some(chunk)) = field.try_next().await {
            let data = chunk;

            if field.name() == "item" {
                let v = &data.to_vec();
                let strv = std::str::from_utf8(v).unwrap_or("{}");
                let new_itm: Item = serde_json::from_str(strv).unwrap_or(Item::new());
                itm.merge(&new_itm);
            }
        }
    }

    /* call auth hooks */
    {
        let routes = srv
            .rw
            .get_internals()
            .await
            .safe_strstr("itm_auth_hook", &HashMap::new());
        for route in routes {
            if !call_item_auth_hook(
                &mut srv,
                &route.1,
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
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let mut itm_clone = itm.clone();

        let old_itm = srv_mut.rw.get_item(&mc.collection, itm.id).await;
        /* call pre edit hooks */
        {
            let routes = (*srv_mut)
                .rw
                .get_internals()
                .await
                .safe_strstr("item_pre_edit_hook", &HashMap::new());
            for route in &routes {
                let parts: Vec<&str> = route.1.split(":").collect();
                if parts[0] == mc.collection {
                    let res = call_item_pre_edit_hook(
                        &mut (*srv_mut),
                        parts[1],
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
                        info!("Item pre edit hook failed: {} - {}", parts[1], res.error);
                        let s = serde_json::to_string(&res);
                        return HttpResponse::Ok().body(s.unwrap_or("{}".to_string()));
                    }
                }
            }
        }

        /* call hooks */
        /*
        if old_itm != None {
            let routes = (*srv_mut)
                .rw
                .get_internals()
                .await
                .safe_strstr("item_post_edit_hook", &HashMap::new());
            for route in routes {
                let parts: Vec<&str> = route.1.split(":").collect();
                if parts[0] == mc.collection {
                    call_item_post_edit_hook(
                        &mut (*srv_mut),
                        &parts[1],
                        &mc.collection,
                        itm.id,
                        true,
                    )
                    .await;
                }
            }
        }
        */

        (*srv_mut)
            .rw
            .set_item(&mc.collection, &itm_clone, mc.merge)
            .await;
        info!("Collection {} element {} set", mc.collection, itm.id);

        /* call hooks */
        {
            let routes = (*srv_mut)
                .rw
                .get_internals()
                .await
                .safe_strstr("item_post_edit_hook", &HashMap::new());
            for route in routes {
                let parts: Vec<&str> = route.1.split(":").collect();
                if parts[0] == mc.collection {
                    call_item_post_edit_hook(
                        &mut (*srv_mut),
                        &parts[1],
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
        }

        return HttpResponse::Ok().body(
            serde_json::to_string(&ProcessResult {
                succeeded: true,
                error: "".to_string(),
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
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    let usr = get_user(&mut srv, user.id().unwrap()).await;

    let mc = serde_qs::from_str::<MergeColl>(&req.query_string()).unwrap();
    let itm = serde_qs::from_str::<Item>(&req.query_string()).unwrap();

    /* call auth hooks */
    {
        let routes = srv
            .rw
            .get_internals()
            .await
            .safe_strstr("itm_auth_hook", &HashMap::new());
        for route in routes {
            if !call_item_auth_hook(&mut srv, &route.1, &usr, &mc.collection, itm.id, None, true)
                .await
            {
                return HttpResponse::Forbidden().into();
            }
        }
    }

    let srv_mut = srv.deref_mut();
    if srv_mut.has_collection(&mc.collection) {
        let old_itm = srv_mut.rw.get_item(&mc.collection, itm.id).await;
        let mut new_itm = Item::new();

        /* call pre edit hooks before removal */
        {
            let routes = (*srv_mut)
                .rw
                .get_internals()
                .await
                .safe_strstr("item_pre_edit_hook", &HashMap::new());
            for route in &routes {
                let parts: Vec<&str> = route.1.split(":").collect();
                if parts[0] == mc.collection {
                    let res = call_item_pre_edit_hook(
                        &mut (*srv_mut),
                        parts[1],
                        &usr,
                        &mc.collection,
                        old_itm.clone(),
                        &mut new_itm,
                        DataObjectAction::Delete,
                        mc.merge,
                    )
                    .await;
                    if !res.succeeded {
                        info!("Item pre edit hook failed: {} - {}", parts[1], res.error);
                        let s = serde_json::to_string(&res);
                        return HttpResponse::Ok().body(s.unwrap_or("{}".to_string()));
                    }
                }
            }
        }

        if srv_mut.rw.del_item(&mc.collection, itm.id).await {
            info!("Collection {} element {} removed", mc.collection, itm.id);
        }

        /* call hooks */
        {
            let routes = srv_mut
                .rw
                .get_internals()
                .await
                .safe_strstr("item_post_edit_hook", &HashMap::new());
            for route in routes {
                let parts: Vec<&str> = route.1.split(":").collect();
                if parts[0] == mc.collection {
                    call_item_post_edit_hook(
                        srv_mut,
                        &parts[1],
                        &mc.collection,
                        old_itm.clone(),
                        itm.id,
                        DataObjectAction::Delete,
                    )
                    .await;
                }
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
    let srv_lock = data.server.lock();
    let mut srv = srv_lock.borrow_mut();
    let usr = get_user(&mut srv, user.id().unwrap()).await;

    let lq = serde_qs::from_str::<ListQuery>(&req.query_string()).unwrap();

    if !srv.has_collection(&lq.collection) {
        error!("Collection {} doesn't exist", lq.collection);
        return HttpResponse::BadRequest().into();
    }

    let mut lr = ListResult {
        map: HashMap::new(),
        total_count: 0,
    };

    if lq.id != u64::MAX {
        let res = srv.rw.get_item(&lq.collection, lq.id).await;
        if res == None {
            error!(
                "Collection {} requested element {} doesn't exist",
                lq.collection, lq.id
            );
            return HttpResponse::BadRequest().into();
        }

        if lq.limit == u64::MAX || lq.limit >= 1 {
            lr.map.insert(lq.id, res.unwrap());
            lr.total_count = 1;
            info!(
                "Collection {} requested element {} limit {}",
                lq.collection, lq.id, lq.limit
            );
        }
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

        let routes = srv
            .rw
            .get_internals()
            .await
            .safe_strstr("itm_list_db_filter_hook", &HashMap::new());
        for route in routes {
            let new_filters = call_itm_list_db_filter_hook(
                &mut srv,
                &route.1,
                &usr,
                &lq.collection,
                &lq.context,
                "mongo",
            )
            .await;
            filters.extend(new_filters);
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
    } else if lq.id_list.len() > 0 {
        for id in lq.id_list {
            let res = srv.rw.get_item(&lq.collection, id).await;
            if res != None {
                lr.map.insert(id, res.unwrap());
                lr.total_count += 1;
            }
        }
        info!("Collection {} requested list of IDs", lq.collection);
    } else {
        info!("Collection {} unknown filter", lq.collection);
    }

    /* itm filter hooks */
    {
        let routes = srv
            .rw
            .get_internals()
            .await
            .safe_strstr("itm_list_filter_hook", &HashMap::new());
        let mut sorted_routes: Vec<_> = routes.iter().collect();
        sorted_routes.sort_by(|a, b| a.0.cmp(b.0));
        for route in sorted_routes {
            call_itm_list_filter_hook(
                &mut srv,
                &route.1,
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
