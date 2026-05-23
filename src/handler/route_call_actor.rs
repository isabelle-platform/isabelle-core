/*
 * Isabelle project
 *
 * Copyright 2026 Maxim Menshikov
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 */

//! Actor-mode hook dispatcher.
//!
//! Mirrors `route_call.rs` (which fans out hooks across the trait-based
//! `PluginPool`) but routes through `Data::plugin_registry` instead —
//! sending `PluginHookMessage`s into each registered actor plugin's mpsc
//! and awaiting `oneshot` replies.
//!
//! Both dispatchers coexist during Phase 3 migration. Each registered
//! plugin lives in exactly one path; an empty registry means these
//! dispatchers are no-ops (current state until first plugin migrates).

use crate::state::data::Data;
use isabelle_dm::data_model::data_object_action::DataObjectAction;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use isabelle_plugin_api::actor::{
    CollectionReadReply, ListFilterReply, PluginHookMessage, PreEditReply,
};
use isabelle_plugin_api::api::WebResponse;
use log::warn;
use std::collections::HashMap;
use tokio::sync::oneshot;

/// Pre-edit hook — fans out across all actor plugins, awaiting each reply.
///
/// First plugin that genuinely rejects (`succeeded == false` with an error
/// other than the `"not implemented"` sentinel) short-circuits the
/// dispatcher. The `"not implemented"` reply is a legacy "skip me" signal
/// from the trait-mode era — plugins still emit it when they don't
/// handle the given handle/collection, and the dispatcher must keep
/// fanning out instead of failing the whole call.
///
/// If a plugin returns a `modified_item`, it's swapped into `itm` so the
/// next plugin sees the mutated version. This matches the trait-mode
/// `&mut Item` semantic.
pub async fn call_item_pre_edit_hook_actor(
    srv: &Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    old_itm: Option<Item>,
    itm: &mut Item,
    action: DataObjectAction,
    merge: bool,
) -> ProcessResult {
    // Collect senders into a local Vec to release the borrow on
    // `srv.plugin_registry` before we start awaiting — otherwise the
    // `oneshot::Receiver::await` below would hold the borrow across the
    // suspension, blocking the caller from `&mut srv` later.
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();

    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::ItemPreEdit {
            hndl: hndl.to_string(),
            user: user.clone(),
            collection: collection.to_string(),
            old_item: old_itm.clone(),
            item: itm.clone(),
            action: action.clone(),
            merge,
            reply: reply_tx,
        };

        if sender.send(msg).await.is_err() {
            warn!("call_item_pre_edit_hook_actor: plugin task is gone, skipping");
            continue;
        }

        match reply_rx.await {
            Ok(PreEditReply {
                result,
                modified_item,
            }) => {
                if let Some(new_item) = modified_item {
                    *itm = new_item;
                }
                if !result.succeeded && result.error != "not implemented" {
                    return result;
                }
            }
            Err(_) => {
                warn!("call_item_pre_edit_hook_actor: plugin dropped reply channel");
            }
        }
    }

    ProcessResult {
        succeeded: true,
        error: String::new(),
        data: HashMap::new(),
    }
}

/// Post-edit hook — fire-and-forget fanout. No reply, no short-circuit.
pub async fn call_item_post_edit_hook_actor(
    srv: &Data,
    hndl: &str,
    collection: &str,
    old_itm: Option<Item>,
    id: u64,
    action: DataObjectAction,
) {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    for sender in &senders {
        let msg = PluginHookMessage::ItemPostEdit {
            hndl: hndl.to_string(),
            collection: collection.to_string(),
            old_item: old_itm.clone(),
            id,
            action: action.clone(),
        };
        if sender.send(msg).await.is_err() {
            warn!("call_item_post_edit_hook_actor: plugin task is gone, skipping");
        }
    }
}

/// Auth hook — any single deny short-circuits to `false`.
pub async fn call_item_auth_hook_actor(
    srv: &Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    id: u64,
    new_item: Option<Item>,
    del: bool,
) -> bool {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::ItemAuth {
            hndl: hndl.to_string(),
            user: user.clone(),
            collection: collection.to_string(),
            id,
            new_item: new_item.clone(),
            del,
            reply: reply_tx,
        };
        if sender.send(msg).await.is_err() {
            continue;
        }
        match reply_rx.await {
            Ok(false) => return false,
            Ok(true) => {}
            Err(_) => {
                warn!("call_item_auth_hook_actor: plugin dropped reply");
            }
        }
    }
    true
}

/// List filter hook — sequentially threads the items map through each
/// actor plugin. Plugins receive the page by-value and return a possibly-
/// mutated page; the dispatcher swaps it back into `items`.
pub async fn call_item_list_filter_hook_actor(
    srv: &Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    context: &str,
    items: &mut HashMap<u64, Item>,
) {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::ItemListFilter {
            hndl: hndl.to_string(),
            user: user.clone(),
            collection: collection.to_string(),
            context: context.to_string(),
            items: items.clone(),
            reply: reply_tx,
        };
        if sender.send(msg).await.is_err() {
            continue;
        }
        if let Ok(ListFilterReply { items: out }) = reply_rx.await {
            *items = out;
        }
    }
}

/// DB-side filter hook — collects JSON filter strings from each plugin.
pub async fn call_item_list_db_filter_hook_actor(
    srv: &Data,
    hndl: &str,
    user: &Option<Item>,
    collection: &str,
    context: &str,
    filter_type: &str,
) -> Vec<String> {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    let mut filters = Vec::new();
    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::ItemListDbFilter {
            hndl: hndl.to_string(),
            user: user.clone(),
            collection: collection.to_string(),
            context: context.to_string(),
            filter_type: filter_type.to_string(),
            reply: reply_tx,
        };
        if sender.send(msg).await.is_err() {
            continue;
        }
        if let Ok(f) = reply_rx.await {
            if !f.is_empty() {
                filters.push(f);
            }
        }
    }
    filters
}

/// Collection read hook — sequentially threads the item through plugins.
/// Returns `true` if any plugin asked for persistence (`should_save`).
pub async fn call_collection_read_hook_actor(
    data: &Data,
    hndl: &str,
    collection: &str,
    itm: &mut Item,
) -> bool {
    let senders: Vec<_> = data.plugin_registry.senders().cloned().collect();
    let mut should_save = false;
    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::CollectionRead {
            hndl: hndl.to_string(),
            collection: collection.to_string(),
            item: itm.clone(),
            reply: reply_tx,
        };
        if sender.send(msg).await.is_err() {
            continue;
        }
        if let Ok(CollectionReadReply {
            should_save: ss,
            item: maybe_new,
        }) = reply_rx.await
        {
            if let Some(new_item) = maybe_new {
                *itm = new_item;
            }
            if ss {
                should_save = true;
            }
        }
    }
    should_save
}

/// URL routes — first plugin to return anything other than `NotImplemented`
/// wins. Matches the trait-mode semantic.
pub async fn call_url_route_actor(
    srv: &Data,
    hndl: &str,
    user: &Option<Item>,
    query: &str,
) -> WebResponse {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::RouteUrl {
            hndl: hndl.to_string(),
            user: user.clone(),
            query: query.to_string(),
            reply: reply_tx,
        };
        if sender.send(msg).await.is_err() {
            continue;
        }
        if let Ok(resp) = reply_rx.await {
            if !matches!(resp, WebResponse::NotImplemented) {
                return resp;
            }
        }
    }
    WebResponse::NotImplemented
}

pub async fn call_url_post_route_actor(
    srv: &Data,
    hndl: &str,
    user: &Option<Item>,
    query: &str,
    itm: &Item,
) -> WebResponse {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    let mut response = WebResponse::NotImplemented;
    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::RouteUrlPost {
            hndl: hndl.to_string(),
            user: user.clone(),
            query: query.to_string(),
            item: itm.clone(),
            reply: reply_tx,
        };
        if sender.send(msg).await.is_err() {
            continue;
        }
        if let Ok(resp) = reply_rx.await {
            if !matches!(resp, WebResponse::NotImplemented) {
                response = resp;
            }
        }
    }
    response
}

pub async fn call_url_unprotected_route_actor(
    srv: &Data,
    hndl: &str,
    user: &Option<Item>,
    query: &str,
) -> WebResponse {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::RouteUnprotectedUrl {
            hndl: hndl.to_string(),
            user: user.clone(),
            query: query.to_string(),
            reply: reply_tx,
        };
        if sender.send(msg).await.is_err() {
            continue;
        }
        if let Ok(resp) = reply_rx.await {
            if !matches!(resp, WebResponse::NotImplemented) {
                return resp;
            }
        }
    }
    WebResponse::NotImplemented
}

pub async fn call_url_unprotected_post_route_actor(
    srv: &Data,
    hndl: &str,
    user: &Option<Item>,
    query: &str,
    itm: &Item,
) -> WebResponse {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    let mut response = WebResponse::NotImplemented;
    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::RouteUnprotectedUrlPost {
            hndl: hndl.to_string(),
            user: user.clone(),
            query: query.to_string(),
            item: itm.clone(),
            reply: reply_tx,
        };
        if sender.send(msg).await.is_err() {
            continue;
        }
        if let Ok(resp) = reply_rx.await {
            if !matches!(resp, WebResponse::NotImplemented) {
                response = resp;
            }
        }
    }
    response
}

pub async fn call_url_rest_route_actor(
    srv: &Data,
    hndl: &str,
    method: &str,
    user: &Option<Item>,
    query: &str,
    payload: &str,
) -> WebResponse {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    let mut response = WebResponse::NotImplemented;
    for sender in &senders {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = PluginHookMessage::RouteRest {
            hndl: hndl.to_string(),
            method: method.to_string(),
            user: user.clone(),
            query: query.to_string(),
            payload: payload.to_string(),
            reply: reply_tx,
        };
        if sender.send(msg).await.is_err() {
            continue;
        }
        if let Ok(resp) = reply_rx.await {
            if !matches!(resp, WebResponse::NotImplemented) {
                response = resp;
            }
        }
    }
    response
}

/// OTP hook — fire-and-forget.
pub async fn call_otp_hook_actor(srv: &Data, hndl: &str, itm: Item) {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    for sender in &senders {
        let msg = PluginHookMessage::Otp {
            hndl: hndl.to_string(),
            item: itm.clone(),
        };
        let _ = sender.send(msg).await;
    }
}

/// Periodic job — fire-and-forget. `timing` is "sec" or "min".
///
/// Not currently called from anywhere: the periodic tick loop lives in a
/// raw `thread::spawn` in main.rs with no tokio runtime, so it can't
/// invoke async channel sends. Phase 4 will move that tick onto a tokio
/// timer and wire this in.
#[allow(dead_code)]
pub async fn call_periodic_job_hook_actor(srv: &Data, timing: &str) {
    let senders: Vec<_> = srv.plugin_registry.senders().cloned().collect();
    for sender in &senders {
        let msg = PluginHookMessage::PeriodicJob {
            timing: timing.to_string(),
        };
        let _ = sender.send(msg).await;
    }
}
