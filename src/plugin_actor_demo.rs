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

//! Actor-mode demo plugin (Phase 3 pilot).
//!
//! This plugin exists to validate the actor-mode pipeline end-to-end:
//! `route_call_actor::call_*_actor` → mpsc::Sender → this task →
//! oneshot reply → dispatcher.
//!
//! It doesn't perform any business logic — every hook just logs the
//! event at `trace!` level and returns a passthrough/default reply.
//! Production deployments don't need it; registration is gated by the
//! `actor-demo` cargo feature.

#![cfg(feature = "actor-demo")]

use isabelle_plugin_api::actor::{
    CollectionReadReply, CoreHandle, ListFilterReply, PluginHookMessage, PluginRegistry,
    PreEditReply,
};
use isabelle_plugin_api::api::WebResponse;
use log::trace;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Counters incremented for each hook variant the plugin sees. Exposed
/// for tests that want to assert "the dispatcher actually reached us".
#[derive(Default)]
pub struct DemoStats {
    pub item_pre_edit: AtomicU64,
    pub item_post_edit: AtomicU64,
    pub item_auth: AtomicU64,
    pub item_list_filter: AtomicU64,
    pub item_list_db_filter: AtomicU64,
    pub collection_read: AtomicU64,
    pub route_url: AtomicU64,
    pub route_url_post: AtomicU64,
    pub route_unprotected_url: AtomicU64,
    pub route_unprotected_url_post: AtomicU64,
    pub route_rest: AtomicU64,
    pub otp: AtomicU64,
    pub periodic: AtomicU64,
    pub ping: AtomicU64,
}

/// Register the demo plugin into the supplied registry and spawn its
/// processing task. Returns an `Arc<DemoStats>` the caller (tests or
/// main.rs) can keep to observe activity.
///
/// `_core` is accepted but unused — the demo plugin doesn't call back
/// into core. Real plugins will use it for `core.db_get_item(...).await`
/// etc.
pub fn register_demo(reg: &mut PluginRegistry, _core: CoreHandle) -> Arc<DemoStats> {
    let stats = Arc::new(DemoStats::default());
    let stats_clone = stats.clone();
    let (tx, rx) = mpsc::channel(64);
    actix_rt::spawn(run(rx, stats_clone));
    reg.add("actor-demo", tx);
    stats
}

async fn run(mut rx: mpsc::Receiver<PluginHookMessage>, stats: Arc<DemoStats>) {
    while let Some(msg) = rx.recv().await {
        match msg {
            PluginHookMessage::ItemPreEdit { reply, .. } => {
                stats.item_pre_edit.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: ItemPreEdit");
                let _ = reply.send(PreEditReply::ok_unchanged());
            }
            PluginHookMessage::ItemPostEdit { .. } => {
                stats.item_post_edit.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: ItemPostEdit");
            }
            PluginHookMessage::ItemAuth { reply, .. } => {
                stats.item_auth.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: ItemAuth → allow");
                let _ = reply.send(true);
            }
            PluginHookMessage::ItemListFilter { items, reply, .. } => {
                stats.item_list_filter.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: ItemListFilter");
                let _ = reply.send(ListFilterReply { items });
            }
            PluginHookMessage::ItemListDbFilter { reply, .. } => {
                stats.item_list_db_filter.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: ItemListDbFilter → empty");
                let _ = reply.send(String::new());
            }
            PluginHookMessage::CollectionRead { reply, .. } => {
                stats.collection_read.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: CollectionRead → no save");
                let _ = reply.send(CollectionReadReply::default());
            }
            PluginHookMessage::Otp { .. } => {
                stats.otp.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: Otp");
            }
            PluginHookMessage::PeriodicJob { .. } => {
                stats.periodic.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: PeriodicJob");
            }
            PluginHookMessage::RouteUrl { reply, .. } => {
                stats.route_url.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: RouteUrl → NotImplemented");
                let _ = reply.send(WebResponse::NotImplemented);
            }
            PluginHookMessage::RouteUrlPost { reply, .. } => {
                stats.route_url_post.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: RouteUrlPost → NotImplemented");
                let _ = reply.send(WebResponse::NotImplemented);
            }
            PluginHookMessage::RouteUnprotectedUrl { reply, .. } => {
                stats.route_unprotected_url.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: RouteUnprotectedUrl → NotImplemented");
                let _ = reply.send(WebResponse::NotImplemented);
            }
            PluginHookMessage::RouteUnprotectedUrlPost { reply, .. } => {
                stats
                    .route_unprotected_url_post
                    .fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: RouteUnprotectedUrlPost → NotImplemented");
                let _ = reply.send(WebResponse::NotImplemented);
            }
            PluginHookMessage::RouteRest { reply, .. } => {
                stats.route_rest.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: RouteRest → NotImplemented");
                let _ = reply.send(WebResponse::NotImplemented);
            }
            PluginHookMessage::Ping { reply } => {
                stats.ping.fetch_add(1, Ordering::Relaxed);
                trace!("actor-demo: Ping");
                let _ = reply.send(());
            }
            PluginHookMessage::Shutdown => {
                trace!("actor-demo: Shutdown");
                break;
            }
            _ => {
                // PluginHookMessage is #[non_exhaustive]; ignore unknown
                // variants gracefully so adding new ones doesn't break the
                // demo plugin.
            }
        }
    }
    trace!("actor-demo: task exited");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::route_call_actor::{
        call_item_auth_hook_actor, call_item_post_edit_hook_actor, call_item_pre_edit_hook_actor,
    };
    use crate::state::core_task::spawn_core_task;
    use crate::state::data::Data;
    use crate::state::state::State;
    use isabelle_dm::data_model::data_object_action::DataObjectAction;
    use isabelle_dm::data_model::item::Item;
    use std::ops::DerefMut;

    /// Drives the dispatcher → demo-plugin → reply roundtrip for a few
    /// hook variants. Validates the actor pipeline is wired end-to-end.
    #[test]
    fn dispatcher_reaches_demo_plugin_via_actor_path() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();

        local.block_on(&rt, async {
            // Build minimal infra: State + spawn core task + register demo.
            let state = State::new();
            let handle = spawn_core_task(state.clone());

            // Grab &mut Data from the state and register the demo plugin
            // into its plugin_registry.
            let stats = {
                let srv_lock = state.server.lock();
                let srv = unsafe { &mut (*srv_lock.as_ptr()) };
                register_demo(&mut srv.plugin_registry, handle.clone())
            };

            // Fire each hook variant once.
            let srv_lock = state.server.lock();
            let mut srv = unsafe { &mut (*srv_lock.as_ptr()) };
            let usr: Option<Item> = None;

            // pre_edit
            let mut itm = Item::new();
            let r = call_item_pre_edit_hook_actor(
                srv.deref_mut(),
                "demo-hndl",
                &usr,
                "test",
                None,
                &mut itm,
                DataObjectAction::Create,
                false,
            )
            .await;
            assert!(r.succeeded, "pre_edit reply should be ok");

            // post_edit
            call_item_post_edit_hook_actor(
                srv.deref_mut(),
                "demo-hndl",
                "test",
                None,
                42,
                DataObjectAction::Modify,
            )
            .await;

            // auth
            let allowed = call_item_auth_hook_actor(
                srv.deref_mut(),
                "demo-hndl",
                &usr,
                "test",
                1,
                None,
                false,
            )
            .await;
            assert!(allowed, "demo plugin allows everything");

            drop(srv_lock);

            // Post_edit is fire-and-forget — give the task a tick to
            // actually pick it up before we assert on counters.
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;

            assert_eq!(
                stats.item_pre_edit.load(Ordering::Relaxed),
                1,
                "pre_edit counter"
            );
            assert_eq!(
                stats.item_post_edit.load(Ordering::Relaxed),
                1,
                "post_edit counter"
            );
            assert_eq!(stats.item_auth.load(Ordering::Relaxed), 1, "auth counter");
        });
    }
}
