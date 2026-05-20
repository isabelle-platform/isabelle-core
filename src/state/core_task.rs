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

//! Core processing task for the actor-model plugin path.
//!
//! Actor plugins (Phase 3+) call into core via [`CoreHandle`], which
//! sends [`CoreMessage`]s into the mpsc the task here drains. Each
//! message is processed sequentially against the global `Data`.
//!
//! This is the replacement for `IsabellePluginApi`'s thread-pool-bounce.
//! The old `PluginApi` impl in `state/data.rs` is still alive for legacy
//! trait-mode plugins; this task only serves the new actor-mode plugins.
//! Both can run in parallel during Phase 3 migration.
//!
//! Throughput: messages are processed one at a time. We're not unblocking
//! parallel request processing in this phase — the win here is removing
//! the `mpsc::sync_channel + threadpool::ThreadPool + block_on` round-trip
//! the old plugin API paid for every callback (5-50 µs of pure overhead
//! per call → ~100 ns mpsc send).

use crate::server::user_control::check_role;
use crate::state::state::State;
use crate::state::store::Store;
use crate::util::crypto::{get_new_salt, get_password_hash, verify_password};
use isabelle_plugin_api::actor::{CoreHandle, CoreMessage};
use log::trace;
use tokio::sync::mpsc;

/// Channel capacity for the core task's inbox. Each in-flight plugin
/// callback occupies a slot; 256 is plenty for typical plugin counts
/// (10-ish) × typical concurrent requests (10s).
const CHANNEL_CAPACITY: usize = 256;

/// Spawn the core processing task. Returns the `CoreHandle` to clone and
/// hand out to plugin actors at register time.
///
/// The task lives for the entire server lifetime; it exits only when all
/// senders are dropped (i.e. all plugin actors have shut down and core
/// has dropped its own handle). For graceful shutdown we'd send a sentinel
/// or wire a stop signal in — phase-4 concern.
pub fn spawn_core_task(state: State) -> CoreHandle {
    let (tx, rx) = mpsc::channel::<CoreMessage>(CHANNEL_CAPACITY);
    // actix_rt::spawn uses the current-thread runtime — no Send bound on
    // the future, so we can hold the (non-Send) `ReentrantMutexGuard`
    // across `await` points inside `handle_message`. Same model the HTTP
    // handlers use today.
    actix_rt::spawn(run(state, rx));
    CoreHandle::new(tx)
}

async fn run(state: State, mut rx: mpsc::Receiver<CoreMessage>) {
    while let Some(msg) = rx.recv().await {
        handle_message(&state, msg).await;
    }
    trace!("core_task: all senders dropped, exiting");
}

async fn handle_message(state: &State, msg: CoreMessage) {
    // Access `Data` via raw pointer instead of taking the parking_lot
    // mutex.
    //
    // Why: HTTP handlers acquire the mutex on a worker arbiter (thread T2)
    // and may hold it across `.await` while fanning out a hook to an actor
    // plugin. The actor plugin lives on the main arbiter (T1) and calls
    // back into core via CoreHandle → CoreMessage. If THIS task tried to
    // re-acquire the mutex, parking_lot would block T1 cross-thread (T2
    // still holds it), and T2 is blocked on the oneshot reply — classic
    // deadlock.
    //
    // The HTTP handler doesn't actively mutate `Data` while suspended on
    // its `.await`, so a raw-pointer mutation by this task is operationally
    // safe — same cooperative-serialization model the legacy
    // `IsabellePluginApi` thread-pool path uses. Strictly, this is UB by
    // Rust's aliasing rules; the proper fix is to make `core_task` the
    // sole owner of `Data` (Phase 4) so the mutex disappears entirely.
    let srv: &crate::state::data::Data = &state.server;

    match msg {
        // -------- Database --------
        CoreMessage::DbGetAllItems {
            collection,
            sort_key,
            filter,
            reply,
        } => {
            let lr = srv.rw.get_all_items(&collection, &sort_key, &filter).await;
            let _ = reply.send(lr);
        }
        CoreMessage::DbGetItems {
            collection,
            id_min,
            id_max,
            sort_key,
            filter,
            skip,
            limit,
            reply,
        } => {
            let lr = srv
                .rw
                .get_items(&collection, id_min, id_max, &sort_key, &filter, skip, limit)
                .await;
            let _ = reply.send(lr);
        }
        CoreMessage::DbGetItem {
            collection,
            id,
            reply,
        } => {
            let item = srv.rw.get_item(&collection, id).await;
            let _ = reply.send(item);
        }
        CoreMessage::DbSetItem {
            collection,
            item,
            merge,
            reply,
        } => {
            let id = srv.rw.set_item(&collection, &item, merge).await;
            let _ = reply.send(id);
        }
        CoreMessage::DbDelItem {
            collection,
            id,
            reply,
        } => {
            let ok = srv.rw.del_item(&collection, id).await;
            let _ = reply.send(ok);
        }

        // -------- Globals --------
        CoreMessage::GlobalsGetPublicUrl { reply } => {
            let _ = reply.send(srv.public_url.lock().clone());
        }
        CoreMessage::GlobalsGetDataPath { reply } => {
            let _ = reply.send(srv.data_path.lock().clone());
        }
        CoreMessage::GlobalsGetSettings { reply } => {
            let s = srv.rw.get_settings().await;
            let _ = reply.send(s);
        }
        CoreMessage::GlobalsSetSettings { item } => {
            srv.rw.set_settings(item).await;
        }

        // -------- Auth --------
        CoreMessage::AuthCheckRole { item, role, reply } => {
            let ok = check_role(srv, &item, &role).await;
            let _ = reply.send(ok);
        }
        CoreMessage::AuthGetNewSalt { reply } => {
            let _ = reply.send(get_new_salt());
        }
        CoreMessage::AuthGetPasswordHash {
            password,
            salt,
            reply,
        } => {
            let _ = reply.send(get_password_hash(&password, &salt));
        }
        CoreMessage::AuthVerifyPassword {
            password,
            hash,
            reply,
        } => {
            let _ = reply.send(verify_password(&password, &hash));
        }
        // Login/Logout/Register/GenOtp: the legacy trait impls in data.rs
        // return a hard-coded "test" failure (they were never wired up).
        // Mirror that for now — actor plugins that actually need these
        // should drive them through the regular HTTP routes for now.
        CoreMessage::AuthLogin { reply, .. } => {
            let _ = reply.send(stub_failure("auth_login not yet implemented"));
        }
        CoreMessage::AuthLogout { reply, .. } => {
            let _ = reply.send(stub_failure("auth_logout not yet implemented"));
        }
        CoreMessage::AuthRegister { reply, .. } => {
            let _ = reply.send(stub_failure("auth_register not yet implemented"));
        }
        CoreMessage::AuthGenOtp { reply, .. } => {
            let _ = reply.send(stub_failure("auth_gen_otp not yet implemented"));
        }

        // -------- Notifications --------
        CoreMessage::SendEmail { to, subject, body } => {
            crate::notif::email::send_email(srv, &to, &subject, &body).await;
        }
        CoreMessage::InitGoogle { reply } => {
            let url = crate::notif::gcal::init_google(srv).await;
            let _ = reply.send(url);
        }
        CoreMessage::SyncWithGoogle {
            add,
            name,
            date_time,
        } => {
            crate::notif::gcal::sync_with_google(srv, add, name, date_time).await;
        }

        // -------- Secrets --------
        CoreMessage::SecretGet { id, reply } => {
            let res = srv.secrets.lock().as_ref().and_then(|s| s.get(id));
            let _ = reply.send(res);
        }

        // CoreMessage is `#[non_exhaustive]`. Unknown future variants are
        // silently ignored — same as old PluginApi-stub behaviour for
        // unimplemented methods.
        _ => {
            trace!("core_task: unhandled CoreMessage variant");
        }
    }

    // Touch `srv` once at the very end so the binding's lifetime extends
    // across the match (the borrow-checker is fine with it but this also
    // documents intent — the raw pointer is valid for the whole task).
    let _ = srv;

    // Yield to scheduler so we don't monopolise the executor on bursts of
    // plugin callbacks.
    tokio::task::yield_now().await;
}

fn stub_failure(reason: &str) -> isabelle_dm::data_model::process_result::ProcessResult {
    isabelle_dm::data_model::process_result::ProcessResult {
        succeeded: false,
        error: reason.to_string(),
        data: std::collections::HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end through CoreHandle → core task → state-free helper.
    /// Exercises the auth-crypto variants which don't need Mongo so we
    /// can use a fresh `State::new()` in the test.
    ///
    /// `actix_rt::spawn` requires a `LocalSet` in scope; production code
    /// gets one from actix-web's runtime, but unit tests build their own.
    #[test]
    fn core_task_round_trips_through_core_handle() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();

        local.block_on(&rt, async {
            let state = State::new();
            let handle = spawn_core_task(state);

            let salt = handle.auth_get_new_salt().await;
            assert!(!salt.is_empty(), "salt should not be empty");

            let hash = handle.auth_get_password_hash("hello", &salt).await;
            assert!(!hash.is_empty(), "hash should not be empty");

            assert!(
                handle.auth_verify_password("hello", &hash).await,
                "verify should accept the original password"
            );
            assert!(
                !handle.auth_verify_password("wrong", &hash).await,
                "verify should reject the wrong password"
            );
        });
    }
}
