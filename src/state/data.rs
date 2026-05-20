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
use crate::args::DEFAULT_MAX_PAYLOAD_BYTES;
use crate::handler::route_call::call_collection_read_hook;
use crate::state::route_cache::RouteCache;
use crate::state::store::Store;
use crate::state::store_local::*;
#[cfg(not(feature = "full_file_database"))]
use crate::state::store_mongo::*;
use isabelle_plugin_api::actor::{CoreHandle, PluginRegistry};
use log::info;
use parking_lot::Mutex;
use std::sync::Arc;

/// Server data structure
pub struct Data {
    /// File-based read/write data, which is useful for initial propagation
    /// of database.
    #[cfg(not(feature = "full_file_database"))]
    pub file_rw: StoreLocal,

    /// Read database access struct.
    #[cfg(feature = "full_file_database")]
    pub rw: StoreLocal,
    #[cfg(not(feature = "full_file_database"))]
    pub rw: StoreMongo,

    // The fields below are set once in `main()` startup and never mutated
    // again. They live behind `Mutex` only because the outer lock has been
    // removed — runtime `&Data` access has no other way to assign to them.
    // Reads do `.lock().clone()`; the cost is one uncontended atomic per
    // access, negligible against any actual work the handler does.
    /// Path to Google Calendar.
    pub gc_path: Mutex<String>,

    /// Path to Python binary
    pub py_path: Mutex<String>,

    /// Path to data directory, which is extremely important for file_rw
    pub data_path: Mutex<String>,

    /// Public URL which is needed for constructing backlinks
    pub public_url: Mutex<String>,

    /// Port at which Core resides.
    pub port: std::sync::atomic::AtomicU16,

    /// Max request payload size in bytes
    pub max_payload_bytes: std::sync::atomic::AtomicUsize,

    /// Path to script invoked by POST /system/update
    pub update_script: Mutex<String>,

    /// Encrypted user-data secret store. Populated in main() after data
    /// path is known. Wrapped in `Mutex` so the `secret_*` HTTP handlers
    /// can access it without holding the outer Data lock.
    pub secrets: Mutex<Option<crate::state::secrets::SecretStore>>,

    /// Actor-model plugin registry. Holds an `mpsc::Sender<PluginHookMessage>`
    /// per registered plugin actor.
    pub plugin_registry: PluginRegistry,

    /// Handle to the core processing task that services `CoreMessage`s from
    /// plugin actors. Set by `main()` after the task is spawned; before
    /// that it's `None`. Cloned out and passed to each actor plugin at
    /// register time.
    pub core_handle: Option<CoreHandle>,

    /// Pre-parsed routing tables derived from `internals.js`. Built once at
    /// startup via `rebuild_route_cache()` and treated as immutable from then
    /// on (matches the immutability of `internals.js` itself).
    pub route_cache: Mutex<Arc<RouteCache>>,
}

impl Data {
    pub fn new() -> Self {
        #[cfg(feature = "full_file_database")]
        let rw = StoreLocal::new();
        #[cfg(not(feature = "full_file_database"))]
        let rw = StoreMongo::new();
        Self {
            #[cfg(not(feature = "full_file_database"))]
            file_rw: StoreLocal::new(),

            rw: rw,

            gc_path: Mutex::new(String::new()),
            py_path: Mutex::new(String::new()),
            data_path: Mutex::new(String::new()),
            public_url: Mutex::new(String::new()),
            port: std::sync::atomic::AtomicU16::new(8090),
            max_payload_bytes: std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_PAYLOAD_BYTES),
            update_script: Mutex::new(String::new()),
            secrets: Mutex::new(None),
            plugin_registry: PluginRegistry::new(),
            core_handle: None,
            route_cache: Mutex::new(Arc::new(RouteCache::default())),
        }
    }

    /// Rebuild the pre-parsed route cache from the current `internals.js`.
    /// Called once at startup; `internals.js` is treated as immutable so
    /// no invalidation logic is required.
    pub async fn rebuild_route_cache(&self) {
        let internals = self.rw.get_internals().await;
        let new = Arc::new(RouteCache::from_internals(&internals));
        info!(
            "Route cache built: {} url + {} unprotected + {} rest + {} pre-edit ({} wildcard) + {} post-edit ({} wildcard)",
            new.url_routes.len(),
            new.unprotected_url_routes.len(),
            new.rest_routes.len(),
            new.item_pre_edit.values().map(|v| v.len()).sum::<usize>(),
            new.item_pre_edit_wildcard.len(),
            new.item_post_edit.values().map(|v| v.len()).sum::<usize>(),
            new.item_post_edit_wildcard.len(),
        );
        *self.route_cache.lock() = new;
    }

    /// Check existence of collection
    pub fn has_collection(&self, collection: &str) -> bool {
        return self.rw.collections.contains_key(collection);
    }

    /// Early initialization
    pub async fn init_checks(&self) {
        let internals = self.rw.get_internals().await;
        let routes: Vec<String> = internals
            .strstrs
            .get("collection_read_hook")
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        let collections = self.rw.get_collections().await;

        // Load all collections
        for collection in &collections {
            // Load all items and resave them
            let items = self.rw.get_item_ids(collection).await;
            for itm in items {
                let loaded_item_opt = self.rw.get_item(collection, itm.0).await;
                if loaded_item_opt.is_none() {
                    continue;
                }
                let mut loaded_item = loaded_item_opt.unwrap();
                let mut should_be_saved = false;
                for hndl in &routes {
                    if call_collection_read_hook(self, hndl, collection, &mut loaded_item).await {
                        should_be_saved = true;
                    }
                }
                if should_be_saved {
                    self.rw.set_item(collection, &loaded_item, false).await;
                }
            }
        }
    }

    /// Initialize the data path for plugins. Plugins read it via
    /// `CoreHandle::globals_get_data_path().await`.
    pub async fn init_data_path(&self) {
        let data_path = self.data_path.lock().clone();
        info!("Data path for plugins: {}", data_path);
        // Set environment variable for ABI-stable access by plugins
        std::env::set_var("ISABELLE_DATA_PATH", &data_path);
    }
}
