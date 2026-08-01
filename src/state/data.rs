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
use std::sync::OnceLock;

/// Server data structure
pub struct Data {
    /// File-based read/write data, which is useful for initial propagation
    /// of database.
    #[cfg(not(feature = "full_file_database"))]
    pub file_rw: StoreLocal,

    /// Read/write database access.
    ///
    /// A trait object rather than the concrete backend: the choice between
    /// Mongo and the file store is a build-time detail, and holding it behind
    /// `Store` is what lets a test substitute an in-memory implementation and
    /// exercise the HTTP handlers at all. Everything the handlers need is on
    /// the trait — including `find_user` and `has_collection`, which used to
    /// be reached by poking at the concrete type's fields.
    pub rw: Box<dyn Store + Send + Sync>,

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
    ///
    /// Filled once during startup, then read-only for the process lifetime.
    /// `OnceLock` states that directly, and is what lets startup publish it
    /// through a shared `&Data` — the registry cannot be built any earlier,
    /// because the plugins it holds need the `CoreHandle`, which in turn needs
    /// the `Arc<Data>` to already exist. Reaching for `&mut` here (by casting
    /// away the shared reference) is undefined behaviour, threading argument
    /// or not: `&T` promises the compiler nobody writes through it.
    plugin_registry: OnceLock<PluginRegistry>,

    /// Handle to the core processing task that services `CoreMessage`s from
    /// plugin actors. Published once the task is spawned; see
    /// `plugin_registry` for why it is a `OnceLock`.
    core_handle: OnceLock<CoreHandle>,

    /// Pre-parsed routing tables derived from `internals.js`. Built once at
    /// startup via `rebuild_route_cache()` and treated as immutable from then
    /// on (matches the immutability of `internals.js` itself).
    pub route_cache: Mutex<Arc<RouteCache>>,
}

impl Data {
    pub fn new() -> Self {
        #[cfg(feature = "full_file_database")]
        let rw: Box<dyn Store + Send + Sync> = Box::new(StoreLocal::new());
        #[cfg(not(feature = "full_file_database"))]
        let rw: Box<dyn Store + Send + Sync> = Box::new(StoreMongo::new());
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
            plugin_registry: OnceLock::new(),
            core_handle: OnceLock::new(),
            route_cache: Mutex::new(Arc::new(RouteCache::default())),
        }
    }

    /// The registered plugin actors.
    ///
    /// Before startup publishes the registry — and in tests that never do —
    /// this yields an empty registry, so hook dispatch fans out to nobody
    /// instead of panicking.
    pub fn plugin_registry(&self) -> &PluginRegistry {
        static EMPTY: OnceLock<PluginRegistry> = OnceLock::new();
        self.plugin_registry
            .get()
            .unwrap_or_else(|| EMPTY.get_or_init(PluginRegistry::new))
    }

    /// Publish the plugin registry. Called once, during startup.
    ///
    /// Returns the registry back if one was already published, which can only
    /// happen if `run()` were invoked twice against the same `Data`.
    pub fn set_plugin_registry(&self, registry: PluginRegistry) -> Result<(), PluginRegistry> {
        self.plugin_registry.set(registry)
    }

    /// Handle to the core task, once it has been spawned.
    pub fn core_handle(&self) -> Option<&CoreHandle> {
        self.core_handle.get()
    }

    /// Publish the core task handle. Called once, during startup.
    pub fn set_core_handle(&self, handle: CoreHandle) -> Result<(), CoreHandle> {
        self.core_handle.set(handle)
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
        self.rw.has_collection(collection)
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
