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
use crate::check_role;
use crate::get_new_salt;
use crate::get_password_hash;
use crate::handler::route_call::call_collection_read_hook;
use crate::init_google;
use crate::send_email;
use crate::state::route_cache::RouteCache;
use crate::state::store::Store;
use crate::state::store_local::*;
#[cfg(not(feature = "full_file_database"))]
use crate::state::store_mongo::*;
use crate::sync_with_google;
use crate::verify_password;
use crate::G_STATE;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::list_result::ListResult;
use isabelle_dm::data_model::process_result::ProcessResult;
use isabelle_plugin_api::actor::{CoreHandle, PluginRegistry};
use isabelle_plugin_api::api::*;
use isabelle_plugin_api::plugin_pool::PluginPool;
use parking_lot::Mutex;
use log::info;
use log::trace;
use std::any::Any;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Arc;
use threadpool::ThreadPool;
use tokio::runtime::Runtime;

struct IsabellePluginApi {
    thread_pool: ThreadPool,
    runtime: Arc<Runtime>,
}

unsafe impl Send for IsabellePluginApi {}

impl IsabellePluginApi {
    fn new() -> Self {
        return IsabellePluginApi {
            thread_pool: threadpool::Builder::new().build(),
            runtime: Arc::new(Runtime::new().unwrap()),
        };
    }
}

/*
 * It is important to note that in all cases Plugin API is called through
 * locations already protected by mutex. Therefore, we may safely omit
 * the lock requirement.
 */
impl PluginApi for IsabellePluginApi {
    fn db_get_all_items(&self, collection: &str, sort_key: &str, filter: &str) -> ListResult {
        trace!("db_get_all_items++");
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let sort_key1 = sort_key.to_string().clone();
        let filter1 = filter.to_string().clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    srv_mut
                        .rw
                        .get_all_items(&collection1, &sort_key1, &filter1)
                        .await
                }))
                .unwrap();
        });
        let res = receiver.recv().unwrap();
        trace!("db_get_all_items--");
        res
    }

    fn db_get_items(
        &self,
        collection: &str,
        id_min: u64,
        id_max: u64,
        sort_key: &str,
        filter: &str,
        skip: u64,
        limit: u64,
    ) -> ListResult {
        trace!("db_get_items++");
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let sort_key1 = sort_key.to_string().clone();
        let filter1 = filter.to_string().clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    srv_mut
                        .rw
                        .get_items(
                            &collection1,
                            id_min,
                            id_max,
                            &sort_key1,
                            &filter1,
                            skip,
                            limit,
                        )
                        .await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("db_get_items--");
        res
    }

    fn db_get_item(&self, collection: &str, id: u64) -> Option<Item> {
        trace!("db_get_item++");
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    srv_mut.rw.get_item(&collection1, id).await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("db_get_item--");
        res
    }

    fn db_set_item(&self, collection: &str, itm: &Item, merge: bool) -> u64 {
        trace!("db_set_item++");
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let itm1 = itm.clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    srv_mut.rw.set_item(&collection1, &itm1, merge).await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("db_set_item--");
        res
    }

    fn db_del_item(&self, collection: &str, id: u64) -> bool {
        trace!("db_del_item++");
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    srv_mut.rw.del_item(&collection1, id).await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("db_del_item--");
        res
    }

    fn globals_get_public_url(&self) -> String {
        trace!("globals_get_public_url++");
        let srv_mut: &crate::state::data::Data = &G_STATE.server;
        let url = srv_mut.public_url.lock().clone();
        trace!("globals_get_public_url--");
        url
    }

    fn globals_get_settings(&self) -> Item {
        trace!("globals_get_settings++");
        let (sender, receiver) = mpsc::channel();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    srv_mut.rw.get_settings().await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("globals_get_settings--");
        res
    }

    fn globals_set_settings(&self, item: &Item) {
        trace!("globals_set_settings++");
        let (sender, receiver) = mpsc::channel();
        let rt = Arc::clone(&self.runtime);
        let item_clone = item.clone();
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    srv_mut.rw.set_settings(item_clone).await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("globals_set_settings--");
        res
    }

    fn auth_check_role(&self, itm: &Option<Item>, role: &str) -> bool {
        trace!("auth_check_role++");
        let user = itm.clone();
        let role = role.to_string();
        let (sender, receiver) = mpsc::channel();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    trace!("blocking check role 1");
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    trace!("blocking check role 2");
                    let r = check_role(srv_mut, &user, &role).await;
                    trace!("blocking check role 3");
                    r
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("auth_check_role--");
        res
    }
    fn auth_get_new_salt(&self) -> String {
        get_new_salt()
    }
    fn auth_get_password_hash(&self, pw: &str, salt: &str) -> String {
        get_password_hash(pw, salt)
    }
    fn auth_verify_password(&self, pw: &str, pw_hash: &str) -> bool {
        verify_password(pw, pw_hash)
    }

    fn auth_login(&self, _login: &str, _password: &str) -> ProcessResult {
        return ProcessResult {
            succeeded: false,
            error: "test".to_string(),
            data: HashMap::new(),
        };
    }

    fn auth_logout(&self, _login: &str) -> ProcessResult {
        return ProcessResult {
            succeeded: false,
            error: "test".to_string(),
            data: HashMap::new(),
        };
    }

    fn auth_gen_otp(&self, _login: &str) -> ProcessResult {
        return ProcessResult {
            succeeded: false,
            error: "test".to_string(),
            data: HashMap::new(),
        };
    }

    fn auth_register(&self, _login: &str, _email: &str) -> ProcessResult {
        return ProcessResult {
            succeeded: false,
            error: "test".to_string(),
            data: HashMap::new(),
        };
    }

    fn fn_send_email(&self, to: &str, subject: &str, body: &str) {
        trace!("fn_send_email++");
        let (sender, receiver) = mpsc::channel();
        let to = to.to_string();
        let subject = subject.to_string();
        let body = body.to_string();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    send_email(srv_mut, &to, &subject, &body).await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("fn_send_email--");
        res
    }

    fn fn_init_google(&self) -> String {
        trace!("fn_init_google++");
        let (sender, receiver) = mpsc::channel();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    init_google(srv_mut).await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("fn_init_google--");
        res
    }

    fn fn_sync_with_google(&self, add: bool, name: String, date_time: String) {
        trace!("fn_sync_with_google++");
        let (sender, receiver) = mpsc::channel();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut: &crate::state::data::Data = &G_STATE.server;
                    sync_with_google(srv_mut, add, name, date_time).await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("fn_sync_with_google--");
        res
    }

    fn fn_get_state(&self, handle: &str) -> &mut Option<Box<dyn Any + Send>> {
        // NOTE: returning a mutable reference to a global slot is inherently risky;
        // see the `UnsafeCell` field doc for the safety story.
        trace!("fn_get_state++");
        let srv_mut: &crate::state::data::Data = &G_STATE.server;
        // SAFETY: cooperative serialization — IsabellePluginApi is called
        // by trait-mode plugins which run synchronously within an HTTP
        // handler that's blocked awaiting their reply, so no concurrent
        // access happens.
        let opaque: &mut HashMap<String, Option<Box<dyn Any + Send>>> =
            unsafe { &mut *srv_mut.opaque_data.get() };
        let none_slot: &mut Option<Box<dyn Any + Send>> =
            unsafe { &mut *srv_mut.none_object.get() };

        if handle == "opt_data_path" {
            let present = opaque.contains_key(handle);
            let kind = if present {
                match opaque.get(handle) {
                    Some(Some(v)) => {
                        if v.downcast_ref::<Vec<u8>>().is_some() {
                            "Some(Vec<u8>)"
                        } else if v.downcast_ref::<String>().is_some() {
                            "Some(String)"
                        } else {
                            "Some(NonString)"
                        }
                    }
                    Some(None) => "None",
                    None => "Missing",
                }
            } else {
                "Missing"
            };
            log::info!(
                "[plugin_state][get] key='{}' present={} kind={} opaque_len={}",
                handle,
                present,
                kind,
                opaque.len()
            );

            if let Some(Some(v)) = opaque.get(handle) {
                if let Some(b) = v.downcast_ref::<Vec<u8>>() {
                    let s = String::from_utf8_lossy(b).to_string();
                    log::info!("[plugin_state][get] key='{}' value(bytes)='{}'", handle, s);
                } else if let Some(s) = v.downcast_ref::<String>() {
                    log::info!("[plugin_state][get] key='{}' value='{}'", handle, s);
                }
            }
        }

        if opaque.contains_key(handle) {
            let obj = opaque.get_mut(handle).unwrap();
            trace!("fn_get_state--");
            return obj;
        } else {
            trace!("fn_get_state--");
            return none_slot;
        }
    }

    fn secret_get(&self, id: u64) -> Option<Item> {
        trace!("secret_get++");
        let srv_mut: &crate::state::data::Data = &G_STATE.server;
        let res = srv_mut.secrets.lock().as_ref().and_then(|s| s.get(id));
        trace!("secret_get--");
        res
    }

    fn secret_get_by_name(&self, name: &str) -> Option<Item> {
        trace!("secret_get_by_name++");
        let srv_mut: &crate::state::data::Data = &G_STATE.server;
        let res = srv_mut
            .secrets
            .lock()
            .as_ref()
            .and_then(|s| s.get_by_name(name));
        trace!("secret_get_by_name--");
        res
    }

    fn secret_list(&self) -> Vec<(u64, String)> {
        trace!("secret_list++");
        let srv_mut: &crate::state::data::Data = &G_STATE.server;
        let res = srv_mut
            .secrets
            .lock()
            .as_ref()
            .map(|s| s.list())
            .unwrap_or_default();
        trace!("secret_list--");
        res
    }

    fn secret_set(&self, item: &Item, merge: bool) -> Result<u64, String> {
        trace!("secret_set++");
        let srv_mut: &crate::state::data::Data = &G_STATE.server;
        let res = match srv_mut.secrets.lock().as_mut() {
            Some(s) => s.set(item, merge).map_err(|e| e.to_string()),
            None => Err("secret store is not initialized".to_string()),
        };
        trace!("secret_set--");
        res
    }

    fn secret_del(&self, id: u64) -> bool {
        trace!("secret_del++");
        let srv_mut: &crate::state::data::Data = &G_STATE.server;
        let res = match srv_mut.secrets.lock().as_mut() {
            Some(s) => s.del(id).unwrap_or(false),
            None => false,
        };
        trace!("secret_del--");
        res
    }

    fn fn_set_state(&self, handle: &str, value: Option<Box<dyn Any + Send>>) {
        // Verbose logging for the problematic key to catch who overwrites/clears it.
        trace!("fn_set_state++");
        let srv_mut: &crate::state::data::Data = &G_STATE.server;
        // SAFETY: see `fn_get_state`.
        let opaque: &mut HashMap<String, Option<Box<dyn Any + Send>>> =
            unsafe { &mut *srv_mut.opaque_data.get() };

        if handle == "opt_data_path" {
            let new_kind = match &value {
                Some(v) => {
                    if v.downcast_ref::<Vec<u8>>().is_some() {
                        "Some(Vec<u8>)"
                    } else if v.downcast_ref::<String>().is_some() {
                        "Some(String)"
                    } else {
                        "Some(NonString)"
                    }
                }
                None => "None",
            };
            let old_present = opaque.contains_key(handle);
            let old_kind = if old_present {
                match opaque.get(handle) {
                    Some(Some(v)) => {
                        if v.downcast_ref::<Vec<u8>>().is_some() {
                            "Some(Vec<u8>)"
                        } else if v.downcast_ref::<String>().is_some() {
                            "Some(String)"
                        } else {
                            "Some(NonString)"
                        }
                    }
                    Some(None) => "None",
                    None => "Missing",
                }
            } else {
                "Missing"
            };

            log::info!(
                "[plugin_state][set] key='{}' old_present={} old_kind={} -> new_kind={} opaque_len_before={}",
                handle,
                old_present,
                old_kind,
                new_kind,
                opaque.len()
            );

            if let Some(v) = &value {
                if let Some(b) = v.downcast_ref::<Vec<u8>>() {
                    let s = String::from_utf8_lossy(b).to_string();
                    log::info!(
                        "[plugin_state][set] key='{}' new_value(bytes)='{}'",
                        handle,
                        s
                    );
                } else if let Some(s) = v.downcast_ref::<String>() {
                    log::info!("[plugin_state][set] key='{}' new_value='{}'", handle, s);
                }
            }
        }

        if opaque.contains_key(handle) {
            opaque.remove(handle);
        }
        opaque.insert(handle.to_string(), value);
        trace!("fn_set_state--");
    }
}

// SAFETY: `Data` is shared across actix worker arbiters via `Arc<Data>`.
// All runtime-mutable fields (`rw`, `file_rw`, `secrets`, `plugin_pool`,
// `route_cache`) are wrapped in `parking_lot::Mutex` and access goes
// through `&self`. The remaining non-`Sync` fields — `opaque_data`,
// `plugin_api: Box<dyn PluginApi>`, `none_object` — are accessed via the
// same raw-pointer-escape pattern the legacy `IsabellePluginApi` used
// (and continues to use for trait-mode plugins). That access is
// cooperatively-serialised by convention: HTTP handlers don't mutate
// these fields, only `IsabellePluginApi` does, and its callers are
// already in a sync state when the call happens. Phase-4 cleanup is to
// wrap `opaque_data` in a `Mutex` too once `fn_get_state`'s `&mut`-
// returning shape is retired with the trait-mode plugin API.
unsafe impl Sync for Data {}

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

    /// Plugin control (legacy trait-dispatch path). Phase-out is gradual:
    /// new plugins register into `plugin_registry` (actor model); old
    /// trait-based plugins keep using this pool.
    ///
    /// Wrapped in `Mutex` so `Data` can be shared via `Arc` without the
    /// outer `parking_lot::ReentrantMutex` — hook callsites lock briefly
    /// to fan out, then release.
    pub plugin_pool: Mutex<PluginPool>,

    /// Actor-model plugin registry. Holds an `mpsc::Sender<PluginHookMessage>`
    /// per registered plugin actor. Empty until Phase 3 starts migrating
    /// individual plugins over.
    pub plugin_registry: PluginRegistry,

    /// Handle to the core processing task that services `CoreMessage`s from
    /// plugin actors. Set by `main()` after the task is spawned; before
    /// that it's `None`. Cloned out and passed to each actor plugin at
    /// register time.
    pub core_handle: Option<CoreHandle>,

    /// Plugin API instance (legacy thread-pool-bounce path, paired with
    /// `plugin_pool`). Replaced for actor-mode plugins by `CoreHandle`
    /// which is given to each plugin at register time and routes through
    /// the core processing task.
    pub plugin_api: Box<dyn PluginApi>,

    /// Opaque data (mainly for plugins).
    ///
    /// Wrapped in `UnsafeCell` so the legacy `PluginApi::fn_get_state` —
    /// which returns `&mut Option<Box<dyn Any + Send>>` and can't be
    /// retrofitted to a `Mutex` guard — keeps compiling under `&Data`.
    /// Safety relies on cooperative serialization (same model as the
    /// pre-Phase-4 `IsabellePluginApi` raw-pointer escape).
    pub opaque_data: std::cell::UnsafeCell<HashMap<String, Option<Box<dyn Any + Send>>>>,

    /// Pre-parsed routing tables derived from `internals.js`. Built once at
    /// startup via `rebuild_route_cache()` and treated as immutable from then
    /// on (matches the immutability of `internals.js` itself).
    ///
    /// Wrapped in `Mutex<Arc<...>>` so `rebuild_route_cache` can be `&self`
    /// (needed so `Data` can live behind `Arc<Data>` without an outer lock).
    /// Readers do `state.route_cache.lock().clone()` — cheap atomic Arc bump,
    /// no contention since the inner Arc is shared.
    pub route_cache: Mutex<Arc<RouteCache>>,

    /// Purely internal none-object for proper boxing
    none_object: std::cell::UnsafeCell<Option<Box<dyn Any + Send>>>,
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
            plugin_pool: Mutex::new(PluginPool {
                plugins: Vec::new(),
            }),
            plugin_registry: PluginRegistry::new(),
            core_handle: None,
            plugin_api: Box::new(IsabellePluginApi::new()),
            opaque_data: std::cell::UnsafeCell::new(HashMap::new()),
            route_cache: Mutex::new(Arc::new(RouteCache::default())),
            none_object: std::cell::UnsafeCell::new(None),
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

    /// Initialize the data path for plugins
    pub async fn init_data_path(&self) {
        let data_path = self.data_path.lock().clone();
        info!("Data path for plugins: {}", data_path);
        // Set environment variable for ABI-stable access by plugins
        std::env::set_var("ISABELLE_DATA_PATH", &data_path);
        self.plugin_api.fn_set_state(
            "opt_data_path",
            Some(Box::new(data_path.into_bytes())),
        );
    }
}
