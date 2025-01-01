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
use std::sync::Arc;
use crate::check_role;
use crate::get_new_salt;
use crate::get_password_hash;
use crate::handler::route::call_collection_read_hook;
use crate::init_google;
use crate::send_email;
use crate::state::store::Store;
use crate::state::store_local::*;
#[cfg(not(feature = "full_file_database"))]
use crate::state::store_mongo::*;
use crate::sync_with_google;
use crate::verify_password;
use crate::G_STATE;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::list_result::ListResult;
use isabelle_plugin_api::api::*;
use isabelle_plugin_api::plugin_pool::PluginPool;
use std::any::Any;
use std::collections::HashMap;
use std::sync::mpsc;
use tokio::runtime::Runtime;
use threadpool::ThreadPool;

struct IsabellePluginApi {
    thread_pool: ThreadPool,
    runtime: Arc<Runtime>
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

impl PluginApi for IsabellePluginApi {
    fn db_get_all_items(&self, collection: &str, sort_key: &str, filter: &str) -> ListResult {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let sort_key1 = sort_key.to_string().clone();
        let filter1 = filter.to_string().clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(
                    rt.block_on(async {
                        srv_mut
                            .rw
                            .get_all_items(&collection1, &sort_key1, &filter1)
                            .await
                    }))
                .unwrap();
        });
        receiver.recv().unwrap()
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
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let sort_key1 = sort_key.to_string().clone();
        let filter1 = filter.to_string().clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
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
        receiver.recv().unwrap()
    }
    fn db_get_item(&self, collection: &str, id: u64) -> Option<Item> {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    srv_mut.rw.get_item(&collection1, id).await
                }))
                .unwrap()
        });
        receiver.recv().unwrap()
    }

    fn db_set_item(&self, collection: &str, itm: &Item, merge: bool) {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let itm1 = itm.clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    srv_mut.rw.set_item(&collection1, &itm1, merge).await
                }))
                .unwrap()
        });
        receiver.recv().unwrap()
    }

    fn db_del_item(&self, collection: &str, id: u64) -> bool {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    srv_mut.rw.del_item(&collection1, id).await
                }))
                .unwrap()
        });
        receiver.recv().unwrap()
    }

    fn globals_get_public_url(&self) -> String {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        srv_mut.public_url.clone()
    }
    fn globals_get_settings(&self) -> Item {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    srv_mut.rw.get_settings().await
                }))
                .unwrap()
        });
        receiver.recv().unwrap()
    }

    fn auth_check_role(&self, itm: &Option<Item>, role: &str) -> bool {
        let user = itm.clone();
        let role = role.to_string();
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    check_role(srv_mut, &user, &role).await
                }))
                .unwrap()
        });
        receiver.recv().unwrap()
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

    fn fn_send_email(&self, to: &str, subject: &str, body: &str) {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let to = to.to_string();
        let subject = subject.to_string();
        let body = body.to_string();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    send_email(srv_mut, &to, &subject, &body).await
                }))
                .unwrap()
        });
        receiver.recv().unwrap()
    }

    fn fn_init_google(&self) -> String {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    init_google(srv_mut).await
                }))
                .unwrap()
        });
        receiver.recv().unwrap()
    }
    fn fn_sync_with_google(&self, add: bool, name: String, date_time: String) {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        let (sender, receiver) = mpsc::channel();
        let rt = Arc::clone(&self.runtime);
        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    sync_with_google(srv_mut, add, name, date_time).await
                }))
                .unwrap()
        });
        receiver.recv().unwrap()
    }

    fn fn_get_state(&self, handle: &str) -> &mut Option<Box<(dyn Any + Send)>> {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };
        if srv_mut.opaque_data.contains_key(handle) {
            let obj = srv_mut.opaque_data.get_mut(handle).unwrap();
            return obj;
        } else {
            return &mut srv_mut.none_object;
        }
    }

    fn fn_set_state(&self, handle: &str, value: Option<Box<(dyn Any + Send)>>) {
        let srv_lock = G_STATE.server.lock();
        let srv_mut = unsafe { &mut (*srv_lock.as_ptr()) };

        if srv_mut.opaque_data.contains_key(handle) {
            srv_mut.opaque_data.remove(handle);
        }
        srv_mut.opaque_data.insert(handle.to_string(), value);
    }
}

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

    /// Path to Google Calendar.
    pub gc_path: String,

    /// Path to Python binary
    pub py_path: String,

    /// Path to data directory, which is extremely important for file_rw
    pub data_path: String,

    /// Public URL which is needed for constructing backlinks
    pub public_url: String,

    /// Port at which Core resides.
    pub port: u16,

    /// Plugin control
    pub plugin_pool: PluginPool,

    /// Plugin API instance
    pub plugin_api: Box<dyn PluginApi>,

    /// Opaque data (mainly for plugins)
    pub opaque_data: HashMap<String, Option<Box<(dyn Any + Send)>>>,

    /// Purely internal none-object for proper boxing
    none_object: Option<Box<(dyn Any + Send)>>,
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

            gc_path: "".to_string(),
            py_path: "".to_string(),
            data_path: "".to_string(),
            public_url: "".to_string(),
            port: 8090,
            plugin_pool: PluginPool {
                plugins: Vec::new(),
            },
            plugin_api: Box::new(IsabellePluginApi::new()),
            opaque_data: HashMap::new(),
            none_object: None,
        }
    }

    /// Check existence of collection
    pub fn has_collection(&mut self, collection: &str) -> bool {
        return self.rw.collections.contains_key(collection);
    }

    /// Early initialization
    pub async fn init_checks(&mut self) {
        let internals = self.rw.get_internals().await;
        let routes = internals.safe_strstr("collection_read_hook", &HashMap::new());
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
                for route in &routes {
                    if call_collection_read_hook(self, &route.1, collection, &mut loaded_item).await
                    {
                        should_be_saved = true;
                    }
                }
                if should_be_saved {
                    self.rw.set_item(collection, &loaded_item, false).await;
                }
            }
        }
    }
}
