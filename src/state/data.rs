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
use crate::check_role;
use crate::get_new_salt;
use crate::get_password_hash;
use crate::handler::route_call::call_collection_read_hook;
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
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
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
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
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
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
                    srv_mut.rw.get_item(&collection1, id).await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("db_get_item--");
        res
    }

    fn db_set_item(&self, collection: &str, itm: &Item, merge: bool) {
        trace!("db_set_item++");
        let (sender, receiver) = mpsc::channel();
        let collection1 = collection.to_string().clone();
        let itm1 = itm.clone();
        let rt = Arc::clone(&self.runtime);

        self.thread_pool.execute(move || {
            sender
                .send(rt.block_on(async {
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
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
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
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
        let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
        let url = srv_mut.public_url.clone();
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
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
                    srv_mut.rw.get_settings().await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("globals_get_settings--");
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
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
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
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
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
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
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
                    let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
                    sync_with_google(srv_mut, add, name, date_time).await
                }))
                .unwrap()
        });
        let res = receiver.recv().unwrap();
        trace!("fn_sync_with_google--");
        res
    }

    fn fn_get_state(&self, handle: &str) -> &mut Option<Box<(dyn Any + Send)>> {
        trace!("fn_get_state++");
        let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };
        if srv_mut.opaque_data.contains_key(handle) {
            let obj = srv_mut.opaque_data.get_mut(handle).unwrap();
            trace!("fn_get_state--");
            return obj;
        } else {
            trace!("fn_get_state--");
            return &mut srv_mut.none_object;
        }
    }

    fn fn_set_state(&self, handle: &str, value: Option<Box<(dyn Any + Send)>>) {
        trace!("fn_set_state++");
        let srv_mut = unsafe { G_STATE.server.data_ptr().as_mut().unwrap().get_mut() };

        if srv_mut.opaque_data.contains_key(handle) {
            srv_mut.opaque_data.remove(handle);
        }
        srv_mut.opaque_data.insert(handle.to_string(), value);
        trace!("fn_set_state--");
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
