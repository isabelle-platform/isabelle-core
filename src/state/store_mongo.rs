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
use bson::Document;
use futures_util::TryStreamExt;
use isabelle_dm::data_model::list_result::ListResult;
extern crate serde_json;

use crate::state::store::Store;
use async_trait::async_trait;
use isabelle_dm::data_model::item::*;
use log::{debug, info, trace};
use serde_json::Value;

use mongodb::{bson::doc, Client, Collection, IndexModel};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

/// Mongo storage implementation
#[derive(Debug, Clone)]
pub struct StoreMongo {
    /// URL to Mongo database
    pub path: String,

    /// Local settings path (like for Local storage)
    pub local_path: String,

    /// Collection hash map
    pub collections: HashMap<String, u64>,

    /// Items map
    pub items: HashMap<u64, HashMap<u64, bool>>,

    /// Item counters
    pub items_count: HashMap<u64, u64>,

    /// Actual Mongo client
    pub client: Option<mongodb::Client>,

    /// Database name
    pub database_name: String,
}

unsafe impl Send for StoreMongo {}

impl StoreMongo {
    #[cfg(not(feature = "full_file_database"))]
    pub fn new() -> Self {
        Self {
            path: "".to_string(),
            local_path: "".to_string(),
            collections: HashMap::new(),
            items: HashMap::new(),
            items_count: HashMap::new(),
            client: None,
            database_name: "isabelle".to_string(),
        }
    }

    pub async fn do_conn(&mut self) -> bool {
        if self.client.is_none() {
            loop {
                let client = Client::with_uri_str(&self.path).await;
                match client {
                    Ok(cl) => {
                        self.client = Some(cl);
                        return true;
                    }
                    Err(_err) => {
                        self.client = None;
                        info!(
                            "MongoDB connection failed ({} / {}), retrying in 30 seconds",
                            self.path, self.database_name
                        );
                        sleep(Duration::from_secs(30)).await;
                    }
                };
            }
        }

        return true;
    }

    pub async fn json_to_bson(&mut self, json_string: &str) -> Result<Document, bool> {
        // Parse JSON string into serde_json::Value
        let js_res = serde_json::from_str(json_string);
        let js: Value;
        match js_res {
            Ok(tmp) => {
                js = tmp;
            }
            Err(_error) => {
                return Err(false);
            }
        }

        // Convert serde_json::Value into BSON Document
        let bs_res = bson::ser::to_document(&js);

        match bs_res {
            Ok(tmp) => {
                return Ok(tmp);
            }
            Err(_error) => {
                return Err(false);
            }
        }
    }
}

#[async_trait]
impl Store for StoreMongo {
    async fn connect(&mut self, url: &str, alturl: &str) {
        // Preserve parameters
        self.path = url.to_string();
        self.local_path = alturl.to_string();

        // Connect
        let res = self.do_conn().await;
        if res {
            // If successful, create all collections
            info!("Connected {} / {}!", url, self.database_name);
            let internals = self.get_internals().await;
            let collections = internals.safe_strstr("collections", &HashMap::new());
            debug!("Collections: {}", collections.len());
            let db = self.client.as_ref().unwrap().database(&self.database_name);
            for coll_name in collections {
                debug!("Create collection {}", &coll_name.1);

                // Mongo can report successful URI parsing / client creation, but still fail
                // actual operations until server selection succeeds. During initial startup
                // we want to retry these transient errors instead of panicking.
                loop {
                    let create_res = db.create_collection(&coll_name.1).await;
                    if create_res.is_err() {
                        info!(
                            "MongoDB operation failed during initial connect (create_collection: {}), retrying in 30 seconds",
                            &coll_name.1
                        );
                        sleep(Duration::from_secs(30)).await;
                        // Drop client and reconnect to force fresh server selection
                        self.client = None;
                        self.do_conn().await;
                        continue;
                    }

                    let coll: Collection<Item> = db.collection(&coll_name.1);
                    let index: IndexModel = IndexModel::builder().keys(doc! { "id": 1 }).build();
                    let _result = coll.create_index(index).await;

                    let coll_idx = self.collections.len().try_into().unwrap();
                    self.collections.insert(coll_name.1.to_string(), coll_idx);

                    let mut map: HashMap<u64, bool> = HashMap::new();
                    let filter = doc! {}; // An empty filter matches all documents

                    // Find documents in the collection and fill hash map/counter
                    let cursor_res = coll.find(filter).await;
                    if cursor_res.is_err() {
                        info!(
                            "MongoDB operation failed during initial connect (find: {}), retrying in 30 seconds",
                            &coll_name.1
                        );
                        sleep(Duration::from_secs(30)).await;
                        self.client = None;
                        self.do_conn().await;
                        continue;
                    }

                    let mut cursor = cursor_res.unwrap();
                    let mut count = 0;
                    loop {
                        let next_res = cursor.try_next().await;
                        match next_res {
                            Ok(opt) => {
                                if let Some(doc) = opt {
                                    map.insert(doc.id, true);
                                    count = std::cmp::max(count, doc.id);
                                } else {
                                    break;
                                }
                            }
                            Err(_e) => {
                                info!(
                                    "MongoDB operation failed during initial connect (cursor: {}), retrying in 30 seconds",
                                    &coll_name.1
                                );
                                sleep(Duration::from_secs(30)).await;
                                self.client = None;
                                self.do_conn().await;
                                continue;
                            }
                        }
                    }

                    self.items.insert(coll_idx, map);
                    self.items_count.insert(coll_idx, count);
                    break;
                }
            }
        } else {
            info!("Not connected");
        }
    }

    async fn disconnect(&mut self) {}

    async fn get_collections(&mut self) -> Vec<String> {
        let colls = self
            .client
            .as_ref()
            .unwrap()
            .database(&self.database_name)
            .list_collection_names()
            .await
            .unwrap();
        let mut lst: Vec<String> = Vec::new();

        for coll in &colls {
            lst.push(coll.clone());
        }

        return lst;
    }

    async fn get_item_ids(&mut self, collection: &str) -> HashMap<u64, bool> {
        if !self.collections.contains_key(collection) {
            return HashMap::new();
        }

        let coll_id = self.collections[collection];
        return self.items[&coll_id].clone();
    }

    async fn get_all_items(
        &mut self,
        collection: &str,
        sort_key: &str,
        filter: &str,
    ) -> ListResult {
        return self
            .get_items(
                collection,
                u64::MAX,
                u64::MAX,
                sort_key,
                filter,
                u64::MAX,
                u64::MAX,
            )
            .await;
    }

    async fn get_item(&mut self, collection: &str, id: u64) -> Option<Item> {
        let coll = self
            .client
            .as_ref()
            .unwrap()
            .database(&self.database_name)
            .collection(collection);
        let filter = doc! {
            "id": id as i64,
        };

        let result = coll.find_one(filter).await;

        match result {
            Ok(r) => {
                if r.is_none() {
                    return None;
                }
                return Some(r.unwrap());
            }
            Err(_e) => {}
        };
        return None;
    }

    async fn get_items(
        &mut self,
        collection: &str,
        id_min: u64,
        id_max: u64,
        sort_key: &str,
        filter: &str,
        skip: u64,
        limit: u64,
    ) -> ListResult {
        let mut lr = ListResult {
            map: HashMap::new(),
            total_count: 0,
        };
        let itms = self
            .items
            .get_mut(&self.collections[collection])
            .unwrap()
            .clone();
        let mut eff_id_min = id_min;
        let eff_id_max = id_max;
        let mut count = 0;
        let mut eff_skip = skip;
        let mut care_about_sort = false;
        let eff_limit: i64;

        if eff_skip == u64::MAX {
            eff_skip = 0;
        }

        if eff_id_min == u64::MAX {
            eff_id_min = 0;
            if sort_key != "" {
                care_about_sort = true;
            }
        }

        if limit > (i64::MAX as u64) {
            eff_limit = i64::MAX;
        } else {
            eff_limit = limit as i64;
        }

        debug!(
            "Getting {} in range {} - {} ({}-{}) skip {} limit {} sort key {} (care {}) filter {}",
            &collection,
            eff_id_min,
            eff_id_max,
            id_min,
            id_max,
            eff_skip,
            eff_limit,
            sort_key,
            care_about_sort,
            filter
        );
        if care_about_sort {
            let coll: Collection<Item> = self
                .client
                .as_ref()
                .unwrap()
                .database(&self.database_name)
                .collection(collection);

            let json_bson: Document = if filter != "" {
                debug!("Using real filter: {}", filter);
                let bson_document = self.json_to_bson(filter).await;
                match bson_document {
                    Ok(d) => d,
                    Err(_err) => {
                        trace!("Using empty filter due to error");
                        Document::new()
                    }
                }
            } else {
                trace!("Using empty filter");
                Document::new()
            };

            let count = coll.count_documents(json_bson.clone()).await;
            lr.total_count = count.unwrap_or(0);

            let mut cursor = coll
                .find(json_bson)
                .sort(doc! { sort_key: 1 })
                .skip(eff_skip)
                .limit(eff_limit)
                .await;
            loop {
                let result = cursor.as_mut().unwrap().try_next().await;
                match result {
                    Ok(r) => {
                        let c = r.clone();
                        if c.is_none() {
                            break;
                        }

                        lr.map
                            .insert(c.as_ref().unwrap().id, c.as_ref().unwrap().clone());
                    }
                    Err(_e) => {
                        debug!("Error: {}", _e);
                        break;
                    }
                };
            }
        } else {
            for itm in &itms {
                if itm.0 >= &eff_id_min && itm.0 <= &eff_id_max {
                    let new_item = self.get_item(collection, *itm.0).await;
                    if !new_item.is_none() {
                        if count >= eff_skip {
                            lr.map.insert(*itm.0, new_item.unwrap());
                        }
                        count = count + 1;
                        if count >= eff_skip && (count - eff_skip) >= eff_limit as u64 {
                            break;
                        }
                    }
                }
            }

            lr.total_count = itms.len() as u64;
        }

        debug!(
            " - result: {} items, total {}",
            lr.map.len(),
            lr.total_count
        );
        return lr;
    }

    async fn set_item(&mut self, collection: &str, exp_itm: &Item, merge: bool) -> u64 {
        let mut itm = exp_itm.clone();
        if itm.bools.contains_key("__security_preserve") {
            itm.bools.remove("__security_preserve");
        }

        if itm.id == u64::MAX {
            let coll_id = self.collections[collection];
            if self.items.contains_key(&coll_id) {
                itm.id = self.items_count[&coll_id] + 1;
            }
        }

        let old_itm = if itm.id != u64::MAX {
            self.get_item(collection, itm.id).await
        } else {
            None
        };
        let mut new_itm = itm.clone();
        if !old_itm.as_ref().is_none() && merge {
            new_itm = old_itm.as_ref().unwrap().clone();
            new_itm.merge(&itm);
        }

        let coll: Collection<Item> = self
            .client
            .as_ref()
            .unwrap()
            .database(&self.database_name)
            .collection(collection);
        let filter = doc! {
            "id": itm.id as i64,
        };

        if old_itm.as_ref().is_none() {
            let _res = coll.insert_one(new_itm.clone()).await;
        } else {
            let _res = coll.replace_one(filter, new_itm.clone()).await;
        }

        let coll_id = self.collections[collection];
        if self.items.contains_key(&coll_id) {
            let coll = self.items.get_mut(&coll_id).unwrap();
            if coll.contains_key(&new_itm.id) {
                *(coll.get_mut(&new_itm.id).unwrap()) = true;
            } else {
                coll.insert(new_itm.id, true);
            }
            if self.items_count.contains_key(&coll_id) {
                let cnt = self.items_count.get_mut(&coll_id).unwrap();
                if new_itm.id > *cnt {
                    *cnt = new_itm.id;
                }
            } else {
                self.items_count.insert(coll_id, new_itm.id + 1);
            }
        }

        return new_itm.id;
    }

    async fn del_item(&mut self, collection: &str, id: u64) -> bool {
        let coll: Collection<Item> = self
            .client
            .as_ref()
            .unwrap()
            .database(&self.database_name)
            .collection(collection);
        let filter = doc! {
            "id": id as i64,
        };

        let _res = coll.delete_one(filter).await;

        let coll_id = self.collections[collection];
        if self.items.contains_key(&coll_id) {
            let coll = self.items.get_mut(&coll_id).unwrap();
            if coll.contains_key(&id) {
                coll.remove(&id);
                return true;
            }
        }
        return false;
    }

    async fn get_credentials(&mut self) -> String {
        return self.local_path.clone() + "/credentials.json";
    }

    async fn get_pickle(&mut self) -> String {
        return self.local_path.clone() + "/token.pickle";
    }

    async fn get_internals(&mut self) -> Item {
        let tmp_data_path = self.local_path.clone() + "/internals.js";

        let read_data = std::fs::read_to_string(tmp_data_path);
        if let Err(_e) = read_data {
            return Item::new();
        }
        let text = read_data.unwrap();
        let itm: Item = serde_json::from_str(&text).unwrap();
        return itm;
    }

    async fn get_settings(&mut self) -> Item {
        let tmp_data_path = self.local_path.clone() + "/settings.js";

        let read_data = std::fs::read_to_string(tmp_data_path);
        if let Err(_e) = read_data {
            return Item::new();
        }
        let text = read_data.unwrap();
        let itm: Item = serde_json::from_str(&text).unwrap();
        return itm;
    }

    async fn set_settings(&mut self, itm: Item) {
        let tmp_data_path = self.local_path.clone() + "/settings.js";
        let s = serde_json::to_string(&itm);
        std::fs::write(tmp_data_path, s.unwrap()).expect("Couldn't write item");
    }
}
