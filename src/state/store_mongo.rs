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
use crate::util::bson_wrapper::{u64_to_decimal128, BsonItem};
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

    /// Cached `internals.js` (loaded lazily on first access, never invalidated:
    /// the file is treated as immutable runtime configuration).
    pub internals_cache: Option<Item>,
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
            internals_cache: None,
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

                    let coll: Collection<BsonItem> = db.collection(&coll_name.1);
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
                                if let Some(bson_doc) = opt {
                                    let item: Item = bson_doc.into();
                                    map.insert(item.id, true);
                                    count = std::cmp::max(count, item.id);
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
        let coll: Collection<BsonItem> = self
            .client
            .as_ref()
            .unwrap()
            .database(&self.database_name)
            .collection(collection);
        let filter = doc! {
            "id": u64_to_decimal128(id),
        };

        let result = coll.find_one(filter).await;

        match result {
            Ok(r) => {
                if r.is_none() {
                    return None;
                }
                let bson_item = r.unwrap();
                let item: Item = bson_item.into();
                return Some(item);
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

        let eff_skip = if skip == u64::MAX { 0 } else { skip };
        let eff_limit: i64 = if limit == u64::MAX || limit > i64::MAX as u64 {
            i64::MAX
        } else {
            limit as i64
        };
        // Default sort_key to "id" so pagination is deterministic. There is a
        // Mongo index on "id" set up in connect(), so this is cheap.
        let eff_sort_key = if sort_key.is_empty() { "id" } else { sort_key };

        let mut base: Document = if !filter.is_empty() {
            match self.json_to_bson(filter).await {
                Ok(d) => d,
                Err(_) => {
                    trace!("get_items: failed to parse filter, using empty: {}", filter);
                    Document::new()
                }
            }
        } else {
            Document::new()
        };

        if id_min != u64::MAX || id_max != u64::MAX {
            let mut id_constraint = Document::new();
            if id_min != u64::MAX {
                id_constraint.insert("$gte", u64_to_decimal128(id_min));
            }
            if id_max != u64::MAX {
                id_constraint.insert("$lte", u64_to_decimal128(id_max));
            }
            let id_doc = doc! { "id": id_constraint };
            if base.is_empty() {
                base = id_doc;
            } else {
                let prev = std::mem::take(&mut base);
                base.insert("$and", vec![prev, id_doc]);
            }
        }

        debug!(
            "Getting {} id range {} - {} sort {} skip {} limit {} filter {:?}",
            collection, id_min, id_max, eff_sort_key, eff_skip, eff_limit, base
        );

        let coll: Collection<BsonItem> = self
            .client
            .as_ref()
            .unwrap()
            .database(&self.database_name)
            .collection(collection);

        lr.total_count = coll.count_documents(base.clone()).await.unwrap_or(0);

        let mut cursor = match coll
            .find(base)
            .sort(doc! { eff_sort_key: 1 })
            .skip(eff_skip)
            .limit(eff_limit)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                debug!("get_items cursor error: {}", e);
                return lr;
            }
        };

        loop {
            match cursor.try_next().await {
                Ok(Some(bson_item)) => {
                    let item: Item = bson_item.into();
                    lr.map.insert(item.id, item);
                }
                Ok(None) => break,
                Err(e) => {
                    debug!("get_items iteration error: {}", e);
                    break;
                }
            }
        }

        debug!(
            " - result: {} items, total {}",
            lr.map.len(),
            lr.total_count
        );
        lr
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

        let coll: Collection<BsonItem> = self
            .client
            .as_ref()
            .unwrap()
            .database(&self.database_name)
            .collection(collection);
        let filter = doc! {
            "id": u64_to_decimal128(itm.id),
        };

        let bson_new_itm = BsonItem::from_item(&new_itm);

        if old_itm.as_ref().is_none() {
            let res = coll.insert_one(bson_new_itm.clone()).await;
            if let Err(e) = res {
                log::error!("Error inserting item id={}: {:?}", new_itm.id, e);
            }
        } else {
            let res = coll.replace_one(filter, bson_new_itm.clone()).await;
            if let Err(e) = res {
                log::error!("Error replacing item id={}: {:?}", new_itm.id, e);
            }
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
        let coll: Collection<BsonItem> = self
            .client
            .as_ref()
            .unwrap()
            .database(&self.database_name)
            .collection(collection);
        let filter = doc! {
            "id": u64_to_decimal128(id),
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
        if self.internals_cache.is_none() {
            let tmp_data_path = self.local_path.clone() + "/internals.js";
            let itm = match std::fs::read_to_string(&tmp_data_path) {
                Ok(text) => serde_json::from_str(&text).unwrap(),
                Err(_) => Item::new(),
            };
            self.internals_cache = Some(itm);
        }
        self.internals_cache.as_ref().unwrap().clone()
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
