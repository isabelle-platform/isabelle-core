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
use log::{debug, info, trace, warn};
use serde_json::Value;

use mongodb::options::IndexOptions;
use mongodb::{bson::doc, Client, Collection, IndexModel};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::Instant;
use tokio::time::{sleep, Duration};

/// TTL for the session-scope `user` lookup cache. Short enough that role
/// demotions / account locks propagate within seconds, long enough that
/// chatty clients amortise the Mongo round-trip across many requests.
const USER_CACHE_TTL: Duration = Duration::from_secs(30);

/// Mongo storage implementation.
///
/// Phase 4 lock decomposition: runtime-mutated fields are wrapped in
/// `parking_lot::Mutex` so all trait methods can take `&self`. The store is
/// then shareable across concurrent request handlers without an outer lock.
/// Connect-time-only state (`path`, `local_path`, `collections`, `client`,
/// `database_name`) stays plain since `connect` is `&mut self` and not
/// called concurrently.
pub struct StoreMongo {
    /// URL to Mongo database (set at connect, then read-only)
    pub path: String,

    /// Local settings path (like for Local storage; set at connect)
    pub local_path: String,

    /// Collection name → internal coll_id (populated in `connect`, read-only after)
    pub collections: HashMap<String, u64>,

    /// Per-collection set of known item IDs. Mutated by `set_item` / `del_item`.
    pub items: Mutex<HashMap<u64, HashMap<u64, bool>>>,

    /// Per-collection running max-id counter (used for new-id generation).
    pub items_count: Mutex<HashMap<u64, u64>>,

    /// Actual Mongo client. Set in `connect`; the `Client` itself is
    /// internally `Arc<...>` so it's safely shareable for `&self` reads.
    pub client: Option<mongodb::Client>,

    /// Database name (set at construction)
    pub database_name: String,

    /// Cached `internals.js` (loaded lazily on first access, never invalidated:
    /// the file is treated as immutable runtime configuration).
    pub internals_cache: Mutex<Option<Item>>,

    /// Session-scope cache for `find_user(login)` results. Key is whatever
    /// the session cookie holds (login or email — same key the caller
    /// passes). TTL is `USER_CACHE_TTL`. Invalidated wholesale on any write
    /// to the `user` collection.
    pub user_cache: Mutex<HashMap<String, (Item, Instant)>>,
}

unsafe impl Send for StoreMongo {}

impl std::fmt::Debug for StoreMongo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreMongo")
            .field("path", &self.path)
            .field("local_path", &self.local_path)
            .field("database_name", &self.database_name)
            .field("collections_len", &self.collections.len())
            .finish_non_exhaustive()
    }
}

impl StoreMongo {
    #[cfg(not(feature = "full_file_database"))]
    pub fn new() -> Self {
        Self {
            path: "".to_string(),
            local_path: "".to_string(),
            collections: HashMap::new(),
            items: Mutex::new(HashMap::new()),
            items_count: Mutex::new(HashMap::new()),
            client: None,
            database_name: "isabelle".to_string(),
            internals_cache: Mutex::new(None),
            user_cache: Mutex::new(HashMap::new()),
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

    /// Resolve a session principal (login or email) to its `user` Item,
    /// using a short-TTL in-memory cache. Cache invalidation is handled
    /// in `set_item`/`del_item` for the `user` collection, including
    /// writes that come through the plugin API (which also funnel through
    /// these methods).
    pub async fn find_user(&self, login: &str) -> Option<Item> {
        {
            let cache = self.user_cache.lock();
            if let Some((item, expires)) = cache.get(login) {
                if *expires > Instant::now() {
                    return Some(item.clone());
                }
            }
        } // ← release the lock before awaiting Mongo

        // Caller is expected to have run `login_has_bad_symbols`; the JSON
        // here is hand-built but the input is already screened of `"\\{}[]$`.
        let filter = format!(
            "{{ \"$or\": [ {{ \"strs.login\": \"{}\" }}, {{ \"strs.email\": \"{}\" }} ] }}",
            login, login
        );
        let user_opt = self.find_one("user", &filter).await;

        if let Some(user) = &user_opt {
            self.user_cache.lock().insert(
                login.to_string(),
                (user.clone(), Instant::now() + USER_CACHE_TTL),
            );
        }

        user_opt
    }

    /// Single-document lookup by a JSON filter string. Bypasses the
    /// `count_documents + find + cursor` cycle of `get_items(... limit=1)`,
    /// so it's the right primitive for things like `get_user` where the
    /// caller only needs the first match.
    pub async fn find_one(&self, collection: &str, filter: &str) -> Option<Item> {
        let bson_filter = if filter.is_empty() {
            Document::new()
        } else {
            match self.json_to_bson(filter).await {
                Ok(d) => d,
                Err(_) => {
                    trace!(
                        "find_one: failed to parse filter, returning None: {}",
                        filter
                    );
                    return None;
                }
            }
        };

        let coll: Collection<BsonItem> = self
            .client
            .as_ref()
            .unwrap()
            .database(&self.database_name)
            .collection(collection);

        match coll.find_one(bson_filter).await {
            Ok(Some(bson_item)) => Some(bson_item.into()),
            Ok(None) => None,
            Err(e) => {
                trace!("find_one error on {}: {}", collection, e);
                None
            }
        }
    }

    pub async fn json_to_bson(&self, json_string: &str) -> Result<Document, bool> {
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
            // Extra indexes declared in internals.js as a `strstrs` category
            // "indexes". Each value is "collection:field[:unique]"; fields are
            // indexed ascending (covers descending sort too for single-field).
            let extra_indexes = internals.safe_strstr("indexes", &HashMap::new());
            debug!(
                "Collections: {}, declared indexes: {}",
                collections.len(),
                extra_indexes.len()
            );
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

                    // Ensure declared extra indexes for this collection.
                    for (_, spec) in &extra_indexes {
                        let parts: Vec<&str> = spec.split(':').collect();
                        if parts.len() < 2 || parts[0] != coll_name.1.as_str() {
                            continue;
                        }
                        let field = parts[1];
                        if field.is_empty() {
                            warn!("Skipping malformed index spec: {}", spec);
                            continue;
                        }
                        let unique = parts.get(2).copied() == Some("unique");
                        let model = if unique {
                            IndexModel::builder()
                                .keys(doc! { field: 1 })
                                .options(IndexOptions::builder().unique(true).build())
                                .build()
                        } else {
                            IndexModel::builder().keys(doc! { field: 1 }).build()
                        };
                        match coll.create_index(model).await {
                            Ok(r) => debug!(
                                "Index ensured: {}.{} (unique={}) → {}",
                                coll_name.1, field, unique, r.index_name
                            ),
                            Err(e) => {
                                warn!("Failed to ensure index {}.{}: {}", coll_name.1, field, e)
                            }
                        }
                    }

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

                    self.items.lock().insert(coll_idx, map);
                    self.items_count.lock().insert(coll_idx, count);
                    break;
                }
            }
        } else {
            info!("Not connected");
        }
    }

    async fn disconnect(&mut self) {}

    async fn get_collections(&self) -> Vec<String> {
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

    async fn get_item_ids(&self, collection: &str) -> HashMap<u64, bool> {
        if !self.collections.contains_key(collection) {
            return HashMap::new();
        }
        let coll_id = self.collections[collection];
        let items = self.items.lock();
        items.get(&coll_id).cloned().unwrap_or_default()
    }

    async fn get_all_items(&self, collection: &str, sort_key: &str, filter: &str) -> ListResult {
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

    async fn get_item(&self, collection: &str, id: u64) -> Option<Item> {
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
        &self,
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

    async fn set_item(&self, collection: &str, exp_itm: &Item, merge: bool) -> u64 {
        let mut itm = exp_itm.clone();
        if itm.bools.contains_key("__security_preserve") {
            itm.bools.remove("__security_preserve");
        }

        if itm.id == u64::MAX {
            let coll_id = self.collections[collection];
            let items = self.items.lock();
            if items.contains_key(&coll_id) {
                drop(items);
                let counts = self.items_count.lock();
                itm.id = counts[&coll_id] + 1;
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
        {
            let mut items = self.items.lock();
            if let Some(set) = items.get_mut(&coll_id) {
                set.insert(new_itm.id, true);
            }
        }
        {
            let mut counts = self.items_count.lock();
            match counts.get_mut(&coll_id) {
                Some(cnt) => {
                    if new_itm.id > *cnt {
                        *cnt = new_itm.id;
                    }
                }
                None => {
                    counts.insert(coll_id, new_itm.id + 1);
                }
            }
        }

        // Any write to `user` (registration, profile edit, otp clear, login
        // counter bump, …) may shift role flags or rename the principal —
        // drop the whole user cache. Same call site handles plugin writes
        // since `IsabellePluginApi::db_set_item` routes through here.
        if collection == "user" {
            self.user_cache.lock().clear();
        }

        return new_itm.id;
    }

    async fn del_item(&self, collection: &str, id: u64) -> bool {
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

        if collection == "user" {
            self.user_cache.lock().clear();
        }

        let coll_id = self.collections[collection];
        let mut items = self.items.lock();
        if let Some(set) = items.get_mut(&coll_id) {
            if set.contains_key(&id) {
                set.remove(&id);
                return true;
            }
        }
        return false;
    }

    async fn get_credentials(&self) -> String {
        return self.local_path.clone() + "/credentials.json";
    }

    async fn get_pickle(&self) -> String {
        return self.local_path.clone() + "/token.pickle";
    }

    async fn get_internals(&self) -> Item {
        {
            let cache = self.internals_cache.lock();
            if let Some(item) = cache.as_ref() {
                return item.clone();
            }
        }
        // Cache miss: read+parse outside the lock (sync I/O, no await).
        let tmp_data_path = self.local_path.clone() + "/internals.js";
        let itm = match std::fs::read_to_string(&tmp_data_path) {
            Ok(text) => serde_json::from_str(&text).unwrap(),
            Err(_) => Item::new(),
        };
        // Populate cache. Race-tolerant: if another caller filled it
        // concurrently we just overwrite with an equivalent value.
        let mut cache = self.internals_cache.lock();
        *cache = Some(itm.clone());
        itm
    }

    async fn get_settings(&self) -> Item {
        let tmp_data_path = self.local_path.clone() + "/settings.js";
        let read_data = std::fs::read_to_string(tmp_data_path);
        if let Err(_e) = read_data {
            return Item::new();
        }
        let text = read_data.unwrap();
        let itm: Item = serde_json::from_str(&text).unwrap();
        return itm;
    }

    async fn set_settings(&self, itm: Item) {
        let tmp_data_path = self.local_path.clone() + "/settings.js";
        let s = serde_json::to_string(&itm);
        std::fs::write(tmp_data_path, s.unwrap()).expect("Couldn't write item");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn user_item(login: &str, email: &str) -> Item {
        let mut it = Item::new();
        it.id = 1;
        it.strs.insert("login".into(), login.into());
        it.strs.insert("email".into(), email.into());
        it
    }

    /// Cache hit must not touch the Mongo client — otherwise `find_user`
    /// would panic on `self.client.as_ref().unwrap()` because no connection
    /// is set up in this test. The fact that the call returns successfully
    /// is itself the assertion that the fast path bypassed Mongo.
    #[test]
    fn find_user_returns_fresh_cache_entry_without_touching_mongo() {
        let store = StoreMongo::new();
        // No client connected — any Mongo call would panic.
        assert!(store.client.is_none());

        let cached = user_item("alice", "alice@example.com");
        let expires = Instant::now() + USER_CACHE_TTL;
        store
            .user_cache
            .lock()
            .insert("alice".to_string(), (cached.clone(), expires));

        let got = rt().block_on(store.find_user("alice"));
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.strs.get("login").map(String::as_str), Some("alice"));
        assert_eq!(
            got.strs.get("email").map(String::as_str),
            Some("alice@example.com")
        );
    }

    /// find_user returns a clone, not a reference — mutating the returned
    /// Item must not affect the cached copy. Documents the design intent
    /// since the function signature returns Option<Item> by value.
    #[test]
    fn find_user_returns_clone_independent_of_cache() {
        let store = StoreMongo::new();
        let expires = Instant::now() + USER_CACHE_TTL;
        store.user_cache.lock().insert(
            "alice".to_string(),
            (user_item("alice", "alice@example.com"), expires),
        );

        let rt = rt();
        let mut first = rt.block_on(store.find_user("alice")).unwrap();
        first.strs.insert("login".into(), "tampered".into());

        let second = rt.block_on(store.find_user("alice")).unwrap();
        assert_eq!(second.strs.get("login").map(String::as_str), Some("alice"));
    }

    /// Cache key is the session principal (whatever the caller passes).
    /// A user that logged in via email gets a separate cache entry from
    /// the same user logged in via login. That's accepted overhead — the
    /// alternative (canonical-key resolution) would require an extra
    /// Mongo round-trip on every cache hit.
    #[test]
    fn user_cache_keyed_by_session_principal_not_canonical_login() {
        let store = StoreMongo::new();
        let expires = Instant::now() + USER_CACHE_TTL;
        store.user_cache.lock().insert(
            "alice@example.com".to_string(),
            (user_item("alice", "alice@example.com"), expires),
        );

        let rt = rt();
        // Looking up by email hits the cache.
        assert!(rt.block_on(store.find_user("alice@example.com")).is_some());
        // Looking up the same user by login MISSES — would fall through to
        // Mongo (which would panic here). We assert by checking the cache
        // map directly that no "alice" entry was inserted as a side effect.
        assert!(!store.user_cache.lock().contains_key("alice"));
    }
}
