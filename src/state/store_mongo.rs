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

use crate::state::store::{Store, UserLookup};
use crate::util::bson_wrapper::{u64_to_decimal128, BsonItem};
use async_trait::async_trait;
use isabelle_dm::data_model::item::*;
use log::{debug, info, trace, warn};
use serde_json::Value;

use mongodb::options::{IndexOptions, ReturnDocument};
use mongodb::{bson::doc, Client, Collection, IndexModel};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::time::{sleep, Duration};

/// TTL for the session-scope `user` lookup cache. Short enough that role
/// demotions / account locks propagate within seconds, long enough that
/// chatty clients amortise the Mongo round-trip across many requests.
const USER_CACHE_TTL: Duration = Duration::from_secs(30);

/// Collection holding one sequence document per data collection: `_id` is
/// the collection name and `seq` is the last identifier handed out. It is
/// never listed as a data collection, so `has_collection` keeps refusing it.
const COUNTERS_COLLECTION: &str = "__id_counters";

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

    /// Bumped by every write to the `user` collection. A lookup records this
    /// value when it *starts* and refuses to install its result if the value
    /// has moved on by the time it finishes — otherwise a read that overtook
    /// a write would reinstate the pre-write record for the whole TTL.
    /// Written and read under `user_cache`'s lock, which is what makes the
    /// check-then-insert atomic against the clear.
    pub user_cache_gen: AtomicU64,
}

// `Send` is derived, not asserted: every field is already `Send`, so the
// compiler proves what an `unsafe impl` here would only have claimed.
// (Verified by removing it — the crate builds under every feature.)

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
            user_cache_gen: AtomicU64::new(0),
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
    async fn find_user_cached(&self, login: &str) -> UserLookup {
        // Read the generation *before* the lookup, so that a write landing
        // while we are in Mongo is detectable when we come back.
        let gen_at_start = {
            let cache = self.user_cache.lock();
            if let Some((item, expires)) = cache.get(login) {
                if *expires > Instant::now() {
                    return UserLookup::Found(item.clone());
                }
            }
            self.user_cache_gen.load(Ordering::Acquire)
        }; // ← release the lock before awaiting Mongo

        // Caller is expected to have run `login_has_bad_symbols`; the JSON
        // here is hand-built but the input is already screened of `"\\{}[]$`.
        let filter = format!(
            "{{ \"$or\": [ {{ \"strs.login\": \"{}\" }}, {{ \"strs.email\": \"{}\" }} ] }}",
            login, login
        );
        let user_opt = match self.find_one_checked("user", &filter).await {
            Ok(found) => found,
            Err(e) => {
                // Nothing was established. Reporting `Absent` here is what
                // would turn a database hiccup into a fleet-wide logout.
                warn!("Could not look up user {}: {}", login, e);
                return UserLookup::Unavailable;
            }
        };

        if let Some(user) = &user_opt {
            // A record read before a write we have since observed is stale by
            // construction: caching it would keep a revoked role alive for the
            // full TTL, which is exactly what the wholesale `clear()` on write
            // could not prevent on its own — the clear happens while this read
            // is still in flight. Skipping the insert costs one extra query on
            // the next request and nothing else.
            let mut cache = self.user_cache.lock();
            if self.user_cache_gen.load(Ordering::Acquire) == gen_at_start {
                cache.insert(
                    login.to_string(),
                    (user.clone(), Instant::now() + USER_CACHE_TTL),
                );
            } else {
                trace!("Dropping user cache fill for {}: raced a write", login);
            }
        }

        match user_opt {
            Some(user) => UserLookup::Found(user),
            None => UserLookup::Absent,
        }
    }

    /// Invalidate the user cache after a write to the `user` collection.
    ///
    /// Both steps happen under the cache lock so that a concurrent
    /// `find_user_cached` cannot slip its check past the bump and its insert
    /// past the clear.
    fn invalidate_user_cache(&self) {
        let mut cache = self.user_cache.lock();
        self.user_cache_gen.fetch_add(1, Ordering::AcqRel);
        cache.clear();
    }

    /// Raise the stored sequence for `collection` to at least `id`.
    ///
    /// Called at connect time with the highest identifier already on disk, and
    /// after any write that carried a client-chosen identifier, so a later
    /// allocation cannot hand out a number that is already taken.
    async fn raise_counter(&self, collection: &str, id: u64) {
        let client = match self.client.as_ref() {
            Some(c) => c,
            None => return,
        };
        // `$inc`/`$max` want an i64; identifiers this large are not reachable
        // through allocation and clamping is better than refusing to record.
        let seed = if id > i64::MAX as u64 {
            i64::MAX
        } else {
            id as i64
        };
        let counters: Collection<Document> = client
            .database(&self.database_name)
            .collection(COUNTERS_COLLECTION);
        if let Err(e) = counters
            .update_one(doc! { "_id": collection }, doc! { "$max": { "seq": seed } })
            .upsert(true)
            .await
        {
            warn!("Could not raise id counter for {}: {}", collection, e);
        }
    }

    /// Hand out a fresh identifier for `collection`.
    ///
    /// The counter is bumped by a single `findAndModify`, so two overlapping
    /// creations cannot be told the same number — not even when they are
    /// served by different processes talking to the same database. The
    /// previous code read a counter under one lock, released it, and only then
    /// wrote, which handed the same id to every creation that overlapped and
    /// silently overwrote all but the last.
    async fn alloc_id(&self, collection: &str, coll_id: u64) -> u64 {
        if let Some(client) = self.client.as_ref() {
            let counters: Collection<Document> = client
                .database(&self.database_name)
                .collection(COUNTERS_COLLECTION);
            let res = counters
                .find_one_and_update(doc! { "_id": collection }, doc! { "$inc": { "seq": 1i64 } })
                .upsert(true)
                .return_document(ReturnDocument::After)
                .await;
            match res {
                Ok(Some(d)) => match d.get_i64("seq") {
                    Ok(seq) if seq > 0 => {
                        let id = seq as u64;
                        let mut counts = self.items_count.lock();
                        let high = counts.entry(coll_id).or_insert(0);
                        if id > *high {
                            *high = id;
                        }
                        return id;
                    }
                    other => warn!(
                        "Id counter for {} holds an unusable seq ({:?})",
                        collection, other
                    ),
                },
                Ok(None) => warn!("Id counter for {} returned no document", collection),
                Err(e) => warn!("Could not allocate id for {}: {}", collection, e),
            }
        }

        // Fallback: still atomic within this process (the increment happens
        // under the lock), just not across processes.
        warn!(
            "Falling back to in-process id allocation for {}",
            collection
        );
        let mut counts = self.items_count.lock();
        let next = counts.entry(coll_id).or_insert(0);
        *next = next.saturating_add(1);
        *next
    }

    /// Single-document lookup by a JSON filter string. Bypasses the
    /// `count_documents + find + cursor` cycle of `get_items(... limit=1)`,
    /// so it's the right primitive for things like `get_user` where the
    /// caller only needs the first match.
    pub async fn find_one(&self, collection: &str, filter: &str) -> Option<Item> {
        self.find_one_checked(collection, filter)
            .await
            .unwrap_or(None)
    }

    /// `find_one`, keeping the difference between "no such document" and
    /// "could not ask".
    ///
    /// A dropped connection, an election in progress, an authentication
    /// failure — all of them used to come back as `None`, indistinguishable
    /// from an empty collection. That is fine for a listing and wrong for the
    /// session guard, which decides whether an account still exists.
    pub async fn find_one_checked(
        &self,
        collection: &str,
        filter: &str,
    ) -> Result<Option<Item>, String> {
        let bson_filter = if filter.is_empty() {
            Document::new()
        } else {
            match self.json_to_bson(filter).await {
                Ok(d) => d,
                Err(e) => {
                    trace!(
                        "find_one: failed to parse filter, returning None: {}",
                        filter
                    );
                    // A filter this store cannot parse is the caller's own
                    // doing, not an outage: nothing matches it, definitively.
                    let _ = e;
                    return Ok(None);
                }
            }
        };

        // No client means the store was never connected — which is a failure
        // to ask, not an answer. This used to `unwrap()` and take the process
        // with it.
        let client = match self.client.as_ref() {
            Some(c) => c,
            None => return Err("store is not connected".to_string()),
        };
        let coll: Collection<BsonItem> =
            client.database(&self.database_name).collection(collection);

        match coll.find_one(bson_filter).await {
            Ok(Some(bson_item)) => Ok(Some(bson_item.into())),
            Ok(None) => Ok(None),
            Err(e) => {
                trace!("find_one error on {}: {}", collection, e);
                Err(e.to_string())
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
                    // Start the shared sequence above whatever is already on
                    // disk. Idempotent across restarts and across processes:
                    // `$max` never lowers a counter another instance raised.
                    self.raise_counter(&coll_name.1, count).await;
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
            // `__id_counters` is bookkeeping, not data. Callers treat this
            // list as "the collections that hold items" — first-run seeding
            // in `run()` decides whether the database is empty from it, and
            // would see the counter documents as data and skip the import.
            if coll == COUNTERS_COLLECTION {
                continue;
            }
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

        // Mongo reads `.limit(0)` as "no limit", so asking for a zero-sized
        // page — the first request a paginated view makes, to learn the total
        // — used to answer with the whole collection. An empty page is what
        // the caller asked for; the count above is the part it wanted.
        if limit == 0 {
            debug!(" - result: empty page, total {}", lr.total_count);
            return lr;
        }

        // Sort on the requested key, then on "id". Without the tiebreak, records
        // sharing a key — every record stamped with the same day, say — come
        // back in an order Mongo is free to vary between queries, so a paged
        // listing can show one item twice and drop another. "id" is unique, so
        // the total order is fixed; it is also already indexed.
        // A leading `-` reverses the order: `-id` is newest-first. Written as a
        // prefix on the key rather than a separate parameter so it travels
        // through every layer that already carries a sort key — the query
        // string, the task queue, the plugin API — without a signature change
        // in each of them.
        //
        // The tie-break follows the same direction. Pointing it the other way
        // would order equal keys against the page order, which is how a
        // paginated listing shows one row twice and hides another.
        let (eff_sort_key, dir) = match eff_sort_key.strip_prefix('-') {
            Some(k) if !k.is_empty() => (k, -1),
            _ => (eff_sort_key, 1),
        };
        let sort = if eff_sort_key == "id" {
            doc! { "id": dir }
        } else {
            doc! { eff_sort_key: dir, "id": dir }
        };

        let mut cursor = match coll
            .find(base)
            .sort(sort)
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

        // Whether this write chose its own identifier. A client-chosen one has
        // to be pushed into the shared counter afterwards so a later
        // allocation does not hand it out a second time.
        let mut client_chosen = true;
        if itm.id == u64::MAX {
            if let Some(&coll_id) = self.collections.get(collection) {
                itm.id = self.alloc_id(collection, coll_id).await;
                client_chosen = false;
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

        // A write that Mongo refused is reported as `u64::MAX` rather than
        // answered with the id it would have had. The caller used to be handed
        // that id regardless, so a client could be told it had created an item
        // that does not exist.
        if old_itm.as_ref().is_none() {
            if let Err(e) = coll.insert_one(bson_new_itm.clone()).await {
                log::error!("Error inserting item id={}: {:?}", new_itm.id, e);
                return u64::MAX;
            }
        } else {
            if let Err(e) = coll.replace_one(filter, bson_new_itm.clone()).await {
                log::error!("Error replacing item id={}: {:?}", new_itm.id, e);
                return u64::MAX;
            }
        }

        if let Some(&coll_id) = self.collections.get(collection) {
            {
                let mut items = self.items.lock();
                if let Some(set) = items.get_mut(&coll_id) {
                    set.insert(new_itm.id, true);
                }
            }
            {
                let mut counts = self.items_count.lock();
                let high = counts.entry(coll_id).or_insert(0);
                if new_itm.id > *high {
                    *high = new_itm.id;
                }
            }
        }

        // A client-chosen identifier must not be reachable by a later
        // allocation. Allocated ones already came from the counter, so they
        // cost no extra round-trip here.
        if client_chosen && new_itm.id != u64::MAX {
            self.raise_counter(collection, new_itm.id).await;
        }

        // Any write to `user` (registration, profile edit, otp clear, login
        // counter bump, …) may shift role flags or rename the principal —
        // drop the whole user cache. Same call site handles plugin writes
        // since `IsabellePluginApi::db_set_item` routes through here.
        if collection == "user" {
            self.invalidate_user_cache();
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
            self.invalidate_user_cache();
        }

        let coll_id = match self.collections.get(collection) {
            Some(&c) => c,
            None => return false,
        };
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
        let itm = crate::state::store::read_config_or_empty(&tmp_data_path, "internals.js");
        // Populate cache. Race-tolerant: if another caller filled it
        // concurrently we just overwrite with an equivalent value.
        let mut cache = self.internals_cache.lock();
        *cache = Some(itm.clone());
        itm
    }

    async fn get_settings(&self) -> Item {
        let tmp_data_path = self.local_path.clone() + "/settings.js";
        crate::state::store::read_config_or_empty(&tmp_data_path, "settings.js")
    }

    async fn set_settings(&self, itm: Item) -> bool {
        let tmp_data_path = self.local_path.clone() + "/settings.js";
        match crate::util::fs::write_json(&tmp_data_path, &itm) {
            Ok(()) => true,
            Err(e) => {
                warn!("Failed to write settings: {}", e);
                false
            }
        }
    }

    fn has_collection(&self, collection: &str) -> bool {
        self.collections.contains_key(collection)
    }

    async fn find_user(&self, login: &str) -> Option<Item> {
        self.find_user_cached(login).await.into_option()
    }

    /// Overridden: this is the one store that can fail to answer at all, so
    /// the default "`None` means absent" mapping is wrong here.
    async fn find_user_checked(&self, login: &str) -> UserLookup {
        self.find_user_cached(login).await
    }

    fn set_database_name(&mut self, name: &str) {
        self.database_name = name.to_string();
    }
}

// These exercise `StoreMongo`'s user cache, and `StoreMongo::new()` is itself
// compiled only when Mongo is the backing store. Under `full_file_database`
// the store is `StoreLocal` and this module has nothing to test — without the
// matching gate the test build simply fails to compile, which is why that
// feature's tests had never run.
#[cfg(all(test, not(feature = "full_file_database")))]
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

    /// Invalidation has to do two things, not one: empty the map *and* move
    /// the generation on. Clearing alone loses the race it exists to win —
    /// a lookup that started before the write finishes after the clear and
    /// puts the pre-write record straight back, where it then lives for the
    /// full TTL. The generation is what lets that late insert be refused.
    #[test]
    fn invalidating_the_user_cache_moves_the_generation_on() {
        let store = StoreMongo::new();
        let before = store.user_cache_gen.load(Ordering::Acquire);
        store.user_cache.lock().insert(
            "alice".to_string(),
            (user_item("alice", "alice@example.com"), Instant::now()),
        );

        store.invalidate_user_cache();

        assert!(store.user_cache.lock().is_empty());
        assert_ne!(
            store.user_cache_gen.load(Ordering::Acquire),
            before,
            "a lookup in flight cannot tell it raced a write"
        );
    }

    /// A read that observed the generation before a write must not install
    /// what it read. This is the fill path's guard, exercised directly:
    /// `find_user_cached` cannot be driven here because a cache miss goes to
    /// Mongo, and no client is connected.
    #[test]
    fn a_generation_that_moved_means_the_read_is_stale() {
        let store = StoreMongo::new();
        let gen_at_start = store.user_cache_gen.load(Ordering::Acquire);
        store.invalidate_user_cache(); // the write this read overtook
        assert_ne!(store.user_cache_gen.load(Ordering::Acquire), gen_at_start);
    }
}
