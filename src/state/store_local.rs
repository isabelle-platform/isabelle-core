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
use isabelle_dm::data_model::list_result::ListResult;
use std::path::Path;

use crate::state::store::{read_config_or_empty, Store};
use async_trait::async_trait;
use isabelle_dm::data_model::item::*;
use log::{debug, error, trace};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;

/// Local storage implementation. See StoreMongo's docstring for the
/// `&self` + interior-mutability pattern; same reasoning applies here.
pub struct StoreLocal {
    /// Path to folder (set at connect)
    pub path: String,

    /// Collection name → coll_id (set at connect)
    pub collections: HashMap<String, u64>,

    /// Per-collection set of known item IDs.
    pub items: Mutex<HashMap<u64, HashMap<u64, bool>>>,

    /// Per-collection running max-id counter.
    pub items_count: Mutex<HashMap<u64, u64>>,

    /// Cached `internals.js` (loaded lazily on first access, never invalidated:
    /// the file is treated as immutable runtime configuration).
    pub internals_cache: Mutex<Option<Item>>,
}

// `Send` is derived, not asserted: every field is already `Send`, so the
// compiler proves what an `unsafe impl` here would only have claimed.
// (Verified by removing it — the crate builds under every feature.)

impl std::fmt::Debug for StoreLocal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreLocal")
            .field("path", &self.path)
            .field("collections_len", &self.collections.len())
            .finish_non_exhaustive()
    }
}

impl StoreLocal {
    pub fn new() -> Self {
        Self {
            path: "".to_string(),
            collections: HashMap::new(),
            items: Mutex::new(HashMap::new()),
            items_count: Mutex::new(HashMap::new()),
            internals_cache: Mutex::new(None),
        }
    }
}

#[async_trait]
impl Store for StoreLocal {
    async fn connect(&mut self, url: &str, _alturl: &str) {
        self.path = url.to_string();
        let collections = fs::read_dir(self.path.to_string() + "/collection").unwrap();
        for coll in collections {
            let idx = coll.as_ref().unwrap().file_name().into_string().unwrap();
            let coll_index: u64 = self.items.lock().len().try_into().unwrap();
            self.items.lock().insert(coll_index, HashMap::new());
            self.collections.insert(idx.clone(), coll_index);
            trace!("New collection {}", idx.clone());

            let cnt_str =
                std::fs::read_to_string(self.path.clone() + "/collection/" + &idx + "/cnt");
            if let Err(_e) = cnt_str {
                error!("Failed to read counter");
                continue;
            }

            let parsed = cnt_str.as_ref().unwrap().trim().parse::<u64>();
            if let Err(_e) = parsed {
                error!("Failed to parse counter {}", cnt_str.as_ref().unwrap());
                continue;
            }

            self.items_count
                .lock()
                .insert(self.collections[&idx], *parsed.as_ref().unwrap());
            trace!(" - index: {}", self.collections[&idx]);
            trace!(" - counter: {}", parsed.as_ref().unwrap());

            let data_files = fs::read_dir(self.path.to_string() + "/collection/" + &idx).unwrap();
            for data_file in data_files {
                let data_file_idx = data_file
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .into_string()
                    .unwrap();
                let tmp_path = self.path.to_string() + "/collection/" + &idx + "/" + &data_file_idx;
                if Path::new(&tmp_path).is_dir() {
                    let mut items = self.items.lock();
                    let m = items.get_mut(&coll_index).unwrap();
                    m.insert(data_file_idx.parse::<u64>().unwrap(), true);
                    trace!("{}: idx {}", &idx, &data_file_idx);
                }
            }
        }
    }

    async fn disconnect(&mut self) {}

    async fn get_collections(&self) -> Vec<String> {
        self.collections.keys().cloned().collect()
    }

    async fn get_item_ids(&self, collection: &str) -> HashMap<u64, bool> {
        if !self.collections.contains_key(collection) {
            return HashMap::new();
        }
        let coll_id = self.collections[collection];
        self.items.lock().get(&coll_id).cloned().unwrap_or_default()
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
        let tmp_path = self.path.to_string()
            + "/collection/"
            + collection
            + "/"
            + &id.to_string()
            + "/data.js";
        if Path::new(&tmp_path).is_file() {
            // A file that exists but does not parse is a torn write, not a
            // reason to kill the request: unwrapping here meant one bad
            // `data.js` panicked every read of that item, for good.
            match crate::util::fs::read_json::<Item>(&tmp_path) {
                Ok(itm) => return Some(itm),
                Err(e) => {
                    error!("Unreadable item {} of {}: {}", id, collection, e);
                    return None;
                }
            }
        }
        return None;
    }

    async fn get_items(
        &self,
        collection: &str,
        id_min: u64,
        id_max: u64,
        _sort_key: &str,
        _filter: &str,
        skip: u64,
        limit: u64,
    ) -> ListResult {
        let mut lr = ListResult {
            map: HashMap::new(),
            total_count: 0,
        };
        let itms = self
            .items
            .lock()
            .get(&self.collections[collection])
            .cloned()
            .unwrap_or_default();

        let eff_skip = if skip == u64::MAX { 0 } else { skip };
        let eff_id_min = if id_min == u64::MAX { 0 } else { id_min };
        let eff_id_max = if id_max == u64::MAX { u64::MAX } else { id_max };
        // u64::MAX → effectively unbounded
        let eff_limit = limit;

        // Deterministic order: sort ids ascending before applying skip/limit.
        // sort_key / filter are not supported by the file store; ignored.
        let mut ids: Vec<u64> = itms
            .keys()
            .copied()
            .filter(|id| *id >= eff_id_min && *id <= eff_id_max)
            .collect();
        ids.sort_unstable();
        lr.total_count = ids.len() as u64;

        debug!(
            "Getting {} in range {} - {} skip {} limit {} total {}",
            &collection, eff_id_min, eff_id_max, eff_skip, eff_limit, lr.total_count
        );

        let mut count: u64 = 0;
        for id in ids {
            if count >= eff_skip {
                if (count - eff_skip) >= eff_limit {
                    break;
                }
                if let Some(item) = self.get_item(collection, id).await {
                    lr.map.insert(id, item);
                }
            }
            count += 1;
        }

        debug!(" - result: {} items", lr.map.len());
        return lr;
    }

    async fn set_item(&self, collection: &str, exp_itm: &Item, merge: bool) -> u64 {
        let mut itm = exp_itm.clone();

        if itm.bools.contains_key("__security_preserve") {
            itm.bools.remove("__security_preserve");
        }

        // The identifier is allocated with the counter lock held across the
        // read and the increment. It used to read under one lock, release it,
        // and write afterwards, so two creations that overlapped were told the
        // same number and one file quietly overwrote the other. There is only
        // ever one process behind this store, but there are many request
        // threads, which is enough for the race.
        if itm.id == u64::MAX {
            if let Some(&coll_id) = self.collections.get(collection) {
                let mut counts = self.items_count.lock();
                let next = counts.entry(coll_id).or_insert(0);
                *next = next.saturating_add(1);
                itm.id = *next;
            }
        }

        let old_itm = self.get_item(collection, itm.id).await;
        let mut new_itm = itm.clone();
        if !old_itm.is_none() && merge {
            new_itm = old_itm.unwrap().clone();
            new_itm.merge(&itm);
        }
        let tmp_path =
            self.path.to_string() + "/collection/" + collection + "/" + &new_itm.id.to_string();

        let _dir_create_err = std::fs::create_dir(&tmp_path);

        // Written atomically, and a failure is reported rather than fatal.
        // `expect()` here dropped the client's connection with no status on a
        // full or read-only disk, and the plain write left a truncated
        // `data.js` behind that every later read then failed to parse.
        let tmp_data_path = tmp_path.clone() + "/data.js";
        if let Err(e) = crate::util::fs::write_json(&tmp_data_path, &new_itm) {
            error!(
                "Failed to write item {} of {}: {}",
                new_itm.id, collection, e
            );
            return u64::MAX;
        }

        if let Some(&coll_id) = self.collections.get(collection) {
            {
                let mut items = self.items.lock();
                if let Some(coll) = items.get_mut(&coll_id) {
                    coll.insert(new_itm.id, true);
                }
            }
            let mut counts = self.items_count.lock();
            let high = counts.entry(coll_id).or_insert(0);
            if new_itm.id >= *high {
                *high = new_itm.id;
                let cnt_path = self.path.to_string() + "/collection/" + collection + "/cnt";
                if let Err(e) = crate::util::fs::atomic_write(
                    std::path::Path::new(&cnt_path),
                    new_itm.id.to_string().as_bytes(),
                    crate::util::fs::DEFAULT_MODE,
                ) {
                    error!("Failed to persist the counter of {}: {}", collection, e);
                }
            }
        }

        return new_itm.id;
    }

    async fn del_item(&self, collection: &str, id: u64) -> bool {
        let tmp_path = self.path.to_string() + "/" + collection + "/" + &id.to_string();
        let path = Path::new(&tmp_path);
        if path.exists() {
            let _res = std::fs::remove_dir_all(tmp_path);
        }
        let coll_id = self.collections[collection];
        let mut items = self.items.lock();
        if let Some(coll) = items.get_mut(&coll_id) {
            if coll.contains_key(&id) {
                coll.remove(&id);
                return true;
            }
        }
        return false;
    }

    async fn get_credentials(&self) -> String {
        return self.path.clone() + "/credentials.json";
    }

    async fn get_pickle(&self) -> String {
        return self.path.clone() + "/token.pickle";
    }

    async fn get_internals(&self) -> Item {
        {
            let cache = self.internals_cache.lock();
            if let Some(item) = cache.as_ref() {
                return item.clone();
            }
        }
        let tmp_data_path = self.path.clone() + "/internals.js";
        let itm = read_config_or_empty(&tmp_data_path, "internals.js");
        let mut cache = self.internals_cache.lock();
        *cache = Some(itm.clone());
        itm
    }

    async fn get_settings(&self) -> Item {
        read_config_or_empty(&(self.path.clone() + "/settings.js"), "settings.js")
    }

    async fn set_settings(&self, itm: Item) -> bool {
        let tmp_data_path = self.path.clone() + "/settings.js";
        match crate::util::fs::write_json(&tmp_data_path, &itm) {
            Ok(()) => true,
            Err(e) => {
                error!("Failed to write settings: {}", e);
                false
            }
        }
    }

    fn has_collection(&self, collection: &str) -> bool {
        self.collections.contains_key(collection)
    }

    /// No index and no query language here, so this is a scan: read the
    /// collection and match in Rust. That is the same cost the caller used to
    /// pay inline, and the reason this backend is documented as sample/test
    /// only — `StoreMongo` answers the same question from an index.
    ///
    /// Matching is case-insensitive on both `login` and `email`, which is how
    /// people actually type their own address.
    async fn find_user(&self, login: &str) -> Option<Item> {
        let wanted = login.to_lowercase();
        let users = self.get_all_items("user", "", "").await;
        for item in users.map.values() {
            let matches = |field: &str| {
                item.strs
                    .get(field)
                    .map(|v| v.to_lowercase() == wanted)
                    .unwrap_or(false)
            };
            if matches("login") || matches("email") {
                return Some(item.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a StoreLocal with a fixture collection on disk. The store is
    /// initialised manually (not via `connect`) so tests are independent of
    /// `connect()`'s own behaviour. We hand-write each item's `data.js` so
    /// `get_item` (which reads it back) sees the same data we asserted.
    fn make_store_with_items(ids: &[u64]) -> (TempDir, StoreLocal) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_string_lossy().to_string();

        let coll_dir = dir.path().join("collection").join("test");
        std::fs::create_dir_all(&coll_dir).unwrap();
        // `cnt` is used by connect(); harmless extra here.
        std::fs::write(
            coll_dir.join("cnt"),
            ids.iter().max().unwrap_or(&0).to_string(),
        )
        .unwrap();

        let mut item_map: HashMap<u64, bool> = HashMap::new();
        for &id in ids {
            let item_dir = coll_dir.join(id.to_string());
            std::fs::create_dir_all(&item_dir).unwrap();
            let mut it = Item::new();
            it.id = id;
            it.strs.insert("name".into(), format!("item{}", id));
            std::fs::write(
                item_dir.join("data.js"),
                serde_json::to_string(&it).unwrap(),
            )
            .unwrap();
            item_map.insert(id, true);
        }

        let store = StoreLocal {
            path,
            collections: HashMap::from([("test".to_string(), 0u64)]),
            items: Mutex::new(HashMap::from([(0u64, item_map)])),
            items_count: Mutex::new(HashMap::from([(0u64, *ids.iter().max().unwrap_or(&0))])),
            internals_cache: Mutex::new(None),
        };
        (dir, store)
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn sorted_ids(lr: &ListResult) -> Vec<u64> {
        let mut v: Vec<u64> = lr.map.keys().copied().collect();
        v.sort_unstable();
        v
    }

    // ---- identifier allocation ----

    /// Every creation must get its own identifier. The old code read the
    /// counter under one lock, released it, and wrote afterwards, so two
    /// creations that overlapped were told the same number and one item's
    /// file was silently overwritten by the other's.
    ///
    /// A unit test cannot interleave the two halves of that window, so what
    /// it pins is the invariant the fix establishes: allocation is a single
    /// increment, ids never repeat, and they continue above what is already
    /// on disk.
    #[test]
    fn consecutive_creations_get_distinct_ids() {
        let (_dir, store) = make_store_with_items(&[1, 2, 3]);
        let rt = rt();

        let mut ids = Vec::new();
        for _ in 0..5 {
            let mut itm = Item::new();
            itm.strs.insert("name".into(), "new".into());
            ids.push(rt.block_on(store.set_item("test", &itm, false)));
        }

        assert_eq!(ids, vec![4, 5, 6, 7, 8], "ids repeated or skipped");
        let unique: std::collections::HashSet<u64> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len(), "an id was handed out twice");
        // And nothing was written over: three seeded plus five created.
        assert_eq!(store.items.lock()[&0].len(), 8);
    }

    /// A creation must not land on an identifier that already exists, which
    /// is what "read the counter, then write" produced whenever the counter
    /// lagged the data.
    #[test]
    fn a_new_id_never_lands_on_an_existing_item() {
        let (_dir, store) = make_store_with_items(&[1, 2, 3]);
        let rt = rt();
        let mut itm = Item::new();
        itm.strs.insert("name".into(), "new".into());
        let id = rt.block_on(store.set_item("test", &itm, false));
        assert!(id > 3, "new id {} collides with a seeded item", id);
        assert_eq!(
            rt.block_on(store.get_item("test", 1))
                .unwrap()
                .safe_str("name", ""),
            "item1",
            "the creation overwrote an existing item"
        );
    }

    /// An item file that exists but does not parse — a write torn by a crash
    /// or a full disk — must be reported as absent, not panic every read of
    /// that item from then on.
    #[test]
    fn a_torn_item_file_reads_as_absent() {
        let (dir, store) = make_store_with_items(&[1]);
        std::fs::write(
            dir.path().join("collection/test/1/data.js"),
            "{\"strs\":{\"name\"",
        )
        .unwrap();
        assert!(rt().block_on(store.get_item("test", 1)).is_none());
    }

    // ---- get_items pagination ----

    #[test]
    fn get_items_returns_all_when_no_paging() {
        let (_dir, mut store) = make_store_with_items(&[3, 1, 2, 5, 4]);
        let rt = rt();
        let lr =
            rt.block_on(store.get_items("test", u64::MAX, u64::MAX, "", "", u64::MAX, u64::MAX));
        assert_eq!(sorted_ids(&lr), vec![1, 2, 3, 4, 5]);
        assert_eq!(lr.total_count, 5);
    }

    #[test]
    fn get_items_paginates_in_id_ascending_order() {
        // Items inserted out-of-order; with skip=2 limit=2 we must get the
        // 3rd and 4th by sorted id (3, 4), not arbitrary HashMap order.
        let (_dir, mut store) = make_store_with_items(&[5, 1, 4, 2, 3]);
        let rt = rt();
        let lr = rt.block_on(store.get_items("test", u64::MAX, u64::MAX, "", "", 2, 2));
        assert_eq!(sorted_ids(&lr), vec![3, 4]);
        // total_count reflects how many matched the range (all 5), not page size.
        assert_eq!(lr.total_count, 5);
    }

    #[test]
    fn get_items_limit_zero_returns_empty_page_but_full_total() {
        let (_dir, mut store) = make_store_with_items(&[1, 2, 3]);
        let rt = rt();
        let lr = rt.block_on(store.get_items("test", u64::MAX, u64::MAX, "", "", 0, 0));
        assert!(lr.map.is_empty());
        assert_eq!(lr.total_count, 3);
    }

    #[test]
    fn get_items_id_range_filters_total_count_too() {
        let (_dir, mut store) = make_store_with_items(&[1, 2, 3, 4, 5, 6, 7]);
        let rt = rt();
        let lr = rt.block_on(store.get_items("test", 3, 5, "", "", 0, u64::MAX));
        assert_eq!(sorted_ids(&lr), vec![3, 4, 5]);
        // Critical: total_count is the size of the filtered range, NOT the
        // whole collection. This was the bug we fixed.
        assert_eq!(lr.total_count, 3);
    }

    #[test]
    fn get_items_skip_past_end_yields_empty() {
        let (_dir, mut store) = make_store_with_items(&[1, 2, 3]);
        let rt = rt();
        let lr = rt.block_on(store.get_items("test", u64::MAX, u64::MAX, "", "", 10, u64::MAX));
        assert!(lr.map.is_empty());
        assert_eq!(lr.total_count, 3);
    }

    #[test]
    fn get_items_skip_max_is_treated_as_zero() {
        // skip = u64::MAX is the unset sentinel; must behave as 0.
        let (_dir, mut store) = make_store_with_items(&[1, 2, 3]);
        let rt = rt();
        let lr = rt.block_on(store.get_items("test", u64::MAX, u64::MAX, "", "", u64::MAX, 2));
        assert_eq!(sorted_ids(&lr), vec![1, 2]);
    }

    // ---- internals_cache ----

    #[test]
    fn get_internals_loads_from_disk_first_time() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_string_lossy().to_string();

        let mut it = Item::new();
        it.strs.insert("default_site_name".into(), "Test".into());
        std::fs::write(
            dir.path().join("internals.js"),
            serde_json::to_string(&it).unwrap(),
        )
        .unwrap();

        let mut store = StoreLocal::new();
        store.path = path;
        assert!(store.internals_cache.lock().is_none());

        let result = rt().block_on(store.get_internals());
        assert_eq!(
            result.strs.get("default_site_name").map(String::as_str),
            Some("Test")
        );
        assert!(store.internals_cache.lock().is_some());
    }

    #[test]
    fn get_internals_is_cached_across_calls() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_string_lossy().to_string();

        let mut it = Item::new();
        it.strs
            .insert("default_site_name".into(), "Original".into());
        std::fs::write(
            dir.path().join("internals.js"),
            serde_json::to_string(&it).unwrap(),
        )
        .unwrap();

        let mut store = StoreLocal::new();
        store.path = path.clone();

        let rt = rt();
        let first = rt.block_on(store.get_internals());
        assert_eq!(
            first.strs.get("default_site_name").map(String::as_str),
            Some("Original")
        );

        // Mutate the file on disk. Cache should ignore this — internals.js is
        // treated as immutable runtime config.
        let mut mutated = Item::new();
        mutated
            .strs
            .insert("default_site_name".into(), "Changed".into());
        std::fs::write(
            dir.path().join("internals.js"),
            serde_json::to_string(&mutated).unwrap(),
        )
        .unwrap();

        let second = rt.block_on(store.get_internals());
        assert_eq!(
            second.strs.get("default_site_name").map(String::as_str),
            Some("Original")
        );
    }

    #[test]
    fn get_internals_missing_file_caches_empty() {
        let dir = TempDir::new().unwrap();
        let mut store = StoreLocal::new();
        store.path = dir.path().to_string_lossy().to_string();

        let rt = rt();
        let result = rt.block_on(store.get_internals());
        assert!(result.strs.is_empty());
        assert!(result.strstrs.is_empty());

        // Second call still returns empty without retrying disk read.
        let second = rt.block_on(store.get_internals());
        assert!(second.strs.is_empty());
        assert!(store.internals_cache.lock().is_some());
    }
}
