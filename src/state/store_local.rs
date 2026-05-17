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

use crate::state::store::Store;
use async_trait::async_trait;
use isabelle_dm::data_model::item::*;
use log::{debug, error, trace};
use std::collections::HashMap;
use std::fs;

/// Local storage implementation
#[derive(Debug, Clone)]
pub struct StoreLocal {
    /// Path to folder
    pub path: String,

    /// Collection hash map
    pub collections: HashMap<String, u64>,

    /// All items
    pub items: HashMap<u64, HashMap<u64, bool>>,

    /// Item counters
    pub items_count: HashMap<u64, u64>,

    /// Cached `internals.js` (loaded lazily on first access, never invalidated:
    /// the file is treated as immutable runtime configuration).
    pub internals_cache: Option<Item>,
}

unsafe impl Send for StoreLocal {}

impl StoreLocal {
    pub fn new() -> Self {
        Self {
            path: "".to_string(),
            collections: HashMap::new(),
            items: HashMap::new(),
            items_count: HashMap::new(),
            internals_cache: None,
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
            let new_col: HashMap<u64, bool> = HashMap::new();
            let coll_index = self.items.len().try_into().unwrap();
            self.items.insert(coll_index, new_col);
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
                    let m = self.items.get_mut(&coll_index).unwrap();
                    (*m).insert(data_file_idx.parse::<u64>().unwrap(), true);
                    trace!("{}: idx {}", &idx, &data_file_idx);
                }
            }
        }
    }

    async fn disconnect(&mut self) {}

    async fn get_collections(&mut self) -> Vec<String> {
        let mut lst: Vec<String> = Vec::new();

        for coll in &self.collections {
            lst.push(coll.0.clone());
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
        let tmp_path = self.path.to_string()
            + "/collection/"
            + collection
            + "/"
            + &id.to_string()
            + "/data.js";
        if Path::new(&tmp_path).is_file() {
            let text = std::fs::read_to_string(tmp_path).unwrap();
            let itm: Item = serde_json::from_str(&text).unwrap();
            return Some(itm);
        }
        return None;
    }

    async fn get_items(
        &mut self,
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
            .get_mut(&self.collections[collection])
            .unwrap()
            .clone();

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

        let old_itm = self.get_item(collection, itm.id).await;
        let mut new_itm = itm.clone();
        if !old_itm.is_none() && merge {
            new_itm = old_itm.unwrap().clone();
            new_itm.merge(&itm);
        }
        let tmp_path =
            self.path.to_string() + "/collection/" + collection + "/" + &new_itm.id.to_string();

        let _dir_create_err = std::fs::create_dir(&tmp_path);

        let tmp_data_path = tmp_path.clone() + "/data.js";
        let s = serde_json::to_string(&new_itm);
        std::fs::write(tmp_data_path, s.unwrap()).expect("Couldn't write item");

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
                    let _res = std::fs::write(
                        self.path.to_string() + "/collection/" + collection + "/cnt",
                        (new_itm.id + 1).to_string(),
                    );
                }
            } else {
                self.items_count.insert(coll_id, new_itm.id + 1);
                let _res = std::fs::write(
                    self.path.to_string() + "/collection/" + collection + "/cnt",
                    (new_itm.id + 1).to_string(),
                );
            }
        }

        return new_itm.id;
    }

    async fn del_item(&mut self, collection: &str, id: u64) -> bool {
        let tmp_path = self.path.to_string() + "/" + collection + "/" + &id.to_string();
        let path = Path::new(&tmp_path);
        if path.exists() {
            let _res = std::fs::remove_dir_all(tmp_path);
        }
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
        return self.path.clone() + "/credentials.json";
    }

    async fn get_pickle(&mut self) -> String {
        return self.path.clone() + "/token.pickle";
    }

    async fn get_internals(&mut self) -> Item {
        if self.internals_cache.is_none() {
            let tmp_data_path = self.path.clone() + "/internals.js";
            let itm = match std::fs::read_to_string(&tmp_data_path) {
                Ok(text) => serde_json::from_str(&text).unwrap(),
                Err(_) => Item::new(),
            };
            self.internals_cache = Some(itm);
        }
        self.internals_cache.as_ref().unwrap().clone()
    }

    async fn get_settings(&mut self) -> Item {
        let tmp_data_path = self.path.clone() + "/settings.js";

        let read_data = std::fs::read_to_string(tmp_data_path);
        if let Err(_e) = read_data {
            return Item::new();
        }
        let text = read_data.unwrap();
        let itm: Item = serde_json::from_str(&text).unwrap();
        return itm;
    }

    async fn set_settings(&mut self, itm: Item) {
        let tmp_data_path = self.path.clone() + "/settings.js";
        let s = serde_json::to_string(&itm);
        std::fs::write(tmp_data_path, s.unwrap()).expect("Couldn't write item");
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
            items: HashMap::from([(0u64, item_map)]),
            items_count: HashMap::from([(0u64, *ids.iter().max().unwrap_or(&0))]),
            internals_cache: None,
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
        assert!(store.internals_cache.is_none());

        let result = rt().block_on(store.get_internals());
        assert_eq!(
            result.strs.get("default_site_name").map(String::as_str),
            Some("Test")
        );
        assert!(store.internals_cache.is_some());
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
        assert!(store.internals_cache.is_some());
    }
}
