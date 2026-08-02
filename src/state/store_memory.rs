/*
 * Isabelle project
 *
 * Copyright 2026 Maxim Menshikov
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 */
//! In-memory [`Store`] for tests.
//!
//! The HTTP handlers hold the bulk of this crate's access-control logic, and
//! until `Data::rw` became a trait object none of it could be tested: the
//! store was a concrete `StoreMongo`, so reaching a handler meant reaching a
//! database. This backend closes that gap — it keeps items in a map, needs no
//! I/O, and lets a test assert on what a handler actually did to the data.
//!
//! It is a test fixture, not a third production backend: `get_items` ignores
//! the filter string (there is no query engine here), which is fine because
//! the filter is validated and rejected *before* the store is reached.

use crate::state::store::Store;
use async_trait::async_trait;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::list_result::ListResult;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// Cheap to clone: a test hands one clone to `Data` and keeps another to
/// assert on, and both see the same items.
#[derive(Clone)]
pub struct StoreMemory {
    collections: Arc<Mutex<HashMap<String, HashMap<u64, Item>>>>,
    internals: Arc<Mutex<Item>>,
    settings: Arc<Mutex<Item>>,
}

impl Default for StoreMemory {
    fn default() -> Self {
        Self::with_collections(&[])
    }
}

impl StoreMemory {
    /// A store holding the named collections, all empty.
    pub fn with_collections(names: &[&str]) -> Self {
        let mut collections = HashMap::new();
        for name in names {
            collections.insert(name.to_string(), HashMap::new());
        }
        Self {
            collections: Arc::new(Mutex::new(collections)),
            internals: Arc::new(Mutex::new(Item::new())),
            settings: Arc::new(Mutex::new(Item::new())),
        }
    }

    /// Seed an item, bypassing `set_item`, so a test can arrange state
    /// without depending on the write path it may be about to exercise.
    pub fn seed(&self, collection: &str, item: Item) {
        self.collections
            .lock()
            .entry(collection.to_string())
            .or_default()
            .insert(item.id, item);
    }

    /// Read an item back for assertions.
    pub fn peek(&self, collection: &str, id: u64) -> Option<Item> {
        self.collections
            .lock()
            .get(collection)
            .and_then(|c| c.get(&id).cloned())
    }

    pub fn count(&self, collection: &str) -> usize {
        self.collections
            .lock()
            .get(collection)
            .map(|c| c.len())
            .unwrap_or(0)
    }

    pub fn set_internals(&self, item: Item) {
        *self.internals.lock() = item;
    }

    fn next_id(&self, collection: &str) -> u64 {
        self.collections
            .lock()
            .get(collection)
            .and_then(|c| c.keys().filter(|id| **id != u64::MAX).max().copied())
            .unwrap_or(0)
            + 1
    }
}

#[async_trait]
impl Store for StoreMemory {
    async fn connect(&mut self, _addr: &str, _altaddr: &str) {}

    async fn disconnect(&mut self) {}

    async fn get_collections(&self) -> Vec<String> {
        self.collections.lock().keys().cloned().collect()
    }

    async fn get_item_ids(&self, collection: &str) -> HashMap<u64, bool> {
        self.collections
            .lock()
            .get(collection)
            .map(|c| c.keys().map(|id| (*id, true)).collect())
            .unwrap_or_default()
    }

    async fn get_all_items(&self, collection: &str, _sort_key: &str, _filter: &str) -> ListResult {
        let map: HashMap<u64, Item> = self
            .collections
            .lock()
            .get(collection)
            .cloned()
            .unwrap_or_default();
        ListResult {
            total_count: map.len() as u64,
            map,
        }
    }

    async fn get_item(&self, collection: &str, id: u64) -> Option<Item> {
        self.peek(collection, id)
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
        let all = self
            .collections
            .lock()
            .get(collection)
            .cloned()
            .unwrap_or_default();

        let mut ids: Vec<u64> = all
            .keys()
            .copied()
            .filter(|id| id_min == u64::MAX || *id >= id_min)
            .filter(|id| id_max == u64::MAX || *id <= id_max)
            .collect();
        ids.sort_unstable();
        let total_count = ids.len() as u64;

        let skip = if skip == u64::MAX { 0 } else { skip } as usize;
        let limit = if limit == u64::MAX {
            usize::MAX
        } else {
            limit as usize
        };

        let map = ids
            .into_iter()
            .skip(skip)
            .take(limit)
            .map(|id| (id, all[&id].clone()))
            .collect();

        ListResult { map, total_count }
    }

    async fn set_item(&self, collection: &str, itm: &Item, merge: bool) -> u64 {
        let id = if itm.id == u64::MAX {
            self.next_id(collection)
        } else {
            itm.id
        };

        let mut collections = self.collections.lock();
        let coll = collections.entry(collection.to_string()).or_default();

        let stored = match (merge, coll.get(&id)) {
            (true, Some(old)) => {
                let mut merged = old.clone();
                merged.merge(itm);
                merged
            }
            _ => itm.clone(),
        };
        let mut stored = stored;
        stored.id = id;
        coll.insert(id, stored);
        id
    }

    async fn del_item(&self, collection: &str, id: u64) -> bool {
        self.collections
            .lock()
            .get_mut(collection)
            .map(|c| c.remove(&id).is_some())
            .unwrap_or(false)
    }

    async fn get_credentials(&self) -> String {
        String::new()
    }

    async fn get_pickle(&self) -> String {
        String::new()
    }

    async fn get_internals(&self) -> Item {
        self.internals.lock().clone()
    }

    async fn get_settings(&self) -> Item {
        self.settings.lock().clone()
    }

    async fn set_settings(&self, itm: Item) -> bool {
        *self.settings.lock() = itm;
        true
    }

    fn has_collection(&self, collection: &str) -> bool {
        self.collections.lock().contains_key(collection)
    }

    async fn find_user(&self, login: &str) -> Option<Item> {
        let wanted = login.to_lowercase();
        let collections = self.collections.lock();
        let users = collections.get("user")?;
        users
            .values()
            .find(|item| {
                ["login", "email"].iter().any(|field| {
                    item.strs
                        .get(*field)
                        .map(|v| v.to_lowercase() == wanted)
                        .unwrap_or(false)
                })
            })
            .cloned()
    }
}
