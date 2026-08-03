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
use async_trait::async_trait;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::list_result::ListResult;
use std::collections::HashMap;

/// Read a configuration Item (`settings.js`, `internals.js`) from disk,
/// falling back to an empty one.
///
/// Shared by both stores, and the reason it exists is the failure mode it
/// removes. These files were parsed with `serde_json::from_str(..).unwrap()`,
/// and `/is_logged_in` — an unauthenticated endpoint — reads settings on every
/// call. Since the files were also written non-atomically, a single
/// interrupted write left a truncated `settings.js` that made every such
/// request panic, permanently, with no restart clearing it.
///
/// An empty Item is the right fallback for both: it is already what a missing
/// file yields, and every reader goes through `safe_*` accessors with
/// defaults. The loud log line is what tells an operator to go and look.
pub fn read_config_or_empty(path: &str, what: &str) -> Item {
    match crate::util::fs::read_json::<Item>(path) {
        Ok(itm) => itm,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Item::new(),
        Err(e) => {
            log::error!(
                "Unreadable {} at {} ({}); continuing with defaults",
                what,
                path,
                e
            );
            Item::new()
        }
    }
}

/// Store implementation.
///
/// All runtime operations take `&self` so the store can be shared across
/// concurrent request handlers without an outer lock. Implementations use
/// interior mutability (typically `parking_lot::Mutex`) for caches that
/// need to be updated at runtime.
///
/// `connect`/`disconnect` are the exceptions — they take `&mut self`
/// because they (re)build all internal state and are only called from
/// startup/shutdown paths where exclusive access is naturally available.
#[async_trait]
pub trait Store {
    /// Connect the store to database
    async fn connect(&mut self, addr: &str, altaddr: &str);

    /// Disconnect the store
    #[allow(dead_code)]
    async fn disconnect(&mut self);

    /// Get all collections
    async fn get_collections(&self) -> Vec<String>;

    /// Get all item IDs (can be exhausting)
    async fn get_item_ids(&self, collection: &str) -> HashMap<u64, bool>;

    /// Get all items (can be exhausting unless you provide filter)
    async fn get_all_items(&self, collection: &str, sort_key: &str, filter: &str) -> ListResult;

    /// Get item by specific ID
    async fn get_item(&self, collection: &str, id: u64) -> Option<Item>;

    /// Get items by given parameters. Use u64::MAX for IDs you don't know.
    async fn get_items(
        &self,
        collection: &str,
        id_min: u64,
        id_max: u64,
        sort_key: &str,
        filter: &str,
        skip: u64,
        limit: u64,
    ) -> ListResult;

    /// Write the item to the database
    async fn set_item(&self, collection: &str, itm: &Item, merge: bool) -> u64;

    /// Read the item from the database
    async fn del_item(&self, collection: &str, id: u64) -> bool;

    /// Get credentials
    async fn get_credentials(&self) -> String;

    /// Get Google Authentication pickle
    async fn get_pickle(&self) -> String;

    /// Read internal data (like internal settings not exposed to user)
    async fn get_internals(&self) -> Item;

    /// Read settings item
    async fn get_settings(&self) -> Item;

    /// Write the settings item. Returns whether it reached durable storage.
    ///
    /// The result is not decorative: this used to be `expect("Couldn't write
    /// item")`, so a full or read-only disk killed the handler outright, and
    /// before that the caller reported "Settings edited" regardless. A write
    /// that did not happen has to be something the caller can tell a client
    /// about.
    async fn set_settings(&self, itm: Item) -> bool;

    /// Whether the store knows this collection.
    ///
    /// Collections are declared in `internals.js` and registered at connect
    /// time; anything else must be refused rather than created on demand.
    fn has_collection(&self, collection: &str) -> bool;

    /// Look a user up by login *or* email.
    ///
    /// On the trait rather than on the concrete store because it is the one
    /// lookup on the authenticated request path — every handler resolves the
    /// session principal through it — and backends can serve it far better
    /// than a generic filtered listing (the Mongo store answers from an
    /// indexed `find_one` behind a short-lived cache).
    async fn find_user(&self, login: &str) -> Option<Item>;

    /// `find_user`, but able to say that it could not ask.
    ///
    /// `Option` flattens "there is no such account" and "the database did not
    /// answer" into one `None`, and the session guard has to tell those apart:
    /// treating an unreachable store as proof that an account is gone revokes
    /// every live session in the deployment the moment the database blinks,
    /// and since the sessions live in cookies, revoking one rewrites the
    /// client's cookie — so the outage does not end when the database comes
    /// back. Everyone has to log in again.
    ///
    /// The default is for stores that cannot be unreachable: a store held in
    /// this process either has the record or does not.
    async fn find_user_checked(&self, login: &str) -> UserLookup {
        match self.find_user(login).await {
            Some(itm) => UserLookup::Found(itm),
            None => UserLookup::Absent,
        }
    }

    /// Name the database to connect to. Meaningful only for backends that
    /// have one; the file-backed store ignores it.
    fn set_database_name(&mut self, _name: &str) {}
}

/// What a `user` lookup could establish.
#[derive(Debug, Clone, PartialEq)]
pub enum UserLookup {
    /// The store answered, and this is the record.
    Found(Item),
    /// The store answered, and there is no such account.
    Absent,
    /// The store could not be asked, so nothing was established either way.
    /// Callers must not read this as `Absent`.
    Unavailable,
}

impl UserLookup {
    /// The record, if there is one. For callers that genuinely cannot act on
    /// the distinction and would have had an `Option` anyway.
    pub fn into_option(self) -> Option<Item> {
        match self {
            UserLookup::Found(itm) => Some(itm),
            _ => None,
        }
    }
}
