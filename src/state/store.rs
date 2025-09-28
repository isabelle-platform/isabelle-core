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

/// Store implementation
#[async_trait]
pub trait Store {
    /// Connect the store to database
    async fn connect(&mut self, addr: &str, altaddr: &str);

    /// Disconnect the store
    #[allow(dead_code)]
    async fn disconnect(&mut self);

    /// Get all collections
    async fn get_collections(&mut self) -> Vec<String>;

    /// Get all item IDs (can be exhausting)
    async fn get_item_ids(&mut self, collection: &str) -> HashMap<u64, bool>;

    /// Get all items (can be exhausting unless you provide filter)
    async fn get_all_items(&mut self, collection: &str, sort_key: &str, filter: &str)
        -> ListResult;

    /// Get item by specific ID
    async fn get_item(&mut self, collection: &str, id: u64) -> Option<Item>;

    /// Get items by given parameters. Use u64::MAX for IDs you don't know.
    async fn get_items(
        &mut self,
        collection: &str,
        id_min: u64,
        id_max: u64,
        sort_key: &str,
        filter: &str,
        skip: u64,
        limit: u64,
    ) -> ListResult;

    /// Write the item to the database
    async fn set_item(&mut self, collection: &str, itm: &Item, merge: bool) -> u64;

    /// Read the item from the database
    async fn del_item(&mut self, collection: &str, id: u64) -> bool;

    /// Get credentials
    async fn get_credentials(&mut self) -> String;

    /// Get Google Authentication pickle
    async fn get_pickle(&mut self) -> String;

    /// Read internal data (like internal settings not exposed to user)
    async fn get_internals(&mut self) -> Item;

    /// Read settings item
    async fn get_settings(&mut self) -> Item;

    /// Write settings item
    async fn set_settings(&mut self, itm: Item);
}
