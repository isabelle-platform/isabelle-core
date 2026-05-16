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

//! Pre-parsed routing tables derived from `internals.js`.
//!
//! `internals.js` stores route and hook specs as colon-separated strings
//! (e.g. `"path:method:handler"`, `"collection:handler"`). The original
//! dispatch code re-parsed these on every request: iterate the route map,
//! `String::split(':').collect::<Vec<_>>()`, compare. That's a `Vec<&str>`
//! allocation per route per request plus O(M) scan.
//!
//! Since `internals.js` is treated as immutable runtime configuration, we
//! parse once at startup and hand out an `Arc<RouteCache>` to handlers.
//! Lookups become O(1) hash hits with zero allocation per request.

use isabelle_dm::data_model::item::Item;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct RouteCache {
    /// Authenticated custom routes: `req.path()` → handler name.
    /// Source: `internals.strstrs["extra_route"]` (`"path:method:handler"`).
    pub url_routes: HashMap<String, String>,

    /// Public custom routes: same shape as `url_routes`.
    /// Source: `internals.strstrs["extra_unprotected_route"]`.
    pub unprotected_url_routes: HashMap<String, String>,

    /// REST custom routes.
    /// Source: `internals.strstrs["extra_rest_route"]`.
    pub rest_routes: HashMap<String, String>,

    /// Pre-edit hooks bound to a specific collection: collection → handlers.
    /// Source: `internals.strstrs["item_pre_edit_hook"]` (`"collection:handler"`).
    pub item_pre_edit: HashMap<String, Vec<String>>,

    /// Pre-edit hooks bound to all collections (`"*:handler"`).
    pub item_pre_edit_wildcard: Vec<String>,

    /// Post-edit hooks bound to a specific collection.
    pub item_post_edit: HashMap<String, Vec<String>>,

    /// Post-edit hooks bound to all collections.
    pub item_post_edit_wildcard: Vec<String>,
}

impl RouteCache {
    pub fn from_internals(internals: &Item) -> Self {
        let mut c = Self::default();
        let empty = HashMap::new();

        let parse_path_route = |spec: &str, into: &mut HashMap<String, String>| {
            let parts: Vec<&str> = spec.split(':').collect();
            // Format: "path:method:handler" — accept >=3 segments; ignore method
            // (actix already routes by verb), record path→handler.
            if parts.len() >= 3 && !parts[0].is_empty() && !parts[2].is_empty() {
                into.insert(parts[0].to_string(), parts[2].to_string());
            }
        };

        for spec in internals
            .strstrs
            .get("extra_route")
            .unwrap_or(&empty)
            .values()
        {
            parse_path_route(spec, &mut c.url_routes);
        }
        for spec in internals
            .strstrs
            .get("extra_unprotected_route")
            .unwrap_or(&empty)
            .values()
        {
            parse_path_route(spec, &mut c.unprotected_url_routes);
        }
        for spec in internals
            .strstrs
            .get("extra_rest_route")
            .unwrap_or(&empty)
            .values()
        {
            parse_path_route(spec, &mut c.rest_routes);
        }

        let parse_collection_hook = |spec: &str,
                                     by_coll: &mut HashMap<String, Vec<String>>,
                                     wildcard: &mut Vec<String>| {
            let parts: Vec<&str> = spec.split(':').collect();
            // Format: "collection:handler" or "*:handler"
            if parts.len() >= 2 && !parts[1].is_empty() {
                if parts[0] == "*" {
                    wildcard.push(parts[1].to_string());
                } else if !parts[0].is_empty() {
                    by_coll
                        .entry(parts[0].to_string())
                        .or_default()
                        .push(parts[1].to_string());
                }
            }
        };

        for spec in internals
            .strstrs
            .get("item_pre_edit_hook")
            .unwrap_or(&empty)
            .values()
        {
            parse_collection_hook(spec, &mut c.item_pre_edit, &mut c.item_pre_edit_wildcard);
        }
        for spec in internals
            .strstrs
            .get("item_post_edit_hook")
            .unwrap_or(&empty)
            .values()
        {
            parse_collection_hook(spec, &mut c.item_post_edit, &mut c.item_post_edit_wildcard);
        }

        c
    }
}
