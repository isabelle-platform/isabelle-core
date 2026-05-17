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

#[cfg(test)]
mod tests {
    use super::*;

    fn item_with(category: &str, entries: &[(&str, &str)]) -> Item {
        let mut it = Item::new();
        let inner: HashMap<String, String> = entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        it.strstrs.insert(category.to_string(), inner);
        it
    }

    fn item_multi(categories: &[(&str, &[(&str, &str)])]) -> Item {
        let mut it = Item::new();
        for (cat, entries) in categories {
            let inner: HashMap<String, String> = entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            it.strstrs.insert(cat.to_string(), inner);
        }
        it
    }

    #[test]
    fn empty_internals_yields_empty_cache() {
        let cache = RouteCache::from_internals(&Item::new());
        assert!(cache.url_routes.is_empty());
        assert!(cache.unprotected_url_routes.is_empty());
        assert!(cache.rest_routes.is_empty());
        assert!(cache.item_pre_edit.is_empty());
        assert!(cache.item_pre_edit_wildcard.is_empty());
        assert!(cache.item_post_edit.is_empty());
        assert!(cache.item_post_edit_wildcard.is_empty());
    }

    #[test]
    fn extra_route_parses_path_to_handler_ignoring_method() {
        let it = item_with(
            "extra_route",
            &[
                ("1", "/system/stat:get:plugin_stat"),
                ("2", "/system/log:post:plugin_log"),
            ],
        );
        let c = RouteCache::from_internals(&it);
        assert_eq!(c.url_routes.get("/system/stat").map(String::as_str), Some("plugin_stat"));
        assert_eq!(c.url_routes.get("/system/log").map(String::as_str), Some("plugin_log"));
        assert!(c.unprotected_url_routes.is_empty());
        assert!(c.rest_routes.is_empty());
    }

    #[test]
    fn extra_unprotected_route_and_rest_route_use_separate_maps() {
        let it = item_multi(&[
            ("extra_unprotected_route", &[("1", "/public/x:get:pub_x")]),
            ("extra_rest_route", &[("1", "/api/y:post:rest_y")]),
        ]);
        let c = RouteCache::from_internals(&it);
        assert!(c.url_routes.is_empty());
        assert_eq!(c.unprotected_url_routes.get("/public/x").map(String::as_str), Some("pub_x"));
        assert_eq!(c.rest_routes.get("/api/y").map(String::as_str), Some("rest_y"));
    }

    #[test]
    fn item_pre_edit_hook_splits_collection_specific_and_wildcard() {
        let it = item_with(
            "item_pre_edit_hook",
            &[
                ("1", "user:check_unique"),
                ("2", "user:hash_password"),
                ("3", "*:audit_log"),
                ("4", "node:sync"),
            ],
        );
        let c = RouteCache::from_internals(&it);

        let mut user_hooks: Vec<&str> = c
            .item_pre_edit
            .get("user")
            .unwrap()
            .iter()
            .map(String::as_str)
            .collect();
        user_hooks.sort();
        assert_eq!(user_hooks, vec!["check_unique", "hash_password"]);

        assert_eq!(c.item_pre_edit.get("node").unwrap().as_slice(), &["sync".to_string()]);
        assert_eq!(c.item_pre_edit_wildcard, vec!["audit_log".to_string()]);
        // post_edit untouched
        assert!(c.item_post_edit.is_empty());
        assert!(c.item_post_edit_wildcard.is_empty());
    }

    #[test]
    fn item_post_edit_hook_handles_wildcard_and_specific() {
        let it = item_with(
            "item_post_edit_hook",
            &[
                ("1", "*:webhook_fanout"),
                ("2", "test:notify_engine"),
            ],
        );
        let c = RouteCache::from_internals(&it);
        assert_eq!(c.item_post_edit_wildcard, vec!["webhook_fanout".to_string()]);
        assert_eq!(c.item_post_edit.get("test").unwrap().as_slice(), &["notify_engine".to_string()]);
        // pre_edit untouched
        assert!(c.item_pre_edit.is_empty());
        assert!(c.item_pre_edit_wildcard.is_empty());
    }

    #[test]
    fn malformed_specs_are_skipped_not_panicking() {
        let it = item_multi(&[
            (
                "extra_route",
                &[
                    ("1", "nopath"),                  // only 1 segment
                    ("2", "/p:get"),                  // 2 segments
                    ("3", ":get:handler"),            // empty path
                    ("4", "/p:get:"),                 // empty handler
                    ("5", "/ok:method:handler_ok"),   // good one
                ],
            ),
            (
                "item_pre_edit_hook",
                &[
                    ("1", "onlycollection"),  // 1 segment
                    ("2", ":handler"),        // empty collection
                    ("3", "coll:"),           // empty handler
                    ("4", "good:handler_ok"), // good
                    ("5", "*:wild_ok"),       // good wildcard
                ],
            ),
        ]);
        let c = RouteCache::from_internals(&it);

        // Only the "good" extra_route survives.
        assert_eq!(c.url_routes.len(), 1);
        assert_eq!(c.url_routes.get("/ok").map(String::as_str), Some("handler_ok"));

        // Only "good" pre-edit + wildcard survive.
        assert_eq!(c.item_pre_edit.len(), 1);
        assert_eq!(c.item_pre_edit.get("good").unwrap().as_slice(), &["handler_ok".to_string()]);
        assert_eq!(c.item_pre_edit_wildcard, vec!["wild_ok".to_string()]);
    }

    #[test]
    fn duplicate_paths_last_one_wins() {
        let it = item_with(
            "extra_route",
            &[
                ("1", "/dup:get:first"),
                ("2", "/dup:get:second"),
            ],
        );
        let c = RouteCache::from_internals(&it);
        // HashMap iter order isn't guaranteed; the final value is one of the two
        // — we don't pin which. Just assert that the path is present.
        assert!(c.url_routes.contains_key("/dup"));
        let v = c.url_routes.get("/dup").unwrap();
        assert!(v == "first" || v == "second");
        assert_eq!(c.url_routes.len(), 1);
    }

    #[test]
    fn handler_with_internal_colons_keeps_only_third_segment() {
        // Spec says "path:method:handler" — the parser uses parts[2] which is
        // the FIRST colon-delimited handler chunk. Anything after that is
        // dropped. Documenting current behaviour so a future refactor can
        // decide to support multi-colon handlers consciously.
        let it = item_with(
            "extra_route",
            &[("1", "/p:get:handler:with:colons")],
        );
        let c = RouteCache::from_internals(&it);
        assert_eq!(c.url_routes.get("/p").map(String::as_str), Some("handler"));
    }

    #[test]
    fn unknown_category_is_ignored() {
        // Random category name shouldn't leak into any of the cache fields.
        let it = item_with("some_other_category", &[("1", "foo:bar:baz")]);
        let c = RouteCache::from_internals(&it);
        assert!(c.url_routes.is_empty());
        assert!(c.item_pre_edit.is_empty());
    }
}

