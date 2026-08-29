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

//! OpenAPI description of this deployment's HTTP surface.
//!
//! The document is generated per request rather than committed as a file,
//! because half of the surface does not exist until a deployment starts: every
//! `extra_route` / `extra_unprotected_route` / `extra_rest_route` a plugin
//! declares in `internals.js` becomes a real path in `run()`, and the set of
//! collections `/itm/*` accepts is whatever the store holds. A checked-in
//! `openapi.yaml` would describe core and nothing else, and would drift from
//! the handlers the first time one of them changed.
//!
//! Core's own endpoints are described by the table below — the schemas belong
//! to `isabelle-dm`, so nothing can derive them, and a hand-written table is
//! what a derive-based generator would have produced anyway. Plugin routes are
//! read out of `internals.js`, which is where `run()` reads them from, so the
//! two cannot disagree about which paths exist.
//!
//! Both endpoints are public by default. A description is not a credential:
//! every endpoint it names still authenticates its own callers, and the
//! endpoints an anonymous caller may reach are exactly the ones that are meant
//! to be reachable anonymously. What the document does disclose is the
//! deployment's shape — which plugin routes exist, which collections the store
//! holds — so `--openapi-private` closes it to anyone but an administrator for
//! deployments that would rather not publish that.

use crate::server::secret::ensure_admin;
use crate::state::state::State;
use actix_identity::Identity;
use actix_web::{web, HttpResponse};
use isabelle_dm::data_model::item::Item;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

/// Where the document itself is served.
pub const OPENAPI_PATH: &str = "/openapi.json";

/// Where the human-readable rendering of it is served.
pub const DOCS_PATH: &str = "/docs";

/// Which of `run()`'s three dynamic route tables a plugin route came from.
///
/// The distinction is not cosmetic: an unprotected route is reachable without
/// a session, a protected one answers 401 without it, and a REST route takes a
/// raw body instead of multipart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteKind {
    /// `extra_route`: requires a session.
    Protected,
    /// `extra_unprotected_route`: served to anyone.
    Unprotected,
    /// `extra_rest_route`: raw-body route, session optional.
    Rest,
}

impl RouteKind {
    fn internals_key(&self) -> &'static str {
        match self {
            RouteKind::Protected => "extra_route",
            RouteKind::Unprotected => "extra_unprotected_route",
            RouteKind::Rest => "extra_rest_route",
        }
    }

    fn tag(&self) -> &'static str {
        match self {
            RouteKind::Protected => "plugin",
            RouteKind::Unprotected => "plugin (public)",
            RouteKind::Rest => "plugin (rest)",
        }
    }
}

/// One route a plugin added through `internals.js`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PluginRoute {
    pub path: String,
    /// `"get"` or `"post"` — the only two `run()` registers.
    pub method: String,
    /// Name of the plugin hook the route dispatches to.
    pub handler: String,
    pub kind: RouteKind,
}

/// Read the plugin route tables out of `internals.js`.
///
/// The spec format is `"path:method:handler"`. This mirrors `run()`'s parse
/// exactly, including its strictness: `run()` compares the method against the
/// literals `"post"` and `"get"`, so a spec written `"/x:GET:h"` registers no
/// route at all and must not appear in the document either. Malformed entries
/// are skipped rather than reported — they are already skipped at startup.
pub fn plugin_routes(internals: &Item) -> Vec<PluginRoute> {
    let mut out: Vec<PluginRoute> = Vec::new();

    for kind in [
        RouteKind::Protected,
        RouteKind::Unprotected,
        RouteKind::Rest,
    ] {
        let specs = match internals.strstrs.get(kind.internals_key()) {
            Some(s) => s,
            None => continue,
        };
        for spec in specs.values() {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() < 3 {
                continue;
            }
            let (path, method, handler) = (parts[0], parts[1], parts[2]);
            if path.is_empty() || handler.is_empty() {
                continue;
            }
            if method != "get" && method != "post" {
                continue;
            }
            let route = PluginRoute {
                path: path.to_string(),
                method: method.to_string(),
                handler: handler.to_string(),
                kind,
            };
            if !out.contains(&route) {
                out.push(route);
            }
        }
    }

    // `internals.strstrs` is a map, so iteration order varies between runs.
    // Sort so that two fetches of the document compare equal.
    out.sort_by(|a, b| (&a.path, &a.method).cmp(&(&b.path, &b.method)));
    out
}

fn schema_ref(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{}", name) })
}

fn u64_schema() -> Value {
    json!({ "type": "integer", "format": "int64", "minimum": 0 })
}

fn query_param(name: &str, schema: Value, description: &str) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "schema": schema,
        "description": description,
    })
}

fn json_response(description: &str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": { "application/json": { "schema": schema } },
    })
}

fn empty_response(description: &str) -> Value {
    json!({ "description": description })
}

/// The unset sentinel every numeric `ListQuery` field defaults to.
const UNSET: &str = "18446744073709551615 (`u64::MAX`) when omitted";

/// Build the whole document.
///
/// `server_url` is the deployment's public URL (`--pub-url`); `collections`
/// is what the store reports, used to constrain the `collection` parameter to
/// the names `/itm/*` will actually accept. `admin_only` is whether this
/// deployment runs with `--openapi-private`, which the document has to state
/// about itself — the two meta endpoints are the only ones whose reachability
/// depends on a flag rather than on the handler.
pub fn build_spec(
    server_url: &str,
    collections: &[String],
    routes: &[PluginRoute],
    admin_only: bool,
) -> Value {
    let mut paths = core_paths(collections, admin_only);

    for route in routes {
        let entry = paths.entry(route.path.clone()).or_insert_with(|| json!({}));
        let operation = plugin_operation(route);
        if let Some(obj) = entry.as_object_mut() {
            obj.insert(route.method.clone(), operation);
        }
    }

    assign_operation_ids(&mut paths);

    let servers = if server_url.is_empty() {
        json!([{ "url": "/" }])
    } else {
        json!([{ "url": server_url }])
    };

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Isabelle core API",
            "version": env!("CARGO_PKG_VERSION"),
            "description":
                "Generated at request time from this running deployment: core's own \
                 endpoints plus every plugin route declared in `internals.js`. \
                 Authentication is a session cookie (`id`) obtained from `POST /login`; \
                 it is `SameSite=Lax`, so the API and the UI have to be same-site.",
            "license": { "name": "MIT", "identifier": "MIT" },
        },
        "servers": servers,
        "security": [ { "sessionCookie": [] } ],
        "tags": [
            { "name": "auth", "description": "Sessions, registration and one-time codes." },
            { "name": "items", "description": "The generic collection store." },
            { "name": "settings", "description": "Deployment settings. Admin only." },
            { "name": "secrets", "description": "Encrypted secret store. Admin only." },
            { "name": "system", "description": "Operational endpoints. Admin only." },
            { "name": "meta", "description": "This document." },
            { "name": "plugin", "description": "Plugin routes requiring a session." },
            { "name": "plugin (public)", "description": "Plugin routes served without a session." },
            { "name": "plugin (rest)", "description": "Plugin routes taking a raw request body." },
        ],
        "paths": Value::Object(paths),
        "components": {
            "securitySchemes": {
                "sessionCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "id",
                    "description":
                        "Session cookie issued by `POST /login`. Signed and encrypted; \
                         invalidated by `POST /logout`, by a password or role change, and \
                         by deleting the account.",
                },
            },
            "schemas": schemas(),
        },
    })
}

/// Give every operation an `operationId`.
///
/// Client generators name the methods they emit after it, and a document
/// without one leaves them inventing names that change whenever a path is
/// re-ordered. Derived from the verb and the path, so it is stable for as long
/// as the endpoint is; a collision — two paths differing only in a character
/// that normalizes to `_` — is broken by a suffix rather than silently
/// producing a document with two operations claiming one id.
fn assign_operation_ids(paths: &mut serde_json::Map<String, Value>) {
    let mut taken: Vec<String> = Vec::new();

    for (path, methods) in paths.iter_mut() {
        let methods = match methods.as_object_mut() {
            Some(m) => m,
            None => continue,
        };
        for (method, op) in methods.iter_mut() {
            let mut id = format!("{}{}", method, normalize_path(path));
            let mut n = 2;
            while taken.contains(&id) {
                id = format!("{}{}_{}", method, normalize_path(path), n);
                n += 1;
            }
            taken.push(id.clone());
            if let Some(obj) = op.as_object_mut() {
                obj.insert("operationId".to_string(), json!(id));
            }
        }
    }
}

fn normalize_path(path: &str) -> String {
    let mut out = String::new();
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        out.push('_');
        out.extend(
            segment
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }),
        );
    }
    out
}

/// Core's own endpoints.
fn core_paths(collections: &[String], admin_only: bool) -> serde_json::Map<String, Value> {
    let mut collection_schema = json!({ "type": "string" });
    if !collections.is_empty() {
        let mut sorted: Vec<&String> = collections.iter().collect();
        sorted.sort();
        collection_schema["enum"] = json!(sorted);
    }

    let collection_param = json!({
        "name": "collection",
        "in": "query",
        "required": true,
        "schema": collection_schema,
        "description": "Collection to act on. An unknown name is answered 400.",
    });

    let merge_param = query_param(
        "merge",
        json!({ "type": "boolean", "default": false }),
        "Merge into the stored item instead of replacing it.",
    );

    let process_result_200 = json_response(
        "Outcome envelope. Note that a *refused* operation is also a 200 with \
         `succeeded: false` — the status alone is not the answer.",
        schema_ref("ProcessResult"),
    );

    let mut paths = serde_json::Map::new();

    paths.insert(
        "/is_logged_in".to_string(),
        json!({ "get": {
            "tags": ["auth"],
            "summary": "Current session, plus the branding an unauthenticated UI still needs",
            "description":
                "Never fails: without a session it answers the same document with an empty \
                 `username`, `id` 0 and no roles, so a login screen can render from it.",
            "security": [ {}, { "sessionCookie": [] } ],
            "responses": {
                "200": json_response("The caller, as far as the server knows it.", schema_ref("DetailedLoginUser")),
            },
        }}),
    );

    paths.insert(
        "/login".to_string(),
        json!({ "post": {
            "tags": ["auth"],
            "summary": "Exchange credentials for a session cookie",
            "description":
                "`password` accepts either the account password or a live one-time code \
                 from `/gen_otp`; a successful login burns the code. Failure is reported \
                 as 200 with `succeeded: false` and a deliberately unspecific error.",
            "security": [ {} ],
            "requestBody": {
                "required": true,
                "content": { "multipart/form-data": { "schema": {
                    "type": "object",
                    "required": ["username", "password"],
                    "properties": {
                        "username": { "type": "string", "description": "Login or email." },
                        "password": { "type": "string" },
                    },
                }}},
            },
            "responses": {
                "200": process_result_200.clone(),
                "400": json_response("Body malformed, or not read within the deadline.", schema_ref("ProcessResult")),
                "413": json_response("Body over `--max-payload`.", schema_ref("ProcessResult")),
                "500": json_response("The session could not be established.", schema_ref("ProcessResult")),
            },
        }}),
    );

    paths.insert(
        "/auth/providers".to_string(),
        json!({ "get": {
            "tags": ["auth"],
            "summary": "Which identity providers are configured",
            "description":
                "Read by a login screen, so it answers without a session. A provider is \
                 listed when its entry exists in the secret store and carries everything \
                 that provider needs; nothing about the credentials themselves is \
                 returned.",
            "security": [ {} ],
            "responses": {
                "200": json_response("The configured providers.", json!({
                    "type": "object",
                    "properties": { "providers": { "type": "array", "items": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "example": "google" },
                            "name": { "type": "string", "example": "Google" },
                        },
                    }}},
                })),
            },
        }}),
    );

    paths.insert(
        "/auth/config".to_string(),
        json!({
            "get": {
                "tags": ["auth"],
                "summary": "How the identity providers are configured",
                "description":
                    "Administrators only. Returns each provider's public settings — the \
                     client id, the redirect URI in use and the one that would be used by \
                     default — plus `has_secret`, which says whether a client secret or \
                     signing key is stored. The secret itself is never returned, by this \
                     or any other endpoint. `problem` carries whatever stops the provider \
                     being usable, so a half-finished configuration says what is missing.",
                "responses": {
                    "200": json_response("The configuration.", json!({ "type": "object" })),
                    "401": empty_response("No session."),
                    "403": empty_response("Not an administrator."),
                },
            },
            "post": {
                "tags": ["auth"],
                "summary": "Configure a provider",
                "description":
                    "Administrators only. Every field is optional and an absent one is \
                     left alone. `client_secret` and `private_key` cannot be read back, so \
                     an empty string means unchanged rather than deleted — use \
                     `/auth/config/forget` to remove a provider. The result is checked \
                     before it is stored, so an unreadable Apple key is refused here \
                     rather than at a token endpoint weeks later.",
                "requestBody": {
                    "required": true,
                    "content": { "application/json": { "schema": {
                        "type": "object",
                        "required": ["provider"],
                        "properties": {
                            "provider": { "type": "string", "enum": ["google", "apple"] },
                            "client_id": { "type": "string" },
                            "client_secret": { "type": "string", "description": "Google. Blank leaves it unchanged." },
                            "team_id": { "type": "string", "description": "Apple." },
                            "key_id": { "type": "string", "description": "Apple." },
                            "private_key": { "type": "string", "description": "Apple, the `.p8` in full. Blank leaves it unchanged." },
                            "redirect_uri": { "type": "string", "description": "Blank falls back to the deployment default." },
                        },
                    }}},
                },
                "responses": {
                    "200": process_result_200.clone(),
                    "400": empty_response("Body malformed, or not read within the deadline."),
                    "401": empty_response("No session."),
                    "403": empty_response("Not an administrator."),
                },
            },
        }),
    );

    paths.insert(
        "/auth/config/forget".to_string(),
        json!({ "post": {
            "tags": ["auth"],
            "summary": "Remove a provider's configuration",
            "description":
                "Administrators only. This is also how a provider is switched off: one \
                 exists for a deployment exactly when its configuration does. Forgetting \
                 one that was never configured succeeds.",
            "requestBody": {
                "required": true,
                "content": { "application/json": { "schema": {
                    "type": "object",
                    "required": ["provider"],
                    "properties": { "provider": { "type": "string", "enum": ["google", "apple"] } },
                }}},
            },
            "responses": {
                "200": process_result_200.clone(),
                "401": empty_response("No session."),
                "403": empty_response("Not an administrator."),
            },
        }}),
    );

    paths.insert(
        "/auth/{provider}/start".to_string(),
        json!({ "get": {
            "tags": ["auth"],
            "summary": "Begin signing in with an identity provider",
            "description":
                "A browser navigation, not a fetch: it answers 302 to the provider's \
                 consent screen and sets a short-lived cookie that ties the callback to \
                 this browser. `next` is where the browser is sent afterwards and is \
                 reduced to a path on this site.",
            "security": [ {} ],
            "parameters": [
                { "name": "provider", "in": "path", "required": true,
                  "schema": { "type": "string", "enum": ["google", "apple"] } },
                { "name": "next", "in": "query", "required": false,
                  "schema": { "type": "string", "example": "/" } },
            ],
            "responses": {
                "302": empty_response("To the provider, or back to `next` with `auth_error` when the provider is not configured."),
                "404": empty_response("No such provider."),
            },
        }}),
    );

    paths.insert(
        "/auth/{provider}/callback".to_string(),
        json!({
            "get": {
                "tags": ["auth"],
                "summary": "Finish signing in (redirect callback)",
                "description":
                    "Where the provider returns the browser. On success a session cookie \
                     is issued and the browser is sent to the `next` recorded at the \
                     start; otherwise it goes to the same place with `auth_error` set to \
                     one of `denied`, `unverified`, `registration_closed`, `inactive`, \
                     `mismatched` or `failed`. The detail behind a refusal is logged, not \
                     put in the URL.",
                "security": [ {} ],
                "parameters": [
                    { "name": "provider", "in": "path", "required": true,
                      "schema": { "type": "string", "enum": ["google", "apple"] } },
                    { "name": "code", "in": "query", "required": false, "schema": { "type": "string" } },
                    { "name": "state", "in": "query", "required": false, "schema": { "type": "string" } },
                    { "name": "error", "in": "query", "required": false, "schema": { "type": "string" } },
                ],
                "responses": {
                    "302": empty_response("Signed in, or refused with `auth_error`."),
                    "404": empty_response("No such provider."),
                },
            },
            "post": {
                "tags": ["auth"],
                "summary": "Finish signing in (form_post callback)",
                "description":
                    "The same exchange for providers that answer by POSTing the form \
                     back. Apple requires this whenever a scope is requested, and the \
                     address is a scope.",
                "security": [ {} ],
                "parameters": [
                    { "name": "provider", "in": "path", "required": true,
                      "schema": { "type": "string", "enum": ["google", "apple"] } },
                ],
                "requestBody": {
                    "required": true,
                    "content": { "application/x-www-form-urlencoded": { "schema": {
                        "type": "object",
                        "properties": {
                            "code": { "type": "string" },
                            "state": { "type": "string" },
                            "error": { "type": "string" },
                        },
                    }}},
                },
                "responses": {
                    "302": empty_response("Signed in, or refused with `auth_error`."),
                    "404": empty_response("No such provider."),
                },
            },
        }),
    );

    paths.insert(
        "/logout".to_string(),
        json!({ "post": {
            "tags": ["auth"],
            "summary": "End the session — on every device",
            "description":
                "The session lives entirely in the cookie, so this also raises the \
                 account's session generation. That is what actually revokes copies of \
                 the cookie, and it is account-wide: other devices are signed out too.",
            "responses": {
                "200": empty_response("Signed out."),
                "401": empty_response("No session to end."),
            },
        }}),
    );

    paths.insert(
        "/register".to_string(),
        json!({ "post": {
            "tags": ["auth"],
            "summary": "Self-registration",
            "description":
                "Refused with `succeeded: false` when self-registration is disabled in \
                 `internals.js`, when the login or the email is taken, or when either \
                 contains characters the user lookup cannot handle. The account is \
                 created inactive.",
            "security": [ {} ],
            "requestBody": {
                "required": true,
                "content": { "multipart/form-data": { "schema": {
                    "type": "object",
                    "required": ["login", "email"],
                    "properties": {
                        "login": { "type": "string" },
                        "email": { "type": "string" },
                        "dry": {
                            "type": "string",
                            "enum": ["true", "false"],
                            "description": "`\"true\"` checks availability without writing.",
                        },
                    },
                }}},
            },
            "responses": {
                "200": process_result_200.clone(),
                "400": json_response("Body malformed, or not read within the deadline.", schema_ref("ProcessResult")),
                "413": json_response("Body over `--max-payload`.", schema_ref("ProcessResult")),
            },
        }}),
    );

    paths.insert(
        "/gen_otp".to_string(),
        json!({ "post": {
            "tags": ["auth"],
            "summary": "Issue a one-time code to an account",
            "description":
                "Always answers `succeeded: true`, whether or not the account exists, is \
                 active, or is being throttled — otherwise the endpoint enumerates logins. \
                 The code is delivered by the `otp_hook` plugin, never in this response.",
            "security": [ {} ],
            "requestBody": {
                "required": true,
                "content": { "multipart/form-data": { "schema": {
                    "type": "object",
                    "required": ["username"],
                    "properties": { "username": { "type": "string", "description": "Login or email." } },
                }}},
            },
            "responses": {
                "200": process_result_200.clone(),
                "400": json_response("Body malformed, or not read within the deadline.", schema_ref("ProcessResult")),
                "413": json_response("Body over `--max-payload`.", schema_ref("ProcessResult")),
            },
        }}),
    );

    paths.insert(
        "/itm/list".to_string(),
        json!({ "get": {
            "tags": ["items"],
            "summary": "Read items from a collection",
            "description":
                "Three mutually exclusive selections, in the order they are tried: a single \
                 `id`; a range/filter query (`id_min`/`id_max`/`sort_key`/`filter`); or an \
                 explicit `id_list`. With none of them the result is empty.\n\n\
                 `filter` and `sort_key` are constrained to the fields the UI builds — both \
                 reach the database, and `total_count` is counted before any plugin filter \
                 redacts anything. In the `user` collection, credentials are stripped from \
                 every record except the caller's own, unless the caller is an admin.\n\n\
                 `limit: 0` is an empty page with a real `total_count`, which is how a \
                 paginated view asks for the count alone.",
            "parameters": [
                collection_param.clone(),
                query_param("id", u64_schema(), &format!("Single item; {}.", UNSET)),
                query_param("id_min", u64_schema(), &format!("Range start, inclusive; {}.", UNSET)),
                query_param("id_max", u64_schema(), &format!("Range end, inclusive; {}.", UNSET)),
                query_param("id_list", json!({ "type": "array", "items": u64_schema() }),
                    "Explicit ids, `serde_qs` style: `id_list[0]=1&id_list[1]=2`. Ids that \
                     do not exist are skipped and not counted."),
                query_param("skip", u64_schema(), "Items to skip. Unset means 0."),
                query_param("limit", u64_schema(), "Page size. Unset means no limit."),
                query_param("sort_key", json!({ "type": "string" }),
                    "Field to sort by, ascending, with `id` as the tiebreak. Rejected with \
                     400 if not an allowed field."),
                query_param("filter", json!({ "type": "string" }),
                    "MongoDB query document as JSON. Validated against the same field \
                     allowlist as `sort_key`; plugin-supplied filters are ANDed with it."),
                query_param("context", json!({ "type": "string" }),
                    "Passed to the plugin list filters. Defaults to `full` for a \
                     single-`id` read, so plugins skip their listing trim."),
            ],
            "responses": {
                "200": json_response("Matching items, keyed by id.", schema_ref("ListResult")),
                "400": empty_response("Unknown collection, malformed query, rejected filter or sort key, or a missing single `id`."),
                "401": empty_response("No session."),
            },
        }}),
    );

    paths.insert(
        "/itm/edit".to_string(),
        json!({ "post": {
            "tags": ["items"],
            "summary": "Create or update an item",
            "description":
                "The item is assembled from the query string and then merged with the JSON \
                 `item` field of the body, which wins. `id` unset (`u64::MAX`) creates; an \
                 existing id updates. Plugin pre-edit hooks can refuse the write — that is \
                 reported as 200 with `succeeded: false`.\n\n\
                 A write that changes a password or a role raises the account's session \
                 generation, which signs that account out everywhere.",
            "parameters": [
                collection_param.clone(),
                merge_param.clone(),
                query_param("id", u64_schema(), &format!("Item to update; {} creates a new one.", UNSET)),
            ],
            "requestBody": {
                "required": false,
                "content": { "multipart/form-data": { "schema": {
                    "type": "object",
                    "properties": { "item": {
                        "type": "string",
                        "description": "The item as a JSON `Item` document. Unparseable JSON is logged and treated as an empty item.",
                    }},
                }}},
            },
            "responses": {
                "200": json_response(
                    "`data.id` carries the stored id. A pre-edit hook's refusal has the same status and `succeeded: false`.",
                    schema_ref("ProcessResult")),
                "400": empty_response("Unknown collection, or a query the item model cannot parse."),
                "401": empty_response("No session."),
                "403": empty_response("An item auth hook refused the write."),
                "413": empty_response("Body over `--max-payload`."),
                "500": json_response("The store did not accept the write.", schema_ref("ProcessResult")),
            },
        }}),
    );

    paths.insert(
        "/itm/del".to_string(),
        json!({ "post": {
            "tags": ["items"],
            "summary": "Delete an item",
            "description":
                "Deleting an id that does not exist is not an error: the hooks run and the \
                 answer is 200 either way.",
            "parameters": [
                collection_param.clone(),
                merge_param,
                json!({
                    "name": "id",
                    "in": "query",
                    "required": true,
                    "schema": u64_schema(),
                    "description": "Item to remove.",
                }),
            ],
            "responses": {
                "200": empty_response("Removed, or there was nothing to remove."),
                "400": empty_response("Unknown collection or malformed query."),
                "401": empty_response("No session."),
                "403": empty_response("An item auth hook refused the deletion."),
            },
        }}),
    );

    paths.insert(
        "/setting/list".to_string(),
        json!({ "get": {
            "tags": ["settings"],
            "summary": "Read the deployment settings",
            "responses": {
                "200": json_response("The settings item.", schema_ref("Item")),
                "401": empty_response("No session."),
                "403": empty_response("Not an admin."),
            },
        }}),
    );

    paths.insert(
        "/setting/edit".to_string(),
        json!({ "post": {
            "tags": ["settings"],
            "summary": "Write the deployment settings",
            "description": "Assembled from the query string and merged with the body's `item` field, as `/itm/edit` is.",
            "requestBody": {
                "required": false,
                "content": { "multipart/form-data": { "schema": {
                    "type": "object",
                    "properties": { "item": { "type": "string", "description": "Settings as a JSON `Item` document." } },
                }}},
            },
            "responses": {
                "200": process_result_200.clone(),
                "400": empty_response("Malformed query."),
                "401": empty_response("No session."),
                "403": empty_response("Not an admin."),
                "413": empty_response("Body over `--max-payload`."),
                "500": json_response("The settings write did not reach the store.", schema_ref("ProcessResult")),
            },
        }}),
    );

    paths.insert(
        "/setting/gcal_auth".to_string(),
        json!({ "post": {
            "tags": ["settings"],
            "summary": "Begin Google Calendar authorization",
            "responses": {
                "200": { "description": "The Google consent URL to send the admin to.",
                         "content": { "text/plain": { "schema": { "type": "string" } } } },
                "401": empty_response("No session."),
                "403": empty_response("Not an admin."),
            },
        }}),
    );

    paths.insert(
        "/setting/gcal_auth_end".to_string(),
        json!({ "post": {
            "tags": ["settings"],
            "summary": "Complete Google Calendar authorization",
            "description": "Called with the parameters Google appended to the redirect.",
            "parameters": [
                json!({ "name": "state", "in": "query", "required": true, "schema": { "type": "string" } }),
                json!({ "name": "code", "in": "query", "required": true, "schema": { "type": "string" } }),
                json!({ "name": "scope", "in": "query", "required": true, "schema": { "type": "string" } }),
            ],
            "responses": {
                "200": { "description": "Result of the token exchange.",
                         "content": { "text/plain": { "schema": { "type": "string" } } } },
                "400": empty_response("A query missing any of the three parameters."),
                "401": empty_response("No session."),
                "403": empty_response("Not an admin."),
            },
        }}),
    );

    paths.insert(
        "/system/update".to_string(),
        json!({ "post": {
            "tags": ["system"],
            "summary": "Run the configured update script",
            "description":
                "Runs `--update-script` and waits for it. `data` carries `stdout`, `stderr` \
                 and `exit_code`. With no script configured the answer is 200 with \
                 `succeeded: false`.",
            "responses": {
                "200": process_result_200.clone(),
                "401": empty_response("No session."),
                "403": empty_response("Not an admin."),
            },
        }}),
    );

    let secret_id_body = json!({
        "required": true,
        "content": { "application/json": { "schema": {
            "type": "object",
            "required": ["id"],
            "properties": { "id": u64_schema() },
        }}},
    });

    paths.insert(
        "/secret/list".to_string(),
        json!({ "get": {
            "tags": ["secrets"],
            "summary": "List secret ids and names",
            "description": "Names and ids only — values are never listed.",
            "responses": {
                "200": json_response("Every stored secret, by reference.",
                    json!({ "type": "array", "items": schema_ref("SecretRef") })),
                "401": empty_response("No session."),
                "403": empty_response("Not an admin."),
            },
        }}),
    );

    paths.insert(
        "/secret/get".to_string(),
        json!({ "post": {
            "tags": ["secrets"],
            "summary": "Read one secret, masked",
            "description":
                "Secret values come back as the placeholder `<hidden>`; writing that \
                 placeholder back leaves the stored value alone, so a client can \
                 round-trip an item it cannot read.",
            "requestBody": secret_id_body.clone(),
            "responses": {
                "200": json_response("The secret item, with values masked.", schema_ref("Item")),
                "401": empty_response("No session."),
                "403": empty_response("Not an admin."),
                "404": json_response("No such secret.", schema_ref("ProcessResult")),
            },
        }}),
    );

    paths.insert(
        "/secret/edit".to_string(),
        json!({ "post": {
            "tags": ["secrets"],
            "summary": "Create or update a secret",
            "description":
                "Merge semantics: fields the caller omits keep their stored values, and a \
                 field sent as `<hidden>` is left untouched.",
            "requestBody": {
                "required": true,
                "content": { "application/json": { "schema": schema_ref("Item") } },
            },
            "responses": {
                "200": json_response("`data.id` carries the stored id.", schema_ref("ProcessResult")),
                "400": empty_response("Body malformed, or not read within the deadline."),
                "401": empty_response("No session."),
                "403": empty_response("Not an admin."),
                "413": empty_response("Body over `--max-payload`."),
            },
        }}),
    );

    paths.insert(
        "/secret/del".to_string(),
        json!({ "post": {
            "tags": ["secrets"],
            "summary": "Delete a secret",
            "requestBody": secret_id_body,
            "responses": {
                "200": json_response("Removed.", schema_ref("ProcessResult")),
                "401": empty_response("No session."),
                "403": empty_response("Not an admin."),
                "404": json_response("There was nothing to remove.", schema_ref("ProcessResult")),
            },
        }}),
    );

    // The two below are the only endpoints whose reachability is a deployment
    // setting rather than a property of the handler, so the document has to
    // say which way this deployment is configured.
    let mut meta_openapi = json!({ "get": {
        "tags": ["meta"],
        "summary": "This document",
        "responses": {
            "200": json_response("The OpenAPI document for this deployment.", json!({ "type": "object" })),
        },
    }});
    let mut meta_docs = json!({ "get": {
        "tags": ["meta"],
        "summary": "This document, rendered",
        "description": "Server-rendered HTML — no scripts and no external assets, so it works offline.",
        "responses": {
            "200": { "description": "The rendering.",
                     "content": { "text/html": { "schema": { "type": "string" } } } },
        },
    }});

    for (op, note) in [
        (&mut meta_openapi, "Served without a session."),
        (&mut meta_docs, "Served without a session."),
    ] {
        let get = &mut op["get"];
        if admin_only {
            get["description"] = json!(format!(
                "{}This deployment runs with `--openapi-private`, so the description is \
                 served to administrators only.",
                get["description"]
                    .as_str()
                    .map(|d| format!("{} ", d))
                    .unwrap_or_default()
            ));
            let responses = get["responses"].as_object_mut().unwrap();
            responses.insert("401".to_string(), empty_response("No session."));
            responses.insert("403".to_string(), empty_response("Not an admin."));
        } else {
            get["security"] = json!([{}, { "sessionCookie": [] }]);
            get["description"] = json!(format!(
                "{}{}",
                get["description"]
                    .as_str()
                    .map(|d| format!("{} ", d))
                    .unwrap_or_default(),
                note
            ));
        }
    }

    paths.insert(OPENAPI_PATH.to_string(), meta_openapi);
    paths.insert(DOCS_PATH.to_string(), meta_docs);

    paths
}

/// What can be said about a route whose handler lives in a plugin.
///
/// The path, the verb and whether a session is required are known from
/// `internals.js`; the request and response shapes are the plugin's business
/// and are described as free-form.
fn plugin_operation(route: &PluginRoute) -> Value {
    let mut op = json!({
        "tags": [route.kind.tag()],
        "summary": format!("Plugin route → `{}`", route.handler),
        "responses": {
            "200": { "description": "Whatever the plugin hook returns." },
            "404": { "description": "The path is registered but no hook answers to it." },
        },
    });

    let description = match route.kind {
        RouteKind::Protected => {
            "Registered from `internals.js` as `extra_route`. Requires a session."
        }
        RouteKind::Unprotected => {
            "Registered from `internals.js` as `extra_unprotected_route`. Served without a \
             session; the hook is told whether one was present."
        }
        RouteKind::Rest => {
            "Registered from `internals.js` as `extra_rest_route`. The body is handed to the \
             hook verbatim, as UTF-8 text, under `--max-payload` and `--body-timeout`. The \
             hook may also open a session for the caller."
        }
    };
    op["description"] = json!(description);

    if route.kind != RouteKind::Protected {
        op["security"] = json!([{}, { "sessionCookie": [] }]);
    }

    let responses = op["responses"].as_object_mut().unwrap();
    match route.kind {
        RouteKind::Protected => {
            responses.insert("401".to_string(), empty_response("No session."));
        }
        RouteKind::Rest => {
            responses.insert(
                "400".to_string(),
                empty_response("Body malformed, not valid UTF-8, or not read within the deadline."),
            );
            responses.insert(
                "413".to_string(),
                empty_response("Body over `--max-payload`."),
            );
        }
        RouteKind::Unprotected => {}
    }

    if route.method == "post" && route.kind != RouteKind::Rest {
        op["requestBody"] = json!({
            "required": false,
            "content": { "multipart/form-data": { "schema": { "type": "object" } } },
        });
    }
    if route.method == "post" && route.kind == RouteKind::Rest {
        op["requestBody"] = json!({
            "required": false,
            "content": { "*/*": { "schema": { "type": "string" } } },
        });
    }

    op
}

/// The `isabelle-dm` types the endpoints exchange.
///
/// Written out rather than derived: they belong to another crate, so no derive
/// of ours can reach them.
fn schemas() -> Value {
    let str_map = json!({ "type": "object", "additionalProperties": { "type": "string" } });

    json!({
        "Item": {
            "type": "object",
            "description":
                "The universal record. Values live in per-type maps rather than named \
                 fields, so a collection's shape is a convention rather than a schema.",
            "properties": {
                "id": {
                    "type": "integer", "format": "int64", "minimum": 0,
                    "description": "18446744073709551615 (`u64::MAX`) means unset — on a write, \"allocate one\".",
                },
                "strs": str_map.clone(),
                "strstrs": {
                    "type": "object",
                    "additionalProperties": str_map.clone(),
                    "description": "Named groups of string pairs.",
                },
                "strids": {
                    "type": "object",
                    "additionalProperties": { "type": "array", "items": u64_schema() },
                    "description": "Named lists of ids.",
                },
                "bools": { "type": "object", "additionalProperties": { "type": "boolean" } },
                "u64s": { "type": "object", "additionalProperties": u64_schema() },
                "ids": { "type": "object", "additionalProperties": u64_schema() },
                "root_node": schema_ref("ItemDataNode"),
            },
        },
        "ItemDataNode": {
            "type": "object",
            "description": "Tree-shaped item payload.",
            "properties": {
                "value": { "type": "string" },
                "value_type": { "type": "string" },
                "writable": { "type": "boolean" },
                "action": { "type": "string" },
                "subnodes": { "type": "object", "additionalProperties": schema_ref("ItemDataNode") },
            },
        },
        "ListResult": {
            "type": "object",
            "properties": {
                "map": {
                    "type": "object",
                    "additionalProperties": schema_ref("Item"),
                    "description": "Items on this page, keyed by their id rendered as a string.",
                },
                "total_count": {
                    "type": "integer", "format": "int64", "minimum": 0,
                    "description":
                        "Matches before pagination. Counted on the database query, so plugin \
                         list filters — which run per page — do not reduce it.",
                },
            },
            "required": ["map", "total_count"],
        },
        "ProcessResult": {
            "type": "object",
            "description": "Outcome envelope. Carried by 200 responses as well as failures, so `succeeded` has to be read.",
            "properties": {
                "succeeded": { "type": "boolean" },
                "error": { "type": "string", "description": "Empty when `succeeded` is true." },
                "data": str_map.clone(),
            },
            "required": ["succeeded", "error", "data"],
        },
        "DetailedLoginUser": {
            "type": "object",
            "properties": {
                "username": { "type": "string", "description": "The session's email. Empty when there is no session." },
                "id": u64_schema(),
                "role": {
                    "type": "array", "items": { "type": "string" },
                    "description": "Roles held, from the `role_is_*` flags that are set to true.",
                },
                "site_name": { "type": "string" },
                "site_logo": { "type": "string" },
                "licensed_to": { "type": "string" },
                "params": str_map,
            },
            "required": ["username", "id", "role", "site_name", "site_logo", "licensed_to", "params"],
        },
        "SecretRef": {
            "type": "object",
            "properties": { "id": u64_schema(), "name": { "type": "string" } },
            "required": ["id", "name"],
        },
    })
}

/// Assemble the document for the deployment behind `data`.
async fn spec_for(data: &web::Data<State>) -> Value {
    let srv: &crate::state::data::Data = &data.server;
    let internals = srv.rw.get_internals().await;
    let collections = srv.rw.get_collections().await;
    let public_url = srv.public_url.lock().clone();
    build_spec(
        &public_url,
        &collections,
        &plugin_routes(&internals),
        srv.openapi_private.load(Ordering::Relaxed),
    )
}

/// Refuse the caller when this deployment keeps its description private.
///
/// `--openapi-private` is off by default, so this normally lets everyone
/// through; the `Identity` is therefore extracted as an `Option`, which is what
/// lets an anonymous request reach the handler at all rather than being turned
/// away by the extractor with a 401 before any of this runs.
async fn ensure_visible(
    data: &web::Data<State>,
    user: &Option<Identity>,
) -> Result<(), HttpResponse> {
    if !data.server.openapi_private.load(Ordering::Relaxed) {
        return Ok(());
    }
    match user {
        Some(user) => ensure_admin(data, user).await,
        None => Err(HttpResponse::Unauthorized().into()),
    }
}

/// `GET /openapi.json`
pub async fn openapi_json(user: Option<Identity>, data: web::Data<State>) -> HttpResponse {
    if let Err(r) = ensure_visible(&data, &user).await {
        return r;
    }
    HttpResponse::Ok().json(spec_for(&data).await)
}

/// `GET /docs`
pub async fn openapi_docs(user: Option<Identity>, data: web::Data<State>) -> HttpResponse {
    if let Err(r) = ensure_visible(&data, &user).await {
        return r;
    }
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(render_html(&spec_for(&data).await))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render the document as a static page.
///
/// Deliberately server-rendered and asset-free rather than a Swagger UI or
/// Redoc embed: those are a script tag pointing at a CDN, which is third-party
/// JavaScript running on this origin in whatever browser opens the page —
/// including an administrator's, the one session on the deployment that can do
/// everything. The machine-readable document is right there at
/// `/openapi.json` for anyone who wants the full experience locally.
fn render_html(spec: &Value) -> String {
    let mut out = String::new();
    let title = spec["info"]["title"].as_str().unwrap_or("API");
    let version = spec["info"]["version"].as_str().unwrap_or("");

    out.push_str(&format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} {}</title><style>\
         :root {{ color-scheme: light dark; }}\
         body {{ font: 15px/1.5 -apple-system, system-ui, sans-serif; margin: 0 auto; \
                 max-width: 52rem; padding: 2rem 1.25rem 6rem; }}\
         h1 {{ font-size: 1.5rem; margin-bottom: .25rem; }}\
         h2 {{ font-size: 1.05rem; margin: 2.5rem 0 .5rem; text-transform: uppercase; \
               letter-spacing: .06em; opacity: .65; }}\
         .op {{ border: 1px solid rgba(128,128,128,.35); border-radius: 8px; \
                padding: .75rem 1rem; margin: .5rem 0; }}\
         .sig {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .95rem; }}\
         .m {{ display: inline-block; min-width: 3.2rem; font-weight: 700; }}\
         .get {{ color: #2b7a2b; }} .post {{ color: #9a4b00; }}\
         .sum {{ margin: .35rem 0 0; font-weight: 600; }}\
         .desc {{ margin: .35rem 0 0; opacity: .85; white-space: pre-wrap; }}\
         table {{ border-collapse: collapse; margin: .6rem 0 0; width: 100%; font-size: .9rem; }}\
         th, td {{ text-align: left; vertical-align: top; padding: .2rem .5rem .2rem 0; }}\
         th {{ opacity: .6; font-weight: 600; }}\
         code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}\
         .req {{ color: #b00; }}\
         </style></head><body>\n",
        esc(title),
        esc(version)
    ));

    out.push_str(&format!(
        "<h1>{} <small>{}</small></h1>\n",
        esc(title),
        esc(version)
    ));
    if let Some(d) = spec["info"]["description"].as_str() {
        out.push_str(&format!("<p class=\"desc\">{}</p>\n", esc(d)));
    }
    if let Some(url) = spec["servers"][0]["url"].as_str() {
        out.push_str(&format!(
            "<p class=\"desc\">Server: <code>{}</code> · machine-readable: \
             <a href=\"{}\"><code>{}</code></a></p>\n",
            esc(url),
            OPENAPI_PATH,
            OPENAPI_PATH
        ));
    }

    // Group operations by their first tag, in the order the document declares
    // the tags, so related endpoints stay together.
    let empty = Vec::new();
    let tags = spec["tags"].as_array().unwrap_or(&empty);
    let paths = match spec["paths"].as_object() {
        Some(p) => p,
        None => return out + "</body></html>\n",
    };

    for tag in tags {
        let name = tag["name"].as_str().unwrap_or("");
        let mut ops: Vec<(&String, &str, &Value)> = Vec::new();
        for (path, methods) in paths {
            for (method, op) in methods.as_object().into_iter().flatten() {
                if op["tags"][0].as_str() == Some(name) {
                    ops.push((path, method.as_str(), op));
                }
            }
        }
        if ops.is_empty() {
            continue;
        }
        ops.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

        out.push_str(&format!("<h2>{}</h2>\n", esc(name)));
        if let Some(d) = tag["description"].as_str() {
            out.push_str(&format!("<p class=\"desc\">{}</p>\n", esc(d)));
        }
        for (path, method, op) in ops {
            out.push_str(&render_operation(path, method, op));
        }
    }

    out.push_str("</body></html>\n");
    out
}

fn render_operation(path: &str, method: &str, op: &Value) -> String {
    let mut out = String::from("<div class=\"op\">");
    out.push_str(&format!(
        "<div class=\"sig\"><span class=\"m {}\">{}</span> {}</div>",
        esc(method),
        esc(&method.to_uppercase()),
        esc(path)
    ));
    if let Some(s) = op["summary"].as_str() {
        out.push_str(&format!("<p class=\"sum\">{}</p>", esc(s)));
    }
    if let Some(d) = op["description"].as_str() {
        out.push_str(&format!("<p class=\"desc\">{}</p>", esc(d)));
    }

    if let Some(params) = op["parameters"].as_array() {
        if !params.is_empty() {
            out.push_str("<table><tr><th>Query</th><th>Type</th><th></th></tr>");
            for p in params {
                let required = p["required"].as_bool().unwrap_or(false);
                out.push_str(&format!(
                    "<tr><td><code>{}</code>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                    esc(p["name"].as_str().unwrap_or("")),
                    if required {
                        " <span class=\"req\">*</span>"
                    } else {
                        ""
                    },
                    esc(&type_of(&p["schema"])),
                    esc(p["description"].as_str().unwrap_or(""))
                ));
            }
            out.push_str("</table>");
        }
    }

    if let Some(content) = op["requestBody"]["content"].as_object() {
        for (mime, body) in content {
            out.push_str(&format!(
                "<table><tr><th>Body</th><th colspan=\"2\"><code>{}</code></th></tr>",
                esc(mime)
            ));
            let required: Vec<&str> = body["schema"]["required"]
                .as_array()
                .map(|r| r.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            match body["schema"]["properties"].as_object() {
                Some(props) => {
                    for (field, schema) in props {
                        out.push_str(&format!(
                            "<tr><td><code>{}</code>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                            esc(field),
                            if required.contains(&field.as_str()) { " <span class=\"req\">*</span>" } else { "" },
                            esc(&type_of(schema)),
                            esc(schema["description"].as_str().unwrap_or(""))
                        ));
                    }
                }
                None => {
                    out.push_str(&format!(
                        "<tr><td colspan=\"3\"><code>{}</code></td></tr>",
                        esc(&type_of(&body["schema"]))
                    ));
                }
            }
            out.push_str("</table>");
        }
    }

    if let Some(responses) = op["responses"].as_object() {
        out.push_str("<table><tr><th>Status</th><th>Type</th><th></th></tr>");
        let mut codes: Vec<&String> = responses.keys().collect();
        codes.sort();
        for code in codes {
            let r = &responses[code];
            let schema = r["content"]
                .as_object()
                .and_then(|c| c.values().next())
                .map(|c| type_of(&c["schema"]))
                .unwrap_or_default();
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                esc(code),
                esc(&schema),
                esc(r["description"].as_str().unwrap_or(""))
            ));
        }
        out.push_str("</table>");
    }

    out.push_str("</div>\n");
    out
}

/// A one-line rendering of a schema: the type name for a `$ref`, the JSON
/// type otherwise.
fn type_of(schema: &Value) -> String {
    if let Some(r) = schema["$ref"].as_str() {
        return r.rsplit('/').next().unwrap_or(r).to_string();
    }
    match schema["type"].as_str() {
        Some("array") => format!("{}[]", type_of(&schema["items"])),
        Some(t) => t.to_string(),
        None => String::new(),
    }
}

/// Who gets the document, through a real app.
///
/// The unit tests above prove the document is right; these prove it reaches
/// the callers it should. The default is everyone — a description is not a
/// credential — and `--openapi-private` is the deployment's way to say
/// otherwise, so both directions are pinned here.
#[cfg(test)]
mod handler_tests {
    use super::*;
    use crate::server::login::login;
    use crate::server::secret::secret_list;
    use crate::state::data::Data;
    use crate::state::store_memory::StoreMemory;
    use crate::util::crypto::{get_new_salt, get_password_hash};
    use actix_web::cookie::Cookie;
    use actix_web::{test, App};

    const BOUNDARY: &str = "----isabelletestboundary";

    fn account(login: &str, admin: bool) -> Item {
        let mut itm = Item::new();
        itm.id = if admin { 1 } else { 2 };
        itm.set_str("login", login);
        itm.set_str("email", &format!("{}@example.org", login));
        itm.set_str("password", &get_password_hash("hunter2", &get_new_salt()));
        itm.set_bool("role_is_active", true);
        if admin {
            itm.set_bool("role_is_admin", true);
        }
        itm
    }

    macro_rules! app_with {
        ($state:expr) => {
            test::init_service(
                App::new()
                    .app_data($state)
                    .wrap(actix_identity::IdentityMiddleware::default())
                    .wrap(
                        actix_session::SessionMiddleware::builder(
                            actix_session::storage::CookieSessionStore::default(),
                            actix_web::cookie::Key::from(&[0u8; 64]),
                        )
                        .cookie_secure(false)
                        .build(),
                    )
                    .route("/login", web::post().to(login))
                    // Stands in for every endpoint the document describes: the
                    // description being public must not make any of them so.
                    .route("/secret/list", web::get().to(secret_list))
                    .route(OPENAPI_PATH, web::get().to(openapi_json))
                    .route(DOCS_PATH, web::get().to(openapi_docs)),
            )
            .await
        };
    }

    fn state(private: bool) -> web::Data<State> {
        let store = StoreMemory::with_collections(&["user"]);
        store.seed("user", account("admin", true));
        store.seed("user", account("bob", false));
        let mut data = Data::new();
        data.rw = Box::new(store);
        data.openapi_private.store(private, Ordering::Relaxed);
        web::Data::new(State::from_data(data))
    }

    /// Log in and hand back the session cookie.
    ///
    /// A macro rather than a function: `init_service` returns an opaque
    /// `impl Service`, and naming that type takes `actix_http` — a crate this
    /// one does not depend on directly.
    macro_rules! sign_in {
        ($app:expr, $username:expr) => {{
            let cookie = sign_in_body($username);
            let res = test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/login")
                    .insert_header((
                        "content-type",
                        format!("multipart/form-data; boundary={}", BOUNDARY),
                    ))
                    .set_payload(cookie)
                    .to_request(),
            )
            .await;
            let raw = res
                .response()
                .cookies()
                .find(|c| c.name() == "id")
                .expect("no session cookie was issued");
            Cookie::new(raw.name().to_string(), raw.value().to_string())
        }};
    }

    fn sign_in_body(username: &str) -> String {
        format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n{u}\r\n\
             --{b}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n\
             --{b}--\r\n",
            b = BOUNDARY,
            u = username
        )
    }

    /// The default: no session, and the document is served anyway. The
    /// `Identity` extractor refuses an anonymous caller outright, so this also
    /// pins that the handlers take an `Option` — with a bare `Identity` the
    /// endpoint would be admin-only no matter what the flag said.
    #[actix_web::test]
    async fn the_document_is_public_by_default() {
        let app = app_with!(state(false));

        let body = test::call_and_read_body(
            &app,
            test::TestRequest::get().uri(OPENAPI_PATH).to_request(),
        )
        .await;
        let spec: Value = serde_json::from_slice(&body).expect("the document is not JSON");
        assert_eq!(spec["openapi"], "3.1.0");
        assert!(spec["paths"]["/login"]["post"].is_object());
        assert_eq!(
            spec["paths"]["/itm/list"]["get"]["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == "collection")
                .unwrap()["schema"]["enum"],
            json!(["user"])
        );
        // And it says of itself that it needs no session.
        assert_eq!(spec["paths"][OPENAPI_PATH]["get"]["security"][0], json!({}));

        let res =
            test::call_service(&app, test::TestRequest::get().uri(DOCS_PATH).to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(
            res.headers().get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
    }

    /// Publishing the description must not publish anything else: the
    /// endpoints it names still turn away callers who have no business there.
    #[actix_web::test]
    async fn a_public_document_does_not_open_the_endpoints_it_describes() {
        let app = app_with!(state(false));
        let res = test::call_service(
            &app,
            test::TestRequest::get().uri("/secret/list").to_request(),
        )
        .await;
        assert_eq!(res.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    /// With `--openapi-private`, both endpoints go back to being admin-only.
    #[actix_web::test]
    async fn openapi_private_closes_both_endpoints() {
        let app = app_with!(state(true));

        for path in [OPENAPI_PATH, DOCS_PATH] {
            let res =
                test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
            assert_eq!(
                res.status(),
                actix_web::http::StatusCode::UNAUTHORIZED,
                "{} was served to an anonymous caller",
                path
            );
        }

        let bob = sign_in!(app, "bob");
        for path in [OPENAPI_PATH, DOCS_PATH] {
            let res = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(path)
                    .cookie(bob.clone())
                    .to_request(),
            )
            .await;
            assert_eq!(
                res.status(),
                actix_web::http::StatusCode::FORBIDDEN,
                "{} was served to a logged-in non-admin",
                path
            );
        }

        let admin = sign_in!(app, "admin");
        let body = test::call_and_read_body(
            &app,
            test::TestRequest::get()
                .uri(OPENAPI_PATH)
                .cookie(admin)
                .to_request(),
        )
        .await;
        let spec: Value = serde_json::from_slice(&body).expect("the document is not JSON");
        assert_eq!(spec["openapi"], "3.1.0");
        // And it says so about itself, rather than still claiming to be public.
        assert!(spec["paths"][OPENAPI_PATH]["get"]["security"].is_null());
        assert!(spec["paths"][DOCS_PATH]["get"]["responses"]["403"].is_object());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn internals_with(category: &str, specs: &[&str]) -> Item {
        let mut it = Item::new();
        let inner: HashMap<String, String> = specs
            .iter()
            .enumerate()
            .map(|(i, s)| (i.to_string(), s.to_string()))
            .collect();
        it.strstrs.insert(category.to_string(), inner);
        it
    }

    /// The three route tables `run()` reads have to be the three this reads,
    /// and each has to keep its own kind — an unprotected route documented as
    /// protected tells a client to authenticate where it need not, and the
    /// reverse tells it the opposite.
    #[test]
    fn routes_are_read_from_all_three_tables() {
        let mut it = Item::new();
        for (cat, spec) in [
            ("extra_route", "/a:get:handler_a"),
            ("extra_unprotected_route", "/b:post:handler_b"),
            ("extra_rest_route", "/c:post:handler_c"),
        ] {
            let mut inner = HashMap::new();
            inner.insert("1".to_string(), spec.to_string());
            it.strstrs.insert(cat.to_string(), inner);
        }

        let routes = plugin_routes(&it);
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].path, "/a");
        assert_eq!(routes[0].kind, RouteKind::Protected);
        assert_eq!(routes[0].method, "get");
        assert_eq!(routes[1].kind, RouteKind::Unprotected);
        assert_eq!(routes[2].kind, RouteKind::Rest);
        assert_eq!(routes[2].handler, "handler_c");
    }

    /// `run()` registers a route only when the method is exactly `"get"` or
    /// `"post"`, and skips specs with too few segments. Documenting a path
    /// that was never registered sends clients at a 404.
    #[test]
    fn only_the_specs_run_would_register_are_documented() {
        let it = internals_with(
            "extra_route",
            &[
                "/ok:get:handler",
                "/upper:GET:handler", // run() compares against "get" literally
                "/nomethod:handler",  // two segments
                ":get:handler",       // no path
                "/nohandler:get:",    // no handler
                "/put:put:handler",   // run() registers neither verb
            ],
        );

        let routes = plugin_routes(&it);
        assert_eq!(routes.len(), 1, "documented: {:?}", routes);
        assert_eq!(routes[0].path, "/ok");
    }

    /// `internals.strstrs` is a `HashMap`, so two fetches of the document must
    /// not disagree about the order of the paths in it.
    #[test]
    fn route_order_is_stable() {
        let it = internals_with(
            "extra_route",
            &["/c:get:h", "/a:get:h", "/b:post:h", "/a:post:h"],
        );
        let paths: Vec<(String, String)> = plugin_routes(&it)
            .into_iter()
            .map(|r| (r.path, r.method))
            .collect();
        assert_eq!(
            paths,
            vec![
                ("/a".to_string(), "get".to_string()),
                ("/a".to_string(), "post".to_string()),
                ("/b".to_string(), "post".to_string()),
                ("/c".to_string(), "get".to_string()),
            ]
        );
    }

    /// A plugin route lands in the document under its own path and verb,
    /// beside core's, rather than replacing anything.
    #[test]
    fn plugin_routes_join_the_core_ones() {
        let routes = plugin_routes(&internals_with(
            "extra_unprotected_route",
            &["/plugin/ping:get:ping"],
        ));
        let spec = build_spec(
            "https://app.example.com",
            &["user".to_string()],
            &routes,
            false,
        );

        assert!(spec["paths"]["/itm/list"]["get"].is_object());
        assert_eq!(
            spec["paths"]["/plugin/ping"]["get"]["summary"]
                .as_str()
                .unwrap(),
            "Plugin route → `ping`"
        );
        assert_eq!(spec["servers"][0]["url"], "https://app.example.com");
    }

    /// Two routes on one path with different verbs are two operations on one
    /// path item, not one overwriting the other.
    #[test]
    fn one_path_can_carry_both_verbs() {
        let routes = plugin_routes(&internals_with(
            "extra_rest_route",
            &["/api/thing:get:read", "/api/thing:post:write"],
        ));
        let spec = build_spec("", &[], &routes, false);
        assert!(spec["paths"]["/api/thing"]["get"].is_object());
        assert!(spec["paths"]["/api/thing"]["post"].is_object());
    }

    /// Protected plugin routes must not be marked as callable without a
    /// session, and unprotected ones must be.
    #[test]
    fn security_follows_the_route_table() {
        let mut it = Item::new();
        for (cat, spec) in [
            ("extra_route", "/private:get:h"),
            ("extra_unprotected_route", "/public:get:h"),
        ] {
            let mut inner = HashMap::new();
            inner.insert("1".to_string(), spec.to_string());
            it.strstrs.insert(cat.to_string(), inner);
        }
        let spec = build_spec("", &[], &plugin_routes(&it), false);

        // No override means the document-wide `sessionCookie` requirement.
        assert!(spec["paths"]["/private"]["get"]["security"].is_null());
        assert!(spec["paths"]["/private"]["get"]["responses"]["401"].is_object());

        // `{}` in the list is "no security applies".
        assert_eq!(
            spec["paths"]["/public"]["get"]["security"][0],
            json!({}),
            "an unprotected route was documented as needing a session"
        );
    }

    /// The `collection` parameter is constrained to what the store actually
    /// holds — anything else is answered 400 by the handlers.
    #[test]
    fn collections_constrain_the_collection_parameter() {
        let spec = build_spec("", &["user".to_string(), "node".to_string()], &[], false);
        let params = spec["paths"]["/itm/list"]["get"]["parameters"]
            .as_array()
            .unwrap();
        let collection = params
            .iter()
            .find(|p| p["name"] == "collection")
            .expect("no collection parameter");
        assert_eq!(collection["schema"]["enum"], json!(["node", "user"]));
        assert_eq!(collection["required"], json!(true));

        // With no collections known, the parameter stays an unconstrained string.
        let empty = build_spec("", &[], &[], false);
        let params = empty["paths"]["/itm/list"]["get"]["parameters"]
            .as_array()
            .unwrap();
        let collection = params.iter().find(|p| p["name"] == "collection").unwrap();
        assert!(collection["schema"]["enum"].is_null());
    }

    /// Client generators name their methods after `operationId`, so every
    /// operation needs one and no two may share it.
    #[test]
    fn every_operation_has_a_unique_id() {
        let routes = plugin_routes(&internals_with(
            "extra_route",
            // Two paths that normalize to the same identifier: the second has
            // to be broken apart rather than overwriting the first.
            &["/a-b:get:h", "/a_b:get:h", "/a/b:post:h"],
        ));
        let spec = build_spec("", &["user".to_string()], &routes, false);

        let mut ids: Vec<&str> = Vec::new();
        for (path, methods) in spec["paths"].as_object().unwrap() {
            for (method, op) in methods.as_object().unwrap() {
                let id = op["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{} {} has no operationId", method, path));
                ids.push(id);
            }
        }
        assert_eq!(spec["paths"]["/a/b"]["post"]["operationId"], "post_a_b");

        let total = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "two operations share an operationId");
    }

    /// Every `$ref` in the document has to resolve, or the whole thing is
    /// unusable in any tool that reads it.
    #[test]
    fn every_ref_resolves() {
        let routes = plugin_routes(&internals_with("extra_route", &["/x:post:h"]));
        let spec = build_spec("https://example.org", &["user".to_string()], &routes, false);
        let schemas = spec["components"]["schemas"].as_object().unwrap();

        fn collect_refs(v: &Value, into: &mut Vec<String>) {
            match v {
                Value::Object(map) => {
                    for (k, val) in map {
                        if k == "$ref" {
                            if let Some(s) = val.as_str() {
                                into.push(s.to_string());
                            }
                        }
                        collect_refs(val, into);
                    }
                }
                Value::Array(items) => items.iter().for_each(|i| collect_refs(i, into)),
                _ => {}
            }
        }

        let mut refs = Vec::new();
        collect_refs(&spec, &mut refs);
        assert!(
            !refs.is_empty(),
            "the document has no schema references at all"
        );
        for r in refs {
            let name = r
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("unexpected reference form: {}", r));
            assert!(schemas.contains_key(name), "dangling reference: {}", r);
        }
    }

    /// Descriptions carry `<`, `>` and `&`, and the page is served to an
    /// administrator's browser: a route path or a handler name from
    /// `internals.js` must not be able to become markup.
    #[test]
    fn the_rendered_page_escapes_what_it_prints() {
        let routes = plugin_routes(&internals_with(
            "extra_unprotected_route",
            &["/x<script>alert(1)</script>:get:h"],
        ));
        let html = render_html(&build_spec("", &[], &routes, false));
        assert!(
            !html.contains("<script>"),
            "an injected tag survived into the page"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    /// The page has to show every operation the document has, or reading it
    /// gives a false picture of the API.
    #[test]
    fn the_rendered_page_lists_every_operation() {
        let routes = plugin_routes(&internals_with("extra_route", &["/plugin/x:post:h"]));
        let spec = build_spec("", &["user".to_string()], &routes, false);
        let html = render_html(&spec);

        for (path, methods) in spec["paths"].as_object().unwrap() {
            for method in methods.as_object().unwrap().keys() {
                assert!(
                    html.contains(&esc(path)),
                    "{} {} is missing from the page",
                    method,
                    path
                );
            }
        }
        // And nothing is loaded from anywhere else. The page is served to an
        // administrator's browser on this origin, so a CDN script tag would be
        // third-party code running with the most privileged session on the
        // deployment.
        assert!(!html.contains("<script"));
        assert!(!html.contains("src="));
        assert!(!html.contains("href=\"http"));
    }
}
