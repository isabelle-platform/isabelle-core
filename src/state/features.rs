/*
 * Isabelle project
 *
 * Copyright 2023-2026 Maxim Menshikov
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

//! What this deployment is allowed to do, declared on disk.
//!
//! `features.js` sits in the data directory beside `settings.js` and
//! `internals.js`, and it is the one configuration file core never writes.
//! That is the whole point of it: which features a deployment has is a
//! decision taken outside the running system — by whoever installs it — and a
//! decision nothing reachable over HTTP can revise. There is no edit endpoint
//! and no store method that writes one, so an administrator's session, a
//! leaked token and a plugin are all equally unable to grant a feature that
//! was not granted on disk.
//!
//! The file is a JSON object: each key is a feature name, and its value is
//! whatever the feature wants to say about itself.
//!
//! ```json
//! {
//!   "reports": { "formats": ["pdf", "csv"], "retention_days": 90 },
//!   "sso": true,
//!   "beta_ui": null
//! }
//! ```
//!
//! Core reads exactly one thing out of that: the set of keys. The values are
//! carried through untouched and handed to plugins, which is why the shape of
//! a descriptor is nobody's business but the feature's own — core has no
//! schema to violate and no opinion to become wrong. Over HTTP only the names
//! are served; see `server::feature`.
//!
//! # Reaching it from a plugin
//!
//! Inside core, `Data::features()` hands back the whole document. A plugin
//! asks for it over the actor channel — `CoreHandle::features_all()`, with
//! `features_get`, `features_has` and `features_list` on top of it — which
//! core answers from the same loaded copy in `state::core_task`. There is no
//! message that writes one, so a plugin can read the deployment's feature
//! set and cannot widen it.
//!
//! # An unreadable file lists nothing
//!
//! A missing, truncated or non-object `features.js` yields an empty set, and
//! an empty set means no feature is declared. That is the opposite of the
//! fallback `settings.js` gets — an empty settings item means *defaults*,
//! which is harmless, whereas an empty feature list means *nothing is
//! permitted*, and permitting things because a file failed to parse is not a
//! failure mode worth having. So the direction is deliberate, and the loud
//! log line on the way is what tells an operator that a deployment which
//! should have features has none.

use log::{error, info, warn};
use serde_json::Value;
use std::collections::BTreeMap;

/// The file, relative to the data directory.
pub const FILE_NAME: &str = "features.js";

/// The features a deployment declares, with their descriptors.
///
/// `BTreeMap` rather than `HashMap`: the names go out over the API, and a
/// list whose order changes between two calls that read the same file is a
/// diff in somebody's UI test for no reason at all.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Features {
    map: BTreeMap<String, Value>,
}

impl Features {
    /// An empty set — no feature is declared.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read `<data_path>/features.js`.
    ///
    /// Never fails: every way of not having a usable file ends in an empty
    /// set and a log line. A parse error is `error!` because somebody edited
    /// the file and got it wrong and would like to know; a missing file is
    /// `warn!` because it is both the untouched-install case and the case
    /// where an update forgot to carry the file over, and only the operator
    /// can tell those apart.
    pub fn load(data_path: &str) -> Self {
        let path = format!("{}/{}", data_path.trim_end_matches('/'), FILE_NAME);
        match crate::util::fs::read_json::<Value>(&path) {
            Ok(Value::Object(map)) => Self {
                map: map.into_iter().collect(),
            },
            Ok(other) => {
                error!(
                    "{} is {}, not an object of feature name → descriptor; \
                     continuing with no features",
                    path,
                    type_name_of(&other)
                );
                Self::new()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!("No {}; this deployment declares no features", path);
                Self::new()
            }
            Err(e) => {
                error!("Unreadable {} ({}); continuing with no features", path, e);
                Self::new()
            }
        }
    }

    /// Build from already-parsed entries. For tests and for a caller that
    /// obtained the document some other way.
    pub fn from_map(map: BTreeMap<String, Value>) -> Self {
        Self { map }
    }

    /// The declared feature names, sorted.
    ///
    /// This is the whole of what the HTTP API serves, so it is the one view
    /// that must not accidentally start carrying descriptors with it.
    pub fn names(&self) -> Vec<&str> {
        self.map.keys().map(|k| k.as_str()).collect()
    }

    /// Whether a feature is declared at all.
    pub fn has(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    /// One feature's descriptor, exactly as the file spells it.
    ///
    /// `None` means the feature is not declared. A declared feature whose
    /// descriptor is `null` answers `Some(Value::Null)` — the file said
    /// something, and it said nothing in particular.
    pub fn descriptor(&self, name: &str) -> Option<&Value> {
        self.map.get(name)
    }

    /// Every feature and its descriptor. What plugins get.
    pub fn all(&self) -> &BTreeMap<String, Value> {
        &self.map
    }

    /// How many features are declared.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// What a JSON value is, for a message an operator has to act on.
fn type_name_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Log what was loaded, at startup.
pub fn log_summary(features: &Features) {
    if features.is_empty() {
        info!("Features: none declared");
    } else {
        info!(
            "Features: {} declared ({})",
            features.len(),
            features.names().join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    /// Write a `features.js` into a fresh directory and load it back.
    fn loaded(contents: &str) -> Features {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), contents).unwrap();
        Features::load(&dir.path().to_string_lossy())
    }

    /// The descriptor is the feature's own business: core stores whatever
    /// JSON is there and hands it back unchanged. If this ever starts
    /// coercing values into a shape, a deployment's feature file silently
    /// stops meaning what it says.
    #[test]
    fn a_descriptor_may_be_any_json_at_all() {
        let f = loaded(
            r#"{
                "reports": { "formats": ["pdf", "csv"], "limits": { "rows": 10000 } },
                "sso": true,
                "seats": 25,
                "tier": "enterprise",
                "regions": ["eu", "us"],
                "beta_ui": null
            }"#,
        );

        assert_eq!(
            f.names(),
            vec!["beta_ui", "regions", "reports", "seats", "sso", "tier"]
        );
        assert_eq!(
            f.descriptor("reports"),
            Some(&json!({ "formats": ["pdf", "csv"], "limits": { "rows": 10000 } }))
        );
        assert_eq!(f.descriptor("sso"), Some(&json!(true)));
        assert_eq!(f.descriptor("seats"), Some(&json!(25)));
        assert_eq!(f.descriptor("tier"), Some(&json!("enterprise")));
        assert_eq!(f.descriptor("regions"), Some(&json!(["eu", "us"])));
        assert_eq!(f.descriptor("beta_ui"), Some(&Value::Null));
    }

    /// A declared feature with a `null` descriptor is still declared. The
    /// distinction is the reason `descriptor` returns an `Option` of a value
    /// rather than flattening both cases into "nothing there".
    #[test]
    fn a_null_descriptor_is_not_an_absent_feature() {
        let f = loaded(r#"{ "beta_ui": null }"#);
        assert!(f.has("beta_ui"));
        assert_eq!(f.descriptor("beta_ui"), Some(&Value::Null));
        assert!(!f.has("something_else"));
        assert_eq!(f.descriptor("something_else"), None);
    }

    /// Every way of not having a usable file means the same thing, and it is
    /// the safe thing: no feature is declared. Permitting features because a
    /// file failed to parse is the failure this direction rules out.
    #[test]
    fn nothing_is_declared_when_the_file_cannot_be_used() {
        // Missing entirely.
        let dir = tempdir().unwrap();
        assert!(Features::load(&dir.path().to_string_lossy()).is_empty());

        // Truncated mid-write — what a non-atomic writer used to leave.
        assert!(loaded(r#"{ "reports": { "formats": ["pd"#).is_empty());

        // Valid JSON, wrong shape. Each of these is a plausible mistake:
        // a list of names, a single name, a flag, an empty document.
        for wrong in [r#"["reports", "sso"]"#, r#""reports""#, "true", "null"] {
            let f = loaded(wrong);
            assert!(f.is_empty(), "{} was accepted as a feature set", wrong);
        }
    }

    /// An empty object is a deployment that deliberately declares nothing,
    /// and it must load cleanly rather than being lumped in with the broken
    /// files above.
    #[test]
    fn an_empty_object_is_a_valid_empty_declaration() {
        let f = loaded("{}");
        assert!(f.is_empty());
        assert_eq!(f.names(), Vec::<&str>::new());
    }

    /// The names go out over the API, so their order is part of the answer.
    /// Two loads of the same file must not disagree about it.
    #[test]
    fn names_come_back_in_a_stable_order() {
        let contents = r#"{ "zeta": 1, "alpha": 2, "Mixed": 3, "beta": 4 }"#;
        let first = loaded(contents);
        let second = loaded(contents);
        assert_eq!(first.names(), second.names());
        assert_eq!(first.names(), vec!["Mixed", "alpha", "beta", "zeta"]);
    }

    /// A trailing slash on the data path must not produce `//features.js`.
    #[test]
    fn the_data_path_may_end_in_a_slash() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), r#"{ "sso": true }"#).unwrap();
        let with_slash = Features::load(&(dir.path().to_string_lossy().into_owned() + "/"));
        assert!(with_slash.has("sso"));
    }
}
