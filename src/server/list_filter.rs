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
//! Validation of the query filter `/itm/list` accepts from a client.
//!
//! The listing endpoint used to pass the caller's `filter` string straight
//! into `json_to_bson`, which accepts any Mongo query document. That made the
//! endpoint a general-purpose query oracle over every collection: the response
//! carries `total_count`, computed by `count_documents` on the caller's query
//! *before* any `itm_list_filter_hook` gets to redact the returned items, so
//! filtering on a field the caller may not read still leaks whether — and how
//! many — documents match it. Character by character, that reconstructs a live
//! OTP or a stored credential without ever reading a single item body.
//!
//! Filters produced by plugins (`itm_list_db_filter_hook`) are server-side
//! code and stay unrestricted; only the client-supplied string goes through
//! here.
//!
//! Two independent restrictions, both required to pass:
//!
//!   * **Shape.** Only the query forms the UI actually builds: boolean
//!     combinators over leaves, each leaf a field compared to a scalar with a
//!     comparison operator, or to a list of scalars with a membership one.
//!     This rejects `$regex`, `$where`, `$expr`, `$function`, `$text` and
//!     friends outright.
//!   * **Field.** No field whose name looks like a credential, in any
//!     collection.
//!
//! The field rule is a denylist, which is the weaker of the two designs — a
//! new secret-bearing field named outside these patterns would not be covered.
//! The robust version is a per-collection allowlist of filterable fields
//! declared in `internals.js`; until that exists, the shape restriction is
//! what keeps the damage bounded, since equality and range comparisons on a
//! field the attacker must already be able to name is a far cry from `$regex`
//! over anything.

use isabelle_dm::data_model::item::Item;
use serde_json::Value;

/// Boolean combinators a client filter may use. Both take an array of
/// sub-filters and neither can express a computation.
const ALLOWED_COMBINATORS: [&str; 2] = ["$and", "$or"];

/// Comparison operators allowed inside a leaf. Deliberately excludes every
/// operator that can evaluate an expression or a pattern (`$regex`, `$where`,
/// `$expr`, `$function`, `$jsonSchema`, `$text`, `$mod`, …).
const ALLOWED_LEAF_OPS: [&str; 6] = ["$eq", "$ne", "$gt", "$gte", "$lt", "$lte"];

/// Membership operators, which take a list of scalars instead of one. They say
/// no more than a chain of `$eq` joined by `$or` would, and the UI needs them:
/// "these projects" is one selection, not one project.
const ALLOWED_SET_OPS: [&str; 2] = ["$in", "$nin"];

/// Cap on how many values a membership test may name. A filter is a query
/// string; without a bound it is also an unbounded allocation, and no honest
/// selection in this UI is anywhere near this long.
const MAX_SET_OPERANDS: usize = 256;

/// Substrings that mark a field as credential-bearing. Matched against each
/// dot-separated segment of the field path, case-insensitively.
///
/// `key` alone is deliberately absent: real fields like `engine_key_status`,
/// `ssh_keyless` and `installed_keyless` are ordinary status flags, and
/// blocking them would break legitimate filtering while protecting nothing.
const CREDENTIAL_MARKERS: [&str; 9] = [
    "password",
    "passwd",
    "secret",
    "token",
    "salt",
    "otp",
    "api_key",
    "apikey",
    "credential",
];

/// Nesting limit for combinators. The UI builds a single `$and` of leaves;
/// anything deeper is a caller doing something the UI never does.
const MAX_DEPTH: usize = 4;

/// Whether a field name names a credential, by the same rule the filter guard
/// uses to decide what a client may not filter on.
///
/// A name a client is not allowed to *ask about* is a name it should not be
/// *handed* either, so both live off `CREDENTIAL_MARKERS` and cannot drift.
fn is_credential_field(name: &str) -> bool {
    let lowered = name.to_lowercase();
    CREDENTIAL_MARKERS.iter().any(|m| lowered.contains(m))
}

/// Remove every credential-bearing field from an item, across all its typed
/// maps.
///
/// `/itm/list` serves the `user` collection like any other, so an ordinary
/// logged-in account could read every account in full: `strs.password` (the
/// Argon2 hash — offline cracking material for everyone), `strs.otp` (a live
/// second credential while it lasts), `otp_expires_at`, every role flag.
/// Redaction was left to `itm_list_filter_hook`, which is to say to a plugin
/// a stock deployment does not have.
///
/// Removing rather than masking is safe here because the caller this runs for
/// is neither the record's owner nor an admin, so it has no write path that
/// could round-trip the item back and blank the real value.
pub fn redact_credentials(itm: &mut Item) {
    itm.strs.retain(|k, _| !is_credential_field(k));
    itm.strstrs.retain(|k, _| !is_credential_field(k));
    itm.strids.retain(|k, _| !is_credential_field(k));
    itm.bools.retain(|k, _| !is_credential_field(k));
    itm.u64s.retain(|k, _| !is_credential_field(k));
    itm.ids.retain(|k, _| !is_credential_field(k));
}

/// Whether a client may name this field in a filter or as a sort key.
///
/// Rejects credential-bearing names, operator-looking names (a `$` anywhere
/// would be interpreted by Mongo rather than treated as a path), and the
/// empty path.
pub fn field_is_allowed(path: &str) -> bool {
    if path.is_empty() || path.contains('$') {
        return false;
    }
    let lowered = path.to_lowercase();
    for segment in lowered.split('.') {
        if segment.is_empty() {
            return false;
        }
        if CREDENTIAL_MARKERS.iter().any(|m| segment.contains(m)) {
            return false;
        }
    }
    true
}

/// Validate a client-supplied filter string.
///
/// An empty filter means "no filter" and is accepted. Returns `Err` with a
/// reason meant for the server log — the client is told only that its filter
/// was rejected, so this cannot be used to probe which fields exist.
pub fn validate_client_filter(filter: &str) -> Result<(), String> {
    if filter.trim().is_empty() {
        return Ok(());
    }

    let parsed: Value = match serde_json::from_str(filter) {
        Ok(v) => v,
        Err(e) => return Err(format!("filter is not valid JSON: {}", e)),
    };

    validate_node(&parsed, 0)
}

fn validate_node(node: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("filter nested deeper than {} levels", MAX_DEPTH));
    }

    let obj = match node.as_object() {
        Some(o) => o,
        None => return Err("filter node is not an object".to_string()),
    };

    for (key, value) in obj {
        if key.starts_with('$') {
            if !ALLOWED_COMBINATORS.contains(&key.as_str()) {
                return Err(format!("operator {} is not allowed", key));
            }
            let branches = match value.as_array() {
                Some(a) => a,
                None => return Err(format!("{} expects an array", key)),
            };
            if branches.is_empty() {
                return Err(format!("{} expects a non-empty array", key));
            }
            for branch in branches {
                validate_node(branch, depth + 1)?;
            }
        } else {
            if !field_is_allowed(key) {
                return Err(format!("field {} may not be filtered on", key));
            }
            validate_leaf_value(key, value)?;
        }
    }

    Ok(())
}

/// A leaf compares a field either to a scalar directly, or to a scalar through
/// a comparison operator. Anything else — an array, a nested document, an
/// unknown operator — is rejected.
fn validate_leaf_value(field: &str, value: &Value) -> Result<(), String> {
    if is_scalar(value) {
        return Ok(());
    }

    let obj = match value.as_object() {
        Some(o) => o,
        None => return Err(format!("field {} compared to a non-scalar", field)),
    };

    if obj.is_empty() {
        return Err(format!("field {} has an empty comparison", field));
    }

    for (op, operand) in obj {
        if ALLOWED_SET_OPS.contains(&op.as_str()) {
            let items = match operand.as_array() {
                Some(a) => a,
                None => {
                    return Err(format!("operator {} on {} expects a list", op, field));
                }
            };
            if items.len() > MAX_SET_OPERANDS {
                return Err(format!(
                    "operator {} on {} names {} values, more than the {} allowed",
                    op,
                    field,
                    items.len(),
                    MAX_SET_OPERANDS
                ));
            }
            if !items.iter().all(is_scalar) {
                return Err(format!(
                    "operator {} on {} expects a list of scalars",
                    op, field
                ));
            }
            continue;
        }
        if !ALLOWED_LEAF_OPS.contains(&op.as_str()) {
            return Err(format!("operator {} is not allowed on {}", op, field));
        }
        if !is_scalar(operand) {
            return Err(format!("operator {} on {} expects a scalar", op, field));
        }
    }

    Ok(())
}

fn is_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// A user record as the database holds it: the hash, a live one-time
    /// code and its bookkeeping, alongside the fields a listing legitimately
    /// shows.
    fn stored_user() -> Item {
        let mut itm = Item::new();
        itm.id = 7;
        itm.set_str("login", "alice");
        itm.set_str("email", "alice@example.org");
        itm.set_str("password", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA");
        itm.set_str("otp", "123456789");
        itm.set_str("salt", "c2FsdA");
        itm.set_str("api_key", "ak_live_1");
        itm.set_u64("otp_expires_at", 1_800_000_000);
        itm.set_u64("otp_attempts", 0);
        itm.set_bool("role_is_admin", true);
        itm.set_bool("role_is_active", true);
        itm
    }

    /// Everything an attacker wanted out of `GET /itm/list?collection=user`:
    /// offline cracking material for every account, and a live second
    /// credential for any account with an outstanding code.
    #[test]
    fn credentials_do_not_survive_redaction() {
        let mut itm = stored_user();
        redact_credentials(&mut itm);
        for gone in ["password", "otp", "salt", "api_key"] {
            assert!(
                !itm.strs.contains_key(gone),
                "strs.{} was still served",
                gone
            );
        }
        // The OTP bookkeeping is part of the code's state and goes with it.
        assert!(!itm.u64s.contains_key("otp_expires_at"));
        assert!(!itm.u64s.contains_key("otp_attempts"));
    }

    /// Redaction has to leave a usable record behind — a listing that shows
    /// no name is not a listing.
    #[test]
    fn ordinary_fields_survive_redaction() {
        let mut itm = stored_user();
        redact_credentials(&mut itm);
        assert_eq!(itm.id, 7);
        assert_eq!(itm.safe_str("login", ""), "alice");
        assert_eq!(itm.safe_str("email", ""), "alice@example.org");
        assert!(itm.safe_bool("role_is_admin", false));
        assert!(itm.safe_bool("role_is_active", false));
    }

    /// The two rules are driven by one list, so a name a client may not
    /// filter on is a name it is not handed either. If they ever diverge,
    /// the filter guard becomes the only defence again.
    #[test]
    fn what_cannot_be_filtered_on_cannot_be_read() {
        for field in [
            "password",
            "passwd",
            "secret_value",
            "token",
            "salt",
            "otp",
            "api_key",
            "apikey",
            "credential",
        ] {
            assert!(
                !field_is_allowed(&format!("strs.{}", field)),
                "{} is filterable",
                field
            );
            let mut itm = Item::new();
            itm.set_str(field, "x");
            redact_credentials(&mut itm);
            assert!(
                itm.strs.is_empty(),
                "{} is filter-guarded but still served",
                field
            );
        }
    }

    /// `key` is deliberately not a marker — `engine_key_status` and friends
    /// are ordinary status flags, and stripping them would quietly break
    /// listings while protecting nothing.
    #[test]
    fn status_flags_that_merely_mention_keys_are_kept() {
        let mut itm = Item::new();
        itm.set_bool("engine_key_status", true);
        itm.set_bool("ssh_keyless", true);
        redact_credentials(&mut itm);
        assert_eq!(itm.bools.len(), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_takes_a_list_of_scalars_and_nothing_else() {
        assert!(validate_client_filter("{\"ids.workspace\":{\"$in\":[1,\"a\",true]}}").is_ok());
        assert!(
            validate_client_filter("{\"ids.workspace\":{\"$in\":3}}").is_err(),
            "a bare scalar is not a list"
        );
        assert!(
            validate_client_filter("{\"ids.workspace\":{\"$in\":[{\"$ne\":1}]}}").is_err(),
            "a document inside the list would smuggle an operator back in"
        );
        assert!(
            validate_client_filter("{\"ids.workspace\":{\"$in\":[[1,2]]}}").is_err(),
            "nested arrays are not scalars either"
        );
    }

    /// A filter arrives as a query string; the list it names must stay bounded.
    #[test]
    fn a_membership_list_is_capped() {
        let ids: Vec<String> = (0..MAX_SET_OPERANDS + 1).map(|i| i.to_string()).collect();
        let filter = format!("{{\"ids.workspace\":{{\"$in\":[{}]}}}}", ids.join(","));
        assert!(validate_client_filter(&filter).is_err());
    }

    /// The exact shapes the midair UI builds (test list and analysis list
    /// filter panels). If any of these stop validating, the UI breaks.
    #[test]
    fn filters_built_by_the_ui_are_accepted() {
        assert!(validate_client_filter("").is_ok());
        assert!(validate_client_filter("{\"ids.workspace\":3}").is_ok());
        // The project scope in the top bar: several workspaces at once.
        assert!(validate_client_filter("{\"ids.workspace\":{\"$in\":[1,2,3]}}").is_ok());
        assert!(
            validate_client_filter("{\"strids.workspaces\":{\"$in\":[4]}}").is_ok(),
            "a device names its projects as a list"
        );
        assert!(validate_client_filter("{\"u64s.time\":{\"$gte\":1700000000}}").is_ok());
        assert!(validate_client_filter(
            "{\"$and\":[{\"u64s.time\":{\"$gte\":1700000000}},\
             {\"u64s.time\":{\"$lt\":1700086400}},{\"ids.user\":7}]}"
        )
        .is_ok());
        // The analysis page emits the same thing with padding whitespace.
        assert!(validate_client_filter("{ \"$and\": [ { \"ids.user\": 7 } ] }").is_ok());
    }

    /// The attack this module exists to stop: extracting a live OTP one
    /// character at a time by reading `total_count`.
    #[test]
    fn otp_probing_is_rejected() {
        assert!(validate_client_filter("{\"strs.otp\":{\"$regex\":\"^1\"}}").is_err());
        // Regex banned, but so is the field — equality and ordering probes on
        // a credential must fail on their own.
        assert!(validate_client_filter("{\"strs.otp\":\"123456789\"}").is_err());
        assert!(validate_client_filter("{\"strs.otp\":{\"$gte\":\"5\"}}").is_err());
    }

    /// Ordering comparisons on a string field are a binary search, so a
    /// password hash must be unreachable even without `$regex`.
    #[test]
    fn credential_fields_are_rejected_everywhere() {
        for field in [
            "strs.password",
            "strs.salt",
            "strs.deploy_password",
            "strs.ts_git_password",
            "strs.bublik_ssh_password",
            "strs.ai_claude_api_key",
            "strs.delta_token",
            "strs.horizon_api_token",
            "strs.otp_expires_at",
        ] {
            let filter = format!("{{\"{}\":{{\"$gte\":\"a\"}}}}", field);
            assert!(
                validate_client_filter(&filter).is_err(),
                "{} should be rejected",
                field
            );
            assert!(!field_is_allowed(field), "{} should be rejected", field);
        }
    }

    /// Sort keys the UI actually passes. `itm_list` rejects the request
    /// outright when one of these fails, so a false positive here is an
    /// immediately visible breakage.
    ///
    /// They are stored field paths rather than bare names because that is
    /// what the sort has to address: `get_items` hands the key straight to
    /// Mongo, and documents keep their fields under `strs`/`u64s`/`ids`. A
    /// bare `"name"` names a top-level field no document has, which sorts
    /// everything equal and makes `skip`/`limit` paging undefined.
    #[test]
    fn sort_keys_used_by_the_ui_are_accepted() {
        for key in ["strs.name", "u64s.time", "id"] {
            assert!(field_is_allowed(key), "{} should be allowed", key);
        }
    }

    /// Status flags that merely contain "key" are ordinary fields.
    #[test]
    fn key_lookalike_fields_stay_filterable() {
        assert!(field_is_allowed("strs.engine_key_status"));
        assert!(field_is_allowed("bools.ssh_keyless"));
        assert!(field_is_allowed("bools.installed_keyless"));
    }

    #[test]
    fn case_does_not_evade_the_field_rule() {
        assert!(!field_is_allowed("strs.PassWord"));
        assert!(!field_is_allowed("strs.OTP"));
    }

    /// Every operator that can evaluate an expression or a pattern.
    #[test]
    fn evaluation_operators_are_rejected() {
        for filter in [
            "{\"$where\":\"this.strs.otp[0]=='1'\"}",
            "{\"strs.name\":{\"$regex\":\"^a\"}}",
            "{\"$expr\":{\"$eq\":[\"$strs.name\",\"a\"]}}",
            "{\"strs.name\":{\"$function\":{\"body\":\"f\"}}}",
            "{\"$text\":{\"$search\":\"a\"}}",
            "{\"strs.name\":{\"$exists\":true}}",
            "{\"strs.name\":{\"$mod\":[2,0]}}",
            "{\"$nor\":[{\"ids.user\":1}]}",
        ] {
            assert!(
                validate_client_filter(filter).is_err(),
                "{} should be rejected",
                filter
            );
        }
    }

    /// Membership is allowed, but it is not a way around the field rule: a
    /// credential field stays unfilterable whatever the operator.
    #[test]
    fn membership_does_not_reopen_credential_fields() {
        for filter in [
            "{\"strs.otp\":{\"$in\":[\"1\",\"2\"]}}",
            "{\"strs.password\":{\"$nin\":[\"a\"]}}",
            "{\"$or\":[{\"strs.api_key\":{\"$in\":[\"k\"]}}]}",
        ] {
            assert!(
                validate_client_filter(filter).is_err(),
                "{} should be rejected",
                filter
            );
        }
    }

    /// A denied field must stay denied however deeply it is buried.
    #[test]
    fn combinators_do_not_smuggle_denied_fields() {
        assert!(validate_client_filter(
            "{\"$and\":[{\"ids.user\":1},{\"$or\":[{\"strs.password\":{\"$gt\":\"a\"}}]}]}"
        )
        .is_err());
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(validate_client_filter("not json").is_err());
        assert!(validate_client_filter("[]").is_err());
        assert!(validate_client_filter("\"str\"").is_err());
        assert!(validate_client_filter("{\"$and\":{}}").is_err());
        assert!(validate_client_filter("{\"$and\":[]}").is_err());
        // A field path that is really an operator reference.
        assert!(validate_client_filter("{\"$strs.name\":1}").is_err());
        assert!(!field_is_allowed("strs..name"));
        assert!(!field_is_allowed(""));
    }

    #[test]
    fn deep_nesting_is_rejected() {
        let mut filter = "{\"ids.user\":1}".to_string();
        for _ in 0..MAX_DEPTH + 1 {
            filter = format!("{{\"$and\":[{}]}}", filter);
        }
        assert!(validate_client_filter(&filter).is_err());
    }
}

/// Property-based coverage for the filter validator.
///
/// The example-based tests above check the attacks I thought of, which is
/// exactly their limitation: they cannot fail on a shape that never occurred
/// to me. These generate filters from a grammar that deliberately mixes safe
/// and hostile field names and operators, then assert the invariant the
/// validator exists to hold — stated independently, by walking the parsed
/// tree, rather than by calling the validator again.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::{json, Value};

    /// Field names a filter might carry: paths the UI really sends, paths
    /// that would leak a credential, and paths that are malformed outright.
    /// Field names a filter might carry: paths the UI really sends, paths
    /// that would leak a credential, and paths that are malformed outright.
    ///
    /// Weighted toward acceptable names on purpose. The property below is an
    /// implication — *if* the validator accepts, *then* the filter is
    /// harmless — and an implication whose premise is rarely true passes
    /// without testing anything. `generator_is_not_vacuous` keeps this honest.
    fn field_name() -> impl Strategy<Value = String> {
        prop_oneof![
            6 => Just("ids.user".to_string()),
            6 => Just("ids.workspace".to_string()),
            6 => Just("u64s.time".to_string()),
            6 => Just("strs.name".to_string()),
            3 => Just("bools.ssh_keyless".to_string()),
            3 => Just("strs.engine_key_status".to_string()),
            2 => Just("strs.password".to_string()),
            1 => Just("strs.PassWord".to_string()),
            1 => Just("strs.salt".to_string()),
            2 => Just("strs.otp".to_string()),
            1 => Just("strs.deploy_password".to_string()),
            1 => Just("strs.ai_claude_api_key".to_string()),
            1 => Just("strs.delta_token".to_string()),
            1 => Just("$where".to_string()),
            1 => Just("strs..name".to_string()),
            1 => Just("".to_string()),
        ]
    }

    fn scalar() -> impl Strategy<Value = Value> {
        prop_oneof![
            any::<i32>().prop_map(|n| json!(n)),
            any::<bool>().prop_map(|b| json!(b)),
            "[a-z]{0,6}".prop_map(Value::String),
            Just(Value::Null),
        ]
    }

    /// Comparison operators, mixing the permitted ones with the evaluating
    /// ones the validator must refuse.
    /// Comparison operators, mixing the permitted ones with the evaluating
    /// ones the validator must refuse.
    fn leaf_op() -> impl Strategy<Value = String> {
        prop_oneof![
            4 => Just("$eq".to_string()),
            4 => Just("$ne".to_string()),
            4 => Just("$gt".to_string()),
            4 => Just("$gte".to_string()),
            4 => Just("$lt".to_string()),
            4 => Just("$lte".to_string()),
            2 => Just("$regex".to_string()),
            2 => Just("$where".to_string()),
            2 => Just("$in".to_string()),
            2 => Just("$exists".to_string()),
            2 => Just("$expr".to_string()),
        ]
    }

    fn leaf_value() -> impl Strategy<Value = Value> {
        prop_oneof![
            5 => scalar(),
            5 => (leaf_op(), scalar()).prop_map(|(op, v)| json!({ op: v })),
            // Arrays are never a valid leaf, but a generator that never
            // produces them cannot show that.
            1 => proptest::collection::vec(scalar(), 1..3).prop_map(Value::Array),
        ]
    }

    /// A filter tree: leaves, and combinators over them. Includes `$nor`,
    /// which is structurally harmless but outside the allowlist.
    fn filter_json() -> impl Strategy<Value = Value> {
        let leaf = (field_name(), leaf_value()).prop_map(|(f, v)| json!({ f: v }));
        leaf.prop_recursive(4, 24, 3, |inner| {
            prop_oneof![(
                prop_oneof![
                    4 => Just("$and".to_string()),
                    4 => Just("$or".to_string()),
                    1 => Just("$nor".to_string())
                ],
                proptest::collection::vec(inner, 1..3)
            )
                .prop_map(|(op, branches)| json!({ op: branches })),]
        })
    }

    /// Independent restatement of the field rule: does any field path
    /// anywhere in this tree name a credential?
    fn mentions_credential(node: &Value) -> bool {
        const MARKERS: [&str; 9] = [
            "password",
            "passwd",
            "secret",
            "token",
            "salt",
            "otp",
            "api_key",
            "apikey",
            "credential",
        ];
        match node {
            Value::Object(map) => map.iter().any(|(k, v)| {
                let named = !k.starts_with('$')
                    && k.to_lowercase()
                        .split('.')
                        .any(|seg| MARKERS.iter().any(|m| seg.contains(m)));
                named || mentions_credential(v)
            }),
            Value::Array(items) => items.iter().any(mentions_credential),
            _ => false,
        }
    }

    /// Independent restatement of the shape rule: does any `$`-prefixed key
    /// fall outside what the validator permits?
    fn uses_forbidden_operator(node: &Value) -> bool {
        const OK: [&str; 8] = ["$and", "$or", "$eq", "$ne", "$gt", "$gte", "$lt", "$lte"];
        match node {
            Value::Object(map) => map.iter().any(|(k, v)| {
                (k.starts_with('$') && !OK.contains(&k.as_str())) || uses_forbidden_operator(v)
            }),
            Value::Array(items) => items.iter().any(uses_forbidden_operator),
            _ => false,
        }
    }

    /// Guard against a vacuous property.
    ///
    /// `accepted_filters_are_harmless` only tests anything on inputs the
    /// validator accepts. If the generator drifted — or the validator grew
    /// strict enough to reject nearly everything — that property would keep
    /// passing while checking nothing at all. This asserts the premise is
    /// actually met often enough for the implication to have content, and it
    /// is the reason the mutation "allow $regex" is caught rather than missed.
    #[test]
    fn generator_is_not_vacuous() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::deterministic();
        let strategy = filter_json();
        let (mut accepted, mut with_operator) = (0, 0);
        const SAMPLES: usize = 400;

        for _ in 0..SAMPLES {
            let value = strategy.new_tree(&mut runner).unwrap().current();
            if validate_client_filter(&value.to_string()).is_ok() {
                accepted += 1;
                if value.to_string().contains('$') {
                    with_operator += 1;
                }
            }
        }

        assert!(
            accepted * 5 >= SAMPLES,
            "only {}/{} generated filters were accepted — the property is \
             nearly vacuous",
            accepted,
            SAMPLES
        );
        assert!(
            with_operator > 0,
            "no accepted filter used an operator, so operator handling is \
             never exercised"
        );
    }

    proptest! {
        /// The whole point of the validator: nothing it accepts may reach a
        /// credential field or an operator that can evaluate or pattern-match.
        #[test]
        fn accepted_filters_are_harmless(v in filter_json()) {
            let filter = v.to_string();
            if validate_client_filter(&filter).is_ok() {
                prop_assert!(
                    !mentions_credential(&v),
                    "accepted a filter naming a credential: {}", filter
                );
                prop_assert!(
                    !uses_forbidden_operator(&v),
                    "accepted a filter using a forbidden operator: {}", filter
                );
            }
        }

        /// Validation must be a decision, never a panic — the input is a
        /// query-string parameter from an unauthenticated-adjacent caller.
        #[test]
        fn validation_never_panics(s in ".*") {
            let _ = validate_client_filter(&s);
        }

        #[test]
        fn field_check_never_panics(s in ".*") {
            let _ = field_is_allowed(&s);
        }

        /// Whatever `field_is_allowed` lets through must satisfy every part
        /// of the rule, stated here independently.
        #[test]
        fn allowed_fields_satisfy_the_rule(s in "[a-zA-Z_.$]{0,24}") {
            if field_is_allowed(&s) {
                prop_assert!(!s.is_empty());
                prop_assert!(!s.contains('$'));
                prop_assert!(!s.split('.').any(|seg| seg.is_empty()));
                prop_assert!(!s.to_lowercase().contains("password"));
                prop_assert!(!s.to_lowercase().contains("otp"));
                prop_assert!(!s.to_lowercase().contains("salt"));
                prop_assert!(!s.to_lowercase().contains("token"));
            }
        }
    }
}
