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
//!     comparison operator. This rejects `$regex`, `$where`, `$expr`,
//!     `$function`, `$text` and friends outright.
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

use serde_json::Value;

/// Boolean combinators a client filter may use. Both take an array of
/// sub-filters and neither can express a computation.
const ALLOWED_COMBINATORS: [&str; 2] = ["$and", "$or"];

/// Comparison operators allowed inside a leaf. Deliberately excludes every
/// operator that can evaluate an expression or a pattern (`$regex`, `$where`,
/// `$expr`, `$function`, `$jsonSchema`, `$text`, `$mod`, …).
const ALLOWED_LEAF_OPS: [&str; 6] = ["$eq", "$ne", "$gt", "$gte", "$lt", "$lte"];

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
mod tests {
    use super::*;

    /// The exact shapes the midair UI builds (test list and analysis list
    /// filter panels). If any of these stop validating, the UI breaks.
    #[test]
    fn filters_built_by_the_ui_are_accepted() {
        assert!(validate_client_filter("").is_ok());
        assert!(validate_client_filter("{\"ids.workspace\":3}").is_ok());
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
            "{\"strs.name\":{\"$in\":[\"a\",\"b\"]}}",
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
