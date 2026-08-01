/*
 * Isabelle project
 *
 * Copyright 2023-2026 Maxim Menshikov
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
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

//! BSON wrapper for Item to support full u64 range in MongoDB.
//!
//! BSON doesn't support unsigned 64-bit integers (u64), only i64.
//! This module provides conversion to Decimal128 with backward compatibility.

use isabelle_dm::data_model::item::{Item, ItemDataNode};
use mongodb::bson::{Bson, Decimal128};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// Convert u64 to Decimal128 for BSON storage
#[inline]
pub fn u64_to_decimal128(val: u64) -> Decimal128 {
    Decimal128::from_str(&val.to_string()).unwrap_or_else(|_| Decimal128::from_str("0").unwrap())
}

/// Convert Decimal128 back to u64
#[inline]
pub fn decimal128_to_u64(val: Decimal128) -> u64 {
    val.to_string().parse::<u64>().unwrap_or(0)
}

/// Custom serde for u64 fields - writes as Decimal128, reads from i64/Decimal128
pub mod u64_as_flexible {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let decimal = u64_to_decimal128(*val);
        decimal.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bson = Bson::deserialize(deserializer)?;
        match bson {
            Bson::Int64(i) => Ok(i as u64),
            Bson::Int32(i) => Ok(i as u64),
            Bson::Decimal128(d) => Ok(decimal128_to_u64(d)),
            _ => Ok(0),
        }
    }
}

/// Custom serde for HashMap<String, u64>
pub mod hashmap_u64_as_flexible {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(map: &HashMap<String, u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let converted: HashMap<String, Decimal128> = map
            .iter()
            .map(|(k, &v)| (k.clone(), u64_to_decimal128(v)))
            .collect();
        converted.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<String, u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bson_map = HashMap::<String, Bson>::deserialize(deserializer)?;
        let mut result = HashMap::new();
        for (k, v) in bson_map {
            let val = match v {
                Bson::Int64(i) => i as u64,
                Bson::Int32(i) => i as u64,
                Bson::Decimal128(d) => decimal128_to_u64(d),
                _ => 0,
            };
            result.insert(k, val);
        }
        Ok(result)
    }
}

/// Custom serde for HashMap<String, Vec<u64>>
pub mod hashmap_vec_u64_as_flexible {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(map: &HashMap<String, Vec<u64>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let converted: HashMap<String, Vec<Decimal128>> = map
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.iter().map(|&val| u64_to_decimal128(val)).collect(),
                )
            })
            .collect();
        converted.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<String, Vec<u64>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bson_map = HashMap::<String, Vec<Bson>>::deserialize(deserializer)?;
        let mut result = HashMap::new();
        for (k, v_vec) in bson_map {
            let mut vec = Vec::new();
            for v in v_vec {
                let val = match v {
                    Bson::Int64(i) => i as u64,
                    Bson::Int32(i) => i as u64,
                    Bson::Decimal128(d) => decimal128_to_u64(d),
                    _ => 0,
                };
                vec.push(val);
            }
            result.insert(k, vec);
        }
        Ok(result)
    }
}

/// BSON-compatible Item wrapper with flexible u64 serialization.
/// Supports backward compatibility with existing i64 data.
/// Default for `root_node` when a (legacy) document predates the field.
/// Mirrors the upstream `Item` serde behaviour so documents written before
/// `root_node`/`ItemDataNode` existed still deserialize instead of erroring
/// out the whole startup cursor.
fn default_root_node() -> ItemDataNode {
    ItemDataNode::new()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BsonItem {
    #[serde(with = "u64_as_flexible")]
    pub id: u64,
    #[serde(default)]
    pub strs: HashMap<String, String>,
    #[serde(default)]
    pub strstrs: HashMap<String, HashMap<String, String>>,
    #[serde(default, with = "hashmap_vec_u64_as_flexible")]
    pub strids: HashMap<String, Vec<u64>>,
    #[serde(default)]
    pub bools: HashMap<String, bool>,
    #[serde(default, with = "hashmap_u64_as_flexible")]
    pub u64s: HashMap<String, u64>,
    #[serde(default, with = "hashmap_u64_as_flexible")]
    pub ids: HashMap<String, u64>,
    #[serde(default = "default_root_node")]
    pub root_node: ItemDataNode,
}

impl From<Item> for BsonItem {
    fn from(item: Item) -> Self {
        BsonItem {
            id: item.id,
            strs: item.strs,
            strstrs: item.strstrs,
            strids: item.strids,
            bools: item.bools,
            u64s: item.u64s,
            ids: item.ids,
            root_node: item.root_node,
        }
    }
}

impl From<BsonItem> for Item {
    fn from(bson_item: BsonItem) -> Self {
        let mut item = Item::new();
        item.id = bson_item.id;
        item.strs = bson_item.strs;
        item.strstrs = bson_item.strstrs;
        item.strids = bson_item.strids;
        item.bools = bson_item.bools;
        item.u64s = bson_item.u64s;
        item.ids = bson_item.ids;
        item.root_node = bson_item.root_node;
        item
    }
}

impl BsonItem {
    /// Create BsonItem from Item reference
    pub fn from_item(item: &Item) -> Self {
        BsonItem::from(item.clone())
    }

    /// Convert BsonItem to Item
    pub fn to_item(&self) -> Item {
        Item::from(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::doc;

    /// BSON has no unsigned 64-bit integer, which is the entire reason this
    /// module exists. The values that must survive the detour through
    /// `Decimal128` include `u64::MAX` — `Item::new()` uses it as the "no id
    /// assigned yet" sentinel, and `set_item` keys its insert-vs-replace
    /// decision on it, so losing it would silently turn every new item into a
    /// write against id 0.
    #[test]
    fn u64_survives_the_decimal128_round_trip() {
        for value in [
            0u64,
            1,
            42,
            i32::MAX as u64,
            i64::MAX as u64,
            i64::MAX as u64 + 1,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let back = decimal128_to_u64(u64_to_decimal128(value));
            assert_eq!(back, value, "{} did not survive the round trip", value);
        }
    }

    /// Decimal128 must render these as plain digits. If it ever switched to
    /// exponent notation, `parse::<u64>()` in `decimal128_to_u64` would fail
    /// and silently yield 0.
    #[test]
    fn large_values_are_not_rendered_in_exponent_notation() {
        for value in [u64::MAX, u64::MAX - 1, 1_000_000_000_000_000_000] {
            let rendered = u64_to_decimal128(value).to_string();
            assert!(
                !rendered.contains('E') && !rendered.contains('e'),
                "{} rendered as {}, which would parse back as 0",
                value,
                rendered
            );
            assert_eq!(rendered, value.to_string());
        }
    }

    fn sample_item() -> Item {
        let mut item = Item::new();
        item.id = u64::MAX - 3;
        item.set_str("name", "example");
        item.set_bool("role_is_active", true);
        item.set_u64("time", 1_700_000_000);
        item.set_id("workspace", u64::MAX);
        item.set_strid("members", &vec![1, u64::MAX, 0]);
        let mut nested = HashMap::new();
        nested.insert("k".to_string(), "v".to_string());
        item.set_strstr("meta", &nested);
        item
    }

    /// Every typed map has to come back intact, ids included. This is the
    /// conversion every read and every write goes through.
    #[test]
    fn item_survives_the_bson_document_round_trip() {
        let original = sample_item();
        let doc = mongodb::bson::to_document(&BsonItem::from_item(&original)).unwrap();
        let decoded: BsonItem = mongodb::bson::from_document(doc).unwrap();
        let result = decoded.to_item();

        assert_eq!(result.id, original.id);
        assert_eq!(result.strs, original.strs);
        assert_eq!(result.bools, original.bools);
        assert_eq!(result.u64s, original.u64s);
        assert_eq!(result.ids, original.ids);
        assert_eq!(result.strids, original.strids);
        assert_eq!(result.strstrs, original.strstrs);
    }

    /// Backward compatibility is the other half of this module's job:
    /// documents written before the Decimal128 change store ids as Int64 or
    /// Int32, and those must still load.
    #[test]
    fn ids_stored_as_int64_or_int32_still_load() {
        let legacy = doc! {
            "id": 7i64,
            "strs": {},
            "bools": {},
            "u64s": { "time": 1700i64, "small": 5i32 },
            "ids": { "workspace": 3i32 },
            "strids": { "members": [1i64, 2i32] },
        };
        let decoded: BsonItem = mongodb::bson::from_document(legacy).unwrap();
        assert_eq!(decoded.id, 7);
        assert_eq!(decoded.u64s.get("time"), Some(&1700));
        assert_eq!(decoded.u64s.get("small"), Some(&5));
        assert_eq!(decoded.ids.get("workspace"), Some(&3));
        assert_eq!(decoded.strids.get("members"), Some(&vec![1, 2]));
    }

    /// A missing typed map means an empty one, not a failure to load: items
    /// are written sparsely and most documents lack most of these.
    #[test]
    fn absent_maps_default_to_empty() {
        let sparse = doc! { "id": 1i64 };
        let decoded: BsonItem = mongodb::bson::from_document(sparse).unwrap();
        assert_eq!(decoded.id, 1);
        assert!(decoded.strs.is_empty());
        assert!(decoded.u64s.is_empty());
        assert!(decoded.ids.is_empty());
        assert!(decoded.strids.is_empty());
        assert!(decoded.strstrs.is_empty());
        assert!(decoded.bools.is_empty());
    }

    /// Documented deliberately, because it is a sharp edge rather than a
    /// nicety: a numeric field holding an unexpected BSON type decodes to 0
    /// instead of erroring. For `id` that silently aliases a record onto id 0
    /// rather than refusing to load it.
    #[test]
    fn unexpected_numeric_types_decode_to_zero_rather_than_failing() {
        let odd = doc! { "id": "not a number", "u64s": { "time": true } };
        let decoded: BsonItem = mongodb::bson::from_document(odd).unwrap();
        assert_eq!(decoded.id, 0);
        assert_eq!(decoded.u64s.get("time"), Some(&0));
    }
}
