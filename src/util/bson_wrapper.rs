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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BsonItem {
    #[serde(with = "u64_as_flexible")]
    pub id: u64,
    pub strs: HashMap<String, String>,
    pub strstrs: HashMap<String, HashMap<String, String>>,
    #[serde(with = "hashmap_vec_u64_as_flexible")]
    pub strids: HashMap<String, Vec<u64>>,
    pub bools: HashMap<String, bool>,
    #[serde(with = "hashmap_u64_as_flexible")]
    pub u64s: HashMap<String, u64>,
    #[serde(with = "hashmap_u64_as_flexible")]
    pub ids: HashMap<String, u64>,
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
