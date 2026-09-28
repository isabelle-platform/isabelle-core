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
//! Who a record belongs to.
//!
//! Some collections are owned: the flavour names them in
//! `internals.owned_collections`, and each of their records carries the
//! account that created it in `ids.owner`. The server writes that field, not
//! the client: a new record is stamped with whoever sends it, and a change
//! keeps the owner it had, whatever the request says. Deciding what an owner
//! may do with it is left to the plugins' hooks, which see the stamped record.
//!
//! Records written before a collection was owned carry no owner and keep
//! none: they belong to the administrators.
//!
//! Secrets are owned the same way, in the same field, by `server::secret`.

use isabelle_dm::data_model::item::Item;

/// The internals entry naming the owned collections.
pub const INTERNALS_OWNED: &str = "owned_collections";
/// The field that holds the owner's id.
pub const FIELD_OWNER: &str = "owner";

/// Whether `collection` is one whose records have an owner.
pub fn is_owned(internals: &Item, collection: &str) -> bool {
    internals
        .strstrs
        .get(INTERNALS_OWNED)
        .map_or(false, |m| m.values().any(|c| c == collection))
}

/// The owner of `item`, if it has one.
pub fn owner_of(item: &Item) -> Option<u64> {
    item.ids.get(FIELD_OWNER).copied()
}

/// Put the right owner on `item` before it is written: `caller` for a new
/// record, the one it already has for an existing one.
pub fn stamp(item: &mut Item, old: Option<&Item>, caller: u64) {
    match old {
        None => {
            item.ids.insert(FIELD_OWNER.to_string(), caller);
        }
        Some(old) => match owner_of(old) {
            Some(owner) => {
                item.ids.insert(FIELD_OWNER.to_string(), owner);
            }
            None => {
                item.ids.remove(FIELD_OWNER);
            }
        },
    }
}

/// Whether `user` may see and change a record owned as `item` is: its owner
/// may, and an administrator may. A record with no owner is the
/// administrators' alone.
pub fn may_touch(item: &Item, user: u64, admin: bool) -> bool {
    admin || owner_of(item) == Some(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(owner: Option<u64>) -> Item {
        let mut i = Item::new();
        if let Some(o) = owner {
            i.ids.insert(FIELD_OWNER.to_string(), o);
        }
        i
    }

    #[test]
    fn a_new_record_belongs_to_whoever_sends_it() {
        let mut sent = owned(Some(99));
        stamp(&mut sent, None, 5);
        assert_eq!(owner_of(&sent), Some(5));
    }

    #[test]
    fn a_change_keeps_the_owner_whatever_it_says() {
        let mut sent = owned(Some(5));
        stamp(&mut sent, Some(&owned(Some(3))), 5);
        assert_eq!(owner_of(&sent), Some(3));
    }

    #[test]
    fn an_unowned_record_stays_the_administrators() {
        let mut sent = owned(Some(5));
        stamp(&mut sent, Some(&owned(None)), 5);
        assert_eq!(owner_of(&sent), None);
        assert!(!may_touch(&sent, 5, false));
        assert!(may_touch(&sent, 5, true));
    }

    #[test]
    fn owned_collections_come_from_internals() {
        let mut internals = Item::new();
        let mut m = std::collections::HashMap::new();
        m.insert("1".to_string(), "workspace".to_string());
        internals.strstrs.insert(INTERNALS_OWNED.to_string(), m);
        assert!(is_owned(&internals, "workspace"));
        assert!(!is_owned(&internals, "test"));
        assert!(!is_owned(&Item::new(), "workspace"));
    }
}
