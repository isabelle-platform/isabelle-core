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
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use isabelle_dm::data_model::item::Item;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const FORMAT_VERSION: u32 = 1;
const NAME_FIELD: &str = "name";
const SECRET_KEY_PREFIX: &str = "secret";
const HIDDEN_PLACEHOLDER: &str = "<hidden>";

fn is_secret_key(k: &str) -> bool {
    k.starts_with(SECRET_KEY_PREFIX)
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u32,
    next_id: u64,
    entries: HashMap<u64, Item>,
}

pub struct SecretStore {
    cipher: Aes256Gcm,
    path: PathBuf,
    entries: HashMap<u64, Item>,
    name_index: HashMap<String, u64>,
    next_id: u64,
}

impl SecretStore {
    /// Open or create the secret store. The master key is loaded from
    /// `key_path`; if the file does not exist, a fresh random key is
    /// written there with restrictive permissions. The encrypted blob
    /// lives at `store_path`; an absent file means an empty store.
    pub fn open(key_path: &Path, store_path: &Path) -> io::Result<Self> {
        let key_bytes = load_or_create_key(key_path)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

        let (entries, next_id) = if store_path.exists() {
            let blob = fs::read(store_path)?;
            decrypt_and_parse(&cipher, &blob).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to decrypt secret store: {}", e),
                )
            })?
        } else {
            (HashMap::new(), 0)
        };

        let name_index = build_name_index(&entries)?;

        Ok(Self {
            cipher,
            path: store_path.to_path_buf(),
            entries,
            name_index,
            next_id,
        })
    }

    /// Internal-only: read a secret by id, returning the raw Item with all
    /// values intact. Must NEVER be wired to an HTTP handler.
    #[allow(dead_code)]
    pub fn get(&self, id: u64) -> Option<Item> {
        self.entries.get(&id).cloned()
    }

    /// Internal-only: read a secret by name, returning the raw Item.
    #[allow(dead_code)]
    pub fn get_by_name(&self, name: &str) -> Option<Item> {
        let id = *self.name_index.get(name)?;
        self.entries.get(&id).cloned()
    }

    /// External-facing read: same Item but every `strs[k]` whose key starts
    /// with "secret" has its value replaced with `"<hidden>"`. Other typed
    /// maps (bools/u64s/strstrs/ids/strids) are returned as-is.
    pub fn get_masked(&self, id: u64) -> Option<Item> {
        let mut it = self.entries.get(&id)?.clone();
        for (k, v) in it.strs.iter_mut() {
            if is_secret_key(k) {
                *v = HIDDEN_PLACEHOLDER.to_string();
            }
        }
        Some(it)
    }

    /// (id, name) pairs, sorted by name.
    pub fn list(&self) -> Vec<(u64, String)> {
        let mut out: Vec<(u64, String)> = self
            .entries
            .iter()
            .map(|(id, it)| (*id, it.strs.get(NAME_FIELD).cloned().unwrap_or_default()))
            .collect();
        out.sort_by(|a, b| a.1.cmp(&b.1));
        out
    }

    /// Insert or update a secret. Returns the assigned id.
    ///
    /// Rules:
    /// * `item.strs["name"]` must be present and non-empty (after merge).
    /// * If `item.id == u64::MAX`, a new id is allocated.
    /// * If `merge == true`, the incoming Item is merged on top of the
    ///   existing one (via `Item::merge`); fields not present in the
    ///   incoming Item are preserved.
    /// * For any `strs[k]` in the resulting Item where `k` starts with
    ///   "secret" and the value equals `"<hidden>"`, the existing value is
    ///   restored (or the field dropped if there was no existing value).
    ///   This lets clients round-trip a masked Item back to /secret/edit
    ///   without overwriting secrets they cannot read.
    /// * Names must be unique; renaming an existing entry is allowed as
    ///   long as the new name is not used by a different id.
    /// * On return `entries[id].id == id` always holds.
    pub fn set(&mut self, item: &Item, merge: bool) -> io::Result<u64> {
        let target_id = if item.id == u64::MAX {
            self.next_id
        } else {
            item.id
        };

        let existing = self.entries.get(&target_id).cloned();

        let mut final_item = if merge {
            match &existing {
                Some(e) => {
                    let mut base = e.clone();
                    base.merge(item);
                    base
                }
                None => item.clone(),
            }
        } else {
            item.clone()
        };

        // Restore hidden-placeholder secret strs from the existing entry.
        let secret_keys: Vec<String> = final_item
            .strs
            .keys()
            .filter(|k| is_secret_key(k))
            .cloned()
            .collect();
        for k in secret_keys {
            if final_item.strs.get(&k).map(String::as_str) == Some(HIDDEN_PLACEHOLDER) {
                match existing.as_ref().and_then(|e| e.strs.get(&k)) {
                    Some(prev) => {
                        final_item.strs.insert(k, prev.clone());
                    }
                    None => {
                        final_item.strs.remove(&k);
                    }
                }
            }
        }

        let name = final_item.strs.get(NAME_FIELD).cloned().unwrap_or_default();
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret item must have a non-empty strs[\"name\"]",
            ));
        }
        if let Some(&other_id) = self.name_index.get(&name) {
            if other_id != target_id {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("secret name '{}' already in use by id {}", name, other_id),
                ));
            }
        }

        let prev_name = existing
            .as_ref()
            .and_then(|e| e.strs.get(NAME_FIELD).cloned());

        // Enforce entries[k].id == k invariant before serialization.
        final_item.id = target_id;

        let mut new_entries = self.entries.clone();
        new_entries.insert(target_id, final_item);
        let new_next_id = std::cmp::max(self.next_id, target_id.saturating_add(1));

        self.flush_state(&new_entries, new_next_id)?;

        self.entries = new_entries;
        self.next_id = new_next_id;
        if let Some(p) = prev_name {
            if p != name && self.name_index.get(&p).copied() == Some(target_id) {
                self.name_index.remove(&p);
            }
        }
        self.name_index.insert(name, target_id);
        Ok(target_id)
    }

    pub fn del(&mut self, id: u64) -> io::Result<bool> {
        if !self.entries.contains_key(&id) {
            return Ok(false);
        }
        let mut new_entries = self.entries.clone();
        let removed = new_entries.remove(&id).unwrap();
        self.flush_state(&new_entries, self.next_id)?;
        self.entries = new_entries;
        if let Some(name) = removed.strs.get(NAME_FIELD).cloned() {
            if self.name_index.get(&name).copied() == Some(id) {
                self.name_index.remove(&name);
            }
        }
        Ok(true)
    }

    fn flush_state(&self, entries: &HashMap<u64, Item>, next_id: u64) -> io::Result<()> {
        let env = Envelope {
            v: FORMAT_VERSION,
            next_id,
            entries: entries.clone(),
        };
        let plaintext = serde_json::to_vec(&env)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {}", e)))?;
        let blob = encrypt_blob(&self.cipher, &plaintext)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encrypt: {}", e)))?;
        atomic_write(&self.path, &blob, 0o600)
    }
}

fn build_name_index(entries: &HashMap<u64, Item>) -> io::Result<HashMap<String, u64>> {
    let mut idx: HashMap<String, u64> = HashMap::new();
    for (id, it) in entries {
        if let Some(name) = it.strs.get(NAME_FIELD) {
            if name.is_empty() {
                continue;
            }
            if let Some(other) = idx.insert(name.clone(), *id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "duplicate secret name '{}' in store (ids {} and {})",
                        name, other, id
                    ),
                ));
            }
        }
    }
    Ok(idx)
}

fn decrypt_and_parse(cipher: &Aes256Gcm, blob: &[u8]) -> Result<(HashMap<u64, Item>, u64), String> {
    if blob.len() < NONCE_LEN {
        return Err("blob shorter than nonce".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| e.to_string())?;

    // Try the current envelope format first.
    if let Ok(env) = serde_json::from_slice::<Envelope>(&plaintext) {
        // Repair the entries[k].id == k invariant defensively.
        let mut entries = env.entries;
        let mut max_id: u64 = 0;
        for (id, it) in entries.iter_mut() {
            it.id = *id;
            if *id >= max_id {
                max_id = *id;
            }
        }
        let next_id = std::cmp::max(env.next_id, max_id.saturating_add(1));
        return Ok((entries, next_id));
    }

    // Fallback: legacy HashMap<String, Item> format. Migrate by allocating
    // sequential ids and using the legacy string key as strs["name"].
    let legacy: HashMap<String, Item> = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("unrecognized blob format: {}", e))?;
    let mut entries: HashMap<u64, Item> = HashMap::new();
    let mut next_id: u64 = 0;
    let mut keys: Vec<String> = legacy.keys().cloned().collect();
    keys.sort();
    for k in keys {
        let mut it = legacy.get(&k).unwrap().clone();
        it.id = next_id;
        it.strs.insert(NAME_FIELD.to_string(), k);
        entries.insert(next_id, it);
        next_id += 1;
    }
    Ok((entries, next_id))
}

fn load_or_create_key(path: &Path) -> io::Result<[u8; KEY_LEN]> {
    if path.exists() {
        let bytes = fs::read(path)?;
        if bytes.len() != KEY_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "secret key file {} must contain exactly {} bytes (got {})",
                    path.display(),
                    KEY_LEN,
                    bytes.len()
                ),
            ));
        }
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&bytes);
        Ok(out)
    } else {
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic_write(path, &key, 0o600)?;
        Ok(key)
    }
}

fn encrypt_blob(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

#[cfg(unix)]
fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(not(unix))]
fn atomic_write(path: &Path, data: &[u8], _mode: u32) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn item_named(name: &str, pairs: &[(&str, &str)]) -> Item {
        let mut it = Item::new();
        it.id = u64::MAX;
        it.strs.insert(NAME_FIELD.to_string(), name.to_string());
        for (k, v) in pairs {
            it.strs.insert((*k).to_string(), (*v).to_string());
        }
        it
    }

    fn paths(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        (dir.path().join("k"), dir.path().join("s.enc"))
    }

    /// SecretStore intentionally does not implement Debug, so we cannot
    /// use Result::unwrap_err.
    fn expect_err<T>(r: io::Result<T>) -> io::Error {
        match r {
            Ok(_) => panic!("expected Err"),
            Err(e) => e,
        }
    }

    // -------- key file lifecycle --------

    #[test]
    fn first_open_creates_key_file_and_no_store() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let store = SecretStore::open(&k, &s).unwrap();
        assert!(k.exists());
        assert!(!s.exists());
        assert!(store.list().is_empty());
        assert_eq!(fs::read(&k).unwrap().len(), KEY_LEN);
    }

    #[test]
    fn rejects_key_file_of_wrong_size() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        fs::write(&k, b"short").unwrap();
        assert_eq!(
            expect_err(SecretStore::open(&k, &s)).kind(),
            io::ErrorKind::InvalidData
        );
    }

    // -------- id allocation --------

    #[test]
    fn first_insert_allocates_id_zero() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store.set(&item_named("a", &[]), false).unwrap();
        assert_eq!(id, 0);
        assert_eq!(store.get(0).unwrap().id, 0, "item.id must equal map key");
    }

    #[test]
    fn ids_are_sequential() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id_a = store.set(&item_named("a", &[]), false).unwrap();
        let id_b = store.set(&item_named("b", &[]), false).unwrap();
        let id_c = store.set(&item_named("c", &[]), false).unwrap();
        assert_eq!((id_a, id_b, id_c), (0, 1, 2));
    }

    #[test]
    fn item_id_field_matches_map_key_after_set() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        for n in 0..5 {
            let id = store
                .set(&item_named(&format!("n{}", n), &[]), false)
                .unwrap();
            assert_eq!(store.get(id).unwrap().id, id);
        }
    }

    #[test]
    fn explicit_id_is_honored_and_bumps_counter() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let mut it = item_named("a", &[]);
        it.id = 100;
        let id = store.set(&it, false).unwrap();
        assert_eq!(id, 100);
        // next allocation must skip past 100
        let next = store.set(&item_named("b", &[]), false).unwrap();
        assert_eq!(next, 101);
    }

    // -------- name uniqueness --------

    #[test]
    fn empty_name_is_rejected() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let mut it = Item::new();
        it.id = u64::MAX;
        let err = expect_err(store.set(&it, false));
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn duplicate_name_on_insert_rejected() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set(&item_named("dup", &[("v", "1")]), false).unwrap();
        let err = expect_err(store.set(&item_named("dup", &[("v", "2")]), false));
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn rename_to_free_name_succeeds() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store.set(&item_named("old", &[("v", "1")]), false).unwrap();
        let mut updated = item_named("new", &[("v", "2")]);
        updated.id = id;
        let id2 = store.set(&updated, false).unwrap();
        assert_eq!(id, id2, "rename must preserve id");
        assert!(store.get_by_name("old").is_none());
        assert_eq!(store.get_by_name("new").unwrap().id, id);
    }

    #[test]
    fn rename_to_taken_name_rejected() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id_a = store.set(&item_named("a", &[]), false).unwrap();
        let _id_b = store.set(&item_named("b", &[]), false).unwrap();
        let mut rename_a_to_b = item_named("b", &[("v", "x")]);
        rename_a_to_b.id = id_a;
        let err = expect_err(store.set(&rename_a_to_b, false));
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        // original state must be intact
        assert_eq!(
            store.get(id_a).unwrap().strs.get(NAME_FIELD).cloned(),
            Some("a".into())
        );
    }

    #[test]
    fn update_same_id_same_name_is_a_noop_collision_check() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store.set(&item_named("a", &[("v", "1")]), false).unwrap();
        let mut update = item_named("a", &[("v", "2")]);
        update.id = id;
        let id2 = store.set(&update, false).unwrap();
        assert_eq!(id, id2);
        assert_eq!(
            store.get(id).unwrap().strs.get("v").cloned(),
            Some("2".into())
        );
    }

    // -------- persistence --------

    #[test]
    fn next_id_persists_across_reopen() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        {
            let mut store = SecretStore::open(&k, &s).unwrap();
            store.set(&item_named("a", &[]), false).unwrap();
            store.set(&item_named("b", &[]), false).unwrap();
        }
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id_c = store.set(&item_named("c", &[]), false).unwrap();
        assert_eq!(id_c, 2, "next id after reopen must continue counter");
    }

    #[test]
    fn name_index_rebuilt_on_reopen() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let id_b = {
            let mut store = SecretStore::open(&k, &s).unwrap();
            store.set(&item_named("a", &[]), false).unwrap();
            store.set(&item_named("b", &[("v", "x")]), false).unwrap()
        };
        let store = SecretStore::open(&k, &s).unwrap();
        assert_eq!(store.get_by_name("b").unwrap().id, id_b);
        assert_eq!(
            store.get_by_name("b").unwrap().strs.get("v").cloned(),
            Some("x".into())
        );
    }

    #[test]
    fn persists_full_item_fields() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let id = {
            let mut store = SecretStore::open(&k, &s).unwrap();
            store
                .set(
                    &item_named("svc", &[("login", "alice"), ("token", "tok-1")]),
                    false,
                )
                .unwrap()
        };
        let store = SecretStore::open(&k, &s).unwrap();
        let it = store.get(id).unwrap();
        assert_eq!(it.id, id);
        assert_eq!(it.strs.get("login").cloned(), Some("alice".into()));
        assert_eq!(it.strs.get("token").cloned(), Some("tok-1".into()));
    }

    // -------- delete --------

    #[test]
    fn del_existing_removes_entry_and_frees_name() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store.set(&item_named("a", &[]), false).unwrap();
        assert!(store.del(id).unwrap());
        assert!(store.get(id).is_none());
        assert!(store.get_by_name("a").is_none());
        // name is now free for reuse
        let id2 = store.set(&item_named("a", &[]), false).unwrap();
        assert_ne!(id2, id);
    }

    #[test]
    fn del_missing_returns_false_without_writing() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        assert!(!store.del(42).unwrap());
        assert!(!s.exists());
    }

    #[test]
    fn del_persists_across_reopen() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let id = {
            let mut store = SecretStore::open(&k, &s).unwrap();
            let id = store.set(&item_named("a", &[]), false).unwrap();
            store.set(&item_named("b", &[]), false).unwrap();
            store.del(id).unwrap();
            id
        };
        let store = SecretStore::open(&k, &s).unwrap();
        assert!(store.get(id).is_none());
        assert!(store.get_by_name("b").is_some());
    }

    // -------- list --------

    #[test]
    fn list_returns_id_name_sorted_by_name() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id_z = store.set(&item_named("zeta", &[]), false).unwrap();
        let id_a = store.set(&item_named("alpha", &[]), false).unwrap();
        let id_m = store.set(&item_named("mu", &[]), false).unwrap();
        assert_eq!(
            store.list(),
            vec![
                (id_a, "alpha".into()),
                (id_m, "mu".into()),
                (id_z, "zeta".into())
            ]
        );
    }

    // -------- security properties --------

    #[test]
    fn nonce_is_random_per_write() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set(&item_named("a", &[("v", "1")]), false).unwrap();
        let blob1 = fs::read(&s).unwrap();
        // re-write same content
        let mut update = item_named("a", &[("v", "1")]);
        update.id = 0;
        store.set(&update, false).unwrap();
        let blob2 = fs::read(&s).unwrap();
        assert_ne!(blob1, blob2);
        assert_ne!(&blob1[..NONCE_LEN], &blob2[..NONCE_LEN]);
    }

    #[test]
    fn store_blob_does_not_contain_plaintext() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store
            .set(
                &item_named("a", &[("token", "SUPERSECRETVALUE12345")]),
                false,
            )
            .unwrap();
        let blob = fs::read(&s).unwrap();
        assert!(!blob.windows(20).any(|w| w == b"SUPERSECRETVALUE1234"));
        // Name itself must not appear either, since the whole envelope is
        // encrypted.
        assert!(!blob.windows(11).any(|w| w == b"SUPERSECRET"));
    }

    #[test]
    fn tampered_blob_fails_to_decrypt() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        {
            let mut store = SecretStore::open(&k, &s).unwrap();
            store.set(&item_named("a", &[]), false).unwrap();
        }
        let mut blob = fs::read(&s).unwrap();
        blob[NONCE_LEN + 1] ^= 0xFF;
        fs::write(&s, &blob).unwrap();
        assert_eq!(
            expect_err(SecretStore::open(&k, &s)).kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn truncated_blob_fails_to_decrypt() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        {
            let mut store = SecretStore::open(&k, &s).unwrap();
            store.set(&item_named("a", &[]), false).unwrap();
        }
        let blob = fs::read(&s).unwrap();
        fs::write(&s, &blob[..blob.len() - 4]).unwrap();
        assert_eq!(
            expect_err(SecretStore::open(&k, &s)).kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        {
            let mut store = SecretStore::open(&k, &s).unwrap();
            store.set(&item_named("a", &[]), false).unwrap();
        }
        fs::write(&k, vec![0xAAu8; KEY_LEN]).unwrap();
        assert_eq!(
            expect_err(SecretStore::open(&k, &s)).kind(),
            io::ErrorKind::InvalidData
        );
    }

    // -------- edge cases --------

    #[test]
    fn unicode_and_special_chars() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let payload = "пароль 🔐 with \"quotes\", \nnewlines";
        let id = store
            .set(&item_named("ключ", &[("значение", payload)]), false)
            .unwrap();
        let store2 = SecretStore::open(&k, &s).unwrap();
        assert_eq!(
            store2.get(id).unwrap().strs.get("значение").cloned(),
            Some(payload.into())
        );
        assert_eq!(store2.get_by_name("ключ").unwrap().id, id);
    }

    #[test]
    fn many_keys_persist_with_correct_ids() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let ids: Vec<u64> = {
            let mut store = SecretStore::open(&k, &s).unwrap();
            (0..200)
                .map(|i| {
                    store
                        .set(&item_named(&format!("n{:03}", i), &[]), false)
                        .unwrap()
                })
                .collect()
        };
        assert_eq!(ids, (0u64..200u64).collect::<Vec<_>>());
        let store = SecretStore::open(&k, &s).unwrap();
        assert_eq!(store.list().len(), 200);
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(store.get(*id).unwrap().id, *id);
            assert_eq!(
                store.get(*id).unwrap().strs.get(NAME_FIELD).cloned(),
                Some(format!("n{:03}", i))
            );
        }
    }

    // -------- migration from legacy format --------

    #[test]
    fn migrates_legacy_string_keyed_format() {
        // Hand-craft a legacy blob: encrypt a HashMap<String, Item>.
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        // Initialize key.
        {
            let _ = SecretStore::open(&k, &s).unwrap();
        }
        let key_bytes = fs::read(&k).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

        let mut legacy: HashMap<String, Item> = HashMap::new();
        let mut a = Item::new();
        a.strs.insert("login".into(), "alice".into());
        legacy.insert("svc-a".into(), a);
        let mut b = Item::new();
        b.strs.insert("token".into(), "tok-b".into());
        legacy.insert("svc-b".into(), b);

        let plaintext = serde_json::to_vec(&legacy).unwrap();
        let blob = encrypt_blob(&cipher, &plaintext).unwrap();
        fs::write(&s, &blob).unwrap();

        // Open via SecretStore — migration must succeed.
        let store = SecretStore::open(&k, &s).unwrap();
        let by_name_a = store.get_by_name("svc-a").unwrap();
        let by_name_b = store.get_by_name("svc-b").unwrap();
        assert_eq!(by_name_a.strs.get("login").cloned(), Some("alice".into()));
        assert_eq!(by_name_b.strs.get("token").cloned(), Some("tok-b".into()));
        // ids assigned and item.id matches map key
        assert_eq!(by_name_a.id, store.get(by_name_a.id).unwrap().id);
        assert_eq!(by_name_b.id, store.get(by_name_b.id).unwrap().id);
        // names recorded as strs["name"]
        assert_eq!(
            by_name_a.strs.get(NAME_FIELD).cloned(),
            Some("svc-a".into())
        );
        assert_eq!(
            by_name_b.strs.get(NAME_FIELD).cloned(),
            Some("svc-b".into())
        );
    }

    #[test]
    fn corrupt_envelope_with_duplicate_names_rejected_on_load() {
        // Hand-craft an envelope with two entries sharing strs["name"]
        // and confirm load rejects it.
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let _ = SecretStore::open(&k, &s).unwrap();
        let key_bytes = fs::read(&k).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

        let mut entries: HashMap<u64, Item> = HashMap::new();
        let mut a = Item::new();
        a.id = 0;
        a.strs.insert(NAME_FIELD.into(), "dup".into());
        entries.insert(0, a);
        let mut b = Item::new();
        b.id = 1;
        b.strs.insert(NAME_FIELD.into(), "dup".into());
        entries.insert(1, b);
        let env = Envelope {
            v: FORMAT_VERSION,
            next_id: 2,
            entries,
        };
        let plaintext = serde_json::to_vec(&env).unwrap();
        let blob = encrypt_blob(&cipher, &plaintext).unwrap();
        fs::write(&s, &blob).unwrap();

        assert_eq!(
            expect_err(SecretStore::open(&k, &s)).kind(),
            io::ErrorKind::InvalidData
        );
    }

    // -------- file layout --------

    #[test]
    fn no_tmp_file_left_after_write() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set(&item_named("a", &[]), false).unwrap();
        assert!(!s.with_extension("tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn key_and_store_have_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set(&item_named("a", &[]), false).unwrap();
        let key_mode = fs::metadata(&k).unwrap().permissions().mode() & 0o777;
        let store_mode = fs::metadata(&s).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600);
        assert_eq!(store_mode, 0o600);
    }

    // -------- masking on read & "<hidden>" preservation on write --------

    #[test]
    fn get_masked_replaces_secret_strs_with_placeholder() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(
                &item_named(
                    "stripe",
                    &[
                        ("secret_token", "sk_live_real"),
                        ("secret_refresh", "ref_real"),
                        ("description", "production"),
                    ],
                ),
                false,
            )
            .unwrap();
        let masked = store.get_masked(id).unwrap();
        assert_eq!(masked.id, id);
        assert_eq!(
            masked.strs.get("secret_token").map(String::as_str),
            Some(HIDDEN_PLACEHOLDER)
        );
        assert_eq!(
            masked.strs.get("secret_refresh").map(String::as_str),
            Some(HIDDEN_PLACEHOLDER)
        );
        // Non-secret fields untouched.
        assert_eq!(
            masked.strs.get("description").cloned(),
            Some("production".into())
        );
        assert_eq!(masked.strs.get(NAME_FIELD).cloned(), Some("stripe".into()));
    }

    #[test]
    fn get_returns_raw_values_unmasked() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(&item_named("svc", &[("secret_token", "real")]), false)
            .unwrap();
        // Internal raw read must NOT mask.
        assert_eq!(
            store.get(id).unwrap().strs.get("secret_token").cloned(),
            Some("real".into())
        );
    }

    #[test]
    fn masking_does_not_touch_non_strs_maps() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let mut it = item_named("svc", &[("secret_token", "real")]);
        it.bools.insert("secret_revoked".into(), true);
        it.u64s.insert("secret_expires_at".into(), 1735689600);
        let id = store.set(&it, false).unwrap();
        let masked = store.get_masked(id).unwrap();
        // strs masked
        assert_eq!(
            masked.strs.get("secret_token").map(String::as_str),
            Some(HIDDEN_PLACEHOLDER)
        );
        // typed maps left intact (masking is strs-only by design)
        assert_eq!(masked.bools.get("secret_revoked").copied(), Some(true));
        assert_eq!(
            masked.u64s.get("secret_expires_at").copied(),
            Some(1735689600)
        );
    }

    #[test]
    fn masking_only_applies_to_keys_with_secret_prefix() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(
                &item_named(
                    "svc",
                    &[
                        ("secret_x", "hidden-this"),
                        ("Secret_y", "case-sensitive-no-mask"),
                        ("not_secret", "visible"),
                        ("api_secret", "visible-too"),
                    ],
                ),
                false,
            )
            .unwrap();
        let masked = store.get_masked(id).unwrap();
        assert_eq!(
            masked.strs.get("secret_x").map(String::as_str),
            Some(HIDDEN_PLACEHOLDER)
        );
        // Capital S — does not match the lowercase prefix.
        assert_eq!(
            masked.strs.get("Secret_y").cloned(),
            Some("case-sensitive-no-mask".into())
        );
        assert_eq!(
            masked.strs.get("not_secret").cloned(),
            Some("visible".into())
        );
        assert_eq!(
            masked.strs.get("api_secret").cloned(),
            Some("visible-too".into())
        );
    }

    #[test]
    fn hidden_placeholder_on_update_preserves_existing_secret() {
        // Round-trip workflow: GET masked, modify a non-secret field, PUT.
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(
                &item_named(
                    "svc",
                    &[("secret_token", "REAL_TOKEN"), ("description", "old")],
                ),
                false,
            )
            .unwrap();
        // Simulate client: read masked, edit description, send back.
        let mut returned = store.get_masked(id).unwrap();
        returned.strs.insert("description".into(), "new".into());
        // returned.strs["secret_token"] is still "<hidden>"
        store.set(&returned, true).unwrap();
        let raw = store.get(id).unwrap();
        assert_eq!(
            raw.strs.get("secret_token").cloned(),
            Some("REAL_TOKEN".into()),
            "<hidden> placeholder must preserve the existing secret value"
        );
        assert_eq!(raw.strs.get("description").cloned(), Some("new".into()));
    }

    #[test]
    fn real_value_for_secret_field_overwrites() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(&item_named("svc", &[("secret_token", "OLD")]), false)
            .unwrap();
        let mut update = item_named("svc", &[("secret_token", "NEW")]);
        update.id = id;
        store.set(&update, true).unwrap();
        assert_eq!(
            store.get(id).unwrap().strs.get("secret_token").cloned(),
            Some("NEW".into())
        );
    }

    #[test]
    fn hidden_placeholder_on_insert_drops_field() {
        // New entry with secret_x = "<hidden>" — there's nothing to preserve;
        // the field must not land on disk as the literal "<hidden>".
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(
                &item_named(
                    "svc",
                    &[("secret_token", HIDDEN_PLACEHOLDER), ("description", "x")],
                ),
                true,
            )
            .unwrap();
        let raw = store.get(id).unwrap();
        assert!(
            raw.strs.get("secret_token").is_none(),
            "<hidden> on a brand-new entry must drop the field"
        );
        assert_eq!(raw.strs.get("description").cloned(), Some("x".into()));
    }

    #[test]
    fn merge_default_preserves_untouched_non_secret_fields() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(
                &item_named(
                    "svc",
                    &[
                        ("secret_token", "REAL"),
                        ("description", "keep-me"),
                        ("env", "prod"),
                    ],
                ),
                false,
            )
            .unwrap();
        // Client sends a partial update touching only `env`.
        let mut update = Item::new();
        update.id = id;
        update.strs.insert("env".into(), "staging".into());
        store.set(&update, true).unwrap();
        let raw = store.get(id).unwrap();
        assert_eq!(raw.strs.get("env").cloned(), Some("staging".into()));
        assert_eq!(raw.strs.get("description").cloned(), Some("keep-me".into()));
        assert_eq!(raw.strs.get("secret_token").cloned(), Some("REAL".into()));
        assert_eq!(raw.strs.get(NAME_FIELD).cloned(), Some("svc".into()));
    }

    #[test]
    fn replace_mode_with_hidden_still_preserves_secret() {
        // merge=false: incoming Item replaces existing entirely, but a
        // "<hidden>" value for a secret field still falls back to the
        // existing value.
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(
                &item_named("svc", &[("secret_token", "REAL"), ("description", "old")]),
                false,
            )
            .unwrap();
        let mut replace = item_named(
            "svc",
            &[("secret_token", HIDDEN_PLACEHOLDER), ("description", "new")],
        );
        replace.id = id;
        store.set(&replace, false).unwrap();
        let raw = store.get(id).unwrap();
        assert_eq!(raw.strs.get("secret_token").cloned(), Some("REAL".into()));
        assert_eq!(raw.strs.get("description").cloned(), Some("new".into()));
    }

    #[test]
    fn replace_mode_drops_unmentioned_non_secret_fields() {
        // Sanity: merge=false really is replace for non-secret fields.
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(
                &item_named(
                    "svc",
                    &[
                        ("secret_token", "REAL"),
                        ("description", "old"),
                        ("env", "p"),
                    ],
                ),
                false,
            )
            .unwrap();
        let mut replace = item_named("svc", &[("secret_token", HIDDEN_PLACEHOLDER)]);
        replace.id = id;
        store.set(&replace, false).unwrap();
        let raw = store.get(id).unwrap();
        // secret preserved
        assert_eq!(raw.strs.get("secret_token").cloned(), Some("REAL".into()));
        // non-secret unmentioned fields dropped
        assert!(raw.strs.get("description").is_none());
        assert!(raw.strs.get("env").is_none());
    }

    #[test]
    fn rename_via_merge_preserves_secret() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(&item_named("old", &[("secret_token", "REAL")]), false)
            .unwrap();
        let mut rename = Item::new();
        rename.id = id;
        rename.strs.insert(NAME_FIELD.into(), "new".into());
        store.set(&rename, true).unwrap();
        let raw = store.get(id).unwrap();
        assert_eq!(raw.strs.get(NAME_FIELD).cloned(), Some("new".into()));
        assert_eq!(raw.strs.get("secret_token").cloned(), Some("REAL".into()));
        assert!(store.get_by_name("old").is_none());
        assert_eq!(store.get_by_name("new").unwrap().id, id);
    }

    #[test]
    fn merge_update_without_name_field_keeps_existing_name() {
        // Validation of name happens AFTER merge, so a partial PUT without
        // strs["name"] must not fail.
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let id = store
            .set(&item_named("svc", &[("description", "x")]), false)
            .unwrap();
        let mut update = Item::new();
        update.id = id;
        update.strs.insert("description".into(), "y".into());
        store.set(&update, true).unwrap();
        let raw = store.get(id).unwrap();
        assert_eq!(raw.strs.get(NAME_FIELD).cloned(), Some("svc".into()));
        assert_eq!(raw.strs.get("description").cloned(), Some("y".into()));
    }
}
