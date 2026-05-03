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
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub struct SecretStore {
    cipher: Aes256Gcm,
    path: PathBuf,
    entries: HashMap<String, Item>,
}

impl SecretStore {
    /// Open or create the secret store. The master key is loaded from
    /// `key_path`; if the file does not exist, a fresh random key is
    /// written there with restrictive permissions. The encrypted blob
    /// lives at `store_path`; an absent file means an empty store.
    pub fn open(key_path: &Path, store_path: &Path) -> io::Result<Self> {
        let key_bytes = load_or_create_key(key_path)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

        let entries = if store_path.exists() {
            let blob = fs::read(store_path)?;
            decrypt_blob(&cipher, &blob).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to decrypt secret store: {}", e),
                )
            })?
        } else {
            HashMap::new()
        };

        Ok(Self {
            cipher,
            path: store_path.to_path_buf(),
            entries,
        })
    }

    /// Internal-only: read a secret by key. There is no HTTP route that
    /// exposes this; values must never leave the process via the public API.
    #[allow(dead_code)]
    pub fn get(&self, key: &str) -> Option<Item> {
        self.entries.get(key).cloned()
    }

    pub fn list_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.entries.keys().cloned().collect();
        keys.sort();
        keys
    }

    pub fn set(&mut self, key: &str, item: &Item) -> io::Result<()> {
        self.entries.insert(key.to_string(), item.clone());
        self.flush()
    }

    pub fn del(&mut self, key: &str) -> io::Result<bool> {
        let removed = self.entries.remove(key).is_some();
        if removed {
            self.flush()?;
        }
        Ok(removed)
    }

    fn flush(&self) -> io::Result<()> {
        let plaintext = serde_json::to_vec(&self.entries).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {}", e))
        })?;
        let blob = encrypt_blob(&self.cipher, &plaintext).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("encrypt: {}", e))
        })?;
        atomic_write(&self.path, &blob, 0o600)
    }
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

fn decrypt_blob(cipher: &Aes256Gcm, blob: &[u8]) -> Result<HashMap<String, Item>, String> {
    if blob.len() < NONCE_LEN {
        return Err("blob shorter than nonce".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
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

    fn item_with(pairs: &[(&str, &str)]) -> Item {
        let mut it = Item::new();
        for (k, v) in pairs {
            it.strs.insert((*k).to_string(), (*v).to_string());
        }
        it
    }

    fn paths(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        (dir.path().join("k"), dir.path().join("s.enc"))
    }

    /// SecretStore intentionally does not implement Debug (no leakage of
    /// decrypted contents via {:?}), so we can't use Result::unwrap_err.
    fn expect_err(r: io::Result<SecretStore>) -> io::Error {
        match r {
            Ok(_) => panic!("expected Err"),
            Err(e) => e,
        }
    }

    // -------- initialization & key file lifecycle --------

    #[test]
    fn first_open_creates_key_file_and_no_store() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let store = SecretStore::open(&k, &s).unwrap();
        assert!(k.exists(), "key file must be created on first open");
        assert!(!s.exists(), "store file must not be created until first write");
        assert!(store.list_keys().is_empty());
        let bytes = fs::read(&k).unwrap();
        assert_eq!(bytes.len(), KEY_LEN, "key file must hold exactly 32 bytes");
    }

    #[test]
    fn key_file_is_reused_across_opens() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let _ = SecretStore::open(&k, &s).unwrap();
        let key1 = fs::read(&k).unwrap();
        let _ = SecretStore::open(&k, &s).unwrap();
        let key2 = fs::read(&k).unwrap();
        assert_eq!(key1, key2, "subsequent opens must not regenerate the key");
    }

    #[test]
    fn rejects_key_file_of_wrong_size() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        fs::write(&k, b"too-short").unwrap();
        let err = expect_err(SecretStore::open(&k, &s));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn creates_parent_directory_for_key_file() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested/deep/key");
        let store_path = dir.path().join("s.enc");
        let _ = SecretStore::open(&nested, &store_path).unwrap();
        assert!(nested.exists());
    }

    // -------- round-trip and persistence --------

    #[test]
    fn set_get_returns_full_item_fields() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let it = item_with(&[("login", "alice"), ("token", "tok-1"), ("scope", "r/w")]);
        store.set("svc", &it).unwrap();
        let got = store.get("svc").unwrap();
        assert_eq!(got.strs.get("login").cloned(), Some("alice".into()));
        assert_eq!(got.strs.get("token").cloned(), Some("tok-1".into()));
        assert_eq!(got.strs.get("scope").cloned(), Some("r/w".into()));
    }

    #[test]
    fn set_overwrites_existing_value() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set("dup", &item_with(&[("v", "1")])).unwrap();
        store.set("dup", &item_with(&[("v", "2")])).unwrap();
        assert_eq!(store.get("dup").unwrap().strs.get("v").cloned(), Some("2".into()));
        assert_eq!(store.list_keys(), vec!["dup".to_string()]);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        {
            let mut store = SecretStore::open(&k, &s).unwrap();
            store.set("k1", &item_with(&[("x", "y")])).unwrap();
            store.set("k2", &item_with(&[("a", "b")])).unwrap();
        }
        let store = SecretStore::open(&k, &s).unwrap();
        assert_eq!(store.get("k1").unwrap().strs.get("x").cloned(), Some("y".into()));
        assert_eq!(store.get("k2").unwrap().strs.get("a").cloned(), Some("b".into()));
    }

    #[test]
    fn get_missing_returns_none() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let store = SecretStore::open(&k, &s).unwrap();
        assert!(store.get("nope").is_none());
    }

    #[test]
    fn del_missing_returns_false_and_skips_flush() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        assert!(!store.del("ghost").unwrap());
        assert!(!s.exists(), "deleting a missing key from empty store must not create the blob");
    }

    #[test]
    fn del_existing_removes_and_persists() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set("a", &item_with(&[("v", "1")])).unwrap();
        store.set("b", &item_with(&[("v", "2")])).unwrap();
        assert!(store.del("a").unwrap());
        let store2 = SecretStore::open(&k, &s).unwrap();
        assert!(store2.get("a").is_none());
        assert!(store2.get("b").is_some());
    }

    // -------- list ordering --------

    #[test]
    fn list_keys_is_sorted() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        for name in &["zeta", "alpha", "mu", "beta"] {
            store.set(name, &item_with(&[("v", name)])).unwrap();
        }
        assert_eq!(
            store.list_keys(),
            vec!["alpha".to_string(), "beta".into(), "mu".into(), "zeta".into()]
        );
    }

    // -------- security properties --------

    #[test]
    fn nonce_is_random_per_write() {
        // Writing the same plaintext twice must produce different ciphertexts
        // (random nonce + tag), otherwise we have nonce reuse.
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set("k", &item_with(&[("v", "1")])).unwrap();
        let blob1 = fs::read(&s).unwrap();
        store.set("k", &item_with(&[("v", "1")])).unwrap();
        let blob2 = fs::read(&s).unwrap();
        assert_ne!(blob1, blob2, "two writes of identical content must differ on disk");
        assert_ne!(&blob1[..NONCE_LEN], &blob2[..NONCE_LEN], "nonces must differ");
    }

    #[test]
    fn store_blob_does_not_contain_plaintext() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store
            .set("k", &item_with(&[("token", "SUPERSECRETVALUE12345")]))
            .unwrap();
        let blob = fs::read(&s).unwrap();
        assert!(
            !blob.windows(20).any(|w| w == b"SUPERSECRETVALUE1234"),
            "ciphertext must not contain plaintext substring"
        );
    }

    #[test]
    fn tampered_blob_fails_to_decrypt() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        {
            let mut store = SecretStore::open(&k, &s).unwrap();
            store.set("k", &item_with(&[("v", "x")])).unwrap();
        }
        // Flip a byte inside the ciphertext (past the nonce).
        let mut blob = fs::read(&s).unwrap();
        let idx = NONCE_LEN + 1;
        blob[idx] ^= 0xFF;
        fs::write(&s, &blob).unwrap();
        let err = expect_err(SecretStore::open(&k, &s));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_blob_fails_to_decrypt() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        {
            let mut store = SecretStore::open(&k, &s).unwrap();
            store.set("k", &item_with(&[("v", "x")])).unwrap();
        }
        // Cut off the GCM tag at the end.
        let blob = fs::read(&s).unwrap();
        fs::write(&s, &blob[..blob.len() - 4]).unwrap();
        let err = expect_err(SecretStore::open(&k, &s));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn blob_shorter_than_nonce_is_rejected() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        // First create a valid key.
        let _ = SecretStore::open(&k, &s).unwrap();
        // Now write a too-short blob.
        fs::write(&s, vec![0u8; NONCE_LEN - 1]).unwrap();
        let err = expect_err(SecretStore::open(&k, &s));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn wrong_key_cannot_decrypt_existing_store() {
        let dir = tempdir().unwrap();
        let (k1, s) = paths(&dir);
        {
            let mut store = SecretStore::open(&k1, &s).unwrap();
            store.set("k", &item_with(&[("v", "x")])).unwrap();
        }
        // Replace the key file with a different 32-byte key.
        fs::write(&k1, vec![0xAAu8; KEY_LEN]).unwrap();
        let err = expect_err(SecretStore::open(&k1, &s));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // -------- edge cases --------

    #[test]
    fn empty_item_round_trip() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set("empty", &Item::new()).unwrap();
        let got = store.get("empty").unwrap();
        assert!(got.strs.is_empty());
    }

    #[test]
    fn unicode_and_binary_safe_values() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let payload = "пароль 🔐 with \"quotes\", newlines\nand tabs\t";
        store
            .set("ключ", &item_with(&[("значение", payload)]))
            .unwrap();
        let store2 = SecretStore::open(&k, &s).unwrap();
        assert_eq!(
            store2.get("ключ").unwrap().strs.get("значение").cloned(),
            Some(payload.into())
        );
    }

    #[test]
    fn large_value_round_trip() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        let big = "X".repeat(64 * 1024);
        store.set("big", &item_with(&[("v", &big)])).unwrap();
        let store2 = SecretStore::open(&k, &s).unwrap();
        assert_eq!(store2.get("big").unwrap().strs.get("v").map(String::len), Some(big.len()));
    }

    #[test]
    fn many_keys() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        for i in 0..200 {
            store
                .set(&format!("k{:03}", i), &item_with(&[("i", &i.to_string())]))
                .unwrap();
        }
        let store2 = SecretStore::open(&k, &s).unwrap();
        assert_eq!(store2.list_keys().len(), 200);
        assert_eq!(
            store2.get("k042").unwrap().strs.get("i").cloned(),
            Some("42".into())
        );
    }

    // -------- file layout --------

    #[test]
    fn no_tmp_file_left_after_successful_write() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set("k", &item_with(&[("v", "1")])).unwrap();
        let tmp = s.with_extension("tmp");
        assert!(!tmp.exists(), "tmp file must be renamed away after flush");
    }

    #[cfg(unix)]
    #[test]
    fn key_and_store_files_have_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set("k", &item_with(&[("v", "1")])).unwrap();

        let key_mode = fs::metadata(&k).unwrap().permissions().mode() & 0o777;
        let store_mode = fs::metadata(&s).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600, "key file must be 0600");
        assert_eq!(store_mode, 0o600, "store file must be 0600");
    }

    #[test]
    fn empty_value_string_round_trip() {
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set("k", &item_with(&[("v", "")])).unwrap();
        assert_eq!(
            store.get("k").unwrap().strs.get("v").cloned(),
            Some(String::new())
        );
    }

    #[test]
    fn empty_key_string_is_storable() {
        // Documents current behavior: empty string is a valid key at the
        // SecretStore layer. The HTTP layer rejects empty keys separately.
        let dir = tempdir().unwrap();
        let (k, s) = paths(&dir);
        let mut store = SecretStore::open(&k, &s).unwrap();
        store.set("", &item_with(&[("v", "x")])).unwrap();
        assert_eq!(store.list_keys(), vec!["".to_string()]);
        assert!(store.get("").is_some());
    }
}
