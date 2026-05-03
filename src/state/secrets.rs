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

    #[test]
    fn roundtrip_set_get_del() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("k");
        let store_path = dir.path().join("s.enc");

        let mut item_a = Item::new();
        item_a.strs.insert("login".into(), "alpha".into());
        item_a.strs.insert("token".into(), "tok-a".into());

        let mut item_b = Item::new();
        item_b.strs.insert("login".into(), "beta".into());

        let mut s = SecretStore::open(&key_path, &store_path).unwrap();
        s.set("a", &item_a).unwrap();
        s.set("b", &item_b).unwrap();
        assert_eq!(s.get("a").unwrap().strs.get("token").cloned(), Some("tok-a".into()));

        let s2 = SecretStore::open(&key_path, &store_path).unwrap();
        assert_eq!(s2.get("b").unwrap().strs.get("login").cloned(), Some("beta".into()));

        let mut s3 = SecretStore::open(&key_path, &store_path).unwrap();
        assert!(s3.del("a").unwrap());
        assert_eq!(s3.list_keys(), vec!["b".to_string()]);
    }
}
