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

//! Durable file replacement.
//!
//! `std::fs::write` truncates the target and then writes into it, so an
//! interruption anywhere in between — a crash, a full disk, a container being
//! killed — leaves a file that exists, is readable, and is not valid JSON.
//! Every reader of `settings.js`, `internals.js` and the per-item `data.js`
//! then fails to parse it, and `/is_logged_in` is an unauthenticated endpoint
//! that reads settings on every call. One interrupted write turned into a
//! permanent outage that no restart cleared.
//!
//! Writing to a sibling temporary file and renaming it over the target makes
//! the replacement atomic for any reader: they see the old contents or the new
//! ones, never a half of either.

use std::fs;
use std::io;
use std::path::Path;

/// Default permissions for data files: owner read/write. Callers holding
/// credential material pass something stricter or equal.
pub const DEFAULT_MODE: u32 = 0o600;

/// Replace `path` with `data`, atomically.
///
/// The temporary file is a sibling of the target so that the rename stays
/// within one filesystem — `rename` across mount points fails, and a fallback
/// copy would reintroduce exactly the torn write this exists to prevent.
///
/// Any failure after the staging file exists takes it back out again. Leaving
/// it behind would put a half-written `settings.js.tmp` next to the file it
/// was staging, which is the litter this function is supposed to make
/// impossible — and on a disk that filled up, the leftovers are what keeps it
/// full.
#[cfg(unix)]
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = tmp_sibling(path);
    let staged = || -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()
    }();
    finish(staged, &tmp, path)
}

#[cfg(not(unix))]
pub fn atomic_write(path: &Path, data: &[u8], _mode: u32) -> io::Result<()> {
    let tmp = tmp_sibling(path);
    let staged = || -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()
    }();
    finish(staged, &tmp, path)
}

/// Rename the staged file over the target, or clean it up if staging failed.
fn finish(staged: io::Result<()>, tmp: &Path, path: &Path) -> io::Result<()> {
    if let Err(e) = staged {
        let _ = fs::remove_file(tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(tmp, path) {
        let _ = fs::remove_file(tmp);
        return Err(e);
    }
    sync_parent(path);
    Ok(())
}

/// Flush the directory entry the rename just created.
///
/// `sync_all` on the staging file makes its *contents* durable, but the
/// rename that publishes them is a change to the parent directory, and that
/// is a separate write. Without this, a crash right after a successful
/// `atomic_write` can come back up with the target still naming the old
/// inode — the write is atomic either way, so nothing is torn, but the caller
/// was told the new contents had landed and they had not.
///
/// Best-effort: a filesystem that refuses to open a directory (some network
/// mounts) or to fsync one is not a reason to fail a write that has already
/// been published.
fn sync_parent(path: &Path) {
    if let Ok(dir) = fs::File::open(parent_dir(path)) {
        let _ = dir.sync_all();
    }
}

/// The directory whose entry names `path`.
///
/// `Path::parent` answers `Some("")` for a bare relative filename, and the
/// empty path opens nothing — so the one case where the fsync would silently
/// never happen is the plainest one. That resolves to the current directory.
fn parent_dir(path: &Path) -> std::path::PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    }
}

/// `foo.js` → `foo.js.tmp`.
///
/// Appending rather than replacing the extension matters: `with_extension`
/// would map both `data.js` and `data.json` onto the same `data.tmp`, so two
/// writers in one directory would corrupt each other's staging file.
fn tmp_sibling(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Serialize `value` as JSON and replace `path` with it atomically.
///
/// Returns the error rather than panicking: a write that cannot happen is
/// something the caller has to be able to report, and `expect()` on this path
/// drops the client's connection with no status at all.
pub fn write_json<T: serde::Serialize>(path: &str, value: &T) -> io::Result<()> {
    let encoded = serde_json::to_vec(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {}", e)))?;
    atomic_write(Path::new(path), &encoded, DEFAULT_MODE)
}

/// Read and parse a JSON file, or report why not.
///
/// A missing file and an unparseable one are different situations and the
/// callers treat them differently, so this does not flatten them into
/// `Option`.
pub fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> io::Result<T> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("parse: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn a_replaced_file_holds_the_new_contents() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.js");
        atomic_write(&path, b"{\"a\":1}", DEFAULT_MODE).unwrap();
        atomic_write(&path, b"{\"a\":2}", DEFAULT_MODE).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"a\":2}");
    }

    /// The staging file must not be left behind — a stray `settings.js.tmp`
    /// in a data directory is confusing at best and gets backed up at worst.
    #[test]
    fn no_staging_file_survives_the_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.js");
        atomic_write(&path, b"{}", DEFAULT_MODE).unwrap();
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind {:?}", leftovers);
    }

    /// Two files whose names differ only by extension must not share a
    /// staging path, or concurrent writes corrupt each other.
    #[test]
    fn staging_paths_do_not_collide_across_extensions() {
        let a = tmp_sibling(Path::new("/data/item.js"));
        let b = tmp_sibling(Path::new("/data/item.json"));
        assert_ne!(a, b);
    }

    #[test]
    fn round_trips_through_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("x.js").to_string_lossy().into_owned();
        write_json(&path, &vec![1u64, 2, 3]).unwrap();
        let back: Vec<u64> = read_json(&path).unwrap();
        assert_eq!(back, vec![1, 2, 3]);
    }

    /// A torn file is reported, not panicked on. This is the failure the
    /// atomic write prevents and the readers still have to survive.
    #[test]
    fn a_truncated_file_is_an_error_not_a_panic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("torn.js");
        fs::write(&path, "{\"strs\":{\"a\"").unwrap();
        let got: io::Result<serde_json::Value> = read_json(&path.to_string_lossy());
        assert!(got.is_err());
    }

    #[test]
    fn a_missing_file_is_distinguishable_from_a_broken_one() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.js");
        let got: io::Result<serde_json::Value> = read_json(&missing.to_string_lossy());
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    /// A write that cannot happen must leave the target exactly as it was.
    /// The staging file is what makes this possible, and it is also what
    /// gets left behind if nobody takes it away.
    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_neither_litter_nor_damage() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.js");
        atomic_write(&path, b"{\"a\":1}", DEFAULT_MODE).unwrap();

        // Read-only directory: the staging file cannot be created, so the
        // write fails at the first step.
        let mut perms = fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o500);
        fs::set_permissions(dir.path(), perms).unwrap();

        let got = atomic_write(&path, b"{\"a\":2}", DEFAULT_MODE);

        let mut perms = fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(dir.path(), perms).unwrap();

        assert!(got.is_err(), "a write into a read-only directory succeeded");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "{\"a\":1}",
            "a failed write damaged the target"
        );
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind {:?}", leftovers);
    }

    /// The rename is published through the parent directory, so the parent is
    /// what the post-rename fsync has to open. `Path::parent` answers with an
    /// empty path for a bare relative filename, and an empty path opens
    /// nothing — so without this the one case where the fsync would quietly
    /// never happen is the plainest one.
    #[test]
    fn the_parent_of_a_bare_relative_name_is_the_current_directory() {
        assert_eq!(parent_dir(Path::new("settings.js")), Path::new("."));
        assert_eq!(
            parent_dir(Path::new("/data/settings.js")),
            Path::new("/data")
        );
        assert_eq!(
            parent_dir(Path::new("collection/user/data.js")),
            Path::new("collection/user")
        );
    }
}
