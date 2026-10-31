//! Automatic disk budgeting: look at how big the data filesystem is, decide
//! how the deployment's consumers may share it, and keep a guaranteed slice of
//! free space for the host itself.
//!
//! The platform's three big disk consumers — MongoDB, uploaded files, and the
//! scratch of each analysis/test job — can between them fill a disk, and a
//! disk with no free space is one where the database aborts and the host
//! wedges. Rather than make an operator hand-size every limit, the server
//! reads the filesystem's total size and computes the split itself, reserving
//! headroom for the host before anything else gets a share.
//!
//! The policy and budget shapes, and the one pure computation
//! ([`plan_budget`]), live in `isabelle_plugin_api::actor` so a plugin agrees
//! with core without re-implementing them. This module is core's side: the
//! `statvfs` reader, the active policy stored on [`Data`], the minute
//! [`monitor`] that maintains [`Data::disk_low`], and the [`report`]/
//! [`set_policy`]/[`load_policy`] a plugin reaches through the CoreHandle.
//!
//! What is *enforced* today is the reserve: [`monitor`] stats the filesystem
//! that holds `data_path` (where uploads live, and where MongoDB's data lives
//! too when it shares that filesystem — the usual single-host case) and sets
//! [`Data::disk_low`] when its available space reaches the reserve; the upload
//! path then refuses new file writes while the flag is set. The per-consumer
//! caps are the computed split: `per_job_disk` is what a per-job cap is derived
//! from, the others document the intended share. A hard per-Mongo cap would
//! need Mongo's own `dbPath` stat'd separately and is not wired here.

use crate::state::data::Data;
use isabelle_dm::data_model::item::Item;
use isabelle_plugin_api::actor::{plan_budget, DiskMetrics, DiskPolicy, DiskReport};
use std::sync::atomic::Ordering;

/// `statvfs(path)` as `(total, available)` bytes, or `None` if it cannot be
/// stat'd. `available` uses `f_bavail` (blocks free to non-root) — the space a
/// server process can really write — scaled by `f_frsize`; `total` is
/// `f_blocks`. Through rustix's safe wrapper, as the crate forbids `unsafe`.
pub fn disk_stat(path: &str) -> Option<(u64, u64)> {
    let s = rustix::fs::statvfs(path).ok()?;
    let frsize = s.f_frsize as u64;
    Some((
        (s.f_blocks as u64).saturating_mul(frsize),
        (s.f_bavail as u64).saturating_mul(frsize),
    ))
}

/// The data filesystem path to watch — `data_path`, or `.` if it is unset.
fn watch_path(srv: &Data) -> String {
    let p = srv.data_path.lock().clone();
    if p.is_empty() {
        ".".to_string()
    } else {
        p
    }
}

/// The full disk situation a plugin reads: live metrics, the computed budget,
/// and the active policy. A filesystem that cannot be stat'd reports zero
/// metrics with the current `disk_low` flag, so a caller still sees the policy
/// and a safe (no-cap) budget.
pub fn report(srv: &Data) -> DiskReport {
    let policy = *srv.disk_policy.lock();
    let disk_low = srv.disk_low.load(Ordering::Relaxed);
    let (total, avail) = disk_stat(&watch_path(srv)).unwrap_or((0, 0));
    DiskReport {
        metrics: DiskMetrics {
            total_bytes: total,
            avail_bytes: avail,
            disk_low,
        },
        budget: plan_budget(total, &policy),
        policy,
    }
}

/// Replace the active policy and persist it, so a set survives a restart.
/// Returns whether the persisted write succeeded (the in-memory policy is
/// updated regardless, so the running server honours it immediately).
pub async fn set_policy(srv: &Data, policy: DiskPolicy) -> bool {
    *srv.disk_policy.lock() = policy;
    let mut settings = srv.rw.get_settings().await;
    policy_to_item(&policy, &mut settings);
    srv.rw.set_settings(settings).await
}

/// Load the policy persisted in settings into [`Data`] at startup. Missing keys
/// keep the shipped default, so a deployment that never set one is unaffected.
pub async fn load_policy(srv: &Data) {
    let settings = srv.rw.get_settings().await;
    let policy = policy_from_item(&settings, DiskPolicy::default());
    *srv.disk_policy.lock() = policy;
}

// Settings keys for the persisted policy. Floats are stored as strings and
// parsed back; a malformed stored value falls back to the default field.
const K_FLOOR: &str = "disk_root_reserve_floor";
const K_RES_FRAC: &str = "disk_root_reserve_frac";
const K_MONGO: &str = "disk_mongo_frac";
const K_UPLOAD: &str = "disk_upload_frac";
const K_JOB: &str = "disk_job_frac";
const K_JOBS: &str = "disk_max_concurrent_jobs";

fn policy_to_item(p: &DiskPolicy, item: &mut Item) {
    item.set_str(K_FLOOR, &p.root_reserve_floor.to_string());
    item.set_str(K_RES_FRAC, &p.root_reserve_frac.to_string());
    item.set_str(K_MONGO, &p.mongo_frac.to_string());
    item.set_str(K_UPLOAD, &p.upload_frac.to_string());
    item.set_str(K_JOB, &p.job_frac.to_string());
    item.set_str(K_JOBS, &p.max_concurrent_jobs.to_string());
}

fn policy_from_item(item: &Item, base: DiskPolicy) -> DiskPolicy {
    let u = |k: &str, d: u64| item.safe_str(k, "").trim().parse::<u64>().unwrap_or(d);
    let f = |k: &str, d: f64| item.safe_str(k, "").trim().parse::<f64>().unwrap_or(d);
    DiskPolicy {
        root_reserve_floor: u(K_FLOOR, base.root_reserve_floor),
        root_reserve_frac: f(K_RES_FRAC, base.root_reserve_frac),
        mongo_frac: f(K_MONGO, base.mongo_frac),
        upload_frac: f(K_UPLOAD, base.upload_frac),
        job_frac: f(K_JOB, base.job_frac),
        max_concurrent_jobs: u(K_JOBS, base.max_concurrent_jobs),
    }
}

/// Run one disk check and update [`Data::disk_low`]. Called every minute from
/// the periodic loop.
///
/// Stats the data filesystem, plans the budget under the active policy, and
/// sets the flag when available space is at or below the reserve (clears it on
/// recovery). The transition is logged — entering the low state as an error,
/// because the server is now shedding work; leaving it as info. A filesystem
/// that cannot be stat'd is left as-is, not assumed full: a transient stat
/// failure must not start refusing uploads on its own.
pub fn monitor(srv: &Data) {
    let path = watch_path(srv);
    let Some((total, avail)) = disk_stat(&path) else {
        log::warn!(target: "isabelle::disk", "could not stat data filesystem at {}", path);
        return;
    };
    let policy = *srv.disk_policy.lock();
    let budget = plan_budget(total, &policy);
    let low = avail <= budget.root_reserve;
    let was = srv.disk_low.swap(low, Ordering::Relaxed);

    if low && !was {
        log::error!(
            target: "isabelle::disk",
            "data filesystem {} low: {} MiB free, reserve is {} MiB — refusing new \
             uploads and jobs until it recovers",
            path,
            avail / (1024 * 1024),
            budget.root_reserve / (1024 * 1024),
        );
    } else if !low && was {
        log::info!(
            target: "isabelle::disk",
            "data filesystem {} recovered: {} MiB free, above the {} MiB reserve",
            path,
            avail / (1024 * 1024),
            budget.root_reserve / (1024 * 1024),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_stat_reads_the_current_filesystem() {
        // The working directory always exists; its filesystem has a nonzero
        // size. This also proves the statvfs binding links and runs.
        let (total, _avail) = disk_stat(".").expect("statvfs of . failed");
        assert!(total > 0, "a mounted filesystem has a nonzero size");
    }

    #[test]
    fn policy_round_trips_through_settings_and_defaults_fill_gaps() {
        let p = DiskPolicy {
            root_reserve_floor: 7 * 1024 * 1024 * 1024,
            root_reserve_frac: 0.15,
            mongo_frac: 0.40,
            upload_frac: 0.35,
            job_frac: 0.25,
            max_concurrent_jobs: 8,
        };
        let mut item = Item::new();
        policy_to_item(&p, &mut item);
        assert_eq!(policy_from_item(&item, DiskPolicy::default()), p);

        // An empty item keeps every default.
        assert_eq!(
            policy_from_item(&Item::new(), DiskPolicy::default()),
            DiskPolicy::default()
        );

        // A malformed stored value falls back to the base for that field only.
        let mut bad = Item::new();
        bad.set_str(K_JOBS, "lots");
        assert_eq!(
            policy_from_item(&bad, DiskPolicy::default()).max_concurrent_jobs,
            DiskPolicy::default().max_concurrent_jobs
        );
    }
}
