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
//! Maintenance: closing the installation to new operations for the few
//! minutes an update of it takes, at a moment when none is running.
//!
//! An update stops this process. Whatever a plugin was doing stops being
//! watched, and whoever pressed a button in that minute gets an error page.
//! So an update is not started at once. It is *asked for*:
//!
//! ```text
//!   open ──ask──▶ waiting ──nothing running──▶ closed ──reopen──▶ open
//!                    └── waited too long ──▶ open, and it says why
//! ```
//!
//! The core does not know what an installation does that must not be cut
//! off — a machine being built, a test run being collected. Plugins do, and
//! say so: each such piece of work is opened with `CoreHandle::
//! operation_begin` and closed with `operation_end`. The core only counts.
//!
//! While **waiting**, nothing changes for anybody. The moment the count is
//! zero the gate is closed, in the same step as the look, so nothing can
//! start in between. While **closed**, `operation_begin` refuses, and that
//! is all the core does: signing in, reading and writing records go on, and
//! what else must wait is a plugin's to decide, by asking whether it is
//! closed. It reopens when told, and by itself after a set number of
//! minutes if nobody tells it — an update that failed halfway must not leave
//! an installation refusing work until somebody notices.
//!
//! The state is a file, `platform/maintenance.json` under the data path,
//! and not a setting: it is read by the update script, which is a root
//! shell that cannot sign in, and it has to survive the restart it exists
//! for. The script asks the same way, by leaving `maintenance-request`
//! beside it (`action=begin` or `action=end`, optionally `minutes=` and
//! `wait_hours=`); see `maintenance.sh` in isabelle-scripts.

use chrono::{DateTime, Duration, Utc};
use isabelle_plugin_api::actor::MaintenanceInfo;
use log::{error, info, warn};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const STATE_FILE: &str = "maintenance.json";
const REQUEST_FILE: &str = "maintenance-request";

/// How long the installation stays closed when nobody says, in minutes.
pub const DEFAULT_MINUTES: u64 = 15;
/// How long a quiet moment is waited for when nobody says, in hours.
pub const DEFAULT_WAIT_HOURS: u64 = 6;
/// The settings an administrator changes those two with.
pub const MINUTES_SETTING: &str = "maintenance_minutes";
pub const WAIT_HOURS_SETTING: &str = "maintenance_wait_hours";

/// What is kept in the file.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// `open`, `waiting` or `closed`. Empty reads as `open`.
    pub state: String,
    pub asked_at: String,
    /// Who asked: a login, a plugin, or `the update script`.
    pub asked_by: String,
    /// What for, in the asker's words.
    pub reason: String,
    /// While waiting: when to stop waiting.
    pub wait_until: String,
    pub closed_at: String,
    /// While closed: when it reopens by itself.
    pub reopen_at: String,
    /// How long to stay closed once closed.
    pub minutes: u64,
    /// How the last request ended, for whoever asked.
    pub note: String,
}

impl State {
    fn is(&self, s: &str) -> bool {
        match s {
            "open" => self.state.is_empty() || self.state == "open",
            other => self.state == other,
        }
    }

    fn name(&self) -> &str {
        if self.is("open") {
            "open"
        } else {
            &self.state
        }
    }
}

fn at(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn ask_state(
    st: &mut State,
    now: DateTime<Utc>,
    by: &str,
    reason: &str,
    minutes: u64,
    wait_hours: u64,
) {
    st.state = "waiting".into();
    st.asked_at = now.to_rfc3339();
    st.asked_by = by.to_string();
    st.reason = reason.to_string();
    st.wait_until = (now + Duration::hours(wait_hours.clamp(1, 72) as i64)).to_rfc3339();
    st.closed_at.clear();
    st.reopen_at.clear();
    st.minutes = minutes.clamp(1, 120);
    st.note.clear();
}

fn shut(st: &mut State, now: DateTime<Utc>) {
    st.state = "closed".into();
    st.closed_at = now.to_rfc3339();
    st.reopen_at = (now + Duration::minutes(st.minutes.clamp(1, 120) as i64)).to_rfc3339();
    st.wait_until.clear();
}

fn open(st: &mut State, note: &str) {
    st.state = "open".into();
    st.wait_until.clear();
    st.closed_at.clear();
    st.reopen_at.clear();
    st.reason.clear();
    st.note = note.to_string();
}

/// What a step did.
#[derive(Debug, PartialEq)]
enum Effect {
    Nothing,
    Closed,
    Reopened,
    GaveUp,
}

/// Move the state on by the clock and by what is running. `running` is what
/// is open now; an empty one while waiting is the quiet moment.
fn advance(st: &mut State, now: DateTime<Utc>, running: &[String]) -> Effect {
    if st.is("waiting") {
        if running.is_empty() {
            shut(st, now);
            return Effect::Closed;
        }
        if at(&st.wait_until).map(|t| now >= t).unwrap_or(true) {
            open(
                st,
                &format!(
                    "Not closed: the wait for a quiet moment ran out. Still running: {}.",
                    running.join("; ")
                ),
            );
            return Effect::GaveUp;
        }
        return Effect::Nothing;
    }
    if st.is("closed") && at(&st.reopen_at).map(|t| now >= t).unwrap_or(true) {
        let minutes = st.minutes;
        open(
            st,
            &format!("Reopened by itself: nobody reopened it within {minutes} minute(s)."),
        );
        return Effect::Reopened;
    }
    Effect::Nothing
}

/// A request a script left, read as data: unknown keys, and anything that is
/// not a number where one is expected, are ignored.
#[derive(Debug, Default, PartialEq)]
struct Request {
    action: String,
    minutes: Option<u64>,
    wait_hours: Option<u64>,
}

fn parse_request(text: &str) -> Request {
    let mut r = Request::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match (k.trim(), v.trim()) {
            ("action", v) => r.action = v.to_string(),
            ("minutes", v) => r.minutes = v.parse().ok(),
            ("wait_hours", v) => r.wait_hours = v.parse().ok(),
            _ => {}
        }
    }
    r
}

/// Everything, under one lock: the state, and what is open. One lock is the
/// point — "is anything running" and "close" must be one question.
struct Inner {
    /// Where the files are; `None` until [`load`].
    dir: Option<PathBuf>,
    st: State,
    next_token: u64,
    /// What is open: token → the words it was opened with.
    open: BTreeMap<u64, String>,
    /// The installation's own numbers, as last read from the settings.
    minutes: u64,
    wait_hours: u64,
}

static INNER: Mutex<Inner> = Mutex::new(Inner {
    dir: None,
    st: State {
        state: String::new(),
        asked_at: String::new(),
        asked_by: String::new(),
        reason: String::new(),
        wait_until: String::new(),
        closed_at: String::new(),
        reopen_at: String::new(),
        minutes: 0,
        note: String::new(),
    },
    next_token: 1,
    open: BTreeMap::new(),
    minutes: DEFAULT_MINUTES,
    wait_hours: DEFAULT_WAIT_HOURS,
});

impl Inner {
    fn running(&self) -> Vec<String> {
        self.open.values().cloned().collect()
    }

    fn info(&self) -> MaintenanceInfo {
        MaintenanceInfo {
            state: self.st.name().to_string(),
            asked_by: self.st.asked_by.clone(),
            reason: self.st.reason.clone(),
            wait_until: self.st.wait_until.clone(),
            reopen_at: self.st.reopen_at.clone(),
            note: self.st.note.clone(),
            running: self.running(),
        }
    }

    fn persist(&self) {
        if let Some(dir) = &self.dir {
            write_state(dir, &self.st);
        }
    }

    /// Apply the clock and the count, and write the file if that changed it.
    fn step(&mut self, now: DateTime<Utc>) {
        let running = self.running();
        match advance(&mut self.st, now, &running) {
            Effect::Closed => warn!(
                "maintenance: closed, nothing is running. Reopens at {} unless told sooner",
                self.st.reopen_at
            ),
            Effect::Reopened | Effect::GaveUp => warn!("maintenance: {}", self.st.note),
            Effect::Nothing => return,
        }
        self.persist();
    }
}

fn read_state(dir: &Path) -> State {
    std::fs::read_to_string(dir.join(STATE_FILE))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Written beside and renamed into place: the script that polls this file
/// must never read half of it.
fn write_state(dir: &Path, st: &State) {
    let _ = std::fs::create_dir_all(dir);
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    let text = serde_json::to_string_pretty(st).unwrap_or_default();
    if std::fs::write(&tmp, text).is_err() || std::fs::rename(&tmp, dir.join(STATE_FILE)).is_err() {
        error!(
            "maintenance: could not write {} — a script waiting on it will not see the change",
            dir.join(STATE_FILE).display()
        );
    }
}

/// At start: an installation that was closed when it stopped is closed when
/// it starts, until it is told otherwise or the time is up.
pub fn load(data_path: &str) {
    let dir = PathBuf::from(data_path).join("platform");
    let st = read_state(&dir);
    if st.is("closed") {
        warn!(
            "maintenance: starting closed, until {} unless reopened",
            st.reopen_at
        );
    }
    let mut i = INNER.lock();
    i.st = st;
    i.dir = Some(dir);
}

/// The installation's own numbers, from its settings. Read where settings
/// can be awaited — at start and whenever somebody asks through the API —
/// and kept for the clock, which cannot await.
pub fn set_defaults(minutes: Option<u64>, wait_hours: Option<u64>) {
    let mut i = INNER.lock();
    i.minutes = minutes.unwrap_or(DEFAULT_MINUTES);
    i.wait_hours = wait_hours.unwrap_or(DEFAULT_WAIT_HOURS);
}

/// Open an operation. `None` when closed, unless it is one being carried on
/// across a restart — that one was running already, and letting it finish is
/// what a closing waits for.
pub fn begin(title: &str, resumed: bool) -> Option<u64> {
    let mut i = INNER.lock();
    if i.st.is("closed") && !resumed {
        info!("maintenance: refused while closed: {}", title);
        return None;
    }
    let token = i.next_token;
    i.next_token += 1;
    i.open.insert(token, title.to_string());
    Some(token)
}

/// Close an operation. If it was the last one a closing waited for, the
/// closing happens here and not a second later.
pub fn end(token: u64) {
    let mut i = INNER.lock();
    if i.open.remove(&token).is_some() {
        i.step(Utc::now());
    }
}

pub fn info() -> MaintenanceInfo {
    INNER.lock().info()
}

/// Ask for a closing at the next quiet moment — which may be now. Already
/// closed, whoever asks again has what they wanted.
pub fn ask(
    by: &str,
    reason: &str,
    minutes: Option<u64>,
    wait_hours: Option<u64>,
) -> MaintenanceInfo {
    let mut i = INNER.lock();
    if !i.st.is("closed") {
        let (m, w) = (
            minutes.unwrap_or(i.minutes),
            wait_hours.unwrap_or(i.wait_hours),
        );
        let now = Utc::now();
        ask_state(&mut i.st, now, by, reason, m, w);
        warn!(
            "maintenance: {} asked to close at the next quiet moment (waiting until {})",
            by, i.st.wait_until
        );
        i.persist();
        i.step(now);
    }
    i.info()
}

/// Close now, whatever is running. What is running carries on.
pub fn close_now(by: &str, reason: &str, minutes: Option<u64>) -> MaintenanceInfo {
    let mut i = INNER.lock();
    let now = Utc::now();
    i.st.asked_at = now.to_rfc3339();
    i.st.asked_by = by.to_string();
    i.st.reason = reason.to_string();
    i.st.minutes = minutes.unwrap_or(i.minutes).clamp(1, 120);
    i.st.note.clear();
    shut(&mut i.st, now);
    warn!(
        "maintenance: {} closed the installation until {}",
        by, i.st.reopen_at
    );
    i.persist();
    i.info()
}

/// Take operations again, and drop a request that is still waiting.
pub fn reopen(by: &str) -> MaintenanceInfo {
    let mut i = INNER.lock();
    if !i.st.is("open") {
        let was = i.st.state.clone();
        open(&mut i.st, "");
        warn!(
            "maintenance: {} reopened the installation (it was {})",
            by, was
        );
        i.persist();
    }
    i.info()
}

/// Every second, from the core's clock: a request a script left, and the
/// state moved on.
pub fn tick() {
    let request_path = match &INNER.lock().dir {
        Some(d) => d.join(REQUEST_FILE),
        None => return,
    };
    // Acted on once. Removed only after the state file says what came of
    // it: the script takes the request's going as the sign that the state
    // is now the answer to it.
    if let Ok(text) = std::fs::read_to_string(&request_path) {
        let req = parse_request(&text);
        match req.action.as_str() {
            "begin" => {
                ask("the update script", "update", req.minutes, req.wait_hours);
            }
            "end" => {
                reopen("the update script");
            }
            other => warn!("maintenance: a request with action {:?} was ignored", other),
        }
        if let Err(e) = std::fs::remove_file(&request_path) {
            error!(
                "maintenance: could not remove {} ({}) — it will be read again every second",
                request_path.display(),
                e
            );
        }
    }
    INNER.lock().step(Utc::now());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        at(s).unwrap()
    }

    const NOON: &str = "2026-11-18T12:00:00+00:00";

    fn busy() -> Vec<String> {
        vec!["Build the instance for acme".to_string()]
    }

    #[test]
    fn asked_for_it_closes_only_when_nothing_runs() {
        let mut st = State::default();
        ask_state(&mut st, t(NOON), "ops", "update", 15, 6);
        assert!(st.is("waiting"));

        // Something is running: nothing changes for anybody.
        assert_eq!(
            advance(&mut st, t("2026-11-18T12:30:00+00:00"), &busy()),
            Effect::Nothing
        );
        assert!(st.is("waiting"));

        // Quiet: closed, and it knows when it reopens by itself.
        assert_eq!(
            advance(&mut st, t("2026-11-18T13:00:00+00:00"), &[]),
            Effect::Closed
        );
        assert!(st.is("closed"));
        assert_eq!(t(&st.reopen_at), t("2026-11-18T13:15:00+00:00"));
    }

    #[test]
    fn a_wait_that_runs_out_says_what_was_in_the_way() {
        let mut st = State::default();
        ask_state(&mut st, t(NOON), "ops", "update", 15, 6);
        assert_eq!(
            advance(&mut st, t("2026-11-18T17:59:00+00:00"), &busy()),
            Effect::Nothing
        );
        assert_eq!(
            advance(&mut st, t("2026-11-18T18:00:00+00:00"), &busy()),
            Effect::GaveUp
        );
        assert!(st.is("open"));
        assert!(
            st.note.contains("Build the instance for acme"),
            "{}",
            st.note
        );
    }

    #[test]
    fn closed_reopens_by_itself_when_nobody_does() {
        let mut st = State::default();
        ask_state(&mut st, t(NOON), "ops", "update", 10, 6);
        advance(&mut st, t(NOON), &[]);
        // Work that was let through (carried on across a restart) does not
        // hold the reopening off.
        assert_eq!(
            advance(&mut st, t("2026-11-18T12:09:59+00:00"), &busy()),
            Effect::Nothing
        );
        assert!(st.is("closed"));
        assert_eq!(
            advance(&mut st, t("2026-11-18T12:10:00+00:00"), &busy()),
            Effect::Reopened
        );
        assert!(st.is("open"));
        assert!(st.note.contains("10 minute"), "{}", st.note);
    }

    #[test]
    fn a_closed_state_with_no_time_on_it_does_not_stay_closed_for_ever() {
        // A file somebody wrote by hand, or half of one.
        let mut st = State {
            state: "closed".into(),
            ..State::default()
        };
        assert_eq!(advance(&mut st, t(NOON), &[]), Effect::Reopened);
    }

    #[test]
    fn open_is_left_alone() {
        let mut st = State::default();
        assert_eq!(advance(&mut st, t(NOON), &busy()), Effect::Nothing);
        assert!(st.is("open"));
        assert_eq!(st.name(), "open");
    }

    #[test]
    fn what_is_asked_for_is_kept_within_reason() {
        let mut st = State::default();
        ask_state(&mut st, t(NOON), "ops", "", 0, 0);
        assert_eq!(st.minutes, 1);
        assert_eq!(t(&st.wait_until), t("2026-11-18T13:00:00+00:00"));
        ask_state(&mut st, t(NOON), "ops", "", 100_000, 100_000);
        assert_eq!(st.minutes, 120);
        assert_eq!(t(&st.wait_until), t("2026-11-21T12:00:00+00:00"));
    }

    #[test]
    fn a_request_is_read_as_data() {
        assert_eq!(
            parse_request("action=begin\nminutes=20\nwait_hours=2\n"),
            Request {
                action: "begin".into(),
                minutes: Some(20),
                wait_hours: Some(2),
            }
        );
        // Shell in a value is a value; a number that is not one is absent.
        assert_eq!(
            parse_request("action=end; rm -rf /\nminutes=$(id)\nnonsense\n"),
            Request {
                action: "end; rm -rf /".into(),
                minutes: None,
                wait_hours: None,
            }
        );
    }

    #[test]
    fn the_state_survives_the_file() {
        let dir = std::env::temp_dir().join(format!("isabelle-maint-{}", std::process::id()));
        let mut st = State::default();
        ask_state(&mut st, t(NOON), "ops", "update to main-541", 15, 6);
        write_state(&dir, &st);
        assert_eq!(read_state(&dir), st);
        // No file, or one that is not JSON, is an open installation.
        let _ = std::fs::write(dir.join(STATE_FILE), "{ half");
        assert!(read_state(&dir).is("open"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole path through the lock, as a plugin and a script use it.
    /// One test, because the state under the lock is the process's.
    #[test]
    fn an_operation_holds_the_closing_off_and_its_end_closes() {
        reopen("test");
        let build = begin("Build the instance for acme", false).expect("open: taken");
        let i = ask("an administrator", "update", Some(5), Some(1));
        assert_eq!(i.state, "waiting");
        assert_eq!(i.running, vec!["Build the instance for acme".to_string()]);
        // Waiting changes nothing for anybody.
        let other = begin("Restart shop", false).expect("waiting: still taken");
        end(other);
        assert_eq!(info().state, "waiting");
        // The last one ends: closed in that step.
        end(build);
        assert!(info().is_closed());
        assert_eq!(begin("Build another", false), None);
        // One carried on across a restart is counted, not refused.
        let carried = begin("Build the instance for acme", true).expect("resumed");
        end(carried);
        assert!(info().is_closed());
        // Asked again while closed: it is what they wanted.
        assert!(ask("the update script", "update", None, None).is_closed());
        assert_eq!(reopen("test").state, "open");
        assert!(begin("Build another", false).is_some());
    }
}
