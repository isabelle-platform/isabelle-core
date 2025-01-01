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
use crate::state::store::*;
use log::info;
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Sync specific entry with google
pub async fn sync_with_google(
    srv: &mut crate::state::data::Data,
    add: bool,
    name: String,
    date_time: String,
) {
    let settings = srv.rw.get_settings().await;
    if !settings.safe_bool("sync_google_cal", false)
        || settings.safe_str("sync_google_creds", "") == ""
        || settings.safe_str("sync_google_email", "") == ""
        || settings.safe_str("sync_google_cal_name", "") == ""
    {
        info!("gcal: sync is disabled");
        return;
    }

    /* Put credentials to json file */
    let mut dir = env::current_exe().unwrap();
    dir.pop();
    let creds = srv.rw.get_credentials().await;
    let pickle = srv.rw.get_pickle().await;
    let mut file = File::create(creds.clone()).unwrap();

    write!(file, "{}", settings.strs["sync_google_creds"].clone()).ok();

    info!("gcal: synchronizing entry...");
    /* Run google calendar sync */
    Command::new(srv.py_path.clone())
        .current_dir(srv.gc_path.clone())
        .arg("-m")
        .arg("igc")
        .arg("-e")
        .arg(settings.strs["sync_google_email"].clone())
        .arg("-c")
        .arg(settings.strs["sync_google_cal_name"].clone())
        .arg("-creds")
        .arg(creds)
        .arg("-pickle")
        .arg(pickle)
        .arg(if add { "-add" } else { "-delete" })
        .arg("-add-name")
        .arg(name)
        .arg("-add-date-time")
        .arg(date_time)
        .spawn()
        .expect("Failed to sync with Google");
    info!("gcal: synchronization is done");
}

/// Initialize Google Calendar
pub async fn init_google(srv: &mut crate::state::data::Data) -> String {
    let settings = srv.rw.get_settings().await;
    if !settings.safe_bool("sync_google_cal", false)
        || settings.safe_str("sync_google_creds", "") == ""
        || settings.safe_str("sync_google_email", "") == ""
        || settings.safe_str("sync_google_cal_name", "") == ""
    {
        info!("gcal: sync is disabled");
        return "no_sync".to_string();
    }

    /* Put credentials to json file */
    let mut dir = env::current_exe().unwrap();
    dir.pop();
    let creds = srv.rw.get_credentials().await;
    let pickle = srv.rw.get_pickle().await;

    if !Path::new(&pickle).exists() {
        return "no_token".to_string();
    }

    let mut file = File::create(creds.clone()).unwrap();
    write!(file, "{}", settings.strs["sync_google_creds"].clone()).ok();

    info!("Syncing entry with Google...");
    /* Run google calendar sync */
    let res = Command::new(srv.py_path.clone())
        .current_dir(srv.gc_path.clone())
        .arg("-m")
        .arg("igc")
        .arg("-e")
        .arg(settings.strs["sync_google_email"].clone())
        .arg("-c")
        .arg(settings.strs["sync_google_cal_name"].clone())
        .arg("-creds")
        .arg(creds)
        .arg("-pickle")
        .arg(pickle)
        .arg("-init")
        .output()
        .expect("Failed to sync with Google");
    info!("Initialization of Google is done");
    return String::from_utf8(res.stdout).unwrap();
}

/// Authenticate Google
pub async fn auth_google(srv: &mut crate::state::data::Data) -> String {
    let settings = srv.rw.get_settings().await;
    if !settings.safe_bool("sync_google_cal", false)
        || settings.safe_str("sync_google_creds", "") == ""
    {
        info!("Don't auth with google");
        return "no_auth".to_string();
    }

    /* Put credentials to json file */
    let mut dir = env::current_exe().unwrap();
    dir.pop();
    let creds = srv.rw.get_credentials().await;
    let pickle = srv.rw.get_pickle().await;

    if Path::new(&pickle).exists() {
        return "token_exists".to_string();
    }

    let mut file = File::create(creds.clone()).unwrap();
    write!(file, "{}", settings.strs["sync_google_creds"].clone()).ok();

    info!("Authentication with Google...");
    /* Run google calendar sync */
    let _res = Command::new(srv.py_path.clone())
        .current_dir(srv.gc_path.clone())
        .arg("-m")
        .arg("igc")
        .arg("-flow-start")
        .arg("-flow-url")
        .arg(dir.display().to_string() + "/flow.url")
        .arg("-flow-backlink")
        .arg(srv.public_url.clone() + "/setting/gcal_auth")
        .arg("-creds")
        .arg(creds)
        .arg("-pickle")
        .arg(pickle)
        .spawn();
    info!("Flow is running");

    for _i in 1..10 {
        if Path::new(&(dir.display().to_string() + "/flow.url")).exists() {
            let s = fs::read_to_string(&(dir.display().to_string() + "/flow.url")).unwrap();
            info!("URL provided");
            return s;
        }
        thread::sleep(Duration::from_millis(5000));
    }

    info!("Flow timed out");

    return "running".to_string();
}

/// Finish Google Authentication
pub async fn auth_google_end(
    srv: &mut crate::state::data::Data,
    full_query: String,
    state: String,
    code: String,
) -> String {
    let settings = srv.rw.get_settings().await;
    info!("Ending Google authentication...");
    if !settings.safe_bool("sync_google_cal", false)
        || settings.safe_str("sync_google_creds", "") == ""
    {
        info!("Don't auth with google");
        return "no_auth".to_string();
    }

    info!("Putting credentials to file");
    /* Put credentials to json file */
    let mut dir = env::current_exe().unwrap();
    dir.pop();
    let creds = srv.rw.get_credentials().await;
    let pickle = srv.rw.get_pickle().await;

    if Path::new(&pickle).exists() {
        info!("Token exists?");
        return "token_exists".to_string();
    }

    let mut file = File::create(creds.clone()).unwrap();
    write!(file, "{}", settings.strs["sync_google_creds"].clone()).ok();

    info!("Finish Authentication with Google...");
    /* Run google calendar sync */
    let _res = Command::new(srv.py_path.clone())
        .current_dir(srv.gc_path.clone())
        .arg("-m")
        .arg("igc")
        .arg("-flow-end")
        .arg("-flow-code")
        .arg(code)
        .arg("-flow-state")
        .arg(state)
        .arg("-flow-complete-url")
        .arg(full_query)
        .arg("-flow-backlink")
        .arg(srv.public_url.clone() + "/setting/gcal_auth")
        .arg("-creds")
        .arg(creds)
        .arg("-pickle")
        .arg(pickle)
        .spawn();
    info!("Started OAuth saver");

    thread::sleep(Duration::from_millis(5000));

    return "running".to_string();
}
