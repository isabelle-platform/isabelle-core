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
use crate::state::store::Store;
use isabelle_dm::data_model::item::Item;
use log::trace;

/// Check if login has bad symbols
pub fn login_has_bad_symbols(login: &str) -> bool {
    let bad_symbols = ['"', '\\', '{', '}', '[', ']', '$'];
    login.chars().any(|c| bad_symbols.contains(&c))
}

/// Get user by given login
pub async fn get_user(srv: &mut crate::state::data::Data, login: String) -> Option<Item> {
    if login_has_bad_symbols(&login) {
        return None;
    }

    let filter = "{ \"$or\": [ { \"strs.login\": \"".to_owned() + &login + "\" }, "
            + "{ \"strs.email\": \"" + &login + "\" } ]}";
    let users = srv.rw.get_all_items("user", "name", &filter).await;
    let tmp_login = login.to_lowercase();
    trace!("Users: {}", users.map.len());
    for item in &users.map {
        if item.1.strs.contains_key("login") && item.1.strs["login"].to_lowercase() == tmp_login {
            return Some(item.1.clone());
        }
        if item.1.strs.contains_key("email") && item.1.strs["email"].to_lowercase() == tmp_login {
            return Some(item.1.clone());
        }
    }

    return None;
}

/// Check user role
pub async fn check_role(
    srv: &mut crate::state::data::Data,
    user: &Option<Item>,
    role: &str,
) -> bool {
    let role_is = srv
        .rw
        .get_internals()
        .await
        .safe_str("user_role_prefix", "role_is_");
    if user.is_none() {
        return false;
    }
    return user
        .as_ref()
        .unwrap()
        .safe_bool(&(role_is.to_owned() + role), false);
}

/// Clear OTP for all users with given login/email
pub async fn clear_otp(srv: &mut crate::state::data::Data, login: String) {
    if login_has_bad_symbols(&login) {
        return;
    }

    let filter = "{ \"$or\": [ { \"strs.login\": \"".to_owned() + &login + "\" }, "
            + "{ \"strs.email\": \"" + &login + "\" } ]}";
    let users = srv.rw.get_all_items("user", "name", &filter).await;
    let tmp_login = login.to_lowercase();
    for item in &users.map {
        if item.1.strs.contains_key("login")
            && item.1.strs["login"].to_lowercase() == tmp_login
            && item.1.strs.contains_key("email")
            && item.1.strs["email"].to_lowercase() == tmp_login
        {
            let mut itm = item.1.clone();
            itm.set_str("otp", "");
            srv.rw.set_item("user", &itm, false).await;
            return;
        }
    }
}
