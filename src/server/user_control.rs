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
#[cfg(feature = "full_file_database")]
use log::trace;

/// Lifetime of a one-time password, in seconds.
pub const OTP_TTL_SECS: u64 = 600;

/// How many failed OTP attempts burn the code.
pub const OTP_MAX_ATTEMPTS: u64 = 5;

/// Minimal interval between two OTP issues for the same account.
pub const OTP_RESEND_INTERVAL_SECS: u64 = 60;

/// Current wall-clock time as a UNIX timestamp.
pub fn now_ts() -> u64 {
    let ts = chrono::Utc::now().timestamp();
    if ts < 0 {
        0
    } else {
        ts as u64
    }
}

/// Check if login has bad symbols
pub fn login_has_bad_symbols(login: &str) -> bool {
    let bad_symbols = ['"', '\\', '{', '}', '[', ']', '$'];
    login.chars().any(|c| bad_symbols.contains(&c))
}

/// Check that a login/email is usable as a lookup key.
///
/// `get_user` returns `None` for anything containing filter metacharacters,
/// so a record created with such a login would be permanently unfindable —
/// and, worse, would slip past any "is this login taken?" check. Registration
/// must reject these up front instead of relying on the lookup.
pub fn login_is_acceptable(login: &str) -> bool {
    !login.is_empty() && login.len() <= 254 && !login_has_bad_symbols(login)
}

/// What registration is allowed to do with the records it found.
#[derive(Debug, PartialEq, Eq)]
pub enum RegistrationTarget {
    /// No record matches either key — create a fresh one.
    Create,
    /// Both keys resolve to the same unfinished self-registration; accept the
    /// re-submit as a no-op.
    Resume(u64),
    /// Some record already owns one of the keys. It belongs to someone else
    /// (or to a finished registration) and must not be touched.
    Taken,
}

/// Decide what `/register` may do, given the lookups by login and by email.
///
/// Registration must never edit a record it did not create. The previous rule
/// — reuse anything with `logged_once == false` and overwrite its email — did
/// not distinguish an abandoned self-registration from an account an operator
/// provisioned and nobody has logged into yet. Both look identical, because
/// `logged_once` is only set by a successful login. That made every unused
/// account (an admin, say) takeable by whoever guessed its login: repoint the
/// email, request an OTP, receive the code.
///
/// So the only reuse permitted is an exact re-submit: both lookups land on the
/// same record, that record was created by registration itself, and it has
/// never been logged into. Nothing is rewritten in that case.
pub fn registration_target(
    usr_by_login: &Option<Item>,
    usr_by_email: &Option<Item>,
) -> RegistrationTarget {
    match (usr_by_login, usr_by_email) {
        (None, None) => RegistrationTarget::Create,
        (Some(by_login), Some(by_email))
            if by_login.id == by_email.id
                && by_login.safe_bool("self_registered", false)
                && !by_login.safe_bool("logged_once", false) =>
        {
            RegistrationTarget::Resume(by_login.id)
        }
        _ => RegistrationTarget::Taken,
    }
}

/// Whether the OTP stored on a record is still usable as a credential.
///
/// A record written before OTP expiry existed has no `otp_expires_at`, and is
/// treated as expired rather than valid forever.
pub fn otp_is_live(itm: &Item, now: u64) -> bool {
    !itm.safe_str("otp", "").is_empty()
        && itm.safe_u64("otp_expires_at", 0) > now
        && itm.safe_u64("otp_attempts", 0) < OTP_MAX_ATTEMPTS
}

/// Whether a new OTP may be issued for this record right now.
pub fn otp_may_be_issued(itm: &Item, now: u64) -> bool {
    itm.safe_bool("role_is_active", false)
        && now >= itm.safe_u64("otp_issued_at", 0) + OTP_RESEND_INTERVAL_SECS
}

/// Get user by given login
pub async fn get_user(srv: &crate::state::data::Data, login: String) -> Option<Item> {
    if login_has_bad_symbols(&login) {
        return None;
    }

    // Mongo path: short-TTL session cache + indexed find_one. Cache lives
    // on StoreMongo and is invalidated wholesale on any write to the
    // `user` collection (incl. plugin writes via the PluginApi).
    #[cfg(not(feature = "full_file_database"))]
    {
        srv.rw.find_user(&login).await
    }

    // File-store path: no JSON filter parser in StoreLocal — fall back
    // to fetching everything and matching in Rust. Sample/test only.
    #[cfg(feature = "full_file_database")]
    {
        let filter = "{ \"$or\": [ { \"strs.login\": \"".to_owned()
            + &login
            + "\" }, "
            + "{ \"strs.email\": \""
            + &login
            + "\" } ]}";
        let users = srv.rw.get_all_items("user", "name", &filter).await;
        let tmp_login = login.to_lowercase();
        trace!("Users: {}", users.map.len());
        for item in &users.map {
            if item.1.strs.contains_key("login") && item.1.strs["login"].to_lowercase() == tmp_login
            {
                return Some(item.1.clone());
            }
            if item.1.strs.contains_key("email") && item.1.strs["email"].to_lowercase() == tmp_login
            {
                return Some(item.1.clone());
            }
        }
        None
    }
}

/// Whether `user` currently holds `role`.
///
/// Deactivating an account has to revoke what it can already do, not just stop
/// it logging in again. This check used to read the role flag alone, so a
/// deactivated admin holding a live session cookie kept full access to
/// `/secret/*` (unmasked credential values), `/setting/*` and `/system/update`
/// — the only handlers guarded by it — until the cookie expired on its own.
/// With `CookieSessionStore` there is nothing server-side to expire or delete,
/// so short of rotating the signing key and logging everybody out, there was
/// no way to take that access away.
///
/// Requiring `role_is_active` here turns deactivation into a real revocation
/// lever: every request re-reads the user record, so clearing the flag takes
/// effect immediately, across every session and device.
///
/// This cannot lock out anyone who is able to log in: `login` already refuses
/// accounts whose `role_is_active` is not true, so any session that exists
/// passed that same check when it was created.
///
/// `role_is_active` is spelled out rather than composed from
/// `user_role_prefix`, matching how `login` and the plugin-side authorization
/// hooks name it — the prefix applies to the role being asked about, not to
/// the active flag.
fn role_is_granted(user: &Item, role_prefix: &str, role: &str) -> bool {
    if !user.safe_bool("role_is_active", false) {
        return false;
    }
    user.safe_bool(&(role_prefix.to_owned() + role), false)
}

/// Check user role. See [`role_is_granted`] for why an inactive account holds
/// no roles at all.
pub async fn check_role(srv: &crate::state::data::Data, user: &Option<Item>, role: &str) -> bool {
    let user = match user {
        Some(u) => u,
        None => return false,
    };
    let role_is = srv
        .rw
        .get_internals()
        .await
        .safe_str("user_role_prefix", "role_is_");
    role_is_granted(user, &role_is, role)
}

/// Record a failed OTP attempt so that a code can be brute-forced only a
/// bounded number of times before it has to be re-requested.
pub async fn bump_otp_attempts(srv: &crate::state::data::Data, id: u64, attempts: u64) {
    let mut itm = Item::new();
    itm.id = id;
    itm.set_u64("otp_attempts", attempts.saturating_add(1));
    srv.rw.set_item("user", &itm, true).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A user record as an operator would provision it: real login and email,
    /// no self-registration marker, never logged in.
    fn provisioned(id: u64) -> Item {
        let mut itm = Item::new();
        itm.id = id;
        itm.set_str("login", "admin");
        itm.set_str("email", "admin@example.org");
        itm.set_bool("role_is_admin", true);
        itm
    }

    fn self_registered(id: u64) -> Item {
        let mut itm = Item::new();
        itm.id = id;
        itm.set_str("login", "bob");
        itm.set_str("email", "bob@example.org");
        itm.set_bool("self_registered", true);
        itm
    }

    #[test]
    fn free_login_and_email_create_a_record() {
        assert_eq!(
            registration_target(&None, &None),
            RegistrationTarget::Create
        );
    }

    /// The account takeover: guess the login of a provisioned-but-unused
    /// account, submit your own email. Registration must refuse rather than
    /// repoint the record's email at the attacker.
    #[test]
    fn provisioned_account_cannot_be_claimed_by_login() {
        let existing = Some(provisioned(7));
        assert_eq!(
            registration_target(&existing, &None),
            RegistrationTarget::Taken
        );
    }

    /// The mirror image: keep your own login, submit the victim's email.
    #[test]
    fn provisioned_account_cannot_be_claimed_by_email() {
        let existing = Some(provisioned(7));
        assert_eq!(
            registration_target(&None, &existing),
            RegistrationTarget::Taken
        );
    }

    /// Even an exact (login, email) match must not be reused when the record
    /// was not created by registration itself.
    #[test]
    fn provisioned_account_is_not_resumable() {
        let existing = Some(provisioned(7));
        assert_eq!(
            registration_target(&existing, &existing),
            RegistrationTarget::Taken
        );
    }

    #[test]
    fn unfinished_self_registration_resumes() {
        let existing = Some(self_registered(3));
        assert_eq!(
            registration_target(&existing, &existing),
            RegistrationTarget::Resume(3)
        );
    }

    #[test]
    fn finished_self_registration_is_taken() {
        let mut itm = self_registered(3);
        itm.set_bool("logged_once", true);
        let existing = Some(itm);
        assert_eq!(
            registration_target(&existing, &existing),
            RegistrationTarget::Taken
        );
    }

    /// Two different records: the login belongs to one user, the email to
    /// another. Reusing either would corrupt an account.
    #[test]
    fn login_and_email_of_different_records_is_taken() {
        let by_login = Some(self_registered(3));
        let by_email = Some(self_registered(4));
        assert_eq!(
            registration_target(&by_login, &by_email),
            RegistrationTarget::Taken
        );
    }

    fn with_otp(expires_at: u64, attempts: u64) -> Item {
        let mut itm = Item::new();
        itm.set_str("otp", "123456789");
        itm.set_u64("otp_expires_at", expires_at);
        itm.set_u64("otp_attempts", attempts);
        itm
    }

    #[test]
    fn fresh_otp_is_live() {
        assert!(otp_is_live(&with_otp(1_000, 0), 999));
    }

    #[test]
    fn expired_otp_is_dead() {
        assert!(!otp_is_live(&with_otp(1_000, 0), 1_000));
        assert!(!otp_is_live(&with_otp(1_000, 0), 1_001));
    }

    /// Records written before OTP expiry existed have no `otp_expires_at`.
    /// They must not be treated as valid forever.
    #[test]
    fn legacy_otp_without_expiry_is_dead() {
        let mut itm = Item::new();
        itm.set_str("otp", "123456789");
        assert!(!otp_is_live(&itm, 0));
    }

    #[test]
    fn exhausted_otp_is_dead() {
        assert!(otp_is_live(&with_otp(1_000, OTP_MAX_ATTEMPTS - 1), 0));
        assert!(!otp_is_live(&with_otp(1_000, OTP_MAX_ATTEMPTS), 0));
    }

    #[test]
    fn empty_otp_is_dead() {
        let mut itm = with_otp(1_000, 0);
        itm.set_str("otp", "");
        assert!(!otp_is_live(&itm, 0));
    }

    #[test]
    fn inactive_account_gets_no_otp() {
        let mut itm = Item::new();
        itm.set_bool("role_is_active", false);
        assert!(!otp_may_be_issued(&itm, 10_000));
    }

    #[test]
    fn otp_issue_is_throttled() {
        let mut itm = Item::new();
        itm.set_bool("role_is_active", true);
        itm.set_u64("otp_issued_at", 10_000);
        assert!(!otp_may_be_issued(
            &itm,
            10_000 + OTP_RESEND_INTERVAL_SECS - 1
        ));
        assert!(otp_may_be_issued(&itm, 10_000 + OTP_RESEND_INTERVAL_SECS));
    }

    fn admin(active: bool) -> Item {
        let mut itm = Item::new();
        itm.id = 1;
        itm.set_bool("role_is_admin", true);
        itm.set_bool("role_is_active", active);
        itm
    }

    #[test]
    fn active_admin_holds_the_admin_role() {
        assert!(role_is_granted(&admin(true), "role_is_", "admin"));
    }

    /// The revocation lever: clearing `role_is_active` has to take the role
    /// away from a session that already exists, not merely block the next
    /// login. `/secret/*`, `/setting/*` and `/system/update` are guarded by
    /// this check and nothing else.
    #[test]
    fn deactivated_admin_holds_no_roles() {
        assert!(!role_is_granted(&admin(false), "role_is_", "admin"));
    }

    /// A record with no `role_is_active` at all is inactive. Such a user
    /// cannot log in either, so no live session can be affected.
    #[test]
    fn missing_active_flag_grants_nothing() {
        let mut itm = Item::new();
        itm.set_bool("role_is_admin", true);
        assert!(!role_is_granted(&itm, "role_is_", "admin"));
    }

    /// Being active is not itself a role — it is a precondition for holding
    /// one.
    #[test]
    fn active_alone_grants_no_role() {
        let mut itm = Item::new();
        itm.set_bool("role_is_active", true);
        assert!(!role_is_granted(&itm, "role_is_", "admin"));
    }

    /// The prefix applies to the role being asked about; the active flag keeps
    /// its fixed name, as `login` and the authz hooks spell it.
    #[test]
    fn role_prefix_is_configurable_but_active_is_not() {
        let mut itm = Item::new();
        itm.set_bool("role_is_active", true);
        itm.set_bool("perm_admin", true);
        assert!(role_is_granted(&itm, "perm_", "admin"));
        itm.set_bool("role_is_active", false);
        assert!(!role_is_granted(&itm, "perm_", "admin"));
    }

    #[test]
    fn logins_that_cannot_be_looked_up_are_rejected() {
        assert!(login_is_acceptable("bob"));
        assert!(login_is_acceptable("bob@example.org"));
        assert!(!login_is_acceptable(""));
        // `get_user` returns None for these, so they would report as free.
        assert!(!login_is_acceptable("bob$"));
        assert!(!login_is_acceptable("{\"$ne\": null}"));
    }
}
