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
//! What an authenticated identity means for this deployment.
//!
//! There is more than one way into an account that is not a password typed
//! here — an identity provider, a directory — and each of them ends at the
//! same question: this is who they say they are, so which record is that, and
//! may they have it? The answer is the same for all of them, so it is written
//! once.

use crate::state::store::Store;
use isabelle_dm::data_model::item::Item;
use log::info;

/// Why a sign-in was refused, as the browser is told.
///
/// A slug rather than a sentence: this travels in a URL the user can read and
/// forward, and the detail behind it — which record, which provider, which
/// mismatch — belongs in the log, not in an address bar.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Refusal {
    /// The user said no at the provider, or the provider gave up.
    Denied,
    /// The provider will not vouch for the address.
    Unverified,
    /// No account, and this deployment does not accept new ones.
    RegistrationClosed,
    /// There is an account and it is switched off.
    Inactive,
    /// The address belongs to an account already tied to a different one at
    /// this provider.
    Mismatched,
    /// Anything that went wrong on the way.
    Failed,
}

impl Refusal {
    pub fn slug(self) -> &'static str {
        match self {
            Refusal::Denied => "denied",
            Refusal::Unverified => "unverified",
            Refusal::RegistrationClosed => "registration_closed",
            Refusal::Inactive => "inactive",
            Refusal::Mismatched => "mismatched",
            Refusal::Failed => "failed",
        }
    }
}

/// What signing in with this identity should do.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolution {
    /// Sign in as the record with this id, recording the provider subject.
    SignIn(u64),
    /// There is no such account and one may be made.
    Create,
    Refuse(Refusal),
}

/// Decide what an authenticated identity means for this deployment.
///
/// Kept apart from the request handling because this is the part with the
/// security argument in it, and it is worth being able to state that argument
/// as tests rather than as a comment. It is shared by every way in that is
/// not a local password — an identity provider, a directory — because the
/// argument is the same one in each case and having it twice would mean
/// having it differently.
///
/// The address is the key. It is what the rest of this core already treats as
/// the principal — a session is stamped with an email — so keying on anything
/// else would create a second kind of account that could not log in the
/// ordinary way. What guards it is that whoever vouched for the address must
/// actually have vouched for it, and that once a record has been signed into
/// from one source identity it will not accept another: an address that
/// changes hands elsewhere cannot pick up the record that was left behind.
///
/// `subject` is the source's own immutable identifier for the account — a
/// provider's `sub`, a directory entry's DN — and `subject_key` is where it
/// is remembered, one key per source so that several can be linked to one
/// record without colliding.
pub fn resolve_identity(
    existing: Option<&Item>,
    email: &str,
    verified: bool,
    subject: &str,
    subject_key: &str,
    allow_self_registration: bool,
) -> Resolution {
    if email.trim().is_empty() {
        return Resolution::Refuse(Refusal::Unverified);
    }
    if !verified {
        return Resolution::Refuse(Refusal::Unverified);
    }
    let existing = match existing {
        None => {
            return if allow_self_registration {
                Resolution::Create
            } else {
                Resolution::Refuse(Refusal::RegistrationClosed)
            }
        }
        Some(u) => u,
    };
    // The lookup that found this record matches a login *or* an email, which
    // is right for a password sign-in — people type either — but not here.
    // What the provider vouched for is an address, so an account is only the
    // right one if that is the address it holds; otherwise an account whose
    // login happened to be somebody else's email address could be signed
    // into by that somebody else.
    if !existing
        .safe_str("email", "")
        .trim()
        .eq_ignore_ascii_case(email.trim())
    {
        return Resolution::Refuse(Refusal::Mismatched);
    }
    if !existing.safe_bool("role_is_active", false) {
        return Resolution::Refuse(Refusal::Inactive);
    }
    let known = existing.safe_str(subject_key, "");
    if !known.is_empty() && known != subject {
        return Resolution::Refuse(Refusal::Mismatched);
    }
    Resolution::SignIn(existing.id)
}

/// Read the directory configuration out of the encrypted secret store.
///
/// Presence is the switch, as it is for the identity providers: a directory
/// with no entry is not consulted.
pub fn ldap_config(srv: &crate::state::data::Data) -> Option<crate::util::ldap::LdapConfig> {
    let guard = srv.secrets.lock();
    let item = guard.as_ref()?.get_by_name(LDAP_SECRET)?;
    Some(crate::util::ldap::LdapConfig {
        url: item.safe_str("url", ""),
        bind_dn: item.safe_str("bind_dn", ""),
        bind_password: item.safe_str("bind_password", ""),
        base_dn: item.safe_str("base_dn", ""),
        user_filter: item.safe_str("user_filter", ""),
        user_dn_template: item.safe_str("user_dn_template", ""),
        email_attribute: item.safe_str("email_attribute", ""),
        name_attribute: item.safe_str("name_attribute", ""),
        allow_plaintext: item.safe_bool("allow_plaintext", false),
    })
}

/// The name of the secret-store entry that configures the directory.
pub const LDAP_SECRET: &str = "ldap";

/// Where a directory entry's DN is remembered on a record.
pub const LDAP_SUBJECT_KEY: &str = "ldap_dn";

/// Carry out what `resolve_identity` decided, and hand back the record that
/// is about to be signed in as.
///
/// The write is here rather than at each caller because it is the same write
/// every time — remember which identity this was, mark the account as one
/// that has been used — and because getting it slightly different in two
/// places is how records end up meaning different things.
pub async fn record_for(
    srv: &crate::state::data::Data,
    resolution: &Resolution,
    existing: Option<Item>,
    email: &str,
    name: &str,
    subject: &str,
    subject_key: &str,
) -> Option<Item> {
    match resolution {
        Resolution::Refuse(_) => None,
        Resolution::SignIn(id) => {
            let mut itm = Item::new();
            itm.id = *id;
            itm.set_str(subject_key, subject);
            itm.set_bool("logged_once", true);
            srv.rw.set_item("user", &itm, true).await;
            existing
        }
        Resolution::Create => {
            let mut itm = Item::new();
            itm.set_str("login", email);
            itm.set_str("email", email);
            itm.set_str(
                "name",
                if name.trim().is_empty() {
                    email
                } else {
                    name.trim()
                },
            );
            itm.set_str(subject_key, subject);
            itm.set_bool("self_registered", true);
            itm.set_bool("role_is_active", true);
            itm.set_bool("logged_once", true);
            let id = srv.rw.set_item("user", &itm, false).await;
            info!("Registered {} as id {}", email, id);
            srv.rw.get_item("user", id).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE: &str = "oauth_google_subject";
    const APPLE: &str = "oauth_apple_subject";

    /// A record as an operator would leave it: an address, switched on, and
    /// nothing else.
    fn account(email: &str) -> Item {
        let mut itm = Item::new();
        itm.id = 7;
        itm.set_str("login", email);
        itm.set_str("email", email);
        itm.set_bool("role_is_active", true);
        itm
    }

    fn linked(email: &str, key: &str, subject: &str) -> Item {
        let mut itm = account(email);
        itm.set_str(key, subject);
        itm
    }

    fn decide(existing: Option<&Item>, email: &str, subject: &str) -> Resolution {
        resolve_identity(existing, email, true, subject, GOOGLE, true)
    }

    // ---- what counts as an identity at all -----------------------------

    #[test]
    fn an_address_nobody_vouched_for_is_not_an_identity() {
        assert_eq!(
            resolve_identity(None, "a@b.test", false, "sub", GOOGLE, true),
            Resolution::Refuse(Refusal::Unverified)
        );
    }

    #[test]
    fn an_empty_address_is_not_an_identity() {
        for email in ["", "   ", "\t\n"] {
            assert_eq!(
                resolve_identity(None, email, true, "sub", GOOGLE, true),
                Resolution::Refuse(Refusal::Unverified),
                "{email:?}"
            );
        }
    }

    /// Checked before anything is looked up: an unverified address must not
    /// even get as far as being compared with a record.
    #[test]
    fn an_unverified_address_is_refused_even_when_it_matches_a_record() {
        let usr = account("a@b.test");
        assert_eq!(
            resolve_identity(Some(&usr), "a@b.test", false, "sub", GOOGLE, true),
            Resolution::Refuse(Refusal::Unverified)
        );
    }

    // ---- no record yet --------------------------------------------------

    #[test]
    fn an_unknown_address_is_registered_where_registration_is_open() {
        assert_eq!(decide(None, "new@b.test", "sub"), Resolution::Create);
    }

    #[test]
    fn an_unknown_address_is_refused_where_registration_is_closed() {
        assert_eq!(
            resolve_identity(None, "new@b.test", true, "sub", GOOGLE, false),
            Resolution::Refuse(Refusal::RegistrationClosed)
        );
    }

    // ---- the record an operator made ahead of time ----------------------

    /// The whole point of being able to add an account by hand: it has never
    /// been signed into, carries no identifier from anywhere, and the first
    /// sign-in should simply land on it.
    #[test]
    fn a_prepared_account_is_signed_into_on_the_first_visit() {
        let usr = account("someone@b.test");
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub"),
            Resolution::SignIn(7)
        );
    }

    /// And it works the same when the operator only filled in the address,
    /// leaving the login blank.
    #[test]
    fn a_record_with_only_an_address_is_still_that_account() {
        let mut usr = Item::new();
        usr.id = 7;
        usr.set_str("email", "someone@b.test");
        usr.set_bool("role_is_active", true);
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub"),
            Resolution::SignIn(7)
        );
    }

    // ---- how the address is compared -----------------------------------

    #[test]
    fn addresses_are_compared_as_addresses_not_as_bytes() {
        let usr = account("SomeOne@Example.COM");
        assert_eq!(
            decide(Some(&usr), "someone@example.com", "sub"),
            Resolution::SignIn(7)
        );
    }

    #[test]
    fn surrounding_whitespace_does_not_make_it_a_different_address() {
        let mut usr = account("someone@b.test");
        usr.set_str("email", "  someone@b.test  ");
        assert_eq!(
            decide(Some(&usr), " someone@b.test ", "sub"),
            Resolution::SignIn(7)
        );
    }

    /// The lookup that produced this record matches a login *or* an email,
    /// because that is what a typed sign-in needs. A vouched-for address is
    /// not a login, so a record that merely uses one as its login is not it.
    #[test]
    fn a_record_whose_login_is_the_address_but_whose_address_is_not_is_refused() {
        let mut usr = account("impostor@b.test");
        usr.set_str("login", "someone@b.test");
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub"),
            Resolution::Refuse(Refusal::Mismatched)
        );
    }

    /// A record with no address at all cannot be the account for one.
    #[test]
    fn a_record_with_no_address_is_refused() {
        let mut usr = account("someone@b.test");
        usr.set_str("email", "");
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub"),
            Resolution::Refuse(Refusal::Mismatched)
        );
    }

    // ---- the account's own state ---------------------------------------

    /// Whoever vouched for the address does not get to overrule this
    /// deployment about whether the account is switched on.
    #[test]
    fn a_deactivated_account_is_refused_however_good_the_identity() {
        let mut usr = account("someone@b.test");
        usr.set_bool("role_is_active", false);
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub"),
            Resolution::Refuse(Refusal::Inactive)
        );
    }

    /// A record with no activity flag at all has not been switched on.
    #[test]
    fn an_account_that_never_said_it_was_active_is_not() {
        let mut usr = Item::new();
        usr.id = 7;
        usr.set_str("email", "someone@b.test");
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub"),
            Resolution::Refuse(Refusal::Inactive)
        );
    }

    /// The order the checks run in, pinned: a record that is both the wrong
    /// account and switched off is reported as the wrong account. Saying
    /// "inactive" about somebody else's record would confirm it exists.
    #[test]
    fn the_wrong_record_is_reported_as_wrong_before_it_is_reported_as_off() {
        let mut usr = account("impostor@b.test");
        usr.set_bool("role_is_active", false);
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub"),
            Resolution::Refuse(Refusal::Mismatched)
        );
    }

    // ---- staying with the same identity --------------------------------

    #[test]
    fn the_identity_that_linked_the_account_keeps_signing_into_it() {
        let usr = linked("someone@b.test", GOOGLE, "sub-1");
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub-1"),
            Resolution::SignIn(7)
        );
    }

    /// The guard on keying by address: an address that changes hands at the
    /// source cannot pick up the record that was left behind.
    #[test]
    fn a_different_identity_at_the_same_address_is_refused() {
        let usr = linked("someone@b.test", GOOGLE, "sub-1");
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub-2"),
            Resolution::Refuse(Refusal::Mismatched)
        );
    }

    /// Each source is remembered under its own key, so one record can be
    /// reached by several without them colliding.
    #[test]
    fn sources_are_remembered_separately() {
        let usr = linked("someone@b.test", GOOGLE, "google-sub");
        // Apple has not been linked yet, so this is a first link, not a clash.
        assert_eq!(
            resolve_identity(Some(&usr), "someone@b.test", true, "apple-sub", APPLE, true),
            Resolution::SignIn(7)
        );
        // And the directory likewise.
        assert_eq!(
            resolve_identity(
                Some(&usr),
                "someone@b.test",
                true,
                "dn=x",
                LDAP_SUBJECT_KEY,
                true
            ),
            Resolution::SignIn(7)
        );
        // While Google itself still has to be the same Google account.
        assert_eq!(
            resolve_identity(Some(&usr), "someone@b.test", true, "other", GOOGLE, true),
            Resolution::Refuse(Refusal::Mismatched)
        );
    }

    /// A record linked to three sources at once answers to all three.
    #[test]
    fn a_record_can_be_reached_by_every_source_it_has_been_linked_to() {
        let mut usr = linked("someone@b.test", GOOGLE, "g");
        usr.set_str(APPLE, "a");
        usr.set_str(LDAP_SUBJECT_KEY, "uid=someone,dc=b,dc=test");
        for (key, subject) in [
            (GOOGLE, "g"),
            (APPLE, "a"),
            (LDAP_SUBJECT_KEY, "uid=someone,dc=b,dc=test"),
        ] {
            assert_eq!(
                resolve_identity(Some(&usr), "someone@b.test", true, subject, key, true),
                Resolution::SignIn(7),
                "{key}"
            );
        }
    }

    /// An empty stored identifier is "not linked yet", not "linked to
    /// nothing" — otherwise a record written without one could never be
    /// signed into.
    #[test]
    fn an_unlinked_record_links_on_first_use() {
        let usr = linked("someone@b.test", GOOGLE, "");
        assert_eq!(
            decide(Some(&usr), "someone@b.test", "sub-1"),
            Resolution::SignIn(7)
        );
    }

    /// Registration being closed says nothing about accounts that already
    /// exist: it is about making new ones.
    #[test]
    fn closing_registration_does_not_shut_out_the_accounts_that_exist() {
        let usr = account("someone@b.test");
        assert_eq!(
            resolve_identity(Some(&usr), "someone@b.test", true, "sub", GOOGLE, false),
            Resolution::SignIn(7)
        );
    }

    /// Every refusal has to be sayable in a URL and greppable in a log.
    #[test]
    fn every_refusal_is_a_slug() {
        for r in [
            Refusal::Denied,
            Refusal::Unverified,
            Refusal::RegistrationClosed,
            Refusal::Inactive,
            Refusal::Mismatched,
            Refusal::Failed,
        ] {
            let slug = r.slug();
            assert!(!slug.is_empty());
            assert!(
                slug.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{slug}"
            );
        }
    }
}
