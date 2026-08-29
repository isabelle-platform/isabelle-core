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
//! Signing in against a directory.
//!
//! Unlike the identity providers, this is not a conversation the browser has:
//! the password is typed into our own form and checked by binding to the
//! directory with it. So it hangs off `/login` rather than off a redirect, and
//! what it produces is the same thing the provider flow produces — an address
//! the directory vouches for.
//!
//! Two shapes of deployment are supported, because both are common:
//!
//! * **Search then bind.** A service account looks the person up under a base
//!   DN, and the entry that comes back is bound to with the typed password.
//!   This is the one that copes with people who are not all in one subtree,
//!   and with logging in by an attribute that is not the naming one.
//! * **Direct bind.** The DN is built from a template. Nothing needs a service
//!   account, which suits a small directory laid out one way.
//!
//! Three things here are load-bearing and each has been a way in somewhere:
//! an empty password is refused before it reaches the directory (a bind with
//! a DN and no password is an *anonymous* bind, which succeeds and proves
//! nothing); values interpolated into a DN or a filter are escaped; and a
//! plaintext connection has to be asked for in as many words, because the
//! password crosses the network on it.

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::time::Duration;

/// How long the directory has to answer.
const TIMEOUT: Duration = Duration::from_secs(10);

/// What an operator configured.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LdapConfig {
    /// `ldaps://directory.example.com` or `ldap://…`.
    pub url: String,
    /// The service account used to find people. Empty means the search is
    /// done anonymously, which some directories allow.
    pub bind_dn: String,
    pub bind_password: String,
    /// Where to look. Empty switches to the template.
    pub base_dn: String,
    /// How to look, with `%u` standing for what was typed —
    /// `(uid=%u)`, `(sAMAccountName=%u)`, `(|(uid=%u)(mail=%u))`.
    pub user_filter: String,
    /// The other shape: the DN itself, again with `%u` —
    /// `uid=%u,ou=people,dc=example,dc=com`.
    pub user_dn_template: String,
    /// Which attribute carries the address. This platform's principal is an
    /// email, so an entry without one cannot be signed in.
    pub email_attribute: String,
    pub name_attribute: String,
    /// Whether a plaintext `ldap://` connection is acceptable.
    pub allow_plaintext: bool,
}

impl LdapConfig {
    pub fn email_attribute_or_default(&self) -> &str {
        let a = self.email_attribute.trim();
        if a.is_empty() {
            "mail"
        } else {
            a
        }
    }

    pub fn name_attribute_or_default(&self) -> &str {
        let a = self.name_attribute.trim();
        if a.is_empty() {
            "cn"
        } else {
            a
        }
    }

    /// Whether people are found by searching or by building their DN.
    pub fn searches(&self) -> bool {
        !self.base_dn.trim().is_empty() && !self.user_filter.trim().is_empty()
    }
}

/// Whether this configuration could sign anybody in, and what is missing when
/// it could not.
pub fn validate(cfg: &LdapConfig) -> Result<(), String> {
    let url = cfg.url.trim();
    if url.is_empty() {
        return Err("the directory URL is not set".to_string());
    }
    let secure = url.starts_with("ldaps://");
    if !secure && !url.starts_with("ldap://") {
        return Err("the URL has to start with ldaps:// or ldap://".to_string());
    }
    if !secure && !cfg.allow_plaintext {
        // The password crosses this connection. Saying so out loud is cheap;
        // discovering it from a packet capture is not.
        return Err(
            "ldap:// sends the password in clear. Use ldaps://, or tick the box that says \
             the network is trusted."
                .to_string(),
        );
    }
    if cfg.searches() {
        if !cfg.user_filter.contains("%u") {
            return Err("the user filter has no %u in it, so it cannot match anybody".to_string());
        }
    } else if cfg.user_dn_template.trim().is_empty() {
        return Err(
            "either a base DN with a user filter, or a user DN template, is needed to find \
             people"
                .to_string(),
        );
    } else if !cfg.user_dn_template.contains("%u") {
        return Err("the user DN template has no %u in it".to_string());
    }
    Ok(())
}

/// Who the directory says this is.
#[derive(Debug, Clone, PartialEq)]
pub struct LdapIdentity {
    pub dn: String,
    pub email: String,
    pub name: String,
}

/// Why a sign-in against the directory did not happen.
#[derive(Debug, Clone, PartialEq)]
pub enum LdapError {
    /// The credentials were not accepted — including "no such person".
    /// Deliberately one case: telling the two apart is an account oracle.
    Rejected,
    /// The person exists and was authenticated, but the entry carries no
    /// address, and an address is what an account here is.
    NoAddress,
    /// The directory could not be reached or asked. Not the caller's fault
    /// and not a wrong password, and the log needs to be able to say so.
    Unavailable(String),
}

/// Escape a value going into a DN, per RFC 4514.
///
/// Without this a username containing a comma is a username that chooses its
/// own place in the tree.
pub fn escape_dn_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let chars: Vec<char> = value.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        let first = i == 0;
        let last = i == chars.len() - 1;
        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(*c);
            }
            '#' if first => out.push_str("\\#"),
            ' ' if first || last => out.push_str("\\ "),
            '\0' => out.push_str("\\00"),
            _ => out.push(*c),
        }
    }
    out
}

/// Escape a value going into a search filter, per RFC 4515.
///
/// Without this `*` is every account, and a well-chosen string is a filter of
/// the caller's own devising.
pub fn escape_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

/// The DN a direct-bind configuration would use.
pub fn user_dn(template: &str, username: &str) -> String {
    template.replace("%u", &escape_dn_value(username))
}

/// The filter a searching configuration would use.
pub fn search_filter(filter: &str, username: &str) -> String {
    filter.replace("%u", &escape_filter_value(username))
}

/// Check a username and password against the directory.
pub async fn authenticate(
    cfg: &LdapConfig,
    username: &str,
    password: &str,
) -> Result<LdapIdentity, LdapError> {
    // A bind with a DN and an empty password is an anonymous bind: the
    // directory answers success and has authenticated nobody. Every LDAP
    // login that has ever been bypassed was bypassed here.
    if password.is_empty() || username.trim().is_empty() {
        return Err(LdapError::Rejected);
    }
    if let Err(e) = validate(cfg) {
        return Err(LdapError::Unavailable(e));
    }

    let settings = LdapConnSettings::new().set_conn_timeout(TIMEOUT);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, cfg.url.trim())
        .await
        .map_err(|e| LdapError::Unavailable(format!("connecting to the directory: {}", e)))?;
    // The connection has to be driven for the handle to work; it ends when
    // the handle is dropped.
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            log::warn!("LDAP connection ended: {}", e);
        }
    });
    ldap.with_timeout(TIMEOUT);

    let dn = if cfg.searches() {
        find_dn(&mut ldap, cfg, username).await?
    } else {
        user_dn(cfg.user_dn_template.trim(), username)
    };

    // The bind that is the actual check.
    let bound = ldap
        .simple_bind(&dn, password)
        .await
        .map_err(|e| LdapError::Unavailable(format!("binding as {}: {}", dn, e)))?;
    if bound.rc != 0 {
        return Err(LdapError::Rejected);
    }

    // Read as the person themselves, so a directory that hides attributes
    // from the service account still gives up the address to its owner.
    let identity = read_entry(&mut ldap, cfg, &dn).await;
    let _ = ldap.unbind().await;
    identity
}

/// Look somebody up with the service account and return their DN.
async fn find_dn(
    ldap: &mut ldap3::Ldap,
    cfg: &LdapConfig,
    username: &str,
) -> Result<String, LdapError> {
    if !cfg.bind_dn.trim().is_empty() {
        let bound = ldap
            .simple_bind(cfg.bind_dn.trim(), &cfg.bind_password)
            .await
            .map_err(|e| {
                LdapError::Unavailable(format!("binding as the service account: {}", e))
            })?;
        if bound.rc != 0 {
            // Ours, not theirs: the person typing has no way to fix this and
            // must not be told their password was wrong.
            return Err(LdapError::Unavailable(
                "the directory refused the service account".to_string(),
            ));
        }
    }

    let filter = search_filter(cfg.user_filter.trim(), username);
    let (entries, _) = ldap
        .search(cfg.base_dn.trim(), Scope::Subtree, &filter, vec!["dn"])
        .await
        .map_err(|e| LdapError::Unavailable(format!("searching the directory: {}", e)))?
        .success()
        .map_err(|e| LdapError::Unavailable(format!("searching the directory: {}", e)))?;

    // Exactly one, or nobody. Two matches means the filter does not identify
    // a person, and picking one of them would be picking an account for
    // somebody at random.
    if entries.len() != 1 {
        return Err(LdapError::Rejected);
    }
    let dn = SearchEntry::construct(entries.into_iter().next().unwrap()).dn;
    if dn.trim().is_empty() {
        return Err(LdapError::Rejected);
    }
    Ok(dn)
}

/// Read the address and name off an entry we are bound as.
async fn read_entry(
    ldap: &mut ldap3::Ldap,
    cfg: &LdapConfig,
    dn: &str,
) -> Result<LdapIdentity, LdapError> {
    let email_attr = cfg.email_attribute_or_default().to_string();
    let name_attr = cfg.name_attribute_or_default().to_string();
    let (entries, _) = ldap
        .search(
            dn,
            Scope::Base,
            "(objectClass=*)",
            vec![email_attr.as_str(), name_attr.as_str()],
        )
        .await
        .map_err(|e| LdapError::Unavailable(format!("reading {}: {}", dn, e)))?
        .success()
        .map_err(|e| LdapError::Unavailable(format!("reading {}: {}", dn, e)))?;

    let entry = match entries.into_iter().next() {
        Some(e) => SearchEntry::construct(e),
        None => return Err(LdapError::NoAddress),
    };
    let first = |attr: &str| -> String {
        entry
            .attrs
            .get(attr)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    };
    let email = first(&email_attr).trim().to_lowercase();
    if email.is_empty() {
        return Err(LdapError::NoAddress);
    }
    Ok(LdapIdentity {
        dn: dn.to_string(),
        name: first(&name_attr).trim().to_string(),
        email,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn searching() -> LdapConfig {
        LdapConfig {
            url: "ldaps://directory.example.com".into(),
            base_dn: "ou=people,dc=example,dc=com".into(),
            user_filter: "(uid=%u)".into(),
            ..Default::default()
        }
    }

    /// A username with a comma in it would otherwise choose its own place in
    /// the tree — `admin,ou=admins` reaching a different subtree entirely.
    #[test]
    fn a_username_cannot_rewrite_the_dn_it_is_put_into() {
        assert_eq!(
            user_dn("uid=%u,ou=people,dc=example,dc=com", "alice"),
            "uid=alice,ou=people,dc=example,dc=com"
        );
        // Both the comma and the equals are escaped. RFC 4514 lists EQUALS
        // among the characters an escape may precede, so this is conforming;
        // only the comma strictly has to be, and escaping the other costs
        // nothing and leaves less to reason about.
        assert_eq!(
            user_dn("uid=%u,ou=people,dc=example,dc=com", "alice,ou=admins"),
            "uid=alice\\,ou\\=admins,ou=people,dc=example,dc=com"
        );
        assert_eq!(escape_dn_value("a+b=c"), "a\\+b\\=c");
        assert_eq!(escape_dn_value("#hash"), "\\#hash");
        assert_eq!(escape_dn_value(" pad "), "\\ pad\\ ");
    }

    /// A username of `*` would otherwise match every entry in the directory,
    /// and a well-chosen one would be a filter of the caller's own devising.
    #[test]
    fn a_username_cannot_rewrite_the_filter_it_is_put_into() {
        assert_eq!(search_filter("(uid=%u)", "alice"), "(uid=alice)");
        assert_eq!(search_filter("(uid=%u)", "*"), "(uid=\\2a)");
        assert_eq!(
            search_filter("(uid=%u)", "a)(objectClass=*"),
            "(uid=a\\29\\28objectClass=\\2a)"
        );
        assert_eq!(escape_filter_value("back\\slash"), "back\\5cslash");
    }

    /// The classic bypass: a bind with a DN and no password is an anonymous
    /// bind, which the directory accepts and which proves nothing.
    #[tokio::test]
    async fn an_empty_password_is_refused_without_asking_the_directory() {
        // The URL is unreachable on purpose: reaching it would already be a
        // failure of this test.
        let cfg = LdapConfig {
            url: "ldaps://192.0.2.1".into(),
            user_dn_template: "uid=%u,dc=example,dc=com".into(),
            ..Default::default()
        };
        assert_eq!(
            authenticate(&cfg, "alice", "").await,
            Err(LdapError::Rejected)
        );
        assert_eq!(
            authenticate(&cfg, "", "hunter2").await,
            Err(LdapError::Rejected)
        );
    }

    #[test]
    fn a_plaintext_directory_has_to_be_asked_for_in_as_many_words() {
        let mut cfg = searching();
        cfg.url = "ldap://directory.example.com".into();
        let err = validate(&cfg).unwrap_err();
        assert!(err.contains("in clear"), "{err}");
        cfg.allow_plaintext = true;
        assert_eq!(validate(&cfg), Ok(()));
    }

    #[test]
    fn a_configuration_that_could_not_find_anybody_says_so() {
        assert_eq!(
            validate(&LdapConfig::default()),
            Err("the directory URL is not set".to_string())
        );

        let mut no_way_in = LdapConfig {
            url: "ldaps://d.example.com".into(),
            ..Default::default()
        };
        assert!(validate(&no_way_in).unwrap_err().contains("base DN"));

        // A filter that never mentions the username matches the same person
        // whatever is typed, which is worse than not working.
        no_way_in.base_dn = "dc=example,dc=com".into();
        no_way_in.user_filter = "(objectClass=person)".into();
        assert!(validate(&no_way_in).unwrap_err().contains("%u"));

        no_way_in.user_filter = "(uid=%u)".into();
        assert_eq!(validate(&no_way_in), Ok(()));
    }

    #[test]
    fn a_template_without_the_username_is_refused_too() {
        let cfg = LdapConfig {
            url: "ldaps://d.example.com".into(),
            user_dn_template: "uid=fixed,dc=example,dc=com".into(),
            ..Default::default()
        };
        assert!(validate(&cfg).unwrap_err().contains("%u"));
    }

    /// Which of the two shapes is in use is decided by what was filled in,
    /// and a base DN with a filter is the more capable one.
    #[test]
    fn a_base_dn_with_a_filter_means_searching() {
        assert!(searching().searches());
        let template = LdapConfig {
            url: "ldaps://d.example.com".into(),
            user_dn_template: "uid=%u,dc=example,dc=com".into(),
            ..Default::default()
        };
        assert!(!template.searches());
    }

    #[test]
    fn the_usual_attribute_names_do_not_have_to_be_typed() {
        let cfg = LdapConfig::default();
        assert_eq!(cfg.email_attribute_or_default(), "mail");
        assert_eq!(cfg.name_attribute_or_default(), "cn");
        let named = LdapConfig {
            email_attribute: " userPrincipalName ".into(),
            name_attribute: "displayName".into(),
            ..Default::default()
        };
        assert_eq!(named.email_attribute_or_default(), "userPrincipalName");
        assert_eq!(named.name_attribute_or_default(), "displayName");
    }

    /// The characters RFC 4514 names, one at a time, so a regression shows
    /// which one was dropped rather than that "escaping broke".
    #[test]
    fn every_character_a_dn_reserves_is_escaped() {
        for c in [',', '+', '"', '\\', '<', '>', ';', '='] {
            let escaped = escape_dn_value(&format!("a{}b", c));
            assert_eq!(escaped, format!("a\\{}b", c), "{c:?}");
        }
    }

    /// …and the ones RFC 4515 names.
    #[test]
    fn every_character_a_filter_reserves_is_escaped() {
        for (c, as_hex) in [('\\', "\\5c"), ('*', "\\2a"), ('(', "\\28"), (')', "\\29")] {
            assert_eq!(
                escape_filter_value(&format!("a{}b", c)),
                format!("a{}b", as_hex),
                "{c:?}"
            );
        }
    }

    /// Ordinary text is left alone, or every DN in the directory would be
    /// unreachable.
    #[test]
    fn ordinary_text_passes_through_untouched() {
        for value in ["alice", "alice.smith", "alice-smith_1", "ALICE", "ali ce"] {
            assert_eq!(escape_dn_value(value), value, "{value}");
            assert_eq!(escape_filter_value(value), value, "{value}");
        }
    }

    /// A leading `#` means a hex-encoded DN value, and a leading or trailing
    /// space is dropped by a parser that does not see it escaped.
    #[test]
    fn the_positional_rules_of_a_dn_are_honoured() {
        assert_eq!(escape_dn_value("#a"), "\\#a");
        // Not leading, so not special.
        assert_eq!(escape_dn_value("a#b"), "a#b");
        assert_eq!(escape_dn_value(" a"), "\\ a");
        assert_eq!(escape_dn_value("a "), "a\\ ");
        assert_eq!(escape_dn_value(" "), "\\ ");
    }

    /// A NUL is a string terminator to whatever C library is on the far end.
    #[test]
    fn a_nul_cannot_be_smuggled_through_either() {
        assert_eq!(escape_dn_value("a\0b"), "a\\00b");
        assert_eq!(escape_filter_value("a\0b"), "a\\00b");
    }

    /// Every placeholder is replaced, not just the first — a filter that
    /// matches either of two attributes is the ordinary case.
    #[test]
    fn a_filter_may_name_the_username_more_than_once() {
        assert_eq!(
            search_filter("(|(uid=%u)(mail=%u))", "alice"),
            "(|(uid=alice)(mail=alice))"
        );
        assert_eq!(
            search_filter("(|(uid=%u)(mail=%u))", "a)b"),
            "(|(uid=a\\29b)(mail=a\\29b))"
        );
    }

    /// The whole reason the filter is escaped: this must not become a filter
    /// that matches somebody else, or everybody.
    #[test]
    fn the_classic_filter_injections_are_inert() {
        for attempt in ["*", "*)(uid=*", "admin)(|(uid=*", "\\2a", "a*b"] {
            let filter = search_filter("(uid=%u)", attempt);
            // Exactly one attribute assertion, and the parentheses are the
            // two the template put there.
            assert_eq!(filter.matches('(').count(), 1, "{filter}");
            assert_eq!(filter.matches(')').count(), 1, "{filter}");
            assert!(filter.starts_with("(uid="), "{filter}");
            assert!(filter.ends_with(')'), "{filter}");
        }
    }

    /// And the DN equivalent: the template's own structure has to survive.
    #[test]
    fn the_classic_dn_injections_are_inert() {
        // Counted the way a parser reads it: a backslash consumes whatever
        // follows, so an escaped backslash does not go on to hide the comma
        // after it.
        fn separators(dn: &str) -> usize {
            let mut n = 0;
            let mut chars = dn.chars();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        chars.next();
                    }
                    ',' => n += 1,
                    _ => {}
                }
            }
            n
        }

        let template = "uid=%u,ou=people,dc=example,dc=com";
        for attempt in ["admin,ou=admins", "a=b,c=d", "x+y", "admin\\", "a\\,b"] {
            let dn = user_dn(template, attempt);
            // The template contributes exactly three separators; the username
            // contributes none, whatever it holds.
            assert_eq!(separators(&dn), 3, "{dn}");
            assert!(dn.ends_with(",ou=people,dc=example,dc=com"), "{dn}");
        }
    }

    /// A username that is only whitespace is not a username, and must not
    /// reach the directory as a bind DN of its own.
    #[tokio::test]
    async fn a_blank_username_is_refused_without_asking_the_directory() {
        let cfg = LdapConfig {
            url: "ldaps://192.0.2.1".into(),
            user_dn_template: "uid=%u,dc=example,dc=com".into(),
            ..Default::default()
        };
        for username in ["", " ", "\t"] {
            assert_eq!(
                authenticate(&cfg, username, "hunter2").await,
                Err(LdapError::Rejected),
                "{username:?}"
            );
        }
    }

    /// A configuration that could never work must not be reached over the
    /// network first: the answer is known before anything is dialled.
    #[tokio::test]
    async fn an_unusable_configuration_fails_without_a_connection() {
        // 192.0.2.0/24 is reserved for documentation and routes nowhere, so
        // a connection attempt would hang rather than return promptly.
        let cfg = LdapConfig {
            url: "ldaps://192.0.2.1".into(),
            ..Default::default()
        };
        match authenticate(&cfg, "alice", "hunter2").await {
            Err(LdapError::Unavailable(e)) => assert!(e.contains("base DN"), "{e}"),
            other => panic!("expected a configuration complaint, got {other:?}"),
        }
    }

    /// `ldaps://` needs no permission; it is the plain one that does.
    #[test]
    fn a_secure_url_needs_no_extra_blessing() {
        let cfg = LdapConfig {
            url: "ldaps://directory.example.com:636".into(),
            user_dn_template: "uid=%u,dc=example,dc=com".into(),
            allow_plaintext: false,
            ..Default::default()
        };
        assert_eq!(validate(&cfg), Ok(()));
    }

    #[test]
    fn a_url_of_some_other_scheme_is_refused() {
        for url in ["https://d.example.com", "d.example.com", "ldap:/x", "://d"] {
            let cfg = LdapConfig {
                url: url.into(),
                user_dn_template: "uid=%u,dc=example,dc=com".into(),
                allow_plaintext: true,
                ..Default::default()
            };
            assert!(validate(&cfg).is_err(), "{url}");
        }
    }

    /// Having both shapes filled in is not an error: the search is the more
    /// capable one and wins, which is worth pinning so it does not quietly
    /// become the other way round.
    #[test]
    fn a_configuration_with_both_shapes_searches() {
        let cfg = LdapConfig {
            url: "ldaps://d.example.com".into(),
            base_dn: "dc=example,dc=com".into(),
            user_filter: "(uid=%u)".into(),
            user_dn_template: "uid=%u,dc=example,dc=com".into(),
            ..Default::default()
        };
        assert!(cfg.searches());
        assert_eq!(validate(&cfg), Ok(()));
    }

    /// A base DN with no filter is half a configuration, and the template is
    /// what it falls back to.
    #[test]
    fn a_base_dn_without_a_filter_is_not_a_search() {
        let cfg = LdapConfig {
            url: "ldaps://d.example.com".into(),
            base_dn: "dc=example,dc=com".into(),
            ..Default::default()
        };
        assert!(!cfg.searches());
        assert!(validate(&cfg).unwrap_err().contains("base DN"));
    }
}
