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
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::{error, info};
use std::time::Duration;

/// What marks a body as a document to be rendered rather than text to be
/// read as it stands.
///
/// An exact marker rather than a guess. A message that merely mentions a tag
/// — a plugin quoting one back to somebody, an error containing markup — must
/// not become a web page in somebody's inbox, and nothing written as prose
/// begins with this.
const HTML_MARKER: &str = "<!doctype html";

/// Whether this body is an HTML document.
fn is_html_document(body: &str) -> bool {
    body.trim_start()
        .get(..HTML_MARKER.len())
        .map(|head| head.eq_ignore_ascii_case(HTML_MARKER))
        .unwrap_or(false)
}

/// The same message, for somebody whose client will not render the document.
///
/// Sent beside the HTML rather than instead of it. A mail with no text part
/// is one a text client shows as nothing and a spam filter marks down, and
/// the alternative — asking every caller to write the message twice — is a
/// second thing to keep in step with the first.
///
/// Deliberately crude, because the input is not arbitrary HTML from the web:
/// it is a document this system wrote. Anything it cannot make sense of comes
/// out as the words without their markup, which is still the message.
fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let mut chars = html.chars().peekable();
    let mut skipping: Option<&str> = None;
    let mut tag = String::new();

    while let Some(c) = chars.next() {
        if c != '<' {
            if skipping.is_none() {
                out.push(c);
            }
            continue;
        }
        tag.clear();
        for t in chars.by_ref() {
            if t == '>' {
                break;
            }
            tag.push(t);
        }
        let name = tag
            .trim_start_matches('/')
            .split([' ', '\t', '\n', '/'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        // The two elements whose contents are not words. Skipped wholesale
        // rather than stripped of tags, or a stylesheet would arrive as text.
        if let Some(open) = skipping {
            if tag.starts_with('/') && name == open {
                skipping = None;
            }
            continue;
        }
        match name.as_str() {
            "style" | "script" | "head" if !tag.starts_with('/') => {
                skipping = Some(match name.as_str() {
                    "style" => "style",
                    "script" => "script",
                    _ => "head",
                })
            }
            // Where a line ends in the reading, a line ends in the text.
            "br" | "p" | "div" | "tr" | "li" | "h1" | "h2" | "h3" | "table" => out.push('\n'),
            "td" | "th" => out.push('\t'),
            _ => {}
        }
    }

    let out = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");

    // Tidy: no trailing spaces, and never more than one blank line, so the
    // result reads as a message rather than as a page with its ink removed.
    let mut lines: Vec<String> = Vec::new();
    for line in out.lines() {
        let line = line.trim().to_string();
        if line.is_empty() && lines.last().map(|l: &String| l.is_empty()).unwrap_or(true) {
            continue;
        }
        lines.push(line);
    }
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    lines.join("\n")
}

/// The name of the secret-store entry that holds the mail credentials.
///
/// The same shape the identity providers and the directory use: one named
/// entry, several fields, read by name.
pub const SMTP_SECRET: &str = "smtp";

/// Who to log in to the mail server as.
///
/// From the secret store, which is encrypted at rest under a key of its own,
/// and from the settings only when the store has nothing to say. A password
/// in `settings.js` is a password in every backup of it and in every copy
/// somebody made of the data directory to debug something — which is the
/// whole reason the store exists.
///
/// The fallback is not a courtesy to be tidied away later: an installation
/// that has the password in its settings keeps working across this change,
/// and moving it is then something an operator does when they choose to
/// rather than something that happens to their mail while they are asleep.
fn smtp_credentials(srv: &crate::state::data::Data, settings: &Item) -> (String, String) {
    // The guard is dropped at the end of this block and never held across an
    // await: the store is behind a mutex the HTTP handlers take too.
    let from_store = {
        let guard = srv.secrets.lock();
        guard.as_ref().and_then(|s| s.get_by_name(SMTP_SECRET))
    };
    if let Some(item) = from_store {
        let login = item.safe_str("login", "");
        let password = item.safe_str("password", "");
        if !login.is_empty() || !password.is_empty() {
            return (login, password);
        }
        // An entry with neither is an entry somebody emptied. Falling through
        // to the settings here would quietly bring back the value they were
        // trying to remove.
        return (String::new(), String::new());
    }
    (
        settings.safe_str("smtp_login", ""),
        settings.safe_str("smtp_password", ""),
    )
}

/// Send the email using predefined global options
pub async fn send_email(srv: &crate::state::data::Data, to: &str, subject: &str, body: &str) {
    info!("Checking options...");

    let settings = srv.rw.get_settings().await.clone();

    let smtp_server = settings.safe_str("smtp_server", "");
    let smtp_from = settings.safe_str("smtp_from", "");
    let (smtp_login, smtp_password) = smtp_credentials(srv, &settings);

    info!("Building email...");

    if to == "" || smtp_server == "" || smtp_login == "" || smtp_password == "" || smtp_from == "" {
        info!("Input options not present");
        return;
    }

    let message = match build_message(&smtp_from, to, subject, body) {
        Ok(m) => m,
        Err(e) => {
            // Not a panic. This runs inside the core task, the one that
            // answers every plugin's database call, and a panic there takes
            // that task with it: the senders stay alive, so every later
            // request waits for a reply nobody will ever send. An address
            // somebody typed into their profile must not be able to do that.
            error!("Not sending: {}", e);
            return;
        }
    };

    // Off the core task, and not waited for.
    //
    // The transport is lettre's blocking one, and the conversation it has —
    // DNS, TLS, then SMTP itself — is seconds on a good day and the whole
    // timeout on a bad one. Run here, it would hold the loop that carries
    // every plugin's reads and writes, so a mail server that stopped
    // answering would stop the application. Nothing needs the result: the
    // caller was never given one, because `send_email` has no reply channel.
    let server = smtp_server.clone();
    let creds = Credentials::new(smtp_login.to_owned(), smtp_password.to_owned());
    actix_rt::task::spawn_blocking(move || {
        let relay = match SmtpTransport::relay(&server) {
            Ok(r) => r,
            Err(e) => {
                error!("Cannot reach the mail server '{}': {:?}", server, e);
                return;
            }
        };
        // Said here rather than left to the library's default, so that the
        // longest this can take is a number somebody chose.
        let mailer = relay.credentials(creds).timeout(Some(SMTP_TIMEOUT)).build();
        match mailer.send(&message) {
            Ok(_) => info!("Email sent successfully"),
            Err(e) => error!("Could not send email: {:?}", e),
        }
    });
}

/// How long one attempt at the whole SMTP conversation may take.
///
/// Thirty seconds. Long enough for a slow relay to answer, short enough that
/// a queue of messages to a server that has gone away drains in minutes
/// rather than hours.
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The message, or why there is not one.
///
/// Every failure here used to be an `unwrap`. The addresses are the reason
/// that mattered: `from` is a setting an operator typed and `to` is whatever
/// a person put in their profile, and neither is checked anywhere else.
fn build_message(from: &str, to: &str, subject: &str, body: &str) -> Result<Message, String> {
    let from: Mailbox = from
        .parse()
        .map_err(|e| format!("'smtp_from' is not an address ({from:?}): {e}"))?;
    let to: Mailbox = to
        .parse()
        .map_err(|e| format!("not an address ({to:?}): {e}"))?;

    // A body that is an HTML document is sent as one, with the same message
    // in plain text beside it for a client that will not render it. Anything
    // else is text, exactly as it always was: this is additive, and a caller
    // that has never heard of it is unaffected.
    let builder = Message::builder().from(from).to(to).subject(subject);
    let built = if is_html_document(body) {
        builder.multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(html_to_text(body)),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(String::from(body)),
                ),
        )
    } else {
        builder
            .header(ContentType::TEXT_PLAIN)
            .body(String::from(body))
    };
    built.map_err(|e| format!("could not build the message: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store with the credentials in it, for the tests below.
    fn data_with_secret(login: &str, password: &str) -> crate::state::data::Data {
        let dir = std::env::temp_dir().join(format!(
            "isabelle-smtp-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut store =
            crate::state::secrets::SecretStore::open(&dir.join("key"), &dir.join("secrets.enc"))
                .unwrap();
        let mut itm = Item::new();
        itm.id = u64::MAX;
        itm.set_str("name", SMTP_SECRET);
        itm.set_str("login", login);
        itm.set_str("password", password);
        store.set(&itm, false).unwrap();

        let data = crate::state::data::Data::new();
        *data.secrets.lock() = Some(store);
        data
    }

    fn settings_with(login: &str, password: &str) -> Item {
        let mut s = Item::new();
        s.set_str("smtp_login", login);
        s.set_str("smtp_password", password);
        s
    }

    /// The point of the change: a password in `settings.js` is a password in
    /// every backup of it, so the store is asked first.
    #[test]
    fn the_credentials_come_from_the_secret_store() {
        let data = data_with_secret("mailer", "s3cret");
        let (login, password) = smtp_credentials(&data, &settings_with("old", "stale"));
        assert_eq!(login, "mailer");
        assert_eq!(password, "s3cret");
    }

    /// An installation that has them in its settings keeps working across
    /// this change: moving them is something an operator does when they
    /// choose to, not something that happens to their mail while they sleep.
    #[test]
    fn the_settings_are_used_when_the_store_has_nothing() {
        let data = crate::state::data::Data::new();
        let (login, password) = smtp_credentials(&data, &settings_with("from-settings", "pw"));
        assert_eq!(login, "from-settings");
        assert_eq!(password, "pw");
    }

    /// An entry somebody emptied is an entry somebody emptied. Falling back
    /// to the settings there would quietly restore the value they were
    /// trying to take away.
    #[test]
    fn an_emptied_entry_does_not_bring_the_old_value_back() {
        let data = data_with_secret("", "");
        let (login, password) = smtp_credentials(&data, &settings_with("old", "stale"));
        assert_eq!(login, "");
        assert_eq!(password, "");
    }

    /// Half an entry is still the entry: an operator who set only the
    /// password there has moved that one, and the login beside it is theirs.
    #[test]
    fn a_partly_filled_entry_is_still_the_answer() {
        let data = data_with_secret("", "s3cret");
        let (login, password) = smtp_credentials(&data, &settings_with("old", "stale"));
        assert_eq!(login, "");
        assert_eq!(password, "s3cret");
    }

    /// The reason this exists. `send_email` runs inside the core task — the
    /// one that answers every plugin's database call — and a panic there
    /// takes that task with it: the senders stay alive, so every later
    /// request waits for a reply nobody will ever send. An address somebody
    /// typed into their profile must not be able to do that, and until this
    /// it could.
    #[test]
    fn a_bad_address_is_an_error_and_never_a_panic() {
        for bad in [
            "",
            "not an address",
            "a@b@c",
            "@example.com",
            "a@",
            "a b@c.dev",
        ] {
            let r = build_message("from@example.com", bad, "s", "b");
            assert!(r.is_err(), "accepted {bad:?} as a recipient");
            assert!(r.unwrap_err().contains("not an address"));
        }
        // And the setting, which an operator types and nothing else checks.
        let r = build_message("nonsense", "to@example.com", "s", "b");
        assert!(r.is_err());
        assert!(
            r.unwrap_err().contains("smtp_from"),
            "it should name the setting"
        );
    }

    /// What a good one does.
    #[test]
    fn a_good_address_builds_a_message() {
        assert!(build_message("from@example.com", "to@example.com", "s", "b").is_ok());
        // The forms a mail client writes.
        assert!(build_message(
            "Proteos <from@example.com>",
            "Someone <to@example.com>",
            "s",
            "b"
        )
        .is_ok());
    }

    /// Plain text goes out as it always did, so a caller that has never heard
    /// of documents is unaffected.
    #[test]
    fn text_is_still_sent_as_text() {
        let m = build_message(
            "f@e.dev",
            "t@e.dev",
            "Your login code",
            "Enter this: 123456",
        )
        .expect("a message");
        let wire = String::from_utf8_lossy(&m.formatted()).to_string();
        assert!(wire.contains("text/plain"), "{wire}");
        assert!(!wire.contains("multipart/alternative"), "{wire}");
        assert!(wire.contains("Enter this: 123456"));
    }

    /// A document goes out as both halves, so neither reader is served a
    /// compromise.
    #[test]
    fn a_document_is_sent_as_both_halves() {
        let html = "<!DOCTYPE html><html><body><h1>Ready</h1><p>at a.dev</p></body></html>";
        let m = build_message("f@e.dev", "t@e.dev", "Ready", html).expect("a message");
        let wire = String::from_utf8_lossy(&m.formatted()).to_string();
        assert!(wire.contains("multipart/alternative"), "{wire}");
        assert!(wire.contains("text/plain"), "{wire}");
        assert!(wire.contains("text/html"), "{wire}");
        // And the text half carries the words, not the markup.
        assert!(wire.contains("Ready"));
    }

    /// The longest one attempt may take is a number somebody chose, not a
    /// library default nobody has read.
    #[test]
    fn the_conversation_has_a_deadline() {
        assert_eq!(SMTP_TIMEOUT, Duration::from_secs(30));
    }

    /// An exact marker, not a guess. A message that merely mentions a tag —
    /// an error quoting markup back at somebody — must not arrive as a web
    /// page, and nothing written as prose begins with a doctype.
    #[test]
    fn only_a_document_is_treated_as_one() {
        assert!(is_html_document(
            "<!DOCTYPE html><html><body>hi</body></html>"
        ));
        assert!(is_html_document("\n  <!doctype HTML>\n<html></html>"));

        assert!(!is_html_document("Enter this as password: 123456"));
        assert!(!is_html_document("<p>almost</p>"));
        assert!(!is_html_document("the tag <html> is what you typed"));
        assert!(!is_html_document(""));
    }

    /// The text part carries the words, in the order they are read, without
    /// the markup and without the stylesheet.
    #[test]
    fn the_text_part_is_the_message_without_its_markup() {
        let html = "<!DOCTYPE html><html><head><style>.a { color: red }</style></head>\
                    <body><h1>Your instance is ready</h1>\
                    <p>It answers at <a href=\"https://a.dev\">a.dev</a>.</p>\
                    <table><tr><td>Login</td><td>meow</td></tr></table>\
                    </body></html>";
        let text = html_to_text(html);
        assert!(text.contains("Your instance is ready"), "{text}");
        assert!(text.contains("a.dev"), "{text}");
        assert!(text.contains("Login"), "{text}");
        assert!(text.contains("meow"), "{text}");
        assert!(
            !text.contains("color: red"),
            "the stylesheet is not words: {text}"
        );
        assert!(!text.contains('<'), "{text}");
    }

    /// Entities are read as the characters they stand for, and the result
    /// reads as a message rather than as a page with its ink removed.
    #[test]
    fn the_text_part_is_tidy() {
        let text = html_to_text(
            "<!DOCTYPE html><html><body><p>a &amp; b</p>\n\n\n<p></p>\n\n<p>c</p>\n\n</body></html>",
        );
        assert!(text.contains("a & b"), "{text}");
        assert!(!text.contains("\n\n\n"), "no run of blank lines: {text:?}");
        assert!(!text.ends_with('\n'), "{text:?}");
    }
}
