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
use lettre::message::header::ContentType;
use lettre::message::{MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::{error, info};

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

/// Send the email using predefined global options
pub async fn send_email(srv: &crate::state::data::Data, to: &str, subject: &str, body: &str) {
    info!("Checking options...");

    let settings = srv.rw.get_settings().await.clone();

    let smtp_server = settings.safe_str("smtp_server", "");
    let smtp_login = settings.safe_str("smtp_login", "");
    let smtp_password = settings.safe_str("smtp_password", "");
    let smtp_from = settings.safe_str("smtp_from", "");

    info!("Building email...");

    if to == "" || smtp_server == "" || smtp_login == "" || smtp_password == "" || smtp_from == "" {
        info!("Input options not present");
        return;
    }

    // A body that is an HTML document is sent as one, with the same message
    // in plain text beside it for a client that will not render it. Anything
    // else is text, exactly as it always was: this is additive, and a caller
    // that has never heard of it is unaffected.
    let built = if is_html_document(body) {
        Message::builder()
            .from(smtp_from.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject)
            .multipart(
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
        Message::builder()
            .from(smtp_from.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(String::from(body))
    };
    let email = built.unwrap();

    let creds = Credentials::new(smtp_login.to_owned(), smtp_password.to_owned());

    info!("Sending email...");
    // Open a remote connection to gmail
    let mailer = SmtpTransport::relay(&smtp_server)
        .unwrap()
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => error!("Could not send email: {:?}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
