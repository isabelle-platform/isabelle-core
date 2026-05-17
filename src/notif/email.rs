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
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::{error, info};

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

    let email = Message::builder()
        .from(smtp_from.parse().unwrap())
        .to(to.parse().unwrap())
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(String::from(body))
        .unwrap();

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
