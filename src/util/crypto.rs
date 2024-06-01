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
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;

/// Verify password: the real password, the hash
pub fn verify_password(pw: &str, pw_hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(&pw_hash);
    Argon2::default()
        .verify_password(pw.as_bytes(), &parsed_hash.unwrap())
        .is_ok()
}

/// Get new salt
pub fn get_new_salt() -> String {
    let salt = SaltString::generate(&mut OsRng);
    return salt.to_string();
}

/// Derive hash from given password and salt
pub fn get_password_hash(pw: &str, salt: &str) -> String {
    let argon2 = Argon2::default();

    let saltstr = SaltString::from_b64(&salt).unwrap();
    let password_hash = argon2.hash_password(pw.as_bytes(), saltstr.as_salt());

    return password_hash.unwrap().serialize().as_str().to_string();
}

/// Generate new OTP code
pub fn get_otp_code() -> String {
    let num = rand::thread_rng().gen_range(100000000..999999999);
    num.to_string()
}
