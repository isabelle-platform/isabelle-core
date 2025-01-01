/*
 * Isabelle project
 *
 * Copyright 2023-2025 Maxim Menshikov
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
use clap::Parser;

/// Isabelle - high-performant server for web applications
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Data path
    #[arg(long, default_value("sample-data"))]
    pub data_path: String,

    /// Public URL
    #[arg(long, default_value("http://localhost:8081"))]
    pub pub_url: String,

    /// Public FQDN
    #[arg(long, default_value("localhost"))]
    pub pub_fqdn: String,

    /// Database URL
    #[arg(long, default_value("mongodb://127.0.0.1:27017"))]
    pub db_url: String,

    /// Database name
    #[arg(long, default_value("isabelle"), visible_alias("database"))]
    pub db_name: String,

    /// Plugins directory
    #[arg(long)]
    pub plugin_dir: String,

    /// Google Calendar path
    #[arg(long, default_value(""))]
    pub gc_path: String,

    /// Python path
    #[arg(long, default_value(""))]
    pub py_path: String,

    /// Port number
    #[arg(long, default_value("0.0.0.0"))]
    pub bind_addr: String,

    /// Port number
    #[arg(long, visible_alias("port"))]
    pub bind_port: u16,

    /// First run
    #[arg(long)]
    pub first_run: bool,
}