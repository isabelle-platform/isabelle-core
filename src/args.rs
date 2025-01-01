use clap::Parser;

/// Simple program to greet a person
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
    #[arg(long)]
    pub port: u16,

    /// First run
    #[arg(long)]
    pub first_run: bool,
}