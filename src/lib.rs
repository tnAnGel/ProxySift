#![allow(dead_code)]

pub mod check;
pub mod checkpoint;
pub mod cli;
pub mod database;
pub mod diagnose;
pub mod fetch;
pub mod forward_proxy;
pub mod forward_runner;
pub mod geoip;
pub mod hysteria1;
pub mod outbound;
pub mod output;
pub mod parse;
pub mod pipeline;
pub mod settings;
pub mod singbox_check;
pub mod source_report;
pub mod sources;
pub mod speed;
pub mod table;
pub mod tcp_ping;
pub mod xray;

use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct Summary {
    pub fetch_sources: usize,
    pub fetch_loaded: usize,
    pub fetch_failed: usize,
    pub fetch_failure_examples: Vec<String>,
    pub fetch_secs: f64,
    pub links: usize,
    pub unique: usize,
    pub duplicates: usize,
    pub invalid: usize,
    pub unsupported: usize,
    pub unsupported_details: BTreeMap<String, usize>,
    pub parse_secs: f64,
    pub geo: bool,
    /// Number of distinct recognized country codes assigned during this run.
    pub geo_countries: usize,
    pub geo_secs: f64,
    pub tcp_enabled: bool,
    pub tcp_total: usize,
    pub tcp_alive: usize,
    pub tcp_secs: f64,
    pub speed_enabled: bool,
    pub speed_total: usize,
    pub speed_passed: usize,
    pub speed_unchecked: usize,
    pub speed_secs: f64,
    pub bad_outbounds: usize,
    pub alive: usize,
    pub good: usize,
    pub avg_kbs: f64,
    pub median_kbs: f64,
    pub alive_file: Option<(String, usize)>,
    pub good_file: Option<(String, usize)>,
    pub clash_file: Option<(String, usize)>,
    pub singbox_file: Option<(String, usize)>,
    pub singbox_report_file: Option<(String, usize)>,
    pub speed_report_file: Option<(String, usize)>,
    pub dead_file: Option<(String, usize)>,
    pub raw_file: Option<(String, usize)>,
    pub parsed_file: Option<(String, usize)>,
    pub total_secs: f64,
}

pub mod app;

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    let Some(data_dir) = app.internal_data_path() else {
        eprintln!("ProxySift startup error: Android internal data path unavailable");
        return;
    };
    if let Err(error) = self::app::set_app_data_dir(data_dir.join("files").join("ProxySift")) {
        eprintln!("ProxySift startup error: {error}");
        return;
    }
    if let Err(error) = slint::android::init(app) {
        eprintln!("ProxySift startup error: {error}");
        return;
    }
    if let Err(error) = self::app::launch_gui() {
        eprintln!("ProxySift startup error: {error}");
    }
}
