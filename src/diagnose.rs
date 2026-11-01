//! Structured diagnostics for a single proxy link.
//!
//! This module is included by `xray` so the binary can expose a reusable API
//! without introducing a second runtime/process-management implementation.

use crate::parse::{self, ParseErr, Proxy};
use crate::speed::MeasurementSummary;
use crate::xray::{self, SpeedOpts};
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;

/// Options for one-link diagnostics.
#[derive(Clone, Debug)]
pub struct DiagnosticOptions {
    pub core: PathBuf,
    pub hysteria1_core: Option<PathBuf>,
    pub workdir: PathBuf,
    pub base_port: u16,
    pub start_timeout: Duration,
    pub no_xray_download: bool,
    pub no_hysteria1_download: bool,
    pub speed_url: Option<String>,
    pub connect_timeout_s: f64,
    pub speed_timeout_s: f64,
    pub max_size_mb: f64,
    pub min_speed_kbs: f64,
    /// Number of deterministic speed-test targets, including `speed_url`.
    pub speed_probes: usize,
}

impl DiagnosticOptions {
    /// Create options with conservative defaults; callers provide the runtime
    /// and working-directory paths explicitly.
    pub fn new(core: impl Into<PathBuf>, workdir: impl Into<PathBuf>) -> Self {
        Self {
            core: core.into(),
            hysteria1_core: None,
            workdir: workdir.into(),
            base_port: 20_800,
            start_timeout: Duration::from_secs(10),
            no_xray_download: false,
            no_hysteria1_download: false,
            speed_url: None,
            connect_timeout_s: 5.0,
            speed_timeout_s: 15.0,
            max_size_mb: 10.0,
            min_speed_kbs: 0.0,
            speed_probes: 3,
        }
    }

    pub(super) fn speed_opts(&self) -> SpeedOpts {
        SpeedOpts {
            primary: self.speed_url.clone(),
            connect_timeout_s: self.connect_timeout_s,
            timeout_s: self.speed_timeout_s,
            max_mb: self.max_size_mb,
            min_kb: self.min_speed_kbs,
            speed_probes: self.speed_probes,
        }
    }
}

/// Parsing result as represented in a diagnostic report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum ParseStatus {
    Parsed,
    Invalid(String),
    Unsupported(String),
}

/// First stage that prevented a complete diagnostic.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "stage", content = "reason", rename_all = "snake_case")]
pub enum DiagnosticFailure {
    Parse(String),
    UnsupportedProtocol(String),
    RuntimeUnavailable(String),
    RuntimeStart(String),
    RuntimeExited(String),
    StartupTimeout,
    SocksNotReady(String),
    DownloadFailed,
    BelowMinimum { measured_kbs: f64, minimum_kbs: f64 },
}

/// JSON-friendly speed-probe summary, in KiB/s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub struct ProbeSummary {
    pub median_kbs: f64,
    pub successful_probes: usize,
    pub min_kbs: Option<f64>,
    pub max_kbs: Option<f64>,
}

impl From<MeasurementSummary> for ProbeSummary {
    fn from(summary: MeasurementSummary) -> Self {
        Self {
            median_kbs: summary.median_kbs,
            successful_probes: summary.successful_probes,
            min_kbs: summary.min_kbs,
            max_kbs: summary.max_kbs,
        }
    }
}

/// Structured result for parsing, runtime readiness, and speed probes.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DiagnosticReport {
    pub parsed: ParseStatus,
    pub protocol: Option<String>,
    /// `Some(true)` means the client process was spawned successfully;
    /// `Some(false)` means startup was attempted but not confirmed. `None`
    /// means startup was not attempted.
    pub core_started: Option<bool>,
    /// `Some(true)` means a SOCKS5 greeting/selection handshake succeeded.
    pub socks_ready: Option<bool>,
    pub download_succeeded: Option<bool>,
    /// Multi-target median speed, in KiB/s.
    pub speed_median_kbs: Option<f64>,
    pub measurement: Option<ProbeSummary>,
    pub failure: Option<DiagnosticFailure>,
}

impl DiagnosticReport {
    fn parse_failure(status: ParseStatus, reason: String) -> Self {
        Self {
            parsed: status,
            protocol: None,
            core_started: None,
            socks_ready: None,
            download_succeeded: None,
            speed_median_kbs: None,
            measurement: None,
            failure: Some(DiagnosticFailure::Parse(reason)),
        }
    }
}

/// Parse and diagnose one proxy URI. Parse and runtime failures are returned
/// as structured report fields; `Err` is reserved for invalid options or
/// failures preparing the diagnostic workspace.
pub async fn diagnose_link(link: &str, options: DiagnosticOptions) -> Result<DiagnosticReport> {
    let proxy = match parse::parse_link(link) {
        Ok(proxy) => proxy,
        Err(ParseErr::Invalid(reason)) => {
            return Ok(DiagnosticReport::parse_failure(
                ParseStatus::Invalid(reason.to_string()),
                reason.to_string(),
            ));
        }
        Err(ParseErr::Unsupported(reason)) => {
            return Ok(DiagnosticReport::parse_failure(
                ParseStatus::Unsupported(reason.to_string()),
                reason.to_string(),
            ));
        }
    };

    if options.base_port == 0 {
        anyhow::bail!("diagnostic base_port must be nonzero");
    }
    if options.speed_probes == 0 {
        anyhow::bail!("diagnostic speed_probes must be nonzero");
    }
    tokio::fs::create_dir_all(&options.workdir)
        .await
        .with_context(|| format!("creating diagnostic workdir {}", options.workdir.display()))?;

    Ok(diagnose_proxy(proxy, options).await)
}

async fn diagnose_proxy(proxy: Proxy, options: DiagnosticOptions) -> DiagnosticReport {
    let protocol = proxy.proto.to_string();
    let mut report = DiagnosticReport {
        parsed: ParseStatus::Parsed,
        protocol: Some(protocol.clone()),
        core_started: Some(false),
        socks_ready: Some(false),
        download_succeeded: Some(false),
        speed_median_kbs: Some(0.0),
        measurement: Some(ProbeSummary::default()),
        failure: None,
    };

    if protocol == "hysteria" {
        let core = options
            .hysteria1_core
            .clone()
            .unwrap_or_else(|| crate::hysteria1::default_core_path_next_to(&options.core));
        if let Err(error) =
            crate::hysteria1::ensure_core(&core, options.no_hysteria1_download).await
        {
            report.core_started = None;
            report.socks_ready = None;
            report.download_succeeded = None;
            report.speed_median_kbs = None;
            report.measurement = None;
            report.failure = Some(DiagnosticFailure::RuntimeUnavailable(format!("{error:#}")));
            return report;
        }
        let port = options.base_port;
        let outcome = crate::hysteria1::check_proxy_diagnostic(
            &core,
            &options.workdir,
            &proxy,
            port,
            &options.speed_opts(),
            true,
        )
        .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                report.core_started = None;
                report.socks_ready = None;
                report.download_succeeded = None;
                report.speed_median_kbs = None;
                report.measurement = None;
                report.failure = Some(DiagnosticFailure::RuntimeStart(format!("{error:#}")));
                return report;
            }
        };
        let measurement = outcome.measurement;
        report.core_started = Some(outcome.core_started);
        report.socks_ready = Some(outcome.socks_ready);
        report.download_succeeded = Some(measurement.successful_probes > 0);
        report.speed_median_kbs = Some(measurement.median_kbs);
        report.measurement = Some(measurement.into());
        if !outcome.socks_ready {
            report.failure = Some(DiagnosticFailure::SocksNotReady(
                "Hysteria v1 SOCKS5 listener did not become ready".into(),
            ));
        } else if measurement.successful_probes > 0 {
            if measurement.median_kbs < options.min_speed_kbs {
                report.failure = Some(DiagnosticFailure::BelowMinimum {
                    measured_kbs: measurement.median_kbs,
                    minimum_kbs: options.min_speed_kbs,
                });
            }
        } else {
            // The process and SOCKS handshake succeeded, but every download
            // probe failed. Preserve the completed startup stages.
            report.failure = Some(DiagnosticFailure::DownloadFailed);
        }
        return report;
    }

    if !xray::diagnose_supported(&proxy) {
        report.core_started = None;
        report.socks_ready = None;
        report.download_succeeded = None;
        report.speed_median_kbs = None;
        report.measurement = None;
        report.failure = Some(DiagnosticFailure::UnsupportedProtocol(protocol));
        return report;
    }

    if !options.core.exists() {
        if options.no_xray_download {
            report.core_started = None;
            report.socks_ready = None;
            report.download_succeeded = None;
            report.speed_median_kbs = None;
            report.measurement = None;
            report.failure = Some(DiagnosticFailure::RuntimeUnavailable(format!(
                "Xray core is missing: {} (download disabled)",
                options.core.display()
            )));
            return report;
        }
        if let Err(error) = xray::ensure_core(&options.core, None, false).await {
            report.core_started = None;
            report.socks_ready = None;
            report.download_succeeded = None;
            report.speed_median_kbs = None;
            report.measurement = None;
            report.failure = Some(DiagnosticFailure::RuntimeUnavailable(format!("{error:#}")));
            return report;
        }
    }

    xray::diagnose_runtime(proxy, options, report).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "proxy-rs-diagnose-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn valid_link() -> &'static str {
        "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:443#diagnose-fixture"
    }

    fn options(dir: &TestDir) -> DiagnosticOptions {
        let mut options = DiagnosticOptions::new(dir.path("fake-xray"), dir.path("work"));
        options.no_xray_download = true;
        options.start_timeout = Duration::from_millis(100);
        options.connect_timeout_s = 0.1;
        options.speed_timeout_s = 0.1;
        options.speed_probes = 1;
        options
    }

    #[tokio::test]
    async fn diagnose_link_reports_invalid_and_unsupported_parse_results_without_starting_core() {
        let dir = TestDir::new();
        let invalid = diagnose_link("vless://not-a-valid-proxy", options(&dir))
            .await
            .unwrap();
        assert!(matches!(invalid.parsed, ParseStatus::Invalid(_)));
        assert_eq!(invalid.core_started, None);
        assert!(matches!(invalid.failure, Some(DiagnosticFailure::Parse(_))));

        let unsupported = diagnose_link("ssr://fixture", options(&dir)).await.unwrap();
        assert_eq!(unsupported.parsed, ParseStatus::Unsupported("ssr".into()));
        assert_eq!(unsupported.core_started, None);
        let serialized = serde_json::to_value(&unsupported).unwrap();
        assert_eq!(serialized["parsed"]["status"], "unsupported");
        assert_eq!(serialized["failure"]["stage"], "parse");
    }

    #[tokio::test]
    async fn diagnose_link_reports_missing_runtime_when_download_is_disabled() {
        let dir = TestDir::new();
        let report = diagnose_link(valid_link(), options(&dir)).await.unwrap();

        assert_eq!(report.parsed, ParseStatus::Parsed);
        assert_eq!(report.protocol.as_deref(), Some("vless"));
        assert_eq!(report.core_started, None);
        assert!(matches!(
            report.failure,
            Some(DiagnosticFailure::RuntimeUnavailable(_))
        ));
        assert!(!dir.path("work").join("diagnose_20800.json").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn diagnose_link_distinguishes_started_core_from_missing_socks_readiness() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new();
        let core = dir.path("fake-xray");
        std::fs::write(&core, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&core, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut opts = options(&dir);
        opts.start_timeout = Duration::from_millis(150);

        let report = diagnose_link(valid_link(), opts).await.unwrap();

        assert_eq!(report.core_started, Some(true));
        assert_eq!(report.socks_ready, Some(false));
        assert_eq!(report.download_succeeded, Some(false));
        assert!(matches!(
            report.failure,
            Some(DiagnosticFailure::SocksNotReady(_))
        ));
        assert_eq!(std::fs::read_dir(dir.path("work")).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn diagnose_link_rejects_zero_probe_count_before_workspace_creation() {
        let dir = TestDir::new();
        let mut opts = options(&dir);
        opts.speed_probes = 0;

        let error = diagnose_link(valid_link(), opts).await.unwrap_err();

        assert!(error.to_string().contains("speed_probes"));
        assert!(!dir.path("work").exists());
    }
}
