//! Data model for a source-by-source quality report.
//!
//! This module is intentionally independent of fetching and proxy validation. Callers
//! can create one [`SourceQuality`] per configured subscription and update its counts
//! as each pipeline stage completes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Stable, serializable reason-to-occurrence counts used by source reports.
pub type ReasonCounts = BTreeMap<String, u64>;

/// The furthest pipeline state reached by a source.
///
/// Counts remain independent of this status: a partially processed source can still
/// report its fetched, parsed, duplicate, or TCP-live totals.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// The source has been registered but fetching has not finished.
    #[default]
    Pending,
    /// Fetching failed before response text was available.
    FetchFailed,
    /// Response text was fetched successfully.
    Fetched,
    /// Proxy links from the response have been parsed.
    Parsed,
    /// TCP reachability checks have completed.
    TcpChecked,
    /// Speed checks have completed.
    SpeedChecked,
}

/// Per-source item totals at each quality stage.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct SourceCounts {
    /// Successful response bodies fetched for this source (normally zero or one).
    pub fetched: u64,
    /// Valid, supported proxy links parsed from the source, before deduplication.
    pub valid: u64,
    /// Supported unique `Proxy::key` values first attributed to this source.
    #[serde(default)]
    pub unique: u64,
    /// Valid links discarded because they duplicated an earlier link.
    pub duplicate: u64,
    /// Unique proxies that passed the TCP liveness check.
    pub tcp_live: u64,
    /// TCP-live proxies that met the configured speed threshold.
    pub speed_qualified: u64,
    /// Proxies measured by a speed-check core but below the configured threshold.
    #[serde(default)]
    pub speed_failed: u64,
    /// Unsupported protocol features found in this subscription, keyed by labels
    /// such as `vmess: transport=quic`.
    #[serde(default)]
    pub unsupported_reasons: ReasonCounts,
    /// Invalid links found in this subscription, keyed by parser reason such as
    /// `bad uuid` or `bad vmess json`.
    #[serde(default)]
    pub invalid_reasons: ReasonCounts,
    /// Xray outbound configs rejected before a network probe, grouped by safe
    /// protocol/transport/security descriptors and normalized error category.
    #[serde(default)]
    pub xray_outbound_rejections: ReasonCounts,
}

/// Quality information for one configured source.
///
/// `url` is sanitized at construction and contains no userinfo, query, fragment, or
/// non-root path. The report model never stores a response body or fetch error text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceQuality {
    /// Stable ordinal identifier within the selected source list. Unlike the
    /// sanitized URL, this keeps feeds on the same host distinguishable.
    #[serde(default)]
    pub source_id: String,
    /// Sanitized source URL safe for inclusion in a report by default.
    url: String,
    pub status: SourceStatus,
    /// Safe, normalized fetch failure category. Raw error text can contain URLs.
    #[serde(default)]
    pub fetch_failure: Option<String>,
    /// Total attempts used for a failed source fetch, including the first request.
    #[serde(default)]
    pub fetch_attempts: Option<usize>,
    pub counts: SourceCounts,
}

impl SourceQuality {
    /// Create a source row, sanitizing its URL before retaining it.
    #[cfg(test)]
    pub fn new(url: &str) -> Self {
        Self::with_id(String::new(), url)
    }

    /// Create a source row with a stable identifier that does not expose URL
    /// paths, credentials, or query parameters.
    pub fn with_id(source_id: String, url: &str) -> Self {
        Self {
            source_id,
            url: redact_url(url),
            status: SourceStatus::Pending,
            fetch_failure: None,
            fetch_attempts: None,
            counts: SourceCounts::default(),
        }
    }

    /// Return the sanitized URL retained by this row.
    #[cfg(test)]
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Normalize a fetch error into a low-cardinality label without retaining error
/// text, which may contain a URL or other source-specific data.
pub fn fetch_failure_kind(reason: &str) -> String {
    let reason = reason.trim();
    if let Some(status) = reason.strip_prefix("HTTP ") {
        let status = status.split_whitespace().next().unwrap_or_default();
        if let Ok(code) = status.parse::<u16>() {
            if (100..=599).contains(&code) {
                return format!("http_{code}");
            }
        }
    }
    if reason.contains("время ожидания") || reason.contains("timeout") {
        "timeout".to_owned()
    } else if reason.contains("подключиться") || reason.contains("connect") {
        "connection".to_owned()
    } else if reason.contains("лимит") || reason.contains("превышает лимит") {
        "response_too_large".to_owned()
    } else if reason.contains("304") {
        "not_modified_without_cache".to_owned()
    } else if reason.contains("чтения ответа") || reason.contains("чтение ответа")
    {
        "response_read".to_owned()
    } else if reason.contains("создать HTTP-клиент") {
        "http_client".to_owned()
    } else {
        "request".to_owned()
    }
}

/// A collection of per-source quality rows.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceQualityReport {
    pub sources: Vec<SourceQuality>,
}

impl SourceQualityReport {
    /// Create an empty report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a source row and return it for updates as pipeline stages finish.
    #[cfg(test)]
    pub fn add_source(&mut self, url: &str) -> &mut SourceQuality {
        let source_id = format!("feed-{:03}", self.sources.len() + 1);
        self.add_source_with_id(source_id, url)
    }

    /// Add a source using its stable ordinal ID from the configured source list.
    pub fn add_source_with_id(
        &mut self,
        source_id: impl Into<String>,
        url: &str,
    ) -> &mut SourceQuality {
        self.sources
            .push(SourceQuality::with_id(source_id.into(), url));
        self.sources.last_mut().expect("just pushed a source row")
    }

    /// Backfill IDs for rows loaded from checkpoints written before IDs existed.
    pub fn fill_missing_source_ids(&mut self) {
        for (index, source) in self.sources.iter_mut().enumerate() {
            if source.source_id.is_empty() {
                source.source_id = format!("feed-{:03}", index + 1);
            }
        }
    }

    /// Serialize to compact JSON with source rows sorted by sanitized URL.
    ///
    /// Sorting a cloned view makes output deterministic regardless of completion
    /// order, without changing the report's in-memory order.
    #[cfg(test)]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let mut sorted = self.clone();
        sorted.sources.sort_by(|a, b| {
            a.url
                .cmp(&b.url)
                .then_with(|| a.status.cmp(&b.status))
                .then_with(|| counts_key(&a.counts).cmp(&counts_key(&b.counts)))
                .then_with(|| a.source_id.cmp(&b.source_id))
        });
        serde_json::to_string(&sorted)
    }

    /// Serialize to pretty JSON with stable field and source ordering.
    pub fn to_pretty_json(&self) -> Result<String, serde_json::Error> {
        let mut sorted = self.clone();
        sorted.sources.sort_by(|a, b| {
            a.url
                .cmp(&b.url)
                .then_with(|| a.status.cmp(&b.status))
                .then_with(|| counts_key(&a.counts).cmp(&counts_key(&b.counts)))
                .then_with(|| a.source_id.cmp(&b.source_id))
        });
        serde_json::to_string_pretty(&sorted)
    }
}

impl Ord for SourceStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl PartialOrd for SourceStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn counts_key(
    counts: &SourceCounts,
) -> (u64, u64, u64, u64, u64, u64, u64, String, String, String) {
    (
        counts.fetched,
        counts.valid,
        counts.unique,
        counts.duplicate,
        counts.tcp_live,
        counts.speed_qualified,
        counts.speed_failed,
        serde_json::to_string(&counts.unsupported_reasons).unwrap_or_default(),
        serde_json::to_string(&counts.invalid_reasons).unwrap_or_default(),
        serde_json::to_string(&counts.xray_outbound_rejections).unwrap_or_default(),
    )
}

/// Remove credentials and potentially sensitive URL components.
///
/// The scheme, host, and explicit port remain useful for identifying a feed. Paths
/// are replaced because providers sometimes place access tokens there. Invalid input
/// is replaced wholesale so malformed strings cannot leak credentials into JSON.
pub fn redact_url(input: &str) -> String {
    let Ok(mut url) = url::Url::parse(input) else {
        return "[redacted invalid URL]".to_owned();
    };

    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return "[redacted unsupported URL]".to_owned();
    }

    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    if url.path() != "/" {
        url.set_path("/[redacted]");
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::{fetch_failure_kind, redact_url, SourceCounts, SourceQualityReport, SourceStatus};
    use serde_json::json;

    #[test]
    fn new_rows_have_pending_status_and_zero_counts() {
        let row = super::SourceQuality::new("https://feed.example/subscriptions");

        assert!(row.source_id.is_empty());
        assert_eq!(row.url(), "https://feed.example/[redacted]");
        assert_eq!(row.status, SourceStatus::Pending);
        assert_eq!(row.counts.fetched, 0);
        assert_eq!(row.counts.valid, 0);
        assert_eq!(row.counts.unique, 0);
        assert_eq!(row.counts.duplicate, 0);
        assert_eq!(row.counts.tcp_live, 0);
        assert_eq!(row.counts.speed_qualified, 0);
    }

    #[test]
    fn url_redaction_removes_userinfo_query_fragment_and_path_tokens() {
        let redacted = redact_url(
            "https://alice:secret@feed.example:8443/private/token?key=query-secret#fragment-secret",
        );

        assert_eq!(redacted, "https://feed.example:8443/[redacted]");
        for secret in [
            "alice",
            "secret",
            "token",
            "query-secret",
            "fragment-secret",
        ] {
            assert!(!redacted.contains(secret));
        }
    }

    #[test]
    fn url_redaction_preserves_safe_root_urls_and_ipv6_hosts() {
        assert_eq!(redact_url("https://feed.example/"), "https://feed.example/");
        assert_eq!(
            redact_url("http://[::1]:8080/?token=secret"),
            "http://[::1]:8080/"
        );
    }

    #[test]
    fn url_redaction_replaces_malformed_and_non_http_urls() {
        assert_eq!(
            redact_url("not a url user:password"),
            "[redacted invalid URL]"
        );
        assert_eq!(
            redact_url("ftp://user:password@feed.example/file"),
            "[redacted unsupported URL]"
        );
        assert_eq!(
            redact_url("vless://uuid-secret@proxy.example:443"),
            "[redacted unsupported URL]"
        );
    }

    #[test]
    fn report_json_contains_expected_fields_and_counts_without_body_data() {
        let mut report = SourceQualityReport::new();
        let row = report.add_source("https://user:pass@feed.example/list?token=abc");
        row.status = SourceStatus::SpeedChecked;
        row.counts.fetched = 1;
        row.counts.valid = 12;
        row.counts.unique = 9;
        row.counts.duplicate = 3;
        row.counts.tcp_live = 7;
        row.counts.speed_qualified = 4;
        row.counts.speed_failed = 2;
        assert_eq!(row.source_id, "feed-001");

        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(
            value,
            json!({
                "sources": [{
                    "source_id": "feed-001",
                    "url": "https://feed.example/[redacted]",
                    "status": "speed_checked",
                    "fetch_failure": null,
                    "fetch_attempts": null,
                    "counts": {
                        "fetched": 1,
                        "valid": 12,
                        "unique": 9,
                        "duplicate": 3,
                        "tcp_live": 7,
                        "speed_qualified": 4,
                        "speed_failed": 2,
                        "unsupported_reasons": {},
                        "invalid_reasons": {},
                        "xray_outbound_rejections": {}
                    }
                }]
            })
        );
        let serialized = report.to_json().unwrap();
        assert!(!serialized.contains("pass"));
        assert!(!serialized.contains("abc"));
        assert!(!serialized.contains("response body"));
    }

    #[test]
    fn failed_fetch_report_preserves_attempt_count_without_raw_error_text() {
        let mut report = SourceQualityReport::new();
        let row = report.add_source_with_id("feed-007", "https://feed.example/token-path?secret=x");
        row.status = SourceStatus::FetchFailed;
        row.fetch_failure = Some("http_404".into());
        row.fetch_attempts = Some(3);

        let serialized = report.to_json().unwrap();
        assert!(serialized.contains("\"fetch_failure\":\"http_404\""));
        assert!(serialized.contains("\"fetch_attempts\":3"));
        assert!(!serialized.contains("token-path"));
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn same_host_sources_receive_distinct_safe_ids_and_legacy_rows_are_backfilled() {
        let mut report = SourceQualityReport::new();
        report.add_source_with_id("feed-001", "https://feed.example/one?key=secret");
        report.add_source_with_id("feed-002", "https://feed.example/two?key=other");
        assert_eq!(report.sources[0].url, report.sources[1].url);
        assert_ne!(report.sources[0].source_id, report.sources[1].source_id);
        let json = report.to_pretty_json().unwrap();
        for secret in ["/one", "/two", "secret", "other"] {
            assert!(!json.contains(secret));
        }
        assert!(json.contains("feed-001"));
        assert!(json.contains("feed-002"));

        let mut legacy: SourceQualityReport = serde_json::from_value(json!( {
            "sources": [
                {"url":"https://feed.example/","status":"parsed","counts":{}},
                {"url":"https://feed.example/","status":"fetch_failed","counts":{}}
            ]
        }))
        .unwrap();
        legacy.fill_missing_source_ids();
        assert_eq!(legacy.sources[0].source_id, "feed-001");
        assert_eq!(legacy.sources[1].source_id, "feed-002");
    }

    #[test]
    fn fetch_failure_kind_is_safe_and_does_not_copy_error_details() {
        assert_eq!(fetch_failure_kind("HTTP 404 Not Found"), "http_404");
        assert_eq!(
            fetch_failure_kind("истекло время ожидания источника"),
            "timeout"
        );
        assert_eq!(
            fetch_failure_kind("ошибка HTTP-запроса https://user:secret@example.org/?token=abc"),
            "request"
        );
        assert_eq!(
            fetch_failure_kind("ответ превышает лимит 1048576 байт"),
            "response_too_large"
        );
    }

    #[test]
    fn json_output_is_deterministic_and_sorted_without_reordering_report() {
        let mut report = SourceQualityReport::new();
        report.add_source("https://z.example/feed").counts.valid = 1;
        report.add_source("https://a.example/feed").counts.valid = 2;

        let json = report.to_json().unwrap();
        assert_eq!(json, report.to_json().unwrap());
        assert!(json.find("a.example").unwrap() < json.find("z.example").unwrap());
        assert_eq!(report.sources[0].url(), "https://z.example/[redacted]");

        let pretty = report.to_pretty_json().unwrap();
        assert!(pretty.contains("\n  \"sources\": ["));
        assert!(pretty.find("a.example").unwrap() < pretty.find("z.example").unwrap());
    }

    #[test]
    fn equal_redacted_urls_are_sorted_by_status_then_counts() {
        let mut report = SourceQualityReport::new();
        let higher = report.add_source("https://feed.example/second");
        higher.status = SourceStatus::SpeedChecked;
        higher.counts.valid = 9;
        let parsed = report.add_source("https://feed.example/first");
        parsed.status = SourceStatus::Fetched;
        parsed.counts.valid = 100;
        let lower = report.add_source("https://feed.example/third");
        lower.status = SourceStatus::SpeedChecked;
        lower.counts.valid = 2;

        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        let rows = value["sources"].as_array().unwrap();

        assert_eq!(rows[0]["status"], "fetched");
        assert_eq!(rows[1]["status"], "speed_checked");
        assert_eq!(rows[1]["counts"]["valid"], 2);
        assert_eq!(rows[2]["counts"]["valid"], 9);
        assert_eq!(report.sources[0].counts.valid, 9);
        assert_eq!(report.sources[1].status, SourceStatus::Fetched);
    }

    #[test]
    fn pretty_json_breaks_equal_url_and_status_ties_by_counts() {
        let mut report = SourceQualityReport::new();
        let larger = report.add_source("https://feed.example/first");
        larger.status = SourceStatus::Fetched;
        larger.counts.valid = 9;
        let smaller = report.add_source("https://feed.example/second");
        smaller.status = SourceStatus::Fetched;
        smaller.counts.valid = 2;

        let pretty = report.to_pretty_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&pretty).unwrap();
        let rows = value["sources"].as_array().unwrap();

        assert_eq!(rows[0]["counts"]["valid"], 2);
        assert_eq!(rows[1]["counts"]["valid"], 9);
        assert_eq!(report.sources[0].counts.valid, 9);
    }

    #[test]
    fn fully_equal_source_rows_are_stable_sort_keys() {
        let mut report = SourceQualityReport::new();
        report.add_source("https://feed.example/one");
        report.add_source("https://feed.example/two");
        let before = report.sources.clone();

        let json = report.to_json().unwrap();
        assert_eq!(json, report.to_json().unwrap());
        assert_eq!(report.sources, before);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap()["sources"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn old_source_report_json_deserializes_without_reason_counts() {
        let old_json = r#"{"sources":[{"url":"https://feed.example/","status":"parsed","counts":{"fetched":1,"valid":2,"duplicate":0,"tcp_live":0,"speed_qualified":0}}]}"#;
        let report: SourceQualityReport = serde_json::from_str(old_json).unwrap();
        assert!(report.sources[0].counts.unsupported_reasons.is_empty());
        assert!(report.sources[0].counts.invalid_reasons.is_empty());
    }

    #[test]
    fn old_source_counts_deserialize_with_defaults_for_added_fields() {
        let old_json = r#"{"fetched":1,"valid":2,"duplicate":0,"tcp_live":0,"speed_qualified":0,"unsupported_reasons":{"vmess: transport=quic":3}}"#;
        let counts: SourceCounts = serde_json::from_str(old_json).unwrap();
        assert_eq!(counts.unique, 0);
        assert_eq!(counts.unsupported_reasons["vmess: transport=quic"], 3);
        assert!(counts.invalid_reasons.is_empty());
    }

    #[test]
    fn reason_counts_and_unique_count_are_independent_per_source() {
        let mut counts = SourceCounts {
            unique: 3,
            ..SourceCounts::default()
        };
        *counts.invalid_reasons.entry("bad uuid".into()).or_default() += 2;
        *counts
            .invalid_reasons
            .entry("bad address".into())
            .or_default() += 1;
        *counts
            .unsupported_reasons
            .entry("vmess: transport=quic".into())
            .or_default() += 2;

        assert_eq!(counts.invalid_reasons["bad uuid"], 2);
        assert_eq!(counts.invalid_reasons["bad address"], 1);
        assert_eq!(counts.unique, 3);
        assert_eq!(counts.unsupported_reasons["vmess: transport=quic"], 2);
    }

    #[test]
    fn unsupported_counts_are_serialized_in_stable_key_order() {
        let mut report = SourceQualityReport::new();
        let counts = &mut report.add_source("https://feed.example/").counts;
        counts
            .unsupported_reasons
            .insert("vmess: transport=xhttp".into(), 1);
        counts
            .unsupported_reasons
            .insert("vmess: transport=quic".into(), 2);

        let json = report.to_json().unwrap();
        assert!(json.find("transport=quic").unwrap() < json.find("transport=xhttp").unwrap());
        assert_eq!(json, report.to_json().unwrap());
    }

    #[test]
    fn invalid_counts_are_serialized_and_round_trip() {
        let mut counts = SourceCounts::default();
        counts.invalid_reasons.insert("bad uuid".into(), 1);
        counts.invalid_reasons.insert("bad vmess json".into(), 1);
        counts.unique = 7;

        let json = serde_json::to_string(&counts).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["invalid_reasons"]["bad uuid"], 1);
        assert_eq!(value["invalid_reasons"]["bad vmess json"], 1);
        assert_eq!(value["unique"], 7);
        assert_eq!(serde_json::from_str::<SourceCounts>(&json).unwrap(), counts);
    }

    #[test]
    fn empty_report_serializes_to_stable_empty_collection() {
        let report = SourceQualityReport::new();
        assert_eq!(report.to_json().unwrap(), r#"{"sources":[]}"#);
        assert_eq!(report.to_pretty_json().unwrap(), "{\n  \"sources\": []\n}");
    }

    #[test]
    fn status_serialization_names_are_stable_snake_case() {
        let statuses = [
            (SourceStatus::Pending, "pending"),
            (SourceStatus::FetchFailed, "fetch_failed"),
            (SourceStatus::Fetched, "fetched"),
            (SourceStatus::Parsed, "parsed"),
            (SourceStatus::TcpChecked, "tcp_checked"),
            (SourceStatus::SpeedChecked, "speed_checked"),
        ];

        for (status, expected) in statuses {
            assert_eq!(
                serde_json::to_string(&status).unwrap(),
                format!("\"{expected}\"")
            );
        }
    }

    #[test]
    fn status_ordering_is_total_and_equal_values_compare_equal() {
        let statuses = [
            SourceStatus::Pending,
            SourceStatus::FetchFailed,
            SourceStatus::Fetched,
            SourceStatus::Parsed,
            SourceStatus::TcpChecked,
            SourceStatus::SpeedChecked,
        ];

        for (index, status) in statuses.iter().enumerate() {
            assert_eq!(status.cmp(status), std::cmp::Ordering::Equal);
            assert_eq!(status.partial_cmp(status), Some(std::cmp::Ordering::Equal));
            for later in &statuses[index + 1..] {
                assert_eq!(status.cmp(later), std::cmp::Ordering::Less);
                assert_eq!(later.cmp(status), std::cmp::Ordering::Greater);
            }
        }
    }
}
