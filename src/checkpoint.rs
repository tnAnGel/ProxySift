//! Versioned, atomic persistence for pausing and resuming the proxy pipeline.
//!
//! The CLI persists completed stages here and resumes from the last safe point.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

/// Current on-disk checkpoint format. Bump when serialized fields or semantics
/// change incompatibly; older formats should be migrated explicitly in `load`.
pub const CHECKPOINT_SCHEMA_VERSION: u32 = 3;
/// Checkpoints may contain credentials and large proxy sets; cap parsing memory.
pub const MAX_CHECKPOINT_BYTES: u64 = 512 * 1024 * 1024;

/// The last fully completed pipeline stage represented by a checkpoint.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    #[default]
    Fetched,
    Parsed,
    GeoIp,
    TcpPing,
    Speed,
    Complete,
}

/// Serializable snapshot of `parse::Proxy`, including all computed pipeline
/// fields. Keeping the original and normalized URLs lets callers restore both
/// the current proxy set and the exact link used to produce it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxySnapshot {
    pub proto: String,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub base_url: String,
    pub orig_url: String,
    pub settings: serde_json::Value,
    pub stream: Option<serde_json::Value>,
    pub country: String,
    pub display: String,
    pub ping: Option<u64>,
    pub speed_kbs: f64,
}

impl ProxySnapshot {
    /// Capture a proxy at any pipeline stage.
    pub fn from_proxy(proxy: &crate::parse::Proxy) -> Self {
        Self {
            proto: proxy.proto.to_owned(),
            host: proxy.host.clone(),
            port: proxy.port,
            name: proxy.name.clone(),
            base_url: proxy.base_url.clone(),
            orig_url: proxy.orig_url.clone(),
            settings: proxy.settings.clone(),
            stream: proxy.stream.clone(),
            country: proxy.country.clone(),
            display: proxy.display.clone(),
            ping: proxy.ping,
            speed_kbs: proxy.speed_kbs,
        }
    }

    /// Restore the application's proxy type. Unknown protocols are rejected
    /// instead of being coerced into a different protocol.
    pub fn into_proxy(self) -> Result<crate::parse::Proxy> {
        let proto = match self.proto.as_str() {
            "vless" => "vless",
            "vmess" => "vmess",
            "trojan" => "trojan",
            "shadowsocks" => "shadowsocks",
            "hysteria" => "hysteria",
            "hysteria2" => "hysteria2",
            other => bail!("checkpoint contains unsupported proxy protocol: {other}"),
        };
        Ok(crate::parse::Proxy {
            proto,
            host: self.host,
            port: self.port,
            name: self.name,
            base_url: self.base_url,
            orig_url: self.orig_url,
            settings: self.settings,
            stream: self.stream,
            country: self.country,
            display: self.display,
            ping: self.ping,
            speed_kbs: self.speed_kbs,
        })
    }
}

/// Complete, resumable state for the proxy pipeline.
///
/// `stage` means that stage has finished. `raw_links` are fetched/extracted
/// inputs, `processed_links` records links consumed by the current run, and
/// `proxies` holds the latest per-proxy results (including country, ping, and
/// measured speed). `final_links` stores the rendered output links.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub schema_version: u32,
    pub stage: PipelineStage,
    pub raw_links: Vec<String>,
    pub processed_links: Vec<String>,
    #[serde(default)]
    pub parse_stats: ParseSnapshotStats,
    #[serde(default)]
    pub source_quality: crate::source_report::SourceQualityReport,
    #[serde(default)]
    pub source_owners: HashMap<String, usize>,
    pub proxies: Vec<ProxySnapshot>,
    pub final_links: Vec<String>,
}

/// Parse totals retained so resumed runs can report accurate counters without
/// repeating the parsing stage.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParseSnapshotStats {
    pub links: usize,
    pub parsed: usize,
    pub duplicates: usize,
    pub invalid: usize,
    pub unsupported: usize,
}

impl Default for Checkpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl Checkpoint {
    /// Create an empty checkpoint in the current schema.
    pub fn new() -> Self {
        Self {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            stage: PipelineStage::Fetched,
            raw_links: Vec::new(),
            processed_links: Vec::new(),
            parse_stats: ParseSnapshotStats::default(),
            source_quality: crate::source_report::SourceQualityReport::new(),
            source_owners: HashMap::new(),
            proxies: Vec::new(),
            final_links: Vec::new(),
        }
    }

    /// Persist to `path` using the repository's same-directory atomic writer.
    /// Serialization completes before the destination can be modified.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        self.save_with_limit(path.as_ref(), MAX_CHECKPOINT_BYTES)
    }

    fn save_with_limit(&self, path: &Path, max_bytes: u64) -> Result<()> {
        self.validate_version()?;
        let bytes = serde_json::to_vec_pretty(self).context("serialize checkpoint")?;
        check_size_limit(bytes.len() as u64, max_bytes)?;
        crate::output::write_bytes_atomic(path, &bytes, Some(0o600))
            .context("atomically write checkpoint")
    }

    /// Load a checkpoint. Returns `Ok(None)` only when the file does not exist;
    /// malformed data and unsupported versions are errors and never defaults.
    pub fn load(path: impl AsRef<Path>) -> Result<Option<Self>> {
        Self::load_with_limit(path.as_ref(), MAX_CHECKPOINT_BYTES)
    }

    fn load_with_limit(path: &Path, max_bytes: u64) -> Result<Option<Self>> {
        if let Ok(metadata) = std::fs::metadata(path) {
            check_size_limit(metadata.len(), max_bytes)?;
        }
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("read checkpoint"),
        };
        let bytes = read_limited(file, max_bytes).context("read checkpoint")?;
        let checkpoint: Self =
            serde_json::from_slice(&bytes).context("checkpoint is corrupt or malformed")?;
        checkpoint.validate_version()?;
        Ok(Some(checkpoint))
    }

    /// Record that a pipeline stage has completed and replace its current
    /// proxy results. Callers should save immediately after this operation.
    pub fn record_stage(
        &mut self,
        stage: PipelineStage,
        processed_links: Vec<String>,
        proxies: Vec<ProxySnapshot>,
    ) {
        self.stage = stage;
        self.processed_links = processed_links;
        self.proxies = proxies;
    }

    /// Replace the final rendered links and mark the pipeline complete.
    pub fn complete(&mut self, final_links: Vec<String>) {
        self.final_links = final_links;
        self.stage = PipelineStage::Complete;
    }

    fn validate_version(&self) -> Result<()> {
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION {
            bail!(
                "unsupported checkpoint schema version {}; expected {}",
                self.schema_version,
                CHECKPOINT_SCHEMA_VERSION
            );
        }
        Ok(())
    }
}

fn check_size_limit(size: u64, max_bytes: u64) -> Result<()> {
    if size > max_bytes {
        bail!("checkpoint exceeds the {max_bytes}-byte safety limit");
    }
    Ok(())
}

fn read_limit(max_bytes: u64) -> u64 {
    max_bytes
        .checked_add(1)
        .expect("checkpoint read limit must fit in u64")
}

fn read_limited(mut reader: impl Read, max_bytes: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(read_limit(max_bytes))
        .read_to_end(&mut bytes)?;
    check_size_limit(bytes.len() as u64, max_bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIR_ID: AtomicUsize = AtomicUsize::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("proxy-rs-checkpoint-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("state.json")
        }

        fn directory_entries(&self) -> Vec<PathBuf> {
            std::fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect()
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn proxy_snapshot() -> ProxySnapshot {
        ProxySnapshot {
            proto: "vless".into(),
            host: "edge.example".into(),
            port: 443,
            name: "edge".into(),
            base_url: "vless://id@edge.example:443".into(),
            orig_url: "vless://id@edge.example:443#edge".into(),
            settings: json!({"id": "test-id", "encryption": "none"}),
            stream: Some(json!({"network": "ws", "security": "tls"})),
            country: "DE".into(),
            display: "[DE] - 001".into(),
            ping: Some(32),
            speed_kbs: 128.5,
        }
    }

    #[test]
    fn new_checkpoint_uses_current_schema_and_empty_state() {
        let checkpoint = Checkpoint::new();
        assert_eq!(checkpoint.schema_version, CHECKPOINT_SCHEMA_VERSION);
        assert_eq!(checkpoint.stage, PipelineStage::Fetched);
        assert!(checkpoint.raw_links.is_empty());
        assert!(checkpoint.processed_links.is_empty());
        assert!(checkpoint.proxies.is_empty());
        assert!(checkpoint.final_links.is_empty());
    }

    #[test]
    fn default_checkpoint_matches_new_checkpoint() {
        assert_eq!(Checkpoint::default(), Checkpoint::new());
    }

    #[test]
    fn round_trip_preserves_stage_links_proxy_results_and_final_output() {
        let dir = TestDir::new();
        let mut checkpoint = Checkpoint::new();
        checkpoint.raw_links = vec!["source link".into()];
        checkpoint.record_stage(
            PipelineStage::Speed,
            vec!["processed link".into()],
            vec![proxy_snapshot()],
        );
        checkpoint.complete(vec!["final link".into()]);

        checkpoint.save(dir.file()).unwrap();
        assert_eq!(Checkpoint::load(dir.file()).unwrap(), Some(checkpoint));
    }

    #[test]
    fn stage_recording_replaces_current_results_without_dropping_raw_inputs() {
        let mut checkpoint = Checkpoint::new();
        checkpoint.raw_links.push("input".into());
        checkpoint.record_stage(
            PipelineStage::GeoIp,
            vec!["geoip done".into()],
            vec![proxy_snapshot()],
        );
        checkpoint.record_stage(PipelineStage::TcpPing, vec!["ping done".into()], Vec::new());

        assert_eq!(checkpoint.stage, PipelineStage::TcpPing);
        assert_eq!(checkpoint.raw_links, ["input"]);
        assert_eq!(checkpoint.processed_links, ["ping done"]);
        assert!(checkpoint.proxies.is_empty());
    }

    #[test]
    fn load_returns_none_for_a_missing_file() {
        let dir = TestDir::new();
        assert_eq!(Checkpoint::load(dir.file()).unwrap(), None);
    }

    #[test]
    fn load_rejects_corrupt_json() {
        let dir = TestDir::new();
        std::fs::write(dir.file(), b"{not json").unwrap();
        let error = Checkpoint::load(dir.file()).unwrap_err();
        assert!(error.to_string().contains("corrupt or malformed"));
    }

    #[test]
    fn load_rejects_truncated_checkpoint_without_returning_partial_state() {
        let dir = TestDir::new();
        std::fs::write(dir.file(), br#"{"schema_version":1,"stage":"speed""#).unwrap();
        assert!(Checkpoint::load(dir.file()).is_err());
    }

    #[test]
    fn load_preserves_defaults_for_optional_fields_missing_from_older_schema_three_data() {
        let dir = TestDir::new();
        std::fs::write(
            dir.file(),
            br#"{"schema_version":3,"stage":"parsed","raw_links":["raw"],"processed_links":["parsed"],"proxies":[],"final_links":[]}"#,
        )
        .unwrap();

        let checkpoint = Checkpoint::load(dir.file()).unwrap().unwrap();

        assert_eq!(checkpoint.stage, PipelineStage::Parsed);
        assert_eq!(checkpoint.parse_stats, ParseSnapshotStats::default());
        assert_eq!(
            checkpoint.source_quality,
            crate::source_report::SourceQualityReport::new()
        );
        assert!(checkpoint.source_owners.is_empty());
    }

    #[test]
    fn load_reports_an_existing_directory_as_a_read_error() {
        let dir = TestDir::new();

        let error = Checkpoint::load(&dir.0).unwrap_err();

        assert!(error.to_string().contains("read checkpoint"));
    }

    #[cfg(unix)]
    #[test]
    fn load_reports_symlink_loops_as_read_errors() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new();
        let path = dir.file();
        symlink(&path, &path).unwrap();

        let error = Checkpoint::load(&path).unwrap_err();

        assert!(error.to_string().contains("read checkpoint"));
    }

    #[test]
    fn load_rejects_unknown_schema_version() {
        let dir = TestDir::new();
        std::fs::write(
            dir.file(),
            br#"{"schema_version":999,"stage":"fetched","raw_links":[],"processed_links":[],"proxies":[],"final_links":[]}"#,
        )
        .unwrap();
        let error = Checkpoint::load(dir.file()).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported checkpoint schema version 999"));
    }

    #[test]
    fn save_rejects_a_mutated_unknown_schema_before_touching_destination() {
        let dir = TestDir::new();
        std::fs::write(dir.file(), b"previous checkpoint").unwrap();
        let mut checkpoint = Checkpoint::new();
        checkpoint.schema_version = CHECKPOINT_SCHEMA_VERSION + 1;

        assert!(checkpoint.save(dir.file()).is_err());
        assert_eq!(std::fs::read(dir.file()).unwrap(), b"previous checkpoint");
        assert_eq!(dir.directory_entries().len(), 1);
    }

    #[test]
    fn save_atomically_replaces_an_existing_checkpoint_without_leaving_temp_files() {
        let dir = TestDir::new();
        std::fs::write(dir.file(), b"old data").unwrap();
        let mut checkpoint = Checkpoint::new();
        checkpoint.stage = PipelineStage::Parsed;
        checkpoint.raw_links.push("new input".into());

        checkpoint.save(dir.file()).unwrap();

        assert_eq!(Checkpoint::load(dir.file()).unwrap(), Some(checkpoint));
        assert_eq!(dir.directory_entries(), vec![dir.file()]);
    }

    #[test]
    fn load_rejects_files_above_the_size_limit_before_deserializing() {
        let dir = TestDir::new();
        let file = std::fs::File::create(dir.file()).unwrap();
        file.set_len(MAX_CHECKPOINT_BYTES + 1).unwrap();
        let error = Checkpoint::load(dir.file()).unwrap_err();
        assert!(error.to_string().contains("safety limit"));
    }

    #[test]
    fn checkpoint_limit_is_512_mib_and_includes_the_exact_boundary() {
        assert_eq!(MAX_CHECKPOINT_BYTES, 512 * 1024 * 1024);
        assert!(check_size_limit(MAX_CHECKPOINT_BYTES, MAX_CHECKPOINT_BYTES).is_ok());
        assert!(check_size_limit(MAX_CHECKPOINT_BYTES + 1, MAX_CHECKPOINT_BYTES).is_err());
    }

    #[test]
    fn save_accepts_exact_limit_and_rejects_one_byte_over_without_touching_file() {
        let dir = TestDir::new();
        let path = dir.file();
        let checkpoint = Checkpoint::new();
        let serialized = serde_json::to_vec_pretty(&checkpoint).unwrap();
        let exact_limit = serialized.len() as u64;

        checkpoint.save_with_limit(&path, exact_limit).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), serialized);

        std::fs::write(&path, b"previous").unwrap();
        let error = checkpoint
            .save_with_limit(&path, exact_limit - 1)
            .unwrap_err();
        assert!(error.to_string().contains("safety limit"));
        assert_eq!(std::fs::read(&path).unwrap(), b"previous");
    }

    #[test]
    fn load_accepts_exact_limit_and_rejects_over_limit_during_bounded_read() {
        let dir = TestDir::new();
        let path = dir.file();
        let checkpoint = Checkpoint::new();
        let mut serialized = serde_json::to_vec(&checkpoint).unwrap();
        let exact_limit = serialized.len() as u64;
        std::fs::write(&path, &serialized).unwrap();

        assert_eq!(
            Checkpoint::load_with_limit(&path, exact_limit).unwrap(),
            Some(checkpoint.clone())
        );

        serialized.push(b' ');
        assert_eq!(read_limit(exact_limit), exact_limit + 1);
        assert!(read_limited(std::io::Cursor::new(serialized.clone()), exact_limit).is_err());
        std::fs::write(&path, serialized).unwrap();
        let error = Checkpoint::load_with_limit(&path, exact_limit).unwrap_err();
        assert!(error.to_string().contains("safety limit"));
    }

    #[test]
    fn read_limit_is_exactly_one_byte_over_the_allowed_size() {
        for limit in [0, 1, 1024] {
            assert_eq!(read_limit(limit), limit + 1);
            assert!(read_limited(std::io::Cursor::new(vec![b'x'; limit as usize]), limit).is_ok());
            assert!(
                read_limited(std::io::Cursor::new(vec![b'x'; limit as usize + 1]), limit).is_err()
            );
        }
        assert_eq!(read_limit(MAX_CHECKPOINT_BYTES), 512 * 1024 * 1024 + 1);
    }

    #[cfg(unix)]
    #[test]
    fn save_restricts_checkpoint_permissions_to_the_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new();
        Checkpoint::new().save(dir.file()).unwrap();
        let mode = std::fs::metadata(dir.file()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn proxy_snapshot_round_trips_all_fields() {
        let expected = proxy_snapshot();
        let restored =
            serde_json::from_slice::<ProxySnapshot>(&serde_json::to_vec(&expected).unwrap())
                .unwrap();
        assert_eq!(restored, expected);
    }

    #[test]
    fn proxy_snapshot_rejects_unknown_protocol_when_restoring_application_proxy() {
        let mut snapshot = proxy_snapshot();
        snapshot.proto = "future-proto".into();
        assert!(snapshot.into_proxy().is_err());
    }

    #[test]
    fn proxy_snapshot_restores_each_supported_protocol() {
        for proto in ["vmess", "trojan", "shadowsocks", "hysteria", "hysteria2"] {
            let mut snapshot = proxy_snapshot();
            snapshot.proto = proto.into();

            let restored = snapshot.into_proxy().unwrap();

            assert_eq!(restored.proto, proto);
            assert_eq!(restored.host, "edge.example");
            assert_eq!(restored.port, 443);
        }
    }

    #[test]
    fn unknown_stage_is_rejected_as_malformed_data() {
        let dir = TestDir::new();
        std::fs::write(
            dir.file(),
            br#"{"schema_version":1,"stage":"future_stage","raw_links":[],"processed_links":[],"proxies":[],"final_links":[]}"#,
        )
        .unwrap();
        assert!(Checkpoint::load(dir.file()).is_err());
    }

    #[test]
    fn every_pipeline_stage_serializes_to_its_stable_snake_case_name() {
        let stages = [
            (PipelineStage::Fetched, "fetched"),
            (PipelineStage::Parsed, "parsed"),
            (PipelineStage::GeoIp, "geo_ip"),
            (PipelineStage::TcpPing, "tcp_ping"),
            (PipelineStage::Speed, "speed"),
            (PipelineStage::Complete, "complete"),
        ];

        for (stage, expected) in stages {
            let encoded = serde_json::to_string(&stage).unwrap();
            assert_eq!(encoded, format!("\"{expected}\""));
            assert_eq!(
                serde_json::from_str::<PipelineStage>(&encoded).unwrap(),
                stage
            );
        }
    }

    #[test]
    fn load_rejects_a_required_field_with_the_wrong_json_type() {
        let dir = TestDir::new();
        std::fs::write(
            dir.file(),
            br#"{"schema_version":"3","stage":"fetched","raw_links":[],"processed_links":[],"proxies":[],"final_links":[]}"#,
        )
        .unwrap();

        let error = Checkpoint::load(dir.file()).unwrap_err();

        assert!(error.to_string().contains("corrupt or malformed"));
    }

    #[test]
    fn save_reports_write_failure_and_cleans_up_when_destination_is_a_directory() {
        let dir = TestDir::new();
        let destination = dir.0.join("checkpoint.json");
        std::fs::create_dir(&destination).unwrap();

        let error = Checkpoint::new().save(&destination).unwrap_err();

        assert!(error.to_string().contains("atomically write checkpoint"));
        assert!(destination.is_dir());
        assert_eq!(dir.directory_entries(), vec![destination]);
    }
}
