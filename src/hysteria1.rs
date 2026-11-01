//! Runtime management and speed checking for the upstream Hysteria v1 client.
//!
//! The binary and checksums are pinned to upstream Hysteria v1.3.5. Hysteria v1
//! is not interchangeable with Hysteria v2, so this module accepts only v1
//! proxy settings (`proto == "hysteria"`).

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::process::{Child, Command};
use tokio::time::sleep;

const VERSION: &str = "v1.3.5";
const DOWNLOAD_BASE: &str = "https://github.com/HyNetworks/hysteria/releases/download/v1.3.5";
const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target {
    DarwinAmd64,
    DarwinArm64,
    LinuxAmd64,
    LinuxArm64,
    WindowsAmd64,
    WindowsArm64,
}

impl Target {
    fn asset(self) -> &'static str {
        match self {
            Self::DarwinAmd64 => "hysteria-darwin-amd64",
            Self::DarwinArm64 => "hysteria-darwin-arm64",
            Self::LinuxAmd64 => "hysteria-linux-amd64",
            Self::LinuxArm64 => "hysteria-linux-arm64",
            Self::WindowsAmd64 => "hysteria-windows-amd64.exe",
            Self::WindowsArm64 => "hysteria-windows-arm64.exe",
        }
    }

    fn checksum(self) -> &'static str {
        match self {
            Self::DarwinAmd64 => "c884053a703b79c3783310911c0298678085919bd06ea3c96dbb32199c3ea2fc",
            Self::DarwinArm64 => "ccb705e4171eaf243c163a32d408080f4d4df7293670a8ed1ddce34002057e0c",
            Self::LinuxAmd64 => "41dc8bc3fff6fc1f031666eb294f10b481b80b66229d7c6aca88398d0fba839d",
            Self::LinuxArm64 => "702cd2f3f7bb1d00d463ece4547b6a80de85aa4f6fa8fd1dc7ebd87eb0e2c7b9",
            Self::WindowsAmd64 => {
                "1001bd4a83f6addac166bfdfc3e777f3b751bb397e11b5d8f1d6ec1c2dd44023"
            }
            Self::WindowsArm64 => {
                "1e56301247dd2cc23aa7fae88ca23f5322b7789a84d1cfb0eb1190d2fea1147c"
            }
        }
    }
}

fn target_for(os: &str, arch: &str) -> Option<Target> {
    match (os, arch) {
        ("macos", "x86_64") => Some(Target::DarwinAmd64),
        ("macos", "aarch64") => Some(Target::DarwinArm64),
        ("linux", "x86_64") => Some(Target::LinuxAmd64),
        ("linux", "aarch64") => Some(Target::LinuxArm64),
        ("windows", "x86_64") => Some(Target::WindowsAmd64),
        ("windows", "aarch64") => Some(Target::WindowsArm64),
        _ => None,
    }
}

fn current_target() -> Result<Target> {
    current_target_for(std::env::consts::OS, std::env::consts::ARCH)
}

fn current_target_for(os: &str, arch: &str) -> Result<Target> {
    target_for(os, arch).ok_or_else(|| {
        anyhow!(
            "Hysteria {VERSION} has no pinned binary for {}/{}",
            os,
            arch
        )
    })
}

/// Executable filename used for Hysteria v1 on the current operating system.
pub fn core_bin_name() -> &'static str {
    if cfg!(windows) {
        "hysteria.exe"
    } else {
        "hysteria"
    }
}

/// Places the Hysteria executable beside the application executable.
pub fn default_core_path_next_to(executable: &Path) -> PathBuf {
    executable
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(core_bin_name())
}

/// Makes sure a checksum-verified upstream Hysteria v1.3.5 binary is available.
pub async fn ensure_core(path: &Path, no_download: bool) -> Result<()> {
    let target = current_target()?;
    if is_verified_core(path, target) {
        return Ok(());
    }
    if no_download {
        bail!(
            "Hysteria core is missing or not executable at {}; downloads are disabled",
            path.display()
        );
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("creating Hysteria core directory {}", parent.display()))?;

    let url = format!("{DOWNLOAD_BASE}/{}", target.asset());
    download_and_install_core(path, &url, target.checksum(), target.asset()).await
}

async fn download_and_install_core(
    path: &Path,
    url: &str,
    expected_checksum: &str,
    asset: &str,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("proxy-rs Hysteria runtime")
        .build()
        .context("creating HTTP client for Hysteria download")?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("downloading Hysteria core from {url}"))?
        .error_for_status()
        .context("upstream Hysteria download returned an error status")?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_BINARY_BYTES as u64)
    {
        bail!("Hysteria binary exceeds the {MAX_BINARY_BYTES}-byte download limit");
    }
    let mut bytes = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.context("reading Hysteria binary")? {
        append_download_chunk(&mut bytes, &chunk, MAX_BINARY_BYTES)?;
    }
    if bytes.is_empty() {
        bail!("Hysteria binary size is invalid ({} bytes)", bytes.len());
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if digest != expected_checksum {
        bail!(
            "Hysteria {VERSION} checksum mismatch for {}: expected {}, got {}",
            asset,
            expected_checksum,
            digest
        );
    }

    let temp_path = unique_sibling_path(path, "download");
    let write_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await
            .with_context(|| format!("creating temporary core {}", temp_path.display()))?;
        use tokio::io::AsyncWriteExt;
        file.write_all(&bytes)
            .await
            .context("writing downloaded Hysteria core")?;
        file.flush().await.context("flushing Hysteria core")?;
        drop(file);
        set_executable_permissions(&temp_path).await?;
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            tokio::fs::remove_file(path)
                .await
                .with_context(|| format!("replacing invalid Hysteria core {}", path.display()))?;
        }
        tokio::fs::rename(&temp_path, path)
            .await
            .with_context(|| format!("installing Hysteria core at {}", path.display()))?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if write_result.is_err() {
        let _ = tokio::fs::remove_file(&temp_path).await;
    }
    write_result?;
    Ok(())
}

fn append_download_chunk(bytes: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<()> {
    if bytes.len().saturating_add(chunk.len()) > limit {
        bail!("Hysteria binary exceeds the {limit}-byte download limit");
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

/// Runs Hysteria v1 through a local SOCKS5 listener and returns measured KB/s.
/// Any invalid settings, startup failure, or measurement failure maps to 0.0.
#[allow(dead_code)] // Compatibility wrapper retained for existing callers.
pub async fn check_proxy(
    core: &Path,
    workdir: &Path,
    proxy: &crate::parse::Proxy,
    local_port: u16,
    opts: &crate::xray::SpeedOpts,
) -> f64 {
    check_proxy_diagnostic(core, workdir, proxy, local_port, opts, false)
        .await
        .map(|outcome| outcome.measurement.median_kbs)
        .unwrap_or(0.0)
}

/// Same lifecycle as [`check_proxy`], retaining every configured speed probe.
pub async fn check_proxy_with_probes(
    core: &Path,
    workdir: &Path,
    proxy: &crate::parse::Proxy,
    local_port: u16,
    opts: &crate::xray::SpeedOpts,
) -> Result<CheckOutcome> {
    check_proxy_diagnostic(core, workdir, proxy, local_port, opts, true).await
}

/// Runtime stages and speed results from a Hysteria v1 client check.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CheckOutcome {
    pub core_started: bool,
    pub socks_ready: bool,
    pub measurement: crate::speed::MeasurementSummary,
    pub probes: Vec<crate::speed::ProbeResult>,
}

/// Runs a Hysteria v1 client and preserves process/readiness stages for diagnostics.
pub(crate) async fn check_proxy_diagnostic(
    core: &Path,
    workdir: &Path,
    proxy: &crate::parse::Proxy,
    local_port: u16,
    opts: &crate::xray::SpeedOpts,
    detailed: bool,
) -> Result<CheckOutcome> {
    let config = build_client_config(proxy, local_port)?;
    tokio::fs::create_dir_all(workdir)
        .await
        .with_context(|| format!("creating Hysteria work directory {}", workdir.display()))?;
    let config_path = unique_config_path(workdir)?;
    let _cleanup = RemoveFileOnDrop(config_path.clone());
    let config_text = serde_json::to_vec_pretty(&config).context("serializing Hysteria config")?;
    let mut config_options = tokio::fs::OpenOptions::new();
    config_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        config_options.mode(0o600);
    }
    let mut config_file = config_options
        .open(&config_path)
        .await
        .with_context(|| format!("creating Hysteria config {}", config_path.display()))?;
    use tokio::io::AsyncWriteExt;
    config_file
        .write_all(&config_text)
        .await
        .context("writing Hysteria config")?;
    config_file
        .flush()
        .await
        .context("flushing Hysteria config")?;
    drop(config_file);

    let mut child = Command::new(core)
        .arg("-c")
        .arg(&config_path)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("starting Hysteria client {}", core.display()))?;

    let ready = wait_for_socks(&mut child, local_port, opts.connect_timeout_s).await;
    let (measurement, probes) = if ready && detailed {
        let probes = crate::speed::measure_detailed_probes(
            local_port,
            opts.primary.as_deref(),
            opts.connect_timeout_s,
            opts.timeout_s,
            opts.max_mb,
            opts.speed_probes,
        )
        .await;
        (crate::speed::summarize_probe_results(&probes), probes)
    } else if ready {
        let speed = crate::speed::measure(
            local_port,
            opts.primary.as_deref(),
            opts.connect_timeout_s,
            opts.timeout_s,
            opts.max_mb,
        )
        .await;
        (
            crate::speed::MeasurementSummary {
                median_kbs: speed,
                successful_probes: usize::from(speed > 0.0),
                min_kbs: (speed > 0.0).then_some(speed),
                max_kbs: (speed > 0.0).then_some(speed),
            },
            Vec::new(),
        )
    } else {
        (crate::speed::MeasurementSummary::default(), Vec::new())
    };
    stop_child(&mut child).await;
    Ok(CheckOutcome {
        core_started: true,
        socks_ready: ready,
        measurement,
        probes,
    })
}

async fn wait_for_socks(child: &mut Child, port: u16, timeout_s: f64) -> bool {
    let bounded_timeout = if timeout_s.is_finite() {
        timeout_s.clamp(0.1, 60.0)
    } else {
        1.0
    };
    let timeout = Duration::from_secs_f64(bounded_timeout);
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return false,
            Ok(None) => {}
        }
        if socks5_handshake(port).await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(40)).await;
    }
}

async fn socks5_handshake(port: u16) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_millis(200), async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        stream.write_all(&[5, 1, 0]).await.ok()?;
        let mut response = [0; 2];
        stream.read_exact(&mut response).await.ok()?;
        Some(response == [5, 0])
    })
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

async fn stop_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.start_kill();
    }
    let _ = child.wait().await;
}

fn build_client_config(proxy: &crate::parse::Proxy, local_port: u16) -> Result<Value> {
    if proxy.proto != "hysteria" {
        bail!("expected Hysteria v1 proxy, got {}", proxy.proto);
    }
    let settings = proxy
        .settings
        .as_object()
        .ok_or_else(|| anyhow!("Hysteria settings must be a JSON object"))?;
    let host = settings
        .get("address")
        .and_then(Value::as_str)
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| anyhow!("Hysteria settings have no server address"))?;
    let port = settings
        .get("port")
        .and_then(Value::as_u64)
        .filter(|port| (1..=u16::MAX as u64).contains(port))
        .ok_or_else(|| anyhow!("Hysteria settings have an invalid server port"))?;
    if local_port == 0 {
        bail!("Hysteria local SOCKS port must be nonzero");
    }

    let server = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let protocol = optional_string(settings, "protocol")?.unwrap_or("udp");
    if !matches!(protocol, "udp" | "wechat-video" | "faketcp") {
        bail!("unsupported Hysteria v1 protocol {protocol:?}");
    }
    let auth = optional_string(settings, "auth")?.unwrap_or("");
    let up_mbps = positive_u64(settings, "upmbps")?;
    let down_mbps = positive_u64(settings, "downmbps")?;
    let insecure = match settings.get("insecure") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| anyhow!("Hysteria insecure setting must be boolean"))?,
        None => false,
    };

    let mut config = Map::new();
    config.insert("server".into(), json!(server));
    config.insert("protocol".into(), json!(protocol));
    config.insert("auth_str".into(), json!(auth));
    config.insert("up_mbps".into(), json!(up_mbps));
    config.insert("down_mbps".into(), json!(down_mbps));
    config.insert(
        "socks5".into(),
        json!({"listen": format!("127.0.0.1:{local_port}")}),
    );
    if settings.get("obfs").and_then(Value::as_str) == Some("xplus") {
        if let Some(password) = settings
            .get("obfsParam")
            .or_else(|| settings.get("obfs-param"))
            .or_else(|| settings.get("obfs-password"))
            .and_then(Value::as_str)
        {
            if !password.is_empty() {
                config.insert("obfs".into(), json!(password));
            }
        }
    }
    if let Some(server_name) = optional_string(settings, "peer")? {
        if !server_name.is_empty() {
            config.insert("server_name".into(), json!(server_name));
        }
    }
    config.insert("insecure".into(), json!(insecure));
    if let Some(alpn) = optional_string(settings, "alpn")? {
        if !alpn.is_empty() {
            config.insert("alpn".into(), json!(alpn));
        }
    }
    Ok(Value::Object(config))
}

fn optional_string<'a>(settings: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
    settings
        .get(key)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| anyhow!("Hysteria setting {key:?} must be a string"))
        })
        .transpose()
}

fn positive_u64(settings: &Map<String, Value>, key: &str) -> Result<u64> {
    settings
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| anyhow!("Hysteria setting {key:?} must be a positive integer"))
}

fn unique_config_path(workdir: &Path) -> Result<PathBuf> {
    for _ in 0..16 {
        let path = unique_sibling_path(workdir.join("hysteria-client.json").as_path(), "config");
        if !path.exists() {
            return Ok(path);
        }
    }
    bail!("could not allocate a unique Hysteria config path")
}

fn unique_sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(
        ".{name}.{}.{}.{}.{}",
        std::process::id(),
        stamp,
        sequence,
        suffix
    ))
}

struct RemoveFileOnDrop(PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(windows)]
    {
        path.extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        true
    }
}

fn is_verified_core(path: &Path, target: Target) -> bool {
    is_verified_core_with_checksum(path, target.checksum())
}

fn is_verified_core_with_checksum(path: &Path, expected_checksum: &str) -> bool {
    if !is_executable_file(path) {
        return false;
    }
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if metadata.len() == 0 || metadata.len() > MAX_BINARY_BYTES as u64 {
        return false;
    }
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
            Err(_) => return false,
        }
    }
    format!("{:x}", hasher.finalize()) == expected_checksum
}

async fn set_executable_permissions(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o755))
            .await
            .context("setting Hysteria executable permissions")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Proxy;
    use serde_json::json;
    use std::fs;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "proxy-rs-hysteria1-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn serve_http(response: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).await;
            stream.write_all(&response).await.unwrap();
        });
        (format!("http://{address}/core"), task)
    }

    fn proxy(settings: Value) -> Proxy {
        Proxy {
            proto: "hysteria",
            host: "hy.example".into(),
            port: 443,
            name: "test".into(),
            base_url: String::new(),
            orig_url: String::new(),
            settings,
            stream: None,
            country: String::new(),
            display: String::new(),
            ping: None,
            speed_kbs: 0.0,
        }
    }

    fn valid_settings() -> Value {
        json!({
            "address": "hy.example", "port": 443, "auth": "auth \"quoted\" \\ value",
            "protocol": "wechat-video", "upmbps": 100, "downmbps": 250,
            "obfs": "xplus", "obfsParam": "obfs-secret", "peer": "sni.example",
            "insecure": true, "alpn": "h3"
        })
    }

    #[test]
    fn target_mappings_and_pinned_checksums_cover_all_six_requested_targets() {
        let cases = [
            (
                "macos",
                "x86_64",
                "hysteria-darwin-amd64",
                "c884053a703b79c3783310911c0298678085919bd06ea3c96dbb32199c3ea2fc",
            ),
            (
                "macos",
                "aarch64",
                "hysteria-darwin-arm64",
                "ccb705e4171eaf243c163a32d408080f4d4df7293670a8ed1ddce34002057e0c",
            ),
            (
                "linux",
                "x86_64",
                "hysteria-linux-amd64",
                "41dc8bc3fff6fc1f031666eb294f10b481b80b66229d7c6aca88398d0fba839d",
            ),
            (
                "linux",
                "aarch64",
                "hysteria-linux-arm64",
                "702cd2f3f7bb1d00d463ece4547b6a80de85aa4f6fa8fd1dc7ebd87eb0e2c7b9",
            ),
            (
                "windows",
                "x86_64",
                "hysteria-windows-amd64.exe",
                "1001bd4a83f6addac166bfdfc3e777f3b751bb397e11b5d8f1d6ec1c2dd44023",
            ),
            (
                "windows",
                "aarch64",
                "hysteria-windows-arm64.exe",
                "1e56301247dd2cc23aa7fae88ca23f5322b7789a84d1cfb0eb1190d2fea1147c",
            ),
        ];
        for (os, arch, asset, checksum) in cases {
            let target = target_for(os, arch).unwrap();
            assert_eq!(target.asset(), asset);
            assert_eq!(target.checksum(), checksum);
            assert_eq!(target.checksum().len(), 64);
            assert!(target
                .checksum()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()));
        }
        assert_eq!(target_for("linux", "x86"), None);
        assert_eq!(target_for("freebsd", "x86_64"), None);
        let error = current_target_for("freebsd", "x86_64").unwrap_err();
        assert!(error
            .to_string()
            .contains("no pinned binary for freebsd/x86_64"));
    }

    #[test]
    fn download_chunk_limit_accepts_the_boundary_and_rejects_overflow_before_append() {
        let mut bytes = b"ab".to_vec();
        append_download_chunk(&mut bytes, b"cde", 5).unwrap();
        assert_eq!(bytes, b"abcde");

        let error = append_download_chunk(&mut bytes, b"f", 5).unwrap_err();
        assert!(error
            .to_string()
            .contains("exceeds the 5-byte download limit"));
        assert_eq!(bytes, b"abcde");
    }

    #[test]
    fn binary_path_is_next_to_application_and_uses_platform_filename() {
        let app = Path::new("/opt/proxy-rs/bin/proxy-rs");
        let path = default_core_path_next_to(app);
        assert_eq!(path.parent(), app.parent());
        assert_eq!(path.file_name().unwrap(), core_bin_name());
    }

    #[test]
    fn config_maps_v1_settings_and_json_escapes_secrets() {
        let config = build_client_config(&proxy(valid_settings()), 10808).unwrap();
        assert_eq!(config["server"], "hy.example:443");
        assert_eq!(config["protocol"], "wechat-video");
        assert_eq!(config["auth_str"], "auth \"quoted\" \\ value");
        assert_eq!(config["up_mbps"], 100);
        assert_eq!(config["down_mbps"], 250);
        assert_eq!(config["obfs"], "obfs-secret");
        assert_eq!(config["server_name"], "sni.example");
        assert_eq!(config["insecure"], true);
        assert_eq!(config["alpn"], "h3");
        assert_eq!(config["socks5"]["listen"], "127.0.0.1:10808");
        let encoded = serde_json::to_string(&config).unwrap();
        assert!(serde_json::from_str::<Value>(&encoded).is_ok());
    }

    #[test]
    fn config_brackets_ipv6_and_omits_obfs_without_xplus_mode() {
        let mut settings = valid_settings();
        settings["address"] = json!("2001:db8::1");
        settings["obfs"] = json!("");
        let config = build_client_config(&proxy(settings), 1080).unwrap();
        assert_eq!(config["server"], "[2001:db8::1]:443");
        assert!(config.get("obfs").is_none());
    }

    #[test]
    fn config_uses_v1_defaults_and_accepts_legacy_obfs_parameter_aliases() {
        let mut settings = valid_settings();
        settings["protocol"] = json!("udp");
        settings["auth"] = json!("");
        settings["insecure"] = json!(false);
        settings.as_object_mut().unwrap().remove("peer");
        settings.as_object_mut().unwrap().remove("alpn");
        settings.as_object_mut().unwrap().remove("obfsParam");
        settings["obfs-param"] = json!("legacy-secret");

        let config = build_client_config(&proxy(settings), 10808).unwrap();

        assert_eq!(config["protocol"], "udp");
        assert_eq!(config["auth_str"], "");
        assert_eq!(config["insecure"], false);
        assert_eq!(config["obfs"], "legacy-secret");
        assert!(config.get("server_name").is_none());
        assert!(config.get("alpn").is_none());

        let mut settings = valid_settings();
        settings.as_object_mut().unwrap().remove("obfsParam");
        settings["obfs-password"] = json!("alternate-secret");
        let config = build_client_config(&proxy(settings), 10808).unwrap();
        assert_eq!(config["obfs"], "alternate-secret");
    }

    #[test]
    fn config_applies_missing_option_defaults_and_omits_empty_optional_values() {
        let settings = json!({
            "address":"host", "port":443, "upmbps":1, "downmbps":1,
            "obfs":"xplus", "obfsParam":"", "peer":"", "alpn":""
        });

        let config = build_client_config(&proxy(settings), 1080).unwrap();

        assert_eq!(config["protocol"], "udp");
        assert_eq!(config["auth_str"], "");
        assert_eq!(config["insecure"], false);
        assert!(config.get("obfs").is_none());
        assert!(config.get("server_name").is_none());
        assert!(config.get("alpn").is_none());
    }

    #[test]
    fn config_rejects_blank_address_and_out_of_range_or_non_integer_ports() {
        for (address, port) in [
            ("  ", json!(443)),
            ("host", json!(u16::MAX as u64 + 1)),
            ("host", json!(443.5)),
        ] {
            let settings = json!({
                "address":address, "port":port, "upmbps":1, "downmbps":1
            });
            assert!(build_client_config(&proxy(settings), 1080).is_err());
        }
    }

    #[test]
    fn malformed_or_incompatible_settings_are_rejected() {
        for settings in [
            json!([]),
            json!({"port":443,"upmbps":1,"downmbps":1}),
            json!({"address":"host","port":0,"upmbps":1,"downmbps":1}),
            json!({"address":"host","port":443,"upmbps":0,"downmbps":1}),
            json!({"address":"host","port":443,"upmbps":1,"downmbps":1,"insecure":"yes"}),
            json!({"address":"host","port":443,"upmbps":1,"downmbps":1,"protocol":"quic"}),
        ] {
            assert!(build_client_config(&proxy(settings), 1080).is_err());
        }
        let mut not_hysteria = proxy(valid_settings());
        not_hysteria.proto = "hysteria2";
        assert!(build_client_config(&not_hysteria, 1080).is_err());
        assert!(build_client_config(&proxy(valid_settings()), 0).is_err());
    }

    #[test]
    fn config_rejects_missing_rates_and_non_string_optional_fields() {
        for settings in [
            json!({"address":"host","port":443,"downmbps":1}),
            json!({"address":"host","port":443,"upmbps":1}),
            json!({"address":"host","port":443,"upmbps":1,"downmbps":1,"auth":7}),
            json!({"address":"host","port":443,"upmbps":1,"downmbps":1,"peer":false}),
            json!({"address":"host","port":443,"upmbps":1,"downmbps":1,"alpn":[]}),
        ] {
            assert!(build_client_config(&proxy(settings), 1080).is_err());
        }
    }

    #[test]
    #[cfg(unix)]
    fn verified_core_check_rejects_corrupt_and_non_executable_fixtures() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestDir::new();
        let corrupt = temp.0.join("corrupt-core");
        fs::write(&corrupt, b"not the pinned Hysteria binary").unwrap();
        fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!is_verified_core(&corrupt, Target::DarwinArm64));

        let non_executable = temp.0.join("non-executable-core");
        fs::write(&non_executable, b"fixture").unwrap();
        assert!(!is_verified_core(&non_executable, Target::DarwinArm64));
        assert!(!is_verified_core(
            &temp.0.join("missing"),
            Target::DarwinArm64
        ));
    }

    #[cfg(unix)]
    #[test]
    fn verified_core_check_accepts_an_executable_with_the_expected_digest() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestDir::new();
        let path = temp.0.join("verified-core");
        let bytes = b"local verified Hysteria fixture";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let checksum = format!("{:x}", Sha256::digest(bytes));

        assert!(is_verified_core_with_checksum(&path, &checksum));
        assert!(!is_verified_core_with_checksum(&path, "wrong digest"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_proxy_measures_after_a_local_socks_listener_becomes_ready() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let temp = TestDir::new();
        let fake_core = temp.0.join("fake-hysteria");
        fs::write(&fake_core, "#!/bin/sh\nsleep 30\n").unwrap();
        fs::set_permissions(&fake_core, fs::Permissions::from_mode(0o755)).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let socks_fixture = tokio::spawn(async move {
            let (mut readiness, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            readiness.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            readiness.write_all(&[5, 0]).await.unwrap();
            drop(readiness);

            // The measurement client reaches the same local fixture and is
            // closed immediately, so no external proxy or download is used.
            let (measurement, _) = listener.accept().await.unwrap();
            drop(measurement);
        });
        let workdir = temp.0.join("work");
        let opts = crate::xray::SpeedOpts {
            primary: Some("http://127.0.0.1:9/no-network".into()),
            connect_timeout_s: 0.1,
            timeout_s: 0.1,
            max_mb: 0.5,
            min_kb: 0.0,
            speed_probes: 1,
        };

        let outcome = check_proxy_diagnostic(
            &fake_core,
            &workdir,
            &proxy(valid_settings()),
            port,
            &opts,
            true,
        )
        .await
        .unwrap();

        socks_fixture.await.unwrap();
        assert!(outcome.core_started);
        assert!(outcome.socks_ready);
        assert_eq!(outcome.measurement.successful_probes, 0);
        assert_eq!(fs::read_dir(workdir).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_core_exit_returns_zero_and_removes_its_unique_config() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TestDir::new();
        let fake_core = temp.0.join("fake-hysteria");
        fs::write(&fake_core, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&fake_core, fs::Permissions::from_mode(0o755)).unwrap();
        let workdir = temp.0.join("work");
        let port_reservation = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = port_reservation.local_addr().unwrap().port();
        drop(port_reservation);
        let proxy = proxy(valid_settings());
        let opts = crate::xray::SpeedOpts {
            primary: Some("http://127.0.0.1:9/no-network".into()),
            connect_timeout_s: 0.5,
            timeout_s: 0.1,
            max_mb: 0.5,
            min_kb: 0.0,
            speed_probes: 1,
        };

        let speed = check_proxy(&fake_core, &workdir, &proxy, port, &opts).await;

        assert_eq!(speed, 0.0);
        assert_eq!(fs::read_dir(workdir).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socks_readiness_requires_a_valid_socks5_greeting() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
        });
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();

        assert!(socks5_handshake(port).await);

        server.await.unwrap();
        stop_child(&mut child).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socks_readiness_rejects_wrong_greeting_and_a_closed_port() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 2]).await.unwrap();
        });
        assert!(!socks5_handshake(port).await);
        server.await.unwrap();

        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(!socks5_handshake(closed_port).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_proxy_timeout_kills_fake_core_and_removes_config() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestDir::new();
        let core = temp.0.join("hysteria-never-listens");
        let pid_file = temp.0.join("child.pid");
        fs::write(
            &core,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nwhile :; do :; done\n",
                pid_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&core, fs::Permissions::from_mode(0o755)).unwrap();
        let workdir = temp.0.join("work");
        let reservation = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let opts = crate::xray::SpeedOpts {
            primary: Some("http://127.0.0.1:9/no-network".into()),
            connect_timeout_s: 0.5,
            timeout_s: 0.1,
            max_mb: 0.5,
            min_kb: 0.0,
            speed_probes: 1,
        };

        let speed = check_proxy(&core, &workdir, &proxy(valid_settings()), port, &opts).await;

        assert_eq!(speed, 0.0);
        assert_eq!(fs::read_dir(&workdir).unwrap().count(), 0);
        let pid: u32 = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", "kill -0 \"$1\" 2>/dev/null", "sh", &pid.to_string()])
            .output()
            .unwrap();
        assert!(
            !status.status.success(),
            "timed-out fake Hysteria child must be stopped"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_proxy_cleans_config_when_fake_process_cannot_start() {
        let temp = TestDir::new();
        let workdir = temp.0.join("work");
        let unused_port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = unused_port.local_addr().unwrap().port();
        drop(unused_port);
        let speed = check_proxy(
            &temp.0.join("missing-fake-core"),
            &workdir,
            &proxy(valid_settings()),
            port,
            &crate::xray::SpeedOpts {
                primary: None,
                connect_timeout_s: 0.1,
                timeout_s: 0.1,
                max_mb: 0.1,
                min_kb: 0.0,
                speed_probes: 1,
            },
        )
        .await;

        assert_eq!(speed, 0.0);
        assert_eq!(fs::read_dir(workdir).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn ensure_core_honors_no_download_without_creating_files() {
        let temp = TestDir::new();
        let missing = temp.0.join("hysteria");
        let error = ensure_core(&missing, true).await.unwrap_err();
        assert!(error.to_string().contains("downloads are disabled"));
        assert!(!missing.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_download_verifies_and_installs_core_replacing_invalid_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestDir::new();
        let path = temp.0.join("nested/hysteria");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"invalid existing core").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        let bytes = b"deterministic fake Hysteria executable".to_vec();
        let checksum = format!("{:x}", Sha256::digest(&bytes));
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        )
        .into_bytes();
        response.extend_from_slice(&bytes);
        let (url, server) = serve_http(response).await;

        download_and_install_core(&path, &url, &checksum, "fixture-core")
            .await
            .unwrap();

        server.await.unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(is_executable_file(&path));
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_download_removes_temporary_file_when_existing_target_cannot_be_replaced() {
        let temp = TestDir::new();
        let target = temp.0.join("hysteria");
        fs::create_dir(&target).unwrap();
        let bytes = b"valid local download";
        let checksum = format!("{:x}", Sha256::digest(bytes));
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        )
        .into_bytes();
        response.extend_from_slice(bytes);
        let (url, server) = serve_http(response).await;

        let error = download_and_install_core(&target, &url, &checksum, "fixture-core")
            .await
            .unwrap_err();

        server.await.unwrap();
        assert!(error
            .to_string()
            .contains("replacing invalid Hysteria core"));
        assert!(target.is_dir());
        assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn local_download_rejects_http_errors_checksum_mismatch_empty_and_oversized_body() {
        let temp = TestDir::new();
        let cases = [
            (
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string(),
                Vec::new(),
                "upstream Hysteria download returned an error status",
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
                    .to_string(),
                b"wrong".to_vec(),
                "checksum mismatch",
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string(),
                Vec::new(),
                "size is invalid",
            ),
            (
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MAX_BINARY_BYTES + 1
                ),
                Vec::new(),
                "exceeds the",
            ),
        ];

        for (index, (headers, body, expected_error)) in cases.into_iter().enumerate() {
            let path = temp.0.join(format!("failed-{index}/hysteria"));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut response = headers.into_bytes();
            response.extend_from_slice(&body);
            let (url, server) = serve_http(response).await;
            let error = download_and_install_core(&path, &url, "expected-checksum", "fixture-core")
                .await
                .unwrap_err();
            server.await.unwrap();

            assert!(error.to_string().contains(expected_error), "{error:#}");
            assert!(!path.exists());
            assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 0);
        }
    }
}
