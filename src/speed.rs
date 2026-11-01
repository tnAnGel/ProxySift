use crate::check::socks_client;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::Duration;
use std::time::Instant;

pub const DEFAULT_TARGETS: &[&str] = &[
    "https://speed.cloudflare.com/__down?bytes=10000000",
    "https://proof.ovh.net/files/100Mb.dat",
    "http://speedtest.tele2.net/100MB.zip",
    "https://speed.hetzner.de/100MB.bin",
    "https://mirror.leaseweb.com/speedtest/100mb.bin",
    "https://yandex.ru/internet/api/v0/measure/download?size=10000000",
];

fn remaining_time(start: Instant, timeout: Duration) -> Option<Duration> {
    let remaining = timeout.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        None
    } else {
        Some(remaining)
    }
}

async fn timeout_future<F: Future>(
    future: F,
    timeout: Duration,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(timeout, future).await
}

fn target_pool(primary: Option<&str>) -> Vec<String> {
    let mut pool = Vec::new();
    if let Some(url) = primary.filter(|url| !url.is_empty()) {
        pool.push(url.to_string());
    }
    let mut targets: Vec<String> = DEFAULT_TARGETS.iter().map(|url| url.to_string()).collect();
    if primary.is_none() {
        let mut rng = rand::thread_rng();
        targets.shuffle(&mut rng);
    }
    pool.extend(targets);
    pool
}

fn detailed_target_pool(primary: Option<&str>, limit: usize) -> Vec<String> {
    let mut pool = Vec::with_capacity(limit.min(DEFAULT_TARGETS.len() + 1));
    if let Some(url) = primary.filter(|url| !url.is_empty()) {
        pool.push(url.to_string());
    }
    for target in DEFAULT_TARGETS {
        if pool.len() >= limit {
            break;
        }
        if !pool.iter().any(|existing| existing == target) {
            pool.push((*target).to_string());
        }
    }
    pool.truncate(limit);
    pool
}

fn positive_speed(total: u64, secs: f64) -> Option<f64> {
    if !secs.is_finite() || secs <= 0.0 {
        return None;
    }
    let kbs = (total as f64 / 1024.0) / secs;
    if !kbs.is_finite() || kbs <= 0.0 {
        None
    } else {
        Some(kbs)
    }
}

async fn try_download(
    client: &reqwest::Client,
    url: &str,
    _connect_timeout: Duration,
    timeout: Duration,
    max_bytes: u64,
) -> Option<(u64, f64)> {
    try_download_at(
        client,
        url,
        timeout,
        max_bytes,
        Instant::now(),
        Some(timeout),
    )
    .await
}

async fn try_download_at(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    max_bytes: u64,
    start: Instant,
    request_timeout: Option<Duration>,
) -> Option<(u64, f64)> {
    let mut request = client.get(url);
    if let Some(request_timeout) = request_timeout {
        request = request.timeout(request_timeout);
    }
    let resp = request.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let mut resp = resp;
    let mut total: u64 = 0;
    loop {
        if total >= max_bytes {
            break;
        }
        let Some(remaining) = remaining_time(start, timeout) else {
            break;
        };
        match timeout_future(resp.chunk(), remaining).await {
            Ok(Ok(Some(chunk))) => {
                let remaining_bytes = max_bytes.saturating_sub(total);
                total += (chunk.len() as u64).min(remaining_bytes);
            }
            Ok(Ok(None)) => break,
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    if total == 0 {
        return None;
    }
    let secs = start.elapsed().as_secs_f64().max(0.1);
    Some((total, secs))
}

/// Замер скорости через socks. Возвращает KB/s (0.0 = мусор/недоступно).
pub async fn measure(
    port: u16,
    primary: Option<&str>,
    conn_timeout_s: f64,
    timeout_s: f64,
    max_mb: f64,
) -> f64 {
    let conn_timeout = Duration::from_secs_f64(conn_timeout_s.max(1.0));
    let timeout = Duration::from_secs_f64(timeout_s.max(1.0));
    let max_bytes = ((max_mb.max(0.5)) * 1024.0 * 1024.0) as u64;
    measure_with_client(
        socks_client(port, conn_timeout),
        primary,
        conn_timeout,
        timeout,
        max_bytes,
    )
    .await
}

/// Summary of a multi-target speed measurement. Speeds are in KiB/s, matching
/// the existing [`measure`] API (bytes / 1024 / seconds).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MeasurementSummary {
    /// Median speed among successful probes, in KiB/s. Zero when none succeeded.
    pub median_kbs: f64,
    /// Number of targets that returned at least 1 KiB and a finite positive speed.
    pub successful_probes: usize,
    /// Lowest successful probe speed in KiB/s; `None` when there were no successes.
    pub min_kbs: Option<f64>,
    /// Highest successful probe speed in KiB/s; `None` when there were no successes.
    pub max_kbs: Option<f64>,
}

/// Outcome of one speed-test target. Failure details deliberately contain no
/// response body, request headers, or error text that could expose credentials.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// URL tested for this probe.
    pub target_url: String,
    /// Whether the response passed the minimum-size and speed checks.
    pub status: ProbeStatus,
    /// Number of response bytes consumed, capped by the configured limit.
    pub transferred_bytes: u64,
    /// Wall-clock duration of this probe in seconds.
    pub elapsed_seconds: f64,
    /// Measured speed in KiB/s; present only for successful probes.
    pub speed_kbs: Option<f64>,
    /// Safe, structured failure classification; absent on success.
    pub failure_reason: Option<ProbeFailure>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Success,
    Failure,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeFailure {
    HttpStatus { status: u16 },
    Timeout,
    Request,
    Body,
    TooSmall,
    InvalidSpeed,
}

/// Measures a proxy against up to `target_count` distinct targets in a stable
/// order. A non-empty `primary` URL is first, followed by built-in targets in
/// declaration order. Each target is probed at most once. Failed, empty, timed
/// out, and sub-1-KiB responses are excluded. Returns a zero median and empty
/// range if no probe succeeds. All reported speeds use KiB/s (bytes / 1024 / s).
pub async fn measure_detailed(
    port: u16,
    primary: Option<&str>,
    conn_timeout_s: f64,
    timeout_s: f64,
    max_mb: f64,
    target_count: usize,
) -> MeasurementSummary {
    let probes = measure_detailed_probes(
        port,
        primary,
        conn_timeout_s,
        timeout_s,
        max_mb,
        target_count,
    )
    .await;
    summarize_probe_results(&probes)
}

/// Calculate median/range statistics from retained per-target results.
pub fn summarize_probe_results(probes: &[ProbeResult]) -> MeasurementSummary {
    let mut speeds: Vec<f64> = probes
        .iter()
        .filter(|probe| probe.status == ProbeStatus::Success)
        .filter_map(|probe| probe.speed_kbs)
        .filter(|speed| speed.is_finite() && *speed > 0.0)
        .collect();
    if speeds.is_empty() {
        return MeasurementSummary::default();
    }
    speeds.sort_by(f64::total_cmp);
    let middle = speeds.len() / 2;
    let median_kbs = if speeds.len().is_multiple_of(2) {
        speeds[middle - 1] / 2.0 + speeds[middle] / 2.0
    } else {
        speeds[middle]
    };
    MeasurementSummary {
        median_kbs,
        successful_probes: speeds.len(),
        min_kbs: speeds.first().copied(),
        max_kbs: speeds.last().copied(),
    }
}

/// Measures each selected target and retains its individual outcome.
///
/// This returns one serializable [`ProbeResult`] per target, including failed
/// probes. Error details are intentionally classified rather than exposing
/// reqwest error strings or response bodies.
pub async fn measure_detailed_probes(
    port: u16,
    primary: Option<&str>,
    conn_timeout_s: f64,
    timeout_s: f64,
    max_mb: f64,
    target_count: usize,
) -> Vec<ProbeResult> {
    let conn_timeout = safe_duration(conn_timeout_s, 1.0);
    let timeout = safe_duration(timeout_s, 1.0);
    let max_bytes = ((max_mb.max(0.5)) * 1024.0 * 1024.0) as u64;
    let targets = detailed_target_pool(primary, target_count);
    let client = match socks_client(port, conn_timeout) {
        Ok(client) => client,
        Err(_) => {
            return targets
                .into_iter()
                .map(|target_url| ProbeResult::failure(target_url, 0, 0.0, ProbeFailure::Request))
                .collect();
        }
    };
    let mut results = Vec::with_capacity(targets.len());
    for target in targets {
        results.push(try_download_detailed(&client, target, timeout, max_bytes).await);
    }
    results
}

#[allow(dead_code)] // Constructors are reached by the detailed probe API.
impl ProbeResult {
    fn success(
        target_url: String,
        transferred_bytes: u64,
        elapsed_seconds: f64,
        speed_kbs: f64,
    ) -> Self {
        Self {
            target_url,
            status: ProbeStatus::Success,
            transferred_bytes,
            elapsed_seconds,
            speed_kbs: Some(speed_kbs),
            failure_reason: None,
        }
    }

    fn failure(
        target_url: String,
        transferred_bytes: u64,
        elapsed_seconds: f64,
        failure_reason: ProbeFailure,
    ) -> Self {
        Self {
            target_url,
            status: ProbeStatus::Failure,
            transferred_bytes,
            elapsed_seconds,
            speed_kbs: None,
            failure_reason: Some(failure_reason),
        }
    }
}

#[allow(dead_code)] // Called by measure_detailed_probes.
async fn try_download_detailed(
    client: &reqwest::Client,
    target_url: String,
    timeout: Duration,
    max_bytes: u64,
) -> ProbeResult {
    let start = Instant::now();
    let elapsed = |start: Instant| start.elapsed().as_secs_f64();
    let request = client.get(&target_url).timeout(timeout).send();
    let response = match timeout_future(request, timeout).await {
        Err(_) => {
            return ProbeResult::failure(target_url, 0, elapsed(start), ProbeFailure::Timeout);
        }
        Ok(Err(error)) if error.is_timeout() => {
            return ProbeResult::failure(target_url, 0, elapsed(start), ProbeFailure::Timeout);
        }
        Ok(Err(_)) => {
            return ProbeResult::failure(target_url, 0, elapsed(start), ProbeFailure::Request);
        }
        Ok(Ok(response)) => response,
    };
    if !response.status().is_success() {
        return ProbeResult::failure(
            target_url,
            0,
            elapsed(start),
            ProbeFailure::HttpStatus {
                status: response.status().as_u16(),
            },
        );
    }

    let mut response = response;
    let mut transferred_bytes = 0_u64;
    while transferred_bytes < max_bytes {
        let Some(remaining) = remaining_time(start, timeout) else {
            return ProbeResult::failure(
                target_url,
                transferred_bytes,
                elapsed(start),
                ProbeFailure::Timeout,
            );
        };
        match timeout_future(response.chunk(), remaining).await {
            Err(_) => {
                return ProbeResult::failure(
                    target_url,
                    transferred_bytes,
                    elapsed(start),
                    ProbeFailure::Timeout,
                );
            }
            Ok(Err(error)) if error.is_timeout() => {
                return ProbeResult::failure(
                    target_url,
                    transferred_bytes,
                    elapsed(start),
                    ProbeFailure::Timeout,
                );
            }
            Ok(Err(_)) => {
                return ProbeResult::failure(
                    target_url,
                    transferred_bytes,
                    elapsed(start),
                    ProbeFailure::Body,
                );
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(chunk))) => {
                let remaining_bytes = max_bytes.saturating_sub(transferred_bytes);
                transferred_bytes += (chunk.len() as u64).min(remaining_bytes);
            }
        }
    }

    let elapsed_seconds = elapsed(start);
    if transferred_bytes < 1024 {
        return ProbeResult::failure(
            target_url,
            transferred_bytes,
            elapsed_seconds,
            ProbeFailure::TooSmall,
        );
    }
    match positive_speed(transferred_bytes, elapsed_seconds) {
        Some(speed_kbs) => {
            ProbeResult::success(target_url, transferred_bytes, elapsed_seconds, speed_kbs)
        }
        None => ProbeResult::failure(
            target_url,
            transferred_bytes,
            elapsed_seconds,
            ProbeFailure::InvalidSpeed,
        ),
    }
}

#[allow(dead_code)] // Called from measure_detailed.
fn safe_duration(seconds: f64, minimum_seconds: f64) -> Duration {
    let seconds = if seconds.is_finite() {
        seconds.max(minimum_seconds)
    } else {
        minimum_seconds
    };
    // Bound huge but finite inputs too; Duration::from_secs_f64 panics when
    // the input rounds beyond its representable range.
    Duration::from_secs_f64(seconds.min(365.0 * 24.0 * 60.0 * 60.0))
}

#[allow(dead_code)] // Shared implementation for measure_detailed.
async fn measure_targets<F, Fut>(
    targets: Vec<String>,
    timeout: Duration,
    mut download: F,
) -> MeasurementSummary
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Option<(u64, f64)>>,
{
    let mut speeds = Vec::with_capacity(targets.len());
    for target in targets {
        let result = timeout_future(download(target), timeout).await;
        let Ok(Some((bytes, seconds))) = result else {
            continue;
        };
        if bytes < 1024 {
            continue;
        }
        if let Some(speed) = positive_speed(bytes, seconds) {
            speeds.push(speed);
        }
    }

    if speeds.is_empty() {
        return MeasurementSummary::default();
    }
    speeds.sort_by(f64::total_cmp);
    let middle = speeds.len() / 2;
    let median_kbs = if speeds.len() % 2 == 0 {
        speeds[middle - 1] / 2.0 + speeds[middle] / 2.0
    } else {
        speeds[middle]
    };
    MeasurementSummary {
        median_kbs,
        successful_probes: speeds.len(),
        min_kbs: speeds.first().copied(),
        max_kbs: speeds.last().copied(),
    }
}

async fn measure_with_client(
    client: anyhow::Result<reqwest::Client>,
    primary: Option<&str>,
    conn_timeout: Duration,
    timeout: Duration,
    max_bytes: u64,
) -> f64 {
    let client = match client {
        Ok(c) => c,
        Err(_) => return 0.0,
    };
    let pool = target_pool(primary);
    measure_pool(pool, |url| {
        let client = &client;
        async move { try_download(client, &url, conn_timeout, timeout, max_bytes).await }
    })
    .await
}

async fn measure_pool<F, Fut>(pool: Vec<String>, mut download: F) -> f64
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Option<(u64, f64)>>,
{
    for url in &pool {
        if let Some((total, secs)) = download(url.clone()).await {
            if total < 1024 {
                continue;
            }
            if let Some(kbs) = positive_speed(total, secs) {
                return kbs;
            }
        }
    }
    0.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn detailed_targets_keep_a_stable_order_and_deduplicate_primary() {
        let primary = DEFAULT_TARGETS[1];
        let targets = detailed_target_pool(Some(primary), 4);

        assert_eq!(targets[0], primary);
        assert_eq!(targets[1], DEFAULT_TARGETS[0]);
        assert_eq!(targets[2], DEFAULT_TARGETS[2]);
        assert_eq!(targets[3], DEFAULT_TARGETS[3]);
        assert_eq!(detailed_target_pool(None, 2), DEFAULT_TARGETS[..2]);
        assert!(detailed_target_pool(Some("primary"), 0).is_empty());
    }

    #[test]
    fn probe_result_serializes_success_and_safe_failure_details() {
        let success = ProbeResult::success("https://example.test/data".into(), 2048, 0.5, 4.0);
        let failure = ProbeResult::failure(
            "https://example.test/data".into(),
            0,
            0.1,
            ProbeFailure::HttpStatus { status: 503 },
        );
        let success_json = serde_json::to_value(&success).unwrap();
        let failure_json = serde_json::to_value(&failure).unwrap();

        assert_eq!(success_json["target_url"], "https://example.test/data");
        assert_eq!(success_json["status"], "success");
        assert_eq!(success_json["transferred_bytes"], 2048);
        assert_eq!(success_json["speed_kbs"], 4.0);
        assert!(success_json["failure_reason"].is_null());
        assert_eq!(failure_json["status"], "failure");
        assert_eq!(failure_json["failure_reason"]["kind"], "http_status");
        assert_eq!(failure_json["failure_reason"]["status"], 503);
        assert!(failure_json["speed_kbs"].is_null());
        assert!(!failure_json.to_string().contains("error text"));
    }

    #[tokio::test]
    async fn detailed_probe_classifies_http_status_and_small_body() {
        let (status_url, status_server) = serve_once(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )
        .await;
        let (small_url, small_server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntiny".to_vec(),
        )
        .await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let status = try_download_detailed(&client, status_url, Duration::from_secs(1), 4096).await;
        let small = try_download_detailed(&client, small_url, Duration::from_secs(1), 4096).await;
        status_server.await.unwrap();
        small_server.await.unwrap();

        assert_eq!(status.status, ProbeStatus::Failure);
        assert_eq!(
            status.failure_reason,
            Some(ProbeFailure::HttpStatus { status: 503 })
        );
        assert_eq!(small.failure_reason, Some(ProbeFailure::TooSmall));
        assert_eq!(small.transferred_bytes, 4);
        assert!(status.elapsed_seconds.is_finite());
        assert!(small.elapsed_seconds.is_finite());
    }

    #[tokio::test]
    async fn detailed_probe_records_successful_transfer_and_speed() {
        let body = vec![b'x'; 2048];
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut response = response.into_bytes();
        response.extend_from_slice(&body);
        let (url, server) = serve_once(response).await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let result =
            try_download_detailed(&client, url.clone(), Duration::from_secs(1), 4096).await;
        server.await.unwrap();

        assert_eq!(result.target_url, url);
        assert_eq!(result.status, ProbeStatus::Success);
        assert_eq!(result.transferred_bytes, 2048);
        assert!(result.elapsed_seconds > 0.0);
        assert!(result.speed_kbs.unwrap() > 0.0);
        assert_eq!(result.failure_reason, None);
    }

    #[tokio::test]
    async fn detailed_probe_classifies_timeout_body_and_request_failures() {
        let (timeout_url, timeout_server) =
            serve_slow_body(b"x", b"y", Duration::from_millis(100)).await;
        let (body_url, body_server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nshort".to_vec(),
        )
        .await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let timeout =
            try_download_detailed(&client, timeout_url, Duration::from_millis(20), 4096).await;
        let body = try_download_detailed(&client, body_url, Duration::from_secs(1), 4096).await;
        let request =
            try_download_detailed(&client, "invalid url".into(), Duration::from_secs(1), 4096)
                .await;
        timeout_server.await.unwrap();
        body_server.await.unwrap();

        assert_eq!(timeout.failure_reason, Some(ProbeFailure::Timeout));
        assert_eq!(body.failure_reason, Some(ProbeFailure::Body));
        assert_eq!(body.transferred_bytes, 5);
        assert_eq!(request.failure_reason, Some(ProbeFailure::Request));
    }

    #[tokio::test]
    async fn detailed_measurement_summarizes_multiple_local_http_probes() {
        let mut targets = Vec::new();
        let mut servers = Vec::new();
        for &byte in b"abc" {
            let body = vec![byte; 2048];
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            let (url, server) = serve_once(response).await;
            targets.push(url);
            servers.push(server);
        }
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let summary = measure_targets(targets, Duration::from_secs(2), |url| {
            let client = &client;
            async move {
                try_download(
                    client,
                    &url,
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    4096,
                )
                .await
            }
        })
        .await;
        for server in servers {
            server.await.unwrap();
        }

        assert_eq!(summary.successful_probes, 3);
        assert!(summary.median_kbs > 0.0);
        assert!(summary.min_kbs.unwrap() <= summary.median_kbs);
        assert!(summary.median_kbs <= summary.max_kbs.unwrap());
    }

    #[tokio::test]
    async fn detailed_measurement_handles_empty_results_and_timed_out_probes() {
        let summary = measure_targets(
            vec!["small".into(), "timeout".into(), "invalid-speed".into()],
            Duration::from_millis(10),
            |target| async move {
                match target.as_str() {
                    "small" => Some((10, 1.0)),
                    "timeout" => std::future::pending().await,
                    _ => Some((2048, f64::INFINITY)),
                }
            },
        )
        .await;

        assert_eq!(summary, MeasurementSummary::default());
    }

    #[test]
    fn remaining_time_returns_none_once_the_deadline_has_passed() {
        let start = Instant::now() - Duration::from_secs(1);
        assert_eq!(remaining_time(start, Duration::from_secs(1)), None);
        assert!(remaining_time(Instant::now(), Duration::from_secs(1)).is_some());
    }

    #[tokio::test]
    async fn timeout_future_reports_an_expired_timeout() {
        let result = timeout_future(std::future::pending::<()>(), Duration::ZERO).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn measure_returns_zero_when_client_creation_fails() {
        let speed = measure_with_client(
            Err(anyhow::anyhow!("fixture error")),
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            1024,
        )
        .await;
        assert_eq!(speed, 0.0);
    }

    #[test]
    fn target_pool_shuffles_fallback_targets_without_losing_any() {
        let mut actual = target_pool(None);
        let mut expected: Vec<String> = DEFAULT_TARGETS.iter().map(|url| url.to_string()).collect();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    fn positive_speed_rejects_a_zero_result() {
        assert_eq!(positive_speed(1024, f64::INFINITY), None);
    }

    #[tokio::test]
    async fn measure_continues_when_a_download_has_no_positive_speed() {
        let speed = measure_pool(vec!["fixture".into()], |_| async {
            Some((1024, f64::INFINITY))
        })
        .await;
        assert_eq!(speed, 0.0);
    }

    async fn serve_once(response: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        (format!("http://{addr}/download"), task)
    }

    async fn serve_slow_body(
        initial_body: &'static [u8],
        remaining_body: &'static [u8],
        delay: Duration,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let content_length = initial_body.len() + remaining_body.len();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(initial_body).await.unwrap();
            tokio::time::sleep(delay).await;
            let _ = stream.write_all(remaining_body).await;
            let _ = stream.shutdown().await;
        });
        (format!("http://{addr}/slow"), task)
    }

    #[tokio::test]
    async fn local_http_fixtures_handle_eof_before_request_headers_finish() {
        let (url, server) = serve_once(Vec::new()).await;
        let address = url
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /download HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        server.await.unwrap();

        let (url, server) = serve_slow_body(b"a", b"b", Duration::ZERO).await;
        let address = url
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /slow HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn try_download_reads_from_a_local_http_server() {
        let body = vec![b'x'; 2048];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        let (url, server) = serve_once(response).await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let result = try_download(
            &client,
            &url,
            Duration::from_secs(1),
            Duration::from_secs(2),
            4096,
        )
        .await;
        server.await.unwrap();

        let (bytes, seconds) = result.unwrap();
        assert_eq!(bytes, 2048);
        assert!(seconds >= 0.1);
    }

    #[tokio::test]
    async fn try_download_rejects_non_success_status_and_empty_body() {
        let (url, server) = serve_once(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope".to_vec(),
        )
        .await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();
        let result = try_download(
            &client,
            &url,
            Duration::from_secs(1),
            Duration::from_secs(2),
            4096,
        )
        .await;
        server.await.unwrap();
        assert!(result.is_none());

        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        )
        .await;
        let result = try_download(
            &client,
            &url,
            Duration::from_secs(1),
            Duration::from_secs(2),
            4096,
        )
        .await;
        server.await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn try_download_caps_counted_bytes_at_the_requested_limit() {
        let body = vec![b'c'; 2048];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        let (url, server) = serve_once(response).await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let result = try_download(
            &client,
            &url,
            Duration::from_secs(1),
            Duration::from_secs(2),
            1024,
        )
        .await;
        server.await.unwrap();

        assert_eq!(result.unwrap().0, 1024);
    }

    #[tokio::test]
    async fn try_download_returns_none_for_an_invalid_url() {
        let client = reqwest::Client::new();

        let result = try_download(
            &client,
            "://invalid-url",
            Duration::from_secs(1),
            Duration::from_secs(1),
            1024,
        )
        .await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn try_download_keeps_bytes_received_before_a_truncated_body() {
        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nshort".to_vec(),
        )
        .await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let result = try_download(
            &client,
            &url,
            Duration::from_secs(1),
            Duration::from_secs(2),
            4096,
        )
        .await;
        server.await.unwrap();

        assert_eq!(result.unwrap().0, 5);
    }

    #[tokio::test]
    async fn try_download_returns_bytes_received_before_a_slow_body_times_out() {
        let (url, server) =
            serve_slow_body(b"first chunk", b"second chunk", Duration::from_millis(150)).await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let result = try_download(
            &client,
            &url,
            Duration::from_secs(1),
            Duration::from_millis(50),
            4096,
        )
        .await;
        server.await.unwrap();

        assert_eq!(result.unwrap().0, b"first chunk".len() as u64);
    }

    #[tokio::test]
    async fn try_download_applies_its_chunk_timeout_without_a_request_timeout() {
        let (url, server) =
            serve_slow_body(b"first chunk", b"second chunk", Duration::from_millis(150)).await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let result = try_download_at(
            &client,
            &url,
            Duration::from_millis(50),
            4096,
            Instant::now(),
            None,
        )
        .await;
        server.await.unwrap();

        assert_eq!(result.unwrap().0, b"first chunk".len() as u64);
    }

    #[tokio::test]
    async fn try_download_stops_when_started_after_its_deadline() {
        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata".to_vec(),
        )
        .await;
        let client = reqwest::Client::builder().http1_only().build().unwrap();

        let result = try_download_at(
            &client,
            &url,
            Duration::from_secs(1),
            4096,
            Instant::now() - Duration::from_secs(2),
            Some(Duration::from_secs(1)),
        )
        .await;
        server.await.unwrap();

        assert!(result.is_none());
    }

    async fn socks5_once() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 2];
            client.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0; greeting[1] as usize];
            client.read_exact(&mut methods).await.unwrap();
            client.write_all(&[5, 0]).await.unwrap();

            let mut request = [0; 4];
            client.read_exact(&mut request).await.unwrap();
            assert_eq!(request[0], 5);
            assert_eq!(request[1], 1);
            let host = match request[3] {
                1 => {
                    let mut octets = [0; 4];
                    client.read_exact(&mut octets).await.unwrap();
                    std::net::Ipv4Addr::from(octets).to_string()
                }
                3 => {
                    let mut length = [0; 1];
                    client.read_exact(&mut length).await.unwrap();
                    let mut name = vec![0; length[0] as usize];
                    client.read_exact(&mut name).await.unwrap();
                    let name = String::from_utf8(name).unwrap();
                    if name == "localhost" {
                        "127.0.0.1".to_string()
                    } else {
                        name
                    }
                }
                atyp => panic!("unsupported SOCKS address type {atyp}"),
            };
            let mut remote_port = [0; 2];
            client.read_exact(&mut remote_port).await.unwrap();
            let remote_port = u16::from_be_bytes(remote_port);
            let mut remote = tokio::net::TcpStream::connect((host.as_str(), remote_port))
                .await
                .unwrap();
            client
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            tokio::io::copy_bidirectional(&mut client, &mut remote)
                .await
                .unwrap();
        });
        (port, task)
    }

    async fn socks5_client(port: u16) -> tokio::net::TcpStream {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        client
    }

    #[tokio::test]
    async fn socks_fixture_accepts_a_non_localhost_domain_address() {
        let remote_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let remote_port = remote_listener.local_addr().unwrap().port();
        let remote_task = tokio::spawn(async move {
            let (stream, _) = remote_listener.accept().await.unwrap();
            drop(stream);
        });
        let (proxy_port, proxy_task) = socks5_once().await;
        let mut client = socks5_client(proxy_port).await;
        let domain = b"127.0.0.1";
        let mut request = vec![5, 1, 0, 3, domain.len() as u8];
        request.extend_from_slice(domain);
        request.extend_from_slice(&remote_port.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut response = [0; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0);
        drop(client);
        proxy_task.await.unwrap();
        remote_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks_fixture_rejects_an_unsupported_address_type() {
        let (port, server) = socks5_once().await;
        let mut client = socks5_client(port).await;
        client.write_all(&[5, 1, 0, 4]).await.unwrap();
        let error = server.await.unwrap_err();
        assert!(error.is_panic());
    }

    #[tokio::test]
    async fn measure_downloads_through_a_local_socks5_proxy() {
        let body = vec![b'z'; 2048];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        let (url, http_server) = serve_once(response).await;
        let url = url.replace("127.0.0.1", "localhost");
        let (socks_port, socks_server) = socks5_once().await;

        let speed = measure(socks_port, Some(&url), 1.0, 2.0, 0.5).await;

        http_server.await.unwrap();
        socks_server.await.unwrap();
        assert!(speed > 0.0);
    }

    #[tokio::test]
    async fn measure_rejects_a_self_signed_tls_certificate_through_socks5() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::Arc;
        use tokio_rustls::TlsAcceptor;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.key_pair.serialize_der(),
        ));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_port = listener.local_addr().unwrap().port();
        let tls_server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            assert!(acceptor.accept(stream).await.is_err());
        });
        let (socks_port, socks_server) = socks5_once().await;
        let url = format!("https://localhost:{tls_port}/speed");

        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}")).unwrap();
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .http1_only()
            .build()
            .unwrap();
        let result = try_download(
            &client,
            &url,
            Duration::from_secs(1),
            Duration::from_secs(2),
            4096,
        )
        .await;

        tls_server.await.unwrap();
        socks_server.await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn measure_downloads_over_https_when_local_certificate_is_trusted() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::Arc;
        use tokio::io::AsyncReadExt;
        use tokio_rustls::TlsAcceptor;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.key_pair.serialize_der(),
        ));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_port = listener.local_addr().unwrap().port();
        let body = vec![b't'; 2048];
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let tls_server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = [0; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(request[..read].starts_with(b"GET /speed HTTP/1.1"));
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        });

        let (socks_port, socks_server) = socks5_once().await;
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}")).unwrap();
        let trusted = reqwest::Certificate::from_der(certificate.cert.der().as_ref()).unwrap();
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .add_root_certificate(trusted)
            .http1_only()
            .build()
            .unwrap();
        let url = format!("https://localhost:{tls_port}/speed");

        let speed = measure_with_client(
            Ok(client),
            Some(&url),
            Duration::from_secs(1),
            Duration::from_secs(2),
            4096,
        )
        .await;

        tls_server.await.unwrap();
        socks_server.await.unwrap();
        assert!(speed > 0.0);
    }

    #[tokio::test]
    async fn measure_returns_zero_for_an_unavailable_local_socks_proxy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let speed = measure(port, None, 1.0, 1.0, 0.5).await;

        assert_eq!(speed, 0.0);
    }

    #[tokio::test]
    async fn measure_uses_fallback_targets_when_primary_url_is_empty() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let speed = measure(port, Some(""), 1.0, 1.0, 0.5).await;

        assert_eq!(speed, 0.0);
    }

    #[tokio::test]
    async fn measure_skips_a_download_smaller_than_one_kilobyte() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nsmall body";
        let (url, http_server) = serve_once(response.to_vec()).await;
        let (socks_port, socks_server) = socks5_once().await;

        let speed = measure(socks_port, Some(&url), 1.0, 2.0, 0.5).await;

        http_server.await.unwrap();
        socks_server.await.unwrap();
        assert_eq!(speed, 0.0);
    }
}
