use crate::{
    cli::Cli,
    fetch::{self, FetchOptions},
    forward_proxy::{self, ForwardProxy, ProbeResult},
    geoip::{self, GeoDb},
    pipeline::{PipelineProgress, ProgressCallback},
};
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

const GEOIP_CONCURRENCY: usize = 128;
const GEOLITE_URL: &str =
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb";

#[derive(Clone, Debug)]
pub struct CheckedForwardProxy {
    pub probe: ProbeResult,
    pub country: String,
    pub source: String,
}

pub async fn run(
    cli: &Cli,
    pasted_links: &str,
    limit: usize,
    use_geoip: bool,
    progress: ProgressCallback,
) -> Result<Vec<CheckedForwardProxy>> {
    run_with_options(
        cli,
        pasted_links,
        (limit > 0).then_some(limit),
        use_geoip,
        cli.workers,
        cli.proxy_timeout,
        progress,
    )
    .await
}

/// Run HTTP/SOCKS checks using CLI defaults and the optional UI overrides.
/// `None` limit checks every unique proxy received from subscriptions and pasted links.
pub async fn run_from_cli(
    cli: &Cli,
    pasted_links: &str,
    use_geoip: bool,
    progress: ProgressCallback,
) -> Result<Vec<CheckedForwardProxy>> {
    run_with_options(
        cli,
        pasted_links,
        cli.limit,
        use_geoip,
        cli.workers,
        cli.proxy_timeout,
        progress,
    )
    .await
}

/// Extended runner API. The legacy [`run`] API remains available and preserves
/// its `limit == 0` meaning of unlimited.
pub async fn run_with_options(
    cli: &Cli,
    pasted_links: &str,
    limit: Option<usize>,
    use_geoip: bool,
    workers: Option<usize>,
    proxy_timeout: Option<f64>,
    progress: ProgressCallback,
) -> Result<Vec<CheckedForwardProxy>> {
    let workers = workers.or(cli.workers).map(|value| value.clamp(1, 4096));
    let proxy_timeout = proxy_timeout
        .or(cli.proxy_timeout)
        .map(|value| value.clamp(0.1, 3600.0));
    let source_urls = cli.url.clone();
    report(
        &progress,
        "Источники",
        format!("Загружаем {} подписок", source_urls.len()),
    );
    let fetch_report = fetch::fetch_all_with_options(
        &source_urls,
        &FetchOptions {
            concurrency: workers.unwrap_or(cli.fetch_concurrency),
            timeout: Duration::from_secs_f64(cli.fetch_timeout.max(1.0)),
            max_response_bytes: cli.max_source_bytes,
            retries: cli.fetch_retries,
            insecure_tls: cli.insecure_source_tls,
            cache_dir: (!cli.no_fetch_cache).then(|| PathBuf::from(&cli.fetch_cache_dir)),
        },
    )
    .await;

    let mut candidates = Vec::new();
    let mut source_by_fingerprint = HashMap::new();
    let mut valid_lines = 0;
    let mut invalid_lines = 0;
    for success in &fetch_report.successes {
        let label = source_urls
            .iter()
            .position(|url| url == &success.url)
            .map(|index| format!("Подписка {}", index + 1))
            .unwrap_or_else(|| "Подписка".to_owned());
        let parsed = forward_proxy::parse_subscription_with_report(&success.text);
        valid_lines += parsed.valid_lines;
        invalid_lines += parsed.invalid_lines;
        for proxy in parsed.proxies {
            source_by_fingerprint
                .entry(proxy.fingerprint.clone())
                .or_insert_with(|| label.clone());
            candidates.push(proxy);
        }
    }
    let (manual_proxies, manual_valid, manual_invalid, manual_sources) =
        parse_manual_proxy_sources(pasted_links);
    valid_lines += manual_valid;
    invalid_lines += manual_invalid;
    for proxy in manual_proxies {
        source_by_fingerprint
            .entry(proxy.fingerprint.clone())
            .or_insert_with(|| {
                manual_sources
                    .get(&proxy.fingerprint)
                    .cloned()
                    .unwrap_or_else(|| "Вставлено вручную".to_owned())
            });
        candidates.push(proxy);
    }
    candidates = deduplicate(candidates);
    if let Some(limit) = limit {
        candidates.truncate(limit);
    }

    if candidates.is_empty() {
        let processed_lines = valid_lines + invalid_lines;
        bail!(
            "Не найдено поддерживаемых HTTP/SOCKS прокси. Обработано строк: {processed_lines}; корректных: {valid_lines}; пропущено: {invalid_lines}. Загружено подписок: {}, ошибок загрузки: {}. Используйте IP:PORT или схемы http://, https://, socks4://, socks4a://, socks5://, socks5h://.",
            fetch_report.successes.len(),
            fetch_report.failures.len()
        );
    }

    report(
        &progress,
        "Разбор",
        format!(
            "Найдено уникальных прокси: {}; корректных строк: {valid_lines}; пропущено строк: {invalid_lines}",
            candidates.len()
        ),
    );

    let countries = if use_geoip {
        let db_path = cli
            .geoip_db
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("GeoLite2-Country.mmdb"));
        report(&progress, "GeoIP", "Проверяем локальную базу стран");
        geoip::ensure_db(&db_path, GEOLITE_URL)
            .await
            .context("не удалось подготовить базу GeoIP")?;
        let database = GeoDb::open(&db_path)?;
        resolve_countries(&candidates, &database).await
    } else {
        HashMap::new()
    };

    let timeout = Duration::from_secs_f64(
        proxy_timeout
            .unwrap_or(cli.speed_timeout)
            .clamp(0.1, 3600.0),
    );
    let concurrency = workers.unwrap_or(64);
    let total = candidates.len();
    let completed = Arc::new(AtomicUsize::new(0));
    let last_report_ms = Arc::new(AtomicUsize::new(0));
    let started = std::time::Instant::now();
    let mut probes = futures::stream::iter(candidates.into_iter().enumerate())
        .map(|(index, proxy)| {
            let progress = progress.clone();
            let completed = completed.clone();
            let last_report_ms = last_report_ms.clone();
            async move {
                let source_fingerprint = proxy.fingerprint.clone();
                let probe = forward_proxy::probe(&proxy, timeout).await;
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                let elapsed_ms = started.elapsed().as_millis() as usize;
                let previous_report_ms = last_report_ms.swap(elapsed_ms, Ordering::Relaxed);
                if done == total
                    || done % 10 == 0
                    || elapsed_ms.saturating_sub(previous_report_ms) >= 250
                {
                    progress(PipelineProgress::update(
                        "Проверка HTTP/SOCKS",
                        format!("Проверено {done} из {total}"),
                        done,
                        total,
                        started.elapsed(),
                    ));
                }
                (index, source_fingerprint, probe)
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

    // Keep the displayed row order stable even though checks run concurrently.
    probes.sort_by_key(|(index, _, _)| *index);
    let mut output = Vec::with_capacity(probes.len());
    for (_, source_fingerprint, probe) in probes {
        let country = countries
            .get(&probe.proxy.host)
            .cloned()
            .unwrap_or_else(|| "XX".into());
        let source = source_by_fingerprint
            .remove(&source_fingerprint)
            .unwrap_or_else(|| "—".to_owned());
        output.push(CheckedForwardProxy {
            probe,
            country,
            source,
        });
    }
    Ok(output)
}

/// Parse manually supplied proxies while preserving optional provenance markers
/// emitted by the saved-source collector. Each marker applies to the proxy
/// lines that follow it until the next marker.
fn parse_manual_proxy_sources(
    input: &str,
) -> (Vec<ForwardProxy>, usize, usize, HashMap<String, String>) {
    const SOURCE_MARKER: &str = "# ProxySift-Source:";

    if !input.lines().any(|line| line.trim().starts_with(SOURCE_MARKER)) {
        let parsed = forward_proxy::parse_subscription_with_report(input);
        let sources = parsed
            .proxies
            .iter()
            .map(|proxy| (proxy.fingerprint.clone(), "Вставлено вручную".to_owned()))
            .collect();
        return (
            parsed.proxies,
            parsed.valid_lines,
            parsed.invalid_lines,
            sources,
        );
    }

    let mut proxies = Vec::new();
    let mut sources = HashMap::new();
    let mut valid = 0;
    let mut invalid = 0;
    let mut section = String::new();
    let mut source = "Вставлено вручную".to_owned();

    let flush = |section: &mut String,
                 source: &str,
                 proxies: &mut Vec<ForwardProxy>,
                 sources: &mut HashMap<String, String>,
                 valid: &mut usize,
                 invalid: &mut usize| {
        if section.trim().is_empty() {
            section.clear();
            return;
        }
        let parsed = forward_proxy::parse_subscription_with_report(section);
        *valid += parsed.valid_lines;
        *invalid += parsed.invalid_lines;
        for proxy in parsed.proxies {
            sources
                .entry(proxy.fingerprint.clone())
                .or_insert_with(|| source.to_owned());
            proxies.push(proxy);
        }
        section.clear();
    };

    for line in input.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix(SOURCE_MARKER) {
            flush(
                &mut section,
                &source,
                &mut proxies,
                &mut sources,
                &mut valid,
                &mut invalid,
            );
            let value = value.trim();
            source = url::Url::parse(value)
                .ok()
                .filter(|url| matches!(url.scheme(), "http" | "https"))
                .map(|_| value.to_owned())
                .unwrap_or_else(|| "Вставлено вручную".to_owned());
        } else {
            section.push_str(line);
            section.push('\n');
        }
    }
    flush(
        &mut section,
        &source,
        &mut proxies,
        &mut sources,
        &mut valid,
        &mut invalid,
    );
    (proxies, valid, invalid, sources)
}

fn report(progress: &ProgressCallback, phase: &str, detail: impl Into<String>) {
    progress(PipelineProgress {
        phase: phase.to_owned(),
        detail: detail.into(),
        completed: 0,
        total: 0,
        rate_per_sec: 0.0,
        remaining_seconds: None,
    });
}

fn deduplicate(proxies: Vec<ForwardProxy>) -> Vec<ForwardProxy> {
    let mut seen = HashSet::new();
    proxies
        .into_iter()
        .filter(|proxy| seen.insert(proxy.fingerprint.clone()))
        .collect()
}

async fn resolve_countries(
    candidates: &[ForwardProxy],
    database: &GeoDb,
) -> HashMap<String, String> {
    let hosts = candidates
        .iter()
        .map(|candidate| candidate.host.clone())
        .collect::<HashSet<_>>();
    let resolved = futures::stream::iter(hosts)
        .map(|host| async move {
            let ip = if let Ok(ip) = host.parse::<IpAddr>() {
                Some(ip)
            } else {
                tokio::net::lookup_host((host.as_str(), 80))
                    .await
                    .ok()
                    .and_then(|addresses| {
                        addresses
                            .map(|address| address.ip())
                            .find(|ip| is_public_ip(*ip))
                    })
            };
            (host, ip)
        })
        .buffer_unordered(GEOIP_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    resolved
        .into_iter()
        .map(|(host, ip)| {
            let country = ip
                .and_then(|ip| database.country_for_ip(ip))
                .unwrap_or_else(|| "XX".into())
                .to_ascii_uppercase();
            (host, country)
        })
        .collect()
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_unspecified()
                && !ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
        }
    }
}
