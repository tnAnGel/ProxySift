//! Bounded, SSRF-aware collection of saved proxy subscription sources.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Result};
use futures::{stream, StreamExt};
use reqwest::{redirect::Policy, Client, Url};

use crate::{
    forward_proxy::{parse_subscription_with_report, ForwardProxy},
    proxy_grabber::{validate_source_url, DiscoveredSource, ProxyGrabberStore, SourceRefresh},
};

/// Select explicitly named saved sources or every currently active source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxySourceSelection {
    Ids(Vec<i64>),
    AllActive,
}

/// Progress emitted after each source finishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyCollectionProgress {
    pub completed: usize,
    pub total: usize,
    pub source_id: i64,
    pub valid_count: usize,
    pub invalid_count: usize,
    pub error: Option<String>,
}

/// Callback invoked synchronously as individual source requests complete.
pub type ProxyCollectionProgressCallback = Arc<dyn Fn(ProxyCollectionProgress) + Send + Sync>;

/// One parsed proxy together with the saved source that supplied it.
#[derive(Clone, Debug)]
pub struct CollectedProxy {
    pub source_id: i64,
    pub source_url: String,
    pub proxy: ForwardProxy,
}

/// Result for one attempted source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxySourceResult {
    pub source_id: i64,
    pub source_url: String,
    pub valid_count: usize,
    pub invalid_count: usize,
    pub error: Option<String>,
}

/// Aggregate parse and fetch results. `valid_count` and `invalid_count` count
/// parsed lines before cross-source proxy deduplication.
#[derive(Clone, Debug, Default)]
pub struct ProxyCollectionReport {
    pub proxies: Vec<CollectedProxy>,
    pub sources: Vec<ProxySourceResult>,
    pub valid_count: usize,
    pub invalid_count: usize,
    pub errors: Vec<String>,
}

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CONCURRENCY: usize = 64;

/// Fetch selected saved sources, parse their subscriptions, and persist each
/// source's last fetch status and parsed proxy count.
///
/// Explicit IDs may refer to inactive saved sources. `AllActive` selects only
/// active records. A missing requested ID is returned as an error before any
/// network requests are made.
pub async fn collect_proxy_sources(
    store: &ProxyGrabberStore,
    selection: ProxySourceSelection,
    per_source_timeout: Duration,
    concurrency: usize,
    progress: Option<ProxyCollectionProgressCallback>,
) -> Result<ProxyCollectionReport> {
    let sources = match &selection {
        ProxySourceSelection::AllActive => store.list_sources(true)?,
        ProxySourceSelection::Ids(ids) => {
            let all = store.list_sources(false)?;
            let by_id = all
                .into_iter()
                .map(|source| (source.id, source))
                .collect::<std::collections::HashMap<_, _>>();
            let mut selected = Vec::with_capacity(ids.len());
            let mut seen = HashSet::new();
            for id in ids {
                if !seen.insert(*id) {
                    continue;
                }
                selected.push(
                    by_id
                        .get(id)
                        .cloned()
                        .ok_or_else(|| anyhow!("saved source {id} does not exist"))?,
                );
            }
            selected
        }
    };

    let total = sources.len();
    let timeout = per_source_timeout.clamp(Duration::from_millis(1), MAX_TIMEOUT);
    let limit = concurrency.clamp(1, MAX_CONCURRENCY);
    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback = progress.clone();

    let mut results = stream::iter(sources.into_iter().map(|source| {
        let store = store.clone();
        let completed = Arc::clone(&completed);
        let callback = callback.clone();
        async move {
            let result = collect_one(&store, source, timeout).await;
            let finished = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if let Some(callback) = callback {
                callback(ProxyCollectionProgress {
                    completed: finished,
                    total,
                    source_id: result.source.source_id,
                    valid_count: result.source.valid_count,
                    invalid_count: result.source.invalid_count,
                    error: result.source.error.clone(),
                });
            }
            result
        }
    }))
    .buffer_unordered(limit)
    .collect::<Vec<_>>()
    .await;

    // Keep output independent of request completion order.
    results.sort_by_key(|result| result.source.source_id);
    let mut report = ProxyCollectionReport::default();
    let mut fingerprints = HashSet::new();
    for result in results {
        report.valid_count += result.source.valid_count;
        report.invalid_count += result.source.invalid_count;
        if let Some(error) = &result.source.error {
            report
                .errors
                .push(format!("source {}: {error}", result.source.source_id));
        }
        for proxy in result.proxies {
            if fingerprints.insert(proxy.proxy.fingerprint.clone()) {
                report.proxies.push(proxy);
            }
        }
        report.sources.push(result.source);
    }
    Ok(report)
}

struct OneSourceResult {
    source: ProxySourceResult,
    proxies: Vec<CollectedProxy>,
}

async fn collect_one(
    store: &ProxyGrabberStore,
    source: DiscoveredSource,
    timeout: Duration,
) -> OneSourceResult {
    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;
    let mut proxies = Vec::new();

    let fetched =
        match tokio::time::timeout(timeout, fetch_subscription(&source.url, timeout)).await {
            Ok(result) => result,
            Err(_) => Err("source collection timed out".to_owned()),
        };
    let source_downloaded = fetched.is_ok();
    let error = match fetched {
        Ok(body) => {
            let parsed = parse_subscription_with_report(&body);
            valid_count = parsed.valid_lines;
            invalid_count = parsed.invalid_lines;
            proxies = parsed
                .proxies
                .into_iter()
                .map(|proxy| CollectedProxy {
                    source_id: source.id,
                    source_url: source.url.clone(),
                    proxy,
                })
                .collect();
            if proxies.is_empty() {
                Some("source downloaded, but no supported proxy entries were found".to_owned())
            } else {
                None
            }
        }
        Err(error) => Some(error),
    };

    let status = if error.is_none() {
        "success"
    } else if source_downloaded {
        // A reachable HTML page or an empty response is not a usable proxy feed.
        "unrecognized"
    } else {
        "failed"
    };
    let refresh = SourceRefresh {
        status: status.to_owned(),
        count: source_downloaded.then_some(proxies.len() as u64),
        fetched_at: None,
    };
    let error = match store.update_source_refresh(source.id, &refresh) {
        Ok(true) => error,
        Ok(false) => Some(
            error.unwrap_or_else(|| "source disappeared before fetch result was saved".to_owned()),
        ),
        Err(save_error) => Some(match error {
            Some(fetch_error) => format!("{fetch_error}; failed to save fetch result: {save_error}"),
            None => format!("failed to save fetch result: {save_error}"),
        }),
    };

    OneSourceResult {
        source: ProxySourceResult {
            source_id: source.id,
            source_url: source.url,
            valid_count,
            invalid_count,
            error,
        },
        proxies,
    }
}

async fn fetch_subscription(value: &str, timeout: Duration) -> std::result::Result<String, String> {
    let normalized =
        validate_source_url(value).map_err(|_| "invalid or disallowed source URL".to_owned())?;
    let url = Url::parse(&normalized).map_err(|_| "invalid source URL".to_owned())?;
    let host = url
        .host_str()
        .ok_or_else(|| "source URL has no host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "source URL has no valid port".to_owned())?;

    // Resolve ourselves, reject the entire answer set if any address is unsafe,
    // and pin the accepted addresses into this request's client to prevent DNS
    // rebinding between validation and connection.
    let addresses = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => {
            let resolved = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| "source DNS lookup timed out".to_owned())?
                .map_err(|_| "source DNS lookup failed".to_owned())?
                .collect::<Vec<_>>();
            if resolved.is_empty() {
                return Err("source DNS returned no addresses".to_owned());
            }
            resolved
        }
    };
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err("source DNS resolved to a non-public address".to_owned());
    }

    let remaining = timeout;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(remaining)
        .gzip(true)
        .brotli(true);
    if host.parse::<IpAddr>().is_err() {
        builder = builder.resolve_to_addrs(host, &addresses);
    }
    let client = builder
        .build()
        .map_err(|_| "failed to configure HTTP client".to_owned())?;

    let response = tokio::time::timeout(remaining, client.get(url).send())
        .await
        .map_err(|_| "source request timed out".to_owned())?
        .map_err(|_| "source request failed".to_owned())?;
    if response.status().is_redirection() {
        return Err("source returned a redirect; redirects are disabled".to_owned());
    }
    if !response.status().is_success() {
        return Err(format!(
            "source returned HTTP {}",
            response.status().as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err("source response exceeds the 8 MiB limit".to_owned());
    }

    let mut body = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = tokio::time::timeout(remaining, chunks.next())
        .await
        .map_err(|_| "source response timed out".to_owned())?
    {
        let chunk = chunk.map_err(|_| "failed to read source response".to_owned())?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err("source response exceeds the 8 MiB limit".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| "source response is not valid UTF-8".to_owned())
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_v4(mapped);
            }
            let segments = ip.segments();
            // Reject both the well-known IPv4-translatable prefix and the
            // local-use NAT64 prefix. The former may encode private IPv4
            // destinations in its final 32 bits.
            if segments[0] == 0x0064 && segments[1] == 0xff9b {
                return false;
            }
            let globally_routed_unicast = segments[0] & 0xe000 == 0x2000;
            globally_routed_unicast
                && !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !(segments[0] == 0x2001 && segments[1] <= 0x01ff)
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && !(segments[0] == 0x2002)
                && !(segments[0] == 0x3fff && segments[1] & 0xfff0 == 0)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}
