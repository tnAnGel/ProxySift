use anyhow::{anyhow, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::error::Error as _;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use url::Url;

const PROBE_HOST: &str = "example.com";
const PROBE_PORT: u16 = 80;
const PROBE_URL: &str = "http://example.com/";
const PROBE_HTTPS_URL: &str = "https://example.com/";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ForwardProxyProtocol {
    Auto,
    Http,
    Https,
    Socks4,
    Socks4a,
    Socks5,
}

impl ForwardProxyProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks4 => "socks4",
            Self::Socks4a => "socks4a",
            Self::Socks5 => "socks5",
        }
    }
}

impl fmt::Display for ForwardProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone)]
pub struct ForwardProxy {
    pub protocol: ForwardProxyProtocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub name: String,
    pub original_uri: String,
    pub fingerprint: String,
}

impl ForwardProxy {
    /// Returns a URI suitable for persistence that contains no credentials.
    pub fn redacted_uri(&self) -> String {
        format!(
            "{}://{}:{}",
            self.protocol.as_str(),
            authority_host(&self.host),
            self.port
        )
    }
}

impl fmt::Debug for ForwardProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardProxy")
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username.as_ref().map(|_| "[redacted]"))
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("name", &self.name)
            .field("original_uri", &self.redacted_uri())
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl fmt::Display for ForwardProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted_uri())
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub proxy: ForwardProxy,
    pub status: String,
    pub alive: bool,
    pub ping_ms: Option<u64>,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct SubscriptionParseReport {
    pub proxies: Vec<ForwardProxy>,
    pub valid_lines: usize,
    pub invalid_lines: usize,
}

/// Parses a supported forward-proxy URI.
pub fn parse_uri(input: &str) -> Result<ForwardProxy> {
    let original_uri = input.trim();
    if !original_uri.contains("://") {
        return parse_auto_authority(original_uri);
    }
    let url = Url::parse(original_uri).map_err(|_| anyhow!("invalid proxy URI"))?;

    let protocol = match url.scheme() {
        "http" => ForwardProxyProtocol::Http,
        "https" => ForwardProxyProtocol::Https,
        "socks4" => ForwardProxyProtocol::Socks4,
        "socks4a" => ForwardProxyProtocol::Socks4a,
        "socks5" | "socks5h" => ForwardProxyProtocol::Socks5,
        _ => return Err(anyhow!("unsupported proxy protocol")),
    };

    if !(url.path().is_empty() || url.path() == "/") || url.query().is_some() {
        return Err(anyhow!(
            "proxy URI must contain only an endpoint and optional name"
        ));
    }

    let raw_host = url
        .host_str()
        .ok_or_else(|| anyhow!("proxy URI is missing a host"))?;
    let host = canonical_host(raw_host);
    let port = url
        .port_or_known_default()
        .or_else(|| match protocol {
            ForwardProxyProtocol::Auto => None,
            ForwardProxyProtocol::Http => Some(80),
            ForwardProxyProtocol::Https => Some(443),
            ForwardProxyProtocol::Socks4
            | ForwardProxyProtocol::Socks4a
            | ForwardProxyProtocol::Socks5 => Some(1080),
        })
        .ok_or_else(|| anyhow!("proxy URI is missing a valid port"))?;
    if port == 0 {
        return Err(anyhow!("proxy URI port must be between 1 and 65535"));
    }

    let had_userinfo = !url.username().is_empty() || url.password().is_some();
    let username = if had_userinfo {
        Some(decode_userinfo(url.username())?)
    } else {
        None
    };
    let password = url.password().map(decode_userinfo).transpose()?;

    let name = url
        .fragment()
        .filter(|fragment| !fragment.trim().is_empty())
        .map(|fragment| decode_userinfo(fragment))
        .transpose()?
        .map(|value| redact_name(&value, username.as_deref(), password.as_deref()))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("{}:{}", authority_host(&host), port));

    let fingerprint = fingerprint(
        protocol,
        &host,
        port,
        username.as_deref(),
        password.as_deref(),
    );

    Ok(ForwardProxy {
        protocol,
        host,
        port,
        username,
        password,
        name,
        original_uri: original_uri.to_owned(),
        fingerprint,
    })
}

fn parse_auto_authority(input: &str) -> Result<ForwardProxy> {
    let url = Url::parse(&format!("http://{input}"))
        .map_err(|_| anyhow!("expected host:port without a proxy scheme"))?;
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(anyhow!("expected only host:port without a proxy scheme"));
    }

    let raw_host = url
        .host_str()
        .ok_or_else(|| anyhow!("proxy address is missing a host"))?;
    let port = url
        .port()
        .ok_or_else(|| anyhow!("proxy address is missing an explicit port"))?;
    if port == 0 {
        return Err(anyhow!("proxy URI port must be between 1 and 65535"));
    }

    let host = canonical_host(raw_host);
    let protocol = ForwardProxyProtocol::Auto;
    let fingerprint = fingerprint(protocol, &host, port, None, None);
    let name = format!("{}:{port}", authority_host(&host));
    Ok(ForwardProxy {
        protocol,
        host,
        port,
        username: None,
        password: None,
        name,
        original_uri: input.to_owned(),
        fingerprint,
    })
}

/// Parses direct proxy URI lines, or a base64-encoded list of such lines.
pub fn parse_subscription(input: &str) -> Vec<ForwardProxy> {
    parse_subscription_with_report(input).proxies
}

pub fn parse_subscription_with_report(input: &str) -> SubscriptionParseReport {
    let direct = parse_uri_lines(input);
    if !direct.proxies.is_empty() {
        return direct;
    }

    let compact = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let encoded = compact.as_bytes();
    let decoded_candidates = [
        STANDARD.decode(encoded).ok(),
        STANDARD_NO_PAD.decode(encoded).ok(),
        URL_SAFE.decode(encoded).ok(),
        URL_SAFE_NO_PAD.decode(encoded).ok(),
    ];
    for decoded in decoded_candidates.into_iter().flatten() {
        let Ok(decoded) = String::from_utf8(decoded) else {
            continue;
        };
        let parsed = parse_uri_lines(&decoded);
        if !parsed.proxies.is_empty() {
            return parsed;
        }
    }

    direct
}

fn parse_uri_lines(input: &str) -> SubscriptionParseReport {
    let mut report = SubscriptionParseReport::default();
    let mut proxies = Vec::new();
    for line in input.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_uri(line) {
            Ok(proxy) => {
                report.valid_lines += 1;
                proxies.push(proxy);
            }
            Err(_) => report.invalid_lines += 1,
        }
    }
    report.proxies = deduplicate(proxies);
    report
}

fn deduplicate(proxies: Vec<ForwardProxy>) -> Vec<ForwardProxy> {
    let mut seen = std::collections::HashSet::new();
    proxies
        .into_iter()
        .filter(|proxy| seen.insert(proxy.fingerprint.clone()))
        .collect()
}

fn canonical_host(host: &str) -> String {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = unbracketed.parse::<Ipv4Addr>() {
        address.to_string()
    } else if let Ok(address) = unbracketed.parse::<Ipv6Addr>() {
        address.to_string()
    } else {
        unbracketed.to_ascii_lowercase()
    }
}

fn authority_host(host: &str) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn decode_userinfo(value: &str) -> Result<String> {
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| anyhow!("proxy URI contains non-UTF-8 encoded text"))
}

fn redact_name(name: &str, username: Option<&str>, password: Option<&str>) -> String {
    let mut redacted = name.to_owned();
    for secret in [username, password].into_iter().flatten() {
        if !secret.is_empty() {
            redacted = redacted.replace(secret, "[redacted]");
        }
    }
    redacted
}

fn fingerprint(
    protocol: ForwardProxyProtocol,
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"proxy-sift-forward-proxy-v1\0");
    hash_field(&mut hash, protocol.as_str().as_bytes());
    hash_field(&mut hash, host.as_bytes());
    hash_field(&mut hash, &port.to_be_bytes());
    hash_optional_field(&mut hash, username);
    hash_optional_field(&mut hash, password);
    format!("{:x}", hash.finalize())
}

fn hash_field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn hash_optional_field(hash: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash_field(hash, value.as_bytes());
        }
        None => hash.update([0]),
    }
}

/// Checks whether a forward proxy can carry an HTTP request to the probe target.
pub async fn probe(proxy: &ForwardProxy, timeout: Duration) -> ProbeResult {
    let started = Instant::now();
    if proxy.protocol == ForwardProxyProtocol::Auto {
        return probe_auto(proxy, timeout).await;
    }

    let checked = tokio::time::timeout(timeout, async {
        probe_known_protocol(proxy, timeout, started).await
    })
    .await;

    match checked {
        Ok(result) => result,
        Err(_) => result(proxy, "timeout", false, None, "proxy check timed out"),
    }
}

async fn probe_auto(proxy: &ForwardProxy, timeout: Duration) -> ProbeResult {
    // Each candidate gets its own full timeout. Keep auto-detection in the
    // user-facing order: HTTP, HTTPS, SOCKS4, then SOCKS5. SOCKS4a remains
    // available when explicitly selected, but is not a separate auto attempt.
    const CANDIDATES: [ForwardProxyProtocol; 4] = [
        ForwardProxyProtocol::Http,
        ForwardProxyProtocol::Https,
        ForwardProxyProtocol::Socks4,
        ForwardProxyProtocol::Socks5,
    ];
    let mut saw_timeout = false;

    for protocol in CANDIDATES {
        let candidate = with_protocol(proxy, protocol);
        let started = Instant::now();
        let (result, protocol_confirmed) = if protocol == ForwardProxyProtocol::Socks5 {
            match tokio::time::timeout(
                timeout,
                probe_socks5_auto(&candidate, timeout, started),
            )
            .await
            {
                Ok(Some(result)) => (result, true),
                Ok(None) => continue,
                Err(_) => {
                    saw_timeout = true;
                    continue;
                }
            }
        } else {
            match tokio::time::timeout(
                timeout,
                probe_known_protocol(&candidate, timeout, started),
            )
            .await
            {
                Ok(result) => (result, false),
                Err(_) => {
                    saw_timeout = true;
                    continue;
                }
            }
        };

        saw_timeout |= result.status == "timeout";
        if protocol_confirmed
            || result.alive
            || matches!(
                result.status.as_str(),
                "auth_required" | "auth_failed" | "proxy_rejected"
            )
        {
            return result;
        }
    }

    if saw_timeout {
        return result(
            proxy,
            "timeout",
            false,
            None,
            "no proxy protocol responded within the configured timeout",
        );
    }

    result(
        proxy,
        "protocol_unknown",
        false,
        None,
        "could not detect a working HTTP, HTTPS, SOCKS4, or SOCKS5 proxy protocol",
    )
}

async fn probe_known_protocol(
    proxy: &ForwardProxy,
    timeout: Duration,
    started: Instant,
) -> ProbeResult {
    match proxy.protocol {
        ForwardProxyProtocol::Auto => unreachable!("auto proxies use probe_auto"),
        ForwardProxyProtocol::Http | ForwardProxyProtocol::Https => {
            probe_http(proxy, timeout, started).await
        }
        ForwardProxyProtocol::Socks5 => probe_socks5(proxy, timeout, started).await,
        ForwardProxyProtocol::Socks4 | ForwardProxyProtocol::Socks4a => {
            probe_socks4(proxy, started).await
        }
    }
}

fn with_protocol(proxy: &ForwardProxy, protocol: ForwardProxyProtocol) -> ForwardProxy {
    let mut candidate = proxy.clone();
    candidate.protocol = protocol;
    candidate.fingerprint = fingerprint(
        protocol,
        &candidate.host,
        candidate.port,
        candidate.username.as_deref(),
        candidate.password.as_deref(),
    );
    candidate
}

async fn probe_socks5_auto(
    proxy: &ForwardProxy,
    timeout: Duration,
    started: Instant,
) -> Option<ProbeResult> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .ok()?;
    // Offer both no-auth and username/password so a SOCKS5 server can
    // identify itself even when this bare host:port has no credentials.
    stream.write_all(&[5, 2, 0, 2]).await.ok()?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await.ok()?;
    if response[0] != 5 {
        return None;
    }

    match response[1] {
        0 => Some(probe_socks5(proxy, timeout, started).await),
        2 | 255 => Some(result(
            proxy,
            "auth_required",
            false,
            Some(elapsed_ms(started)),
            "SOCKS5 proxy requires credentials",
        )),
        _ => None,
    }
}

async fn probe_http(proxy: &ForwardProxy, timeout: Duration, started: Instant) -> ProbeResult {
    // Exercise CONNECT for both HTTP and HTTPS proxies. For HTTPS proxies,
    // reqwest additionally negotiates TLS to the proxy before issuing CONNECT;
    // the HTTPS target then verifies the tunneled TLS path end to end.
    probe_http_with_builder(
        proxy,
        timeout,
        started,
        PROBE_HTTPS_URL,
        reqwest::Client::builder(),
    )
    .await
}

async fn probe_http_with_builder(
    proxy: &ForwardProxy,
    timeout: Duration,
    started: Instant,
    probe_url: &str,
    client_builder: reqwest::ClientBuilder,
) -> ProbeResult {
    let proxy_url = format!(
        "{}://{}:{}",
        proxy.protocol.as_str(),
        authority_host(&proxy.host),
        proxy.port
    );
    let mut proxy_config = match reqwest::Proxy::all(&proxy_url) {
        Ok(proxy_config) => proxy_config,
        Err(_) => {
            return result(
                proxy,
                "probe_failed",
                false,
                None,
                "could not configure the proxy connection",
            )
        }
    };
    if proxy.username.is_some() || proxy.password.is_some() {
        proxy_config = proxy_config.basic_auth(
            proxy.username.as_deref().unwrap_or_default(),
            proxy.password.as_deref().unwrap_or_default(),
        );
    }

    let client = match client_builder
        .proxy(proxy_config)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return result(
                proxy,
                "probe_failed",
                false,
                None,
                "could not configure the proxy request",
            )
        }
    };

    let response = match client.get(probe_url).send().await {
        Ok(response) => response,
        Err(error) if error.is_timeout() => {
            return result(
                proxy,
                "timeout",
                false,
                Some(elapsed_ms(started)),
                "proxy request timed out",
            )
        }
        Err(error) if error.is_connect() && is_proxy_auth_required(&error) => {
            let (label, detail) = if proxy.username.is_some() || proxy.password.is_some() {
                ("auth_failed", "proxy rejected the supplied credentials")
            } else {
                ("auth_required", "proxy requires authentication")
            };
            return result(proxy, label, false, Some(elapsed_ms(started)), detail);
        }
        Err(error) if error.is_connect() => {
            return result(
                proxy,
                "connection_failed",
                false,
                Some(elapsed_ms(started)),
                "could not connect through the proxy",
            )
        }
        Err(_) => {
            return result(
                proxy,
                "probe_failed",
                false,
                Some(elapsed_ms(started)),
                "proxy request failed",
            )
        }
    };

    let status = response.status();
    if status.as_u16() == 407 {
        let (label, detail) = if proxy.username.is_some() || proxy.password.is_some() {
            ("auth_failed", "proxy rejected the supplied credentials")
        } else {
            ("auth_required", "proxy requires authentication")
        };
        return result(proxy, label, false, Some(elapsed_ms(started)), detail);
    }

    result(
        proxy,
        "alive",
        true,
        Some(elapsed_ms(started)),
        &format!("proxy forwarded the request (HTTP {})", status.as_u16()),
    )
}

fn is_proxy_auth_required(error: &reqwest::Error) -> bool {
    let mut source = error.source();
    while let Some(cause) = source {
        if cause.to_string() == "tunnel error: proxy authorization required" {
            return true;
        }
        source = cause.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    async fn read_headers(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
        let mut headers = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            if stream.read(&mut byte).await? == 0 {
                break;
            }
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        Ok(headers)
    }

    #[tokio::test]
    async fn https_proxy_establishes_tls_connect_tunnel_and_https_request() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "example.com".into()])
                .unwrap();
        let trusted_root = reqwest::Certificate::from_der(certificate.cert.der().as_ref()).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.key_pair.serialize_der(),
        ));
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut proxy_tls = acceptor.accept(stream).await.unwrap();
            let connect_request = read_headers(&mut proxy_tls).await.unwrap();
            assert!(connect_request.starts_with(b"CONNECT example.com:443 HTTP/1.1"));
            proxy_tls
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();

            let mut destination_tls = acceptor.accept(proxy_tls).await.unwrap();
            let target_request = read_headers(&mut destination_tls).await.unwrap();
            assert!(target_request.starts_with(b"GET / HTTP/1.1"));
            destination_tls
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let proxy = parse_uri(&format!("https://localhost:{port}")).unwrap();
        let result = probe_http_with_builder(
            &proxy,
            Duration::from_secs(3),
            Instant::now(),
            PROBE_HTTPS_URL,
            reqwest::Client::builder().add_root_certificate(trusted_root),
        )
        .await;

        server.await.unwrap();
        assert!(result.alive, "{}: {}", result.status, result.detail);
        assert_eq!(result.status, "alive");
    }

    #[tokio::test]
    async fn connect_407_is_reported_as_missing_or_rejected_authentication() {
        for (proxy_uri, expected_status) in [
            ("http://localhost:{port}", "auth_required"),
            ("http://user:secret@localhost:{port}", "auth_failed"),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_headers(&mut stream).await.unwrap();
                assert!(request.starts_with(b"CONNECT example.com:443 HTTP/1.1"));
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await
                    .unwrap();
            });
            let proxy = parse_uri(&proxy_uri.replace("{port}", &port.to_string())).unwrap();
            let result = probe_http_with_builder(
                &proxy,
                Duration::from_secs(3),
                Instant::now(),
                PROBE_HTTPS_URL,
                reqwest::Client::builder(),
            )
            .await;

            server.await.unwrap();
            assert_eq!(result.status, expected_status);
            assert!(!result.alive);
            assert!(!result.detail.contains("secret"));
        }
    }
}

async fn probe_socks5(proxy: &ForwardProxy, timeout: Duration, started: Instant) -> ProbeResult {
    let mut proxy_url = match Url::parse(&format!(
        "socks5h://{}:{}",
        authority_host(&proxy.host),
        proxy.port
    )) {
        Ok(url) => url,
        Err(_) => {
            return result(
                proxy,
                "probe_failed",
                false,
                None,
                "could not configure the SOCKS5 proxy",
            )
        }
    };
    if proxy.username.is_some() || proxy.password.is_some() {
        if proxy_url
            .set_username(proxy.username.as_deref().unwrap_or_default())
            .is_err()
            || proxy_url
                .set_password(Some(proxy.password.as_deref().unwrap_or_default()))
                .is_err()
        {
            return result(
                proxy,
                "probe_failed",
                false,
                None,
                "could not configure SOCKS5 authentication",
            );
        }
    }

    let proxy_config = match reqwest::Proxy::all(proxy_url.as_str()) {
        Ok(proxy_config) => proxy_config,
        Err(_) => {
            return result(
                proxy,
                "probe_failed",
                false,
                None,
                "could not configure the SOCKS5 proxy",
            )
        }
    };
    let client = match reqwest::Client::builder()
        .proxy(proxy_config)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return result(
                proxy,
                "probe_failed",
                false,
                None,
                "could not configure the SOCKS5 request",
            )
        }
    };

    match client.get(PROBE_URL).send().await {
        Ok(response) => result(
            proxy,
            "alive",
            true,
            Some(elapsed_ms(started)),
            &format!(
                "SOCKS5 proxy forwarded the request (HTTP {})",
                response.status().as_u16()
            ),
        ),
        Err(error) if error.is_timeout() => result(
            proxy,
            "timeout",
            false,
            Some(elapsed_ms(started)),
            "SOCKS5 request timed out",
        ),
        Err(error) if error.is_connect() => result(
            proxy,
            "connection_failed",
            false,
            Some(elapsed_ms(started)),
            "could not connect through the SOCKS5 proxy",
        ),
        Err(_) => result(
            proxy,
            "probe_failed",
            false,
            Some(elapsed_ms(started)),
            "SOCKS5 request failed",
        ),
    }
}

async fn probe_socks4(proxy: &ForwardProxy, started: Instant) -> ProbeResult {
    if proxy.password.is_some() {
        return result(
            proxy,
            "unsupported_auth",
            false,
            None,
            "SOCKS4 does not support password authentication",
        );
    }

    let username = proxy.username.as_deref().unwrap_or_default();
    if username.as_bytes().contains(&0) || username.len() > 255 {
        return result(
            proxy,
            "invalid_credentials",
            false,
            None,
            "SOCKS4 user ID is invalid",
        );
    }

    match socks4_exchange(proxy, username).await {
        Ok(()) => result(
            proxy,
            "alive",
            true,
            Some(elapsed_ms(started)),
            "SOCKS4 proxy established a tunnel and returned an HTTP response",
        ),
        Err(Socks4Failure::Rejected) => result(
            proxy,
            "proxy_rejected",
            false,
            Some(elapsed_ms(started)),
            "SOCKS4 proxy rejected the CONNECT request",
        ),
        Err(Socks4Failure::UserIdRejected) => result(
            proxy,
            "auth_failed",
            false,
            Some(elapsed_ms(started)),
            "SOCKS4 proxy rejected the supplied user ID",
        ),
        Err(Socks4Failure::TargetResolution) => result(
            proxy,
            "target_resolution_failed",
            false,
            Some(elapsed_ms(started)),
            "could not resolve the probe target to IPv4",
        ),
        Err(Socks4Failure::Connect) => result(
            proxy,
            "connection_failed",
            false,
            Some(elapsed_ms(started)),
            "could not connect to the SOCKS4 proxy",
        ),
        Err(Socks4Failure::Io | Socks4Failure::InvalidResponse) => result(
            proxy,
            "probe_failed",
            false,
            Some(elapsed_ms(started)),
            "SOCKS4 handshake or tunnel request failed",
        ),
    }
}

#[derive(Clone, Copy)]
enum Socks4Failure {
    Connect,
    Io,
    Rejected,
    UserIdRejected,
    TargetResolution,
    InvalidResponse,
}

async fn socks4_exchange(
    proxy: &ForwardProxy,
    username: &str,
) -> std::result::Result<(), Socks4Failure> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|_| Socks4Failure::Connect)?;

    let destination = if proxy.protocol == ForwardProxyProtocol::Socks4a {
        Ipv4Addr::new(0, 0, 0, 1)
    } else {
        tokio::net::lookup_host((PROBE_HOST, PROBE_PORT))
            .await
            .map_err(|_| Socks4Failure::TargetResolution)?
            .find_map(|address| match address.ip() {
                std::net::IpAddr::V4(address) => Some(address),
                std::net::IpAddr::V6(_) => None,
            })
            .ok_or(Socks4Failure::TargetResolution)?
    };

    let mut request = Vec::with_capacity(9 + username.len() + PROBE_HOST.len());
    request.extend_from_slice(&[4, 1]);
    request.extend_from_slice(&PROBE_PORT.to_be_bytes());
    request.extend_from_slice(&destination.octets());
    request.extend_from_slice(username.as_bytes());
    request.push(0);
    if proxy.protocol == ForwardProxyProtocol::Socks4a {
        request.extend_from_slice(PROBE_HOST.as_bytes());
        request.push(0);
    }
    stream
        .write_all(&request)
        .await
        .map_err(|_| Socks4Failure::Io)?;

    let mut response = [0_u8; 8];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| Socks4Failure::Io)?;
    if response[0] != 0 {
        return Err(Socks4Failure::InvalidResponse);
    }
    match response[1] {
        90 => {}
        93 => return Err(Socks4Failure::UserIdRejected),
        91 | 92 => return Err(Socks4Failure::Rejected),
        _ => return Err(Socks4Failure::InvalidResponse),
    }

    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {PROBE_HOST}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .map_err(|_| Socks4Failure::Io)?;
    read_http_status_line(&mut stream)
        .await
        .map(|_| ())
        .map_err(|_| Socks4Failure::InvalidResponse)
}

async fn read_http_status_line(stream: &mut TcpStream) -> std::io::Result<u16> {
    let mut line = Vec::with_capacity(64);
    loop {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            break;
        }
        if line.len() >= 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP status line is too long",
            ));
        }
        if byte != b'\r' {
            line.push(byte);
        }
    }

    let line = std::str::from_utf8(&line)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP status"))?;
    let mut parts = line.split_ascii_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HTTP response",
        ));
    }
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HTTP status",
        ));
    }
    let status = status
        .parse::<u16>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP status"))?;
    if !(100..=599).contains(&status) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP status is outside the valid range",
        ));
    }
    Ok(status)
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn result(
    proxy: &ForwardProxy,
    status: &str,
    alive: bool,
    ping_ms: Option<u64>,
    detail: &str,
) -> ProbeResult {
    ProbeResult {
        proxy: proxy.clone(),
        status: status.to_owned(),
        alive,
        ping_ms,
        detail: detail.to_owned(),
    }
}
