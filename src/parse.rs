use crate::outbound::{
    b64_any, build_stream, normalize_ss_method, q, q_or, ss_method_supported, ss_settings,
    trojan_settings, vless_settings, vmess_settings,
};
use percent_encoding::percent_decode_str;
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;
use url::Url;

#[derive(Clone, Debug)]
pub struct Proxy {
    pub proto: &'static str,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub base_url: String,
    pub orig_url: String,
    pub settings: Value,
    pub stream: Option<Value>,
    pub country: String,
    pub display: String,
    pub ping: Option<u64>,
    pub speed_kbs: f64,
}

impl Proxy {
    pub fn key(&self) -> String {
        format!(
            "{}|{}",
            self.settings,
            self.stream
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default()
        )
    }

    /// Stable, credential-free identity for archive joins and deduplication.
    pub fn fingerprint(&self) -> String {
        let identity = format!("{}|{}", self.proto, self.key());
        format!("{:x}", Sha256::digest(identity.as_bytes()))
    }
}

#[derive(Debug)]
pub enum ParseErr {
    Unsupported(&'static str),
    Invalid(&'static str),
}

#[derive(Debug, Default)]
pub struct ParseStats {
    pub links: usize,
    pub parsed: usize,
    pub duplicates: usize,
    pub invalid: usize,
    pub invalid_reasons: HashMap<&'static str, usize>,
    pub unsupported: HashMap<&'static str, usize>,
    /// Detailed unsupported values, keyed by stable labels such as
    /// `vmess: transport=quic`.
    pub unsupported_details: BTreeMap<String, usize>,
}

fn link_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|hy2|tuic|anytls|socks5?|mierus|wireguard|wg)://[^\s"'<>\\]+"#,
        )
        .unwrap()
    })
}

fn clean_link(raw: &str) -> String {
    let mut s: String = raw
        .trim()
        .replace("&amp;", "&")
        .replace(['\u{feff}', '\u{200b}'], "");
    while let Some(last) = s.chars().last() {
        if matches!(last, '"' | '\'' | ',' | ';' | '<' | '>' | '|')
            || (last == ')' && s.matches('(').count() < s.matches(')').count())
            || (last == ']' && s.matches('[').count() < s.matches(']').count())
        {
            s.pop();
        } else {
            break;
        }
    }
    s
}

pub fn extract_links(text: &str) -> Vec<String> {
    link_re()
        .find_iter(text)
        .map(|m| clean_link(m.as_str()))
        .filter(|s| is_extracted_link(s))
        .collect()
}

fn is_extracted_link(link: &str) -> bool {
    link.contains("://") && link.len() > 8
}

fn decode_component(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn clean_proxy_name(raw: &str) -> String {
    const AD_MARKERS: &[&str] = &[
        "t.me/",
        "telegram.me/",
        "subscribe",
        "подпис",
        "реклам",
        "advert",
        "channel",
        "канал",
        "join us",
        "follow us",
        "контакт",
        "promo",
        "промокод",
    ];

    raw.split(['|', '｜', '•', '·'])
        .filter_map(|segment| {
            let segment = segment.trim();
            let lower = segment.to_lowercase();
            if AD_MARKERS.iter().any(|marker| lower.contains(marker)) {
                return None;
            }

            let cleaned = segment
                .split_whitespace()
                .filter(|token| {
                    let lower = token.to_lowercase();
                    !token.starts_with('@')
                        && !lower.contains("t.me/")
                        && !lower.contains("telegram.me/")
                        && !lower.starts_with("http://")
                        && !lower.starts_with("https://")
                        && !lower.starts_with("www.")
                })
                .collect::<Vec<_>>()
                .join(" ");
            (!cleaned.is_empty()).then_some(cleaned)
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn params_of(u: &Url) -> HashMap<String, String> {
    u.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn uri_params_of(u: &Url) -> HashMap<String, String> {
    u.query()
        .unwrap_or_default()
        .split('&')
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| {
            let (key, value) = entry.split_once('=').unwrap_or((entry, ""));
            Some((
                percent_decode_str(key).decode_utf8().ok()?.into_owned(),
                percent_decode_str(value).decode_utf8().ok()?.into_owned(),
            ))
        })
        .collect()
}

fn plausible_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() >= 16
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_' || c == '.')
}

fn host_port(u: &Url, default_port: u16) -> Result<(String, u16), ParseErr> {
    let host = u
        .host_str()
        .ok_or(ParseErr::Invalid("no host"))?
        .to_string();
    let port = u.port().unwrap_or(default_port);
    if host.is_empty() || port == 0 {
        return Err(ParseErr::Invalid("bad host/port"));
    }
    Ok((host, port))
}

const FLOW_ALLOWED: &[&str] = &["", "xtls-rprx-vision", "xtls-rprx-vision-udp443"];

fn normalize_flow(raw: &str) -> Result<String, ParseErr> {
    let f = raw.to_ascii_lowercase();
    let f = if f == "xtls-rprx-visi" {
        "xtls-rprx-vision".to_string()
    } else {
        f
    };
    if FLOW_ALLOWED.contains(&f.as_str()) {
        Ok(f)
    } else {
        Err(ParseErr::Invalid("bad flow"))
    }
}

fn parse_vless(link: &str) -> Result<Proxy, ParseErr> {
    let u = Url::parse(link).map_err(|_| ParseErr::Invalid("bad url"))?;
    let (host, port) = host_port(&u, 443)?;
    let id = decode_component(u.username());
    if !plausible_id(&id) {
        return Err(ParseErr::Invalid("bad uuid"));
    }
    let mut params = params_of(&u);

    let encryption = q_or(&params, "encryption", "none").to_ascii_lowercase();
    if !matches!(encryption.as_str(), "none") {
        return Err(ParseErr::Invalid("bad encryption"));
    }
    let security = q_or(&params, "security", "none").to_ascii_lowercase();
    if !matches!(security.as_str(), "tls" | "reality" | "none" | "auto") {
        return Err(ParseErr::Invalid("bad security"));
    }
    let flow = normalize_flow(q_or(&params, "flow", ""))?;
    if !flow.is_empty() && !matches!(security.as_str(), "tls" | "reality") {
        return Err(ParseErr::Invalid("flow without tls"));
    }
    params.insert("flow".into(), flow);
    if security == "reality" {
        let pbk = q(&params, "pbk").unwrap_or("");
        if pbk.is_empty() || b64_any(pbk).map(|v| v.len()) != Some(32) {
            return Err(ParseErr::Invalid("bad reality pbk"));
        }
        if let Some(sid) = q(&params, "sid") {
            if !sid.is_empty()
                && !(sid.len() % 2 == 0
                    && sid.len() <= 16
                    && sid.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Err(ParseErr::Invalid("bad reality sid"));
            }
        }
        let spx = q_or(&params, "spx", "/");
        if !spx.starts_with('/') {
            return Err(ParseErr::Invalid("bad spiderX"));
        }
    }

    let raw_net = q_or(&params, "type", "tcp").to_ascii_lowercase();
    let net = match raw_net.as_str() {
        "tcp" => "raw",
        "splithttp" | "split-http" => "xhttp",
        "mkcp" | "m-kcp" => "kcp",
        "websocket" => "ws",
        "gun" => "grpc",
        other => other,
    };
    let stream = build_stream(net, &security, &params, &host)
        .ok_or(ParseErr::Unsupported("vless transport"))?;
    let settings = vless_settings(&host, port, &id, &params);

    Ok(Proxy {
        proto: "vless",
        host,
        port,
        name: clean_proxy_name(&decode_component(u.fragment().unwrap_or(""))),
        base_url: link.split('#').next().unwrap_or(link).to_string(),
        orig_url: link.to_string(),
        settings,
        stream: Some(stream),
        country: String::new(),
        display: String::new(),
        ping: None,
        speed_kbs: 0.0,
    })
}

fn vmess_stream(
    net: &str,
    security: &str,
    params: &HashMap<String, String>,
    host: &str,
) -> Result<Value, ParseErr> {
    build_stream(net, security, params, host).ok_or(ParseErr::Unsupported("vmess transport"))
}

fn parse_vmess(link: &str) -> Result<Proxy, ParseErr> {
    let cleaned = link.replace(['\u{feff}', '\u{200b}', '\n', '\r'], "");

    if cleaned.contains('@') {
        let u = Url::parse(&cleaned).map_err(|_| ParseErr::Invalid("bad url"))?;
        let (host, port) = host_port(&u, 443)?;
        let id = decode_component(u.username());
        if !plausible_id(&id) {
            return Err(ParseErr::Invalid("bad uuid"));
        }
        let params = params_of(&u);
        let aid: i64 = q_or(&params, "aid", "0").parse().unwrap_or(-1);
        if aid < 0 {
            return Err(ParseErr::Invalid("bad aid"));
        }
        let cipher = q_or(&params, "encryption", "auto").to_ascii_lowercase();
        if !matches!(
            cipher.as_str(),
            "auto" | "aes-128-gcm" | "chacha20-poly1305" | "none" | "zero"
        ) {
            return Err(ParseErr::Invalid("bad cipher"));
        }
        let raw_net: String = q_or(&params, "type", "tcp")
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        let raw_net = if raw_net.is_empty() {
            "tcp".to_string()
        } else {
            raw_net
        };
        let net = if raw_net == "httpupgrade" {
            "httpupgrade"
        } else {
            raw_net.as_str()
        };
        let security = q_or(&params, "security", "none").to_ascii_lowercase();
        let security = if security.is_empty() {
            "none".to_string()
        } else {
            security
        };
        let stream = vmess_stream(net, &security, &params, &host)?;
        let settings = vmess_settings(&host, port, &id, &cipher);
        return Ok(Proxy {
            proto: "vmess",
            host,
            port,
            name: clean_proxy_name(&decode_component(u.fragment().unwrap_or(""))),
            base_url: link.split('#').next().unwrap_or(link).to_string(),
            orig_url: link.to_string(),
            settings,
            stream: Some(stream),
            country: String::new(),
            display: String::new(),
            ping: None,
            speed_kbs: 0.0,
        });
    }

    let content = cleaned
        .trim_start_matches("vmess://")
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    let bytes = b64_any(content).ok_or(ParseErr::Invalid("bad vmess base64"))?;
    let text = String::from_utf8_lossy(&bytes);
    let data: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| ParseErr::Invalid("bad vmess json"))?;
    let obj = data
        .as_object()
        .ok_or(ParseErr::Invalid("vmess not object"))?;

    let get = |k: &str| -> String {
        obj.get(k)
            .map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => String::new(),
            })
            .unwrap_or_default()
    };

    let id = get("id");
    if !plausible_id(&id) {
        return Err(ParseErr::Invalid("bad uuid"));
    }
    let host = get("add");
    let port: u16 = get("port").parse().unwrap_or(0);
    if host.is_empty() || port == 0 {
        return Err(ParseErr::Invalid("bad address"));
    }
    let cipher = if get("scy").is_empty() {
        "auto".to_string()
    } else {
        get("scy").to_ascii_lowercase()
    };
    if !matches!(
        cipher.as_str(),
        "auto" | "aes-128-gcm" | "chacha20-poly1305" | "none" | "zero"
    ) {
        return Err(ParseErr::Invalid("bad cipher"));
    }
    let raw_net: String = get("net")
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let raw_net = if raw_net.is_empty() {
        "tcp".to_string()
    } else {
        raw_net
    };
    let net = if raw_net == "httpupgrade" {
        "httpupgrade"
    } else {
        raw_net.as_str()
    };
    let security = if get("tls").is_empty() {
        "none".to_string()
    } else {
        get("tls").to_ascii_lowercase()
    };

    let mut params: HashMap<String, String> = HashMap::new();
    for (key, field) in [
        ("path", "path"),
        ("host", "host"),
        ("sni", "sni"),
        ("fp", "fp"),
        ("alpn", "alpn"),
        ("mode", "mode"),
    ] {
        let v = get(field);
        if !v.is_empty() {
            params.insert(key.to_string(), v);
        }
    }

    let stream = vmess_stream(net, &security, &params, &host)?;
    let settings = vmess_settings(&host, port, &id, &cipher);
    let name = clean_proxy_name(obj.get("ps").and_then(|v| v.as_str()).unwrap_or("vmess"));
    Ok(Proxy {
        proto: "vmess",
        host,
        port,
        name,
        base_url: link.split('#').next().unwrap_or(link).to_string(),
        orig_url: link.to_string(),
        settings,
        stream: Some(stream),
        country: String::new(),
        display: String::new(),
        ping: None,
        speed_kbs: 0.0,
    })
}

fn parse_trojan(link: &str) -> Result<Proxy, ParseErr> {
    let u = Url::parse(link).map_err(|_| ParseErr::Invalid("bad url"))?;
    let (host, port) = host_port(&u, 443)?;
    let password = decode_component(u.username());
    if password.is_empty() {
        return Err(ParseErr::Invalid("empty password"));
    }
    let mut params = params_of(&u);
    if !params.contains_key("sni") {
        if let Some(peer) = params.get("peer").cloned() {
            params.insert("sni".into(), peer);
        }
    }
    let security = q_or(&params, "security", "tls").to_ascii_lowercase();
    if !matches!(security.as_str(), "tls" | "reality") {
        return Err(ParseErr::Invalid("bad security"));
    }
    let raw_net = q_or(&params, "type", "tcp").to_ascii_lowercase();
    let net = match raw_net.as_str() {
        "tcp" => "raw",
        "splithttp" | "split-http" => "xhttp",
        "mkcp" | "m-kcp" => "kcp",
        "websocket" => "ws",
        "gun" => "grpc",
        other => other,
    };
    let stream = build_stream(net, &security, &params, &host)
        .ok_or(ParseErr::Unsupported("trojan transport"))?;
    let settings = trojan_settings(&host, port, &password, &params);

    Ok(Proxy {
        proto: "trojan",
        host,
        port,
        name: clean_proxy_name(&decode_component(u.fragment().unwrap_or(""))),
        base_url: link.split('#').next().unwrap_or(link).to_string(),
        orig_url: link.to_string(),
        settings,
        stream: Some(stream),
        country: String::new(),
        display: String::new(),
        ping: None,
        speed_kbs: 0.0,
    })
}

fn parse_ss(link: &str) -> Result<Proxy, ParseErr> {
    let without_frag = link.split('#').next().unwrap_or(link);
    if Url::parse(without_frag)
        .ok()
        .is_some_and(|url| url.query_pairs().any(|(key, _)| key == "plugin"))
    {
        // Shadowsocks plugins are not supported by the Xray speed-check core.
        // Never silently test/export a connection with a required plugin removed.
        return Err(ParseErr::Unsupported("ss plugin"));
    }
    let (main, name) = match link.split_once('#') {
        Some((m, n)) => (m, clean_proxy_name(&decode_component(n))),
        None => (without_frag, "ss".to_string()),
    };

    let (method, password, host, port) = ss_method_password_host_port(main)?;

    if host.is_empty() || port == 0 {
        return Err(ParseErr::Invalid("bad ss address"));
    }
    if method.is_empty() {
        return Err(ParseErr::Invalid("empty ss method"));
    }
    if !ss_method_supported(&method) {
        return Err(ParseErr::Unsupported("ss method"));
    }
    let settings = ss_settings(&host, port, &method, &password);

    Ok(Proxy {
        proto: "shadowsocks",
        host,
        port,
        name,
        base_url: link.split('#').next().unwrap_or(link).to_string(),
        orig_url: link.to_string(),
        settings,
        stream: None,
        country: String::new(),
        display: String::new(),
        ping: None,
        speed_kbs: 0.0,
    })
}

fn ss_method_password_host_port(main: &str) -> Result<(String, String, String, u16), ParseErr> {
    let (method, password, host, port) = if main.contains('@') {
        let url = Url::parse(main).map_err(|_| ParseErr::Invalid("bad ss url"))?;
        let userinfo = decode_component(url.username());
        let decoded = if userinfo.contains(':') {
            userinfo
        } else {
            let bytes = b64_any(&userinfo).ok_or(ParseErr::Invalid("bad ss userinfo"))?;
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let (method, password) = decoded
            .split_once(':')
            .ok_or(ParseErr::Invalid("ss userinfo missing method separator"))?;
        let host = url
            .host_str()
            .ok_or(ParseErr::Invalid("no host"))?
            .to_string();
        (
            method.to_string(),
            password.to_string(),
            host,
            url.port().unwrap_or(0),
        )
    } else {
        let payload = main
            .trim_start_matches("ss://")
            .split('?')
            .next()
            .unwrap_or("");
        let bytes = b64_any(payload).ok_or(ParseErr::Invalid("bad ss base64"))?;
        let decoded = String::from_utf8_lossy(&bytes).into_owned();
        let (auth, address) = decoded
            .rsplit_once('@')
            .ok_or(ParseErr::Invalid("ss legacy missing endpoint separator"))?;
        let (method, password) = auth
            .split_once(':')
            .ok_or(ParseErr::Invalid("ss legacy missing method separator"))?;
        let (host, port) = address
            .rsplit_once(':')
            .ok_or(ParseErr::Invalid("ss legacy missing port"))?;
        (
            method.to_string(),
            password.to_string(),
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port.parse().unwrap_or(0),
        )
    };

    Ok((normalize_ss_method(&method), password, host, port))
}

fn hysteria2_multiport_url(link: &str) -> Option<(String, String)> {
    let scheme_end = link.find("://")?;
    let authority_start = scheme_end + 3;
    let authority_end = link[authority_start..]
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(link.len());
    let authority = &link[authority_start..authority_end];
    let server = authority
        .rsplit_once('@')
        .map_or(authority, |(_, server)| server);

    let port_start = if server.starts_with('[') {
        let close = server.find(']')?;
        (server.as_bytes().get(close + 1) == Some(&b':')).then_some(close + 2)?
    } else {
        server.rfind(':')? + 1
    };
    let ports = &server[port_start..];
    if !ports.contains([',', '-']) {
        return None;
    }

    let mut first_port = None;
    for item in ports.split(',') {
        let (first, last) = item.split_once('-').unwrap_or((item, item));
        let first: u16 = first.parse().ok()?;
        let last: u16 = last.parse().ok()?;
        if first == 0 || last == 0 || first > last {
            return None;
        }
        first_port.get_or_insert(first);
    }
    let first_port = first_port?;
    let port_spec_start = authority_start
        + (server.as_ptr() as usize - link[authority_start..authority_end].as_ptr() as usize)
        + port_start;
    let mut normalized = String::with_capacity(link.len());
    normalized.push_str(&link[..port_spec_start]);
    normalized.push_str(&first_port.to_string());
    normalized.push_str(&link[authority_end..]);
    Some((normalized, ports.to_string()))
}

fn parse_hysteria(link: &str, version: u8) -> Result<Proxy, ParseErr> {
    let (parse_link, authority_ports) = if version == 2 {
        hysteria2_multiport_url(link)
            .map(|(normalized, ports)| (normalized, Some(ports)))
            .unwrap_or_else(|| (link.to_string(), None))
    } else {
        (link.to_string(), None)
    };
    let u = Url::parse(&parse_link).map_err(|_| ParseErr::Invalid("bad hysteria url"))?;
    if version == 1 && u.port().is_none() {
        return Err(ParseErr::Invalid("missing hysteria port"));
    }
    let (host, port) = host_port(&u, if version == 2 { 443 } else { 0 })?;
    let params = uri_params_of(&u);
    let (proto, settings, stream) = if version == 2 {
        let auth = match u.password() {
            Some(password) => format!(
                "{}:{}",
                decode_component(u.username()),
                decode_component(password)
            ),
            None => decode_component(u.username()),
        };
        let obfs = q_or(&params, "obfs", "").to_ascii_lowercase();
        if !obfs.is_empty() && !matches!(obfs.as_str(), "salamander" | "gecko") {
            return Err(ParseErr::Invalid("bad hysteria2 obfs"));
        }
        let obfs_password = params
            .get("obfs-password")
            .or_else(|| params.get("obfs_password"))
            .cloned()
            .unwrap_or_default();
        if obfs == "salamander" && obfs_password.is_empty() {
            return Err(ParseErr::Invalid("empty hysteria2 obfs password"));
        }
        let insecure = parse_insecure(params.get("insecure").map(String::as_str))?;
        let insecure_present = params.contains_key("insecure");
        let server_name = q_or(&params, "sni", "");

        let mut settings = Map::new();
        settings.insert("version".into(), json!(2));
        settings.insert("address".into(), Value::String(host.clone()));
        settings.insert("port".into(), json!(port));
        settings.insert("auth".into(), Value::String(auth.clone()));
        if let Some(ports) = authority_ports
            .as_deref()
            .or_else(|| params.get("ports").map(String::as_str))
        {
            settings.insert("ports".into(), Value::String(ports.to_string()));
        }
        if !obfs.is_empty() {
            settings.insert("obfs".into(), Value::String(obfs.clone()));
        }
        if !obfs_password.is_empty() {
            settings.insert("obfs-password".into(), Value::String(obfs_password.clone()));
        }
        if !server_name.is_empty() {
            settings.insert("serverName".into(), Value::String(server_name.into()));
        }
        if insecure_present {
            settings.insert("insecure".into(), Value::Bool(insecure));
        }
        if let Some(pin) = params.get("pinSHA256").filter(|value| !value.is_empty()) {
            settings.insert("pinSHA256".into(), Value::String(pin.clone()));
        }
        if let Some(ech) = params.get("ech").filter(|value| !value.is_empty()) {
            settings.insert("ech".into(), Value::String(ech.clone()));
        }

        let mut tls = Map::new();
        if !server_name.is_empty() {
            tls.insert("serverName".into(), Value::String(server_name.into()));
        }
        if insecure_present {
            tls.insert("allowInsecure".into(), Value::Bool(insecure));
        }
        if let Some(pin) = params.get("pinSHA256").filter(|value| !value.is_empty()) {
            tls.insert("pinnedPeerCertSha256".into(), Value::String(pin.clone()));
        }
        if let Some(ech) = params.get("ech").filter(|value| !value.is_empty()) {
            tls.insert("echConfigList".into(), Value::String(ech.clone()));
        }
        let mut stream = json!({
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": Value::Object(tls),
            "hysteriaSettings": {"version": 2, "auth": auth}
        });
        let mut udp_masks = Vec::new();
        if obfs == "salamander" {
            udp_masks.push(json!({
                "type":"salamander",
                "settings":{"password":obfs_password}
            }));
        }
        if let Some(ports) = authority_ports
            .as_deref()
            .or_else(|| params.get("ports").map(String::as_str))
        {
            udp_masks.push(json!({
                "type":"udphop",
                "settings":{"mode":"intervallocal", "interval":"30", "remotePorts":ports}
            }));
        }
        if !udp_masks.is_empty() {
            stream["finalmask"] = json!({"udp": udp_masks});
        }
        ("hysteria2", Value::Object(settings), Some(stream))
    } else {
        let auth = params
            .get("auth")
            .or_else(|| params.get("auth-str"))
            .or_else(|| params.get("auth_str"))
            .cloned()
            .unwrap_or_else(|| decode_component(u.username()));
        let protocol = q_or(&params, "protocol", "udp").to_ascii_lowercase();
        if !matches!(protocol.as_str(), "udp" | "wechat-video" | "faketcp") {
            return Err(ParseErr::Invalid("bad hysteria protocol"));
        }
        let insecure = parse_insecure(params.get("insecure").map(String::as_str))?;
        let peer = params
            .get("peer")
            .or_else(|| params.get("sni"))
            .cloned()
            .unwrap_or_default();
        let parse_bandwidth = |key: &str| -> Result<u64, ParseErr> {
            params
                .get(key)
                .map(|value| {
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or(ParseErr::Invalid("bad hysteria bandwidth"))
                })
                .transpose()?
                .ok_or(ParseErr::Invalid("missing hysteria bandwidth"))
        };
        let up = parse_bandwidth("upmbps")?;
        let down = parse_bandwidth("downmbps")?;
        let obfs = q_or(&params, "obfs", "").to_ascii_lowercase();
        if !obfs.is_empty() && obfs != "xplus" {
            return Err(ParseErr::Invalid("bad hysteria obfs"));
        }
        let mut settings = Map::new();
        settings.insert("version".into(), json!(1));
        settings.insert("address".into(), Value::String(host.clone()));
        settings.insert("port".into(), json!(port));
        settings.insert("auth".into(), Value::String(auth));
        settings.insert("peer".into(), Value::String(peer.clone()));
        settings.insert("sni".into(), Value::String(peer));
        settings.insert("insecure".into(), Value::Bool(insecure));
        settings.insert("protocol".into(), Value::String(protocol));
        settings.insert("obfs".into(), Value::String(obfs));
        if let Some(value) = params
            .get("obfsParam")
            .or_else(|| params.get("obfs-param"))
            .or_else(|| params.get("obfs-password"))
        {
            settings.insert("obfsParam".into(), Value::String(value.clone()));
        }
        settings.insert("upmbps".into(), json!(up));
        settings.insert("downmbps".into(), json!(down));
        if let Some(alpn) = params.get("alpn").filter(|value| !value.is_empty()) {
            settings.insert("alpn".into(), Value::String(alpn.clone()));
        }
        ("hysteria", Value::Object(settings), None)
    };
    let name = clean_proxy_name(&decode_component(u.fragment().unwrap_or("")));
    Ok(Proxy {
        proto,
        host,
        port,
        name,
        base_url: link.split('#').next().unwrap_or(link).to_string(),
        orig_url: link.to_string(),
        settings,
        stream,
        country: String::new(),
        display: String::new(),
        ping: None,
        speed_kbs: 0.0,
    })
}

fn parse_insecure(value: Option<&str>) -> Result<bool, ParseErr> {
    match value.map(str::to_ascii_lowercase).as_deref() {
        None | Some("0") | Some("false") => Ok(false),
        Some("1") | Some("true") => Ok(true),
        _ => Err(ParseErr::Invalid("bad hysteria insecure")),
    }
}

pub fn parse_link(link: &str) -> Result<Proxy, ParseErr> {
    let lower = link.to_ascii_lowercase();
    if lower.starts_with("vless://") {
        parse_vless(link)
    } else if lower.starts_with("vmess://") {
        parse_vmess(link)
    } else if lower.starts_with("trojan://") {
        parse_trojan(link)
    } else if lower.starts_with("ss://") {
        parse_ss(link)
    } else if lower.starts_with("ssr://") {
        Err(ParseErr::Unsupported("ssr"))
    } else if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        parse_hysteria(link, 2)
    } else if lower.starts_with("hysteria://") {
        parse_hysteria(link, 1)
    } else if lower.starts_with("tuic://") {
        Err(ParseErr::Unsupported("tuic"))
    } else if lower.starts_with("anytls://") {
        Err(ParseErr::Unsupported("anytls"))
    } else {
        Err(ParseErr::Unsupported("other"))
    }
}

pub fn parse_all(links: Vec<String>) -> (Vec<Proxy>, ParseStats) {
    let mut stats = ParseStats {
        links: links.len(),
        ..Default::default()
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<Proxy> = Vec::new();
    for link in links {
        match parse_link(&link) {
            Ok(p) => {
                let key = p.key();
                if seen.insert(key) {
                    out.push(p);
                } else {
                    stats.duplicates += 1;
                }
            }
            Err(ParseErr::Unsupported(proto)) => {
                *stats.unsupported.entry(proto).or_insert(0) += 1;
                *stats
                    .unsupported_details
                    .entry(unsupported_reason_key(&link, proto))
                    .or_insert(0) += 1;
            }
            Err(ParseErr::Invalid(reason)) => {
                stats.invalid += 1;
                *stats.invalid_reasons.entry(reason).or_insert(0) += 1;
            }
        }
    }
    stats.parsed = out.len();
    (out, stats)
}

/// Return a stable, secret-safe label for a specific unsupported feature.
///
/// Only the transport or cipher/method value is included. Credentials, URL paths,
/// query parameters other than the selected feature, and fragments are never copied.
pub fn unsupported_reason_key(link: &str, category: &str) -> String {
    let scheme = link
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_owned());
    let (protocol, field) = match category {
        "vmess transport" => ("vmess", "transport"),
        "vless transport" => ("vless", "transport"),
        "trojan transport" => ("trojan", "transport"),
        "ss method" => ("ss", "method"),
        "ss plugin" => ("ss", "plugin"),
        _ => (scheme.as_str(), "feature"),
    };
    let value = match field {
        "transport" => transport_value(link, protocol),
        "method" => shadowsocks_method(link),
        "plugin" => "configured".to_owned(),
        _ => category.to_owned(),
    };
    format!("{protocol}: {field}={}", safe_reason_value(&value))
}

fn safe_reason_value(value: &str) -> String {
    let value = value.trim();
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return if value.is_empty() {
            "empty".to_owned()
        } else {
            "nonstandard".to_owned()
        };
    }
    value.chars().take(80).collect()
}

fn transport_value(link: &str, protocol: &str) -> String {
    if protocol == "vmess" && !link.contains('@') {
        let payload = link
            .trim_start_matches("vmess://")
            .split(['#', '?'])
            .next()
            .unwrap_or_default();
        let Some(decoded) = b64_any(payload) else {
            return "unknown".to_owned();
        };
        return serde_json::from_slice::<Value>(&decoded)
            .ok()
            .and_then(|json| json.get("net").and_then(Value::as_str).map(str::to_owned))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "tcp".to_owned());
    }
    Url::parse(link)
        .ok()
        .and_then(|url| {
            let params = params_of(&url);
            params.get("type").or_else(|| params.get("net")).cloned()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "tcp".to_owned())
}

fn shadowsocks_method(link: &str) -> String {
    let without_fragment = link.split('#').next().unwrap_or(link);
    ss_method_password_host_port(without_fragment)
        .map(|(method, _, _, _)| method)
        .unwrap_or_else(|_| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde_json::json;

    const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";

    fn invalid_reason(result: Result<Proxy, ParseErr>) -> &'static str {
        match result {
            Err(ParseErr::Invalid(reason)) => reason,
            Err(ParseErr::Unsupported(proto)) => {
                panic!("expected invalid input, got unsupported {proto}")
            }
            Ok(proxy) => panic!("expected invalid input, parsed {}", proxy.proto),
        }
    }

    fn unsupported_proto(result: Result<Proxy, ParseErr>) -> &'static str {
        match result {
            Err(ParseErr::Unsupported(proto)) => proto,
            Err(ParseErr::Invalid(reason)) => {
                panic!("expected unsupported protocol, got invalid {reason}")
            }
            Ok(proxy) => panic!("expected unsupported protocol, parsed {}", proxy.proto),
        }
    }

    fn vmess_json_link(value: Value) -> String {
        let encoded = STANDARD.encode(value.to_string());
        format!("vmess://{encoded}")
    }

    #[test]
    fn extract_links_cleans_wrappers_and_preserves_balanced_punctuation() {
        let text = "Links: (VLESS://id@example.com:443?type=tcp#name), ss://abc==; and (trojan://pw@example.net:443/path(a)))";
        assert_eq!(
            extract_links(text),
            vec![
                "VLESS://id@example.com:443?type=tcp#name".to_string(),
                "ss://abc==".to_string(),
                "trojan://pw@example.net:443/path(a)".to_string(),
            ]
        );
    }

    #[test]
    fn clean_proxy_name_removes_channel_ads_and_keeps_node_label() {
        assert_eq!(
            clean_proxy_name("US 🇺🇸 | @Raydikalx | 085CBB"),
            "US 🇺🇸 | 085CBB"
        );
        assert_eq!(
            clean_proxy_name("🇩🇪 Germany | Join our channel | t.me/example | Node-7"),
            "🇩🇪 Germany | Node-7"
        );
        assert_eq!(clean_proxy_name("🇫🇷 Paris @proxy_news"), "🇫🇷 Paris");
    }

    #[test]
    fn parse_hysteria2_strips_advertising_from_fragment_name() {
        let proxy = parse_link(
            "hy2://099830134df5ac3a04a4b21d39b8c395@163.192.14.135:50160?insecure=1&sni=vk.com#US%20%F0%9F%87%BA%F0%9F%87%B8%20%7C%20%40Raydikalx%20%7C%20085CBB",
        )
        .unwrap();
        assert_eq!(proxy.name, "US 🇺🇸 | 085CBB");
        assert_eq!(proxy.settings["auth"], "099830134df5ac3a04a4b21d39b8c395");
        assert_eq!(proxy.settings["insecure"], true);
    }

    #[test]
    fn extract_links_decodes_html_ampersands_and_removes_invisible_chars() {
        let text = "vless://ab\u{200b}cd@example.com:443?x=1&amp;y=2\u{feff}";
        assert_eq!(
            extract_links(text),
            vec!["vless://abcd@example.com:443?x=1&y=2".to_string()]
        );
    }

    #[test]
    fn extract_links_ignores_non_links_and_trailing_delimiters() {
        assert!(extract_links("https://example.com vless:// ss://\"'").is_empty());
        assert_eq!(
            extract_links("<ss://valid-token|>"),
            vec!["ss://valid-token"]
        );
        assert_eq!(
            extract_links("wg://example.com/path]"),
            ["wg://example.com/path"]
        );
    }

    #[test]
    fn clean_link_only_removes_unmatched_closing_delimiters() {
        assert_eq!(
            clean_link("vless://node.example/path(foo))"),
            "vless://node.example/path(foo)"
        );
        assert_eq!(
            clean_link("vless://node.example/path[bar]]"),
            "vless://node.example/path[bar]"
        );
        assert_eq!(
            clean_link("vless://node.example/path(foo)"),
            "vless://node.example/path(foo)"
        );
        assert_eq!(
            clean_link("vless://node.example/path[bar]"),
            "vless://node.example/path[bar]"
        );
    }

    #[test]
    fn extracted_link_filter_checks_scheme_and_strict_minimum_length() {
        assert!(!is_extracted_link("abcdefgh"));
        assert!(!is_extracted_link("https://"));
        assert!(!is_extracted_link("ss://abc")); // exactly eight bytes
        assert!(is_extracted_link("ss://abcd")); // nine bytes
    }

    #[test]
    fn plausible_id_accepts_maximum_length_and_rejects_one_byte_over() {
        assert!(plausible_id(&"a".repeat(128)));
        assert!(!plausible_id(&"a".repeat(129)));
    }

    #[test]
    fn plausible_id_rejects_empty_short_and_non_hex_values() {
        assert!(!plausible_id(""));
        assert!(!plausible_id("0123456789abcde"));
        assert!(!plausible_id("0123456789abcdeg"));
        assert!(plausible_id("0123456789abcdef"));
    }

    #[test]
    fn normalize_flow_accepts_empty_and_case_insensitive_aliases() {
        assert_eq!(normalize_flow("").unwrap(), "");
        assert_eq!(
            normalize_flow("XTLS-RPRX-VISI").unwrap(),
            "xtls-rprx-vision"
        );
        assert_eq!(
            normalize_flow("XTLS-RPRX-VISION").unwrap(),
            "xtls-rprx-vision"
        );
        assert!(matches!(
            normalize_flow("unsupported"),
            Err(ParseErr::Invalid("bad flow"))
        ));
    }

    #[test]
    fn extract_links_recognizes_extractor_schemes_and_handles_unmatched_wrappers() {
        let text = concat!(
            "ssr://payload ",
            "hysteria2://payload ",
            "hy2://payload ",
            "hysteria://payload ",
            "tuic://payload ",
            "anytls://payload ",
            "socks://payload ",
            "socks5://payload ",
            "mierus://payload ",
            "wireguard://payload ",
            "wg://payload ",
            "(vless://node.example/path]",
        );
        assert_eq!(
            extract_links(text),
            [
                "ssr://payload",
                "hysteria2://payload",
                "hy2://payload",
                "hysteria://payload",
                "tuic://payload",
                "anytls://payload",
                "socks://payload",
                "socks5://payload",
                "mierus://payload",
                "wireguard://payload",
                "wg://payload",
                "vless://node.example/path",
            ]
        );
    }

    #[test]
    fn parse_vless_decodes_name_and_applies_defaults() {
        let link = format!("vless://{UUID}@example.com#%20Node%20");
        let proxy = parse_link(&link).unwrap();
        assert_eq!(
            (proxy.proto, proxy.host.as_str(), proxy.port),
            ("vless", "example.com", 443)
        );
        assert_eq!(proxy.name, "Node");
        assert_eq!(proxy.settings["id"], UUID);
        assert_eq!(proxy.stream.as_ref().unwrap()["network"], "raw");
        assert_eq!(proxy.stream.as_ref().unwrap()["security"], "none");
        assert_eq!(proxy.base_url, format!("vless://{UUID}@example.com"));
    }

    #[test]
    fn parse_vless_accepts_reality_and_normalizes_flow_alias() {
        let pbk = STANDARD.encode([7u8; 32]);
        let link = format!(
            "vless://{UUID}@example.com:8443?security=REALITY&pbk={pbk}&sid=a1b2&flow=xtls-rprx-visi&type=tcp#edge"
        );
        let proxy = parse_link(&link).unwrap();
        assert_eq!(proxy.port, 8443);
        assert_eq!(proxy.settings["flow"], "xtls-rprx-vision");
        let stream = proxy.stream.unwrap();
        assert_eq!(stream["network"], "raw");
        assert_eq!(stream["security"], "reality");
        assert_eq!(stream["realitySettings"]["password"], pbk);
    }

    #[test]
    fn parse_vless_accepts_current_vision_flow_variant() {
        let proxy = parse_link(&format!(
            "vless://{UUID}@example.com?security=tls&flow=xtls-rprx-vision-udp443"
        ))
        .unwrap();
        assert_eq!(proxy.settings["flow"], "xtls-rprx-vision-udp443");
    }

    #[test]
    fn parse_vless_checks_uuid_length_and_reality_parameters() {
        for id in ["a".repeat(16), "b".repeat(128)] {
            assert!(parse_link(&format!("vless://{id}@example.com")).is_ok());
        }
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "vless://{}@example.com",
                "a".repeat(129)
            ))),
            "bad uuid"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "vless://{UUID}@example.com?security=reality&pbk=bad"
            ))),
            "bad reality pbk"
        );
        let pbk = STANDARD.encode([1u8; 32]);
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "vless://{UUID}@example.com?security=reality&pbk={pbk}&sid=xyz"
            ))),
            "bad reality sid"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "vless://{UUID}@example.com?security=reality&pbk={pbk}&spx=not-absolute"
            ))),
            "bad spiderX"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "vless://{UUID}@example.com?security=unknown"
            ))),
            "bad security"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "vless://{UUID}@example.com?flow=not-a-flow&security=tls"
            ))),
            "bad flow"
        );

        for (alias, expected) in [("splithttp", "xhttp"), ("mkcp", "kcp")] {
            let proxy = parse_link(&format!("vless://{UUID}@example.com?type={alias}")).unwrap();
            assert_eq!(proxy.stream.unwrap()["network"], expected);
        }
    }

    #[test]
    fn parse_vless_validates_id_characters_ports_and_decodes_lossy_fragments() {
        for id in ["a".repeat(15), format!("{}!", "a".repeat(16))] {
            assert_eq!(
                invalid_reason(parse_link(&format!("vless://{id}@example.com"))),
                "bad uuid"
            );
        }
        assert_eq!(
            invalid_reason(parse_link(&format!("vless://{UUID}@example.com:0"))),
            "bad host/port"
        );

        let proxy = parse_link(&format!("vless://{UUID}@example.com#A%FF%20B")).unwrap();
        assert_eq!(proxy.name, "A� B");
    }

    #[test]
    fn parse_vless_auto_security_and_empty_reality_sid_use_expected_defaults() {
        let auto = parse_link(&format!(
            "vless://{UUID}@node.example?security=auto&encryption=NONE&type=tcp"
        ))
        .unwrap();
        assert_eq!(auto.stream.as_ref().unwrap()["security"], "none");
        assert_eq!(auto.settings["encryption"], "NONE");

        let pbk = STANDARD.encode([9u8; 32]);
        let reality = parse_link(&format!(
            "vless://{UUID}@node.example?security=reality&pbk={pbk}&sid=&spx=/"
        ))
        .unwrap();
        assert_eq!(reality.stream.unwrap()["realitySettings"]["shortId"], "");
    }

    #[test]
    fn parse_vmess_json_base64_and_uri_forms() {
        let json_link = vmess_json_link(
            json!({"id": UUID, "add": "vmess.example", "port": 8443, "ps": " json ", "net": "ws", "tls": "tls", "path": "/v"}),
        );
        let json_proxy = parse_link(&json_link).unwrap();
        assert_eq!(
            (json_proxy.proto, json_proxy.host.as_str(), json_proxy.port),
            ("vmess", "vmess.example", 8443)
        );
        assert_eq!(json_proxy.name, "json");
        assert_eq!(json_proxy.stream.as_ref().unwrap()["network"], "ws");

        let uri = format!("vmess://{UUID}@uri.example:443?type=ws&security=tls&path=%2Fws#uri");
        let uri_proxy = parse_link(&uri).unwrap();
        assert_eq!(uri_proxy.name, "uri");
        assert_eq!(uri_proxy.settings["id"], UUID);
        assert_eq!(uri_proxy.stream.unwrap()["network"], "ws");
    }

    #[test]
    fn parse_vmess_json_handles_non_string_fields_and_empty_defaults() {
        let link = vmess_json_link(json!({
            "id": UUID,
            "add": "vmess.example",
            "port": 8443,
            "net": "---",
            "tls": "",
            "path": true,
            "host": null,
            "sni": false,
            "fp": [],
            "alpn": 5,
            "mode": {},
            "ps": "boolean fields"
        }));

        let proxy = parse_link(&link).unwrap();
        assert_eq!(proxy.name, "boolean fields");
        assert_eq!(proxy.port, 8443, "numeric JSON port is converted to text");
        assert_eq!(proxy.stream.as_ref().unwrap()["network"], "raw");
        assert_eq!(proxy.stream.as_ref().unwrap()["security"], "none");

        let alias = vmess_json_link(json!({
            "id": UUID,
            "add": "vmess.example",
            "port": 8443,
            "net": "h2",
            "tls": "tls"
        }));
        assert!(matches!(
            parse_link(&alias),
            Err(ParseErr::Unsupported("vmess transport"))
        ));
    }

    #[test]
    fn parse_vmess_uri_validates_uuid_aid_cipher_and_normalizes_aliases() {
        assert_eq!(
            invalid_reason(parse_link("vmess://short@example.com")),
            "bad uuid"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!("vmess://{UUID}@example.com?aid=-1"))),
            "bad aid"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "vmess://{UUID}@example.com?encryption=invalid"
            ))),
            "bad cipher"
        );

        let proxy = parse_link(&format!(
            "vmess://{UUID}@example.com?type=httpupgrade&security=#alias"
        ))
        .unwrap();
        assert_eq!(proxy.name, "alias");
        assert_eq!(proxy.stream.unwrap()["network"], "httpupgrade");

        let empty_type =
            parse_link(&format!("vmess://{UUID}@example.com?type=---&security=tls")).unwrap();
        assert_eq!(empty_type.stream.unwrap()["network"], "raw");
    }

    #[test]
    fn parse_vmess_uri_strips_invisible_wrappers_and_defaults_empty_options() {
        let link = format!("vmess://\u{feff}{UUID}@node.example?type=---&security=#edge\u{200b}\n");
        let proxy = parse_link(&link).unwrap();
        assert_eq!(proxy.proto, "vmess");
        assert_eq!(proxy.name, "edge");
        assert_eq!(proxy.stream.as_ref().unwrap()["network"], "raw");
        assert_eq!(proxy.stream.unwrap()["security"], "none");
    }

    #[test]
    fn parse_vmess_accepts_current_xray_transport_names_and_aliases() {
        for (input, expected) in [
            ("tcp", "raw"),
            ("raw", "raw"),
            ("ws", "ws"),
            ("websocket", "ws"),
            ("grpc", "grpc"),
            ("gun", "grpc"),
            ("kcp", "kcp"),
            ("mkcp", "kcp"),
            ("httpupgrade", "httpupgrade"),
            ("xhttp", "xhttp"),
            ("splithttp", "xhttp"),
            ("hysteria", "hysteria"),
        ] {
            let uri = format!("vmess://{UUID}@node.example?type={input}&security=tls");
            let proxy = parse_link(&uri).unwrap_or_else(|err| panic!("{input}: {err:?}"));
            let stream = proxy.stream.unwrap();
            assert_eq!(stream["network"], expected, "{input}");
            if expected == "hysteria" {
                assert_eq!(stream["hysteriaSettings"]["version"], 2);
            }
        }
        assert_eq!(
            unsupported_proto(parse_link(&format!(
                "vmess://{UUID}@node.example?type=quic"
            ))),
            "vmess transport"
        );
    }

    #[test]
    fn parse_vmess_uri_strips_transport_control_characters_before_decoding() {
        let uri = format!("vmess://\u{feff}{UUID}@node.example?type=websocket\n#clean");
        let proxy = parse_link(&uri).unwrap();
        assert_eq!(proxy.name, "clean");
        assert_eq!(proxy.stream.unwrap()["network"], "ws");
        assert_eq!(proxy.orig_url, uri);
    }

    #[test]
    fn parse_vmess_json_rejects_missing_or_invalid_addresses_and_ports() {
        for value in [
            json!({"id": UUID, "add": "", "port": 443}),
            json!({"id": UUID, "add": "node.example", "port": 0}),
            json!({"id": UUID, "add": "node.example", "port": "not-a-port"}),
        ] {
            assert_eq!(
                invalid_reason(parse_link(&vmess_json_link(value))),
                "bad address"
            );
        }
    }

    #[test]
    fn parse_vmess_json_rejects_an_invalid_id() {
        let link = vmess_json_link(json!({
            "id": "invalid-id",
            "add": "node.example",
            "port": 443
        }));
        assert_eq!(invalid_reason(parse_link(&link)), "bad uuid");
    }

    #[test]
    fn parse_trojan_supports_peer_alias_and_defaults() {
        let proxy =
            parse_link("trojan://secret@example.org?peer=sni.example#%20secure%20").unwrap();
        assert_eq!(
            (proxy.proto, proxy.port, proxy.name.as_str()),
            ("trojan", 443, "secure")
        );
        assert_eq!(proxy.settings["password"], "secret");
        let stream = proxy.stream.unwrap();
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["serverName"], "sni.example");

        let explicit_sni =
            parse_link("trojan://secret@example.org?sni=explicit.example&peer=ignored.example")
                .unwrap();
        assert_eq!(
            explicit_sni.stream.unwrap()["tlsSettings"]["serverName"],
            "explicit.example"
        );
    }

    #[test]
    fn parse_trojan_handles_transport_aliases_and_unknown_networks() {
        for (alias, expected) in [("splithttp", "xhttp"), ("mkcp", "kcp")] {
            let proxy = parse_link(&format!("trojan://secret@example.org?type={alias}")).unwrap();
            assert_eq!(proxy.stream.unwrap()["network"], expected);
        }
        assert_eq!(
            unsupported_proto(parse_link("trojan://secret@example.org?type=unknown")),
            "trojan transport"
        );
    }

    #[test]
    fn parse_trojan_decodes_credentials_and_builds_reality_grpc_stream() {
        let pbk = STANDARD.encode([9u8; 32]);
        let proxy = parse_link(&format!(
            "trojan://s%3Aecret@node.example:8443?security=reality&pbk={pbk}&type=gun&path=%2Fsvc#secure"
        ))
        .unwrap();

        assert_eq!(proxy.settings["password"], "s:ecret");
        assert_eq!(proxy.name, "secure");
        assert_eq!(proxy.stream.as_ref().unwrap()["network"], "grpc");
        assert_eq!(proxy.stream.unwrap()["grpcSettings"]["serviceName"], "svc");
    }

    #[test]
    fn parse_trojan_decodes_credentials_and_accepts_reality_over_grpc() {
        let proxy = parse_link(
            "trojan://p%40ss%3Aword@node.example:8443?security=reality&type=gun&pbk=public-key&sni=front.example",
        )
        .unwrap();
        assert_eq!(proxy.settings["password"], "p@ss:word");
        assert_eq!(proxy.stream.as_ref().unwrap()["security"], "reality");
        assert_eq!(proxy.stream.as_ref().unwrap()["network"], "grpc");
        assert_eq!(
            proxy.stream.unwrap()["realitySettings"]["serverName"],
            "front.example"
        );
    }

    #[test]
    fn vmess_http_and_h2_are_not_misreported_as_xhttp() {
        for network in ["http", "h2"] {
            let legacy_json = vmess_json_link(json!({
                "id": UUID,
                "add": "vmess.example",
                "port": 443,
                "net": network,
            }));
            assert!(matches!(
                parse_link(&legacy_json),
                Err(ParseErr::Unsupported("vmess transport"))
            ));
            assert!(matches!(
                parse_link(&format!("vmess://{UUID}@vmess.example:443?type={network}")),
                Err(ParseErr::Unsupported("vmess transport"))
            ));
        }
    }

    #[test]
    fn shadowsocks_plugin_links_are_not_silently_parsed_without_the_plugin() {
        let link = "ss://YWVzLTI1Ni1nY206cGFzcw==@node.example:8388?plugin=obfs-local%3Bobfs%3Dtls";
        assert!(matches!(
            parse_link(link),
            Err(ParseErr::Unsupported("ss plugin"))
        ));
    }

    #[test]
    fn parse_hysteria1_and_hysteria2_uri_forms() {
        let v1 = parse_link(
            "hysteria://node.example:8443?auth=token&protocol=wechat-video&peer=sni.example&insecure=1&upmbps=20&downmbps=100#H1",
        )
        .unwrap();
        assert_eq!(v1.proto, "hysteria");
        assert_eq!((v1.host.as_str(), v1.port), ("node.example", 8443));
        assert_eq!(v1.name, "H1");
        assert_eq!(v1.settings["version"], 1);
        assert_eq!(v1.settings["auth"], "token");
        assert_eq!(v1.settings["protocol"], "wechat-video");
        assert_eq!(v1.settings["peer"], "sni.example");
        assert_eq!(v1.settings["insecure"], true);
        assert_eq!(v1.settings["upmbps"], 20);
        assert_eq!(v1.settings["downmbps"], 100);
        assert!(v1.stream.is_none());

        let v2 = parse_link(
            "hy2://my%3Asecret@node.example?sni=front.example&obfs=salamander&obfs-password=hidden&insecure=0&pinSHA256=abcd&ech=encoded#H2%20node",
        )
        .unwrap();
        assert_eq!(v2.proto, "hysteria2");
        assert_eq!(v2.name, "H2 node");
        assert_eq!(v2.settings["version"], 2);
        assert_eq!(v2.settings["auth"], "my:secret");
        assert_eq!(v2.settings["serverName"], "front.example");
        assert_eq!(v2.settings["obfs"], "salamander");
        assert_eq!(v2.settings["obfs-password"], "hidden");
        assert_eq!(v2.settings["insecure"], false);
        assert_eq!(v2.settings["pinSHA256"], "abcd");
        assert_eq!(v2.stream.as_ref().unwrap()["network"], "hysteria");
        assert_eq!(
            v2.stream.as_ref().unwrap()["tlsSettings"]["allowInsecure"],
            false
        );

        let default_port = parse_link("hysteria2://password@node.example").unwrap();
        assert_eq!(default_port.port, 443);
    }

    #[test]
    fn parse_hysteria2_preserves_plus_and_supports_authority_port_hopping() {
        let proxy = parse_link(
            "hysteria2://token+with%2Bplus@hy2.example:443,5000-6000/?obfs=salamander&obfs-password=mask+pass#hopping",
        )
        .unwrap();

        assert_eq!((proxy.host.as_str(), proxy.port), ("hy2.example", 443));
        assert_eq!(proxy.settings["auth"], "token+with+plus");
        assert_eq!(proxy.settings["ports"], "443,5000-6000");
        assert_eq!(proxy.settings["obfs-password"], "mask+pass");
        let stream = proxy.stream.unwrap();
        assert_eq!(stream["finalmask"]["udp"].as_array().unwrap().len(), 2);
        assert_eq!(stream["finalmask"]["udp"][0]["type"], "salamander");
        assert_eq!(stream["finalmask"]["udp"][1]["type"], "udphop");
        assert_eq!(
            stream["finalmask"]["udp"][1]["settings"]["remotePorts"],
            "443,5000-6000"
        );

        for ports in ["0,443", "6000-5000", "443,invalid"] {
            let link = format!("hy2://password@hy2.example:{ports}");
            assert!(parse_link(&link).is_err(), "invalid hopping ports: {ports}");
        }
    }

    #[test]
    fn parse_hysteria2_query_ports_and_ipv6_build_udp_hop_mask() {
        let proxy = parse_link(
            "hy2://pw@[2001:db8::1]?ports=20000-20010,30000&obfs=salamander&obfs_password=mask",
        )
        .unwrap();

        assert_eq!(proxy.host, "[2001:db8::1]");
        assert_eq!(proxy.port, 443);
        assert_eq!(proxy.settings["ports"], "20000-20010,30000");
        assert_eq!(proxy.settings["obfs-password"], "mask");
        assert_eq!(
            proxy.stream.unwrap()["finalmask"]["udp"],
            json!([
                {"type":"salamander", "settings":{"password":"mask"}},
                {"type":"udphop", "settings":{"mode":"intervallocal", "interval":"30", "remotePorts":"20000-20010,30000"}}
            ])
        );
    }

    #[test]
    fn parse_hysteria1_accepts_legacy_auth_alias_and_username_fallback() {
        let alias =
            parse_link("hysteria://node.example:443?auth_str=from-query&upmbps=1&downmbps=2")
                .unwrap();
        assert_eq!(alias.settings["auth"], "from-query");

        let username =
            parse_link("hysteria://from-userinfo@node.example:443?upmbps=1&downmbps=2").unwrap();
        assert_eq!(username.settings["auth"], "from-userinfo");
    }

    #[test]
    fn parse_hysteria2_query_ports_and_empty_optional_parameters_are_handled() {
        let proxy = parse_link(
            "hy2://@hy2.example?ports=2000-2010,3000&obfs_password=mask&sni=&insecure=false&pinSHA256=&ech=",
        )
        .unwrap();
        assert_eq!(proxy.settings["auth"], "");
        assert_eq!(proxy.settings["ports"], "2000-2010,3000");
        assert_eq!(proxy.settings["obfs-password"], "mask");
        assert_eq!(proxy.settings["insecure"], false);
        assert!(proxy.settings.get("serverName").is_none());
        assert!(proxy.settings.get("pinSHA256").is_none());
        assert_eq!(
            proxy.stream.unwrap()["finalmask"]["udp"][0]["type"],
            "udphop"
        );

        // Query-form port lists are copied as supplied to the hop finalmask.
        let fallback = parse_link("hy2://pw@hy2.example?ports=invalid").unwrap();
        assert_eq!(fallback.settings["ports"], "invalid");
        assert_eq!(
            fallback.stream.unwrap()["finalmask"]["udp"][0]["settings"]["remotePorts"],
            "invalid"
        );
    }

    #[test]
    fn parse_hysteria2_skips_empty_and_malformed_query_components() {
        let proxy = parse_link("hy2://pw@hy2.example?&bare&%FF=value&bad=%FF").unwrap();

        assert_eq!(proxy.settings["auth"], "pw");
        assert!(proxy.settings.get("ports").is_none());
        assert!(proxy.settings.get("serverName").is_none());
        assert!(proxy.stream.unwrap()["tlsSettings"]
            .as_object()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn parse_hysteria1_covers_auth_aliases_defaults_and_required_bandwidth_errors() {
        for key in ["auth-str", "auth_str"] {
            let proxy = parse_link(&format!(
                "hysteria://node.example:443?{key}=token&upmbps=1&downmbps=2"
            ))
            .unwrap();
            assert_eq!(proxy.settings["auth"], "token", "{key}");
            assert_eq!(proxy.settings["protocol"], "udp");
            assert_eq!(proxy.settings["insecure"], false);
            assert_eq!(proxy.settings["obfs"], "");
        }

        for (query, expected) in [
            ("", "missing hysteria bandwidth"),
            ("upmbps=1", "missing hysteria bandwidth"),
            ("upmbps=bad&downmbps=2", "bad hysteria bandwidth"),
            ("upmbps=1&downmbps=0", "bad hysteria bandwidth"),
        ] {
            let link = format!("hysteria://node.example:443?{query}");
            assert_eq!(invalid_reason(parse_link(&link)), expected, "{query}");
        }
    }

    #[test]
    fn parse_hysteria_rejects_malformed_auth_obfs_security_and_bandwidth() {
        for (link, expected) in [
            (
                "hy2://pass@node.example?obfs=unknown&obfs-password=x",
                "bad hysteria2 obfs",
            ),
            (
                "hy2://pass@node.example?obfs=salamander",
                "empty hysteria2 obfs password",
            ),
            (
                "hy2://pass@node.example?insecure=2",
                "bad hysteria insecure",
            ),
            (
                "hysteria://node.example:443?protocol=unknown&upmbps=1&downmbps=1",
                "bad hysteria protocol",
            ),
            (
                "hysteria://node.example:443?upmbps=0&downmbps=1",
                "bad hysteria bandwidth",
            ),
            (
                "hysteria://node.example:443?upmbps=1&downmbps=fast",
                "bad hysteria bandwidth",
            ),
            (
                "hysteria://node.example:443?upmbps=1",
                "missing hysteria bandwidth",
            ),
            (
                "hysteria://node.example?upmbps=1&downmbps=1",
                "missing hysteria port",
            ),
            (
                "hysteria://node.example:443?upmbps=1&downmbps=1&obfs=unknown",
                "bad hysteria obfs",
            ),
        ] {
            assert_eq!(invalid_reason(parse_link(link)), expected, "{link}");
        }
    }

    #[test]
    fn host_port_rejects_missing_hosts_and_port_zero() {
        let no_host = Url::parse("file:///tmp/proxy").unwrap();
        assert!(matches!(
            host_port(&no_host, 443),
            Err(ParseErr::Invalid("no host"))
        ));

        let zero_port = Url::parse("vless://example.com:0").unwrap();
        assert!(matches!(
            host_port(&zero_port, 443),
            Err(ParseErr::Invalid("bad host/port"))
        ));
    }

    #[test]
    fn parse_ss_accepts_plain_userinfo_credentials() {
        let proxy = parse_link("ss://aes-128-gcm%3Aplain@example.org:8388").unwrap();
        assert_eq!(proxy.settings["method"], "aes-128-gcm");
        assert_eq!(proxy.settings["password"], "plain");
    }

    #[test]
    fn parse_hysteria2_builds_xray_stream_and_preserves_optional_settings() {
        let proxy = parse_link(
            "hysteria2://my%3Asecret@hy2.example:8443?obfs=salamander&obfs-password=mask&sni=cdn.example&insecure=1&pinSHA256=pin&ech=ech-list#edge",
        )
        .unwrap();
        assert_eq!(proxy.proto, "hysteria2");
        assert_eq!((proxy.host.as_str(), proxy.port), ("hy2.example", 8443));
        assert_eq!(proxy.settings["address"], "hy2.example");
        assert_eq!(proxy.settings["port"], 8443);
        assert_eq!(proxy.settings["auth"], "my:secret");
        assert_eq!(proxy.settings["obfs"], "salamander");
        assert_eq!(proxy.settings["obfs-password"], "mask");
        assert_eq!(proxy.settings["serverName"], "cdn.example");
        assert_eq!(proxy.settings["insecure"], true);
        assert_eq!(proxy.settings["pinSHA256"], "pin");
        assert_eq!(proxy.settings["ech"], "ech-list");

        let stream = proxy.stream.unwrap();
        assert_eq!(stream["network"], "hysteria");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["serverName"], "cdn.example");
        assert_eq!(stream["tlsSettings"]["allowInsecure"], true);
        assert_eq!(stream["tlsSettings"]["pinnedPeerCertSha256"], "pin");
        assert_eq!(stream["tlsSettings"]["echConfigList"], "ech-list");
        assert_eq!(
            stream["hysteriaSettings"],
            json!({"version": 2, "auth": "my:secret"})
        );
    }

    #[test]
    fn parse_hysteria2_alias_defaults_and_optional_tls_shape() {
        let proxy = parse_link("hy2://password@hy2.example#default").unwrap();
        assert_eq!(proxy.proto, "hysteria2");
        assert_eq!(proxy.port, 443);
        assert_eq!(proxy.settings["auth"], "password");
        assert_eq!(
            proxy.stream.unwrap(),
            json!({
                "network": "hysteria",
                "security": "tls",
                "tlsSettings": {},
                "hysteriaSettings": {"version": 2, "auth": "password"}
            })
        );

        let userpass = parse_link("hy2://user:pass@hy2.example").unwrap();
        assert_eq!(
            userpass.stream.unwrap()["hysteriaSettings"]["auth"],
            "user:pass"
        );

        let gecko = parse_link("hy2://password@hy2.example?obfs=gecko").unwrap();
        assert_eq!(gecko.settings["obfs"], "gecko");
        assert!(gecko.settings.get("obfs-password").is_none());
    }

    #[test]
    fn parse_hysteria1_preserves_mihomo_fields_and_requires_explicit_port() {
        let proxy = parse_link(
            "hysteria://hy1.example:5678?auth=secret&peer=sni.example&insecure=1&obfs=xplus&obfsParam=mask&upmbps=100&downmbps=250&protocol=wechat-video&alpn=hysteria#legacy",
        )
        .unwrap();
        assert_eq!(proxy.proto, "hysteria");
        assert_eq!(proxy.stream, None);
        assert_eq!(proxy.settings["address"], "hy1.example");
        assert_eq!(proxy.settings["port"], 5678);
        assert_eq!(proxy.settings["auth"], "secret");
        assert_eq!(proxy.settings["peer"], "sni.example");
        assert_eq!(proxy.settings["insecure"], true);
        assert_eq!(proxy.settings["protocol"], "wechat-video");
        assert_eq!(proxy.settings["obfs"], "xplus");
        assert_eq!(proxy.settings["obfsParam"], "mask");
        assert_eq!(proxy.settings["upmbps"], 100);
        assert_eq!(proxy.settings["downmbps"], 250);
        assert_eq!(proxy.settings["alpn"], "hysteria");
        assert_eq!(
            invalid_reason(parse_link("hysteria://hy1.example")),
            "missing hysteria port"
        );
    }

    #[test]
    fn parse_hysteria_rejects_invalid_auth_obfs_protocol_and_bandwidth() {
        for link in [
            "hysteria://host.example:443?protocol=unknown",
            "hysteria://host.example:443?obfs=unknown",
            "hysteria://host.example:443?upmbps=0",
            "hysteria2://pw@host.example?obfs=salamander",
            "hysteria2://pw@host.example?insecure=maybe",
            "hysteria2://pw@host.example?obfs=unknown",
        ] {
            assert!(
                matches!(parse_link(link), Err(ParseErr::Invalid(_))),
                "expected invalid URI: {link}"
            );
        }
        assert_eq!(
            invalid_reason(parse_link("hysteria://host.example:443?insecure=maybe")),
            "bad hysteria insecure"
        );
    }

    #[test]
    fn parse_ss_normalizes_all_xray_aead_cipher_aliases() {
        for (input, expected) in [
            ("aead_aes_128_gcm", "aes-128-gcm"),
            ("AEAD_AES_256_GCM", "aes-256-gcm"),
            ("aead_chacha20_poly1305", "chacha20-ietf-poly1305"),
            ("aead_xchacha20_poly1305", "xchacha20-ietf-poly1305"),
            ("chacha20-poly1305", "chacha20-ietf-poly1305"),
            ("xchacha20-poly1305", "xchacha20-ietf-poly1305"),
            ("2022-blake3-aes-128-gcm", "2022-blake3-aes-128-gcm"),
            ("2022-blake3-aes-256-gcm", "2022-blake3-aes-256-gcm"),
            (
                "2022-blake3-chacha20-poly1305",
                "2022-blake3-chacha20-poly1305",
            ),
        ] {
            let link = format!("ss://{input}%3Asecret@ss.example:8388");
            let proxy = parse_link(&link).unwrap_or_else(|err| panic!("{input}: {err:?}"));
            assert_eq!(proxy.settings["method"], expected, "{input}");
        }
    }

    #[test]
    fn parse_ss_accepts_every_cipher_supported_by_mihomo_export() {
        for method in crate::outbound::SS_MIHOMO_ONLY_METHODS {
            let link = format!("ss://{method}%3Asecret@ss.example:8388");
            let proxy = parse_link(&link).unwrap_or_else(|err| panic!("{method}: {err:?}"));
            assert_eq!(proxy.settings["method"], *method, "{method}");
        }
    }

    #[test]
    fn parse_ss_supports_userinfo_and_base64_variants() {
        let auth = STANDARD.encode("aes-128-gcm:pass");
        let uri = parse_link(&format!("ss://{auth}@example.org:8388#%20plain%20")).unwrap();
        assert_eq!(
            (uri.proto, uri.host.as_str(), uri.port, uri.name.as_str()),
            ("shadowsocks", "example.org", 8388, "plain")
        );
        assert_eq!(uri.settings["password"], "pass");

        let legacy = format!(
            "ss://{}",
            STANDARD.encode("aes-128-gcm:legacy@[2001:db8::1]:443")
        );
        let proxy = parse_link(&legacy).unwrap();
        assert_eq!(proxy.host, "2001:db8::1");
        assert_eq!(proxy.port, 443);
        assert_eq!(proxy.name, "ss");

        let userinfo = STANDARD.encode("aes-128-gcm:encoded");
        let encoded = parse_link(&format!("ss://{userinfo}@encoded.example:8388")).unwrap();
        assert_eq!(encoded.host, "encoded.example");
        assert_eq!(encoded.settings["password"], "encoded");
    }

    #[test]
    fn shadowsocks_method_extraction_matches_plain_and_base64_parse_forms() {
        let plain =
            ss_method_password_host_port("ss://aes-128-gcm%3Aplain-secret@plain.example:8388")
                .unwrap();
        assert_eq!(plain.0, "aes-128-gcm");

        let auth = STANDARD.encode("aes-128-gcm:encoded-secret");
        let base64_userinfo =
            ss_method_password_host_port(&format!("ss://{auth}@userinfo.example:8388")).unwrap();
        assert_eq!(base64_userinfo.0, "aes-128-gcm");

        let payload = STANDARD.encode("aes-128-gcm:legacy-secret@legacy.example:8388");
        let base64_payload = ss_method_password_host_port(&format!("ss://{payload}")).unwrap();
        assert_eq!(base64_payload.0, "aes-128-gcm");
    }

    #[test]
    fn shadowsocks_empty_method_is_invalid_and_reported_as_empty() {
        assert_eq!(
            invalid_reason(parse_link("ss://%3Asecret@node.example:8388")),
            "empty ss method"
        );
        assert_eq!(
            unsupported_reason_key("ss://%3Asecret@node.example:8388", "ss method"),
            "ss: method=empty"
        );
    }

    #[test]
    fn parse_ss_rejects_malformed_userinfo_and_legacy_address_fields() {
        for (link, expected) in [
            ("ss://not-base64!@example.org:8388", "bad ss userinfo"),
            (
                "ss://YWJj@example.org:8388",
                "ss userinfo missing method separator",
            ),
            (
                "ss://YWVzLTI1Ni1nY206cGFzcw==@example.org",
                "bad ss address",
            ),
            ("ss://", "bad ss base64"),
        ] {
            assert_eq!(invalid_reason(parse_link(link)), expected, "{link}");
        }

        for payload in ["aes-128-gcm:pass@host:0", "aes-128-gcm:pass@host:nope"] {
            let link = format!("ss://{}", STANDARD.encode(payload));
            assert_eq!(
                invalid_reason(parse_link(&link)),
                "bad ss address",
                "{payload}"
            );
        }
    }

    #[test]
    fn parse_link_reports_invalid_boundaries_and_transport_errors() {
        assert_eq!(
            invalid_reason(parse_link("vless://short@example.com")),
            "bad uuid"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "vless://{UUID}@example.com?encryption=aes"
            ))),
            "bad encryption"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "vless://{UUID}@example.com?flow=xtls-rprx-vision"
            ))),
            "flow without tls"
        );
        assert_eq!(
            invalid_reason(parse_link("trojan://@example.com")),
            "empty password"
        );
        assert_eq!(
            invalid_reason(parse_link("trojan://pw@example.com?security=none")),
            "bad security"
        );
        assert_eq!(
            unsupported_proto(parse_link(&format!(
                "vless://{UUID}@example.com?type=unknown"
            ))),
            "vless transport"
        );
        assert_eq!(
            invalid_reason(parse_link("vmess://not-base64!")),
            "bad vmess base64"
        );
        assert_eq!(
            invalid_reason(parse_link("ss://not-base64!")),
            "bad ss base64"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!(
                "ss://{}@example.com:0",
                STANDARD.encode("aes-128-gcm:pw")
            ))),
            "bad ss address"
        );
        assert_eq!(
            unsupported_proto(parse_link(&format!(
                "ss://{}@example.com:8388",
                STANDARD.encode("unsupported:pw")
            ))),
            "ss method"
        );
        assert_eq!(invalid_reason(parse_link("vmess://e30=")), "bad uuid");
        assert_eq!(
            invalid_reason(parse_link(&vmess_json_link(json!({"id": UUID})))),
            "bad address"
        );
        assert_eq!(
            invalid_reason(parse_link(&vmess_json_link(
                json!({"id": UUID, "add": "host", "port": 443, "scy": "invalid"})
            ))),
            "bad cipher"
        );
        assert_eq!(
            invalid_reason(parse_link("ss://YWVz")),
            "ss legacy missing endpoint separator"
        );
    }

    #[test]
    fn parse_vmess_and_legacy_ss_report_malformed_payload_shapes() {
        assert_eq!(
            invalid_reason(parse_link(&format!("vmess://{}", STANDARD.encode("{{")))),
            "bad vmess json"
        );
        assert_eq!(
            invalid_reason(parse_link(&format!("vmess://{}", STANDARD.encode("[]")))),
            "vmess not object"
        );

        for (payload, expected) in [
            ("cipher-only@host:443", "ss legacy missing method separator"),
            ("cipher:password@host", "ss legacy missing port"),
            ("cipher:password@", "ss legacy missing port"),
        ] {
            let link = format!("ss://{}", STANDARD.encode(payload));
            assert_eq!(invalid_reason(parse_link(&link)), expected, "{payload}");
        }
    }

    #[test]
    fn parse_vmess_reports_unsupported_transport_in_uri_and_json_forms() {
        assert_eq!(
            unsupported_proto(parse_link(&format!(
                "vmess://{UUID}@node.example?type=quic"
            ))),
            "vmess transport"
        );

        let link = vmess_json_link(json!({
            "id": UUID,
            "add": "node.example",
            "port": 443,
            "net": "quic"
        }));
        assert_eq!(unsupported_proto(parse_link(&link)), "vmess transport");
    }

    #[test]
    fn parse_link_classifies_protocols_case_insensitively() {
        for (link, expected) in [
            ("ssr://anything", "ssr"),
            ("tuic://anything", "tuic"),
            ("anytls://anything", "anytls"),
            ("custom://anything", "other"),
        ] {
            assert_eq!(unsupported_proto(parse_link(link)), expected, "{link}");
        }
        assert_eq!(
            parse_link("hysteria2://anything").unwrap().proto,
            "hysteria2"
        );
        assert_eq!(parse_link("hy2://anything").unwrap().proto, "hysteria2");
        assert_eq!(
            parse_link(&format!("VLESS://{UUID}@example.com"))
                .unwrap()
                .proto,
            "vless"
        );
    }

    #[test]
    fn parse_all_deduplicates_by_outbound_and_counts_errors() {
        let vless = format!("vless://{UUID}@example.com#first");
        let same_outbound = format!("vless://{UUID}@example.com#second");
        let distinct = format!("vless://{UUID}@other.example");
        let (proxies, stats) = parse_all(vec![
            vless,
            same_outbound,
            distinct,
            "vless://bad@example.com".into(),
            "tuic://unsupported".into(),
            "hysteria2://unsupported".into(),
        ]);

        assert_eq!(proxies.len(), 3);
        assert_eq!(proxies[0].name, "first");
        assert_eq!(stats.links, 6);
        assert_eq!(stats.parsed, 3);
        assert_eq!(stats.duplicates, 1);
        assert_eq!(stats.invalid, 1);
        assert_eq!(stats.invalid_reasons.get("bad uuid"), Some(&1));
        assert_eq!(stats.unsupported.get("tuic"), Some(&1));
        assert_eq!(stats.unsupported.get("hysteria2"), None);
    }

    #[test]
    fn unsupported_details_count_exact_transport_values_deterministically() {
        let (proxies, stats) = parse_all(vec![
            format!("vmess://{UUID}@node.example?type=quic"),
            format!("vmess://{UUID}@node.example?type=unknown"),
            format!("vmess://{UUID}@node.example?type=quic"),
        ]);

        assert!(proxies.is_empty());
        assert_eq!(stats.unsupported_details["vmess: transport=quic"], 2);
        assert_eq!(stats.unsupported_details["vmess: transport=unknown"], 1);
        assert_eq!(
            stats
                .unsupported_details
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["vmess: transport=quic", "vmess: transport=unknown"]
        );
    }

    #[test]
    fn unsupported_reason_labels_do_not_copy_credentials_or_other_query_secrets() {
        let reason = unsupported_reason_key(
            &format!("vmess://{UUID}:password@node.example?type=QuIc&token=secret#private"),
            "vmess transport",
        );

        assert_eq!(reason, "vmess: transport=QuIc");
        for secret in ["password", "token", "secret", "private", "node.example"] {
            assert!(!reason.contains(secret));
        }
    }

    #[test]
    fn unsupported_shadowsocks_reason_reports_only_the_exact_cipher_name() {
        let (proxies, stats) = parse_all(vec![
            "ss://not-a-real-cipher%3Aplain-secret@plain.example:8388?token=query-secret#private-name".into(),
            format!(
                "ss://{}@userinfo.example:8388?token=query-secret#private-name",
                STANDARD.encode("not-a-real-cipher:base64-secret")
            ),
            format!(
                "ss://{}?token=query-secret#private-name",
                STANDARD.encode("not-a-real-cipher:legacy-secret@legacy.example:8388")
            ),
        ]);

        assert!(proxies.is_empty());
        assert_eq!(stats.unsupported_details["ss: method=not-a-real-cipher"], 3);
        let reason = stats.unsupported_details.keys().next().unwrap();
        for secret in [
            "plain-secret",
            "base64-secret",
            "legacy-secret",
            "token",
            "query-secret",
            "private-name",
            "plain.example",
            "userinfo.example",
            "legacy.example",
        ] {
            assert!(!reason.contains(secret));
        }
    }

    #[test]
    fn unsupported_shadowsocks_reason_distinguishes_literal_unknown_from_nonstandard() {
        assert_eq!(
            unsupported_reason_key("ss://unknown%3Asecret@host.example:8388", "ss method"),
            "ss: method=unknown"
        );
        assert_eq!(
            unsupported_reason_key(
                "ss://custom%21cipher%3Asecret@host.example:8388",
                "ss method"
            ),
            "ss: method=nonstandard"
        );
    }

    #[test]
    fn parse_all_deduplicates_only_equal_outbound_settings_and_streams() {
        let same_outbound_different_fragment = format!("vless://{UUID}@example.com#renamed");
        let different_transport = format!("vless://{UUID}@example.com?type=ws#ws");
        let different_port = format!("vless://{UUID}@example.com:8443#port");
        let input = vec![
            format!("vless://{UUID}@example.com#first"),
            same_outbound_different_fragment,
            different_transport,
            different_port,
            format!("vless://{UUID}@example.com#again"),
        ];

        let (proxies, stats) = parse_all(input);
        assert_eq!(proxies.len(), 3);
        assert_eq!(proxies[0].name, "first");
        assert_eq!(proxies[1].stream.as_ref().unwrap()["network"], "ws");
        assert_eq!(proxies[2].settings["port"], 8443);
        assert_eq!(stats.links, 5);
        assert_eq!(stats.parsed, 3);
        assert_eq!(stats.duplicates, 2);
        assert_eq!(stats.invalid, 0);
        assert!(stats.unsupported.is_empty());
    }

    #[test]
    fn parse_all_empty_input_has_zeroed_stats() {
        let (proxies, stats) = parse_all(Vec::new());
        assert!(proxies.is_empty());
        assert_eq!(stats.links, 0);
        assert_eq!(stats.parsed, 0);
        assert_eq!(stats.duplicates, 0);
        assert_eq!(stats.invalid, 0);
        assert!(stats.invalid_reasons.is_empty());
        assert!(stats.unsupported.is_empty());
    }
    #[test]
    fn parse_assertion_helpers_report_unexpected_result_variants() {
        let valid = parse_link(&format!("vless://{UUID}@example.com")).unwrap();
        assert!(std::panic::catch_unwind(|| invalid_reason(Ok(valid.clone()))).is_err());
        assert!(std::panic::catch_unwind(|| {
            invalid_reason(Err(ParseErr::Unsupported("unexpected")))
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| unsupported_proto(Ok(valid))).is_err());
        assert!(std::panic::catch_unwind(|| {
            unsupported_proto(Err(ParseErr::Invalid("unexpected")))
        })
        .is_err());
    }

    #[test]
    fn deterministic_malformed_uri_corpus_never_panics() {
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for case in 0..2_000 {
            let len = (next(&mut state) % 192) as usize;
            let mut input = String::with_capacity(len + 10);
            input.push_str(match case % 4 {
                0 => "vless://",
                1 => "vmess://",
                2 => "trojan://",
                _ => "ss://",
            });
            for _ in 0..len {
                input.push(char::from(next(&mut state) as u8));
            }
            assert!(
                std::panic::catch_unwind(|| parse_link(&input)).is_ok(),
                "case {case}"
            );
        }
    }

    #[test]
    fn deterministic_uri_mutations_keep_parse_and_dedup_accounting_consistent() {
        let base = format!("vless://{UUID}@example.org:443?type=tcp#seed");
        let mut state = 0xbb67_ae85_84ca_a73bu64;
        let mut links = Vec::with_capacity(514);
        for case in 0..512 {
            let mut candidate = base.clone();
            let position = (next(&mut state) as usize) % candidate.len();
            candidate.replace_range(
                position..position + 1,
                &char::from(next(&mut state) as u8).to_string(),
            );
            if case % 7 == 0 {
                candidate.push_str("%GG");
            }
            links.push(candidate);
        }
        links.extend([base.clone(), base]);

        let total = links.len();
        let (proxies, stats) = parse_all(links);
        assert_eq!(stats.links, total);
        assert_eq!(
            stats.parsed
                + stats.duplicates
                + stats.invalid
                + stats.unsupported.values().sum::<usize>(),
            total
        );
        assert_eq!(proxies.len(), stats.parsed);
    }

    #[test]
    fn deterministic_property_like_inputs_never_panic_during_extraction_or_parsing() {
        let atoms = [
            "vless://",
            "VMESS://",
            "trojan://",
            "ss://",
            "@",
            ":0",
            "%",
            "%GG",
            "#",
            "?type=",
            "&amp;",
            "\u{200b}",
            "\u{feff}",
            "\u{fffd}",
            "[::1]",
            "\\",
            "\"",
            "'",
            "<",
            ">",
            "(",
            ")",
            "]",
            "|",
            "\n",
            "\r",
            "\t",
            "💥",
        ];
        let mut state = 0x3c6e_f372_fe94_f82bu64;
        let mut corpus = Vec::new();
        for case in 0..512 {
            let mut value = String::new();
            for _ in 0..(next(&mut state) % 12 + 1) {
                value.push_str(atoms[(next(&mut state) as usize) % atoms.len()]);
            }
            if case % 2 == 0 {
                value.insert_str(0, "vless://");
            } else if case % 3 == 0 {
                value.insert_str(0, "ss://");
            }
            assert!(
                std::panic::catch_unwind(|| extract_links(&value)).is_ok(),
                "extract case {case}: {value:?}"
            );
            assert!(
                std::panic::catch_unwind(|| parse_link(&value)).is_ok(),
                "parse case {case}: {value:?}"
            );
            corpus.push(value);
        }

        let total = corpus.len();
        let (proxies, stats) = parse_all(corpus);
        assert_eq!(stats.links, total);
        assert_eq!(
            stats.parsed
                + stats.duplicates
                + stats.invalid
                + stats.unsupported.values().sum::<usize>(),
            total
        );
        assert_eq!(proxies.len(), stats.parsed);
    }

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }
}
