//! Generate a complete sing-box JSON config from xray-shaped proxy records.
//!
//! This crate is intentionally self-contained and performs no I/O. Conversion
//! is allowlist-based: if a non-empty input option cannot be represented
//! without changing its meaning, that node is skipped with a reason.
//!
//! Supported mappings: VLESS (TCP/raw, WS, gRPC, HTTP, HTTPUpgrade; TLS and
//! Reality), VMess (the same V2Ray transports and TLS), Shadowsocks methods
//! accepted by sing-box (without SIP003 plugins), Trojan (the same transports
//! and TLS), Hysteria v1 (UDP mode), and Hysteria2 (TLS, Salamander or Gecko).
//! V2Ray mKCP, V2Ray QUIC, XHTTP/SplitHTTP, SSR, plugin options, unknown fields,
//! and settings without a behavior-preserving sing-box equivalent are skipped.

use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::HashSet;

/// One proxy in the same input shape used by `proxy-clash`.
#[derive(Clone, Debug)]
pub struct Source {
    /// vless | vmess | trojan | shadowsocks | hysteria | hysteria2
    pub proto: String,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub country: String,
    /// Xray outbound `settings` object.
    pub settings: Value,
    /// Xray `streamSettings` object, when present.
    pub stream: Option<Value>,
}

/// Listener options for the complete generated config.
#[derive(Clone, Debug)]
pub struct Options {
    /// Address for the local mixed (SOCKS/HTTP) inbound.
    pub listen: String,
    pub listen_port: u16,
    /// Include a selector with all converted nodes and a direct fallback.
    pub include_selector: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1".into(),
            listen_port: 2080,
            include_selector: true,
        }
    }
}

/// Per-input-node conversion result, retaining source identity and reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeResult {
    pub name: String,
    pub protocol: String,
    pub tag: Option<String>,
    pub reason: Option<String>,
}

/// Summary of generated and skipped nodes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub supported: Vec<NodeResult>,
    pub skipped_nodes: Vec<NodeResult>,
}

impl Report {
    pub fn supported_count(&self) -> usize {
        self.supported.len()
    }

    pub fn skipped_count(&self) -> usize {
        self.skipped_nodes.len()
    }
}

/// Convert sources into a pretty-printed, complete sing-box JSON configuration.
pub fn render(sources: &[Source], options: &Options) -> anyhow::Result<(String, Report)> {
    anyhow::ensure!(
        !options.listen.trim().is_empty(),
        "mixed inbound listen address is empty"
    );
    anyhow::ensure!(
        options.listen_port != 0,
        "mixed inbound listen port must be nonzero"
    );
    let mut report = Report::default();
    let mut outbounds = Vec::with_capacity(sources.len() + 2);
    let mut tags = HashSet::new();

    for source in sources {
        let name = if source.name.trim().is_empty() {
            format!("{}:{}", source.server, source.port)
        } else {
            source.name.trim().to_owned()
        };
        match convert(source) {
            Ok(mut outbound) => {
                let tag = unique_tag(&name, &mut tags);
                outbound["tag"] = Value::String(tag.clone());
                outbounds.push(outbound);
                report.supported.push(NodeResult {
                    name,
                    protocol: source.proto.clone(),
                    tag: Some(tag),
                    reason: None,
                });
            }
            Err(reason) => report.skipped_nodes.push(NodeResult {
                name,
                protocol: source.proto.clone(),
                tag: None,
                reason: Some(reason),
            }),
        }
    }

    let node_tags: Vec<String> = report
        .supported
        .iter()
        .filter_map(|node| node.tag.clone())
        .collect();
    let mut final_outbound = "direct".to_owned();
    if options.include_selector && !node_tags.is_empty() {
        let mut selector_tags = node_tags.clone();
        selector_tags.push("direct".into());
        outbounds.push(json!({
            "type": "selector",
            "tag": "proxy",
            "outbounds": selector_tags,
            "default": node_tags[0]
        }));
        final_outbound = "proxy".into();
    }
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));

    let config = json!({
        "log": { "level": "info" },
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": options.listen,
            "listen_port": options.listen_port
        }],
        "outbounds": outbounds,
        "route": { "final": final_outbound }
    });
    Ok((serde_json::to_string_pretty(&config)?, report))
}

fn unique_tag(name: &str, used: &mut HashSet<String>) -> String {
    let base: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_ .".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim()
        .replace(' ', "_");
    let base = if base.is_empty() { "proxy" } else { &base };
    if used.insert(base.to_owned()) {
        return base.to_owned();
    }
    for n in 2u64.. {
        let candidate = format!("{base}_{n}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("unique suffix space exhausted")
}

fn convert(source: &Source) -> Result<Value, String> {
    if source.server.trim().is_empty() {
        return Err("server is empty".into());
    }
    if source.port == 0 {
        return Err("server port must be between 1 and 65535".into());
    }
    let settings = source
        .settings
        .as_object()
        .ok_or_else(|| "settings must be a JSON object".to_owned())?;
    let mut outbound = match source.proto.as_str() {
        "vless" => convert_vless(source, settings)?,
        "vmess" => convert_vmess(source, settings)?,
        "trojan" => convert_trojan(source, settings)?,
        "shadowsocks" | "ss" => convert_shadowsocks(source, settings)?,
        "hysteria" | "hysteria1" => convert_hysteria1(source, settings)?,
        "hysteria2" | "hy2" => convert_hysteria2(source, settings)?,
        other => return Err(format!("unsupported protocol `{other}`")),
    };
    match source.proto.as_str() {
        "hysteria" | "hysteria1" if source.stream.as_ref().is_some_and(|v| !v.is_null()) => {
            return Err(
                "Hysteria v1 streamSettings are not supported; refusing to ignore them".into(),
            );
        }
        "hysteria2" | "hy2" => validate_hysteria2_stream(source.stream.as_ref(), settings)?,
        _ => {}
    }
    if !matches!(
        source.proto.as_str(),
        "hysteria" | "hysteria1" | "hysteria2" | "hy2"
    ) {
        if let Some(stream) = source.stream.as_ref() {
            apply_stream(&mut outbound, &source.proto, stream)?;
        }
    }
    Ok(outbound)
}

fn endpoint(source: &Source, kind: &str) -> Value {
    json!({ "type": kind, "server": source.server, "server_port": source.port })
}

fn convert_vless(source: &Source, s: &Map<String, Value>) -> Result<Value, String> {
    reject_unknown(s, &["address", "port", "level", "id", "flow", "encryption"])?;
    let id = required_string(s, "id")?;
    let mut out = endpoint(source, "vless");
    out["uuid"] = json!(id);
    if let Some(flow) = nonempty_string(s, "flow")? {
        if flow != "xtls-rprx-vision" {
            return Err(format!("unsupported VLESS flow `{flow}`"));
        }
        out["flow"] = json!(flow);
    }
    if let Some(encryption) = nonempty_string(s, "encryption")? {
        if encryption != "none" {
            return Err(format!("unsupported VLESS encryption `{encryption}`"));
        }
    }
    validate_xray_level(s)?;
    Ok(out)
}

fn convert_vmess(source: &Source, s: &Map<String, Value>) -> Result<Value, String> {
    reject_unknown(
        s,
        &[
            "address",
            "port",
            "level",
            "id",
            "security",
            "alterId",
            "alter_id",
            "experiments",
        ],
    )?;
    validate_xray_level(s)?;
    if nonempty_string(s, "experiments")?.is_some() {
        return Err("VMess experiments are not supported by sing-box".into());
    }
    let id = required_string(s, "id")?;
    let security = nonempty_string(s, "security")?.unwrap_or("auto");
    if ![
        "auto",
        "none",
        "zero",
        "aes-128-gcm",
        "chacha20-poly1305",
        "aes-128-ctr",
    ]
    .contains(&security)
    {
        return Err(format!("unsupported VMess security `{security}`"));
    }
    let alter_id = match s.get("alterId").or_else(|| s.get("alter_id")) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| "VMess alterId must be a non-negative integer".to_owned())?,
        None => 0,
    };
    if alter_id > u32::MAX as u64 {
        return Err("VMess alterId is outside the sing-box u32 range".into());
    }
    let mut out = endpoint(source, "vmess");
    out["uuid"] = json!(id);
    out["security"] = json!(security);
    out["alter_id"] = json!(alter_id);
    Ok(out)
}

fn convert_trojan(source: &Source, s: &Map<String, Value>) -> Result<Value, String> {
    reject_unknown(s, &["address", "port", "level", "password", "flow"])?;
    validate_xray_level(s)?;
    if nonempty_string(s, "flow")?.is_some() {
        return Err("Trojan flow has no equivalent in sing-box".into());
    }
    let mut out = endpoint(source, "trojan");
    out["password"] = json!(required_string(s, "password")?);
    Ok(out)
}

fn convert_shadowsocks(source: &Source, s: &Map<String, Value>) -> Result<Value, String> {
    reject_unknown(
        s,
        &[
            "address",
            "port",
            "level",
            "method",
            "password",
            "uot",
            "uotVersion",
            "plugin",
            "plugin-opts",
            "plugin_opts",
        ],
    )?;
    validate_xray_level(s)?;
    if s.get("uot")
        .is_some_and(|value| value != &Value::Bool(false))
    {
        return Err("Shadowsocks UDP-over-TCP is not mapped by this exporter".into());
    }
    if s.get("uotVersion").is_some_and(|value| value != &json!(0)) {
        return Err("non-default Shadowsocks UOT version is not supported".into());
    }
    if nonempty_string(s, "plugin")?.is_some() {
        return Err(
            "Shadowsocks SIP003 plugins are not mapped; refusing to drop plugin options".into(),
        );
    }
    if nonempty_value(s, "plugin-opts") || nonempty_value(s, "plugin_opts") {
        return Err(
            "Shadowsocks plugin options are present without a supported plugin mapping".into(),
        );
    }
    let method = required_string(s, "method")?;
    const METHODS: &[&str] = &[
        "none",
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "rc4-md5",
        "chacha20-ietf",
        "xchacha20",
    ];
    if !METHODS.contains(&method) {
        return Err(format!("unsupported Shadowsocks cipher `{method}`"));
    }
    let mut out = endpoint(source, "shadowsocks");
    out["method"] = json!(method);
    out["password"] = json!(required_string(s, "password")?);
    Ok(out)
}

fn validate_xray_level(settings: &Map<String, Value>) -> Result<(), String> {
    if settings.get("level").is_some_and(|level| !level.is_u64()) {
        return Err("Xray user level must be a non-negative integer".into());
    }
    Ok(())
}

fn convert_hysteria1(source: &Source, s: &Map<String, Value>) -> Result<Value, String> {
    reject_unknown(
        s,
        &[
            "address",
            "port",
            "version",
            "auth",
            "authStr",
            "auth-str",
            "protocol",
            "obfs",
            "obfsParam",
            "obfs-param",
            "obfs-password",
            "up",
            "upMbps",
            "up_mbps",
            "upmbps",
            "down",
            "downMbps",
            "down_mbps",
            "downmbps",
            "ports",
            "hopInterval",
            "hop-interval",
            "peer",
            "sni",
            "serverName",
            "insecure",
            "allowInsecure",
            "pinSHA256",
            "alpn",
            "tls",
            "tlsSettings",
        ],
    )?;
    if let Some(protocol) = nonempty_string(s, "protocol")? {
        if protocol != "udp" {
            return Err(format!(
                "Hysteria v1 protocol mode `{protocol}` has no equivalent in sing-box"
            ));
        }
    }
    for (direction, aliases) in [
        ("upload", &["up", "upMbps", "up_mbps", "upmbps"][..]),
        (
            "download",
            &["down", "downMbps", "down_mbps", "downmbps"][..],
        ),
    ] {
        if !aliases.iter().any(|key| {
            s.get(*key).is_some_and(|v| {
                v.as_u64().is_some() || v.as_str().is_some_and(|text| !text.is_empty())
            })
        }) {
            return Err(format!(
                "Hysteria v1 {direction} bandwidth is required by sing-box"
            ));
        }
    }
    let mut out = endpoint(source, "hysteria");
    let auth = first_string(s, &["auth", "authStr", "auth-str"])?;
    if let Some(auth) = auth {
        out["auth_str"] = json!(auth);
    }
    copy_rate(
        s,
        &["up", "upMbps", "up_mbps", "upmbps"],
        &mut out,
        "up",
        "up_mbps",
    )?;
    copy_rate(
        s,
        &["down", "downMbps", "down_mbps", "downmbps"],
        &mut out,
        "down",
        "down_mbps",
    )?;
    copy_ports_and_hop(s, &mut out)?;
    match nonempty_string(s, "obfs")? {
        Some("xplus") => {
            let password = first_string(s, &["obfsParam", "obfs-param", "obfs-password"])?
                .ok_or_else(|| "Hysteria v1 xplus obfuscation requires its password".to_owned())?;
            out["obfs"] = json!(password);
        }
        Some(other) => return Err(format!("unsupported Hysteria v1 obfuscation `{other}`")),
        None if first_string(s, &["obfsParam", "obfs-param", "obfs-password"])?.is_some() => {
            return Err("Hysteria v1 obfuscation password supplied without xplus mode".into())
        }
        None => {}
    }
    let sni = first_string(s, &["sni", "serverName", "peer"])?;
    let mut tls = tls_config(s, s.get("tlsSettings").or_else(|| s.get("tls")), sni, "")?;
    apply_hysteria_tls_extras(s, &mut tls)?;
    out["tls"] = tls;
    Ok(out)
}

fn convert_hysteria2(source: &Source, s: &Map<String, Value>) -> Result<Value, String> {
    reject_unknown(
        s,
        &[
            "address",
            "port",
            "version",
            "auth",
            "password",
            "obfs",
            "obfs-password",
            "obfsPassword",
            "obfs_password",
            "up",
            "upMbps",
            "up_mbps",
            "upmbps",
            "down",
            "downMbps",
            "down_mbps",
            "downmbps",
            "ports",
            "hopInterval",
            "hop-interval",
            "serverName",
            "sni",
            "insecure",
            "allowInsecure",
            "pinSHA256",
            "alpn",
            "tls",
            "tlsSettings",
        ],
    )?;
    let mut out = endpoint(source, "hysteria2");
    out["password"] = json!(first_string(s, &["password", "auth"])?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing Hysteria2 password/auth".to_owned())?);
    if let Some(obfs) = nonempty_string(s, "obfs")? {
        if !["salamander", "gecko"].contains(&obfs) {
            return Err(format!("unsupported Hysteria2 obfuscation `{obfs}`"));
        }
        let password = first_string(s, &["obfs-password", "obfsPassword", "obfs_password"])?;
        if obfs == "salamander" && password.is_none() {
            return Err("Hysteria2 salamander obfuscation requires a password".into());
        }
        let mut config = json!({ "type": obfs });
        if let Some(password) = password {
            config["password"] = json!(password);
        }
        out["obfs"] = config;
    } else if first_string(s, &["obfs-password", "obfsPassword", "obfs_password"])?
        .is_some_and(|s| !s.is_empty())
    {
        return Err("Hysteria2 obfs password supplied without an obfs type".into());
    }
    copy_rate(
        s,
        &["up", "upMbps", "up_mbps", "upmbps"],
        &mut out,
        "up",
        "up_mbps",
    )?;
    copy_rate(
        s,
        &["down", "downMbps", "down_mbps", "downmbps"],
        &mut out,
        "down",
        "down_mbps",
    )?;
    copy_ports_and_hop(s, &mut out)?;
    let sni = first_string(s, &["sni", "serverName"])?;
    let stream_tls = source
        .stream
        .as_ref()
        .and_then(|stream| stream.get("tlsSettings"));
    let mut tls = tls_config(
        s,
        s.get("tlsSettings").or_else(|| s.get("tls")).or(stream_tls),
        sni,
        "",
    )?;
    apply_hysteria_tls_extras(s, &mut tls)?;
    out["tls"] = tls;
    Ok(out)
}

fn validate_hysteria2_stream(
    stream: Option<&Value>,
    settings: &Map<String, Value>,
) -> Result<(), String> {
    let Some(stream) = stream else { return Ok(()) };
    if stream.is_null() {
        return Ok(());
    }
    let stream = stream
        .as_object()
        .ok_or_else(|| "Hysteria2 streamSettings must be a JSON object".to_owned())?;
    reject_unknown(
        stream,
        &[
            "network",
            "security",
            "tlsSettings",
            "hysteriaSettings",
            "finalmask",
        ],
    )?;
    if nonempty_string(stream, "network")?.is_some_and(|v| v != "hysteria") {
        return Err("Hysteria2 requires the Hysteria network in streamSettings".into());
    }
    if nonempty_string(stream, "security")?.is_some_and(|v| v != "tls") {
        return Err("Hysteria2 requires TLS security in streamSettings".into());
    }
    if let Some(hysteria) = stream.get("hysteriaSettings") {
        let hysteria = hysteria
            .as_object()
            .ok_or_else(|| "hysteriaSettings must be an object".to_owned())?;
        reject_unknown(hysteria, &["version", "auth"])?;
        if hysteria
            .get("version")
            .and_then(Value::as_u64)
            .is_some_and(|v| v != 2)
        {
            return Err("streamSettings describe a Hysteria version other than 2".into());
        }
        if let Some(auth) = hysteria.get("auth").and_then(Value::as_str) {
            let expected = first_string(settings, &["auth", "password"])?.unwrap_or("");
            if auth != expected {
                return Err("Hysteria2 stream auth does not match settings auth".into());
            }
        }
    }
    if let Some(tls) = stream.get("tlsSettings") {
        let tls = tls
            .as_object()
            .ok_or_else(|| "Hysteria2 tlsSettings must be an object".to_owned())?;
        if let (Some(from_settings), Some(from_stream)) = (
            settings.get("insecure").and_then(Value::as_bool),
            tls.get("allowInsecure").and_then(Value::as_bool),
        ) {
            if from_settings != from_stream {
                return Err(
                    "Hysteria2 insecure setting conflicts with tlsSettings.allowInsecure".into(),
                );
            }
        }
        if let (Some(from_settings), Some(from_stream)) = (
            str_any(settings, &["serverName", "sni"]),
            str_any(tls, &["serverName", "sni"]),
        ) {
            if from_settings != from_stream {
                return Err("Hysteria2 server name conflicts with tlsSettings".into());
            }
        }
        if let (Some(from_settings), Some(from_stream)) = (
            settings.get("pinSHA256").and_then(Value::as_str),
            tls.get("pinnedPeerCertSha256").and_then(Value::as_str),
        ) {
            if from_settings != from_stream {
                return Err("Hysteria2 certificate pin conflicts with tlsSettings".into());
            }
        }
    }
    if let Some(finalmask) = stream.get("finalmask") {
        let finalmask = finalmask
            .as_object()
            .ok_or_else(|| "Hysteria2 finalmask must be an object".to_owned())?;
        reject_unknown(finalmask, &["udp"])?;
        let mut expected = Vec::new();
        if nonempty_string(settings, "obfs")? == Some("salamander") {
            let password = first_string(
                settings,
                &["obfs-password", "obfsPassword", "obfs_password"],
            )?
            .unwrap_or("");
            expected.push(json!({"type":"salamander","settings":{"password":password}}));
        }
        if let Some(ports) = nonempty_string(settings, "ports")? {
            expected.push(json!({"type":"udphop","settings":{"mode":"intervallocal","interval":"30","remotePorts":ports}}));
        }
        if finalmask.get("udp").and_then(Value::as_array) != Some(&expected) {
            return Err("Hysteria2 finalmask contains unsupported or inconsistent options".into());
        }
    }
    Ok(())
}

fn apply_stream(out: &mut Value, proto: &str, stream: &Value) -> Result<(), String> {
    let s = stream
        .as_object()
        .ok_or_else(|| "streamSettings must be a JSON object".to_owned())?;
    reject_unknown(
        s,
        &[
            "network",
            "security",
            "tlsSettings",
            "realitySettings",
            "wsSettings",
            "grpcSettings",
            "httpSettings",
            "httpupgradeSettings",
            "tcpSettings",
            "sockopt",
            "dsSettings",
        ],
    )?;
    if nonempty_value(s, "sockopt")
        || nonempty_value(s, "dsSettings")
        || nonempty_value(s, "tcpSettings")
    {
        return Err(
            "stream contains socket, domain-socket, or TCP header options without a safe mapping"
                .into(),
        );
    }
    let security = nonempty_string(s, "security")?.unwrap_or("none");
    let tls = match security {
        "none" => {
            if nonempty_value(s, "tlsSettings") || nonempty_value(s, "realitySettings") {
                return Err("TLS/Reality settings exist while stream security is `none`".into());
            }
            None
        }
        "tls" => Some(tls_config(s, s.get("tlsSettings"), None, "")?),
        "reality" => {
            if proto != "vless" {
                return Err("Reality is only mapped for VLESS by this converter".into());
            }
            Some(tls_config(s, s.get("realitySettings"), None, "reality")?)
        }
        other => return Err(format!("unsupported stream security `{other}`")),
    };
    if let Some(tls) = tls {
        out["tls"] = tls;
    } else if proto == "vless" && out.get("flow").is_some() {
        return Err("VLESS flow requires TLS or Reality security".into());
    }
    let network = nonempty_string(s, "network")?.unwrap_or("tcp");
    if network == "tcp" || network == "raw" {
        for key in [
            "wsSettings",
            "grpcSettings",
            "httpSettings",
            "httpupgradeSettings",
        ] {
            if nonempty_value(s, key) {
                return Err(format!("{key} present but network is `{network}`"));
            }
        }
        return Ok(());
    }
    let (key, transport) = match network {
        "ws" => ("wsSettings", "ws"),
        "grpc" => ("grpcSettings", "grpc"),
        "http" | "h2" => ("httpSettings", "http"),
        "httpupgrade" => ("httpupgradeSettings", "httpupgrade"),
        "kcp" | "mkcp" => return Err("mKCP transport is not supported by sing-box".into()),
        "quic" => return Err("V2Ray QUIC transport is not supported by this converter".into()),
        "xhttp" | "splithttp" => {
            return Err("XHTTP/SplitHTTP transport has no supported sing-box mapping".into())
        }
        other => return Err(format!("unsupported V2Ray transport `{other}`")),
    };
    for (candidate, _) in [
        ("wsSettings", "ws"),
        ("grpcSettings", "grpc"),
        ("httpSettings", "http"),
        ("httpupgradeSettings", "httpupgrade"),
    ] {
        if candidate != key && nonempty_value(s, candidate) {
            return Err(format!("{candidate} conflicts with network `{network}`"));
        }
    }
    let options = s.get(key).unwrap_or(&Value::Null);
    let options = options
        .as_object()
        .ok_or_else(|| format!("{key} must be an object"))?;
    let mapped = map_transport(transport, options)?;
    out["transport"] = mapped;
    Ok(())
}

fn map_transport(kind: &str, s: &Map<String, Value>) -> Result<Value, String> {
    let mut t = Map::new();
    t.insert("type".into(), json!(kind));
    match kind {
        "ws" => {
            reject_unknown(
                s,
                &["path", "headers", "maxEarlyData", "earlyDataHeaderName"],
            )?;
            copy_json(s, "path", &mut t, "path")?;
            let headers = header_map(s)?;
            if !headers.is_null() {
                t.insert("headers".into(), headers);
            }
            if let Some(v) = optional_u64(s, "maxEarlyData")? {
                t.insert("max_early_data".into(), json!(v));
            }
            copy_json(s, "earlyDataHeaderName", &mut t, "early_data_header_name")?;
        }
        "grpc" => {
            reject_unknown(s, &["serviceName", "multiMode"])?;
            if let Some(value) = s.get("multiMode") {
                let enabled = value
                    .as_bool()
                    .ok_or_else(|| "gRPC multiMode must be a boolean".to_owned())?;
                if enabled {
                    return Err("gRPC multiMode has no direct sing-box transport equivalent".into());
                }
            }
            copy_json(s, "serviceName", &mut t, "service_name")?;
        }
        "http" | "httpupgrade" => {
            reject_unknown(s, &["host", "path", "method", "headers"])?;
            if let Some(host) = s.get("host") {
                if let Some(host) = host.as_str() {
                    t.insert("host".into(), json!([host]));
                } else if host
                    .as_array()
                    .is_some_and(|a| a.iter().all(Value::is_string))
                {
                    t.insert("host".into(), host.clone());
                } else {
                    return Err("HTTP transport host must be a string or array of strings".into());
                }
            }
            copy_json(s, "path", &mut t, "path")?;
            if kind == "http" {
                copy_json(s, "method", &mut t, "method")?;
            } else if s.contains_key("method") {
                return Err("HTTPUpgrade does not support the HTTP method option".into());
            }
            let headers = header_map(s)?;
            if !headers.is_null() {
                t.insert("headers".into(), headers);
            }
        }
        _ => unreachable!(),
    }
    Ok(Value::Object(t))
}

fn header_map(s: &Map<String, Value>) -> Result<Value, String> {
    let Some(headers) = s.get("headers") else {
        return Ok(Value::Null);
    };
    let headers = headers
        .as_object()
        .ok_or_else(|| "transport headers must be an object".to_owned())?;
    let mut result = Map::new();
    for (key, value) in headers {
        if !value.is_string() {
            return Err(format!("transport header `{key}` must be a string"));
        }
        result.insert(key.clone(), value.clone());
    }
    Ok(Value::Object(result))
}

fn tls_config(
    settings: &Map<String, Value>,
    legacy: Option<&Value>,
    sni: Option<&str>,
    reality_key: &str,
) -> Result<Value, String> {
    let nested = legacy.and_then(Value::as_object);
    if legacy.is_some() && nested.is_none() {
        return Err("TLS settings must be an object".into());
    }
    if let Some(nested) = nested {
        reject_unknown(
            nested,
            &[
                "serverName",
                "server_name",
                "sni",
                "allowInsecure",
                "allow_insecure",
                "insecure",
                "alpn",
                "publicKey",
                "public_key",
                "shortId",
                "short_id",
                "fingerprint",
                "spiderX",
                "pinnedPeerCertSha256",
            ],
        )?;
    }
    let mut tls = json!({ "enabled": true });
    let server_name = sni
        .or_else(|| nested.and_then(|n| str_any(n, &["serverName", "server_name", "sni"])))
        .or_else(|| str_any(settings, &["serverName", "server_name", "sni", "peer"]));
    if let Some(name) = server_name {
        tls["server_name"] = json!(name);
    }
    let insecure = nested
        .and_then(|n| bool_any(n, &["allowInsecure", "allow_insecure", "insecure"]))
        .or_else(|| {
            bool_any(
                settings,
                &[
                    "allowInsecure",
                    "allow_insecure",
                    "insecure",
                    "skipCertVerify",
                ],
            )
        })
        .unwrap_or(false);
    if insecure {
        tls["insecure"] = json!(true);
    }
    if let Some(alpn) = nested
        .and_then(|n| n.get("alpn"))
        .or_else(|| settings.get("alpn"))
    {
        if let Some(list) = alpn.as_array().filter(|a| a.iter().all(Value::is_string)) {
            tls["alpn"] = Value::Array(list.clone());
        } else if let Some(value) = alpn.as_str() {
            tls["alpn"] = json!(value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>());
        } else {
            return Err("TLS ALPN must be a string or array of strings".into());
        }
    }
    if let Some(pin) = nested.and_then(|n| n.get("pinnedPeerCertSha256")) {
        if let Some(pin) = pin.as_str() {
            tls["certificate_sha256"] = json!([pin]);
        } else if pin
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
        {
            tls["certificate_sha256"] = pin.clone();
        } else {
            return Err("pinnedPeerCertSha256 must be a string or an array of strings".into());
        }
    }
    if reality_key == "reality" {
        let reality = legacy
            .and_then(Value::as_object)
            .ok_or_else(|| "Reality settings must be an object".to_owned())?;
        reject_unknown(
            reality,
            &[
                "serverName",
                "server_name",
                "publicKey",
                "public_key",
                "shortId",
                "short_id",
                "fingerprint",
                "spiderX",
            ],
        )?;
        let public_key = str_any(reality, &["publicKey", "public_key"])
            .ok_or_else(|| "Reality publicKey is required".to_owned())?;
        let short_id = str_any(reality, &["shortId", "short_id"])
            .ok_or_else(|| "Reality shortId is required (empty string is valid)".to_owned())
            .or_else(|_| {
                if reality.contains_key("shortId") || reality.contains_key("short_id") {
                    Ok("")
                } else {
                    Err("Reality shortId is required".to_owned())
                }
            })?;
        tls["reality"] = json!({ "enabled": true, "public_key": public_key, "short_id": short_id });
        let fingerprint = str_any(reality, &["fingerprint"]).unwrap_or("chrome");
        if ![
            "chrome",
            "firefox",
            "edge",
            "safari",
            "360",
            "qq",
            "ios",
            "android",
            "random",
            "randomized",
        ]
        .contains(&fingerprint)
        {
            return Err(format!(
                "unsupported Reality uTLS fingerprint `{fingerprint}`"
            ));
        }
        tls["utls"] = json!({ "enabled": true, "fingerprint": fingerprint });
        if nonempty_value(reality, "spiderX") {
            return Err("Reality spiderX has no sing-box client field".into());
        }
    }
    Ok(tls)
}

fn apply_hysteria_tls_extras(settings: &Map<String, Value>, tls: &mut Value) -> Result<(), String> {
    if let Some(pin) = nonempty_string(settings, "pinSHA256")? {
        tls["certificate_sha256"] = json!([pin]);
    }
    if let Some(expected_name) = nonempty_string(settings, "nameCertVerify")? {
        let server_name = tls.get("server_name").and_then(Value::as_str);
        if server_name != Some(expected_name) {
            return Err(
                "nameCertVerify differs from SNI; sing-box cannot preserve both values".into(),
            );
        }
    }
    Ok(())
}

fn reject_unknown(map: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    if let Some(key) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!(
            "unmapped option `{key}`; refusing to silently drop it"
        ));
    }
    Ok(())
}

fn required_string<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing or invalid `{key}`"))
}

fn nonempty_string<'a>(map: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("`{key}` must be a string")),
    }
}

fn first_string<'a>(map: &'a Map<String, Value>, keys: &[&str]) -> Result<Option<&'a str>, String> {
    for key in keys {
        if let Some(value) = nonempty_string(map, key)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn str_any<'a>(map: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        map.get(*key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    })
}

fn bool_any(map: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| map.get(*key).and_then(Value::as_bool))
}

fn nonempty_value(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key)
        .is_some_and(|v| !v.is_null() && v != &json!(false) && v != &json!("") && v != &json!({}))
}

fn copy_rate(
    settings: &Map<String, Value>,
    keys: &[&str],
    outbound: &mut Value,
    text_key: &str,
    numeric_key: &str,
) -> Result<(), String> {
    for key in keys {
        if let Some(value) = settings.get(*key).filter(|v| !v.is_null()) {
            if value.as_u64().is_some_and(|n| n > 0) {
                outbound[numeric_key] = value.clone();
            } else if let Some(text) = value.as_str().filter(|s| !s.is_empty()) {
                outbound[text_key] = json!(text);
            } else {
                return Err(format!(
                    "`{key}` must be a non-negative integer or bandwidth string"
                ));
            }
            return Ok(());
        }
    }
    Ok(())
}

fn copy_ports_and_hop(settings: &Map<String, Value>, outbound: &mut Value) -> Result<(), String> {
    if let Some(ports) = nonempty_string(settings, "ports")? {
        let port_parts: Vec<&str> = ports.split(',').collect();
        if port_parts.iter().any(|part| part.trim().is_empty()) {
            return Err("port hopping list contains an empty entry".into());
        }
        let ports: Vec<String> = port_parts
            .into_iter()
            .map(str::trim)
            .map(|port| {
                let (start, end) = port
                    .split_once('-')
                    .or_else(|| port.split_once(':'))
                    .unwrap_or((port, port));
                let start = start.parse::<u16>().ok();
                let end = end.parse::<u16>().ok();
                match (start, end) {
                    (Some(a), Some(b)) if a > 0 && b > 0 && a <= b => Ok(if a == b {
                        a.to_string()
                    } else {
                        format!("{a}:{b}")
                    }),
                    _ => Err(format!("invalid port range `{port}`")),
                }
            })
            .collect::<Result<_, _>>()?;
        if ports.is_empty() {
            return Err("port hopping list is empty".into());
        }
        outbound["server_ports"] = json!(ports);
        outbound.as_object_mut().unwrap().remove("server_port");
    }
    for key in ["hopInterval", "hop-interval"] {
        if let Some(value) = settings.get(key).filter(|v| !v.is_null()) {
            if let Some(seconds) = value.as_u64() {
                outbound["hop_interval"] = json!(format!("{seconds}s"));
            } else if let Some(duration) = value.as_str().filter(|s| !s.is_empty()) {
                outbound["hop_interval"] = json!(duration);
            } else {
                return Err(format!(
                    "`{key}` must be a non-negative seconds value or duration string"
                ));
            }
            break;
        }
    }
    Ok(())
}

fn copy_json(
    map: &Map<String, Value>,
    key: &str,
    out: &mut Map<String, Value>,
    target: &str,
) -> Result<(), String> {
    if let Some(value) = map.get(key) {
        if !value.is_string() {
            return Err(format!("`{key}` must be a string"));
        }
        out.insert(target.into(), value.clone());
    }
    Ok(())
}

fn optional_u64(map: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    match map.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("`{key}` must be a non-negative integer")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn source(proto: &str, settings: Value, stream: Option<Value>) -> Source {
        Source {
            proto: proto.into(),
            name: "node".into(),
            server: "proxy.example".into(),
            port: 443,
            country: "DE".into(),
            settings,
            stream,
        }
    }

    #[test]
    fn renders_complete_config_with_all_six_families_and_selector() {
        let sources = vec![
            source(
                "vless",
                json!({"id":"u","flow":"xtls-rprx-vision"}),
                Some(
                    json!({"network":"tcp","security":"tls","tlsSettings":{"serverName":"v.example"}}),
                ),
            ),
            source(
                "vmess",
                json!({"id":"u","security":"auto","alterId":0}),
                None,
            ),
            source(
                "shadowsocks",
                json!({"method":"aes-256-gcm","password":"secret"}),
                None,
            ),
            source("trojan", json!({"password":"secret"}), None),
            source(
                "hysteria",
                json!({"auth":"secret","peer":"h.example","upmbps":20,"downmbps":50,"protocol":"udp"}),
                None,
            ),
            source(
                "hysteria2",
                json!({"auth":"secret","serverName":"h2.example","obfs":"salamander","obfs-password":"mask"}),
                None,
            ),
        ];
        let (text, report) = render(&sources, &Options::default()).unwrap();
        let config: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            report.supported_count(),
            6,
            "skipped: {:?}",
            report.skipped_nodes
        );
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(config["inbounds"][0]["type"], "mixed");
        assert_eq!(config["route"]["final"], "proxy");
        assert_eq!(config["outbounds"][0]["tls"]["server_name"], "v.example");
        assert_eq!(config["outbounds"][1]["alter_id"], 0);
        assert_eq!(config["outbounds"][2]["type"], "shadowsocks");
        assert_eq!(config["outbounds"][4]["type"], "hysteria");
        assert_eq!(config["outbounds"][4]["up_mbps"], 20);
        assert_eq!(config["outbounds"][5]["obfs"]["type"], "salamander");
    }

    #[test]
    fn maps_supported_v2ray_transports_and_tls_reality() {
        let ws = source(
            "vless",
            json!({"id":"u"}),
            Some(
                json!({"network":"ws","security":"tls","wsSettings":{"path":"/ws","headers":{"Host":"front.example"}},"tlsSettings":{"serverName":"sni.example","alpn":["h2"]}}),
            ),
        );
        let grpc = source(
            "trojan",
            json!({"password":"pw"}),
            Some(json!({"network":"grpc","grpcSettings":{"serviceName":"edge"}})),
        );
        let reality = source(
            "vless",
            json!({"id":"u"}),
            Some(
                json!({"network":"tcp","security":"reality","realitySettings":{"serverName":"cover.example","publicKey":"pk","shortId":"ab"}}),
            ),
        );
        let (_, report) = render(&[ws, grpc, reality], &Options::default()).unwrap();
        assert_eq!(report.supported_count(), 3, "{:?}", report.skipped_nodes);
        let ws_source = source(
            "vless",
            json!({"id":"u"}),
            Some(
                json!({"network":"ws","security":"tls","wsSettings":{"path":"/ws","headers":{"Host":"front.example"}},"tlsSettings":{"serverName":"sni.example","alpn":["h2"]}}),
            ),
        );
        let (text, _) = render(&[ws_source], &Options::default()).unwrap();
        let config: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(config["outbounds"][0]["transport"]["type"], "ws");
        assert_eq!(
            config["outbounds"][0]["transport"]["headers"]["Host"],
            "front.example"
        );
        assert_eq!(config["outbounds"][0]["tls"]["alpn"][0], "h2");
        let reality_source = source(
            "vless",
            json!({"id":"u"}),
            Some(
                json!({"network":"tcp","security":"reality","realitySettings":{"serverName":"cover.example","publicKey":"pk","shortId":"ab"}}),
            ),
        );
        let (text, _) = render(&[reality_source], &Options::default()).unwrap();
        let config: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(config["outbounds"][0]["tls"]["reality"]["public_key"], "pk");
        assert_eq!(
            config["outbounds"][0]["tls"]["utls"],
            json!({"enabled":true,"fingerprint":"chrome"})
        );
    }

    #[test]
    fn explains_skips_for_unsupported_transport_cipher_and_unknown_options() {
        let inputs = [
            source("vmess", json!({"id":"u"}), Some(json!({"network":"xhttp"}))),
            source(
                "ss",
                json!({"method":"unsupported-cipher","password":"pw"}),
                None,
            ),
            source("trojan", json!({"password":"pw","futureFlag":true}), None),
            source("ssr", json!({}), None),
        ];
        let (_, report) = render(&inputs, &Options::default()).unwrap();
        assert_eq!(report.supported_count(), 0);
        assert_eq!(report.skipped_count(), 4);
        assert!(report.skipped_nodes[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("XHTTP"));
        assert!(report.skipped_nodes[1]
            .reason
            .as_deref()
            .unwrap()
            .contains("cipher"));
        assert!(report.skipped_nodes[2]
            .reason
            .as_deref()
            .unwrap()
            .contains("futureFlag"));
        assert!(report.skipped_nodes[3]
            .reason
            .as_deref()
            .unwrap()
            .contains("unsupported protocol"));
    }

    #[test]
    fn rejects_ss_plugins_and_hysteria_insecure_unknown_options_without_loss() {
        let ss = source(
            "ss",
            json!({"method":"aes-256-gcm","password":"pw","plugin":"obfs-local"}),
            None,
        );
        let hy2 = source(
            "hysteria2",
            json!({"auth":"pw","insecure":true,"ech":"encoded"}),
            None,
        );
        let (_, report) = render(&[ss, hy2], &Options::default()).unwrap();
        assert!(report.skipped_nodes[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("SIP003"));
        assert!(report.skipped_nodes[1]
            .reason
            .as_deref()
            .unwrap()
            .contains("ech"));
    }

    #[test]
    fn maps_hysteria2_xray_stream_port_hopping_and_certificate_pin_safely() {
        let node = source(
            "hysteria2",
            json!({
                "auth":"pw",
                "ports":"20000-20010,30000",
                "obfs":"salamander",
                "obfs-password":"mask",
                "serverName":"edge.example",
                "pinSHA256":"cert-pin"
            }),
            Some(json!({
                "network":"hysteria",
                "security":"tls",
                "tlsSettings": {
                    "serverName":"edge.example",
                    "pinnedPeerCertSha256":"cert-pin"
                },
                "hysteriaSettings":{"version":2,"auth":"pw"},
                "finalmask":{"udp":[
                    {"type":"salamander","settings":{"password":"mask"}},
                    {"type":"udphop","settings":{"mode":"intervallocal","interval":"30","remotePorts":"20000-20010,30000"}}
                ]}
            })),
        );
        let (text, report) = render(&[node], &Options::default()).unwrap();
        assert_eq!(report.supported_count(), 1, "{:?}", report.skipped_nodes);
        let config: Value = serde_json::from_str(&text).unwrap();
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["server_ports"][0], "20000:20010");
        assert_eq!(outbound["server_ports"][1], "30000");
        assert!(outbound.get("server_port").is_none());
        assert_eq!(outbound["tls"]["certificate_sha256"][0], "cert-pin");

        let mut inconsistent = source(
            "hysteria2",
            json!({"auth":"pw","insecure":true}),
            Some(json!({
                "network":"hysteria","security":"tls","tlsSettings":{"allowInsecure":false}
            })),
        );
        inconsistent.name = "conflict".into();
        let (_, report) = render(&[inconsistent], &Options::default()).unwrap();
        assert!(report.skipped_nodes[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("conflicts"));
    }

    #[test]
    fn tag_collisions_are_unique_and_empty_input_still_has_valid_config() {
        let sources = vec![
            source("trojan", json!({"password":"a"}), None),
            source("trojan", json!({"password":"b"}), None),
        ];
        let (_, report) = render(&sources, &Options::default()).unwrap();
        assert_eq!(report.supported[0].tag, Some("node".into()));
        assert_eq!(report.supported[1].tag, Some("node_2".into()));
        let (text, _) = render(&[], &Options::default()).unwrap();
        let config: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(config["route"]["final"], "direct");
        assert_eq!(config["outbounds"][0]["type"], "direct");
    }
}
