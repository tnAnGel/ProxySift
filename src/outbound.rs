use serde_json::{json, Map, Value};
use std::collections::HashMap;

pub fn b64_any(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let padded = if t.len().is_multiple_of(4) {
        t.to_string()
    } else {
        format!("{}{}", t, "=".repeat(4 - t.len() % 4))
    };
    base64::engine::general_purpose::STANDARD
        .decode(&padded)
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE
                .decode(&padded)
                .ok()
        })
}

pub fn q<'a>(map: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    map.get(key).map(|s| s.as_str())
}

pub fn q_or<'a>(map: &'a HashMap<String, String>, key: &str, default: &'a str) -> &'a str {
    q(map, key).unwrap_or(default)
}

fn truthy(v: Option<&str>) -> bool {
    matches!(v, Some("1") | Some("true") | Some("yes"))
}

/// Строит streamSettings. None = протокол/сетка не поддерживается ядром.
pub fn build_stream(
    net: &str,
    security: &str,
    params: &HashMap<String, String>,
    address: &str,
) -> Option<Value> {
    let network = match net {
        "tcp" => "raw",
        "splithttp" => "xhttp",
        "mkcp" => "kcp",
        "websocket" => "ws",
        "gun" => "grpc",
        "http-upgrade" => "httpupgrade",
        other => other,
    };
    if matches!(network, "http" | "h2" | "h3" | "quic" | "masque") {
        return None;
    }
    if !matches!(
        network,
        "raw" | "ws" | "grpc" | "kcp" | "xhttp" | "httpupgrade" | "hysteria"
    ) {
        return None;
    }
    if security == "reality" && !matches!(network, "raw" | "xhttp" | "grpc") {
        return None;
    }
    if network == "hysteria" && security != "tls" {
        return None;
    }

    let mut stream = Map::new();
    stream.insert("network".into(), Value::String(network.to_string()));
    stream.insert(
        "security".into(),
        Value::String(if security == "auto" {
            "none".into()
        } else {
            security.to_string()
        }),
    );

    let sni = q_or(params, "sni", "").to_string();
    let hostp = q_or(params, "host", "").to_string();
    let server_name = if !sni.is_empty() {
        sni
    } else if !hostp.is_empty() {
        hostp
    } else {
        address.to_string()
    };
    let fingerprint = {
        let fp = q_or(params, "fp", "");
        if fp.is_empty() {
            "chrome".to_string()
        } else {
            fp.to_string()
        }
    };

    if security == "tls" {
        let mut tls = Map::new();
        tls.insert("serverName".into(), Value::String(server_name));
        tls.insert("fingerprint".into(), Value::String(fingerprint));
        if let Some(alpn) = q(params, "alpn") {
            let list: Vec<Value> = alpn
                .split(',')
                .map(|s| Value::String(s.trim().to_string()))
                .filter(|v| !v.as_str().unwrap().is_empty())
                .collect();
            if !list.is_empty() {
                tls.insert("alpn".into(), Value::Array(list));
            }
        }
        if let Some(pcs) = q(params, "pcs") {
            if !pcs.is_empty() {
                tls.insert(
                    "pinnedPeerCertSha256".into(),
                    Value::String(pcs.to_string()),
                );
            }
        }
        if let Some(vcn) = q(params, "vcn") {
            if !vcn.is_empty() {
                tls.insert(
                    "verifyPeerCertByName".into(),
                    Value::String(vcn.to_string()),
                );
            }
        }
        if let Some(ech) = q(params, "ech") {
            if !ech.is_empty() {
                tls.insert("echConfigList".into(), Value::String(ech.to_string()));
            }
        }
        if truthy(q(params, "insecure")) || truthy(q(params, "allowInsecure")) {
            tls.insert("allowInsecure".into(), Value::Bool(true));
        }
        stream.insert("tlsSettings".into(), Value::Object(tls));
    } else if security == "reality" {
        let pbk = q(params, "pbk")?;
        if pbk.is_empty() {
            return None;
        }
        let mut reality = Map::new();
        reality.insert("password".into(), Value::String(pbk.to_string()));
        reality.insert(
            "shortId".into(),
            Value::String(q_or(params, "sid", "").to_string()),
        );
        reality.insert("serverName".into(), Value::String(server_name));
        reality.insert("fingerprint".into(), Value::String(fingerprint));
        reality.insert(
            "spiderX".into(),
            Value::String(q_or(params, "spx", "/").to_string()),
        );
        if let Some(pqv) = q(params, "pqv") {
            if !pqv.is_empty() {
                reality.insert("mldsa65Verify".into(), Value::String(pqv.to_string()));
            }
        }
        stream.insert("realitySettings".into(), Value::Object(reality));
    }

    match network {
        "xhttp" => {
            let mut xs = Map::new();
            xs.insert(
                "path".into(),
                Value::String(q_or(params, "path", "/").to_string()),
            );
            xs.insert(
                "host".into(),
                Value::String(q_or(params, "host", "").to_string()),
            );
            xs.insert(
                "mode".into(),
                Value::String(q_or(params, "mode", "auto").to_string()),
            );
            if let Some(extra) = q(params, "extra") {
                if let Ok(v) = serde_json::from_str::<Value>(extra) {
                    xs.insert("extra".into(), v);
                }
            }
            stream.insert("xhttpSettings".into(), Value::Object(xs));
        }
        "grpc" => {
            let service = q_or(params, "path", "/").trim_matches('/').to_string();
            let mut gs = Map::new();
            gs.insert("serviceName".into(), Value::String(service));
            stream.insert("grpcSettings".into(), Value::Object(gs));
        }
        "ws" | "httpupgrade" => {
            let mut ws = Map::new();
            ws.insert(
                "path".into(),
                Value::String(q_or(params, "path", "/").to_string()),
            );
            ws.insert(
                "host".into(),
                Value::String(q_or(params, "host", "").to_string()),
            );
            let key = if network == "httpupgrade" {
                "httpupgradeSettings"
            } else {
                "wsSettings"
            };
            stream.insert(key.into(), Value::Object(ws));
        }
        "kcp" => {
            let header = q_or(params, "headerType", "");
            if !header.is_empty() && header != "none" && q(params, "fm").is_none() {
                return None;
            }
        }
        "hysteria" => {
            let mut hs = Map::new();
            hs.insert("version".into(), json!(2));
            if let Some(auth) = q(params, "auth") {
                if !auth.is_empty() {
                    hs.insert("auth".into(), Value::String(auth.to_string()));
                }
            }
            stream.insert("hysteriaSettings".into(), Value::Object(hs));
        }
        _ => {}
    }

    if let Some(fm) = q(params, "fm") {
        if let Ok(v) = serde_json::from_str::<Value>(fm) {
            if v.is_object() {
                stream.insert("finalmask".into(), v);
            }
        }
    }

    Some(Value::Object(stream))
}

pub fn vless_settings(
    address: &str,
    port: u16,
    id: &str,
    params: &HashMap<String, String>,
) -> Value {
    json!({
        "address": address,
        "port": port,
        "level": 0,
        "id": id,
        "encryption": q_or(params, "encryption", "none"),
        "flow": q_or(params, "flow", ""),
    })
}

pub fn vmess_settings(address: &str, port: u16, id: &str, scy: &str) -> Value {
    json!({
        "address": address,
        "port": port,
        "level": 0,
        "id": id,
        "security": scy,
        "experiments": "",
    })
}

pub fn trojan_settings(
    address: &str,
    port: u16,
    password: &str,
    params: &HashMap<String, String>,
) -> Value {
    json!({
        "address": address,
        "port": port,
        "level": 0,
        "password": password,
        "flow": q_or(params, "flow", ""),
    })
}

pub fn ss_settings(address: &str, port: u16, method: &str, password: &str) -> Value {
    json!({
        "address": address,
        "port": port,
        "method": method,
        "password": password,
        "uot": false,
        "uotVersion": 0,
    })
}

pub fn normalize_ss_method(method: &str) -> String {
    match method.trim().to_ascii_lowercase().as_str() {
        "chacha20-poly1305" | "aead_chacha20_poly1305" => "chacha20-ietf-poly1305".to_string(),
        "xchacha20-poly1305" | "aead_xchacha20_poly1305" => "xchacha20-ietf-poly1305".to_string(),
        "aead_aes_128_gcm" => "aes-128-gcm".to_string(),
        "aead_aes_256_gcm" => "aes-256-gcm".to_string(),
        other => other.to_string(),
    }
}

pub const SS_ALLOWED_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
];

/// Additional Shadowsocks ciphers supported by Mihomo export but not by the
/// bundled Xray speed-check core.
pub const SS_MIHOMO_ONLY_METHODS: &[&str] = &[
    "aes-128-ccm",
    "aes-192-ccm",
    "aes-256-ccm",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-gcm-siv",
    "aes-192-gcm",
    "aes-256-gcm-siv",
    "aegis-128l",
    "aegis-256",
    "aez-384",
    "chacha20",
    "chacha20-ietf",
    "chacha8-ietf-poly1305",
    "deoxys-ii-256-128",
    "lea-128-gcm",
    "lea-192-gcm",
    "lea-256-gcm",
    "none",
    "rabbit128-poly1305",
    "rc4-md5",
    "xchacha20",
];

pub fn ss_method_supported(method: &str) -> bool {
    let method = method.to_ascii_lowercase();
    SS_ALLOWED_METHODS.contains(&method.as_str())
        || SS_MIHOMO_ONLY_METHODS.contains(&method.as_str())
}

pub fn ss_method_supported_by_xray(method: &str) -> bool {
    SS_ALLOWED_METHODS.contains(&method.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn b64_any_decodes_standard_and_unpadded_input() {
        assert_eq!(b64_any("SGVsbG8=").as_deref(), Some(b"Hello".as_slice()));
        assert_eq!(b64_any("  SGVsbG8  ").as_deref(), Some(b"Hello".as_slice()));
    }

    #[test]
    fn b64_any_accepts_url_safe_alphabet_and_unpadded_input() {
        assert_eq!(b64_any("_w").as_deref(), Some(&[0xff][..]));
    }

    #[test]
    fn b64_any_rejects_empty_and_malformed_input() {
        assert_eq!(b64_any(""), None);
        assert_eq!(b64_any(" \n\t "), None);
        assert_eq!(b64_any("not base64!"), None);
        assert_eq!(b64_any("a"), None);
    }

    #[test]
    fn build_stream_normalizes_transport_aliases_and_auto_security() {
        let stream = build_stream("tcp", "auto", &HashMap::new(), "node.example").unwrap();
        assert_eq!(stream["network"], "raw");
        assert_eq!(stream["security"], "none");
        assert!(stream.get("tlsSettings").is_none());

        let stream = build_stream("websocket", "none", &HashMap::new(), "node.example").unwrap();
        assert_eq!(stream["network"], "ws");
        assert_eq!(stream["wsSettings"]["path"], "/");
        assert_eq!(stream["wsSettings"]["host"], "");
    }

    #[test]
    fn build_stream_rejects_unsupported_networks_and_reality_transports() {
        for network in ["http", "h2", "h3", "quic", "masque", "unknown"] {
            assert!(build_stream(network, "none", &HashMap::new(), "node.example").is_none());
        }
        for network in ["ws", "httpupgrade", "kcp"] {
            assert!(build_stream(
                network,
                "reality",
                &params(&[("pbk", "key")]),
                "node.example"
            )
            .is_none());
        }
        assert!(build_stream("raw", "reality", &HashMap::new(), "node.example").is_none());
        assert!(build_stream("xhttp", "reality", &HashMap::new(), "node.example").is_none());
    }

    #[test]
    fn build_stream_supports_xray_hysteria_transport_only_with_tls() {
        assert!(build_stream("hysteria", "none", &HashMap::new(), "node.example").is_none());
        let stream = build_stream(
            "hysteria",
            "tls",
            &params(&[("auth", "secret")]),
            "node.example",
        )
        .unwrap();
        assert_eq!(stream["network"], "hysteria");
        assert_eq!(stream["hysteriaSettings"]["version"], 2);
        assert_eq!(stream["hysteriaSettings"]["auth"], "secret");
    }

    #[test]
    fn build_stream_populates_tls_options_and_uses_sni_precedence() {
        let stream = build_stream(
            "raw",
            "tls",
            &params(&[
                ("sni", "sni.example"),
                ("host", "host.example"),
                ("fp", "firefox"),
                ("alpn", "h2, http/1.1, ,"),
                ("pcs", "cert-hash"),
                ("vcn", "verify.example"),
                ("ech", "ech-config"),
                ("insecure", "true"),
            ]),
            "address.example",
        )
        .unwrap();

        assert_eq!(
            stream["tlsSettings"],
            json!({
                "serverName": "sni.example",
                "fingerprint": "firefox",
                "alpn": ["h2", "http/1.1"],
                "pinnedPeerCertSha256": "cert-hash",
                "verifyPeerCertByName": "verify.example",
                "echConfigList": "ech-config",
                "allowInsecure": true,
            })
        );
    }

    #[test]
    fn build_stream_omits_empty_optional_tls_options() {
        let stream = build_stream(
            "raw",
            "tls",
            &params(&[("alpn", " , "), ("pcs", ""), ("vcn", ""), ("ech", "")]),
            "node.example",
        )
        .unwrap();

        let tls = &stream["tlsSettings"];
        for key in [
            "alpn",
            "pinnedPeerCertSha256",
            "verifyPeerCertByName",
            "echConfigList",
        ] {
            assert!(tls.get(key).is_none(), "empty {key} must be omitted");
        }
    }

    #[test]
    fn build_stream_uses_host_then_address_and_default_fingerprint() {
        let host_stream = build_stream(
            "raw",
            "tls",
            &params(&[("host", "host.example")]),
            "address.example",
        )
        .unwrap();
        assert_eq!(host_stream["tlsSettings"]["serverName"], "host.example");
        assert_eq!(host_stream["tlsSettings"]["fingerprint"], "chrome");

        let address_stream =
            build_stream("raw", "tls", &HashMap::new(), "address.example").unwrap();
        assert_eq!(
            address_stream["tlsSettings"]["serverName"],
            "address.example"
        );
    }

    #[test]
    fn build_stream_truthy_flags_are_case_sensitive_and_support_both_keys() {
        for (key, value) in [
            ("insecure", "1"),
            ("insecure", "yes"),
            ("allowInsecure", "true"),
        ] {
            let stream =
                build_stream("raw", "tls", &params(&[(key, value)]), "node.example").unwrap();
            assert_eq!(stream["tlsSettings"]["allowInsecure"], true);
        }
        for value in ["TRUE", "Yes", "0", ""] {
            let stream = build_stream(
                "raw",
                "tls",
                &params(&[("insecure", value)]),
                "node.example",
            )
            .unwrap();
            assert!(stream["tlsSettings"].get("allowInsecure").is_none());
        }
    }

    #[test]
    fn build_stream_requires_reality_public_key_and_applies_defaults() {
        assert!(build_stream("raw", "reality", &HashMap::new(), "node.example").is_none());
        assert!(build_stream("raw", "reality", &params(&[("pbk", "")]), "node.example").is_none());

        let stream = build_stream(
            "raw",
            "reality",
            &params(&[("pbk", "public-key")]),
            "node.example",
        )
        .unwrap();
        assert_eq!(stream["realitySettings"]["password"], "public-key");
        assert_eq!(stream["realitySettings"]["shortId"], "");
        assert_eq!(stream["realitySettings"]["serverName"], "node.example");
        assert_eq!(stream["realitySettings"]["fingerprint"], "chrome");
        assert_eq!(stream["realitySettings"]["spiderX"], "/");
        assert!(stream["realitySettings"].get("mldsa65Verify").is_none());
    }

    #[test]
    fn build_stream_adds_reality_mldsa_verification_only_when_nonempty() {
        let with_value = build_stream(
            "raw",
            "reality",
            &params(&[("pbk", "public-key"), ("pqv", "verification-key")]),
            "node.example",
        )
        .unwrap();
        assert_eq!(
            with_value["realitySettings"]["mldsa65Verify"],
            "verification-key"
        );

        let empty_value = build_stream(
            "raw",
            "reality",
            &params(&[("pbk", "public-key"), ("pqv", "")]),
            "node.example",
        )
        .unwrap();
        assert!(empty_value["realitySettings"]
            .get("mldsa65Verify")
            .is_none());
    }

    #[test]
    fn build_stream_handles_xhttp_extra_and_ignores_invalid_json() {
        let stream = build_stream(
            "splithttp",
            "none",
            &params(&[
                ("path", "/custom"),
                ("host", "cdn.example"),
                ("mode", "packet-up"),
                ("extra", r#"{"headers":{"x":"y"}}"#),
            ]),
            "node.example",
        )
        .unwrap();
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(
            stream["xhttpSettings"],
            json!({
                "path": "/custom",
                "host": "cdn.example",
                "mode": "packet-up",
                "extra": {"headers": {"x": "y"}}
            })
        );

        let invalid =
            build_stream("xhttp", "none", &params(&[("extra", "{")]), "node.example").unwrap();
        assert!(invalid["xhttpSettings"].get("extra").is_none());
    }

    #[test]
    fn build_stream_handles_grpc_ws_and_httpupgrade_settings() {
        let grpc = build_stream(
            "gun",
            "none",
            &params(&[("path", "///svc///")]),
            "node.example",
        )
        .unwrap();
        assert_eq!(grpc["network"], "grpc");
        assert_eq!(grpc["grpcSettings"]["serviceName"], "svc");

        let ws = build_stream("ws", "none", &HashMap::new(), "node.example").unwrap();
        assert!(ws.get("wsSettings").is_some());
        let upgrade = build_stream("httpupgrade", "none", &HashMap::new(), "node.example").unwrap();
        assert_eq!(
            upgrade["httpupgradeSettings"],
            json!({"path": "/", "host": ""})
        );
        assert!(upgrade.get("wsSettings").is_none());
    }

    #[test]
    fn build_stream_http_upgrade_alias_and_hysteria_optional_auth_are_covered() {
        let alias = build_stream(
            "http-upgrade",
            "none",
            &params(&[("path", "/upgrade"), ("host", "front.example")]),
            "node.example",
        )
        .unwrap();
        assert_eq!(alias["network"], "httpupgrade");
        assert_eq!(
            alias["httpupgradeSettings"],
            json!({"path": "/upgrade", "host": "front.example"})
        );

        let no_auth = build_stream("hysteria", "tls", &HashMap::new(), "node.example").unwrap();
        assert_eq!(no_auth["hysteriaSettings"]["version"], 2);
        assert!(no_auth["hysteriaSettings"].get("auth").is_none());
        assert!(build_stream("hysteria", "reality", &HashMap::new(), "node.example").is_none());
    }

    #[test]
    fn build_stream_omits_empty_hysteria_auth() {
        let stream =
            build_stream("hysteria", "tls", &params(&[("auth", "")]), "node.example").unwrap();

        assert!(stream["hysteriaSettings"].get("auth").is_none());
    }

    #[test]
    fn build_stream_validates_kcp_header_and_finalmask_json() {
        assert!(build_stream(
            "mkcp",
            "none",
            &params(&[("headerType", "utp")]),
            "node.example"
        )
        .is_none());
        assert!(build_stream(
            "kcp",
            "none",
            &params(&[("headerType", "utp"), ("fm", "{}")]),
            "node.example"
        )
        .is_some());
        assert!(build_stream(
            "kcp",
            "none",
            &params(&[("headerType", "none")]),
            "node.example"
        )
        .is_some());

        let valid = build_stream(
            "raw",
            "none",
            &params(&[("fm", r#"{"enabled":true}"#)]),
            "node.example",
        )
        .unwrap();
        assert_eq!(valid["finalmask"], json!({"enabled": true}));
        for invalid in ["not json", "[]", "null", "1"] {
            let stream =
                build_stream("raw", "none", &params(&[("fm", invalid)]), "node.example").unwrap();
            assert!(stream.get("finalmask").is_none());
        }
    }

    #[test]
    fn shadowsocks_method_normalization_trims_and_maps_aliases() {
        assert_eq!(
            normalize_ss_method("  CHACHA20-POLY1305  "),
            "chacha20-ietf-poly1305"
        );
        assert_eq!(
            normalize_ss_method("XChaCha20-Poly1305"),
            "xchacha20-ietf-poly1305"
        );
        assert_eq!(normalize_ss_method(" AES-256-GCM "), "aes-256-gcm");
        assert_eq!(normalize_ss_method(""), "");
    }

    #[test]
    fn shadowsocks_validation_accepts_exact_allowlist_only() {
        for method in SS_ALLOWED_METHODS {
            assert!(
                ss_method_supported(method),
                "expected supported method: {method}"
            );
        }
        for method in ["", " aes-256-gcm", "chacha20-poly1305 ", "unknown"] {
            assert!(
                !ss_method_supported(method),
                "unexpectedly supported method: {method}"
            );
        }
        assert!(ss_method_supported(&normalize_ss_method(
            "CHACHA20-POLY1305"
        )));
    }

    #[test]
    fn shadowsocks_method_validation_is_case_insensitive_and_rejects_removed_methods() {
        assert!(ss_method_supported("AES-256-GCM"));
        assert!(ss_method_supported("2022-BLAKE3-AES-128-GCM"));
        assert!(!ss_method_supported("plain"));
    }

    #[test]
    fn mihomo_only_shadowsocks_ciphers_are_parseable_but_not_xray_speed_checkable() {
        for method in SS_MIHOMO_ONLY_METHODS {
            assert!(ss_method_supported(method), "{method}");
            assert!(!ss_method_supported_by_xray(method), "{method}");
        }
        assert!(ss_method_supported("none"));
        assert!(ss_method_supported("aes-128-cfb"));
    }

    #[test]
    fn protocol_settings_helpers_preserve_credentials_and_protocol_defaults() {
        let vless = vless_settings("vless.example", 443, "uuid", &HashMap::new());
        assert_eq!(
            vless,
            json!({
                "address": "vless.example",
                "port": 443,
                "level": 0,
                "id": "uuid",
                "encryption": "none",
                "flow": ""
            })
        );

        let vmess = vmess_settings("vmess.example", 8443, "vmess-id", "chacha20-poly1305");
        assert_eq!(
            vmess,
            json!({
                "address": "vmess.example",
                "port": 8443,
                "level": 0,
                "id": "vmess-id",
                "security": "chacha20-poly1305",
                "experiments": ""
            })
        );

        let trojan = trojan_settings("trojan.example", 443, "p@ss", &HashMap::new());
        assert_eq!(trojan["password"], "p@ss");
        assert_eq!(trojan["flow"], "");

        let shadowsocks = ss_settings("ss.example", 8388, "aes-256-gcm", "s:ecret");
        assert_eq!(shadowsocks["method"], "aes-256-gcm");
        assert_eq!(shadowsocks["password"], "s:ecret");
        assert_eq!(shadowsocks["uot"], false);
        assert_eq!(shadowsocks["uotVersion"], 0);
    }

    #[test]
    fn xray_shadowsocks_method_check_is_case_insensitive_but_keeps_its_allowlist() {
        assert!(ss_method_supported_by_xray("AES-256-GCM"));
        assert!(ss_method_supported_by_xray("2022-BLAKE3-CHACHA20-POLY1305"));
        assert!(!ss_method_supported_by_xray("AES-128-CFB"));
        assert!(!ss_method_supported_by_xray("unknown"));
    }
}
