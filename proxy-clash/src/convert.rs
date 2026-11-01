//! xray settings/stream -> Clash/mihomo proxy (best-effort).

use crate::{num, put, str_val, Source};
use serde_json::Value;
use serde_yaml_ng::{Mapping, Value as Yaml};

const DEFAULT_HYSTERIA1_UP: &str = "10 Mbps";
const DEFAULT_HYSTERIA1_DOWN: &str = "50 Mbps";

/// Преобразует [`Source`] в Clash-proxy. `None` — неизвестный протокол.
pub fn to_clash(s: &Source) -> Option<Mapping> {
    let st = &s.settings;
    let mut m = Mapping::new();
    put(&mut m, "name", str_val(&s.name));

    match s.proto.as_str() {
        "vless" => {
            put(&mut m, "type", str_val("vless"));
            put(&mut m, "server", str_val(&s.server));
            put(&mut m, "port", num(s.port as u64));
            put(&mut m, "uuid", str_val(jstr(st, "id").unwrap_or("")));
            if let Some(f) = jstr(st, "flow").filter(|x| !x.is_empty()) {
                put(&mut m, "flow", str_val(f));
            }
        }
        "vmess" => {
            put(&mut m, "type", str_val("vmess"));
            put(&mut m, "server", str_val(&s.server));
            put(&mut m, "port", num(s.port as u64));
            put(&mut m, "uuid", str_val(jstr(st, "id").unwrap_or("")));
            put(&mut m, "alterId", num(0));
            let cipher = jstr(st, "security")
                .filter(|c| !c.is_empty() && *c != "none")
                .unwrap_or("auto");
            put(&mut m, "cipher", str_val(cipher));
        }
        "trojan" => {
            put(&mut m, "type", str_val("trojan"));
            put(&mut m, "server", str_val(&s.server));
            put(&mut m, "port", num(s.port as u64));
            put(
                &mut m,
                "password",
                str_val(jstr(st, "password").unwrap_or("")),
            );
        }
        "shadowsocks" => {
            put(&mut m, "type", str_val("ss"));
            put(&mut m, "server", str_val(&s.server));
            put(&mut m, "port", num(s.port as u64));
            put(
                &mut m,
                "cipher",
                str_val(&normalize_ss_method(jstr(st, "method").unwrap_or("none"))),
            );
            put(
                &mut m,
                "password",
                str_val(jstr(st, "password").unwrap_or("")),
            );
        }
        "hysteria" | "hysteria1" => {
            put(&mut m, "type", str_val("hysteria"));
            put(&mut m, "server", str_val(&s.server));
            put(&mut m, "port", num(s.port as u64));
            put(
                &mut m,
                "auth-str",
                str_val(setting_str(st, &["auth", "authStr", "auth-str"]).unwrap_or("")),
            );
            let protocol = setting_str(st, &["protocol"]).unwrap_or("udp");
            put(&mut m, "protocol", str_val(protocol));
            // Hysteria 1 share links name the obfuscation mode `xplus` and
            // carry its password separately as `obfsParam`; Mihomo expects
            // the password itself in the `obfs` field.
            if setting_str(st, &["obfs"]) == Some("xplus") {
                copy_text_setting(
                    &mut m,
                    "obfs",
                    st,
                    &["obfsParam", "obfs-param", "obfs-password"],
                );
            } else {
                copy_text_setting(&mut m, "obfs", st, &["obfs"]);
            }
            copy_rate_setting(&mut m, "up", st, &["up", "upMbps", "up_mbps"]);
            copy_rate_setting(&mut m, "down", st, &["down", "downMbps", "down_mbps"]);
            if s.proto == "hysteria" || s.proto == "hysteria1" {
                if !m.contains_key(str_val("up")) {
                    put(&mut m, "up", str_val(DEFAULT_HYSTERIA1_UP));
                }
                if !m.contains_key(str_val("down")) {
                    put(&mut m, "down", str_val(DEFAULT_HYSTERIA1_DOWN));
                }
            }
            copy_text_setting(&mut m, "ports", st, &["ports"]);
            copy_scalar_setting(&mut m, "hop-interval", st, &["hopInterval", "hop-interval"]);
            apply_hysteria_tls(&mut m, st);
        }
        "hysteria2" | "hy2" => {
            put(&mut m, "type", str_val("hysteria2"));
            put(&mut m, "server", str_val(&s.server));
            put(&mut m, "port", num(s.port as u64));
            put(
                &mut m,
                "password",
                str_val(setting_str(st, &["password", "auth", "authStr"]).unwrap_or("")),
            );
            copy_text_setting(&mut m, "obfs", st, &["obfs"]);
            copy_text_setting(
                &mut m,
                "obfs-password",
                st,
                &["obfsPassword", "obfs-password", "obfs_password"],
            );
            copy_rate_setting(&mut m, "up", st, &["up", "upMbps", "up_mbps"]);
            copy_rate_setting(&mut m, "down", st, &["down", "downMbps", "down_mbps"]);
            copy_text_setting(&mut m, "ports", st, &["ports"]);
            copy_scalar_setting(&mut m, "hop-interval", st, &["hopInterval", "hop-interval"]);
            apply_hysteria_tls(&mut m, st);
        }
        _ => return None,
    }

    if !matches!(
        s.proto.as_str(),
        "hysteria" | "hysteria1" | "hysteria2" | "hy2"
    ) {
        apply_stream(&mut m, &s.proto, s.stream.as_ref());
    }
    put(&mut m, "udp", Yaml::Bool(true));
    Some(m)
}

fn setting_str<'a>(settings: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| settings.get(*key).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
}

fn copy_text_setting(m: &mut Mapping, output_key: &str, settings: &Value, keys: &[&str]) {
    if let Some(value) = setting_str(settings, keys) {
        put(m, output_key, str_val(value));
    }
}

fn copy_rate_setting(m: &mut Mapping, output_key: &str, settings: &Value, keys: &[&str]) {
    let value = keys.iter().find_map(|key| {
        settings.get(*key).and_then(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .or_else(|| value.as_number().map(ToString::to_string))
        })
    });
    if let Some(value) = value {
        put(m, output_key, str_val(&value));
    }
}

fn copy_scalar_setting(m: &mut Mapping, output_key: &str, settings: &Value, keys: &[&str]) {
    let value = keys
        .iter()
        .find_map(|key| settings.get(*key).filter(|value| !value.is_null()));
    if let Some(value) = value {
        match value {
            Value::String(value) if !value.is_empty() => put(m, output_key, str_val(value)),
            Value::Number(value) => {
                if let Some(number) = value.as_u64() {
                    put(m, output_key, num(number));
                } else if let Some(number) = value.as_i64() {
                    put(m, output_key, Yaml::Number(number.into()));
                }
            }
            _ => {}
        }
    }
}

fn apply_hysteria_tls(m: &mut Mapping, settings: &Value) {
    let tls = settings.get("tls").filter(|value| value.is_object());
    let tls_settings = settings.get("tlsSettings");
    let server_name = setting_str(settings, &["sni", "serverName", "servername"])
        .or_else(|| tls.and_then(|tls| setting_str(tls, &["serverName", "sni"])))
        .or_else(|| tls_settings.and_then(|tls| setting_str(tls, &["serverName", "sni"])));
    if let Some(server_name) = server_name {
        put(m, "sni", str_val(server_name));
    }

    let skip_verify = ["insecure", "allowInsecure", "skipCertVerify"]
        .iter()
        .find_map(|key| settings.get(*key).and_then(Value::as_bool))
        .or_else(|| {
            tls.and_then(|tls| {
                ["insecure", "allowInsecure", "skipCertVerify"]
                    .iter()
                    .find_map(|key| tls.get(*key).and_then(Value::as_bool))
            })
        })
        .or_else(|| {
            tls_settings.and_then(|tls| {
                ["insecure", "allowInsecure", "skipCertVerify"]
                    .iter()
                    .find_map(|key| tls.get(*key).and_then(Value::as_bool))
            })
        })
        .unwrap_or(false);
    if skip_verify {
        put(m, "skip-cert-verify", Yaml::Bool(true));
    }

    if let Some(name) = setting_str(settings, &["nameCertVerify", "name-cert-verify"])
        .or_else(|| tls.and_then(|tls| setting_str(tls, &["nameCertVerify", "name-cert-verify"])))
        .or_else(|| {
            tls_settings.and_then(|tls| setting_str(tls, &["nameCertVerify", "name-cert-verify"]))
        })
    {
        put(m, "name-cert-verify", str_val(name));
    }

    if let Some(fingerprint) =
        setting_str(settings, &["fingerprint", "pinSHA256", "clientFingerprint"])
            .or_else(|| {
                tls.and_then(|tls| {
                    setting_str(tls, &["fingerprint", "pinSHA256", "clientFingerprint"])
                })
            })
            .or_else(|| {
                tls_settings.and_then(|tls| {
                    setting_str(tls, &["fingerprint", "pinSHA256", "clientFingerprint"])
                })
            })
    {
        put(m, "fingerprint", str_val(fingerprint));
    }
    let alpn = settings
        .get("alpn")
        .or_else(|| tls.and_then(|tls| tls.get("alpn")))
        .or_else(|| tls_settings.and_then(|tls| tls.get("alpn")));
    if let Some(alpn) = alpn {
        let values: Vec<Yaml> = if let Some(alpn) = alpn.as_array() {
            alpn.iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str_val)
                .collect()
        } else if let Some(alpn) = alpn.as_str() {
            alpn.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str_val)
                .collect()
        } else {
            Vec::new()
        };
        if !values.is_empty() {
            put(m, "alpn", Yaml::Sequence(values));
        }
    }

    if let Some(config) = setting_str(settings, &["ech"])
        .or_else(|| tls.and_then(|tls| setting_str(tls, &["ech"])))
        .or_else(|| tls_settings.and_then(|tls| setting_str(tls, &["ech"])))
    {
        let mut ech_opts = Mapping::new();
        put(&mut ech_opts, "enable", Yaml::Bool(true));
        put(&mut ech_opts, "config", str_val(config));
        put(m, "ech-opts", Yaml::Mapping(ech_opts));
    }
}

/// Переносит tls/reality и транспорт из xray streamSettings в Clash-поля.
fn apply_stream(m: &mut Mapping, proto: &str, stream: Option<&Value>) {
    let net = stream.and_then(|v| jstr(v, "network")).unwrap_or("raw");
    let sec = stream.and_then(|v| jstr(v, "security")).unwrap_or("none");
    // trojan в mihomo использует `sni`, остальные — `servername`.
    let sni_key = if proto == "trojan" {
        "sni"
    } else {
        "servername"
    };

    match sec {
        "tls" => {
            put(m, "tls", Yaml::Bool(true));
            if let Some(t) = stream.and_then(|v| v.get("tlsSettings")) {
                if let Some(sni) = jstr(t, "serverName").filter(|x| !x.is_empty()) {
                    put(m, sni_key, str_val(sni));
                }
                if let Some(fp) = jstr(t, "fingerprint").filter(|x| !x.is_empty()) {
                    put(m, "client-fingerprint", str_val(fp));
                }
                if jbool(t, "allowInsecure") {
                    put(m, "skip-cert-verify", Yaml::Bool(true));
                }
                if let Some(alpn) = t.get("alpn").and_then(|a| a.as_array()) {
                    let list: Vec<Yaml> = alpn
                        .iter()
                        .filter_map(|x| x.as_str())
                        .filter(|x| !x.is_empty())
                        .map(str_val)
                        .collect();
                    if !list.is_empty() {
                        put(m, "alpn", Yaml::Sequence(list));
                    }
                }
            }
        }
        "reality" => {
            put(m, "tls", Yaml::Bool(true));
            if let Some(r) = stream.and_then(|v| v.get("realitySettings")) {
                if let Some(sni) = jstr(r, "serverName").filter(|x| !x.is_empty()) {
                    put(m, sni_key, str_val(sni));
                }
                let fp = jstr(r, "fingerprint")
                    .filter(|x| !x.is_empty())
                    .unwrap_or("chrome");
                put(m, "client-fingerprint", str_val(fp));
                let mut ro = Mapping::new();
                // В xray публичный ключ reality лежит в поле `password`.
                if let Some(pk) = jstr(r, "password").filter(|x| !x.is_empty()) {
                    put(&mut ro, "public-key", str_val(pk));
                }
                if let Some(sid) = jstr(r, "shortId") {
                    put(&mut ro, "short-id", str_val(sid));
                }
                if !ro.is_empty() {
                    put(m, "reality-opts", Yaml::Mapping(ro));
                }
            }
        }
        _ => {}
    }

    match net {
        "raw" | "tcp" => {}
        "ws" => {
            put(m, "network", str_val("ws"));
            if let Some(ws) = stream.and_then(|v| v.get("wsSettings")) {
                ws_opts(m, ws, false);
            }
        }
        // mihomo изображает v2ray http-upgrade как ws с флагом.
        "httpupgrade" => {
            put(m, "network", str_val("ws"));
            if let Some(ws) = stream.and_then(|v| v.get("httpupgradeSettings")) {
                ws_opts(m, ws, true);
            }
        }
        "grpc" => {
            put(m, "network", str_val("grpc"));
            if let Some(gs) = stream.and_then(|v| v.get("grpcSettings")) {
                if let Some(svc) = jstr(gs, "serviceName").filter(|x| !x.is_empty()) {
                    let mut go = Mapping::new();
                    put(&mut go, "grpc-service-name", str_val(svc));
                    put(m, "grpc-opts", Yaml::Mapping(go));
                }
            }
        }
        "xhttp" => {
            put(m, "network", str_val("xhttp"));
            if let Some(xs) = stream.and_then(|v| v.get("xhttpSettings")) {
                let mut xo = Mapping::new();
                if let Some(path) = jstr(xs, "path").filter(|x| !x.is_empty()) {
                    put(&mut xo, "path", str_val(path));
                }
                if let Some(host) = jstr(xs, "host").filter(|x| !x.is_empty()) {
                    put(&mut xo, "host", str_val(host));
                }
                if let Some(mode) = jstr(xs, "mode").filter(|x| !x.is_empty()) {
                    put(&mut xo, "mode", str_val(mode));
                }
                if !xo.is_empty() {
                    put(m, "xhttp-opts", Yaml::Mapping(xo));
                }
            }
        }
        other => {
            put(m, "network", str_val(other));
        }
    }
}

fn ws_opts(m: &mut Mapping, ws: &Value, v2ray_http_upgrade: bool) {
    let mut o = Mapping::new();
    if let Some(path) = jstr(ws, "path").filter(|x| !x.is_empty()) {
        put(&mut o, "path", str_val(path));
    }
    if let Some(host) = jstr(ws, "host").filter(|x| !x.is_empty()) {
        let mut h = Mapping::new();
        put(&mut h, "Host", str_val(host));
        put(&mut o, "headers", Yaml::Mapping(h));
    }
    if v2ray_http_upgrade {
        put(&mut o, "v2ray-http-upgrade", Yaml::Bool(true));
    }
    if !o.is_empty() {
        put(m, "ws-opts", Yaml::Mapping(o));
    }
}

fn normalize_ss_method(method: &str) -> String {
    match method.trim().to_ascii_lowercase().as_str() {
        "chacha20-poly1305" => "chacha20-ietf-poly1305".to_string(),
        "xchacha20-poly1305" => "xchacha20-ietf-poly1305".to_string(),
        "plain" => "none".to_string(),
        other => other.to_string(),
    }
}

fn jstr<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

fn jbool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn source(proto: &str, settings: Value, stream: Option<Value>) -> Source {
        Source {
            proto: proto.into(),
            name: "proxy".into(),
            server: "proxy.example".into(),
            port: 443,
            country: "DE".into(),
            settings,
            stream,
        }
    }

    fn string<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a str> {
        mapping.get(str_val(key)).and_then(Yaml::as_str)
    }

    #[test]
    fn maps_protocol_credentials_and_defaults() {
        let cases = [
            (
                source("vless", json!({"id":"uuid", "flow":"vision"}), None),
                "vless",
                "uuid",
            ),
            (
                source("vmess", json!({"id":"uuid", "security":"none"}), None),
                "vmess",
                "uuid",
            ),
            (
                source("trojan", json!({"password":"secret"}), None),
                "trojan",
                "secret",
            ),
            (
                source(
                    "shadowsocks",
                    json!({"method":"plain", "password":"secret"}),
                    None,
                ),
                "ss",
                "secret",
            ),
        ];

        for (src, expected_type, expected_credential) in cases {
            let proxy = to_clash(&src).expect("supported protocol");
            assert_eq!(string(&proxy, "type"), Some(expected_type));
            assert_eq!(string(&proxy, "server"), Some("proxy.example"));
            assert_eq!(proxy.get(str_val("port")).and_then(Yaml::as_u64), Some(443));
            assert_eq!(proxy.get(str_val("udp")), Some(&Yaml::Bool(true)));
            let credential = if expected_type == "ss" {
                "password"
            } else {
                "uuid"
            };
            let credential = if expected_type == "trojan" || expected_type == "ss" {
                "password"
            } else {
                credential
            };
            assert_eq!(string(&proxy, credential), Some(expected_credential));
        }
    }

    #[test]
    fn protocol_specific_optional_values_and_invalid_types_use_defaults() {
        let vless = to_clash(&source("vless", json!({"id": 12, "flow": ""}), None)).unwrap();
        assert_eq!(string(&vless, "uuid"), Some(""));
        assert!(!vless.contains_key(str_val("flow")));

        for security in ["", "none", "chacha20-ietf-poly1305"] {
            let vmess = to_clash(&source("vmess", json!({"security": security}), None)).unwrap();
            assert_eq!(
                string(&vmess, "cipher"),
                Some(if security.is_empty() || security == "none" {
                    "auto"
                } else {
                    security
                })
            );
            assert_eq!(
                vmess.get(str_val("alterId")).and_then(Yaml::as_u64),
                Some(0)
            );
        }

        let ss = to_clash(&source("shadowsocks", json!({"method": 3}), None)).unwrap();
        assert_eq!(string(&ss, "cipher"), Some("none"));
        assert_eq!(string(&ss, "password"), Some(""));
        assert_eq!(
            string(
                &to_clash(&source("hysteria2", json!({}), None)).unwrap(),
                "type"
            ),
            Some("hysteria2")
        );
    }

    #[test]
    fn unknown_protocol_is_skipped_and_malformed_hysteria_alpn_is_omitted() {
        assert!(to_clash(&source("unknown", json!({}), None)).is_none());

        let hysteria = to_clash(&source("hy2", json!({ "tls": { "alpn": false } }), None)).unwrap();
        assert!(!hysteria.contains_key(str_val("alpn")));
    }

    #[test]
    fn maps_hysteria_v1_options_to_mihomo_fields() {
        let proxy = to_clash(&source(
            "hysteria",
            json!({
                "auth": "secret",
                "protocol": "wechat-video",
                "obfs": "xplus",
                "obfsParam": "obfuscation-secret",
                "upMbps": 25,
                "down_mbps": "80 Mbps",
                "ports": "1000-2000",
                "hopInterval": 15,
                "sni": "front.example",
                "insecure": true,
                "alpn": "h3,http/1.1"
            }),
            None,
        ))
        .unwrap();

        assert_eq!(string(&proxy, "type"), Some("hysteria"));
        assert_eq!(string(&proxy, "auth-str"), Some("secret"));
        assert_eq!(string(&proxy, "protocol"), Some("wechat-video"));
        assert_eq!(string(&proxy, "obfs"), Some("obfuscation-secret"));
        assert_eq!(string(&proxy, "up"), Some("25"));
        assert_eq!(string(&proxy, "down"), Some("80 Mbps"));
        assert_eq!(string(&proxy, "ports"), Some("1000-2000"));
        assert_eq!(
            proxy.get(str_val("hop-interval")).and_then(Yaml::as_u64),
            Some(15)
        );
        assert_eq!(string(&proxy, "sni"), Some("front.example"));
        assert_eq!(
            proxy.get(str_val("skip-cert-verify")),
            Some(&Yaml::Bool(true))
        );
        assert_eq!(
            proxy.get(str_val("alpn")),
            Some(&Yaml::Sequence(vec![str_val("h3"), str_val("http/1.1")]))
        );
        assert_eq!(proxy.get(str_val("udp")), Some(&Yaml::Bool(true)));
    }

    #[test]
    fn maps_hysteria2_uri_options_and_tls_settings() {
        let proxy = to_clash(&source(
            "hysteria2",
            json!({
                "password": "hy2-password",
                "obfs": "salamander",
                "obfsPassword": "obfs-password",
                "up": "30 Mbps",
                "down": 200,
                "ports": "443-8443",
                "hopInterval": 30,
                "tls": {
                    "serverName": "tls.example",
                    "insecure": false,
                    "nameCertVerify": "cert.example",
                    "pinSHA256": "sha256-pin",
                    "ech": "base64-ech-config",
                    "alpn": ["h3"]
                }
            }),
            None,
        ))
        .unwrap();

        assert_eq!(string(&proxy, "type"), Some("hysteria2"));
        assert_eq!(string(&proxy, "password"), Some("hy2-password"));
        assert_eq!(string(&proxy, "obfs"), Some("salamander"));
        assert_eq!(string(&proxy, "obfs-password"), Some("obfs-password"));
        assert_eq!(string(&proxy, "up"), Some("30 Mbps"));
        assert_eq!(string(&proxy, "down"), Some("200"));
        assert_eq!(string(&proxy, "ports"), Some("443-8443"));
        assert_eq!(
            proxy.get(str_val("hop-interval")).and_then(Yaml::as_u64),
            Some(30)
        );
        assert_eq!(string(&proxy, "sni"), Some("tls.example"));
        assert_eq!(string(&proxy, "fingerprint"), Some("sha256-pin"));
        assert_eq!(string(&proxy, "name-cert-verify"), Some("cert.example"));
        let ech_opts = proxy
            .get(str_val("ech-opts"))
            .and_then(Yaml::as_mapping)
            .unwrap();
        assert_eq!(ech_opts.get(str_val("enable")), Some(&Yaml::Bool(true)));
        assert_eq!(
            ech_opts.get(str_val("config")).and_then(Yaml::as_str),
            Some("base64-ech-config")
        );
        assert!(!proxy.contains_key(str_val("skip-cert-verify")));
    }

    #[test]
    fn hysteria_variants_default_and_ignore_malformed_optional_fields() {
        let v1 = to_clash(&source(
            "hysteria1",
            json!({ "auth": 7, "protocol": false, "up": [], "insecure": "true" }),
            Some(json!("malformed stream")),
        ))
        .unwrap();
        assert_eq!(string(&v1, "type"), Some("hysteria"));
        assert_eq!(string(&v1, "auth-str"), Some(""));
        assert_eq!(string(&v1, "protocol"), Some("udp"));
        assert_eq!(string(&v1, "up"), Some(DEFAULT_HYSTERIA1_UP));
        assert_eq!(string(&v1, "down"), Some(DEFAULT_HYSTERIA1_DOWN));
        assert!(!v1.contains_key(str_val("skip-cert-verify")));

        let v2 = to_clash(&source("hy2", json!({}), None)).unwrap();
        assert_eq!(string(&v2, "type"), Some("hysteria2"));
        assert_eq!(string(&v2, "password"), Some(""));
        assert!(!v2.contains_key(str_val("obfs")));
        assert!(!v2.contains_key(str_val("sni")));
        assert!(!v2.contains_key(str_val("up")));
        assert!(!v2.contains_key(str_val("down")));
    }

    #[test]
    fn normalizes_shadowsocks_methods_case_and_whitespace() {
        assert_eq!(
            normalize_ss_method(" CHACHA20-POLY1305 "),
            "chacha20-ietf-poly1305"
        );
        assert_eq!(
            normalize_ss_method("xchacha20-poly1305"),
            "xchacha20-ietf-poly1305"
        );
        assert_eq!(normalize_ss_method("PLAIN"), "none");
        assert_eq!(normalize_ss_method("aes-128-gcm"), "aes-128-gcm");
    }

    #[test]
    fn maps_tls_fields_and_filters_invalid_alpn_values() {
        let src = source(
            "vless",
            json!({"id":"id"}),
            Some(json!({"network":"tcp", "security":"tls", "tlsSettings":{
                "serverName":"sni.example", "fingerprint":"firefox", "allowInsecure":true,
                "alpn":["h2", "", 4, "http/1.1"]
            }})),
        );
        let proxy = to_clash(&src).unwrap();
        assert_eq!(proxy.get(str_val("tls")), Some(&Yaml::Bool(true)));
        assert_eq!(string(&proxy, "servername"), Some("sni.example"));
        assert_eq!(string(&proxy, "client-fingerprint"), Some("firefox"));
        assert_eq!(
            proxy.get(str_val("skip-cert-verify")),
            Some(&Yaml::Bool(true))
        );
        assert_eq!(
            proxy
                .get(str_val("alpn"))
                .and_then(Yaml::as_sequence)
                .unwrap(),
            &vec![str_val("h2"), str_val("http/1.1")]
        );

        let no_sni = to_clash(&source(
            "vless",
            json!({}),
            Some(json!({
                "security":"tls", "tlsSettings":{"serverName":"", "fingerprint":"", "alpn":["", 1]}
            })),
        ))
        .unwrap();
        assert!(!no_sni.contains_key(str_val("servername")));
        assert!(!no_sni.contains_key(str_val("client-fingerprint")));
        assert!(!no_sni.contains_key(str_val("alpn")));
        assert!(!no_sni.contains_key(str_val("skip-cert-verify")));
    }

    #[test]
    fn maps_reality_defaults_and_trojan_sni_key() {
        let vless = to_clash(&source(
            "vless",
            json!({}),
            Some(json!({
                "security":"reality", "realitySettings":{"password":"pub", "shortId":"01"}
            })),
        ))
        .unwrap();
        assert_eq!(string(&vless, "client-fingerprint"), Some("chrome"));
        let reality = vless
            .get(str_val("reality-opts"))
            .and_then(Yaml::as_mapping)
            .unwrap();
        assert_eq!(string(reality, "public-key"), Some("pub"));
        assert_eq!(string(reality, "short-id"), Some("01"));

        let fingerprint = to_clash(&source(
            "vless",
            json!({}),
            Some(json!({
                "security":"reality", "realitySettings":{"fingerprint":"firefox"}
            })),
        ))
        .unwrap();
        assert_eq!(string(&fingerprint, "client-fingerprint"), Some("firefox"));

        let trojan = to_clash(&source(
            "trojan",
            json!({}),
            Some(json!({
                "security":"reality", "realitySettings":{"serverName":"sni.example"}
            })),
        ))
        .unwrap();
        assert_eq!(string(&trojan, "sni"), Some("sni.example"));
        assert!(!trojan.contains_key(str_val("servername")));
        assert!(!trojan.contains_key(str_val("reality-opts")));
    }

    #[test]
    fn maps_supported_networks_and_transport_options() {
        let raw = to_clash(&source("vless", json!({}), None)).unwrap();
        assert!(!raw.contains_key(str_val("network")));

        let ws = to_clash(&source(
            "vless",
            json!({}),
            Some(json!({"network":"ws", "wsSettings":{
                "path":"/socket", "host":"ws.example"
            }})),
        ))
        .unwrap();
        assert_eq!(string(&ws, "network"), Some("ws"));
        let ws_opts = ws
            .get(str_val("ws-opts"))
            .and_then(Yaml::as_mapping)
            .unwrap();
        assert_eq!(string(ws_opts, "path"), Some("/socket"));
        assert_eq!(
            string(
                ws_opts
                    .get(str_val("headers"))
                    .and_then(Yaml::as_mapping)
                    .unwrap(),
                "Host"
            ),
            Some("ws.example")
        );

        let upgrade = to_clash(&source(
            "vless",
            json!({}),
            Some(json!({"network":"httpupgrade", "httpupgradeSettings":{
                "path":"/upgrade", "host":"upgrade.example"
            }})),
        ))
        .unwrap();
        assert_eq!(string(&upgrade, "network"), Some("ws"));
        let upgrade_opts = upgrade
            .get(str_val("ws-opts"))
            .and_then(Yaml::as_mapping)
            .unwrap();
        assert_eq!(
            upgrade_opts.get(str_val("v2ray-http-upgrade")),
            Some(&Yaml::Bool(true))
        );
        assert_eq!(string(upgrade_opts, "path"), Some("/upgrade"));

        let grpc = to_clash(&source(
            "vless",
            json!({}),
            Some(json!({"network":"grpc", "grpcSettings":{"serviceName":"svc"}})),
        ))
        .unwrap();
        assert_eq!(string(&grpc, "network"), Some("grpc"));
        let grpc_opts = grpc
            .get(str_val("grpc-opts"))
            .and_then(Yaml::as_mapping)
            .unwrap();
        assert_eq!(string(grpc_opts, "grpc-service-name"), Some("svc"));

        let xhttp = to_clash(&source(
            "vless",
            json!({}),
            Some(json!({"network":"xhttp", "xhttpSettings":{
                "path":"/x", "host":"x.example", "mode":"packet-up"
            }})),
        ))
        .unwrap();
        assert_eq!(string(&xhttp, "network"), Some("xhttp"));
        let xhttp_opts = xhttp
            .get(str_val("xhttp-opts"))
            .and_then(Yaml::as_mapping)
            .unwrap();
        assert_eq!(string(xhttp_opts, "path"), Some("/x"));
        assert_eq!(string(xhttp_opts, "host"), Some("x.example"));
        assert_eq!(string(xhttp_opts, "mode"), Some("packet-up"));

        let kcp = to_clash(&source("vless", json!({}), Some(json!({"network":"kcp"})))).unwrap();
        assert_eq!(string(&kcp, "network"), Some("kcp"));
    }

    #[test]
    fn httpupgrade_without_settings_keeps_network_without_options() {
        let upgrade = to_clash(&source(
            "vless",
            json!({}),
            Some(json!({"network":"httpupgrade"})),
        ))
        .unwrap();

        assert_eq!(string(&upgrade, "network"), Some("ws"));
        assert!(!upgrade.contains_key(str_val("ws-opts")));
    }

    #[test]
    fn malformed_stream_settings_are_ignored_without_panicking() {
        for stream in [
            json!(null),
            json!("bad"),
            json!({"network": 4, "security": false}),
            json!({"network":"ws", "wsSettings": 1}),
            json!({"network":"grpc", "grpcSettings":{"serviceName": 7}}),
            json!({"network":"xhttp", "xhttpSettings":[]}),
        ] {
            let proxy = to_clash(&source("vless", json!({}), Some(stream))).unwrap();
            assert_eq!(proxy.get(str_val("udp")), Some(&Yaml::Bool(true)));
        }
    }

    #[test]
    fn missing_protocol_settings_are_ignored() {
        let cases = [
            json!({"security":"tls"}),
            json!({"security":"reality"}),
            json!({"network":"grpc"}),
            json!({"network":"xhttp"}),
        ];

        for stream in cases {
            let proxy = to_clash(&source("vless", json!({}), Some(stream))).unwrap();
            assert_eq!(proxy.get(str_val("udp")), Some(&Yaml::Bool(true)));
        }
    }

    #[test]
    fn maps_protocol_specific_fields_and_tls_server_names() {
        let vless = to_clash(&source(
            "vless",
            json!({"id":"vless-id", "flow":"xtls-rprx-vision"}),
            Some(json!({"network":"tcp", "security":"tls", "tlsSettings":{
                "serverName":"vless.example", "alpn":["h2"]
            }})),
        ))
        .unwrap();
        assert_eq!(string(&vless, "uuid"), Some("vless-id"));
        assert_eq!(string(&vless, "flow"), Some("xtls-rprx-vision"));
        assert_eq!(string(&vless, "servername"), Some("vless.example"));

        let vmess = to_clash(&source(
            "vmess",
            json!({"id":"vmess-id", "security":"aes-128-gcm"}),
            Some(json!({"network":"ws", "security":"tls", "tlsSettings":{
                "serverName":"vmess.example"
            }, "wsSettings":{"path":"/vmess"}})),
        ))
        .unwrap();
        assert_eq!(string(&vmess, "uuid"), Some("vmess-id"));
        assert_eq!(string(&vmess, "cipher"), Some("aes-128-gcm"));
        assert_eq!(string(&vmess, "servername"), Some("vmess.example"));
        assert_eq!(string(&vmess, "network"), Some("ws"));

        let trojan = to_clash(&source(
            "trojan",
            json!({"password":"trojan-password"}),
            Some(json!({"security":"tls", "tlsSettings":{
                "serverName":"trojan.example", "fingerprint":"chrome"
            }})),
        ))
        .unwrap();
        assert_eq!(string(&trojan, "password"), Some("trojan-password"));
        assert_eq!(string(&trojan, "sni"), Some("trojan.example"));
        assert_eq!(string(&trojan, "client-fingerprint"), Some("chrome"));
        assert!(!trojan.contains_key(str_val("servername")));

        let ss = to_clash(&source(
            "shadowsocks",
            json!({"method":"CHACHA20-POLY1305", "password":"ss-password"}),
            None,
        ))
        .unwrap();
        assert_eq!(string(&ss, "cipher"), Some("chacha20-ietf-poly1305"));
        assert_eq!(string(&ss, "password"), Some("ss-password"));
    }

    #[test]
    fn hysteria_tls_fallbacks_and_scalar_rates_cover_supported_value_shapes() {
        let proxy = to_clash(&source(
            "hy2",
            json!({
                "authStr":"fallback-password",
                "up_mbps":-5,
                "downMbps":false,
                "hop-interval":-2,
                "tlsSettings":{
                    "sni":"fallback.example",
                    "allowInsecure":true,
                    "clientFingerprint":"firefox",
                    "alpn":" h3, ,h2 ",
                    "ech":"ech-config"
                }
            }),
            None,
        ))
        .unwrap();

        assert_eq!(string(&proxy, "password"), Some("fallback-password"));
        assert_eq!(string(&proxy, "up"), Some("-5"));
        assert!(!proxy.contains_key(str_val("down")));
        assert_eq!(
            proxy.get(str_val("hop-interval")).and_then(Yaml::as_i64),
            Some(-2)
        );
        assert_eq!(string(&proxy, "sni"), Some("fallback.example"));
        assert_eq!(string(&proxy, "fingerprint"), Some("firefox"));
        assert_eq!(
            proxy.get(str_val("skip-cert-verify")),
            Some(&Yaml::Bool(true))
        );
        assert_eq!(
            proxy.get(str_val("alpn")),
            Some(&Yaml::Sequence(vec![str_val("h3"), str_val("h2")]))
        );
        assert_eq!(
            proxy
                .get(str_val("ech-opts"))
                .and_then(Yaml::as_mapping)
                .and_then(|opts| opts.get(str_val("config")))
                .and_then(Yaml::as_str),
            Some("ech-config")
        );
    }

    #[test]
    fn empty_transport_options_and_unknown_transport_are_handled() {
        for (network, options_key) in [
            ("ws", "ws-opts"),
            ("grpc", "grpc-opts"),
            ("xhttp", "xhttp-opts"),
        ] {
            let proxy = to_clash(&source(
                "vless",
                json!({}),
                Some(json!({"network":network})),
            ))
            .unwrap();
            assert_eq!(string(&proxy, "network"), Some(network));
            assert!(!proxy.contains_key(str_val(options_key)));
        }

        let unknown = to_clash(&source(
            "vless",
            json!({}),
            Some(json!({"network":"future-transport", "security":"unknown"})),
        ))
        .unwrap();
        assert_eq!(string(&unknown, "network"), Some("future-transport"));
        assert!(!unknown.contains_key(str_val("tls")));
        assert_eq!(unknown.get(str_val("udp")), Some(&Yaml::Bool(true)));
    }
}
