//! Генерация конфига Clash / mihomo из нейтрального описания прокси.
//!
//! Крейт ничего не знает о типах основного проекта: на вход подаются
//! [`Source`] с xray-подобными `settings`/`stream` (как `serde_json::Value`),
//! на выходе — готовый YAML ([`render`]). Никакого I/O — только чистая логика.

mod convert;
mod groups;
mod rules;

use anyhow::Result;
use serde_json::Value;
use serde_yaml_ng::{Mapping, Value as Yaml};
use std::collections::HashSet;

/// Один прокси на входе генератора.
#[derive(Clone, Debug)]
pub struct Source {
    /// vless | vmess | trojan | shadowsocks | hysteria | hysteria2
    pub proto: String,
    /// Отображаемое имя (например `[DE] - 001`)
    pub name: String,
    pub server: String,
    pub port: u16,
    /// ISO-код страны (`XX`, `CLOUDFLARE`, `RU-BLOCKED`, …)
    pub country: String,
    /// xray outbound settings
    pub settings: Value,
    /// xray streamSettings (может отсутствовать)
    pub stream: Option<Value>,
}

/// Параметры генерации.
#[derive(Clone, Debug)]
pub struct Options {
    /// Создавать группы по странам (`🇽🇽 XX`, `🌐 Прочие`)
    pub include_country: bool,
    /// Создавать группы-категории (Telegram/AI/YouTube/Игры)
    pub include_categories: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            include_country: true,
            include_categories: true,
        }
    }
}

/// Имя группы ручного маршрута «напрямую» (транзит русских правил и т.п.).
pub(crate) const DIRECT_GROUP: &str = "🟢 Напрямую";

/// Что получилось в итоге.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Сколько прокси попало в конфиг
    pub proxies: usize,
    /// Сколько пропущено (неподдерживаемый протокол)
    pub skipped: usize,
    /// Сколько стран сгруппировано
    pub countries: usize,
    /// Сколько групп создано (включая 🚀/🌍/🔓/🟢 и авто ♻️/⚡/⚖️)
    pub groups: usize,
}

/// Собирает конфиг Clash/mihomo в строку YAML.
pub fn render(sources: &[Source], opt: &Options) -> Result<(String, Report)> {
    let mut entries: Vec<groups::Entry> = Vec::with_capacity(sources.len());
    let mut proxies: Vec<Yaml> = Vec::with_capacity(sources.len());
    let mut used: HashSet<String> = HashSet::new();
    let mut skipped = 0usize;

    for s in sources {
        let mut m = match convert::to_clash(s) {
            Some(m) => m,
            None => {
                skipped += 1;
                continue;
            }
        };

        let base = if s.name.trim().is_empty() {
            format!("{}:{}", s.server, s.port)
        } else {
            s.name.trim().to_string()
        };
        let mut name = base.clone();
        if !used.insert(name.clone()) {
            // Есть не более sources.len() уже занятых имён, поэтому среди
            // sources.len() + 1 суффиксов гарантированно найдётся свободный.
            for suffix in 2..=sources.len().saturating_add(2) {
                let candidate = format!("{base} #{suffix}");
                if used.insert(candidate.clone()) {
                    name = candidate;
                    break;
                }
            }
        }
        put(&mut m, "name", str_val(&name));

        entries.push(groups::Entry {
            name,
            country: s.country.clone(),
        });
        proxies.push(Yaml::Mapping(m));
    }

    let (group_list, countries) = groups::build(&entries, opt);
    let groups_count = group_list.len();

    let mut root = Mapping::new();
    rules::insert_globals(&mut root);
    put(&mut root, "proxy-groups", Yaml::Sequence(group_list));
    put(&mut root, "proxies", Yaml::Sequence(proxies));
    put(&mut root, "rules", rules::rules(opt.include_categories));

    let body = serde_yaml_ng::to_string(&Yaml::Mapping(root))?;
    let header = format!(
        "# Сгенерировано proxy-rs (proxy-clash)\n# прокси: {} | групп: {} | стран: {}\n",
        entries.len(),
        groups_count,
        countries
    );

    Ok((
        format!("{header}{body}"),
        Report {
            proxies: entries.len(),
            skipped,
            countries,
            groups: groups_count,
        },
    ))
}

// ------------------------- вспомогательные API -------------------------

pub(crate) fn put(m: &mut Mapping, key: &str, value: Yaml) {
    m.insert(Yaml::String(key.to_string()), value);
}

pub(crate) fn str_val(s: &str) -> Yaml {
    Yaml::String(s.to_string())
}

pub(crate) fn num(n: u64) -> Yaml {
    Yaml::Number(serde_yaml_ng::Number::from(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vless(name: &str, country: &str, net: &str, sec: &str, stream_extra: Value) -> Source {
        let mut stream = json!({ "network": net, "security": sec });
        if sec == "reality" {
            stream["realitySettings"] = json!({
                "password": "PBK",
                "shortId": "abcd",
                "serverName": "example.com",
                "fingerprint": "chrome",
            });
        } else if sec == "tls" {
            stream["tlsSettings"] = json!({
                "serverName": "sni.example",
                "fingerprint": "firefox",
                "allowInsecure": true,
            });
        }
        if let Value::Object(extra) = stream_extra {
            for (k, v) in extra {
                stream[k] = v;
            }
        }
        Source {
            proto: "vless".into(),
            name: name.into(),
            server: "1.2.3.4".into(),
            port: 443,
            country: country.into(),
            settings: json!({ "address": "1.2.3.4", "port": 443, "id": "uuid-1", "flow": "xtls-rprx-vision" }),
            stream: Some(stream),
        }
    }

    #[test]
    fn renders_valid_yaml_with_groups() {
        let src = vec![
            vless("[DE] - 001", "DE", "raw", "reality", json!({})),
            vless(
                "[DE] - 002",
                "DE",
                "ws",
                "tls",
                json!({ "wsSettings": { "path": "/x", "host": "h.example" } }),
            ),
            vless(
                "[RU] - 001",
                "RU",
                "grpc",
                "tls",
                json!({ "grpcSettings": { "serviceName": "svc" } }),
            ),
        ];
        let (yaml, rep) = render(&src, &Options::default()).unwrap();
        assert_eq!(rep.proxies, 3);
        assert_eq!(rep.skipped, 0);
        assert!(rep.groups >= 6, "групп: {}", rep.groups);

        let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        assert!(parsed.get("proxies").unwrap().as_sequence().unwrap().len() == 3);
        assert!(parsed.get("proxy-groups").is_some());
        assert!(parsed.get("rules").is_some());
        assert!(yaml.contains("reality-opts"));
        assert!(yaml.contains("public-key: PBK"));
        assert!(yaml.contains("ws-opts"));
        assert!(yaml.contains("grpc-service-name: svc"));
    }

    #[test]
    fn trojan_uses_sni() {
        let mut s = vless("[XX] - 001", "XX", "ws", "tls", json!({}));
        s.proto = "trojan".into();
        s.settings = json!({ "address": "1.2.3.4", "port": 443, "password": "pw" });
        let (yaml, _) = render(&[s], &Options::default()).unwrap();
        assert!(yaml.contains("sni: sni.example"), "{yaml}");
        assert!(!yaml.contains("servername: sni.example"));
    }

    #[test]
    fn renders_hysteria_v1_and_v2_proxy_entries() {
        let mut v1 = vless("hy1", "DE", "raw", "none", json!({}));
        v1.proto = "hysteria".into();
        v1.settings = json!({
            "auth": "legacy-auth",
            "obfs": "legacy-obfs",
            "upMbps": 12,
            "downMbps": 45,
            "sni": "hy1.example"
        });

        let mut v2 = vless("hy2", "NL", "raw", "none", json!({}));
        v2.proto = "hysteria2".into();
        v2.settings = json!({
            "password": "hy2-password",
            "obfs": "salamander",
            "obfsPassword": "hy2-obfs",
            "ports": "443-8443",
            "hopInterval": 30,
            "tls": { "serverName": "hy2.example", "insecure": true }
        });

        let (yaml, report) = render(&[v1, v2], &Options::default()).unwrap();
        let root: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        let proxies = root.get("proxies").unwrap().as_sequence().unwrap();
        assert_eq!(report.proxies, 2);
        assert_eq!(report.skipped, 0);
        assert_eq!(
            proxies[0]
                .get("type")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("hysteria")
        );
        assert_eq!(
            proxies[0]
                .get("auth-str")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("legacy-auth")
        );
        assert_eq!(
            proxies[0]
                .get("protocol")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("udp")
        );
        assert_eq!(
            proxies[0].get("up").and_then(serde_yaml_ng::Value::as_str),
            Some("12")
        );
        assert_eq!(
            proxies[1]
                .get("type")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("hysteria2")
        );
        assert_eq!(
            proxies[1]
                .get("password")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("hy2-password")
        );
        assert_eq!(
            proxies[1]
                .get("obfs-password")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("hy2-obfs")
        );
        assert_eq!(
            proxies[1]
                .get("ports")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("443-8443")
        );
        assert_eq!(
            proxies[1]
                .get("hop-interval")
                .and_then(serde_yaml_ng::Value::as_u64),
            Some(30)
        );
        assert_eq!(
            proxies[1].get("sni").and_then(serde_yaml_ng::Value::as_str),
            Some("hy2.example")
        );
        assert_eq!(
            proxies[1]
                .get("skip-cert-verify")
                .and_then(serde_yaml_ng::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn skips_unknown_proto() {
        let mut s = vless("[XX] - 001", "XX", "raw", "none", json!({}));
        s.proto = "unknown".into();
        let (_, rep) = render(&[s], &Options::default()).unwrap();
        assert_eq!(rep.proxies, 0);
        assert_eq!(rep.skipped, 1);
    }

    #[test]
    fn dedupes_names() {
        let a = vless("dup", "DE", "raw", "none", json!({}));
        let b = vless("dup", "DE", "raw", "none", json!({}));
        let (yaml, rep) = render(&[a, b], &Options::default()).unwrap();
        assert_eq!(rep.proxies, 2);
        assert!(yaml.contains("dup #2"));
    }

    #[test]
    fn toggles_remove_groups() {
        let src = vec![vless("[DE] - 001", "DE", "raw", "none", json!({}))];
        let (yaml, rep) = render(
            &src,
            &Options {
                include_country: false,
                include_categories: false,
            },
        )
        .unwrap();
        assert_eq!(rep.countries, 0);
        assert_eq!(rep.groups, 6);
        assert!(!yaml.contains("Telegram"));
    }

    #[test]
    fn empty_and_unsupported_inputs_still_render_parseable_yaml() {
        let mut unsupported = vless("unknown", "XX", "raw", "none", json!({}));
        unsupported.proto = "unknown".into();
        for sources in [Vec::new(), vec![unsupported]] {
            let (yaml, report) = render(&sources, &Options::default()).unwrap();
            let root: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
            assert!(root
                .get("proxies")
                .unwrap()
                .as_sequence()
                .unwrap()
                .is_empty());
            assert!(root.get("proxy-groups").unwrap().as_sequence().is_some());
            assert!(root.get("rules").unwrap().as_sequence().is_some());
            assert_eq!(report.proxies, 0);
            assert_eq!(report.skipped, sources.len());
        }
    }

    #[test]
    fn trims_names_and_resolves_collisions_deterministically() {
        let a = vless("  same  ", "DE", "raw", "none", json!({}));
        let b = vless("same", "DE", "raw", "none", json!({}));
        let c = vless("", "XX", "raw", "none", json!({}));
        let d = vless("same", "DE", "raw", "none", json!({}));
        let (yaml, report) = render(&[a, b, c, d], &Options::default()).unwrap();
        let root: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        let names: Vec<&str> = root
            .get("proxies")
            .unwrap()
            .as_sequence()
            .unwrap()
            .iter()
            .map(|proxy| proxy.get("name").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(names, ["same", "same #2", "1.2.3.4:443", "same #3"]);
        assert_eq!(report.proxies, 4);
        assert_eq!(report.skipped, 0);
    }

    #[test]
    fn non_object_stream_extras_are_ignored() {
        let source = vless("proxy", "DE", "raw", "none", json!(null));
        let (yaml, report) = render(&[source], &Options::default()).unwrap();

        assert_eq!(report.proxies, 1);
        assert!(yaml.contains("name: proxy"));
    }

    #[test]
    fn render_report_matches_serialized_sections() {
        let sources = vec![
            vless("one", "DE", "raw", "none", json!({})),
            vless("two", "RU-BLOCKED", "raw", "none", json!({})),
        ];
        let (yaml, report) = render(&sources, &Options::default()).unwrap();
        let root: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(
            root.get("proxies").unwrap().as_sequence().unwrap().len(),
            report.proxies
        );
        assert_eq!(
            root.get("proxy-groups")
                .unwrap()
                .as_sequence()
                .unwrap()
                .len(),
            report.groups
        );
        assert_eq!(report.countries, 2);
        assert!(yaml.starts_with("# Сгенерировано proxy-rs (proxy-clash)\n"));
    }

    #[test]
    fn renders_all_requested_protocol_families_with_their_credentials_and_transports() {
        let mut vless_source = vless(
            "vless",
            "DE",
            "grpc",
            "tls",
            json!({"grpcSettings":{"serviceName":"vless-service"}}),
        );
        vless_source.settings["flow"] = json!("xtls-rprx-vision");

        let mut vmess = vless(
            "vmess",
            "NL",
            "ws",
            "tls",
            json!({
                "wsSettings":{"path":"/vmess", "host":"vmess.example"}
            }),
        );
        vmess.proto = "vmess".into();
        vmess.settings = json!({"id":"vmess-id", "security":"aes-128-gcm"});

        let mut ss = vless("ss", "JP", "raw", "none", json!({}));
        ss.proto = "shadowsocks".into();
        ss.settings = json!({"method":"chacha20-poly1305", "password":"ss-password"});

        let mut trojan = vless(
            "trojan",
            "GB",
            "grpc",
            "tls",
            json!({
                "grpcSettings":{"serviceName":"trojan-service"}
            }),
        );
        trojan.proto = "trojan".into();
        trojan.settings = json!({"password":"trojan-password"});

        let mut hysteria1 = vless("hysteria1", "FR", "raw", "none", json!({}));
        hysteria1.proto = "hysteria1".into();
        hysteria1.settings = json!({"auth":"hy1-auth", "upMbps":12, "downMbps":40});

        let mut hysteria2 = vless("hysteria2", "SE", "raw", "none", json!({}));
        hysteria2.proto = "hysteria2".into();
        hysteria2.settings =
            json!({"password":"hy2-password", "obfs":"salamander", "obfsPassword":"hy2-obfs"});

        let (yaml, report) = render(
            &[vless_source, vmess, ss, trojan, hysteria1, hysteria2],
            &Options::default(),
        )
        .unwrap();
        let root: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        let proxies = root.get("proxies").unwrap().as_sequence().unwrap();

        assert_eq!(report.proxies, 6);
        assert_eq!(report.skipped, 0);
        assert_eq!(
            proxies
                .iter()
                .map(|proxy| proxy.get("type").unwrap().as_str().unwrap())
                .collect::<Vec<_>>(),
            ["vless", "vmess", "ss", "trojan", "hysteria", "hysteria2"]
        );
        assert_eq!(
            proxies[0]
                .get("flow")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            proxies[0]
                .get("grpc-opts")
                .and_then(|v| v.get("grpc-service-name"))
                .and_then(serde_yaml_ng::Value::as_str),
            Some("vless-service")
        );
        assert_eq!(
            proxies[1]
                .get("uuid")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("vmess-id")
        );
        assert_eq!(
            proxies[1]
                .get("ws-opts")
                .and_then(|v| v.get("path"))
                .and_then(serde_yaml_ng::Value::as_str),
            Some("/vmess")
        );
        assert_eq!(
            proxies[2]
                .get("cipher")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("chacha20-ietf-poly1305")
        );
        assert_eq!(
            proxies[2]
                .get("password")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("ss-password")
        );
        assert_eq!(
            proxies[3]
                .get("password")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("trojan-password")
        );
        assert_eq!(
            proxies[3].get("sni").and_then(serde_yaml_ng::Value::as_str),
            Some("sni.example")
        );
        assert_eq!(
            proxies[4]
                .get("auth-str")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("hy1-auth")
        );
        assert_eq!(
            proxies[5]
                .get("password")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("hy2-password")
        );
        assert_eq!(
            proxies[5]
                .get("obfs-password")
                .and_then(serde_yaml_ng::Value::as_str),
            Some("hy2-obfs")
        );
    }
}
