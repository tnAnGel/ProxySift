//! Глобальные секции и правила маршрутизации Clash/mihomo.

use crate::{num, put, str_val, DIRECT_GROUP};
use serde_yaml_ng::{Mapping, Value as Yaml};

/// Добавляет в корневой mapping глобальные секции (шаблон проекта).
pub fn insert_globals(root: &mut Mapping) {
    put(root, "mode", str_val("rule"));
    put(root, "ipv6", Yaml::Bool(false));
    put(root, "log-level", str_val("info"));
    put(root, "allow-lan", Yaml::Bool(false));
    put(root, "unified-delay", Yaml::Bool(true));
    put(root, "tcp-concurrent", Yaml::Bool(true));
    put(root, "external-controller", str_val("127.0.0.1:9090"));
    put(root, "dns", dns());
    put(root, "keep-alive-idle", num(600));
    put(root, "keep-alive-interval", num(30));
    put(root, "profile", profile());
    put(root, "sniffer", sniffer());
}

/// Список правил маршрутизации.
pub fn rules(include_categories: bool) -> Yaml {
    let mut r: Vec<Yaml> = vec![
        str_val("GEOSITE,private,DIRECT"),
        str_val("GEOIP,private,DIRECT,no-resolve"),
        str_val("GEOSITE,category-ads-all,REJECT"),
        str_val(&format!("GEOSITE,CATEGORY-BANK-RU,{DIRECT_GROUP}")),
        str_val(&format!("GEOSITE,category-ru,{DIRECT_GROUP}")),
        str_val(&format!("GEOIP,RU,{DIRECT_GROUP},no-resolve")),
    ];

    let blocked = if include_categories {
        r.push(str_val("GEOSITE,youtube,📺 YouTube"));
        r.push(str_val("GEOSITE,telegram,💬 Telegram"));
        r.push(str_val("GEOSITE,openai,🤖 AI"));
        r.push(str_val("GEOSITE,GOOGLE-GEMINI,🤖 AI"));
        "🔓 Заблокированные"
    } else {
        "🚀 Прокси"
    };

    r.push(Yaml::String(format!("GEOSITE,RU-BLOCKED,{blocked}")));
    r.push(str_val("MATCH,🚀 Прокси"));
    Yaml::Sequence(r)
}

fn dns() -> Yaml {
    let mut m = Mapping::new();
    put(&mut m, "enable", Yaml::Bool(true));
    put(&mut m, "listen", str_val("0.0.0.0:1053"));
    put(&mut m, "ipv6", Yaml::Bool(false));
    put(&mut m, "enhanced-mode", str_val("fake-ip"));
    put(&mut m, "fake-ip-range", str_val("198.18.0.1/16"));
    put(
        &mut m,
        "fake-ip-filter",
        Yaml::Sequence(vec![
            str_val("*.lan"),
            str_val("*.local"),
            str_val("localhost.ptlogin2.qq.com"),
        ]),
    );
    put(
        &mut m,
        "default-nameserver",
        Yaml::Sequence(vec![str_val("223.5.5.5"), str_val("8.8.8.8")]),
    );
    put(
        &mut m,
        "nameserver",
        Yaml::Sequence(vec![
            str_val("https://cloudflare-dns.com/dns-query"),
            str_val("https://dns.google/dns-query"),
            str_val("tls://8.8.8.8"),
        ]),
    );
    let mut policy = Mapping::new();
    put(
        &mut policy,
        "geosite:category-ru",
        str_val("https://dns.alidns.com/dns-query"),
    );
    put(
        &mut policy,
        "geosite:RU-BLOCKED",
        str_val("https://cloudflare-dns.com/dns-query"),
    );
    put(&mut m, "nameserver-policy", Yaml::Mapping(policy));
    Yaml::Mapping(m)
}

fn profile() -> Yaml {
    let mut m = Mapping::new();
    put(&mut m, "store-selected", Yaml::Bool(true));
    put(&mut m, "store-fake-ip", Yaml::Bool(true));
    Yaml::Mapping(m)
}

fn sniffer() -> Yaml {
    let mut m = Mapping::new();
    put(&mut m, "enable", Yaml::Bool(true));

    let mut sniff = Mapping::new();
    put(&mut sniff, "HTTP", sniff_proto(&["80", "8080-8880"], true));
    put(&mut sniff, "TLS", sniff_proto(&["443", "8443"], false));
    put(&mut sniff, "QUIC", sniff_proto(&["443", "8443"], false));
    put(&mut m, "sniff", Yaml::Mapping(sniff));

    put(
        &mut m,
        "skip-domain",
        Yaml::Sequence(vec![str_val("Mijia Cloud"), str_val("dlg.io.mi.com")]),
    );
    Yaml::Mapping(m)
}

fn sniff_proto(ports: &[&str], override_destination: bool) -> Yaml {
    let mut m = Mapping::new();
    put(
        &mut m,
        "ports",
        Yaml::Sequence(ports.iter().map(|p| str_val(p)).collect()),
    );
    if override_destination {
        put(&mut m, "override-destination", Yaml::Bool(true));
    }
    Yaml::Mapping(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globals_present() {
        let mut root = Mapping::new();
        insert_globals(&mut root);
        for key in [
            "mode",
            "dns",
            "profile",
            "sniffer",
            "keep-alive-idle",
            "external-controller",
            "proxy-groups",
        ] {
            if key == "proxy-groups" {
                continue; // добавляется отдельно
            }
            assert!(root.contains_key(Yaml::String(key.into())), "нет {key}");
        }
    }

    #[test]
    fn rules_with_categories_route_blocked() {
        let seq = rules(true);
        let list = seq.as_sequence().unwrap();
        assert!(list
            .iter()
            .any(|v| v.as_str() == Some("GEOSITE,youtube,📺 YouTube")));
        assert!(list.iter().any(|v| v.as_str() == Some("MATCH,🚀 Прокси")));
    }

    #[test]
    fn rules_without_categories_skip_youtube() {
        let seq = rules(false);
        let list = seq.as_sequence().unwrap();
        assert!(!list
            .iter()
            .any(|v| v.as_str() == Some("GEOSITE,youtube,📺 YouTube")));
        assert!(list
            .iter()
            .any(|v| v.as_str() == Some("GEOSITE,RU-BLOCKED,🚀 Прокси")));
    }

    #[test]
    fn russian_rules_route_to_direct_group() {
        let seq = rules(true);
        let list = seq.as_sequence().unwrap();
        let expect = [
            format!("GEOSITE,CATEGORY-BANK-RU,{DIRECT_GROUP}"),
            format!("GEOSITE,category-ru,{DIRECT_GROUP}"),
            format!("GEOIP,RU,{DIRECT_GROUP},no-resolve"),
        ];
        for rule in &expect {
            assert!(
                list.iter().any(|v| v.as_str() == Some(rule.as_str())),
                "нет {rule}"
            );
        }
    }

    #[test]
    fn process_name_rules_removed() {
        let seq = rules(true);
        let list = seq.as_sequence().unwrap();
        assert!(!list.iter().any(|v| v
            .as_str()
            .map(|s| s.starts_with("PROCESS-NAME"))
            .unwrap_or(false)));
    }

    #[test]
    fn category_toggle_only_changes_service_rules_and_blocked_route() {
        let with_categories = rules(true).as_sequence().unwrap().clone();
        let without_categories = rules(false).as_sequence().unwrap().clone();
        for rule in [
            "GEOSITE,youtube,📺 YouTube",
            "GEOSITE,telegram,💬 Telegram",
            "GEOSITE,openai,🤖 AI",
            "GEOSITE,GOOGLE-GEMINI,🤖 AI",
        ] {
            assert!(with_categories
                .iter()
                .any(|value| value.as_str() == Some(rule)));
            assert!(!without_categories
                .iter()
                .any(|value| value.as_str() == Some(rule)));
        }
        assert!(with_categories
            .iter()
            .any(|value| value.as_str() == Some("GEOSITE,RU-BLOCKED,🔓 Заблокированные")));
        assert!(without_categories
            .iter()
            .any(|value| value.as_str() == Some("GEOSITE,RU-BLOCKED,🚀 Прокси")));
        assert_eq!(
            with_categories.last().and_then(Yaml::as_str),
            Some("MATCH,🚀 Прокси")
        );
        assert_eq!(
            without_categories.last().and_then(Yaml::as_str),
            Some("MATCH,🚀 Прокси")
        );
    }

    #[test]
    fn globals_have_expected_nested_types_and_values() {
        let mut root = Mapping::new();
        insert_globals(&mut root);
        assert_eq!(root.get("mode").and_then(Yaml::as_str), Some("rule"));
        assert_eq!(root.get("ipv6"), Some(&Yaml::Bool(false)));

        let dns = root.get("dns").and_then(Yaml::as_mapping).unwrap();
        assert_eq!(
            dns.get("enhanced-mode").and_then(Yaml::as_str),
            Some("fake-ip")
        );
        assert_eq!(
            dns.get("fake-ip-filter")
                .and_then(Yaml::as_sequence)
                .unwrap()
                .len(),
            3
        );
        assert!(dns
            .get("nameserver-policy")
            .and_then(Yaml::as_mapping)
            .unwrap()
            .contains_key(Yaml::String("geosite:category-ru".into())));

        let profile = root.get("profile").and_then(Yaml::as_mapping).unwrap();
        assert_eq!(profile.get("store-selected"), Some(&Yaml::Bool(true)));
        assert_eq!(profile.get("store-fake-ip"), Some(&Yaml::Bool(true)));

        let sniffer = root.get("sniffer").and_then(Yaml::as_mapping).unwrap();
        let sniff = sniffer.get("sniff").and_then(Yaml::as_mapping).unwrap();
        assert_eq!(
            sniff
                .get("HTTP")
                .and_then(Yaml::as_mapping)
                .unwrap()
                .get("override-destination"),
            Some(&Yaml::Bool(true))
        );
        assert!(!sniff
            .get("TLS")
            .and_then(Yaml::as_mapping)
            .unwrap()
            .contains_key(Yaml::String("override-destination".into())));
    }
}
