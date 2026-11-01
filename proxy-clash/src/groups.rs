//! proxy-groups: сначала селекторы (🚀 Прокси / 🌍 Страны / 🔓 Заблокированные /
//! 🟢 Напрямую и категории Telegram/AI/YouTube/Игры), затем авто-группы
//! (♻️ Fallback / ⚡ Авто / ⚖️ Баланс) и в конце группы по странам (включая
//! псевдо-страны вроде Cloudflare/RU-BLOCKED).

use crate::{num, put, str_val, Options, DIRECT_GROUP};
use serde_yaml_ng::{Mapping, Value as Yaml};
use std::collections::BTreeMap;

/// Прокси для группировки.
pub struct Entry {
    pub name: String,
    pub country: String,
}

const AUTO: &str = "⚡ Авто";
const BALANCE: &str = "⚖️ Баланс";
const FALLBACK: &str = "♻️ Fallback";
const MAIN: &str = "🚀 Прокси";
const COUNTRIES: &str = "🌍 Страны";
const BLOCKED: &str = "🔓 Заблокированные";
const OTHER: &str = "🌐 Прочие";
const CATEGORIES: [&str; 4] = ["💬 Telegram", "🤖 AI", "📺 YouTube", "🎮 Игры"];
const TEST_URL: &str = "http://cp.cloudflare.com/generate_204";

/// Возвращает список групп и число стран.
pub fn build(entries: &[Entry], opt: &Options) -> (Vec<Yaml>, usize) {
    let all: Vec<Yaml> = entries.iter().map(|e| str_val(&e.name)).collect();

    let (country_groups, country_names, countries) = if opt.include_country {
        build_countries(entries)
    } else {
        (Vec::new(), Vec::new(), 0)
    };
    let has_countries = !country_names.is_empty();

    let mut groups: Vec<Yaml> = Vec::new();

    // Наборы для ручного выбора: авто-группы и страны (агрегат + отдельные).
    let mut auto_picks = vec![str_val(AUTO), str_val(BALANCE), str_val(FALLBACK)];
    if has_countries {
        auto_picks.push(str_val(COUNTRIES));
    }
    let country_picks = if has_countries {
        country_names.clone()
    } else {
        Vec::new()
    };

    // 🚀 Прокси: ручной выбор верхнего уровня.
    let mut main_members = vec![str_val("DIRECT")];
    main_members.extend(auto_picks.clone());
    main_members.push(str_val(BLOCKED));
    main_members.extend(country_picks.clone());
    groups.push(select(MAIN, main_members));

    // 🌍 Страны: ручная (Manual) группа со всеми странами/псевдо-странами.
    if has_countries {
        groups.push(select(COUNTRIES, country_names.clone()));
    }

    // 🔓 Заблокированные: выбор для заблокированных сервисов.
    let mut blocked_members = auto_picks.clone();
    blocked_members.extend(country_picks.clone());
    groups.push(select(BLOCKED, blocked_members));

    // 🟢 Напрямую: ручной маршрут (DIRECT по умолчанию).
    let mut direct_members = vec![str_val("DIRECT"), str_val(MAIN)];
    direct_members.extend(auto_picks.clone());
    direct_members.push(str_val(BLOCKED));
    direct_members.extend(country_picks.clone());
    groups.push(select(DIRECT_GROUP, direct_members));

    if opt.include_categories {
        let mut cat_members = vec![str_val(MAIN)];
        cat_members.extend(auto_picks.clone());
        cat_members.push(str_val(BLOCKED));
        cat_members.extend(country_picks.clone());
        for name in CATEGORIES {
            groups.push(select(name, cat_members.clone()));
        }
    }

    // Авто-группы без ручного выбора — ниже селекторов.
    groups.push(fallback(FALLBACK, all.clone()));
    groups.push(url_test(AUTO, all.clone()));
    groups.push(load_balance(BALANCE, all));

    // Страны — в самом низу (их выбирают редко).
    groups.extend(country_groups);

    (groups, countries)
}

fn build_countries(entries: &[Entry]) -> (Vec<Yaml>, Vec<Yaml>, usize) {
    let mut buckets: BTreeMap<String, Vec<Yaml>> = BTreeMap::new();
    for e in entries {
        buckets
            .entry(country_group(&e.country))
            .or_default()
            .push(str_val(&e.name));
    }

    let mut groups = Vec::with_capacity(buckets.len());
    let mut names = Vec::with_capacity(buckets.len());
    for (name, members) in buckets {
        names.push(str_val(&name));
        groups.push(url_test(&name, members));
    }
    let count = groups.len();
    (groups, names, count)
}

fn country_group(code: &str) -> String {
    let up = code.trim().to_ascii_uppercase();
    // `XX` = страна не определена — в общую группу, без фейкового флага.
    if up.is_empty() || up == "XX" {
        return OTHER.to_string();
    }
    if let Some(f) = flag(&up) {
        return format!("{f} {up}");
    }
    // Псевдо-страны из geoip.dat — отдельная группа, как у настоящих стран.
    let icon = match up.as_str() {
        "CLOUDFLARE" => "☁️",
        "RU-BLOCKED" => "🔒",
        _ => "🏳️",
    };
    format!("{icon} {up}")
}

/// ISO alpha-2 -> эмодзи-флаг (региональные индикаторы).
fn flag(code: &str) -> Option<String> {
    let b = code.as_bytes();
    if b.len() != 2 || !b.iter().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let mut s = String::with_capacity(8);
    for c in b {
        s.push(
            char::from_u32(0x1F1E6 + (c.to_ascii_uppercase() - b'A') as u32)
                .unwrap_or(char::REPLACEMENT_CHARACTER),
        );
    }
    Some(s)
}

fn select(name: &str, proxies: Vec<Yaml>) -> Yaml {
    let mut m = Mapping::new();
    put(&mut m, "name", str_val(name));
    put(&mut m, "type", str_val("select"));
    put(&mut m, "proxies", Yaml::Sequence(proxies));
    Yaml::Mapping(m)
}

fn url_test(name: &str, proxies: Vec<Yaml>) -> Yaml {
    let mut m = Mapping::new();
    put(&mut m, "name", str_val(name));
    put(&mut m, "type", str_val("url-test"));
    put(&mut m, "url", str_val(TEST_URL));
    put(&mut m, "interval", num(300));
    put(&mut m, "tolerance", num(50));
    put(&mut m, "lazy", Yaml::Bool(false));
    put(&mut m, "proxies", Yaml::Sequence(proxies));
    Yaml::Mapping(m)
}

fn fallback(name: &str, proxies: Vec<Yaml>) -> Yaml {
    let mut m = Mapping::new();
    put(&mut m, "name", str_val(name));
    put(&mut m, "type", str_val("fallback"));
    put(&mut m, "url", str_val(TEST_URL));
    put(&mut m, "interval", num(300));
    put(&mut m, "lazy", Yaml::Bool(false));
    put(&mut m, "proxies", Yaml::Sequence(proxies));
    Yaml::Mapping(m)
}

fn load_balance(name: &str, proxies: Vec<Yaml>) -> Yaml {
    let mut m = Mapping::new();
    put(&mut m, "name", str_val(name));
    put(&mut m, "type", str_val("load-balance"));
    put(&mut m, "strategy", str_val("consistent-hashing"));
    put(&mut m, "url", str_val(TEST_URL));
    put(&mut m, "interval", num(300));
    put(&mut m, "proxies", Yaml::Sequence(proxies));
    Yaml::Mapping(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_group<'a>(groups: &'a [Yaml], name: &str) -> (usize, &'a Yaml) {
        groups
            .iter()
            .enumerate()
            .find(|(_, group)| group.get("name").and_then(Yaml::as_str) == Some(name))
            .unwrap_or_else(|| panic!("нет группы {name}"))
    }

    fn entries() -> Vec<Entry> {
        vec![
            Entry {
                name: "[DE] - 001".into(),
                country: "DE".into(),
            },
            Entry {
                name: "[DE] - 002".into(),
                country: "DE".into(),
            },
            Entry {
                name: "[XX] - 001".into(),
                country: "XX".into(),
            },
            Entry {
                name: "[CF] - 001".into(),
                country: "CLOUDFLARE".into(),
            },
        ]
    }

    #[test]
    fn creates_country_and_category_groups() {
        let (groups, countries) = build(&entries(), &Options::default());
        // 🇩🇪 DE + ☁️ CLOUDFLARE + 🌐 Прочие (XX)
        assert_eq!(countries, 3);
        // селекторы: 🚀 + 🌍 Страны + 🔓 + 🟢 Напрямую (4) + 4 категории = 8
        // авто: ♻️ Fallback + ⚡ + ⚖️ = 3; страны: 3
        assert_eq!(groups.len(), 8 + 3 + 3);
    }

    #[test]
    fn direct_group_is_manual_and_first_is_direct() {
        let (groups, _) = build(&entries(), &Options::default());
        let g = groups
            .iter()
            .find(|g| g.get("name").and_then(|n| n.as_str()) == Some(DIRECT_GROUP))
            .expect("нет группы 🟢 Напрямую");
        assert_eq!(g.get("type").and_then(|t| t.as_str()), Some("select"));
        let members: Vec<&str> = g
            .get("proxies")
            .and_then(|p| p.as_sequence())
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(members.first().copied(), Some("DIRECT"));
        assert!(members.contains(&"🚀 Прокси"));
        assert!(members.contains(&"🔓 Заблокированные"));
        assert!(members.contains(&FALLBACK));
        assert!(members.contains(&"🇩🇪 DE"));
    }

    #[test]
    fn categories_come_before_country_groups() {
        let (groups, _) = build(&entries(), &Options::default());
        let idx = |name: &str| find_group(&groups, name).0;
        assert!(idx("💬 Telegram") < idx("☁️ CLOUDFLARE"));
        assert!(idx(DIRECT_GROUP) < idx("💬 Telegram"));
        // авто-группы ниже селекторов, но выше страновых групп
        assert!(idx("💬 Telegram") < idx(FALLBACK));
        assert!(idx(AUTO) < idx("☁️ CLOUDFLARE"));
        assert!(idx(BALANCE) < idx("☁️ CLOUDFLARE"));
    }

    #[test]
    fn fallback_group_uses_all_proxies() {
        let (groups, _) = build(&entries(), &Options::default());
        let g = groups
            .iter()
            .find(|g| g.get("name").and_then(|n| n.as_str()) == Some(FALLBACK))
            .expect("нет группы ♻️ Fallback");
        assert_eq!(g.get("type").and_then(|t| t.as_str()), Some("fallback"));
        let members: Vec<&str> = g
            .get("proxies")
            .and_then(|p| p.as_sequence())
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(members.len(), entries().len());
        assert!(members.contains(&"[DE] - 001"));
        assert!(members.contains(&"[CF] - 001"));
    }

    #[test]
    fn automatic_groups_have_expected_probe_and_balance_settings() {
        let (groups, _) = build(&entries(), &Options::default());
        let find = |name: &str| find_group(&groups, name).1;
        let auto = find(AUTO);
        assert_eq!(auto.get("type").and_then(Yaml::as_str), Some("url-test"));
        assert_eq!(auto.get("url").and_then(Yaml::as_str), Some(TEST_URL));
        assert_eq!(auto.get("interval").and_then(Yaml::as_u64), Some(300));
        assert_eq!(auto.get("tolerance").and_then(Yaml::as_u64), Some(50));
        assert_eq!(auto.get("lazy"), Some(&Yaml::Bool(false)));

        let fallback = find(FALLBACK);
        assert_eq!(
            fallback.get("type").and_then(Yaml::as_str),
            Some("fallback")
        );
        assert_eq!(fallback.get("lazy"), Some(&Yaml::Bool(false)));

        let balance = find(BALANCE);
        assert_eq!(
            balance.get("type").and_then(Yaml::as_str),
            Some("load-balance")
        );
        assert_eq!(
            balance.get("strategy").and_then(Yaml::as_str),
            Some("consistent-hashing")
        );
        assert_eq!(balance.get("url").and_then(Yaml::as_str), Some(TEST_URL));
    }

    #[test]
    fn selectors_include_country_groups() {
        let (groups, _) = build(&entries(), &Options::default());
        for name in [MAIN, BLOCKED, DIRECT_GROUP, "💬 Telegram"] {
            let g = find_group(&groups, name).1;
            let members: Vec<&str> = g
                .get("proxies")
                .and_then(|p| p.as_sequence())
                .unwrap()
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            assert!(members.contains(&"🇩🇪 DE"), "{name}: нет 🇩🇪 DE");
            assert!(
                members.contains(&"☁️ CLOUDFLARE"),
                "{name}: нет ☁️ CLOUDFLARE"
            );
            assert!(members.contains(&"🌐 Прочие"), "{name}: нет 🌐 Прочие");
        }
    }

    #[test]
    #[should_panic(expected = "нет группы missing")]
    fn missing_group_lookup_reports_the_requested_name() {
        find_group(&[], "missing");
    }

    #[test]
    fn has_countries_manual_group() {
        let (groups, _) = build(&entries(), &Options::default());
        let countries_group = groups
            .iter()
            .find(|g| g.get("name").and_then(|n| n.as_str()) == Some("🌍 Страны"))
            .expect("нет группы 🌍 Страны");
        let members = countries_group
            .get("proxies")
            .and_then(|p| p.as_sequence())
            .unwrap();
        let names: Vec<&str> = members.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"🇩🇪 DE"));
        assert!(names.contains(&"☁️ CLOUDFLARE"));
        assert!(names.contains(&"🌐 Прочие"));
        assert_eq!(
            countries_group.get("type").and_then(|t| t.as_str()),
            Some("select")
        );
    }

    #[test]
    fn cloudflare_and_ru_blocked_get_own_groups() {
        let src = vec![
            Entry {
                name: "[CF] - 001".into(),
                country: "CLOUDFLARE".into(),
            },
            Entry {
                name: "[RB] - 001".into(),
                country: "RU-BLOCKED".into(),
            },
            Entry {
                name: "[ZZ] - 001".into(),
                country: "RE-FILTER".into(),
            },
        ];
        let (groups, countries) = build(&src, &Options::default());
        assert_eq!(countries, 3);
        let names: Vec<String> = groups
            .iter()
            .filter_map(|g| g.get("name").and_then(|n| n.as_str()))
            .map(str::to_string)
            .collect();
        assert!(names.contains(&"☁️ CLOUDFLARE".to_string()));
        assert!(names.contains(&"🔒 RU-BLOCKED".to_string()));
        assert!(names.contains(&"🏳️ RE-FILTER".to_string()));
    }

    #[test]
    fn flag_for_iso_code() {
        assert_eq!(flag("de").unwrap(), "🇩🇪");
        assert!(flag("XX").is_some());
        assert!(flag("CLOUDFLARE").is_none());
        assert!(flag("").is_none());
        assert!(flag("A1").is_none());
        assert!(flag("ABC").is_none());
    }

    #[test]
    fn only_unknown_go_to_other() {
        let (_, countries) = build(&entries(), &Options::default());
        assert_eq!(countries, 3);
    }

    #[test]
    fn no_country_no_categories() {
        let (groups, countries) = build(
            &entries(),
            &Options {
                include_country: false,
                include_categories: false,
            },
        );
        assert_eq!(countries, 0);
        assert_eq!(groups.len(), 6);
        assert!(groups
            .iter()
            .all(|g| g.get("name").and_then(|n| n.as_str()) != Some("🌍 Страны")));
        assert!(groups
            .iter()
            .any(|g| g.get("name").and_then(|n| n.as_str()) == Some(DIRECT_GROUP)));
    }

    #[test]
    fn empty_entries_keep_only_empty_auto_groups_when_features_disabled() {
        let (groups, countries) = build(
            &[],
            &Options {
                include_country: false,
                include_categories: false,
            },
        );
        assert_eq!(countries, 0);
        assert_eq!(groups.len(), 6);
        for group in &groups {
            let kind = group.get("type").and_then(Yaml::as_str).unwrap();
            if matches!(kind, "fallback" | "url-test" | "load-balance") {
                assert!(group
                    .get("proxies")
                    .and_then(Yaml::as_sequence)
                    .unwrap()
                    .is_empty());
            }
        }
    }

    #[test]
    fn country_codes_are_trimmed_case_insensitively_and_sorted() {
        let src = vec![
            Entry {
                name: "b".into(),
                country: " de ".into(),
            },
            Entry {
                name: "a".into(),
                country: "DE".into(),
            },
            Entry {
                name: "c".into(),
                country: "".into(),
            },
            Entry {
                name: "d".into(),
                country: "xx".into(),
            },
        ];
        let (groups, count) = build(&src, &Options::default());
        assert_eq!(count, 2);
        let country_names: Vec<&str> = groups
            .iter()
            .filter_map(|group| group.get("name").and_then(Yaml::as_str))
            .filter(|name| name.starts_with("🇩🇪") || *name == OTHER)
            .collect();
        assert_eq!(country_names, ["🇩🇪 DE", OTHER]);
        let de = groups
            .iter()
            .find(|group| group.get("name").and_then(Yaml::as_str) == Some("🇩🇪 DE"))
            .unwrap();
        assert_eq!(
            de.get("proxies").and_then(Yaml::as_sequence).unwrap().len(),
            2
        );
    }
}
