use crate::cli::Cli;
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::Path;

pub struct Sources {
    pub fetch_urls: Vec<String>,
    pub direct_links: Vec<String>,
}

pub fn collect(cli: &Cli) -> Result<Sources> {
    let mut urls: Vec<String> = Vec::new();

    if Path::new(&cli.sources).exists() {
        let text = std::fs::read_to_string(&cli.sources)
            .with_context(|| format!("не удалось прочитать {}", cli.sources))?;
        let data: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("битый JSON: {}", cli.sources))?;
        let obj = data.as_object().context(
            "sources.json должен быть объектом {\"1\": [...], \"2\": [...], \"3\": [...]}",
        )?;

        let sets: Vec<String> = if cli.set.eq_ignore_ascii_case("all") {
            obj.keys().cloned().collect()
        } else {
            vec![cli.set.clone()]
        };
        for key in sets {
            match obj.get(&key) {
                Some(serde_json::Value::Array(list)) => {
                    for item in list {
                        if let Some(u) = item.as_str() {
                            urls.push(u.to_string());
                        }
                    }
                }
                _ => bail!("в sources.json нет набора \"{}\"", key),
            }
        }
    } else if cli.url.is_empty() && cli.file.is_none() {
        bail!("не найден {} — укажите --sources, -u или -f", cli.sources);
    }

    urls.extend(cli.url.iter().cloned());

    let mut direct_links: Vec<String> = Vec::new();
    if let Some(path) = &cli.file {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("не удалось прочитать {}", path))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("http://") || lower.starts_with("https://") {
                urls.push(line.to_string());
            } else if line.contains("://") {
                direct_links.push(line.to_string());
            }
        }
    }

    let mut seen = HashSet::new();
    urls.retain(|u| seen.insert(u.clone()));
    Ok(Sources {
        fetch_urls: urls,
        direct_links,
    })
}

#[cfg(test)]
mod tests {
    use super::collect;
    use crate::cli::Cli;
    use clap::Parser;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "proxy-rs-sources-tests-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cli(sources: &Path, additional_args: &[&str]) -> Cli {
        let mut args = vec!["proxy-rs", "--sources", sources.to_str().unwrap()];
        args.extend_from_slice(additional_args);
        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn collect_reads_selected_json_set_and_all_sets() {
        let temp = TempDir::new();
        let sources = temp.write(
            "sources.json",
            r#"{"1":["https://one.example/list"],"2":["https://two.example/list"],"3":["https://three.example/list",7]}"#,
        );

        let selected = collect(&cli(&sources, &["--set", "2"])).unwrap();
        assert_eq!(selected.fetch_urls, ["https://two.example/list"]);
        assert!(selected.direct_links.is_empty());

        let all = collect(&cli(&sources, &["--set", "ALL"])).unwrap();
        assert_eq!(
            all.fetch_urls,
            [
                "https://one.example/list",
                "https://two.example/list",
                "https://three.example/list"
            ]
        );
    }

    #[test]
    fn collect_separates_direct_links_from_subscription_urls() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            "# comment\n\n  https://feed.example/list  \nvless://id@example.com:443\nnot-a-link\n",
        );
        let sources = temp.write("sources.json", r#"{"3":[]}"#);
        let collected = collect(&cli(
            &sources,
            &[
                "-u",
                "https://extra.example/list",
                "-f",
                links.to_str().unwrap(),
            ],
        ))
        .unwrap();
        assert_eq!(
            collected.fetch_urls,
            ["https://extra.example/list", "https://feed.example/list"]
        );
        assert_eq!(collected.direct_links, ["vless://id@example.com:443"]);
    }

    #[test]
    fn collect_deduplicates_fetch_urls_and_preserves_first_seen_order() {
        let temp = TempDir::new();
        let sources = temp.write(
            "sources.json",
            r#"{"3":["https://same.example/list","https://from-set.example/list"]}"#,
        );
        let links = temp.write(
            "links.txt",
            "https://same.example/list\nhttps://from-file.example/list\n",
        );
        let collected = collect(&cli(
            &sources,
            &[
                "-u",
                "https://from-set.example/list",
                "-u",
                "https://extra.example/list",
                "-f",
                links.to_str().unwrap(),
            ],
        ))
        .unwrap();

        assert_eq!(
            collected.fetch_urls,
            [
                "https://same.example/list",
                "https://from-set.example/list",
                "https://extra.example/list",
                "https://from-file.example/list"
            ]
        );
    }

    #[test]
    fn collect_rejects_invalid_sources_configurations_and_files() {
        let temp = TempDir::new();
        let invalid_json = temp.write("invalid.json", "{");
        assert!(collect(&cli(&invalid_json, &[])).is_err());

        let wrong_shape = temp.write("wrong-shape.json", "[]");
        assert!(collect(&cli(&wrong_shape, &[])).is_err());

        let invalid_set = temp.write("sets.json", r#"{"1":[]}"#);
        assert!(collect(&cli(&invalid_set, &["--set", "2"])).is_err());

        let missing_sources = temp.0.join("missing-sources.json");
        assert!(collect(&cli(&missing_sources, &[])).is_err());

        let valid_sources = temp.write("valid.json", r#"{"3":[]}"#);
        let missing_file = temp.0.join("missing-links.txt");
        assert!(collect(&cli(
            &valid_sources,
            &["-f", missing_file.to_str().unwrap()]
        ))
        .is_err());
    }

    #[test]
    fn collect_allows_missing_sources_when_an_explicit_url_is_given() {
        let temp = TempDir::new();
        let missing_sources = temp.0.join("optional-sources.json");
        let collected = collect(&cli(
            &missing_sources,
            &["-u", "https://explicit.example/list"],
        ))
        .unwrap();

        assert_eq!(collected.fetch_urls, ["https://explicit.example/list"]);
        assert!(collected.direct_links.is_empty());
    }

    #[test]
    fn collect_allows_missing_sources_when_a_link_file_is_given() {
        let temp = TempDir::new();
        let missing_sources = temp.0.join("optional-sources.json");
        let links = temp.write("links.txt", "vless://id@example.com:443\n");

        let collected = collect(&cli(&missing_sources, &["-f", links.to_str().unwrap()])).unwrap();

        assert!(collected.fetch_urls.is_empty());
        assert_eq!(collected.direct_links, ["vless://id@example.com:443"]);
    }

    #[test]
    fn collect_reports_sources_read_errors() {
        let temp = TempDir::new();
        let sources_directory = temp.0.join("sources-directory");
        fs::create_dir(&sources_directory).unwrap();

        let error = collect(&cli(&sources_directory, &[]))
            .err()
            .expect("reading a directory as sources.json must fail");
        assert!(error.to_string().contains("не удалось прочитать"));
    }
}
