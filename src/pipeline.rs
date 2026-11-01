use super::Summary;
use crate::checkpoint;
use crate::cli::Cli;
use crate::fetch;
use crate::geoip;
use crate::output;
use crate::parse::{self, Proxy};
use crate::source_report;
use crate::sources;
use crate::speed;
use crate::tcp_ping;
use crate::xray::{self, SpeedOpts};
use colored::Colorize;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct PipelineProgress {
    pub phase: String,
    pub detail: String,
    pub completed: usize,
    pub total: usize,
    pub rate_per_sec: f64,
    pub remaining_seconds: Option<f64>,
}

impl PipelineProgress {
    pub fn update(
        phase: impl Into<String>,
        detail: impl Into<String>,
        completed: usize,
        total: usize,
        elapsed: std::time::Duration,
    ) -> Self {
        let rate_per_sec = completed as f64 / elapsed.as_secs_f64().max(f64::EPSILON);
        let remaining_seconds = if completed < total && rate_per_sec > 0.0 {
            Some((total - completed) as f64 / rate_per_sec)
        } else if completed >= total {
            Some(0.0)
        } else {
            None
        };
        Self {
            phase: phase.into(),
            detail: detail.into(),
            completed,
            total,
            rate_per_sec,
            remaining_seconds,
        }
    }
}

pub type ProgressCallback = Arc<dyn Fn(PipelineProgress) + Send + Sync>;

fn emit_progress(
    callback: &Option<ProgressCallback>,
    phase: impl Into<String>,
    detail: impl Into<String>,
) {
    if let Some(callback) = callback {
        callback(PipelineProgress {
            phase: phase.into(),
            detail: detail.into(),
            completed: 0,
            total: 0,
            rate_per_sec: 0.0,
            remaining_seconds: None,
        });
    }
}

#[derive(serde::Serialize)]
struct SpeedReportEntry<'a> {
    source_id: Option<String>,
    name: &'a str,
    protocol: &'a str,
    server: &'a str,
    port: u16,
    median_kbs: Option<f64>,
    successful_probes: Option<usize>,
    min_kbs: Option<f64>,
    max_kbs: Option<f64>,
    probes: Option<Vec<speed::ProbeResult>>,
}

pub(super) fn default_geoip_path() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(default_asset_path(&exe, "geoip.dat"))
}

pub(super) fn default_core_path() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(default_asset_path(&exe, xray::core_bin_name()))
}

fn default_asset_path(executable: &Path, asset: &str) -> PathBuf {
    executable
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(asset)
}

fn geoip_db_path(configured: Option<&str>) -> anyhow::Result<PathBuf> {
    match configured {
        Some(path) => Ok(PathBuf::from(path)),
        None => default_geoip_path(),
    }
}

/// Ищет файл: сначала по пути, потом рядом с exe, потом в bin/ проекта.
pub(super) fn resolve_default(path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    resolve_default_from(
        &p,
        std::env::current_exe().ok().as_deref(),
        Path::new("bin"),
    )
}

pub(super) fn resolve_default_from(path: &Path, exe: Option<&Path>, bin_dir: &Path) -> PathBuf {
    let p = path.to_path_buf();
    if p.exists() {
        return p;
    }
    if let Some(dir) = exe.and_then(Path::parent) {
        let cand = dir.join(&p);
        if cand.exists() {
            return cand;
        }
    }
    let bin = bin_dir.join(&p);
    if bin.exists() {
        return bin;
    }
    p
}

fn write_source_report(
    cli: &Cli,
    report: &source_report::SourceQualityReport,
) -> anyhow::Result<()> {
    if let Some(path) = &cli.source_report {
        output::write_text_atomic(path, &report.to_pretty_json()?)?;
    }
    Ok(())
}

fn save_checkpoint(cli: &Cli, checkpoint: &checkpoint::Checkpoint) -> anyhow::Result<()> {
    if let Some(path) = &cli.checkpoint {
        checkpoint.save(path)?;
    }
    Ok(())
}

pub(super) fn filter_proxy_protocol_country(
    proxies: &mut Vec<Proxy>,
    protocols: &[String],
    countries: &[String],
) -> usize {
    let before = proxies.len();
    let allowed_protocols: HashSet<String> = protocols
        .iter()
        .map(|protocol| protocol.to_ascii_lowercase())
        .collect();
    let allowed_countries: HashSet<String> = countries
        .iter()
        .map(|country| country.trim().to_ascii_uppercase())
        .collect();
    proxies.retain(|proxy| {
        (allowed_protocols.is_empty() || allowed_protocols.contains(proxy.proto))
            && (allowed_countries.is_empty()
                || allowed_countries.contains(&proxy.country.trim().to_ascii_uppercase()))
    });
    before - proxies.len()
}

fn safe_outbound_shape(proxy: &parse::Proxy) -> String {
    fn field(value: Option<&str>) -> String {
        value
            .filter(|value| {
                !value.is_empty()
                    && value
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            })
            .map(|value| value.chars().take(40).collect())
            .unwrap_or_else(|| "unknown".to_owned())
    }

    if proxy.proto == "shadowsocks" {
        let method = proxy
            .settings
            .get("method")
            .and_then(serde_json::Value::as_str);
        return format!("{}: method={}", proxy.proto, field(method));
    }
    let stream = proxy.stream.as_ref();
    let transport = field(
        stream
            .and_then(|value| value.get("network"))
            .and_then(serde_json::Value::as_str),
    );
    let security = field(
        stream
            .and_then(|value| value.get("security"))
            .and_then(serde_json::Value::as_str),
    );
    format!(
        "{}: transport={transport}, security={security}",
        proxy.proto
    )
}

pub(super) fn filter_previously_seen(proxies: &mut Vec<Proxy>, existing: &str) -> usize {
    let known: HashSet<String> = existing
        .lines()
        .filter_map(|line| parse::parse_link(line).ok().map(|proxy| proxy.key()))
        .collect();
    let before = proxies.len();
    proxies.retain(|proxy| !known.contains(&proxy.key()));
    before - proxies.len()
}

pub(super) fn retain_within_max_ping(candidates: &mut Vec<Proxy>, max_ping: u64) -> Vec<String> {
    if max_ping == 0 {
        return Vec::new();
    }

    let mut rejected = Vec::new();
    candidates.retain(|proxy| {
        if matches!(proxy.proto, "hysteria" | "hysteria2")
            || proxy.ping.is_some_and(|ping| ping <= max_ping)
        {
            true
        } else {
            rejected.push(proxy.base_url.clone());
            false
        }
    });
    rejected
}

pub async fn run(cli: Cli) -> anyhow::Result<Summary> {
    run_inner(cli, None).await
}

#[allow(dead_code)]
pub async fn run_with_progress(cli: Cli, callback: ProgressCallback) -> anyhow::Result<Summary> {
    run_inner(cli, Some(callback)).await
}

async fn run_inner(mut cli: Cli, callback: Option<ProgressCallback>) -> anyhow::Result<Summary> {
    cli.apply_checker_overrides();
    cli.sources = resolve_default(&cli.sources).display().to_string();
    cli.core = resolve_default(&cli.core).display().to_string();
    let started = Instant::now();

    macro_rules! info {
        ($($arg:tt)*) => {
            println!("{}  {}", format!("[+{:.0}s]", started.elapsed().as_secs_f64()).dimmed(), format!($($arg)*))
        };
    }
    macro_rules! success {
        ($($arg:tt)*) => {
            println!("{}  {} {}", format!("[+{:.0}s]", started.elapsed().as_secs_f64()).dimmed(), "✓".green().bold(), format!($($arg)*).green())
        };
    }
    macro_rules! warning {
        ($($arg:tt)*) => {
            println!("{}  {} {}", format!("[+{:.0}s]", started.elapsed().as_secs_f64()).dimmed(), "!".yellow().bold(), format!($($arg)*).yellow())
        };
    }
    macro_rules! phase {
        ($number:expr, $title:expr) => {
            println!(
                "\n{} {}",
                format!("━━ {} ━━", $number).cyan().bold(),
                $title.bold()
            )
        };
    }

    let mut sum = Summary::default();

    // ------------------------------------------------------------------
    // 1. Источники
    // ------------------------------------------------------------------
    let mut checkpoint = if cli.resume {
        let path = cli
            .checkpoint
            .as_deref()
            .expect("CLI validation requires a checkpoint path for --resume");
        checkpoint::Checkpoint::load(path)?
            .ok_or_else(|| anyhow::anyhow!("checkpoint для --resume не найден: {path}"))?
    } else {
        checkpoint::Checkpoint::new()
    };
    let resume_stage = checkpoint.stage;
    if cli.resume
        && resume_stage < checkpoint::PipelineStage::Parsed
        && (resume_stage != checkpoint::PipelineStage::Fetched || checkpoint.raw_links.is_empty())
    {
        anyhow::bail!("checkpoint ещё не содержит завершённый этап парсинга");
    }
    let mut source_quality = checkpoint.source_quality.clone();
    source_quality.fill_missing_source_ids();
    let mut source_owner: HashMap<String, usize> = checkpoint.source_owners.clone();
    let mut proxies;
    if cli.resume {
        if resume_stage == checkpoint::PipelineStage::Fetched {
            let raw_links = checkpoint.raw_links.clone();
            let (restored, stats) = parse::parse_all(raw_links.clone());
            proxies = restored;
            sum.links = stats.links;
            sum.unique = stats.parsed;
            sum.duplicates = stats.duplicates;
            sum.invalid = stats.invalid;
            sum.unsupported = stats.unsupported.values().sum();
            sum.unsupported_details = stats.unsupported_details.clone();
            checkpoint.parse_stats = checkpoint::ParseSnapshotStats {
                links: stats.links,
                parsed: stats.parsed,
                duplicates: stats.duplicates,
                invalid: stats.invalid,
                unsupported: stats.unsupported.values().sum(),
            };
            checkpoint.record_stage(
                checkpoint::PipelineStage::Parsed,
                raw_links,
                proxies
                    .iter()
                    .map(checkpoint::ProxySnapshot::from_proxy)
                    .collect(),
            );
            save_checkpoint(&cli, &checkpoint)?;
        } else {
            proxies = checkpoint
                .proxies
                .iter()
                .cloned()
                .map(checkpoint::ProxySnapshot::into_proxy)
                .collect::<anyhow::Result<Vec<_>>>()?;
            sum.links = checkpoint.parse_stats.links;
            sum.unique = checkpoint.parse_stats.parsed;
            sum.duplicates = checkpoint.parse_stats.duplicates;
            sum.invalid = checkpoint.parse_stats.invalid;
            sum.unsupported = checkpoint.parse_stats.unsupported;
            sum.unsupported_details = parse::parse_all(checkpoint.raw_links.clone())
                .1
                .unsupported_details;
        }
        if proxies.is_empty() {
            anyhow::bail!("checkpoint не содержит прокси для продолжения");
        }
        sum.unique = proxies.len();
        info!(
            "Продолжение с завершённого этапа {:?}: {} прокси",
            resume_stage,
            proxies.len()
        );
    } else {
        phase!("1/6", "ИСТОЧНИКИ И ЗАГРУЗКА");
        emit_progress(
            &callback,
            "Источники",
            "Собираем встроенный каталог и подписки",
        );
        let src = sources::collect(&cli)?;
        sum.fetch_sources = src.fetch_urls.len();
        emit_progress(
            &callback,
            "Источники",
            format!("Найдено источников: {}", src.fetch_urls.len()),
        );
        info!("Источников подписок: {}", src.fetch_urls.len());
        if src.fetch_urls.is_empty() && src.direct_links.is_empty() {
            anyhow::bail!("нет источников для загрузки");
        }

        // ------------------------------------------------------------------
        // 2. Загрузка
        // ------------------------------------------------------------------
        let t = Instant::now();
        let report = fetch::fetch_all_with_options(
            &src.fetch_urls,
            &fetch::FetchOptions {
                concurrency: cli.fetch_concurrency,
                timeout: std::time::Duration::from_secs_f64(cli.fetch_timeout),
                max_response_bytes: cli.max_source_bytes,
                retries: cli.fetch_retries,
                insecure_tls: cli.insecure_source_tls,
                cache_dir: (!cli.no_fetch_cache).then(|| PathBuf::from(&cli.fetch_cache_dir)),
            },
        )
        .await;
        emit_progress(
            &callback,
            "Источники",
            format!(
                "Загружено источников: {} из {}",
                report.successes.len(),
                src.fetch_urls.len()
            ),
        );
        let success_by_url: HashMap<&str, &fetch::FetchSuccess> = report
            .successes
            .iter()
            .map(|success| (success.url.as_str(), success))
            .collect();
        let failure_by_url: HashMap<&str, &fetch::FetchFailure> = report
            .failures
            .iter()
            .map(|failure| (failure.url.as_str(), failure))
            .collect();
        let mut seen_source_keys = HashSet::new();
        for (source_order, source_url) in src.fetch_urls.iter().enumerate() {
            let source_id = format!("feed-{:03}", source_order + 1);
            if let Some(success) = success_by_url.get(source_url.as_str()) {
                let index = source_quality.sources.len();
                let row = source_quality.add_source_with_id(source_id, source_url);
                row.status = source_report::SourceStatus::Fetched;
                row.counts.fetched = 1;
                for link in parse::extract_links(&success.text) {
                    match parse::parse_link(&link) {
                        Ok(proxy) => {
                            row.counts.valid += 1;
                            let key = proxy.key();
                            if !seen_source_keys.insert(key.clone()) {
                                row.counts.duplicate += 1;
                            } else {
                                row.counts.unique += 1;
                                source_owner.insert(key, index);
                            }
                        }
                        Err(parse::ParseErr::Unsupported(category)) => {
                            let reason = parse::unsupported_reason_key(&link, category);
                            *row.counts.unsupported_reasons.entry(reason).or_insert(0) += 1;
                        }
                        Err(parse::ParseErr::Invalid(reason)) => {
                            *row.counts
                                .invalid_reasons
                                .entry(reason.to_owned())
                                .or_insert(0) += 1;
                        }
                    }
                }
                row.status = source_report::SourceStatus::Parsed;
            } else if let Some(failure) = failure_by_url.get(source_url.as_str()) {
                let row = source_quality.add_source_with_id(source_id, source_url);
                row.status = source_report::SourceStatus::FetchFailed;
                row.fetch_failure = Some(source_report::fetch_failure_kind(&failure.reason));
                row.fetch_attempts = Some(failure.attempts);
            } else {
                let row = source_quality.add_source_with_id(source_id, source_url);
                row.status = source_report::SourceStatus::Pending;
            }
        }
        let mut texts = report.texts;
        let unchanged_from_cache = report
            .successes
            .iter()
            .filter(|success| success.cache == fetch::CacheDisposition::NotModified)
            .count();
        let stale_from_cache = report
            .successes
            .iter()
            .filter(|success| success.cache == fetch::CacheDisposition::StaleFallback)
            .count();
        sum.fetch_loaded = texts.len();
        sum.fetch_failed = report.failures.len();
        sum.fetch_failure_examples = report
            .failures
            .iter()
            .take(5)
            .map(|failure| {
                format!(
                    "{} — {} (попыток: {})",
                    source_report::redact_url(&failure.url),
                    failure.reason,
                    failure.attempts
                )
            })
            .collect();
        sum.fetch_secs = t.elapsed().as_secs_f64();
        if sum.fetch_failed == 0 {
            success!(
                "Загружено подписок: {}, ошибок: {}, без изменений в кэше: {}, использовано устаревших копий: {}",
                texts.len(),
                sum.fetch_failed,
                unchanged_from_cache,
                stale_from_cache
            );
        } else {
            warning!(
                "Загружено подписок: {}, ошибок: {}, без изменений в кэше: {}, использовано устаревших копий: {}",
                texts.len(),
                sum.fetch_failed,
                unchanged_from_cache,
                stale_from_cache
            );
        }
        for example in &sum.fetch_failure_examples {
            warning!("Ошибка источника: {example}");
        }
        if texts.is_empty() && !src.fetch_urls.is_empty() && src.direct_links.is_empty() {
            anyhow::bail!(
                "не удалось загрузить ни одного источника (ошибок: {})",
                sum.fetch_failed
            );
        }
        if !texts.is_empty() {
            output::write_lines_atomic(&cli.raw_output, &texts)?;
            sum.raw_file = Some((cli.raw_output.clone(), texts.len()));
            success!("Сохранено: {} ({} подписок)", cli.raw_output, texts.len());
        }

        // ------------------------------------------------------------------
        // 3. Парсинг + дедуп
        // ------------------------------------------------------------------
        phase!("2/6", "РАЗБОР ССЫЛОК");
        emit_progress(&callback, "Разбор", "Разбираем URI и удаляем дубли");
        let t = Instant::now();
        let mut links: Vec<String> = Vec::new();
        for t in &texts {
            links.extend(parse::extract_links(t));
        }
        texts.clear();
        links.extend(src.direct_links);

        let raw_links_for_checkpoint = links.clone();
        checkpoint.raw_links = raw_links_for_checkpoint.clone();
        checkpoint.source_quality = source_quality.clone();
        checkpoint.source_owners = source_owner.clone();
        checkpoint.record_stage(
            checkpoint::PipelineStage::Fetched,
            raw_links_for_checkpoint.clone(),
            Vec::new(),
        );
        save_checkpoint(&cli, &checkpoint)?;
        let (parsed_proxies, stats) = parse::parse_all(links);
        proxies = parsed_proxies;
        sum.parse_secs = t.elapsed().as_secs_f64();
        sum.links = stats.links;
        sum.unique = stats.parsed;
        sum.duplicates = stats.duplicates;
        sum.invalid = stats.invalid;
        sum.unsupported = stats.unsupported.values().sum();
        sum.unsupported_details = stats.unsupported_details.clone();
        emit_progress(
            &callback,
            "Разбор",
            format!("Уникальных узлов: {}", sum.unique),
        );
        checkpoint.parse_stats = checkpoint::ParseSnapshotStats {
            links: stats.links,
            parsed: stats.parsed,
            duplicates: stats.duplicates,
            invalid: stats.invalid,
            unsupported: stats.unsupported.values().sum(),
        };
        info!(
            "Ссылок: {}, уникальных прокси: {}, дублей: {}, некорректных: {}",
            stats.links, stats.parsed, stats.duplicates, stats.invalid
        );
        if !stats.unsupported.is_empty() {
            let list: Vec<(&&'static str, &usize)> = stats.unsupported.iter().collect();
            let txt: Vec<String> = list.iter().map(|(k, v)| format!("{k}: {v}")).collect();
            warning!("Неподдерживаемые протоколы: {}", txt.join(", "));
            let table = crate::table::render_count_table(
                stats
                    .unsupported_details
                    .iter()
                    .map(|(reason, count)| (reason.clone(), *count)),
            );
            if !stats.unsupported_details.is_empty() {
                warning!("Детализация неподдержки:\n{table}");
            }
        }
        if !stats.invalid_reasons.is_empty() {
            let table = crate::table::render_count_table(
                stats
                    .invalid_reasons
                    .iter()
                    .map(|(reason, count)| ((*reason).to_owned(), *count)),
            );
            warning!("Причины некорректных:\n{table}");
        }
        if proxies.is_empty() {
            write_source_report(&cli, &source_quality)?;
            anyhow::bail!("не найдено ни одного подходящего прокси");
        }
        checkpoint.raw_links = raw_links_for_checkpoint.clone();
        checkpoint.record_stage(
            checkpoint::PipelineStage::Parsed,
            raw_links_for_checkpoint,
            proxies
                .iter()
                .map(checkpoint::ProxySnapshot::from_proxy)
                .collect(),
        );
        save_checkpoint(&cli, &checkpoint)?;
    }

    if let Some(seed) = cli.shuffle_seed {
        let mut rng = StdRng::seed_from_u64(seed);
        proxies.shuffle(&mut rng);
    } else if cli.shuffle {
        proxies.shuffle(&mut rand::thread_rng());
    }
    if let Some(n) = cli.limit {
        if proxies.len() > n {
            proxies.truncate(n);
            info!("Ограничение --limit: оставлено {n} прокси");
        }
    }

    output::write_lines_atomic(
        &cli.parsed_output,
        &proxies
            .iter()
            .map(|p| output::line(p, false))
            .collect::<Vec<_>>(),
    )?;
    sum.parsed_file = Some((cli.parsed_output.clone(), proxies.len()));
    success!(
        "Сохранено: {} ({} прокси до проверок)",
        cli.parsed_output,
        proxies.len()
    );

    phase!("3/6", "GEOIP И ИМЕНА СТРАН");
    emit_progress(
        &callback,
        "GeoIP",
        format!("Определяем страну для {} узлов", proxies.len()),
    );
    // ------------------------------------------------------------------
    // 4. GeoIP: страна + переименование в [XX] - NNN
    // ------------------------------------------------------------------
    let rename = !cli.no_geoip;
    sum.geo = rename;
    if rename {
        if resume_stage < checkpoint::PipelineStage::GeoIp {
            let t = Instant::now();
            let db_path = geoip_db_path(cli.geoip_db.as_deref())?;
            geoip::ensure_db(&db_path, &cli.geoip_url).await?;
            let db = geoip::GeoDb::open(&db_path)?;
            if let Some(database_type) = db.database_type() {
                info!("База GeoIP: {database_type} (MaxMind DB)");
            } else {
                let (nc, n4, n6) = db.stats();
                info!("База: {nc} стран, {n4} IPv4-сетей, {n6} IPv6-сетей");
            }
            let counts = geoip::assign_countries(&mut proxies, &db).await?;
            sum.geo_countries = counts
                .keys()
                .filter(|country| country.as_str() != "XX")
                .count();
            geoip::print_country_summary(&counts);
            sum.geo_secs = t.elapsed().as_secs_f64();
        }
    } else if resume_stage < checkpoint::PipelineStage::GeoIp {
        for p in proxies.iter_mut() {
            p.display = p.name.clone();
        }
    }
    if resume_stage < checkpoint::PipelineStage::GeoIp && cli.only_new {
        let existing = match std::fs::read_to_string(&cli.output) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let removed = filter_previously_seen(&mut proxies, &existing);
        info!("--only-new: удалено уже известных прокси: {removed}");
    }
    if resume_stage < checkpoint::PipelineStage::GeoIp
        && (!cli.protocol.is_empty() || !cli.country.is_empty())
    {
        let removed = filter_proxy_protocol_country(&mut proxies, &cli.protocol, &cli.country);
        info!("Фильтры протокол/страна: удалено {removed} прокси");
    }
    checkpoint.record_stage(
        checkpoint::PipelineStage::GeoIp,
        checkpoint.processed_links.clone(),
        proxies
            .iter()
            .map(checkpoint::ProxySnapshot::from_proxy)
            .collect(),
    );
    checkpoint.source_quality = source_quality.clone();
    save_checkpoint(&cli, &checkpoint)?;

    output::write_lines_atomic(
        &cli.parsed_output,
        &proxies
            .iter()
            .map(|p| output::line(p, rename))
            .collect::<Vec<_>>(),
    )?;
    success!(
        "Обновлено: {} (имена {})",
        cli.parsed_output,
        if rename { "GeoIP" } else { "без GeoIP" }
    );

    let mut dead_urls: Vec<String> = Vec::new();

    phase!("4/6", "TCP-ПРОВЕРКА");
    emit_progress(
        &callback,
        "TCP-проверка",
        format!("Проверяем доступность {} узлов", proxies.len()),
    );
    // ------------------------------------------------------------------
    // 5. Фаза 1: TCP ping — живые / мёртвые
    // ------------------------------------------------------------------
    let mut candidates = proxies;
    sum.tcp_enabled = !cli.no_tcp_ping;
    if !cli.no_tcp_ping && resume_stage < checkpoint::PipelineStage::TcpPing {
        info!(
            "Фаза 1 (TCP ping): {} адресов, timeout {}s, конкурентность {}, попытки {}{}",
            candidates.len(),
            cli.tcp_timeout,
            cli.tcp_concurrency,
            cli.tcp_retries,
            if cli.tcp_max_ms > 0 {
                format!(", max {} ms", cli.tcp_max_ms)
            } else {
                String::new()
            }
        );
        let t = Instant::now();
        let (alive, dead, st) = tcp_ping::filter_with_progress(
            candidates,
            cli.tcp_timeout,
            cli.tcp_concurrency,
            cli.tcp_retries,
            cli.tcp_max_ms,
            callback.clone(),
        )
        .await;
        sum.tcp_secs = t.elapsed().as_secs_f64();
        sum.tcp_total = st.total;
        sum.tcp_alive = st.alive;
        success!(
            "Живых узлов {}/{} (TCP: {}/{}; макс. RTT {} мс), UDP без TCP-проверки {}, мёртвых {}",
            st.alive,
            st.total,
            st.tcp_alive,
            st.checked,
            st.max_ms_seen,
            st.udp_skipped,
            st.dead
        );
        dead_urls.extend(dead.iter().map(|p| p.base_url.clone()));
        for proxy in &alive {
            if !matches!(proxy.proto, "hysteria" | "hysteria2") {
                if let Some(index) = source_owner.get(&proxy.key()) {
                    source_quality.sources[*index].counts.tcp_live += 1;
                }
            }
        }
        for row in &mut source_quality.sources {
            if row.status == source_report::SourceStatus::Parsed {
                row.status = source_report::SourceStatus::TcpChecked;
            }
        }
        candidates = alive;
    }

    if candidates.is_empty() {
        warning!("Нет живых прокси после TCP ping.");
        if let Some(path) = &cli.dead {
            output::write_lines_atomic(path, &dead_urls)?;
            sum.dead_file = Some((path.clone(), dead_urls.len()));
        }
        if let Some(path) = &cli.json_output {
            output::write_proxy_json(path, &[])?;
        }
        checkpoint.proxies.clear();
        checkpoint.complete(Vec::new());
        save_checkpoint(&cli, &checkpoint)?;
        write_source_report(&cli, &source_quality)?;
        sum.total_secs = started.elapsed().as_secs_f64();
        emit_progress(&callback, "Завершено", "Рабочих узлов не найдено");
        return Ok(sum);
    }

    // --max-ping отсекает по TCP RTT (из фазы 1)
    if cli.max_ping > 0 {
        let before = candidates.len();
        dead_urls.extend(retain_within_max_ping(&mut candidates, cli.max_ping));
        if candidates.len() < before {
            warning!(
                "--max-ping {}: отброшено {} с более высоким TCP ping",
                cli.max_ping,
                before - candidates.len()
            );
        }
    }

    checkpoint.record_stage(
        checkpoint::PipelineStage::TcpPing,
        checkpoint.processed_links.clone(),
        candidates
            .iter()
            .map(checkpoint::ProxySnapshot::from_proxy)
            .collect(),
    );
    checkpoint.source_quality = source_quality.clone();
    save_checkpoint(&cli, &checkpoint)?;

    // Сохраняем результат TCP-этапа сразу
    if !cli.no_tcp_ping {
        let mut tcp_alive = candidates.clone();
        tcp_alive.sort_by_key(|p| p.ping.unwrap_or(u64::MAX));
        output::write_lines_atomic(
            &cli.output,
            &tcp_alive
                .iter()
                .map(|p| output::line(p, rename))
                .collect::<Vec<_>>(),
        )?;
        sum.alive_file = Some((cli.output.clone(), tcp_alive.len()));
        if let Some(path) = &cli.dead {
            output::write_lines_atomic(path, &dead_urls)?;
            sum.dead_file = Some((path.clone(), dead_urls.len()));
        }
        success!(
            "Сохранено после TCP: {} ({} живых){}",
            cli.output,
            tcp_alive.len(),
            match &cli.dead {
                Some(p) => format!(", {p} ({} мёртвых)", dead_urls.len()),
                None => String::new(),
            }
        );
    }

    let mut alive: Vec<Proxy>;
    let mut good: Vec<Proxy> = Vec::new();
    let mut speed_measurements = HashMap::new();
    let mut speed_probe_results = HashMap::new();

    phase!("5/6", "ПРОВЕРКА СКОРОСТИ");
    emit_progress(
        &callback,
        "Скорость",
        format!("Проверяем скорость для {} узлов", candidates.len()),
    );
    // ------------------------------------------------------------------
    // 6. Скорость через xray — единственный тест живости
    // ------------------------------------------------------------------
    sum.speed_enabled = !cli.no_speed;
    if cli.no_speed {
        candidates.sort_by_key(|p| p.ping.unwrap_or(u64::MAX));
        alive = candidates.clone();
        info!(
            "Скорость выключена (--no-speed): живых по TCP ping {}",
            alive.len()
        );
    } else if resume_stage >= checkpoint::PipelineStage::Speed {
        good = candidates.clone();
        good.sort_by(|a, b| {
            b.speed_kbs
                .partial_cmp(&a.speed_kbs)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sum.speed_passed = good.len();
        sum.speed_total = good.len();
        output::write_lines_atomic(
            &cli.good_output,
            &good
                .iter()
                .map(|proxy| output::line(proxy, rename))
                .collect::<Vec<_>>(),
        )?;
        sum.good_file = Some((cli.good_output.clone(), good.len()));
        alive = candidates.clone();
    } else {
        let core_path = if PathBuf::from(&cli.core).exists() {
            PathBuf::from(&cli.core)
        } else {
            default_core_path()?
        };
        xray::ensure_core(&core_path, cli.xray_url.as_deref(), cli.no_xray_download).await?;
        cli.core = core_path.display().to_string();

        let checker = xray::Checker::new(&cli)?;
        info!(
            "Фаза 2 (замер скорости): {} прокси, батчи {}, потоков {}, до {:.1} MB, мин {:.1} KB/s",
            candidates.len(),
            cli.batch,
            cli.speed_threads,
            cli.speed_max_mb,
            cli.min_kb
        );
        let opts = SpeedOpts {
            primary: cli.speed_url.clone(),
            connect_timeout_s: cli.speed_connect_timeout,
            timeout_s: cli.speed_timeout,
            max_mb: cli.speed_max_mb,
            min_kb: cli.min_kb,
            speed_probes: cli.speed_probes,
        };
        let t = Instant::now();
        let passed = checker
            .run_all_with_progress(
                candidates.clone(),
                cli.batch,
                cli.batch_workers,
                opts,
                "замер скорости",
                Some(cli.good_output.clone()),
                callback.clone(),
            )
            .await?;
        sum.speed_secs = t.elapsed().as_secs_f64();
        sum.speed_passed = passed.len();
        sum.bad_outbounds = checker.bad_outbounds();
        let bad_outbound_rejections = checker.bad_outbound_rejections();
        let mut rejection_groups = BTreeMap::<String, u64>::new();
        for proxy in &candidates {
            let key = proxy.key();
            if let Some(reason) = bad_outbound_rejections.get(&key) {
                *rejection_groups
                    .entry(format!("{}: {reason}", safe_outbound_shape(proxy)))
                    .or_default() += 1;
                if let Some(index) = source_owner.get(&key) {
                    *source_quality.sources[*index]
                        .counts
                        .xray_outbound_rejections
                        .entry(format!("{}: {reason}", safe_outbound_shape(proxy)))
                        .or_insert(0) += 1;
                }
            }
        }
        if !rejection_groups.is_empty() {
            let table = crate::table::render_count_table(
                rejection_groups
                    .into_iter()
                    .map(|(reason, count)| (reason, count as usize)),
            );
            warning!("Причины отказа outbound Xray:\n{table}");
        }
        speed_measurements = checker.speed_measurements();
        speed_probe_results = checker.speed_probe_results();
        let unchecked_keys = checker.speed_unchecked_keys();
        sum.speed_unchecked = unchecked_keys.len();
        sum.speed_total = candidates.len().saturating_sub(unchecked_keys.len());

        let passed_keys: HashSet<String> = passed.iter().map(|p| p.key()).collect();
        for proxy in &passed {
            if let Some(index) = source_owner.get(&proxy.key()) {
                source_quality.sources[*index].counts.speed_qualified += 1;
            }
        }
        for proxy in &candidates {
            let key = proxy.key();
            if speed_measurements.contains_key(&key) && !passed_keys.contains(&key) {
                if let Some(index) = source_owner.get(&key) {
                    source_quality.sources[*index].counts.speed_failed += 1;
                }
            }
        }
        for row in &mut source_quality.sources {
            if matches!(
                row.status,
                source_report::SourceStatus::Parsed | source_report::SourceStatus::TcpChecked
            ) {
                row.status = source_report::SourceStatus::SpeedChecked;
            }
        }
        for p in &candidates {
            if !passed_keys.contains(&p.key()) && !unchecked_keys.contains(&p.key()) {
                dead_urls.push(p.base_url.clone());
            }
        }

        success!(
            "Прошли порог скорости: {}/{}; без проверки подходящим ядром: {}",
            passed.len(),
            sum.speed_total,
            sum.speed_unchecked
        );

        good = passed.clone();
        good.sort_by(|a, b| {
            b.speed_kbs
                .partial_cmp(&a.speed_kbs)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        output::write_lines_atomic(
            &cli.good_output,
            &good
                .iter()
                .map(|p| output::line(p, rename))
                .collect::<Vec<_>>(),
        )?;
        sum.good_file = Some((cli.good_output.clone(), good.len()));
        println!("\n{}", "  Топ по скорости".cyan().bold());
        output::print_top(&good, true);

        alive = passed;
        alive.sort_by_key(|p| p.ping.unwrap_or(u64::MAX));
        checkpoint.record_stage(
            checkpoint::PipelineStage::Speed,
            checkpoint.processed_links.clone(),
            good.iter()
                .map(checkpoint::ProxySnapshot::from_proxy)
                .collect(),
        );
        checkpoint.source_quality = source_quality.clone();
        save_checkpoint(&cli, &checkpoint)?;
    }

    output::write_lines_atomic(
        &cli.output,
        &alive
            .iter()
            .map(|p| output::line(p, rename))
            .collect::<Vec<_>>(),
    )?;
    sum.alive_file = Some((cli.output.clone(), alive.len()));
    println!("\n{}", "  Живые прокси · сортировка по ping".cyan().bold());
    output::print_top(&alive, !cli.no_speed);

    phase!("6/6", "СОХРАНЕНИЕ РЕЗУЛЬТАТОВ");
    emit_progress(&callback, "Сохранение", "Записываем результаты запуска");
    // ------------------------------------------------------------------
    // 7. Мёртвые + итог
    // ------------------------------------------------------------------
    if let Some(path) = &cli.dead {
        output::write_lines_atomic(path, &dead_urls)?;
        sum.dead_file = Some((path.clone(), dead_urls.len()));
    }
    if let Some(path) = &cli.json_output {
        let source_labels = alive
            .iter()
            .map(|proxy| {
                let source = source_owner
                    .get(&proxy.key())
                    .and_then(|index| source_quality.sources.get(*index))
                    .map(|source| {
                        format!(
                            "Источник {}",
                            source
                                .source_id
                                .trim_start_matches("feed-")
                                .trim_start_matches('0')
                        )
                    })
                    .unwrap_or_else(|| "Добавлено вручную".to_owned());
                (proxy.key(), source)
            })
            .collect();
        output::write_proxy_json_with_sources(path, &alive, &source_labels)?;
    }

    sum.alive = alive.len();
    sum.good = good.len();
    if !good.is_empty() {
        let speeds: Vec<f64> = good.iter().map(|p| p.speed_kbs).collect();
        sum.avg_kbs = speeds.iter().sum::<f64>() / speeds.len() as f64;
        let mut sorted = speeds.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = sorted.len() / 2;
        sum.median_kbs = if sorted.len().is_multiple_of(2) {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        };
    }

    if let Some(path) = &cli.speed_report {
        let rows: Vec<_> = candidates
            .iter()
            .map(|proxy| {
                let measurement = speed_measurements.get(&proxy.key());
                SpeedReportEntry {
                    source_id: source_owner
                        .get(&proxy.key())
                        .map(|index| source_quality.sources[*index].source_id.clone()),
                    name: if proxy.display.is_empty() {
                        &proxy.name
                    } else {
                        &proxy.display
                    },
                    protocol: proxy.proto,
                    server: &proxy.host,
                    port: proxy.port,
                    median_kbs: measurement.map(|value| value.median_kbs),
                    successful_probes: measurement.map(|value| value.successful_probes),
                    min_kbs: measurement.and_then(|value| value.min_kbs),
                    max_kbs: measurement.and_then(|value| value.max_kbs),
                    probes: speed_probe_results.get(&proxy.key()).map(|probes| {
                        probes
                            .iter()
                            .cloned()
                            .map(|mut probe| {
                                probe.target_url = source_report::redact_url(&probe.target_url);
                                probe
                            })
                            .collect()
                    }),
                }
            })
            .collect();
        let json = serde_json::to_string_pretty(&rows)?;
        output::write_text_atomic(path, &json)?;
        sum.speed_report_file = Some((path.clone(), rows.len()));
    }

    // ------------------------------------------------------------------
    // 8. Clash/mihomo конфиг из good-прокси
    // ------------------------------------------------------------------
    if let Some(path) = &cli.clash {
        if good.is_empty() {
            info!("Clash: пропуск — нет прокси, прошедших порог скорости");
        } else {
            let sources: Vec<proxy_clash::Source> = good
                .iter()
                .map(|p| proxy_clash::Source {
                    proto: p.proto.to_string(),
                    name: if p.display.is_empty() {
                        p.name.clone()
                    } else {
                        p.display.clone()
                    },
                    server: p.host.clone(),
                    port: p.port,
                    country: p.country.clone(),
                    settings: p.settings.clone(),
                    stream: p.stream.clone(),
                })
                .collect();
            let opts = proxy_clash::Options {
                include_country: !cli.clash_no_country,
                include_categories: !cli.clash_no_categories,
            };
            let (text, report) = proxy_clash::render(&sources, &opts)?;
            output::write_text_atomic(path, &text)?;
            if report.skipped > 0 {
                warning!(
                    "Clash: пропущено неподдерживаемых протоколов: {}",
                    report.skipped
                );
            }
            success!(
                "Сохранено: {} ({} прокси, групп {}, стран {})",
                path,
                report.proxies,
                report.groups,
                report.countries
            );
            sum.clash_file = Some((path.clone(), report.proxies));
        }
    }

    if let Some(path) = &cli.singbox {
        if good.is_empty() {
            info!("sing-box: пропуск — нет прокси, прошедших порог скорости");
            if let Some(report_path) = &cli.singbox_report {
                let report = proxy_singbox::Report::default();
                output::write_text_atomic(report_path, &serde_json::to_string_pretty(&report)?)?;
                sum.singbox_report_file = Some((report_path.clone(), 0));
            }
        } else {
            let sources: Vec<proxy_singbox::Source> = good
                .iter()
                .map(|proxy| proxy_singbox::Source {
                    proto: proxy.proto.to_string(),
                    name: if proxy.display.is_empty() {
                        proxy.name.clone()
                    } else {
                        proxy.display.clone()
                    },
                    server: proxy.host.clone(),
                    port: proxy.port,
                    country: proxy.country.clone(),
                    settings: proxy.settings.clone(),
                    stream: proxy.stream.clone(),
                })
                .collect();
            let (json, report) =
                proxy_singbox::render(&sources, &proxy_singbox::Options::default())?;
            output::write_text_atomic(path, &json)?;
            if cli.singbox_check {
                let binary = cli.singbox_bin.as_deref().map(Path::new);
                let result = crate::singbox_check::validate(binary, Path::new(path))?;
                success!(
                    "sing-box проверил конфиг: {} ({})",
                    result.version,
                    result.binary
                );
            }
            if let Some(report_path) = &cli.singbox_report {
                output::write_text_atomic(report_path, &serde_json::to_string_pretty(&report)?)?;
                sum.singbox_report_file = Some((report_path.clone(), report.skipped_count()));
            }
            if report.skipped_count() > 0 {
                warning!(
                    "sing-box: пропущено неподдерживаемых узлов: {}",
                    report.skipped_count()
                );
                for skipped in &report.skipped_nodes {
                    warning!(
                        "sing-box: {} пропущен — {}",
                        skipped.protocol,
                        skipped
                            .reason
                            .as_deref()
                            .unwrap_or("неподдерживаемая конфигурация")
                    );
                }
            }
            success!("Сохранено: {} ({} узлов)", path, report.supported_count());
            sum.singbox_file = Some((path.clone(), report.supported_count()));
        }
    }

    write_source_report(&cli, &source_quality)?;

    checkpoint.proxies = alive
        .iter()
        .map(checkpoint::ProxySnapshot::from_proxy)
        .collect();
    checkpoint.complete(
        alive
            .iter()
            .map(|proxy| output::line(proxy, rename))
            .collect(),
    );
    checkpoint.source_quality = source_quality.clone();
    save_checkpoint(&cli, &checkpoint)?;

    sum.total_secs = started.elapsed().as_secs_f64();

    success!(
        "Готово за {:.1}s | живых: {} | good: {}",
        sum.total_secs,
        alive.len(),
        good.len()
    );
    emit_progress(
        &callback,
        "Завершено",
        format!("Доступно узлов: {} · выше порога: {}", sum.alive, sum.good),
    );
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    struct TestDir(PathBuf);

    thread_local! {
        static DEFAULT_TEST_OUTPUT_DIR: RefCell<Option<TestDir>> = RefCell::new(None);
    }

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("proxy-rs-pipeline-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn write_fake_xray(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let script = r##"#!/bin/sh
if [ "$1" = version ]; then
  echo 'Xray local unit fixture'
  exit 0
fi
exec python3 - "$3" <<'PY'
import ipaddress, json, select, socket, sys, threading
port = int(json.load(open(sys.argv[1]))["inbounds"][0]["port"])
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen()
def exact(client, count):
    data = b""
    while len(data) < count:
        part = client.recv(count - len(data))
        if not part:
            raise EOFError()
        data += part
    return data
def handle(client):
    remote = None
    try:
        _, methods = exact(client, 2)
        exact(client, methods)
        client.sendall(b"\x05\x00")
        _, command, _, atyp = exact(client, 4)
        if command != 1:
            raise ValueError("expected CONNECT")
        if atyp == 1:
            host = socket.inet_ntoa(exact(client, 4))
        elif atyp == 3:
            length = exact(client, 1)[0]
            host = exact(client, length).decode()
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, exact(client, 16))
        else:
            raise ValueError("unsupported address type")
        destination_port = int.from_bytes(exact(client, 2), "big")
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("non-loopback destination blocked")
        remote = socket.create_connection((host, destination_port), timeout=3)
        client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        while True:
            ready, _, _ = select.select([client, remote], [], [], 5)
            if not ready:
                break
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                (remote if source is client else client).sendall(data)
    except Exception:
        pass
    finally:
        client.close()
        if remote:
            remote.close()
while True:
    client, _ = server.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
PY
"##;
        let mut contents = script.to_string();
        if contents.len() < 1_000_100 {
            contents.push_str(&"#".repeat(1_000_100 - contents.len()));
        }
        std::fs::write(path, contents).expect("write local fake Xray");
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    async fn serve_speed_fixture() -> (String, tokio::task::JoinHandle<()>) {
        serve_speed_fixture_for(1).await
    }

    #[cfg(unix)]
    async fn serve_speed_fixture_for(requests: usize) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind local speed fixture");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let body = vec![b'x'; 16 * 1024];
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().await.expect("accept speed request");
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request).await.expect("read speed request");
                stream
                    .write_all(headers.as_bytes())
                    .await
                    .expect("write speed response headers");
                stream
                    .write_all(&body)
                    .await
                    .expect("write speed response body");
            }
        });
        (format!("http://{address}/speed-fixture"), task)
    }

    #[cfg(unix)]
    async fn serve_cached_subscription(body: String) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind local subscription fixture");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept source request");
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let count = stream.read(&mut chunk).await.expect("read source request");
                    assert_ne!(count, 0, "client closed before sending HTTP headers");
                    request.extend_from_slice(&chunk[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                if request_index == 0 {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"fixture-v1\"\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                } else {
                    assert!(
                        String::from_utf8_lossy(&request)
                            .to_ascii_lowercase()
                            .contains("if-none-match: \"fixture-v1\"")
                    );
                    stream
                        .write_all(b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n")
                        .await
                        .unwrap();
                }
            }
        });
        (format!("http://{address}/subscription"), task)
    }

    #[cfg(unix)]
    async fn serve_subscription_once(body: String) -> (String, tokio::task::JoinHandle<()>) {
        serve_subscription_response_once("200 OK", body).await
    }

    #[cfg(unix)]
    async fn serve_subscription_response_once(
        status: &'static str,
        body: String,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind one-shot subscription fixture");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept subscription request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream
                    .read(&mut chunk)
                    .await
                    .expect("read subscription request");
                assert_ne!(count, 0, "client closed before sending HTTP headers");
                request.extend_from_slice(&chunk[..count]);
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write subscription response");
        });
        (format!("http://{address}/subscription"), task)
    }

    #[cfg(unix)]
    async fn serve_tcp_target() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind local TCP target");
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept local TCP probe");
                drop(stream);
            }
        });
        (port, task)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_completes_local_speed_good_and_clash_pipeline() {
        let temp = TestDir::new();
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            concat!(
                "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:443#local-unit-speed-node\n",
                "vless://11234567-89ab-cdef-0123-456789abcdef@127.0.0.1:8443#second-local-speed-node\n"
            ),
        )
        .unwrap();
        let core = temp.path("fake-xray");
        write_fake_xray(&core);
        let (speed_url, speed_server) = serve_speed_fixture_for(2).await;

        let mut cli = cli();
        cli.file = Some(links.display().to_string());
        cli.sources = temp.path("missing-sources.json").display().to_string();
        cli.output = temp.path("alive.txt").display().to_string();
        cli.raw_output = temp.path("raw.txt").display().to_string();
        cli.parsed_output = temp.path("parsed.txt").display().to_string();
        cli.good_output = temp.path("good.txt").display().to_string();
        cli.clash = Some(temp.path("clash.yaml").display().to_string());
        cli.singbox = Some(temp.path("sing-box.json").display().to_string());
        cli.singbox_report = Some(temp.path("sing-box-report.json").display().to_string());
        cli.speed_report = Some(temp.path("speed-report.json").display().to_string());
        cli.core = core.display().to_string();
        cli.workdir = temp.path("work").display().to_string();
        cli.speed_url = Some(speed_url);
        cli.speed_timeout = 3.0;
        cli.speed_connect_timeout = 2.0;
        cli.speed_probes = 1;
        cli.min_kb = 0.0;
        cli.batch = 1;
        cli.batch_workers = 1;
        cli.speed_threads = 1;
        cli.no_geoip = true;
        cli.no_tcp_ping = true;
        cli.no_xray_download = true;

        let summary = run(cli).await.unwrap();
        speed_server.await.unwrap();

        assert_eq!(summary.speed_total, 2);
        assert_eq!(summary.speed_passed, 2);
        assert_eq!(summary.good, 2);
        assert_eq!(
            summary.clash_file.as_ref().map(|(_, count)| *count),
            Some(2)
        );
        assert!(
            std::fs::read_to_string(temp.path("good.txt"))
                .unwrap()
                .contains("local-unit-speed-node")
        );
        let clash = std::fs::read_to_string(temp.path("clash.yaml")).unwrap();
        assert!(clash.contains("local-unit-speed-node"), "{clash}");
        assert!(clash.contains("proxy-groups:"), "{clash}");
        let singbox: serde_json::Value =
            serde_json::from_slice(&std::fs::read(temp.path("sing-box.json")).unwrap()).unwrap();
        assert_eq!(singbox["outbounds"][0]["type"], "vless");
        let singbox_report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(temp.path("sing-box-report.json")).unwrap())
                .unwrap();
        assert_eq!(singbox_report["supported"].as_array().unwrap().len(), 2);
        let speed_report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(temp.path("speed-report.json")).unwrap())
                .unwrap();
        assert_eq!(speed_report.as_array().unwrap().len(), 2);
        assert!(speed_report[0]["median_kbs"].as_f64().unwrap() > 0.0);
        let probes = speed_report[0]["probes"].as_array().unwrap();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0]["status"], "success");
        assert!(probes[0]["speed_kbs"].as_f64().unwrap() > 0.0);
        assert!(probes[0]["failure_reason"].is_null());
        assert!(
            probes[0]["target_url"]
                .as_str()
                .unwrap()
                .contains("[redacted]")
        );
        assert_eq!(
            summary.singbox_file.as_ref().map(|(_, count)| *count),
            Some(2)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_records_speed_rejections_as_dead_without_creating_good_or_clash_files() {
        let temp = TestDir::new();
        let (port, tcp_server) = serve_tcp_target().await;
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            format!("vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:{port}#slow-node\n"),
        )
        .unwrap();
        let core = temp.path("fake-xray");
        write_fake_xray(&core);
        let (speed_url, speed_server) = serve_speed_fixture().await;
        let dead = temp.path("dead.txt");
        let clash = temp.path("clash.yaml");
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = temp.path("missing-sources.json").display().to_string();
        options.core = core.display().to_string();
        options.workdir = temp.path("work").display().to_string();
        options.speed_url = Some(speed_url);
        options.speed_timeout = 3.0;
        options.speed_connect_timeout = 2.0;
        options.speed_probes = 1;
        options.min_kb = 1_000_000.0;
        options.batch = 1;
        options.batch_workers = 1;
        options.speed_threads = 1;
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_xray_download = true;
        options.dead = Some(dead.display().to_string());
        options.clash = Some(clash.display().to_string());

        let summary = run(options).await.unwrap();
        speed_server.await.unwrap();
        tcp_server.abort();

        assert_eq!(summary.speed_total, 1);
        assert_eq!(summary.speed_passed, 0);
        assert_eq!(summary.good, 0);
        assert_eq!(summary.dead_file.as_ref().map(|(_, count)| *count), Some(1));
        assert!(std::fs::read_to_string(dead).unwrap().contains("127.0.0.1"));
        assert!(!clash.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_reports_unsupported_speed_cipher_as_unchecked_not_dead() {
        let temp = TestDir::new();
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            "ss://YWVzLTEyOC1jZmI6cGFzcw==@127.0.0.1:8388#mihomo-only-cipher\n",
        )
        .unwrap();
        let core = temp.path("fake-xray");
        write_fake_xray(&core);
        let dead = temp.path("dead.txt");
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = temp.path("missing-sources.json").display().to_string();
        options.core = core.display().to_string();
        options.workdir = temp.path("work").display().to_string();
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_xray_download = true;
        options.no_hysteria1_download = true;
        options.dead = Some(dead.display().to_string());

        let summary = run(options).await.unwrap();

        assert_eq!(summary.speed_total, 0);
        assert_eq!(summary.speed_passed, 0);
        assert_eq!(summary.speed_unchecked, 1);
        assert_eq!(summary.dead_file.as_ref().map(|(_, count)| *count), Some(0));
        assert_eq!(std::fs::read_to_string(dead).unwrap(), "");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_tracks_source_quality_through_tcp_and_speed_stages() {
        let temp = TestDir::new();
        let (port, tcp_server) = serve_tcp_target().await;
        let link = format!(
            "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:{port}#source-speed-node"
        );
        let (url, source_server) =
            serve_subscription_once(format!("{link}\n{link}\nvless://bad@bad.example\n")).await;
        let (second_url, second_source_server) = serve_subscription_once(format!(
            "{link}\nvmess://01234567-89ab-cdef-0123-456789abcdef@bad.example:443?type=quic\n"
        ))
        .await;
        let sources = temp.path("sources.json");
        std::fs::write(
            &sources,
            serde_json::json!({"3": [url.clone(), second_url.clone()]}).to_string(),
        )
        .unwrap();
        let core = temp.path("fake-xray");
        write_fake_xray(&core);
        let (speed_url, speed_server) = serve_speed_fixture().await;
        let report_path = temp.path("source-report.json");

        let mut options = cli();
        options.sources = sources.display().to_string();
        options.source_report = Some(report_path.display().to_string());
        options.fetch_cache_dir = temp.path("cache").display().to_string();
        options.output = temp.path("alive.txt").display().to_string();
        options.raw_output = temp.path("raw.txt").display().to_string();
        options.parsed_output = temp.path("parsed.txt").display().to_string();
        options.good_output = temp.path("good.txt").display().to_string();
        options.core = core.display().to_string();
        options.workdir = temp.path("work").display().to_string();
        options.speed_url = Some(speed_url);
        options.speed_timeout = 3.0;
        options.speed_connect_timeout = 2.0;
        options.speed_probes = 1;
        options.fetch_concurrency = 1;
        options.min_kb = 0.0;
        options.batch = 1;
        options.batch_workers = 1;
        options.speed_threads = 1;
        options.no_geoip = true;
        options.no_xray_download = true;
        options.tcp_max_ms = 10_000;

        let summary = run(options).await.unwrap();
        source_server.await.unwrap();
        second_source_server.await.unwrap();
        speed_server.await.unwrap();
        tcp_server.abort();

        assert_eq!(summary.alive, 1);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
        let sources = report["sources"].as_array().unwrap();
        let first = sources
            .iter()
            .find(|source| source["url"] == source_report::redact_url(&url))
            .unwrap();
        assert_eq!(first["status"], "speed_checked");
        assert_eq!(first["counts"]["fetched"], 1);
        assert_eq!(first["counts"]["valid"], 2);
        assert_eq!(first["counts"]["unique"], 1);
        assert_eq!(first["counts"]["duplicate"], 1);
        assert_eq!(first["counts"]["invalid_reasons"]["bad uuid"], 1);
        assert_eq!(first["counts"]["tcp_live"], 1);
        assert_eq!(first["counts"]["speed_qualified"], 1);
        let second = sources
            .iter()
            .find(|source| source["url"] == source_report::redact_url(&second_url))
            .unwrap();
        assert_eq!(second["counts"]["valid"], 1);
        assert_eq!(second["counts"]["unique"], 0);
        assert_eq!(second["counts"]["duplicate"], 1);
        assert_eq!(
            second["counts"]["unsupported_reasons"]["vmess: transport=quic"],
            1
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_reports_fetched_proxy_rejected_by_tcp_with_empty_dead_and_json_outputs() {
        let temp = TestDir::new();
        // Hold the port on 127.0.0.1 while targeting 127.0.0.2. Both are
        // loopback addresses, but the listener cannot accept the probe target.
        let occupied = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        let link =
            format!("vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.2:{port}#tcp-rejected");
        let (url, source_server) = serve_subscription_once(format!("{link}\n")).await;
        let sources = temp.path("sources.json");
        std::fs::write(&sources, serde_json::json!({"3": [url]}).to_string()).unwrap();
        let report_path = temp.path("source-report.json");
        let dead_path = temp.path("dead.txt");
        let json_path = temp.path("proxies.json");

        let mut options = cli();
        options.sources = sources.display().to_string();
        options.fetch_cache_dir = temp.path("cache").display().to_string();
        options.source_report = Some(report_path.display().to_string());
        options.dead = Some(dead_path.display().to_string());
        options.json_output = Some(json_path.display().to_string());
        options.tcp_timeout = 0.1;
        options.tcp_retries = 0;
        options.tcp_concurrency = 1;
        options.no_geoip = true;
        options.no_speed = true;

        let summary = run(options).await.unwrap();
        source_server.await.unwrap();
        assert!(
            occupied.local_addr().is_ok(),
            "fixture listener must stay bound"
        );

        assert_eq!(summary.alive, 0);
        assert_eq!(summary.dead_file.as_ref().map(|(_, count)| *count), Some(1));
        assert!(
            std::fs::read_to_string(dead_path)
                .unwrap()
                .contains(&format!("127.0.0.2:{port}"))
        );
        assert_eq!(std::fs::read_to_string(json_path).unwrap(), "[]");
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
        assert_eq!(report["sources"][0]["status"], "tcp_checked");
        assert_eq!(report["sources"][0]["counts"]["tcp_live"], 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_counts_valid_links_and_ignores_malformed_links_from_fetched_source() {
        let temp = TestDir::new();
        let link = "vless://01234567-89ab-cdef-0123-456789abcdef@local.example:443#valid";
        let unsupported =
            "vmess://01234567-89ab-cdef-0123-456789abcdef@node.example:443?type=quic#unsupported";
        let (url, source_server) =
            serve_subscription_once(format!("{link}\n{unsupported}\nnot-a-proxy\nvless://bad\n"))
                .await;
        let source_url = format!(
            "{}?token=query-secret",
            url.replacen("://", "://alice:feed-secret@", 1)
        );
        let sources = temp.path("sources.json");
        std::fs::write(&sources, serde_json::json!({"3": [source_url]}).to_string()).unwrap();
        let report_path = temp.path("source-report.json");
        let mut options = cli();
        options.sources = sources.display().to_string();
        options.source_report = Some(report_path.display().to_string());
        options.fetch_cache_dir = temp.path("cache").display().to_string();
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_speed = true;

        let summary = run(options).await.unwrap();
        source_server.await.unwrap();

        assert_eq!(summary.unique, 1);
        assert_eq!(summary.alive, 1);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
        let source = &report["sources"][0];
        assert_eq!(source["status"], "parsed");
        assert_eq!(source["counts"]["valid"], 1);
        assert_eq!(source["counts"]["duplicate"], 0);
        assert_eq!(
            source["counts"]["unsupported_reasons"]["vmess: transport=quic"],
            1
        );
        let report_json = std::fs::read_to_string(report_path).unwrap();
        for secret in ["alice", "feed-secret", "query-secret"] {
            assert!(
                !report_json.contains(secret),
                "source report leaked {secret}"
            );
        }
    }

    #[tokio::test]
    async fn run_reparses_fetched_checkpoint_and_writes_parsed_outputs() {
        let temp = TestDir::new();
        let link = "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:9#fetched-resume";
        let mut checkpoint = checkpoint::Checkpoint::new();
        checkpoint.raw_links = vec![link.to_string()];
        checkpoint.record_stage(
            checkpoint::PipelineStage::Fetched,
            vec![link.to_string()],
            Vec::new(),
        );
        let checkpoint_path = temp.path("fetched.json");
        checkpoint.save(&checkpoint_path).unwrap();

        let mut options = cli();
        options.resume = true;
        options.checkpoint = Some(checkpoint_path.display().to_string());
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_speed = true;
        options.output = temp.path("alive.txt").display().to_string();
        options.parsed_output = temp.path("parsed.txt").display().to_string();

        let summary = run(options).await.unwrap();

        assert_eq!(summary.links, 1);
        assert_eq!(summary.unique, 1);
        assert_eq!(summary.alive, 1);
        assert!(
            std::fs::read_to_string(temp.path("parsed.txt"))
                .unwrap()
                .contains("fetched-resume")
        );
        assert_eq!(
            checkpoint::Checkpoint::load(checkpoint_path)
                .unwrap()
                .unwrap()
                .stage,
            checkpoint::PipelineStage::Complete
        );
    }

    #[tokio::test]
    async fn run_rejects_resume_when_checkpoint_is_missing() {
        let temp = TestDir::new();
        let checkpoint_path = temp.path("missing.checkpoint.json");
        let mut options = cli();
        options.resume = true;
        options.checkpoint = Some(checkpoint_path.display().to_string());

        let error = run(options).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("checkpoint для --resume не найден")
        );
    }

    #[tokio::test]
    async fn run_rejects_resume_before_a_parse_stage_is_complete() {
        let temp = TestDir::new();
        let checkpoint_path = temp.path("new.checkpoint.json");
        checkpoint::Checkpoint::new()
            .save(&checkpoint_path)
            .unwrap();
        let mut options = cli();
        options.resume = true;
        options.checkpoint = Some(checkpoint_path.display().to_string());

        let error = run(options).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("checkpoint ещё не содержит завершённый этап парсинга")
        );
    }

    #[tokio::test]
    async fn run_rejects_an_empty_source_selection() {
        let temp = TestDir::new();
        let sources = temp.path("sources.json");
        std::fs::write(&sources, r#"{"3":[]}"#).unwrap();
        let mut options = cli();
        options.sources = sources.display().to_string();

        let error = run(options).await.unwrap_err();

        assert!(error.to_string().contains("нет источников для загрузки"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_reports_fetch_failure_and_returns_when_all_subscriptions_fail() {
        let temp = TestDir::new();
        let (url, source_server) =
            serve_subscription_response_once("503 Service Unavailable", String::new()).await;
        let sources = temp.path("sources.json");
        std::fs::write(&sources, serde_json::json!({"3": [url]}).to_string()).unwrap();
        let mut options = cli();
        options.sources = sources.display().to_string();
        options.fetch_retries = 0;
        options.fetch_timeout = 1.0;
        options.no_fetch_cache = true;

        let error = run(options).await.unwrap_err();
        source_server.await.unwrap();

        assert!(
            error
                .to_string()
                .contains("не удалось загрузить ни одного источника (ошибок: 1)")
        );
    }

    #[tokio::test]
    async fn run_rejects_resume_checkpoint_without_proxy_snapshots() {
        let temp = TestDir::new();
        let checkpoint_path = temp.path("empty-proxies.checkpoint.json");
        let mut checkpoint = checkpoint::Checkpoint::new();
        checkpoint.record_stage(checkpoint::PipelineStage::Parsed, Vec::new(), Vec::new());
        checkpoint.save(&checkpoint_path).unwrap();
        let mut options = cli();
        options.resume = true;
        options.checkpoint = Some(checkpoint_path.display().to_string());

        let error = run(options).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("checkpoint не содержит прокси для продолжения")
        );
    }

    #[tokio::test]
    async fn run_restores_multiple_speed_results_and_computes_even_median() {
        let temp = TestDir::new();
        let checkpoint_path = temp.path("speed.checkpoint.json");
        let mut slower = proxy(
            "01234567-89ab-cdef-0123-456789abcdef",
            "slower.example",
            "US",
        );
        slower.display = "slower".into();
        slower.speed_kbs = 100.0;
        slower.ping = Some(10);
        let mut faster = proxy(
            "11234567-89ab-cdef-0123-456789abcdef",
            "faster.example",
            "US",
        );
        faster.display = "faster".into();
        faster.speed_kbs = 200.0;
        faster.ping = Some(20);
        let mut checkpoint = checkpoint::Checkpoint::new();
        checkpoint.record_stage(
            checkpoint::PipelineStage::Speed,
            Vec::new(),
            vec![
                checkpoint::ProxySnapshot::from_proxy(&slower),
                checkpoint::ProxySnapshot::from_proxy(&faster),
            ],
        );
        checkpoint.save(&checkpoint_path).unwrap();
        let mut options = cli();
        options.resume = true;
        options.checkpoint = Some(checkpoint_path.display().to_string());
        options.good_output = temp.path("good.txt").display().to_string();
        options.output = temp.path("alive.txt").display().to_string();

        let summary = run(options).await.unwrap();

        assert_eq!(summary.good, 2);
        assert_eq!(summary.speed_total, 2);
        assert_eq!(summary.speed_passed, 2);
        assert_eq!(summary.avg_kbs, 150.0);
        assert_eq!(summary.median_kbs, 150.0);
        let good = std::fs::read_to_string(temp.path("good.txt")).unwrap();
        assert!(good.find("faster").unwrap() < good.find("slower").unwrap());
    }

    #[tokio::test]
    async fn run_errors_when_parsing_produces_no_supported_proxies() {
        let temp = TestDir::new();
        let links = temp.path("invalid-links.txt");
        std::fs::write(&links, "not-a-proxy\ntuic://unsupported\n").unwrap();
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = temp.path("missing-sources.json").display().to_string();
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_speed = true;

        let error = run(options).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("не найдено ни одного подходящего прокси")
        );
    }

    #[tokio::test]
    async fn run_writes_empty_dead_json_and_source_report_outputs_when_filters_remove_all() {
        let temp = TestDir::new();
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:9#filtered-out\n",
        )
        .unwrap();
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = temp.path("missing-sources.json").display().to_string();
        options.output = temp.path("alive.txt").display().to_string();
        options.dead = Some(temp.path("dead.txt").display().to_string());
        options.json_output = Some(temp.path("alive.json").display().to_string());
        options.source_report = Some(temp.path("source-report.json").display().to_string());
        options.protocol = vec!["trojan".into()];
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_speed = true;

        let summary = run(options).await.unwrap();

        assert_eq!(summary.alive, 0);
        assert_eq!(summary.dead_file.as_ref().map(|(_, count)| *count), Some(0));
        assert_eq!(std::fs::read_to_string(temp.path("dead.txt")).unwrap(), "");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(temp.path("alive.json")).unwrap()
            )
            .unwrap(),
            serde_json::json!([])
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(temp.path("source-report.json")).unwrap()
            )
            .unwrap()["sources"],
            serde_json::json!([])
        );
    }

    fn protobuf_varint(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        while value >= 0x80 {
            bytes.push((value as u8) | 0x80);
            value >>= 7;
        }
        bytes.push(value as u8);
        bytes
    }

    fn protobuf_bytes(field: u64, value: &[u8]) -> Vec<u8> {
        let mut bytes = protobuf_varint((field << 3) | 2);
        bytes.extend(protobuf_varint(value.len() as u64));
        bytes.extend(value);
        bytes
    }

    fn protobuf_uint(field: u64, value: u64) -> Vec<u8> {
        let mut bytes = protobuf_varint(field << 3);
        bytes.extend(protobuf_varint(value));
        bytes
    }

    fn geoip_fixture() -> Vec<u8> {
        let mut database = Vec::new();
        for index in 0..10 {
            let mut entry = Vec::new();
            if index == 0 {
                let mut cidr = protobuf_bytes(1, &[8, 8, 8, 8]);
                cidr.extend(protobuf_uint(2, 32));
                entry.extend(protobuf_bytes(1, b"US"));
                entry.extend(protobuf_bytes(2, &cidr));
            }
            entry.extend(protobuf_bytes(9, &vec![0; 1100]));
            database.extend(protobuf_bytes(1, &entry));
        }
        database
    }

    #[tokio::test]
    async fn run_assigns_geoip_and_writes_renamed_local_outputs() {
        let temp = TestDir::new();
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            "vless://01234567-89ab-cdef-0123-456789abcdef@8.8.8.8:443#geoip-output\n",
        )
        .unwrap();
        let database = temp.path("geoip.dat");
        std::fs::write(&database, geoip_fixture()).unwrap();
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = temp.path("missing-sources.json").display().to_string();
        options.geoip_db = Some(database.display().to_string());
        options.geoip_url = "http://127.0.0.1:1/geoip.dat".into();
        options.output = temp.path("alive.txt").display().to_string();
        options.parsed_output = temp.path("parsed.txt").display().to_string();
        options.no_tcp_ping = true;
        options.no_speed = true;

        let summary = run(options).await.unwrap();

        assert!(summary.geo);
        assert_eq!(summary.geo_countries, 1);
        assert_eq!(summary.alive, 1);
        assert!(
            std::fs::read_to_string(temp.path("parsed.txt"))
                .unwrap()
                .contains("[US] - 001")
        );
        assert!(
            std::fs::read_to_string(temp.path("alive.txt"))
                .unwrap()
                .contains("[US] - 001")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_reports_cached_source_and_tcp_live_counters() {
        let temp = TestDir::new();
        let (port, tcp_server) = serve_tcp_target().await;
        let link = format!(
            "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:{port}#cached-source-node"
        );
        let body = format!("{link}\n{link}\n");
        let (url, source_server) = serve_cached_subscription(body).await;
        let sources = temp.path("sources.json");
        std::fs::write(&sources, serde_json::json!({"3": [url]}).to_string()).unwrap();
        let report_path = temp.path("source-report.json");

        for _ in 0..2 {
            let mut options = cli();
            options.sources = sources.display().to_string();
            options.output = temp.path("alive.txt").display().to_string();
            options.raw_output = temp.path("raw.txt").display().to_string();
            options.parsed_output = temp.path("parsed.txt").display().to_string();
            options.good_output = temp.path("good.txt").display().to_string();
            options.fetch_cache_dir = temp.path("cache").display().to_string();
            options.source_report = Some(report_path.display().to_string());
            options.no_geoip = true;
            options.no_speed = true;
            options.tcp_timeout = 1.0;
            options.tcp_retries = 1;
            let summary = run(options).await.unwrap();
            assert_eq!(summary.alive, 1);

            let report: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
            let source = &report["sources"][0];
            assert_eq!(source["status"], "tcp_checked");
            assert_eq!(source["counts"]["fetched"], 1);
            assert_eq!(source["counts"]["valid"], 2);
            assert_eq!(source["counts"]["duplicate"], 1);
            assert_eq!(source["counts"]["tcp_live"], 1);
        }

        source_server.await.unwrap();
        tcp_server.abort();
    }

    #[tokio::test]
    async fn run_applies_limit_before_only_new_and_handles_missing_previous_output() {
        let temp = TestDir::new();
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            concat!(
                "vless://01234567-89ab-cdef-0123-456789abcdef@first.example:443#new-node\n",
                "vless://11234567-89ab-cdef-0123-456789abcdef@second.example:443#known-node\n"
            ),
        )
        .unwrap();
        let output = temp.path("alive.txt");
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = temp.path("missing-sources.json").display().to_string();
        options.output = output.display().to_string();
        options.parsed_output = temp.path("parsed.txt").display().to_string();
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_speed = true;
        options.only_new = true;
        options.limit = Some(1);

        let summary = run(options).await.unwrap();

        assert_eq!(summary.unique, 2);
        assert_eq!(summary.alive, 1);
        let alive = std::fs::read_to_string(output).unwrap();
        assert!(alive.contains("new-node"));
        assert!(!alive.contains("known-node"));
    }

    #[tokio::test]
    async fn run_shuffles_candidates_without_dropping_links() {
        let temp = TestDir::new();
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            concat!(
                "vless://01234567-89ab-cdef-0123-456789abcdef@first.example:443#first-node\n",
                "vless://11234567-89ab-cdef-0123-456789abcdef@second.example:443#second-node\n"
            ),
        )
        .unwrap();
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = temp.path("missing-sources.json").display().to_string();
        options.parsed_output = temp.path("parsed.txt").display().to_string();
        options.shuffle = true;
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_speed = true;

        let summary = run(options).await.unwrap();

        assert_eq!(summary.unique, 2);
        assert_eq!(
            std::fs::read_to_string(temp.path("parsed.txt"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn shuffle_seed_repeats_the_same_candidate_order() {
        let run_with_seed = async |suffix: &str| {
            let temp = TestDir::new();
            let links = temp.path("links.txt");
            std::fs::write(
                &links,
                concat!(
                    "vless://01234567-89ab-cdef-0123-456789abcdef@first.example:443#first-node\n",
                    "vless://11234567-89ab-cdef-0123-456789abcdef@second.example:443#second-node\n",
                    "vless://21234567-89ab-cdef-0123-456789abcdef@third.example:443#third-node\n",
                    "vless://31234567-89ab-cdef-0123-456789abcdef@fourth.example:443#fourth-node\n"
                ),
            )
            .unwrap();
            let mut options = cli();
            options.file = Some(links.display().to_string());
            options.sources = temp.path("missing-sources.json").display().to_string();
            options.parsed_output = temp
                .path(&format!("parsed-{suffix}.txt"))
                .display()
                .to_string();
            options.shuffle_seed = Some(42);
            options.no_geoip = true;
            options.no_tcp_ping = true;
            options.no_speed = true;

            run(options).await.unwrap();
            std::fs::read_to_string(temp.path(&format!("parsed-{suffix}.txt"))).unwrap()
        };

        assert_eq!(run_with_seed("a").await, run_with_seed("b").await);
    }

    #[tokio::test]
    async fn run_resuming_at_geoip_skips_geoip_download_and_only_new_filter() {
        let temp = TestDir::new();
        let checkpoint_path = temp.path("geoip.checkpoint.json");
        let mut saved_proxy = proxy(
            "01234567-89ab-cdef-0123-456789abcdef",
            "resume.example",
            "US",
        );
        saved_proxy.name = "resumed-node".into();
        saved_proxy.display = "resumed-node".into();
        let mut checkpoint = checkpoint::Checkpoint::new();
        checkpoint.record_stage(
            checkpoint::PipelineStage::GeoIp,
            Vec::new(),
            vec![checkpoint::ProxySnapshot::from_proxy(&saved_proxy)],
        );
        checkpoint.save(&checkpoint_path).unwrap();

        let output = temp.path("alive.txt");
        std::fs::write(&output, format!("{}\n", saved_proxy.orig_url)).unwrap();
        let mut options = cli();
        options.resume = true;
        options.checkpoint = Some(checkpoint_path.display().to_string());
        options.geoip_db = Some(temp.path("missing-geoip.dat").display().to_string());
        options.no_geoip = false;
        options.no_tcp_ping = true;
        options.no_speed = true;
        options.only_new = true;
        options.output = output.display().to_string();

        let summary = run(options).await.unwrap();

        assert!(summary.geo);
        assert_eq!(summary.alive, 1);
        assert!(
            std::fs::read_to_string(output)
                .unwrap()
                .contains("resume.example")
        );
    }

    #[tokio::test]
    async fn run_does_not_write_an_empty_raw_subscription_file_for_direct_links() {
        let temp = TestDir::new();
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            "vless://01234567-89ab-cdef-0123-456789abcdef@direct.example:443#direct-node\n",
        )
        .unwrap();
        let sources = temp.path("sources.json");
        std::fs::write(&sources, r#"{"3":[]}"#).unwrap();
        let raw = temp.path("raw.txt");
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = sources.display().to_string();
        options.raw_output = raw.display().to_string();
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_speed = true;

        let summary = run(options).await.unwrap();

        assert_eq!(summary.fetch_loaded, 0);
        assert!(summary.raw_file.is_none());
        assert!(!raw.exists());
    }

    #[tokio::test]
    async fn run_reports_only_new_output_read_errors() {
        let temp = TestDir::new();
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            "vless://01234567-89ab-cdef-0123-456789abcdef@node.example:443#new-node\n",
        )
        .unwrap();
        let output_directory = temp.path("alive-directory");
        std::fs::create_dir(&output_directory).unwrap();
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = temp.path("missing-sources.json").display().to_string();
        options.output = output_directory.display().to_string();
        options.parsed_output = temp.path("parsed.txt").display().to_string();
        options.no_geoip = true;
        options.no_tcp_ping = true;
        options.no_speed = true;
        options.only_new = true;

        let error = run(options).await.unwrap_err();

        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(output_directory.is_dir());
    }

    #[tokio::test]
    async fn run_filters_resumed_tcp_results_by_max_ping_and_writes_rejected_proxy_dead() {
        let temp = TestDir::new();
        let checkpoint_path = temp.path("tcp.checkpoint.json");
        let mut fast = proxy("01234567-89ab-cdef-0123-456789abcdef", "fast.example", "US");
        fast.display = "fast-node".into();
        fast.ping = Some(1);
        let mut slow = proxy("11234567-89ab-cdef-0123-456789abcdef", "slow.example", "US");
        slow.display = "slow-node".into();
        slow.ping = Some(20);
        let mut checkpoint = checkpoint::Checkpoint::new();
        checkpoint.record_stage(
            checkpoint::PipelineStage::TcpPing,
            Vec::new(),
            vec![
                checkpoint::ProxySnapshot::from_proxy(&fast),
                checkpoint::ProxySnapshot::from_proxy(&slow),
            ],
        );
        checkpoint.save(&checkpoint_path).unwrap();
        let mut options = cli();
        options.resume = true;
        options.checkpoint = Some(checkpoint_path.display().to_string());
        options.output = temp.path("alive.txt").display().to_string();
        options.dead = Some(temp.path("dead.txt").display().to_string());
        options.max_ping = 5;
        options.no_speed = true;

        let summary = run(options).await.unwrap();

        assert_eq!(summary.alive, 1);
        assert_eq!(summary.dead_file.as_ref().map(|(_, count)| *count), Some(1));
        let alive = std::fs::read_to_string(temp.path("alive.txt")).unwrap();
        let dead = std::fs::read_to_string(temp.path("dead.txt")).unwrap();
        assert!(alive.contains("fast-node"));
        assert!(!alive.contains("slow-node"));
        assert!(dead.contains("slow.example"));
    }

    #[tokio::test]
    async fn run_completes_when_max_ping_rejects_every_resumed_tcp_result() {
        let temp = TestDir::new();
        let checkpoint_path = temp.path("all-slow.checkpoint.json");
        let mut slow = proxy("01234567-89ab-cdef-0123-456789abcdef", "slow.example", "US");
        slow.display = "slow-node".into();
        slow.ping = Some(20);
        let mut checkpoint = checkpoint::Checkpoint::new();
        checkpoint.record_stage(
            checkpoint::PipelineStage::TcpPing,
            Vec::new(),
            vec![checkpoint::ProxySnapshot::from_proxy(&slow)],
        );
        checkpoint.save(&checkpoint_path).unwrap();

        let output = temp.path("alive.txt");
        let dead = temp.path("dead.txt");
        let mut options = cli();
        options.resume = true;
        options.checkpoint = Some(checkpoint_path.display().to_string());
        options.output = output.display().to_string();
        options.dead = Some(dead.display().to_string());
        options.max_ping = 5;
        options.no_speed = true;

        let summary = run(options).await.unwrap();

        assert_eq!(summary.alive, 0);
        assert_eq!(summary.good, 0);
        assert_eq!(summary.dead_file.as_ref().map(|(_, count)| *count), Some(1));
        assert_eq!(std::fs::read_to_string(output).unwrap(), "");
        assert!(
            std::fs::read_to_string(dead)
                .unwrap()
                .contains("slow.example")
        );
        let saved = checkpoint::Checkpoint::load(checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(saved.stage, checkpoint::PipelineStage::Complete);
        assert!(saved.final_links.is_empty());
    }

    fn proxy(id: &str, host: &str, country: &str) -> Proxy {
        parse::parse_link(&format!(
            "vless://{id}@{host}:443?type=tcp&security=none#{id}"
        ))
        .map(|mut proxy| {
            proxy.country = country.into();
            proxy
        })
        .unwrap()
    }

    #[test]
    fn outbound_failure_shape_keeps_protocol_fields_and_excludes_secrets() {
        let vless = proxy(
            "01234567-89ab-cdef-0123-456789abcdef",
            "proxy.example",
            "US",
        );
        assert_eq!(
            safe_outbound_shape(&vless),
            "vless: transport=raw, security=none"
        );
        assert!(!safe_outbound_shape(&vless).contains("01234567"));

        let mut empty_fields = vless.clone();
        empty_fields.stream = Some(serde_json::json!({"network": "", "security": ""}));
        assert_eq!(
            safe_outbound_shape(&empty_fields),
            "vless: transport=unknown, security=unknown"
        );

        let ss = parse::parse_link("ss://YWVzLTI1Ni1nY206c2VjcmV0@proxy.example:8388").unwrap();
        assert_eq!(safe_outbound_shape(&ss), "shadowsocks: method=aes-256-gcm");
        assert!(!safe_outbound_shape(&ss).contains("secret"));
    }

    fn cli() -> Cli {
        let mut options = Cli::try_parse_from(["proxy-rs"]).unwrap();
        DEFAULT_TEST_OUTPUT_DIR.with(|slot| {
            let mut slot = slot.borrow_mut();
            let output_dir = slot.get_or_insert_with(TestDir::new);
            options.output = output_dir.path("alive.txt").display().to_string();
            options.raw_output = output_dir.path("raw.txt").display().to_string();
            options.parsed_output = output_dir.path("parsed.txt").display().to_string();
            options.good_output = output_dir.path("good.txt").display().to_string();
        });
        options
    }

    #[test]
    fn resolve_default_from_checks_original_executable_and_bin_paths_in_order() {
        let dir = TestDir::new();
        let exe_dir = dir.path("exe");
        let bin_dir = dir.path("bin");
        std::fs::create_dir_all(&exe_dir).unwrap();
        std::fs::create_dir_all(&bin_dir).unwrap();
        let executable = exe_dir.join("proxy-rs");
        let name = Path::new("geoip.dat");

        let original = dir.path("geoip.dat");
        std::fs::write(&original, b"original").unwrap();
        let executable_copy = exe_dir.join(name);
        std::fs::write(&executable_copy, b"exe").unwrap();
        let bin_copy = bin_dir.join(name);
        std::fs::write(&bin_copy, b"bin").unwrap();
        assert_eq!(
            resolve_default_from(&original, Some(&executable), &bin_dir),
            original
        );

        std::fs::remove_file(&original).unwrap();
        assert_eq!(
            resolve_default_from(name, Some(&executable), &bin_dir),
            executable_copy
        );

        std::fs::remove_file(&executable_copy).unwrap();
        assert_eq!(
            resolve_default_from(name, Some(&executable), &bin_dir),
            bin_copy
        );

        std::fs::remove_file(&bin_copy).unwrap();
        assert_eq!(
            resolve_default_from(name, Some(&executable), &bin_dir),
            name
        );
        assert_eq!(resolve_default_from(name, None, &bin_dir), name);
    }

    #[test]
    fn resolve_default_from_uses_bin_path_without_an_executable() {
        let dir = TestDir::new();
        let bin_dir = dir.path("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let name = Path::new("geoip.dat");
        let bin_copy = bin_dir.join(name);
        std::fs::write(&bin_copy, b"bin").unwrap();

        assert_eq!(resolve_default_from(name, None, &bin_dir), bin_copy);
    }

    #[test]
    fn default_runtime_paths_are_next_to_the_current_executable() {
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(default_geoip_path().unwrap(), exe_dir.join("geoip.dat"));
        assert_eq!(
            default_core_path().unwrap(),
            exe_dir.join(xray::core_bin_name())
        );
    }

    #[test]
    fn default_asset_and_geoip_paths_cover_parentless_executable_and_override() {
        assert_eq!(
            default_asset_path(Path::new(""), "geoip.dat"),
            PathBuf::from("./geoip.dat")
        );
        assert_eq!(
            default_asset_path(Path::new("/opt/proxy-rs/proxy-rs"), "xray"),
            PathBuf::from("/opt/proxy-rs/xray")
        );
        assert_eq!(
            geoip_db_path(Some("custom/geoip.dat")).unwrap(),
            PathBuf::from("custom/geoip.dat")
        );
        assert_eq!(geoip_db_path(None).unwrap(), default_geoip_path().unwrap());
    }

    #[tokio::test]
    async fn run_writes_empty_outputs_and_completes_checkpoint_when_tcp_rejects_all() {
        let temp = TestDir::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let links = temp.path("links.txt");
        std::fs::write(
            &links,
            format!("vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:{port}#closed-port\n"),
        )
        .unwrap();
        let checkpoint_path = temp.path("run.checkpoint.json");
        let json_path = temp.path("alive.json");
        let dead_path = temp.path("dead.txt");
        let report_path = temp.path("sources-report.json");
        let mut options = cli();
        options.file = Some(links.display().to_string());
        options.sources = temp.path("missing-sources.json").display().to_string();
        options.checkpoint = Some(checkpoint_path.display().to_string());
        options.json_output = Some(json_path.display().to_string());
        options.dead = Some(dead_path.display().to_string());
        options.source_report = Some(report_path.display().to_string());
        options.no_geoip = true;
        options.no_speed = true;
        options.tcp_timeout = 0.2;
        options.tcp_retries = 0;

        let summary = run(options).await.unwrap();

        assert_eq!(summary.tcp_total, 1);
        assert_eq!(summary.tcp_alive, 0);
        assert_eq!(summary.alive, 0);
        assert_eq!(std::fs::read_to_string(&json_path).unwrap(), "[]");
        assert!(
            std::fs::read_to_string(&dead_path)
                .unwrap()
                .contains(&format!("127.0.0.1:{port}"))
        );
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
        assert_eq!(report["sources"].as_array().unwrap().len(), 0);
        let checkpoint = checkpoint::Checkpoint::load(checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.stage, checkpoint::PipelineStage::Complete);
        assert!(checkpoint.final_links.is_empty());
    }

    #[tokio::test]
    async fn run_restores_speed_checkpoint_and_uses_proxy_name_for_clash_fallback() {
        let temp = TestDir::new();
        let checkpoint_path = temp.path("speed.checkpoint.json");
        let mut slower = proxy("01234567-89ab-cdef-0123-456789abcdef", "slow.example", "DE");
        slower.name = "slow-name".into();
        slower.display.clear();
        slower.ping = Some(20);
        slower.speed_kbs = 100.0;
        let mut faster = proxy("11234567-89ab-cdef-0123-456789abcdef", "fast.example", "US");
        faster.name = "fast-name".into();
        faster.display = "fast-marker".into();
        faster.ping = Some(5);
        faster.speed_kbs = 200.0;
        let mut checkpoint = checkpoint::Checkpoint::new();
        checkpoint.record_stage(
            checkpoint::PipelineStage::Speed,
            Vec::new(),
            vec![
                checkpoint::ProxySnapshot::from_proxy(&slower),
                checkpoint::ProxySnapshot::from_proxy(&faster),
            ],
        );
        checkpoint.save(&checkpoint_path).unwrap();
        let mut options = cli();
        options.resume = true;
        options.checkpoint = Some(checkpoint_path.display().to_string());
        options.no_tcp_ping = true;
        options.clash = Some(temp.path("clash.yaml").display().to_string());
        options.good_output = temp.path("good.txt").display().to_string();
        options.output = temp.path("alive.txt").display().to_string();

        let summary = run(options).await.unwrap();

        assert_eq!(summary.good, 2);
        assert_eq!(summary.avg_kbs, 150.0);
        assert_eq!(summary.median_kbs, 150.0);
        let good = std::fs::read_to_string(temp.path("good.txt")).unwrap();
        assert!(good.find("fast.example").unwrap() < good.find("slow.example").unwrap());
        let clash = std::fs::read_to_string(temp.path("clash.yaml")).unwrap();
        assert!(clash.contains("slow-name"));
    }

    #[test]
    fn source_report_writer_is_optional_and_writes_pretty_report_when_configured() {
        let dir = TestDir::new();
        let mut report = source_report::SourceQualityReport::new();
        report.add_source("https://example.test/sub");

        assert!(write_source_report(&cli(), &report).is_ok());

        let path = dir.path("report.json");
        let mut configured = cli();
        configured.source_report = Some(path.display().to_string());
        write_source_report(&configured, &report).unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&contents).unwrap()["sources"][0]["url"],
            "https://example.test/[redacted]"
        );
        assert!(contents.contains('\n'));
    }

    #[test]
    fn checkpoint_writer_is_optional_and_persists_configured_checkpoint() {
        let dir = TestDir::new();
        let mut checkpoint = checkpoint::Checkpoint::new();
        checkpoint.raw_links.push("local input".into());

        save_checkpoint(&cli(), &checkpoint).unwrap();

        let path = dir.path("state.json");
        let mut configured = cli();
        configured.checkpoint = Some(path.display().to_string());
        save_checkpoint(&configured, &checkpoint).unwrap();
        assert_eq!(
            checkpoint::Checkpoint::load(path).unwrap(),
            Some(checkpoint)
        );
    }

    #[test]
    fn source_report_writer_returns_filesystem_errors() {
        let dir = TestDir::new();
        let destination = dir.path("report-directory");
        std::fs::create_dir(&destination).unwrap();
        let report = source_report::SourceQualityReport::new();
        let mut options = cli();
        options.source_report = Some(destination.display().to_string());

        let error = write_source_report(&options, &report).unwrap_err();

        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(destination.is_dir());
    }

    #[test]
    fn checkpoint_writer_returns_filesystem_errors() {
        let dir = TestDir::new();
        let destination = dir.path("checkpoint-directory");
        std::fs::create_dir(&destination).unwrap();
        let checkpoint = checkpoint::Checkpoint::new();
        let mut options = cli();
        options.checkpoint = Some(destination.display().to_string());

        let error = save_checkpoint(&options, &checkpoint).unwrap_err();

        assert!(error.to_string().contains("atomically write checkpoint"));
        assert!(destination.is_dir());
    }

    #[test]
    fn protocol_and_country_filters_are_case_insensitive_and_composable() {
        let mut proxies = vec![
            proxy("01234567-89ab-cdef-0123-456789abcdef", "de.example", " de "),
            proxy("11234567-89ab-cdef-0123-456789abcdef", "us.example", "US"),
            proxy("21234567-89ab-cdef-0123-456789abcdef", "de2.example", "FR"),
        ];

        let removed =
            filter_proxy_protocol_country(&mut proxies, &["VLESS".into()], &[" de ".into()]);

        assert_eq!(removed, 2);
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].host, "de.example");
    }

    #[test]
    fn protocol_and_country_filters_allow_empty_lists_and_report_removals() {
        let mut proxies = vec![
            proxy("01234567-89ab-cdef-0123-456789abcdef", "one.example", "DE"),
            proxy("11234567-89ab-cdef-0123-456789abcdef", "two.example", "US"),
        ];
        assert_eq!(filter_proxy_protocol_country(&mut proxies, &[], &[]), 0);
        assert_eq!(
            filter_proxy_protocol_country(&mut proxies, &["trojan".into()], &[]),
            2
        );
        assert!(proxies.is_empty());
    }

    #[test]
    fn previously_seen_filter_ignores_invalid_lines_and_matches_proxy_identity() {
        let known = proxy(
            "01234567-89ab-cdef-0123-456789abcdef",
            "known.example",
            "DE",
        );
        let same_identity_different_name = "vless://01234567-89ab-cdef-0123-456789abcdef@known.example:443?type=tcp&security=none#renamed";
        let mut candidates = vec![
            known.clone(),
            proxy("11234567-89ab-cdef-0123-456789abcdef", "new.example", "DE"),
        ];

        let removed = filter_previously_seen(
            &mut candidates,
            &format!("not a proxy\n{same_identity_different_name}\n"),
        );

        assert_eq!(removed, 1);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].host, "new.example");
        assert_eq!(
            known.key(),
            parse::parse_link(same_identity_different_name)
                .unwrap()
                .key()
        );
    }

    #[test]
    fn max_ping_zero_disables_filter_and_positive_limit_keeps_boundary_only() {
        let mut unlimited = vec![
            proxy(
                "01234567-89ab-cdef-0123-456789abcdef",
                "unknown.example",
                "DE",
            ),
            proxy("11234567-89ab-cdef-0123-456789abcdef", "slow.example", "DE"),
        ];
        unlimited[0].ping = None;
        unlimited[1].ping = Some(101);
        assert!(retain_within_max_ping(&mut unlimited, 0).is_empty());
        assert_eq!(unlimited.len(), 2);

        let mut limited = vec![
            proxy("21234567-89ab-cdef-0123-456789abcdef", "fast.example", "DE"),
            proxy(
                "31234567-89ab-cdef-0123-456789abcdef",
                "boundary.example",
                "DE",
            ),
            proxy("41234567-89ab-cdef-0123-456789abcdef", "slow.example", "DE"),
            proxy(
                "51234567-89ab-cdef-0123-456789abcdef",
                "unknown.example",
                "DE",
            ),
        ];
        limited[0].ping = Some(20);
        limited[1].ping = Some(100);
        limited[2].ping = Some(101);
        limited[3].ping = None;

        let rejected = retain_within_max_ping(&mut limited, 100);

        assert_eq!(
            rejected,
            [
                "vless://41234567-89ab-cdef-0123-456789abcdef@slow.example:443?type=tcp&security=none",
                "vless://51234567-89ab-cdef-0123-456789abcdef@unknown.example:443?type=tcp&security=none"
            ]
        );
        assert_eq!(
            limited.iter().map(|proxy| proxy.ping).collect::<Vec<_>>(),
            [Some(20), Some(100)]
        );
    }

    #[test]
    fn max_ping_keeps_hysteria_without_tcp_rtt_and_rejects_unknown_tcp_rtt() {
        let mut hysteria1 = proxy("01234567-89ab-cdef-0123-456789abcdef", "hy1.example", "DE");
        hysteria1.proto = "hysteria";
        hysteria1.ping = None;
        let mut hysteria2 = proxy("11234567-89ab-cdef-0123-456789abcdef", "hy2.example", "US");
        hysteria2.proto = "hysteria2";
        hysteria2.ping = None;
        let mut unknown_tcp = proxy(
            "21234567-89ab-cdef-0123-456789abcdef",
            "unknown.example",
            "FR",
        );
        unknown_tcp.ping = None;
        let mut candidates = vec![hysteria1, hysteria2, unknown_tcp];

        let rejected = retain_within_max_ping(&mut candidates, 100);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].proto, "hysteria");
        assert_eq!(candidates[1].proto, "hysteria2");
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0].contains("unknown.example"));
    }
}
