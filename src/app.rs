use crate::{
    cli::Cli,
    database::{self, ArchiveStore},
    forward_runner::{self, CheckedForwardProxy},
    pipeline, settings, Summary,
};
use anyhow::Context;
use clap::Parser;
use directories::ProjectDirs;
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use std::io::Write;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;

slint::include_modules!();

static APP_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
const CHECK_OUTPUT_FILES: &[&str] = &[
    "raw.txt",
    "parsed.txt",
    "alive.txt",
    "good.txt",
    "dead.txt",
    "proxy-results.json",
];
const SUPPORTED_SOURCE_SETS: &[&str] = &["1", "2", "3"];
type SourceCatalogs = BTreeMap<String, Vec<String>>;

struct OutputSnapshot {
    backup_directory: PathBuf,
    existing_files: Vec<(String, bool)>,
}

impl OutputSnapshot {
    fn create(output_directory: &Path) -> anyhow::Result<Self> {
        let backup_directory = output_directory.join(format!(
            ".proxysift-rollback-{}-{}",
            std::process::id(),
            current_timestamp()
        ));
        fs::create_dir(&backup_directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                fs::set_permissions(&backup_directory, fs::Permissions::from_mode(0o700))
            {
                let _ = fs::remove_dir_all(&backup_directory);
                return Err(error.into());
            }
        }

        let snapshot_result = (|| -> anyhow::Result<Vec<(String, bool)>> {
            let mut existing_files = Vec::with_capacity(CHECK_OUTPUT_FILES.len());
            for name in CHECK_OUTPUT_FILES {
                let source = output_directory.join(name);
                match fs::read(&source) {
                    Ok(bytes) => {
                        let backup = backup_directory.join(name);
                        fs::write(&backup, bytes)?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            fs::set_permissions(&backup, fs::Permissions::from_mode(0o600))?;
                        }
                        existing_files.push(((*name).to_owned(), true));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        existing_files.push(((*name).to_owned(), false));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(existing_files)
        })();
        let existing_files = match snapshot_result {
            Ok(existing_files) => existing_files,
            Err(error) => {
                let _ = fs::remove_dir_all(&backup_directory);
                return Err(error);
            }
        };

        Ok(Self {
            backup_directory,
            existing_files,
        })
    }

    fn restore(self, output_directory: &Path) -> anyhow::Result<()> {
        let mut first_error = None;
        for (name, existed) in &self.existing_files {
            let path = output_directory.join(name);
            let result = if *existed {
                fs::read(self.backup_directory.join(name)).and_then(|bytes| {
                    crate::output::write_bytes_atomic(&path, &bytes, Some(0o600))
                        .map_err(|error| std::io::Error::other(error.to_string()))
                })
            } else {
                match fs::remove_file(&path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error),
                }
            };
            if let Err(error) = result {
                first_error.get_or_insert_with(|| anyhow::anyhow!("{name}: {error}"));
            }
        }
        if let Err(error) = fs::remove_dir_all(&self.backup_directory) {
            first_error
                .get_or_insert_with(|| anyhow::anyhow!("ошибка удаления резервной копии: {error}"));
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn discard(self) -> anyhow::Result<()> {
        fs::remove_dir_all(self.backup_directory)?;
        Ok(())
    }
}

fn restore_optional_file(path: &Path, previous: Option<&[u8]>) -> anyhow::Result<()> {
    if let Some(bytes) = previous {
        crate::output::write_bytes_atomic(path, bytes, Some(0o600))?;
    } else {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn open_path(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = Command::new("explorer");
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = Command::new("xdg-open");
    command.arg(path).spawn().map(|_| ())
}

fn copy_to_clipboard(value: &str) -> anyhow::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    fn copy_with_command(program: &str, arguments: &[&str], value: &str) -> std::io::Result<()> {
        let mut child = Command::new(program)
            .args(arguments)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("clipboard stdin is unavailable"))?
            .write_all(value.as_bytes())?;
        let status = child.wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "{program} exited with {status}"
            )))
        }
    }

    #[cfg(target_os = "macos")]
    {
        return copy_with_command("pbcopy", &[], value)
            .context("не удалось скопировать адрес в буфер обмена");
    }
    #[cfg(target_os = "windows")]
    {
        return copy_with_command("clip", &[], value)
            .context("не удалось скопировать адрес в буфер обмена");
    }
    #[cfg(target_os = "linux")]
    {
        let mut last_error = None;
        for (program, arguments) in [
            ("wl-copy", &[][..]),
            ("xclip", &["-selection", "clipboard"][..]),
            ("xsel", &["--clipboard", "--input"][..]),
        ] {
            match copy_with_command(program, arguments, value) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    last_error = Some(error);
                }
                Err(error) => {
                    return Err(error).context("не удалось скопировать адрес в буфер обмена");
                }
            }
        }
        return Err(
            last_error.unwrap_or_else(|| std::io::Error::other("clipboard utility not found"))
        )
        .context("установите wl-copy, xclip или xsel для копирования");
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = value;
        anyhow::bail!("копирование в буфер обмена не поддерживается на этой платформе");
    }
}

pub fn set_app_data_dir(path: PathBuf) -> anyhow::Result<()> {
    fs::create_dir_all(&path)?;
    APP_DATA_DIR
        .set(path)
        .map_err(|_| anyhow::anyhow!("папка данных приложения уже задана"))
}

fn app_data_dir() -> anyhow::Result<PathBuf> {
    if let Some(path) = APP_DATA_DIR.get() {
        return Ok(path.clone());
    }
    if let Some(path) = std::env::var_os("PROXYSIFT_DATA_DIR") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            anyhow::bail!("PROXYSIFT_DATA_DIR должен содержать абсолютный путь");
        }
        fs::create_dir_all(&path).context("не удалось создать папку данных ProxySift")?;
        return Ok(path);
    }
    let dirs = ProjectDirs::from("org", "ProxySift", "ProxySift")
        .ok_or_else(|| anyhow::anyhow!("не удалось определить папку данных приложения"))?;
    let path = dirs.data_local_dir().to_path_buf();
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn settings_from_window(window: &AppWindow) -> settings::AppSettings {
    let checker_mode = window.get_checker_mode().to_string();
    let active_subscriptions = window.get_subscriptions().to_string();
    let active_proxy_links = window.get_proxy_links().to_string();
    let (vpn_subscriptions, forward_subscriptions) = if checker_mode == "forward" {
        (
            window.get_vpn_subscriptions().to_string(),
            active_subscriptions,
        )
    } else {
        (
            active_subscriptions,
            window.get_forward_subscriptions().to_string(),
        )
    };
    let (vpn_proxy_links, forward_proxy_links) = if checker_mode == "forward" {
        (window.get_vpn_proxy_links().to_string(), active_proxy_links)
    } else {
        (
            active_proxy_links,
            window.get_forward_proxy_links().to_string(),
        )
    };
    settings::AppSettings {
        subscriptions: vpn_subscriptions,
        proxy_links: vpn_proxy_links,
        forward_subscriptions: Some(forward_subscriptions),
        forward_proxy_links: Some(forward_proxy_links),
        use_default_sources: window.get_use_default_sources(),
        source_set: window.get_source_set().to_string(),
        worker_count_value: window.get_worker_count_value().to_string(),
        timeout_value: window.get_timeout_value().to_string(),
        threshold_value: window.get_threshold_value().to_string(),
        threshold_unit: window.get_threshold_unit().to_string(),
        use_speed: window.get_use_speed(),
        use_geoip: window.get_use_geoip(),
        output_directory: window.get_output_directory().to_string(),
        checker_mode,
    }
}

fn save_window_settings(window: &AppWindow, data_dir: &Path) -> anyhow::Result<()> {
    settings::save(data_dir, &settings_from_window(window))
}

fn window_settings_are_valid(window: &AppWindow) -> bool {
    let workers = window.get_worker_count_value().parse::<usize>();
    let timeout = window.get_timeout_value().parse::<f64>();
    let threshold = window.get_threshold_value().parse::<f64>();
    workers.is_ok_and(|value| (1..=512).contains(&value))
        && timeout.is_ok_and(|value| value.is_finite() && (0.1..=3600.0).contains(&value))
        && threshold
            .is_ok_and(|value| value.is_finite() && (0.0..=1_000_000_000.0).contains(&value))
        && matches!(window.get_threshold_unit().as_str(), "КБ/с" | "МБ/с")
        && matches!(window.get_source_set().as_str(), "1" | "2" | "3")
        && matches!(window.get_checker_mode().as_str(), "vpn" | "forward")
}

fn persist_window_settings(window: &AppWindow, data_dir: &Path) {
    match save_window_settings(window, data_dir) {
        Ok(()) => {
            if window
                .get_last_error()
                .starts_with("Не удалось сохранить настройки:")
            {
                window.set_last_error(SharedString::default());
            }
        }
        Err(error) => {
            window.set_last_error(format!("Не удалось сохранить настройки: {error}").into())
        }
    }
}

fn output_location_label(output: &std::path::Path) -> String {
    let folder = output
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "results".into());
    let parent = output
        .parent()
        .and_then(std::path::Path::file_name)
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "ProxySift".into());
    let parent = if parent.to_ascii_lowercase().contains("proxysift") {
        "ProxySift".into()
    } else {
        parent
    };
    format!("…/{parent}/{folder}")
}

fn configure_cli(
    subscriptions: &str,
    pasted_links: &str,
    output: &std::path::Path,
    workers: usize,
    proxy_timeout: f64,
    threshold: f64,
    use_speed: bool,
    use_geoip: bool,
    use_default_sources: bool,
    source_set: &str,
    catalog_sets: &SourceCatalogs,
) -> anyhow::Result<Cli> {
    let data = app_data_dir()?;
    let sources = data.join("run-sources.json");
    let mut run_sources = catalog_sets.clone();
    if !use_default_sources {
        run_sources.insert(source_set.to_owned(), Vec::new());
    }
    crate::output::write_bytes_atomic(
        &sources,
        &serde_json::to_vec_pretty(&run_sources)?,
        Some(0o600),
    )?;
    let mut cli = Cli::try_parse_from(["proxy-sift"])?;
    cli.set = source_set.to_owned();
    cli.sources = sources.display().to_string();
    cli.url = subscriptions
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();

    let pasted_links = pasted_links.trim();
    if !pasted_links.is_empty() {
        let input = data.join("pasted-proxies.txt");
        crate::output::write_bytes_atomic(&input, pasted_links.as_bytes(), Some(0o600))?;
        cli.file = Some(input.display().to_string());
    }

    cli.limit = None;
    cli.workers = Some(workers);
    cli.proxy_timeout = Some(proxy_timeout);
    cli.shuffle = true;
    cli.min_kb = threshold;
    cli.no_speed = !use_speed;
    cli.no_geoip = !use_geoip;
    cli.fetch_cache_dir = data.join("subscription-cache").display().to_string();
    cli.core = data
        .join(crate::xray::core_bin_name())
        .display()
        .to_string();
    cli.geoip_db = Some(data.join("GeoLite2-Country.mmdb").display().to_string());
    cli.geoip_url =
        "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"
            .into();
    cli.workdir = data.join("runtime").display().to_string();
    cli.output = output.join("alive.txt").display().to_string();
    cli.raw_output = output.join("raw.txt").display().to_string();
    cli.parsed_output = output.join("parsed.txt").display().to_string();
    cli.good_output = output.join("good.txt").display().to_string();
    cli.dead = Some(output.join("dead.txt").display().to_string());
    cli.json_output = Some(output.join("proxy-results.json").display().to_string());
    cli.speed_report = use_speed.then(|| output.join("speed-report.json").display().to_string());
    cli.validate().map_err(anyhow::Error::msg)?;
    Ok(cli)
}

#[derive(serde::Deserialize)]
struct ProxyResult {
    protocol: String,
    server: String,
    port: u16,
    country: String,
    ping_ms: Option<u64>,
    speed_kbs: f64,
    #[serde(default)]
    source: String,
}

enum CompletedCheck {
    Vpn(Summary),
    Forward(Vec<CheckedForwardProxy>),
}

#[derive(Clone, Debug)]
struct DatabasePager {
    query: String,
    cursors: Vec<Option<(i64, i64)>>,
    next_cursor: Option<(i64, i64)>,
    page_index: usize,
    has_next: bool,
}

impl Default for DatabasePager {
    fn default() -> Self {
        Self {
            query: String::new(),
            cursors: vec![None],
            next_cursor: None,
            page_index: 0,
            has_next: false,
        }
    }
}

type DatabasePagers = Arc<Mutex<HashMap<bool, DatabasePager>>>;

fn load_database_view(
    window: &AppWindow,
    archive: &ArchiveStore,
    pagers: &DatabasePagers,
    vpn_only: bool,
) {
    let (query, cursor, page_index) = {
        let mut states = pagers.lock().unwrap_or_else(|poison| poison.into_inner());
        let state = states.entry(vpn_only).or_default();
        if state.cursors.is_empty() {
            state.cursors.push(None);
        }
        (
            state.query.clone(),
            state.cursors.last().copied().flatten(),
            state.page_index,
        )
    };

    let page = match archive.page(vpn_only, &query, cursor) {
        Ok(page) => page,
        Err(error) => {
            window.set_database_error(format!("Не удалось прочитать базу данных: {error}").into());
            window.set_database_rows(ModelRc::from([].as_slice()));
            window.set_database_total("0".into());
            window.set_database_has_previous(false);
            window.set_database_has_next(false);
            return;
        }
    };

    let rows = page
        .rows
        .iter()
        .map(|row| {
            let (country, flag) = country_display(&row.country);
            DatabaseRow {
                id: row.id.to_string().into(),
                protocol: row.protocol.to_uppercase().into(),
                address: format!("{}:{}", row.host, row.port).into(),
                name: row.name.clone().into(),
                country: if flag.is_empty() {
                    country.into()
                } else {
                    format!("{flag} {country}").into()
                },
                status: row.status.clone().into(),
                ping: row
                    .ping_ms
                    .map(|value| format!("{value} мс"))
                    .unwrap_or_else(|| "—".into())
                    .into(),
                speed: row
                    .speed_kbs
                    .filter(|value| *value > 0.0)
                    .map(format_speed)
                    .unwrap_or_else(|| "—".into())
                    .into(),
                first_seen: database::display_timestamp(row.first_seen_at).into(),
                last_seen: database::display_timestamp(row.last_seen_at).into(),
                checks: row.seen_count.to_string().into(),
            }
        })
        .collect::<Vec<_>>();
    let pages = page.total.div_ceil(database::PAGE_SIZE as u64).max(1);
    window.set_database_rows(ModelRc::from(rows.as_slice()));
    window.set_database_total(page.total.to_string().into());
    window.set_database_query(query.into());
    window.set_database_page_label(format!("Страница {} из {pages}", page_index + 1).into());
    window.set_database_has_previous(page_index > 0);
    window.set_database_has_next(page.has_next);
    window.set_database_error(SharedString::default());

    let mut states = pagers.lock().unwrap_or_else(|poison| poison.into_inner());
    let state = states.entry(vpn_only).or_default();
    state.next_cursor = page.next_cursor;
    state.has_next = page.has_next;
}

fn load_database_detail(window: &AppWindow, archive: &ArchiveStore, id: i64, vpn_only: bool) {
    let detail = match archive.detail(id, vpn_only) {
        Ok(Some(detail)) => detail,
        Ok(None) => {
            window.set_database_error("Эта запись больше не найдена в архиве.".into());
            window.set_database_detail_open(false);
            return;
        }
        Err(error) => {
            window.set_database_error(
                format!("Не удалось прочитать статистику узла: {error}").into(),
            );
            return;
        }
    };
    let row = &detail.row;
    let (country, flag) = country_display(&row.country);
    window.set_database_detail_id(row.id.to_string().into());
    window.set_database_detail_address(format!("{}:{}", row.host, row.port).into());
    window.set_database_detail_protocol(row.protocol.to_uppercase().into());
    window.set_database_detail_name(row.name.clone().into());
    window.set_database_detail_country(
        if flag.is_empty() {
            country
        } else {
            format!("{flag} {country}")
        }
        .into(),
    );
    window.set_database_detail_status(row.status.clone().into());
    window.set_database_detail_ping(
        row.ping_ms
            .map(|value| format!("{value} мс"))
            .unwrap_or_else(|| "—".into())
            .into(),
    );
    window.set_database_detail_speed(
        row.speed_kbs
            .filter(|value| *value > 0.0)
            .map(format_speed)
            .unwrap_or_else(|| "—".into())
            .into(),
    );
    window.set_database_detail_first_seen(database::display_timestamp(row.first_seen_at).into());
    window.set_database_detail_last_seen(database::display_timestamp(row.last_seen_at).into());
    window.set_database_detail_checks(row.seen_count.to_string().into());
    window.set_database_detail_available(detail.available_count.to_string().into());
    let success_rate = if row.seen_count == 0 {
        "—".to_owned()
    } else {
        format!(
            "{:.0}%",
            detail.available_count as f64 / row.seen_count as f64 * 100.0
        )
    };
    window.set_database_detail_success_rate(success_rate.into());
    window.set_database_detail_average_ping(
        detail
            .average_ping_ms
            .map(|value| format!("{value} мс"))
            .unwrap_or_else(|| "—".into())
            .into(),
    );
    window.set_database_detail_best_speed(
        detail
            .best_speed_kbs
            .map(format_speed)
            .unwrap_or_else(|| "—".into())
            .into(),
    );
    let observations = detail
        .observations
        .iter()
        .map(|observation| {
            let (country, flag) = country_display(&observation.country);
            ArchiveObservationRow {
                run: observation.run_id.to_string().into(),
                time: database::display_timestamp(observation.checked_at).into(),
                status: observation.status.clone().into(),
                country: if flag.is_empty() {
                    country.into()
                } else {
                    format!("{flag} {country}").into()
                },
                ping: observation
                    .ping_ms
                    .map(|value| format!("{value} мс"))
                    .unwrap_or_else(|| "—".into())
                    .into(),
                speed: observation
                    .speed_kbs
                    .filter(|value| *value > 0.0)
                    .map(format_speed)
                    .unwrap_or_else(|| "—".into())
                    .into(),
                failure_reason: observation
                    .failure_reason
                    .as_deref()
                    .filter(|reason| !reason.trim().is_empty())
                    .map(str::to_owned)
                    .or_else(|| {
                        (observation.status == "Не прошёл")
                            .then(|| "Причина не сохранялась для этой проверки.".to_owned())
                    })
                    .unwrap_or_default()
                    .into(),
                summary: format!(
                    "{} · {} · {} сек.",
                    if observation.checker_mode == "forward" {
                        "HTTP/SOCKS"
                    } else {
                        "VPN"
                    },
                    observation.run_summary,
                    observation.elapsed_seconds
                )
                .into(),
            }
        })
        .collect::<Vec<_>>();
    window.set_database_detail_observations(ModelRc::from(observations.as_slice()));
    window.set_database_error(SharedString::default());
    window.set_database_detail_open(true);
}

fn set_pipeline_progress(window: &AppWindow, progress: pipeline::PipelineProgress) {
    window.set_status(progress.phase.clone().into());
    window.set_status_detail(progress.detail.into());
    window.set_progress_stage(progress.phase.into());
    if progress.total == 0 {
        window.set_progress_completed("—".into());
        window.set_progress_total("—".into());
        window.set_progress_rate("—".into());
        window.set_progress_eta("—".into());
        window.set_progress_percent(0);
    } else {
        window.set_progress_completed(progress.completed.to_string().into());
        window.set_progress_total(progress.total.to_string().into());
        window.set_progress_rate(
            if progress.rate_per_sec.is_finite() && progress.rate_per_sec > 0.0 {
                format!("{:.1}", progress.rate_per_sec).into()
            } else {
                "—".into()
            },
        );
        window.set_progress_eta(
            progress
                .remaining_seconds
                .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
                .map(format_eta)
                .unwrap_or_else(|| "считаем…".into())
                .into(),
        );
        window.set_progress_percent(
            ((progress.completed.min(progress.total) as f64 / progress.total as f64) * 100.0)
                .round() as i32,
        );
    }
    window.set_progress_visible(true);
}

fn format_eta(seconds: f64) -> String {
    let seconds = seconds.ceil().min(u64::MAX as f64) as u64;
    if seconds >= 3600 {
        format!("{} ч {} мин", seconds / 3600, (seconds % 3600) / 60)
    } else if seconds >= 60 {
        format!("{} мин {} сек", seconds / 60, seconds % 60)
    } else {
        format!("{seconds} сек")
    }
}

fn reset_check_progress(window: &AppWindow) {
    window.set_progress_visible(false);
    window.set_progress_completed("0".into());
    window.set_progress_total("0".into());
    window.set_progress_rate("—".into());
    window.set_progress_eta("—".into());
    window.set_progress_percent(0);
    window.set_progress_stage("Готов к запуску".into());
}

fn start_archive_recheck(
    window: &AppWindow,
    target: database::RecheckTarget,
    archive: Arc<ArchiveStore>,
    pagers: DatabasePagers,
    history_path: PathBuf,
    cancellation: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    catalog_state: Arc<Mutex<SourceCatalogs>>,
) -> anyhow::Result<()> {
    if window.get_checking() {
        anyhow::bail!("Сначала дождитесь завершения текущей проверки.");
    }
    if target.original_link.trim().is_empty() {
        anyhow::bail!("Для этой записи нет ссылки, необходимой для повторной проверки.");
    }

    let data = app_data_dir()?;
    let run_key = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let output = data.join("single-checks").join(format!(
        "node-{}-{}-{run_key}",
        target.id,
        std::process::id()
    ));
    fs::create_dir_all(&output)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            output.parent().expect("single-checks parent"),
            fs::Permissions::from_mode(0o700),
        )?;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    }

    let source_set = normalized_source_set(window.get_source_set().as_str()).to_owned();
    let catalogs = catalog_state
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    let use_speed = target.is_vpn && window.get_use_speed();
    let use_geoip = window.get_use_geoip();
    let workers = window
        .get_worker_count_value()
        .parse::<usize>()
        .ok()
        .filter(|value| (1..=512).contains(value))
        .context("Укажите число потоков от 1 до 512.")?;
    let proxy_timeout = window
        .get_timeout_value()
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && (0.1..=3600.0).contains(value))
        .context("Укажите таймаут от 0,1 до 3600 секунд.")?;
    let threshold = if use_speed {
        let multiplier = if window.get_threshold_unit().to_string() == "МБ/с" {
            1024.0
        } else {
            1.0
        };
        window
            .get_threshold_value()
            .parse::<f64>()
            .context("Укажите корректный порог скорости в настройках.")?
            * multiplier
    } else {
        0.0
    };
    let pasted_path = data.join("pasted-proxies.txt");
    let previous_pasted = match fs::read(&pasted_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let cli_result = configure_cli(
        "",
        &target.original_link,
        &output,
        workers,
        proxy_timeout,
        threshold,
        use_speed,
        use_geoip,
        false,
        &source_set,
        &catalogs,
    );
    restore_optional_file(&pasted_path, previous_pasted.as_deref())?;
    let mut cli = cli_result?;
    let single_link_path = output.join("single-node.txt");
    crate::output::write_bytes_atomic(
        &single_link_path,
        target.original_link.trim().as_bytes(),
        Some(0o600),
    )?;
    cli.file = Some(single_link_path.display().to_string());
    let target_id = target.id;
    let vpn_only = target.is_vpn;
    let address = format!("{}:{}", target.host, target.port);
    let (cancel_sender, cancel_receiver) = oneshot::channel();
    *cancellation
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some(cancel_sender);
    window.set_checking(true);
    window.set_elapsed_seconds(0);
    window.set_progress_visible(true);
    window.set_progress_stage("Подготовка проверки".into());
    window.set_progress_completed("0".into());
    window.set_progress_total("1".into());
    window.set_progress_rate("—".into());
    window.set_progress_eta("считаем…".into());
    window.set_progress_percent(0);
    window.set_database_rechecking_id(target_id.to_string().into());
    window.set_database_error(SharedString::default());
    window.set_status("Повторно проверяем один узел".into());
    window.set_status_detail(format!("{address} · используется текущий профиль проверки").into());

    let ui = window.as_weak();
    let worker_archive = archive.clone();
    let worker_cancellation = cancellation.clone();
    std::thread::spawn(move || {
        let started = Instant::now();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build();
        let result = match runtime {
            Ok(runtime) => {
                let progress_window = ui.clone();
                let progress: pipeline::ProgressCallback = Arc::new(move |progress| {
                    let progress_window = progress_window.clone();
                    let _ = progress_window.upgrade_in_event_loop(move |window| {
                        set_pipeline_progress(&window, progress);
                    });
                });
                runtime.block_on(async move {
                    if vpn_only {
                        tokio::select! {
                            result = pipeline::run_with_progress(cli, progress) => {
                                result.map(|summary| Some(CompletedCheck::Vpn(summary)))
                            },
                            _ = cancel_receiver => Ok(None),
                        }
                    } else {
                        let link = target.original_link;
                        tokio::select! {
                            result = forward_runner::run(&cli, &link, 1, use_geoip, progress) => {
                                result.map(|results| Some(CompletedCheck::Forward(results)))
                            },
                            _ = cancel_receiver => Ok(None),
                        }
                    }
                })
            }
            Err(error) => Err(anyhow::anyhow!(
                "Не удалось запустить сетевой runtime: {error}"
            )),
        };
        let elapsed = started.elapsed().as_secs();

        let (outcome, summary, database_error) = match result {
            Ok(Some(CompletedCheck::Vpn(summary))) => {
                let persist_error = worker_archive
                    .record_completed_run(&output, &summary, elapsed)
                    .err()
                    .map(|error| error.to_string());
                let detail = worker_archive
                    .detail(target_id, true)
                    .ok()
                    .flatten()
                    .map(|detail| detail.row.status)
                    .unwrap_or_else(|| format!("Проверка завершена · найдено {}", summary.unique));
                ("Успешно".to_owned(), detail, persist_error)
            }
            Ok(Some(CompletedCheck::Forward(results))) => {
                let records = results
                    .iter()
                    .map(|result| {
                        let probe = &result.probe;
                        database::ArchiveRecord {
                            fingerprint: probe.proxy.fingerprint.clone(),
                            protocol: probe.proxy.protocol.as_str().to_owned(),
                            host: probe.proxy.host.clone(),
                            port: probe.proxy.port,
                            name: probe.proxy.name.clone(),
                            original_link: probe.proxy.original_uri.clone(),
                            country: result.country.clone(),
                            is_vpn: false,
                            status: forward_status_label(&probe.status, probe.alive).to_owned(),
                            failure_reason: forward_failure_reason(&probe.status, probe.alive),
                            ping_ms: probe.ping_ms,
                            speed_kbs: None,
                        }
                    })
                    .collect::<Vec<_>>();
                let status = results
                    .first()
                    .map(|result| forward_status_label(&result.probe.status, result.probe.alive))
                    .unwrap_or("Проверка завершена без результата")
                    .to_owned();
                let persist_error = worker_archive
                    .record_observations(
                        &records,
                        if status == "Доступен" { 1 } else { 0 },
                        elapsed,
                    )
                    .err()
                    .map(|error| error.to_string());
                ("Успешно".to_owned(), status, persist_error)
            }
            Ok(None) => {
                let message = "Повторная проверка отменена".to_owned();
                let persist_error = persist_non_success_run(
                    Some(&worker_archive),
                    if vpn_only { "vpn" } else { "forward" },
                    "Отменён",
                    &message,
                    elapsed,
                );
                ("Отменён".to_owned(), message, persist_error)
            }
            Err(error) => {
                let message = format!("Ошибка проверки: {error:#}");
                let persist_error = persist_non_success_run(
                    Some(&worker_archive),
                    if vpn_only { "vpn" } else { "forward" },
                    "Ошибка",
                    &message,
                    elapsed,
                );
                ("Ошибка".to_owned(), message, persist_error)
            }
        };

        let _ = fs::remove_dir_all(&output);
        if let Some(parent) = output.parent() {
            if fs::read_dir(parent).is_ok_and(|mut entries| entries.next().is_none()) {
                let _ = fs::remove_dir(parent);
            }
        }
        let history_archive = worker_archive.clone();
        let _ = ui.upgrade_in_event_loop(move |window| {
            worker_cancellation
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take();
            window.set_checking(false);
            reset_check_progress(&window);
            window.set_elapsed_seconds(elapsed.min(i32::MAX as u64) as i32);
            window.set_database_rechecking_id(SharedString::default());
            window.set_status(
                if outcome == "Успешно" {
                    "Повторная проверка завершена"
                } else if outcome == "Отменён" {
                    "Повторная проверка отменена"
                } else {
                    "Повторная проверка завершилась с ошибкой"
                }
                .into(),
            );
            window.set_status_detail(format!("{address} · {summary}").into());
            if let Some(error) = &database_error {
                window.set_database_error(format!("Не удалось обновить архив: {error}").into());
            } else {
                window.set_database_error(SharedString::default());
            }
            append_run_history(
                &window,
                &history_path,
                if vpn_only { "vpn" } else { "forward" },
                &outcome,
                &summary,
                elapsed,
                Some(&history_archive),
            );
            let active_page = window.get_active_page().to_string();
            if active_page == "db-proxy" || active_page == "db-vpn" {
                load_database_view(&window, &history_archive, &pagers, active_page == "db-vpn");
            }
            if window.get_database_detail_open()
                && window.get_database_detail_id().to_string() == target_id.to_string()
            {
                load_database_detail(&window, &history_archive, target_id, vpn_only);
            }
        });
    });
    Ok(())
}

fn reset_database_search(
    window: &AppWindow,
    archive: &ArchiveStore,
    pagers: &DatabasePagers,
    vpn_only: bool,
    query: &str,
) {
    {
        let mut states = pagers.lock().unwrap_or_else(|poison| poison.into_inner());
        let state = states.entry(vpn_only).or_default();
        state.query = query.to_string();
        state.cursors = vec![None];
        state.next_cursor = None;
        state.page_index = 0;
        state.has_next = false;
    }
    load_database_view(window, archive, pagers, vpn_only);
}

fn move_database_page(
    window: &AppWindow,
    archive: &ArchiveStore,
    pagers: &DatabasePagers,
    vpn_only: bool,
    direction: i32,
) {
    {
        let mut states = pagers.lock().unwrap_or_else(|poison| poison.into_inner());
        let state = states.entry(vpn_only).or_default();
        if direction > 0 && state.has_next {
            if let Some(cursor) = state.next_cursor {
                state.cursors.push(Some(cursor));
                state.page_index = state.page_index.saturating_add(1);
            }
        } else if direction < 0 && state.page_index > 0 {
            state.cursors.pop();
            state.page_index -= 1;
        }
    }
    load_database_view(window, archive, pagers, vpn_only);
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct StoredRun {
    number: u64,
    finished_at: u64,
    outcome: String,
    summary: String,
    elapsed_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checker_mode: Option<String>,
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn relative_timestamp(timestamp: u64, now: u64) -> String {
    let age = now.saturating_sub(timestamp);
    match age {
        0..=59 => "только что".into(),
        60..=3599 => format!("{} мин. назад", age / 60),
        3600..=86399 => format!("{} ч. назад", age / 3600),
        86400..=2_592_000 => format!("{} дн. назад", age / 86400),
        _ => "более месяца назад".into(),
    }
}

fn elapsed_label(seconds: u64) -> String {
    if seconds >= 3600 {
        format!("{} ч {} мин", seconds / 3600, (seconds % 3600) / 60)
    } else if seconds >= 60 {
        format!("{} мин {} с", seconds / 60, seconds % 60)
    } else {
        format!("{seconds} с")
    }
}

fn read_run_history(path: &std::path::Path) -> Vec<StoredRun> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<StoredRun>>(&text).ok())
        .unwrap_or_default()
}

fn history_rows(entries: &[StoredRun]) -> Vec<RunHistoryRow> {
    let now = current_timestamp();
    entries
        .iter()
        .map(|entry| RunHistoryRow {
            title: format!("Запуск #{}", entry.number).into(),
            time: relative_timestamp(entry.finished_at, now).into(),
            outcome: entry.outcome.clone().into(),
            summary: entry.summary.clone().into(),
            elapsed: elapsed_label(entry.elapsed_seconds).into(),
        })
        .collect()
}

fn stored_runs_from_archive(entries: &[database::RunHistoryEntry]) -> Vec<StoredRun> {
    entries
        .iter()
        .map(|entry| StoredRun {
            number: u64::try_from(entry.id).unwrap_or_default(),
            finished_at: u64::try_from(entry.checked_at.max(0) / 1000).unwrap_or_default(),
            outcome: entry.outcome.clone(),
            summary: entry.summary.clone(),
            elapsed_seconds: entry.elapsed_seconds,
            checker_mode: None,
        })
        .collect()
}

fn legacy_runs_for_import(entries: &[StoredRun]) -> Vec<database::LegacyRunImport> {
    entries
        .iter()
        .map(|entry| database::LegacyRunImport {
            number: entry.number,
            record: database::RunHistoryRecord {
                checked_at: i64::try_from(entry.finished_at.saturating_mul(1000))
                    .unwrap_or(i64::MAX),
                checker_mode: entry
                    .checker_mode
                    .as_deref()
                    .filter(|mode| matches!(*mode, "vpn" | "forward"))
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        if entry.summary.starts_with("Работают ") {
                            "forward".into()
                        } else {
                            "vpn".into()
                        }
                    }),
                outcome: entry.outcome.clone(),
                summary: entry.summary.clone(),
                candidate_count: 0,
                alive_count: 0,
                elapsed_seconds: entry.elapsed_seconds,
            },
        })
        .collect()
}

fn new_run_history_record(
    checker_mode: &str,
    outcome: &str,
    summary: &str,
    elapsed_seconds: u64,
) -> database::RunHistoryRecord {
    database::RunHistoryRecord {
        checked_at: i64::try_from(current_timestamp().saturating_mul(1000)).unwrap_or(i64::MAX),
        checker_mode: checker_mode.into(),
        outcome: outcome.into(),
        summary: summary.into(),
        candidate_count: 0,
        alive_count: 0,
        elapsed_seconds,
    }
}

fn persist_non_success_run(
    archive: Option<&ArchiveStore>,
    checker_mode: &str,
    outcome: &str,
    summary: &str,
    elapsed_seconds: u64,
) -> Option<String> {
    archive
        .and_then(|archive| {
            archive
                .record_run_state(&new_run_history_record(
                    checker_mode,
                    outcome,
                    summary,
                    elapsed_seconds,
                ))
                .err()
        })
        .map(|error| error.to_string())
}

fn append_run_history(
    window: &AppWindow,
    path: &std::path::Path,
    checker_mode: &str,
    outcome: &str,
    summary: &str,
    elapsed_seconds: u64,
    archive: Option<&ArchiveStore>,
) {
    let mut entries = read_run_history(path);
    let number = entries
        .first()
        .map_or(1, |entry| entry.number.saturating_add(1));
    entries.insert(
        0,
        StoredRun {
            number,
            finished_at: current_timestamp(),
            outcome: outcome.into(),
            summary: summary.into(),
            elapsed_seconds,
            checker_mode: Some(checker_mode.into()),
        },
    );
    entries.truncate(50);
    if let Ok(json) = serde_json::to_vec_pretty(&entries) {
        let _ = crate::output::write_bytes_atomic(path, &json, Some(0o600));
    }
    let displayed_entries =
        match archive.and_then(|archive| archive.recent_runs(database::RUN_HISTORY_LIMIT).ok()) {
            Some(recent) => {
                let mut recent = stored_runs_from_archive(&recent);
                let current_timestamp = current_timestamp();
                let current_was_persisted = recent.first().is_some_and(|entry| {
                    entry.outcome == outcome
                        && entry.summary == summary
                        && entry.finished_at.abs_diff(current_timestamp) <= 2
                });
                if !current_was_persisted {
                    recent.insert(0, entries[0].clone());
                    recent.truncate(database::RUN_HISTORY_LIMIT);
                }
                recent
            }
            None => entries,
        };
    let rows = history_rows(&displayed_entries);
    window.set_run_history(ModelRc::from(rows.as_slice()));
}

fn set_runtime_status(window: &AppWindow, data: &std::path::Path) {
    let core = data.join(crate::xray::core_bin_name());
    window.set_core_path(core.display().to_string().into());
    let installed_core = crate::xray::installed_core_version(&core);
    let core_ready = installed_core.is_some();
    window.set_core_status(
        if core_ready {
            "Готово"
        } else {
            "Не найдено"
        }
        .into(),
    );
    window.set_core_detail(
        installed_core
            .map(|version| format!("Установлена версия {version}"))
            .unwrap_or_else(|| "Последняя версия загружается при нажатии кнопки".into())
            .into(),
    );
    window.set_core_action_label(
        if core_ready {
            "Проверить обновления"
        } else {
            "Установить Xray"
        }
        .into(),
    );

    let geoip = data.join("GeoLite2-Country.mmdb");
    window.set_geoip_path(geoip.display().to_string().into());
    let geoip_ready = crate::geoip::GeoDb::open(&geoip).is_ok();
    let geoip_version = crate::geoip::GeoDb::installed_geolite_version(&geoip);
    let geoip_revision = crate::geoip::GeoDb::installed_geolite_revision(&geoip);
    window.set_geoip_status(
        if geoip_ready {
            "Найдено"
        } else {
            "Не найдено"
        }
        .into(),
    );
    window.set_geoip_detail(
        match (geoip_version, geoip_revision.as_deref()) {
            (Some(version), Some(revision)) => format!(
                "Версия базы: {version} · ревизия {}",
                short_revision(revision)
            ),
            (Some(version), None) => format!("Версия базы: {version} · ревизия не сохранена"),
            (None, _) => "Версия появится после установки базы".into(),
        }
        .into(),
    );
    window.set_geoip_action_label(
        if geoip_ready {
            "Проверить обновления"
        } else {
            "Установить базу"
        }
        .into(),
    );
}

fn short_revision(revision: &str) -> &str {
    revision.get(..12).unwrap_or(revision)
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct NotificationReadState {
    active_fingerprint: String,
    read_fingerprint: String,
}

fn load_notification_state(data: &Path) -> NotificationReadState {
    fs::read_to_string(data.join("notifications.json"))
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

fn save_notification_state(data: &Path, state: &NotificationReadState) {
    if fs::create_dir_all(data).is_err() {
        return;
    }
    let Ok(contents) = serde_json::to_vec(state) else {
        return;
    };
    let path = data.join("notifications.json");
    let temp = data.join(format!(".notifications.{}.tmp", std::process::id()));
    if fs::write(&temp, contents).is_err() {
        return;
    }
    #[cfg(windows)]
    if path.exists() && fs::remove_file(&path).is_err() {
        let _ = fs::remove_file(&temp);
        return;
    }
    if fs::rename(&temp, &path).is_err() {
        let _ = fs::remove_file(&temp);
    }
}

fn acknowledge_notifications(data: &Path) {
    let mut state = load_notification_state(data);
    state.read_fingerprint = state.active_fingerprint.clone();
    save_notification_state(data, &state);
}

fn publish_notifications(
    window: &AppWindow,
    data: &Path,
    messages: Vec<String>,
    sound_on_new: bool,
) {
    let message = messages.join("\n");
    let fingerprint = message.clone();
    let mut state = load_notification_state(data);
    let is_new = !fingerprint.is_empty() && state.active_fingerprint != fingerprint;
    let is_unread = !fingerprint.is_empty() && state.read_fingerprint != fingerprint;
    state.active_fingerprint = fingerprint.clone();
    save_notification_state(data, &state);

    window.set_notification_count(messages.len().min(i32::MAX as usize) as i32);
    window.set_notification_message(message.into());
    window.set_notification_unread(is_unread);
    if is_new && sound_on_new {
        play_notification_sound();
    }
}

fn play_notification_sound() {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("afplay")
            .arg("/System/Library/Sounds/Glass.aiff")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                "[System.Media.SystemSounds]::Asterisk.Play()",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let played = Command::new("canberra-gtk-play")
            .args(["-i", "message-new-instant"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok();
        if !played {
            let _ = Command::new("paplay")
                .arg("/usr/share/sounds/freedesktop/stereo/message-new-instant.oga")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
    }
}

struct RuntimeCheck {
    installed_core: Option<String>,
    latest_core: String,
    installed_geoip: Option<String>,
    installed_geoip_revision: Option<String>,
    latest_geoip: crate::geoip::GeoLiteRelease,
}

fn geoip_release_is_outdated(
    installed_revision: Option<&str>,
    latest: &crate::geoip::GeoLiteRelease,
) -> bool {
    match installed_revision.filter(|revision| !revision.is_empty()) {
        Some(revision) => revision != latest.revision,
        // The display date can stay unchanged while the upstream file revision
        // changes. Without a recorded revision, freshness cannot be confirmed.
        None => true,
    }
}

#[derive(Clone, Copy)]
enum RuntimeJob {
    Check,
    Core { update: bool },
    GeoIp,
}

enum RuntimeJobResult {
    Checked(RuntimeCheck),
    CoreInstalled(Option<String>),
    GeoIpInstalled(crate::geoip::GeoLiteRelease),
    Cancelled,
}

fn run_runtime_job(
    data: &std::path::Path,
    job: RuntimeJob,
    mut cancel: oneshot::Receiver<()>,
) -> anyhow::Result<RuntimeJobResult> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("не удалось запустить сетевой runtime")?;
    let core_path = data.join(crate::xray::core_bin_name());
    let geoip_path = data.join("GeoLite2-Country.mmdb");
    let operation = async {
        match job {
            RuntimeJob::Check => {
                let (latest_geoip, latest_core) = tokio::try_join!(
                    crate::geoip::latest_geolite_release(),
                    crate::xray::latest_core_version()
                )?;
                Ok(RuntimeJobResult::Checked(RuntimeCheck {
                    installed_core: crate::xray::installed_core_version(&core_path),
                    latest_core,
                    installed_geoip: crate::geoip::GeoDb::installed_geolite_version(&geoip_path),
                    installed_geoip_revision: crate::geoip::GeoDb::installed_geolite_revision(
                        &geoip_path,
                    ),
                    latest_geoip,
                }))
            }
            RuntimeJob::Core { update } => {
                if update {
                    crate::xray::update_core(&core_path).await?;
                } else {
                    crate::xray::ensure_core(&core_path, None, false).await?;
                }
                Ok(RuntimeJobResult::CoreInstalled(
                    crate::xray::installed_core_version(&core_path),
                ))
            }
            RuntimeJob::GeoIp => {
                let release = crate::geoip::latest_geolite_release().await?;
                crate::geoip::install_geolite_release(&geoip_path, &release).await?;
                Ok(RuntimeJobResult::GeoIpInstalled(release))
            }
        }
    };
    runtime.block_on(async {
        tokio::select! {
            _ = &mut cancel => Ok(RuntimeJobResult::Cancelled),
            result = operation => result,
        }
    })
}

fn start_runtime_job(
    window: &AppWindow,
    weak_window: slint::Weak<AppWindow>,
    data: PathBuf,
    busy: Arc<AtomicBool>,
    cancel_slot: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    job: RuntimeJob,
) {
    if busy.swap(true, Ordering::AcqRel) {
        return;
    }
    window.set_runtime_busy(true);
    window.set_runtime_message(
        match job {
            RuntimeJob::Check => "Проверяю версии Xray и базы GeoIP…",
            RuntimeJob::Core { update: true } => "Загружаю и проверяю обновление Xray…",
            RuntimeJob::Core { update: false } => "Устанавливаю Xray…",
            RuntimeJob::GeoIp => "Загружаю и проверяю базу GeoIP…",
        }
        .into(),
    );
    let (cancel_sender, cancel_receiver) = oneshot::channel();
    *cancel_slot
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some(cancel_sender);
    let finish_cancel_slot = cancel_slot.clone();

    std::thread::spawn(move || {
        let result = run_runtime_job(&data, job, cancel_receiver);
        let _ = weak_window.upgrade_in_event_loop(move |window| {
            finish_cancel_slot
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take();
            busy.store(false, Ordering::Release);
            window.set_runtime_busy(false);
            match result {
                Ok(RuntimeJobResult::Checked(check)) => {
                    set_runtime_status(&window, &data);
                    let core_is_outdated =
                        check.installed_core.as_deref() != Some(check.latest_core.as_str());
                    let core_detail = match &check.installed_core {
                        Some(installed) if !core_is_outdated => {
                            format!("Версия {installed} · обновлений нет")
                        }
                        Some(installed) => {
                            format!("Установлена {installed} · доступна {}", check.latest_core)
                        }
                        None => format!("Доступна версия {}", check.latest_core),
                    };
                    window.set_core_status(
                        if check.installed_core.is_none() {
                            "Не найдено"
                        } else if core_is_outdated {
                            "Обновление"
                        } else {
                            "Актуально"
                        }
                        .into(),
                    );
                    window.set_core_detail(core_detail.into());
                    window.set_core_action_label(
                        if check.installed_core.is_none() {
                            "Установить Xray"
                        } else if core_is_outdated {
                            "Обновить Xray"
                        } else {
                            "Проверить обновления"
                        }
                        .into(),
                    );

                    let geoip_is_outdated = geoip_release_is_outdated(
                        check.installed_geoip_revision.as_deref(),
                        &check.latest_geoip,
                    );
                    let latest_geoip_revision = short_revision(&check.latest_geoip.revision);
                    let latest_geoip_date = check
                        .latest_geoip
                        .published_at
                        .get(..10)
                        .unwrap_or("дата неизвестна");
                    let geoip_detail = match &check.installed_geoip {
                        Some(installed) if !geoip_is_outdated => {
                            if let Some(revision) = check.installed_geoip_revision.as_deref() {
                                format!(
                                    "Версия {} · ревизия {} · актуальна",
                                    installed,
                                    short_revision(revision)
                                )
                            } else {
                                format!("Версия {} · ревизия не сохранена", installed)
                            }
                        }
                        Some(installed) => format!(
                            "Установлена {} · доступна {} от {} · ревизия {}",
                            installed,
                            check.latest_geoip.version,
                            latest_geoip_date,
                            latest_geoip_revision
                        ),
                        None => format!(
                            "Доступна версия {} от {} · ревизия {}",
                            check.latest_geoip.version, latest_geoip_date, latest_geoip_revision
                        ),
                    };
                    window.set_geoip_status(
                        if check.installed_geoip.is_none() {
                            "Не найдено"
                        } else if geoip_is_outdated {
                            "Обновление"
                        } else {
                            "Актуально"
                        }
                        .into(),
                    );
                    window.set_geoip_detail(geoip_detail.into());
                    window.set_geoip_action_label(
                        if check.installed_geoip.is_none() {
                            "Установить базу"
                        } else if geoip_is_outdated {
                            "Обновить базу"
                        } else {
                            "Проверить обновления"
                        }
                        .into(),
                    );
                    window.set_runtime_message(
                        format!(
                            "GeoLite: релиз {} от {} · ревизия {} · Xray: {}.",
                            check.latest_geoip.version,
                            latest_geoip_date,
                            latest_geoip_revision,
                            check.latest_core
                        )
                        .into(),
                    );

                    let mut notifications = Vec::new();
                    if core_is_outdated {
                        if let Some(installed) = check.installed_core.as_deref() {
                            notifications.push(format!(
                                "Обновление Xray: {installed} → {}",
                                check.latest_core
                            ));
                        } else {
                            notifications.push(format!(
                                "Доступна установка Xray {}",
                                check.latest_core
                            ));
                        }
                    }
                    if geoip_is_outdated {
                        if check.installed_geoip.is_some() {
                            notifications.push(format!(
                                "Обновление GeoIP: релиз от {latest_geoip_date} · ревизия {latest_geoip_revision}"
                            ));
                        } else {
                            notifications.push(format!(
                                "Доступна база GeoIP от {latest_geoip_date} · ревизия {latest_geoip_revision}"
                            ));
                        }
                    }
                    let sound_on_new = !notifications.is_empty();
                    publish_notifications(&window, &data, notifications, sound_on_new);
                }
                Ok(RuntimeJobResult::CoreInstalled(version)) => {
                    set_runtime_status(&window, &data);
                    if let Some(version) = version {
                        window.set_core_detail(format!("Установлена версия {version}").into());
                        window.set_core_action_label("Проверить обновления".into());
                        window.set_runtime_message(
                            format!("Xray {version} готов к проверкам.").into(),
                        );
                        publish_notifications(
                            &window,
                            &data,
                            vec![format!("Xray {version} установлен и готов к проверкам.")],
                            true,
                        );
                    } else {
                        window.set_runtime_message(
                            "Xray установился, но проверка версии не прошла.".into(),
                        );
                        publish_notifications(
                            &window,
                            &data,
                            vec!["Xray установился, но проверка версии не прошла.".into()],
                            true,
                        );
                    }
                }
                Ok(RuntimeJobResult::GeoIpInstalled(release)) => {
                    set_runtime_status(&window, &data);
                    window.set_geoip_detail(
                        format!(
                            "Версия {} · обновлена {} · ревизия {}",
                            release.version,
                            release.published_at.get(..10).unwrap_or("дата неизвестна"),
                            short_revision(&release.revision)
                        )
                        .into(),
                    );
                    window.set_geoip_action_label("Проверить обновления".into());
                    window.set_runtime_message(
                        format!(
                            "GeoLite {} установлена и проверена · ревизия {}.",
                            release.version,
                            short_revision(&release.revision)
                        )
                        .into(),
                    );
                    publish_notifications(
                        &window,
                        &data,
                        vec![format!(
                            "База GeoIP {} обновлена и проверена.",
                            release.version
                        )],
                        true,
                    );
                }
                Ok(RuntimeJobResult::Cancelled) => {
                    set_runtime_status(&window, &data);
                    window.set_runtime_message(
                        "Операция отменена. Предыдущий компонент сохранён.".into(),
                    );
                }
                Err(error) => {
                    let message = format!("Не удалось выполнить действие: {error}");
                    window.set_runtime_message(message.clone().into());
                    publish_notifications(&window, &data, vec![message], true);
                }
            }
        });
    });
}

/// Локализованное название и флаг для ISO-кода страны из GeoIP.
fn country_display(iso: &str) -> (String, String) {
    let iso = iso.trim();
    if iso.is_empty() || iso == "—" || iso == "UNKNOWN" {
        return ("—".into(), String::new());
    }
    let code = iso.to_ascii_uppercase();
    let name = match code.as_str() {
        "RU" => "Россия",
        "US" => "США",
        "GB" => "Великобритания",
        "DE" => "Германия",
        "NL" => "Нидерланды",
        "FR" => "Франция",
        "IT" => "Италия",
        "ES" => "Испания",
        "PT" => "Португалия",
        "PL" => "Польша",
        "UA" => "Украина",
        "BY" => "Беларусь",
        "KZ" => "Казахстан",
        "TR" => "Турция",
        "SE" => "Швеция",
        "NO" => "Норвегия",
        "FI" => "Финляндия",
        "DK" => "Дания",
        "CH" => "Швейцария",
        "AT" => "Австрия",
        "BE" => "Бельгия",
        "CZ" => "Чехия",
        "SK" => "Словакия",
        "HU" => "Венгрия",
        "RO" => "Румыния",
        "BG" => "Болгария",
        "GR" => "Греция",
        "RS" => "Сербия",
        "HR" => "Хорватия",
        "SI" => "Словения",
        "EE" => "Эстония",
        "LV" => "Латвия",
        "LT" => "Литва",
        "MD" => "Молдова",
        "GE" => "Грузия",
        "AM" => "Армения",
        "AZ" => "Азербайджан",
        "IL" => "Израиль",
        "AE" => "ОАЭ",
        "SA" => "Саудовская Аравия",
        "QA" => "Катар",
        "KW" => "Кувейт",
        "EG" => "Египет",
        "ZA" => "ЮАР",
        "NG" => "Нигерия",
        "KE" => "Кения",
        "MA" => "Марокко",
        "IN" => "Индия",
        "PK" => "Пакистан",
        "BD" => "Бангладеш",
        "LK" => "Шри-Ланка",
        "NP" => "Непал",
        "CN" => "Китай",
        "HK" => "Гонконг",
        "TW" => "Тайвань",
        "JP" => "Япония",
        "KR" => "Южная Корея",
        "SG" => "Сингапур",
        "MY" => "Малайзия",
        "TH" => "Таиланд",
        "VN" => "Вьетнам",
        "ID" => "Индонезия",
        "PH" => "Филиппины",
        "AU" => "Австралия",
        "NZ" => "Новая Зеландия",
        "CA" => "Канада",
        "MX" => "Мексика",
        "BR" => "Бразилия",
        "AR" => "Аргентина",
        "CL" => "Чили",
        "CO" => "Колумбия",
        "PE" => "Перу",
        "VE" => "Венесуэла",
        "EC" => "Эквадор",
        "UY" => "Уругвай",
        "PY" => "Парагвай",
        "BO" => "Боливия",
        "CR" => "Коста-Рика",
        "PA" => "Панама",
        "CU" => "Куба",
        "DO" => "Доминикана",
        "PR" => "Пуэрто-Рико",
        "JM" => "Ямайка",
        "IS" => "Исландия",
        "IE" => "Ирландия",
        "LU" => "Люксембург",
        "MT" => "Мальта",
        "CY" => "Кипр",
        "AL" => "Албания",
        "MK" => "Македония",
        "BA" => "Босния и Герцеговина",
        "ME" => "Черногория",
        "MN" => "Монголия",
        "KH" => "Камбоджа",
        "LA" => "Лаос",
        "MM" => "Мьянма",
        "BN" => "Бруней",
        "MV" => "Мальдивы",
        "AF" => "Афганистан",
        "IQ" => "Ирак",
        "IR" => "Иран",
        "SY" => "Сирия",
        "JO" => "Иордания",
        "LB" => "Ливан",
        "OM" => "Оман",
        "BH" => "Бахрейн",
        "YE" => "Йемен",
        "LY" => "Ливия",
        "TN" => "Тунис",
        "DZ" => "Алжир",
        "SD" => "Судан",
        "ET" => "Эфиопия",
        "GH" => "Гана",
        "TZ" => "Танзания",
        "UG" => "Уганда",
        "ZM" => "Замбия",
        "ZW" => "Зимбабве",
        "MZ" => "Мозамбик",
        "AO" => "Ангола",
        "CM" => "Камерун",
        "CI" => "Кот-д’Ивуар",
        "SN" => "Сенегал",
        "ML" => "Мали",
        "RW" => "Руанда",
        "BW" => "Ботсвана",
        "NA" => "Намибия",
        "MU" => "Маврикий",
        "FJ" => "Фиджи",
        "PG" => "Папуа — Новая Гвинея",
        "NC" => "Новая Каледония",
        "PF" => "Французская Полинезия",
        _ => return (iso.into(), String::new()),
    };
    let flag = if code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()) {
        code.bytes()
            .filter_map(|b| char::from_u32(0x1F1E6 + u32::from(b - b'A')))
            .collect::<String>()
    } else {
        String::new()
    };
    (name.into(), flag)
}

fn format_speed(speed_kbs: f64) -> String {
    let rounded = speed_kbs.round().max(0.0) as u64;
    let digits = rounded.to_string();
    let mut out = String::with_capacity(digits.len() + 4);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out.push_str(" КБ/с");
    out
}

fn proxy_row(
    status: &str,
    host: &str,
    port: u16,
    protocol: &str,
    country: &str,
    ping: String,
    speed: String,
    source: &str,
) -> ProxyRow {
    let (country, flag) = country_display(country);
    ProxyRow {
        status: status.into(),
        node: format!("{host}:{port}").into(),
        protocol: protocol.to_uppercase().into(),
        country: country.into(),
        flag: flag.into(),
        ping: ping.into(),
        speed: speed.into(),
        source: source.into(),
    }
}

fn numeric_cell(value: &str, suffix: &str) -> Option<f64> {
    value
        .trim()
        .strip_suffix(suffix)
        .map(str::trim)
        .map(|number| number.replace(' ', ""))
        .and_then(|number| number.parse::<f64>().ok())
        .filter(|number| number.is_finite())
}

fn compare_numeric_cells(
    left: &str,
    right: &str,
    suffix: &str,
    descending: bool,
) -> std::cmp::Ordering {
    match (numeric_cell(left, suffix), numeric_cell(right, suffix)) {
        (Some(left), Some(right)) => {
            if descending {
                right.total_cmp(&left)
            } else {
                left.total_cmp(&right)
            }
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn sort_proxy_rows(rows: &mut [ProxyRow], column: &str, descending: bool) {
    rows.sort_by(|left, right| {
        let ordering = match column {
            "status" => left.status.to_lowercase().cmp(&right.status.to_lowercase()),
            "protocol" => left
                .protocol
                .to_lowercase()
                .cmp(&right.protocol.to_lowercase()),
            "country" => left
                .country
                .to_lowercase()
                .cmp(&right.country.to_lowercase()),
            "ping" => compare_numeric_cells(&left.ping, &right.ping, " мс", descending),
            "speed" => compare_numeric_cells(&left.speed, &right.speed, " КБ/с", descending),
            "source" => left.source.to_lowercase().cmp(&right.source.to_lowercase()),
            _ => left.node.to_lowercase().cmp(&right.node.to_lowercase()),
        };
        let ordering = if matches!(column, "ping" | "speed") || !descending {
            ordering
        } else {
            ordering.reverse()
        };
        ordering.then_with(|| left.node.to_lowercase().cmp(&right.node.to_lowercase()))
    });
}

fn update_visible_proxy_rows(window: &AppWindow, rows: &[ProxyRow]) {
    let query = window.get_search_query().to_string().to_lowercase();
    let filter = window.get_result_filter().to_string();
    let threshold_multiplier = if window.get_threshold_unit().to_string() == "МБ/с" {
        1024.0
    } else {
        1.0
    };
    let threshold =
        window.get_threshold_value().parse::<f64>().unwrap_or(0.0) * threshold_multiplier;
    let mut filtered = rows
        .iter()
        .filter(|row| {
            let matches_query = query.is_empty()
                || [
                    row.node.as_str(),
                    row.protocol.as_str(),
                    row.country.as_str(),
                ]
                .iter()
                .any(|value| value.to_lowercase().contains(&query));
            let dead = row.status != "Доступен";
            let speed = row
                .speed
                .trim_end_matches(" КБ/с")
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .parse::<f64>()
                .unwrap_or(0.0);
            let matches_filter = match filter.as_str() {
                "Живые" => !dead,
                "Быстрые" => !dead && speed >= threshold && speed > 0.0,
                "Недоступные" => dead,
                _ => true,
            };
            matches_query && matches_filter
        })
        .cloned()
        .collect::<Vec<_>>();
    sort_proxy_rows(
        &mut filtered,
        &window.get_result_sort_column().to_string(),
        window.get_result_sort_descending(),
    );
    window.set_proxy_rows(ModelRc::from(filtered.as_slice()));
}

fn load_proxy_rows(output: &std::path::Path) -> Vec<ProxyRow> {
    let Ok(json) = fs::read_to_string(output.join("proxy-results.json")) else {
        return Vec::new();
    };
    let Ok(results) = serde_json::from_str::<Vec<ProxyResult>>(&json) else {
        return Vec::new();
    };
    results
        .into_iter()
        .map(|proxy| {
            proxy_row(
                "Доступен",
                &proxy.server,
                proxy.port,
                &proxy.protocol,
                &proxy.country,
                proxy
                    .ping_ms
                    .map(|value| format!("{value} мс"))
                    .unwrap_or_else(|| "—".into()),
                if proxy.speed_kbs > 0.0 {
                    format_speed(proxy.speed_kbs)
                } else {
                    "—".into()
                },
                &display_source(&proxy.source),
            )
        })
        .collect()
}

fn load_dead_rows(output: &std::path::Path) -> Vec<ProxyRow> {
    fs::read_to_string(output.join("dead.txt"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| crate::parse::parse_link(line).ok())
        .map(|proxy| {
            proxy_row(
                "Недоступен",
                &proxy.host,
                proxy.port,
                proxy.proto,
                &proxy.country,
                "—".into(),
                "—".into(),
                "—",
            )
        })
        .collect()
}

fn is_subscription_feed_url(value: &str, checker_mode: &str) -> bool {
    if !is_http_source_url(value) {
        return false;
    }
    if checker_mode != "forward" {
        return true;
    }

    // In HTTP/SOCKS mode, a bare http(s)://host:port is a valid individual
    // proxy address. Feed URLs normally have a path or query, so keep the
    // bare authority in the manual-proxy field.
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.path() != "/" || url.query().is_some() || url.fragment().is_some()
}

fn normalize_subscription_inputs(window: &AppWindow) -> bool {
    let checker_mode = window.get_checker_mode().to_string();
    let old_subscriptions = window.get_subscriptions().to_string();
    let old_proxy_links = window.get_proxy_links().to_string();
    let mut urls = old_subscriptions
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut proxy_links = Vec::new();
    for line in old_proxy_links.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if is_subscription_feed_url(line, &checker_mode) {
            urls.push(line.to_owned());
        } else {
            proxy_links.push(line);
        }
    }

    let mut seen = std::collections::HashSet::new();
    urls.retain(|url| seen.insert(url.clone()));
    let subscriptions = urls.join("\n");
    let proxy_links = proxy_links.join("\n");
    let changed = subscriptions != old_subscriptions || proxy_links != old_proxy_links;
    if changed {
        window.set_subscriptions(subscriptions.into());
        window.set_proxy_links(proxy_links.into());
    }
    changed
}

fn remember_active_source_inputs(window: &AppWindow) {
    if window.get_checker_mode() == "forward" {
        window.set_forward_subscriptions(window.get_subscriptions());
        window.set_forward_proxy_links(window.get_proxy_links());
    } else {
        window.set_vpn_subscriptions(window.get_subscriptions());
        window.set_vpn_proxy_links(window.get_proxy_links());
    }
}

fn subscription_preview(window: &AppWindow) {
    let subscriptions = window.get_subscriptions().to_string();
    let links = window.get_proxy_links().to_string();
    window.set_has_manual_links(!links.trim().is_empty());
    let urls = subscriptions
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let summary = if !urls.is_empty() {
        if window.get_checker_mode() == "forward" {
            format!("{} URL-{}", urls.len(), url_source_noun(urls.len()))
        } else {
            format!("Добавлено {} URL", urls.len())
        }
    } else {
        if window.get_checker_mode() == "forward" {
            "URL-источники не добавлены".to_string()
        } else {
            "VPN-подписки не добавлены".to_string()
        }
    };
    let entries = urls
        .iter()
        .map(|url| SharedString::from(*url))
        .collect::<Vec<_>>();
    let lines = entries.iter().take(2).cloned().collect::<Vec<_>>();
    window.set_subscription_summary(summary.into());
    window.set_subscription_lines(ModelRc::from(lines.as_slice()));
    window.set_subscription_entries(ModelRc::from(entries.as_slice()));
}

fn url_source_noun(count: usize) -> &'static str {
    match count % 10 {
        1 if count % 100 != 11 => "источник",
        2..=4 if !(12..=14).contains(&(count % 100)) => "источника",
        _ => "источников",
    }
}

fn source_count_label(count: usize) -> String {
    let noun = match count % 10 {
        1 if count % 100 != 11 => "источник",
        2..=4 if !(12..=14).contains(&(count % 100)) => "источника",
        _ => "источников",
    };
    format!("{count} {noun}")
}

fn load_source_catalog(data: &std::path::Path) -> anyhow::Result<SourceCatalogs> {
    let path = data.join("catalog-sources.json");
    let mut catalogs = serde_json::from_str::<SourceCatalogs>(include_str!("../bin/sources.json"))?;
    if path.exists() {
        let saved = serde_json::from_slice::<SourceCatalogs>(&fs::read(path)?)?;
        for source_set in SUPPORTED_SOURCE_SETS {
            if let Some(entries) = saved.get(*source_set) {
                catalogs.insert((*source_set).to_owned(), entries.clone());
            }
        }
    } else {
        save_source_catalog(data, &catalogs)?;
    }
    for source_set in SUPPORTED_SOURCE_SETS {
        catalogs.entry((*source_set).to_owned()).or_default();
    }
    if migrate_known_catalog_urls(&mut catalogs) {
        save_source_catalog(data, &catalogs)?;
    }
    Ok(catalogs)
}

fn migrate_known_catalog_urls(catalogs: &mut SourceCatalogs) -> bool {
    const URL_MIGRATIONS: &[(&str, &str)] = &[(
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/HakurouKen/free-node/main/public",
    )];

    let mut changed = false;
    for entries in catalogs.values_mut() {
        for entry in entries.iter_mut() {
            if let Some((_, replacement)) = URL_MIGRATIONS
                .iter()
                .find(|(obsolete, _)| entry.as_str() == *obsolete)
            {
                *entry = (*replacement).to_owned();
                changed = true;
            }
        }

        let mut unique = HashSet::with_capacity(entries.len());
        let original_len = entries.len();
        entries.retain(|entry| unique.insert(entry.clone()));
        changed |= entries.len() != original_len;
    }
    changed
}

fn save_source_catalog(data: &std::path::Path, catalogs: &SourceCatalogs) -> anyhow::Result<()> {
    let path = data.join("catalog-sources.json");
    crate::output::write_bytes_atomic(&path, &serde_json::to_vec_pretty(catalogs)?, Some(0o600))
}

fn update_catalog_ui(window: &AppWindow, source_set: &str, entries: &[String]) {
    let items = entries
        .iter()
        .map(|entry| SharedString::from(entry.as_str()))
        .collect::<Vec<_>>();
    window.set_catalog_entries(ModelRc::from(items.as_slice()));
    window.set_source_count_label(source_count_label(items.len()).into());
    window.set_source_set(source_set.into());
}

fn normalized_source_set(value: &str) -> &str {
    if SUPPORTED_SOURCE_SETS.contains(&value) {
        value
    } else {
        "3"
    }
}

fn is_http_source_url(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
}

fn summary_to_window(
    window: &AppWindow,
    summary: Summary,
    elapsed: u64,
    out: &std::path::Path,
    history_path: &std::path::Path,
    all_rows: &Arc<Mutex<Vec<ProxyRow>>>,
    database_error: Option<String>,
    archive: Option<&ArchiveStore>,
    database_pagers: &DatabasePagers,
) {
    window.set_checking(false);
    reset_check_progress(window);
    window.set_elapsed_seconds(elapsed as i32);
    window.set_status("Проверка завершена".into());
    let detail = if summary.speed_enabled {
        format!(
            "{} найдено · {} выше порога · медиана {:.1} КБ/с",
            summary.unique, summary.good, summary.median_kbs
        )
    } else {
        format!("{} найдено · TCP живых {}", summary.unique, summary.alive)
    };
    window.set_status_detail(detail.clone().into());
    window.set_count_alive(summary.alive.to_string().into());
    window.set_count_good(summary.good.to_string().into());
    window.set_count_speed(if summary.speed_enabled {
        format!("{:.1} КБ/с", summary.median_kbs).into()
    } else {
        "выкл.".into()
    });
    window.set_count_fetched(summary.unique.to_string().into());
    window.set_count_dead(
        summary
            .dead_file
            .as_ref()
            .map_or(0, |(_, count)| *count)
            .to_string()
            .into(),
    );
    let files = [
        ("alive.txt", summary.alive),
        ("good.txt", summary.good),
        (
            "dead.txt",
            summary.dead_file.as_ref().map_or(0, |(_, count)| *count),
        ),
        ("parsed.txt", summary.unique),
        ("raw.txt", summary.fetch_loaded),
    ]
    .into_iter()
    .filter(|(name, _)| out.join(name).exists())
    .map(|(name, count)| SharedString::from(format!("{name} · {count}")))
    .collect::<Vec<_>>();
    window.set_output_files(ModelRc::from(files.as_slice()));
    let mut rows = load_proxy_rows(out);
    rows.extend(load_dead_rows(out));
    *all_rows.lock().unwrap_or_else(|poison| poison.into_inner()) = rows.clone();
    update_visible_proxy_rows(window, &rows);
    if let Some(error) = database_error {
        let message = format!("Проверка завершена, но архив не обновлён: {error}");
        window.set_last_error(message.into());
        window.set_database_error(format!("Не удалось сохранить результаты: {error}").into());
    } else {
        window.set_last_error(SharedString::default());
        window.set_database_error(SharedString::default());
    }
    append_run_history(
        window,
        history_path,
        "vpn",
        "Успешно",
        &detail,
        elapsed,
        archive,
    );
    if let Some(archive) = archive {
        let active_page = window.get_active_page().to_string();
        if active_page == "db-proxy" || active_page == "db-vpn" {
            load_database_view(window, archive, database_pagers, active_page == "db-vpn");
        }
    }
}

fn forward_results_to_window(
    window: &AppWindow,
    results: Vec<CheckedForwardProxy>,
    elapsed: u64,
    history_path: &Path,
    all_rows: &Arc<Mutex<Vec<ProxyRow>>>,
    database_error: Option<String>,
    archive: Option<&ArchiveStore>,
    database_pagers: &DatabasePagers,
) {
    let alive_count = results.iter().filter(|result| result.probe.alive).count();
    let mut ping_values = results
        .iter()
        .filter_map(|result| result.probe.ping_ms)
        .collect::<Vec<_>>();
    ping_values.sort_unstable();
    let median_ping = if ping_values.is_empty() {
        None
    } else {
        Some(ping_values[ping_values.len() / 2])
    };

    let rows = results
        .iter()
        .map(|result| {
            let probe = &result.probe;
            proxy_row(
                forward_status_label(&probe.status, probe.alive),
                &probe.proxy.host,
                probe.proxy.port,
                probe.proxy.protocol.as_str(),
                &result.country,
                probe
                    .ping_ms
                    .map(|value| format!("{value} мс"))
                    .unwrap_or_else(|| "—".into()),
                "—".into(),
                &result.source,
            )
        })
        .collect::<Vec<_>>();
    *all_rows.lock().unwrap_or_else(|poison| poison.into_inner()) = rows.clone();
    update_visible_proxy_rows(window, &rows);
    window.set_checking(false);
    reset_check_progress(window);
    window.set_elapsed_seconds(elapsed.min(i32::MAX as u64) as i32);
    window.set_status("Проверка завершена".into());
    let detail = format!("Работают {alive_count} из {} прокси", results.len());
    window.set_status_detail(detail.clone().into());
    window.set_count_fetched(results.len().to_string().into());
    window.set_count_alive(alive_count.to_string().into());
    window.set_count_good(alive_count.to_string().into());
    window.set_count_dead((results.len() - alive_count).to_string().into());
    window.set_count_speed(
        median_ping
            .map(|value| format!("{value} мс"))
            .unwrap_or_else(|| "—".into())
            .into(),
    );
    let no_output_files: &[SharedString] = &[];
    window.set_output_files(ModelRc::from(no_output_files));

    if let Some(error) = database_error {
        window.set_last_error(format!("Проверка завершена, но архив не обновлён: {error}").into());
        window.set_database_error(format!("Не удалось сохранить результаты: {error}").into());
    } else {
        window.set_last_error(SharedString::default());
        window.set_database_error(SharedString::default());
    }
    append_run_history(
        window,
        history_path,
        "forward",
        "Успешно",
        &detail,
        elapsed,
        archive,
    );

    if let Some(archive) = archive {
        let active_page = window.get_active_page().to_string();
        if active_page == "db-proxy" || active_page == "db-vpn" {
            let vpn_only = active_page == "db-vpn";
            let query = window.get_database_query().to_string();
            reset_database_search(window, archive, database_pagers, vpn_only, &query);
        }
    }
}

fn display_source(source: &str) -> String {
    if source.is_empty() {
        return "—".to_owned();
    }
    source
        .strip_prefix("Источник feed-")
        .or_else(|| source.strip_prefix("Источник "))
        .map(|number| format!("Источник {}", number.trim_start_matches('0')))
        .unwrap_or_else(|| source.to_owned())
}

fn forward_status_label(status: &str, alive: bool) -> &'static str {
    match status {
        "auth_required" => "Нужна авторизация",
        "auth_failed" | "invalid_credentials" => "Ошибка авторизации",
        "unsupported_auth" => "Авторизация не поддерживается",
        "timeout" => "Таймаут",
        "connection_failed" => "Нет соединения",
        "target_resolution_failed" => "Не найден целевой адрес",
        "proxy_rejected" => "Прокси отклонил запрос",
        "protocol_unknown" => "Тип прокси не определён",
        "alive" if alive => "Доступен",
        _ if alive => "Доступен",
        _ => "Не прошёл",
    }
}

fn forward_failure_reason(status: &str, alive: bool) -> Option<String> {
    if alive {
        return None;
    }
    let reason = match status {
        "timeout" => "Истёк таймаут ответа прокси.",
        "auth_required" => "Прокси требует логин и пароль.",
        "auth_failed" => "Прокси отклонил учётные данные.",
        "unsupported_auth" => "Способ авторизации прокси не поддерживается.",
        "invalid_credentials" => "Прокси отклонил идентификатор SOCKS4.",
        "connection_failed" => "Не удалось установить соединение с прокси.",
        "target_resolution_failed" => "Не удалось разрешить адрес тестового сайта.",
        "proxy_rejected" => "Прокси отклонил запрос к тестовому сайту.",
        "protocol_unknown" => "Не удалось определить тип прокси.",
        _ => "Проверка прокси завершилась ошибкой.",
    };
    Some(reason.to_owned())
}

pub fn launch_gui() -> anyhow::Result<()> {
    let data = app_data_dir()?;
    let (preferences, preferences_error) = match settings::load(&data) {
        Ok(preferences) => (preferences, None),
        Err(error) => (settings::AppSettings::default(), Some(error.to_string())),
    };
    let settings_writable = preferences_error.is_none();
    let configured_output = PathBuf::from(preferences.output_directory.trim());
    let output = if configured_output.as_os_str().is_empty() {
        data.join("results")
    } else if configured_output.is_absolute() {
        configured_output
    } else {
        data.join(configured_output)
    };
    fs::create_dir_all(&output)?;
    let initial_catalogs = load_source_catalog(&data)?;
    let initial_source_set = normalized_source_set(&preferences.source_set).to_owned();
    let initial_catalog = initial_catalogs
        .get(&initial_source_set)
        .cloned()
        .unwrap_or_default();
    let database_path = data.join("proxy-history.sqlite3");
    let (archive, database_init_error) = match ArchiveStore::initialize(&database_path) {
        Ok(archive) => (Some(Arc::new(archive)), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let window = AppWindow::new()?;
    if let Err(error) = crate::proxy_finder::wire(&window, &data) {
        let errors = [SharedString::from(format!(
            "Не удалось подготовить страницу поиска прокси: {error}"
        ))];
        window.set_proxy_search_errors(ModelRc::from(errors.as_slice()));
        window.set_proxy_search_status("Хранилище поиска недоступно".into());
    }
    window
        .global::<Palette>()
        .set_color_scheme(slint::private_unstable_api::re_exports::ColorScheme::Light);
    let initial_checker_mode = if matches!(preferences.checker_mode.as_str(), "vpn" | "forward") {
        preferences.checker_mode.as_str()
    } else {
        "vpn"
    };
    let forward_subscriptions = preferences
        .forward_subscriptions
        .clone()
        .unwrap_or_else(|| {
            if initial_checker_mode == "forward" {
                preferences.subscriptions.clone()
            } else {
                String::new()
            }
        });
    let forward_proxy_links = preferences.forward_proxy_links.clone().unwrap_or_else(|| {
        if initial_checker_mode == "forward" {
            preferences.proxy_links.clone()
        } else {
            String::new()
        }
    });
    window.set_vpn_subscriptions(preferences.subscriptions.clone().into());
    window.set_forward_subscriptions(forward_subscriptions.clone().into());
    window.set_vpn_proxy_links(preferences.proxy_links.clone().into());
    window.set_forward_proxy_links(forward_proxy_links.clone().into());
    window.set_subscriptions(
        if initial_checker_mode == "forward" {
            forward_subscriptions
        } else {
            preferences.subscriptions.clone()
        }
        .into(),
    );
    window.set_proxy_links(
        if initial_checker_mode == "forward" {
            forward_proxy_links
        } else {
            preferences.proxy_links.clone()
        }
        .into(),
    );
    window.set_use_default_sources(preferences.use_default_sources);
    window.set_source_set(initial_source_set.clone().into());
    window.set_worker_count_value(preferences.worker_count_value.clone().into());
    window.set_timeout_value(preferences.timeout_value.clone().into());
    window.set_threshold_value(preferences.threshold_value.clone().into());
    window.set_threshold_unit(preferences.threshold_unit.clone().into());
    window.set_use_speed(preferences.use_speed);
    window.set_use_geoip(preferences.use_geoip);
    window.set_checker_mode(initial_checker_mode.into());
    if preferences.checker_mode == "forward" {
        window.set_status_detail(
            "Добавьте URL-источники HTTP/SOCKS или вставьте прокси для проверки.".into(),
        );
    }
    window.set_output_directory(output.display().to_string().into());
    window.set_output_location_label(output_location_label(&output).into());
    update_catalog_ui(&window, &initial_source_set, &initial_catalog);
    window.set_data_directory(data.display().to_string().into());
    window.set_database_path(database_path.display().to_string().into());
    if let Some(error) = &database_init_error {
        window.set_database_error(format!("Не удалось открыть архив: {error}").into());
    }
    if let Some(error) = &preferences_error {
        window.set_last_error(
            format!("Не удалось загрузить настройки; использованы значения по умолчанию: {error}")
                .into(),
        );
    }
    let history_path = data.join("run-history.json");
    let legacy_history = read_run_history(&history_path);
    let initial_history = if let Some(archive) = archive.as_deref() {
        let legacy_records = legacy_runs_for_import(&legacy_history);
        if let Err(error) = archive.import_legacy_runs_with_numbers(&legacy_records) {
            window.set_database_error(
                format!("Не удалось перенести историю запусков: {error}").into(),
            );
        }
        match archive.recent_runs(database::RUN_HISTORY_LIMIT) {
            Ok(entries) => {
                let entries = stored_runs_from_archive(&entries);
                history_rows(&entries)
            }
            Err(error) => {
                window.set_database_error(
                    format!("Не удалось прочитать историю запусков: {error}").into(),
                );
                history_rows(&legacy_history)
            }
        }
    } else {
        history_rows(&legacy_history)
    };
    window.set_run_history(ModelRc::from(initial_history.as_slice()));
    set_runtime_status(&window, &data);
    let normalized_subscriptions = normalize_subscription_inputs(&window);
    remember_active_source_inputs(&window);
    subscription_preview(&window);
    if normalized_subscriptions && settings_writable {
        persist_window_settings(&window, &data);
    }

    let database_pagers: DatabasePagers = Arc::new(Mutex::new(HashMap::new()));
    let cancellation: Arc<Mutex<Option<oneshot::Sender<()>>>> = Arc::new(Mutex::new(None));
    let load_database_window = window.as_weak();
    let load_database_archive = archive.clone();
    let load_database_error = database_init_error.clone();
    let load_database_pagers = database_pagers.clone();
    window.on_load_database(move |vpn_only| {
        let Some(window) = load_database_window.upgrade() else {
            return;
        };
        if let Some(archive) = load_database_archive.as_deref() {
            load_database_view(&window, archive, &load_database_pagers, vpn_only);
        } else if let Some(error) = &load_database_error {
            window.set_database_error(format!("Не удалось открыть архив: {error}").into());
        }
    });

    let search_database_window = window.as_weak();
    let search_database_archive = archive.clone();
    let search_database_error = database_init_error.clone();
    let search_database_pagers = database_pagers.clone();
    window.on_database_search_changed(move |vpn_only, query| {
        let Some(window) = search_database_window.upgrade() else {
            return;
        };
        if let Some(archive) = search_database_archive.as_deref() {
            reset_database_search(
                &window,
                archive,
                &search_database_pagers,
                vpn_only,
                query.as_str(),
            );
        } else if let Some(error) = &search_database_error {
            window.set_database_error(format!("Не удалось открыть архив: {error}").into());
        }
    });

    let page_database_window = window.as_weak();
    let page_database_archive = archive.clone();
    let page_database_error = database_init_error.clone();
    let page_database_pagers = database_pagers.clone();
    window.on_database_page_changed(move |vpn_only, direction| {
        let Some(window) = page_database_window.upgrade() else {
            return;
        };
        if let Some(archive) = page_database_archive.as_deref() {
            move_database_page(&window, archive, &page_database_pagers, vpn_only, direction);
        } else if let Some(error) = &page_database_error {
            window.set_database_error(format!("Не удалось открыть архив: {error}").into());
        }
    });

    let select_database_row_window = window.as_weak();
    let select_database_row_archive = archive.clone();
    let select_database_row_error = database_init_error.clone();
    window.on_database_row_selected(move |vpn_only, id| {
        let Some(window) = select_database_row_window.upgrade() else {
            return;
        };
        let Ok(id) = id.as_str().parse::<i64>() else {
            window.set_database_error("Не удалось определить выбранную запись.".into());
            return;
        };
        if let Some(archive) = select_database_row_archive.as_deref() {
            load_database_detail(&window, archive, id, vpn_only);
        } else if let Some(error) = &select_database_row_error {
            window.set_database_error(format!("Не удалось открыть архив: {error}").into());
        }
    });

    let catalog_state = Arc::new(Mutex::new(initial_catalogs));
    let recheck_database_row_window = window.as_weak();
    let recheck_database_row_archive = archive.clone();
    let recheck_database_row_error = database_init_error.clone();
    let recheck_database_row_pagers = database_pagers.clone();
    let recheck_database_row_cancellation = cancellation.clone();
    let recheck_database_row_history = history_path.clone();
    let recheck_database_row_catalogs = catalog_state.clone();
    window.on_database_row_recheck(move |vpn_only, id| {
        let Some(window) = recheck_database_row_window.upgrade() else {
            return;
        };
        let Ok(id) = id.as_str().parse::<i64>() else {
            window.set_database_error("Не удалось определить запись для проверки.".into());
            return;
        };
        let Some(archive) = recheck_database_row_archive.clone() else {
            if let Some(error) = &recheck_database_row_error {
                window.set_database_error(format!("Не удалось открыть архив: {error}").into());
            }
            return;
        };
        let target = match archive.recheck_target(id, vpn_only) {
            Ok(Some(target)) => target,
            Ok(None) => {
                window.set_database_error("Запись не найдена в выбранном архиве.".into());
                return;
            }
            Err(error) => {
                window.set_database_error(format!("Не удалось загрузить запись: {error}").into());
                return;
            }
        };
        if let Err(error) = start_archive_recheck(
            &window,
            target,
            archive,
            recheck_database_row_pagers.clone(),
            recheck_database_row_history.clone(),
            recheck_database_row_cancellation.clone(),
            recheck_database_row_catalogs.clone(),
        ) {
            window.set_database_error(error.to_string().into());
        }
    });
    let select_catalog_window = window.as_weak();
    let select_catalog_state = catalog_state.clone();
    window.on_select_source_set(move |value| {
        let Some(window) = select_catalog_window.upgrade() else {
            return;
        };
        let source_set = normalized_source_set(value.as_str()).to_owned();
        let entries = select_catalog_state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&source_set)
            .cloned()
            .unwrap_or_default();
        update_catalog_ui(&window, &source_set, &entries);
    });

    let add_catalog_window = window.as_weak();
    let add_catalog_state = catalog_state.clone();
    let add_catalog_data = data.clone();
    window.on_add_catalog_entry(move |value| {
        let Some(window) = add_catalog_window.upgrade() else {
            return;
        };
        let url = value.to_string().trim().to_owned();
        if !is_http_source_url(&url) {
            window
                .set_catalog_editor_error("Введите корректную ссылку с адресом источника.".into());
            return;
        }

        let source_set = window.get_source_set().to_string();
        let mut catalogs = add_catalog_state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut updated = catalogs.clone();
        {
            let entries = updated.entry(source_set.clone()).or_default();
            if entries.iter().any(|entry| entry == &url) {
                window.set_catalog_editor_error("Такая ссылка уже есть в каталоге.".into());
                return;
            }
            entries.push(url);
        }
        if let Err(error) = save_source_catalog(&add_catalog_data, &updated) {
            window.set_catalog_editor_error(error.to_string().into());
            return;
        }
        let updated_entries = updated.get(&source_set).cloned().unwrap_or_default();
        *catalogs = updated;
        update_catalog_ui(&window, &source_set, &updated_entries);
        window.set_catalog_editor_error(SharedString::default());
        window.set_draft_catalog_url(SharedString::default());
        window.set_show_catalog_editor(false);
    });

    let remove_catalog_window = window.as_weak();
    let remove_catalog_state = catalog_state.clone();
    let remove_catalog_data = data.clone();
    window.on_remove_catalog_entry(move |index| {
        let Some(window) = remove_catalog_window.upgrade() else {
            return;
        };
        let Ok(index) = usize::try_from(index) else {
            return;
        };
        let source_set = window.get_source_set().to_string();
        let mut catalogs = remove_catalog_state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(current_entries) = catalogs.get(&source_set) else {
            return;
        };
        if index >= current_entries.len() {
            return;
        }
        let mut updated = catalogs.clone();
        updated.entry(source_set.clone()).or_default().remove(index);
        if let Err(error) = save_source_catalog(&remove_catalog_data, &updated) {
            window.set_catalog_editor_error(error.to_string().into());
            return;
        }
        let visible_entries = updated.get(&source_set).cloned().unwrap_or_default();
        *catalogs = updated;
        update_catalog_ui(&window, &source_set, &visible_entries);
        window.set_catalog_editor_error(SharedString::default());
    });

    let subscriptions_window = window.as_weak();
    let subscriptions_data = data.clone();
    window.on_subscriptions_changed(move || {
        if let Some(window) = subscriptions_window.upgrade() {
            normalize_subscription_inputs(&window);
            remember_active_source_inputs(&window);
            subscription_preview(&window);
            if settings_writable {
                persist_window_settings(&window, &subscriptions_data);
            }
        }
    });

    let preferences_window = window.as_weak();
    let preferences_data = data.clone();
    let preferences_timer = Timer::default();
    window.on_preferences_changed(move || {
        if !settings_writable {
            return;
        }
        let weak_window = preferences_window.clone();
        let data_dir = preferences_data.clone();
        preferences_timer.start(
            TimerMode::SingleShot,
            std::time::Duration::from_millis(400),
            move || {
                if let Some(window) = weak_window.upgrade() {
                    if window_settings_are_valid(&window) {
                        persist_window_settings(&window, &data_dir);
                    }
                }
            },
        );
    });

    let minimize_window = window.as_weak();
    window.on_minimize_window(move || {
        if let Some(window) = minimize_window.upgrade() {
            window.window().set_minimized(true);
        }
    });
    let maximize_window = window.as_weak();
    window.on_toggle_maximize_window(move || {
        if let Some(window) = maximize_window.upgrade() {
            let handle = window.window();
            handle.set_maximized(!handle.is_maximized());
        }
    });

    let all_rows = Arc::new(Mutex::new(Vec::<ProxyRow>::new()));
    let mode_window = window.as_weak();
    let mode_rows = all_rows.clone();
    let mode_data = data.clone();
    let mode_settings_writable = settings_writable;
    window.on_select_checker_mode(move |mode| {
        if let Some(window) = mode_window.upgrade() {
            let mode = if mode.as_str() == "forward" {
                "forward"
            } else {
                "vpn"
            };
            let previous_mode = window.get_checker_mode().to_string();
            if previous_mode == "forward" {
                window.set_forward_subscriptions(window.get_subscriptions());
                window.set_forward_proxy_links(window.get_proxy_links());
            } else {
                window.set_vpn_subscriptions(window.get_subscriptions());
                window.set_vpn_proxy_links(window.get_proxy_links());
            }
            window.set_checker_mode(mode.into());
            if mode == "forward" {
                window.set_subscriptions(window.get_forward_subscriptions());
                window.set_proxy_links(window.get_forward_proxy_links());
            } else {
                window.set_subscriptions(window.get_vpn_subscriptions());
                window.set_proxy_links(window.get_vpn_proxy_links());
            }
            normalize_subscription_inputs(&window);
            remember_active_source_inputs(&window);
            subscription_preview(&window);
            if mode_settings_writable {
                persist_window_settings(&window, &mode_data);
            }
            window.set_result_filter("Все".into());
            window.set_search_query(SharedString::default());
            window.set_count_fetched("0".into());
            window.set_count_alive("0".into());
            window.set_count_good("0".into());
            window.set_count_dead("0".into());
            window.set_count_speed("—".into());
            window.set_output_files(ModelRc::from([].as_slice()));
            window.set_proxy_rows(ModelRc::from([].as_slice()));
            window.set_status("Готов к запуску".into());
            window.set_status_detail(if mode == "forward" {
                "Добавьте URL-источники HTTP/SOCKS или вставьте прокси для проверки.".into()
            } else {
                "Настройки корректны. Можно начать проверку.".into()
            });
            window.set_last_error(SharedString::default());
            *mode_rows
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = Vec::new();
        }
    });
    let rows_for_filter = all_rows.clone();
    let filter_window = window.as_weak();
    window.on_filter_results(move || {
        let Some(window) = filter_window.upgrade() else {
            return;
        };
        let rows = rows_for_filter
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        update_visible_proxy_rows(&window, &rows);
    });
    let sort_window = window.as_weak();
    window.on_sort_results(move |column| {
        if let Some(window) = sort_window.upgrade() {
            if window.get_result_sort_column() == column {
                window.set_result_sort_descending(!window.get_result_sort_descending());
            } else {
                window.set_result_sort_column(column);
                window.set_result_sort_descending(true);
            }
            window.invoke_filter_results();
        }
    });
    let filter_window = window.as_weak();
    window.on_select_result_filter(move |filter| {
        if let Some(window) = filter_window.upgrade() {
            window.set_result_filter(filter);
            window.invoke_filter_results();
        }
    });
    let export_window = window.as_weak();
    window.on_export_results(move || {
        let Some(window) = export_window.upgrade() else {
            return;
        };
        let mut csv = String::from("Статус,Узел,Протокол,Страна,Ping,Скорость,Источник\n");
        for row in window.get_proxy_rows().iter() {
            let fields = [
                row.status.as_str(),
                row.node.as_str(),
                row.protocol.as_str(),
                row.country.as_str(),
                row.ping.as_str(),
                row.speed.as_str(),
                row.source.as_str(),
            ];
            csv.push_str(
                &fields
                    .iter()
                    .map(|field| format!("\"{}\"", field.replace('"', "\"\"")))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            csv.push('\n');
        }
        let output = PathBuf::from(window.get_output_directory().to_string());
        let mut index = 0u64;
        let result = loop {
            let filename = if index == 0 {
                "proxy-results.csv".to_owned()
            } else {
                format!("proxy-results-{index}.csv")
            };
            let path = output.join(filename);
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(csv.as_bytes()) {
                        let _ = fs::remove_file(&path);
                        break Err(error);
                    }
                    break Ok(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    index = match index.checked_add(1) {
                        Some(index) => index,
                        None => break Err(error),
                    };
                }
                Err(error) => break Err(error),
            }
        };
        match result {
            Ok(path) => {
                window.set_last_error(SharedString::default());
                window.set_status_detail(format!("CSV сохранён: {}", path.display()).into());
            }
            Err(error) => {
                window.set_last_error(format!("Не удалось сохранить CSV: {error}").into());
            }
        }
    });
    let copy_window = window.as_weak();
    window.on_copy_proxy_address(move |address| {
        if let Some(window) = copy_window.upgrade() {
            match copy_to_clipboard(address.as_str()) {
                Ok(()) => {
                    window.set_last_error(SharedString::default());
                    window.set_status_detail(format!("Скопирован адрес {}", address).into());
                }
                Err(error) => window.set_last_error(error.to_string().into()),
            }
        }
    });
    let folder_window = window.as_weak();
    window.on_open_results_folder(move || {
        let Some(window) = folder_window.upgrade() else {
            return;
        };
        let path = PathBuf::from(window.get_output_directory().to_string());
        if let Err(error) = open_path(&path) {
            window.set_last_error(format!("Не удалось открыть папку: {error}").into());
        }
    });

    let app_data_window = window.as_weak();
    let app_data_path = data.clone();
    window.on_open_app_data_directory(move || {
        if let Some(window) = app_data_window.upgrade() {
            if let Err(error) = open_path(&app_data_path) {
                window.set_last_error(format!("Не удалось открыть папку данных: {error}").into());
            }
        }
    });
    let runtime_busy = Arc::new(AtomicBool::new(false));
    let runtime_cancel: Arc<Mutex<Option<oneshot::Sender<()>>>> = Arc::new(Mutex::new(None));
    let notification_data = data.clone();
    window.on_acknowledge_notifications(move || {
        acknowledge_notifications(&notification_data);
    });
    let refresh_window = window.as_weak();
    let refresh_data_path = data.clone();
    let refresh_busy = runtime_busy.clone();
    let refresh_cancel = runtime_cancel.clone();
    window.on_refresh_runtime_status(move || {
        if let Some(window) = refresh_window.upgrade() {
            if refresh_busy.load(Ordering::Acquire) {
                if let Some(sender) = refresh_cancel
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .take()
                {
                    let _ = sender.send(());
                    window.set_runtime_message("Останавливаю операцию…".into());
                }
                return;
            }
            start_runtime_job(
                &window,
                refresh_window.clone(),
                refresh_data_path.clone(),
                refresh_busy.clone(),
                refresh_cancel.clone(),
                RuntimeJob::Check,
            );
        }
    });
    let core_window = window.as_weak();
    let core_data = data.clone();
    let core_busy = runtime_busy.clone();
    let core_cancel = runtime_cancel.clone();
    window.on_manage_core(move || {
        if let Some(window) = core_window.upgrade() {
            let action = window.get_core_action_label().to_string();
            let job = match action.as_str() {
                "Установить Xray" => RuntimeJob::Core { update: false },
                "Обновить Xray" => RuntimeJob::Core { update: true },
                _ => RuntimeJob::Check,
            };
            start_runtime_job(
                &window,
                core_window.clone(),
                core_data.clone(),
                core_busy.clone(),
                core_cancel.clone(),
                job,
            );
        }
    });
    let geoip_window = window.as_weak();
    let geoip_data = data.clone();
    let geoip_busy = runtime_busy.clone();
    let geoip_cancel = runtime_cancel.clone();
    window.on_manage_geoip(move || {
        if let Some(window) = geoip_window.upgrade() {
            let action = window.get_geoip_action_label().to_string();
            let job = match action.as_str() {
                "Установить базу" | "Обновить базу" => RuntimeJob::GeoIp,
                _ => RuntimeJob::Check,
            };
            start_runtime_job(
                &window,
                geoip_window.clone(),
                geoip_data.clone(),
                geoip_busy.clone(),
                geoip_cancel.clone(),
                job,
            );
        }
    });
    start_runtime_job(
        &window,
        window.as_weak(),
        data.clone(),
        runtime_busy.clone(),
        runtime_cancel.clone(),
        RuntimeJob::Check,
    );

    let cancel_slot = cancellation.clone();
    window.on_cancel_check(move || {
        if let Some(sender) = cancel_slot.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = sender.send(());
        }
    });

    let timer_started = Arc::new(Mutex::new(None::<Instant>));
    let tick_window = window.as_weak();
    let tick_started = timer_started.clone();
    let timer = Timer::default();
    timer.start(
        TimerMode::Repeated,
        std::time::Duration::from_secs(1),
        move || {
            if let Some(window) = tick_window.upgrade() {
                if let Some(started) = *tick_started
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                {
                    window.set_elapsed_seconds(
                        started.elapsed().as_secs().min(i32::MAX as u64) as i32
                    );
                }
            }
        },
    );

    let check_window = window.as_weak();
    let cancel_sender = cancellation.clone();
    let elapsed_clock = timer_started.clone();
    let rows_for_summary = all_rows.clone();
    let output_path = output.clone();
    let history_file = history_path.clone();
    let check_catalog_state = catalog_state.clone();
    let check_archive = archive.clone();
    let check_database_error = database_init_error.clone();
    let check_database_pagers = database_pagers.clone();
    let check_settings_data = data.clone();
    let check_settings_writable = settings_writable;
    window.on_start_check(move || {
        let Some(window) = check_window.upgrade() else {
            return;
        };
        if window.get_checking() {
            return;
        }
        let subscriptions = window.get_subscriptions().to_string();
        let pasted_links = window.get_proxy_links().to_string();
        if subscriptions
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .any(|line| !is_http_source_url(line))
        {
            window.set_last_error(
                "Ссылки подписок должны быть корректными URL с http:// или https://.".into(),
            );
            return;
        }
        let output_text = window.get_output_directory().to_string();
        let output = if output_text.trim().is_empty() {
            output_path.clone()
        } else {
            PathBuf::from(output_text.trim())
        };
        let workers = match window.get_worker_count_value().parse::<usize>() {
            Ok(workers) if (1..=512).contains(&workers) => workers,
            Err(_) => {
                window.set_last_error("Укажите число потоков от 1 до 512.".into());
                return;
            }
            _ => {
                window.set_last_error("Число потоков должно быть от 1 до 512.".into());
                return;
            }
        };
        let proxy_timeout = match window.get_timeout_value().parse::<f64>() {
            Ok(timeout) if timeout.is_finite() && (0.1..=3600.0).contains(&timeout) => timeout,
            _ => {
                window.set_last_error("Таймаут должен быть от 0,1 до 3600 секунд.".into());
                return;
            }
        };
        let use_speed = window.get_use_speed();
        let use_geoip = window.get_use_geoip();
        let use_default_sources = window.get_use_default_sources();
        let source_set = normalized_source_set(window.get_source_set().as_str()).to_owned();
        let checker_mode = window.get_checker_mode().to_string();
        let forward_mode = checker_mode == "forward";
        let threshold = if !forward_mode && use_speed {
            let multiplier = if window.get_threshold_unit().to_string() == "МБ/с" {
                1024.0
            } else {
                1.0
            };
            let threshold = match window.get_threshold_value().parse::<f64>() {
                Ok(threshold) => threshold * multiplier,
                Err(_) => {
                    window.set_last_error("Укажите корректный порог скорости.".into());
                    return;
                }
            };
            if !threshold.is_finite() || threshold < 0.0 || threshold > 1_000_000_000.0 {
                window.set_last_error(
                    "Порог скорости вне допустимого диапазона. Проверьте значение и единицы."
                        .into(),
                );
                return;
            }
            threshold
        } else {
            0.0
        };
        if forward_mode && !pasted_links.trim().is_empty() {
            let parsed = crate::forward_proxy::parse_subscription_with_report(&pasted_links);
            if parsed.invalid_lines > 0 || parsed.proxies.is_empty() {
                window.set_last_error(
                    "Вставьте IP:PORT или ссылку HTTP(S), SOCKS4/4a, SOCKS5/5h — по одной записи на строку.".into(),
                );
                return;
            }
        }
        let catalog_sets = check_catalog_state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        let has_builtin_sources = use_default_sources
            && !forward_mode
            && catalog_sets
                .get(&source_set)
                .is_some_and(|entries| !entries.is_empty());
        if !has_builtin_sources
            && subscriptions.trim().is_empty()
            && pasted_links.trim().is_empty()
        {
            window.set_last_error(
                if forward_mode {
                    "Для HTTP/SOCKS добавьте URL подходящей подписки или вставьте прокси-ссылки."
                } else {
                    "Нет источников для проверки. Включите каталог или добавьте подписку/прокси-ссылки."
                }
                .into(),
            );
            return;
        }

        let cli = match configure_cli(
            &subscriptions,
            &pasted_links,
            &output,
            workers,
            proxy_timeout,
            threshold,
            use_speed,
            use_geoip,
            use_default_sources && !forward_mode,
            &source_set,
            &catalog_sets,
        ) {
            Ok(cli) => cli,
            Err(error) => {
                window.set_last_error(error.to_string().into());
                return;
            }
        };
        if let Err(error) = fs::create_dir_all(&output) {
            window.set_last_error(error.to_string().into());
            return;
        }
        if check_settings_writable {
            if let Err(error) = save_window_settings(&window, &check_settings_data) {
                window.set_last_error(format!("Не удалось сохранить настройки: {error}").into());
                return;
            }
        }

        let (cancel_tx, cancel_rx) = oneshot::channel();
        *cancel_sender
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(cancel_tx);
        *elapsed_clock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(Instant::now());
        window.set_checking(true);
        window.set_elapsed_seconds(0);
        window.set_progress_visible(true);
        window.set_progress_stage("Подготовка проверки".into());
        window.set_progress_completed("0".into());
        window.set_progress_total("—".into());
        window.set_progress_rate("—".into());
        window.set_progress_eta("считаем…".into());
        window.set_progress_percent(0);
        window.set_last_error(SharedString::default());
        window.set_status("Загружаем и разбираем источники".into());
        window.set_status_detail(if forward_mode {
            "Дальше будут проверка HTTP/SOCKS и определение страны".into()
        } else {
            "Дальше будут GeoIP, TCP ping и замер скорости".into()
        });

        let ui = check_window.clone();
        let output_dir = output.clone();
        let rows_for_summary = rows_for_summary.clone();
        let history_path = history_file.clone();
        let archive = check_archive.clone();
        let database_error = check_database_error.clone();
        let database_pagers = check_database_pagers.clone();
        let forward_links = pasted_links.clone();
        let forward_geoip = use_geoip;
        std::thread::spawn(move || {
            let started = Instant::now();
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let message = format!("Не удалось запустить сетевой runtime: {error}");
                    let elapsed = started.elapsed().as_secs();
                    let mode = if forward_mode { "forward" } else { "vpn" };
                    let history_database_error = persist_non_success_run(
                        archive.as_deref(),
                        mode,
                        "Ошибка",
                        &message,
                        elapsed,
                    );
                    let history_archive = archive.clone();
                    let _ = ui.upgrade_in_event_loop(move |window| {
                        window.set_checking(false);
                        reset_check_progress(&window);
                        window.set_status("Проверка завершилась с ошибкой".into());
                        window.set_last_error(message.clone().into());
                        append_run_history(
                            &window,
                            &history_path,
                            mode,
                            "Ошибка",
                            &message,
                            elapsed,
                            history_archive.as_deref(),
                        );
                        if let Some(error) = &history_database_error {
                            window.set_database_error(
                                format!("Не удалось сохранить запуск в SQLite: {error}").into(),
                            );
                        }
                    });
                    return;
                }
            };
            let output_snapshot = match OutputSnapshot::create(&output_dir) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    let message = format!("Не удалось сохранить прежние результаты: {error}");
                    let elapsed = started.elapsed().as_secs();
                    let mode = if forward_mode { "forward" } else { "vpn" };
                    let history_database_error = persist_non_success_run(
                        archive.as_deref(),
                        mode,
                        "Ошибка",
                        &message,
                        elapsed,
                    );
                    let history_archive = archive.clone();
                    let _ = ui.upgrade_in_event_loop(move |window| {
                        window.set_checking(false);
                        reset_check_progress(&window);
                        window.set_status("Проверка не запущена".into());
                        window.set_last_error(message.clone().into());
                        append_run_history(
                            &window,
                            &history_path,
                            mode,
                            "Ошибка",
                            &message,
                            elapsed,
                            history_archive.as_deref(),
                        );
                        if let Some(error) = &history_database_error {
                            window.set_database_error(
                                format!("Не удалось сохранить запуск в SQLite: {error}").into(),
                            );
                        }
                    });
                    return;
                }
            };
            let progress_window = ui.clone();
            let progress_callback: pipeline::ProgressCallback = Arc::new(move |progress| {
                let progress_window = progress_window.clone();
                let _ = progress_window.upgrade_in_event_loop(move |window| {
                    set_pipeline_progress(&window, progress);
                });
            });
            let result = runtime.block_on(async move {
                if forward_mode {
                    tokio::select! {
                        result = forward_runner::run_from_cli(
                            &cli,
                            &forward_links,
                            forward_geoip,
                            progress_callback,
                        ) => result.map(|results| Some(CompletedCheck::Forward(results))),
                        _ = cancel_rx => Ok(None),
                    }
                } else {
                    tokio::select! {
                        result = pipeline::run_with_progress(cli, progress_callback) => result.map(|summary| Some(CompletedCheck::Vpn(summary))),
                        _ = cancel_rx => Ok(None),
                    }
                }
            });
            let elapsed = started.elapsed().as_secs();
            match result {
                Ok(Some(CompletedCheck::Vpn(summary))) => {
                    let _ = output_snapshot.discard();
                    let database_error = match archive.as_deref() {
                        Some(archive) => archive
                            .record_completed_run(&output_dir, &summary, elapsed)
                            .err()
                            .map(|error| error.to_string()),
                        None => database_error,
                    };
                    let _ = ui.upgrade_in_event_loop(move |window| {
                        summary_to_window(
                            &window,
                            summary,
                            elapsed,
                            &output_dir,
                            &history_path,
                            &rows_for_summary,
                            database_error,
                            archive.as_deref(),
                            &database_pagers,
                        )
                    });
                }
                Ok(Some(CompletedCheck::Forward(results))) => {
                    let _ = output_snapshot.discard();
                    let database_error = match archive.as_deref() {
                        Some(archive) => {
                            let records = results
                                .iter()
                                .map(|result| {
                                    let probe = &result.probe;
                                    database::ArchiveRecord {
                                        fingerprint: probe.proxy.fingerprint.clone(),
                                        protocol: probe.proxy.protocol.as_str().to_owned(),
                                        host: probe.proxy.host.clone(),
                                        port: probe.proxy.port,
                                        name: probe.proxy.name.clone(),
                                        original_link: probe.proxy.original_uri.clone(),
                                        country: result.country.clone(),
                                        is_vpn: false,
                                        status: forward_status_label(&probe.status, probe.alive).to_owned(),
                                        failure_reason: forward_failure_reason(&probe.status, probe.alive),
                                        ping_ms: probe.ping_ms,
                                        speed_kbs: None,
                                    }
                                })
                                .collect::<Vec<_>>();
                            let alive = results.iter().filter(|result| result.probe.alive).count();
                            archive
                                .record_observations(&records, alive, elapsed)
                                .err()
                                .map(|error| error.to_string())
                        }
                        None => database_error,
                    };
                    let _ = ui.upgrade_in_event_loop(move |window| {
                        forward_results_to_window(
                            &window,
                            results,
                            elapsed,
                            &history_path,
                            &rows_for_summary,
                            database_error,
                            archive.as_deref(),
                            &database_pagers,
                        )
                    });
                }
                Ok(None) => {
                    let rollback_error = output_snapshot
                        .restore(&output_dir)
                        .err()
                        .map(|error| error.to_string());
                    let mode = if forward_mode { "forward" } else { "vpn" };
                    let history_database_error = persist_non_success_run(
                        archive.as_deref(),
                        mode,
                        "Отменена",
                        "Остановлено пользователем",
                        elapsed,
                    );
                    let history_archive = archive.clone();
                    let _ = ui.upgrade_in_event_loop(move |window| {
                        window.set_checking(false);
                        reset_check_progress(&window);
                        window.set_status("Проверка отменена".into());
                        window.set_status_detail(if let Some(error) = &rollback_error {
                            format!("Не удалось полностью восстановить файлы результатов: {error}")
                                .into()
                        } else {
                            "Предыдущие файлы результатов восстановлены".into()
                        });
                        if let Some(error) = &rollback_error {
                            window.set_last_error(error.clone().into());
                        }
                        append_run_history(
                            &window,
                            &history_path,
                            mode,
                            "Отменена",
                            "Остановлено пользователем",
                            elapsed,
                            history_archive.as_deref(),
                        );
                        if let Some(error) = &history_database_error {
                            window.set_database_error(
                                format!("Не удалось сохранить запуск в SQLite: {error}").into(),
                            );
                        }
                    });
                }
                Err(error) => {
                    let message = match output_snapshot.restore(&output_dir) {
                        Ok(()) => error.to_string(),
                        Err(restore_error) => {
                            format!("{error}; не удалось восстановить прошлые результаты: {restore_error}")
                        }
                    };
                    let mode = if forward_mode { "forward" } else { "vpn" };
                    let history_database_error = persist_non_success_run(
                        archive.as_deref(),
                        mode,
                        "Ошибка",
                        &message,
                        elapsed,
                    );
                    let history_archive = archive.clone();
                    let _ = ui.upgrade_in_event_loop(move |window| {
                        window.set_checking(false);
                        reset_check_progress(&window);
                        window.set_status("Проверка завершилась с ошибкой".into());
                        window.set_last_error(message.clone().into());
                        append_run_history(
                            &window,
                            &history_path,
                            mode,
                            "Ошибка",
                            &message,
                            elapsed,
                            history_archive.as_deref(),
                        );
                        if let Some(error) = &history_database_error {
                            window.set_database_error(
                                format!("Не удалось сохранить запуск в SQLite: {error}").into(),
                            );
                        }
                    });
                }
            }
        });
    });

    window.run()?;
    let _ = timer.stop();
    Ok(())
}
