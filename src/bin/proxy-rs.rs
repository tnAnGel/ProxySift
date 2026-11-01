#[path = "../check.rs"]
mod check;
#[path = "../checkpoint.rs"]
mod checkpoint;
#[path = "../cli.rs"]
mod cli;
#[path = "../diagnose.rs"]
mod diagnose;
#[path = "../fetch.rs"]
mod fetch;
#[path = "../geoip.rs"]
mod geoip;
#[path = "../hysteria1.rs"]
mod hysteria1;
#[path = "../outbound.rs"]
mod outbound;
#[path = "../output.rs"]
mod output;
#[path = "../parse.rs"]
mod parse;
#[path = "../pipeline.rs"]
mod pipeline;
#[path = "../singbox_check.rs"]
mod singbox_check;
#[path = "../source_report.rs"]
mod source_report;
#[path = "../sources.rs"]
mod sources;
#[path = "../speed.rs"]
mod speed;
#[path = "../table.rs"]
mod table;
#[path = "../tcp_ping.rs"]
mod tcp_ping;
#[path = "../xray.rs"]
mod xray;

use clap::Parser;
use cli::Cli;
use colored::Colorize;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

fn fmt_dur(secs: f64) -> String {
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        let m = (secs / 60.0).floor() as u64;
        let s = secs - m as f64 * 60.0;
        format!("{m}m {s:.0}s")
    }
}

fn fmt_speed(kbs: f64) -> String {
    if kbs >= 1024.0 {
        format!("{:.1} MB/s", kbs / 1024.0)
    } else {
        format!("{kbs:.1} KB/s")
    }
}

fn percentage(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64 * 100.0
    }
}

fn has_fetch_failures(summary: &Summary) -> bool {
    summary.fetch_failed > 0
}

fn has_bad_outbounds(summary: &Summary) -> bool {
    summary.bad_outbounds > 0
}

#[derive(Debug, Default)]
struct Summary {
    fetch_sources: usize,
    fetch_loaded: usize,
    fetch_failed: usize,
    fetch_failure_examples: Vec<String>,
    fetch_secs: f64,
    links: usize,
    unique: usize,
    duplicates: usize,
    invalid: usize,
    unsupported: usize,
    unsupported_details: BTreeMap<String, usize>,
    parse_secs: f64,
    geo: bool,
    geo_countries: usize,
    geo_secs: f64,
    tcp_enabled: bool,
    tcp_total: usize,
    tcp_alive: usize,
    tcp_secs: f64,
    speed_enabled: bool,
    speed_total: usize,
    speed_passed: usize,
    speed_unchecked: usize,
    speed_secs: f64,
    bad_outbounds: usize,
    alive: usize,
    good: usize,
    avg_kbs: f64,
    median_kbs: f64,
    alive_file: Option<(String, usize)>,
    good_file: Option<(String, usize)>,
    clash_file: Option<(String, usize)>,
    singbox_file: Option<(String, usize)>,
    singbox_report_file: Option<(String, usize)>,
    speed_report_file: Option<(String, usize)>,
    dead_file: Option<(String, usize)>,
    raw_file: Option<(String, usize)>,
    parsed_file: Option<(String, usize)>,
    total_secs: f64,
}

fn print_summary(s: &Summary) {
    let line = "═".repeat(46);
    println!("\n{}", line.bold().cyan());
    println!("{}", "  ИТОГИ".bold().cyan());
    println!("{}", line.bold().cyan());

    println!(
        "  {} {}",
        "Общее время:".bold(),
        fmt_dur(s.total_secs).yellow()
    );

    println!("\n  {}", "Источники".cyan().bold());
    println!(
        "    {:<15} {:>9}   {:<15} {:>9}   {}",
        "Подписок:",
        s.fetch_sources,
        "Загружено:",
        s.fetch_loaded,
        fmt_dur(s.fetch_secs)
    );
    if has_fetch_failures(s) {
        println!(
            "    {} {}",
            "Ошибок загрузки:".yellow().bold(),
            s.fetch_failed.to_string().yellow()
        );
        for failure in &s.fetch_failure_examples {
            println!("      {} {failure}", "!".yellow().bold());
        }
    }
    println!(
        "    {:<15} {:>9}   {:<15} {:>9}   {}",
        "Ссылок:",
        s.links,
        "Уникальных:",
        format!("{:>9}", s.unique).green(),
        fmt_dur(s.parse_secs).dimmed()
    );
    println!(
        "    {:<13} {:>8}   {:<13} {:>8}   {:<13} {:>8}",
        "Дубликатов:", s.duplicates, "Некорр.:", s.invalid, "Неподдерж.:", s.unsupported
    );
    if !s.unsupported_details.is_empty() {
        let table = crate::table::render_count_table(
            s.unsupported_details
                .iter()
                .map(|(reason, count)| (reason.clone(), *count)),
        );
        println!("\n  Детализация неподдержки:\n{table}");
    }

    if s.geo {
        println!("\n  {}", "GeoIP".cyan().bold());
        println!(
            "    стран: {}   ({})",
            s.geo_countries.to_string().green(),
            fmt_dur(s.geo_secs).dimmed()
        );
    }

    if s.tcp_enabled {
        println!("\n  {}", "TCP ping".cyan().bold());
        let pct = percentage(s.tcp_alive, s.tcp_total);
        println!(
            "    живых: {}/{} ({pct:.1}%)   ({})",
            s.tcp_alive.to_string().green(),
            s.tcp_total,
            fmt_dur(s.tcp_secs)
        );
    }

    if s.speed_enabled {
        println!("\n  {}", "Проверка скорости".cyan().bold());
        let pct = percentage(s.speed_passed, s.speed_total);
        println!(
            "    прошли порог: {}/{} ({pct:.1}%)   ({})",
            s.speed_passed.to_string().green(),
            s.speed_total,
            fmt_dur(s.speed_secs)
        );
        if s.speed_unchecked > 0 {
            println!(
                "    без проверки подходящим ядром: {}",
                s.speed_unchecked.to_string().yellow()
            );
        }
        if s.good > 0 {
            println!(
                "    средняя: {}   медиана: {}",
                fmt_speed(s.avg_kbs).cyan(),
                fmt_speed(s.median_kbs).cyan()
            );
        }
        if has_bad_outbounds(s) {
            println!(
                "    {} {}",
                "Некорректных outbound:".yellow(),
                s.bad_outbounds.to_string().yellow()
            );
        }
    }

    println!(
        "  {} {}",
        "Живых:".bold(),
        s.alive.to_string().green().bold()
    );

    let files: Vec<String> = [
        s.raw_file.as_ref(),
        s.parsed_file.as_ref(),
        s.alive_file.as_ref(),
        s.good_file.as_ref(),
        s.clash_file.as_ref(),
        s.singbox_file.as_ref(),
        s.singbox_report_file.as_ref(),
        s.speed_report_file.as_ref(),
        s.dead_file.as_ref(),
    ]
    .into_iter()
    .flatten()
    .map(|(p, n)| format!("{p} ({n})"))
    .collect();
    if !files.is_empty() {
        println!("\n  {}", "Файлы".cyan().bold());
        for file in files {
            println!("    {} {}", "•".dimmed(), file);
        }
    }
    println!("{}", line.bold().cyan());
}

#[tokio::main]
async fn main() {
    if let Err(error) = run_app().await {
        print_error(&error);
        std::process::exit(1);
    }
}

async fn run_app() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Err(message) = cli.validate() {
        use clap::{error::ErrorKind, CommandFactory};
        Cli::command()
            .error(ErrorKind::ValueValidation, message)
            .exit();
    }
    if let Some(path) = &cli.check_one {
        return run_check_one(&cli, path).await;
    }
    run_app_with_cancellation(cli, pipeline::run, tokio::signal::ctrl_c()).await
}

async fn run_check_one(cli: &Cli, path: &str) -> anyhow::Result<()> {
    use anyhow::Context;

    let contents = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("не удалось прочитать файл диагностики: {path}"))?;
    let links: Vec<_> = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    anyhow::ensure!(
        links.len() == 1,
        "--check-one ожидает ровно один URI прокси в файле (найдено: {})",
        links.len()
    );

    let mut options =
        diagnose::DiagnosticOptions::new(pipeline::resolve_default(&cli.core), &cli.workdir);
    options.base_port = cli.lport;
    options.start_timeout = std::time::Duration::from_secs_f64(cli.core_start_timeout);
    options.no_xray_download = cli.no_xray_download;
    options.no_hysteria1_download = cli.no_hysteria1_download;
    options.speed_url = cli.speed_url.clone();
    options.connect_timeout_s = cli.speed_connect_timeout;
    options.speed_timeout_s = cli.speed_timeout;
    options.max_size_mb = cli.speed_max_mb;
    options.min_speed_kbs = cli.min_kb;
    options.speed_probes = cli.speed_probes;

    let report = diagnose::diagnose_link(links[0], options).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if let Some(failure) = report.failure {
        anyhow::bail!("диагностика не пройдена: {failure:?}");
    }
    Ok(())
}

async fn run_app_with_cancellation<F, Fut, S>(
    cli: Cli,
    run_pipeline: F,
    signal: S,
) -> anyhow::Result<()>
where
    F: FnOnce(Cli) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Summary>>,
    S: std::future::Future<Output = std::io::Result<()>>,
{
    let alive_path = PathBuf::from(&cli.output);
    let previous_alive = read_previous_alive(&alive_path)?;
    match run_with_cancellation(run_pipeline(cli), signal).await? {
        RunOutcome::Completed(summary) => print_summary(&summary),
        RunOutcome::Cancelled => handle_cancelled_run(&alive_path, previous_alive)?,
    }
    Ok(())
}

fn handle_cancelled_run(alive_path: &Path, previous_alive: Option<Vec<u8>>) -> anyhow::Result<()> {
    restore_cancelled_alive(alive_path, previous_alive)?;
    println!("\nОтменено по Ctrl-C.");
    Ok(())
}

fn read_previous_alive(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn print_error(error: &anyhow::Error) {
    let stderr = std::io::stderr();
    write_error(&mut stderr.lock(), error);
}

fn write_error(writer: &mut impl std::io::Write, error: &anyhow::Error) {
    let mut causes = error.chain();
    if let Some(context) = causes.next() {
        let _ = writeln!(
            writer,
            "\n{} {}",
            "✖ Ошибка".red().bold(),
            context.to_string().red()
        );
    }
    for cause in causes {
        let _ = writeln!(
            writer,
            "  {} {}",
            "└─".yellow().bold(),
            cause.to_string().yellow()
        );
    }
}

fn restore_cancelled_alive(path: &Path, previous: Option<Vec<u8>>) -> anyhow::Result<()> {
    match previous {
        Some(bytes) => output::write_bytes_atomic(path, &bytes, None),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        },
    }
}

enum RunOutcome {
    Completed(Box<Summary>),
    Cancelled,
}

async fn run_with_cancellation<R, C>(run: R, cancellation: C) -> anyhow::Result<RunOutcome>
where
    R: std::future::Future<Output = anyhow::Result<Summary>>,
    C: std::future::Future<Output = std::io::Result<()>>,
{
    tokio::select! {
        result = run => result.map(|summary| RunOutcome::Completed(Box::new(summary))),
        signal = cancellation => {
            signal?;
            Ok(RunOutcome::Cancelled)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{fmt_dur, fmt_speed, percentage, print_summary, Summary};
    use super::{pipeline, run_with_cancellation};
    use crate::parse;
    use clap::Parser;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn write_error_formats_root_cause_and_context_chain() {
        let error = anyhow::anyhow!("socket closed").context("request failed");
        let mut output = Vec::new();

        super::write_error(&mut output, &error);

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("request failed"), "{output:?}");
        assert!(output.contains("socket closed"), "{output:?}");
        assert!(output.find("request failed").unwrap() < output.find("socket closed").unwrap());
    }

    #[test]
    fn write_error_formats_single_error_without_a_cause_line() {
        let error = anyhow::anyhow!("standalone failure");
        let mut output = Vec::new();

        super::write_error(&mut output, &error);

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("standalone failure"), "{output:?}");
        assert_eq!(output.matches("└─").count(), 0, "{output:?}");
    }

    #[test]
    fn print_error_writes_to_standard_error() {
        super::print_error(&anyhow::anyhow!("fixture failure"));
    }

    #[tokio::test]
    async fn cancellation_signal_returns_distinct_outcome_and_drops_pipeline() {
        struct DropFlag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = DropFlag(std::sync::Arc::clone(&dropped));
        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
        signal_tx.send(Ok(())).unwrap();

        let outcome = run_with_cancellation(
            async move {
                let _flag = flag;
                std::future::pending::<anyhow::Result<Summary>>().await
            },
            async move { signal_rx.await.unwrap() },
        )
        .await
        .unwrap();

        assert!(matches!(outcome, super::RunOutcome::Cancelled));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn run_app_cancellation_restores_previous_alive_file() {
        let temp = TempDir::new();
        let alive = temp.write("alive.txt", "previous result\n");
        let cli = temp.cli(None, &[]);
        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
        signal_tx.send(Ok(())).unwrap();

        super::run_app_with_cancellation(
            cli,
            |_| async { std::future::pending::<anyhow::Result<Summary>>().await },
            async move { signal_rx.await.unwrap() },
        )
        .await
        .unwrap();

        assert_eq!(fs::read(alive).unwrap(), b"previous result\n");
    }

    #[tokio::test]
    async fn run_app_returns_pipeline_error_without_changing_previous_alive_file() {
        let temp = TempDir::new();
        let alive = temp.write("alive.txt", "previous result\n");
        let cli = temp.cli(None, &[]);

        let error = super::run_app_with_cancellation(
            cli,
            |_| async { anyhow::bail!("local pipeline failure") },
            std::future::pending::<std::io::Result<()>>(),
        )
        .await
        .unwrap_err();

        assert_eq!(error.to_string(), "local pipeline failure");
        assert_eq!(fs::read(alive).unwrap(), b"previous result\n");
    }

    #[tokio::test]
    async fn completed_pipeline_returns_its_summary() {
        let expected = Summary {
            links: 7,
            unique: 3,
            alive: 2,
            ..Summary::default()
        };

        let outcome = run_with_cancellation(
            async { Ok(expected) },
            std::future::pending::<std::io::Result<()>>(),
        )
        .await
        .unwrap();

        match outcome {
            super::RunOutcome::Completed(summary) => {
                assert_eq!(summary.links, 7);
                assert_eq!(summary.unique, 3);
                assert_eq!(summary.alive, 2);
            }
            super::RunOutcome::Cancelled => panic!("pipeline completion was lost"),
        }
    }

    #[tokio::test]
    async fn pipeline_error_is_returned_when_it_finishes_first() {
        let result = run_with_cancellation(
            async { anyhow::bail!("pipeline failed") },
            std::future::pending::<std::io::Result<()>>(),
        )
        .await;

        let error = result.err().unwrap();
        assert_eq!(error.to_string(), "pipeline failed");
    }

    #[tokio::test]
    async fn cancellation_signal_error_is_propagated() {
        let result =
            run_with_cancellation(std::future::pending::<anyhow::Result<Summary>>(), async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "signal handler failed",
                ))
            })
            .await;

        let error = result.err().unwrap();
        assert_eq!(error.to_string(), "signal handler failed");
    }

    #[test]
    fn cancellation_restores_prior_alive_file_or_removes_new_partial_file() {
        let temp = TempDir::new();
        let existing = temp.path().join("alive.txt");
        fs::write(&existing, b"previous result\n").unwrap();
        let previous = Some(fs::read(&existing).unwrap());
        fs::write(&existing, b"partial tcp result\n").unwrap();

        super::restore_cancelled_alive(&existing, previous).unwrap();
        assert_eq!(fs::read(&existing).unwrap(), b"previous result\n");

        let new_file = temp.path().join("new-alive.txt");
        fs::write(&new_file, b"partial tcp result\n").unwrap();
        super::restore_cancelled_alive(&new_file, None).unwrap();
        assert!(!new_file.exists());
        super::restore_cancelled_alive(&new_file, None).unwrap();
    }

    #[test]
    fn cancelled_run_restores_previous_alive_file() {
        let temp = TempDir::new();
        let alive = temp.write("alive.txt", "partial result\n");

        super::handle_cancelled_run(&alive, Some(b"previous result\n".to_vec())).unwrap();

        assert_eq!(fs::read(alive).unwrap(), b"previous result\n");
    }

    #[test]
    fn cancellation_restore_propagates_file_removal_errors() {
        let temp = TempDir::new();

        let error = super::restore_cancelled_alive(temp.path(), None).unwrap_err();

        assert!(error.downcast_ref::<std::io::Error>().is_some());
    }

    static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

    fn serve_subscription(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        });
        format!("http://{address}/subscription?token=personal-secret")
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
        bytes.extend_from_slice(value);
        bytes
    }

    fn protobuf_uint(field: u64, value: u64) -> Vec<u8> {
        let mut bytes = protobuf_varint(field << 3);
        bytes.extend(protobuf_varint(value));
        bytes
    }

    fn geoip_fixture(entries: &[(&str, [u8; 4])]) -> Vec<u8> {
        let mut database = Vec::new();
        for (country, address) in entries {
            let mut cidr = protobuf_bytes(1, address);
            cidr.extend(protobuf_uint(2, 32));
            let mut entry = protobuf_bytes(1, country.as_bytes());
            entry.extend(protobuf_bytes(2, &cidr));
            // GeoIP cache validation requires a non-trivial file size; the
            // parser safely skips this valid unknown protobuf field.
            entry.extend(protobuf_bytes(9, &vec![0; 1100]));
            database.extend(protobuf_bytes(1, &entry));
        }
        for _ in entries.len()..10 {
            database.extend(protobuf_bytes(1, &[]));
        }
        database
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("proxy-rs-main-tests-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create temporary test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).expect("write test fixture");
            path
        }

        fn cli(&self, file: Option<&Path>, extra: &[&str]) -> crate::cli::Cli {
            let sources = self.0.join("missing-sources.json");
            let mut args = vec![
                "proxy-rs".to_string(),
                "--sources".to_string(),
                sources.display().to_string(),
                "--output".to_string(),
                self.0.join("alive.txt").display().to_string(),
                "--raw-output".to_string(),
                self.0.join("raw.txt").display().to_string(),
                "--parsed-output".to_string(),
                self.0.join("parsed.txt").display().to_string(),
                "--good-output".to_string(),
                self.0.join("good.txt").display().to_string(),
                "--no-geoip".to_string(),
                "--no-tcp-ping".to_string(),
                "--no-speed".to_string(),
            ];
            if let Some(file) = file {
                args.extend(["--file".to_string(), file.display().to_string()]);
            }
            args.extend(extra.iter().map(|arg| (*arg).to_string()));
            crate::cli::Cli::try_parse_from(args).expect("parse test CLI arguments")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn duration_switches_from_seconds_to_minutes() {
        assert_eq!(fmt_dur(59.0), "59.0s");
        assert_eq!(fmt_dur(60.0), "1m 0s");
        assert_eq!(fmt_dur(125.0), "2m 5s");
    }

    #[test]
    fn speed_switches_from_kilobytes_to_megabytes() {
        assert_eq!(fmt_speed(0.0), "0.0 KB/s");
        assert_eq!(fmt_speed(1024.0), "1.0 MB/s");
    }

    #[test]
    fn percentage_handles_zero_and_regular_totals() {
        assert_eq!(percentage(1, 0), 0.0);
        assert_eq!(percentage(1, 4), 25.0);
        assert_eq!(percentage(4, 4), 100.0);
    }

    #[test]
    fn max_ping_keeps_inclusive_and_unknown_pings_only_when_unlimited() {
        let links = vec![
            "vless://01234567-89ab-cdef-0123-456789abcdef@fast.example:443#fast".to_string(),
            "vless://01234567-89ab-cdef-0123-456789abcdef@slow.example:443#slow".to_string(),
            "vless://01234567-89ab-cdef-0123-456789abcdef@unknown.example:443#unknown".to_string(),
        ];
        let (mut proxies, _) = parse::parse_all(links);
        proxies[0].ping = Some(25);
        proxies[1].ping = Some(26);
        proxies[2].ping = None;

        let rejected = pipeline::retain_within_max_ping(&mut proxies, 25);

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].host, "fast.example");
        assert_eq!(
            rejected,
            [
                "vless://01234567-89ab-cdef-0123-456789abcdef@slow.example:443",
                "vless://01234567-89ab-cdef-0123-456789abcdef@unknown.example:443",
            ]
        );

        let mut unlimited = parse::parse_all(vec![
            "vless://01234567-89ab-cdef-0123-456789abcdef@unknown.example:443#unknown".to_string(),
        ])
        .0;
        assert!(pipeline::retain_within_max_ping(&mut unlimited, 0).is_empty());
        assert_eq!(unlimited.len(), 1);
    }

    #[test]
    fn max_ping_keeps_hysteria_proxies_without_tcp_measurements() {
        let links = vec![
            "hysteria://secret@h1.example:443?protocol=udp&upmbps=10&downmbps=50#h1".to_string(),
            "hysteria2://secret@h2.example:443?insecure=1#h2".to_string(),
            "vless://01234567-89ab-cdef-0123-456789abcdef@unknown.example:443#unknown".to_string(),
        ];
        let (mut proxies, stats) = parse::parse_all(links);
        assert_eq!(stats.parsed, 3);

        let rejected = pipeline::retain_within_max_ping(&mut proxies, 25);

        assert_eq!(proxies.len(), 2);
        assert!(proxies
            .iter()
            .all(|proxy| matches!(proxy.proto, "hysteria" | "hysteria2")));
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0].contains("unknown.example"));
    }

    #[test]
    fn protocol_and_country_filters_are_case_insensitive_and_composable() {
        let links = vec![
            "vless://01234567-89ab-cdef-0123-456789abcdef@us.example:443#us".to_string(),
            "trojan://password@de.example:443#de".to_string(),
            "vless://01234567-89ab-cdef-0123-456789abcdef@de.example:443#vless-de".to_string(),
        ];
        let (mut proxies, _) = parse::parse_all(links);
        for proxy in &mut proxies {
            proxy.country = if proxy.host.starts_with("us") {
                "US"
            } else {
                "DE"
            }
            .into();
        }

        let removed = pipeline::filter_proxy_protocol_country(
            &mut proxies,
            &["VLESS".into()],
            &["de".into()],
        );

        assert_eq!(removed, 2);
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].host, "de.example");
        assert_eq!(proxies[0].proto, "vless");
    }

    #[test]
    fn only_new_filter_removes_existing_outbound_keys_and_keeps_new_ones() {
        let links = vec![
            "vless://01234567-89ab-cdef-0123-456789abcdef@known.example:443#old".to_string(),
            "vless://01234567-89ab-cdef-0123-456789abcdef@fresh.example:443#new".to_string(),
        ];
        let (mut proxies, _) = parse::parse_all(links);
        let existing = "vless://01234567-89ab-cdef-0123-456789abcdef@known.example:443#old\n";

        assert_eq!(pipeline::filter_previously_seen(&mut proxies, existing), 1);
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].host, "fresh.example");
    }

    #[test]
    fn default_asset_paths_are_next_to_the_running_executable() {
        let exe = std::env::current_exe().unwrap();
        let exe_dir = exe.parent().unwrap();

        assert_eq!(
            pipeline::default_geoip_path().unwrap(),
            exe_dir.join("geoip.dat")
        );
        assert_eq!(
            pipeline::default_core_path().unwrap(),
            exe_dir.join(crate::xray::core_bin_name())
        );
    }

    #[test]
    fn resolve_default_prefers_existing_path_and_falls_back_when_missing() {
        let temp = TempDir::new();
        let present = temp.write("present.dat", "fixture");

        assert_eq!(
            pipeline::resolve_default(present.to_str().unwrap()),
            present
        );
        let missing = temp.path().join("missing.dat");
        assert_eq!(
            pipeline::resolve_default(missing.to_str().unwrap()),
            missing
        );
    }

    #[test]
    fn resolve_default_finds_assets_beside_the_test_executable() {
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let name = format!(
            "proxy-rs-main-path-test-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        );
        let sibling = exe_dir.join(&name);
        fs::write(&sibling, "fixture").unwrap();

        let resolved = pipeline::resolve_default(&name);

        let _ = fs::remove_file(&sibling);
        assert_eq!(resolved, sibling);
    }

    #[test]
    fn resolve_default_searches_executable_then_bin_then_original_path() {
        let temp = TempDir::new();
        let executable_dir = temp.path().join("exe");
        let bin_dir = temp.path().join("bin");
        fs::create_dir(&executable_dir).unwrap();
        fs::create_dir(&bin_dir).unwrap();
        let name = "asset.dat";
        let original = PathBuf::from(name);
        let sibling = executable_dir.join(name);
        let bundled = bin_dir.join(name);
        fs::write(&sibling, "executable asset").unwrap();
        fs::write(&bundled, "bundled asset").unwrap();

        assert_eq!(
            pipeline::resolve_default_from(
                &original,
                Some(&executable_dir.join("proxy-rs")),
                &bin_dir
            ),
            sibling
        );

        fs::remove_file(&sibling).unwrap();
        assert_eq!(
            pipeline::resolve_default_from(&original, None, &bin_dir),
            bundled
        );

        fs::remove_file(&bundled).unwrap();
        assert_eq!(
            pipeline::resolve_default_from(&original, None, &bin_dir),
            original
        );
    }

    #[tokio::test]
    async fn run_processes_direct_link_file_without_geoip_tcp_or_xray() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            "# local fixture\nvless://01234567-89ab-cdef-0123-456789abcdef@proxy.example:443#test-node\n",
        );

        let summary = pipeline::run(temp.cli(Some(&links), &[])).await.unwrap();

        assert_eq!(summary.fetch_sources, 0);
        assert_eq!(summary.fetch_loaded, 0);
        assert_eq!(summary.links, 1);
        assert_eq!(summary.unique, 1);
        assert_eq!(summary.alive, 1);
        assert_eq!(summary.good, 0);
        assert!(!summary.geo);
        assert!(!summary.tcp_enabled);
        assert!(!summary.speed_enabled);
        assert_eq!(
            fs::read_to_string(temp.path().join("parsed.txt")).unwrap(),
            fs::read_to_string(temp.path().join("alive.txt")).unwrap()
        );
        assert!(fs::read_to_string(temp.path().join("alive.txt"))
            .unwrap()
            .contains("proxy.example"));
    }

    #[tokio::test]
    async fn checkpoint_resume_skips_source_loading_and_restores_completed_results() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            "vless://01234567-89ab-cdef-0123-456789abcdef@proxy.example:443#resumed\n",
        );
        let checkpoint = temp.path().join("run.checkpoint.json");
        let checkpoint_arg = checkpoint.to_string_lossy().to_string();

        let first = pipeline::run(temp.cli(Some(&links), &["--checkpoint", &checkpoint_arg]))
            .await
            .unwrap();
        assert_eq!(first.unique, 1);
        assert!(checkpoint.exists());

        let resumed = pipeline::run(temp.cli(None, &["--checkpoint", &checkpoint_arg, "--resume"]))
            .await
            .unwrap();
        assert_eq!(resumed.links, 1);
        assert_eq!(resumed.unique, 1);
        assert_eq!(
            fs::read_to_string(temp.path().join("alive.txt")).unwrap(),
            fs::read_to_string(temp.path().join("parsed.txt")).unwrap()
        );
    }

    #[tokio::test]
    async fn source_quality_report_tracks_valid_and_duplicate_links_without_leaking_url_secrets() {
        let temp = TempDir::new();
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let url = serve_subscription(format!(
            "vless://{id}@proxy.example:443#first\nvless://{id}@proxy.example:443#duplicate\n"
        ));
        let sources = temp.write("sources.json", &format!(r#"{{"3":["{url}"]}}"#));
        let report_path = temp.path().join("source-report.json");
        let mut cli = temp.cli(
            None,
            &[
                "--source-report",
                report_path.to_str().unwrap(),
                "--no-fetch-cache",
            ],
        );
        cli.sources = sources.display().to_string();

        pipeline::run(cli).await.unwrap();

        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
        assert_eq!(report["sources"][0]["status"], "parsed");
        assert_eq!(report["sources"][0]["counts"]["fetched"], 1);
        assert_eq!(report["sources"][0]["counts"]["valid"], 2);
        assert_eq!(report["sources"][0]["counts"]["duplicate"], 1);
        let json = report.to_string();
        assert!(!json.contains("personal-secret"));
        assert!(!json.contains("subscription"));
    }

    #[tokio::test]
    async fn run_reports_parse_statistics_and_applies_shuffle_and_limit() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            concat!(
                "vless://01234567-89ab-cdef-0123-456789abcdef@first.example:443#first\n",
                "vless://01234567-89ab-cdef-0123-456789abcdef@second.example:8443#second\n",
                "vless://01234567-89ab-cdef-0123-456789abcdef@first.example:443#duplicate\n",
                "ssr://unsupported\n",
                "vless://bad@broken.example:443#invalid\n"
            ),
        );

        let summary = pipeline::run(temp.cli(Some(&links), &["--shuffle", "--limit", "1"]))
            .await
            .unwrap();

        assert_eq!(summary.links, 5);
        assert_eq!(summary.unique, 2);
        assert_eq!(summary.duplicates, 1);
        assert_eq!(summary.unsupported, 1);
        assert_eq!(summary.invalid, 1);
        assert_eq!(summary.alive, 1);
        let parsed = fs::read_to_string(temp.path().join("parsed.txt")).unwrap();
        assert_eq!(parsed.lines().count(), 1);
    }

    #[tokio::test]
    async fn run_keeps_a_proxy_reachable_on_a_local_tcp_listener() {
        let temp = TempDir::new();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let links = temp.write(
            "links.txt",
            &format!(
                "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:{port}#local-listener\n"
            ),
        );
        let mut cli = temp.cli(Some(&links), &[]);
        cli.no_tcp_ping = false;
        cli.tcp_timeout = 1.0;
        cli.tcp_retries = 1;
        cli.tcp_concurrency = 1;
        cli.dead = Some(temp.path().join("dead.txt").display().to_string());

        let summary = pipeline::run(cli).await.unwrap();

        assert_eq!(summary.tcp_total, 1);
        assert_eq!(summary.tcp_alive, 1);
        assert_eq!(summary.alive, 1);
        assert_eq!(summary.dead_file.as_ref().unwrap().1, 0);
        assert!(fs::read_to_string(temp.path().join("alive.txt"))
            .unwrap()
            .contains("127.0.0.1"));
        assert_eq!(
            fs::read_to_string(temp.path().join("dead.txt")).unwrap(),
            ""
        );
        drop(listener);
    }

    #[tokio::test]
    async fn run_returns_summary_when_local_tcp_prefilter_finds_no_alive_proxy() {
        let temp = TempDir::new();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let links = temp.write(
            "links.txt",
            &format!(
                "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:{port}#closed-local-port\n"
            ),
        );
        let mut cli = temp.cli(Some(&links), &[]);
        cli.no_tcp_ping = false;
        cli.tcp_timeout = 0.2;
        cli.tcp_retries = 1;
        cli.tcp_concurrency = 1;
        cli.dead = Some(temp.path().join("dead.txt").display().to_string());

        let summary = pipeline::run(cli).await.unwrap();

        assert_eq!(summary.tcp_total, 1);
        assert_eq!(summary.tcp_alive, 0);
        assert_eq!(summary.alive, 0);
        assert!(summary.dead_file.is_some());
        assert!(fs::read_to_string(temp.path().join("dead.txt"))
            .unwrap()
            .contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn run_keeps_local_tcp_listener_and_writes_closed_proxy_to_dead_output() {
        let temp = TempDir::new();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let live_port = listener.local_addr().unwrap().port();
        let accept = std::thread::spawn(move || {
            let _ = listener.accept().unwrap();
        });
        let closed_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);
        let links = temp.write(
            "links.txt",
            &format!(
                "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:{live_port}#live-local\n\
                 vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:{closed_port}#closed-local\n"
            ),
        );
        let json_path = temp.path().join("tcp-results.json");
        let json_arg = json_path.to_string_lossy().to_string();
        let mut cli = temp.cli(Some(&links), &["--json-output", &json_arg]);
        cli.no_tcp_ping = false;
        cli.tcp_timeout = 0.2;
        cli.tcp_retries = 0;
        cli.tcp_concurrency = 1;
        cli.dead = Some(temp.path().join("dead.txt").display().to_string());

        let summary = pipeline::run(cli).await.unwrap();
        accept.join().unwrap();

        assert_eq!(summary.tcp_total, 2);
        assert_eq!(summary.tcp_alive, 1);
        assert_eq!(summary.alive, 1);
        let alive = fs::read_to_string(temp.path().join("alive.txt")).unwrap();
        assert!(alive.contains(&format!("127.0.0.1:{live_port}")));
        assert!(!alive.contains(&closed_port.to_string()));
        let dead = fs::read_to_string(temp.path().join("dead.txt")).unwrap();
        assert!(dead.contains(&format!("127.0.0.1:{closed_port}")));
        assert!(!dead.contains(&format!("127.0.0.1:{live_port}")));
        let json: serde_json::Value =
            serde_json::from_slice(&fs::read(json_path).unwrap()).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["server"], "127.0.0.1");
    }

    #[tokio::test]
    async fn run_propagates_local_geoip_download_http_error() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            "vless://01234567-89ab-cdef-0123-456789abcdef@proxy.example:443#geoip-error\n",
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        });
        let database = temp.path().join("missing-geoip.dat");
        let mut cli = temp.cli(Some(&links), &[]);
        cli.no_geoip = false;
        cli.geoip_db = Some(database.display().to_string());
        cli.geoip_url = format!("http://{address}/geoip.dat");

        let error = pipeline::run(cli).await.unwrap_err();

        assert!(format!("{error:#}").contains("503"), "{error:#}");
    }

    #[tokio::test]
    async fn run_returns_missing_xray_error_when_speed_checks_are_enabled_offline() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            "vless://01234567-89ab-cdef-0123-456789abcdef@proxy.example:443#xray-error\n",
        );
        let mut cli = temp.cli(Some(&links), &[]);
        cli.no_speed = false;
        cli.no_xray_download = true;
        cli.core = temp.path().join("missing-xray").display().to_string();

        let error = pipeline::run(cli).await.unwrap_err();

        assert!(
            error.to_string().contains("не найдено рабочее ядро xray"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn run_rejects_when_every_local_subscription_fetch_fails() {
        let temp = TempDir::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        });
        let url = format!("http://{address}/feed");
        let cli = temp.cli(
            None,
            &["--url", &url, "--fetch-retries", "0", "--no-fetch-cache"],
        );

        let error = pipeline::run(cli).await.unwrap_err();

        assert!(error
            .to_string()
            .contains("не удалось загрузить ни одного источника"));
    }

    #[tokio::test]
    async fn run_stops_when_selected_sources_and_direct_links_are_empty() {
        let temp = TempDir::new();
        let sources = temp.write("sources.json", r#"{"3":[]}"#);
        let mut cli = temp.cli(None, &["--set", "3"]);
        cli.sources = sources.display().to_string();

        let error = pipeline::run(cli).await.unwrap_err();

        assert!(error.to_string().contains("нет источников для загрузки"));
    }

    #[tokio::test]
    async fn run_returns_source_file_errors_before_pipeline_starts() {
        let temp = TempDir::new();
        let malformed = temp.write("sources.json", "{");
        let mut cli = temp.cli(None, &[]);
        cli.sources = malformed.display().to_string();

        let error = pipeline::run(cli).await.unwrap_err();

        assert!(error.to_string().contains("битый JSON"));
    }

    #[tokio::test]
    async fn run_rejects_files_without_supported_proxy_links() {
        let temp = TempDir::new();
        let links = temp.write("links.txt", "not a proxy link\nssr://unsupported\n");

        let error = pipeline::run(temp.cli(Some(&links), &[]))
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("не найдено ни одного подходящего прокси"));
    }

    #[tokio::test]
    async fn run_propagates_output_write_errors() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            "vless://01234567-89ab-cdef-0123-456789abcdef@proxy.example:443#test-node\n",
        );
        let mut cli = temp.cli(Some(&links), &[]);
        cli.parsed_output = temp
            .path()
            .join("missing-directory/parsed.txt")
            .display()
            .to_string();

        let error = pipeline::run(cli).await.unwrap_err();

        assert!(error.to_string().contains("не удалось создать"));
    }

    #[tokio::test]
    async fn run_resumes_from_fetched_checkpoint_without_loading_sources() {
        let temp = TempDir::new();
        let checkpoint_path = temp.path().join("fetched.checkpoint.json");
        let checkpoint_arg = checkpoint_path.to_string_lossy().to_string();
        let link = "vless://01234567-89ab-cdef-0123-456789abcdef@checkpoint.example:443#restored";
        let mut checkpoint = crate::checkpoint::Checkpoint::new();
        checkpoint.raw_links.push(link.to_string());
        checkpoint.save(&checkpoint_path).unwrap();

        let summary = pipeline::run(temp.cli(None, &["--checkpoint", &checkpoint_arg, "--resume"]))
            .await
            .unwrap();

        assert_eq!(summary.links, 1);
        assert_eq!(summary.unique, 1);
        assert!(fs::read_to_string(temp.path().join("alive.txt"))
            .unwrap()
            .contains("checkpoint.example"));
        let saved = crate::checkpoint::Checkpoint::load(&checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(saved.stage, crate::checkpoint::PipelineStage::Complete);
    }

    #[tokio::test]
    async fn run_rejects_resume_checkpoint_before_parse_stage() {
        let temp = TempDir::new();
        let checkpoint_path = temp.path().join("empty.checkpoint.json");
        crate::checkpoint::Checkpoint::new()
            .save(&checkpoint_path)
            .unwrap();
        let checkpoint_arg = checkpoint_path.to_string_lossy().to_string();

        let error = pipeline::run(temp.cli(None, &["--checkpoint", &checkpoint_arg, "--resume"]))
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("не содержит завершённый этап парсинга"));
    }

    #[tokio::test]
    async fn run_writes_safe_json_and_checkpoint_and_skips_empty_clash_output() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            "vless://01234567-89ab-cdef-0123-456789abcdef@proxy.example:443#credential-free-name\n",
        );
        let json_path = temp.path().join("proxies.json");
        let checkpoint_path = temp.path().join("run.checkpoint.json");
        let clash_path = temp.path().join("clash.yaml");
        let json_arg = json_path.to_string_lossy().to_string();
        let checkpoint_arg = checkpoint_path.to_string_lossy().to_string();
        let clash_arg = clash_path.to_string_lossy().to_string();

        let summary = pipeline::run(temp.cli(
            Some(&links),
            &[
                "--json-output",
                &json_arg,
                "--checkpoint",
                &checkpoint_arg,
                "--clash",
                &clash_arg,
            ],
        ))
        .await
        .unwrap();

        let proxies: serde_json::Value =
            serde_json::from_slice(&fs::read(json_path).unwrap()).unwrap();
        assert_eq!(proxies.as_array().unwrap().len(), 1);
        assert_eq!(proxies[0]["server"], "proxy.example");
        assert!(!proxies.to_string().contains("01234567-89ab-cdef"));
        assert_eq!(summary.alive, 1);
        assert_eq!(summary.good, 0);
        assert!(!clash_path.exists());
        assert_eq!(
            crate::checkpoint::Checkpoint::load(checkpoint_path)
                .unwrap()
                .unwrap()
                .stage,
            crate::checkpoint::PipelineStage::Complete
        );
    }

    #[tokio::test]
    async fn run_records_fetch_failure_when_direct_links_can_continue_pipeline() {
        let temp = TempDir::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        });
        let links = temp.write(
            "links.txt",
            "vless://01234567-89ab-cdef-0123-456789abcdef@local.example:443#direct\n",
        );
        let report_path = temp.path().join("source-report.json");
        let report_arg = report_path.to_string_lossy().to_string();
        let url = format!("http://{address}/feed?token=private-value");

        let summary = pipeline::run(temp.cli(
            Some(&links),
            &[
                "--url",
                &url,
                "--fetch-retries",
                "0",
                "--no-fetch-cache",
                "--source-report",
                &report_arg,
            ],
        ))
        .await
        .unwrap();

        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
        assert_eq!(summary.fetch_failed, 1);
        assert_eq!(summary.alive, 1);
        assert_eq!(report["sources"][0]["status"], "fetch_failed");
        assert_eq!(report["sources"][0]["fetch_failure"], "http_503");
        assert!(!report.to_string().contains("private-value"));
    }

    #[tokio::test]
    async fn run_assigns_geoip_from_local_database_without_dns_or_network() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            "vless://01234567-89ab-cdef-0123-456789abcdef@8.8.8.8:443#geo-fixture\n",
        );
        let database = temp.write("geoip.dat", "");
        fs::write(&database, geoip_fixture(&[("US", [8, 8, 8, 8])])).unwrap();
        let db_arg = database.to_string_lossy().to_string();
        let mut cli = temp.cli(Some(&links), &[]);
        cli.no_geoip = false;
        cli.geoip_db = Some(db_arg);
        cli.geoip_url = "http://127.0.0.1:1/geoip.dat".into();

        let summary = pipeline::run(cli).await.unwrap();

        assert!(summary.geo);
        assert_eq!(summary.geo_countries, 1);
        assert_eq!(summary.alive, 1);
        let output = fs::read_to_string(temp.path().join("alive.txt")).unwrap();
        assert!(output.contains("#[US] - 001"), "{output}");
    }

    #[tokio::test]
    async fn run_applies_only_new_protocol_and_geoip_country_filters_together() {
        let temp = TempDir::new();
        let links = temp.write(
            "links.txt",
            concat!(
                "vless://01234567-89ab-cdef-0123-456789abcdef@8.8.8.8:443#known\n",
                "vless://01234567-89ab-cdef-0123-456789abcdef@9.9.9.9:443#new-us\n",
                "trojan://fixture-password@1.1.1.1:443#wrong-protocol\n",
                "vless://01234567-89ab-cdef-0123-456789abcdef@4.4.4.4:443#wrong-country\n",
            ),
        );
        let database = temp.write("geoip.dat", "");
        fs::write(
            &database,
            geoip_fixture(&[
                ("US", [8, 8, 8, 8]),
                ("US", [9, 9, 9, 9]),
                ("US", [1, 1, 1, 1]),
                ("AU", [4, 4, 4, 4]),
            ]),
        )
        .unwrap();
        let db_arg = database.to_string_lossy().to_string();
        let existing = "vless://01234567-89ab-cdef-0123-456789abcdef@8.8.8.8:443#already-present\n";
        fs::write(temp.path().join("alive.txt"), existing).unwrap();
        let mut cli = temp.cli(
            Some(&links),
            &["--only-new", "--protocol", "VLESS", "--country", "us"],
        );
        cli.no_geoip = false;
        cli.geoip_db = Some(db_arg);
        cli.geoip_url = "http://127.0.0.1:1/geoip.dat".into();

        let summary = pipeline::run(cli).await.unwrap();

        assert_eq!(summary.unique, 4);
        assert_eq!(summary.alive, 1);
        let output = fs::read_to_string(temp.path().join("alive.txt")).unwrap();
        assert!(output.contains("9.9.9.9"), "{output}");
        assert!(!output.contains("8.8.8.8"), "{output}");
        assert!(!output.contains("1.1.1.1"), "{output}");
    }

    fn checkpoint_at_stage(temp: &TempDir, stage: crate::checkpoint::PipelineStage) -> PathBuf {
        let link = "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:9#restored-stage";
        let mut proxy = parse::parse_link(link).unwrap();
        proxy.country = "DE".into();
        proxy.display = "[DE] - 001".into();
        proxy.ping = Some(17);
        proxy.speed_kbs = 64.0;

        let mut checkpoint = crate::checkpoint::Checkpoint::new();
        checkpoint.parse_stats.links = 1;
        checkpoint.parse_stats.parsed = 1;
        checkpoint.record_stage(
            stage,
            vec![link.to_string()],
            vec![crate::checkpoint::ProxySnapshot::from_proxy(&proxy)],
        );
        let path = temp.path().join(format!("{stage:?}.checkpoint.json"));
        checkpoint.save(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn run_resumes_from_tcp_checkpoint_without_rechecking_tcp_or_xray() {
        let temp = TempDir::new();
        let checkpoint = checkpoint_at_stage(&temp, crate::checkpoint::PipelineStage::TcpPing);
        let checkpoint_arg = checkpoint.to_string_lossy().to_string();
        let mut cli = temp.cli(None, &["--checkpoint", &checkpoint_arg, "--resume"]);
        cli.no_tcp_ping = false;

        let summary = pipeline::run(cli).await.unwrap();

        assert_eq!(summary.alive, 1);
        assert!(!summary.speed_enabled);
        assert!(fs::read_to_string(temp.path().join("alive.txt"))
            .unwrap()
            .contains("127.0.0.1:9"));
        assert_eq!(
            crate::checkpoint::Checkpoint::load(checkpoint)
                .unwrap()
                .unwrap()
                .stage,
            crate::checkpoint::PipelineStage::Complete
        );
    }

    #[tokio::test]
    async fn run_resumes_from_speed_checkpoint_without_rechecking_or_xray() {
        let temp = TempDir::new();
        let checkpoint = checkpoint_at_stage(&temp, crate::checkpoint::PipelineStage::Speed);
        let checkpoint_arg = checkpoint.to_string_lossy().to_string();
        let mut cli = temp.cli(None, &["--checkpoint", &checkpoint_arg, "--resume"]);
        cli.no_tcp_ping = false;
        cli.no_speed = false;

        let summary = pipeline::run(cli).await.unwrap();

        assert_eq!(summary.alive, 1);
        assert_eq!(summary.good, 1);
        assert_eq!(summary.speed_passed, 1);
        assert_eq!(summary.avg_kbs, 64.0);
        assert!(fs::read_to_string(temp.path().join("good.txt"))
            .unwrap()
            .contains("127.0.0.1:9"));
    }

    #[test]
    fn print_summary_covers_enabled_and_populated_sections() {
        let summary = Summary {
            fetch_sources: 2,
            fetch_loaded: 1,
            fetch_failed: 1,
            fetch_failure_examples: vec!["source failed".into()],
            links: 4,
            unique: 2,
            duplicates: 1,
            invalid: 1,
            unsupported: 1,
            geo: true,
            geo_countries: 3,
            tcp_enabled: true,
            tcp_total: 2,
            tcp_alive: 1,
            speed_enabled: true,
            speed_total: 1,
            speed_passed: 1,
            bad_outbounds: 1,
            alive: 1,
            good: 1,
            avg_kbs: 2048.0,
            median_kbs: 1024.0,
            raw_file: Some(("raw.txt".into(), 1)),
            parsed_file: Some(("parsed.txt".into(), 2)),
            alive_file: Some(("alive.txt".into(), 1)),
            good_file: Some(("good.txt".into(), 1)),
            clash_file: Some(("clash.yaml".into(), 1)),
            dead_file: Some(("dead.txt".into(), 1)),
            ..Summary::default()
        };

        print_summary(&summary);
    }

    #[test]
    fn print_summary_handles_disabled_and_empty_optional_sections() {
        print_summary(&Summary::default());
    }

    #[test]
    fn print_summary_handles_enabled_empty_tcp_and_speed_sections() {
        print_summary(&Summary {
            tcp_enabled: true,
            tcp_total: 0,
            speed_enabled: true,
            speed_total: 0,
            ..Summary::default()
        });
    }

    #[test]
    fn summary_conditions_report_only_nonzero_source_and_outbound_errors() {
        let mut summary = Summary::default();
        assert!(!super::has_fetch_failures(&summary));
        assert!(!super::has_bad_outbounds(&summary));

        summary.fetch_failed = 1;
        summary.bad_outbounds = 1;
        assert!(super::has_fetch_failures(&summary));
        assert!(super::has_bad_outbounds(&summary));
    }

    #[test]
    fn read_previous_alive_distinguishes_missing_empty_and_unreadable_paths() {
        let temp = TempDir::new();
        let missing = temp.path().join("missing-alive.txt");
        assert_eq!(super::read_previous_alive(&missing).unwrap(), None);

        let existing = temp.write("alive.txt", "");
        assert_eq!(
            super::read_previous_alive(&existing).unwrap(),
            Some(Vec::new())
        );

        let directory = temp.path().join("alive-directory");
        fs::create_dir(&directory).unwrap();
        assert!(super::read_previous_alive(&directory).is_err());
    }
}
