use crate::{parse, Summary};
use anyhow::{bail, Context, Result};
use rusqlite::{
    params, params_from_iter, types::Value, Connection, OptionalExtension, Transaction,
};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SCHEMA_VERSION: i64 = 4;
const LEGACY_RUN_IMPORT_PATH: &str = "legacy-json-run-history:v1";
pub const PAGE_SIZE: usize = 50;
pub const RUN_HISTORY_LIMIT: usize = 50;

#[derive(Clone, Debug)]
pub struct ArchiveRow {
    pub id: i64,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub country: String,
    pub status: String,
    pub ping_ms: Option<u64>,
    pub speed_kbs: Option<f64>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub seen_count: u64,
}

#[derive(Clone, Debug)]
pub struct ArchiveRecord {
    pub fingerprint: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub original_link: String,
    pub country: String,
    pub is_vpn: bool,
    pub status: String,
    pub ping_ms: Option<u64>,
    pub speed_kbs: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct ArchiveObservation {
    pub run_id: i64,
    pub checker_mode: String,
    pub checked_at: i64,
    pub outcome: String,
    pub run_summary: String,
    pub elapsed_seconds: u64,
    pub status: String,
    pub country: String,
    pub ping_ms: Option<u64>,
    pub speed_kbs: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct ArchiveDetail {
    pub row: ArchiveRow,
    pub observations: Vec<ArchiveObservation>,
    pub available_count: u64,
    pub average_ping_ms: Option<u64>,
    pub best_speed_kbs: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct RecheckTarget {
    pub id: i64,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub original_link: String,
    pub is_vpn: bool,
}

#[derive(Debug)]
pub struct ArchivePage {
    pub rows: Vec<ArchiveRow>,
    pub total: u64,
    pub has_next: bool,
    pub next_cursor: Option<(i64, i64)>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ArchiveCounts {
    pub proxies: u64,
    pub vpn: u64,
}

#[derive(Clone, Debug)]
pub struct RunHistoryEntry {
    pub id: i64,
    pub checked_at: i64,
    pub outcome: String,
    pub summary: String,
    pub elapsed_seconds: u64,
}

#[derive(Clone, Debug)]
pub struct RunHistoryRecord {
    pub checked_at: i64,
    pub checker_mode: String,
    pub outcome: String,
    pub summary: String,
    pub candidate_count: usize,
    pub alive_count: usize,
    pub elapsed_seconds: u64,
}

/// A legacy run paired with its stable identifier from the JSON run-history file.
#[derive(Clone, Debug)]
pub struct LegacyRunImport {
    pub number: u64,
    pub record: RunHistoryRecord,
}

#[derive(Deserialize)]
struct ProbeResult {
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    country: String,
    ping_ms: Option<u64>,
    #[serde(default)]
    speed_kbs: Option<f64>,
}

#[derive(Clone)]
struct Candidate {
    fingerprint: String,
    protocol: String,
    host: String,
    port: u16,
    name: String,
    original_link: String,
    country: String,
    is_vpn: bool,
    status: String,
    ping_ms: Option<u64>,
    speed_kbs: Option<f64>,
}

pub struct ArchiveStore {
    path: PathBuf,
}

impl ArchiveStore {
    pub fn initialize(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("не удалось создать папку базы данных {}", parent.display())
            })?;
        }

        let mut connection = Connection::open(&path)
            .with_context(|| format!("не удалось открыть базу данных {}", path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA cache_size = -8192;
             PRAGMA wal_autocheckpoint = 1000;
             PRAGMA journal_size_limit = 16777216;",
        )?;

        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            bail!("база данных создана более новой версией ProxySift (схема {version})");
        }
        if version == 0 {
            let transaction = connection.transaction()?;
            create_schema(&transaction)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        } else if version < SCHEMA_VERSION {
            let transaction = connection.transaction()?;
            migrate_schema(&transaction, version)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        set_private_file_permissions(&path)?;
        connection.execute_batch("PRAGMA optimize;")?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connect(&self) -> Result<Connection> {
        let connection = Connection::open(&self.path)
            .with_context(|| format!("не удалось открыть базу данных {}", self.path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA temp_store = MEMORY;
             PRAGMA cache_size = -8192;",
        )?;
        Ok(connection)
    }

    pub fn counts(&self) -> Result<ArchiveCounts> {
        let connection = self.connect()?;
        let (proxies, vpn) = connection.query_row(
            "SELECT proxy_count, vpn_count FROM archive_stats WHERE id = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        Ok(ArchiveCounts {
            proxies: proxies.max(0) as u64,
            vpn: vpn.max(0) as u64,
        })
    }

    pub fn recent_runs(&self, limit: usize) -> Result<Vec<RunHistoryEntry>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT id, checked_at, outcome, summary, elapsed_seconds
             FROM check_runs ORDER BY checked_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([usize_to_i64(limit.min(RUN_HISTORY_LIMIT))], |row| {
            let elapsed: i64 = row.get(4)?;
            Ok(RunHistoryEntry {
                id: row.get(0)?,
                checked_at: row.get(1)?,
                outcome: row.get(2)?,
                summary: row.get(3)?,
                elapsed_seconds: elapsed.max(0) as u64,
            })
        })?;
        let entries = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(entries)
    }

    pub fn record_run_state(&self, record: &RunHistoryRecord) -> Result<()> {
        let mode = normalize_checker_mode(&record.checker_mode)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        insert_run(
            &transaction,
            record.checked_at,
            &mode,
            &record.outcome,
            &record.summary,
            record.candidate_count,
            record.alive_count,
            record.elapsed_seconds,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Imports legacy JSON rows only when no equivalent run has been migrated yet.
    pub fn import_legacy_runs(&self, records: &[RunHistoryRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let mut update = transaction.prepare_cached(
            "UPDATE check_runs
             SET checker_mode = ?1, summary = ?2
             WHERE outcome = ?3 AND checked_at BETWEEN ?4 AND (?4 + 999)
               AND summary = ''",
        )?;
        let mut insert = transaction.prepare_cached(
            "INSERT INTO check_runs (
                checked_at, candidate_count, alive_count, elapsed_seconds,
                checker_mode, outcome, summary
             )
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
             WHERE NOT EXISTS (
                SELECT 1 FROM check_runs
                WHERE outcome = ?6 AND checked_at BETWEEN ?1 AND (?1 + 999)
             )",
        )?;
        for record in records {
            let mode = normalize_checker_mode(&record.checker_mode)?;
            update.execute(params![
                mode,
                record.summary,
                record.outcome,
                record.checked_at,
            ])?;
            insert.execute(params![
                record.checked_at,
                usize_to_i64(record.candidate_count),
                usize_to_i64(record.alive_count),
                u64_to_i64(record.elapsed_seconds),
                mode,
                record.outcome,
                record.summary,
            ])?;
        }
        drop(update);
        drop(insert);
        transaction.commit()?;
        Ok(())
    }

    /// Imports JSON history using the original run number as an idempotency key.
    ///
    /// Existing unkeyed rows from the previous importer are reused when a matching
    /// legacy row can be identified; otherwise a distinct row is inserted.
    pub fn import_legacy_runs_with_numbers(&self, records: &[LegacyRunImport]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let mut find_existing = transaction.prepare_cached(
            "SELECT id FROM check_runs
             WHERE legacy_import_key IS NULL AND outcome = ?1
               AND checked_at BETWEEN ?2 AND (?2 + 999)
               AND (summary = ?3 OR summary = '')
             ORDER BY CASE WHEN summary = ?3 THEN 0 ELSE 1 END, id
             LIMIT 1",
        )?;
        let mut claim_existing = transaction.prepare_cached(
            "UPDATE check_runs SET legacy_import_key = ?1
             WHERE id = ?2 AND legacy_import_key IS NULL",
        )?;
        let mut update_existing = transaction.prepare_cached(
            "UPDATE check_runs SET checker_mode = ?1, summary = ?2
             WHERE legacy_import_key = ?3 AND summary = ''",
        )?;
        let mut insert = transaction.prepare_cached(
            "INSERT INTO check_runs (
                checked_at, candidate_count, alive_count, elapsed_seconds,
                checker_mode, outcome, summary, legacy_import_key
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(legacy_import_key) DO NOTHING",
        )?;

        for item in records {
            let record = &item.record;
            let mode = normalize_checker_mode(&record.checker_mode)?;
            let import_key = format!("{LEGACY_RUN_IMPORT_PATH}:{}", item.number);
            let existing_id = find_existing
                .query_row(
                    params![record.outcome, record.checked_at, record.summary],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if let Some(id) = existing_id {
                claim_existing.execute(params![import_key, id])?;
            }
            update_existing.execute(params![mode, record.summary, import_key])?;
            insert.execute(params![
                record.checked_at,
                usize_to_i64(record.candidate_count),
                usize_to_i64(record.alive_count),
                u64_to_i64(record.elapsed_seconds),
                mode,
                record.outcome,
                record.summary,
                import_key,
            ])?;
        }
        drop(find_existing);
        drop(claim_existing);
        drop(update_existing);
        drop(insert);
        transaction.commit()?;
        Ok(())
    }

    pub fn page(
        &self,
        vpn_only: bool,
        query: &str,
        cursor: Option<(i64, i64)>,
    ) -> Result<ArchivePage> {
        let connection = self.connect()?;
        let mut conditions = vec![format!("is_vpn = {}", i64::from(vpn_only))];

        let mut count_values = Vec::<Value>::new();
        if !query.trim().is_empty() {
            let escaped = query
                .trim()
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            let pattern = format!("{escaped}%");
            count_values.push(Value::Text(pattern));
            let placeholder = format!("?{}", count_values.len());
            conditions.push(format!(
                "(protocol LIKE {placeholder} ESCAPE '\\' OR host LIKE {placeholder} ESCAPE '\\' OR name LIKE {placeholder} ESCAPE '\\' OR country LIKE {placeholder} ESCAPE '\\')"
            ));
        }
        let filter = if conditions.is_empty() {
            "1 = 1".to_string()
        } else {
            conditions.join(" AND ")
        };

        let total = if query.trim().is_empty() {
            let column = if vpn_only { "vpn_count" } else { "proxy_count" };
            let sql = format!("SELECT {column} FROM archive_stats WHERE id = 1");
            connection
                .query_row(&sql, [], |row| row.get::<_, i64>(0))?
                .max(0) as u64
        } else {
            let total_sql = format!("SELECT COUNT(*) FROM proxies WHERE {filter}");
            connection
                .query_row(&total_sql, params_from_iter(count_values.iter()), |row| {
                    row.get::<_, i64>(0)
                })?
                .max(0) as u64
        };

        let mut values = count_values;
        let mut page_filter = filter;
        if let Some((last_seen, id)) = cursor {
            let last_seen_index = values.len() + 1;
            let id_index = values.len() + 2;
            values.push(Value::Integer(last_seen));
            values.push(Value::Integer(id));
            page_filter.push_str(&format!(
                " AND (last_seen_at, id) < (?{last_seen_index}, ?{id_index})"
            ));
        }
        let limit_index = values.len() + 1;
        values.push(Value::Integer((PAGE_SIZE + 1) as i64));
        let sql = format!(
            "SELECT id, protocol, host, port, name, country, latest_status,
                    latest_ping_ms, latest_speed_kbs, first_seen_at, last_seen_at, seen_count
             FROM proxies WHERE {page_filter}
             ORDER BY last_seen_at DESC, id DESC LIMIT ?{limit_index}"
        );
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement
            .query_map(params_from_iter(values.iter()), |row| {
                let port: i64 = row.get(3)?;
                let ping: Option<i64> = row.get(7)?;
                Ok(ArchiveRow {
                    id: row.get(0)?,
                    protocol: row.get(1)?,
                    host: row.get(2)?,
                    port: port.clamp(0, u16::MAX as i64) as u16,
                    name: row.get(4)?,
                    country: row.get(5)?,
                    status: row.get(6)?,
                    ping_ms: ping.map(|value| value.max(0) as u64),
                    speed_kbs: row.get(8)?,
                    first_seen_at: row.get(9)?,
                    last_seen_at: row.get(10)?,
                    seen_count: row.get::<_, i64>(11)?.max(0) as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let has_next = rows.len() > PAGE_SIZE;
        if has_next {
            rows.pop();
        }
        let next_cursor = rows.last().map(|row| (row.last_seen_at, row.id));
        Ok(ArchivePage {
            rows,
            total,
            has_next,
            next_cursor,
        })
    }

    pub fn detail(&self, id: i64, vpn_only: bool) -> Result<Option<ArchiveDetail>> {
        let connection = self.connect()?;
        let row = connection
            .query_row(
                "SELECT id, protocol, host, port, name, country, latest_status,
                        latest_ping_ms, latest_speed_kbs, first_seen_at, last_seen_at, seen_count
                 FROM proxies WHERE id = ?1 AND is_vpn = ?2",
                params![id, i64::from(vpn_only)],
                |row| {
                    let port: i64 = row.get(3)?;
                    let ping: Option<i64> = row.get(7)?;
                    Ok(ArchiveRow {
                        id: row.get(0)?,
                        protocol: row.get(1)?,
                        host: row.get(2)?,
                        port: port.clamp(0, u16::MAX as i64) as u16,
                        name: row.get(4)?,
                        country: row.get(5)?,
                        status: row.get(6)?,
                        ping_ms: ping.map(|value| value.max(0) as u64),
                        speed_kbs: row.get(8)?,
                        first_seen_at: row.get(9)?,
                        last_seen_at: row.get(10)?,
                        seen_count: row.get::<_, i64>(11)?.max(0) as u64,
                    })
                },
            )
            .optional()?;
        let Some(row) = row else {
            return Ok(None);
        };

        let mut statement = connection.prepare(
            "SELECT runs.id, runs.checker_mode, runs.checked_at, runs.outcome,
                    runs.summary, runs.elapsed_seconds, observations.status,
                    observations.country, observations.ping_ms, observations.speed_kbs
             FROM observations
             JOIN check_runs AS runs ON runs.id = observations.run_id
             WHERE observations.proxy_id = ?1
             ORDER BY observations.observed_at DESC, runs.id DESC",
        )?;
        let observations = statement
            .query_map([id], |observation| {
                let ping: Option<i64> = observation.get(8)?;
                let elapsed: i64 = observation.get(5)?;
                Ok(ArchiveObservation {
                    run_id: observation.get(0)?,
                    checker_mode: observation.get(1)?,
                    checked_at: observation.get(2)?,
                    outcome: observation.get(3)?,
                    run_summary: observation.get(4)?,
                    elapsed_seconds: elapsed.max(0) as u64,
                    status: observation.get(6)?,
                    country: observation.get(7)?,
                    ping_ms: ping.map(|value| value.max(0) as u64),
                    speed_kbs: observation.get(9)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let available_count = observations
            .iter()
            .filter(|observation| observation.status == "Доступен")
            .count() as u64;
        let ping_values = observations
            .iter()
            .filter_map(|observation| observation.ping_ms)
            .collect::<Vec<_>>();
        let average_ping_ms = (!ping_values.is_empty()).then(|| {
            (ping_values.iter().map(|value| u128::from(*value)).sum::<u128>()
                / ping_values.len() as u128) as u64
        });
        let best_speed_kbs = observations
            .iter()
            .filter_map(|observation| observation.speed_kbs)
            .filter(|speed| speed.is_finite() && *speed > 0.0)
            .reduce(f64::max);

        Ok(Some(ArchiveDetail {
            row,
            observations,
            available_count,
            average_ping_ms,
            best_speed_kbs,
        }))
    }

    pub fn recheck_target(&self, id: i64, vpn_only: bool) -> Result<Option<RecheckTarget>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT id, protocol, host, port, original_link, is_vpn
                 FROM proxies WHERE id = ?1 AND is_vpn = ?2",
                params![id, i64::from(vpn_only)],
                |row| {
                    let port: i64 = row.get(3)?;
                    Ok(RecheckTarget {
                        id: row.get(0)?,
                        protocol: row.get(1)?,
                        host: row.get(2)?,
                        port: port.clamp(0, u16::MAX as i64) as u16,
                        original_link: row.get(4)?,
                        is_vpn: row.get::<_, i64>(5)? != 0,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn record_observations(
        &self,
        records: &[ArchiveRecord],
        _alive_count: usize,
        elapsed_seconds: u64,
    ) -> Result<()> {
        for record in records {
            if record.is_vpn != is_vpn_protocol(&record.protocol) {
                bail!(
                    "is_vpn не соответствует протоколу {} для {}",
                    record.protocol,
                    record.fingerprint
                );
            }
        }

        // The observation table permits one row per proxy per run. Deduplicate
        // inputs here as well so a repeated fingerprint does not abort the
        // entire run transaction or inflate the proxy's seen_count.
        let mut seen_fingerprints = HashSet::with_capacity(records.len());
        let unique_records = records
            .iter()
            .filter(|record| seen_fingerprints.insert(record.fingerprint.as_str()))
            .collect::<Vec<_>>();
        let unique_alive_count = unique_records
            .iter()
            .filter(|record| record.status == "Доступен")
            .count();

        let checked_at = now_millis();
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let summary = format!(
            "Работают {unique_alive_count} из {} прокси",
            unique_records.len()
        );
        let run_id = insert_run(
            &transaction,
            checked_at,
            "forward",
            "Успешно",
            &summary,
            unique_records.len(),
            unique_alive_count,
            elapsed_seconds,
        )?;

        let mut upsert = transaction.prepare_cached(
            "INSERT INTO proxies (
                fingerprint, protocol, host, port, name, original_link, country, is_vpn,
                latest_status, latest_ping_ms, latest_speed_kbs, first_seen_at, last_seen_at, seen_count
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, 1
             )
             ON CONFLICT(fingerprint) DO UPDATE SET
                protocol = excluded.protocol,
                host = excluded.host,
                port = excluded.port,
                name = CASE WHEN excluded.name = '' THEN proxies.name ELSE excluded.name END,
                original_link = excluded.original_link,
                country = CASE WHEN excluded.country = '' THEN proxies.country ELSE excluded.country END,
                is_vpn = excluded.is_vpn,
                latest_status = excluded.latest_status,
                latest_ping_ms = excluded.latest_ping_ms,
                latest_speed_kbs = excluded.latest_speed_kbs,
                last_seen_at = excluded.last_seen_at,
                seen_count = proxies.seen_count + 1
             RETURNING id",
        )?;
        let mut observation = transaction.prepare_cached(
            "INSERT INTO observations (
                run_id, proxy_id, status, country, ping_ms, speed_kbs, observed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;

        for record in unique_records {
            let ping_ms = record.ping_ms.map(u64_to_i64);
            let speed_kbs = record
                .speed_kbs
                .filter(|value| value.is_finite() && *value >= 0.0);
            let proxy_id = upsert.query_row(
                params![
                    record.fingerprint,
                    record.protocol,
                    record.host,
                    i64::from(record.port),
                    record.name,
                    record.original_link,
                    record.country,
                    i64::from(record.is_vpn),
                    record.status,
                    ping_ms,
                    speed_kbs,
                    checked_at,
                ],
                |row| row.get::<_, i64>(0),
            )?;
            observation.execute(params![
                run_id,
                proxy_id,
                record.status,
                record.country,
                ping_ms,
                speed_kbs,
                checked_at,
            ])?;
        }

        drop(observation);
        drop(upsert);
        transaction.commit()?;
        Ok(())
    }

    pub fn record_completed_run(
        &self,
        results_dir: &Path,
        summary: &Summary,
        elapsed_seconds: u64,
    ) -> Result<()> {
        let parsed_path = results_dir.join("parsed.txt");
        let parsed = fs::read_to_string(&parsed_path)
            .with_context(|| format!("не удалось прочитать {}", parsed_path.display()))?;
        let results_path = results_dir.join("proxy-results.json");
        let probe_results = fs::read_to_string(&results_path)
            .ok()
            .and_then(|text| serde_json::from_str::<Vec<ProbeResult>>(&text).ok())
            .unwrap_or_default();
        let alive = probe_results
            .into_iter()
            .filter(|row| !row.fingerprint.is_empty())
            .map(|row| (row.fingerprint.clone(), row))
            .collect::<HashMap<_, _>>();
        let dead_path = results_dir.join("dead.txt");
        let dead = fs::read_to_string(&dead_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| parse::parse_link(line.trim()).ok())
            .map(|proxy| proxy.fingerprint())
            .collect::<HashSet<_>>();

        let mut candidates = HashMap::<String, Candidate>::new();
        for line in parsed
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let Ok(proxy) = parse::parse_link(line) else {
                continue;
            };
            let fingerprint = proxy.fingerprint();
            let probe = alive.get(&fingerprint);
            let status = if probe.is_some() {
                "Доступен"
            } else if dead.contains(&fingerprint) {
                "Не прошёл"
            } else {
                "Найден"
            };
            // Read the generated country label from the raw fragment because
            // protocol parsers such as VMess may prefer the embedded name.
            let displayed_country = summary
                .geo
                .then(|| {
                    line.rsplit_once('#')
                        .and_then(|(_, display)| geoip_country_from_display(display))
                })
                .flatten();
            let country = probe
                .map(|row| row.country.as_str())
                .filter(|value| !value.trim().is_empty())
                .or(displayed_country)
                .unwrap_or(&proxy.country)
                .to_string();
            let name = probe
                .map(|row| row.name.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    if summary.geo && geoip_country_from_display(&proxy.name).is_some() {
                        String::new()
                    } else {
                        proxy.name.clone()
                    }
                });
            candidates.insert(
                fingerprint.clone(),
                Candidate {
                    fingerprint,
                    protocol: proxy.proto.to_string(),
                    host: proxy.host,
                    port: proxy.port,
                    name,
                    original_link: proxy.orig_url,
                    country,
                    is_vpn: is_vpn_protocol(proxy.proto),
                    status: status.to_string(),
                    ping_ms: probe.and_then(|row| row.ping_ms),
                    speed_kbs: probe
                        .and_then(|row| row.speed_kbs)
                        .filter(|value| value.is_finite() && *value > 0.0),
                },
            );
        }

        let checked_at = now_millis();
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let run_summary = if summary.speed_enabled {
            format!(
                "{} найдено · {} выше порога · медиана {:.1} КБ/с",
                summary.unique, summary.good, summary.median_kbs
            )
        } else {
            format!("{} найдено · TCP живых {}", summary.unique, summary.alive)
        };
        let run_id = insert_run(
            &transaction,
            checked_at,
            "vpn",
            "Успешно",
            &run_summary,
            candidates.len(),
            summary.alive,
            elapsed_seconds,
        )?;

        let mut upsert = transaction.prepare_cached(
            "INSERT INTO proxies (
                fingerprint, protocol, host, port, name, original_link, country, is_vpn,
                latest_status, latest_ping_ms, latest_speed_kbs, first_seen_at, last_seen_at, seen_count
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, 1
             )
             ON CONFLICT(fingerprint) DO UPDATE SET
                protocol = excluded.protocol,
                host = excluded.host,
                port = excluded.port,
                name = CASE WHEN excluded.name = '' THEN proxies.name ELSE excluded.name END,
                original_link = excluded.original_link,
                country = CASE WHEN excluded.country = '' THEN proxies.country ELSE excluded.country END,
                is_vpn = excluded.is_vpn,
                latest_status = excluded.latest_status,
                latest_ping_ms = excluded.latest_ping_ms,
                latest_speed_kbs = excluded.latest_speed_kbs,
                last_seen_at = excluded.last_seen_at,
                seen_count = proxies.seen_count + 1
             RETURNING id",
        )?;
        let mut observation = transaction.prepare_cached(
            "INSERT INTO observations (
                run_id, proxy_id, status, country, ping_ms, speed_kbs, observed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;

        for candidate in candidates.values() {
            let proxy_id = upsert.query_row(
                params![
                    candidate.fingerprint,
                    candidate.protocol,
                    candidate.host,
                    candidate.port as i64,
                    candidate.name,
                    candidate.original_link,
                    candidate.country,
                    i64::from(candidate.is_vpn),
                    candidate.status,
                    candidate
                        .ping_ms
                        .map(|value| value.min(i64::MAX as u64) as i64),
                    candidate.speed_kbs,
                    checked_at,
                ],
                |row| row.get::<_, i64>(0),
            )?;
            observation.execute(params![
                run_id,
                proxy_id,
                candidate.status,
                candidate.country,
                candidate
                    .ping_ms
                    .map(|value| value.min(i64::MAX as u64) as i64),
                candidate.speed_kbs,
                checked_at,
            ])?;
        }
        drop(observation);
        drop(upsert);
        transaction.commit()?;
        Ok(())
    }
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn normalize_checker_mode(mode: &str) -> Result<String> {
    match mode {
        "vpn" | "forward" => Ok(mode.to_owned()),
        _ => bail!("неизвестный режим проверки: {mode}"),
    }
}

fn geoip_country_from_display(name: &str) -> Option<&str> {
    let display = name.strip_prefix('[')?;
    let (country, sequence) = display.split_once("] - ")?;
    if country.is_empty()
        || !country.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
        || sequence.len() < 3
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(country)
}

fn insert_run(
    transaction: &Transaction<'_>,
    checked_at: i64,
    checker_mode: &str,
    outcome: &str,
    summary: &str,
    candidate_count: usize,
    alive_count: usize,
    elapsed_seconds: u64,
) -> Result<i64> {
    transaction.execute(
        "INSERT INTO check_runs (
            checked_at, candidate_count, alive_count, elapsed_seconds,
            checker_mode, outcome, summary
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            checked_at,
            usize_to_i64(candidate_count),
            usize_to_i64(alive_count),
            u64_to_i64(elapsed_seconds),
            checker_mode,
            outcome,
            summary,
        ],
    )?;
    Ok(transaction.last_insert_rowid())
}

fn create_schema(transaction: &Transaction<'_>) -> Result<()> {
    transaction.execute_batch(
        "CREATE TABLE check_runs (
            id INTEGER PRIMARY KEY,
            checked_at INTEGER NOT NULL,
            candidate_count INTEGER NOT NULL CHECK (candidate_count >= 0),
            alive_count INTEGER NOT NULL CHECK (alive_count >= 0),
            elapsed_seconds INTEGER NOT NULL CHECK (elapsed_seconds >= 0),
            checker_mode TEXT NOT NULL CHECK (checker_mode IN ('vpn', 'forward')),
            outcome TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            legacy_import_key TEXT
         );

         CREATE TABLE proxies (
            id INTEGER PRIMARY KEY,
            fingerprint TEXT NOT NULL UNIQUE,
            protocol TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
            name TEXT NOT NULL DEFAULT '',
            original_link TEXT NOT NULL,
            country TEXT NOT NULL DEFAULT '',
            is_vpn INTEGER NOT NULL CHECK (is_vpn IN (0, 1)),
            latest_status TEXT NOT NULL,
            latest_ping_ms INTEGER,
            latest_speed_kbs REAL,
            first_seen_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            seen_count INTEGER NOT NULL DEFAULT 1 CHECK (seen_count > 0)
         );

         CREATE TABLE observations (
            run_id INTEGER NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,
            proxy_id INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            country TEXT NOT NULL DEFAULT '',
            ping_ms INTEGER,
            speed_kbs REAL,
            observed_at INTEGER NOT NULL,
            PRIMARY KEY (run_id, proxy_id)
         ) WITHOUT ROWID;

         CREATE TABLE archive_stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            proxy_count INTEGER NOT NULL DEFAULT 0,
            vpn_count INTEGER NOT NULL DEFAULT 0
         );
         INSERT INTO archive_stats (id, proxy_count, vpn_count) VALUES (1, 0, 0);

         CREATE INDEX idx_proxies_recent ON proxies(last_seen_at DESC, id DESC);
         CREATE INDEX idx_proxies_vpn_recent ON proxies(is_vpn, last_seen_at DESC, id DESC);
         CREATE INDEX idx_proxies_host ON proxies(host COLLATE NOCASE);
         CREATE INDEX idx_proxies_protocol_recent ON proxies(protocol COLLATE NOCASE, last_seen_at DESC, id DESC);
         CREATE INDEX idx_proxies_name ON proxies(name COLLATE NOCASE);
         CREATE INDEX idx_proxies_country ON proxies(country COLLATE NOCASE);
         CREATE INDEX idx_observations_proxy_run ON observations(proxy_id, run_id DESC);
         CREATE INDEX idx_check_runs_checked_at ON check_runs(checked_at DESC, id DESC);
         CREATE INDEX idx_check_runs_mode_recent ON check_runs(checker_mode, checked_at DESC, id DESC);
         CREATE UNIQUE INDEX idx_check_runs_legacy_import_key ON check_runs(legacy_import_key);

         CREATE TRIGGER proxies_stats_insert AFTER INSERT ON proxies BEGIN
            UPDATE archive_stats
            SET proxy_count = proxy_count + (1 - NEW.is_vpn),
                vpn_count = vpn_count + NEW.is_vpn
            WHERE id = 1;
         END;
         CREATE TRIGGER proxies_stats_vpn_update AFTER UPDATE OF is_vpn ON proxies
         WHEN OLD.is_vpn <> NEW.is_vpn BEGIN
            UPDATE archive_stats
            SET proxy_count = proxy_count + OLD.is_vpn - NEW.is_vpn,
                vpn_count = vpn_count + NEW.is_vpn - OLD.is_vpn
            WHERE id = 1;
         END;
         CREATE TRIGGER proxies_stats_delete AFTER DELETE ON proxies BEGIN
            UPDATE archive_stats
            SET proxy_count = proxy_count - (1 - OLD.is_vpn),
                vpn_count = vpn_count - OLD.is_vpn
            WHERE id = 1;
         END;",
    )?;
    Ok(())
}

fn migrate_schema(transaction: &Transaction<'_>, from_version: i64) -> Result<()> {
    if from_version < 2 {
        transaction.execute_batch(
            "ALTER TABLE check_runs ADD COLUMN checker_mode TEXT NOT NULL DEFAULT 'vpn';
             ALTER TABLE check_runs ADD COLUMN outcome TEXT NOT NULL DEFAULT 'Успешно';
             ALTER TABLE check_runs ADD COLUMN summary TEXT NOT NULL DEFAULT '';

             UPDATE check_runs
             SET checker_mode = CASE WHEN EXISTS (
                 SELECT 1
                 FROM observations
                 JOIN proxies ON proxies.id = observations.proxy_id
                 WHERE observations.run_id = check_runs.id AND proxies.is_vpn = 0
             ) THEN 'forward' ELSE 'vpn' END;",
        )?;
        transaction.execute(
            "CREATE INDEX idx_check_runs_mode_recent ON check_runs(checker_mode, checked_at DESC, id DESC)",
            [],
        )?;
    }
    if from_version < 3 {
        transaction.execute_batch(
            "ALTER TABLE check_runs ADD COLUMN legacy_import_key TEXT;
             CREATE UNIQUE INDEX idx_check_runs_legacy_import_key
                 ON check_runs(legacy_import_key);",
        )?;
    }
    if from_version < 4 {
        let archive_tables_exist: bool = transaction.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'archive_stats'
             ) AND EXISTS (
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'proxies'
             )",
            [],
            |row| row.get(0),
        )?;
        if archive_tables_exist {
            transaction.execute_batch(
                "UPDATE archive_stats
             SET proxy_count = (SELECT COUNT(*) FROM proxies WHERE is_vpn = 0),
                 vpn_count = (SELECT COUNT(*) FROM proxies WHERE is_vpn = 1)
             WHERE id = 1;

             DROP TRIGGER IF EXISTS proxies_stats_insert;
             DROP TRIGGER IF EXISTS proxies_stats_vpn_update;
             DROP TRIGGER IF EXISTS proxies_stats_delete;

             CREATE TRIGGER proxies_stats_insert AFTER INSERT ON proxies BEGIN
                UPDATE archive_stats
                SET proxy_count = proxy_count + (1 - NEW.is_vpn),
                    vpn_count = vpn_count + NEW.is_vpn
                WHERE id = 1;
             END;
             CREATE TRIGGER proxies_stats_vpn_update AFTER UPDATE OF is_vpn ON proxies
             WHEN OLD.is_vpn <> NEW.is_vpn BEGIN
                UPDATE archive_stats
                SET proxy_count = proxy_count + OLD.is_vpn - NEW.is_vpn,
                    vpn_count = vpn_count + NEW.is_vpn - OLD.is_vpn
                WHERE id = 1;
             END;
             CREATE TRIGGER proxies_stats_delete AFTER DELETE ON proxies BEGIN
                UPDATE archive_stats
                SET proxy_count = proxy_count - (1 - OLD.is_vpn),
                    vpn_count = vpn_count - OLD.is_vpn
                WHERE id = 1;
             END;",
            )?;
        }
    }
    Ok(())
}

fn is_vpn_protocol(protocol: &str) -> bool {
    matches!(
        protocol.to_ascii_lowercase().as_str(),
        "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria" | "hysteria2"
    )
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub fn display_timestamp(timestamp: i64) -> String {
    let seconds = timestamp.max(0) / 1000;
    let days = seconds / 86_400;
    let seconds_in_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_in_day / 3600;
    let minute = (seconds_in_day % 3600) / 60;
    format!("{day:02}.{month:02}.{year:04} {hour:02}:{minute:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDb(PathBuf);

    impl TestDb {
        fn new() -> Self {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("proxy-sift-database-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> PathBuf {
            self.0.join("archive.sqlite3")
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn legacy_import(number: u64, checked_at: i64, summary: &str) -> LegacyRunImport {
        LegacyRunImport {
            number,
            record: RunHistoryRecord {
                checked_at,
                checker_mode: "vpn".into(),
                outcome: "Успешно".into(),
                summary: summary.into(),
                candidate_count: 12,
                alive_count: 9,
                elapsed_seconds: 4,
            },
        }
    }

    fn run_count(store: &ArchiveStore) -> i64 {
        store
            .connect()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM check_runs", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn imports_distinct_same_outcome_runs_within_one_second() {
        let db = TestDb::new();
        let store = ArchiveStore::initialize(db.path()).unwrap();

        store
            .import_legacy_runs_with_numbers(&[
                legacy_import(17, 1_800_000_000_000, "first"),
                legacy_import(18, 1_800_000_000_500, "second"),
            ])
            .unwrap();

        assert_eq!(run_count(&store), 2);
        let runs = store.recent_runs(10).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].summary, "second");
        assert_eq!(runs[1].summary, "first");
    }

    #[test]
    fn repeated_keyed_import_is_idempotent() {
        let db = TestDb::new();
        let store = ArchiveStore::initialize(db.path()).unwrap();
        let imports = [legacy_import(29, 1_800_000_000_000, "same")];

        store.import_legacy_runs_with_numbers(&imports).unwrap();
        store.import_legacy_runs_with_numbers(&imports).unwrap();

        assert_eq!(run_count(&store), 1);
    }

    #[test]
    fn v2_schema_migration_preserves_existing_run_data() {
        let db = TestDb::new();
        let path = db.path();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE check_runs (
                    id INTEGER PRIMARY KEY,
                    checked_at INTEGER NOT NULL,
                    candidate_count INTEGER NOT NULL,
                    alive_count INTEGER NOT NULL,
                    elapsed_seconds INTEGER NOT NULL,
                    checker_mode TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT ''
                 );
                 INSERT INTO check_runs VALUES
                    (7, 123456, 24, 11, 8, 'forward', 'Успешно', 'saved summary');
                 PRAGMA user_version = 2;",
            )
            .unwrap();
        drop(connection);

        let store = ArchiveStore::initialize(path).unwrap();
        let connection = store.connect().unwrap();
        let saved: (i64, i64, i64, i64, i64, String, String, Option<String>) = connection
            .query_row(
                "SELECT id, checked_at, candidate_count, alive_count, elapsed_seconds,
                        checker_mode, outcome, legacy_import_key
                 FROM check_runs WHERE id = 7",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            saved,
            (
                7,
                123456,
                24,
                11,
                8,
                "forward".into(),
                "Успешно".into(),
                None
            )
        );
        let summary: String = connection
            .query_row("SELECT summary FROM check_runs WHERE id = 7", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(summary, "saved summary");
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn fresh_initialization_creates_import_key_schema_and_empty_history() {
        let db = TestDb::new();
        let store = ArchiveStore::initialize(db.path()).unwrap();

        assert_eq!(run_count(&store), 0);
        let connection = store.connect().unwrap();
        let column_exists: bool = connection
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM pragma_table_info('check_runs')
                    WHERE name = 'legacy_import_key'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(column_exists);
        let store = ArchiveStore::initialize(db.path()).unwrap();
        assert_eq!(run_count(&store), 0);
    }

    #[test]
    fn proxy_and_vpn_pages_have_disjoint_rows_and_counts() {
        let db = TestDb::new();
        let store = ArchiveStore::initialize(db.path()).unwrap();
        let records = [
            ArchiveRecord {
                fingerprint: "http|proxy.example|8080".into(),
                protocol: "http".into(),
                host: "proxy.example".into(),
                port: 8080,
                name: String::new(),
                original_link: "http://proxy.example:8080".into(),
                country: "US".into(),
                is_vpn: false,
                status: "Доступен".into(),
                ping_ms: Some(25),
                speed_kbs: None,
            },
            ArchiveRecord {
                fingerprint: "vless|vpn.example|443".into(),
                protocol: "vless".into(),
                host: "vpn.example".into(),
                port: 443,
                name: String::new(),
                original_link: "vless://id@vpn.example:443".into(),
                country: "DE".into(),
                is_vpn: true,
                status: "Найден".into(),
                ping_ms: None,
                speed_kbs: None,
            },
        ];
        store.record_observations(&records, 1, 1).unwrap();

        let proxies = store.page(false, "", None).unwrap();
        let vpn = store.page(true, "", None).unwrap();
        let counts = store.counts().unwrap();

        assert_eq!(proxies.total, 1);
        assert_eq!(proxies.rows.len(), 1);
        assert_eq!(proxies.rows[0].protocol, "http");
        assert_eq!(vpn.total, 1);
        assert_eq!(vpn.rows.len(), 1);
        assert_eq!(vpn.rows[0].protocol, "vless");
        assert_eq!(counts.proxies, 1);
        assert_eq!(counts.vpn, 1);
    }

    #[test]
    fn v3_migration_recounts_disjoint_archives_and_replaces_stats_triggers() {
        let db = TestDb::new();
        let store = ArchiveStore::initialize(db.path()).unwrap();
        let records = [
            ArchiveRecord {
                fingerprint: "http|one.example|8080".into(),
                protocol: "http".into(),
                host: "one.example".into(),
                port: 8080,
                name: String::new(),
                original_link: "http://one.example:8080".into(),
                country: String::new(),
                is_vpn: false,
                status: "Найден".into(),
                ping_ms: None,
                speed_kbs: None,
            },
            ArchiveRecord {
                fingerprint: "trojan|vpn.example|443".into(),
                protocol: "trojan".into(),
                host: "vpn.example".into(),
                port: 443,
                name: String::new(),
                original_link: "trojan://secret@vpn.example:443".into(),
                country: String::new(),
                is_vpn: true,
                status: "Найден".into(),
                ping_ms: None,
                speed_kbs: None,
            },
        ];
        store.record_observations(&records, 0, 1).unwrap();
        let connection = store.connect().unwrap();
        connection
            .execute("UPDATE archive_stats SET proxy_count = 2 WHERE id = 1", [])
            .unwrap();
        connection
            .pragma_update(None, "user_version", 3_i64)
            .unwrap();
        drop(connection);

        let store = ArchiveStore::initialize(db.path()).unwrap();
        let counts = store.counts().unwrap();
        assert_eq!(counts.proxies, 1);
        assert_eq!(counts.vpn, 1);

        let next_proxy = ArchiveRecord {
            fingerprint: "socks5|two.example|1080".into(),
            protocol: "socks5".into(),
            host: "two.example".into(),
            port: 1080,
            name: String::new(),
            original_link: "socks5://two.example:1080".into(),
            country: String::new(),
            is_vpn: false,
            status: "Найден".into(),
            ping_ms: None,
            speed_kbs: None,
        };
        store.record_observations(&[next_proxy], 0, 1).unwrap();
        assert_eq!(store.counts().unwrap().proxies, 2);
        assert_eq!(store.page(false, "", None).unwrap().total, 2);
        assert_eq!(store.page(true, "", None).unwrap().total, 1);
    }
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}
