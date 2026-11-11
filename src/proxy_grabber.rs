//! Persistence for editable proxy-source discovery queries and discovered URLs.
//!
//! This module intentionally does not implement search-provider APIs or perform
//! network requests. Provider identifiers are strings so additional providers
//! can be introduced without changing the persistence schema.

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

/// A persisted, editable search request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchQuery {
    pub id: i64,
    /// Search text or provider-specific query expression.
    pub query: String,
    /// Stable provider key, such as `manual` or a future API provider name.
    pub provider: String,
    pub title: String,
    pub added_at: i64,
    pub updated_at: i64,
    pub active: bool,
}

/// Values required to create a search query.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NewSearchQuery {
    pub query: String,
    pub provider: String,
    pub title: String,
    pub active: bool,
}

/// Replacement values for an existing search query.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateSearchQuery {
    pub query: String,
    pub provider: String,
    pub title: String,
    pub active: bool,
}

/// Describes how a discovered source behaves over time.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceClassification {
    /// A point-in-time result or archive that is not expected to keep changing.
    Snapshot,
    /// A URL expected to provide a changing proxy list over time.
    RollingFeed,
}

impl SourceClassification {
    fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::RollingFeed => "rolling_feed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "snapshot" => Ok(Self::Snapshot),
            "rolling_feed" => Ok(Self::RollingFeed),
            _ => bail!("unknown source classification `{value}`"),
        }
    }
}

/// A discovered HTTP(S) source URL and its refresh metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredSource {
    pub id: i64,
    /// Search query that first discovered this record, if any.
    pub query_id: Option<i64>,
    pub provider: String,
    pub title: String,
    pub url: String,
    pub classification: SourceClassification,
    pub added_at: i64,
    pub last_seen_at: i64,
    pub active: bool,
    /// Provider/application-defined status key from the last fetch.
    pub last_fetch_status: Option<String>,
    pub last_fetch_count: Option<u64>,
    pub last_fetched_at: Option<i64>,
}

/// Values required to add a source directly, without a discovery run.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NewSource {
    pub query_id: Option<i64>,
    pub provider: String,
    pub title: String,
    pub url: String,
    pub classification: SourceClassification,
    pub active: bool,
}

/// Replacement values for an existing source.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateSource {
    pub query_id: Option<i64>,
    pub provider: String,
    pub title: String,
    pub url: String,
    pub classification: SourceClassification,
    pub active: bool,
}

/// One source returned by a completed discovery operation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryItem {
    pub provider: String,
    pub title: String,
    pub url: String,
    pub classification: SourceClassification,
}

/// Status and count recorded when a source refresh completes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRefresh {
    /// Provider/application-defined key, for example `success`, `http_404`, or
    /// `not_modified`. Kept open-ended to avoid coupling storage to a fetcher.
    pub status: String,
    /// Number of proxy entries returned/parsed, when known.
    pub count: Option<u64>,
    /// Optional explicit Unix timestamp in milliseconds; defaults to now.
    pub fetched_at: Option<i64>,
}

/// SQLite-backed persistence for source discovery data.
#[derive(Clone, Debug)]
pub struct ProxyGrabberStore {
    path: PathBuf,
}

impl ProxyGrabberStore {
    /// Open or create a database file and initialize this module's tables.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create database directory {}", parent.display())
            })?;
        }

        let store = Self { path };
        let connection = store.connect()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS proxy_grabber_queries (
                id INTEGER PRIMARY KEY,
                query TEXT NOT NULL,
                provider TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                added_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                active INTEGER NOT NULL CHECK (active IN (0, 1))
             );
             CREATE INDEX IF NOT EXISTS proxy_grabber_queries_active_idx
                ON proxy_grabber_queries(active, id);
             CREATE TABLE IF NOT EXISTS proxy_grabber_sources (
                id INTEGER PRIMARY KEY,
                query_id INTEGER REFERENCES proxy_grabber_queries(id) ON DELETE SET NULL,
                provider TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL,
                classification TEXT NOT NULL CHECK (classification IN ('snapshot', 'rolling_feed')),
                added_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                active INTEGER NOT NULL CHECK (active IN (0, 1)),
                last_fetch_status TEXT,
                last_fetch_count INTEGER CHECK (last_fetch_count IS NULL OR last_fetch_count >= 0),
                last_fetched_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS proxy_grabber_sources_active_idx
                ON proxy_grabber_sources(active, id);
             CREATE INDEX IF NOT EXISTS proxy_grabber_sources_url_idx
                ON proxy_grabber_sources(url);
             CREATE INDEX IF NOT EXISTS proxy_grabber_sources_query_idx
                ON proxy_grabber_sources(query_id, id);
             CREATE TABLE IF NOT EXISTS proxy_grabber_credentials (
                provider TEXT PRIMARY KEY,
                secret TEXT NOT NULL,
                updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS proxy_grabber_preferences (
                preference TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS proxy_grabber_fetch_history (
                id INTEGER PRIMARY KEY,
                source_id INTEGER NOT NULL REFERENCES proxy_grabber_sources(id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                proxy_count INTEGER CHECK (proxy_count IS NULL OR proxy_count >= 0),
                fetched_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS proxy_grabber_fetch_history_source_idx
                ON proxy_grabber_fetch_history(source_id, fetched_at DESC);",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to secure database {}", store.path.display()))?;
        }
        Ok(store)
    }

    /// Return the database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Store a provider API credential locally. Empty values remove the key.
    pub fn set_credential(&self, provider: &str, secret: &str) -> Result<()> {
        let provider = provider.trim();
        if !matches!(provider, "serpapi" | "github" | "brave") {
            bail!("unsupported search provider credential");
        }
        let connection = self.connect()?;
        if secret.trim().is_empty() {
            connection.execute(
                "DELETE FROM proxy_grabber_credentials WHERE provider = ?1",
                [provider],
            )?;
        } else {
            connection.execute(
                "INSERT INTO proxy_grabber_credentials (provider, secret, updated_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(provider) DO UPDATE SET secret = excluded.secret, updated_at = excluded.updated_at",
                params![provider, secret.trim(), now_millis()?],
            )?;
        }
        Ok(())
    }

    /// Read a configured provider key without exposing it to UI models or logs.
    pub fn credential(&self, provider: &str) -> Result<Option<String>> {
        let provider = provider.trim();
        if !matches!(provider, "serpapi" | "github" | "brave") {
            bail!("unsupported search provider credential");
        }
        self.connect()?
            .query_row(
                "SELECT secret FROM proxy_grabber_credentials WHERE provider = ?1",
                [provider],
                |row| row.get(0),
            )
            .optional()
            .context("failed to read search provider credential")
    }

    /// Return only provider names, never credential values.
    pub fn configured_credentials(&self) -> Result<Vec<String>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT provider FROM proxy_grabber_credentials ORDER BY provider",
        )?;
        let providers = statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list configured search providers")?;
        Ok(providers)
    }

    /// Persist a supported discovery preference without mixing it into the VPN settings.
    pub fn set_preference(&self, preference: &str, value: &str) -> Result<()> {
        if preference != "selected_engines" {
            bail!("unsupported proxy discovery preference");
        }
        self.connect()?.execute(
            "INSERT INTO proxy_grabber_preferences (preference, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(preference) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![preference, value, now_millis()?],
        )?;
        Ok(())
    }

    /// Read a supported discovery preference.
    pub fn preference(&self, preference: &str) -> Result<Option<String>> {
        if preference != "selected_engines" {
            bail!("unsupported proxy discovery preference");
        }
        self.connect()?
            .query_row(
                "SELECT value FROM proxy_grabber_preferences WHERE preference = ?1",
                [preference],
                |row| row.get(0),
            )
            .optional()
            .context("failed to read proxy discovery preference")
    }

    /// Add a query and return its assigned row ID.
    pub fn add_query(&self, query: &NewSearchQuery) -> Result<i64> {
        validate_query(query)?;
        let now = now_millis()?;
        let connection = self.connect()?;
        connection.execute(
            "INSERT INTO proxy_grabber_queries
                (query, provider, title, added_at, updated_at, active)
             VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
            params![
                query.query.trim(),
                query.provider.trim(),
                query.title.trim(),
                now,
                query.active
            ],
        )?;
        Ok(connection.last_insert_rowid())
    }

    /// Replace all editable fields of a query. Returns false if its ID is absent.
    pub fn update_query(&self, id: i64, query: &UpdateSearchQuery) -> Result<bool> {
        validate_query_fields(&query.query, &query.provider)?;
        let connection = self.connect()?;
        let changed = connection.execute(
            "UPDATE proxy_grabber_queries
             SET query = ?1, provider = ?2, title = ?3, active = ?4, updated_at = ?5
             WHERE id = ?6",
            params![
                query.query.trim(),
                query.provider.trim(),
                query.title.trim(),
                query.active,
                now_millis()?,
                id
            ],
        )?;
        Ok(changed != 0)
    }

    /// Delete a query. Related sources remain and have their query ID cleared.
    pub fn delete_query(&self, id: i64) -> Result<bool> {
        Ok(self
            .connect()?
            .execute("DELETE FROM proxy_grabber_queries WHERE id = ?1", [id])?
            != 0)
    }

    /// List queries in insertion order. Set `active_only` to filter disabled rows.
    pub fn list_queries(&self, active_only: bool) -> Result<Vec<SearchQuery>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT id, query, provider, title, added_at, updated_at, active
             FROM proxy_grabber_queries
             WHERE (?1 = 0 OR active = 1)
             ORDER BY id",
        )?;
        let rows = statement.query_map([active_only], row_to_query)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list proxy discovery queries")
    }

    /// Add a source directly and return its assigned row ID.
    pub fn add_source(&self, source: &NewSource) -> Result<i64> {
        validate_source(source)?;
        let now = now_millis()?;
        let connection = self.connect()?;
        connection.execute(
            "INSERT INTO proxy_grabber_sources
                (query_id, provider, title, url, classification, added_at, last_seen_at, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
            params![
                source.query_id,
                source.provider.trim(),
                source.title.trim(),
                source.url.trim(),
                source.classification.as_str(),
                now,
                source.active
            ],
        )?;
        Ok(connection.last_insert_rowid())
    }

    /// Replace editable fields of a source, retaining its timestamps and fetch metadata.
    pub fn update_source(&self, id: i64, source: &UpdateSource) -> Result<bool> {
        validate_source_fields(&source.provider, &source.url)?;
        let connection = self.connect()?;
        let changed = connection.execute(
            "UPDATE proxy_grabber_sources
             SET query_id = ?1, provider = ?2, title = ?3, url = ?4,
                 classification = ?5, active = ?6
             WHERE id = ?7",
            params![
                source.query_id,
                source.provider.trim(),
                source.title.trim(),
                source.url.trim(),
                source.classification.as_str(),
                source.active,
                id
            ],
        )?;
        Ok(changed != 0)
    }

    /// Delete a source. Returns false if its ID is absent.
    pub fn delete_source(&self, id: i64) -> Result<bool> {
        Ok(self
            .connect()?
            .execute("DELETE FROM proxy_grabber_sources WHERE id = ?1", [id])?
            != 0)
    }

    /// List sources in insertion order. Set `active_only` to filter disabled rows.
    pub fn list_sources(&self, active_only: bool) -> Result<Vec<DiscoveredSource>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT id, query_id, provider, title, url, classification,
                    added_at, last_seen_at, active, last_fetch_status,
                    last_fetch_count, last_fetched_at
             FROM proxy_grabber_sources
             WHERE (?1 = 0 OR active = 1)
             ORDER BY id",
        )?;
        let rows = statement.query_map([active_only], row_to_source)?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(classification, mut source)| {
                source.classification = SourceClassification::parse(&classification)?;
                Ok(source)
            })
            .collect()
    }

    /// Persist one completed discovery result atomically.
    ///
    /// Existing rows with the same query ID, provider, and exact URL have their
    /// title/classification refreshed and `last_seen_at` advanced. Missing
    /// results are not deactivated because discovery may be partial.
    pub fn persist_discovery_result(
        &self,
        query_id: i64,
        items: &[DiscoveryItem],
    ) -> Result<usize> {
        let now = now_millis()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        ensure_query_exists(&transaction, query_id)?;
        let mut changed = 0usize;

        for item in items {
            validate_source_fields(&item.provider, &item.url)?;
            let existing_id = transaction
                .query_row(
                    "SELECT id FROM proxy_grabber_sources
                     WHERE query_id = ?1 AND provider = ?2 AND url = ?3
                     ORDER BY id LIMIT 1",
                    params![query_id, item.provider.trim(), item.url.trim()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;

            if let Some(id) = existing_id {
                transaction.execute(
                    "UPDATE proxy_grabber_sources
                     SET title = ?1, classification = ?2, last_seen_at = ?3
                     WHERE id = ?4",
                    params![item.title.trim(), item.classification.as_str(), now, id],
                )?;
            } else {
                transaction.execute(
                    "INSERT INTO proxy_grabber_sources
                        (query_id, provider, title, url, classification,
                         added_at, last_seen_at, active)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)",
                    params![
                        query_id,
                        item.provider.trim(),
                        item.title.trim(),
                        item.url.trim(),
                        item.classification.as_str(),
                        now
                    ],
                )?;
            }
            changed += 1;
        }

        transaction.commit()?;
        Ok(changed)
    }

    /// Record the result of fetching a source and return false if it does not exist.
    pub fn update_source_refresh(&self, id: i64, refresh: &SourceRefresh) -> Result<bool> {
        if refresh.status.trim().is_empty() {
            bail!("fetch status must not be empty");
        }
        let count = refresh
            .count
            .map(i64::try_from)
            .transpose()
            .context("fetch count exceeds SQLite integer range")?;
        let fetched_at = match refresh.fetched_at {
            Some(timestamp) if timestamp >= 0 => timestamp,
            Some(_) => bail!("fetch timestamp must be non-negative"),
            None => now_millis()?,
        };
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE proxy_grabber_sources
             SET last_fetch_status = ?1, last_fetch_count = ?2, last_fetched_at = ?3
             WHERE id = ?4",
            params![refresh.status.trim(), count, fetched_at, id],
        )?;
        if changed != 0 {
            transaction.execute(
                "INSERT INTO proxy_grabber_fetch_history (source_id, status, proxy_count, fetched_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, refresh.status.trim(), count, fetched_at],
            )?;
        }
        transaction.commit()?;
        Ok(changed != 0)
    }

    fn connect(&self) -> Result<Connection> {
        let connection = Connection::open(&self.path)
            .with_context(|| format!("failed to open database {}", self.path.display()))?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(connection)
    }
}

/// Validate and normalize an HTTP(S) source URL without making a network request.
///
/// Rejects non-web schemes, missing hosts, credentials, fragments, control
/// characters, and literal IPs that are not globally routable. DNS names are
/// not resolved here; a future fetcher must enforce its own redirect and
/// resolved-address policy before connecting.
pub fn validate_source_url(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("source URL is empty or contains control characters");
    }
    let parsed = Url::parse(value).context("source URL is not a valid absolute URL")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("source URL must use http or https");
    }
    if parsed.host_str().is_none() {
        bail!("source URL must include a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("source URL must not include credentials");
    }
    if parsed.fragment().is_some() {
        bail!("source URL must not include a fragment");
    }
    if let Some(host) = parsed.host_str() {
        if host.eq_ignore_ascii_case("localhost")
            || host.to_ascii_lowercase().ends_with(".localhost")
        {
            bail!("source URL must not target localhost");
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !is_global_ip(ip) {
                bail!("source URL must not target a non-public IP address");
            }
        }
    }
    Ok(parsed.to_string())
}

fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_multicast()
                || a == 0
                || a == 100 && (64..=127).contains(&b)
                || a == 192 && b == 0 && c == 0
                || a == 192 && b == 0 && c == 2
                || a == 192 && b == 88 && c == 99
                || a == 198 && (b == 18 || b == 19)
                || a == 198 && b == 51 && c == 100
                || a == 203 && b == 0 && c == 113
                || a >= 224)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || segments[0] & 0xffc0 == 0xfe80
                || segments[0] & 0xff00 == 0xff00)
        }
    }
}

fn validate_query(query: &NewSearchQuery) -> Result<()> {
    validate_query_fields(&query.query, &query.provider)
}

fn validate_query_fields(query: &str, provider: &str) -> Result<()> {
    if query.trim().is_empty() {
        bail!("search query must not be empty");
    }
    if provider.trim().is_empty() {
        bail!("provider must not be empty");
    }
    if query.chars().any(char::is_control) || provider.chars().any(char::is_control) {
        bail!("query and provider must not contain control characters");
    }
    Ok(())
}

fn validate_source(source: &NewSource) -> Result<()> {
    validate_source_fields(&source.provider, &source.url)?;
    if let Some(query_id) = source.query_id {
        if query_id <= 0 {
            bail!("query ID must be positive");
        }
    }
    Ok(())
}

fn validate_source_fields(provider: &str, url: &str) -> Result<()> {
    if provider.trim().is_empty() || provider.chars().any(char::is_control) {
        bail!("provider must not be empty or contain control characters");
    }
    validate_source_url(url)?;
    Ok(())
}

fn ensure_query_exists(transaction: &Transaction<'_>, query_id: i64) -> Result<()> {
    if query_id <= 0 {
        bail!("query ID must be positive");
    }
    let exists = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM proxy_grabber_queries WHERE id = ?1)",
        [query_id],
        |row| row.get::<_, bool>(0),
    )?;
    if !exists {
        return Err(anyhow!("search query {query_id} does not exist"));
    }
    Ok(())
}

fn row_to_query(row: &Row<'_>) -> rusqlite::Result<SearchQuery> {
    Ok(SearchQuery {
        id: row.get(0)?,
        query: row.get(1)?,
        provider: row.get(2)?,
        title: row.get(3)?,
        added_at: row.get(4)?,
        updated_at: row.get(5)?,
        active: row.get(6)?,
    })
}

// Keep the encoded classification alongside the decoded row so conversion
// errors can be reported by the public list method as an anyhow error.
fn row_to_source(row: &Row<'_>) -> rusqlite::Result<(String, DiscoveredSource)> {
    let classification: String = row.get(5)?;
    let count: Option<i64> = row.get(10)?;
    let count = count
        .map(|value| {
            u64::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    10,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })
        })
        .transpose()?;
    let source = DiscoveredSource {
        id: row.get(0)?,
        query_id: row.get(1)?,
        provider: row.get(2)?,
        title: row.get(3)?,
        url: row.get(4)?,
        classification: SourceClassification::Snapshot,
        added_at: row.get(6)?,
        last_seen_at: row.get(7)?,
        active: row.get(8)?,
        last_fetch_status: row.get(9)?,
        last_fetch_count: count,
        last_fetched_at: row.get(11)?,
    };
    Ok((classification, source))
}

fn now_millis() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    i64::try_from(duration.as_millis()).context("system timestamp exceeds SQLite integer range")
}
