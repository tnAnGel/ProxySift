use crate::parse::Proxy;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use futures::stream::{self, StreamExt};
use maxminddb::Reader;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36";
#[allow(dead_code)]
const GEOLITE_COMMITS_API: &str = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/commits?path=GeoLite2-Country.mmdb&sha=download&per_page=1";
const GEOLITE_CONTENTS_API: &str =
    "https://api.github.com/repos/P3TERX/GeoLite.mmdb/contents/GeoLite2-Country.mmdb?ref=";
const MIN_GEOLITE_BYTES: u64 = 1_000_000;
const MAX_GEOLITE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GEOIP_DAT_BYTES: u64 = 128 * 1024 * 1024;

fn is_git_revision(revision: &str) -> bool {
    revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn geolite_download_url(revision: &str) -> String {
    format!(
        "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/{revision}/GeoLite2-Country.mmdb"
    )
}

async fn response_bytes_limited(
    mut response: reqwest::Response,
    limit: u64,
    description: &str,
) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|size| size > limit) {
        bail!("{description} превышает лимит {limit} байт");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("не удалось прочитать {description}"))?
    {
        if bytes.len().saturating_add(chunk.len()) as u64 > limit {
            bail!("{description} превышает лимит {limit} байт");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() || shift > 63 {
            return None;
        }
        let b = buf[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
}

struct RangeV4 {
    start: u32,
    end: u32,
    country: usize,
}

struct RangeV6 {
    start: u128,
    end: u128,
    country: usize,
}

pub struct GeoDb {
    v4: Vec<RangeV4>,
    v6: Vec<RangeV6>,
    names: Vec<String>,
    mmdb: Option<Reader<Vec<u8>>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct GeoLiteRelease {
    pub version: String,
    pub published_at: String,
    pub download_url: String,
    pub size: u64,
    pub revision: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct GithubFileCommit {
    sha: String,
    commit: GithubCommitDetails,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct GithubCommitDetails {
    message: String,
    committer: GithubCommitSignature,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct GithubCommitSignature {
    date: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct GithubFileMetadata {
    size: u64,
    download_url: String,
}

#[derive(Deserialize, Serialize)]
#[allow(dead_code)]
struct StoredGeoLiteRelease {
    version: String,
    published_at: String,
    #[serde(default)]
    revision: String,
}

fn mask_u32(prefix: u32) -> (u32, u32) {
    if prefix == 0 {
        (0, u32::MAX)
    } else if prefix >= 32 {
        (u32::MAX, 0)
    } else {
        let m = u32::MAX << (32 - prefix);
        (m, !m)
    }
}

fn mask_u128(prefix: u32) -> (u128, u128) {
    if prefix == 0 {
        (0, u128::MAX)
    } else if prefix >= 128 {
        (u128::MAX, 0)
    } else {
        let m = u128::MAX << (128 - prefix);
        (m, !m)
    }
}

fn parse_cidr(cidr: &[u8]) -> Option<(&[u8], u32)> {
    let mut pos = 0usize;
    let mut ip: Option<&[u8]> = None;
    let mut prefix: u32 = 0;
    while pos < cidr.len() {
        let key = read_varint(cidr, &mut pos)?;
        let field = key >> 3;
        match (field, key & 7) {
            (1, 2) => {
                let len = read_varint(cidr, &mut pos)? as usize;
                if len > cidr.len().saturating_sub(pos) {
                    return None;
                }
                ip = Some(&cidr[pos..pos + len]);
                pos += len;
            }
            (2, 0) => {
                prefix = read_varint(cidr, &mut pos)? as u32;
            }
            (_, 0) => {
                read_varint(cidr, &mut pos)?;
            }
            (_, 2) => {
                let len = read_varint(cidr, &mut pos)? as usize;
                if len > cidr.len().saturating_sub(pos) {
                    return None;
                }
                pos += len;
            }
            _ => return None,
        }
    }
    ip.map(|ip| (ip, prefix))
}

impl GeoDb {
    /// Разбирает geoip.dat (protobuf: Geoip{country_code, cidr[]}).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut names: Vec<String> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut v4: Vec<RangeV4> = Vec::new();
        let mut v6: Vec<RangeV6> = Vec::new();
        let mut entries = 0usize;

        let mut pos = 0usize;
        while pos < bytes.len() {
            let key = match read_varint(bytes, &mut pos) {
                Some(k) => k,
                None => break,
            };
            if key >> 3 != 1 || key & 7 != 2 {
                bail!("geoip.dat: неожиданный protobuf-ключ {key}");
            }
            let len = read_varint(bytes, &mut pos).context("geoip.dat: битый varint")? as usize;
            if len > bytes.len().saturating_sub(pos) {
                bail!("geoip.dat: запись выходит за границу файла");
            }
            let payload = &bytes[pos..pos + len];
            pos += len;
            entries += 1;

            let mut cpos = 0usize;
            let mut country = String::new();
            while cpos < payload.len() {
                let ikey = read_varint(payload, &mut cpos).context("geoip.dat: битый inner key")?;
                let ifield = ikey >> 3;
                match (ifield, ikey & 7) {
                    (1, 2) => {
                        let ilen = read_varint(payload, &mut cpos)
                            .context("geoip.dat: country_code")?
                            as usize;
                        if ilen > payload.len().saturating_sub(cpos) {
                            bail!("geoip.dat: country_code за границей");
                        }
                        country = String::from_utf8_lossy(&payload[cpos..cpos + ilen]).into_owned();
                        cpos += ilen;
                    }
                    (2, 2) => {
                        let ilen =
                            read_varint(payload, &mut cpos).context("geoip.dat: cidr")? as usize;
                        if ilen > payload.len().saturating_sub(cpos) {
                            bail!("geoip.dat: cidr за границей");
                        }
                        let cidr = &payload[cpos..cpos + ilen];
                        cpos += ilen;
                        if let Some((ip, prefix)) = parse_cidr(cidr) {
                            let cidx = match index.get(&country) {
                                Some(i) => *i,
                                None => {
                                    let i = names.len();
                                    names.push(country.clone());
                                    index.insert(country.clone(), i);
                                    i
                                }
                            };
                            if ip.len() == 4 && prefix <= 32 {
                                let raw = u32::from_be_bytes([ip[0], ip[1], ip[2], ip[3]]);
                                let (sm, em) = mask_u32(prefix);
                                v4.push(RangeV4 {
                                    start: raw & sm,
                                    end: raw | em,
                                    country: cidx,
                                });
                            } else if ip.len() == 16 && prefix <= 128 {
                                let mut arr = [0u8; 16];
                                arr.copy_from_slice(ip);
                                let raw = u128::from_be_bytes(arr);
                                let (sm, em) = mask_u128(prefix);
                                v6.push(RangeV6 {
                                    start: raw & sm,
                                    end: raw | em,
                                    country: cidx,
                                });
                            }
                        }
                    }
                    (_, 2) => {
                        let ilen =
                            read_varint(payload, &mut cpos).context("geoip.dat: skip")? as usize;
                        if ilen > payload.len().saturating_sub(cpos) {
                            bail!("geoip.dat: skip за границей");
                        }
                        cpos += ilen;
                    }
                    (_, 0) => {
                        read_varint(payload, &mut cpos).context("geoip.dat: varint")?;
                    }
                    _ => bail!("geoip.dat: неожиданный wire type"),
                }
            }
        }

        if entries < 10 || names.is_empty() || (v4.is_empty() && v6.is_empty()) {
            bail!("geoip.dat: разобрано слишком мало (записей: {entries})");
        }
        v4.sort_by_key(|r| r.start);
        v6.sort_by_key(|r| r.start);
        Ok(Self {
            v4,
            v6,
            names,
            mmdb: None,
        })
    }

    pub fn open(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("не удалось прочитать {}", path.display()))?;
        if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("mmdb"))
        {
            return Self::from_mmdb(bytes)
                .with_context(|| format!("не удалось открыть MaxMind DB {}", path.display()));
        }
        Self::parse(&bytes).with_context(|| format!("не удалось разобрать {}", path.display()))
    }

    fn from_mmdb(bytes: Vec<u8>) -> Result<Self> {
        let reader =
            Reader::from_source(bytes).context("не удалось прочитать формат MaxMind DB")?;
        if !reader.metadata().database_type.ends_with("Country") {
            bail!(
                "ожидалась база стран GeoLite2-Country, получена {}",
                reader.metadata().database_type
            );
        }
        reader.verify().context("проверка целостности MaxMind DB")?;
        Ok(Self {
            v4: Vec::new(),
            v6: Vec::new(),
            names: Vec::new(),
            mmdb: Some(reader),
        })
    }

    fn validate_mmdb_bytes(bytes: Vec<u8>) -> Result<()> {
        Self::from_mmdb(bytes)?;
        Ok(())
    }

    pub fn database_type(&self) -> Option<&str> {
        self.mmdb
            .as_ref()
            .map(|reader| reader.metadata().database_type.as_str())
    }

    #[allow(dead_code)]
    pub fn country_for_ip(&self, ip: IpAddr) -> Option<String> {
        self.iso_for(ip).map(str::to_owned)
    }

    #[allow(dead_code)]
    fn mmdb_version(path: &Path) -> Option<String> {
        let reader = Reader::open_readfile(path).ok()?;
        let build_epoch = reader.metadata().build_epoch;
        Some(format_epoch_version(build_epoch))
    }

    #[allow(dead_code)]
    pub fn installed_geolite_version(path: &Path) -> Option<String> {
        Self::validate_mmdb_path(path).ok()?;
        let database_version = Self::mmdb_version(path)?;
        let sidecar = geolite_version_path(path);
        if let Ok(contents) = std::fs::read_to_string(sidecar) {
            if let Ok(version) = serde_json::from_str::<StoredGeoLiteRelease>(&contents) {
                if !version.version.is_empty() {
                    return Some(version.version);
                }
            }
        }
        Some(database_version)
    }

    #[allow(dead_code)]
    pub fn installed_geolite_revision(path: &Path) -> Option<String> {
        Self::validate_mmdb_path(path).ok()?;
        let sidecar = geolite_version_path(path);
        let contents = std::fs::read_to_string(sidecar).ok()?;
        let version = serde_json::from_str::<StoredGeoLiteRelease>(&contents).ok()?;
        is_git_revision(&version.revision).then_some(version.revision)
    }

    fn validate_mmdb_path(path: &Path) -> Result<()> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("не удалось прочитать {}", path.display()))?;
        Self::validate_mmdb_bytes(bytes)
    }

    pub fn stats(&self) -> (usize, usize, usize) {
        (self.names.len(), self.v4.len(), self.v6.len())
    }

    fn iso_for(&self, ip: IpAddr) -> Option<&str> {
        if let Some(reader) = &self.mmdb {
            let lookup = reader.lookup(ip).ok()?;
            let country = lookup.decode::<maxminddb::geoip2::Country>().ok()??;
            return country
                .country
                .iso_code
                .or(country.registered_country.iso_code);
        }
        let idx = match ip {
            IpAddr::V4(a) => {
                let x = u32::from(a);
                let i = self.v4.partition_point(|r| r.start <= x);
                if i == 0 || x > self.v4[i - 1].end {
                    return None;
                }
                self.v4[i - 1].country
            }
            IpAddr::V6(a) => {
                let x = u128::from(a);
                let i = self.v6.partition_point(|r| r.start <= x);
                if i == 0 || x > self.v6[i - 1].end {
                    return None;
                }
                self.v6[i - 1].country
            }
        };
        self.names.get(idx).map(|s| s.as_str())
    }
}

#[allow(dead_code)]
fn format_epoch_version(epoch: u64) -> String {
    let days = (epoch / 86_400) as i64;
    let z = days + 719_468;
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
    format!("{year:04}.{month:02}.{day:02}")
}

#[allow(dead_code)]
fn geolite_version_path(path: &Path) -> PathBuf {
    path.with_extension("mmdb.version.json")
}

fn store_geolite_version(
    path: &Path,
    version: &str,
    published_at: &str,
    revision: &str,
) -> Result<()> {
    let stored = StoredGeoLiteRelease {
        version: version.to_string(),
        published_at: published_at.to_string(),
        revision: revision.to_string(),
    };
    let metadata = serde_json::to_vec_pretty(&stored)?;
    crate::output::write_bytes_atomic(&geolite_version_path(path), &metadata, None)?;
    Ok(())
}

/// Reads the latest GeoLite2 Country file revision from the upstream download branch.
#[allow(dead_code)]
pub async fn latest_geolite_release() -> Result<GeoLiteRelease> {
    let client = reqwest::Client::builder()
        .user_agent("ProxySift")
        .build()
        .context("не удалось создать HTTP-клиент GeoIP")?;
    let commits = client
        .get(GEOLITE_COMMITS_API)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .context("не удалось проверить обновления GeoIP")?
        .error_for_status()
        .context("GitHub вернул ошибку при проверке GeoIP")?
        .json::<Vec<GithubFileCommit>>()
        .await
        .context("не удалось прочитать историю GeoLite")?;
    let commit = commits
        .into_iter()
        .next()
        .context("в ветке download не найдена база GeoLite Country")?;
    if !is_git_revision(&commit.sha) {
        bail!("GitHub вернул некорректную revision GeoLite");
    }
    let metadata = client
        .get(format!("{GEOLITE_CONTENTS_API}{}", commit.sha))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .context("не удалось получить метаданные файла GeoLite")?
        .error_for_status()
        .context("GitHub вернул ошибку при чтении файла GeoLite")?
        .json::<GithubFileMetadata>()
        .await
        .context("не удалось прочитать метаданные файла GeoLite")?;
    if !(MIN_GEOLITE_BYTES..=MAX_GEOLITE_BYTES).contains(&metadata.size) {
        bail!(
            "GitHub вернул подозрительный размер GeoLite: {} байт",
            metadata.size
        );
    }
    let published_at = commit.commit.committer.date;
    let version = commit
        .commit
        .message
        .lines()
        .next()
        .map(str::trim)
        .filter(|message| message.len() == 10 && message.as_bytes()[4] == b'.')
        .map(str::to_owned)
        .unwrap_or_else(|| {
            published_at
                .get(..10)
                .unwrap_or("дата-неизвестна")
                .replace('-', ".")
        });
    Ok(GeoLiteRelease {
        version,
        published_at,
        download_url: geolite_download_url(&commit.sha),
        size: metadata.size,
        revision: commit.sha,
    })
}

/// Downloads and validates a release before atomically replacing the local MMDB.
#[allow(dead_code)]
pub async fn install_geolite_release(path: &Path, release: &GeoLiteRelease) -> Result<()> {
    if !is_git_revision(&release.revision) {
        bail!("некорректная revision GeoLite");
    }
    if release.download_url != geolite_download_url(&release.revision) {
        bail!("URL GeoLite не соответствует закреплённой upstream revision");
    }
    if !(MIN_GEOLITE_BYTES..=MAX_GEOLITE_BYTES).contains(&release.size) {
        bail!("некорректный размер релиза GeoLite: {} байт", release.size);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("не удалось создать каталог {}", parent.display()))?;
        }
    }
    let client = reqwest::Client::builder()
        .user_agent("ProxySift")
        .build()
        .context("не удалось создать HTTP-клиент GeoIP")?;
    let response = client
        .get(&release.download_url)
        .timeout(Duration::from_secs(120))
        .send()
        .await
        .with_context(|| format!("не удалось скачать {}", release.download_url))?
        .error_for_status()
        .context("ошибка ответа при скачивании GeoLite")?;
    let bytes = response_bytes_limited(response, MAX_GEOLITE_BYTES, "файл GeoLite").await?;
    if bytes.len() as u64 != release.size {
        bail!(
            "размер GeoLite не совпадает с GitHub (получено {}, ожидалось {})",
            bytes.len(),
            release.size
        );
    }
    let previous_database = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("не удалось сохранить прежний файл {}", path.display()))
        }
    };
    crate::output::write_bytes_atomic_checked(path, &bytes, None, GeoDb::validate_mmdb_path)?;
    if let Err(metadata_error) = store_geolite_version(
        path,
        &release.version,
        &release.published_at,
        &release.revision,
    ) {
        let rollback = match previous_database {
            Some(previous) => crate::output::write_bytes_atomic(path, &previous, None),
            None => std::fs::remove_file(path).with_context(|| {
                format!(
                    "не удалось удалить новый файл {} при откате",
                    path.display()
                )
            }),
        };
        if let Err(rollback_error) = rollback {
            return Err(metadata_error).context(format!(
                "не удалось сохранить revision GeoLite; откат базы также завершился ошибкой: {rollback_error:#}"
            ));
        }
        return Err(metadata_error)
            .context("не удалось сохранить revision GeoLite; прежняя база восстановлена");
    }
    Ok(())
}

/// Скачивает geoip.dat, если файла нет или он битый.
pub async fn ensure_db(path: &Path, url: &str) -> Result<()> {
    if path.exists() {
        if GeoDb::open(path).is_ok() {
            return Ok(());
        }
    }
    if path
        .extension()
        .is_some_and(|extension| extension.to_string_lossy().eq_ignore_ascii_case("mmdb"))
    {
        let release = latest_geolite_release().await?;
        return install_geolite_release(path, &release).await;
    }
    println!(
        "  {} {} → {}",
        "↓".cyan().bold(),
        "Загружаю базу GeoIP".cyan(),
        path.display().to_string().white()
    );
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("не удалось создать каталог {}", parent.display()))?;
        }
    }
    let client = reqwest::Client::builder()
        .user_agent(UA)
        .build()
        .context("reqwest client")?;
    let resp = client
        .get(url)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .with_context(|| format!("не удалось скачать {url}"))?
        .error_for_status()
        .context("ошибка ответа при скачивании geoip.dat")?;
    let bytes = response_bytes_limited(resp, MAX_GEOIP_DAT_BYTES, "файл geoip.dat").await?;
    if bytes.len() < 1024 {
        bail!(
            "скачана подозрительно маленькая база GeoIP ({} байт)",
            bytes.len()
        );
    }
    GeoDb::parse(&bytes).context("скачанный файл не является валидным geoip.dat")?;
    crate::output::write_bytes_atomic(path, &bytes, None)?;
    Ok(())
}

fn local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_loopback() || a.is_unspecified() || a.is_private() || a.is_link_local()
        }
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || (a.segments()[0] & 0xfe00) == 0xfc00
                || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

async fn resolve_host(host: String) -> (String, Option<IpAddr>) {
    let ip = if let Ok(addr) = host.parse::<IpAddr>() {
        if local_ip(addr) {
            None
        } else {
            Some(addr)
        }
    } else {
        tokio::net::lookup_host((host.clone(), 0))
            .await
            .ok()
            .and_then(|mut addrs| addrs.next().map(|a| a.ip()))
            .filter(|ip| !local_ip(*ip))
    };
    (host, ip)
}

/// Определяет страну для каждого прокси и переименовывает в [XX] - NNN.
pub async fn assign_countries(proxies: &mut [Proxy], db: &GeoDb) -> Result<HashMap<String, usize>> {
    let hosts: Vec<String> = {
        let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for p in proxies.iter() {
            if p.host.parse::<IpAddr>().is_err() {
                set.insert(p.host.clone());
            }
        }
        set.into_iter().collect()
    };

    let pb = indicatif::ProgressBar::new(hosts.len() as u64).with_style(
        indicatif::ProgressStyle::with_template(
            "{spinner:.green} GeoIP резолв {pos}/{len} хостов [{elapsed_precise}<{eta_precise}]",
        )
        .expect("built-in GeoIP progress template is valid"),
    );
    let resolved: HashMap<String, Option<IpAddr>> = stream::iter(hosts)
        .map(|host| {
            let pb = pb.clone();
            async move {
                let r = resolve_host(host).await;
                pb.inc(1);
                r
            }
        })
        .buffer_unordered(512)
        .collect()
        .await;
    pb.finish_and_clear();

    let mut counters: HashMap<String, u32> = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();

    for p in proxies.iter_mut() {
        let ip = match p.host.parse::<IpAddr>() {
            Ok(addr) if local_ip(addr) => None,
            Ok(addr) => Some(addr),
            Err(_) => resolved.get(&p.host).and_then(|x| *x),
        };
        let iso = ip
            .and_then(|ip| db.iso_for(ip))
            .unwrap_or("XX")
            .to_ascii_uppercase();
        let n = counters.entry(iso.clone()).or_insert(0);
        *n += 1;
        p.country = iso.clone();
        p.display = format!("[{}] - {:03}", iso, *n);
        *counts.entry(iso).or_insert(0) += 1;
    }

    Ok(counts)
}

pub fn print_country_summary(counts: &HashMap<String, usize>) {
    if let Some(line) = country_summary_line(counts) {
        println!("  {}", line.cyan());
    }
}

fn country_summary_line(counts: &HashMap<String, usize>) -> Option<String> {
    if counts.is_empty() {
        return None;
    }
    let mut list: Vec<(&String, &usize)> = counts.iter().collect();
    list.sort_by(|a, b| b.1.cmp(a.1));
    let shown: Vec<String> = list
        .iter()
        .take(12)
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    Some(format!(
        "Стран в результатах: {}, распределение: {}",
        counts.len(),
        shown.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Proxy;
    use serde_json::json;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    fn field_bytes(field: u64, value: &[u8]) -> Vec<u8> {
        let mut out = varint((field << 3) | 2);
        out.extend(varint(value.len() as u64));
        out.extend(value);
        out
    }

    fn field_varint(field: u64, value: u64) -> Vec<u8> {
        let mut out = varint(field << 3);
        out.extend(varint(value));
        out
    }

    fn cidr(ip: &[u8], prefix: u32) -> Vec<u8> {
        let mut out = field_bytes(1, ip);
        out.extend(field_varint(2, prefix as u64));
        out
    }

    fn entry(country: &str, blocks: &[(&[u8], u32)]) -> Vec<u8> {
        let mut payload = field_bytes(1, country.as_bytes());
        for (ip, prefix) in blocks {
            payload.extend(field_bytes(2, &cidr(ip, *prefix)));
        }
        field_bytes(1, &payload)
    }

    // GeoDb::parse rejects tiny databases, so pad fixtures with valid empty entries.
    fn database(first_entries: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = first_entries.concat();
        for _ in first_entries.len()..10 {
            bytes.extend(field_bytes(1, &[]));
        }
        bytes
    }

    fn padded_database() -> Vec<u8> {
        let mut payload = field_bytes(1, b"US");
        payload.extend(field_bytes(2, &cidr(&[8, 8, 8, 8], 32)));
        payload.extend(field_bytes(9, &vec![0; 1100]));
        database(&[field_bytes(1, &payload)])
    }

    fn temp_path(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "proxy-rs-geoip-{}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    async fn serve_once(
        status: &'static str,
        body: Vec<u8>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            let headers = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        });
        (format!("http://{address}/geoip.dat"), task)
    }

    fn proxy(host: &str) -> Proxy {
        Proxy {
            proto: "vless",
            host: host.into(),
            port: 443,
            name: String::new(),
            base_url: String::new(),
            orig_url: String::new(),
            settings: json!({}),
            stream: None,
            country: String::new(),
            display: String::new(),
            ping: None,
            speed_kbs: 0.0,
        }
    }

    #[test]
    fn read_varint_decodes_boundaries_and_advances_position() {
        for value in [0, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let bytes = varint(value);
            let mut pos = 0;
            assert_eq!(read_varint(&bytes, &mut pos), Some(value));
            assert_eq!(pos, bytes.len());
        }
    }

    #[test]
    fn read_varint_rejects_truncated_and_overlong_values() {
        let mut pos = 0;
        assert_eq!(read_varint(&[], &mut pos), None);
        assert_eq!(read_varint(&[0x80], &mut pos), None);

        let mut pos = 0;
        assert_eq!(read_varint(&[0x80; 10], &mut pos), None);
    }

    #[test]
    fn cidr_masks_cover_zero_full_and_partial_prefixes() {
        assert_eq!(mask_u32(0), (0, u32::MAX));
        assert_eq!(mask_u32(32), (u32::MAX, 0));
        assert_eq!(mask_u32(24), (0xffff_ff00, 0xff));
        assert_eq!(mask_u128(0), (0, u128::MAX));
        assert_eq!(mask_u128(128), (u128::MAX, 0));
        assert_eq!(mask_u128(120), (u128::MAX << 8, 0xff));
    }

    #[test]
    fn parse_cidr_reads_fields_in_any_order_and_skips_unknown_fields() {
        let mut bytes = field_varint(2, 24);
        bytes.extend(field_bytes(9, b"ignored"));
        bytes.extend(field_bytes(1, &[192, 0, 2, 7]));
        assert_eq!(parse_cidr(&bytes), Some((&[192, 0, 2, 7][..], 24)));
    }

    #[test]
    fn parse_cidr_rejects_missing_ip_bad_wire_and_truncated_fields() {
        assert_eq!(parse_cidr(&field_varint(2, 24)), None);
        assert_eq!(parse_cidr(&[0x0b]), None); // field 1, unsupported group wire type
        assert_eq!(parse_cidr(&[0x0d]), None); // field 1, unsupported fixed-width wire type
        assert_eq!(parse_cidr(&[0x80]), None); // truncated field key
        assert_eq!(parse_cidr(&[0x0a, 0x80]), None); // truncated IP length
        assert_eq!(parse_cidr(&[0x0a, 0x04, 0x01]), None); // truncated IP payload
        assert_eq!(parse_cidr(&[0x10, 0x80]), None); // truncated prefix varint
        assert_eq!(parse_cidr(&[0x1a, 0x00]), None); // unknown field with unsupported wire type
        assert_eq!(parse_cidr(&[0x4a, 0x02, 0x01]), None); // truncated unknown bytes field
        assert_eq!(parse_cidr(&[0x48, 0x80]), None); // truncated unknown varint field
    }

    #[test]
    fn parse_skips_unknown_fields_and_reuses_country_indices() {
        let mut first = entry("US", &[(&[8, 8, 8, 0], 24)]);
        let mut payload = field_bytes(1, b"US");
        payload.extend(field_bytes(2, &cidr(&[1, 1, 1, 1], 32)));
        payload.extend(field_bytes(7, b"metadata"));
        payload.extend(field_varint(8, 123));
        first.extend(field_bytes(1, &payload));

        let db = GeoDb::parse(&database(&[first])).unwrap();

        assert_eq!(db.stats(), (1, 2, 0));
        assert_eq!(db.iso_for("8.8.8.8".parse().unwrap()), Some("US"));
        assert_eq!(db.iso_for("1.1.1.1".parse().unwrap()), Some("US"));
    }

    #[test]
    fn parse_reports_truncated_top_level_key_after_valid_entries() {
        let mut bytes = database(&[entry("US", &[(&[8, 8, 8, 8], 32)])]);
        bytes.truncate(entry("US", &[(&[8, 8, 8, 8], 32)]).len());
        for _ in 1..9 {
            bytes.extend(field_bytes(1, &[]));
        }
        bytes.push(0x80);

        let error = GeoDb::parse(&bytes).err().unwrap().to_string();
        assert!(error.contains("записей: 9"), "{error}");
    }

    #[test]
    fn open_reads_and_parses_a_database_and_adds_path_context_on_errors() {
        let path = temp_path("open");
        std::fs::write(&path, database(&[entry("US", &[(&[8, 8, 8, 8], 32)])])).unwrap();
        assert_eq!(GeoDb::open(&path).unwrap().stats(), (1, 1, 0));
        std::fs::write(&path, b"invalid").unwrap();
        let error = GeoDb::open(&path).err().unwrap().to_string();
        assert!(error.contains(&path.display().to_string()), "{error}");
        std::fs::remove_file(&path).unwrap();

        let missing = temp_path("missing");
        let error = GeoDb::open(&missing).err().unwrap().to_string();
        assert!(error.contains(&missing.display().to_string()), "{error}");
    }

    #[tokio::test]
    async fn ensure_db_uses_valid_cache_without_network() {
        let path = temp_path("cache");
        std::fs::write(&path, padded_database()).unwrap();

        ensure_db(&path, "http://127.0.0.1:1/unreachable")
            .await
            .unwrap();

        assert_eq!(GeoDb::open(&path).unwrap().stats(), (1, 1, 0));
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn ensure_db_replaces_invalid_cache_with_a_valid_local_download() {
        let path = temp_path("invalid-cache");
        std::fs::write(&path, b"stale invalid cache").unwrap();
        let (url, server) = serve_once("200 OK", padded_database()).await;

        ensure_db(&path, &url).await.unwrap();

        assert_eq!(GeoDb::open(&path).unwrap().stats(), (1, 1, 0));
        server.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn ensure_db_downloads_valid_database_and_reuses_it() {
        let path = temp_path("download");
        let (url, server) = serve_once("200 OK", padded_database()).await;

        ensure_db(&path, &url).await.unwrap();
        ensure_db(&path, "http://127.0.0.1:1/unreachable")
            .await
            .unwrap();

        assert_eq!(GeoDb::open(&path).unwrap().stats(), (1, 1, 0));
        server.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn ensure_db_rejects_a_self_signed_tls_certificate() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::TlsAcceptor;

        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![generated.cert.der().clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            assert!(
                acceptor.accept(stream).await.is_err(),
                "the server should observe the client's rejection of its certificate"
            );
        });
        let path = temp_path("untrusted-tls");
        let url = format!("https://localhost:{}/geoip.dat", address.port());

        let error = ensure_db(&path, &url).await.unwrap_err();

        server.await.unwrap();
        assert!(error.to_string().contains("не удалось скачать"));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn ensure_db_downloads_to_a_relative_filename() {
        let path = temp_path("relative-download")
            .file_name()
            .unwrap()
            .to_owned();
        let path = std::path::PathBuf::from(path);
        let (url, server) = serve_once("200 OK", padded_database()).await;

        ensure_db(&path, &url).await.unwrap();
        assert_eq!(GeoDb::open(&path).unwrap().stats(), (1, 1, 0));
        server.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn ensure_db_rejects_small_and_invalid_downloads_without_replacing_cache() {
        let path = temp_path("invalid-download");
        std::fs::write(&path, b"keep existing contents").unwrap();

        let (url, server) = serve_once("200 OK", b"too small".to_vec()).await;
        assert!(ensure_db(&path, &url).await.is_err());
        server.await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"keep existing contents");

        let (url, server) = serve_once("200 OK", vec![0; 1200]).await;
        assert!(ensure_db(&path, &url).await.is_err());
        server.await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"keep existing contents");
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn ensure_db_cleans_up_temporary_download_when_destination_is_a_directory() {
        let parent = temp_path("directory-destination");
        std::fs::create_dir(&parent).unwrap();
        let destination = parent.join("geoip.dat");
        std::fs::create_dir(&destination).unwrap();
        let (url, server) = serve_once("200 OK", padded_database()).await;

        assert!(ensure_db(&destination, &url).await.is_err());
        server.await.unwrap();

        let entries = std::fs::read_dir(&parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, [std::ffi::OsString::from("geoip.dat")]);
        assert!(destination.is_dir());
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[tokio::test]
    async fn ensure_db_reports_empty_destination_after_download() {
        let (url, server) = serve_once("200 OK", padded_database()).await;

        let error = ensure_db(Path::new(""), &url).await.unwrap_err();
        server.await.unwrap();

        assert!(error
            .to_string()
            .contains("путь назначения не содержит имени файла"));
    }

    #[tokio::test]
    async fn ensure_db_reports_http_errors_and_parent_creation_failures() {
        let path = temp_path("http-error");
        let (url, server) = serve_once("404 Not Found", b"missing".to_vec()).await;
        assert!(ensure_db(&path, &url).await.is_err());
        server.await.unwrap();

        let parent = temp_path("not-a-directory");
        std::fs::write(&parent, b"file").unwrap();
        let nested = parent.join("geoip.dat");
        assert!(ensure_db(&nested, "http://127.0.0.1:1/unreachable")
            .await
            .is_err());
        std::fs::remove_file(parent).unwrap();
    }

    #[tokio::test]
    async fn ensure_db_reports_local_connection_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let error = ensure_db(
            &temp_path("connection-error"),
            &format!("http://{address}/geoip.dat"),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("не удалось скачать"));
    }

    #[test]
    fn parse_builds_ipv4_ranges_for_partial_and_full_prefixes() {
        let bytes = database(&[
            entry("AA", &[(&[192, 0, 2, 99], 24)]),
            entry("BB", &[(&[198, 51, 100, 7], 32)]),
        ]);
        let db = GeoDb::parse(&bytes).unwrap();
        assert_eq!(db.iso_for("192.0.2.0".parse().unwrap()), Some("AA"));
        assert_eq!(db.iso_for("192.0.2.255".parse().unwrap()), Some("AA"));
        assert_eq!(db.iso_for("192.0.3.0".parse().unwrap()), None);
        assert_eq!(db.iso_for("198.51.100.7".parse().unwrap()), Some("BB"));
        assert_eq!(db.iso_for("198.51.100.8".parse().unwrap()), None);
        assert_eq!(db.stats(), (2, 2, 0));
    }

    #[test]
    fn parse_builds_ipv6_ranges_for_partial_and_full_prefixes() {
        let block: Ipv6Addr = "2001:db8:abcd::1234".parse().unwrap();
        let exact: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
        let bytes = database(&[
            entry("V6", &[(block.octets().as_slice(), 48)]),
            entry("EX", &[(exact.octets().as_slice(), 128)]),
        ]);
        let db = GeoDb::parse(&bytes).unwrap();
        assert_eq!(
            db.iso_for("2001:db8:abcd:ffff::1".parse().unwrap()),
            Some("V6")
        );
        assert_eq!(db.iso_for("2001:db8:abce::1".parse().unwrap()), None);
        assert_eq!(db.iso_for(exact.into()), Some("EX"));
        assert_eq!(db.stats(), (2, 0, 2));
    }

    #[test]
    fn iso_lookup_checks_inclusive_ipv4_and_ipv6_range_boundaries_and_gaps() {
        let network_v6: Ipv6Addr = "2001:db8:abcd::".parse().unwrap();
        let db = GeoDb::parse(&database(&[
            entry("V4", &[(&[192, 0, 2, 0], 24)]),
            entry("V6", &[(network_v6.octets().as_slice(), 120)]),
        ]))
        .unwrap();

        assert_eq!(db.iso_for("192.0.2.0".parse().unwrap()), Some("V4"));
        assert_eq!(db.iso_for("192.0.2.255".parse().unwrap()), Some("V4"));
        assert_eq!(db.iso_for("192.0.3.0".parse().unwrap()), None);
        assert_eq!(db.iso_for("2001:db8:abcd::".parse().unwrap()), Some("V6"));
        assert_eq!(db.iso_for("2001:db8:abcd::ff".parse().unwrap()), Some("V6"));
        assert_eq!(db.iso_for("2001:db8:abcd::100".parse().unwrap()), None);
    }

    #[test]
    fn parse_accepts_default_routes_and_skips_invalid_address_width_or_prefix() {
        let bytes = database(&[entry(
            "ALL",
            &[
                (&[203, 0, 113, 9], 0),
                (&[203, 0, 113, 9], 33),
                (&[1, 2, 3], 24),
                (&[0; 16], 129),
            ],
        )]);
        let db = GeoDb::parse(&bytes).unwrap();
        assert_eq!(db.iso_for("255.255.255.255".parse().unwrap()), Some("ALL"));
        assert_eq!(db.stats(), (1, 1, 0));
    }

    #[test]
    fn parse_skips_malformed_cidr_and_keeps_valid_ranges() {
        let mut payload = field_bytes(1, b"US");
        payload.extend(field_bytes(2, &[0x0d])); // unsupported fixed-width CIDR field
        payload.extend(field_bytes(2, &cidr(&[8, 8, 8, 8], 32)));
        let db = GeoDb::parse(&database(&[field_bytes(1, &payload)])).unwrap();

        assert_eq!(db.stats(), (1, 1, 0));
        assert_eq!(db.iso_for("8.8.8.8".parse().unwrap()), Some("US"));
    }

    #[test]
    fn parse_rejects_malformed_outer_and_inner_protobuf() {
        assert!(GeoDb::parse(&[0x0a, 0x05, 0x01]).is_err()); // outer length exceeds input
        assert!(GeoDb::parse(&[0x0a, 0x80]).is_err()); // truncated outer length
        assert!(GeoDb::parse(&[0x08, 0x00]).is_err()); // unexpected top-level key
        assert!(GeoDb::parse(&database(&[field_bytes(1, &[0x0a, 0x80])])).is_err());
        assert!(GeoDb::parse(&database(&[field_bytes(1, &[0x0b])])).is_err());
        assert!(GeoDb::parse(&database(&[field_bytes(1, &[0x0a, 0x04, 0x41])])).is_err());
        assert!(GeoDb::parse(&database(&[field_bytes(1, &[0x12, 0x02, 0x01])])).is_err());
        assert!(GeoDb::parse(&database(&[field_bytes(1, &[0x4a, 0x02, 0x01])])).is_err());
        assert!(GeoDb::parse(&database(&[field_bytes(1, &[0x48, 0x80])])).is_err());
    }

    #[test]
    fn parse_requires_enough_entries_and_at_least_one_valid_range() {
        let few = entry("AA", &[(&[192, 0, 2, 1], 24)]);
        assert!(GeoDb::parse(&few).is_err());
        assert!(GeoDb::parse(&database(&[entry("AA", &[])])).is_err());
    }

    #[test]
    fn local_ip_recognizes_private_special_and_public_addresses() {
        for ip in [
            "127.0.0.1",
            "10.2.3.4",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
        ] {
            assert!(local_ip(ip.parse().unwrap()), "{ip} should be local");
        }
        for ip in ["8.8.8.8", "1.1.1.1"] {
            assert!(!local_ip(ip.parse().unwrap()), "{ip} should be public");
        }
        for ip in ["::", "::1", "fc00::1", "fd12::1", "fe80::1"] {
            assert!(local_ip(ip.parse().unwrap()), "{ip} should be local");
        }
        assert!(!local_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[tokio::test]
    async fn assign_countries_assigns_public_and_local_ip_addresses_without_dns() {
        let bytes = database(&[
            entry("us", &[(&[8, 8, 8, 0], 24)]),
            entry("de", &[(&[1, 1, 1, 1], 32)]),
        ]);
        let db = GeoDb::parse(&bytes).unwrap();
        let mut proxies = vec![
            proxy("8.8.8.8"),
            proxy("8.8.8.9"),
            proxy("1.1.1.1"),
            proxy("192.168.1.10"),
            proxy("203.0.113.1"),
        ];

        let counts = assign_countries(&mut proxies, &db).await.unwrap();

        assert_eq!(counts.get("US"), Some(&2));
        assert_eq!(counts.get("DE"), Some(&1));
        assert_eq!(counts.get("XX"), Some(&2));
        assert_eq!(
            proxies
                .iter()
                .map(|p| p.country.as_str())
                .collect::<Vec<_>>(),
            ["US", "US", "DE", "XX", "XX"]
        );
        assert_eq!(proxies[0].display, "[US] - 001");
        assert_eq!(proxies[1].display, "[US] - 002");
        assert_eq!(proxies[2].display, "[DE] - 001");
        assert_eq!(proxies[3].display, "[XX] - 001");
        assert_eq!(proxies[4].display, "[XX] - 002");
    }

    #[tokio::test]
    async fn assign_countries_keeps_local_ip_unassigned_even_if_database_has_a_country() {
        let db = GeoDb::parse(&database(&[
            entry("PRIVATE", &[(&[192, 168, 1, 0], 24)]),
            entry("PUBLIC", &[(&[8, 8, 8, 0], 24)]),
        ]))
        .unwrap();
        let mut proxies = vec![proxy("192.168.1.10"), proxy("8.8.8.8")];

        let counts = assign_countries(&mut proxies, &db).await.unwrap();

        assert_eq!(counts.get("XX"), Some(&1));
        assert_eq!(counts.get("PUBLIC"), Some(&1));
        assert_eq!(proxies[0].country, "XX");
        assert_eq!(proxies[1].country, "PUBLIC");
    }

    #[tokio::test]
    async fn assign_countries_resolves_localhost_once_and_handles_empty_input() {
        let db = GeoDb::parse(&database(&[entry("US", &[(&[8, 8, 8, 8], 32)])])).unwrap();
        let mut proxies = vec![proxy("localhost"), proxy("localhost")];

        let counts = assign_countries(&mut proxies, &db).await.unwrap();

        assert_eq!(counts.get("XX"), Some(&2));
        assert_eq!(proxies[0].display, "[XX] - 001");
        assert_eq!(proxies[1].display, "[XX] - 002");

        let mut empty = [];
        assert!(assign_countries(&mut empty, &db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn resolve_host_keeps_public_ip_literals_and_excludes_local_literals() {
        assert_eq!(
            resolve_host("8.8.8.8".into()).await.1,
            Some("8.8.8.8".parse().unwrap())
        );
        assert_eq!(resolve_host("127.0.0.1".into()).await.1, None);
    }

    #[test]
    fn country_summary_is_sorted_limited_and_empty_for_no_countries() {
        let empty = HashMap::new();
        assert_eq!(country_summary_line(&empty), None);
        print_country_summary(&empty);

        let counts: HashMap<_, _> = (1..=13).map(|n| (format!("C{n:02}"), n)).collect();
        let line = country_summary_line(&counts).unwrap();
        assert_eq!(
            line,
            "Стран в результатах: 13, распределение: C13: 13, C12: 12, C11: 11, C10: 10, C09: 9, C08: 8, C07: 7, C06: 6, C05: 5, C04: 4, C03: 3, C02: 2"
        );
        print_country_summary(&counts);
    }

    #[test]
    fn iso_lookup_keeps_ipv4_and_ipv6_families_separate() {
        let db = GeoDb {
            v4: Vec::new(),
            v6: Vec::new(),
            names: Vec::new(),
            mmdb: None,
        };
        assert_eq!(db.iso_for(IpAddr::V4(Ipv4Addr::LOCALHOST)), None);
        assert_eq!(db.iso_for(IpAddr::V6(Ipv6Addr::LOCALHOST)), None);
    }

    #[test]
    fn deterministic_malformed_protobuf_corpus_never_panics() {
        // Valid length-delimited keys followed by u64::MAX encoded as their lengths.
        for malformed in [
            vec![
                0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            ],
            vec![
                0x0a, 0x01, 0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            ],
        ] {
            assert!(std::panic::catch_unwind(|| GeoDb::parse(&malformed)).is_ok());
        }

        let mut state = 0x3c6e_f372_fe94_f82bu64;
        for case in 0..2_000 {
            let len = (next(&mut state) % 256) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(next(&mut state) as u8);
            }
            assert!(
                std::panic::catch_unwind(|| GeoDb::parse(&bytes)).is_ok(),
                "case {case}"
            );
        }
    }

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }
}
