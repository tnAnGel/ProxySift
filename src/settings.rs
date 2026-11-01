use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const SETTINGS_FILE: &str = "settings.json";
const CURRENT_VERSION: u32 = 1;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Persistent user preferences for ProxySift.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub subscriptions: String,
    pub proxy_links: String,
    pub use_default_sources: bool,
    pub source_set: String,
    pub worker_count_value: String,
    pub timeout_value: String,
    pub threshold_value: String,
    pub threshold_unit: String,
    pub use_speed: bool,
    pub use_geoip: bool,
    pub output_directory: String,
    pub checker_mode: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            subscriptions: String::new(),
            proxy_links: String::new(),
            use_default_sources: true,
            source_set: "3".into(),
            worker_count_value: "32".into(),
            timeout_value: "10".into(),
            threshold_value: "100".into(),
            threshold_unit: "КБ/с".into(),
            use_speed: true,
            use_geoip: true,
            output_directory: String::new(),
            checker_mode: "vpn".into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct VersionedSettings {
    version: u32,
    #[serde(flatten)]
    settings: AppSettings,
}

/// Load settings from `<data_dir>/settings.json`, using UI defaults when absent.
pub fn load(data_dir: &Path) -> Result<AppSettings> {
    let path = data_dir.join(SETTINGS_FILE);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AppSettings::default());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };

    let value: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("malformed settings file {}", path.display()))?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("settings file {} has no valid version", path.display()))?;
    if version > u64::from(CURRENT_VERSION) {
        anyhow::bail!(
            "settings file {} uses unsupported future version {version} (supported: {CURRENT_VERSION})",
            path.display()
        );
    }
    if version != u64::from(CURRENT_VERSION) {
        anyhow::bail!(
            "settings file {} has unsupported version {version}",
            path.display()
        );
    }

    serde_json::from_value(value)
        .with_context(|| format!("malformed settings file {}", path.display()))
}

/// Save settings atomically to `<data_dir>/settings.json`.
pub fn save(data_dir: &Path, settings: &AppSettings) -> Result<()> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data directory {}", data_dir.display()))?;

    let path = data_dir.join(SETTINGS_FILE);
    let temp_path = data_dir.join(format!(
        ".{SETTINGS_FILE}.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let result = write_temp_and_replace(&temp_path, &path, settings);
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn write_temp_and_replace(temp_path: &Path, path: &Path, settings: &AppSettings) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp_path)
        .with_context(|| {
            format!(
                "failed to create temporary settings file in {}",
                temp_path.parent().unwrap_or(Path::new(".")).display()
            )
        })?;
    write_settings(file, temp_path, path, settings)
}

fn write_settings(
    mut file: File,
    temp_path: &Path,
    path: &Path,
    settings: &AppSettings,
) -> Result<()> {
    let versioned = VersionedSettings {
        version: CURRENT_VERSION,
        settings: settings.clone(),
    };
    serde_json::to_writer_pretty(&mut file, &versioned).context("failed to serialize settings")?;
    file.write_all(b"\n")
        .context("failed to finish settings file")?;
    file.sync_all().context("failed to flush settings file")?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to secure settings file {}", temp_path.display()))?;
    }

    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("failed to replace {}", path.display()))?;
    }
    fs::rename(temp_path, path).with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}
