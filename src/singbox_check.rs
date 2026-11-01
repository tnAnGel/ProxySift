use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

#[derive(Clone, Debug, serde::Serialize)]
pub struct ValidationResult {
    pub binary: String,
    pub version: String,
}

/// Validate a generated configuration with the official sing-box CLI.
pub fn validate(binary: Option<&Path>, config: &Path) -> Result<ValidationResult> {
    let binary = binary.unwrap_or_else(|| Path::new("sing-box"));
    let binary_label = binary.display().to_string();
    let version_output = Command::new(binary)
        .arg("version")
        .output()
        .with_context(|| format!("не удалось запустить sing-box ({binary_label})"))?;
    if !version_output.status.success() {
        bail!(
            "sing-box ({binary_label}) version завершился с кодом {}: {}",
            exit_code(&version_output.status),
            process_output(&version_output.stdout, &version_output.stderr)
        );
    }
    let version = String::from_utf8_lossy(&version_output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    if version.is_empty() {
        bail!("sing-box ({binary_label}) не вернул версию");
    }

    let check_output = Command::new(binary)
        .arg("check")
        .arg("-c")
        .arg(config)
        .output()
        .with_context(|| format!("не удалось запустить sing-box check ({binary_label})"))?;
    if !check_output.status.success() {
        bail!(
            "sing-box {version} отклонил конфигурацию {} (код {}): {}",
            config.display(),
            exit_code(&check_output.status),
            process_output(&check_output.stdout, &check_output.stderr)
        );
    }

    Ok(ValidationResult {
        binary: binary_label,
        version,
    })
}

fn exit_code(status: &std::process::ExitStatus) -> String {
    status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".to_owned())
}

fn process_output(stdout: &[u8], stderr: &[u8]) -> String {
    let output = String::from_utf8_lossy(if stderr.is_empty() { stdout } else { stderr });
    let output = output.trim();
    if output.is_empty() {
        "вывод отсутствует".to_owned()
    } else {
        output.chars().take(1000).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{exit_code, process_output};

    #[test]
    fn process_output_prefers_stderr_and_limits_diagnostic_size() {
        assert_eq!(process_output(b"stdout", b" stderr "), "stderr");
        assert_eq!(process_output(b"", b""), "вывод отсутствует");
        assert_eq!(process_output(&vec![b'x'; 1200], b"").len(), 1000);
    }

    #[test]
    fn exit_code_reports_exit_code_or_signal() {
        #[cfg(unix)]
        let status = {
            use std::os::unix::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(7 << 8)
        };
        #[cfg(windows)]
        let status = {
            use std::os::windows::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(7)
        };
        assert_eq!(exit_code(&status), "7");
    }
}
