//! Portable user-level supervision templates for QRM-PROD-1.
//!
//! Templates contain only explicit executable/config/log paths supplied by the local operator.
//! They do not embed certificate material, credentials, Herdr sockets, or shell fragments.

use crate::{
    config::validate_absolute_path,
    error::{RelayError, RelayResult},
};
use std::path::Path;

/// Renders a macOS user LaunchAgent plist with bounded restart behavior.
pub fn render_launch_agent(
    label: &str,
    binary: &Path,
    config: &Path,
    stdout: &Path,
    stderr: &Path,
) -> RelayResult<String> {
    validate_identifier(label)?;
    for path in [binary, config, stdout, stderr] {
        validate_absolute_path("supervision.path", path)?;
    }
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>{}</string><string>--config</string><string>{}</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>30</integer>\n<key>Umask</key><integer>63</integer>\n<key>StandardOutPath</key><string>{}</string>\n<key>StandardErrorPath</key><string>{}</string>\n</dict></plist>\n",
        escape_xml(binary),
        escape_xml(config),
        escape_xml(stdout),
        escape_xml(stderr),
    ))
}

/// Renders a Linux systemd user service with bounded restart and start-rate limits.
pub fn render_systemd_user_unit(binary: &Path, config: &Path) -> RelayResult<String> {
    validate_absolute_path("supervision.binary", binary)?;
    validate_absolute_path("supervision.config", config)?;
    Ok(format!(
        "[Unit]\nDescription=Herdr-dog QUIC Relay\nAfter=network-online.target\n\n[Service]\nExecStart={} --config {}\nRestart=on-failure\nRestartSec=30s\nStartLimitIntervalSec=300\nStartLimitBurst=5\nUMask=0077\nNoNewPrivileges=yes\n\n[Install]\nWantedBy=default.target\n",
        escape_systemd(binary),
        escape_systemd(config),
    ))
}

/// Rejects labels that could inject plist or unit structure.
fn validate_identifier(value: &str) -> RelayResult<()> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        return Err(RelayError::InvalidConfiguration {
            field: "supervision.label",
            reason: "supervisor label is invalid",
        });
    }
    Ok(())
}

/// Escapes the small XML character set needed for an absolute path.
fn escape_xml(path: &Path) -> String {
    path.to_string_lossy()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Escapes whitespace for a systemd ExecStart path without invoking a shell.
fn escape_systemd(path: &Path) -> String {
    path.to_string_lossy().replace(' ', "\\x20")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // TEST:relay/src/supervision.rs[tests::templates_have_bounded_restart_policy]
    #[test]
    fn templates_have_bounded_restart_policy() {
        let plist = render_launch_agent(
            "com.example.herdrrelay",
            Path::new("/Users/ray/.local/bin/herdogrelay"),
            Path::new("/Users/ray/.config/herdr-dog/relay.toml"),
            Path::new("/Users/ray/.local/state/herdrrelay.out"),
            Path::new("/Users/ray/.local/state/herdrrelay.err"),
        )
        .expect("plist");
        assert!(plist.contains("ThrottleInterval"));
        assert!(plist.contains("KeepAlive"));
        let unit = render_systemd_user_unit(
            Path::new("/home/ray/.local/bin/herdogrelay"),
            Path::new("/home/ray/.config/herdr-dog/relay.toml"),
        )
        .expect("unit");
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("UMask=0077"));
    }
}
