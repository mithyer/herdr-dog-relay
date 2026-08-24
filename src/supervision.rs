//! Portable user-level supervision templates for QRM-PROD-1.
//!
//! Templates contain only explicit executable/config/log paths supplied by the local operator.
//! They do not embed certificate material, credentials, Herdr sockets, or shell fragments.

use crate::{
    config::validate_absolute_path,
    error::{RelayError, RelayResult},
};
use std::{os::unix::ffi::OsStrExt, path::Path};

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
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>{}</string><string>--config</string><string>{}</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>30</integer>\n<key>Umask</key><integer>63</integer>\n<key>StandardOutPath</key><string>{}</string>\n<key>StandardErrorPath</key><string>{}</string>\n</dict></plist>\n",
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
        "[Unit]\nDescription=Herdr-dog QUIC Relay\nAfter=network-online.target\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\n[Service]\nExecStart={} --config {}\nRestart=on-failure\nRestartSec=30s\nUMask=0077\nNoNewPrivileges=yes\n\n[Install]\nWantedBy=default.target\n",
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

/// Escapes every non-portable byte for a systemd ExecStart argument without a shell.
fn escape_systemd(path: &Path) -> String {
    path.as_os_str()
        .as_bytes()
        .iter()
        .fold(String::new(), |mut escaped, byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
                escaped.push(*byte as char);
            } else {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\x{byte:02x}");
            }
            escaped
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    #[cfg(target_os = "macos")]
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    // TEST:relay/src/supervision.rs[tests::macos_launch_agent_template_is_valid_in_disposable_directory]
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_template_is_valid_in_disposable_directory() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory: PathBuf =
            std::env::temp_dir().join(format!("herdr-dog-launchagent-{suffix}"));
        fs::create_dir(&directory).expect("disposable directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("disposable directory mode");
        let plist_path = directory.join("com.example.herdrrelay.plist");
        let plist = render_launch_agent(
            "com.example.herdrrelay",
            Path::new("/Users/ray/.local/bin/herdogrelay"),
            Path::new("/Users/ray/.config/herdr-dog/relay.toml"),
            &directory.join("stdout.log"),
            &directory.join("stderr.log"),
        )
        .expect("LaunchAgent template");
        fs::write(&plist_path, plist).expect("LaunchAgent plist");
        fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o600))
            .expect("LaunchAgent plist mode");
        assert!(
            Command::new("/usr/bin/plutil")
                .args(["-lint", plist_path.to_str().expect("plist path")])
                .status()
                .expect("plutil")
                .success()
        );
        assert_eq!(
            fs::metadata(&plist_path)
                .expect("plist metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        fs::remove_dir_all(directory).expect("disposable cleanup");
    }

    // TEST:relay/src/supervision.rs[tests::templates_reject_injection_and_escape_paths]
    #[test]
    fn templates_reject_injection_and_escape_paths() {
        assert!(
            render_launch_agent(
                "com.example/herdrrelay",
                Path::new("/Users/ray/.local/bin/herdogrelay"),
                Path::new("/Users/ray/.config/herdr-dog/relay.toml"),
                Path::new("/Users/ray/.local/state/out"),
                Path::new("/Users/ray/.local/state/err"),
            )
            .is_err()
        );
        let plist = render_launch_agent(
            "com.example.herdrrelay",
            Path::new("/Users/ray/Relay & Tools/herdogrelay"),
            Path::new("/Users/ray/.config/herdr-dog/relay.toml"),
            Path::new("/Users/ray/.local/state/out"),
            Path::new("/Users/ray/.local/state/err"),
        )
        .expect("escaped plist");
        assert!(plist.contains("Relay &amp; Tools"));
        assert!(!plist.contains("/bin/sh"));
        let unit = render_systemd_user_unit(
            Path::new("/home/ray/Relay \"Tools\"/herdogrelay"),
            Path::new("/home/ray/.config/herdr-dog/relay\\config.toml"),
        )
        .expect("escaped unit");
        assert!(unit.contains("Relay\\x20\\x22Tools\\x22"));
        assert!(unit.contains("relay\\x5cconfig.toml"));
        assert!(unit.contains("NoNewPrivileges=yes"));
    }

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
        assert!(plist.contains("SuccessfulExit</key><false/>"));
        assert!(!plist.contains("KeepAlive</key><true/>"));
        let unit = render_systemd_user_unit(
            Path::new("/home/ray/.local/bin/herdogrelay"),
            Path::new("/home/ray/.config/herdr-dog/relay.toml"),
        )
        .expect("unit");
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("[Unit]\nDescription=Herdr-dog QUIC Relay\nAfter=network-online.target\nStartLimitIntervalSec=300\nStartLimitBurst=5"));
        assert!(unit.contains("UMask=0077"));
    }

    // TEST:relay/src/supervision.rs[tests::shipped_launch_agent_template_uses_failure_only_restart]
    #[test]
    fn shipped_launch_agent_template_uses_failure_only_restart() {
        // Keep the installable template aligned with the rendered no-restart-on-clean-exit policy.
        let plist = include_str!("../deploy/macos/com.mithyer.herdrrelay.plist");
        assert!(plist.contains("<key>SuccessfulExit</key>\n        <false/>"));
        assert!(!plist.contains("<key>KeepAlive</key>\n    <true/>"));
    }

    // TEST:relay/src/supervision.rs[tests::shipped_systemd_template_keeps_start_limits_in_unit]
    #[test]
    fn shipped_systemd_template_keeps_start_limits_in_unit() {
        // systemd ignores StartLimit settings in [Service], so the shipped unit must match the renderer.
        let unit = include_str!("../deploy/linux/herdogrelay.service");
        assert!(unit.contains("Wants=network-online.target\n# Bound crash-loop restarts before systemd refuses further starts.\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\n[Service]"));
        assert!(!unit.contains("[Service]\nStartLimitIntervalSec"));
    }
}
