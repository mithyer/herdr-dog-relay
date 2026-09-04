//! Command-line host for the iroh application Relay.

use herdr_dog_relay::{
    config::{DEFAULT_IROH_CONFIG_TOML, IrohRuntimeConfig, RelayConfig, SecurityMode},
    error::RelayError,
    iroh_endpoint::{
        HerdrWorkspacePairingVerifier, IrohRelayEndpoint, PairingVerifier, RejectAllPairing,
    },
};
use std::{env, fmt, path::PathBuf, sync::Arc};

/// Command name used in diagnostics.
const COMMAND_NAME: &str = "herdogrelay";
/// Safe command-line usage text.
const HELP_TEXT: &str = "herdogrelay - iroh application Relay\n\nUsage:\n  herdogrelay [run] [--config PATH] [--port PORT] [--provision-development-identity]\n  herdogrelay update --config PATH\n  herdogrelay revoke --config PATH --app-id APP_ID\n  herdogrelay --print-default-config\n  herdogrelay --help\n  herdogrelay --version\n\nThe run command reads an iroh [iroh] configuration and keeps the endpoint alive until shutdown.\n";

/// One bounded CLI operation.
#[derive(Debug, Eq, PartialEq)]
enum CliCommand {
    /// Starts one configured iroh application Relay endpoint.
    Run {
        config_path: PathBuf,
        port: Option<u16>,
        /// Explicitly provisions a generated local development identity.
        provision_development_identity: bool,
    },
    /// Performs one explicit stable-latest local update.
    Update { config_path: PathBuf },
    /// Revokes one App from the protected local allowlist.
    Revoke {
        config_path: PathBuf,
        app_id: String,
    },
    /// Prints the complete safe configuration template.
    PrintDefaultConfig,
    /// Prints help text.
    Help,
    /// Prints package version.
    Version,
}

/// CLI setup errors with no raw paths or OS messages.
#[derive(Debug)]
enum CliError {
    /// Invalid or incomplete command arguments.
    Usage(String),
    /// Relay configuration/startup failure.
    Relay(RelayError),
}

impl fmt::Display for CliError {
    /// Formats a stable command-line error.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => formatter.write_str(message),
            Self::Relay(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Starts the command-line process.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let result = match parse_args(env::args().skip(1)) {
        Ok(CliCommand::Help) => {
            print!("{HELP_TEXT}");
            Ok(())
        }
        Ok(CliCommand::Version) => {
            println!("{COMMAND_NAME} {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Ok(CliCommand::PrintDefaultConfig) => {
            print!("{DEFAULT_IROH_CONFIG_TOML}");
            Ok(())
        }
        Ok(CliCommand::Run {
            config_path,
            port,
            provision_development_identity,
        }) => run_iroh(config_path, port, provision_development_identity).await,
        Ok(CliCommand::Update { config_path }) => update(config_path).await,
        Ok(CliCommand::Revoke {
            config_path,
            app_id,
        }) => revoke(config_path, app_id),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("{COMMAND_NAME}: {error}");
        std::process::exit(2);
    }
}

/// Parses bounded top-level CLI arguments.
fn parse_args<I, S>(arguments: I) -> Result<CliCommand, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    if matches!(
        arguments.first().map(String::as_str),
        Some("update" | "revoke")
    ) {
        return parse_control_command(&arguments);
    }
    if arguments
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        return Ok(CliCommand::Help);
    }
    if arguments
        .iter()
        .any(|argument| argument == "--version" || argument == "-V")
    {
        return Ok(CliCommand::Version);
    }
    if arguments
        .iter()
        .any(|argument| argument == "--print-default-config")
    {
        return Ok(CliCommand::PrintDefaultConfig);
    }
    let mut config_path = None;
    let mut port = None;
    let mut provision_development_identity = false;
    let mut index = if arguments.first().is_some_and(|argument| argument == "run") {
        1
    } else {
        0
    };
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--config" | "-c" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| CliError::Usage("--config requires a path".to_owned()))?;
                config_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--port" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| CliError::Usage("--port requires a number".to_owned()))?;
                let parsed = value
                    .parse::<u16>()
                    .map_err(|_| CliError::Usage("--port must be a valid UDP port".to_owned()))?;
                if parsed == 0 {
                    return Err(CliError::Usage("--port must be non-zero".to_owned()));
                }
                port = Some(parsed);
                index += 2;
            }
            "--provision-development-identity" => {
                provision_development_identity = true;
                index += 1;
            }
            option => return Err(CliError::Usage(format!("unknown option: {option}"))),
        }
    }
    Ok(CliCommand::Run {
        config_path: config_path
            .unwrap_or_else(|| PathBuf::from(".config/herdr-dog/iroh-relay.toml")),
        port,
        provision_development_identity,
    })
}

/// Parses the bounded local update and revoke commands.
fn parse_control_command(arguments: &[String]) -> Result<CliCommand, CliError> {
    let command = arguments.first().map(String::as_str).unwrap_or_default();
    let mut config_path = PathBuf::from(".config/herdr-dog/relay.toml");
    let mut app_id = None;
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--config" | "-c" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| CliError::Usage("--config requires a path".to_owned()))?;
                config_path = PathBuf::from(value);
                index += 2;
            }
            "--app-id" if command == "revoke" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| CliError::Usage("--app-id requires a value".to_owned()))?;
                app_id = Some(value.clone());
                index += 2;
            }
            option => return Err(CliError::Usage(format!("unknown option: {option}"))),
        }
    }
    match command {
        "update" if app_id.is_none() => Ok(CliCommand::Update { config_path }),
        "revoke" => Ok(CliCommand::Revoke {
            config_path,
            app_id: app_id.ok_or_else(|| CliError::Usage("revoke requires --app-id".to_owned()))?,
        }),
        _ => Err(CliError::Usage(
            "unsupported local control command".to_owned(),
        )),
    }
}

/// Executes the retained legacy fixed-source updater path.
async fn update(config_path: PathBuf) -> Result<(), CliError> {
    let config = RelayConfig::from_path(&config_path).map_err(CliError::Relay)?;
    require_verified_security(&config)?;
    let updater = herdr_dog_relay::updater::FixedSourceUpdater::new(config.update().clone())
        .map_err(CliError::Relay)?;
    let _update_lock = updater.acquire_lock().map_err(CliError::Relay)?;
    let os = match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        _ => {
            return Err(CliError::Usage(
                "unsupported update operating system".to_owned(),
            ));
        }
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        _ => {
            return Err(CliError::Usage(
                "unsupported update architecture".to_owned(),
            ));
        }
    };
    let (archive, checksums) = updater.download_latest(os, arch).map_err(CliError::Relay)?;
    updater
        .verify_checksum(&archive, &checksums)
        .map_err(CliError::Relay)?;
    let staged = updater
        .extract_verified(&archive)
        .map_err(CliError::Relay)?;
    updater
        .verify_staged_startup(&staged)
        .map_err(CliError::Relay)?;
    let installed = std::env::current_exe()
        .map_err(|_| CliError::Usage("current executable path is unavailable".to_owned()))?;
    let backup = installed.with_extension("previous");
    updater
        .replace_binary(&staged, &installed, &backup)
        .map_err(CliError::Relay)?;
    eprintln!(
        "{COMMAND_NAME}: stable-latest binary replaced; restart the user supervisor to create a new Relay generation"
    );
    Ok(())
}

/// Revokes one App through the protected local allowlist only.
fn revoke(config_path: PathBuf, app_id: String) -> Result<(), CliError> {
    let config = RelayConfig::from_path(&config_path).map_err(CliError::Relay)?;
    require_verified_security(&config)?;
    // Revocation is a local allowlist operation and remains available even when new enrollment is disabled.
    let app_id = herdr_dog_relay::enrollment::AppId::new(app_id)
        .map_err(|_| CliError::Usage("--app-id is invalid".to_owned()))?;
    let uid = herdr_dog_relay::material::current_uid().map_err(CliError::Relay)?;
    let mut allowlist = herdr_dog_relay::allowlist::PersistentAllowlist::open(
        config.enrollment().allowlist_path(),
        uid,
    )
    .map_err(CliError::Relay)?;
    let generation = allowlist
        .revoke(&app_id)
        .map_err(|_| CliError::Usage("allowlist entry could not be revoked".to_owned()))?;
    eprintln!("{COMMAND_NAME}: local revocation applied at allowlist generation {generation}");
    Ok(())
}

/// Loads the iroh runtime configuration, binds the endpoint and drains it on termination.
///
/// The endpoint owner remains in this function until the signal branch completes, which makes
/// Router handler drain and final endpoint-socket closure part of the CLI lifecycle.
// TEST:relay/src/bin/herdogrelay.rs[tests::development_identity_requires_recovery_directory]
async fn run_iroh(
    config_path: PathBuf,
    port: Option<u16>,
    provision_development_identity: bool,
) -> Result<(), CliError> {
    let config = IrohRuntimeConfig::from_path(&config_path).map_err(CliError::Relay)?;
    let config = if let Some(port) = port {
        config.with_bind_port(port).map_err(CliError::Relay)?
    } else {
        config
    };
    let endpoint_config = config.to_endpoint_config().map_err(CliError::Relay)?;
    if provision_development_identity && config.development_recovery_directory().is_none() {
        return Err(CliError::Usage(
            "--provision-development-identity requires development_recovery_directory".to_owned(),
        ));
    }
    let verifier: Arc<dyn PairingVerifier> = match config.pairing() {
        Some(pairing) => Arc::new(
            HerdrWorkspacePairingVerifier::from_runtime_config(pairing)
                .map_err(RelayError::from)
                .map_err(CliError::Relay)?,
        ),
        None => Arc::new(RejectAllPairing),
    };
    let endpoint = if provision_development_identity {
        IrohRelayEndpoint::provision_development_identity(endpoint_config, verifier).await
    } else {
        IrohRelayEndpoint::bind(endpoint_config, verifier).await
    }
    .map_err(RelayError::from)
    .map_err(CliError::Relay)?;
    eprintln!(
        "{COMMAND_NAME}: iroh application Relay started; pairing verifier configured={}",
        config.pairing().is_some()
    );
    shutdown_signal().await;
    endpoint
        .shutdown()
        .await
        .map_err(RelayError::from)
        .map_err(CliError::Relay)
}

/// Rejects the test-only relaxed TLS mode at the legacy control-command boundary.
fn require_verified_security(config: &RelayConfig) -> Result<(), CliError> {
    if config.security().mode() != SecurityMode::Verified {
        return Err(CliError::Usage(
            "development_unverified is available only to test harnesses".to_owned(),
        ));
    }
    Ok(())
}
/// Waits for the bounded user-level process termination signals.
#[cfg(unix)]
async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

/// Waits for the platform interrupt signal when Unix signal APIs are unavailable.
#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::{CliCommand, parse_args};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    // TEST:relay/src/bin/herdogrelay.rs[tests::qrm_run_arguments_are_bounded]
    #[test]
    fn qrm_run_arguments_are_bounded() {
        assert_eq!(
            parse_args(["--config", "/tmp/relay.toml", "--port", "18743"]).expect("parse"),
            CliCommand::Run {
                config_path: PathBuf::from("/tmp/relay.toml"),
                port: Some(18_743),
                provision_development_identity: false,
            }
        );
        assert!(parse_args(["--port", "0"]).is_err());
        assert!(parse_args(["--unknown"]).is_err());
    }

    // TEST:relay/src/bin/herdogrelay.rs[tests::development_identity_flag_is_explicit]
    #[test]
    fn development_identity_flag_is_explicit() {
        let command = parse_args([
            "run",
            "--config",
            "/tmp/relay.toml",
            "--provision-development-identity",
        ])
        .expect("provision command");
        assert!(matches!(
            command,
            CliCommand::Run {
                provision_development_identity: true,
                ..
            }
        ));
    }

    // TEST:relay/src/bin/herdogrelay.rs[tests::development_identity_requires_recovery_directory]
    #[tokio::test(flavor = "current_thread")]
    async fn development_identity_requires_recovery_directory() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let config_path = std::env::temp_dir().join(format!(
            "herdr-dog-relay-cli-{}-{nonce}.toml",
            std::process::id()
        ));
        fs::write(&config_path, "[iroh]\n").expect("runtime config");
        // The CLI guard runs before endpoint binding, so this remains an offline test.
        let result = super::run_iroh(config_path.clone(), None, true).await;
        assert!(matches!(
            result,
            Err(super::CliError::Usage(message))
                if message == "--provision-development-identity requires development_recovery_directory"
        ));
        fs::remove_file(config_path).expect("remove runtime config");
    }

    // TEST:relay/src/bin/herdogrelay.rs[tests::qrm_cli_rejects_development_security]
    #[test]
    fn qrm_cli_rejects_development_security() {
        let config = herdr_dog_relay::config::RelayConfig::from_toml_str(
            r#"
[listener]
listen_address = "127.0.0.1"
port = 18743
[security]
mode = "development_unverified"
server_certificate = "/tmp/server.pem"
server_private_key = "/tmp/server.key"
trusted_client_ca = "/tmp/client-ca.pem"
[limits]
max_connections = 64
max_sessions_per_connection = 64
max_control_frame_bytes = 65536
buffer_bytes = 65536
handshake_timeout_secs = 5
idle_timeout_secs = 900
"#,
        )
        .expect("development config");
        assert!(super::require_verified_security(&config).is_err());
    }

    // TEST:relay/src/bin/herdogrelay.rs[tests::qrm_print_commands_are_available]
    #[test]
    fn qrm_print_commands_are_available() {
        assert_eq!(parse_args(["--help"]).expect("help"), CliCommand::Help);
        assert_eq!(
            parse_args(["update", "--config", "/tmp/relay.toml"]).expect("update"),
            CliCommand::Update {
                config_path: PathBuf::from("/tmp/relay.toml")
            }
        );
        assert_eq!(
            parse_args(["revoke", "--config", "/tmp/relay.toml", "--app-id", "app-a"])
                .expect("revoke"),
            CliCommand::Revoke {
                config_path: PathBuf::from("/tmp/relay.toml"),
                app_id: "app-a".to_owned()
            }
        );
        assert_eq!(
            parse_args(["--print-default-config"]).expect("config"),
            CliCommand::PrintDefaultConfig
        );
    }
}
