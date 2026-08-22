//! Command-line host for the QRM-1 single-device QUIC Relay.

use herdr_dog_relay::{
    config::{DEFAULT_CONFIG_TOML, RelayConfig, SecurityMode},
    error::RelayError,
    quic_server::QuicRelayServer,
};
use std::{env, fmt, path::PathBuf};

/// Command name used in diagnostics.
const COMMAND_NAME: &str = "herdogrelay";
/// Safe command-line usage text.
const HELP_TEXT: &str = "herdogrelay - single-device QUIC TLS 1.3 Relay\n\nUsage:\n  herdogrelay [--config PATH] [--port PORT]\n  herdogrelay --print-default-config\n  herdogrelay --help\n  herdogrelay --version\n";

/// One bounded CLI operation.
#[derive(Debug, Eq, PartialEq)]
enum CliCommand {
    /// Starts one configured Relay server.
    Run {
        config_path: PathBuf,
        port: Option<u16>,
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
            print!("{DEFAULT_CONFIG_TOML}");
            Ok(())
        }
        Ok(CliCommand::Run { config_path, port }) => run(config_path, port).await,
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
    let mut index = 0;
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
            option => return Err(CliError::Usage(format!("unknown option: {option}"))),
        }
    }
    Ok(CliCommand::Run {
        config_path: config_path.unwrap_or_else(|| PathBuf::from(".config/herdr-dog/relay.toml")),
        port,
    })
}

/// Loads validated configuration, binds the UDP listener and serves until termination.
async fn run(config_path: PathBuf, port: Option<u16>) -> Result<(), CliError> {
    let config = RelayConfig::from_path(&config_path).map_err(CliError::Relay)?;
    require_verified_security(&config)?;
    let config = if let Some(port) = port {
        config.with_port(port).map_err(CliError::Relay)?
    } else {
        config
    };
    let generation = rand::random::<u64>().max(1);
    let server = QuicRelayServer::bind(config, generation)
        .await
        .map_err(CliError::Relay)?;
    let address = server.local_addr().map_err(CliError::Relay)?;
    eprintln!("{COMMAND_NAME}: listening on UDP {address}");
    server
        .serve_until(shutdown_signal())
        .await
        .map_err(CliError::Relay)
}

/// Rejects the test-only relaxed TLS mode at the production CLI boundary.
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
    use std::path::PathBuf;

    // TEST:relay/src/bin/herdogrelay.rs[tests::qrm_run_arguments_are_bounded]
    #[test]
    fn qrm_run_arguments_are_bounded() {
        assert_eq!(
            parse_args(["--config", "/tmp/relay.toml", "--port", "18743"]).expect("parse"),
            CliCommand::Run {
                config_path: PathBuf::from("/tmp/relay.toml"),
                port: Some(18_743)
            }
        );
        assert!(parse_args(["--port", "0"]).is_err());
        assert!(parse_args(["--unknown"]).is_err());
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
            parse_args(["--print-default-config"]).expect("config"),
            CliCommand::PrintDefaultConfig
        );
    }
}
