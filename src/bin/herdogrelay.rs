//! Command-line host for the Herdr-dog Relay listener.

use herdr_dog_relay::{
    config::{DEFAULT_CONFIG_TOML, RelayConfig},
    listener::TailscaleListener,
};
use std::{
    env, fmt,
    path::{Path, PathBuf},
    process::Command,
};

/// The default user-level configuration location used by the CLI.
const DEFAULT_CONFIG_SUFFIX: &str = ".config/herdr-dog/relay.toml";
/// The command name shown in user-facing diagnostics.
const COMMAND_NAME: &str = "herdogrelay";
/// The short command-line usage text.
const HELP_TEXT: &str = "herdogrelay - authenticated Herdr-dog byte relay\n\nUsage:\n  herdogrelay [--config PATH]\n  herdogrelay --print-default-config\n  herdogrelay --help\n  herdogrelay --version\n\nOptions:\n  -c, --config PATH       Read the validated TOML configuration from PATH.\n      --print-default-config\n                          Print the complete commented v1 TOML template.\n  -h, --help              Print this help text.\n  -V, --version           Print the CLI version.\n\nThe relay uses a user-level process and does not require sudo.\n";

/// One parsed CLI operation.
#[derive(Debug)]
enum CliCommand {
    /// Start the listener using the selected configuration file.
    Run { config_path: PathBuf },
    /// Print the complete safe configuration template and exit.
    PrintDefaultConfig,
    /// Print command usage and exit.
    Help,
    /// Print the package version and exit.
    Version,
}

/// A bounded error emitted by command-line setup or relay startup.
#[derive(Debug)]
enum CliError {
    /// The user supplied an invalid option or omitted its value.
    Usage(String),
    /// The current effective Unix UID could not be determined safely.
    CurrentUid,
    /// The relay library rejected configuration or startup.
    Relay(herdr_dog_relay::error::RelayError),
}

impl fmt::Display for CliError {
    /// Formats a redacted CLI error without exposing paths, credentials, or raw OS messages.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::CurrentUid => write!(formatter, "could not determine the current Unix user"),
            Self::Relay(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Starts the command-line process and converts failures into a non-zero exit status.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arguments = env::args().skip(1);
    let result = match parse_args(arguments) {
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
        Ok(CliCommand::Run { config_path }) => run_relay(&config_path).await,
        Err(error) => Err(error),
    };

    if let Err(error) = result {
        eprintln!("{COMMAND_NAME}: {error}");
        std::process::exit(2);
    }
}

/// Parses command-line arguments without interpreting configuration or network data.
///
/// - Parameter arguments: Arguments after the executable name.
/// - Returns: One bounded CLI operation or a usage error.
fn parse_args<I, S>(arguments: I) -> Result<CliCommand, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut config_path = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.into().as_str() {
            "-c" | "--config" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| CliError::Usage("--config requires a path".to_owned()))?;
                config_path = Some(expand_home(PathBuf::from(value.into()))?);
            }
            "--print-default-config" => return Ok(CliCommand::PrintDefaultConfig),
            "-h" | "--help" => return Ok(CliCommand::Help),
            "-V" | "--version" => return Ok(CliCommand::Version),
            option => {
                return Err(CliError::Usage(format!("unknown option: {option}")));
            }
        }
    }

    Ok(CliCommand::Run {
        config_path: config_path.unwrap_or(default_config_path()?),
    })
}

/// Expands a leading `~/` using the current user's home directory without normalizing other paths.
///
/// - Parameter path: User-supplied configuration path.
/// - Returns: The path with an optional leading home marker expanded.
fn expand_home(path: PathBuf) -> Result<PathBuf, CliError> {
    let Some(value) = path.to_str() else {
        return Ok(path);
    };
    if value == "~" {
        return home_directory();
    }
    if let Some(relative) = value.strip_prefix("~/") {
        return home_directory().map(|home| home.join(relative));
    }
    Ok(path)
}

/// Resolves the default user-level configuration path.
///
/// - Returns: `$HOME/.config/herdr-dog/relay.toml`.
fn default_config_path() -> Result<PathBuf, CliError> {
    home_directory().map(|home| home.join(DEFAULT_CONFIG_SUFFIX))
}

/// Reads the current user's home directory from the process environment.
///
/// - Returns: A non-empty home directory path.
fn home_directory() -> Result<PathBuf, CliError> {
    let home = env::var_os("HOME").filter(|value| !value.is_empty());
    home.map(PathBuf::from).ok_or(CliError::Usage(
        "HOME is required when --config is omitted or uses ~/".to_owned(),
    ))
}

/// Resolves the effective Unix UID through the platform's user utility.
///
/// Using the utility keeps the binary free of unsafe UID syscalls while preserving the exact
/// effective-user ownership check performed by the relay socket adapter.
///
/// - Returns: The current effective Unix UID.
fn current_uid() -> Result<u32, CliError> {
    let output = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(|_| CliError::CurrentUid)?;
    if !output.status.success() {
        return Err(CliError::CurrentUid);
    }
    String::from_utf8(output.stdout)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .ok_or(CliError::CurrentUid)
}

/// Loads the validated configuration, binds the listener, and serves until termination.
///
/// - Parameter config_path: Path to the validated relay TOML file.
/// - Returns: A redacted setup or serving error.
async fn run_relay(config_path: &Path) -> Result<(), CliError> {
    let config = RelayConfig::from_path(config_path).map_err(CliError::Relay)?;
    let listener = TailscaleListener::bind(&config, current_uid()?)
        .await
        .map_err(CliError::Relay)?;
    let address = listener.local_addr().map_err(CliError::Relay)?;
    eprintln!(
        "{COMMAND_NAME}: listening on {}:{}",
        address.ip(),
        address.port()
    );
    let report = listener
        .serve_until(shutdown_signal())
        .await
        .map_err(CliError::Relay)?;
    eprintln!(
        "{COMMAND_NAME}: stopped accepted={} rejected={} completed={} failed={} cancelled={}",
        report.accepted(),
        report.rejected(),
        report.completed(),
        report.failed(),
        report.cancelled()
    );
    Ok(())
}

/// Waits for the user-level process termination signals supported by the host.
///
/// - Returns: After SIGINT, SIGTERM, or the platform's equivalent interrupt signal.
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
///
/// - Returns: After the platform's interrupt signal.
#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::{CliCommand, parse_args};
    use std::path::PathBuf;

    // TEST:relay/src/bin/herdogrelay.rs[tests::config_option_is_parsed]
    #[test]
    fn config_option_is_parsed() {
        let command = parse_args(["--config", "/tmp/relay.toml"]).expect("parse config option");
        match command {
            CliCommand::Run { config_path } => {
                assert_eq!(config_path, PathBuf::from("/tmp/relay.toml"));
            }
            _ => panic!("expected run command"),
        }
    }

    // TEST:relay/src/bin/herdogrelay.rs[tests::print_default_config_is_selected]
    #[test]
    fn print_default_config_is_selected() {
        assert!(matches!(
            parse_args(["--print-default-config"]).expect("parse template option"),
            CliCommand::PrintDefaultConfig
        ));
    }

    // TEST:relay/src/bin/herdogrelay.rs[tests::non_home_config_path_is_unchanged]
    #[test]
    fn non_home_config_path_is_unchanged() {
        let path = PathBuf::from("/tmp/relay.toml");
        assert_eq!(super::expand_home(path.clone()).expect("expand path"), path);
    }

    // TEST:relay/src/bin/herdogrelay.rs[tests::named_home_path_is_not_rewritten]
    #[test]
    fn named_home_path_is_not_rewritten() {
        let path = PathBuf::from("~other/relay.toml");
        assert_eq!(super::expand_home(path.clone()).expect("expand path"), path);
    }

    // TEST:relay/src/bin/herdogrelay.rs[tests::unknown_option_is_rejected]
    #[test]
    fn unknown_option_is_rejected() {
        let error = parse_args(["--unknown"]).expect_err("unknown option must fail");
        assert!(error.to_string().contains("unknown option"));
    }
}
