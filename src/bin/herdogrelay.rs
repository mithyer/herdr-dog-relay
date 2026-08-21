//! Command-line host for the Herdr-dog Relay listener.

use herdr_dog_relay::{
    config::{DEFAULT_CONFIG_TOML, RelayConfig},
    listener::TailscaleListener,
    manager::{
        DEFAULT_MANAGER_CONFIG_TOML, Manager, ManagerConfig, epoch_seconds, run_relay_child,
    },
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
const HELP_TEXT: &str = "herdogrelay - authenticated Herdr-dog byte relay\n\nUsage:\n  herdogrelay [--config PATH]\n  herdogrelay manager [--config PATH]\n  herdogrelay relay-child --ipc PATH --session NAME --generation N --data-port PORT --parent-pid PID\n  herdogrelay --print-default-config\n  herdogrelay --print-manager-config\n  herdogrelay --print-launch-agent --config PATH\n  herdogrelay --help\n  herdogrelay --version\n\nOptions:\n  -c, --config PATH       Read the validated TOML configuration from PATH.\n      --print-default-config\n                          Print the complete commented v1 relay TOML template.\n      --print-manager-config\n                          Print the complete commented RSB-2 Manager TOML template.\n      --print-launch-agent --config PATH\n                          Print a safe user-level Manager LaunchAgent plist.\n  -h, --help              Print this help text.\n  -V, --version           Print the package version.\n\nThe relay uses a user-level process and does not require sudo.\n";

/// One parsed CLI operation.
#[derive(Debug)]
enum CliCommand {
    /// Start the standalone listener using the selected v1 configuration file.
    Run { config_path: PathBuf },
    /// Start the local RSB-2 Manager lifecycle host.
    Manager { config_path: PathBuf },
    /// Start one controlled same-binary relay child lifecycle process.
    RelayChild {
        /// Protected Manager bootstrap IPC path.
        ipc_path: PathBuf,
        /// Canonical session passed by Manager.
        session: String,
        /// Manager-owned child generation.
        generation: u64,
        /// Manager-reserved data port.
        data_port: u16,
        /// Manager process ID for child orphan cleanup.
        parent_pid: u32,
    },
    /// Print the complete safe relay configuration template and exit.
    PrintDefaultConfig,
    /// Print the complete safe Manager configuration template and exit.
    PrintManagerConfig,
    /// Print a user-level Manager LaunchAgent template and exit.
    PrintLaunchAgent { config_path: PathBuf },
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
        Ok(CliCommand::PrintManagerConfig) => {
            print!("{DEFAULT_MANAGER_CONFIG_TOML}");
            Ok(())
        }
        Ok(CliCommand::PrintLaunchAgent { config_path }) => {
            match ManagerConfig::from_path(&config_path) {
                Ok(config) => config
                    .launch_agent_plist(&config_path)
                    .map(|plist| {
                        print!("{plist}");
                    })
                    .map_err(CliError::Relay),
                Err(error) => Err(CliError::Relay(error)),
            }
        }
        Ok(CliCommand::Manager { config_path }) => run_manager(&config_path).await,
        Ok(CliCommand::RelayChild {
            ipc_path,
            session,
            generation,
            data_port,
            parent_pid,
        }) => run_relay_child(&ipc_path, &session, generation, data_port, parent_pid)
            .await
            .map_err(CliError::Relay),
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
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    match arguments.first().map(String::as_str) {
        Some("manager") => parse_manager_command(&arguments[1..]),
        Some("relay-child") => parse_child_command(&arguments[1..]),
        _ => parse_top_level_command(&arguments),
    }
}

/// Parse the top-level standalone relay and template commands.
fn parse_top_level_command(arguments: &[String]) -> Result<CliCommand, CliError> {
    let mut config_path = None;
    let mut print_launch_agent = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "-c" | "--config" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| CliError::Usage("--config requires a path".to_owned()))?;
                config_path = Some(expand_home(PathBuf::from(value))?);
                index += 2;
            }
            "--print-default-config" => return Ok(CliCommand::PrintDefaultConfig),
            "--print-manager-config" => return Ok(CliCommand::PrintManagerConfig),
            "--print-launch-agent" => {
                print_launch_agent = true;
                index += 1;
            }
            "-h" | "--help" => return Ok(CliCommand::Help),
            "-V" | "--version" => return Ok(CliCommand::Version),
            option => return Err(CliError::Usage(format!("unknown option: {option}"))),
        }
    }
    if print_launch_agent {
        let config_path = config_path.ok_or_else(|| {
            CliError::Usage("--print-launch-agent requires --config PATH".to_owned())
        })?;
        return Ok(CliCommand::PrintLaunchAgent { config_path });
    }
    Ok(CliCommand::Run {
        config_path: config_path.unwrap_or(default_config_path()?),
    })
}

/// Parse the Manager lifecycle command without accepting arbitrary arguments.
fn parse_manager_command(arguments: &[String]) -> Result<CliCommand, CliError> {
    let mut config_path = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "-c" | "--config" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::Usage("manager --config requires a path".to_owned())
                })?;
                config_path = Some(expand_home(PathBuf::from(value))?);
                index += 2;
            }
            "-h" | "--help" => return Ok(CliCommand::Help),
            option => return Err(CliError::Usage(format!("unknown manager option: {option}"))),
        }
    }
    Ok(CliCommand::Manager {
        config_path: config_path.unwrap_or(default_manager_config_path()?),
    })
}

/// Parse the internally controlled relay-child command.
fn parse_child_command(arguments: &[String]) -> Result<CliCommand, CliError> {
    let mut ipc_path = None;
    let mut session = None;
    let mut generation = None;
    let mut data_port = None;
    let mut parent_pid = None;
    let mut index = 0;
    while index < arguments.len() {
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| CliError::Usage("relay-child option requires a value".to_owned()))?;
        match arguments[index].as_str() {
            "--ipc" => ipc_path = Some(expand_home(PathBuf::from(value))?),
            "--session" => session = Some(value.clone()),
            "--generation" => generation = Some(parse_number(value, "generation")?),
            "--data-port" => data_port = Some(parse_number(value, "data-port")?),
            "--parent-pid" => parent_pid = Some(parse_number(value, "parent-pid")?),
            option => {
                return Err(CliError::Usage(format!(
                    "unknown relay-child option: {option}"
                )));
            }
        }
        index += 2;
    }
    Ok(CliCommand::RelayChild {
        ipc_path: ipc_path
            .ok_or_else(|| CliError::Usage("relay-child requires --ipc".to_owned()))?,
        session: session
            .ok_or_else(|| CliError::Usage("relay-child requires --session".to_owned()))?,
        generation: generation
            .ok_or_else(|| CliError::Usage("relay-child requires --generation".to_owned()))?,
        data_port: data_port
            .ok_or_else(|| CliError::Usage("relay-child requires --data-port".to_owned()))?,
        parent_pid: parent_pid
            .ok_or_else(|| CliError::Usage("relay-child requires --parent-pid".to_owned()))?,
    })
}

/// Parse one bounded unsigned command-line number.
fn parse_number<T>(value: &str, field: &str) -> Result<T, CliError>
where
    T: std::str::FromStr,
{
    value
        .parse()
        .map_err(|_| CliError::Usage(format!("{field} must be a valid number")))
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

/// Resolves the default user-level Manager configuration path.
///
/// - Returns: `$HOME/.config/herdr-dog/manager/manager.toml`.
fn default_manager_config_path() -> Result<PathBuf, CliError> {
    home_directory().map(|home| home.join(".config/herdr-dog/manager/manager.toml"))
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

/// Loads the Manager configuration and owns the local lifecycle process until shutdown.
async fn run_manager(config_path: &Path) -> Result<(), CliError> {
    let config = ManagerConfig::from_path(config_path).map_err(CliError::Relay)?;
    let mut manager = Manager::open(config, current_uid()?).map_err(CliError::Relay)?;
    eprintln!(
        "{COMMAND_NAME}: manager ready generation={} sessions={}",
        manager.broker_generation(),
        manager.status().len()
    );
    let mut reap_interval = tokio::time::interval(manager.config().heartbeat_interval());
    let mut shutdown = Box::pin(shutdown_signal());
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = reap_interval.tick() => {
                let now = epoch_seconds().map_err(CliError::Relay)?;
                manager.reap(now).await.map_err(CliError::Relay)?;
            }
        }
    }
    Ok(())
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

    // TEST:relay/src/bin/herdogrelay.rs[tests::manager_subcommand_is_parsed]
    #[test]
    fn manager_subcommand_is_parsed() {
        let command = parse_args(["manager", "--config", "/tmp/manager.toml"])
            .expect("parse manager command");
        match command {
            CliCommand::Manager { config_path } => {
                assert_eq!(config_path, PathBuf::from("/tmp/manager.toml"));
            }
            _ => panic!("expected manager command"),
        }
    }

    // TEST:relay/src/bin/herdogrelay.rs[tests::relay_child_command_is_bounded]
    #[test]
    fn relay_child_command_is_bounded() {
        let command = parse_args([
            "relay-child",
            "--ipc",
            "/tmp/child.sock",
            "--session",
            "work",
            "--generation",
            "7",
            "--data-port",
            "18753",
            "--parent-pid",
            "42",
        ])
        .expect("parse child command");
        match command {
            CliCommand::RelayChild {
                ipc_path,
                session,
                generation,
                data_port,
                parent_pid,
            } => {
                assert_eq!(ipc_path, PathBuf::from("/tmp/child.sock"));
                assert_eq!(session, "work");
                assert_eq!(generation, 7);
                assert_eq!(data_port, 18_753);
                assert_eq!(parent_pid, 42);
            }
            _ => panic!("expected relay-child command"),
        }
    }

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
