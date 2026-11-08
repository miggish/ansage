mod cli;
mod config;
mod control;
mod daemon;
mod fib;
mod http;
mod peer;
mod rib;

use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, ValueEnum};
use tracing::error;
use tracing_subscriber::EnvFilter;

use cli::Command;
use config::Config;

/// Config file used when `--config` is not given.
const DEFAULT_CONFIG: &str = "ansage.toml";

/// BGP speaker that announces your own prefixes. Without a command it runs
/// the daemon.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the configuration file [default: ansage.toml]. With a client
    /// command, its `control_socket` is used.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    /// Control socket for the client commands [default: from --config, else
    /// /run/ansage/ansage.sock].
    #[arg(short, long, global = true)]
    socket: Option<PathBuf>,
    /// Client commands: print the raw JSON reply.
    #[arg(long, global = true)]
    json: bool,
    /// Daemon log format: text (colored on a terminal) or json (one object per
    /// line).
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match args.command {
        None => {
            let path = args.config.unwrap_or_else(|| DEFAULT_CONFIG.into());
            match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime.block_on(run_daemon(&path, args.log_format)),
                Err(err) => {
                    eprintln!("ansage: cannot start the runtime: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(Command::Check) => {
            let path = args.config.unwrap_or_else(|| DEFAULT_CONFIG.into());
            match Config::load(&path) {
                Ok(config) => {
                    println!(
                        "{}: OK, {} neighbors, {} own prefixes",
                        path.display(),
                        config.neighbors.len(),
                        config.announce.len()
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("ansage: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(command) => {
            let socket = match socket_path(args.socket, args.config.as_deref()) {
                Ok(socket) => socket,
                Err(err) => {
                    eprintln!("ansage: {err}");
                    return ExitCode::FAILURE;
                }
            };
            cli::run(&socket, args.json, command)
        }
    }
}

async fn run_daemon(config_path: &Path, log_format: LogFormat) -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let logs = tracing_subscriber::fmt().with_env_filter(filter);
    match log_format {
        LogFormat::Json => logs.json().init(),
        // Colors only for a person at a terminal (journald and files get
        // plain text); NO_COLOR is honored by tracing-subscriber itself.
        LogFormat::Text => logs.with_ansi(std::io::stdout().is_terminal()).init(),
    }
    match daemon::run(config_path).await {
        Ok(daemon::Exit::Stopped) => ExitCode::SUCCESS,
        Ok(daemon::Exit::Restart) => ExitCode::from(daemon::RESTART_EXIT_CODE),
        Err(err) => {
            error!("{err}");
            ExitCode::FAILURE
        }
    }
}

/// `--socket`, else the config's `control_socket`, else the default.
fn socket_path(socket: Option<PathBuf>, config: Option<&Path>) -> Result<PathBuf, String> {
    match (socket, config) {
        (Some(socket), _) => Ok(socket),
        (None, Some(path)) => match Config::load(path) {
            Ok(config) if config.control_socket.as_os_str().is_empty() => Err(format!(
                "control_socket is turned off in {}",
                path.display()
            )),
            Ok(config) => Ok(config.control_socket),
            Err(err) => Err(err.to_string()),
        },
        (None, None) => Ok(config::DEFAULT_CONTROL_SOCKET.into()),
    }
}
