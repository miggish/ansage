//! The client side: `ansage <command>` sends one request to the running
//! daemon over its control socket and prints the reply.

mod client;
mod show;
mod upgrade;

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use clap::{Subcommand, ValueEnum};

use crate::control::proto::{PeerAction, Request};

#[derive(Subcommand)]
pub enum Command {
    /// Ask the running ansage (over its control socket).
    Show {
        #[command(subcommand)]
        what: Show,
    },
    /// Announce own prefixes at runtime (until restart or reload).
    Announce {
        #[arg(required = true)]
        prefixes: Vec<String>,
    },
    /// Stop announcing own prefixes at runtime (until restart or reload).
    Withdraw {
        #[arg(required = true)]
        prefixes: Vec<String>,
    },
    /// Drain (RFC 8326): send our routes with GRACEFUL_SHUTDOWN 65535:0
    /// (iBGP: LOCAL_PREF 0, eBGP: `drain_prepend` extra prepends), so
    /// neighbors move traffic to other paths while the sessions stay up.
    /// Lasts until `undrain` or a restart; a reload keeps it.
    Drain {
        /// Return only once the drain is this many seconds old (e.g. before
        /// stopping ansage in a deploy script).
        #[arg(long, value_name = "SECONDS")]
        wait: Option<u64>,
    },
    /// End a drain: our routes go out as usual again.
    Undrain,
    /// Re-read the config file and apply what changed (like SIGHUP, but
    /// with the result).
    Reload,
    /// Restart ansage (e.g. after installing a new binary) while
    /// neighbors with Graceful Restart keep our routes: checks the new
    /// binary and the config, ends the sessions, exits with status 75 (the
    /// systemd unit starts ansage again) and waits until every neighbor is
    /// back and has our full table. Exit 0 only then.
    Upgrade {
        /// The binary systemd will start: checked with `--version` and
        /// `check` against the running config before anything happens.
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Restart even if a neighbor without graceful restart would
        /// withdraw our routes, or ansage does not run under systemd.
        #[arg(long)]
        force: bool,
        /// Only show what would happen per neighbor.
        #[arg(long)]
        dry_run: bool,
        /// Seconds to wait for the neighbors [default: the restart time].
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Check the config file (load and validate) and exit 0 if it is valid.
    Check,
    /// Panic on purpose (tests the panic hook); only when the daemon runs
    /// with ANSAGE_CRASH_TEST=1.
    #[command(hide = true)]
    DebugCrash,
    /// Disable, enable or reset one neighbor.
    Peer {
        /// ID, address or address:port.
        neighbor: String,
        #[command(subcommand)]
        action: PeerCmd,
    },
}

#[derive(Subcommand)]
pub enum PeerCmd {
    /// Close the session (Cease / Administrative Shutdown) and stay down.
    Disable {
        /// Shutdown text sent to the neighbor (RFC 9003).
        #[arg(long)]
        reason: Option<String>,
    },
    /// Connect again after `disable`.
    Enable,
    /// Close the session (Cease / Administrative Reset) and reconnect.
    Reset,
}

#[derive(Subcommand)]
pub enum Show {
    /// ansage, RIB counts and one line per neighbor.
    Summary,
    /// Every neighbor in detail.
    Peers,
    /// One neighbor in detail.
    Peer {
        /// ID, address or address:port.
        neighbor: String,
    },
    /// Routes: all candidates of one prefix, or best routes.
    Rib {
        /// A prefix (exact), or an address (the longest prefix containing it).
        prefix: Option<String>,
        /// Only this family (without a prefix).
        #[arg(long, conflicts_with = "prefix")]
        family: Option<FamilyArg>,
        /// At most this many routes per family [default: 1000].
        #[arg(long, conflicts_with = "prefix")]
        limit: Option<usize>,
    },
    /// Routes ansage installed in the kernel ([kernel]) and their next hops.
    Fib,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum FamilyArg {
    Ipv4,
    Ipv6,
}

/// Commands that talk to a running ansage: one request, one reply.
pub fn run(socket: &Path, json: bool, command: Command) -> ExitCode {
    match command {
        Command::Show { what } => show::run(socket, json, what),
        Command::Announce { prefixes } => call(socket, json, Request::Announce { prefixes }, |v| {
            show::own(v, true)
        }),
        Command::Drain { wait } => drain(socket, json, wait),
        Command::Undrain => call(socket, json, Request::Undrain, |v| show::drain(v, false)),
        Command::Reload => call(socket, json, Request::Reload, show::reload),
        Command::Upgrade {
            binary,
            force,
            dry_run,
            timeout,
        } => upgrade::run(socket, json, binary.as_deref(), force, dry_run, timeout),
        Command::Check => unreachable!("handled before the socket"),
        Command::DebugCrash => call(socket, json, Request::Crash, |_| String::new()),
        Command::Withdraw { prefixes } => call(socket, json, Request::Withdraw { prefixes }, |v| {
            show::own(v, false)
        }),
        Command::Peer { neighbor, action } => {
            let (action, reason) = match action {
                PeerCmd::Disable { reason } => (PeerAction::Disable, reason),
                PeerCmd::Enable => (PeerAction::Enable, None),
                PeerCmd::Reset => (PeerAction::Reset, None),
            };
            let request = Request::Peer {
                peer: neighbor,
                action,
                reason,
            };
            call(socket, json, request, show::peer_action)
        }
    }
}

/// Sends `request` and prints the reply as JSON or through `text`.
fn call(
    socket: &Path,
    json: bool,
    request: Request,
    text: impl FnOnce(&serde_json::Value) -> String,
) -> ExitCode {
    let reply = match client::request(socket, request) {
        Ok(reply) => reply,
        Err(err) => {
            eprintln!("ansage: {err}");
            return ExitCode::FAILURE;
        }
    };
    if json {
        let mut out = serde_json::to_string_pretty(&reply).expect("a JSON value serializes");
        out.push('\n');
        print!("{out}");
    } else {
        print!("{}", text(&reply));
    }
    ExitCode::SUCCESS
}

/// `ansage drain [--wait S]`: drains, then waits until the drain is S
/// seconds old (an earlier drain counts).
fn drain(socket: &Path, json: bool, wait: Option<u64>) -> ExitCode {
    let reply = match client::request(socket, Request::Drain) {
        Ok(reply) => reply,
        Err(err) => {
            eprintln!("ansage: {err}");
            return ExitCode::FAILURE;
        }
    };
    if json {
        let mut out = serde_json::to_string_pretty(&reply).expect("a JSON value serializes");
        out.push('\n');
        print!("{out}");
    } else {
        print!("{}", show::drain(&reply, true));
    }
    let Some(wait) = wait else {
        return ExitCode::SUCCESS;
    };
    let (Some(since), Some(now)) = (reply["drained"].as_u64(), reply["now"].as_u64()) else {
        eprintln!("ansage: the reply has no drain time");
        return ExitCode::FAILURE;
    };
    let age = Duration::from_millis(now.saturating_sub(since));
    let left = Duration::from_secs(wait).saturating_sub(age);
    if !left.is_zero() {
        if !json {
            println!("Waiting {} s", left.as_secs_f64().ceil());
        }
        std::thread::sleep(left);
    }
    ExitCode::SUCCESS
}
