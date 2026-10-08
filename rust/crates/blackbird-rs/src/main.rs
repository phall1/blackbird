//! `blackbird-rs` serves the coordination kernel.
//!
//! `mcp` speaks newline-delimited JSON-RPC on stdin and stdout. `doctor` and
//! `status` read the kernel's own SQLite file. Nothing in this process dials a
//! phux socket or the Go daemon on `127.0.0.1:8081`.

#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    reason = "doctor, status, and MCP responses are the program output"
)]
#![allow(
    clippy::print_stderr,
    reason = "diagnostics stay off the MCP stdout stream"
)]

mod http;
mod mcp;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use blackbird_kernel::Desk;

const HELP: &str = "\
blackbird-rs — coordination kernel (identity, mail, path leases)

Usage:
  blackbird-rs mcp [--db PATH]       Serve the eight MCP tools on stdin/stdout
  blackbird-rs doctor [--db PATH]    Open the database and print counts
  blackbird-rs status [--db PATH]    List projects, agents, and live leases
  blackbird-rs --help
  blackbird-rs --version

The database defaults to $BLACKBIRD_RS_DB, or
$XDG_STATE_HOME/blackbird-rs/coordination.sqlite. It is not the Go daemon's
database. Peer mail, telemetry, and tracker observations stay on that daemon.
";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("blackbird-rs: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print!("{HELP}");
        return Ok(ExitCode::SUCCESS);
    };
    if command == "--help" || command == "-h" {
        print!("{HELP}");
        return Ok(ExitCode::SUCCESS);
    }
    if command == "--version" || command == "-V" {
        println!("blackbird-rs {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    let db = take_db(&mut args)?;
    if args.next().is_some() {
        return Err("unexpected argument; see --help".to_owned());
    }
    let path = database_path(db.as_deref())?;
    let desk = Desk::open(&path).map_err(|err| err.to_string())?;
    match command.as_str() {
        "mcp" => mcp::serve(&desk).map_err(|err| err.to_string()),
        "doctor" => {
            print_doctor(&desk)?;
            Ok(ExitCode::SUCCESS)
        }
        "status" => {
            print_status(&desk)?;
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(format!("unknown command {command}; see --help")),
    }
}

fn take_db(args: &mut impl Iterator<Item = String>) -> Result<Option<String>, String> {
    let mut db = None;
    let mut pending = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--db" {
            db = Some(args.next().ok_or_else(|| "--db needs a path".to_owned())?);
        } else {
            pending.push(arg);
        }
    }
    if !pending.is_empty() {
        return Err(format!("unexpected argument {}; see --help", pending[0]));
    }
    Ok(db)
}

fn database_path(flag: Option<&str>) -> Result<PathBuf, String> {
    if let Some(flag) = flag {
        return Ok(PathBuf::from(flag));
    }
    if let Some(from_env) = env::var_os("BLACKBIRD_RS_DB")
        && !from_env.is_empty()
    {
        return Ok(PathBuf::from(from_env));
    }
    let state = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| "set --db or BLACKBIRD_RS_DB; HOME is not set".to_owned())?;
    Ok(state.join("blackbird-rs").join("coordination.sqlite"))
}

fn print_doctor(desk: &Desk) -> Result<(), String> {
    let summary = desk.summary().map_err(|err| err.to_string())?;
    println!("blackbird-rs");
    println!("database: {}", summary.path.display());
    println!("schema: {}", summary.schema);
    println!(
        "workspaces: {}  agents: {}  active leases: {}  messages: {}",
        summary.workspaces, summary.agents, summary.active_leases, summary.messages
    );
    Ok(())
}

fn print_status(desk: &Desk) -> Result<(), String> {
    let projects = desk.report().map_err(|err| err.to_string())?;
    if projects.is_empty() {
        println!("no projects in {}", desk.path().display());
        return Ok(());
    }
    for project in projects {
        println!("{}", project.project_key);
        if project.agents.is_empty() {
            println!("  agents: none");
        } else {
            println!("  agents: {}", project.agents.join(", "));
        }
        if project.leases.is_empty() {
            println!("  leases: none");
        }
        for lease in project.leases {
            println!("  lease: {lease}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::database_path;

    #[test]
    fn default_database_is_not_the_go_daemon_file() {
        let path = database_path(None).expect("home");
        let text = path.display().to_string();
        assert!(text.contains("blackbird-rs"));
        assert!(text.ends_with("coordination.sqlite"));
        assert!(!text.contains("blackbird/coordination"));
    }
}
