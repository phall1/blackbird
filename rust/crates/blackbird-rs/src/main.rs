//! `blackbird` serves the coordination kernel.
//!
//! `mcp` speaks newline-delimited JSON-RPC on stdin and stdout. `daemon` serves
//! HTTP on a loopback address. `install` copies this binary to a per-user path
//! and registers it with the MCP clients. `doctor` and `status` read the
//! kernel's own SQLite file. Nothing in this process dials a phux socket or the
//! Go daemon on `127.0.0.1:8081`.

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
mod install;
mod mcp;

use std::env;
use std::ffi::OsString;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use blackbird_kernel::Desk;

const DEFAULT_LISTEN: &str = "127.0.0.1:8081";

const HELP: &str = "\
blackbird — coordination kernel (identity, mail, path leases)

Usage:
  blackbird mcp | stdio                 Serve the MCP tools on stdin/stdout
  blackbird daemon [--http-listen ADDR] Serve HTTP on a loopback address
                                        (default 127.0.0.1:8081)
  blackbird doctor                      Open the database and print counts
  blackbird status | agents | reservations | overview
                                        List projects, agents, and live leases
  blackbird inbox                       Print the stored message count
  blackbird install                     Copy the binary, write a user service,
                                        and register the MCP clients
  blackbird uninstall                   Reverse install; the database is kept
  blackbird --version | --help

Global flag, before or after the command:
  --sqlite-path PATH   Database file. Default: $BLACKBIRD_DB, then
                       $XDG_STATE_HOME/blackbird/coordination-v1.sqlite, then
                       $HOME/.local/state/blackbird/coordination-v1.sqlite.
                       The file name differs from the Go daemon's.
";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("blackbird: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let argv: Vec<String> = env::args().skip(1).collect();
    // A bare `--sqlite-path PATH` runs the daemon, so a service unit can pin
    // the database without naming a subcommand.
    let daemon_implied = argv
        .first()
        .is_some_and(|arg| arg.starts_with("--sqlite-path"));
    let (sqlite, rest) = take_sqlite_path(argv)?;
    let command = match rest.first() {
        Some(command) if !(daemon_implied && command.starts_with("--")) => command.as_str(),
        _ if daemon_implied => return run_daemon(sqlite.as_deref(), &rest),
        _ => return print_help(),
    };
    dispatch(command, sqlite.as_deref(), &rest)
}

fn dispatch(command: &str, sqlite: Option<&str>, rest: &[String]) -> Result<ExitCode, String> {
    match command {
        "--help" | "-h" => print_help(),
        "--version" | "-V" | "version" => {
            println!("{}", version_line());
            Ok(ExitCode::SUCCESS)
        }
        "daemon" => run_daemon(sqlite, &rest[1..]),
        "install" => {
            expect_no_args(rest)?;
            run_install()
        }
        "uninstall" => {
            expect_no_args(rest)?;
            run_uninstall()
        }
        "mcp" | "stdio" | "doctor" | "status" | "agents" | "reservations" | "overview"
        | "inbox" => {
            expect_no_args(rest)?;
            let desk = open_desk(sqlite)?;
            run_with_desk(command, &desk)
        }
        _ => Err(format!("unknown command {command}; see --help")),
    }
}

fn run_with_desk(command: &str, desk: &Desk) -> Result<ExitCode, String> {
    match command {
        "mcp" | "stdio" => mcp::serve(desk).map_err(|err| err.to_string()),
        "doctor" => print_doctor(desk).map(|()| ExitCode::SUCCESS),
        "status" | "agents" | "reservations" | "overview" => {
            print_status(desk).map(|()| ExitCode::SUCCESS)
        }
        "inbox" => print_inbox(desk).map(|()| ExitCode::SUCCESS),
        _ => Err(format!("unknown command {command}; see --help")),
    }
}

fn version_line() -> String {
    let version = option_env!("BLACKBIRD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    let commit = option_env!("BLACKBIRD_COMMIT").unwrap_or("unknown");
    let built_at = option_env!("BLACKBIRD_BUILT_AT").unwrap_or("unknown");
    format!("blackbird version={version} commit={commit} built_at={built_at}")
}

fn print_help() -> Result<ExitCode, String> {
    print!("{HELP}");
    Ok(ExitCode::SUCCESS)
}

fn run_daemon(sqlite: Option<&str>, args: &[String]) -> Result<ExitCode, String> {
    let listen = take_http_listen(args)?;
    let path = database_path(sqlite)?;
    serve_http(&path, &listen)
}

/// Binds first, so a bad address fails before the database is touched.
fn serve_http(path: &Path, listen: &str) -> Result<ExitCode, String> {
    let listener = bind_loopback(listen)?;
    let desk = Desk::open(path).map_err(|err| err.to_string())?;
    http::serve(&desk, listener).map_err(|err| err.to_string())?;
    Ok(ExitCode::SUCCESS)
}

fn bind_loopback(listen: &str) -> Result<TcpListener, String> {
    let host = listen.rsplit_once(':').map_or(listen, |(host, _)| host);
    if !matches!(host, "127.0.0.1" | "localhost") {
        return Err(format!(
            "--http-listen host must be 127.0.0.1 or localhost, not {host}"
        ));
    }
    TcpListener::bind(listen).map_err(|err| format!("cannot bind {listen}: {err}"))
}

fn run_install() -> Result<ExitCode, String> {
    let layout = install::Layout::from_env()?;
    let binary = env::current_exe().map_err(|err| format!("cannot locate this binary: {err}"))?;
    let written = install::install_into(&layout, &binary, install::port_free())?;
    println!("binary: {}", written.binary.display());
    println!("launchd: {}", written.unit_plist.display());
    println!("systemd: {}", written.unit_service.display());
    println!("MCP clients registered; the database was not touched");
    Ok(ExitCode::SUCCESS)
}

fn run_uninstall() -> Result<ExitCode, String> {
    let layout = install::Layout::from_env()?;
    install::uninstall_from(&layout)?;
    println!("uninstalled; the database was kept");
    Ok(ExitCode::SUCCESS)
}

fn open_desk(sqlite: Option<&str>) -> Result<Desk, String> {
    let path = database_path(sqlite)?;
    Desk::open(&path).map_err(|err| err.to_string())
}

fn take_sqlite_path(argv: Vec<String>) -> Result<(Option<String>, Vec<String>), String> {
    let mut path = None;
    let mut rest = Vec::new();
    let mut args = argv.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--sqlite-path" {
            path = Some(args.next().ok_or("--sqlite-path needs a path")?);
        } else if let Some(value) = arg.strip_prefix("--sqlite-path=") {
            path = Some(value.to_owned());
        } else {
            rest.push(arg);
        }
    }
    Ok((path, rest))
}

fn take_http_listen(args: &[String]) -> Result<String, String> {
    let mut listen = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--http-listen" {
            listen = Some(iter.next().ok_or("--http-listen needs an address")?.clone());
        } else if let Some(value) = arg.strip_prefix("--http-listen=") {
            listen = Some(value.to_owned());
        } else {
            return Err(format!("unexpected argument {arg}; see --help"));
        }
    }
    Ok(listen.unwrap_or_else(|| DEFAULT_LISTEN.to_owned()))
}

fn expect_no_args(rest: &[String]) -> Result<(), String> {
    match rest.get(1) {
        Some(extra) => Err(format!("unexpected argument {extra}; see --help")),
        None => Ok(()),
    }
}

fn database_path(flag: Option<&str>) -> Result<PathBuf, String> {
    if let Some(flag) = flag.filter(|flag| !flag.is_empty()) {
        return Ok(PathBuf::from(flag));
    }
    if let Some(from_env) = non_empty_var("BLACKBIRD_DB") {
        return Ok(PathBuf::from(from_env));
    }
    let state = non_empty_var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| non_empty_var("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| "set --sqlite-path or BLACKBIRD_DB; HOME is not set".to_owned())?;
    Ok(state.join("blackbird").join("coordination-v1.sqlite"))
}

fn non_empty_var(name: &str) -> Option<OsString> {
    env::var_os(name).filter(|value| !value.is_empty())
}

fn print_doctor(desk: &Desk) -> Result<(), String> {
    let summary = desk.summary().map_err(|err| err.to_string())?;
    println!("blackbird");
    println!("database: {}", summary.path.display());
    println!("schema: {}", summary.schema);
    println!(
        "workspaces: {}  agents: {}  active leases: {}  messages: {}",
        summary.workspaces, summary.agents, summary.active_leases, summary.messages
    );
    Ok(())
}

fn print_inbox(desk: &Desk) -> Result<(), String> {
    let summary = desk.summary().map_err(|err| err.to_string())?;
    println!("messages: {}", summary.messages);
    println!("unread mail is read with blackbird_read");
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
    use super::{bind_loopback, database_path, serve_http, take_http_listen, take_sqlite_path};

    fn words(text: &[&str]) -> Vec<String> {
        text.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn default_database_is_not_the_go_daemon_file() {
        let path = database_path(None).expect("home");
        let text = path.display().to_string();
        assert!(text.ends_with("coordination-v1.sqlite"));
        assert!(!text.ends_with("/coordination.sqlite"));
    }

    #[test]
    fn sqlite_path_is_global_before_or_after_the_command() {
        let (path, rest) =
            take_sqlite_path(words(&["--sqlite-path", "/tmp/a.sqlite", "doctor"])).expect("flag");
        assert_eq!(path.as_deref(), Some("/tmp/a.sqlite"));
        assert_eq!(rest, words(&["doctor"]));

        let (path, rest) =
            take_sqlite_path(words(&["daemon", "--sqlite-path=/tmp/b.sqlite"])).expect("flag");
        assert_eq!(path.as_deref(), Some("/tmp/b.sqlite"));
        assert_eq!(rest, words(&["daemon"]));
    }

    #[test]
    fn sqlite_path_needs_a_value() {
        assert!(take_sqlite_path(words(&["doctor", "--sqlite-path"])).is_err());
    }

    #[test]
    fn http_listen_defaults_and_accepts_the_equals_form() {
        assert_eq!(take_http_listen(&[]).expect("default"), "127.0.0.1:8081");
        let args = words(&["--http-listen=localhost:0"]);
        assert_eq!(take_http_listen(&args).expect("form"), "localhost:0");
    }

    #[test]
    fn listener_refuses_non_loopback_hosts_before_binding() {
        let err = bind_loopback("0.0.0.0:0").expect_err("refused");
        assert!(err.contains("127.0.0.1 or localhost"), "{err}");
    }

    #[test]
    fn daemon_serves_health_on_an_ephemeral_port() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("coordination-v1.sqlite");
        let listener = bind_loopback("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let desk = Desk::open(&path).expect("open");
        std::thread::spawn(move || {
            let _ = http::serve(&desk, listener);
        });
        let mut stream = std::net::TcpStream::connect(addr).expect("connect");
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .expect("write");
        let mut body = String::new();
        stream.read_to_string(&mut body).expect("read");
        assert!(body.contains("{\"status\":\"ok\"}"), "{body}");
    }
}
