//! Per-user install for the Rust daemon. It copies this binary to a stable
//! path, writes a launchd or systemd unit that runs `daemon`, and points the
//! MCP clients it knows about at the loopback listener. Nothing here shells
//! out, and uninstall never touches the database.
//!
//! Every config file is read and checked before anything is written, so a
//! refused merge leaves the whole home as it was.

use std::env;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

const LABEL: &str = "io.phux.blackbird-rust";
const PORT_ADDR: &str = "127.0.0.1:8081";
const MCP_URL: &str = "http://127.0.0.1:8081";
const CODEX_SECTION: &str = "[mcp_servers.blackbird]";

/// Where the install reads and writes. Tests point both at a temp directory.
pub struct Layout {
    pub home: PathBuf,
    pub config_home: PathBuf,
}

/// Paths an install wrote.
#[derive(Debug)]
pub struct Written {
    pub unit_plist: PathBuf,
    pub unit_service: PathBuf,
    pub binary: PathBuf,
}

impl Layout {
    pub fn from_env() -> Result<Self, String> {
        let home = non_empty_var("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")?;
        let config_home =
            non_empty_var("XDG_CONFIG_HOME").map_or_else(|| home.join(".config"), PathBuf::from);
        Ok(Self { home, config_home })
    }

    fn binary(&self) -> PathBuf {
        self.home.join(".local/libexec/blackbird/blackbird")
    }

    fn plist(&self) -> PathBuf {
        self.home
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist"))
    }

    fn service(&self) -> PathBuf {
        self.config_home.join("systemd/user/blackbird-rust.service")
    }

    fn claude(&self) -> PathBuf {
        self.home.join(".claude.json")
    }

    fn opencode(&self) -> PathBuf {
        self.config_home.join("opencode/opencode.json")
    }

    fn codex(&self) -> PathBuf {
        self.home.join(".codex/config.toml")
    }
}

/// True when nothing holds the loopback port the daemon serves on.
pub fn port_free() -> bool {
    TcpListener::bind(PORT_ADDR).is_ok()
}

pub fn install_into(layout: &Layout, binary: &Path, port_free: bool) -> Result<Written, String> {
    if !port_free {
        return Err("8081 is in use; the existing daemon was left running".to_owned());
    }
    let (claude, opencode, codex) = (layout.claude(), layout.opencode(), layout.codex());
    let configs = [
        (
            install_json(
                &claude,
                "mcpServers",
                json!({ "type": "http", "url": MCP_URL }),
            )?,
            claude,
        ),
        (
            install_json(
                &opencode,
                "mcp",
                json!({ "type": "remote", "url": MCP_URL }),
            )?,
            opencode,
        ),
        (install_toml(&codex)?, codex),
    ];

    let copied = layout.binary();
    copy_binary(binary, &copied)?;
    let plist = layout.plist();
    write_file(&plist, &plist_text(&copied))?;
    let service = layout.service();
    write_file(&service, &service_text(&copied))?;
    for (text, path) in &configs {
        write_file(path, text)?;
    }
    Ok(Written {
        unit_plist: plist,
        unit_service: service,
        binary: copied,
    })
}

pub fn uninstall_from(layout: &Layout) -> Result<(), String> {
    let (claude, opencode, codex) = (layout.claude(), layout.opencode(), layout.codex());
    let configs = [
        (uninstall_json(&claude, "mcpServers")?, claude),
        (uninstall_json(&opencode, "mcp")?, opencode),
        (uninstall_toml(&codex)?, codex),
    ];
    for (text, path) in configs {
        if let Some(text) = text {
            write_file(&path, &text)?;
        }
    }
    for path in [layout.plist(), layout.service(), layout.binary()] {
        remove_if_present(&path)?;
    }
    Ok(())
}

fn copy_binary(source: &Path, dest: &Path) -> Result<(), String> {
    if is_same_file(source, dest) {
        return Ok(());
    }
    create_parent(dest)?;
    // Stage beside the destination and rename, so a daemon running from the
    // old copy is never written to in place.
    let staged = dest.with_extension("new");
    fs::copy(source, &staged).map_err(|err| format!("cannot copy {}: {err}", source.display()))?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("cannot chmod {}: {err}", staged.display()))?;
    fs::rename(&staged, dest).map_err(|err| format!("cannot install {}: {err}", dest.display()))
}

fn is_same_file(a: &Path, b: &Path) -> bool {
    matches!((fs::canonicalize(a), fs::canonicalize(b)), (Ok(a), Ok(b)) if a == b)
}

fn plist_text(binary: &Path) -> String {
    let binary = xml_escape(&binary.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{binary}</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
"#
    )
}

fn service_text(binary: &Path) -> String {
    format!(
        "[Unit]\nDescription=Blackbird coordination daemon\n\n[Service]\nExecStart={} daemon\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n",
        binary.display()
    )
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn install_json(path: &Path, table: &str, entry: Value) -> Result<String, String> {
    let mut root = parse_object(path, &read_optional(path)?)?;
    let servers = child_object(&mut root, table, path)?;
    if let Some(existing) = servers
        .get("blackbird")
        .filter(|entry| entry_url(entry) != Some(MCP_URL))
    {
        return Err(conflict(path, entry_url(existing).unwrap_or("no url")));
    }
    servers.insert("blackbird".to_owned(), entry);
    to_text(&root)
}

/// `Ok(None)` means the file holds no blackbird entry of ours to remove.
fn uninstall_json(path: &Path, table: &str) -> Result<Option<String>, String> {
    let text = read_optional(path)?;
    if text.trim().is_empty() {
        return Ok(None);
    }
    let mut root = parse_object(path, &text)?;
    let Some(servers) = root.get_mut(table).and_then(Value::as_object_mut) else {
        return Ok(None);
    };
    if servers.get("blackbird").and_then(entry_url) != Some(MCP_URL) {
        return Ok(None);
    }
    servers.remove("blackbird");
    to_text(&root).map(Some)
}

fn install_toml(path: &Path) -> Result<String, String> {
    let text = read_optional(path)?;
    let lines: Vec<&str> = text.lines().collect();
    let Some((start, end)) = codex_section(&lines) else {
        return Ok(append_section(&text));
    };
    match toml_url(&lines[start + 1..end]) {
        Some(url) if url == MCP_URL => Ok(text),
        Some(url) => Err(conflict(path, &url)),
        None => {
            let mut out = String::new();
            for (index, line) in lines.iter().enumerate() {
                out.push_str(line);
                out.push('\n');
                if index == start {
                    out.push_str(&format!("url = \"{MCP_URL}\"\n"));
                }
            }
            Ok(out)
        }
    }
}

/// `Ok(None)` means the file holds no blackbird section of ours to remove.
fn uninstall_toml(path: &Path) -> Result<Option<String>, String> {
    let text = read_optional(path)?;
    let lines: Vec<&str> = text.lines().collect();
    let Some((start, end)) = codex_section(&lines) else {
        return Ok(None);
    };
    if toml_url(&lines[start + 1..end]).as_deref() != Some(MCP_URL) {
        return Ok(None);
    }
    let kept: String = lines[..start]
        .iter()
        .chain(&lines[end..])
        .map(|line| format!("{line}\n"))
        .collect();
    Ok(Some(kept))
}

/// Header index and the exclusive end of the `[mcp_servers.blackbird]` table.
fn codex_section(lines: &[&str]) -> Option<(usize, usize)> {
    let start = lines.iter().position(|line| line.trim() == CODEX_SECTION)?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(lines.len(), |offset| start + 1 + offset);
    Some((start, end))
}

fn toml_url(section: &[&str]) -> Option<String> {
    section.iter().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "url").then(|| value.trim().trim_matches('"').to_owned())
    })
}

fn append_section(text: &str) -> String {
    let mut out = text.to_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!("{CODEX_SECTION}\nurl = \"{MCP_URL}\"\n"));
    out
}

fn entry_url(entry: &Value) -> Option<&str> {
    entry.get("url")?.as_str()
}

fn child_object<'a>(
    root: &'a mut Map<String, Value>,
    table: &str,
    path: &Path,
) -> Result<&'a mut Map<String, Value>, String> {
    root.entry(table)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            format!(
                "{table} in {} is not a JSON object; left unchanged",
                path.display()
            )
        })
}

fn parse_object(path: &Path, text: &str) -> Result<Map<String, Value>, String> {
    if text.trim().is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_str(text) {
        Ok(Value::Object(root)) => Ok(root),
        Ok(_) => Err(format!(
            "{} is not a JSON object; left unchanged",
            path.display()
        )),
        Err(err) => Err(format!(
            "cannot parse {}: {err}; left unchanged",
            path.display()
        )),
    }
}

fn to_text(root: &Map<String, Value>) -> Result<String, String> {
    serde_json::to_string_pretty(root)
        .map(|text| format!("{text}\n"))
        .map_err(|err| err.to_string())
}

fn conflict(path: &Path, url: &str) -> String {
    format!(
        "{} already has a blackbird entry at {url}; left unchanged",
        path.display()
    )
}

fn read_optional(path: &Path) -> Result<String, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(format!("cannot read {}: {err}", path.display())),
    }
}

fn write_file(path: &Path, text: &str) -> Result<(), String> {
    create_parent(path)?;
    fs::write(path, text).map_err(|err| format!("cannot write {}: {err}", path.display()))
}

fn create_parent(path: &Path) -> Result<(), String> {
    match path.parent() {
        Some(parent) => fs::create_dir_all(parent)
            .map_err(|err| format!("cannot create {}: {err}", parent.display())),
        None => Ok(()),
    }
}

fn remove_if_present(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("cannot remove {}: {err}", path.display())),
    }
}

fn non_empty_var(name: &str) -> Option<std::ffi::OsString> {
    env::var_os(name).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{Layout, install_into, uninstall_from};
    use serde_json::Value;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    fn fixture() -> (TempDir, Layout, PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let layout = Layout {
            home: dir.path().join("home"),
            config_home: dir.path().join("home/.config"),
        };
        let source = dir.path().join("blackbird-src");
        fs::write(&source, "#!/bin/sh\necho blackbird\n").expect("source");
        (dir, layout, source)
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).expect("read")
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&read(path)).expect("json")
    }

    #[test]
    fn install_copies_the_binary_and_registers_each_client() {
        let (_dir, layout, source) = fixture();
        let written = install_into(&layout, &source, true).expect("install");
        let copied = layout.binary();
        assert_eq!(written.binary, copied);
        assert_eq!(
            fs::read(&copied).expect("copy"),
            fs::read(&source).expect("source")
        );
        let mode = fs::metadata(&copied).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o755);

        let plist = read(&written.unit_plist);
        assert!(plist.contains(&format!("<string>{}</string>", copied.display())));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains("io.phux.blackbird-rust"));

        let service = read(&written.unit_service);
        assert!(service.contains(&format!("ExecStart={} daemon", copied.display())));
        assert!(service.contains("Restart=on-failure"));
        assert!(service.contains("WantedBy=default.target"));

        let claude = read_json(&layout.claude());
        assert_eq!(
            claude["mcpServers"]["blackbird"]["url"],
            "http://127.0.0.1:8081"
        );
        let opencode = read_json(&layout.opencode());
        assert_eq!(opencode["mcp"]["blackbird"]["type"], "remote");
        assert_eq!(opencode["mcp"]["blackbird"]["url"], "http://127.0.0.1:8081");
        assert!(
            read(&layout.codex())
                .contains("[mcp_servers.blackbird]\nurl = \"http://127.0.0.1:8081\"")
        );
    }

    #[test]
    fn install_and_uninstall_keep_other_servers() {
        let (_dir, layout, source) = fixture();
        fs::create_dir_all(&layout.home).expect("home");
        fs::write(
            layout.claude(),
            r#"{"numStartups":3,"mcpServers":{"other":{"type":"stdio","command":"x"}}}"#,
        )
        .expect("seed");

        install_into(&layout, &source, true).expect("install");
        let installed = read_json(&layout.claude());
        assert_eq!(installed["numStartups"], 3);
        assert_eq!(installed["mcpServers"]["other"]["command"], "x");

        uninstall_from(&layout).expect("uninstall");
        let remaining = read_json(&layout.claude());
        assert_eq!(remaining["numStartups"], 3);
        assert_eq!(remaining["mcpServers"]["other"]["command"], "x");
        assert!(remaining["mcpServers"].get("blackbird").is_none());
        assert!(!layout.plist().exists());
        assert!(!layout.service().exists());
        assert!(!layout.binary().exists());
    }

    #[test]
    fn busy_port_creates_nothing() {
        let (_dir, layout, source) = fixture();
        let err = install_into(&layout, &source, false).expect_err("busy");
        assert_eq!(err, "8081 is in use; the existing daemon was left running");
        assert!(!layout.plist().exists());
        assert!(!layout.binary().exists());
        assert!(!layout.claude().exists());
    }

    #[test]
    fn foreign_blackbird_url_is_refused_and_left_alone() {
        let (_dir, layout, source) = fixture();
        fs::create_dir_all(&layout.home).expect("home");
        let seeded =
            r#"{"mcpServers":{"blackbird":{"type":"http","url":"http://127.0.0.1:9999"}}}"#;
        fs::write(layout.claude(), seeded).expect("seed");

        let err = install_into(&layout, &source, true).expect_err("conflict");
        assert!(err.contains("left unchanged"), "{err}");
        assert_eq!(read(&layout.claude()), seeded);
        assert!(!layout.plist().exists());
    }

    #[test]
    fn reinstalling_from_the_installed_copy_keeps_the_binary() {
        let (_dir, layout, source) = fixture();
        install_into(&layout, &source, true).expect("first install");
        install_into(&layout, &layout.binary(), true).expect("second install");
        assert_eq!(
            fs::read(layout.binary()).expect("copy"),
            fs::read(&source).expect("source")
        );
    }

    #[test]
    fn codex_config_keeps_other_tables() {
        let (_dir, layout, source) = fixture();
        fs::create_dir_all(&layout.home).expect("home");
        fs::create_dir_all(layout.home.join(".codex")).expect("codex dir");
        fs::write(
            layout.codex(),
            "model = \"x\"\n\n[mcp_servers.other]\nurl = \"http://example.test\"\n",
        )
        .expect("seed");

        install_into(&layout, &source, true).expect("install");
        let installed = read(&layout.codex());
        assert!(installed.contains("model = \"x\""));
        assert!(installed.contains("[mcp_servers.other]\nurl = \"http://example.test\""));
        assert!(installed.contains("[mcp_servers.blackbird]\nurl = \"http://127.0.0.1:8081\""));

        uninstall_from(&layout).expect("uninstall");
        let remaining = read(&layout.codex());
        assert!(remaining.contains("model = \"x\""));
        assert!(remaining.contains("[mcp_servers.other]"));
        assert!(!remaining.contains("[mcp_servers.blackbird]"));
    }
}
