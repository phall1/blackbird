//! The desk is the coordination module: one SQLite file, eight operations.

mod identity;
mod lease;
mod mail;
mod sql;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::Connection;

use crate::error::Error;
use crate::model::{ProjectReport, Summary};

const SCHEMA: &str = include_str!("../schema.sql");

/// Open coordination database.
///
/// The file is created if needed. It is not the Go daemon's database.
#[derive(Debug)]
pub struct Desk {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl Desk {
    /// Open or create `path`, migrating an empty file to schema 1.
    ///
    /// # Errors
    ///
    /// When the directory cannot be created, the file cannot be opened, or the
    /// schema version is not one this kernel understands.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|err| Error::Storage(err.to_string()))?;
            set_private_dir(parent);
        }
        let conn = Connection::open(path).map_err(sql::store)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(sql::store)?;
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))
            .map_err(sql::store)?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(sql::store)?;
        migrate(&conn)?;
        set_private_file(path);
        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// Database path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Row counts. Does not require an agent token.
    ///
    /// # Errors
    ///
    /// When the database cannot be read.
    pub fn summary(&self) -> Result<Summary, Error> {
        let conn = self.lock()?;
        let schema = schema_version(&conn)?;
        Ok(Summary {
            path: self.path.clone(),
            schema,
            workspaces: count(&conn, "SELECT COUNT(*) FROM workspace")?,
            agents: count(&conn, "SELECT COUNT(*) FROM agent")?,
            active_leases: count(
                &conn,
                "SELECT COUNT(*) FROM lease WHERE released_at_us IS NULL AND expires_at_us > \
                 CAST(strftime('%s','now') AS INTEGER) * 1000000",
            )?,
            messages: count(&conn, "SELECT COUNT(*) FROM message")?,
        })
    }

    /// Operator view of names and live leases. Tokens are not included.
    ///
    /// # Errors
    ///
    /// When the database cannot be read.
    pub fn report(&self) -> Result<Vec<ProjectReport>, Error> {
        let conn = self.lock()?;
        let now = crate::time::now_us();
        let mut projects = conn
            .prepare("SELECT id, project_key FROM workspace ORDER BY project_key")
            .map_err(sql::store)?;
        let ids = projects
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql::store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql::store)?;
        drop(projects);
        let mut reports = Vec::with_capacity(ids.len());
        for (id, project_key) in ids {
            sql::reap(&conn, &id, now)?;
            let mut names = conn
                .prepare("SELECT name FROM agent WHERE workspace_id = ?1 ORDER BY name")
                .map_err(sql::store)?;
            let agents = names
                .query_map([&id], |row| row.get(0))
                .map_err(sql::store)?
                .collect::<Result<Vec<String>, _>>()
                .map_err(sql::store)?;
            drop(names);
            let leases = sql::load_active(&conn, &id, now)?
                .into_iter()
                .map(|lease| {
                    let paths = lease
                        .selectors
                        .iter()
                        .map(|(kind, path)| format!("{kind}:{path}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("{} {} {paths}", lease.holder_name, lease.mode)
                })
                .collect();
            reports.push(ProjectReport {
                project_key,
                agents,
                leases,
            });
        }
        Ok(reports)
    }

    pub(super) fn lock(&self) -> Result<MutexGuard<'_, Connection>, Error> {
        self.conn
            .lock()
            .map_err(|_| Error::Storage("database lock poisoned".to_owned()))
    }
}

fn migrate(conn: &Connection) -> Result<(), Error> {
    let version = schema_version(conn)?;
    if version == 0 {
        // One transaction so a crash cannot leave tables without user_version 1.
        let tx = conn.unchecked_transaction().map_err(sql::store)?;
        tx.execute_batch(SCHEMA).map_err(sql::store)?;
        tx.pragma_update(None, "user_version", 1)
            .map_err(sql::store)?;
        tx.commit().map_err(sql::store)?;
        return Ok(());
    }
    if version == 1 {
        return Ok(());
    }
    Err(Error::Storage(format!(
        "unsupported blackbird-rs schema version {version}"
    )))
}

fn schema_version(conn: &Connection) -> Result<i64, Error> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sql::store)
}

fn count(conn: &Connection, sql: &str) -> Result<i64, Error> {
    conn.query_row(sql, [], |row| row.get(0))
        .map_err(sql::store)
}

fn set_private_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn set_private_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
