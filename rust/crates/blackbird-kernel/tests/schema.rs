//! Schema version gate: a fresh file is created, and anything else is refused
//! without a write.

#![allow(
    clippy::expect_used,
    reason = "integration tests fail the process when a fixture cannot be built"
)]

use std::fs;
use std::path::{Path, PathBuf};

use blackbird_kernel::{Desk, Error};
use rusqlite::Connection;

const REFUSED: &str = "unsupported database; no migration performed";

fn fixture_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp");
    let path = dir.path().join("coord.sqlite");
    (dir, path)
}

fn user_version(path: &Path) -> i64 {
    let conn = Connection::open(path).expect("open fixture");
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("read user_version")
}

fn object_names(path: &Path) -> Vec<String> {
    let conn = Connection::open(path).expect("open fixture");
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY name")
        .expect("prepare");
    stmt.query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<Vec<String>, _>>()
        .expect("collect")
}

fn legacy_file(path: &Path, user_version: i64) {
    let conn = Connection::open(path).expect("create fixture");
    conn.pragma_update(None, "user_version", user_version)
        .expect("set user_version");
    conn.execute_batch("CREATE TABLE legacy(id INTEGER);")
        .expect("create legacy table");
}

fn assert_refused(err: &Error) {
    assert!(
        matches!(err, Error::Storage(message) if message == REFUSED),
        "expected refusal, got {err:?}"
    );
}

#[test]
fn schema_fresh_file_is_created_at_version_one() {
    let (_dir, path) = fixture_path();

    let desk = Desk::open(&path).expect("open");
    drop(desk);

    assert_eq!(user_version(&path), 1);
    assert!(object_names(&path).iter().any(|name| name == "workspace"));
}

#[test]
fn schema_unknown_version_is_refused_without_writing() {
    let (_dir, path) = fixture_path();
    legacy_file(&path, 13);
    let before = fs::read(&path).expect("read before");

    let err = Desk::open(&path).expect_err("version 13 must be refused");

    assert_refused(&err);
    let after = fs::read(&path).expect("read after");
    assert_eq!(before, after, "refused open must not change the file");
}

#[test]
fn schema_version_zero_with_objects_is_refused_and_keeps_them() {
    let (_dir, path) = fixture_path();
    legacy_file(&path, 0);

    let err = Desk::open(&path).expect_err("version 0 with tables must be refused");

    assert_refused(&err);
    assert_eq!(user_version(&path), 0);
    assert_eq!(object_names(&path), vec!["legacy".to_owned()]);
}
