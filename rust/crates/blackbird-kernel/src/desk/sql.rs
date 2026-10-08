//! Shared SQLite reads. Each caller holds the desk lock and, when it writes,
//! its own transaction.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::Error;
use crate::model::{Selector, SelectorOut};
use crate::time::ms_between;

pub(super) fn store(err: rusqlite::Error) -> Error {
    Error::Storage(err.to_string())
}

pub(super) struct ActiveLease {
    pub id: String,
    pub holder_id: String,
    pub holder_name: String,
    pub mode: String,
    pub expires_at_us: i64,
    pub selectors: Vec<(String, String)>,
}

pub(super) fn reap(conn: &Connection, workspace: &str, now: i64) -> Result<(), Error> {
    conn.execute(
        "UPDATE lease SET released_at_us = expires_at_us
         WHERE workspace_id = ?1 AND released_at_us IS NULL AND expires_at_us <= ?2",
        params![workspace, now],
    )
    .map_err(store)?;
    Ok(())
}

pub(super) fn load_active(
    conn: &Connection,
    workspace: &str,
    now: i64,
) -> Result<Vec<ActiveLease>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT l.id, l.holder_id, a.name, l.mode, l.expires_at_us, s.kind, s.path
             FROM lease l
             JOIN agent a ON a.id = l.holder_id
             JOIN lease_selector s ON s.lease_id = l.id
             WHERE l.workspace_id = ?1 AND l.released_at_us IS NULL AND l.expires_at_us > ?2
             ORDER BY l.id, s.path",
        )
        .map_err(store)?;
    let rows = stmt
        .query_map(params![workspace, now], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(store)?;
    let mut ordered: Vec<ActiveLease> = Vec::new();
    for row in rows {
        let (id, holder_id, holder_name, mode, expires_at_us, kind, path) = row.map_err(store)?;
        if let Some(last) = ordered.last_mut()
            && last.id == id
        {
            last.selectors.push((kind, path));
            continue;
        }
        ordered.push(ActiveLease {
            id,
            holder_id,
            holder_name,
            mode,
            expires_at_us,
            selectors: vec![(kind, path)],
        });
    }
    Ok(ordered)
}

pub(super) fn same_set(stored: &[(String, String)], requested: &[Selector]) -> bool {
    if stored.len() != requested.len() {
        return false;
    }
    let mut left: Vec<_> = stored
        .iter()
        .map(|(kind, path)| format!("{kind}:{path}"))
        .collect();
    let mut right: Vec<_> = requested
        .iter()
        .map(|selector| format!("{}:{}", selector.kind, selector.path))
        .collect();
    left.sort();
    right.sort();
    left == right
}

pub(super) fn generation(
    conn: &Connection,
    workspace: &str,
    kind: &str,
    path: &str,
) -> Result<u64, Error> {
    let key = format!("{kind}:{path}");
    let counter: Option<i64> = conn
        .query_row(
            "SELECT counter FROM fence WHERE workspace_id = ?1 AND conflict_key = ?2",
            params![workspace, key],
            |row| row.get(0),
        )
        .optional()
        .map_err(store)?;
    Ok(u64::try_from(counter.unwrap_or(0)).unwrap_or(0))
}

pub(super) fn bump_exclusive(
    conn: &Connection,
    workspace: &str,
    selectors: &[Selector],
) -> Result<(), Error> {
    for selector in selectors {
        let key = format!("{}:{}", selector.kind, selector.path);
        conn.execute(
            "INSERT INTO fence(workspace_id, conflict_key, counter) VALUES (?1, ?2, 1)
             ON CONFLICT(workspace_id, conflict_key) DO UPDATE SET counter = counter + 1",
            params![workspace, key],
        )
        .map_err(store)?;
    }
    Ok(())
}

pub(super) fn selector_outs(
    conn: &Connection,
    workspace: &str,
    selectors: &[(String, String)],
) -> Result<Vec<SelectorOut>, Error> {
    let mut out = Vec::with_capacity(selectors.len());
    for (kind, path) in selectors {
        out.push(SelectorOut {
            kind: kind.clone(),
            path: path.clone(),
            claim_generation: generation(conn, workspace, kind, path)?,
        });
    }
    Ok(out)
}

pub(super) fn requested_outs(
    conn: &Connection,
    workspace: &str,
    selectors: &[Selector],
) -> Result<Vec<SelectorOut>, Error> {
    let stored: Vec<_> = selectors
        .iter()
        .map(|selector| (selector.kind.clone(), selector.path.clone()))
        .collect();
    selector_outs(conn, workspace, &stored)
}

pub(super) fn holder(
    conn: &Connection,
    workspace: &str,
    lease: &ActiveLease,
    now: i64,
) -> Result<crate::model::HolderOut, Error> {
    Ok(crate::model::HolderOut {
        lease_id: lease.id.clone(),
        holder_agent_name: lease.holder_name.clone(),
        holder_actor_id: lease.holder_id.clone(),
        mode: lease.mode.clone(),
        selectors: selector_outs(conn, workspace, &lease.selectors)?,
        expires_in_ms: ms_between(lease.expires_at_us, now),
    })
}

pub(super) fn count_unread(conn: &Connection, actor: &str) -> Result<i64, Error> {
    conn.query_row(
        "SELECT COUNT(*) FROM delivery WHERE recipient_id = ?1 AND read_at_us IS NULL",
        params![actor],
        |row| row.get(0),
    )
    .map_err(store)
}
