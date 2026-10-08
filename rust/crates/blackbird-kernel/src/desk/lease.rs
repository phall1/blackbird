//! Path leases. A conflict is a normal `ok: false` result, not an error.
//! Exclusive conflicts with every overlap. Shared conflicts only with exclusive.
//! A lease the caller already holds is not a conflict; claiming the same
//! selector set again renews it as a new lease and bumps the generation.

use std::cmp::Reverse;
use std::thread;
use std::time::Duration;

use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::error::Error;
use crate::model::{
    AgentOut, ClaimResult, HolderOut, ReservationOut, Selector, StatusOut, WaitOut, WaitReason,
    clamp_wait, modes_conflict, parse_limit, parse_mode, parse_selectors, parse_ttl, paths_overlap,
    validate_relative_path,
};
use crate::time::{ms_between, now_us, rfc3339};

use super::Desk;
use super::sql::{self, ActiveLease};

const CONFLICT_OPTIONS: [&str; 4] = ["wait", "narrow", "message", "force"];

impl Desk {
    /// Take or renew the exact selector set.
    ///
    /// # Errors
    ///
    /// When the token, mode, ttl, or selectors are invalid, or the database fails.
    /// An overlapping lease held by someone else returns [`ClaimResult::ok`]` == false`.
    pub fn claim(
        &self,
        token: &str,
        mode: Option<&str>,
        selectors: &[Selector],
        ttl_seconds: Option<u64>,
    ) -> Result<ClaimResult, Error> {
        let session = self.authenticate(token)?;
        let mode = parse_mode(mode)?;
        let ttl = parse_ttl(ttl_seconds)?;
        let selectors = parse_selectors(selectors)?;
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction().map_err(sql::store)?;
        let now = now_us();
        sql::reap(&tx, &session.workspace_id, now)?;
        let active = sql::load_active(&tx, &session.workspace_id, now)?;
        let blockers = conflicting(
            &tx,
            &session.workspace_id,
            &active,
            &session.actor_id,
            &mode,
            &selectors,
            now,
        )?;
        if !blockers.is_empty() {
            tx.commit().map_err(sql::store)?;
            return Ok(refused(blockers));
        }
        supersede(&tx, &active, &session.actor_id, &selectors, now)?;
        let lease_id = insert_lease(
            &tx,
            NewLease {
                workspace: &session.workspace_id,
                actor: &session.actor_id,
                session: &session.session_id,
                mode: &mode,
                selectors: &selectors,
                now,
                ttl,
            },
        )?;
        if mode == "exclusive" {
            sql::bump_exclusive(&tx, &session.workspace_id, &selectors)?;
        }
        let taken = sql::requested_outs(&tx, &session.workspace_id, &selectors)?;
        let expires_at = rfc3339(now + i64::try_from(ttl).unwrap_or(i64::MAX) * 1_000_000);
        tx.commit().map_err(sql::store)?;
        Ok(ClaimResult {
            ok: true,
            lease_id: Some(lease_id),
            mode: Some(mode),
            selectors: taken,
            expires_at: Some(expires_at),
            blocked_by: None,
            blockers: Vec::new(),
            options: Vec::new(),
        })
    }

    /// Release the caller's lease with this exact selector set.
    ///
    /// # Errors
    ///
    /// When no live lease has that set, the token is unknown, or the selectors are invalid.
    pub fn release(&self, token: &str, selectors: &[Selector]) -> Result<ReservationOut, Error> {
        let session = self.authenticate(token)?;
        let selectors = parse_selectors(selectors)?;
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction().map_err(sql::store)?;
        let now = now_us();
        sql::reap(&tx, &session.workspace_id, now)?;
        let active = sql::load_active(&tx, &session.workspace_id, now)?;
        let Some(lease) = active.into_iter().find(|lease| {
            lease.holder_id == session.actor_id && sql::same_set(&lease.selectors, &selectors)
        }) else {
            return Err(Error::not_found(
                "no active claim has that exact selector set; partial release is rejected",
            ));
        };
        tx.execute(
            "UPDATE lease SET released_at_us = ?1 WHERE id = ?2 AND released_at_us IS NULL",
            params![now, lease.id],
        )
        .map_err(sql::store)?;
        let rendered = sql::selector_outs(&tx, &session.workspace_id, &lease.selectors)?;
        tx.commit().map_err(sql::store)?;
        Ok(ReservationOut {
            lease_id: lease.id,
            mode: lease.mode,
            selectors: rendered,
            expires_at: rfc3339(lease.expires_at_us),
            released_at: rfc3339(now),
        })
    }

    /// List agents seen in the last five minutes and the live leases.
    ///
    /// `observe_external` refuses the call. Spend, cost, and tracker reads belong
    /// to the Go daemon; this kernel will not answer them with an empty report.
    ///
    /// # Errors
    ///
    /// When the token or limit is invalid, an external observation was requested,
    /// or the database cannot be read.
    pub fn status(
        &self,
        token: &str,
        path: Option<&str>,
        limit: Option<u16>,
        observe_external: bool,
    ) -> Result<StatusOut, Error> {
        let session = self.authenticate(token)?;
        if observe_external {
            return Err(Error::DependencyUnavailable(
                "this kernel does not observe trackers, spend, or contention cost; peers and claims are unaffected, so call status without those fields".to_owned(),
            ));
        }
        let limit = parse_limit(limit)?;
        if let Some(path) = path.filter(|value| !value.is_empty()) {
            validate_relative_path(path)?;
        }
        let conn = self.lock()?;
        let now = now_us();
        sql::reap(&conn, &session.workspace_id, now)?;
        let agents = list_agents(&conn, &session.workspace_id, now)?;
        let matched = matching_leases(&conn, &session.workspace_id, path, now)?;
        let truncated = matched.len() > usize::from(limit);
        let mut reservations = Vec::new();
        for lease in matched.into_iter().take(usize::from(limit)) {
            reservations.push(sql::holder(&conn, &session.workspace_id, &lease, now)?);
        }
        Ok(StatusOut {
            agents,
            reservations,
            truncated,
        })
    }

    /// Park until the path is free, new mail arrives, or the budget ends.
    ///
    /// Existing unread mail does not wake the wait. A lease the caller already
    /// holds does not block the path. The budget is clamped to 60 seconds.
    ///
    /// # Errors
    ///
    /// When the token is unknown, neither a path nor mail was requested, the
    /// path is illegal, or the database cannot be read.
    pub fn wait(
        &self,
        token: &str,
        path: Option<&str>,
        mode: Option<&str>,
        await_mail: bool,
        timeout_seconds: Option<u64>,
    ) -> Result<WaitOut, Error> {
        let session = self.authenticate(token)?;
        let path = path.filter(|value| !value.is_empty());
        if path.is_none() && !await_mail {
            return Err(Error::invalid(
                "wait needs a path, await_mail, or both; a wait with neither can only hit the deadline",
            ));
        }
        if let Some(path) = path {
            validate_relative_path(path)?;
        }
        let mode = parse_mode(mode)?;
        let budget_us = i64::try_from(clamp_wait(timeout_seconds).saturating_mul(1_000_000))
            .unwrap_or(i64::MAX);
        let start = now_us();
        let deadline = start.saturating_add(budget_us);
        loop {
            let now = now_us();
            if let Some(outcome) = self.poll_wait(&session, path, &mode, await_mail, start, now)? {
                return Ok(outcome);
            }
            if now >= deadline {
                return self.deadline_wait(&session, path, &mode, start);
            }
            let remaining = u64::try_from(deadline - now).unwrap_or(0);
            thread::sleep(Duration::from_micros(remaining.min(crate::model::POLL_US)));
        }
    }

    fn poll_wait(
        &self,
        session: &super::identity::Session,
        path: Option<&str>,
        mode: &str,
        await_mail: bool,
        start: i64,
        now: i64,
    ) -> Result<Option<WaitOut>, Error> {
        let conn = self.lock()?;
        sql::reap(&conn, &session.workspace_id, now)?;
        let blockers = path_blockers(&conn, session, path, mode, now)?;
        if path.is_some() && blockers.is_empty() {
            return Ok(Some(wait_out(
                WaitReason::PathFree,
                start,
                now,
                sql::count_unread(&conn, &session.actor_id)?,
                Vec::new(),
            )));
        }
        if await_mail && new_mail(&conn, &session.actor_id, start)? {
            return Ok(Some(wait_out(
                WaitReason::MailArrived,
                start,
                now,
                sql::count_unread(&conn, &session.actor_id)?,
                blockers,
            )));
        }
        Ok(None)
    }

    fn deadline_wait(
        &self,
        session: &super::identity::Session,
        path: Option<&str>,
        mode: &str,
        start: i64,
    ) -> Result<WaitOut, Error> {
        let conn = self.lock()?;
        let now = now_us();
        let blockers = path_blockers(&conn, session, path, mode, now)?;
        Ok(wait_out(
            WaitReason::Deadline,
            start,
            now,
            sql::count_unread(&conn, &session.actor_id)?,
            blockers,
        ))
    }
}

fn refused(blockers: Vec<HolderOut>) -> ClaimResult {
    ClaimResult {
        ok: false,
        lease_id: None,
        mode: None,
        selectors: Vec::new(),
        expires_at: None,
        blocked_by: blockers.first().cloned(),
        blockers,
        options: CONFLICT_OPTIONS.into_iter().map(str::to_owned).collect(),
    }
}

fn conflicting(
    conn: &Connection,
    workspace: &str,
    active: &[ActiveLease],
    actor: &str,
    mode: &str,
    requested: &[Selector],
    now: i64,
) -> Result<Vec<HolderOut>, Error> {
    let mut blockers = Vec::new();
    for lease in active {
        if lease.holder_id == actor || !lease_blocks(lease, mode, requested) {
            continue;
        }
        blockers.push(sql::holder(conn, workspace, lease, now)?);
    }
    blockers.sort_by_key(|lease| Reverse(lease.expires_in_ms));
    Ok(blockers)
}

fn lease_blocks(lease: &ActiveLease, mode: &str, requested: &[Selector]) -> bool {
    if !modes_conflict(mode, &lease.mode) {
        return false;
    }
    lease.selectors.iter().any(|(kind, path)| {
        requested
            .iter()
            .any(|selector| paths_overlap(&selector.kind, &selector.path, kind, path))
    })
}

fn supersede(
    conn: &Connection,
    active: &[ActiveLease],
    actor: &str,
    requested: &[Selector],
    now: i64,
) -> Result<(), Error> {
    for lease in active {
        if lease.holder_id == actor && sql::same_set(&lease.selectors, requested) {
            conn.execute(
                "UPDATE lease SET released_at_us = ?1 WHERE id = ?2 AND released_at_us IS NULL",
                params![now, lease.id],
            )
            .map_err(sql::store)?;
        }
    }
    Ok(())
}

struct NewLease<'a> {
    workspace: &'a str,
    actor: &'a str,
    session: &'a str,
    mode: &'a str,
    selectors: &'a [Selector],
    now: i64,
    ttl: u64,
}

fn insert_lease(conn: &Connection, lease: NewLease<'_>) -> Result<String, Error> {
    let lease_id = Uuid::now_v7().to_string();
    let ttl_us = i64::try_from(lease.ttl)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    conn.execute(
        "INSERT INTO lease(id, workspace_id, holder_id, session_id, mode, acquired_at_us, expires_at_us)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            lease_id,
            lease.workspace,
            lease.actor,
            lease.session,
            lease.mode,
            lease.now,
            lease.now + ttl_us
        ],
    )
    .map_err(sql::store)?;
    for selector in lease.selectors {
        conn.execute(
            "INSERT INTO lease_selector(lease_id, kind, path) VALUES (?1, ?2, ?3)",
            params![lease_id, selector.kind, selector.path],
        )
        .map_err(sql::store)?;
    }
    Ok(lease_id)
}

fn list_agents(conn: &Connection, workspace: &str, now: i64) -> Result<Vec<AgentOut>, Error> {
    let cutoff = now.saturating_sub(crate::model::ACTIVE_WINDOW_US);
    let mut stmt = conn
        .prepare(
            "SELECT name, id, session_id, last_seen_at_us FROM agent
             WHERE workspace_id = ?1 AND last_seen_at_us >= ?2
             ORDER BY name",
        )
        .map_err(sql::store)?;
    stmt.query_map(params![workspace, cutoff], |row| {
        let seen: i64 = row.get(3)?;
        Ok(AgentOut {
            name: row.get(0)?,
            actor_id: row.get(1)?,
            session_id: row.get(2)?,
            last_seen_at: rfc3339(seen),
        })
    })
    .map_err(sql::store)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(sql::store)
}

fn matching_leases(
    conn: &Connection,
    workspace: &str,
    path: Option<&str>,
    now: i64,
) -> Result<Vec<ActiveLease>, Error> {
    let mut matched: Vec<_> = sql::load_active(conn, workspace, now)?
        .into_iter()
        .filter(|lease| path_matches(lease, path))
        .collect();
    matched.sort_by_key(|lease| Reverse(lease.expires_at_us));
    Ok(matched)
}

fn path_matches(lease: &ActiveLease, path: Option<&str>) -> bool {
    let Some(path) = path.filter(|value| !value.is_empty()) else {
        return true;
    };
    lease
        .selectors
        .iter()
        .any(|(kind, selector_path)| paths_overlap(kind, selector_path, "exact", path))
}

fn path_blockers(
    conn: &Connection,
    session: &super::identity::Session,
    path: Option<&str>,
    mode: &str,
    now: i64,
) -> Result<Vec<HolderOut>, Error> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let requested = [Selector {
        kind: "exact".to_owned(),
        path: path.to_owned(),
    }];
    let active = sql::load_active(conn, &session.workspace_id, now)?;
    conflicting(
        conn,
        &session.workspace_id,
        &active,
        &session.actor_id,
        mode,
        &requested,
        now,
    )
}

fn new_mail(conn: &Connection, actor: &str, start: i64) -> Result<bool, Error> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM delivery d
             JOIN message m ON m.id = d.message_id
             WHERE d.recipient_id = ?1 AND m.sent_at_us > ?2",
            params![actor, start],
            |row| row.get(0),
        )
        .map_err(sql::store)?;
    Ok(count > 0)
}

fn wait_out(
    reason: WaitReason,
    start: i64,
    now: i64,
    pending: i64,
    blockers: Vec<HolderOut>,
) -> WaitOut {
    WaitOut {
        reason: reason.as_str().to_owned(),
        waited_ms: ms_between(now, start).max(0),
        pending_deliveries: pending,
        blockers,
    }
}
