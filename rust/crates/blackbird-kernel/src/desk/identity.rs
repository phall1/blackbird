//! Registration. The raw token is returned once and only its hash is stored.

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::Error;
use crate::model::{
    ACTIVE_WINDOW_US, ConversationSummary, HeldReservation, InboxItem, InboxSummary, JoinOut,
    PeerOut, SNAPSHOT_ITEMS, validate_handle, validate_project,
};
use crate::time::{ms_between, now_us};

use super::Desk;
use super::sql::{self, ActiveLease};

pub(super) struct Session {
    pub workspace_id: String,
    pub actor_id: String,
    pub session_id: String,
}

impl Desk {
    /// Register a new name, or resume one with its existing token.
    ///
    /// A resume mints a new session id, rebinds live leases onto it, and does
    /// not return the token again.
    ///
    /// # Errors
    ///
    /// When the name or project is invalid, the token does not match, or the
    /// database cannot store the row.
    pub fn join(
        &self,
        project_key: &str,
        agent_name: &str,
        registration_token: Option<&str>,
    ) -> Result<JoinOut, Error> {
        validate_project(project_key)?;
        validate_handle(agent_name, "agent_name")?;
        let registration_token = registration_token.filter(|token| !token.is_empty());
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction().map_err(sql::store)?;
        let workspace = ensure_workspace(&tx, project_key)?;
        let now = now_us();
        let existing = lookup_agent(&tx, &workspace, agent_name)?;
        let (actor_id, session_id, issued) = match existing {
            Some(agent) => resume(&tx, &agent, registration_token, now)?,
            None => register_new(&tx, &workspace, agent_name, registration_token, now)?,
        };
        let snapshot = snapshot(&tx, &workspace, &actor_id, now)?;
        tx.commit().map_err(sql::store)?;
        Ok(JoinOut {
            project_key: project_key.to_owned(),
            agent_name: agent_name.to_owned(),
            workspace_id: workspace,
            actor_id,
            session_id,
            registration_token: issued,
            held_reservations: snapshot.held,
            inbox: snapshot.inbox,
            open_conversations: snapshot.conversations,
            other_agents: snapshot.peers,
        })
    }

    pub(super) fn authenticate(&self, token: &str) -> Result<Session, Error> {
        if !token.starts_with("bbm_") {
            return Err(Error::unauthenticated("unknown agent token"));
        }
        let conn = self.lock()?;
        let hash = token_hash(token);
        let found = conn
            .query_row(
                "SELECT a.id, a.workspace_id, a.session_id
                 FROM agent a
                 WHERE a.token_hash = ?1",
                params![hash],
                |row| {
                    Ok(Session {
                        actor_id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        session_id: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(sql::store)?;
        let Some(session) = found else {
            return Err(Error::unauthenticated("unknown agent token"));
        };
        conn.execute(
            "UPDATE agent SET last_seen_at_us = ?1 WHERE id = ?2",
            params![now_us(), session.actor_id],
        )
        .map_err(sql::store)?;
        Ok(session)
    }
}

struct StoredAgent {
    id: String,
    token_hash: String,
}

struct SnapshotParts {
    held: Vec<HeldReservation>,
    inbox: InboxSummary,
    conversations: Vec<ConversationSummary>,
    peers: Vec<PeerOut>,
}

fn resume(
    conn: &Connection,
    agent: &StoredAgent,
    token: Option<&str>,
    now: i64,
) -> Result<(String, String, Option<String>), Error> {
    let Some(token) = token else {
        return Err(Error::unauthenticated(
            "registration_token is required to resume this name",
        ));
    };
    if !hashes_eq(&agent.token_hash, token) {
        return Err(Error::unauthenticated(
            "registration_token does not match this name",
        ));
    }
    let session_id = Uuid::now_v7().to_string();
    conn.execute(
        "UPDATE agent SET session_id = ?1, last_seen_at_us = ?2 WHERE id = ?3",
        params![session_id, now, agent.id],
    )
    .map_err(sql::store)?;
    conn.execute(
        "UPDATE lease SET session_id = ?1
         WHERE holder_id = ?2 AND released_at_us IS NULL AND expires_at_us > ?3",
        params![session_id, agent.id, now],
    )
    .map_err(sql::store)?;
    Ok((agent.id.clone(), session_id, None))
}

fn register_new(
    conn: &Connection,
    workspace: &str,
    name: &str,
    token: Option<&str>,
    now: i64,
) -> Result<(String, String, Option<String>), Error> {
    if token.is_some() {
        return Err(Error::invalid(
            "omit registration_token when registering a new name",
        ));
    }
    let actor_id = Uuid::now_v7().to_string();
    let session_id = Uuid::now_v7().to_string();
    let issued = new_token();
    conn.execute(
        "INSERT INTO agent(id, workspace_id, name, token_hash, session_id, started_at_us, last_seen_at_us)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![
            actor_id,
            workspace,
            name,
            token_hash(&issued),
            session_id,
            now
        ],
    )
    .map_err(sql::store)?;
    Ok((actor_id, session_id, Some(issued)))
}

fn ensure_workspace(conn: &Connection, project_key: &str) -> Result<String, Error> {
    if let Some(id) = lookup_workspace(conn, project_key)? {
        return Ok(id);
    }
    let id = Uuid::now_v7().to_string();
    match conn.execute(
        "INSERT INTO workspace(id, project_key) VALUES (?1, ?2)",
        params![id, project_key],
    ) {
        Ok(_) => Ok(id),
        Err(rusqlite::Error::SqliteFailure(code, _))
            if code.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            lookup_workspace(conn, project_key)?
                .ok_or_else(|| Error::Storage("workspace insert lost a race".to_owned()))
        }
        Err(err) => Err(sql::store(err)),
    }
}

fn lookup_workspace(conn: &Connection, project_key: &str) -> Result<Option<String>, Error> {
    conn.query_row(
        "SELECT id FROM workspace WHERE project_key = ?1",
        params![project_key],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql::store)
}

fn lookup_agent(
    conn: &Connection,
    workspace: &str,
    name: &str,
) -> Result<Option<StoredAgent>, Error> {
    conn.query_row(
        "SELECT id, token_hash FROM agent WHERE workspace_id = ?1 AND name = ?2",
        params![workspace, name],
        |row| {
            Ok(StoredAgent {
                id: row.get(0)?,
                token_hash: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(sql::store)
}

fn snapshot(
    conn: &Connection,
    workspace: &str,
    actor: &str,
    now: i64,
) -> Result<SnapshotParts, Error> {
    sql::reap(conn, workspace, now)?;
    let held = held_reservations(conn, workspace, actor, now)?;
    let inbox = inbox(conn, actor, now)?;
    let conversations = conversations(conn, workspace, actor, now)?;
    let peers = peers(conn, workspace, actor, now)?;
    Ok(SnapshotParts {
        held,
        inbox,
        conversations,
        peers,
    })
}

fn held_reservations(
    conn: &Connection,
    workspace: &str,
    actor: &str,
    now: i64,
) -> Result<Vec<HeldReservation>, Error> {
    let mut held = Vec::new();
    for lease in sql::load_active(conn, workspace, now)? {
        if lease.holder_id != actor {
            continue;
        }
        held.push(held_one(conn, workspace, &lease, now)?);
    }
    Ok(held)
}

fn held_one(
    conn: &Connection,
    workspace: &str,
    lease: &ActiveLease,
    now: i64,
) -> Result<HeldReservation, Error> {
    Ok(HeldReservation {
        lease_id: lease.id.clone(),
        mode: lease.mode.clone(),
        selectors: sql::selector_outs(conn, workspace, &lease.selectors)?,
        expires_in_ms: ms_between(lease.expires_at_us, now),
    })
}

fn inbox(conn: &Connection, actor: &str, now: i64) -> Result<InboxSummary, Error> {
    let unread = sql::count_unread(conn, actor)?;
    let needs_acknowledgement: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM delivery
             WHERE recipient_id = ?1 AND acknowledgement_required = 1 AND acknowledged_at_us IS NULL",
            params![actor],
            |row| row.get(0),
        )
        .map_err(sql::store)?;
    let mut stmt = conn
        .prepare(
            "SELECT m.id, m.conversation_id, author.name, m.subject,
                    d.read_at_us IS NOT NULL, d.acknowledgement_required,
                    d.acknowledged_at_us IS NOT NULL, m.sent_at_us
             FROM delivery d
             JOIN message m ON m.id = d.message_id
             JOIN agent author ON author.id = m.author_id
             WHERE d.recipient_id = ?1
               AND (d.read_at_us IS NULL
                    OR (d.acknowledgement_required = 1 AND d.acknowledged_at_us IS NULL))
             ORDER BY m.sent_at_us DESC
             LIMIT ?2",
        )
        .map_err(sql::store)?;
    let recent = stmt
        .query_map(params![actor, SNAPSHOT_ITEMS], |row| {
            let sent_at_us: i64 = row.get(7)?;
            Ok(InboxItem {
                message_id: row.get(0)?,
                conversation_id: row.get(1)?,
                from: row.get(2)?,
                subject: row.get(3)?,
                read: row.get::<_, i64>(4)? != 0,
                acknowledgement_required: row.get::<_, i64>(5)? != 0,
                acknowledged: row.get::<_, i64>(6)? != 0,
                sent_ms_ago: ms_between(now, sent_at_us).max(0),
            })
        })
        .map_err(sql::store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql::store)?;
    Ok(InboxSummary {
        unread,
        needs_acknowledgement,
        recent,
    })
}

fn conversations(
    conn: &Connection,
    workspace: &str,
    actor: &str,
    now: i64,
) -> Result<Vec<ConversationSummary>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT c.id, c.topic, COUNT(m.id), COALESCE(MAX(m.sent_at_us), c.opened_at_us)
             FROM conversation c
             LEFT JOIN message m ON m.conversation_id = c.id
             WHERE c.workspace_id = ?1 AND (
                 c.opened_by = ?2
                 OR EXISTS (
                     SELECT 1 FROM message mine
                     WHERE mine.conversation_id = c.id AND mine.author_id = ?2
                 )
                 OR EXISTS (
                     SELECT 1 FROM message dm
                     JOIN delivery dd ON dd.message_id = dm.id
                     WHERE dm.conversation_id = c.id AND dd.recipient_id = ?2
                 )
             )
             GROUP BY c.id
             ORDER BY COALESCE(MAX(m.sent_at_us), c.opened_at_us) DESC
             LIMIT ?3",
        )
        .map_err(sql::store)?;
    stmt.query_map(params![workspace, actor, SNAPSHOT_ITEMS], |row| {
        let last_us: i64 = row.get(3)?;
        Ok(ConversationSummary {
            conversation_id: row.get(0)?,
            topic: row.get(1)?,
            messages: row.get(2)?,
            last_message_ms_ago: ms_between(now, last_us).max(0),
        })
    })
    .map_err(sql::store)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(sql::store)
}

fn peers(conn: &Connection, workspace: &str, actor: &str, now: i64) -> Result<Vec<PeerOut>, Error> {
    let cutoff = now.saturating_sub(ACTIVE_WINDOW_US);
    let mut stmt = conn
        .prepare(
            "SELECT name, id, last_seen_at_us FROM agent
             WHERE workspace_id = ?1 AND id != ?2 AND last_seen_at_us >= ?3
             ORDER BY name",
        )
        .map_err(sql::store)?;
    stmt.query_map(params![workspace, actor, cutoff], |row| {
        let seen: i64 = row.get(2)?;
        Ok(PeerOut {
            name: row.get(0)?,
            actor_id: row.get(1)?,
            last_seen_ms_ago: ms_between(now, seen).max(0),
        })
    })
    .map_err(sql::store)?
    .collect::<Result<Vec<_>, _>>()
    .map_err(sql::store)
}

fn new_token() -> String {
    let left = Uuid::new_v4();
    let right = Uuid::new_v4();
    format!("bbm_{}{}", hex(left.as_bytes()), hex(right.as_bytes()))
}

fn token_hash(token: &str) -> String {
    hex(Sha256::digest(token.as_bytes()).as_slice())
}

fn hashes_eq(stored_hash: &str, token: &str) -> bool {
    let got = token_hash(token);
    if stored_hash.len() != got.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in stored_hash.bytes().zip(got.bytes()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
