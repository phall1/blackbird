//! Conversations and immutable mail. A body without recipients is refused,
//! so an open call cannot look like a send that never landed.

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::Error;
use crate::model::{
    AckOut, DeliveryOut, MAX_BODY_BYTES, MAX_RECIPIENTS, MAX_SUBJECT_BYTES, MessageOut, PageOut,
    SayOut, SayRequest, parse_limit, validate_handle, validate_text,
};
use crate::time::{now_us, rfc3339};

use super::Desk;
use super::sql;

impl Desk {
    /// Open or rejoin a thread, and store a message when `to` is non-empty.
    ///
    /// # Errors
    ///
    /// When the token is unknown, a remote address is used, a body is present
    /// without recipients, a recipient is not registered, or the database fails.
    pub fn say(&self, token: &str, request: SayRequest) -> Result<SayOut, Error> {
        let session = self.authenticate(token)?;
        reject_remote(&request)?;
        let sending = !request.to.is_empty();
        if !sending && has_draft(&request) {
            return Err(Error::invalid(
                "to is required to store a message; the body was not stored. Omit subject and body to open a thread",
            ));
        }
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction().map_err(sql::store)?;
        let now = now_us();
        let opened =
            resolve_conversation(&tx, &session.workspace_id, &session.actor_id, &request, now)?;
        if !sending {
            let output = say_from_open(&opened);
            tx.commit().map_err(sql::store)?;
            return Ok(output);
        }
        validate_text(&request.subject, MAX_SUBJECT_BYTES, "subject")?;
        validate_body(&request.body)?;
        let recipients = resolve_recipients(&tx, &session.workspace_id, &request.to)?;
        if let Some(reply) = request.reply_to.as_deref().filter(|id| !id.is_empty()) {
            ensure_reply(&tx, &session.workspace_id, &opened.id, reply)?;
        }
        let message = insert_message(&tx, &session, &opened.id, &request, &recipients, now)?;
        tx.commit().map_err(sql::store)?;
        Ok(say_from_message(&opened, message))
    }

    /// Read the inbox, or one thread when `conversation_id` is set.
    ///
    /// A thread is visible to its opener, its authors, and its recipients.
    ///
    /// # Errors
    ///
    /// When the token or limit is invalid, the thread is not visible, or the
    /// database cannot be read.
    pub fn read(
        &self,
        token: &str,
        conversation_id: Option<&str>,
        unread_only: bool,
        after: u64,
        limit: Option<u16>,
    ) -> Result<PageOut, Error> {
        let session = self.authenticate(token)?;
        let limit = parse_limit(limit)?;
        let conn = self.lock()?;
        let conversation = conversation_id.filter(|id| !id.is_empty());
        if let Some(conversation) = conversation {
            ensure_visible(
                &conn,
                &session.workspace_id,
                &session.actor_id,
                conversation,
            )?;
        }
        let mut messages = fetch_page(
            &conn,
            &session.workspace_id,
            &session.actor_id,
            conversation,
            unread_only,
            after,
            limit,
        )?;
        let has_more = messages.len() > usize::from(limit);
        if has_more {
            messages.pop();
        }
        let next = messages
            .last()
            .map(|message| message.position)
            .unwrap_or(after);
        Ok(PageOut {
            messages,
            next,
            has_more,
        })
    }

    /// Record read or acknowledged for a message delivered to the caller.
    ///
    /// Acknowledging also marks the delivery read. The caller cannot record a
    /// fact for someone else.
    ///
    /// # Errors
    ///
    /// When the token or kind is invalid, or the message is not in this inbox.
    pub fn ack(&self, token: &str, message_id: &str, kind: &str) -> Result<AckOut, Error> {
        let session = self.authenticate(token)?;
        let acknowledge = match kind {
            "read" => false,
            "acknowledged" => true,
            _ => return Err(Error::invalid("kind must be read or acknowledged")),
        };
        if message_id.is_empty() {
            return Err(Error::invalid("message_id is required"));
        }
        let conn = self.lock()?;
        let now = now_us();
        let changed = conn
            .execute(
                "UPDATE delivery SET
                    read_at_us = COALESCE(read_at_us, ?1),
                    acknowledged_at_us = CASE
                        WHEN ?2 = 1 THEN COALESCE(acknowledged_at_us, ?1)
                        ELSE acknowledged_at_us
                    END
                 WHERE message_id = ?3 AND recipient_id = ?4",
                params![now, i64::from(acknowledge), message_id, session.actor_id],
            )
            .map_err(sql::store)?;
        if changed == 0 {
            return Err(Error::not_found("message is not in this agent's inbox"));
        }
        let (read, acknowledged) = conn
            .query_row(
                "SELECT read_at_us IS NOT NULL, acknowledged_at_us IS NOT NULL
                 FROM delivery WHERE message_id = ?1 AND recipient_id = ?2",
                params![message_id, session.actor_id],
                |row| Ok((row.get::<_, i64>(0)? != 0, row.get::<_, i64>(1)? != 0)),
            )
            .map_err(sql::store)?;
        Ok(AckOut {
            message_id: message_id.to_owned(),
            read,
            acknowledged,
        })
    }
}

struct Opened {
    id: String,
    topic: String,
    slug: Option<String>,
    opened_at_us: i64,
    reused: bool,
}

fn reject_remote(request: &SayRequest) -> Result<(), Error> {
    let peer = request
        .peer_project_key
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    let remote = request.to.iter().any(|name| name.contains('@'));
    if peer || remote {
        return Err(Error::RemoteUnsupported);
    }
    Ok(())
}

fn has_draft(request: &SayRequest) -> bool {
    !request.subject.is_empty()
        || !request.body.is_empty()
        || request.reply_to.as_deref().is_some_and(|id| !id.is_empty())
        || request.acknowledgement_required
}

fn resolve_conversation(
    conn: &Connection,
    workspace: &str,
    actor: &str,
    request: &SayRequest,
    now: i64,
) -> Result<Opened, Error> {
    if let Some(id) = request
        .conversation_id
        .as_deref()
        .filter(|id| !id.is_empty())
    {
        return load_conversation(conn, workspace, id);
    }
    if !request.slug.is_empty() {
        validate_handle(&request.slug, "slug")?;
        if let Some(existing) = find_slug(conn, workspace, &request.slug)? {
            return Ok(existing);
        }
    }
    if request.topic.is_empty() {
        return Err(Error::invalid("topic is required when opening a thread"));
    }
    validate_text(&request.topic, MAX_SUBJECT_BYTES, "topic")?;
    let id = Uuid::now_v7().to_string();
    let slug = if request.slug.is_empty() {
        None
    } else {
        Some(request.slug.clone())
    };
    conn.execute(
        "INSERT INTO conversation(id, workspace_id, slug, topic, opened_by, opened_at_us)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, workspace, slug, request.topic, actor, now],
    )
    .map_err(sql::store)?;
    Ok(Opened {
        id,
        topic: request.topic.clone(),
        slug,
        opened_at_us: now,
        reused: false,
    })
}

fn load_conversation(conn: &Connection, workspace: &str, id: &str) -> Result<Opened, Error> {
    conn.query_row(
        "SELECT id, topic, slug, opened_at_us FROM conversation WHERE id = ?1 AND workspace_id = ?2",
        params![id, workspace],
        |row| {
            Ok(Opened {
                id: row.get(0)?,
                topic: row.get(1)?,
                slug: row.get(2)?,
                opened_at_us: row.get(3)?,
                reused: false,
            })
        },
    )
    .optional()
    .map_err(sql::store)?
    .ok_or_else(|| Error::not_found("conversation was not found in this project"))
}

fn find_slug(conn: &Connection, workspace: &str, slug: &str) -> Result<Option<Opened>, Error> {
    conn.query_row(
        "SELECT id, topic, slug, opened_at_us FROM conversation WHERE workspace_id = ?1 AND slug = ?2",
        params![workspace, slug],
        |row| {
            Ok(Opened {
                id: row.get(0)?,
                topic: row.get(1)?,
                slug: row.get(2)?,
                opened_at_us: row.get(3)?,
                reused: true,
            })
        },
    )
    .optional()
    .map_err(sql::store)
}

fn resolve_recipients(
    conn: &Connection,
    workspace: &str,
    names: &[String],
) -> Result<Vec<String>, Error> {
    if names.is_empty() || names.len() > MAX_RECIPIENTS {
        return Err(Error::invalid("to must name between 1 and 256 agents"));
    }
    let mut ids = Vec::with_capacity(names.len());
    let mut seen = Vec::with_capacity(names.len());
    for name in names {
        validate_handle(name, "recipient")?;
        if seen.iter().any(|prior: &String| prior == name) {
            return Err(Error::invalid(format!("duplicate recipient {name}")));
        }
        seen.push(name.clone());
        let id: Option<String> = conn
            .query_row(
                "SELECT id FROM agent WHERE workspace_id = ?1 AND name = ?2",
                params![workspace, name],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql::store)?;
        ids.push(id.ok_or_else(|| Error::not_found(format!("agent {name} is not registered")))?);
    }
    Ok(ids)
}

fn ensure_reply(
    conn: &Connection,
    workspace: &str,
    conversation: &str,
    reply: &str,
) -> Result<(), Error> {
    let found: Option<String> = conn
        .query_row(
            "SELECT conversation_id FROM message WHERE id = ?1 AND workspace_id = ?2",
            params![reply, workspace],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql::store)?;
    if found.as_deref() != Some(conversation) {
        return Err(Error::invalid(
            "reply_to_message_id is not a message in this conversation",
        ));
    }
    Ok(())
}

fn insert_message(
    conn: &Connection,
    session: &super::identity::Session,
    conversation: &str,
    request: &SayRequest,
    recipients: &[String],
    now: i64,
) -> Result<MessageOut, Error> {
    let message_id = Uuid::now_v7().to_string();
    let position = next_position(conn, &session.workspace_id)?;
    let digest = hex(Sha256::digest(request.body.as_bytes()).as_slice());
    let reply = request.reply_to.as_deref().filter(|id| !id.is_empty());
    conn.execute(
        "INSERT INTO message(
            id, conversation_id, workspace_id, author_id, subject, body, digest, reply_to, sent_at_us, position
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            message_id,
            conversation,
            session.workspace_id,
            session.actor_id,
            request.subject,
            request.body,
            digest,
            reply,
            now,
            position
        ],
    )
    .map_err(sql::store)?;
    let mut deliveries = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        conn.execute(
            "INSERT INTO delivery(message_id, recipient_id, acknowledgement_required)
             VALUES (?1, ?2, ?3)",
            params![
                message_id,
                recipient,
                i64::from(request.acknowledgement_required)
            ],
        )
        .map_err(sql::store)?;
        deliveries.push(DeliveryOut {
            recipient_actor_id: recipient.clone(),
            kind: "to".to_owned(),
            read: false,
            acknowledged: false,
        });
    }
    Ok(MessageOut {
        message_id,
        conversation_id: conversation.to_owned(),
        author_actor_id: session.actor_id.clone(),
        subject: request.subject.clone(),
        body: request.body.clone(),
        body_digest: digest,
        reply_to: reply.map(str::to_owned),
        sent_at: rfc3339(now),
        position,
        deliveries,
    })
}

fn next_position(conn: &Connection, workspace: &str) -> Result<u64, Error> {
    let position: i64 = conn
        .query_row(
            "INSERT INTO sequence(workspace_id, next_position) VALUES (?1, 2)
             ON CONFLICT(workspace_id) DO UPDATE SET next_position = next_position + 1
             RETURNING next_position - 1",
            params![workspace],
            |row| row.get(0),
        )
        .map_err(sql::store)?;
    u64::try_from(position).map_err(|_| Error::Storage("message position overflow".to_owned()))
}

fn validate_body(body: &str) -> Result<(), Error> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES || body.contains('\0') {
        return Err(Error::invalid(
            "body must be non-empty and at most 262144 bytes",
        ));
    }
    Ok(())
}

fn say_from_open(opened: &Opened) -> SayOut {
    SayOut {
        conversation_id: opened.id.clone(),
        topic: Some(opened.topic.clone()),
        slug: opened.slug.clone(),
        reused: opened.reused,
        opened_at: Some(rfc3339(opened.opened_at_us)),
        message_id: None,
        author_actor_id: None,
        subject: None,
        body: None,
        body_digest: None,
        reply_to: None,
        sent_at: None,
        position: None,
        deliveries: Vec::new(),
    }
}

fn say_from_message(opened: &Opened, message: MessageOut) -> SayOut {
    SayOut {
        conversation_id: opened.id.clone(),
        topic: Some(opened.topic.clone()),
        slug: opened.slug.clone(),
        reused: opened.reused,
        opened_at: Some(rfc3339(opened.opened_at_us)),
        message_id: Some(message.message_id),
        author_actor_id: Some(message.author_actor_id),
        subject: Some(message.subject),
        body: Some(message.body),
        body_digest: Some(message.body_digest),
        reply_to: message.reply_to,
        sent_at: Some(message.sent_at),
        position: Some(message.position),
        deliveries: message.deliveries,
    }
}

fn ensure_visible(
    conn: &Connection,
    workspace: &str,
    actor: &str,
    conversation: &str,
) -> Result<(), Error> {
    let visible: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM conversation c
             WHERE c.id = ?1 AND c.workspace_id = ?2 AND (
                 c.opened_by = ?3
                 OR EXISTS (
                     SELECT 1 FROM message m WHERE m.conversation_id = c.id AND m.author_id = ?3
                 )
                 OR EXISTS (
                     SELECT 1 FROM message m
                     JOIN delivery d ON d.message_id = m.id
                     WHERE m.conversation_id = c.id AND d.recipient_id = ?3
                 )
             )",
            params![conversation, workspace, actor],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql::store)?;
    if visible.is_none() {
        return Err(Error::not_found(
            "conversation is not visible to this agent",
        ));
    }
    Ok(())
}

fn fetch_page(
    conn: &Connection,
    workspace: &str,
    actor: &str,
    conversation: Option<&str>,
    unread_only: bool,
    after: u64,
    limit: u16,
) -> Result<Vec<MessageOut>, Error> {
    let sql = if conversation.is_some() {
        "SELECT id FROM message
         WHERE workspace_id = ?1 AND conversation_id = ?2 AND position > ?3
         ORDER BY position
         LIMIT ?4"
    } else if unread_only {
        "SELECT m.id FROM message m
         JOIN delivery d ON d.message_id = m.id
         WHERE m.workspace_id = ?1 AND d.recipient_id = ?2 AND d.read_at_us IS NULL AND m.position > ?3
         ORDER BY m.position
         LIMIT ?4"
    } else {
        "SELECT m.id FROM message m
         JOIN delivery d ON d.message_id = m.id
         WHERE m.workspace_id = ?1 AND d.recipient_id = ?2 AND m.position > ?3
         ORDER BY m.position
         LIMIT ?4"
    };
    let mut stmt = conn.prepare(sql).map_err(sql::store)?;
    let second = conversation.unwrap_or(actor);
    let ids = stmt
        .query_map(
            params![
                workspace,
                second,
                i64::try_from(after).unwrap_or(i64::MAX),
                i64::from(limit) + 1
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(sql::store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql::store)?;
    drop(stmt);
    ids.into_iter().map(|id| load_message(conn, &id)).collect()
}

fn load_message(conn: &Connection, id: &str) -> Result<MessageOut, Error> {
    let message = conn
        .query_row(
            "SELECT id, conversation_id, author_id, subject, body, digest, reply_to, sent_at_us, position
             FROM message WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .map_err(sql::store)?;
    let mut stmt = conn
        .prepare(
            "SELECT recipient_id, read_at_us IS NOT NULL, acknowledged_at_us IS NOT NULL
             FROM delivery WHERE message_id = ?1 ORDER BY recipient_id",
        )
        .map_err(sql::store)?;
    let deliveries = stmt
        .query_map(params![id], |row| {
            Ok(DeliveryOut {
                recipient_actor_id: row.get(0)?,
                kind: "to".to_owned(),
                read: row.get::<_, i64>(1)? != 0,
                acknowledged: row.get::<_, i64>(2)? != 0,
            })
        })
        .map_err(sql::store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql::store)?;
    Ok(MessageOut {
        message_id: message.0,
        conversation_id: message.1,
        author_actor_id: message.2,
        subject: message.3,
        body: message.4,
        body_digest: message.5,
        reply_to: message.6,
        sent_at: rfc3339(message.7),
        position: u64::try_from(message.8).unwrap_or(0),
        deliveries,
    })
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
