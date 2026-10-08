//! Wire shapes for the eight coordination operations.
//!
//! Field names match the Go daemon's MCP objects so a harness can speak to
//! either process. This kernel omits peer-mail, spend, and tracker fields
//! rather than inventing empty ones.

use serde::Serialize;

use crate::error::Error;

pub(crate) const DEFAULT_TTL_SECONDS: u64 = 3600;
pub(crate) const MAX_TTL_SECONDS: u64 = 24 * 60 * 60;
pub(crate) const DEFAULT_LIMIT: u16 = 50;
pub(crate) const MAX_LIMIT: u16 = 100;
pub(crate) const MAX_WAIT_SECONDS: u64 = 60;
pub(crate) const MAX_SELECTORS: usize = 256;
pub(crate) const MAX_SELECTOR_BYTES: usize = 4096;
pub(crate) const MAX_HANDLE_BYTES: usize = 128;
pub(crate) const MAX_PROJECT_BYTES: usize = 4096;
pub(crate) const MAX_SUBJECT_BYTES: usize = 512;
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024;
pub(crate) const MAX_RECIPIENTS: usize = 256;
pub(crate) const SNAPSHOT_ITEMS: usize = 5;
pub(crate) const ACTIVE_WINDOW_US: i64 = 5 * 60 * 1_000_000;
pub(crate) const POLL_US: u64 = 250_000;

/// One path a claim covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    /// `exact` or `subtree`.
    pub kind: String,
    /// Repository-relative path. Never absolute, never `..`.
    pub path: String,
}

/// Selector as returned to an agent. `claim_generation` is informational.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SelectorOut {
    /// `exact` or `subtree`.
    pub kind: String,
    /// Repository-relative path.
    pub path: String,
    /// Handoff count for this selector. Zero means no exclusive claim has bumped it.
    #[serde(skip_serializing_if = "is_zero")]
    pub claim_generation: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Who holds a live lease, and for how long the daemon says it has left.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HolderOut {
    /// Lease id.
    pub lease_id: String,
    /// Registered name of the holder.
    pub holder_agent_name: String,
    /// Opaque actor id of the holder.
    pub holder_actor_id: String,
    /// `shared` or `exclusive`.
    pub mode: String,
    /// Paths this lease covers.
    pub selectors: Vec<SelectorOut>,
    /// Milliseconds until expiry, measured by the kernel. Negative means overdue.
    pub expires_in_ms: i64,
}

/// A claim that was stored, or a normal refusal that names the holders.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ClaimResult {
    /// False when another agent holds an overlapping lease. That is not an error.
    pub ok: bool,
    /// Present when `ok` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// `shared` or `exclusive` when `ok` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Selectors taken, when `ok` is true.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<SelectorOut>,
    /// Expiry instant, when `ok` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// The first holder blocking this claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_by: Option<HolderOut>,
    /// Every holder blocking this claim.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<HolderOut>,
    /// What the caller can do next: `wait`, `narrow`, `message`, or `force`.
    /// `force` is a social option. This kernel does not steal a lease.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

/// A lease that was released.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReservationOut {
    /// Lease id.
    pub lease_id: String,
    /// `shared` or `exclusive`.
    pub mode: String,
    /// Exact selector set that was released.
    pub selectors: Vec<SelectorOut>,
    /// When the lease would have expired.
    pub expires_at: String,
    /// When it was released.
    pub released_at: String,
}

/// One still-held lease inside a join snapshot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HeldReservation {
    /// Lease id.
    pub lease_id: String,
    /// `shared` or `exclusive`.
    pub mode: String,
    /// Selectors to send back unchanged on renew or release.
    pub selectors: Vec<SelectorOut>,
    /// Milliseconds left, measured by the kernel.
    pub expires_in_ms: i64,
}

/// One pending delivery shown at registration. The body is not included.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InboxItem {
    /// Message id.
    pub message_id: String,
    /// Conversation the message belongs to.
    pub conversation_id: String,
    /// Author's registered name.
    pub from: String,
    /// Subject line.
    pub subject: String,
    /// Whether this recipient has marked it read.
    pub read: bool,
    /// Whether the sender required an acknowledgement.
    pub acknowledgement_required: bool,
    /// Whether this recipient has acknowledged it.
    pub acknowledged: bool,
    /// Age in milliseconds, measured by the kernel.
    pub sent_ms_ago: i64,
}

/// Mailbox counts over the whole inbox, plus a short recent list.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InboxSummary {
    /// Deliveries this agent has not marked read.
    pub unread: i64,
    /// Deliveries that still require an acknowledgement.
    pub needs_acknowledgement: i64,
    /// Most recent pending deliveries, capped.
    pub recent: Vec<InboxItem>,
}

/// A conversation this agent opened, wrote, or was addressed in.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConversationSummary {
    /// Conversation id.
    pub conversation_id: String,
    /// Topic stored when the conversation was opened.
    pub topic: String,
    /// Messages in the conversation.
    pub messages: i64,
    /// Age of the latest message, or of the open when it is empty.
    pub last_message_ms_ago: i64,
}

/// Another agent with a fresh session in this project.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeerOut {
    /// Registered name.
    pub name: String,
    /// Opaque actor id.
    pub actor_id: String,
    /// Age of the last authenticated call, measured by the kernel.
    pub last_seen_ms_ago: i64,
}

/// What registration rebound onto this process.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JoinOut {
    /// Project key this name is registered under.
    pub project_key: String,
    /// Registered name.
    pub agent_name: String,
    /// Opaque workspace id.
    pub workspace_id: String,
    /// Opaque actor id. Stable across resumes.
    pub actor_id: String,
    /// Opaque session id. New on every resume.
    pub session_id: String,
    /// Present only on the first registration. Resume does not mint another.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_token: Option<String>,
    /// Leases this agent still holds.
    pub held_reservations: Vec<HeldReservation>,
    /// Inbox summary.
    pub inbox: InboxSummary,
    /// Conversations this agent already participates in.
    pub open_conversations: Vec<ConversationSummary>,
    /// Other agents seen inside the active window.
    pub other_agents: Vec<PeerOut>,
}

/// An agent with a session inside the active window.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentOut {
    /// Registered name.
    pub name: String,
    /// Opaque actor id.
    pub actor_id: String,
    /// Current session id.
    pub session_id: String,
    /// Last authenticated call, UTC.
    pub last_seen_at: String,
}

/// Peers and live claims. Tracker and spend observations are refused up front.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusOut {
    /// Agents seen inside the active window, including the caller.
    pub agents: Vec<AgentOut>,
    /// Live leases, longest remaining first.
    pub reservations: Vec<HolderOut>,
    /// True when more leases matched than `limit` returned.
    pub truncated: bool,
}

/// One recipient's receipt on a stored message.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DeliveryOut {
    /// Recipient actor id.
    pub recipient_actor_id: String,
    /// Always `to`. Cc and Bcc are not a kernel surface.
    pub kind: String,
    /// Whether this recipient has marked the message read.
    pub read: bool,
    /// Whether this recipient has acknowledged the exact body.
    pub acknowledged: bool,
}

/// One immutable message.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MessageOut {
    /// Message id.
    pub message_id: String,
    /// Conversation id.
    pub conversation_id: String,
    /// Author actor id.
    pub author_actor_id: String,
    /// Subject line.
    pub subject: String,
    /// Body bytes, decoded as UTF-8 text.
    pub body: String,
    /// SHA-256 of the body, hex encoded.
    pub body_digest: String,
    /// Message this answers, when it is a reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// When the kernel stored it, UTC.
    pub sent_at: String,
    /// Monotonic position inside the workspace, used as the page cursor.
    pub position: u64,
    /// Receipts for every recipient.
    pub deliveries: Vec<DeliveryOut>,
}

/// A page of messages.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PageOut {
    /// Messages in this page, oldest first.
    pub messages: Vec<MessageOut>,
    /// Pass as `after` to read the next page. Zero when the page is empty.
    pub next: u64,
    /// True when another page exists.
    pub has_more: bool,
}

/// Open, rejoin, and maybe send.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SayOut {
    /// Conversation written or opened.
    pub conversation_id: String,
    /// Stored topic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Stored slug, when the conversation has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    /// True when the slug already named a conversation.
    #[serde(skip_serializing_if = "is_false")]
    pub reused: bool,
    /// When the conversation was opened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opened_at: Option<String>,
    /// Present only when a message was stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Author of the stored message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_actor_id: Option<String>,
    /// Stored subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Stored body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// SHA-256 of the stored body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_digest: Option<String>,
    /// Reply target, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// When the message was stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    /// Workspace position of the stored message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<u64>,
    /// Receipts, when a message was stored.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deliveries: Vec<DeliveryOut>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Arguments for [`crate::Desk::say`].
#[derive(Debug, Clone)]
pub struct SayRequest {
    /// Existing conversation. Omit to open or rejoin by slug.
    pub conversation_id: Option<String>,
    /// Topic used when opening. Ignored when the slug already exists.
    pub topic: String,
    /// Stable thread name, unique per project.
    pub slug: String,
    /// Registered peer names. Empty opens without storing a body.
    pub to: Vec<String>,
    /// Subject line. Required when `to` is non-empty.
    pub subject: String,
    /// Message body. Required when `to` is non-empty.
    pub body: String,
    /// Message this answers.
    pub reply_to: Option<String>,
    /// Require each recipient to acknowledge the exact body.
    pub acknowledgement_required: bool,
    /// Set when the caller is trying to address another host's project.
    pub peer_project_key: Option<String>,
}

/// Read or acknowledged, for the authenticated recipient only.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AckOut {
    /// Message the fact was recorded against.
    pub message_id: String,
    /// Whether the delivery is now read.
    pub read: bool,
    /// Whether the delivery is now acknowledged.
    pub acknowledged: bool,
}

/// Why a bounded wait returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitReason {
    /// No other lease conflicts with the path and mode.
    PathFree,
    /// A delivery for the caller was stored after the wait began.
    MailArrived,
    /// Neither happened before the budget.
    Deadline,
}

impl WaitReason {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PathFree => "path_free",
            Self::MailArrived => "mail_arrived",
            Self::Deadline => "deadline",
        }
    }
}

/// What ended a wait, plus the evidence for the next call.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WaitOut {
    /// `path_free`, `mail_arrived`, or `deadline`.
    pub reason: String,
    /// How long the kernel parked, in milliseconds.
    pub waited_ms: i64,
    /// Unread deliveries at the moment the wait ended.
    pub pending_deliveries: i64,
    /// Leases still covering the path. Empty when the path is free or no path was given.
    pub blockers: Vec<HolderOut>,
}

/// Counts a doctor command can print without authenticating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Database file.
    pub path: std::path::PathBuf,
    /// Schema user_version.
    pub schema: i64,
    /// Workspace rows.
    pub workspaces: i64,
    /// Agent rows.
    pub agents: i64,
    /// Leases that have not been released and have not expired.
    pub active_leases: i64,
    /// Stored messages.
    pub messages: i64,
}

/// One project, for the operator status command. Tokens are never included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectReport {
    /// Project key.
    pub project_key: String,
    /// Registered names.
    pub agents: Vec<String>,
    /// Live leases, as holder, mode, and paths.
    pub leases: Vec<String>,
}

pub(crate) fn validate_project(value: &str) -> Result<(), Error> {
    validate_text(value, MAX_PROJECT_BYTES, "project_key")
}

pub(crate) fn validate_handle(value: &str, label: &str) -> Result<(), Error> {
    validate_text(value, MAX_HANDLE_BYTES, label)?;
    if value.contains('@') {
        return Err(Error::invalid(format!(
            "{label} cannot contain '@'; that spelling is a cross-host address"
        )));
    }
    Ok(())
}

pub(crate) fn validate_text(value: &str, max: usize, label: &str) -> Result<(), Error> {
    if value.is_empty() || value != value.trim() || value.len() > max || value.contains('\0') {
        return Err(Error::invalid(format!(
            "{label} must be non-empty, trimmed, and at most {max} bytes"
        )));
    }
    if value.chars().any(|c| c < ' ' || c == '\u{7f}') {
        return Err(Error::invalid(format!(
            "{label} contains a control character"
        )));
    }
    Ok(())
}

pub(crate) fn parse_mode(mode: Option<&str>) -> Result<String, Error> {
    match mode.unwrap_or("").trim() {
        "" | "exclusive" => Ok("exclusive".to_owned()),
        "shared" => Ok("shared".to_owned()),
        _ => Err(Error::invalid("mode must be shared or exclusive")),
    }
}

pub(crate) fn parse_ttl(ttl: Option<u64>) -> Result<u64, Error> {
    match ttl.unwrap_or(DEFAULT_TTL_SECONDS) {
        0 => Err(Error::invalid("ttl_seconds must be at least 1")),
        seconds if seconds > MAX_TTL_SECONDS => {
            Err(Error::invalid("ttl_seconds must be at most 86400"))
        }
        seconds => Ok(seconds),
    }
}

pub(crate) fn parse_limit(limit: Option<u16>) -> Result<u16, Error> {
    match limit.unwrap_or(DEFAULT_LIMIT) {
        0 => Err(Error::invalid("limit must be at least 1")),
        n if n > MAX_LIMIT => Err(Error::invalid("limit must be at most 100")),
        n => Ok(n),
    }
}

pub(crate) fn clamp_wait(timeout: Option<u64>) -> u64 {
    match timeout {
        None | Some(0) => MAX_WAIT_SECONDS,
        Some(seconds) => seconds.min(MAX_WAIT_SECONDS),
    }
}

pub(crate) fn parse_selectors(raw: &[Selector]) -> Result<Vec<Selector>, Error> {
    if raw.is_empty() || raw.len() > MAX_SELECTORS {
        return Err(Error::invalid(
            "selectors must contain between 1 and 256 paths",
        ));
    }
    let mut parsed = Vec::with_capacity(raw.len());
    let mut total = 0usize;
    for selector in raw {
        let kind = match selector.kind.as_str() {
            "exact" | "subtree" => selector.kind.clone(),
            _ => return Err(Error::invalid("selector kind must be exact or subtree")),
        };
        validate_relative_path(&selector.path)?;
        total += kind.len() + 1 + selector.path.len();
        if total > MAX_SELECTOR_BYTES {
            return Err(Error::invalid("selector set exceeds 4096 bytes"));
        }
        let next = Selector {
            kind,
            path: selector.path.clone(),
        };
        if parsed.iter().any(|prior: &Selector| overlaps(prior, &next)) {
            return Err(Error::invalid(
                "selectors in one claim must not overlap each other",
            ));
        }
        parsed.push(next);
    }
    Ok(parsed)
}

pub(crate) fn validate_relative_path(path: &str) -> Result<(), Error> {
    if path.is_empty()
        || path.len() > MAX_SELECTOR_BYTES
        || path.contains('\\')
        || path.starts_with('/')
        || path.contains('\0')
    {
        return Err(Error::invalid(
            "path must be a relative repository path with no backslashes",
        ));
    }
    if path
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(Error::invalid(
            "path must not contain empty, '.' , or '..' segments",
        ));
    }
    Ok(())
}

pub(crate) fn overlaps(left: &Selector, right: &Selector) -> bool {
    paths_overlap(&left.kind, &left.path, &right.kind, &right.path)
}

pub(crate) fn paths_overlap(kind_a: &str, path_a: &str, kind_b: &str, path_b: &str) -> bool {
    if path_a == path_b {
        return true;
    }
    (kind_a == "subtree" && child_of(path_a, path_b))
        || (kind_b == "subtree" && child_of(path_b, path_a))
}

fn child_of(parent: &str, child: &str) -> bool {
    let Some(rest) = child.strip_prefix(parent) else {
        return false;
    };
    rest.starts_with('/')
}

pub(crate) fn modes_conflict(requested: &str, existing: &str) -> bool {
    requested == "exclusive" || existing == "exclusive"
}

#[cfg(test)]
mod tests {
    use super::{Selector, paths_overlap, validate_relative_path};

    #[test]
    fn subtree_covers_a_child_and_not_a_sibling() {
        assert!(paths_overlap("subtree", "src", "exact", "src/main.rs"));
        assert!(!paths_overlap("exact", "src/main.rs", "exact", "src"));
        assert!(!paths_overlap("subtree", "src", "exact", "source"));
        assert!(validate_relative_path("../secret").is_err());
        assert!(validate_relative_path("/etc/passwd").is_err());
        let _ = Selector {
            kind: "exact".to_owned(),
            path: "src".to_owned(),
        };
    }
}
