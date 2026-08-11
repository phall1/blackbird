CREATE TABLE conversations (
    conversation_id TEXT PRIMARY KEY CHECK (length(conversation_id) = 36),
    workspace_id TEXT NOT NULL CHECK (length(workspace_id) = 36),
    run_id TEXT NOT NULL CHECK (length(run_id) = 36),
    opened_by_actor_id TEXT NOT NULL CHECK (length(opened_by_actor_id) = 36),
    opened_by_session_id TEXT NOT NULL CHECK (length(opened_by_session_id) = 36),
    topic TEXT NOT NULL CHECK (length(topic) BETWEEN 1 AND 512),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    opened_at_us INTEGER NOT NULL CHECK (opened_at_us > 0)
) STRICT;

CREATE TABLE messages (
    position INTEGER PRIMARY KEY AUTOINCREMENT CHECK (position BETWEEN 1 AND 9007199254740991),
    message_id TEXT NOT NULL UNIQUE CHECK (length(message_id) = 36),
    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
    workspace_id TEXT NOT NULL CHECK (length(workspace_id) = 36),
    author_actor_id TEXT NOT NULL CHECK (length(author_actor_id) = 36),
    author_session_id TEXT NOT NULL CHECK (length(author_session_id) = 36),
    subject TEXT NOT NULL CHECK (length(CAST(subject AS BLOB)) BETWEEN 1 AND 512),
    body TEXT NOT NULL CHECK (length(CAST(body AS BLOB)) BETWEEN 1 AND 262144),
    body_digest BLOB NOT NULL CHECK (length(body_digest) = 32),
    reply_to_message_id TEXT REFERENCES messages(message_id),
    sent_at_us INTEGER NOT NULL CHECK (sent_at_us > 0),
    UNIQUE (conversation_id, position),
    CHECK (reply_to_message_id IS NULL OR reply_to_message_id <> message_id)
) STRICT;

CREATE TABLE message_deliveries (
    message_id TEXT NOT NULL REFERENCES messages(message_id),
    recipient_actor_id TEXT NOT NULL CHECK (length(recipient_actor_id) = 36),
    recipient_kind TEXT NOT NULL CHECK (recipient_kind IN ('to', 'cc', 'bcc')),
    acknowledgement_required INTEGER NOT NULL CHECK (acknowledgement_required IN (0, 1)),
    available_at_us INTEGER,
    read_at_us INTEGER,
    acknowledged_at_us INTEGER,
    acknowledged_by_session_id TEXT CHECK (acknowledged_by_session_id IS NULL OR length(acknowledged_by_session_id) = 36),
    acknowledged_message_digest BLOB CHECK (acknowledged_message_digest IS NULL OR length(acknowledged_message_digest) = 32),
    PRIMARY KEY (message_id, recipient_actor_id),
    CHECK ((acknowledged_at_us IS NULL AND acknowledged_by_session_id IS NULL AND acknowledged_message_digest IS NULL) OR
           (acknowledged_at_us IS NOT NULL AND acknowledged_by_session_id IS NOT NULL AND acknowledged_message_digest IS NOT NULL))
) STRICT;

CREATE INDEX message_deliveries_inbox_idx ON message_deliveries(recipient_actor_id, message_id);
CREATE INDEX messages_thread_idx ON messages(conversation_id, position);

CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY CHECK (length(lease_id) = 36),
    workspace_id TEXT NOT NULL CHECK (length(workspace_id) = 36),
    holder_actor_id TEXT NOT NULL CHECK (length(holder_actor_id) = 36),
    holder_session_id TEXT NOT NULL CHECK (length(holder_session_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    mode TEXT NOT NULL CHECK (mode IN ('shared', 'exclusive')),
    status TEXT NOT NULL CHECK (status IN ('active', 'released')),
    acquired_at_us INTEGER NOT NULL CHECK (acquired_at_us > 0),
    expires_at_us INTEGER NOT NULL CHECK (expires_at_us > acquired_at_us),
    released_at_us INTEGER,
    CHECK ((status = 'active' AND released_at_us IS NULL) OR (status = 'released' AND released_at_us IS NOT NULL))
) STRICT;

CREATE TABLE lease_selectors (
    lease_id TEXT NOT NULL REFERENCES leases(lease_id),
    selector_ordinal INTEGER NOT NULL CHECK (selector_ordinal BETWEEN 0 AND 255),
    selector_kind TEXT NOT NULL CHECK (selector_kind IN ('exact', 'subtree')),
    selector_path TEXT NOT NULL,
    PRIMARY KEY (lease_id, selector_ordinal),
    UNIQUE (lease_id, selector_kind, selector_path)
) STRICT;

CREATE INDEX lease_selectors_overlap_idx ON lease_selectors(selector_path, selector_kind, lease_id);

CREATE TABLE lease_fence_counters (
    workspace_id TEXT NOT NULL CHECK (length(workspace_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    conflict_key TEXT NOT NULL,
    counter INTEGER NOT NULL CHECK (counter BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (workspace_id, authority_epoch, conflict_key)
) STRICT;

CREATE TABLE lease_fences (
    lease_id TEXT NOT NULL REFERENCES leases(lease_id),
    conflict_key TEXT NOT NULL,
    counter INTEGER NOT NULL CHECK (counter BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (lease_id, conflict_key)
) STRICT;

CREATE TRIGGER messages_no_update
BEFORE UPDATE ON messages BEGIN SELECT RAISE(ABORT, 'messages are immutable'); END;
CREATE TRIGGER messages_no_delete
BEFORE DELETE ON messages BEGIN SELECT RAISE(ABORT, 'messages are immutable'); END;
