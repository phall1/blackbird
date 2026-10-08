CREATE TABLE workspace (
    id TEXT PRIMARY KEY,
    project_key TEXT NOT NULL UNIQUE
);

CREATE TABLE agent (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspace(id),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    started_at_us INTEGER NOT NULL,
    last_seen_at_us INTEGER NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE TABLE conversation (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspace(id),
    slug TEXT,
    topic TEXT NOT NULL,
    opened_by TEXT NOT NULL REFERENCES agent(id),
    opened_at_us INTEGER NOT NULL
);

CREATE UNIQUE INDEX conversation_slug
    ON conversation(workspace_id, slug)
    WHERE slug IS NOT NULL;

CREATE TABLE message (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversation(id),
    workspace_id TEXT NOT NULL REFERENCES workspace(id),
    author_id TEXT NOT NULL REFERENCES agent(id),
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    digest TEXT NOT NULL,
    reply_to TEXT,
    sent_at_us INTEGER NOT NULL,
    position INTEGER NOT NULL,
    UNIQUE (conversation_id, position)
);

CREATE TABLE delivery (
    message_id TEXT NOT NULL REFERENCES message(id),
    recipient_id TEXT NOT NULL REFERENCES agent(id),
    acknowledgement_required INTEGER NOT NULL,
    read_at_us INTEGER,
    acknowledged_at_us INTEGER,
    PRIMARY KEY (message_id, recipient_id)
);

CREATE INDEX delivery_recipient ON delivery(recipient_id);

CREATE TABLE lease (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspace(id),
    holder_id TEXT NOT NULL REFERENCES agent(id),
    session_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    acquired_at_us INTEGER NOT NULL,
    expires_at_us INTEGER NOT NULL,
    released_at_us INTEGER
);

CREATE INDEX lease_workspace ON lease(workspace_id, released_at_us, expires_at_us);

CREATE TABLE lease_selector (
    lease_id TEXT NOT NULL REFERENCES lease(id),
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    PRIMARY KEY (lease_id, kind, path)
);

CREATE TABLE fence (
    workspace_id TEXT NOT NULL,
    conflict_key TEXT NOT NULL,
    counter INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, conflict_key)
);

CREATE TABLE sequence (
    workspace_id TEXT PRIMARY KEY REFERENCES workspace(id),
    next_position INTEGER NOT NULL
);
