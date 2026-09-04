-- Cross-host mail: the three tables that let an agent on one machine address an
-- agent on another without either database learning about the other.
--
-- Nothing here replicates. A message that crosses a host boundary is APPENDED
-- to the receiving host's own mailbox, by that host, using ids that host mints,
-- after that host resolves the recipient in its own project. The sending host
-- keeps its own copy of what it said and a record of what became of it. There
-- is no shared id space, no merge, no clock comparison, and no state either
-- host can change on the other -- which is exactly why no conflict resolution
-- is needed and none is written here.
--
-- The remote agent itself needs no table. It is an ordinary row in
-- coordination_agents named "agent@host", used in both directions: the
-- recipient of mail sent to it, and the author of mail received from it. So a
-- cross-host exchange is one ordinary thread in the ordinary inbox, and read
-- marks, acknowledgements, replies and the mail wakeup all work without knowing
-- a host boundary was crossed. Two properties keep that row from being a way
-- in: its registration_token_digest is random rather than the digest of any
-- token, so it authenticates nobody, and its session is closed as it is
-- created, so it never appears in the active roster as if it were running here.
-- "@" is reserved in a newly registered agent name for the same reason, so the
-- two namespaces cannot collide.

-- coordination_peer_threads correlates two hosts' conversations WITHOUT either
-- adopting the other's conversation id.
--
-- The alternative was to carry the originating conversation id across and store
-- it, and that is the thing this whole design refuses: it would make one host's
-- identity meaningful on another, which is a shared id space by another name
-- and the first step of a merge. A thread key is instead an opaque random
-- correlator minted by whichever host opens the exchange. Each host maps it to
-- a conversation it minted itself, and a reply carries the key back rather than
-- a conversation id, which is what keeps one exchange in one thread on both
-- sides.
--
-- It is keyed by workspace, not globally. A key is a value a peer sends us, and
-- a globally keyed table would let a peer that named project A append into a
-- conversation belonging to project B by sending B's key. Scoping the lookup to
-- the workspace the peer named means a key can only ever reach a conversation
-- in the project whose recipients it also had to resolve.
CREATE TABLE coordination_peer_threads (
    workspace_id TEXT NOT NULL CHECK (length(workspace_id) = 36),
    thread_key TEXT NOT NULL CHECK (length(CAST(thread_key AS BLOB)) BETWEEN 1 AND 64),
    conversation_id TEXT NOT NULL UNIQUE REFERENCES conversations(conversation_id),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    PRIMARY KEY (workspace_id, thread_key)
) STRICT;

-- coordination_peer_outbox is one remote delivery and what became of it. It
-- mirrors exactly one message_deliveries row -- the delivery to the peer's
-- local actor -- so the message body, subject, thread topic and
-- acknowledgement flag are all read by joining rather than copied here. An
-- outbox entry is a pointer to a message, never a second version of one.
--
-- Three columns are nullable, and each absence is a fact rather than a gap:
--
--   next_attempt_at_us  NULL exactly when the entry is terminal. There is no
--                       next attempt, and writing one -- or a zero -- would put
--                       a due entry that will never be attempted into the
--                       drain's own query.
--   last_error          NULL until an attempt has actually failed. "No attempt
--                       has failed" and "an attempt failed for a reason we did
--                       not record" are different facts and only the second is
--                       a defect.
--   remote_message_id   NULL until a peer has NAMED one. It is a receipt for
--                       something on another machine, never an id this host can
--                       resolve, so a placeholder here would be a fabricated
--                       reference to a row that does not exist anywhere.
--
-- The CHECK below is what keeps those three consistent with the state, so a
-- queued entry cannot lose its due time and a settled one cannot keep it.
CREATE TABLE coordination_peer_outbox (
    message_id TEXT NOT NULL REFERENCES messages(message_id),
    peer_actor_id TEXT NOT NULL REFERENCES coordination_agents(actor_id),
    peer_host TEXT NOT NULL CHECK (length(CAST(peer_host AS BLOB)) BETWEEN 1 AND 253),
    peer_agent TEXT NOT NULL CHECK (length(CAST(peer_agent AS BLOB)) BETWEEN 1 AND 128),
    peer_project_key TEXT NOT NULL CHECK (length(CAST(peer_project_key AS BLOB)) BETWEEN 1 AND 4096),
    thread_key TEXT NOT NULL CHECK (length(CAST(thread_key AS BLOB)) BETWEEN 1 AND 64),
    state TEXT NOT NULL CHECK (state IN ('queued', 'delivered', 'undeliverable')),
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 1024),
    queued_at_us INTEGER NOT NULL CHECK (queued_at_us > 0),
    next_attempt_at_us INTEGER CHECK (next_attempt_at_us IS NULL OR next_attempt_at_us > 0),
    settled_at_us INTEGER CHECK (settled_at_us IS NULL OR settled_at_us > 0),
    last_error TEXT CHECK (last_error IS NULL OR length(CAST(last_error AS BLOB)) BETWEEN 1 AND 2048),
    remote_message_id TEXT CHECK (remote_message_id IS NULL OR length(CAST(remote_message_id AS BLOB)) BETWEEN 1 AND 128),
    PRIMARY KEY (message_id, peer_host, peer_agent),
    CHECK (
        (state = 'queued' AND next_attempt_at_us IS NOT NULL AND settled_at_us IS NULL AND remote_message_id IS NULL)
        OR (state <> 'queued' AND next_attempt_at_us IS NULL AND settled_at_us IS NOT NULL)
    ),
    CHECK (remote_message_id IS NULL OR state = 'delivered')
) STRICT;

-- The drain's only query: queued entries whose time has come, oldest first.
CREATE INDEX coordination_peer_outbox_due_idx
ON coordination_peer_outbox(state, next_attempt_at_us, queued_at_us);

-- Settled entries are swept on a retention window, and this is the index that
-- makes the sweep cheap enough to run inside the transaction that settles.
CREATE INDEX coordination_peer_outbox_settled_idx
ON coordination_peer_outbox(settled_at_us);

-- coordination_peer_inbound is the idempotency key for mail arriving here.
--
-- A sender that loses our response retries, and it must not be able to append
-- the same message twice by doing so. The key is the SENDING host's message id
-- scoped by the origin host we VERIFIED -- not the one the payload claimed --
-- so two hosts that mint the same id cannot collide and a host cannot claim
-- another's namespace. The row also gives an operator the join from "this
-- message" to "the message the peer thinks it sent", which is otherwise
-- unrecoverable once the response is gone.
CREATE TABLE coordination_peer_inbound (
    origin_host TEXT NOT NULL CHECK (length(CAST(origin_host AS BLOB)) BETWEEN 1 AND 253),
    origin_message_id TEXT NOT NULL CHECK (length(CAST(origin_message_id AS BLOB)) BETWEEN 1 AND 128),
    message_id TEXT NOT NULL REFERENCES messages(message_id),
    accepted_at_us INTEGER NOT NULL CHECK (accepted_at_us > 0),
    PRIMARY KEY (origin_host, origin_message_id)
) STRICT;

-- An accepted message is a fact about something that already happened on
-- another machine. Nothing may rewrite one, exactly as nothing may rewrite a
-- journal event.
CREATE TRIGGER coordination_peer_inbound_no_update
BEFORE UPDATE ON coordination_peer_inbound BEGIN
    SELECT RAISE(ABORT, 'accepted peer mail is immutable');
END;

-- Every rung records the version it reached, so the manifest's version CHECK has
-- to admit this one.
DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v12;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 13),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v12;
DROP TABLE schema_manifest_v12;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
