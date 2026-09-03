-- Admit the two facts the journal could not record: a refused claim and a
-- completed wait.
--
-- Until this rung every event_type in the closed set above was a SUCCESS --
-- three mail facts and three lease facts -- so the journal could say what
-- worked and nothing about what being blocked cost. A denial and a wait are the
-- denominator of every contention question, and they were never written down.
--
-- They live in coordination_events rather than in a table of their own, and
-- that is a retention decision before it is a modelling one. Migration 0010
-- made this journal, and only this journal, prunable: the retention boundary,
-- the CASCADE from the recipients table and the age-and-count pruner all key on
-- coordination_events.position. A second table would have grown forever until
-- someone taught the pruner about it, and a fact nobody prunes is a fact that
-- eventually costs more than it explains. Reusing the journal also hands these
-- facts the same (workspace_id, actor_id) identity telemetry_model_calls
-- carries, so "what did contention cost" is a join rather than a correlation.
--
-- One thing reusing the journal does NOT buy, and it would be easy to assume
-- otherwise: position is COMMIT order, not occurrence order. Both new facts are
-- written by a paced background drain, so a refusal commits a coalesce window
-- or two after it was decided and therefore sits behind acquisitions that
-- happened after it. occurred_at_us is the authority on when; position is the
-- authority on order-of-record and on cursor progress, and nothing may read one
-- as the other. The age pruner in cmd/blackbird is written to survive exactly
-- this skew rather than to assume it away.
--
-- SQLite cannot widen a CHECK in place, so this is the rebuild-and-copy shape
-- migrations 0005 through 0007 and 0011 used. Two tables are rebuilt rather
-- than one because coordination_event_recipients.position REFERENCES this
-- table ON DELETE CASCADE: renaming the parent rewrites the child's reference
-- to the renamed table, and dropping that parent would then cascade every
-- recipient row into oblivion. Rebuilding the child in the same rung is what
-- keeps a blind copy attributed to the recipient who was blind-copied.
--
-- The copy preserves position, so every consumer cursor, every retention
-- boundary and every recipient row survives.

ALTER TABLE coordination_event_recipients RENAME TO coordination_event_recipients_v11;
ALTER TABLE coordination_events RENAME TO coordination_events_v11;

CREATE TABLE coordination_events (
    position INTEGER PRIMARY KEY AUTOINCREMENT CHECK (position BETWEEN 1 AND 9007199254740991),
    workspace_id TEXT NOT NULL CHECK (length(workspace_id) = 36),
    actor_id TEXT NOT NULL CHECK (length(actor_id) = 36),
    event_type TEXT NOT NULL CHECK (event_type IN ('message.available', 'message.read', 'message.acknowledged',
        'lease.acquired', 'lease.renewed', 'lease.released', 'lease.refused', 'wait.completed')),
    subject_id TEXT NOT NULL CHECK (length(CAST(subject_id AS BLOB)) BETWEEN 1 AND 256),
    occurred_at_us INTEGER NOT NULL CHECK (occurred_at_us > 0),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 2 AND 262144),
    visibility TEXT NOT NULL DEFAULT 'actor' CHECK (visibility IN ('actor', 'recipients', 'workspace'))
) STRICT;
INSERT INTO coordination_events(position, workspace_id, actor_id, event_type, subject_id,
    occurred_at_us, payload, visibility)
SELECT position, workspace_id, actor_id, event_type, subject_id, occurred_at_us, payload, visibility
FROM coordination_events_v11;

CREATE TABLE coordination_event_recipients (
    position INTEGER NOT NULL REFERENCES coordination_events(position) ON DELETE CASCADE,
    actor_id TEXT NOT NULL CHECK (length(actor_id) = 36),
    PRIMARY KEY (position, actor_id)
) STRICT;
INSERT INTO coordination_event_recipients(position, actor_id)
SELECT position, actor_id FROM coordination_event_recipients_v11;

-- position is an AUTOINCREMENT key, so its high-water mark lives in
-- sqlite_sequence rather than in the table. Copying rows carries it only while
-- rows remain: a journal that 0010's pruner emptied completely leaves the new
-- table with no sequence at all, and the next event would then reissue a
-- position that every consumer cursor has already passed -- which reads as a
-- rewritten history rather than a new fact. Carrying the old mark forward is
-- what keeps positions strictly monotone across this rebuild.
INSERT INTO sqlite_sequence(name, seq)
SELECT 'coordination_events', 0
WHERE EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'coordination_events_v11')
  AND NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'coordination_events');
UPDATE sqlite_sequence
SET seq = MAX(seq, (SELECT seq FROM sqlite_sequence WHERE name = 'coordination_events_v11'))
WHERE name = 'coordination_events'
  AND EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'coordination_events_v11');

DROP TABLE coordination_event_recipients_v11;
DROP TABLE coordination_events_v11;

CREATE INDEX coordination_events_actor_idx
ON coordination_events(workspace_id, actor_id, position);
CREATE INDEX coordination_events_workspace_idx
ON coordination_events(workspace_id, position);
CREATE INDEX coordination_event_recipients_actor_idx
ON coordination_event_recipients(actor_id, position);

-- Both tables keep their no_update trigger and neither regains a no_delete one:
-- 0010 removed those deliberately so the journal stays prunable.
CREATE TRIGGER coordination_events_no_update
BEFORE UPDATE ON coordination_events BEGIN SELECT RAISE(ABORT, 'coordination events are immutable'); END;
CREATE TRIGGER coordination_event_recipients_no_update
BEFORE UPDATE ON coordination_event_recipients BEGIN
    SELECT RAISE(ABORT, 'coordination event recipients are immutable');
END;

-- Every rung records the version it reached, so the manifest's version CHECK has
-- to admit this one.
DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v11;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 12),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v11;
DROP TABLE schema_manifest_v11;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
