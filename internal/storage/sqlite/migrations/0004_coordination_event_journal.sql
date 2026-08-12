DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v3;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 4),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v3;
DROP TABLE schema_manifest_v3;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;

CREATE TABLE coordination_event_cursor_keys (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    key BLOB NOT NULL CHECK (length(key) = 32),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0)
) STRICT;

CREATE TABLE coordination_events (
    position INTEGER PRIMARY KEY AUTOINCREMENT CHECK (position BETWEEN 1 AND 9007199254740991),
    workspace_id TEXT NOT NULL CHECK (length(workspace_id) = 36),
    actor_id TEXT NOT NULL CHECK (length(actor_id) = 36),
    event_type TEXT NOT NULL CHECK (event_type IN ('message.available', 'message.read', 'message.acknowledged',
        'lease.acquired', 'lease.renewed', 'lease.released')),
    subject_id TEXT NOT NULL CHECK (length(CAST(subject_id AS BLOB)) BETWEEN 1 AND 256),
    occurred_at_us INTEGER NOT NULL CHECK (occurred_at_us > 0),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 2 AND 262144)
) STRICT;

CREATE INDEX coordination_events_actor_idx
ON coordination_events(workspace_id, actor_id, position);

CREATE TRIGGER coordination_events_no_update
BEFORE UPDATE ON coordination_events BEGIN SELECT RAISE(ABORT, 'coordination events are immutable'); END;
CREATE TRIGGER coordination_events_no_delete
BEFORE DELETE ON coordination_events BEGIN SELECT RAISE(ABORT, 'coordination events are immutable'); END;
CREATE TRIGGER coordination_event_cursor_keys_no_update
BEFORE UPDATE ON coordination_event_cursor_keys BEGIN SELECT RAISE(ABORT, 'coordination cursor key is immutable'); END;
CREATE TRIGGER coordination_event_cursor_keys_no_delete
BEFORE DELETE ON coordination_event_cursor_keys BEGIN SELECT RAISE(ABORT, 'coordination cursor key is immutable'); END;
