-- Delivery progress belongs to the authenticated agent and a named adapter,
-- not to bearer-token text or a harness-local JSON file. Separate consumer IDs
-- let one actor run multiple adapters without either advancing the other.
CREATE TABLE coordination_event_consumers (
    workspace_id TEXT NOT NULL CHECK (length(workspace_id) = 36),
    actor_id TEXT NOT NULL CHECK (length(actor_id) = 36),
    consumer_id TEXT NOT NULL CHECK (length(consumer_id) BETWEEN 1 AND 64),
    position INTEGER NOT NULL CHECK (position >= 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us > 0),
    PRIMARY KEY (workspace_id, actor_id, consumer_id)
) STRICT;

CREATE INDEX coordination_event_consumers_position_idx
ON coordination_event_consumers(workspace_id, position);

DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v8;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 9),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v8;
DROP TABLE schema_manifest_v8;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
