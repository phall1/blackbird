-- A coordination event is one fact, not one copy per audience member. Existing
-- rows retain their actor-scoped meaning; new rows can name either a recipient
-- set or the whole workspace without rewriting persisted history.
ALTER TABLE coordination_events ADD COLUMN visibility TEXT NOT NULL DEFAULT 'actor'
    CHECK (visibility IN ('actor', 'recipients', 'workspace'));

CREATE TABLE coordination_event_recipients (
    position INTEGER NOT NULL REFERENCES coordination_events(position) ON DELETE CASCADE,
    actor_id TEXT NOT NULL CHECK (length(actor_id) = 36),
    PRIMARY KEY (position, actor_id)
) STRICT;

CREATE INDEX coordination_event_recipients_actor_idx
ON coordination_event_recipients(actor_id, position);

CREATE INDEX coordination_events_workspace_idx
ON coordination_events(workspace_id, position);

CREATE TRIGGER coordination_event_recipients_no_update
BEFORE UPDATE ON coordination_event_recipients BEGIN
    SELECT RAISE(ABORT, 'coordination event recipients are immutable');
END;
CREATE TRIGGER coordination_event_recipients_no_delete
BEFORE DELETE ON coordination_event_recipients BEGIN
    SELECT RAISE(ABORT, 'coordination event recipients are immutable');
END;

-- Every rung records the version it reached. SQLite cannot widen this CHECK in
-- place, so preserve the trigger-safe rebuild used by the preceding rungs.
DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v7;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 8),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v7;
DROP TABLE schema_manifest_v7;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
