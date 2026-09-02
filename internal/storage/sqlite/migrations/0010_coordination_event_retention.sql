-- Journal facts are immutable while retained, but unlike message bodies the
-- journal is a cache of recent coordination activity and must be deletable.
DROP TRIGGER coordination_events_no_delete;
DROP TRIGGER coordination_event_recipients_no_delete;

-- retained_from_position is the first position that can still be returned.
-- A cursor at retained_from_position - 1 remains a valid resume boundary.
CREATE TABLE coordination_event_retention (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    retained_from_position INTEGER NOT NULL CHECK (retained_from_position BETWEEN 1 AND 9007199254740991),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us > 0)
) STRICT;
INSERT INTO coordination_event_retention(singleton, retained_from_position, updated_at_us)
VALUES (1, 1, CAST(unixepoch('subsec') * 1000000 AS INTEGER));
CREATE TRIGGER coordination_event_retention_no_delete
BEFORE DELETE ON coordination_event_retention BEGIN
    SELECT RAISE(ABORT, 'coordination event retention boundary cannot be deleted');
END;

DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v9;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 10),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v9;
DROP TABLE schema_manifest_v9;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
