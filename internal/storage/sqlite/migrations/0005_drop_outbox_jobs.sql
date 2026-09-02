-- The outbox was never drained: nothing dispatched a job, advanced its status,
-- or reaped it, so every command appended a row with a full payload BLOB that
-- no reader would ever claim. Dropping the table and its ready-queue index
-- removes unbounded growth rather than deferring a dispatcher that does not
-- exist; reintroducing at-least-once delivery should add its own table with the
-- claim protocol that makes the queue meaningful.
DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v4;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 5),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v4;
DROP TABLE schema_manifest_v4;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;

DROP INDEX outbox_jobs_ready_idx;
DROP TABLE outbox_jobs;
