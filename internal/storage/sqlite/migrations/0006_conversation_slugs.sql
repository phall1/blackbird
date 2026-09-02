-- conversation_open minted a fresh UUID on every call, so an agent that reopens
-- "the auth refactor" after a compaction started a second thread while its
-- teammates kept replying to the first. A slug is the alternate key that makes
-- reopening idempotent: the UUID stays the conversation's identity, the slug
-- only addresses it, and uniqueness is per workspace because that is the scope
-- an agent's names are meaningful in.
--
-- The column is nullable and the index is partial, so every conversation opened
-- without a slug -- including every one already stored -- stays exempt from the
-- constraint rather than colliding on NULL.
ALTER TABLE conversations ADD COLUMN slug TEXT
    CHECK (slug IS NULL OR length(CAST(slug AS BLOB)) BETWEEN 1 AND 128);

CREATE UNIQUE INDEX conversations_slug_idx ON conversations(workspace_id, slug) WHERE slug IS NOT NULL;

-- Every rung records the version it reached, so the manifest's version CHECK has
-- to admit this one. SQLite cannot widen a CHECK in place, hence the rebuild --
-- the same shape migration 0005 used, including dropping and restoring the
-- immutability triggers that would otherwise abort the copy.
DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v5;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 6),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v5;
DROP TABLE schema_manifest_v5;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
