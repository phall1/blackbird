-- Admit 'codex' as a harness.
--
-- The harness column is a closed set on purpose: an open one turns every typo
-- into a new row in every group-by. Widening it is therefore a schema change
-- rather than a config change, and SQLite cannot widen a CHECK in place -- so
-- this is the rebuild-and-copy shape migrations 0005, 0006 and 0007 used.
--
-- Codex is the harness with no plugin surface. Nothing runs inside it that
-- could push an observation, so a daemon-side reader of its own rollout ledger
-- is not one mechanism among two: it is the only way Codex spend is ever
-- observable at all. Until this rung, every such row was refused by the CHECK
-- above -- and refused SILENTLY, because the observation plane counts write
-- failures rather than returning them, exactly as its one hard rule requires.
-- That is the failure this migration exists to prevent, and it is the reason a
-- new harness constant is never only a Go constant.
--
-- The copy preserves observation_id, so every dedupe key and every retention
-- boundary survives; the indexes are recreated because dropping a table drops
-- them with it.

ALTER TABLE telemetry_model_calls RENAME TO telemetry_model_calls_v10;
CREATE TABLE telemetry_model_calls (
    observation_id TEXT PRIMARY KEY CHECK (length(observation_id) = 36),
    dedupe_key TEXT NOT NULL CHECK (length(CAST(dedupe_key AS BLOB)) BETWEEN 1 AND 256),
    project_key TEXT NOT NULL CHECK (length(CAST(project_key AS BLOB)) BETWEEN 1 AND 4096),
    actor_id TEXT NOT NULL CHECK (length(actor_id) = 36),
    session_id TEXT NOT NULL CHECK (length(session_id) = 36),
    harness TEXT NOT NULL CHECK (harness IN ('claude-code', 'codex', 'opencode', 'pi', 'unknown')),
    harness_session TEXT CHECK (harness_session IS NULL
        OR length(CAST(harness_session AS BLOB)) BETWEEN 1 AND 256),
    provider TEXT NOT NULL CHECK (length(CAST(provider AS BLOB)) BETWEEN 1 AND 64),
    model TEXT NOT NULL CHECK (length(CAST(model AS BLOB)) BETWEEN 1 AND 128),
    operation TEXT NOT NULL CHECK (operation IN ('chat', 'completion', 'embedding', 'other')),
    uncached_input_tokens INTEGER NOT NULL CHECK (uncached_input_tokens BETWEEN 0 AND 9007199254740991),
    cache_read_tokens INTEGER NOT NULL CHECK (cache_read_tokens BETWEEN 0 AND 9007199254740991),
    cache_write_tokens INTEGER NOT NULL CHECK (cache_write_tokens BETWEEN 0 AND 9007199254740991),
    output_tokens INTEGER NOT NULL CHECK (output_tokens BETWEEN 0 AND 9007199254740991),
    reasoning_tokens INTEGER CHECK (reasoning_tokens IS NULL
        OR (reasoning_tokens >= 0 AND reasoning_tokens <= output_tokens)),
    outcome TEXT NOT NULL CHECK (outcome IN ('ok', 'error', 'aborted')),
    error_kind TEXT CHECK (error_kind IS NULL OR length(CAST(error_kind AS BLOB)) BETWEEN 1 AND 128),
    started_at_us INTEGER NOT NULL CHECK (started_at_us > 0),
    duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms BETWEEN 0 AND 86400000),
    recorded_at_us INTEGER NOT NULL CHECK (recorded_at_us > 0),
    phux_terminal TEXT CHECK (phux_terminal IS NULL
        OR length(CAST(phux_terminal AS BLOB)) BETWEEN 1 AND 128),
    raw_usage TEXT CHECK (raw_usage IS NULL OR length(CAST(raw_usage AS BLOB)) <= 4096)
) STRICT;
INSERT INTO telemetry_model_calls SELECT * FROM telemetry_model_calls_v10;
DROP TABLE telemetry_model_calls_v10;

ALTER TABLE telemetry_spans RENAME TO telemetry_spans_v10;
CREATE TABLE telemetry_spans (
    span_id TEXT PRIMARY KEY CHECK (length(span_id) = 36),
    dedupe_key TEXT NOT NULL CHECK (length(CAST(dedupe_key AS BLOB)) BETWEEN 1 AND 256),
    project_key TEXT NOT NULL CHECK (length(CAST(project_key AS BLOB)) BETWEEN 1 AND 4096),
    actor_id TEXT NOT NULL CHECK (length(actor_id) = 36),
    session_id TEXT NOT NULL CHECK (length(session_id) = 36),
    harness TEXT NOT NULL CHECK (harness IN ('claude-code', 'codex', 'opencode', 'pi', 'unknown')),
    harness_session TEXT CHECK (harness_session IS NULL
        OR length(CAST(harness_session AS BLOB)) BETWEEN 1 AND 256),
    kind TEXT NOT NULL CHECK (kind IN ('tool', 'build', 'test', 'command', 'turn', 'other')),
    name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 256),
    outcome TEXT NOT NULL CHECK (outcome IN ('ok', 'error', 'aborted')),
    error_kind TEXT CHECK (error_kind IS NULL OR length(CAST(error_kind AS BLOB)) BETWEEN 1 AND 128),
    started_at_us INTEGER NOT NULL CHECK (started_at_us > 0),
    duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms BETWEEN 0 AND 86400000),
    recorded_at_us INTEGER NOT NULL CHECK (recorded_at_us > 0),
    phux_terminal TEXT CHECK (phux_terminal IS NULL
        OR length(CAST(phux_terminal AS BLOB)) BETWEEN 1 AND 128),
    attributes TEXT CHECK (attributes IS NULL OR length(CAST(attributes AS BLOB)) <= 4096)
) STRICT;
INSERT INTO telemetry_spans SELECT * FROM telemetry_spans_v10;
DROP TABLE telemetry_spans_v10;

CREATE UNIQUE INDEX telemetry_model_calls_dedupe_idx ON telemetry_model_calls(actor_id, dedupe_key);
CREATE UNIQUE INDEX telemetry_spans_dedupe_idx ON telemetry_spans(actor_id, dedupe_key);
CREATE INDEX telemetry_model_calls_project_idx ON telemetry_model_calls(project_key, started_at_us);
CREATE INDEX telemetry_model_calls_model_idx ON telemetry_model_calls(model, started_at_us);
CREATE INDEX telemetry_model_calls_sweep_idx ON telemetry_model_calls(recorded_at_us);
CREATE INDEX telemetry_spans_project_idx ON telemetry_spans(project_key, started_at_us);
CREATE INDEX telemetry_spans_sweep_idx ON telemetry_spans(recorded_at_us);

-- Every rung records the version it reached, so the manifest's version CHECK has
-- to admit this one.
DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v10;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 11),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v10;
DROP TABLE schema_manifest_v10;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
