-- The observation plane (ADR-0001). Token spend, latency, model attribution,
-- and span timing for the agent fleet, reported by the harness adapters.
--
-- These tables are deliberately NOT wired into coordination:
--
--   * No foreign keys point from here into coordination_projects or
--     coordination_agents. An FK would let a telemetry row refuse a
--     coordination delete, which is precisely the failure the plane's one hard
--     rule forbids -- telemetry may never make a coordination write fail.
--     project_key and actor_id are stored as plain values, the join happens at
--     query time, and a query tolerates an agent that is gone.
--   * Nothing here is journaled into coordination_events. These are
--     observations, not facts other agents coordinate on.
--   * Nothing here is immutable. Coordination bodies are permanent; telemetry
--     rows carry recorded_at_us so a retention sweep can delete them on a
--     schedule, which is ordinary rather than a policy decision.
--
-- Cost is not a column anywhere below. Price is a function of provider, model,
-- token class, and date; storing a computed cost would freeze one day's price
-- into a durable row. Cost is a projection over these facts, not a fact.

-- The token classes are DISJOINT, and the column names say so because the
-- ambiguity is what makes this data wrong in practice. Harnesses disagree:
-- Codex reports a cumulative input that INCLUDES cached tokens, while
-- OpenCode's tokens.input already EXCLUDES them. Summing those two as though
-- they meant the same thing undercounts one and double-counts the other.
--
--   uncached_input_tokens  processed fresh -- neither served from nor written to cache
--   cache_read_tokens      served from a prompt cache
--   cache_write_tokens     written into a prompt cache this call
--   output_tokens          generated
--   reasoning_tokens       the reasoning subset OF output_tokens, never additional
--
-- What a provider bills as "input" is the sum of the first three. OpenTelemetry's
-- gen_ai.usage.input_tokens is that sum for some exporters and uncached-only for
-- others; that is exactly why this schema refuses the name.
--
-- raw_usage keeps the bounded payload the adapter derived those numbers from.
-- It is the audit trail for the normalization itself: a mapping bug is otherwise
-- undetectable and unrecoverable after the fact, having silently discarded the
-- only evidence that it was wrong.
CREATE TABLE telemetry_model_calls (
    observation_id TEXT PRIMARY KEY CHECK (length(observation_id) = 36),
    dedupe_key TEXT NOT NULL CHECK (length(CAST(dedupe_key AS BLOB)) BETWEEN 1 AND 256),
    project_key TEXT NOT NULL CHECK (length(CAST(project_key AS BLOB)) BETWEEN 1 AND 4096),
    actor_id TEXT NOT NULL CHECK (length(actor_id) = 36),
    session_id TEXT NOT NULL CHECK (length(session_id) = 36),
    harness TEXT NOT NULL CHECK (harness IN ('claude-code', 'opencode', 'pi', 'unknown')),
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
    -- Nullable because not every source measures it. A Claude Code transcript
    -- records what a call cost but never how long it took, and storing a zero
    -- there would put a fabricated instant response into every latency average
    -- this plane exists to compute. NULL says "not measured"; 0 says "instant".
    duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms BETWEEN 0 AND 86400000),
    recorded_at_us INTEGER NOT NULL CHECK (recorded_at_us > 0),
    phux_terminal TEXT CHECK (phux_terminal IS NULL
        OR length(CAST(phux_terminal AS BLOB)) BETWEEN 1 AND 128),
    raw_usage TEXT CHECK (raw_usage IS NULL OR length(CAST(raw_usage AS BLOB)) <= 4096)
) STRICT;

-- A span is the other half of "where does the time go": a tool call, a build, a
-- test run, one whole agent turn. It has a duration and an outcome and no
-- tokens, which is why it is a separate table rather than a nullable half of the
-- one above.
CREATE TABLE telemetry_spans (
    span_id TEXT PRIMARY KEY CHECK (length(span_id) = 36),
    dedupe_key TEXT NOT NULL CHECK (length(CAST(dedupe_key AS BLOB)) BETWEEN 1 AND 256),
    project_key TEXT NOT NULL CHECK (length(CAST(project_key AS BLOB)) BETWEEN 1 AND 4096),
    actor_id TEXT NOT NULL CHECK (length(actor_id) = 36),
    session_id TEXT NOT NULL CHECK (length(session_id) = 36),
    harness TEXT NOT NULL CHECK (harness IN ('claude-code', 'opencode', 'pi', 'unknown')),
    harness_session TEXT CHECK (harness_session IS NULL
        OR length(CAST(harness_session AS BLOB)) BETWEEN 1 AND 256),
    kind TEXT NOT NULL CHECK (kind IN ('tool', 'build', 'test', 'command', 'turn', 'other')),
    name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 256),
    outcome TEXT NOT NULL CHECK (outcome IN ('ok', 'error', 'aborted')),
    error_kind TEXT CHECK (error_kind IS NULL OR length(CAST(error_kind AS BLOB)) BETWEEN 1 AND 128),
    started_at_us INTEGER NOT NULL CHECK (started_at_us > 0),
    -- Nullable because not every source measures it. A Claude Code transcript
    -- records what a call cost but never how long it took, and storing a zero
    -- there would put a fabricated instant response into every latency average
    -- this plane exists to compute. NULL says "not measured"; 0 says "instant".
    duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms BETWEEN 0 AND 86400000),
    recorded_at_us INTEGER NOT NULL CHECK (recorded_at_us > 0),
    phux_terminal TEXT CHECK (phux_terminal IS NULL
        OR length(CAST(phux_terminal AS BLOB)) BETWEEN 1 AND 128),
    attributes TEXT CHECK (attributes IS NULL OR length(CAST(attributes AS BLOB)) <= 4096)
) STRICT;

-- Ingest is idempotent on (actor, dedupe_key), which is what lets an emitter be
-- careless. Every adapter has a duplicate-delivery path: OpenCode reference-counts
-- one supervisor across repeated activations, a transcript reader re-scans from an
-- imprecise watermark, and any of them may retry a request whose response was lost.
-- A live Claude Code transcript carries the same assistant usage twice one
-- millisecond apart, so this is observed behaviour rather than a precaution.
-- An emitter with nothing stable to key on synthesizes a unique value and simply
-- never dedupes, which is correct rather than special.
CREATE UNIQUE INDEX telemetry_model_calls_dedupe_idx ON telemetry_model_calls(actor_id, dedupe_key);
CREATE UNIQUE INDEX telemetry_spans_dedupe_idx ON telemetry_spans(actor_id, dedupe_key);

-- Spend over a window for one project, and the same question sliced by model,
-- are the two queries this plane exists to answer. The sweep index is keyed on
-- recorded_at_us rather than started_at_us because retention is measured from
-- when the daemon durably accepted a row, which is the only clock it controls:
-- an adapter with a wrong clock can misreport when a call started, and must not
-- thereby exempt its rows from deletion.
CREATE INDEX telemetry_model_calls_project_idx ON telemetry_model_calls(project_key, started_at_us);
CREATE INDEX telemetry_model_calls_model_idx ON telemetry_model_calls(model, started_at_us);
CREATE INDEX telemetry_model_calls_sweep_idx ON telemetry_model_calls(recorded_at_us);
CREATE INDEX telemetry_spans_project_idx ON telemetry_spans(project_key, started_at_us);
CREATE INDEX telemetry_spans_sweep_idx ON telemetry_spans(recorded_at_us);

-- Every rung records the version it reached, so the manifest's version CHECK has
-- to admit this one. SQLite cannot widen a CHECK in place, hence the rebuild --
-- the same shape migrations 0005 and 0006 used, including dropping and restoring
-- the immutability triggers that would otherwise abort the copy.
DROP TRIGGER schema_manifest_no_update;
DROP TRIGGER schema_manifest_no_delete;
ALTER TABLE schema_manifest RENAME TO schema_manifest_v6;
CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version BETWEEN 1 AND 7),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;
INSERT INTO schema_manifest(schema_version, checksum)
SELECT schema_version, checksum FROM schema_manifest_v6;
DROP TABLE schema_manifest_v6;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
