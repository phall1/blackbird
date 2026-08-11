CREATE TABLE coordination_projects (
    project_key TEXT PRIMARY KEY CHECK (length(CAST(project_key AS BLOB)) BETWEEN 1 AND 4096),
    workspace_id TEXT NOT NULL UNIQUE CHECK (length(workspace_id) = 36),
    run_id TEXT NOT NULL UNIQUE CHECK (length(run_id) = 36),
    authority_id TEXT NOT NULL CHECK (length(authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0)
) STRICT;

CREATE TABLE coordination_agents (
    actor_id TEXT PRIMARY KEY CHECK (length(actor_id) = 36),
    project_key TEXT NOT NULL REFERENCES coordination_projects(project_key),
    agent_name TEXT NOT NULL CHECK (length(CAST(agent_name AS BLOB)) BETWEEN 1 AND 128),
    registration_token_digest BLOB NOT NULL CHECK (length(registration_token_digest) = 32),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    UNIQUE (project_key, agent_name),
    UNIQUE (registration_token_digest)
) STRICT;

CREATE TABLE coordination_agent_sessions (
    session_id TEXT PRIMARY KEY CHECK (length(session_id) = 36),
    actor_id TEXT NOT NULL REFERENCES coordination_agents(actor_id),
    started_at_us INTEGER NOT NULL CHECK (started_at_us > 0),
    last_seen_at_us INTEGER NOT NULL CHECK (last_seen_at_us >= started_at_us),
    ended_at_us INTEGER CHECK (ended_at_us IS NULL OR ended_at_us >= started_at_us)
) STRICT;

CREATE INDEX coordination_agent_sessions_active_idx
ON coordination_agent_sessions(actor_id, ended_at_us, last_seen_at_us);
