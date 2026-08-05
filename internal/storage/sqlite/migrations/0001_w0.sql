CREATE TABLE schema_migrations (
    migration_id TEXT PRIMARY KEY,
    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    applied_at_us INTEGER NOT NULL CHECK (applied_at_us > 0),
    state TEXT NOT NULL CHECK (state IN ('applying', 'applied', 'resumable'))
) STRICT;

CREATE TABLE schema_manifest (
    schema_version INTEGER PRIMARY KEY CHECK (schema_version = 1),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;

CREATE TABLE database_runtime (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    clean_shutdown INTEGER NOT NULL CHECK (clean_shutdown IN (0, 1)),
    opened_at_us INTEGER NOT NULL CHECK (opened_at_us > 0),
    closed_at_us INTEGER
) STRICT;

INSERT INTO database_runtime(singleton, clean_shutdown, opened_at_us)
VALUES (1, 1, CAST(unixepoch('subsec') * 1000000 AS INTEGER));

CREATE TABLE scope_guards (
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    authority_id TEXT NOT NULL CHECK (length(authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    write_status TEXT NOT NULL,
    guard_generation INTEGER NOT NULL CHECK (guard_generation > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us > 0),
    PRIMARY KEY (scope_kind, scope_id)
) STRICT;

CREATE TABLE writer_control (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    storage_writer_generation TEXT NOT NULL CHECK (length(storage_writer_generation) = 36),
    witness_grant_id TEXT,
    activation_state TEXT NOT NULL CHECK (activation_state IN ('active', 'maintenance', 'sealed')),
    database_role TEXT NOT NULL CHECK (database_role IN ('local_authority', 'edge_projection')),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us > 0)
) STRICT;

CREATE TABLE authority_streams (
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    authority_id TEXT NOT NULL CHECK (length(authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    next_sequence INTEGER NOT NULL CHECK (next_sequence > 0),
    retained_from_sequence INTEGER NOT NULL CHECK (retained_from_sequence > 0),
    digest_algorithm TEXT NOT NULL CHECK (digest_algorithm = 'sha-256'),
    head_digest BLOB NOT NULL CHECK (length(head_digest) = 32),
    next_audit_sequence INTEGER NOT NULL CHECK (next_audit_sequence > 0),
    audit_head_hash BLOB NOT NULL CHECK (length(audit_head_hash) = 32),
    authority_time_floor_us INTEGER NOT NULL CHECK (authority_time_floor_us > 0),
    predecessor_epoch TEXT CHECK (predecessor_epoch IS NULL OR length(predecessor_epoch) = 36),
    PRIMARY KEY (scope_kind, scope_id, authority_epoch)
) STRICT;

CREATE TABLE scheduler_clocks (
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    shard TEXT NOT NULL,
    authority_time_floor_us INTEGER NOT NULL CHECK (authority_time_floor_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us > 0),
    PRIMARY KEY (authority_epoch, shard)
) STRICT;

CREATE TABLE installation_invitations (
    invitation_id TEXT PRIMARY KEY CHECK (length(invitation_id) = 36),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 36),
    authority_id TEXT NOT NULL CHECK (length(authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    bootstrap_generation_id TEXT NOT NULL CHECK (length(bootstrap_generation_id) = 36),
    status TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL CHECK (failed_attempts >= 0),
    expires_at_us INTEGER NOT NULL CHECK (expires_at_us > 0),
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (installation_id, bootstrap_generation_id)
) STRICT;

CREATE TABLE principals (
    principal_id TEXT PRIMARY KEY CHECK (length(principal_id) = 36),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 36),
    kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    public_key_reference TEXT,
    status TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (installation_id, principal_id)
) STRICT;

CREATE TABLE device_registrations (
    device_id TEXT PRIMARY KEY CHECK (length(device_id) = 36),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 36),
    principal_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    credential_algorithm TEXT NOT NULL,
    public_key_reference TEXT NOT NULL,
    spki_fingerprint BLOB NOT NULL CHECK (length(spki_fingerprint) = 32),
    transcript_fingerprint BLOB NOT NULL CHECK (length(transcript_fingerprint) = 32),
    trust_revision INTEGER NOT NULL CHECK (trust_revision > 0),
    status TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    FOREIGN KEY (installation_id, principal_id) REFERENCES principals(installation_id, principal_id)
) STRICT;

CREATE TABLE grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) = 36),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 36),
    workspace_id TEXT CHECK (workspace_id IS NULL OR length(workspace_id) = 36),
    principal_id TEXT NOT NULL,
    capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
    status TEXT NOT NULL,
    expires_at_us INTEGER,
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    FOREIGN KEY (installation_id, principal_id) REFERENCES principals(installation_id, principal_id)
) STRICT;

CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY CHECK (length(workspace_id) = 36),
    home_authority_id TEXT NOT NULL CHECK (length(home_authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    alias TEXT NOT NULL UNIQUE,
    discovery_locator TEXT NOT NULL,
    status TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us)
) STRICT;

CREATE TABLE workspace_memberships (
    membership_id TEXT PRIMARY KEY CHECK (length(membership_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
    status TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (workspace_id, principal_id),
    UNIQUE (workspace_id, membership_id),
    UNIQUE (workspace_id, membership_id, principal_id)
) STRICT;

CREATE TABLE actors (
    actor_id TEXT PRIMARY KEY CHECK (length(actor_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (workspace_id, actor_id)
) STRICT;

CREATE TABLE actor_delegations (
    delegation_id TEXT PRIMARY KEY CHECK (length(delegation_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    principal_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
    status TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (workspace_id, principal_id, actor_id),
    UNIQUE (workspace_id, delegation_id, principal_id, actor_id),
    FOREIGN KEY (workspace_id, actor_id) REFERENCES actors(workspace_id, actor_id),
    FOREIGN KEY (workspace_id, membership_id, principal_id)
        REFERENCES workspace_memberships(workspace_id, membership_id, principal_id)
) STRICT;

CREATE TABLE actor_sessions (
    session_id TEXT PRIMARY KEY CHECK (length(session_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    principal_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    delegation_id TEXT NOT NULL,
    client_instance_id TEXT NOT NULL,
    credential_digest BLOB NOT NULL CHECK (length(credential_digest) = 32),
    status TEXT NOT NULL,
    issued_at_us INTEGER NOT NULL CHECK (issued_at_us > 0),
    expires_at_us INTEGER NOT NULL CHECK (expires_at_us > issued_at_us),
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    FOREIGN KEY (workspace_id, actor_id) REFERENCES actors(workspace_id, actor_id),
    FOREIGN KEY (workspace_id, delegation_id, principal_id, actor_id)
        REFERENCES actor_delegations(workspace_id, delegation_id, principal_id, actor_id)
) STRICT;

CREATE TABLE ceremony_challenges (
    ceremony_id TEXT PRIMARY KEY CHECK (length(ceremony_id) = 36),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    purpose TEXT NOT NULL,
    challenge_digest BLOB NOT NULL CHECK (length(challenge_digest) = 32),
    proof_fingerprint BLOB CHECK (proof_fingerprint IS NULL OR length(proof_fingerprint) = 32),
    status TEXT NOT NULL,
    expires_at_us INTEGER NOT NULL CHECK (expires_at_us > 0),
    consumed_at_us INTEGER,
    version INTEGER NOT NULL CHECK (version > 0)
) STRICT;

CREATE TABLE command_receipts (
    receipt_id TEXT PRIMARY KEY CHECK (length(receipt_id) = 36),
    command_id TEXT NOT NULL UNIQUE CHECK (length(command_id) = 36),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('ordinary_workspace', 'installation_provisioning', 'installation_admin')),
    workspace_id TEXT CHECK (workspace_id IS NULL OR length(workspace_id) = 36),
    installation_id TEXT CHECK (installation_id IS NULL OR length(installation_id) = 36),
    principal_id TEXT CHECK (principal_id IS NULL OR length(principal_id) = 36),
    client_instance_id TEXT,
    transcript_fingerprint BLOB CHECK (transcript_fingerprint IS NULL OR length(transcript_fingerprint) = 32),
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    result_canonical BLOB NOT NULL,
    first_event_sequence INTEGER,
    last_event_sequence INTEGER,
    final_stream_digest BLOB CHECK (final_stream_digest IS NULL OR length(final_stream_digest) = 32),
    guard_digest BLOB NOT NULL CHECK (length(guard_digest) = 32),
    recovery_capsule_digest BLOB CHECK (recovery_capsule_digest IS NULL OR length(recovery_capsule_digest) = 32),
    committed_at_us INTEGER NOT NULL CHECK (committed_at_us > 0),
    CHECK (
        (identity_kind = 'ordinary_workspace' AND workspace_id IS NOT NULL AND installation_id IS NULL AND
            principal_id IS NOT NULL AND client_instance_id IS NOT NULL AND transcript_fingerprint IS NULL) OR
        (identity_kind = 'installation_provisioning' AND workspace_id IS NULL AND installation_id IS NOT NULL AND
            principal_id IS NULL AND client_instance_id IS NULL AND transcript_fingerprint IS NOT NULL) OR
        (identity_kind = 'installation_admin' AND workspace_id IS NULL AND installation_id IS NOT NULL AND
            principal_id IS NOT NULL AND client_instance_id IS NOT NULL AND transcript_fingerprint IS NULL)
    )
) STRICT;

CREATE UNIQUE INDEX command_receipts_ordinary_identity
    ON command_receipts(workspace_id, principal_id, client_instance_id, operation, idempotency_key)
    WHERE identity_kind = 'ordinary_workspace';
CREATE UNIQUE INDEX command_receipts_provisioning_identity
    ON command_receipts(installation_id, transcript_fingerprint, operation, idempotency_key)
    WHERE identity_kind = 'installation_provisioning';
CREATE UNIQUE INDEX command_receipts_installation_admin_identity
    ON command_receipts(installation_id, principal_id, client_instance_id, operation, idempotency_key)
    WHERE identity_kind = 'installation_admin';

CREATE TABLE domain_events (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) = 36),
    command_id TEXT NOT NULL CHECK (length(command_id) = 36),
    receipt_id TEXT NOT NULL REFERENCES command_receipts(receipt_id),
    authority_id TEXT NOT NULL CHECK (length(authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    stream_sequence INTEGER NOT NULL CHECK (stream_sequence > 0),
    previous_stream_digest BLOB NOT NULL CHECK (length(previous_stream_digest) = 32),
    event_digest BLOB NOT NULL CHECK (length(event_digest) = 32),
    stream_digest BLOB NOT NULL CHECK (length(stream_digest) = 32),
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL CHECK (length(aggregate_id) = 36),
    aggregate_version INTEGER NOT NULL CHECK (aggregate_version > 0),
    event_index INTEGER NOT NULL CHECK (event_index >= 0),
    event_type TEXT NOT NULL,
    event_schema INTEGER NOT NULL CHECK (event_schema > 0),
    payload BLOB NOT NULL,
    principal_id TEXT NOT NULL CHECK (length(principal_id) = 36),
    actor_session_id TEXT CHECK (actor_session_id IS NULL OR length(actor_session_id) = 36),
    authorization_digest BLOB NOT NULL CHECK (length(authorization_digest) = 32),
    causation_event_id TEXT CHECK (causation_event_id IS NULL OR length(causation_event_id) = 36),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) = 36),
    recorded_at_us INTEGER NOT NULL CHECK (recorded_at_us > 0),
    UNIQUE (scope_kind, scope_id, authority_epoch, stream_sequence),
    UNIQUE (command_id, event_index),
    UNIQUE (aggregate_kind, aggregate_id, aggregate_version, event_index)
) STRICT;

CREATE TABLE audit_entries (
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    audit_sequence INTEGER NOT NULL CHECK (audit_sequence > 0),
    previous_entry_hash BLOB NOT NULL CHECK (length(previous_entry_hash) = 32),
    entry_hash BLOB NOT NULL CHECK (length(entry_hash) = 32),
    canonical_entry BLOB NOT NULL,
    recorded_at_us INTEGER NOT NULL CHECK (recorded_at_us > 0),
    PRIMARY KEY (scope_kind, scope_id, audit_sequence),
    UNIQUE (entry_hash)
) STRICT;

CREATE TABLE security_denials (
    denial_fingerprint BLOB PRIMARY KEY CHECK (length(denial_fingerprint) = 32),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    subject_kind TEXT NOT NULL,
    subject_id TEXT,
    denial_class TEXT NOT NULL,
    reason TEXT NOT NULL,
    bucket INTEGER NOT NULL CHECK (bucket >= 0),
    occurrence_count INTEGER NOT NULL CHECK (occurrence_count > 0),
    first_recorded_at_us INTEGER NOT NULL CHECK (first_recorded_at_us > 0),
    last_recorded_at_us INTEGER NOT NULL CHECK (last_recorded_at_us >= first_recorded_at_us)
) STRICT;

CREATE TABLE outbox_jobs (
    job_id TEXT PRIMARY KEY CHECK (length(job_id) = 36),
    event_id TEXT NOT NULL REFERENCES domain_events(event_id),
    handler TEXT NOT NULL,
    handler_contract_version INTEGER NOT NULL CHECK (handler_contract_version > 0),
    destination_key TEXT NOT NULL,
    effect_ordinal INTEGER NOT NULL CHECK (effect_ordinal >= 0),
    effect_kind TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload BLOB NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
    available_at_us INTEGER NOT NULL CHECK (available_at_us > 0),
    claim_token TEXT,
    claim_deadline_us INTEGER,
    claim_authority_epoch TEXT CHECK (claim_authority_epoch IS NULL OR length(claim_authority_epoch) = 36),
    last_error_class TEXT,
    result BLOB,
    parked_disposition TEXT,
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (event_id, handler, handler_contract_version, destination_key, effect_ordinal)
) STRICT;

CREATE TABLE projection_checkpoints (
    projection_name TEXT NOT NULL,
    projection_schema INTEGER NOT NULL CHECK (projection_schema > 0),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    contiguous_sequence INTEGER NOT NULL CHECK (contiguous_sequence >= 0),
    stream_digest BLOB NOT NULL CHECK (length(stream_digest) = 32),
    health TEXT NOT NULL CHECK (health IN ('healthy', 'blocked', 'poisoned', 'rebuilding')),
    poison_event_id TEXT,
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us > 0),
    PRIMARY KEY (projection_name, projection_schema, scope_kind, scope_id)
) STRICT;

CREATE TABLE backup_sessions (
    backup_id TEXT PRIMARY KEY CHECK (length(backup_id) = 36),
    state TEXT NOT NULL CHECK (state IN ('capturing', 'retained', 'aborted')),
    database_high_water_digest BLOB CHECK (database_high_water_digest IS NULL OR length(database_high_water_digest) = 32),
    manifest_digest BLOB CHECK (manifest_digest IS NULL OR length(manifest_digest) = 32),
    started_at_us INTEGER NOT NULL CHECK (started_at_us > 0),
    completed_at_us INTEGER
) STRICT;

CREATE INDEX domain_events_aggregate_idx
    ON domain_events(aggregate_kind, aggregate_id, aggregate_version);
CREATE INDEX outbox_jobs_ready_idx
    ON outbox_jobs(status, available_at_us, job_id);
CREATE INDEX security_denials_scope_bucket_idx
    ON security_denials(scope_kind, scope_id, bucket);

CREATE TRIGGER schema_migrations_no_update
BEFORE UPDATE ON schema_migrations BEGIN SELECT RAISE(ABORT, 'schema migration history is immutable'); END;
CREATE TRIGGER schema_migrations_no_delete
BEFORE DELETE ON schema_migrations BEGIN SELECT RAISE(ABORT, 'schema migration history is immutable'); END;
CREATE TRIGGER schema_manifest_no_update
BEFORE UPDATE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER schema_manifest_no_delete
BEFORE DELETE ON schema_manifest BEGIN SELECT RAISE(ABORT, 'schema manifest is immutable'); END;
CREATE TRIGGER command_receipts_no_update
BEFORE UPDATE ON command_receipts BEGIN SELECT RAISE(ABORT, 'command receipts are immutable'); END;
CREATE TRIGGER command_receipts_no_delete
BEFORE DELETE ON command_receipts BEGIN SELECT RAISE(ABORT, 'command receipts are immutable'); END;
CREATE TRIGGER domain_events_no_update
BEFORE UPDATE ON domain_events BEGIN SELECT RAISE(ABORT, 'domain events are immutable'); END;
CREATE TRIGGER domain_events_no_delete
BEFORE DELETE ON domain_events BEGIN SELECT RAISE(ABORT, 'domain events are immutable'); END;
CREATE TRIGGER audit_entries_no_update
BEFORE UPDATE ON audit_entries BEGIN SELECT RAISE(ABORT, 'audit entries are immutable'); END;
CREATE TRIGGER audit_entries_no_delete
BEFORE DELETE ON audit_entries BEGIN SELECT RAISE(ABORT, 'audit entries are immutable'); END;
