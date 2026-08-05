CREATE SCHEMA blackbird;
SET LOCAL search_path = blackbird, pg_catalog;

CREATE TABLE schema_migrations (
    migration_id text PRIMARY KEY,
    checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at_us bigint NOT NULL CHECK (applied_at_us > 0),
    state text NOT NULL CHECK (state IN ('applying', 'applied', 'resumable'))
);
CREATE TABLE schema_manifest (
    schema_version bigint PRIMARY KEY CHECK (schema_version = 1),
    checksum bytea NOT NULL CHECK (octet_length(checksum) = 32)
);
CREATE TABLE database_runtime (
    singleton bigint PRIMARY KEY CHECK (singleton = 1),
    clean_shutdown boolean NOT NULL,
    opened_at_us bigint NOT NULL CHECK (opened_at_us > 0),
    closed_at_us bigint
);
INSERT INTO database_runtime VALUES (1, true, floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint, NULL);

CREATE TABLE scope_guards (
    scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id uuid NOT NULL, authority_id uuid NOT NULL, authority_epoch uuid NOT NULL,
    bootstrap_generation_id uuid, write_status text NOT NULL,
    guard_generation bigint NOT NULL CHECK (guard_generation BETWEEN 1 AND 9007199254740991),
    updated_at_us bigint NOT NULL CHECK (updated_at_us > 0),
    PRIMARY KEY (scope_kind, scope_id)
);
CREATE TABLE writer_control (
    singleton bigint PRIMARY KEY CHECK (singleton = 1), storage_writer_generation uuid NOT NULL,
    witness_grant_id uuid, activation_state text NOT NULL CHECK (activation_state IN ('active', 'maintenance', 'sealed')),
    database_role text NOT NULL CHECK (database_role IN ('hosted_authority', 'edge_projection')),
    updated_at_us bigint NOT NULL CHECK (updated_at_us > 0)
);
CREATE TABLE authority_streams (
    scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id uuid NOT NULL, authority_id uuid NOT NULL, authority_epoch uuid NOT NULL,
    next_sequence bigint NOT NULL CHECK (next_sequence BETWEEN 1 AND 9007199254740991),
    retained_from_sequence bigint NOT NULL CHECK (retained_from_sequence BETWEEN 1 AND 9007199254740991),
    digest_algorithm text NOT NULL CHECK (digest_algorithm = 'sha-256'),
    head_digest bytea NOT NULL CHECK (octet_length(head_digest) = 32),
    next_audit_sequence bigint NOT NULL CHECK (next_audit_sequence BETWEEN 1 AND 9007199254740991),
    audit_head_hash bytea NOT NULL CHECK (octet_length(audit_head_hash) = 32),
    authority_time_floor_us bigint NOT NULL CHECK (authority_time_floor_us > 0),
    clock_status text NOT NULL DEFAULT 'normal' CHECK (clock_status IN ('normal', 'clock_suspect')), predecessor_epoch uuid,
    PRIMARY KEY (scope_kind, scope_id, authority_epoch)
);
CREATE TABLE scheduler_clocks (
    authority_epoch uuid NOT NULL, shard text NOT NULL,
    authority_time_floor_us bigint NOT NULL CHECK (authority_time_floor_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us > 0), PRIMARY KEY (authority_epoch, shard)
);

CREATE TABLE installation_invitations (
    invitation_id uuid PRIMARY KEY, installation_id uuid NOT NULL, authority_id uuid NOT NULL, authority_epoch uuid NOT NULL,
    installation_public_key_reference text NOT NULL,
    invitation_verifier bytea NOT NULL CHECK (octet_length(invitation_verifier) = 32),
    bootstrap_generation_id uuid NOT NULL, status text NOT NULL CHECK (status IN ('pending', 'consumed', 'exhausted')),
    failed_attempts bigint NOT NULL CHECK (failed_attempts BETWEEN 0 AND 5), expires_at_us bigint NOT NULL CHECK (expires_at_us > 0),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), created_at_us bigint NOT NULL CHECK (created_at_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us),
    CHECK ((status = 'pending' AND failed_attempts < 5 AND version = failed_attempts + 1) OR
           (status = 'consumed' AND failed_attempts < 5 AND version = failed_attempts + 2) OR
           (status = 'exhausted' AND failed_attempts = 5 AND version = 6)),
    UNIQUE (installation_id, bootstrap_generation_id)
);
CREATE TABLE principals (
    principal_id uuid PRIMARY KEY, installation_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('human', 'workload', 'service')), display_name text NOT NULL,
    public_key_reference text, status text NOT NULL CHECK (status IN ('active', 'suspended', 'disabled')),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), created_at_us bigint NOT NULL CHECK (created_at_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us), UNIQUE (installation_id, principal_id)
);
CREATE TABLE device_registrations (
    device_id uuid PRIMARY KEY, installation_id uuid NOT NULL, principal_id uuid NOT NULL, display_name text NOT NULL,
    credential_algorithm text, public_key_reference text NOT NULL,
    spki_fingerprint bytea CHECK (spki_fingerprint IS NULL OR octet_length(spki_fingerprint) = 32),
    transcript_fingerprint bytea CHECK (transcript_fingerprint IS NULL OR octet_length(transcript_fingerprint) = 32),
    trust_revision bigint NOT NULL CHECK (trust_revision BETWEEN 1 AND 9007199254740991),
    revocation_revision bigint NOT NULL CHECK (revocation_revision BETWEEN 1 AND 9007199254740991),
    credential_activated_at_us bigint, retiring_credential_algorithm text, retiring_public_key_reference text,
    retiring_spki_fingerprint bytea CHECK (retiring_spki_fingerprint IS NULL OR octet_length(retiring_spki_fingerprint) = 32),
    retiring_transcript_fingerprint bytea CHECK (retiring_transcript_fingerprint IS NULL OR octet_length(retiring_transcript_fingerprint) = 32),
    retiring_credential_expires_at_us bigint,
    rotation_transcript_fingerprint bytea CHECK (rotation_transcript_fingerprint IS NULL OR octet_length(rotation_transcript_fingerprint) = 32),
    rotated_at_us bigint, revoked_at_us bigint,
    status text NOT NULL CHECK (status IN ('pending', 'trusted', 'suspended', 'revoked')),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), created_at_us bigint NOT NULL CHECK (created_at_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us),
    FOREIGN KEY (installation_id, principal_id) REFERENCES principals(installation_id, principal_id),
    CHECK ((status = 'pending' AND credential_algorithm IS NULL AND spki_fingerprint IS NULL AND transcript_fingerprint IS NULL AND credential_activated_at_us IS NULL AND revoked_at_us IS NULL) OR
           (status <> 'pending' AND credential_algorithm = 'ed25519-spki-sha256-v1' AND spki_fingerprint IS NOT NULL AND transcript_fingerprint IS NOT NULL AND credential_activated_at_us IS NOT NULL)),
    CHECK ((retiring_credential_algorithm IS NULL AND retiring_public_key_reference IS NULL AND retiring_spki_fingerprint IS NULL AND retiring_transcript_fingerprint IS NULL AND retiring_credential_expires_at_us IS NULL) OR
           (status = 'trusted' AND retiring_credential_algorithm = 'ed25519-spki-sha256-v1' AND retiring_public_key_reference IS NOT NULL AND retiring_spki_fingerprint IS NOT NULL AND retiring_transcript_fingerprint IS NOT NULL AND retiring_credential_expires_at_us IS NOT NULL AND rotated_at_us IS NOT NULL AND rotation_transcript_fingerprint IS NOT NULL)),
    CHECK ((status = 'revoked' AND revoked_at_us IS NOT NULL) OR (status <> 'revoked' AND revoked_at_us IS NULL))
);
CREATE TABLE grants (
    grant_id uuid PRIMARY KEY, installation_id uuid NOT NULL, workspace_id uuid, principal_id uuid NOT NULL,
    capabilities_json jsonb NOT NULL, status text NOT NULL CHECK (status IN ('active', 'revoked')), expires_at_us bigint,
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), created_at_us bigint NOT NULL CHECK (created_at_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us),
    FOREIGN KEY (installation_id, principal_id) REFERENCES principals(installation_id, principal_id)
);
CREATE TABLE workspaces (
    workspace_id uuid PRIMARY KEY, installation_id uuid NOT NULL, home_authority_id uuid NOT NULL, authority_epoch uuid NOT NULL,
    alias text NOT NULL UNIQUE, discovery_locator text NOT NULL, policy_revision text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'suspended', 'archived')),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), created_at_us bigint NOT NULL CHECK (created_at_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us)
);
CREATE TABLE workspace_memberships (
    membership_id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES workspaces, principal_id uuid NOT NULL REFERENCES principals,
    capabilities_json jsonb NOT NULL, status text NOT NULL CHECK (status IN ('invited', 'active', 'suspended', 'revoked')),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), created_at_us bigint NOT NULL CHECK (created_at_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us), UNIQUE (workspace_id, principal_id),
    UNIQUE (workspace_id, membership_id), UNIQUE (workspace_id, membership_id, principal_id)
);
CREATE TABLE actors (
    actor_id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES workspaces,
    kind text NOT NULL CHECK (kind IN ('human', 'agent', 'automation', 'service')), display_name text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), created_at_us bigint NOT NULL CHECK (created_at_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us), UNIQUE (workspace_id, actor_id)
);
CREATE TABLE actor_delegations (
    delegation_id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES workspaces, principal_id uuid NOT NULL,
    actor_id uuid NOT NULL, membership_id uuid NOT NULL, capabilities_json jsonb NOT NULL,
    status text NOT NULL CHECK (status IN ('proposed', 'active', 'suspended', 'revoked')),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), created_at_us bigint NOT NULL CHECK (created_at_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us), UNIQUE (workspace_id, principal_id, actor_id),
    UNIQUE (workspace_id, delegation_id, principal_id, actor_id),
    FOREIGN KEY (workspace_id, actor_id) REFERENCES actors(workspace_id, actor_id),
    FOREIGN KEY (workspace_id, membership_id, principal_id) REFERENCES workspace_memberships(workspace_id, membership_id, principal_id)
);
CREATE TABLE actor_sessions (
    session_id uuid PRIMARY KEY, authority_id uuid NOT NULL, authority_epoch uuid NOT NULL,
    workspace_id uuid NOT NULL REFERENCES workspaces, principal_id uuid NOT NULL, actor_id uuid NOT NULL, delegation_id uuid NOT NULL,
    delegation_version bigint NOT NULL CHECK (delegation_version BETWEEN 1 AND 9007199254740991), membership_id uuid NOT NULL,
    membership_version bigint NOT NULL CHECK (membership_version BETWEEN 1 AND 9007199254740991), device_id uuid,
    device_version bigint CHECK (device_version IS NULL OR device_version BETWEEN 1 AND 9007199254740991),
    device_trust_revision bigint CHECK (device_trust_revision IS NULL OR device_trust_revision BETWEEN 1 AND 9007199254740991),
    client_instance_id uuid NOT NULL, client_name text NOT NULL, client_version text NOT NULL,
    capabilities_json jsonb NOT NULL, policy_revision text NOT NULL, assurance_class text NOT NULL,
    presentation_credential_reference text NOT NULL,
    presentation_credential_digest bytea NOT NULL CHECK (octet_length(presentation_credential_digest) = 32),
    presentation_credential_audience text NOT NULL,
    presentation_credential_version bigint NOT NULL CHECK (presentation_credential_version BETWEEN 1 AND 9007199254740991),
    status text NOT NULL CHECK (status IN ('active', 'ended', 'revoked', 'expired')),
    issued_at_us bigint NOT NULL CHECK (issued_at_us > 0), expires_at_us bigint NOT NULL CHECK (expires_at_us > issued_at_us),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991), created_at_us bigint NOT NULL CHECK (created_at_us > 0),
    updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us),
    CHECK ((device_id IS NULL AND device_version IS NULL AND device_trust_revision IS NULL) OR
           (device_id IS NOT NULL AND device_version > 0 AND device_trust_revision > 0)),
    FOREIGN KEY (workspace_id, actor_id) REFERENCES actors(workspace_id, actor_id),
    FOREIGN KEY (workspace_id, membership_id, principal_id) REFERENCES workspace_memberships(workspace_id, membership_id, principal_id),
    FOREIGN KEY (workspace_id, delegation_id, principal_id, actor_id) REFERENCES actor_delegations(workspace_id, delegation_id, principal_id, actor_id)
);
CREATE TABLE actor_session_grant_revisions (
    session_id uuid NOT NULL REFERENCES actor_sessions, grant_id uuid NOT NULL REFERENCES grants,
    grant_version bigint NOT NULL CHECK (grant_version BETWEEN 1 AND 9007199254740991), PRIMARY KEY (session_id, grant_id)
);
CREATE TABLE ceremony_challenges (
    ceremony_id uuid PRIMARY KEY, scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'workspace')), scope_id uuid NOT NULL,
    purpose text NOT NULL, proof_fingerprint bytea NOT NULL CHECK (octet_length(proof_fingerprint) = 32),
    installation_id uuid, workspace_id uuid, principal_id uuid NOT NULL, membership_id uuid, actor_id uuid, delegation_id uuid, device_id uuid,
    status text NOT NULL, expires_at_us bigint NOT NULL CHECK (expires_at_us > 0), consumed_at_us bigint,
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    CHECK ((purpose = 'membership_acceptance' AND scope_kind = 'workspace' AND installation_id IS NULL AND workspace_id = scope_id AND membership_id IS NOT NULL AND actor_id IS NULL AND delegation_id IS NULL AND device_id IS NULL) OR
           (purpose IN ('delegation_activation', 'actor_session_start') AND scope_kind = 'workspace' AND installation_id IS NULL AND workspace_id = scope_id AND membership_id IS NULL AND actor_id IS NOT NULL AND delegation_id IS NOT NULL AND device_id IS NULL) OR
           (purpose = 'device_pairing' AND scope_kind = 'installation' AND installation_id = scope_id AND workspace_id IS NULL AND membership_id IS NULL AND actor_id IS NULL AND delegation_id IS NULL AND device_id IS NOT NULL)),
    CHECK ((status = 'pending' AND consumed_at_us IS NULL) OR (status = 'consumed' AND consumed_at_us IS NOT NULL))
);

CREATE TABLE command_receipts (
    receipt_id uuid PRIMARY KEY, command_id uuid NOT NULL UNIQUE,
    scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'workspace')), scope_id uuid NOT NULL,
    authority_id uuid NOT NULL, authority_epoch uuid NOT NULL,
    identity_kind text NOT NULL CHECK (identity_kind IN ('ordinary_workspace', 'installation_provisioning', 'installation_admin')),
    workspace_id uuid, installation_id uuid, principal_id uuid, client_instance_id uuid,
    transcript_fingerprint bytea CHECK (transcript_fingerprint IS NULL OR octet_length(transcript_fingerprint) = 32),
    operation text NOT NULL, operation_major bigint NOT NULL CHECK (operation_major BETWEEN 1 AND 65535), idempotency_key text NOT NULL,
    request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint) = 32), result_digest bytea NOT NULL CHECK (octet_length(result_digest) = 32),
    result_canonical bytea NOT NULL, first_event_sequence bigint NOT NULL CHECK (first_event_sequence BETWEEN 1 AND 9007199254740991),
    last_event_sequence bigint NOT NULL CHECK (last_event_sequence BETWEEN first_event_sequence AND 9007199254740991),
    final_stream_digest bytea NOT NULL CHECK (octet_length(final_stream_digest) = 32), guard_digest bytea NOT NULL CHECK (octet_length(guard_digest) = 32),
    capsule_required boolean NOT NULL, recovery_capsule_canonical bytea,
    recovery_capsule_digest bytea CHECK (recovery_capsule_digest IS NULL OR octet_length(recovery_capsule_digest) = 32),
    recovery_capsule_key_id text, recovery_capsule_public_key bytea CHECK (recovery_capsule_public_key IS NULL OR octet_length(recovery_capsule_public_key) = 32),
    committed_at_us bigint NOT NULL CHECK (committed_at_us > 0),
    CHECK ((identity_kind = 'ordinary_workspace' AND workspace_id IS NOT NULL AND installation_id IS NULL AND principal_id IS NOT NULL AND client_instance_id IS NOT NULL AND transcript_fingerprint IS NULL) OR
           (identity_kind = 'installation_provisioning' AND workspace_id IS NULL AND installation_id IS NOT NULL AND principal_id IS NULL AND client_instance_id IS NULL AND transcript_fingerprint IS NOT NULL) OR
           (identity_kind = 'installation_admin' AND workspace_id IS NULL AND installation_id IS NOT NULL AND principal_id IS NOT NULL AND client_instance_id IS NOT NULL AND transcript_fingerprint IS NULL)),
    CHECK ((NOT capsule_required AND recovery_capsule_canonical IS NULL AND recovery_capsule_digest IS NULL AND recovery_capsule_key_id IS NULL AND recovery_capsule_public_key IS NULL) OR
           (capsule_required AND recovery_capsule_canonical IS NOT NULL AND recovery_capsule_digest IS NOT NULL AND recovery_capsule_key_id IS NOT NULL AND recovery_capsule_public_key IS NOT NULL)),
    CHECK ((operation IN ('installation.bootstrap.v1', 'workspace.create.v1') AND last_event_sequence = first_event_sequence + 2) OR
           (operation NOT IN ('installation.bootstrap.v1', 'workspace.create.v1') AND last_event_sequence = first_event_sequence))
);
CREATE UNIQUE INDEX command_receipts_ordinary_identity ON command_receipts(workspace_id, principal_id, client_instance_id, operation, idempotency_key) WHERE identity_kind = 'ordinary_workspace';
CREATE UNIQUE INDEX command_receipts_provisioning_identity ON command_receipts(installation_id, transcript_fingerprint, operation, idempotency_key) WHERE identity_kind = 'installation_provisioning';
CREATE UNIQUE INDEX command_receipts_installation_admin_identity ON command_receipts(installation_id, principal_id, client_instance_id, operation, idempotency_key) WHERE identity_kind = 'installation_admin';
CREATE TABLE command_receipt_resources (
    receipt_id uuid NOT NULL REFERENCES command_receipts, resource_ordinal bigint NOT NULL CHECK (resource_ordinal BETWEEN 0 AND 9007199254740991),
    aggregate_kind text NOT NULL, aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (receipt_id, resource_ordinal), UNIQUE (receipt_id, aggregate_kind, aggregate_id)
);
CREATE TABLE command_receipt_ceremonies (
    receipt_id uuid NOT NULL REFERENCES command_receipts, ceremony_ordinal bigint NOT NULL CHECK (ceremony_ordinal BETWEEN 0 AND 9007199254740991),
    ceremony_id uuid NOT NULL REFERENCES ceremony_challenges, PRIMARY KEY (receipt_id, ceremony_ordinal), UNIQUE (receipt_id, ceremony_id)
);
CREATE TABLE domain_events (
    event_id uuid PRIMARY KEY, command_id uuid NOT NULL, receipt_id uuid NOT NULL REFERENCES command_receipts,
    authority_id uuid NOT NULL, authority_epoch uuid NOT NULL,
    scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'workspace')), scope_id uuid NOT NULL,
    stream_sequence bigint NOT NULL CHECK (stream_sequence BETWEEN 1 AND 9007199254740991),
    previous_stream_digest bytea NOT NULL CHECK (octet_length(previous_stream_digest) = 32),
    event_digest bytea NOT NULL CHECK (octet_length(event_digest) = 32), stream_digest bytea NOT NULL CHECK (octet_length(stream_digest) = 32),
    aggregate_kind text NOT NULL, aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version BETWEEN 1 AND 9007199254740991),
    event_index bigint NOT NULL CHECK (event_index BETWEEN 0 AND 9007199254740991), event_type text NOT NULL,
    event_schema bigint NOT NULL CHECK (event_schema BETWEEN 1 AND 65535), payload bytea NOT NULL, principal_id uuid NOT NULL,
    actor_session_id uuid, authorization_digest bytea NOT NULL CHECK (octet_length(authorization_digest) = 32),
    causation_event_id uuid, correlation_id uuid NOT NULL, recorded_at_us bigint NOT NULL CHECK (recorded_at_us > 0),
    UNIQUE (scope_kind, scope_id, authority_epoch, stream_sequence), UNIQUE (command_id, event_index),
    UNIQUE (aggregate_kind, aggregate_id, aggregate_version, event_index)
);
CREATE TABLE audit_entries (
    scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'workspace')), scope_id uuid NOT NULL,
    audit_sequence bigint NOT NULL CHECK (audit_sequence BETWEEN 1 AND 9007199254740991),
    previous_entry_hash bytea NOT NULL CHECK (octet_length(previous_entry_hash) = 32), entry_hash bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
    canonical_entry bytea NOT NULL, recorded_at_us bigint NOT NULL CHECK (recorded_at_us > 0),
    PRIMARY KEY (scope_kind, scope_id, audit_sequence), UNIQUE (entry_hash)
);
CREATE TABLE security_denials (
    record_kind text NOT NULL CHECK (record_kind IN ('bootstrap', 'command')),
    denial_fingerprint bytea NOT NULL CHECK (octet_length(denial_fingerprint) = 32),
    scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'workspace')), scope_id uuid NOT NULL,
    subject_kind text NOT NULL, subject_id text, operation text, operation_major bigint, denial_class text NOT NULL, reason text NOT NULL,
    bucket bigint NOT NULL CHECK (bucket BETWEEN 0 AND 9007199254740991),
    occurrence_count bigint NOT NULL CHECK (occurrence_count BETWEEN 1 AND 9007199254740991),
    first_recorded_at_us bigint NOT NULL CHECK (first_recorded_at_us > 0), last_recorded_at_us bigint NOT NULL CHECK (last_recorded_at_us >= first_recorded_at_us),
    CHECK ((record_kind = 'bootstrap' AND subject_kind = 'invitation' AND subject_id IS NOT NULL AND operation IS NULL AND operation_major IS NULL AND bucket = 0) OR
           (record_kind = 'command' AND operation IS NOT NULL AND operation_major BETWEEN 1 AND 9007199254740991))
);
CREATE UNIQUE INDEX security_denials_bootstrap_identity
    ON security_denials(subject_id, denial_fingerprint) WHERE record_kind = 'bootstrap';
CREATE UNIQUE INDEX security_denials_command_identity
    ON security_denials(scope_kind, scope_id, subject_kind, subject_id, operation, operation_major,
        denial_class, bucket, denial_fingerprint) WHERE record_kind = 'command';
CREATE TABLE outbox_jobs (
    job_id uuid PRIMARY KEY, command_id uuid NOT NULL, event_id uuid NOT NULL REFERENCES domain_events,
    handler text NOT NULL, handler_contract_version bigint NOT NULL CHECK (handler_contract_version BETWEEN 1 AND 65535),
    destination_key text NOT NULL, effect_ordinal bigint NOT NULL CHECK (effect_ordinal BETWEEN 0 AND 9007199254740991),
    effect_kind text NOT NULL, idempotency_key text NOT NULL UNIQUE, payload bytea NOT NULL,
    metadata_digest bytea NOT NULL CHECK (octet_length(metadata_digest) = 32), status text NOT NULL,
    attempt_count bigint NOT NULL CHECK (attempt_count BETWEEN 0 AND 9007199254740991), available_at_us bigint NOT NULL CHECK (available_at_us > 0),
    claim_token uuid, claim_deadline_us bigint, claim_authority_epoch uuid, last_error_class text, result bytea, parked_disposition text,
    created_at_us bigint NOT NULL CHECK (created_at_us > 0), updated_at_us bigint NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (command_id, handler, handler_contract_version, destination_key, effect_ordinal),
    UNIQUE (command_id, event_id, handler, handler_contract_version, destination_key, effect_ordinal)
);
CREATE TABLE projection_checkpoints (
    projection_name text NOT NULL, projection_schema bigint NOT NULL CHECK (projection_schema BETWEEN 1 AND 65535),
    scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'workspace')), scope_id uuid NOT NULL, authority_epoch uuid NOT NULL,
    contiguous_sequence bigint NOT NULL CHECK (contiguous_sequence BETWEEN 0 AND 9007199254740991),
    stream_digest bytea NOT NULL CHECK (octet_length(stream_digest) = 32),
    health text NOT NULL CHECK (health IN ('healthy', 'blocked', 'poisoned', 'rebuilding')), poison_event_id uuid,
    updated_at_us bigint NOT NULL CHECK (updated_at_us > 0),
    PRIMARY KEY (projection_name, projection_schema, scope_kind, scope_id, authority_epoch)
);
CREATE TABLE backup_sessions (
    backup_id uuid PRIMARY KEY, state text NOT NULL CHECK (state IN ('capturing', 'retained', 'aborted')),
    database_high_water_digest bytea CHECK (database_high_water_digest IS NULL OR octet_length(database_high_water_digest) = 32),
    manifest_digest bytea CHECK (manifest_digest IS NULL OR octet_length(manifest_digest) = 32),
    started_at_us bigint NOT NULL CHECK (started_at_us > 0), completed_at_us bigint
);

CREATE INDEX domain_events_aggregate_idx ON domain_events(aggregate_kind, aggregate_id, aggregate_version);
CREATE INDEX outbox_jobs_ready_idx ON outbox_jobs(status, available_at_us, job_id);
CREATE INDEX security_denials_scope_bucket_idx ON security_denials(scope_kind, scope_id, bucket);
