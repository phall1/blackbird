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
    bootstrap_generation_id TEXT CHECK (bootstrap_generation_id IS NULL OR length(bootstrap_generation_id) = 36),
    write_status TEXT NOT NULL,
    guard_generation INTEGER NOT NULL CHECK (guard_generation BETWEEN 1 AND 9007199254740991),
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
    next_sequence INTEGER NOT NULL CHECK (next_sequence BETWEEN 1 AND 9007199254740991),
    retained_from_sequence INTEGER NOT NULL CHECK (retained_from_sequence BETWEEN 1 AND 9007199254740991),
    digest_algorithm TEXT NOT NULL CHECK (digest_algorithm = 'sha-256'),
    head_digest BLOB NOT NULL CHECK (length(head_digest) = 32),
    next_audit_sequence INTEGER NOT NULL CHECK (next_audit_sequence BETWEEN 1 AND 9007199254740991),
    audit_head_hash BLOB NOT NULL CHECK (length(audit_head_hash) = 32),
    authority_time_floor_us INTEGER NOT NULL CHECK (authority_time_floor_us > 0),
    clock_status TEXT NOT NULL DEFAULT 'normal' CHECK (clock_status IN ('normal', 'clock_suspect')),
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
    installation_public_key_reference TEXT NOT NULL,
    invitation_verifier BLOB NOT NULL CHECK (length(invitation_verifier) = 32),
    bootstrap_generation_id TEXT NOT NULL CHECK (length(bootstrap_generation_id) = 36),
    status TEXT NOT NULL CHECK (status IN ('pending', 'consumed', 'exhausted')),
    failed_attempts INTEGER NOT NULL CHECK (failed_attempts BETWEEN 0 AND 5),
    expires_at_us INTEGER NOT NULL CHECK (expires_at_us > 0),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    CHECK (
        (status = 'pending' AND failed_attempts < 5 AND version = failed_attempts + 1) OR
        (status = 'consumed' AND failed_attempts < 5 AND version = failed_attempts + 2) OR
        (status = 'exhausted' AND failed_attempts = 5 AND version = 6)
    ),
    UNIQUE (installation_id, bootstrap_generation_id)
) STRICT;

CREATE TABLE principals (
    principal_id TEXT PRIMARY KEY CHECK (length(principal_id) = 36),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 36),
    kind TEXT NOT NULL CHECK (kind IN ('human', 'workload', 'service')),
    display_name TEXT NOT NULL,
    public_key_reference TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'disabled')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (installation_id, principal_id)
) STRICT;

CREATE TABLE device_registrations (
    device_id TEXT PRIMARY KEY CHECK (length(device_id) = 36),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 36),
    principal_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    credential_algorithm TEXT,
    public_key_reference TEXT NOT NULL,
    spki_fingerprint BLOB CHECK (spki_fingerprint IS NULL OR length(spki_fingerprint) = 32),
    transcript_fingerprint BLOB CHECK (transcript_fingerprint IS NULL OR length(transcript_fingerprint) = 32),
    trust_revision INTEGER NOT NULL CHECK (trust_revision BETWEEN 1 AND 9007199254740991),
    revocation_revision INTEGER NOT NULL CHECK (revocation_revision BETWEEN 1 AND 9007199254740991),
    credential_activated_at_us INTEGER,
    retiring_credential_algorithm TEXT,
    retiring_public_key_reference TEXT,
    retiring_spki_fingerprint BLOB CHECK (retiring_spki_fingerprint IS NULL OR length(retiring_spki_fingerprint) = 32),
    retiring_transcript_fingerprint BLOB CHECK (retiring_transcript_fingerprint IS NULL OR length(retiring_transcript_fingerprint) = 32),
    retiring_credential_expires_at_us INTEGER,
    rotation_transcript_fingerprint BLOB CHECK (rotation_transcript_fingerprint IS NULL OR length(rotation_transcript_fingerprint) = 32),
    rotated_at_us INTEGER,
    revoked_at_us INTEGER,
    status TEXT NOT NULL CHECK (status IN ('pending', 'trusted', 'suspended', 'revoked')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    FOREIGN KEY (installation_id, principal_id) REFERENCES principals(installation_id, principal_id),
    CHECK (
        (status = 'pending' AND credential_algorithm IS NULL AND spki_fingerprint IS NULL AND transcript_fingerprint IS NULL AND
            credential_activated_at_us IS NULL AND revoked_at_us IS NULL) OR
        (status <> 'pending' AND credential_algorithm = 'ed25519-spki-sha256-v1' AND
            spki_fingerprint IS NOT NULL AND transcript_fingerprint IS NOT NULL AND credential_activated_at_us IS NOT NULL)
    ),
    CHECK ((retiring_credential_algorithm IS NULL AND retiring_public_key_reference IS NULL AND
        retiring_spki_fingerprint IS NULL AND retiring_transcript_fingerprint IS NULL AND
        retiring_credential_expires_at_us IS NULL) OR
        (status = 'trusted' AND retiring_credential_algorithm = 'ed25519-spki-sha256-v1' AND
        retiring_public_key_reference IS NOT NULL AND retiring_spki_fingerprint IS NOT NULL AND
        retiring_transcript_fingerprint IS NOT NULL AND retiring_credential_expires_at_us IS NOT NULL AND
        rotated_at_us IS NOT NULL AND rotation_transcript_fingerprint IS NOT NULL)),
    CHECK ((status = 'revoked' AND revoked_at_us IS NOT NULL) OR (status <> 'revoked' AND revoked_at_us IS NULL))
) STRICT;

CREATE TABLE grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) = 36),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 36),
    workspace_id TEXT CHECK (workspace_id IS NULL OR length(workspace_id) = 36),
    principal_id TEXT NOT NULL,
    capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    expires_at_us INTEGER,
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    FOREIGN KEY (installation_id, principal_id) REFERENCES principals(installation_id, principal_id)
) STRICT;

CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY CHECK (length(workspace_id) = 36),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 36),
    home_authority_id TEXT NOT NULL CHECK (length(home_authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    alias TEXT NOT NULL UNIQUE,
    discovery_locator TEXT NOT NULL,
    policy_revision TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'archived')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us)
) STRICT;

CREATE TABLE workspace_memberships (
    membership_id TEXT PRIMARY KEY CHECK (length(membership_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
    status TEXT NOT NULL CHECK (status IN ('invited', 'active', 'suspended', 'revoked')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (workspace_id, principal_id),
    UNIQUE (workspace_id, membership_id),
    UNIQUE (workspace_id, membership_id, principal_id)
) STRICT;

CREATE TABLE actors (
    actor_id TEXT PRIMARY KEY CHECK (length(actor_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    kind TEXT NOT NULL CHECK (kind IN ('human', 'agent', 'automation', 'service')),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
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
    status TEXT NOT NULL CHECK (status IN ('proposed', 'active', 'suspended', 'revoked')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
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
    authority_id TEXT NOT NULL CHECK (length(authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    principal_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    delegation_id TEXT NOT NULL,
    delegation_version INTEGER NOT NULL CHECK (delegation_version BETWEEN 1 AND 9007199254740991),
    membership_id TEXT NOT NULL,
    membership_version INTEGER NOT NULL CHECK (membership_version BETWEEN 1 AND 9007199254740991),
    device_id TEXT,
    device_version INTEGER,
    device_trust_revision INTEGER,
    client_instance_id TEXT NOT NULL CHECK (length(client_instance_id) = 36),
    client_name TEXT NOT NULL,
    client_version TEXT NOT NULL,
    capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
    policy_revision TEXT NOT NULL,
    assurance_class TEXT NOT NULL,
    presentation_credential_reference TEXT NOT NULL,
    presentation_credential_digest BLOB NOT NULL CHECK (length(presentation_credential_digest) = 32),
    presentation_credential_audience TEXT NOT NULL,
    presentation_credential_version INTEGER NOT NULL CHECK (presentation_credential_version > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'ended', 'revoked', 'expired')),
    issued_at_us INTEGER NOT NULL CHECK (issued_at_us > 0),
    expires_at_us INTEGER NOT NULL CHECK (expires_at_us > issued_at_us),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    CHECK (
        (device_id IS NULL AND device_version IS NULL AND device_trust_revision IS NULL) OR
        (length(device_id) = 36 AND device_version > 0 AND device_trust_revision > 0)
    ),
    FOREIGN KEY (workspace_id, actor_id) REFERENCES actors(workspace_id, actor_id),
    FOREIGN KEY (workspace_id, membership_id, principal_id)
        REFERENCES workspace_memberships(workspace_id, membership_id, principal_id),
    FOREIGN KEY (workspace_id, delegation_id, principal_id, actor_id)
        REFERENCES actor_delegations(workspace_id, delegation_id, principal_id, actor_id)
) STRICT;

CREATE TABLE actor_session_grant_revisions (
    session_id TEXT NOT NULL REFERENCES actor_sessions(session_id),
    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
    grant_version INTEGER NOT NULL CHECK (grant_version BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (session_id, grant_id)
) STRICT;

CREATE TABLE work_references (
    work_reference_id TEXT PRIMARY KEY CHECK (length(work_reference_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    provider_namespace TEXT NOT NULL CHECK (length(provider_namespace) BETWEEN 1 AND 4096),
    provider_object_id TEXT NOT NULL CHECK (length(provider_object_id) BETWEEN 1 AND 4096),
    provider_locator TEXT NOT NULL CHECK (length(provider_locator) BETWEEN 1 AND 4096),
    provider_version TEXT NOT NULL CHECK (length(provider_version) BETWEEN 1 AND 4096),
    selected_fields BLOB NOT NULL CHECK (length(selected_fields) BETWEEN 2 AND 65536),
    adapter_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    observed_at_us INTEGER NOT NULL CHECK (observed_at_us > 0),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (workspace_id, provider_namespace, provider_object_id)
) STRICT;

CREATE TABLE objectives (
    objective_id TEXT PRIMARY KEY CHECK (length(objective_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 512),
    acceptance_criteria TEXT NOT NULL CHECK (length(acceptance_criteria) BETWEEN 1 AND 8192),
    status TEXT NOT NULL CHECK (status IN ('draft', 'active')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    CHECK ((status = 'draft' AND version = 1) OR (status = 'active' AND version >= 2))
) STRICT;

CREATE TABLE work_units (
    work_unit_id TEXT PRIMARY KEY CHECK (length(work_unit_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    objective_id TEXT NOT NULL REFERENCES objectives(objective_id),
    work_reference_id TEXT NOT NULL REFERENCES work_references(work_reference_id),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 512),
    status TEXT NOT NULL CHECK (status = 'proposed'),
    version INTEGER NOT NULL CHECK (version = 1),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (workspace_id, work_unit_id)
) STRICT;

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    objective_id TEXT NOT NULL REFERENCES objectives(objective_id),
    work_unit_id TEXT NOT NULL REFERENCES work_units(work_unit_id),
    operator_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    status TEXT NOT NULL CHECK (status IN ('planned', 'starting')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    CHECK ((status = 'planned' AND version = 1) OR (status = 'starting' AND version >= 2))
) STRICT;

CREATE TABLE run_participations (
    participation_id TEXT PRIMARY KEY CHECK (length(participation_id) = 36),
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    role TEXT NOT NULL CHECK (length(role) BETWEEN 1 AND 128),
    session_id TEXT REFERENCES actor_sessions(session_id),
    status TEXT NOT NULL CHECK (status IN ('invited', 'active')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (run_id, actor_id),
    CHECK ((status = 'invited' AND session_id IS NULL AND version = 1) OR
           (status = 'active' AND session_id IS NOT NULL AND version >= 2))
) STRICT;

CREATE TABLE runtime_bindings (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) = 36),
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    participation_id TEXT NOT NULL REFERENCES run_participations(participation_id),
    session_id TEXT NOT NULL REFERENCES actor_sessions(session_id),
    runtime_endpoint_id TEXT NOT NULL CHECK (length(runtime_endpoint_id) = 36),
    status TEXT NOT NULL CHECK (status = 'requested'),
    version INTEGER NOT NULL CHECK (version = 1),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (run_id, binding_id)
) STRICT;

CREATE TABLE ceremony_challenges (
    ceremony_id TEXT PRIMARY KEY CHECK (length(ceremony_id) = 36),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    purpose TEXT NOT NULL,
    proof_fingerprint BLOB NOT NULL CHECK (length(proof_fingerprint) = 32),
    installation_id TEXT CHECK (installation_id IS NULL OR length(installation_id) = 36),
    workspace_id TEXT CHECK (workspace_id IS NULL OR length(workspace_id) = 36),
    principal_id TEXT NOT NULL CHECK (length(principal_id) = 36),
    membership_id TEXT CHECK (membership_id IS NULL OR length(membership_id) = 36),
    actor_id TEXT CHECK (actor_id IS NULL OR length(actor_id) = 36),
    delegation_id TEXT CHECK (delegation_id IS NULL OR length(delegation_id) = 36),
    device_id TEXT CHECK (device_id IS NULL OR length(device_id) = 36),
    status TEXT NOT NULL,
    expires_at_us INTEGER NOT NULL CHECK (expires_at_us > 0),
    consumed_at_us INTEGER,
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    CHECK (
        (purpose = 'membership_acceptance' AND scope_kind = 'workspace' AND installation_id IS NULL AND
            workspace_id = scope_id AND membership_id IS NOT NULL AND actor_id IS NULL AND delegation_id IS NULL AND device_id IS NULL) OR
        (purpose IN ('delegation_activation', 'actor_session_start') AND scope_kind = 'workspace' AND installation_id IS NULL AND
            workspace_id = scope_id AND membership_id IS NULL AND actor_id IS NOT NULL AND delegation_id IS NOT NULL AND device_id IS NULL) OR
        (purpose = 'device_pairing' AND scope_kind = 'installation' AND installation_id = scope_id AND
            workspace_id IS NULL AND membership_id IS NULL AND actor_id IS NULL AND delegation_id IS NULL AND device_id IS NOT NULL)
    ),
    CHECK (
        (status = 'pending' AND consumed_at_us IS NULL) OR
        (status = 'consumed' AND consumed_at_us IS NOT NULL)
    )
) STRICT;

CREATE TABLE command_receipts (
    receipt_id TEXT PRIMARY KEY CHECK (length(receipt_id) = 36),
    command_id TEXT NOT NULL UNIQUE CHECK (length(command_id) = 36),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    authority_id TEXT NOT NULL CHECK (length(authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('ordinary_workspace', 'installation_provisioning', 'installation_admin')),
    workspace_id TEXT CHECK (workspace_id IS NULL OR length(workspace_id) = 36),
    installation_id TEXT CHECK (installation_id IS NULL OR length(installation_id) = 36),
    principal_id TEXT CHECK (principal_id IS NULL OR length(principal_id) = 36),
    client_instance_id TEXT CHECK (client_instance_id IS NULL OR length(client_instance_id) = 36),
    transcript_fingerprint BLOB CHECK (transcript_fingerprint IS NULL OR length(transcript_fingerprint) = 32),
    operation TEXT NOT NULL,
    operation_major INTEGER NOT NULL CHECK (operation_major BETWEEN 1 AND 65535),
    idempotency_key TEXT NOT NULL,
    request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32),
    result_canonical BLOB NOT NULL,
    first_event_sequence INTEGER NOT NULL CHECK (first_event_sequence BETWEEN 1 AND 9007199254740991),
    last_event_sequence INTEGER NOT NULL CHECK (last_event_sequence >= first_event_sequence),
    final_stream_digest BLOB NOT NULL CHECK (length(final_stream_digest) = 32),
    guard_digest BLOB NOT NULL CHECK (length(guard_digest) = 32),
    capsule_required INTEGER NOT NULL CHECK (capsule_required IN (0, 1)),
    recovery_capsule_canonical BLOB,
    recovery_capsule_digest BLOB CHECK (recovery_capsule_digest IS NULL OR length(recovery_capsule_digest) = 32),
    recovery_capsule_key_id TEXT,
    recovery_capsule_public_key BLOB CHECK (recovery_capsule_public_key IS NULL OR length(recovery_capsule_public_key) = 32),
    committed_at_us INTEGER NOT NULL CHECK (committed_at_us > 0),
    CHECK (
        (identity_kind = 'ordinary_workspace' AND workspace_id IS NOT NULL AND installation_id IS NULL AND
            principal_id IS NOT NULL AND client_instance_id IS NOT NULL AND transcript_fingerprint IS NULL) OR
        (identity_kind = 'installation_provisioning' AND workspace_id IS NULL AND installation_id IS NOT NULL AND
            principal_id IS NULL AND client_instance_id IS NULL AND transcript_fingerprint IS NOT NULL) OR
        (identity_kind = 'installation_admin' AND workspace_id IS NULL AND installation_id IS NOT NULL AND
            principal_id IS NOT NULL AND client_instance_id IS NOT NULL AND transcript_fingerprint IS NULL)
    ),
    CHECK (
        (capsule_required = 0 AND recovery_capsule_canonical IS NULL AND recovery_capsule_digest IS NULL AND
            recovery_capsule_key_id IS NULL AND recovery_capsule_public_key IS NULL) OR
        (capsule_required = 1 AND recovery_capsule_canonical IS NOT NULL AND recovery_capsule_digest IS NOT NULL AND
            recovery_capsule_key_id IS NOT NULL AND recovery_capsule_public_key IS NOT NULL)
    ),
    CHECK (
        (operation IN ('installation.bootstrap.v1', 'workspace.create.v1') AND last_event_sequence = first_event_sequence + 2) OR
        (operation NOT IN ('installation.bootstrap.v1', 'workspace.create.v1') AND last_event_sequence = first_event_sequence)
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

CREATE TABLE command_receipt_resources (
    receipt_id TEXT NOT NULL REFERENCES command_receipts(receipt_id),
    resource_ordinal INTEGER NOT NULL CHECK (resource_ordinal BETWEEN 0 AND 9007199254740991),
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL CHECK (length(aggregate_id) = 36),
    aggregate_version INTEGER NOT NULL CHECK (aggregate_version BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (receipt_id, resource_ordinal),
    UNIQUE (receipt_id, aggregate_kind, aggregate_id)
) STRICT;

CREATE TABLE command_receipt_ceremonies (
    receipt_id TEXT NOT NULL REFERENCES command_receipts(receipt_id),
    ceremony_ordinal INTEGER NOT NULL CHECK (ceremony_ordinal BETWEEN 0 AND 9007199254740991),
    ceremony_id TEXT NOT NULL REFERENCES ceremony_challenges(ceremony_id),
    PRIMARY KEY (receipt_id, ceremony_ordinal),
    UNIQUE (receipt_id, ceremony_id)
) STRICT;

CREATE TABLE domain_events (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) = 36),
    command_id TEXT NOT NULL CHECK (length(command_id) = 36),
    receipt_id TEXT NOT NULL REFERENCES command_receipts(receipt_id),
    authority_id TEXT NOT NULL CHECK (length(authority_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    stream_sequence INTEGER NOT NULL CHECK (stream_sequence BETWEEN 1 AND 9007199254740991),
    previous_stream_digest BLOB NOT NULL CHECK (length(previous_stream_digest) = 32),
    event_digest BLOB NOT NULL CHECK (length(event_digest) = 32),
    stream_digest BLOB NOT NULL CHECK (length(stream_digest) = 32),
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL CHECK (length(aggregate_id) = 36),
    aggregate_version INTEGER NOT NULL CHECK (aggregate_version BETWEEN 1 AND 9007199254740991),
    event_index INTEGER NOT NULL CHECK (event_index BETWEEN 0 AND 9007199254740991),
    event_type TEXT NOT NULL,
    event_schema INTEGER NOT NULL CHECK (event_schema BETWEEN 1 AND 65535),
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
    audit_sequence INTEGER NOT NULL CHECK (audit_sequence BETWEEN 1 AND 9007199254740991),
    previous_entry_hash BLOB NOT NULL CHECK (length(previous_entry_hash) = 32),
    entry_hash BLOB NOT NULL CHECK (length(entry_hash) = 32),
    canonical_entry BLOB NOT NULL,
    recorded_at_us INTEGER NOT NULL CHECK (recorded_at_us > 0),
    PRIMARY KEY (scope_kind, scope_id, audit_sequence),
    UNIQUE (entry_hash)
) STRICT;

CREATE TABLE security_denials (
    record_kind TEXT NOT NULL CHECK (record_kind IN ('bootstrap', 'command')),
    denial_fingerprint BLOB NOT NULL CHECK (length(denial_fingerprint) = 32),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    subject_kind TEXT NOT NULL,
    subject_id TEXT,
    operation TEXT,
    operation_major INTEGER,
    denial_class TEXT NOT NULL,
    reason TEXT NOT NULL,
    bucket INTEGER NOT NULL CHECK (bucket >= 0),
    occurrence_count INTEGER NOT NULL CHECK (occurrence_count > 0),
    first_recorded_at_us INTEGER NOT NULL CHECK (first_recorded_at_us > 0),
    last_recorded_at_us INTEGER NOT NULL CHECK (last_recorded_at_us >= first_recorded_at_us),
    CHECK (
        (record_kind = 'bootstrap' AND subject_kind = 'invitation' AND subject_id IS NOT NULL AND
            operation IS NULL AND operation_major IS NULL AND bucket = 0) OR
        (record_kind = 'command' AND operation IS NOT NULL AND operation_major IS NOT NULL AND operation_major > 0)
    )
) STRICT;

CREATE UNIQUE INDEX security_denials_bootstrap_identity
    ON security_denials(subject_id, denial_fingerprint)
    WHERE record_kind = 'bootstrap';
CREATE UNIQUE INDEX security_denials_command_identity
    ON security_denials(
        scope_kind, scope_id, subject_kind, subject_id, operation, operation_major,
        denial_class, bucket, denial_fingerprint
    ) WHERE record_kind = 'command';

CREATE TABLE outbox_jobs (
    job_id TEXT PRIMARY KEY CHECK (length(job_id) = 36),
    command_id TEXT NOT NULL CHECK (length(command_id) = 36),
    event_id TEXT NOT NULL REFERENCES domain_events(event_id),
    handler TEXT NOT NULL,
    handler_contract_version INTEGER NOT NULL CHECK (handler_contract_version BETWEEN 1 AND 65535),
    destination_key TEXT NOT NULL,
    effect_ordinal INTEGER NOT NULL CHECK (effect_ordinal BETWEEN 0 AND 9007199254740991),
    effect_kind TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload BLOB NOT NULL,
    metadata_digest BLOB NOT NULL CHECK (length(metadata_digest) = 32),
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL CHECK (attempt_count BETWEEN 0 AND 9007199254740991),
    available_at_us INTEGER NOT NULL CHECK (available_at_us > 0),
    claim_token TEXT,
    claim_deadline_us INTEGER,
    claim_authority_epoch TEXT CHECK (claim_authority_epoch IS NULL OR length(claim_authority_epoch) = 36),
    last_error_class TEXT,
    result BLOB,
    parked_disposition TEXT,
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    UNIQUE (command_id, handler, handler_contract_version, destination_key, effect_ordinal),
    UNIQUE (command_id, event_id, handler, handler_contract_version, destination_key, effect_ordinal)
) STRICT;

CREATE TABLE projection_checkpoints (
    projection_name TEXT NOT NULL,
    projection_schema INTEGER NOT NULL CHECK (projection_schema BETWEEN 1 AND 65535),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('installation', 'workspace')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) = 36),
    authority_epoch TEXT NOT NULL CHECK (length(authority_epoch) = 36),
    contiguous_sequence INTEGER NOT NULL CHECK (contiguous_sequence BETWEEN 0 AND 9007199254740991),
    stream_digest BLOB NOT NULL CHECK (length(stream_digest) = 32),
    health TEXT NOT NULL CHECK (health IN ('healthy', 'blocked', 'poisoned', 'rebuilding')),
    poison_event_id TEXT,
    updated_at_us INTEGER NOT NULL CHECK (updated_at_us > 0),
    PRIMARY KEY (projection_name, projection_schema, scope_kind, scope_id, authority_epoch)
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
