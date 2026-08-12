package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

func writeIdentityState(ctx context.Context, tx pgx.Tx, state application.IdentityState, now time.Time) error {
	current, prior, timestamp := state.Version().Uint64(), state.Version().Uint64()-1, timeMicros(now)
	var tag pgconn.CommandTag
	var err error
	switch value := state.Value().(type) {
	case domain.InstallationInvitationState:
		tag, err = tx.Exec(ctx, `UPDATE installation_invitations SET status=$1,failed_attempts=$2,version=$3,updated_at_us=$4 WHERE invitation_id=$5 AND version=$6`, string(value.Status()), value.FailedAttempts(), current, timestamp, value.ID().String(), prior)
	case domain.PrincipalState:
		var public any
		if value.PublicKeyReference().String() != "" {
			public = value.PublicKeyReference().String()
		}
		tag, err = tx.Exec(ctx, `INSERT INTO principals(principal_id,installation_id,kind,display_name,public_key_reference,status,version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)`, value.ID().String(), value.InstallationID().String(), string(value.Kind()), value.DisplayName().String(), public, string(value.Status()), current, timestamp)
	case domain.DeviceState:
		tag, err = writeDeviceState(ctx, tx, value, current, prior, timestamp)
	case domain.GrantState:
		caps, e := capabilitiesJSON(value.Capabilities())
		if e != nil {
			return e
		}
		var workspace any
		if !value.WorkspaceID().IsZero() {
			workspace = value.WorkspaceID().String()
		}
		tag, err = tx.Exec(ctx, `INSERT INTO grants(grant_id,installation_id,workspace_id,principal_id,capabilities_json,status,version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$8)`, value.ID().String(), value.InstallationID().String(), workspace, value.PrincipalID().String(), caps, string(value.Status()), current, timestamp)
	case domain.WorkspaceState:
		tag, err = tx.Exec(ctx, `INSERT INTO workspaces(workspace_id,installation_id,home_authority_id,authority_epoch,alias,discovery_locator,policy_revision,status,version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`, value.ID().String(), value.InstallationID().String(), value.AuthorityID().String(), value.AuthorityEpoch().String(), value.Alias().String(), value.DiscoveryLocator().String(), value.PolicyRevision().String(), string(value.Status()), current, timestamp)
	case domain.MembershipState:
		caps, e := capabilitiesJSON(value.Capabilities())
		if e != nil {
			return e
		}
		if current == 1 {
			tag, err = tx.Exec(ctx, `INSERT INTO workspace_memberships(membership_id,workspace_id,principal_id,capabilities_json,status,version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$7)`, value.ID().String(), value.WorkspaceID().String(), value.PrincipalID().String(), caps, string(value.Status()), current, timestamp)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE workspace_memberships SET status=$1,version=$2,updated_at_us=$3 WHERE membership_id=$4 AND version=$5`, string(value.Status()), current, timestamp, value.ID().String(), prior)
		}
	case domain.ActorState:
		tag, err = tx.Exec(ctx, `INSERT INTO actors(actor_id,workspace_id,kind,display_name,status,version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$7)`, value.ID().String(), value.WorkspaceID().String(), string(value.Kind()), value.Profile().DisplayName().String(), string(value.Status()), current, timestamp)
	case domain.ActorDelegationState:
		caps, e := capabilitiesJSON(value.Capabilities())
		if e != nil {
			return e
		}
		if current == 1 {
			tag, err = tx.Exec(ctx, `INSERT INTO actor_delegations(delegation_id,workspace_id,principal_id,actor_id,membership_id,capabilities_json,status,version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$9)`, value.ID().String(), value.WorkspaceID().String(), value.PrincipalID().String(), value.ActorID().String(), value.MembershipID().String(), caps, string(value.Status()), current, timestamp)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE actor_delegations SET status=$1,version=$2,updated_at_us=$3 WHERE delegation_id=$4 AND version=$5`, string(value.Status()), current, timestamp, value.ID().String(), prior)
		}
	case domain.ActorSessionState:
		tag, err = insertActorSessionState(ctx, tx, value, timestamp)
	case domain.WorkReferenceState:
		observation := value.Observation()
		if current == 1 {
			tag, err = tx.Exec(ctx, `INSERT INTO work_references(work_reference_id,workspace_id,provider_namespace,
				provider_object_id,provider_locator,provider_version,selected_fields,adapter_principal_id,observed_at_us,
				version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$11)`,
				value.ID().String(), value.WorkspaceID().String(), observation.Namespace().String(), observation.ObjectID().String(),
				observation.Locator().String(), observation.ProviderVersion().String(), observation.Fields().Bytes(),
				observation.AdapterPrincipalID().String(), timeMicros(observation.ObservedAt()), current, timestamp)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE work_references SET provider_locator=$1,provider_version=$2,selected_fields=$3::jsonb,
				observed_at_us=$4,version=$5,updated_at_us=$6 WHERE work_reference_id=$7 AND provider_namespace=$8
				AND provider_object_id=$9 AND adapter_principal_id=$10 AND version=$11`, observation.Locator().String(),
				observation.ProviderVersion().String(), observation.Fields().Bytes(), timeMicros(observation.ObservedAt()), current,
				timestamp, value.ID().String(), observation.Namespace().String(), observation.ObjectID().String(),
				observation.AdapterPrincipalID().String(), prior)
		}
	case domain.ObjectiveState:
		if current == 1 {
			tag, err = tx.Exec(ctx, `INSERT INTO objectives(objective_id,workspace_id,title,acceptance_criteria,status,version,
				created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$7)`, value.ID().String(),
				value.WorkspaceID().String(), value.Title(), value.AcceptanceCriteria(), string(value.Status()), current, timestamp)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE objectives SET status=$1,version=$2,updated_at_us=$3
				WHERE objective_id=$4 AND version=$5`, string(value.Status()), current, timestamp, value.ID().String(), prior)
		}
	case domain.WorkUnitState:
		tag, err = tx.Exec(ctx, `INSERT INTO work_units(work_unit_id,workspace_id,objective_id,work_reference_id,title,status,
			version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)`, value.ID().String(),
			value.WorkspaceID().String(), value.ObjectiveID().String(), value.WorkReferenceID().String(), value.Title(),
			string(value.Status()), current, timestamp)
	case domain.RunState:
		if current == 1 {
			tag, err = tx.Exec(ctx, `INSERT INTO runs(run_id,workspace_id,objective_id,work_unit_id,operator_actor_id,status,
				version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)`, value.ID().String(),
				value.WorkspaceID().String(), value.ObjectiveID().String(), value.WorkUnitID().String(), value.OperatorID().String(),
				string(value.Status()), current, timestamp)
			if err == nil {
				for ordinal, participationID := range value.RequiredParticipationIDs() {
					if _, err = tx.Exec(ctx, `INSERT INTO run_required_participations(workspace_id,run_id,participation_id,
						roster_ordinal) VALUES($1,$2,$3,$4)`, value.WorkspaceID().String(), value.ID().String(),
						participationID.String(), ordinal); err != nil {
						break
					}
				}
			}
		} else {
			tag, err = tx.Exec(ctx, `UPDATE runs SET status=$1,version=$2,updated_at_us=$3 WHERE run_id=$4 AND version=$5`,
				string(value.Status()), current, timestamp, value.ID().String(), prior)
		}
	case domain.RunParticipationState:
		if current == 1 {
			tag, err = tx.Exec(ctx, `INSERT INTO run_participations(participation_id,run_id,actor_id,role,session_id,status,
				version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,NULL,$5,$6,$7,$7)`, value.ID().String(),
				value.RunID().String(), value.ActorID().String(), value.Role(), string(value.Status()), current, timestamp)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE run_participations SET session_id=$1,status=$2,version=$3,updated_at_us=$4
				WHERE participation_id=$5 AND version=$6`, value.ActorSessionID().String(), string(value.Status()), current,
				timestamp, value.ID().String(), prior)
		}
	case domain.RuntimeBindingState:
		tag, err = tx.Exec(ctx, `INSERT INTO runtime_bindings(binding_id,run_id,participation_id,session_id,
			runtime_endpoint_id,status,version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)`,
			value.ID().String(), value.RunID().String(), value.ParticipationID().String(), value.ActorSessionID().String(),
			value.RuntimeEndpointID().String(), string(value.Status()), current, timestamp)
	default:
		return application.ErrInvalidCommandDecision
	}
	if err != nil {
		return fmt.Errorf("write PostgreSQL %s: %w", state.Target().String(), err)
	}
	if tag.RowsAffected() != 1 {
		return commandReferenceConflict("aggregate changed")
	}
	return nil
}

func writeDeviceState(ctx context.Context, tx pgx.Tx, value domain.DeviceState, current, prior uint64, timestamp int64) (pgconn.CommandTag, error) {
	var algorithm, spki, transcript, activatedAt any
	if credential := value.CredentialBinding(); !credential.IsZero() {
		algorithm = credential.Algorithm()
		spkiValue := credential.SPKIFingerprint().Bytes()
		transcriptValue := credential.TranscriptFingerprint()
		spki, transcript = spkiValue[:], transcriptValue[:]
		activatedAt = timeMicros(value.CredentialActivatedAt())
	}
	var retiringAlgorithm, retiringKey, retiringSPKI, retiringTranscript, retiringExpires any
	if retiring, expires, present := value.RetiringCredential(); present {
		retiringAlgorithm, retiringKey = retiring.Algorithm(), retiring.PublicKeyReference().String()
		spkiValue := retiring.SPKIFingerprint().Bytes()
		transcriptValue := retiring.TranscriptFingerprint()
		retiringSPKI, retiringTranscript, retiringExpires = spkiValue[:], transcriptValue[:], timeMicros(expires)
	}
	var rotationTranscript, rotatedAt, revokedAt any
	if fp := value.RotationTranscriptFingerprint(); !fp.IsZero() {
		rotationTranscript = fp[:]
	}
	if !value.RotatedAt().IsZero() {
		rotatedAt = timeMicros(value.RotatedAt())
	}
	if !value.RevokedAt().IsZero() {
		revokedAt = timeMicros(value.RevokedAt())
	}
	if current == 1 {
		return tx.Exec(ctx, `INSERT INTO device_registrations(device_id,installation_id,principal_id,display_name,credential_algorithm,public_key_reference,spki_fingerprint,transcript_fingerprint,trust_revision,revocation_revision,credential_activated_at_us,retiring_credential_algorithm,retiring_public_key_reference,retiring_spki_fingerprint,retiring_transcript_fingerprint,retiring_credential_expires_at_us,rotation_transcript_fingerprint,rotated_at_us,revoked_at_us,status,version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$22)`, value.ID().String(), value.InstallationID().String(), value.PrincipalID().String(), value.DisplayName().String(), algorithm, value.PublicKeyReference().String(), spki, transcript, value.TrustRevision().Uint64(), value.RevocationRevision().Uint64(), activatedAt, retiringAlgorithm, retiringKey, retiringSPKI, retiringTranscript, retiringExpires, rotationTranscript, rotatedAt, revokedAt, string(value.Status()), current, timestamp)
	}
	return tx.Exec(ctx, `UPDATE device_registrations SET credential_algorithm=$1,public_key_reference=$2,spki_fingerprint=$3,transcript_fingerprint=$4,trust_revision=$5,revocation_revision=$6,credential_activated_at_us=$7,retiring_credential_algorithm=$8,retiring_public_key_reference=$9,retiring_spki_fingerprint=$10,retiring_transcript_fingerprint=$11,retiring_credential_expires_at_us=$12,rotation_transcript_fingerprint=$13,rotated_at_us=$14,revoked_at_us=$15,status=$16,version=$17,updated_at_us=$18 WHERE device_id=$19 AND version=$20`, algorithm, value.PublicKeyReference().String(), spki, transcript, value.TrustRevision().Uint64(), value.RevocationRevision().Uint64(), activatedAt, retiringAlgorithm, retiringKey, retiringSPKI, retiringTranscript, retiringExpires, rotationTranscript, rotatedAt, revokedAt, string(value.Status()), current, timestamp, value.ID().String(), prior)
}

func insertActorSessionState(ctx context.Context, tx pgx.Tx, value domain.ActorSessionState, timestamp int64) (pgconn.CommandTag, error) {
	binding := value.Binding()
	caps, err := capabilitiesJSON(value.Capabilities())
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	membership, delegation := binding.MembershipRevision(), binding.DelegationRevision()
	var deviceID, deviceVersion, deviceTrust any
	if device, present := binding.DeviceRevision(); present {
		deviceID, deviceVersion = device.ID(), device.Version().Uint64()
		trust, _ := binding.DeviceTrustRevision()
		deviceTrust = trust.Uint64()
	}
	presentation := value.PresentationCredential()
	digest := presentation.Digest().Bytes()
	tag, err := tx.Exec(ctx, `INSERT INTO actor_sessions(session_id,authority_id,authority_epoch,workspace_id,principal_id,actor_id,delegation_id,delegation_version,membership_id,membership_version,device_id,device_version,device_trust_revision,client_instance_id,client_name,client_version,capabilities_json,policy_revision,assurance_class,presentation_credential_reference,presentation_credential_digest,presentation_credential_audience,presentation_credential_version,status,issued_at_us,expires_at_us,version,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$28)`, value.ID().String(), binding.AuthorityID().String(), binding.AuthorityEpoch().String(), binding.WorkspaceID().String(), binding.PrincipalID().String(), binding.ActorID().String(), delegation.ID(), delegation.Version().Uint64(), membership.ID(), membership.Version().Uint64(), deviceID, deviceVersion, deviceTrust, value.ClientInstanceID().String(), value.ClientMetadata().Name(), value.ClientMetadata().Version(), caps, binding.PolicyRevision().String(), binding.AssuranceClass().String(), presentation.Reference().String(), digest[:], presentation.Audience().String(), presentation.Version(), string(value.Status()), timeMicros(binding.IssuedAt()), timeMicros(binding.AbsoluteExpiry()), value.Version().Uint64(), timestamp)
	if err != nil {
		return tag, err
	}
	for _, grant := range binding.GrantRevisions() {
		if _, err := tx.Exec(ctx, `INSERT INTO actor_session_grant_revisions(session_id,grant_id,grant_version) VALUES($1,$2,$3)`, value.ID().String(), grant.ID(), grant.Version().Uint64()); err != nil {
			return pgconn.CommandTag{}, err
		}
	}
	return tag, nil
}

func insertCommandReceipt(ctx context.Context, tx pgx.Tx, receipt application.ReceiptSnapshot, plan application.ReceiptResultPlan, final domain.StreamDigest, committed time.Time) error {
	identity, result, events := receipt.Identity(), receipt.Result(), receipt.Events()
	fingerprint, digest, guard := receipt.RequestFingerprint(), result.ResponseDigest(), receipt.GuardDigest()
	guardBytes, finalBytes := guard.Bytes(), final.Bytes()
	nullable := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	var transcript any
	if fp := identity.TranscriptFingerprint(); !fp.IsZero() {
		transcript = fp[:]
	}
	var capsuleCanonical, capsuleDigest, capsuleKey, capsulePublic any
	required := false
	if capsule, present := receipt.RecoveryCapsule(); present {
		required = true
		capsuleCanonical = capsule.CanonicalBytes()
		value := capsule.Digest()
		capsuleDigest = value[:]
		capsuleKey = capsule.KeyID()
		capsulePublic = plan.RecoveryCapsulePlan().Ed25519PublicKey()
	}
	_, err := tx.Exec(ctx, `INSERT INTO command_receipts(receipt_id,command_id,scope_kind,scope_id,authority_id,authority_epoch,identity_kind,workspace_id,installation_id,principal_id,client_instance_id,transcript_fingerprint,operation,operation_major,idempotency_key,request_fingerprint,result_digest,result_canonical,first_event_sequence,last_event_sequence,final_stream_digest,guard_digest,capsule_required,recovery_capsule_canonical,recovery_capsule_digest,recovery_capsule_key_id,recovery_capsule_public_key,committed_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`, receipt.ReceiptID().String(), receipt.CommandID().String(), string(identity.Scope().Kind()), identity.Scope().ID(), receipt.AuthorityID().String(), receipt.AuthorityEpoch().String(), string(identity.Kind()), nullable(identity.WorkspaceID().String()), nullable(identity.InstallationID().String()), nullable(identity.PrincipalID().String()), nullable(identity.ClientInstanceID().String()), transcript, identity.Operation().String(), plan.OperationMajor().Uint16(), identity.Key().String(), fingerprint[:], digest[:], result.CanonicalBytes(), events.First().Uint64(), events.Last().Uint64(), finalBytes[:], guardBytes[:], required, capsuleCanonical, capsuleDigest, capsuleKey, capsulePublic, timeMicros(committed))
	if err != nil {
		return fmt.Errorf("insert PostgreSQL command receipt: %w", err)
	}
	for ordinal, resource := range plan.Resources() {
		if _, err := tx.Exec(ctx, `INSERT INTO command_receipt_resources(receipt_id,resource_ordinal,aggregate_kind,aggregate_id,aggregate_version) VALUES($1,$2,$3,$4,$5)`, receipt.ReceiptID().String(), ordinal, string(resource.Kind()), resource.ID(), resource.Version().Uint64()); err != nil {
			return err
		}
	}
	for ordinal, ceremony := range plan.IssuedCeremonies() {
		if _, err := tx.Exec(ctx, `INSERT INTO command_receipt_ceremonies(receipt_id,ceremony_ordinal,ceremony_id) VALUES($1,$2,$3)`, receipt.ReceiptID().String(), ordinal, ceremony.ID().String()); err != nil {
			return err
		}
	}
	return nil
}

func insertDomainEvent(ctx context.Context, tx pgx.Tx, event domain.EventEnvelope) error {
	previous, eventDigest, streamDigest := event.PreviousStreamDigest().Bytes(), event.EventDigest().Bytes(), event.StreamDigest().Bytes()
	authorization := event.AuthorizationDigest().Bytes()
	var actor, cause any
	if v, p := event.ActorSessionID(); p {
		actor = v.String()
	}
	if v, p := event.CausationEventID(); p {
		cause = v.String()
	}
	_, err := tx.Exec(ctx, `INSERT INTO domain_events(event_id,command_id,receipt_id,authority_id,authority_epoch,scope_kind,scope_id,stream_sequence,previous_stream_digest,event_digest,stream_digest,aggregate_kind,aggregate_id,aggregate_version,event_index,event_type,event_schema,payload,principal_id,actor_session_id,authorization_digest,causation_event_id,correlation_id,recorded_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`, event.EventID().String(), event.CommandID().String(), event.CommandReceiptID().String(), event.AuthorityID().String(), event.AuthorityEpoch().String(), string(event.Scope().Kind()), event.Scope().ID(), event.StreamPosition().Uint64(), previous[:], eventDigest[:], streamDigest[:], string(event.Aggregate().Kind()), event.Aggregate().ID(), event.Aggregate().Version().Uint64(), event.EventIndex(), string(event.EventType()), event.SchemaVersion().Uint16(), event.Payload().Bytes(), event.PrincipalID().String(), actor, authorization[:], cause, event.CorrelationID().String(), timeMicros(event.RecordedAt()))
	return err
}

func appendCommandAudit(ctx context.Context, tx pgx.Tx, state lockedCommandState, intent application.AuditIntent) error {
	view, err := application.NewAuditEntryViewV1(application.AuditEntryParams{ChainScopeID: state.spec.Scope(), Sequence: state.stream.nextAudit, AuthorityID: state.spec.AuthorityID(), AuthorityEpoch: state.spec.RequestedEpoch(), RecordedAt: state.time.Value(), Intent: intent, PreviousEntryHash: state.stream.auditHead})
	if err != nil {
		return err
	}
	codec := application.NewProductionCanonicalCodec()
	canonical, digest, err := codec.EncodeAuditEntry(view)
	if err != nil {
		return err
	}
	if err := codec.VerifyAuditEntry(state.stream.auditHead, canonical, digest); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_entries(scope_kind,scope_id,audit_sequence,previous_entry_hash,entry_hash,canonical_entry,recorded_at_us) VALUES($1,$2,$3,$4,$5,$6,$7)`, string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.stream.nextAudit, state.stream.auditHead[:], digest[:], canonical, timeMicros(state.time.Value()))
	return err
}

func insertOutboxEffects(ctx context.Context, tx pgx.Tx, commandID domain.CommandID, effects application.EffectSet, now time.Time) error {
	for _, effect := range effects.Intents() {
		seed := []byte("blackbird.outbox-job/v1\x00" + commandID.String() + "\x00" + effect.Handler() + "\x00" + uintText(uint64(effect.ContractMajor().Uint16())) + "\x00" + effect.DestinationKey() + "\x00" + uintText(uint64(effect.Ordinal())))
		sum := sha256.Sum256(seed)
		metadataDigest := effect.MetadataDigest()
		if _, err := tx.Exec(ctx, `INSERT INTO outbox_jobs(job_id,command_id,event_id,handler,handler_contract_version,destination_key,effect_ordinal,effect_kind,idempotency_key,payload,metadata_digest,status,attempt_count,available_at_us,created_at_us,updated_at_us) VALUES($1,$2,$3,$4,$5,$6,$7,'command_effect',$8,$9,$10,'pending',0,$11,$11,$11)`, digestUUID(sum), commandID.String(), effect.CausingEventID().String(), effect.Handler(), effect.ContractMajor().Uint16(), effect.DestinationKey(), effect.Ordinal(), fmt.Sprintf("%x", sum), effect.Metadata(), metadataDigest[:], timeMicros(now)); err != nil {
			return err
		}
	}
	return nil
}

func verifyFinalCommandState(ctx context.Context, tx pgx.Tx, state lockedCommandState, decision application.CommandDecision) error {
	if err := verifyCurrentAdmission(ctx, tx, state.spec); err != nil {
		return err
	}
	mutated := make(map[domain.AggregateTarget]struct{}, len(decision.Writes()))
	for _, write := range decision.Writes() {
		mutated[write.Target()] = struct{}{}
		persisted, err := loadIdentityState(ctx, tx, write.Target(), false)
		if err != nil {
			return fmt.Errorf("verify PostgreSQL command mutation: %w", err)
		}
		if persisted.Version() != write.Version() || !sameRunRoster(persisted, write) {
			return commandReferenceConflict("command mutation changed")
		}
	}
	if err := verifyDurableCommandEvidence(ctx, tx, state, mutated); err != nil {
		return err
	}
	for _, transition := range decision.CeremonyTransitions() {
		proof := transition.Challenge().ProofDigest()
		status := "pending"
		if transition.Kind() != application.CeremonyReserveAbsent {
			status = "consumed"
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ceremony_challenges WHERE ceremony_id=$1 AND purpose=$2 AND proof_fingerprint=$3 AND status=$4`, transition.Challenge().ID().String(), string(transition.Challenge().Purpose()), proof[:], status).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return commandReferenceConflict("ceremony mutation changed")
		}
	}
	return nil
}

func verifyDurableCommandEvidence(ctx context.Context, tx pgx.Tx, state lockedCommandState, mutated map[domain.AggregateTarget]struct{}) error {
	locked := make(map[string]application.IdentityState, len(state.states))
	for _, observed := range state.states {
		locked[observed.Target().String()] = observed
		if _, changed := mutated[observed.Target()]; changed {
			continue
		}
		current, err := loadIdentityState(ctx, tx, observed.Target(), false)
		if errors.Is(err, pgx.ErrNoRows) {
			return commandReferenceConflict("locked command reference is absent")
		}
		if err != nil {
			return fmt.Errorf("revalidate PostgreSQL command reference: %w", err)
		}
		if current.Version() != observed.Version() || !sameRunRoster(current, observed) {
			return commandReferenceConflict("locked command reference changed")
		}
		locked[observed.Target().String()] = current
	}
	for _, guard := range state.spec.Guards().Evidence() {
		switch guard.Kind() {
		case application.EvidenceCurrentAuthorityEpoch:
			authority, epoch, _ := guard.Authority()
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM scope_guards WHERE scope_kind=$1 AND scope_id=$2 AND authority_id=$3 AND authority_epoch=$4 AND write_status='open'`, guard.TargetKind(), guard.TargetID(), authority.String(), epoch.String()).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return commandReferenceConflict("authority evidence changed")
			}
		case application.EvidenceBootstrapGeneration:
			generation, _ := guard.BootstrapGeneration()
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM scope_guards WHERE scope_kind=$1 AND scope_id=$2 AND bootstrap_generation_id=$3`, guard.TargetKind(), guard.TargetID(), generation.String()).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return commandReferenceConflict("bootstrap evidence changed")
			}
		case application.EvidencePolicyRevision, application.EvidenceLifecycleStatus, application.EvidenceDeviceTrustRevision:
			observed, present := locked[guard.TargetKind()+":"+guard.TargetID()]
			if !present {
				if guard.Kind() == application.EvidencePolicyRevision {
					continue
				}
				return commandReferenceConflict("durable guard target is absent")
			}
			if _, changed := mutated[observed.Target()]; changed {
				continue
			}
			if !identityStateMatchesEvidence(observed, guard) {
				return commandReferenceConflict("durable guard evidence changed")
			}
		}
	}
	return nil
}

func identityStateMatchesEvidence(state application.IdentityState, guard application.EvidenceGuard) bool {
	switch guard.Kind() {
	case application.EvidencePolicyRevision:
		revision, _ := guard.PolicyRevision()
		workspace, ok := state.Value().(domain.WorkspaceState)
		return ok && workspace.PolicyRevision() == revision
	case application.EvidenceLifecycleStatus:
		status, _ := guard.Status()
		switch value := state.Value().(type) {
		case domain.InstallationInvitationState:
			return string(value.Status()) == status
		case domain.PrincipalState:
			return string(value.Status()) == status
		case domain.DeviceState:
			return string(value.Status()) == status
		case domain.GrantState:
			return string(value.Status()) == status
		case domain.WorkspaceState:
			return string(value.Status()) == status
		case domain.MembershipState:
			return string(value.Status()) == status
		case domain.ActorState:
			return string(value.Status()) == status
		case domain.ActorDelegationState:
			return string(value.Status()) == status
		case domain.ActorSessionState:
			return string(value.Status()) == status
		case domain.ObjectiveState:
			return string(value.Status()) == status
		case domain.WorkUnitState:
			return string(value.Status()) == status
		case domain.RunState:
			return string(value.Status()) == status
		case domain.RunParticipationState:
			return string(value.Status()) == status
		case domain.RuntimeBindingState:
			return string(value.Status()) == status
		}
	case application.EvidenceDeviceTrustRevision:
		revision, _ := guard.Revision()
		device, ok := state.Value().(domain.DeviceState)
		return ok && device.TrustRevision() == revision
	}
	return false
}

func advanceCommandStream(ctx context.Context, tx pgx.Tx, state lockedCommandState, final domain.StreamDigest, count uint64) error {
	oldHead, finalHead := state.stream.head.Bytes(), final.Bytes()
	tag, err := tx.Exec(ctx, `UPDATE authority_streams SET next_sequence=next_sequence+$1,head_digest=$2,next_audit_sequence=next_audit_sequence+1,audit_head_hash=(SELECT entry_hash FROM audit_entries WHERE scope_kind=$3 AND scope_id=$4 AND audit_sequence=$5),authority_time_floor_us=$6,clock_status=$7 WHERE scope_kind=$3 AND scope_id=$4 AND authority_id=$8 AND authority_epoch=$9 AND next_sequence=$10 AND head_digest=$11 AND next_audit_sequence=$5 AND audit_head_hash=$12 AND authority_time_floor_us=$13 AND clock_status=$14 AND EXISTS(SELECT 1 FROM scope_guards WHERE scope_kind=$15 AND scope_id=$16 AND authority_id=$8 AND authority_epoch=$9 AND write_status='open' AND guard_generation=$17)`, count, finalHead[:], string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.stream.nextAudit, timeMicros(state.time.Value()), state.stream.clockStatus, state.spec.AuthorityID().String(), state.spec.RequestedEpoch().String(), state.stream.nextEvent, oldHead[:], state.stream.auditHead[:], state.stream.timeFloor, state.stream.observedClockStatus, string(state.spec.Guards().AdmissionScope().Kind()), state.spec.Guards().AdmissionScope().ID(), state.spec.Guards().AdmissionGeneration().Uint64())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return commandReferenceConflict("command stream changed")
	}
	return nil
}
