package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

func (store *Store) rehydrateReceipt(ctx context.Context, tx pgx.Tx, spec application.CommandSpec, header receiptHeader) (application.ReceiptSnapshot, error) {
	if header.operationMajor != spec.OperationMajor().Uint16() {
		return application.ReceiptSnapshot{}, application.ErrInvalidApplicationContract
	}
	resources, err := loadReceiptResources(ctx, tx, header.receiptID)
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	ceremonies, err := loadReceiptCeremonies(ctx, tx, header.receiptID)
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	eventIDs, err := loadReceiptEventIDs(ctx, tx, header.receiptID)
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	first, err := domain.NewStreamPosition(header.first)
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	last, err := domain.NewStreamPosition(header.last)
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	events, err := application.NewEventRange(first, last, uint16(len(eventIDs)))
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	plan, err := application.RehydrateRecoveryCapsulePlan(application.RecoveryCapsuleNotApplicable, "", nil)
	if len(header.capsulePublicKey) != 0 {
		plan, err = application.RehydrateRecoveryCapsulePlan(application.RecoveryCapsuleRequired, header.capsuleKey, header.capsulePublicKey)
	}
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	var sessionBinding *domain.SessionBinding
	var sessionClient domain.ClientInstanceID
	var presentation domain.PresentationCredentialBinding
	for _, resource := range resources {
		if resource.Kind() != domain.AggregateKindActorSession {
			continue
		}
		state, err := loadIdentityState(ctx, tx, resource.Target(), true)
		if err != nil {
			return application.ReceiptSnapshot{}, err
		}
		session := state.Value().(domain.ActorSessionState)
		binding := session.Binding()
		sessionBinding, sessionClient, presentation = &binding, session.ClientInstanceID(), session.PresentationCredential()
	}
	binding, err := application.NewReceiptResultReplayBinding(spec, application.ReceiptResultReplayBindingParams{OriginalCommandID: header.commandID,
		AcceptedAuthorityID: header.authorityID, AcceptedAuthorityEpoch: header.epoch, AcceptedAt: header.committedAt,
		GuardDigest: header.guardDigest, Resources: resources, IssuedCeremonies: ceremonies, EventIDs: eventIDs, Events: events,
		FinalStreamDigest: header.finalDigest, SessionBinding: sessionBinding, SessionClient: sessionClient,
		PresentationCredential: presentation, RecoveryCapsulePlan: plan})
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	codec := application.NewProductionCanonicalCodec()
	result, err := codec.VerifyReceiptResult(header.resultCanonical, header.resultDigest, binding)
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	var draft *application.RecoveryCapsuleDraft
	if len(header.capsuleCanonical) != 0 {
		document, err := codec.VerifyRecoveryCapsule(header.capsuleCanonical, header.capsuleDigest, result, binding)
		if err != nil {
			return application.ReceiptSnapshot{}, err
		}
		value, err := application.NewRecoveryCapsuleDraft(result, document, header.capsuleKey)
		if err != nil {
			return application.ReceiptSnapshot{}, err
		}
		draft = &value
	}
	eventCursor, err := commandEventCursor(header.identity.Scope(), header.epoch, events.Last(), header.finalDigest)
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	return application.NewReceiptSnapshot(application.ReceiptSnapshotParams{ReceiptID: header.receiptID, CommandID: header.commandID,
		Identity: header.identity, RequestFingerprint: header.requestFingerprint, Result: result, AuthorityID: header.authorityID,
		AuthorityEpoch: header.epoch, GuardDigest: header.guardDigest, Events: events, EventCursor: eventCursor,
		CapsuleRequirement: plan.Requirement(), RecoveryCapsule: draft})
}

func commandEventCursor(scope domain.AuthorityScope, epoch domain.AuthorityEpoch, position domain.StreamPosition,
	digest domain.StreamDigest) (application.EventCursor, error) {
	if scope.Kind() == domain.ScopeKindWorkspace {
		workspace, err := domain.ParseWorkspaceID(scope.ID())
		if err != nil {
			return application.EventCursor{}, err
		}
		return encodeEventCursor(workspace, epoch, position.Uint64(), digest.Bytes())
	}
	material := fmt.Sprintf("blackbird-receipt-cursor/v1\x00%s\x00%s\x00%s\x00%d\x00%s",
		scope.Kind(), scope.ID(), epoch.String(), position.Uint64(), digest.String())
	checksum := sha256.Sum256([]byte(material))
	return application.NewEventCursor("bbec1_receipt_" + hex.EncodeToString(checksum[:]))
}

func loadReceiptResources(ctx context.Context, tx pgx.Tx, receipt domain.ReceiptID) ([]domain.AggregateRef, error) {
	rows, err := tx.Query(ctx, `SELECT aggregate_kind,aggregate_id::text,aggregate_version FROM command_receipt_resources WHERE receipt_id=$1 ORDER BY resource_ordinal`, receipt.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.AggregateRef
	for rows.Next() {
		var kind, id string
		var version uint64
		if err := rows.Scan(&kind, &id, &version); err != nil {
			return nil, err
		}
		ref, err := aggregateRefFromParts(domain.AggregateKind(kind), id, mustVersion(version))
		if err != nil {
			return nil, err
		}
		result = append(result, ref)
	}
	return result, rows.Err()
}
func aggregateRefFromParts(kind domain.AggregateKind, id string, version domain.Version) (domain.AggregateRef, error) {
	switch kind {
	case domain.AggregateKindInvitation:
		v, e := domain.ParseInvitationID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindPrincipal:
		v, e := domain.ParsePrincipalID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindDevice:
		v, e := domain.ParseDeviceID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindGrant:
		v, e := domain.ParseGrantID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindWorkspace:
		v, e := domain.ParseWorkspaceID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindMembership:
		v, e := domain.ParseMembershipID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindActor:
		v, e := domain.ParseActorID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindActorDelegation:
		v, e := domain.ParseActorDelegationID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindActorSession:
		v, e := domain.ParseActorSessionID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindWorkReference:
		v, e := domain.ParseWorkReferenceID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindObjective:
		v, e := domain.ParseObjectiveID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindWorkUnit:
		v, e := domain.ParseWorkUnitID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindRun:
		v, e := domain.ParseRunID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindRunParticipation:
		v, e := domain.ParseRunParticipationID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindRuntimeBinding:
		v, e := domain.ParseRuntimeBindingID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	case domain.AggregateKindRuntimeEndpoint:
		v, e := domain.ParseRuntimeEndpointID(id)
		if e != nil {
			return domain.AggregateRef{}, e
		}
		return domain.NewAggregateRef(v, version)
	default:
		return domain.AggregateRef{}, application.ErrInvalidApplicationContract
	}
}
func loadReceiptCeremonies(ctx context.Context, tx pgx.Tx, receipt domain.ReceiptID) ([]domain.CeremonyChallenge, error) {
	rows, err := tx.Query(ctx, `SELECT c.ceremony_id::text FROM command_receipt_ceremonies r JOIN ceremony_challenges c ON c.ceremony_id=r.ceremony_id WHERE r.receipt_id=$1 ORDER BY r.ceremony_ordinal`, receipt.String())
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	result := make([]domain.CeremonyChallenge, 0, len(ids))
	for _, id := range ids {
		ceremony, err := loadCeremonyWithStatus(ctx, tx, id, domain.CeremonyPending, false)
		if err != nil {
			return nil, err
		}
		result = append(result, ceremony)
	}
	return result, nil
}
func loadReceiptEventIDs(ctx context.Context, tx pgx.Tx, receipt domain.ReceiptID) ([]domain.EventID, error) {
	rows, err := tx.Query(ctx, `SELECT event_id::text FROM domain_events WHERE receipt_id=$1 ORDER BY event_index`, receipt.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.EventID
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, err
		}
		id, err := domain.ParseEventID(text)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (store *Store) applyCommandDecision(ctx context.Context, tx pgx.Tx, state lockedCommandState, decision application.CommandDecision) (application.CommandTransactionExecution, error) {
	switch decision.Kind() {
	case application.CommandDecisionReplay:
		receipt, disclosure, full := decision.Replay()
		if !full {
			applied, ok := decision.AppliedOnlyReplay()
			if !ok {
				return application.CommandTransactionExecution{}, application.ErrInvalidCommandDecision
			}
			_ = applied
			receipt, _ = state.resolution.Receipt()
			disclosure = application.ReplayDiscloseAppliedOnly
		}
		return application.ReplayedCommandTransactionExecution(receipt, disclosure)
	case application.CommandDecisionRollback:
		rejection, _ := decision.Rejection()
		denial, _ := decision.DenialAudit()
		return application.RejectedCommandTransactionExecution(rejection, denial)
	case application.CommandDecisionApplied:
		return store.commitAppliedCommand(ctx, tx, state, decision)
	default:
		return application.CommandTransactionExecution{}, application.ErrInvalidCommandDecision
	}
}

func (store *Store) commitAppliedCommand(ctx context.Context, tx pgx.Tx, state lockedCommandState, decision application.CommandDecision) (application.CommandTransactionExecution, error) {
	spec, codec := state.spec, application.NewProductionCanonicalCodec()
	if spec.CommandOperation() == application.CommandCreateWorkspace {
		if err := createWorkspaceAuthority(ctx, tx, state); err != nil {
			return application.CommandTransactionExecution{}, err
		}
	}
	for _, transition := range decision.CeremonyTransitions() {
		if err := applyCeremonyTransition(ctx, tx, transition, timeMicros(state.time.Value())); err != nil {
			return application.CommandTransactionExecution{}, err
		}
	}
	for _, write := range decision.Writes() {
		if err := writeIdentityState(ctx, tx, write, state.time.Value()); err != nil {
			return application.CommandTransactionExecution{}, err
		}
	}
	events := make([]domain.EventEnvelope, len(decision.Facts()))
	previous := state.stream.head
	schemaVersion, err := domain.NewEventSchemaVersion(1)
	if err != nil {
		return application.CommandTransactionExecution{}, err
	}
	for index, intent := range decision.Facts() {
		payload, err := codec.MaterializeIdentityFactPayload(intent.Fact())
		if err != nil {
			return application.CommandTransactionExecution{}, err
		}
		position, err := domain.NewStreamPosition(state.stream.nextEvent + uint64(index))
		if err != nil {
			return application.CommandTransactionExecution{}, err
		}
		params := domain.EventEnvelopeParams{EventID: intent.EventID(), CommandID: spec.CommandID(), AuthorityID: spec.AuthorityID(), AuthorityEpoch: spec.RequestedEpoch(), Scope: spec.Scope(), StreamPosition: position, PreviousStreamDigest: previous, Aggregate: intent.Fact().Origin(), EventIndex: uint16(index), EventType: intent.Fact().Type(), SchemaVersion: schemaVersion, Payload: payload, PrincipalID: spec.Authorship().PrincipalID(), AuthorizationDigest: state.evidence.Digest(), CommandReceiptID: spec.ReceiptID(), CorrelationID: spec.CorrelationID(), RecordedAt: state.time.Value()}
		if attribution, present := spec.Authorship().ActorAttribution(); present {
			actor := attribution.ActorSessionID()
			params.ActorSessionID = &actor
		}
		if cause, present := spec.CausationEventID(); present {
			params.CausationEventID = &cause
		}
		events[index], err = codec.MaterializeIdentityEvent(params)
		if err != nil {
			return application.CommandTransactionExecution{}, err
		}
		previous = events[index].StreamDigest()
	}
	first, last := events[0].StreamPosition(), events[len(events)-1].StreamPosition()
	eventRange, err := application.NewEventRange(first, last, uint16(len(events)))
	if err != nil {
		return application.CommandTransactionExecution{}, err
	}
	result, err := codec.MaterializeReceiptResult(decision.ResultPlan(), first, last, previous)
	if err != nil {
		return application.CommandTransactionExecution{}, err
	}
	var capsule *application.RecoveryCapsuleDraft
	if spec.RecoveryCapsule().Requirement() == application.RecoveryCapsuleRequired {
		document, err := codec.MaterializeRecoveryCapsule(decision.ResultPlan(), result)
		if err != nil {
			return application.CommandTransactionExecution{}, err
		}
		draft, err := application.NewRecoveryCapsuleDraft(result, document, spec.RecoveryCapsule().KeyID())
		if err != nil {
			return application.CommandTransactionExecution{}, err
		}
		capsule = &draft
	}
	eventCursor, err := commandEventCursor(spec.Scope(), spec.RequestedEpoch(), last, previous)
	if err != nil {
		return application.CommandTransactionExecution{}, err
	}
	receipt, err := application.NewReceiptSnapshot(application.ReceiptSnapshotParams{ReceiptID: spec.ReceiptID(), CommandID: spec.CommandID(), Identity: spec.ReceiptIdentity(), RequestFingerprint: spec.RequestFingerprint(), Result: result, AuthorityID: spec.AuthorityID(), AuthorityEpoch: spec.RequestedEpoch(), GuardDigest: state.evidence.Digest(), Events: eventRange, EventCursor: eventCursor, CapsuleRequirement: spec.RecoveryCapsule().Requirement(), RecoveryCapsule: capsule})
	if err != nil {
		return application.CommandTransactionExecution{}, err
	}
	if err := insertCommandReceipt(ctx, tx, receipt, decision.ResultPlan(), previous, state.time.Value()); err != nil {
		return application.CommandTransactionExecution{}, err
	}
	for _, event := range events {
		if err := insertDomainEvent(ctx, tx, event); err != nil {
			return application.CommandTransactionExecution{}, err
		}
	}
	if err := appendCommandAudit(ctx, tx, state, decision.Audit()); err != nil {
		return application.CommandTransactionExecution{}, err
	}
	if err := insertOutboxEffects(ctx, tx, spec.CommandID(), decision.Effects(), state.time.Value()); err != nil {
		return application.CommandTransactionExecution{}, err
	}
	if err := verifyFinalCommandState(ctx, tx, state, decision); err != nil {
		return application.CommandTransactionExecution{}, err
	}
	if err := advanceCommandStream(ctx, tx, state, previous, uint64(len(events))); err != nil {
		return application.CommandTransactionExecution{}, err
	}
	return application.CommittedCommandTransactionExecution(receipt)
}

func createWorkspaceAuthority(ctx context.Context, tx pgx.Tx, state lockedCommandState) error {
	spec := state.spec
	head := state.stream.head.Bytes()
	now := timeMicros(state.time.Value())
	if _, err := tx.Exec(ctx, `INSERT INTO scope_guards(scope_kind,scope_id,authority_id,authority_epoch,write_status,guard_generation,updated_at_us) VALUES('workspace',$1,$2,$3,'open',$4,$5)`, spec.Scope().ID(), spec.AuthorityID().String(), spec.RequestedEpoch().String(), spec.Guards().AdmissionGeneration().Uint64(), now); err != nil {
		return fmt.Errorf("create PostgreSQL workspace guard: %w", err)
	}
	_, err := tx.Exec(ctx, `INSERT INTO authority_streams(scope_kind,scope_id,authority_id,authority_epoch,next_sequence,retained_from_sequence,digest_algorithm,head_digest,next_audit_sequence,audit_head_hash,authority_time_floor_us,clock_status) VALUES('workspace',$1,$2,$3,1,1,'sha-256',$4,1,$5,1,'normal')`, spec.Scope().ID(), spec.AuthorityID().String(), spec.RequestedEpoch().String(), head[:], make([]byte, sha256.Size))
	return err
}

func applyCeremonyTransition(ctx context.Context, tx pgx.Tx, transition application.CeremonyTransition, now int64) error {
	challenge := transition.Challenge()
	proof := challenge.ProofDigest()
	scopeKind, scopeID := domain.ScopeKindWorkspace, challenge.WorkspaceID().String()
	if !challenge.InstallationID().IsZero() {
		scopeKind, scopeID = domain.ScopeKindInstallation, challenge.InstallationID().String()
	}
	nullable := func(value string) any {
		if value == "" {
			return nil
		}
		return value
	}
	if transition.Kind() == application.CeremonyReserveAbsent {
		_, err := tx.Exec(ctx, `INSERT INTO ceremony_challenges(ceremony_id,scope_kind,scope_id,purpose,proof_fingerprint,installation_id,workspace_id,principal_id,membership_id,actor_id,delegation_id,device_id,status,expires_at_us,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',$13,1)`, challenge.ID().String(), string(scopeKind), scopeID, string(challenge.Purpose()), proof[:], nullable(challenge.InstallationID().String()), nullable(challenge.WorkspaceID().String()), challenge.PrincipalID().String(), nullable(challenge.MembershipID().String()), nullable(challenge.ActorID().String()), nullable(challenge.DelegationID().String()), nullable(challenge.DeviceID().String()), timeMicros(challenge.ExpiresAt()))
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE ceremony_challenges SET status='consumed',consumed_at_us=$1,version=2 WHERE ceremony_id=$2 AND purpose=$3 AND proof_fingerprint=$4 AND status='pending' AND version=1`, now, challenge.ID().String(), string(challenge.Purpose()), proof[:])
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return commandReferenceConflict("ceremony changed")
	}
	return nil
}

func digestUUID(sum [sha256.Size]byte) string {
	value := sum
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	text := hex.EncodeToString(value[:16])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:32]
}
func uintText(value uint64) string { return strconv.FormatUint(value, 10) }
