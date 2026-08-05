package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

var (
	errCommandNoCommit     = errors.New("SQLite command transaction requires rollback")
	errCommandClockSuspect = errors.New("SQLite authority clock is suspect")
)

const backwardClockToleranceMicros int64 = 1_000_000

type lockedCommandState struct {
	spec       application.CommandSpec
	stream     commandStream
	states     []application.IdentityState
	ceremonies []domain.CeremonyChallenge
	resolution application.ReceiptResolution
	evidence   application.AppliedGuardEvidence
	time       application.CommandTimeEvidence
}

type commandStream struct {
	nextEvent           uint64
	head                domain.StreamDigest
	nextAudit           uint64
	auditHead           application.Digest
	timeFloor           int64
	clockStatus         string
	observedClockStatus string
}

// ExecuteCommand implements the production command transaction. The callback
// runs only after receipt identity, authority state, aggregate revisions, and
// ceremonies have been resolved under the store's immediate write lock.
func (store *Store) ExecuteCommand(
	ctx context.Context,
	spec application.CommandSpec,
	decide func(application.CommandContext) (application.CommandDecision, error),
) (execution application.CommandTransactionExecution, executionErr error) {
	if decide == nil || spec.CommandID().IsZero() {
		return application.CommandTransactionExecution{}, application.ErrInvalidCommandSpec
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			execution = application.CommandTransactionExecution{}
			executionErr = fmt.Errorf("SQLite command callback panic: %v", recovered)
		}
	}()
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		locked, state, err := store.lockCommandContext(ctx, tx, spec)
		if errors.Is(err, errCommandClockSuspect) {
			if markErr := markCommandClockSuspect(ctx, tx, state); markErr != nil {
				return markErr
			}
			executionErr = commandClockSuspectError()
			return nil
		}
		if err != nil {
			return fmt.Errorf("lock SQLite command context: %w", err)
		}
		decision, err := decide(locked)
		if err != nil {
			return fmt.Errorf("decide SQLite command: %w", err)
		}
		if err := application.ValidateCommandDecision(locked, decision); err != nil {
			return fmt.Errorf("validate SQLite command decision: %w", err)
		}
		execution, err = store.applyCommandDecision(ctx, tx, state, decision)
		if err != nil {
			return fmt.Errorf("apply SQLite command decision: %w", err)
		}
		if decision.Kind() == application.CommandDecisionReplay || decision.Kind() == application.CommandDecisionRollback {
			return errCommandNoCommit
		}
		return nil
	})
	if errors.Is(err, errCommandNoCommit) {
		return execution, nil
	}
	if errors.Is(err, ErrCommitIndeterminate) {
		return application.IndeterminateCommandTransactionExecution(spec)
	}
	if err != nil {
		return application.CommandTransactionExecution{}, err
	}
	if executionErr != nil {
		return application.CommandTransactionExecution{}, executionErr
	}
	return execution, nil
}

func (store *Store) lockCommandContext(
	ctx context.Context,
	tx *sql.Tx,
	spec application.CommandSpec,
) (application.CommandContext, lockedCommandState, error) {
	state := lockedCommandState{spec: spec}
	resolution, err := store.resolveReceipt(ctx, tx, spec)
	if err != nil {
		return application.CommandContext{}, state, err
	}
	state.resolution = resolution

	stream, streamErr := lockCommandStream(ctx, tx, spec)
	if streamErr != nil {
		return application.CommandContext{}, state, streamErr
	}
	state.stream = stream

	guards := spec.Guards()
	evidence, err := application.NewAppliedGuardEvidence(guards, guards.Evidence())
	if err != nil {
		return application.CommandContext{}, state, err
	}
	state.evidence = evidence

	if resolution.Kind() == application.ReceiptAdmitted {
		if err := verifyAdmissionGuard(ctx, tx, spec); err != nil {
			return application.CommandContext{}, state, err
		}
		state.states, state.ceremonies, err = loadCommandReadSet(ctx, tx, spec, true)
		if err != nil {
			return application.CommandContext{}, state, err
		}
	} else {
		if resolution.Kind() == application.ReceiptExactReplay {
			if err := verifyCurrentAdmission(ctx, tx, spec); err != nil {
				return application.CommandContext{}, state, err
			}
			state.states, _, err = loadCommandReadSet(ctx, tx, spec, false)
			if err != nil {
				return application.CommandContext{}, state, err
			}
		}
	}
	var wallMicros int64
	if err := tx.QueryRowContext(ctx, "SELECT CAST(unixepoch('subsec') * 1000000 AS INTEGER)").Scan(&wallMicros); err != nil {
		return application.CommandContext{}, state, fmt.Errorf("read SQLite command authority time: %w", err)
	}
	if resolution.Kind() == application.ReceiptAdmitted {
		regression := stream.timeFloor - wallMicros
		if regression > backwardClockToleranceMicros {
			state.stream.clockStatus = "clock_suspect"
			if spec.AuthorityTimeClass() != application.AuthorityTimeOrdinary {
				return application.CommandContext{}, state, errCommandClockSuspect
			}
		} else if stream.clockStatus == "clock_suspect" {
			if wallMicros < stream.timeFloor {
				if spec.AuthorityTimeClass() != application.AuthorityTimeOrdinary {
					return application.CommandContext{}, state, errCommandClockSuspect
				}
			} else {
				state.stream.clockStatus = "normal"
			}
		}
		if wallMicros <= stream.timeFloor {
			wallMicros = stream.timeFloor + 1
		}
		state.time, err = application.PersistedCommandAuthorityTime(microsTime(wallMicros))
	} else {
		state.time, err = application.ReadOnlyDisclosureTime(microsTime(wallMicros), microsTime(stream.timeFloor))
	}
	if err != nil {
		return application.CommandContext{}, state, err
	}
	if len(state.ceremonies) != 0 {
		locked, contextErr := application.NewCommandContextWithStandaloneCeremonies(
			spec, state.time, state.states, state.ceremonies, resolution, evidence,
		)
		return locked, state, contextErr
	}
	locked, err := application.NewCommandContext(spec, state.time, state.states, resolution, evidence)
	return locked, state, err
}

func lockCommandStream(ctx context.Context, tx *sql.Tx, spec application.CommandSpec) (commandStream, error) {
	var state commandStream
	var nextEvent, nextAudit int64
	var head, auditHead []byte
	var authorityID string
	err := tx.QueryRowContext(ctx, `SELECT authority_id, next_sequence, head_digest, next_audit_sequence,
		audit_head_hash, authority_time_floor_us, clock_status FROM authority_streams
		WHERE scope_kind = ? AND scope_id = ? AND authority_epoch = ?`,
		string(spec.Scope().Kind()), spec.Scope().ID(), spec.RequestedEpoch().String(),
	).Scan(&authorityID, &nextEvent, &head, &nextAudit, &auditHead, &state.timeFloor, &state.clockStatus)
	state.observedClockStatus = state.clockStatus
	if errors.Is(err, sql.ErrNoRows) && spec.CommandOperation() == application.CommandCreateWorkspace {
		// Workspace creation allocates its stream in the same transaction. The
		// installation admission guard is still verified separately.
		genesis, genesisErr := commandStreamGenesis(spec)
		if genesisErr != nil {
			return state, genesisErr
		}
		state.nextEvent, state.nextAudit = 1, 1
		state.head = genesis
		state.timeFloor = 1
		state.clockStatus = "normal"
		state.observedClockStatus = "normal"
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("lock SQLite command stream: %w", err)
	}
	if authorityID != spec.AuthorityID().String() || nextEvent <= 0 || nextAudit <= 0 ||
		len(head) != sha256.Size || len(auditHead) != sha256.Size ||
		(state.clockStatus != "normal" && state.clockStatus != "clock_suspect") {
		return state, application.ErrInvalidCommandContext
	}
	state.nextEvent, state.nextAudit = uint64(nextEvent), uint64(nextAudit)
	var headArray [sha256.Size]byte
	copy(headArray[:], head)
	state.head, err = domain.NewStreamDigest(headArray)
	if err != nil {
		return state, err
	}
	copy(state.auditHead[:], auditHead)
	return state, nil
}

func commandStreamGenesis(spec application.CommandSpec) (domain.StreamDigest, error) {
	authority, err := application.NewCanonicalIdentifier(spec.AuthorityID().String())
	if err != nil {
		return domain.StreamDigest{}, err
	}
	epoch, err := application.NewCanonicalIdentifier(spec.RequestedEpoch().String())
	if err != nil {
		return domain.StreamDigest{}, err
	}
	scopeID, err := application.NewCanonicalIdentifier(spec.Scope().ID())
	if err != nil {
		return domain.StreamDigest{}, err
	}
	kind := application.StreamScopeInstallation
	if spec.Scope().Kind() == domain.ScopeKindWorkspace {
		kind = application.StreamScopeWorkspace
	}
	view, err := application.NewStreamGenesisViewV1(authority, epoch, kind, scopeID, nil)
	if err != nil {
		return domain.StreamDigest{}, err
	}
	return application.NewProductionCanonicalCodec().HashStreamGenesis(view)
}

func verifyAdmissionGuard(ctx context.Context, tx *sql.Tx, spec application.CommandSpec) error {
	if err := verifyCurrentAdmission(ctx, tx, spec); err != nil {
		return err
	}
	plan := spec.Guards()
	if genesis, present := plan.GenesisAbsence(); present {
		var guardCount, streamCount int
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM scope_guards WHERE scope_kind = ? AND scope_id = ?),
			(SELECT count(*) FROM authority_streams WHERE scope_kind = ? AND scope_id = ? AND authority_epoch = ?)`,
			string(genesis.Scope().Kind()), genesis.Scope().ID(), string(genesis.Scope().Kind()), genesis.Scope().ID(),
			genesis.AuthorityEpoch().String()).Scan(&guardCount, &streamCount); err != nil {
			return fmt.Errorf("verify SQLite workspace genesis: %w", err)
		} else if guardCount != 0 || streamCount != 0 {
			return commandReferenceConflict("workspace genesis is no longer absent")
		}
	}
	return nil
}

func verifyCurrentAdmission(ctx context.Context, tx *sql.Tx, spec application.CommandSpec) error {
	plan := spec.Guards()
	var authority, epoch, writeStatus string
	var generation uint64
	err := tx.QueryRowContext(ctx, `SELECT authority_id, authority_epoch, write_status, guard_generation FROM scope_guards
		WHERE scope_kind = ? AND scope_id = ?`, string(plan.AdmissionScope().Kind()), plan.AdmissionScope().ID(),
	).Scan(&authority, &epoch, &writeStatus, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return commandReferenceConflict("command admission is absent")
	}
	if err != nil {
		return fmt.Errorf("verify SQLite command admission: %w", err)
	}
	if authority != spec.AuthorityID().String() || epoch != spec.RequestedEpoch().String() ||
		writeStatus != "open" || generation != plan.AdmissionGeneration().Uint64() {
		return commandReferenceConflict("command admission changed")
	}
	return nil
}

func (store *Store) resolveReceipt(ctx context.Context, tx *sql.Tx, spec application.CommandSpec) (application.ReceiptResolution, error) {
	primary, primaryFound, err := queryReceiptHeader(ctx, tx, "command_id = ?", spec.CommandID().String())
	if err != nil {
		return application.ReceiptResolution{}, err
	}
	predicate, args := receiptIdentityPredicate(spec.ReceiptIdentity())
	secondary, secondaryFound, err := queryReceiptHeader(ctx, tx, predicate, args...)
	if err != nil {
		return application.ReceiptResolution{}, err
	}
	if primaryFound && secondaryFound && primary.receiptID != secondary.receiptID {
		return application.ConflictReceipt(application.ReceiptIntegrityConflict, domain.ReceiptID{})
	}
	if primaryFound {
		if primary.requestFingerprint != spec.RequestFingerprint() || primary.identity != spec.ReceiptIdentity() {
			return application.ConflictReceipt(application.ReceiptCommandIDConflict, primary.receiptID)
		}
		receipt, loadErr := store.rehydrateReceipt(ctx, tx, spec, primary)
		if loadErr != nil {
			return application.ReceiptResolution{}, loadErr
		}
		return application.ReplayReceipt(receipt)
	}
	if !secondaryFound {
		return application.AdmitReceipt(), nil
	}
	if secondary.requestFingerprint == spec.RequestFingerprint() {
		receipt, loadErr := store.rehydrateReceipt(ctx, tx, spec, secondary)
		if loadErr != nil {
			return application.ReceiptResolution{}, loadErr
		}
		return application.ReplayReceipt(receipt)
	}
	return application.ConflictReceipt(application.ReceiptIdempotencyConflict, secondary.receiptID)
}

type receiptHeader struct {
	receiptID          domain.ReceiptID
	commandID          domain.CommandID
	identity           application.ReceiptIdentity
	requestFingerprint domain.CommandFingerprint
	authorityID        domain.AuthorityID
	epoch              domain.AuthorityEpoch
	resultDigest       application.Digest
	resultCanonical    []byte
	first, last        uint64
	finalDigest        domain.StreamDigest
	guardDigest        domain.AuthorizationDigest
	capsuleCanonical   []byte
	capsuleDigest      application.Digest
	capsuleKey         string
	capsulePublicKey   []byte
	committedAt        time.Time
	operationMajor     uint16
}

func queryReceiptHeader(ctx context.Context, tx *sql.Tx, predicate string, args ...any) (receiptHeader, bool, error) {
	query := `SELECT receipt_id, command_id, identity_kind, scope_kind, scope_id, workspace_id, installation_id,
		principal_id, client_instance_id, transcript_fingerprint, operation, operation_major, idempotency_key,
		request_fingerprint, authority_id, authority_epoch, result_digest, result_canonical,
		first_event_sequence, last_event_sequence, final_stream_digest, guard_digest,
		recovery_capsule_canonical, recovery_capsule_digest, recovery_capsule_key_id,
		recovery_capsule_public_key, committed_at_us FROM command_receipts WHERE ` + predicate
	var raw struct {
		receiptID, commandID, kind, scopeKind, scopeID, operation, key               string
		workspace, installation, principal, client, capsuleKey                       sql.NullString
		transcript, request, resultDigest, resultCanonical, finalDigest, guardDigest []byte
		capsuleCanonical, capsuleDigest, capsulePublic                               []byte
		first, last                                                                  sql.NullInt64
		operationMajor                                                               uint16
		authority, epoch                                                             string
		committed                                                                    int64
	}
	err := tx.QueryRowContext(ctx, query, args...).Scan(
		&raw.receiptID, &raw.commandID, &raw.kind, &raw.scopeKind, &raw.scopeID, &raw.workspace,
		&raw.installation, &raw.principal, &raw.client, &raw.transcript, &raw.operation, &raw.operationMajor, &raw.key,
		&raw.request, &raw.authority, &raw.epoch, &raw.resultDigest, &raw.resultCanonical,
		&raw.first, &raw.last, &raw.finalDigest, &raw.guardDigest, &raw.capsuleCanonical,
		&raw.capsuleDigest, &raw.capsuleKey, &raw.capsulePublic, &raw.committed,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return receiptHeader{}, false, nil
	}
	if err != nil {
		return receiptHeader{}, false, err
	}
	header, err := decodeReceiptHeader(raw.receiptID, raw.commandID, raw.kind, raw.scopeKind, raw.scopeID, raw.workspace,
		raw.installation, raw.principal, raw.client, raw.transcript, raw.operation, raw.operationMajor, raw.key, raw.request,
		raw.authority, raw.epoch, raw.resultDigest, raw.resultCanonical, raw.first, raw.last, raw.finalDigest,
		raw.guardDigest, raw.capsuleCanonical, raw.capsuleDigest, raw.capsuleKey, raw.capsulePublic, raw.committed)
	return header, true, err
}

func decodeReceiptHeader(receiptText, commandText, kind, scopeKind, scopeID string, workspace, installation, principal,
	client sql.NullString, transcript []byte, operationText string, operationMajor uint16, keyText string, request []byte, authorityText,
	epochText string, resultDigest, resultCanonical []byte, first, last sql.NullInt64, finalDigest,
	guardDigest, capsuleCanonical, capsuleDigest []byte, capsuleKey sql.NullString, capsulePublic []byte,
	committed int64) (receiptHeader, error) {
	var header receiptHeader
	var err error
	header.receiptID, err = domain.ParseReceiptID(receiptText)
	if err != nil {
		return header, err
	}
	header.commandID, err = domain.ParseCommandID(commandText)
	if err != nil {
		return header, err
	}
	header.authorityID, err = domain.ParseAuthorityID(authorityText)
	if err != nil {
		return header, err
	}
	header.epoch, err = domain.ParseAuthorityEpoch(epochText)
	if err != nil {
		return header, err
	}
	operation, err := domain.NewOperationName(operationText)
	if err != nil {
		return header, err
	}
	key, err := domain.NewIdempotencyKey(keyText)
	if err != nil {
		return header, err
	}
	switch application.ReceiptIdentityKind(kind) {
	case application.ReceiptIdentityOrdinary:
		wid, e := domain.ParseWorkspaceID(workspace.String)
		if e != nil {
			return header, e
		}
		pid, e := domain.ParsePrincipalID(principal.String)
		if e != nil {
			return header, e
		}
		cid, e := domain.ParseClientInstanceID(client.String)
		if e != nil {
			return header, e
		}
		scope, e := domain.NewIdempotencyScope(wid, pid, cid, operation, key)
		if e != nil {
			return header, e
		}
		header.identity, err = application.OrdinaryReceiptIdentity(scope)
	case application.ReceiptIdentityProvisioning:
		iid, e := domain.ParseInstallationID(installation.String)
		if e != nil {
			return header, e
		}
		copy(header.requestFingerprint[:], request)
		var fingerprint domain.CommandFingerprint
		copy(fingerprint[:], transcript)
		authorityScope, e := domain.InstallationScope(iid)
		if e != nil {
			return header, e
		}
		scope, e := domain.NewProvisioningIdempotencyScope(authorityScope, fingerprint, operation, key)
		if e != nil {
			return header, e
		}
		header.identity, err = application.ProvisioningReceiptIdentity(scope)
	case application.ReceiptIdentityInstallationAdmin:
		iid, e := domain.ParseInstallationID(installation.String)
		if e != nil {
			return header, e
		}
		pid, e := domain.ParsePrincipalID(principal.String)
		if e != nil {
			return header, e
		}
		cid, e := domain.ParseClientInstanceID(client.String)
		if e != nil {
			return header, e
		}
		header.identity, err = application.InstallationAdminReceiptIdentity(iid, pid, cid, operation, key)
	default:
		err = application.ErrInvalidReceiptIdentity
	}
	if err != nil || len(request) != sha256.Size || len(resultDigest) != sha256.Size ||
		!first.Valid || !last.Valid || first.Int64 <= 0 || last.Int64 < first.Int64 ||
		len(finalDigest) != sha256.Size || len(guardDigest) != sha256.Size || committed <= 0 ||
		string(header.identity.Scope().Kind()) != scopeKind || header.identity.Scope().ID() != scopeID {
		return header, application.ErrInvalidApplicationContract
	}
	copy(header.requestFingerprint[:], request)
	copy(header.resultDigest[:], resultDigest)
	var finalArray, guardArray [sha256.Size]byte
	copy(finalArray[:], finalDigest)
	copy(guardArray[:], guardDigest)
	header.finalDigest, err = domain.NewStreamDigest(finalArray)
	if err != nil {
		return header, err
	}
	header.guardDigest, err = domain.NewAuthorizationDigest(guardArray)
	if err != nil {
		return header, err
	}
	header.resultCanonical = append([]byte(nil), resultCanonical...)
	header.first, header.last, header.committedAt = uint64(first.Int64), uint64(last.Int64), microsTime(committed)
	header.operationMajor = operationMajor
	if capsuleKey.Valid {
		if len(capsuleDigest) != sha256.Size || len(capsulePublic) != 32 || len(capsuleCanonical) == 0 {
			return header, application.ErrInvalidApplicationContract
		}
		copy(header.capsuleDigest[:], capsuleDigest)
		header.capsuleCanonical = append([]byte(nil), capsuleCanonical...)
		header.capsuleKey, header.capsulePublicKey = capsuleKey.String, append([]byte(nil), capsulePublic...)
	}
	return header, nil
}

func receiptIdentityPredicate(identity application.ReceiptIdentity) (string, []any) {
	switch identity.Kind() {
	case application.ReceiptIdentityOrdinary:
		return `identity_kind = 'ordinary_workspace' AND workspace_id = ? AND principal_id = ? AND client_instance_id = ? AND operation = ? AND idempotency_key = ?`,
			[]any{identity.WorkspaceID().String(), identity.PrincipalID().String(), identity.ClientInstanceID().String(), identity.Operation().String(), identity.Key().String()}
	case application.ReceiptIdentityProvisioning:
		fingerprint := identity.TranscriptFingerprint()
		return `identity_kind = 'installation_provisioning' AND installation_id = ? AND transcript_fingerprint = ? AND operation = ? AND idempotency_key = ?`,
			[]any{identity.InstallationID().String(), fingerprint[:], identity.Operation().String(), identity.Key().String()}
	default:
		return `identity_kind = 'installation_admin' AND installation_id = ? AND principal_id = ? AND client_instance_id = ? AND operation = ? AND idempotency_key = ?`,
			[]any{identity.InstallationID().String(), identity.PrincipalID().String(), identity.ClientInstanceID().String(), identity.Operation().String(), identity.Key().String()}
	}
}

func (store *Store) rehydrateReceipt(ctx context.Context, tx *sql.Tx, spec application.CommandSpec, header receiptHeader) (application.ReceiptSnapshot, error) {
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
		if resource.Kind() == domain.AggregateKindActorSession {
			state, loadErr := loadIdentityState(ctx, tx, resource.Target())
			if loadErr != nil {
				return application.ReceiptSnapshot{}, loadErr
			}
			session := state.Value().(domain.ActorSessionState)
			binding := session.Binding()
			sessionBinding, sessionClient, presentation = &binding, session.ClientInstanceID(), session.PresentationCredential()
		}
	}
	binding, err := application.NewReceiptResultReplayBinding(spec, application.ReceiptResultReplayBindingParams{
		OriginalCommandID: header.commandID, AcceptedAuthorityID: header.authorityID,
		AcceptedAuthorityEpoch: header.epoch, AcceptedAt: header.committedAt, GuardDigest: header.guardDigest,
		Resources: resources, IssuedCeremonies: ceremonies, EventIDs: eventIDs, Events: events,
		FinalStreamDigest: header.finalDigest, SessionBinding: sessionBinding, SessionClient: sessionClient,
		PresentationCredential: presentation, RecoveryCapsulePlan: plan,
	})
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
		document, verifyErr := codec.VerifyRecoveryCapsule(header.capsuleCanonical, header.capsuleDigest, result, binding)
		if verifyErr != nil {
			return application.ReceiptSnapshot{}, verifyErr
		}
		value, draftErr := application.NewRecoveryCapsuleDraft(result, document, header.capsuleKey)
		if draftErr != nil {
			return application.ReceiptSnapshot{}, draftErr
		}
		draft = &value
	}
	eventCursor, err := commandEventCursor(header.identity.Scope(), header.epoch, last, header.finalDigest)
	if err != nil {
		return application.ReceiptSnapshot{}, err
	}
	return application.NewReceiptSnapshot(application.ReceiptSnapshotParams{
		ReceiptID: header.receiptID, CommandID: header.commandID, Identity: header.identity,
		RequestFingerprint: header.requestFingerprint, Result: result, AuthorityID: header.authorityID,
		AuthorityEpoch: header.epoch, GuardDigest: header.guardDigest, Events: events, EventCursor: eventCursor,
		CapsuleRequirement: plan.Requirement(), RecoveryCapsule: draft,
	})
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

func (store *Store) applyCommandDecision(ctx context.Context, tx *sql.Tx, state lockedCommandState, decision application.CommandDecision) (application.CommandTransactionExecution, error) {
	switch decision.Kind() {
	case application.CommandDecisionReplay:
		receipt, disclosure, full := decision.Replay()
		if !full {
			applied, ok := decision.AppliedOnlyReplay()
			if !ok {
				return application.CommandTransactionExecution{}, application.ErrInvalidCommandDecision
			}
			return application.ReplayedCommandTransactionExecution(receiptForAppliedOnly(state.resolution), disclosureFromAppliedOnly(applied))
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

// Applied-only replay still carries the verified receipt inside the locked
// resolution; the execution constructor derives the redacted public shape.
func receiptForAppliedOnly(resolution application.ReceiptResolution) application.ReceiptSnapshot {
	receipt, _ := resolution.Receipt()
	return receipt
}
func disclosureFromAppliedOnly(application.AppliedOnlyReceipt) application.ReplayDisclosure {
	return application.ReplayDiscloseAppliedOnly
}

func (store *Store) commitAppliedCommand(ctx context.Context, tx *sql.Tx, state lockedCommandState, decision application.CommandDecision) (application.CommandTransactionExecution, error) {
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
		params := domain.EventEnvelopeParams{EventID: intent.EventID(), CommandID: spec.CommandID(), AuthorityID: spec.AuthorityID(),
			AuthorityEpoch: spec.RequestedEpoch(), Scope: spec.Scope(), StreamPosition: position, PreviousStreamDigest: previous,
			Aggregate: intent.Fact().Origin(), EventIndex: uint16(index), EventType: intent.Fact().Type(), SchemaVersion: schemaVersion,
			Payload: payload, PrincipalID: spec.Authorship().PrincipalID(), AuthorizationDigest: state.evidence.Digest(),
			CommandReceiptID: spec.ReceiptID(), CorrelationID: spec.CorrelationID(), RecordedAt: state.time.Value()}
		if attribution, present := spec.Authorship().ActorAttribution(); present {
			actorSession := attribution.ActorSessionID()
			params.ActorSessionID = &actorSession
		}
		if causation, present := spec.CausationEventID(); present {
			params.CausationEventID = &causation
		}
		events[index], err = codec.MaterializeIdentityEvent(params)
		if err != nil {
			return application.CommandTransactionExecution{}, err
		}
		previous = events[index].StreamDigest()
	}
	first := events[0].StreamPosition()
	last := events[len(events)-1].StreamPosition()
	eventRange, err := application.NewEventRange(first, last, uint16(len(events)))
	if err != nil {
		return application.CommandTransactionExecution{}, err
	}
	result, err := codec.MaterializeReceiptResult(decision.ResultPlan(), first, last, previous)
	if err != nil {
		return application.CommandTransactionExecution{}, fmt.Errorf("materialize SQLite command receipt: %w", err)
	}
	var capsule *application.RecoveryCapsuleDraft
	if spec.RecoveryCapsule().Requirement() == application.RecoveryCapsuleRequired {
		document, documentErr := codec.MaterializeRecoveryCapsule(decision.ResultPlan(), result)
		if documentErr != nil {
			return application.CommandTransactionExecution{}, documentErr
		}
		draft, draftErr := application.NewRecoveryCapsuleDraft(result, document, spec.RecoveryCapsule().KeyID())
		if draftErr != nil {
			return application.CommandTransactionExecution{}, draftErr
		}
		capsule = &draft
	}
	eventCursor, err := commandEventCursor(spec.Scope(), spec.RequestedEpoch(), last, previous)
	if err != nil {
		return application.CommandTransactionExecution{}, err
	}
	receipt, err := application.NewReceiptSnapshot(application.ReceiptSnapshotParams{ReceiptID: spec.ReceiptID(), CommandID: spec.CommandID(), Identity: spec.ReceiptIdentity(),
		RequestFingerprint: spec.RequestFingerprint(), Result: result, AuthorityID: spec.AuthorityID(), AuthorityEpoch: spec.RequestedEpoch(),
		GuardDigest: state.evidence.Digest(), Events: eventRange, EventCursor: eventCursor,
		CapsuleRequirement: spec.RecoveryCapsule().Requirement(), RecoveryCapsule: capsule})
	if err != nil {
		return application.CommandTransactionExecution{}, fmt.Errorf("construct SQLite command receipt: %w", err)
	}
	if err := insertCommandReceipt(ctx, tx, receipt, decision.ResultPlan(), previous, state.time.Value()); err != nil {
		return application.CommandTransactionExecution{}, fmt.Errorf("insert SQLite command receipt: %w", err)
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
		return application.CommandTransactionExecution{}, fmt.Errorf("verify final SQLite command state: %w", err)
	}
	if err := advanceCommandStream(ctx, tx, state, previous, uint64(len(events))); err != nil {
		return application.CommandTransactionExecution{}, err
	}
	return application.CommittedCommandTransactionExecution(receipt)
}

func createWorkspaceAuthority(ctx context.Context, tx *sql.Tx, state lockedCommandState) error {
	spec := state.spec
	head := state.stream.head.Bytes()
	now := timeMicros(state.time.Value())
	if _, err := tx.ExecContext(ctx, `INSERT INTO scope_guards(scope_kind, scope_id, authority_id, authority_epoch,
		write_status, guard_generation, updated_at_us) VALUES ('workspace', ?, ?, ?, 'open', ?, ?)`, spec.Scope().ID(),
		spec.AuthorityID().String(), spec.RequestedEpoch().String(), spec.Guards().AdmissionGeneration().Uint64(), now); err != nil {
		return fmt.Errorf("create SQLite workspace guard: %w", err)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO authority_streams(scope_kind, scope_id, authority_id, authority_epoch,
		next_sequence, retained_from_sequence, digest_algorithm, head_digest, next_audit_sequence, audit_head_hash, authority_time_floor_us, clock_status)
		VALUES ('workspace', ?, ?, ?, 1, 1, 'sha-256', ?, 1, zeroblob(32), 1, 'normal')`, spec.Scope().ID(), spec.AuthorityID().String(), spec.RequestedEpoch().String(), head[:])
	return err
}

func applyCeremonyTransition(ctx context.Context, tx *sql.Tx, transition application.CeremonyTransition, now int64) error {
	challenge := transition.Challenge()
	proof := challenge.ProofDigest()
	scopeKind, scopeID := domain.ScopeKindWorkspace, challenge.WorkspaceID().String()
	if !challenge.InstallationID().IsZero() {
		scopeKind, scopeID = domain.ScopeKindInstallation, challenge.InstallationID().String()
	}
	var installation, workspace, membership, actor, delegation, device any
	if !challenge.InstallationID().IsZero() {
		installation = challenge.InstallationID().String()
	}
	if !challenge.WorkspaceID().IsZero() {
		workspace = challenge.WorkspaceID().String()
	}
	if !challenge.MembershipID().IsZero() {
		membership = challenge.MembershipID().String()
	}
	if !challenge.ActorID().IsZero() {
		actor = challenge.ActorID().String()
	}
	if !challenge.DelegationID().IsZero() {
		delegation = challenge.DelegationID().String()
	}
	if !challenge.DeviceID().IsZero() {
		device = challenge.DeviceID().String()
	}
	if transition.Kind() == application.CeremonyReserveAbsent {
		_, err := tx.ExecContext(ctx, `INSERT INTO ceremony_challenges(ceremony_id, scope_kind, scope_id, purpose,
			proof_fingerprint, installation_id, workspace_id, principal_id, membership_id, actor_id, delegation_id,
			device_id, status, expires_at_us, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, 1)`,
			challenge.ID().String(), string(scopeKind), scopeID, string(challenge.Purpose()), proof[:], installation, workspace,
			challenge.PrincipalID().String(), membership, actor, delegation, device, timeMicros(challenge.ExpiresAt()))
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE ceremony_challenges SET status = 'consumed', consumed_at_us = ?, version = 2
		WHERE ceremony_id = ? AND purpose = ? AND proof_fingerprint = ? AND status = 'pending' AND version = 1`, now,
		challenge.ID().String(), string(challenge.Purpose()), proof[:])
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read SQLite ceremony CAS result: %w", err)
	}
	if affected != 1 {
		return commandReferenceConflict("ceremony changed")
	}
	return nil
}

func writeIdentityState(ctx context.Context, tx *sql.Tx, state application.IdentityState, now time.Time) error {
	current := state.Version().Uint64()
	prior := current - 1
	timestamp := timeMicros(now)
	var result sql.Result
	var err error
	switch value := state.Value().(type) {
	case domain.InstallationInvitationState:
		result, err = tx.ExecContext(ctx, `UPDATE installation_invitations SET status = ?, failed_attempts = ?, version = ?, updated_at_us = ?
			WHERE invitation_id = ? AND version = ?`, string(value.Status()), value.FailedAttempts(), current, timestamp, value.ID().String(), prior)
	case domain.PrincipalState:
		var public any
		if value.PublicKeyReference().String() != "" {
			public = value.PublicKeyReference().String()
		}
		result, err = tx.ExecContext(ctx, `INSERT INTO principals(principal_id, installation_id, kind, display_name,
			public_key_reference, status, version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			value.ID().String(), value.InstallationID().String(), string(value.Kind()), value.DisplayName().String(), public, string(value.Status()), current, timestamp, timestamp)
	case domain.DeviceState:
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
			retiringSPKIValue := retiring.SPKIFingerprint().Bytes()
			retiringTranscriptValue := retiring.TranscriptFingerprint()
			retiringSPKI, retiringTranscript, retiringExpires = retiringSPKIValue[:], retiringTranscriptValue[:], timeMicros(expires)
		}
		var rotationTranscript, rotatedAt, revokedAt any
		if fingerprint := value.RotationTranscriptFingerprint(); !fingerprint.IsZero() {
			rotationTranscript = fingerprint[:]
		}
		if !value.RotatedAt().IsZero() {
			rotatedAt = timeMicros(value.RotatedAt())
		}
		if !value.RevokedAt().IsZero() {
			revokedAt = timeMicros(value.RevokedAt())
		}
		if current == 1 {
			result, err = tx.ExecContext(ctx, `INSERT INTO device_registrations(device_id, installation_id, principal_id,
				display_name, credential_algorithm, public_key_reference, spki_fingerprint, transcript_fingerprint,
				trust_revision, revocation_revision, credential_activated_at_us, retiring_credential_algorithm,
				retiring_public_key_reference, retiring_spki_fingerprint, retiring_transcript_fingerprint,
				retiring_credential_expires_at_us, rotation_transcript_fingerprint, rotated_at_us, revoked_at_us,
				status, version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				value.ID().String(), value.InstallationID().String(), value.PrincipalID().String(), value.DisplayName().String(), algorithm,
				value.PublicKeyReference().String(), spki, transcript, value.TrustRevision().Uint64(), value.RevocationRevision().Uint64(),
				activatedAt, retiringAlgorithm, retiringKey, retiringSPKI, retiringTranscript, retiringExpires,
				rotationTranscript, rotatedAt, revokedAt, string(value.Status()), current, timestamp, timestamp)
		} else {
			result, err = tx.ExecContext(ctx, `UPDATE device_registrations SET credential_algorithm = ?, public_key_reference = ?,
				spki_fingerprint = ?, transcript_fingerprint = ?, trust_revision = ?, revocation_revision = ?,
				credential_activated_at_us = ?, retiring_credential_algorithm = ?, retiring_public_key_reference = ?,
				retiring_spki_fingerprint = ?, retiring_transcript_fingerprint = ?, retiring_credential_expires_at_us = ?,
				rotation_transcript_fingerprint = ?, rotated_at_us = ?, revoked_at_us = ?, status = ?, version = ?, updated_at_us = ?
				WHERE device_id = ? AND version = ?`,
				algorithm, value.PublicKeyReference().String(), spki, transcript, value.TrustRevision().Uint64(),
				value.RevocationRevision().Uint64(), activatedAt, retiringAlgorithm, retiringKey, retiringSPKI,
				retiringTranscript, retiringExpires, rotationTranscript, rotatedAt, revokedAt, string(value.Status()),
				current, timestamp, value.ID().String(), prior)
		}
	case domain.GrantState:
		capabilities, encodeErr := capabilitiesJSON(value.Capabilities())
		if encodeErr != nil {
			return encodeErr
		}
		var workspace any
		if !value.WorkspaceID().IsZero() {
			workspace = value.WorkspaceID().String()
		}
		result, err = tx.ExecContext(ctx, `INSERT INTO grants(grant_id, installation_id, workspace_id, principal_id,
			capabilities_json, status, version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, value.ID().String(),
			value.InstallationID().String(), workspace, value.PrincipalID().String(), string(capabilities), string(value.Status()), current, timestamp, timestamp)
	case domain.WorkspaceState:
		result, err = tx.ExecContext(ctx, `INSERT INTO workspaces(workspace_id, installation_id, home_authority_id,
			authority_epoch, alias, discovery_locator, policy_revision, status, version, created_at_us, updated_at_us)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, value.ID().String(), value.InstallationID().String(), value.AuthorityID().String(),
			value.AuthorityEpoch().String(), value.Alias().String(), value.DiscoveryLocator().String(), value.PolicyRevision().String(), string(value.Status()), current, timestamp, timestamp)
	case domain.MembershipState:
		capabilities, encodeErr := capabilitiesJSON(value.Capabilities())
		if encodeErr != nil {
			return encodeErr
		}
		if current == 1 {
			result, err = tx.ExecContext(ctx, `INSERT INTO workspace_memberships(membership_id, workspace_id,
			principal_id, capabilities_json, status, version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				value.ID().String(), value.WorkspaceID().String(), value.PrincipalID().String(), string(capabilities), string(value.Status()), current, timestamp, timestamp)
		} else {
			result, err = tx.ExecContext(ctx, `UPDATE workspace_memberships SET status = ?, version = ?, updated_at_us = ? WHERE membership_id = ? AND version = ?`, string(value.Status()), current, timestamp, value.ID().String(), prior)
		}
	case domain.ActorState:
		result, err = tx.ExecContext(ctx, `INSERT INTO actors(actor_id, workspace_id, kind, display_name, status, version,
			created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, value.ID().String(), value.WorkspaceID().String(), string(value.Kind()), value.Profile().DisplayName().String(), string(value.Status()), current, timestamp, timestamp)
	case domain.ActorDelegationState:
		capabilities, encodeErr := capabilitiesJSON(value.Capabilities())
		if encodeErr != nil {
			return encodeErr
		}
		if current == 1 {
			result, err = tx.ExecContext(ctx, `INSERT INTO actor_delegations(delegation_id, workspace_id,
			principal_id, actor_id, membership_id, capabilities_json, status, version, created_at_us, updated_at_us)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, value.ID().String(), value.WorkspaceID().String(), value.PrincipalID().String(), value.ActorID().String(), value.MembershipID().String(), string(capabilities), string(value.Status()), current, timestamp, timestamp)
		} else {
			result, err = tx.ExecContext(ctx, `UPDATE actor_delegations SET status = ?, version = ?, updated_at_us = ? WHERE delegation_id = ? AND version = ?`, string(value.Status()), current, timestamp, value.ID().String(), prior)
		}
	case domain.ActorSessionState:
		result, err = insertActorSessionState(ctx, tx, value, timestamp)
	case domain.WorkReferenceState:
		observation := value.Observation()
		if current == 1 {
			result, err = tx.ExecContext(ctx, `INSERT INTO work_references(work_reference_id, workspace_id,
				provider_namespace, provider_object_id, provider_locator, provider_version, selected_fields,
				adapter_principal_id, observed_at_us, version, created_at_us, updated_at_us)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, value.ID().String(), value.WorkspaceID().String(),
				observation.Namespace().String(), observation.ObjectID().String(), observation.Locator().String(),
				observation.ProviderVersion().String(), observation.Fields().Bytes(), observation.AdapterPrincipalID().String(),
				timeMicros(observation.ObservedAt()), current, timestamp, timestamp)
		} else {
			result, err = tx.ExecContext(ctx, `UPDATE work_references SET provider_locator = ?, provider_version = ?,
				selected_fields = ?, observed_at_us = ?, version = ?, updated_at_us = ? WHERE work_reference_id = ?
				AND provider_namespace = ? AND provider_object_id = ? AND adapter_principal_id = ? AND version = ?`,
				observation.Locator().String(), observation.ProviderVersion().String(), observation.Fields().Bytes(),
				timeMicros(observation.ObservedAt()), current, timestamp, value.ID().String(), observation.Namespace().String(),
				observation.ObjectID().String(), observation.AdapterPrincipalID().String(), prior)
		}
	case domain.ObjectiveState:
		if current == 1 {
			result, err = tx.ExecContext(ctx, `INSERT INTO objectives(objective_id, workspace_id, title,
				acceptance_criteria, status, version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				value.ID().String(), value.WorkspaceID().String(), value.Title(), value.AcceptanceCriteria(),
				string(value.Status()), current, timestamp, timestamp)
		} else {
			result, err = tx.ExecContext(ctx, `UPDATE objectives SET status = ?, version = ?, updated_at_us = ?
				WHERE objective_id = ? AND version = ?`, string(value.Status()), current, timestamp, value.ID().String(), prior)
		}
	case domain.WorkUnitState:
		result, err = tx.ExecContext(ctx, `INSERT INTO work_units(work_unit_id, workspace_id, objective_id,
			work_reference_id, title, status, version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			value.ID().String(), value.WorkspaceID().String(), value.ObjectiveID().String(), value.WorkReferenceID().String(),
			value.Title(), string(value.Status()), current, timestamp, timestamp)
	case domain.RunState:
		if current == 1 {
			result, err = tx.ExecContext(ctx, `INSERT INTO runs(run_id, workspace_id, objective_id, work_unit_id,
				operator_actor_id, status, version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				value.ID().String(), value.WorkspaceID().String(), value.ObjectiveID().String(), value.WorkUnitID().String(),
				value.OperatorID().String(), string(value.Status()), current, timestamp, timestamp)
			if err == nil {
				for ordinal, participationID := range value.RequiredParticipationIDs() {
					if _, err = tx.ExecContext(ctx, `INSERT INTO run_required_participations(
						workspace_id, run_id, participation_id, roster_ordinal) VALUES (?, ?, ?, ?)`,
						value.WorkspaceID().String(), value.ID().String(), participationID.String(), ordinal); err != nil {
						break
					}
				}
			}
		} else {
			result, err = tx.ExecContext(ctx, `UPDATE runs SET status = ?, version = ?, updated_at_us = ?
				WHERE run_id = ? AND version = ?`, string(value.Status()), current, timestamp, value.ID().String(), prior)
		}
	case domain.RunParticipationState:
		if current == 1 {
			result, err = tx.ExecContext(ctx, `INSERT INTO run_participations(participation_id, run_id, actor_id,
				role, session_id, status, version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)`,
				value.ID().String(), value.RunID().String(), value.ActorID().String(), value.Role(), string(value.Status()), current, timestamp, timestamp)
		} else {
			result, err = tx.ExecContext(ctx, `UPDATE run_participations SET session_id = ?, status = ?, version = ?,
				updated_at_us = ? WHERE participation_id = ? AND version = ?`, value.ActorSessionID().String(),
				string(value.Status()), current, timestamp, value.ID().String(), prior)
		}
	case domain.RuntimeBindingState:
		result, err = tx.ExecContext(ctx, `INSERT INTO runtime_bindings(binding_id, run_id, participation_id,
			session_id, runtime_endpoint_id, status, version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			value.ID().String(), value.RunID().String(), value.ParticipationID().String(), value.ActorSessionID().String(),
			value.RuntimeEndpointID().String(), string(value.Status()), current, timestamp, timestamp)
	default:
		return application.ErrInvalidCommandDecision
	}
	if err != nil {
		return fmt.Errorf("write SQLite %s: %w", state.Target().String(), err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read SQLite aggregate CAS result: %w", err)
	}
	if affected != 1 {
		return commandReferenceConflict("aggregate changed")
	}
	return nil
}

func insertActorSessionState(ctx context.Context, tx *sql.Tx, value domain.ActorSessionState, timestamp int64) (sql.Result, error) {
	binding := value.Binding()
	capabilities, err := capabilitiesJSON(value.Capabilities())
	if err != nil {
		return nil, err
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
	result, err := tx.ExecContext(ctx, `INSERT INTO actor_sessions(session_id, authority_id, authority_epoch, workspace_id,
		principal_id, actor_id, delegation_id, delegation_version, membership_id, membership_version, device_id,
		device_version, device_trust_revision, client_instance_id, client_name, client_version, capabilities_json,
		policy_revision, assurance_class, presentation_credential_reference, presentation_credential_digest,
		presentation_credential_audience, presentation_credential_version, status, issued_at_us, expires_at_us,
		version, created_at_us, updated_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		value.ID().String(), binding.AuthorityID().String(), binding.AuthorityEpoch().String(), binding.WorkspaceID().String(),
		binding.PrincipalID().String(), binding.ActorID().String(), delegation.ID(), delegation.Version().Uint64(), membership.ID(),
		membership.Version().Uint64(), deviceID, deviceVersion, deviceTrust, value.ClientInstanceID().String(), value.ClientMetadata().Name(),
		value.ClientMetadata().Version(), string(capabilities), binding.PolicyRevision().String(), binding.AssuranceClass().String(),
		presentation.Reference().String(), digest[:], presentation.Audience().String(), presentation.Version(), string(value.Status()),
		timeMicros(binding.IssuedAt()), timeMicros(binding.AbsoluteExpiry()), value.Version().Uint64(), timestamp, timestamp)
	if err != nil {
		return nil, err
	}
	for _, grant := range binding.GrantRevisions() {
		if _, err := tx.ExecContext(ctx, `INSERT INTO actor_session_grant_revisions(session_id, grant_id, grant_version) VALUES (?, ?, ?)`, value.ID().String(), grant.ID(), grant.Version().Uint64()); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func insertCommandReceipt(ctx context.Context, tx *sql.Tx, receipt application.ReceiptSnapshot, plan application.ReceiptResultPlan, final domain.StreamDigest, committed time.Time) error {
	identity, result, events := receipt.Identity(), receipt.Result(), receipt.Events()
	fingerprint := receipt.RequestFingerprint()
	digest := result.ResponseDigest()
	guard := receipt.GuardDigest()
	guardBytes := guard.Bytes()
	finalBytes := final.Bytes()
	var workspace, installation, principal, client any
	var transcript any
	if !identity.WorkspaceID().IsZero() {
		workspace = identity.WorkspaceID().String()
	}
	if !identity.InstallationID().IsZero() {
		installation = identity.InstallationID().String()
	}
	if !identity.PrincipalID().IsZero() {
		principal = identity.PrincipalID().String()
	}
	if !identity.ClientInstanceID().IsZero() {
		client = identity.ClientInstanceID().String()
	}
	if !identity.TranscriptFingerprint().IsZero() {
		value := identity.TranscriptFingerprint()
		transcript = value[:]
	}
	var capsuleCanonical, capsuleDigest, capsuleKey, capsulePublic any
	capsuleRequired := 0
	if capsule, present := receipt.RecoveryCapsule(); present {
		capsuleRequired = 1
		capsuleCanonical = capsule.CanonicalBytes()
		value := capsule.Digest()
		capsuleDigest = value[:]
		capsuleKey = capsule.KeyID()
		capsulePublic = plan.RecoveryCapsulePlan().Ed25519PublicKey()
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO command_receipts(receipt_id, command_id, scope_kind, scope_id, authority_id,
		authority_epoch, identity_kind, workspace_id, installation_id, principal_id, client_instance_id,
		transcript_fingerprint, operation, operation_major, idempotency_key, request_fingerprint, result_digest,
		result_canonical, first_event_sequence, last_event_sequence, final_stream_digest, guard_digest,
		capsule_required, recovery_capsule_canonical, recovery_capsule_digest, recovery_capsule_key_id,
		recovery_capsule_public_key, committed_at_us)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, receipt.ReceiptID().String(), receipt.CommandID().String(),
		string(identity.Scope().Kind()), identity.Scope().ID(), receipt.AuthorityID().String(), receipt.AuthorityEpoch().String(), string(identity.Kind()),
		workspace, installation, principal, client, transcript, identity.Operation().String(), plan.OperationMajor().Uint16(), identity.Key().String(), fingerprint[:], digest[:], result.CanonicalBytes(),
		events.First().Uint64(), events.Last().Uint64(), finalBytes[:], guardBytes[:], capsuleRequired,
		capsuleCanonical, capsuleDigest, capsuleKey, capsulePublic, timeMicros(committed))
	if err != nil {
		return fmt.Errorf("insert SQLite command receipt: %w", err)
	}
	for ordinal, resource := range plan.Resources() {
		if _, err := tx.ExecContext(ctx, `INSERT INTO command_receipt_resources(receipt_id, resource_ordinal, aggregate_kind, aggregate_id, aggregate_version) VALUES (?, ?, ?, ?, ?)`, receipt.ReceiptID().String(), ordinal, string(resource.Kind()), resource.ID(), resource.Version().Uint64()); err != nil {
			return err
		}
	}
	for ordinal, ceremony := range plan.IssuedCeremonies() {
		if _, err := tx.ExecContext(ctx, `INSERT INTO command_receipt_ceremonies(receipt_id, ceremony_ordinal, ceremony_id) VALUES (?, ?, ?)`, receipt.ReceiptID().String(), ordinal, ceremony.ID().String()); err != nil {
			return err
		}
	}
	return nil
}

func insertDomainEvent(ctx context.Context, tx *sql.Tx, event domain.EventEnvelope) error {
	previous, eventDigest, streamDigest := event.PreviousStreamDigest().Bytes(), event.EventDigest().Bytes(), event.StreamDigest().Bytes()
	authorization := event.AuthorizationDigest().Bytes()
	var actor, cause any
	if value, present := event.ActorSessionID(); present {
		actor = value.String()
	}
	if value, present := event.CausationEventID(); present {
		cause = value.String()
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO domain_events(event_id, command_id, receipt_id, authority_id, authority_epoch,
		scope_kind, scope_id, stream_sequence, previous_stream_digest, event_digest, stream_digest, aggregate_kind,
		aggregate_id, aggregate_version, event_index, event_type, event_schema, payload, principal_id, actor_session_id,
		authorization_digest, causation_event_id, correlation_id, recorded_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventID().String(), event.CommandID().String(), event.CommandReceiptID().String(), event.AuthorityID().String(), event.AuthorityEpoch().String(), string(event.Scope().Kind()), event.Scope().ID(), event.StreamPosition().Uint64(), previous[:], eventDigest[:], streamDigest[:], string(event.Aggregate().Kind()), event.Aggregate().ID(), event.Aggregate().Version().Uint64(), event.EventIndex(), string(event.EventType()), event.SchemaVersion().Uint16(), event.Payload().Bytes(), event.PrincipalID().String(), actor, authorization[:], cause, event.CorrelationID().String(), timeMicros(event.RecordedAt()))
	return err
}

func appendCommandAudit(ctx context.Context, tx *sql.Tx, state lockedCommandState, intent application.AuditIntent) error {
	view, err := application.NewAuditEntryViewV1(application.AuditEntryParams{ChainScopeID: state.spec.Scope(), Sequence: state.stream.nextAudit,
		AuthorityID: state.spec.AuthorityID(), AuthorityEpoch: state.spec.RequestedEpoch(), RecordedAt: state.time.Value(), Intent: intent, PreviousEntryHash: state.stream.auditHead})
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
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_entries(scope_kind, scope_id, audit_sequence, previous_entry_hash, entry_hash, canonical_entry, recorded_at_us) VALUES (?, ?, ?, ?, ?, ?, ?)`, string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.stream.nextAudit, state.stream.auditHead[:], digest[:], canonical, timeMicros(state.time.Value()))
	return err
}

func insertOutboxEffects(
	ctx context.Context,
	tx *sql.Tx,
	commandID domain.CommandID,
	effects application.EffectSet,
	now time.Time,
) error {
	for _, effect := range effects.Intents() {
		metadata := effect.Metadata()
		seed := []byte("blackbird.outbox-job/v1\x00" + commandID.String() + "\x00" + effect.Handler() + "\x00" +
			uintText(uint64(effect.ContractMajor().Uint16())) + "\x00" + effect.DestinationKey() + "\x00" +
			uintText(uint64(effect.Ordinal())))
		sum := sha256.Sum256(seed)
		jobID := digestUUID(sum)
		idempotency := hex.EncodeToString(sum[:])
		metadataDigest := effect.MetadataDigest()
		_, err := tx.ExecContext(ctx, `INSERT INTO outbox_jobs(job_id, command_id, event_id, handler,
			handler_contract_version, destination_key, effect_ordinal, effect_kind, idempotency_key, payload,
			metadata_digest, status, attempt_count, available_at_us, created_at_us, updated_at_us)
			VALUES (?, ?, ?, ?, ?, ?, ?, 'command_effect', ?, ?, ?, 'pending', 0, ?, ?, ?)`,
			jobID, commandID.String(), effect.CausingEventID().String(), effect.Handler(), effect.ContractMajor().Uint16(),
			effect.DestinationKey(), effect.Ordinal(), idempotency, metadata, metadataDigest[:],
			timeMicros(now), timeMicros(now), timeMicros(now))
		if err != nil {
			return err
		}
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

func commandReferenceConflict(message string) error {
	conflict, err := domain.NewConflictError(
		domain.ErrorCodeStateConflict,
		domain.ConflictReference,
		message,
		application.ErrInvalidCommandContext,
	)
	if err != nil {
		return err
	}
	return conflict
}

func commandClockSuspectError() error {
	commandErr, err := domain.NewCommandError(
		domain.ErrorCodeDependencyUnavailable,
		"authority clock is suspect",
		errCommandClockSuspect,
	)
	if err != nil {
		return err
	}
	return commandErr
}

func markCommandClockSuspect(ctx context.Context, tx *sql.Tx, state lockedCommandState) error {
	if err := verifyCurrentAdmission(ctx, tx, state.spec); err != nil {
		return err
	}
	if err := verifyDurableCommandEvidence(ctx, tx, state, nil); err != nil {
		return err
	}
	oldHead := state.stream.head.Bytes()
	result, err := tx.ExecContext(ctx, `UPDATE authority_streams SET clock_status = 'clock_suspect'
		WHERE scope_kind = ? AND scope_id = ? AND authority_id = ? AND authority_epoch = ?
		AND next_sequence = ? AND head_digest = ? AND next_audit_sequence = ? AND audit_head_hash = ?
		AND authority_time_floor_us = ? AND clock_status = ?
		AND EXISTS (SELECT 1 FROM scope_guards WHERE scope_kind = ? AND scope_id = ?
			AND authority_id = ? AND authority_epoch = ? AND write_status = 'open' AND guard_generation = ?)`,
		string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.spec.AuthorityID().String(),
		state.spec.RequestedEpoch().String(), state.stream.nextEvent, oldHead[:], state.stream.nextAudit,
		state.stream.auditHead[:], state.stream.timeFloor, state.stream.observedClockStatus,
		string(state.spec.Guards().AdmissionScope().Kind()), state.spec.Guards().AdmissionScope().ID(),
		state.spec.AuthorityID().String(), state.spec.RequestedEpoch().String(),
		state.spec.Guards().AdmissionGeneration().Uint64(),
	)
	if err != nil {
		return fmt.Errorf("mark SQLite authority clock suspect: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read SQLite clock-suspect CAS result: %w", err)
	}
	if affected != 1 {
		return commandReferenceConflict("authority clock state changed")
	}
	return nil
}

func verifyFinalCommandState(
	ctx context.Context,
	tx *sql.Tx,
	state lockedCommandState,
	decision application.CommandDecision,
) error {
	if err := verifyCurrentAdmission(ctx, tx, state.spec); err != nil {
		return err
	}
	mutated := make(map[domain.AggregateTarget]struct{}, len(decision.Writes()))
	for _, write := range decision.Writes() {
		mutated[write.Target()] = struct{}{}
		persisted, err := loadIdentityState(ctx, tx, write.Target())
		if errors.Is(err, sql.ErrNoRows) {
			return commandReferenceConflict("command mutation is absent")
		}
		if err != nil {
			return fmt.Errorf("verify SQLite command mutation: %w", err)
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
		wantStatus := "pending"
		if transition.Kind() != application.CeremonyReserveAbsent {
			wantStatus = "consumed"
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ceremony_challenges
			WHERE ceremony_id = ? AND purpose = ? AND proof_fingerprint = ? AND status = ?`,
			transition.Challenge().ID().String(), string(transition.Challenge().Purpose()), proof[:], wantStatus,
		).Scan(&count); err != nil {
			return fmt.Errorf("verify SQLite ceremony mutation: %w", err)
		}
		if count != 1 {
			return commandReferenceConflict("ceremony mutation changed")
		}
	}
	return nil
}

func verifyDurableCommandEvidence(
	ctx context.Context,
	tx *sql.Tx,
	state lockedCommandState,
	mutated map[domain.AggregateTarget]struct{},
) error {
	locked := make(map[string]application.IdentityState, len(state.states))
	for _, observed := range state.states {
		locked[observed.Target().String()] = observed
		if _, changed := mutated[observed.Target()]; changed {
			continue
		}
		current, err := loadIdentityState(ctx, tx, observed.Target())
		if errors.Is(err, sql.ErrNoRows) {
			return commandReferenceConflict("locked command reference is absent")
		}
		if err != nil {
			return fmt.Errorf("revalidate SQLite command reference: %w", err)
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
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scope_guards WHERE scope_kind = ? AND scope_id = ?
				AND authority_id = ? AND authority_epoch = ? AND write_status = 'open'`,
				guard.TargetKind(), guard.TargetID(), authority.String(), epoch.String(),
			).Scan(&count); err != nil {
				return fmt.Errorf("revalidate SQLite authority evidence: %w", err)
			}
			if count != 1 {
				return commandReferenceConflict("authority evidence changed")
			}
		case application.EvidenceBootstrapGeneration:
			generation, _ := guard.BootstrapGeneration()
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scope_guards WHERE scope_kind = ? AND scope_id = ?
				AND bootstrap_generation_id = ?`, guard.TargetKind(), guard.TargetID(), generation.String()).Scan(&count); err != nil {
				return fmt.Errorf("revalidate SQLite bootstrap evidence: %w", err)
			}
			if count != 1 {
				return commandReferenceConflict("bootstrap evidence changed")
			}
		case application.EvidencePolicyRevision, application.EvidenceLifecycleStatus,
			application.EvidenceDeviceTrustRevision:
			observed, present := locked[guard.TargetKind()+":"+guard.TargetID()]
			if !present {
				// Installation policy material has no W0 durable row. It remains
				// prepared evidence and must not be manufactured by storage.
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

func sameRunRoster(left, right application.IdentityState) bool {
	leftRun, leftIsRun := left.Value().(domain.RunState)
	rightRun, rightIsRun := right.Value().(domain.RunState)
	if !leftIsRun || !rightIsRun {
		return leftIsRun == rightIsRun
	}
	return slices.Equal(leftRun.RequiredParticipationIDs(), rightRun.RequiredParticipationIDs())
}

func advanceCommandStream(ctx context.Context, tx *sql.Tx, state lockedCommandState, final domain.StreamDigest, count uint64) error {
	oldHead, finalHead := state.stream.head.Bytes(), final.Bytes()
	result, err := tx.ExecContext(ctx, `UPDATE authority_streams SET next_sequence = next_sequence + ?, head_digest = ?,
		next_audit_sequence = next_audit_sequence + 1, audit_head_hash = (SELECT entry_hash FROM audit_entries WHERE scope_kind = ? AND scope_id = ? AND audit_sequence = ?), authority_time_floor_us = ?, clock_status = ?
		WHERE scope_kind = ? AND scope_id = ? AND authority_id = ? AND authority_epoch = ? AND next_sequence = ? AND head_digest = ?
		AND next_audit_sequence = ? AND audit_head_hash = ? AND authority_time_floor_us = ?
		AND clock_status = ?
		AND EXISTS (SELECT 1 FROM scope_guards WHERE scope_kind = ? AND scope_id = ? AND authority_id = ?
			AND authority_epoch = ? AND write_status = 'open' AND guard_generation = ?)`,
		count, finalHead[:], string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.stream.nextAudit,
		timeMicros(state.time.Value()), state.stream.clockStatus, string(state.spec.Scope().Kind()), state.spec.Scope().ID(),
		state.spec.AuthorityID().String(), state.spec.RequestedEpoch().String(), state.stream.nextEvent, oldHead[:], state.stream.nextAudit,
		state.stream.auditHead[:], state.stream.timeFloor, state.stream.observedClockStatus,
		string(state.spec.Guards().AdmissionScope().Kind()),
		state.spec.Guards().AdmissionScope().ID(), state.spec.AuthorityID().String(), state.spec.RequestedEpoch().String(),
		state.spec.Guards().AdmissionGeneration().Uint64())
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read SQLite stream CAS result: %w", err)
	}
	if affected != 1 {
		return commandReferenceConflict("command stream changed")
	}
	return nil
}

func loadReceiptResources(ctx context.Context, tx *sql.Tx, receipt domain.ReceiptID) ([]domain.AggregateRef, error) {
	rows, err := tx.QueryContext(ctx, `SELECT aggregate_kind, aggregate_id, aggregate_version FROM command_receipt_resources
		WHERE receipt_id = ? ORDER BY resource_ordinal`, receipt.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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
		value, err := domain.ParseInvitationID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindPrincipal:
		value, err := domain.ParsePrincipalID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindDevice:
		value, err := domain.ParseDeviceID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindGrant:
		value, err := domain.ParseGrantID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindWorkspace:
		value, err := domain.ParseWorkspaceID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindMembership:
		value, err := domain.ParseMembershipID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindActor:
		value, err := domain.ParseActorID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindActorDelegation:
		value, err := domain.ParseActorDelegationID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindActorSession:
		value, err := domain.ParseActorSessionID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindWorkReference:
		value, err := domain.ParseWorkReferenceID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindObjective:
		value, err := domain.ParseObjectiveID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindWorkUnit:
		value, err := domain.ParseWorkUnitID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindRun:
		value, err := domain.ParseRunID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindRunParticipation:
		value, err := domain.ParseRunParticipationID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindRuntimeBinding:
		value, err := domain.ParseRuntimeBindingID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	case domain.AggregateKindRuntimeEndpoint:
		value, err := domain.ParseRuntimeEndpointID(id)
		if err != nil {
			return domain.AggregateRef{}, err
		}
		return domain.NewAggregateRef(value, version)
	default:
		return domain.AggregateRef{}, application.ErrInvalidApplicationContract
	}
}

func loadReceiptCeremonies(ctx context.Context, tx *sql.Tx, receipt domain.ReceiptID) ([]domain.CeremonyChallenge, error) {
	rows, err := tx.QueryContext(ctx, `SELECT c.ceremony_id FROM command_receipt_ceremonies r
		JOIN ceremony_challenges c ON c.ceremony_id = r.ceremony_id WHERE r.receipt_id = ? ORDER BY r.ceremony_ordinal`, receipt.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var result []domain.CeremonyChallenge
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ceremony, err := loadCeremonyWithStatus(ctx, tx, id, domain.CeremonyPending)
		if err != nil {
			return nil, err
		}
		result = append(result, ceremony)
	}
	return result, rows.Err()
}

func loadReceiptEventIDs(ctx context.Context, tx *sql.Tx, receipt domain.ReceiptID) ([]domain.EventID, error) {
	rows, err := tx.QueryContext(ctx, `SELECT event_id FROM domain_events WHERE receipt_id = ? ORDER BY event_index`, receipt.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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

func loadCommandReadSet(ctx context.Context, tx *sql.Tx, spec application.CommandSpec, admitted bool) ([]application.IdentityState, []domain.CeremonyChallenge, error) {
	plan := spec.Guards()
	targets := make(map[domain.AggregateTarget]struct{})
	expectedVersions := make(map[domain.AggregateTarget]domain.Version)
	if admitted {
		for _, group := range [][]domain.AggregateRef{plan.Authorization(), plan.References()} {
			for _, ref := range group {
				targets[ref.Target()] = struct{}{}
				expectedVersions[ref.Target()] = ref.Version()
			}
		}
		for _, expectation := range plan.Mutations() {
			if expectation.Kind() == domain.ExpectationExpectedVersion {
				targets[expectation.Target()] = struct{}{}
				version, _ := expectation.Version()
				expectedVersions[expectation.Target()] = version
			}
		}
	} else {
		for _, target := range plan.DisclosureTargets() {
			targets[target] = struct{}{}
		}
	}
	states := make([]application.IdentityState, 0, len(targets))
	orderedTargets := make([]domain.AggregateTarget, 0, len(targets))
	for target := range targets {
		orderedTargets = append(orderedTargets, target)
	}
	slices.SortFunc(orderedTargets, func(left, right domain.AggregateTarget) int {
		return strings.Compare(left.String(), right.String())
	})
	for _, target := range orderedTargets {
		state, err := loadIdentityState(ctx, tx, target)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, commandReferenceConflict("declared command reference is absent")
		}
		if err != nil {
			return nil, nil, fmt.Errorf("load SQLite %s: %w", target.String(), err)
		}
		if expected, present := expectedVersions[target]; present && state.Version() != expected {
			return nil, nil, commandReferenceConflict("declared command reference version changed")
		}
		states = append(states, state)
	}
	if admitted {
		for _, expectation := range plan.Mutations() {
			if expectation.Kind() != domain.ExpectationMustNotExist {
				continue
			}
			present, err := identityStateExists(ctx, tx, expectation.Target())
			if err != nil {
				return nil, nil, err
			}
			if present {
				return nil, nil, commandReferenceConflict("command create target already exists")
			}
		}
		for _, claim := range plan.Ceremonies() {
			if claim.Kind() != application.CeremonyReserveAbsent {
				continue
			}
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ceremony_challenges WHERE ceremony_id = ?`, claim.ID().String()).Scan(&count); err != nil {
				return nil, nil, err
			}
			if count != 0 {
				return nil, nil, commandReferenceConflict("ceremony identifier already exists")
			}
		}
	}
	var ceremonies []domain.CeremonyChallenge
	if admitted {
		for _, claim := range plan.Ceremonies() {
			if claim.Kind() != application.CeremonyConsumeStandalone {
				continue
			}
			challenge, err := loadCeremony(ctx, tx, claim.ID().String())
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil, commandReferenceConflict("ceremony is absent")
			}
			if err != nil {
				return nil, nil, err
			}
			ceremonies = append(ceremonies, challenge)
		}
	}
	return states, ceremonies, nil
}

func identityStateExists(ctx context.Context, tx *sql.Tx, target domain.AggregateTarget) (bool, error) {
	table, column, err := stateTable(target.Kind())
	if err != nil {
		return false, err
	}
	var count int
	err = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE "+column+" = ?", target.ID()).Scan(&count)
	return count != 0, err
}

func stateTable(kind domain.AggregateKind) (string, string, error) {
	switch kind {
	case domain.AggregateKindInvitation:
		return "installation_invitations", "invitation_id", nil
	case domain.AggregateKindPrincipal:
		return "principals", "principal_id", nil
	case domain.AggregateKindDevice:
		return "device_registrations", "device_id", nil
	case domain.AggregateKindGrant:
		return "grants", "grant_id", nil
	case domain.AggregateKindWorkspace:
		return "workspaces", "workspace_id", nil
	case domain.AggregateKindMembership:
		return "workspace_memberships", "membership_id", nil
	case domain.AggregateKindActor:
		return "actors", "actor_id", nil
	case domain.AggregateKindActorDelegation:
		return "actor_delegations", "delegation_id", nil
	case domain.AggregateKindActorSession:
		return "actor_sessions", "session_id", nil
	case domain.AggregateKindWorkReference:
		return "work_references", "work_reference_id", nil
	case domain.AggregateKindObjective:
		return "objectives", "objective_id", nil
	case domain.AggregateKindWorkUnit:
		return "work_units", "work_unit_id", nil
	case domain.AggregateKindRun:
		return "runs", "run_id", nil
	case domain.AggregateKindRunParticipation:
		return "run_participations", "participation_id", nil
	case domain.AggregateKindRuntimeBinding:
		return "runtime_bindings", "binding_id", nil
	default:
		return "", "", application.ErrInvalidCommandContext
	}
}

func loadIdentityState(ctx context.Context, tx *sql.Tx, target domain.AggregateTarget) (application.IdentityState, error) {
	var value any
	var err error
	switch target.Kind() {
	case domain.AggregateKindInvitation:
		value, err = loadInvitationState(ctx, tx, target.ID())
	case domain.AggregateKindPrincipal:
		value, err = loadPrincipalState(ctx, tx, target.ID())
	case domain.AggregateKindDevice:
		value, err = loadDeviceState(ctx, tx, target.ID())
	case domain.AggregateKindGrant:
		value, err = loadGrantState(ctx, tx, target.ID())
	case domain.AggregateKindWorkspace:
		value, err = loadWorkspaceState(ctx, tx, target.ID())
	case domain.AggregateKindMembership:
		value, err = loadMembershipState(ctx, tx, target.ID())
	case domain.AggregateKindActor:
		value, err = loadActorState(ctx, tx, target.ID())
	case domain.AggregateKindActorDelegation:
		value, err = loadDelegationState(ctx, tx, target.ID())
	case domain.AggregateKindActorSession:
		value, err = loadActorSessionState(ctx, tx, target.ID())
	case domain.AggregateKindWorkReference:
		value, err = loadWorkReferenceState(ctx, tx, target.ID())
	case domain.AggregateKindObjective:
		value, err = loadObjectiveState(ctx, tx, target.ID())
	case domain.AggregateKindWorkUnit:
		value, err = loadWorkUnitState(ctx, tx, target.ID())
	case domain.AggregateKindRun:
		value, err = loadRunState(ctx, tx, target.ID())
	case domain.AggregateKindRunParticipation:
		value, err = loadRunParticipationState(ctx, tx, target.ID())
	case domain.AggregateKindRuntimeBinding:
		value, err = loadRuntimeBindingState(ctx, tx, target.ID())
	default:
		err = application.ErrInvalidCommandContext
	}
	if err != nil {
		return application.IdentityState{}, err
	}
	return application.NewIdentityState(value)
}

func loadInvitationState(ctx context.Context, tx *sql.Tx, id string) (domain.InstallationInvitationState, error) {
	var invitationID, installationID, key, generation, status string
	var verifier []byte
	var failures uint8
	var expires int64
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT invitation_id, installation_id, installation_public_key_reference,
		invitation_verifier, bootstrap_generation_id, status, failed_attempts, expires_at_us, version
		FROM installation_invitations WHERE invitation_id = ?`, id).Scan(&invitationID, &installationID, &key, &verifier, &generation, &status, &failures, &expires, &version)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	iid, err := domain.ParseInvitationID(invitationID)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	installation, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	publicKey, err := domain.NewPublicKeyReference(key)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	bootstrap, err := domain.ParseBootstrapGenerationID(generation)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	if len(verifier) != sha256.Size {
		return domain.InstallationInvitationState{}, application.ErrInvalidCommandContext
	}
	var fingerprint domain.CommandFingerprint
	copy(fingerprint[:], verifier)
	return domain.RehydrateInstallationInvitation(domain.InstallationInvitationRehydrationParams{ID: iid, InstallationID: installation,
		InstallationPublicKey: publicKey, InvitationVerifier: fingerprint, BootstrapGenerationID: bootstrap,
		ExpiresAt: microsTime(expires), FailedAttempts: failures, Status: domain.InstallationInvitationStatus(status), Version: mustVersion(version)})
}

func loadPrincipalState(ctx context.Context, tx *sql.Tx, id string) (domain.PrincipalState, error) {
	var principalID, installationID, kind, display, status string
	var public sql.NullString
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT principal_id, installation_id, kind, display_name, public_key_reference, status, version FROM principals WHERE principal_id = ?`, id).
		Scan(&principalID, &installationID, &kind, &display, &public, &status, &version)
	if err != nil {
		return domain.PrincipalState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.PrincipalState{}, err
	}
	iid, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.PrincipalState{}, err
	}
	name, err := domain.NewDisplayName(display)
	if err != nil {
		return domain.PrincipalState{}, err
	}
	var key domain.PublicKeyReference
	if public.Valid {
		key, err = domain.NewPublicKeyReference(public.String)
		if err != nil {
			return domain.PrincipalState{}, err
		}
	}
	return domain.RehydratePrincipal(domain.PrincipalRehydrationParams{ID: pid, InstallationID: iid, Kind: domain.PrincipalKind(kind), DisplayName: name, PublicKeyReference: key, Status: domain.PrincipalStatus(status), Version: mustVersion(version)})
}

func loadDeviceState(ctx context.Context, tx *sql.Tx, id string) (domain.DeviceState, error) {
	var deviceID, installationID, principalID, display, key, status string
	var algorithm, retiringAlgorithm, retiringKey sql.NullString
	var spki, transcript, retiringSPKI, retiringTranscript, rotationTranscript []byte
	var activatedAt, retiringExpires, rotatedAt, revokedAt sql.NullInt64
	var trust, revocation, version uint64
	err := tx.QueryRowContext(ctx, `SELECT device_id, installation_id, principal_id, display_name, credential_algorithm,
		public_key_reference, spki_fingerprint, transcript_fingerprint, trust_revision, revocation_revision,
		credential_activated_at_us, retiring_credential_algorithm, retiring_public_key_reference,
		retiring_spki_fingerprint, retiring_transcript_fingerprint, retiring_credential_expires_at_us,
		rotation_transcript_fingerprint, rotated_at_us, revoked_at_us, status, version
		FROM device_registrations WHERE device_id = ?`, id).Scan(&deviceID, &installationID, &principalID, &display,
		&algorithm, &key, &spki, &transcript, &trust, &revocation, &activatedAt, &retiringAlgorithm, &retiringKey,
		&retiringSPKI, &retiringTranscript, &retiringExpires, &rotationTranscript, &rotatedAt, &revokedAt, &status, &version)
	if err != nil {
		return domain.DeviceState{}, err
	}
	did, err := domain.ParseDeviceID(deviceID)
	if err != nil {
		return domain.DeviceState{}, err
	}
	iid, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.DeviceState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.DeviceState{}, err
	}
	name, err := domain.NewDisplayName(display)
	if err != nil {
		return domain.DeviceState{}, err
	}
	public, err := domain.NewPublicKeyReference(key)
	if err != nil {
		return domain.DeviceState{}, err
	}
	ceremony, ceremonyErr := loadOptionalCeremonyByOwner(ctx, tx, domain.CeremonyPurposeDevicePairing, "device_id", deviceID)
	if ceremonyErr != nil {
		return domain.DeviceState{}, ceremonyErr
	}
	credential, err := decodeDeviceCredential(algorithm, key, spki, transcript)
	if err != nil {
		return domain.DeviceState{}, err
	}
	retiring, err := decodeDeviceCredential(retiringAlgorithm, retiringKey.String, retiringSPKI, retiringTranscript)
	if err != nil {
		return domain.DeviceState{}, err
	}
	var rotationFingerprint domain.CommandFingerprint
	if len(rotationTranscript) != 0 {
		if len(rotationTranscript) != sha256.Size {
			return domain.DeviceState{}, application.ErrInvalidCommandContext
		}
		copy(rotationFingerprint[:], rotationTranscript)
	}
	return domain.RehydrateDevice(domain.DeviceRehydrationParams{ID: did, InstallationID: iid, PrincipalID: pid, DisplayName: name,
		PublicKeyReference: public, Status: domain.DeviceStatus(status), Version: mustVersion(version),
		TrustRevision: mustVersion(trust), RevocationRevision: mustVersion(revocation), PairingChallenge: ceremony,
		CredentialBinding: credential, CredentialActivatedAt: nullableMicrosTime(activatedAt), RetiringCredential: retiring,
		RetiringCredentialExpiresAt: nullableMicrosTime(retiringExpires), RotationTranscriptFingerprint: rotationFingerprint,
		RotatedAt: nullableMicrosTime(rotatedAt), RevokedAt: nullableMicrosTime(revokedAt)})
}

func decodeDeviceCredential(
	algorithm sql.NullString,
	key string,
	spki []byte,
	transcript []byte,
) (domain.DeviceCredentialBinding, error) {
	if !algorithm.Valid {
		if len(spki) != 0 || len(transcript) != 0 {
			return domain.DeviceCredentialBinding{}, application.ErrInvalidCommandContext
		}
		return domain.DeviceCredentialBinding{}, nil
	}
	if algorithm.String != domain.DeviceCredentialAlgorithm || len(spki) != sha256.Size || len(transcript) != sha256.Size {
		return domain.DeviceCredentialBinding{}, application.ErrInvalidCommandContext
	}
	public, err := domain.NewPublicKeyReference(key)
	if err != nil {
		return domain.DeviceCredentialBinding{}, err
	}
	var spkiArray [sha256.Size]byte
	copy(spkiArray[:], spki)
	digest, err := domain.NewCredentialDigest(spkiArray)
	if err != nil {
		return domain.DeviceCredentialBinding{}, err
	}
	var fingerprint domain.CommandFingerprint
	copy(fingerprint[:], transcript)
	return domain.NewDeviceCredentialBinding(public, digest, fingerprint)
}

func nullableMicrosTime(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return microsTime(value.Int64)
}

func decodeCapabilities(raw string) (domain.CapabilitySet, error) {
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return domain.CapabilitySet{}, err
	}
	capabilities := make([]domain.Capability, len(values))
	for i, text := range values {
		capability, err := domain.NewCapability(text)
		if err != nil {
			return domain.CapabilitySet{}, err
		}
		capabilities[i] = capability
	}
	return domain.NewCapabilitySet(capabilities...)
}

func loadGrantState(ctx context.Context, tx *sql.Tx, id string) (domain.GrantState, error) {
	var grantID, installationID, principalID, capabilities, status string
	var workspace sql.NullString
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT grant_id, installation_id, workspace_id, principal_id, capabilities_json, status, version FROM grants WHERE grant_id = ?`, id).
		Scan(&grantID, &installationID, &workspace, &principalID, &capabilities, &status, &version)
	if err != nil {
		return domain.GrantState{}, err
	}
	gid, err := domain.ParseGrantID(grantID)
	if err != nil {
		return domain.GrantState{}, err
	}
	iid, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.GrantState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.GrantState{}, err
	}
	var wid domain.WorkspaceID
	if workspace.Valid {
		wid, err = domain.ParseWorkspaceID(workspace.String)
		if err != nil {
			return domain.GrantState{}, err
		}
	}
	set, err := decodeCapabilities(capabilities)
	if err != nil {
		return domain.GrantState{}, err
	}
	return domain.RehydrateGrant(domain.GrantRehydrationParams{ID: gid, InstallationID: iid, WorkspaceID: wid, PrincipalID: pid, Status: domain.GrantStatus(status), Version: mustVersion(version), Capabilities: set})
}

func loadWorkspaceState(ctx context.Context, tx *sql.Tx, id string) (domain.WorkspaceState, error) {
	var workspaceID, installationID, authorityID, epoch, aliasText, discoveryText, policyText, status string
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT workspace_id, installation_id, home_authority_id, authority_epoch, alias, discovery_locator, policy_revision, status, version FROM workspaces WHERE workspace_id = ?`, id).
		Scan(&workspaceID, &installationID, &authorityID, &epoch, &aliasText, &discoveryText, &policyText, &status, &version)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	iid, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	aid, err := domain.ParseAuthorityID(authorityID)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	authorityEpoch, err := domain.ParseAuthorityEpoch(epoch)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	alias, err := domain.NewWorkspaceAlias(aliasText)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	discovery, err := domain.NewDiscoveryLocator(discoveryText)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	policy, err := domain.NewPolicyRevision(policyText)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	return domain.RehydrateWorkspace(domain.WorkspaceRehydrationParams{ID: wid, InstallationID: iid, AuthorityID: aid, AuthorityEpoch: authorityEpoch, Alias: alias, DiscoveryLocator: discovery, PolicyRevision: policy, Status: domain.WorkspaceStatus(status), Version: mustVersion(version)})
}

func loadMembershipState(ctx context.Context, tx *sql.Tx, id string) (domain.MembershipState, error) {
	var membershipID, workspaceID, principalID, capabilities, status string
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT membership_id, workspace_id, principal_id, capabilities_json, status, version FROM workspace_memberships WHERE membership_id = ?`, id).Scan(&membershipID, &workspaceID, &principalID, &capabilities, &status, &version)
	if err != nil {
		return domain.MembershipState{}, err
	}
	mid, err := domain.ParseMembershipID(membershipID)
	if err != nil {
		return domain.MembershipState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.MembershipState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.MembershipState{}, err
	}
	set, err := decodeCapabilities(capabilities)
	if err != nil {
		return domain.MembershipState{}, err
	}
	ceremony, err := loadOptionalCeremonyByOwner(ctx, tx, domain.CeremonyPurposeMembershipAcceptance, "membership_id", membershipID)
	if err != nil {
		return domain.MembershipState{}, err
	}
	return domain.RehydrateMembership(domain.MembershipRehydrationParams{ID: mid, WorkspaceID: wid, PrincipalID: pid, Status: domain.MembershipStatus(status), Version: mustVersion(version), Capabilities: set, AcceptanceChallenge: ceremony})
}

func loadActorState(ctx context.Context, tx *sql.Tx, id string) (domain.ActorState, error) {
	var actorID, workspaceID, kind, display, status string
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT actor_id, workspace_id, kind, display_name, status, version FROM actors WHERE actor_id = ?`, id).Scan(&actorID, &workspaceID, &kind, &display, &status, &version)
	if err != nil {
		return domain.ActorState{}, err
	}
	aid, err := domain.ParseActorID(actorID)
	if err != nil {
		return domain.ActorState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.ActorState{}, err
	}
	name, err := domain.NewDisplayName(display)
	if err != nil {
		return domain.ActorState{}, err
	}
	profile, err := domain.NewActorProfile(name)
	if err != nil {
		return domain.ActorState{}, err
	}
	return domain.RehydrateActor(domain.ActorRehydrationParams{ID: aid, WorkspaceID: wid, Kind: domain.ActorKind(kind), Profile: profile, Status: domain.ActorStatus(status), Version: mustVersion(version)})
}

func loadDelegationState(ctx context.Context, tx *sql.Tx, id string) (domain.ActorDelegationState, error) {
	var delegationID, workspaceID, principalID, actorID, membershipID, capabilities, status string
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT delegation_id, workspace_id, principal_id, actor_id, membership_id, capabilities_json, status, version FROM actor_delegations WHERE delegation_id = ?`, id).Scan(&delegationID, &workspaceID, &principalID, &actorID, &membershipID, &capabilities, &status, &version)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	did, err := domain.ParseActorDelegationID(delegationID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	aid, err := domain.ParseActorID(actorID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	mid, err := domain.ParseMembershipID(membershipID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	set, err := decodeCapabilities(capabilities)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	ceremony, err := loadOptionalCeremonyByOwner(ctx, tx, domain.CeremonyPurposeDelegationActivation, "delegation_id", delegationID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	return domain.RehydrateActorDelegation(domain.ActorDelegationRehydrationParams{ID: did, WorkspaceID: wid, PrincipalID: pid, ActorID: aid, MembershipID: mid, Status: domain.DelegationStatus(status), Version: mustVersion(version), Capabilities: set, ActivationChallenge: ceremony})
}

func loadActorSessionState(ctx context.Context, tx *sql.Tx, id string) (domain.ActorSessionState, error) {
	var sessionID, authorityID, epoch, workspaceID, principalID, actorID, delegationID, membershipID, clientID, clientName, clientVersion, capabilities, policyText, assuranceText, credentialRef, credentialAudience, status string
	var deviceID sql.NullString
	var delegationVersion, membershipVersion, version uint64
	var deviceVersion, deviceTrust sql.NullInt64
	var credentialDigest []byte
	var credentialVersion uint16
	var issued, expires int64
	err := tx.QueryRowContext(ctx, `SELECT session_id, authority_id, authority_epoch, workspace_id, principal_id, actor_id,
		delegation_id, delegation_version, membership_id, membership_version, device_id, device_version,
		device_trust_revision, client_instance_id, client_name, client_version, capabilities_json, policy_revision,
		assurance_class, presentation_credential_reference, presentation_credential_digest,
		presentation_credential_audience, presentation_credential_version, status, issued_at_us, expires_at_us, version
		FROM actor_sessions WHERE session_id = ?`, id).Scan(&sessionID, &authorityID, &epoch, &workspaceID, &principalID,
		&actorID, &delegationID, &delegationVersion, &membershipID, &membershipVersion, &deviceID, &deviceVersion,
		&deviceTrust, &clientID, &clientName, &clientVersion, &capabilities, &policyText, &assuranceText,
		&credentialRef, &credentialDigest, &credentialAudience, &credentialVersion, &status, &issued, &expires, &version)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	sid, err := domain.ParseActorSessionID(sessionID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	authority, err := domain.ParseAuthorityID(authorityID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	authorityEpoch, err := domain.ParseAuthorityEpoch(epoch)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	aid, err := domain.ParseActorID(actorID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	did, err := domain.ParseActorDelegationID(delegationID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	mid, err := domain.ParseMembershipID(membershipID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	delegationRef, err := domain.NewAggregateRef(did, mustVersion(delegationVersion))
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	membershipRef, err := domain.NewAggregateRef(mid, mustVersion(membershipVersion))
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	var deviceRef *domain.AggregateRef
	var trust domain.Version
	if deviceID.Valid {
		parsed, e := domain.ParseDeviceID(deviceID.String)
		if e != nil {
			return domain.ActorSessionState{}, e
		}
		ref, e := domain.NewAggregateRef(parsed, mustVersion(uint64(deviceVersion.Int64)))
		if e != nil {
			return domain.ActorSessionState{}, e
		}
		deviceRef, trust = &ref, mustVersion(uint64(deviceTrust.Int64))
	}
	grantRows, err := tx.QueryContext(ctx, `SELECT grant_id, grant_version FROM actor_session_grant_revisions WHERE session_id = ? ORDER BY grant_id`, sessionID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	var grants []domain.AggregateRef
	for grantRows.Next() {
		var grantID string
		var grantVersion uint64
		if err := grantRows.Scan(&grantID, &grantVersion); err != nil {
			_ = grantRows.Close()
			return domain.ActorSessionState{}, err
		}
		gid, e := domain.ParseGrantID(grantID)
		if e != nil {
			_ = grantRows.Close()
			return domain.ActorSessionState{}, e
		}
		ref, e := domain.NewAggregateRef(gid, mustVersion(grantVersion))
		if e != nil {
			_ = grantRows.Close()
			return domain.ActorSessionState{}, e
		}
		grants = append(grants, ref)
	}
	if err := grantRows.Close(); err != nil {
		return domain.ActorSessionState{}, err
	}
	policy, err := domain.NewPolicyRevision(policyText)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	assurance, err := domain.NewAssuranceClass(assuranceText)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	binding, err := domain.NewSessionBinding(authority, authorityEpoch, wid, pid, aid, membershipRef, delegationRef, deviceRef, trust, grants, policy, assurance, microsTime(issued), microsTime(expires))
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	cid, err := domain.ParseClientInstanceID(clientID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	metadata, err := domain.NewClientMetadata(clientName, clientVersion)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	set, err := decodeCapabilities(capabilities)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	if len(credentialDigest) != sha256.Size {
		return domain.ActorSessionState{}, application.ErrInvalidCommandContext
	}
	var digestArray [sha256.Size]byte
	copy(digestArray[:], credentialDigest)
	credentialDigestValue, err := domain.NewCredentialDigest(digestArray)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	reference, err := domain.NewCredentialReference(credentialRef)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	audience, err := domain.NewCredentialAudience(credentialAudience)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	presentation, err := domain.NewPresentationCredentialBinding(credentialDigestValue, reference, audience, credentialVersion)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	return domain.RehydrateActorSession(domain.ActorSessionRehydrationParams{ID: sid, ClientInstanceID: cid, ClientMetadata: metadata, Status: domain.ActorSessionStatus(status), Version: mustVersion(version), Binding: binding, Capabilities: set, PresentationCredential: presentation})
}

func loadWorkReferenceState(ctx context.Context, tx *sql.Tx, id string) (domain.WorkReferenceState, error) {
	var workReferenceID, workspaceID, namespace, objectID, locator, providerVersion, adapterID string
	var fields []byte
	var observedAt int64
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT work_reference_id, workspace_id, provider_namespace, provider_object_id,
		provider_locator, provider_version, selected_fields, adapter_principal_id, observed_at_us, version
		FROM work_references WHERE work_reference_id = ?`, id).Scan(&workReferenceID, &workspaceID, &namespace,
		&objectID, &locator, &providerVersion, &fields, &adapterID, &observedAt, &version)
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	wid, err := domain.ParseWorkReferenceID(workReferenceID)
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	workspace, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	adapter, err := domain.ParsePrincipalID(adapterID)
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	namespaceValue, err := domain.NewOpaqueProviderValue(namespace)
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	objectValue, err := domain.NewOpaqueProviderValue(objectID)
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	locatorValue, err := domain.NewOpaqueProviderValue(locator)
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	versionValue, err := domain.NewOpaqueProviderValue(providerVersion)
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	payload, err := domain.NewEventPayload(fields)
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	observation, err := domain.NewProviderObservation(namespaceValue, objectValue, locatorValue, versionValue, payload, adapter, microsTime(observedAt))
	if err != nil {
		return domain.WorkReferenceState{}, err
	}
	return domain.RehydrateWorkReference(domain.WorkReferenceRehydrationParams{ID: wid, WorkspaceID: workspace, Observation: observation, Version: mustVersion(version)})
}

func loadObjectiveState(ctx context.Context, tx *sql.Tx, id string) (domain.ObjectiveState, error) {
	var objectiveID, workspaceID, title, criteria, status string
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT objective_id, workspace_id, title, acceptance_criteria, status, version
		FROM objectives WHERE objective_id = ?`, id).Scan(&objectiveID, &workspaceID, &title, &criteria, &status, &version)
	if err != nil {
		return domain.ObjectiveState{}, err
	}
	oid, err := domain.ParseObjectiveID(objectiveID)
	if err != nil {
		return domain.ObjectiveState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.ObjectiveState{}, err
	}
	return domain.RehydrateObjective(domain.ObjectiveRehydrationParams{ID: oid, WorkspaceID: wid, Title: title,
		AcceptanceCriteria: criteria, Status: domain.ObjectiveStatus(status), Version: mustVersion(version)})
}

func loadWorkUnitState(ctx context.Context, tx *sql.Tx, id string) (domain.WorkUnitState, error) {
	var workUnitID, workspaceID, objectiveID, workReferenceID, title, status string
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT work_unit_id, workspace_id, objective_id, work_reference_id, title, status,
		version FROM work_units WHERE work_unit_id = ?`, id).Scan(&workUnitID, &workspaceID, &objectiveID,
		&workReferenceID, &title, &status, &version)
	if err != nil {
		return domain.WorkUnitState{}, err
	}
	wid, err := domain.ParseWorkUnitID(workUnitID)
	if err != nil {
		return domain.WorkUnitState{}, err
	}
	workspace, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.WorkUnitState{}, err
	}
	objective, err := domain.ParseObjectiveID(objectiveID)
	if err != nil {
		return domain.WorkUnitState{}, err
	}
	workReference, err := domain.ParseWorkReferenceID(workReferenceID)
	if err != nil {
		return domain.WorkUnitState{}, err
	}
	return domain.RehydrateWorkUnit(domain.WorkUnitRehydrationParams{ID: wid, WorkspaceID: workspace, ObjectiveID: objective,
		WorkReferenceID: workReference, Title: title, Status: domain.WorkUnitStatus(status), Version: mustVersion(version)})
}

func loadRunState(ctx context.Context, tx *sql.Tx, id string) (domain.RunState, error) {
	var runID, workspaceID, objectiveID, workUnitID, operatorID, status string
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT run_id, workspace_id, objective_id, work_unit_id, operator_actor_id, status,
		version FROM runs WHERE run_id = ?`, id).Scan(&runID, &workspaceID, &objectiveID, &workUnitID, &operatorID, &status, &version)
	if err != nil {
		return domain.RunState{}, err
	}
	rid, err := domain.ParseRunID(runID)
	if err != nil {
		return domain.RunState{}, err
	}
	workspace, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.RunState{}, err
	}
	objective, err := domain.ParseObjectiveID(objectiveID)
	if err != nil {
		return domain.RunState{}, err
	}
	workUnit, err := domain.ParseWorkUnitID(workUnitID)
	if err != nil {
		return domain.RunState{}, err
	}
	operator, err := domain.ParseActorID(operatorID)
	if err != nil {
		return domain.RunState{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT participation_id FROM run_required_participations
		WHERE workspace_id = ? AND run_id = ? ORDER BY roster_ordinal`, workspaceID, runID)
	if err != nil {
		return domain.RunState{}, err
	}
	defer func() { _ = rows.Close() }()
	var required []domain.RunParticipationID
	for rows.Next() {
		var participationID string
		if err := rows.Scan(&participationID); err != nil {
			return domain.RunState{}, err
		}
		parsed, err := domain.ParseRunParticipationID(participationID)
		if err != nil {
			return domain.RunState{}, err
		}
		required = append(required, parsed)
	}
	if err := rows.Err(); err != nil {
		return domain.RunState{}, err
	}
	return domain.RehydrateRun(domain.RunRehydrationParams{ID: rid, WorkspaceID: workspace, ObjectiveID: objective,
		WorkUnitID: workUnit, OperatorID: operator, RequiredParticipationIDs: required,
		Status: domain.RunStatus(status), Version: mustVersion(version)})
}

func loadRunParticipationState(ctx context.Context, tx *sql.Tx, id string) (domain.RunParticipationState, error) {
	var participationID, runID, actorID, role, status string
	var sessionID sql.NullString
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT participation_id, run_id, actor_id, role, session_id, status, version
		FROM run_participations WHERE participation_id = ?`, id).Scan(&participationID, &runID, &actorID, &role, &sessionID, &status, &version)
	if err != nil {
		return domain.RunParticipationState{}, err
	}
	pid, err := domain.ParseRunParticipationID(participationID)
	if err != nil {
		return domain.RunParticipationState{}, err
	}
	rid, err := domain.ParseRunID(runID)
	if err != nil {
		return domain.RunParticipationState{}, err
	}
	actor, err := domain.ParseActorID(actorID)
	if err != nil {
		return domain.RunParticipationState{}, err
	}
	var session domain.ActorSessionID
	if sessionID.Valid {
		session, err = domain.ParseActorSessionID(sessionID.String)
	}
	if err != nil {
		return domain.RunParticipationState{}, err
	}
	return domain.RehydrateRunParticipation(domain.RunParticipationRehydrationParams{ID: pid, RunID: rid, ActorID: actor,
		Role: role, ActorSessionID: session, Status: domain.RunParticipationStatus(status), Version: mustVersion(version)})
}

func loadRuntimeBindingState(ctx context.Context, tx *sql.Tx, id string) (domain.RuntimeBindingState, error) {
	var bindingID, runID, participationID, sessionID, endpointID, status string
	var version uint64
	err := tx.QueryRowContext(ctx, `SELECT binding_id, run_id, participation_id, session_id, runtime_endpoint_id,
		status, version FROM runtime_bindings WHERE binding_id = ?`, id).Scan(&bindingID, &runID, &participationID,
		&sessionID, &endpointID, &status, &version)
	if err != nil {
		return domain.RuntimeBindingState{}, err
	}
	bid, err := domain.ParseRuntimeBindingID(bindingID)
	if err != nil {
		return domain.RuntimeBindingState{}, err
	}
	rid, err := domain.ParseRunID(runID)
	if err != nil {
		return domain.RuntimeBindingState{}, err
	}
	pid, err := domain.ParseRunParticipationID(participationID)
	if err != nil {
		return domain.RuntimeBindingState{}, err
	}
	sid, err := domain.ParseActorSessionID(sessionID)
	if err != nil {
		return domain.RuntimeBindingState{}, err
	}
	eid, err := domain.ParseRuntimeEndpointID(endpointID)
	if err != nil {
		return domain.RuntimeBindingState{}, err
	}
	return domain.RehydrateRuntimeBinding(domain.RuntimeBindingRehydrationParams{ID: bid, RunID: rid, ParticipationID: pid,
		ActorSessionID: sid, RuntimeEndpointID: eid, Status: domain.RuntimeBindingStatus(status), Version: mustVersion(version)})
}

func loadOptionalCeremonyByOwner(ctx context.Context, tx *sql.Tx, purpose domain.CeremonyPurpose, column, id string) (domain.CeremonyChallenge, error) {
	var ceremonyID string
	err := tx.QueryRowContext(ctx, "SELECT ceremony_id FROM ceremony_challenges WHERE purpose = ? AND "+column+" = ?", string(purpose), id).Scan(&ceremonyID)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CeremonyChallenge{}, nil
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	return loadCeremony(ctx, tx, ceremonyID)
}

func loadCeremony(ctx context.Context, tx *sql.Tx, id string) (domain.CeremonyChallenge, error) {
	return loadCeremonyWithStatus(ctx, tx, id, "")
}

func loadCeremonyWithStatus(ctx context.Context, tx *sql.Tx, id string, historicalStatus domain.CeremonyStatus) (domain.CeremonyChallenge, error) {
	var ceremonyID, purpose, status string
	var proof []byte
	var expires int64
	var installation, workspace, principal, membership, actor, delegation, device sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT ceremony_id, purpose, proof_fingerprint, installation_id, workspace_id,
		principal_id, membership_id, actor_id, delegation_id, device_id, status, expires_at_us
		FROM ceremony_challenges WHERE ceremony_id = ?`, id).Scan(&ceremonyID, &purpose, &proof, &installation,
		&workspace, &principal, &membership, &actor, &delegation, &device, &status, &expires)
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if len(proof) != sha256.Size {
		return domain.CeremonyChallenge{}, application.ErrInvalidCommandContext
	}
	params := domain.CeremonyChallengeRehydrationParams{Purpose: domain.CeremonyPurpose(purpose), Status: domain.CeremonyStatus(status), ExpiresAt: microsTime(expires)}
	if historicalStatus != "" {
		params.Status = historicalStatus
	}
	params.ID, err = domain.ParseCeremonyID(ceremonyID)
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	copy(params.ProofDigest[:], proof)
	if installation.Valid {
		params.InstallationID, err = domain.ParseInstallationID(installation.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if workspace.Valid {
		params.WorkspaceID, err = domain.ParseWorkspaceID(workspace.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if principal.Valid {
		params.PrincipalID, err = domain.ParsePrincipalID(principal.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if membership.Valid {
		params.MembershipID, err = domain.ParseMembershipID(membership.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if actor.Valid {
		params.ActorID, err = domain.ParseActorID(actor.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if delegation.Valid {
		params.DelegationID, err = domain.ParseActorDelegationID(delegation.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if device.Valid {
		params.DeviceID, err = domain.ParseDeviceID(device.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	return domain.RehydrateCeremonyChallenge(params)
}

func uintText(value uint64) string { return strconv.FormatUint(value, 10) }
func capabilitiesJSON(set domain.CapabilitySet) ([]byte, error) {
	values := set.Values()
	text := make([]string, len(values))
	for i := range values {
		text[i] = values[i].String()
	}
	return json.Marshal(text)
}
