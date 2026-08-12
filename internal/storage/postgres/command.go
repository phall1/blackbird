package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

var (
	errCommandNoCommit     = errors.New("PostgreSQL command transaction requires rollback")
	errCommandClockSuspect = errors.New("PostgreSQL authority clock is suspect")
	ErrCommitIndeterminate = errors.New("PostgreSQL commit outcome is indeterminate")
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

// ExecuteCommand owns a serializable PostgreSQL transaction and takes a
// transaction-scoped advisory lock keyed by authority scope before row locks.
// The advisory lock makes absent-row predicates (receipt and aggregate
// creation) serializable without relying on process-local mutexes.
func (store *Store) ExecuteCommand(
	ctx context.Context,
	spec application.CommandSpec,
	decide func(application.CommandContext) (application.CommandDecision, error),
) (execution application.CommandTransactionExecution, executionErr error) {
	return store.executeCommand(ctx, spec, decide, 3)
}

func (store *Store) executeCommand(
	ctx context.Context,
	spec application.CommandSpec,
	decide func(application.CommandContext) (application.CommandDecision, error),
	retries int,
) (execution application.CommandTransactionExecution, executionErr error) {
	if decide == nil || spec.CommandID().IsZero() {
		return application.CommandTransactionExecution{}, application.ErrInvalidCommandSpec
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			execution = application.CommandTransactionExecution{}
			executionErr = fmt.Errorf("PostgreSQL command callback panic: %v", recovered)
		}
	}()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return application.CommandTransactionExecution{}, fmt.Errorf("begin PostgreSQL command transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var postCommitErr error
	callbackInvoked := false
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", commandScopeLock(spec)); err == nil {
		var locked application.CommandContext
		var state lockedCommandState
		locked, state, err = store.lockCommandContext(ctx, tx, spec)
		if errors.Is(err, errCommandClockSuspect) {
			err = markCommandClockSuspect(ctx, tx, state)
			postCommitErr = commandClockSuspectError()
		}
		if err == nil {
			if postCommitErr != nil {
				goto commit
			}
			var decision application.CommandDecision
			callbackInvoked = true
			decision, err = decide(locked)
			if err == nil {
				err = application.ValidateCommandDecision(locked, decision)
			}
			if err == nil {
				execution, err = store.applyCommandDecision(ctx, tx, state, decision)
				if err == nil && (decision.Kind() == application.CommandDecisionReplay || decision.Kind() == application.CommandDecisionRollback) {
					err = errCommandNoCommit
				}
			}
		}
	} else {
		err = fmt.Errorf("acquire PostgreSQL command scope lock: %w", err)
	}
	if errors.Is(err, errCommandNoCommit) {
		return execution, nil
	}
	if err != nil {
		if retries > 0 && !callbackInvoked && isSerializationFailure(err) {
			_ = tx.Rollback(context.Background())
			return store.executeCommand(ctx, spec, decide, retries-1)
		}
		return application.CommandTransactionExecution{}, err
	}

commit:
	if err := tx.Commit(ctx); err != nil {
		if errors.Is(err, pgx.ErrTxCommitRollback) {
			return application.CommandTransactionExecution{}, err
		}
		return application.IndeterminateCommandTransactionExecution(spec)
	}
	if postCommitErr != nil {
		return application.CommandTransactionExecution{}, postCommitErr
	}
	return execution, nil
}

func isSerializationFailure(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "40001"
}

func commandScopeLock(spec application.CommandSpec) int64 {
	sum := sha256.Sum256([]byte("blackbird.postgresql-command-scope/v1\x00" + string(spec.Scope().Kind()) + "\x00" + spec.Scope().ID()))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func (store *Store) lockCommandContext(ctx context.Context, tx pgx.Tx, spec application.CommandSpec) (application.CommandContext, lockedCommandState, error) {
	state := lockedCommandState{spec: spec}
	resolution, err := store.resolveReceipt(ctx, tx, spec)
	if err != nil {
		return application.CommandContext{}, state, err
	}
	state.resolution = resolution
	state.stream, err = lockCommandStream(ctx, tx, spec)
	if err != nil {
		return application.CommandContext{}, state, err
	}
	evidence, err := application.NewAppliedGuardEvidence(spec.Guards(), spec.Guards().Evidence())
	if err != nil {
		return application.CommandContext{}, state, err
	}
	state.evidence = evidence
	if resolution.Kind() == application.ReceiptAdmitted {
		if err := verifyAdmissionGuard(ctx, tx, spec); err != nil {
			return application.CommandContext{}, state, err
		}
		state.states, state.ceremonies, err = loadCommandReadSet(ctx, tx, spec, true)
	} else if resolution.Kind() == application.ReceiptExactReplay {
		if err := verifyCurrentAdmission(ctx, tx, spec); err != nil {
			return application.CommandContext{}, state, err
		}
		state.states, _, err = loadCommandReadSet(ctx, tx, spec, false)
	}
	if err != nil {
		return application.CommandContext{}, state, err
	}
	var wall int64
	if err := tx.QueryRow(ctx, "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint").Scan(&wall); err != nil {
		return application.CommandContext{}, state, fmt.Errorf("read PostgreSQL command authority time: %w", err)
	}
	if resolution.Kind() == application.ReceiptAdmitted {
		regression := state.stream.timeFloor - wall
		if regression > backwardClockToleranceMicros {
			state.stream.clockStatus = "clock_suspect"
			if spec.AuthorityTimeClass() != application.AuthorityTimeOrdinary {
				return application.CommandContext{}, state, errCommandClockSuspect
			}
		} else if state.stream.clockStatus == "clock_suspect" {
			if wall < state.stream.timeFloor && spec.AuthorityTimeClass() != application.AuthorityTimeOrdinary {
				return application.CommandContext{}, state, errCommandClockSuspect
			}
			if wall >= state.stream.timeFloor {
				state.stream.clockStatus = "normal"
			}
		}
		if wall <= state.stream.timeFloor {
			wall = state.stream.timeFloor + 1
		}
		state.time, err = application.PersistedCommandAuthorityTime(microsTime(wall))
	} else {
		state.time, err = application.ReadOnlyDisclosureTime(microsTime(wall), microsTime(state.stream.timeFloor))
	}
	if err != nil {
		return application.CommandContext{}, state, err
	}
	if len(state.ceremonies) != 0 {
		locked, contextErr := application.NewCommandContextWithStandaloneCeremonies(spec, state.time, state.states, state.ceremonies, resolution, evidence)
		return locked, state, contextErr
	}
	locked, err := application.NewCommandContext(spec, state.time, state.states, resolution, evidence)
	return locked, state, err
}

func lockCommandStream(ctx context.Context, tx pgx.Tx, spec application.CommandSpec) (commandStream, error) {
	var state commandStream
	var nextEvent, nextAudit int64
	var head, auditHead []byte
	var authorityID string
	err := tx.QueryRow(ctx, `SELECT authority_id::text,next_sequence,head_digest,next_audit_sequence,audit_head_hash,
		authority_time_floor_us,clock_status FROM authority_streams WHERE scope_kind=$1 AND scope_id=$2 AND authority_epoch=$3 FOR UPDATE`,
		string(spec.Scope().Kind()), spec.Scope().ID(), spec.RequestedEpoch().String()).Scan(&authorityID, &nextEvent, &head, &nextAudit, &auditHead, &state.timeFloor, &state.clockStatus)
	state.observedClockStatus = state.clockStatus
	if errors.Is(err, pgx.ErrNoRows) && spec.CommandOperation() == application.CommandCreateWorkspace {
		genesis, genesisErr := commandStreamGenesis(spec)
		state.nextEvent, state.nextAudit, state.head, state.timeFloor = 1, 1, genesis, 1
		state.clockStatus, state.observedClockStatus = "normal", "normal"
		return state, genesisErr
	}
	if err != nil {
		return state, fmt.Errorf("lock PostgreSQL command stream: %w", err)
	}
	if authorityID != spec.AuthorityID().String() || nextEvent <= 0 || nextAudit <= 0 || len(head) != sha256.Size || len(auditHead) != sha256.Size {
		return state, application.ErrInvalidCommandContext
	}
	state.nextEvent, state.nextAudit = uint64(nextEvent), uint64(nextAudit)
	var digest [sha256.Size]byte
	copy(digest[:], head)
	state.head, err = domain.NewStreamDigest(digest)
	copy(state.auditHead[:], auditHead)
	return state, err
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
	scope, err := application.NewCanonicalIdentifier(spec.Scope().ID())
	if err != nil {
		return domain.StreamDigest{}, err
	}
	kind := application.StreamScopeInstallation
	if spec.Scope().Kind() == domain.ScopeKindWorkspace {
		kind = application.StreamScopeWorkspace
	}
	view, err := application.NewStreamGenesisViewV1(authority, epoch, kind, scope, nil)
	if err != nil {
		return domain.StreamDigest{}, err
	}
	return application.NewProductionCanonicalCodec().HashStreamGenesis(view)
}

func verifyCurrentAdmission(ctx context.Context, tx pgx.Tx, spec application.CommandSpec) error {
	plan := spec.Guards()
	var authority, epoch, status string
	var generation uint64
	err := tx.QueryRow(ctx, `SELECT authority_id::text,authority_epoch::text,write_status,guard_generation FROM scope_guards
		WHERE scope_kind=$1 AND scope_id=$2 FOR SHARE`, string(plan.AdmissionScope().Kind()), plan.AdmissionScope().ID()).Scan(&authority, &epoch, &status, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return commandReferenceConflict("command admission is absent")
	}
	if err != nil {
		return fmt.Errorf("verify PostgreSQL command admission: %w", err)
	}
	if authority != spec.AuthorityID().String() || epoch != spec.RequestedEpoch().String() || status != "open" || generation != plan.AdmissionGeneration().Uint64() {
		return commandReferenceConflict("command admission changed")
	}
	return nil
}

func verifyAdmissionGuard(ctx context.Context, tx pgx.Tx, spec application.CommandSpec) error {
	if err := verifyCurrentAdmission(ctx, tx, spec); err != nil {
		return err
	}
	if genesis, present := spec.Guards().GenesisAbsence(); present {
		var guards, streams int
		err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM scope_guards WHERE scope_kind=$1 AND scope_id=$2),
			(SELECT count(*) FROM authority_streams WHERE scope_kind=$1 AND scope_id=$2 AND authority_epoch=$3)`,
			string(genesis.Scope().Kind()), genesis.Scope().ID(), genesis.AuthorityEpoch().String()).Scan(&guards, &streams)
		if err != nil {
			return fmt.Errorf("verify PostgreSQL workspace genesis: %w", err)
		}
		if guards != 0 || streams != 0 {
			return commandReferenceConflict("workspace genesis is no longer absent")
		}
	}
	return nil
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

func (store *Store) resolveReceipt(ctx context.Context, tx pgx.Tx, spec application.CommandSpec) (application.ReceiptResolution, error) {
	primary, primaryFound, err := queryReceiptHeader(ctx, tx, "command_id = $1", spec.CommandID().String())
	if err != nil {
		return application.ReceiptResolution{}, err
	}
	predicate, args := receiptIdentityPredicate(spec.ReceiptIdentity(), 1)
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
		receipt, err := store.rehydrateReceipt(ctx, tx, spec, primary)
		if err != nil {
			return application.ReceiptResolution{}, err
		}
		return application.ReplayReceipt(receipt)
	}
	if !secondaryFound {
		return application.AdmitReceipt(), nil
	}
	if secondary.requestFingerprint == spec.RequestFingerprint() {
		receipt, err := store.rehydrateReceipt(ctx, tx, spec, secondary)
		if err != nil {
			return application.ReceiptResolution{}, err
		}
		return application.ReplayReceipt(receipt)
	}
	return application.ConflictReceipt(application.ReceiptIdempotencyConflict, secondary.receiptID)
}

func receiptIdentityPredicate(identity application.ReceiptIdentity, start int) (string, []any) {
	p := func(n int) string { return fmt.Sprintf("$%d", start+n) }
	switch identity.Kind() {
	case application.ReceiptIdentityOrdinary:
		return `identity_kind='ordinary_workspace' AND workspace_id=` + p(0) + ` AND principal_id=` + p(1) + ` AND client_instance_id=` + p(2) + ` AND operation=` + p(3) + ` AND idempotency_key=` + p(4), []any{identity.WorkspaceID().String(), identity.PrincipalID().String(), identity.ClientInstanceID().String(), identity.Operation().String(), identity.Key().String()}
	case application.ReceiptIdentityProvisioning:
		fingerprint := identity.TranscriptFingerprint()
		return `identity_kind='installation_provisioning' AND installation_id=` + p(0) + ` AND transcript_fingerprint=` + p(1) + ` AND operation=` + p(2) + ` AND idempotency_key=` + p(3), []any{identity.InstallationID().String(), fingerprint[:], identity.Operation().String(), identity.Key().String()}
	default:
		return `identity_kind='installation_admin' AND installation_id=` + p(0) + ` AND principal_id=` + p(1) + ` AND client_instance_id=` + p(2) + ` AND operation=` + p(3) + ` AND idempotency_key=` + p(4), []any{identity.InstallationID().String(), identity.PrincipalID().String(), identity.ClientInstanceID().String(), identity.Operation().String(), identity.Key().String()}
	}
}

func queryReceiptHeader(ctx context.Context, tx pgx.Tx, predicate string, args ...any) (receiptHeader, bool, error) {
	query := `SELECT receipt_id::text,command_id::text,identity_kind,scope_kind,scope_id::text,workspace_id::text,
		installation_id::text,principal_id::text,client_instance_id::text,transcript_fingerprint,operation,operation_major,
		idempotency_key,request_fingerprint,authority_id::text,authority_epoch::text,result_digest,result_canonical,
		first_event_sequence,last_event_sequence,final_stream_digest,guard_digest,recovery_capsule_canonical,
		recovery_capsule_digest,recovery_capsule_key_id,recovery_capsule_public_key,committed_at_us FROM command_receipts WHERE ` + predicate
	var receiptText, commandText, kind, scopeKind, scopeID, operation, key, authority, epoch string
	var workspace, installation, principal, client, capsuleKey sql.NullString
	var transcript, request, resultDigest, resultCanonical, finalDigest, guardDigest, capsuleCanonical, capsuleDigest, capsulePublic []byte
	var first, last int64
	var operationMajor uint16
	var committed int64
	err := tx.QueryRow(ctx, query, args...).Scan(&receiptText, &commandText, &kind, &scopeKind, &scopeID, &workspace, &installation, &principal, &client, &transcript, &operation, &operationMajor, &key, &request, &authority, &epoch, &resultDigest, &resultCanonical, &first, &last, &finalDigest, &guardDigest, &capsuleCanonical, &capsuleDigest, &capsuleKey, &capsulePublic, &committed)
	if errors.Is(err, pgx.ErrNoRows) {
		return receiptHeader{}, false, nil
	}
	if err != nil {
		return receiptHeader{}, false, fmt.Errorf("query PostgreSQL command receipt: %w", err)
	}
	header, err := decodeReceiptHeader(receiptText, commandText, kind, scopeKind, scopeID, workspace, installation, principal, client, transcript, operation, operationMajor, key, request, authority, epoch, resultDigest, resultCanonical, first, last, finalDigest, guardDigest, capsuleCanonical, capsuleDigest, capsuleKey, capsulePublic, committed)
	return header, true, err
}

func decodeReceiptHeader(receiptText, commandText, kind, scopeKind, scopeID string, workspace, installation, principal, client sql.NullString, transcript []byte, operationText string, operationMajor uint16, keyText string, request []byte, authorityText, epochText string, resultDigest, resultCanonical []byte, first, last int64, finalDigest, guardDigest, capsuleCanonical, capsuleDigest []byte, capsuleKey sql.NullString, capsulePublic []byte, committed int64) (receiptHeader, error) {
	var h receiptHeader
	var err error
	if h.receiptID, err = domain.ParseReceiptID(receiptText); err != nil {
		return h, err
	}
	if h.commandID, err = domain.ParseCommandID(commandText); err != nil {
		return h, err
	}
	if h.authorityID, err = domain.ParseAuthorityID(authorityText); err != nil {
		return h, err
	}
	if h.epoch, err = domain.ParseAuthorityEpoch(epochText); err != nil {
		return h, err
	}
	op, err := domain.NewOperationName(operationText)
	if err != nil {
		return h, err
	}
	key, err := domain.NewIdempotencyKey(keyText)
	if err != nil {
		return h, err
	}
	switch application.ReceiptIdentityKind(kind) {
	case application.ReceiptIdentityOrdinary:
		wid, e := domain.ParseWorkspaceID(workspace.String)
		if e != nil {
			return h, e
		}
		pid, e := domain.ParsePrincipalID(principal.String)
		if e != nil {
			return h, e
		}
		cid, e := domain.ParseClientInstanceID(client.String)
		if e != nil {
			return h, e
		}
		scope, e := domain.NewIdempotencyScope(wid, pid, cid, op, key)
		if e != nil {
			return h, e
		}
		h.identity, err = application.OrdinaryReceiptIdentity(scope)
	case application.ReceiptIdentityProvisioning:
		iid, e := domain.ParseInstallationID(installation.String)
		if e != nil {
			return h, e
		}
		var fp domain.CommandFingerprint
		copy(fp[:], transcript)
		scopeValue, e := domain.InstallationScope(iid)
		if e != nil {
			return h, e
		}
		scope, e := domain.NewProvisioningIdempotencyScope(scopeValue, fp, op, key)
		if e != nil {
			return h, e
		}
		h.identity, err = application.ProvisioningReceiptIdentity(scope)
	case application.ReceiptIdentityInstallationAdmin:
		iid, e := domain.ParseInstallationID(installation.String)
		if e != nil {
			return h, e
		}
		pid, e := domain.ParsePrincipalID(principal.String)
		if e != nil {
			return h, e
		}
		cid, e := domain.ParseClientInstanceID(client.String)
		if e != nil {
			return h, e
		}
		h.identity, err = application.InstallationAdminReceiptIdentity(iid, pid, cid, op, key)
	default:
		err = application.ErrInvalidReceiptIdentity
	}
	if err != nil || len(request) != sha256.Size || len(resultDigest) != sha256.Size || first <= 0 || last < first || len(finalDigest) != sha256.Size || len(guardDigest) != sha256.Size || committed <= 0 || string(h.identity.Scope().Kind()) != scopeKind || h.identity.Scope().ID() != scopeID {
		return h, application.ErrInvalidApplicationContract
	}
	copy(h.requestFingerprint[:], request)
	copy(h.resultDigest[:], resultDigest)
	var finalArray, guardArray [sha256.Size]byte
	copy(finalArray[:], finalDigest)
	copy(guardArray[:], guardDigest)
	if h.finalDigest, err = domain.NewStreamDigest(finalArray); err != nil {
		return h, err
	}
	if h.guardDigest, err = domain.NewAuthorizationDigest(guardArray); err != nil {
		return h, err
	}
	h.resultCanonical = append([]byte(nil), resultCanonical...)
	h.first, h.last, h.committedAt = uint64(first), uint64(last), microsTime(committed)
	h.operationMajor = operationMajor
	if capsuleKey.Valid {
		if len(capsuleDigest) != sha256.Size || len(capsulePublic) != 32 || len(capsuleCanonical) == 0 {
			return h, application.ErrInvalidApplicationContract
		}
		copy(h.capsuleDigest[:], capsuleDigest)
		h.capsuleCanonical = append([]byte(nil), capsuleCanonical...)
		h.capsuleKey = capsuleKey.String
		h.capsulePublicKey = append([]byte(nil), capsulePublic...)
	}
	return h, nil
}

func commandReferenceConflict(message string) error {
	conflict, err := domain.NewConflictError(domain.ErrorCodeStateConflict, domain.ConflictReference, message, application.ErrInvalidCommandContext)
	if err != nil {
		return err
	}
	return conflict
}

func commandClockSuspectError() error {
	commandErr, err := domain.NewCommandError(domain.ErrorCodeDependencyUnavailable, "authority clock is suspect", errCommandClockSuspect)
	if err != nil {
		return err
	}
	return commandErr
}

func markCommandClockSuspect(ctx context.Context, tx pgx.Tx, state lockedCommandState) error {
	if err := verifyCurrentAdmission(ctx, tx, state.spec); err != nil {
		return err
	}
	oldHead := state.stream.head.Bytes()
	tag, err := tx.Exec(ctx, `UPDATE authority_streams SET clock_status='clock_suspect' WHERE scope_kind=$1 AND scope_id=$2
		AND authority_id=$3 AND authority_epoch=$4 AND next_sequence=$5 AND head_digest=$6 AND next_audit_sequence=$7
		AND audit_head_hash=$8 AND authority_time_floor_us=$9 AND clock_status=$10 AND EXISTS(SELECT 1 FROM scope_guards
		WHERE scope_kind=$11 AND scope_id=$12 AND authority_id=$3 AND authority_epoch=$4 AND write_status='open' AND guard_generation=$13)`,
		string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.spec.AuthorityID().String(), state.spec.RequestedEpoch().String(),
		state.stream.nextEvent, oldHead[:], state.stream.nextAudit, state.stream.auditHead[:], state.stream.timeFloor, state.stream.observedClockStatus,
		string(state.spec.Guards().AdmissionScope().Kind()), state.spec.Guards().AdmissionScope().ID(), state.spec.Guards().AdmissionGeneration().Uint64())
	if err != nil {
		return fmt.Errorf("mark PostgreSQL authority clock suspect: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return commandReferenceConflict("authority clock state changed")
	}
	return nil
}
