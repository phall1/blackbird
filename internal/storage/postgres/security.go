package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const securityLockID = int64(0x42425345)

var errSecurityNoCommit = errors.New("PostgreSQL security transaction requires rollback")

type lockedSecurityState struct {
	spec          application.SecuritySpec
	authorityTime time.Time
	guardDigest   domain.AuthorizationDigest
	invitation    domain.InstallationInvitationState
	stream        securityStream
	admission     application.DenialAdmission
}

type securityStream struct {
	nextAudit uint64
	auditHead application.Digest
	timeFloor int64
}

func (store *Store) ExecuteSecurity(
	ctx context.Context,
	spec application.SecuritySpec,
	decide func(application.SecurityContext) (application.SecurityDecision, error),
) (execution application.SecurityExecution, executionErr error) {
	if !spec.Operation().Valid() || decide == nil {
		return application.SecurityExecution{}, application.ErrInvalidSecuritySpec
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			execution = application.SecurityExecution{}
			executionErr = fmt.Errorf("PostgreSQL security callback panic: %v", recovered)
		}
	}()
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", securityLockID); err != nil {
			return fmt.Errorf("acquire PostgreSQL security lane: %w", err)
		}
		locked, state, err := store.lockSecurityContext(ctx, tx, spec)
		if err != nil {
			return err
		}
		decision, err := decide(locked)
		if err != nil {
			return err
		}
		if err := application.ValidateSecurityDecision(locked, decision); err != nil {
			return err
		}
		execution, err = store.applySecurityDecision(ctx, tx, state, decision)
		if err != nil {
			return err
		}
		switch decision.Kind() {
		case application.SecurityDecisionRollback, application.SecurityDecisionReplay,
			application.SecurityDecisionSuppressDenial:
			return errSecurityNoCommit
		default:
			return nil
		}
	})
	if errors.Is(err, errSecurityNoCommit) {
		return execution, nil
	}
	if err != nil {
		return application.SecurityExecution{}, err
	}
	return execution, nil
}

func (store *Store) lockSecurityContext(ctx context.Context, tx pgx.Tx, spec application.SecuritySpec) (application.SecurityContext, lockedSecurityState, error) {
	state := lockedSecurityState{spec: spec}
	var wallMicros int64
	if err := tx.QueryRow(ctx, "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint").Scan(&wallMicros); err != nil {
		return application.SecurityContext{}, state, fmt.Errorf("read PostgreSQL authority time: %w", err)
	}
	if spec.Operation() == application.SecurityInitializeInstallation {
		var initialized int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM scope_guards
			WHERE scope_kind = 'installation' AND scope_id = $1`, spec.Scope().ID()).Scan(&initialized); err != nil {
			return application.SecurityContext{}, state, fmt.Errorf("read PostgreSQL initialization guard: %w", err)
		}
		if initialized != 0 {
			return application.SecurityContext{}, state, fmt.Errorf("%w: installation already initialized", application.ErrInvalidSecurityContext)
		}
		state.authorityTime = microsTime(wallMicros)
	} else {
		var authorityID, epoch string
		var generation uint64
		if err := tx.QueryRow(ctx, `SELECT authority_id::text, authority_epoch::text, guard_generation
			FROM scope_guards WHERE scope_kind = $1 AND scope_id = $2 FOR UPDATE`, string(spec.Scope().Kind()), spec.Scope().ID()).Scan(&authorityID, &epoch, &generation); err != nil {
			return application.SecurityContext{}, state, fmt.Errorf("lock PostgreSQL security admission: %w", err)
		}
		if authorityID != spec.AuthorityID().String() || epoch != spec.AuthorityEpoch().String() || generation != spec.AdmissionGeneration().Uint64() {
			return application.SecurityContext{}, state, application.ErrInvalidSecurityContext
		}
		var nextAudit int64
		var auditHead []byte
		if err := tx.QueryRow(ctx, `SELECT next_audit_sequence, audit_head_hash, authority_time_floor_us
			FROM authority_streams WHERE scope_kind = $1 AND scope_id = $2 AND authority_epoch = $3 FOR UPDATE`,
			string(spec.Scope().Kind()), spec.Scope().ID(), spec.AuthorityEpoch().String()).Scan(&nextAudit, &auditHead, &state.stream.timeFloor); err != nil {
			return application.SecurityContext{}, state, fmt.Errorf("lock PostgreSQL authority stream: %w", err)
		}
		if nextAudit <= 0 || len(auditHead) != sha256.Size {
			return application.SecurityContext{}, state, application.ErrInvalidSecurityContext
		}
		state.stream.nextAudit = uint64(nextAudit)
		copy(state.stream.auditHead[:], auditHead)
		if wallMicros <= state.stream.timeFloor {
			wallMicros = state.stream.timeFloor + 1
		}
		state.authorityTime = microsTime(wallMicros)
	}
	digestBytes := sha256.Sum256([]byte("blackbird.postgresql-security-guard/v1\x00" + string(spec.Operation()) + "\x00" +
		string(spec.Scope().Kind()) + "\x00" + spec.Scope().ID() + "\x00" + spec.AuthorityID().String() + "\x00" +
		spec.AuthorityEpoch().String() + "\x00" + strconv.FormatUint(spec.AdmissionGeneration().Uint64(), 10)))
	guardDigest, err := domain.NewAuthorizationDigest(digestBytes)
	if err != nil {
		return application.SecurityContext{}, state, err
	}
	state.guardDigest = guardDigest
	var attempt application.SecurityAttemptResolution
	switch spec.Operation() {
	case application.SecurityResumeBootstrapGeneration, application.SecurityRecordBootstrapDenial:
		state.invitation, err = loadInvitation(ctx, tx, spec)
		if err != nil {
			return application.SecurityContext{}, state, err
		}
		if spec.Operation() == application.SecurityRecordBootstrapDenial {
			attempt = application.FreshSecurityAttempt()
			fingerprint, _ := spec.AttemptFingerprint()
			expectation, _ := spec.InvitationExpectation()
			var version uint64
			var deniedAt int64
			err = tx.QueryRow(ctx, `SELECT occurrence_count, first_recorded_at_us FROM security_denials
				WHERE record_kind = 'bootstrap' AND subject_id = $1 AND denial_fingerprint = $2 AND bucket = 0`, expectation.Target().ID(), fingerprint[:]).Scan(&version, &deniedAt)
			if err == nil {
				record, recordErr := application.NewSecurityDenialRecord(state.invitation.ID(), fingerprint, mustVersion(version), microsTime(deniedAt))
				if recordErr != nil {
					return application.SecurityContext{}, state, recordErr
				}
				attempt, err = application.ReplaySecurityAttempt(record)
				if err != nil {
					return application.SecurityContext{}, state, err
				}
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return application.SecurityContext{}, state, fmt.Errorf("resolve PostgreSQL bootstrap denial: %w", err)
			}
		}
	case application.SecurityRecordCommandDenial:
		state.admission, err = commandDenialAdmission(ctx, tx, spec, state.authorityTime)
		if err != nil {
			return application.SecurityContext{}, state, err
		}
	}
	locked, err := application.NewSecurityContext(spec, state.authorityTime, state.invitation, attempt, state.admission, state.guardDigest)
	return locked, state, err
}

func loadInvitation(ctx context.Context, tx pgx.Tx, spec application.SecuritySpec) (domain.InstallationInvitationState, error) {
	expectation, present := spec.InvitationExpectation()
	if !present {
		return domain.InstallationInvitationState{}, application.ErrInvalidSecurityContext
	}
	var id, installationID, publicKey, generation, status string
	var verifier []byte
	var failures int
	var expiresMicros, version uint64
	err := tx.QueryRow(ctx, `SELECT invitation_id::text, installation_id::text, installation_public_key_reference,
		invitation_verifier, bootstrap_generation_id::text, status, failed_attempts, expires_at_us, version
		FROM installation_invitations WHERE invitation_id = $1 AND installation_id = $2 FOR UPDATE`, expectation.Target().ID(), spec.Scope().ID()).
		Scan(&id, &installationID, &publicKey, &verifier, &generation, &status, &failures, &expiresMicros, &version)
	if err != nil {
		return domain.InstallationInvitationState{}, fmt.Errorf("load PostgreSQL invitation: %w", err)
	}
	invitationID, err := domain.ParseInvitationID(id)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	installation, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	key, err := domain.NewPublicKeyReference(publicKey)
	if err != nil || len(verifier) != sha256.Size || failures < 0 || failures > 255 {
		return domain.InstallationInvitationState{}, application.ErrInvalidSecurityContext
	}
	bootstrapGeneration, err := domain.ParseBootstrapGenerationID(generation)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	domainVersion, err := domain.NewVersion(version)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	var fingerprint domain.CommandFingerprint
	copy(fingerprint[:], verifier)
	return domain.RehydrateInstallationInvitation(domain.InstallationInvitationRehydrationParams{
		ID: invitationID, InstallationID: installation, InstallationPublicKey: key, InvitationVerifier: fingerprint,
		BootstrapGenerationID: bootstrapGeneration, ExpiresAt: microsTime(int64(expiresMicros)), FailedAttempts: uint8(failures),
		Status: domain.InstallationInvitationStatus(status), Version: domainVersion,
	})
}

func commandDenialAdmission(ctx context.Context, tx pgx.Tx, spec application.SecuritySpec, authorityTime time.Time) (application.DenialAdmission, error) {
	draft, present := spec.CommandDenial()
	if !present {
		return application.DenialAdmission{}, application.ErrInvalidSecurityContext
	}
	bucket := authorityTime.Unix() / 60
	subjectKind, subjectID := denialSubjectKey(draft.Subject())
	fingerprint := draft.DenialFingerprint()
	base := []any{string(spec.Scope().Kind()), spec.Scope().ID(), subjectKind, subjectID, draft.Operation().String(), draft.OperationMajor().Uint16(), string(draft.Class()), bucket}
	var duplicate, distinct, scopeEntries int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_denials WHERE record_kind='command' AND scope_kind=$1 AND scope_id=$2
		AND subject_kind=$3 AND subject_id=$4 AND operation=$5 AND operation_major=$6 AND denial_class=$7 AND bucket=$8 AND denial_fingerprint=$9`, append(base, fingerprint[:])...).Scan(&duplicate); err != nil {
		return application.DenialAdmission{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_denials WHERE record_kind='command' AND scope_kind=$1 AND scope_id=$2
		AND subject_kind=$3 AND subject_id=$4 AND operation=$5 AND operation_major=$6 AND denial_class=$7 AND bucket=$8`, base...).Scan(&distinct); err != nil {
		return application.DenialAdmission{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_denials WHERE record_kind='command' AND scope_kind=$1 AND scope_id=$2 AND bucket=$3`, base[0], base[1], bucket).Scan(&scopeEntries); err != nil {
		return application.DenialAdmission{}, err
	}
	if distinct > application.MaxDistinctDenialsPerMinute {
		distinct = application.MaxDistinctDenialsPerMinute
	}
	if scopeEntries > application.MaxDenialEntriesPerScopeMinute {
		scopeEntries = application.MaxDenialEntriesPerScopeMinute
	}
	kind := application.DenialAdmitDistinct
	var summary int
	switch {
	case duplicate != 0:
		kind = application.DenialSuppressDuplicate
	case scopeEntries == application.MaxDenialEntriesPerScopeMinute:
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_denials WHERE record_kind='command' AND scope_kind=$1 AND scope_id=$2 AND bucket=$3 AND reason='denial_scope_saturated'`, base[0], base[1], bucket).Scan(&summary); err != nil {
			return application.DenialAdmission{}, err
		}
		if summary == 0 {
			kind = application.DenialAdmitScopeSaturation
		} else {
			kind = application.DenialSuppressScopeSaturated
		}
	case distinct == application.MaxDistinctDenialsPerMinute:
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_denials WHERE record_kind='command' AND scope_kind=$1 AND scope_id=$2
			AND subject_kind=$3 AND subject_id=$4 AND operation=$5 AND operation_major=$6 AND denial_class=$7 AND bucket=$8 AND reason='denial_bucket_saturated'`, base...).Scan(&summary); err != nil {
			return application.DenialAdmission{}, err
		}
		if summary == 0 {
			kind = application.DenialAdmitSaturation
		} else {
			kind = application.DenialSuppressSaturated
		}
	}
	return application.NewDenialAdmission(kind, authorityTime, uint8(distinct), uint16(scopeEntries))
}

func denialSubjectKey(subject application.DenialSubject) (string, string) {
	if source, present := subject.SourceDigest(); present {
		return string(subject.Kind()), hex.EncodeToString(source[:])
	}
	value := subject.PrincipalID().String()
	if device, present := subject.DeviceID(); present {
		value += ":" + device.String()
	}
	return string(subject.Kind()), value
}

func (store *Store) applySecurityDecision(ctx context.Context, tx pgx.Tx, state lockedSecurityState, decision application.SecurityDecision) (application.SecurityExecution, error) {
	spec := state.spec
	switch decision.Kind() {
	case application.SecurityDecisionRollback:
		rejection, _ := decision.Rejection()
		return application.RejectedSecurityExecution(spec.Operation(), rejection)
	case application.SecurityDecisionReplay:
		record, _ := decision.Denial()
		return application.ReplayedDenialSecurityExecution(record)
	case application.SecurityDecisionSuppressDenial:
		return application.CommandDenialSecurityExecution(false), nil
	}
	if spec.Operation() == application.SecurityInitializeInstallation {
		if err := store.initializeSecurityState(ctx, tx, state, decision); err != nil {
			return application.SecurityExecution{}, err
		}
		state.stream = securityStream{nextAudit: 1, timeFloor: timeMicros(state.authorityTime)}
	} else if err := store.compareAndSwapSecurityState(ctx, tx, state, decision); err != nil {
		return application.SecurityExecution{}, err
	}
	audit, present := decision.Audit()
	if !present {
		return application.SecurityExecution{}, application.ErrInvalidSecurityDecision
	}
	if err := appendSecurityAudit(ctx, tx, state, audit); err != nil {
		return application.SecurityExecution{}, err
	}
	switch decision.Kind() {
	case application.SecurityDecisionInitialize, application.SecurityDecisionGeneration:
		return application.AppliedSecurityExecution(spec.Operation())
	case application.SecurityDecisionDeny:
		record, _ := decision.Denial()
		return application.CommittedDenialSecurityExecution(record)
	case application.SecurityDecisionAuditDenial:
		return application.CommandDenialSecurityExecution(true), nil
	default:
		return application.SecurityExecution{}, application.ErrInvalidSecurityDecision
	}
}

func (store *Store) initializeSecurityState(ctx context.Context, tx pgx.Tx, state lockedSecurityState, decision application.SecurityDecision) error {
	spec := state.spec
	invitation, present := decision.Invitation()
	if !present {
		return application.ErrInvalidSecurityDecision
	}
	oldGeneration, newGeneration, changed := decision.Generations()
	if changed || !oldGeneration.IsZero() || !newGeneration.IsZero() {
		return application.ErrInvalidSecurityDecision
	}
	streamDigest, err := streamGenesis(spec)
	if err != nil {
		return err
	}
	now := timeMicros(state.authorityTime)
	if _, err := tx.Exec(ctx, `INSERT INTO scope_guards(scope_kind,scope_id,authority_id,authority_epoch,bootstrap_generation_id,write_status,guard_generation,updated_at_us)
		VALUES($1,$2,$3,$4,$5,'open',$6,$7)`, string(spec.Scope().Kind()), spec.Scope().ID(), spec.AuthorityID().String(), spec.AuthorityEpoch().String(), invitation.BootstrapGenerationID().String(), spec.AdmissionGeneration().Uint64(), now); err != nil {
		return fmt.Errorf("insert PostgreSQL installation guard: %w", err)
	}
	streamBytes := streamDigest.Bytes()
	if _, err := tx.Exec(ctx, `INSERT INTO authority_streams(scope_kind,scope_id,authority_id,authority_epoch,next_sequence,retained_from_sequence,digest_algorithm,head_digest,next_audit_sequence,audit_head_hash,authority_time_floor_us,clock_status)
		VALUES($1,$2,$3,$4,1,1,'sha-256',$5,1,$6,$7,'normal')`, string(spec.Scope().Kind()), spec.Scope().ID(), spec.AuthorityID().String(), spec.AuthorityEpoch().String(), streamBytes[:], make([]byte, sha256.Size), now); err != nil {
		return fmt.Errorf("insert PostgreSQL authority stream: %w", err)
	}
	return insertInvitation(ctx, tx, invitation, state.authorityTime, spec)
}

func streamGenesis(spec application.SecuritySpec) (domain.StreamDigest, error) {
	authority, err := application.NewCanonicalIdentifier(spec.AuthorityID().String())
	if err != nil {
		return domain.StreamDigest{}, err
	}
	epoch, err := application.NewCanonicalIdentifier(spec.AuthorityEpoch().String())
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

func insertInvitation(ctx context.Context, tx pgx.Tx, invitation domain.InstallationInvitationState, recordedAt time.Time, spec application.SecuritySpec) error {
	verifier := invitation.InvitationVerifier()
	created := invitation.ExpiresAt().Add(-domain.BootstrapInvitationLifetime)
	updated := recordedAt
	if created.After(updated) {
		updated = created
	}
	_, err := tx.Exec(ctx, `INSERT INTO installation_invitations(invitation_id,installation_id,authority_id,authority_epoch,installation_public_key_reference,invitation_verifier,bootstrap_generation_id,status,failed_attempts,expires_at_us,version,created_at_us,updated_at_us)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, invitation.ID().String(), invitation.InstallationID().String(), spec.AuthorityID().String(), spec.AuthorityEpoch().String(), invitation.InstallationPublicKey().String(), verifier[:], invitation.BootstrapGenerationID().String(), string(invitation.Status()), invitation.FailedAttempts(), timeMicros(invitation.ExpiresAt()), invitation.Version().Uint64(), timeMicros(created), timeMicros(updated))
	if err != nil {
		return fmt.Errorf("insert PostgreSQL installation invitation: %w", err)
	}
	return nil
}

func (store *Store) compareAndSwapSecurityState(ctx context.Context, tx pgx.Tx, state lockedSecurityState, decision application.SecurityDecision) error {
	spec, now := state.spec, timeMicros(state.authorityTime)
	var tag pgconn.CommandTag
	var err error
	switch decision.Kind() {
	case application.SecurityDecisionGeneration:
		oldGeneration, newGeneration, _ := decision.Generations()
		if spec.Operation() == application.SecurityRotateBootstrapGeneration {
			tag, err = tx.Exec(ctx, `UPDATE scope_guards SET bootstrap_generation_id=$1,updated_at_us=$2 WHERE scope_kind=$3 AND scope_id=$4 AND authority_id=$5 AND authority_epoch=$6 AND guard_generation=$7 AND bootstrap_generation_id=$8`, newGeneration.String(), now, string(spec.Scope().Kind()), spec.Scope().ID(), spec.AuthorityID().String(), spec.AuthorityEpoch().String(), spec.AdmissionGeneration().Uint64(), oldGeneration.String())
		} else {
			expectation, _ := spec.InvitationExpectation()
			expected, _ := expectation.Version()
			tag, err = tx.Exec(ctx, `UPDATE installation_invitations SET bootstrap_generation_id=$1,updated_at_us=$2 WHERE invitation_id=$3 AND installation_id=$4 AND authority_epoch=$5 AND bootstrap_generation_id=$6 AND version=$7 AND EXISTS(SELECT 1 FROM scope_guards WHERE scope_kind=$8 AND scope_id=$9 AND authority_id=$10 AND authority_epoch=$11 AND guard_generation=$12 AND bootstrap_generation_id=$1)`, newGeneration.String(), now, expectation.Target().ID(), spec.Scope().ID(), spec.AuthorityEpoch().String(), oldGeneration.String(), expected.Uint64(), string(spec.Scope().Kind()), spec.Scope().ID(), spec.AuthorityID().String(), spec.AuthorityEpoch().String(), spec.AdmissionGeneration().Uint64())
		}
	case application.SecurityDecisionDeny:
		invitation, _ := decision.Invitation()
		tag, err = tx.Exec(ctx, `UPDATE installation_invitations SET status=$1,failed_attempts=$2,version=$3,updated_at_us=$4 WHERE invitation_id=$5 AND installation_id=$6 AND authority_epoch=$7 AND version=$8`, string(invitation.Status()), invitation.FailedAttempts(), invitation.Version().Uint64(), now, invitation.ID().String(), invitation.InstallationID().String(), spec.AuthorityEpoch().String(), state.invitation.Version().Uint64())
		if err == nil && tag.RowsAffected() == 1 {
			record, _ := decision.Denial()
			fingerprint := record.AttemptFingerprint()
			_, err = tx.Exec(ctx, `INSERT INTO security_denials(record_kind,denial_fingerprint,scope_kind,scope_id,subject_kind,subject_id,denial_class,reason,bucket,occurrence_count,first_recorded_at_us,last_recorded_at_us) VALUES('bootstrap',$1,$2,$3,'invitation',$4,'authentication','bootstrap_proof_rejected',0,$5,$6,$6)`, fingerprint[:], string(spec.Scope().Kind()), spec.Scope().ID(), record.InvitationID().String(), record.InvitationVersion().Uint64(), timeMicros(record.DeniedAt()))
		}
	case application.SecurityDecisionAuditDenial:
		tag, err = store.insertCommandDenial(ctx, tx, state, decision)
	default:
		return application.ErrInvalidSecurityDecision
	}
	if err != nil {
		return fmt.Errorf("apply PostgreSQL security decision: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: PostgreSQL security compare-and-swap", application.ErrInvalidSecurityContext)
	}
	return nil
}

func (store *Store) insertCommandDenial(ctx context.Context, tx pgx.Tx, state lockedSecurityState, decision application.SecurityDecision) (pgconn.CommandTag, error) {
	record, present := decision.CommandDenialAudit()
	if !present {
		return pgconn.CommandTag{}, application.ErrInvalidSecurityDecision
	}
	draft := record.Draft()
	subjectKind, subjectID := denialSubjectKey(draft.Subject())
	reason := draft.SafeReason()
	if record.Variant() == application.CommandDenialAuditSubjectSaturation {
		reason = "denial_bucket_saturated"
	} else if record.Variant() == application.CommandDenialAuditScopeSaturation {
		reason = "denial_scope_saturated"
	}
	fingerprint, now := draft.DenialFingerprint(), timeMicros(state.authorityTime)
	return tx.Exec(ctx, `INSERT INTO security_denials(record_kind,denial_fingerprint,scope_kind,scope_id,subject_kind,subject_id,operation,operation_major,denial_class,reason,bucket,occurrence_count,first_recorded_at_us,last_recorded_at_us)
		SELECT 'command',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$11 WHERE EXISTS(SELECT 1 FROM scope_guards WHERE scope_kind=$2 AND scope_id=$3 AND authority_id=$12 AND authority_epoch=$13 AND guard_generation=$14)`, fingerprint[:], string(state.spec.Scope().Kind()), state.spec.Scope().ID(), subjectKind, subjectID, draft.Operation().String(), draft.OperationMajor().Uint16(), string(draft.Class()), reason, record.MinuteBucket(), now, state.spec.AuthorityID().String(), state.spec.AuthorityEpoch().String(), state.spec.AdmissionGeneration().Uint64())
}

func appendSecurityAudit(ctx context.Context, tx pgx.Tx, state lockedSecurityState, intent application.AuditIntent) error {
	view, err := application.NewAuditEntryViewV1(application.AuditEntryParams{ChainScopeID: state.spec.Scope(), Sequence: state.stream.nextAudit, AuthorityID: state.spec.AuthorityID(), AuthorityEpoch: state.spec.AuthorityEpoch(), RecordedAt: state.authorityTime, Intent: intent, PreviousEntryHash: state.stream.auditHead})
	if err != nil {
		return fmt.Errorf("materialize PostgreSQL security audit: %w", err)
	}
	codec := application.NewProductionCanonicalCodec()
	canonical, digest, err := codec.EncodeAuditEntry(view)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL security audit: %w", err)
	}
	if err := codec.VerifyAuditEntry(state.stream.auditHead, canonical, digest); err != nil {
		return fmt.Errorf("verify PostgreSQL security audit: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_entries(scope_kind,scope_id,audit_sequence,previous_entry_hash,entry_hash,canonical_entry,recorded_at_us) VALUES($1,$2,$3,$4,$5,$6,$7)`, string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.stream.nextAudit, state.stream.auditHead[:], digest[:], canonical, timeMicros(state.authorityTime)); err != nil {
		return fmt.Errorf("insert PostgreSQL security audit: %w", err)
	}
	tag, err := tx.Exec(ctx, `UPDATE authority_streams SET next_audit_sequence=next_audit_sequence+1,audit_head_hash=$1,authority_time_floor_us=$2 WHERE scope_kind=$3 AND scope_id=$4 AND authority_epoch=$5 AND next_audit_sequence=$6 AND audit_head_hash=$7 AND authority_time_floor_us=$8`, digest[:], timeMicros(state.authorityTime), string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.spec.AuthorityEpoch().String(), state.stream.nextAudit, state.stream.auditHead[:], state.stream.timeFloor)
	if err != nil {
		return fmt.Errorf("advance PostgreSQL security audit head: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: PostgreSQL audit-head compare-and-swap", application.ErrInvalidSecurityContext)
	}
	return nil
}

func microsTime(value int64) time.Time        { return time.UnixMicro(value).UTC() }
func timeMicros(value time.Time) int64        { return value.UTC().UnixMicro() }
func mustVersion(value uint64) domain.Version { version, _ := domain.NewVersion(value); return version }
