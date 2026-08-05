package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

var ErrOrchestrationDependency = errors.New("application orchestration dependency failed")

// AuthenticationRequest and PolicyPreparationRequest contain only routing and
// operation metadata. Command bodies never provide trusted identity evidence.
type AuthenticationRequest struct {
	Operation CommandOperation
	Scope     domain.AuthorityScope
}

type PolicyPreparationRequest struct {
	Operation CommandOperation
	Scope     domain.AuthorityScope
}

type AuthenticationEvidence struct {
	principal  domain.PrincipalID
	device     domain.DeviceID
	hasDevice  bool
	provenance AuditProvenanceEvidence
}

type AuthenticationDecisionKind string

const (
	AuthenticationValid    AuthenticationDecisionKind = "valid"
	AuthenticationRejected AuthenticationDecisionKind = "cryptographically_rejected"
)

type AuthenticationDecision struct {
	kind            AuthenticationDecisionKind
	evidence        AuthenticationEvidence
	rejection       *domain.CommandError
	subject         DenialSubject
	auditProvenance AuditProvenanceEvidence
}

func ValidAuthentication(evidence AuthenticationEvidence) (AuthenticationDecision, error) {
	if evidence.principal.IsZero() {
		return AuthenticationDecision{}, ErrInvalidApplicationContract
	}
	return AuthenticationDecision{
		kind: AuthenticationValid, evidence: evidence, auditProvenance: evidence.provenance,
	}, nil
}

func RejectedAuthentication(
	rejection *domain.CommandError,
	subject DenialSubject,
	provenance AuditProvenanceEvidence,
) (AuthenticationDecision, error) {
	if rejection == nil || !requiresDenialAudit(rejection) ||
		(subject.kind != DenialAttributedSubject && subject.kind != DenialUnattributedSource) ||
		!validAuditProvenanceEvidence(provenance) {
		return AuthenticationDecision{}, ErrInvalidApplicationContract
	}
	return AuthenticationDecision{
		kind: AuthenticationRejected, rejection: rejection, subject: subject, auditProvenance: provenance,
	}, nil
}

func (decision AuthenticationDecision) Kind() AuthenticationDecisionKind { return decision.kind }
func (decision AuthenticationDecision) Evidence() (AuthenticationEvidence, bool) {
	return decision.evidence, decision.kind == AuthenticationValid
}
func (decision AuthenticationDecision) Rejection() (*domain.CommandError, DenialSubject, bool) {
	return decision.rejection, decision.subject, decision.kind == AuthenticationRejected
}
func (decision AuthenticationDecision) provenance() AuditProvenanceEvidence {
	return decision.auditProvenance
}

func NewAuthenticationEvidence(
	principal domain.PrincipalID,
	device *domain.DeviceID,
	provenance AuditProvenanceEvidence,
) (AuthenticationEvidence, error) {
	if principal.IsZero() || !validAuditProvenanceEvidence(provenance) {
		return AuthenticationEvidence{}, ErrInvalidApplicationContract
	}
	evidence := AuthenticationEvidence{principal: principal, provenance: provenance}
	if device != nil {
		if device.IsZero() {
			return AuthenticationEvidence{}, ErrInvalidApplicationContract
		}
		evidence.device, evidence.hasDevice = *device, true
	}
	return evidence, nil
}

func (evidence AuthenticationEvidence) PrincipalID() domain.PrincipalID { return evidence.principal }
func (evidence AuthenticationEvidence) DeviceID() (domain.DeviceID, bool) {
	return evidence.device, evidence.hasDevice
}
func (evidence AuthenticationEvidence) AuditProvenance() AuditProvenanceEvidence {
	return evidence.provenance
}

type PreparedPolicy struct {
	revision domain.PolicyRevision
	digest   Digest
}

func NewPreparedPolicy(revision domain.PolicyRevision, digest Digest) (PreparedPolicy, error) {
	if revision.String() == "" || digest.IsZero() {
		return PreparedPolicy{}, ErrInvalidApplicationContract
	}
	return PreparedPolicy{revision: revision, digest: digest}, nil
}

func (policy PreparedPolicy) Revision() domain.PolicyRevision { return policy.revision }
func (policy PreparedPolicy) Digest() Digest                  { return policy.digest }

// The preparation ports may perform external I/O. The evaluation ports are
// deliberately context-free and may only inspect immutable prepared material
// and the locked CommandContext supplied by the UoW.
type AuthenticationPreparer interface {
	PrepareAuthentication(context.Context, AuthenticationRequest) (AuthenticationDecision, error)
}

type PolicyPreparer interface {
	PreparePolicy(context.Context, PolicyPreparationRequest) (PreparedPolicy, error)
}

type CurrentLockedAuthorization interface {
	AuthorizeLocked(CommandContext, AuthenticationEvidence, PreparedPolicy) (domain.IdentityAuthorization, error)
}

type ReplayDisclosureAuthorization interface {
	AuthorizeReplay(CommandContext, AuthenticationEvidence, PreparedPolicy) (ReplayDisclosure, error)
}

type DenialSecurityPolicy interface {
	DenialFollowUp(CommandContext, AuthenticationEvidence, PreparedPolicy, *domain.CommandError) (SecuritySpec, error)
}

type PresentationCredentialPreparer interface {
	PreparePresentationCredential(context.Context, CommandOperation) (domain.PresentationCredentialBinding, error)
}

type RecoveryCapsuleSignerLookup interface {
	PrepareRecoveryCapsuleSigner(context.Context, string) (PreparedRecoveryCapsuleSigner, error)
}

type BootstrapProofEvidence struct{ opaque []byte }

func NewBootstrapProofEvidence(opaque []byte) (BootstrapProofEvidence, error) {
	if len(opaque) == 0 || len(opaque) > MaxRecoveryCapsuleBytes {
		return BootstrapProofEvidence{}, ErrInvalidApplicationContract
	}
	return BootstrapProofEvidence{opaque: append([]byte(nil), opaque...)}, nil
}

func (evidence BootstrapProofEvidence) Bytes() []byte { return append([]byte(nil), evidence.opaque...) }

func (evidence BootstrapProofEvidence) valid() bool {
	return len(evidence.opaque) > 0 && len(evidence.opaque) <= MaxRecoveryCapsuleBytes
}

type BootstrapProofVerification struct {
	decision ProofDecision[domain.BootstrapProof]
	attempt  BootstrapAttempt
}

func VerifiedBootstrapProof(proof domain.BootstrapProof) BootstrapProofVerification {
	return BootstrapProofVerification{decision: ValidProof(proof)}
}

func RejectedBootstrapProof(attempt BootstrapAttempt) BootstrapProofVerification {
	if attempt.Fingerprint().IsZero() {
		return BootstrapProofVerification{}
	}
	return BootstrapProofVerification{decision: CryptographicallyRejectedProof[domain.BootstrapProof](), attempt: attempt}
}

func (verification BootstrapProofVerification) Decision() ProofDecisionKind {
	return verification.decision.Kind()
}

type BootstrapProofVerifier interface {
	VerifyBootstrapProof(context.Context, BootstrapProofEvidence) (BootstrapProofVerification, error)
}

type CeremonyProofEvidence struct{ opaque []byte }

func NewCeremonyProofEvidence(opaque []byte) (CeremonyProofEvidence, error) {
	if len(opaque) == 0 || len(opaque) > MaxRecoveryCapsuleBytes {
		return CeremonyProofEvidence{}, ErrInvalidApplicationContract
	}
	return CeremonyProofEvidence{opaque: append([]byte(nil), opaque...)}, nil
}

func (evidence CeremonyProofEvidence) Bytes() []byte { return append([]byte(nil), evidence.opaque...) }

func (evidence CeremonyProofEvidence) valid() bool {
	return len(evidence.opaque) > 0 && len(evidence.opaque) <= MaxRecoveryCapsuleBytes
}

// CeremonyProofVerifier exposes closed, purpose-specific verification entry
// points so callers cannot select or manufacture a trusted proof purpose.
type CeremonyProofVerification struct {
	decision ProofDecision[domain.CeremonyProof]
	subject  DenialSubject
}

func ValidCeremonyProof(proof domain.CeremonyProof) (CeremonyProofVerification, error) {
	decision := ValidProof(proof)
	if decision.Kind() != ProofValid {
		return CeremonyProofVerification{}, ErrInvalidApplicationContract
	}
	return CeremonyProofVerification{decision: decision}, nil
}

func RejectedCeremonyProof(subject DenialSubject) (CeremonyProofVerification, error) {
	if subject.kind != DenialAttributedSubject && subject.kind != DenialUnattributedSource {
		return CeremonyProofVerification{}, ErrInvalidApplicationContract
	}
	return CeremonyProofVerification{
		decision: CryptographicallyRejectedProof[domain.CeremonyProof](), subject: subject,
	}, nil
}

func (verification CeremonyProofVerification) Verified() (domain.CeremonyProof, bool) {
	return verification.decision.Verified()
}
func (verification CeremonyProofVerification) RejectionSubject() (DenialSubject, bool) {
	return verification.subject, verification.decision.Kind() == ProofCryptographicallyRejected
}

type CeremonyProofVerifier interface {
	VerifyMembershipAcceptance(context.Context, CeremonyProofEvidence) (CeremonyProofVerification, error)
	VerifyDelegationActivation(context.Context, CeremonyProofEvidence) (CeremonyProofVerification, error)
	VerifyActorSessionHandoff(context.Context, CeremonyProofEvidence) (CeremonyProofVerification, error)
}

type PairingRedemptionVerification struct {
	authorization domain.PairingRedemptionAuthorization
	proof         domain.CeremonyProof
}

func NewPairingRedemptionVerification(
	authorization domain.PairingRedemptionAuthorization,
	proof domain.CeremonyProof,
) (PairingRedemptionVerification, error) {
	if proof.Purpose() != domain.CeremonyPurposeDevicePairing ||
		authorization.PrincipalID() != proof.PrincipalID() || authorization.DeviceID() != proof.DeviceID() ||
		authorization.ChallengeID() != proof.ChallengeID() || authorization.TranscriptFingerprint() != proof.ProofDigest() ||
		authorization.Credential().TranscriptFingerprint() != proof.ProofDigest() {
		return PairingRedemptionVerification{}, ErrInvalidApplicationContract
	}
	return PairingRedemptionVerification{authorization: authorization, proof: proof}, nil
}

func (verification PairingRedemptionVerification) Authorization() domain.PairingRedemptionAuthorization {
	return verification.authorization
}

func (verification PairingRedemptionVerification) Proof() domain.CeremonyProof {
	return verification.proof
}

type PairingRedemptionVerifier interface {
	VerifyPairingRedemption(context.Context, CeremonyProofEvidence) (PairingRedemptionDecision, error)
}

type PairingRedemptionDecision struct {
	verification PairingRedemptionVerification
	valid        bool
	subject      DenialSubject
}

func ValidPairingRedemption(verification PairingRedemptionVerification) (PairingRedemptionDecision, error) {
	if verification.authorization.PrincipalID().IsZero() || verification.proof.ChallengeID().IsZero() {
		return PairingRedemptionDecision{}, ErrInvalidApplicationContract
	}
	return PairingRedemptionDecision{verification: verification, valid: true}, nil
}

func RejectedPairingRedemption(subject DenialSubject) (PairingRedemptionDecision, error) {
	if subject.kind != DenialAttributedSubject && subject.kind != DenialUnattributedSource {
		return PairingRedemptionDecision{}, ErrInvalidApplicationContract
	}
	return PairingRedemptionDecision{subject: subject}, nil
}

func (decision PairingRedemptionDecision) Verified() (PairingRedemptionVerification, bool) {
	return decision.verification, decision.valid
}
func (decision PairingRedemptionDecision) RejectionSubject() (DenialSubject, bool) {
	return decision.subject, !decision.valid &&
		(decision.subject.kind == DenialAttributedSubject || decision.subject.kind == DenialUnattributedSource)
}

type OrchestrationService struct {
	uow                 UnitOfWork
	authentication      AuthenticationPreparer
	policy              PolicyPreparer
	lockedAuthorization CurrentLockedAuthorization
	replayDisclosure    ReplayDisclosureAuthorization
	denialPolicy        DenialSecurityPolicy
	signers             RecoveryCapsuleSignerLookup
	effects             EffectPlanner
	bootstrapProofs     BootstrapProofVerifier
	ceremonyProofs      CeremonyProofVerifier
	pairingRedemptions  PairingRedemptionVerifier
	presentations       PresentationCredentialPreparer
}

type OrchestrationDependencies struct {
	UnitOfWork          UnitOfWork
	Authentication      AuthenticationPreparer
	Policy              PolicyPreparer
	LockedAuthorization CurrentLockedAuthorization
	ReplayDisclosure    ReplayDisclosureAuthorization
	DenialPolicy        DenialSecurityPolicy
	SignerLookup        RecoveryCapsuleSignerLookup
	EffectPlanner       EffectPlanner
	BootstrapProofs     BootstrapProofVerifier
	CeremonyProofs      CeremonyProofVerifier
	PairingRedemptions  PairingRedemptionVerifier
	Presentations       PresentationCredentialPreparer
}

type QueryService struct {
	store QueryStore
	ids   CheckpointIDSource
}

func NewQueryService(store QueryStore, ids CheckpointIDSource) (*QueryService, error) {
	if isNilInterface(store) || isNilInterface(ids) {
		return nil, ErrInvalidQuery
	}
	return &QueryService{store: store, ids: ids}, nil
}

func (service *QueryService) GetContext(ctx context.Context, subject QuerySubject) (ContextCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return ContextCheckpoint{}, err
	}
	id, err := service.ids.NewCheckpointID()
	if err != nil {
		return ContextCheckpoint{}, fmt.Errorf("%w: allocate context checkpoint: %w", ErrOrchestrationDependency, err)
	}
	query, err := NewContextGetQuery(subject, id)
	if err != nil {
		return ContextCheckpoint{}, err
	}
	return service.store.GetContext(ctx, query)
}

func (service *QueryService) SyncEvents(ctx context.Context, subject QuerySubject, after EventCursor, limit uint16) (EventsPage, error) {
	if err := ctx.Err(); err != nil {
		return EventsPage{}, err
	}
	query, err := NewEventsSyncQuery(subject, after, limit)
	if err != nil {
		return EventsPage{}, err
	}
	return service.store.SyncEvents(ctx, query)
}

func NewOrchestrationService(dependencies OrchestrationDependencies) (*OrchestrationService, error) {
	if isNilInterface(dependencies.UnitOfWork) || isNilInterface(dependencies.Authentication) ||
		isNilInterface(dependencies.Policy) || isNilInterface(dependencies.LockedAuthorization) ||
		isNilInterface(dependencies.ReplayDisclosure) || isNilInterface(dependencies.DenialPolicy) ||
		isNilInterface(dependencies.SignerLookup) || isNilInterface(dependencies.EffectPlanner) ||
		isNilInterface(dependencies.BootstrapProofs) || isNilInterface(dependencies.CeremonyProofs) ||
		isNilInterface(dependencies.PairingRedemptions) || isNilInterface(dependencies.Presentations) {
		return nil, ErrInvalidApplicationContract
	}
	return &OrchestrationService{
		uow: dependencies.UnitOfWork, authentication: dependencies.Authentication, policy: dependencies.Policy,
		lockedAuthorization: dependencies.LockedAuthorization, replayDisclosure: dependencies.ReplayDisclosure,
		denialPolicy: dependencies.DenialPolicy, signers: dependencies.SignerLookup,
		effects: dependencies.EffectPlanner, bootstrapProofs: dependencies.BootstrapProofs,
		ceremonyProofs: dependencies.CeremonyProofs, pairingRedemptions: dependencies.PairingRedemptions,
		presentations: dependencies.Presentations,
	}, nil
}

type CommandRequest struct {
	Spec                 CommandSpec
	HashView             CommandHashView
	Authentication       AuthenticationRequest
	Policy               PolicyPreparationRequest
	Audit                AuditRequestContext
	ProtocolCapabilities []string
}

type transitionDecision func(
	CommandContext,
	domain.IdentityAuthorization,
	AuthenticationEvidence,
	PreparedPolicy,
) (OperationCommit, error)

func (service *OrchestrationService) executeCommand(
	ctx context.Context,
	request CommandRequest,
	expected CommandOperation,
	transition transitionDecision,
) (CommandExecution, error) {
	if err := validateCommandRequest(request, expected); err != nil {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	authenticationDecision, err := service.authentication.PrepareAuthentication(ctx, request.Authentication)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: authentication preparation: %w", ErrOrchestrationDependency, err)
	}
	policy, err := service.policy.PreparePolicy(ctx, request.Policy)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: policy preparation: %w", ErrOrchestrationDependency, err)
	}
	if authentication, valid := authenticationDecision.Evidence(); valid {
		return service.executePreparedCommand(ctx, request, authentication, policy, transition)
	}
	rejection, subject, rejected := authenticationDecision.Rejection()
	if !rejected {
		return CommandExecution{}, ErrInvalidApplicationContract
	}
	return service.executePreTransactionDenial(ctx, request, policy, rejection, subject, authenticationDecision.provenance())
}

func (service *OrchestrationService) executePreTransactionDenial(
	ctx context.Context,
	request CommandRequest,
	policy PreparedPolicy,
	rejection *domain.CommandError,
	subject DenialSubject,
	provenance AuditProvenanceEvidence,
) (CommandExecution, error) {
	if rejection == nil || !requiresDenialAudit(rejection) {
		return CommandExecution{}, ErrInvalidApplicationContract
	}
	spec := request.Spec
	major := spec.OperationMajor()
	draft, err := NewCommandDenialDraft(
		spec.Operation(), major, DenialAuthentication, "credential_rejected",
		spec.RequestFingerprint(), subject, &policy.revision, spec.CorrelationID(),
	)
	if err != nil {
		return CommandExecution{}, err
	}
	security, err := RecordCommandDenialSecurity(
		spec.Scope(), spec.AuthorityID(), spec.RequestedEpoch(), spec.Guards().AdmissionGeneration(), draft,
	)
	if err != nil {
		return CommandExecution{}, err
	}
	security, err = bindSecurityAuditContext(security, request.Audit, provenance)
	if err != nil {
		return CommandExecution{}, err
	}
	if err = service.executeCommandDenial(ctx, security); err != nil {
		return CommandExecution{}, err
	}
	return RejectedCommandExecution(rejection)
}

func (service *OrchestrationService) executeProofDenial(
	ctx context.Context,
	request CommandRequest,
	subject DenialSubject,
) (CommandExecution, error) {
	policy, err := service.policy.PreparePolicy(ctx, request.Policy)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: policy preparation: %w", ErrOrchestrationDependency, err)
	}
	provenance, err := NewAuditProvenanceEvidence(request.Spec.AuthorityID(), nil)
	if err != nil {
		return CommandExecution{}, ErrInvalidApplicationContract
	}
	return service.executePreTransactionDenial(
		ctx, request, policy, mustCommandError(domain.ErrorCodeUnauthenticated, "proof rejected"), subject,
		provenance,
	)
}

func (service *OrchestrationService) executePreparedCommand(
	ctx context.Context,
	request CommandRequest,
	authentication AuthenticationEvidence,
	policy PreparedPolicy,
	transition transitionDecision,
) (CommandExecution, error) {
	signer, signerErr := service.prepareSigner(ctx, request.Spec)
	var expectedDecision CommandDecision

	transaction, transactionErr := service.uow.ExecuteCommand(ctx, request.Spec, func(locked CommandContext) (decision CommandDecision, decisionErr error) {
		defer func() {
			if decisionErr == nil {
				expectedDecision = decision
			}
		}()
		switch locked.ReceiptResolution().Kind() {
		case ReceiptExactReplay:
			disclosure, disclosureErr := service.replayDisclosure.AuthorizeReplay(locked, authentication, policy)
			if disclosureErr != nil {
				return service.rollbackDecision(request, locked, authentication, policy, disclosureErr)
			}
			return ReplayCommand(locked, disclosure)
		case ReceiptCommandIDConflict:
			return RollbackCommand(locked, mustCommandError(domain.ErrorCodeCommandIDReused, "command identity was reused"))
		case ReceiptIdempotencyConflict:
			return RollbackCommand(locked, mustCommandError(domain.ErrorCodeIdempotencyKeyReused, "idempotency identity was reused"))
		case ReceiptInProgress:
			return RollbackCommand(locked, mustCommandError(domain.ErrorCodeCommandInProgress, "command is in progress"))
		case ReceiptIntegrityConflict:
			return RollbackCommand(locked, mustCommandError(domain.ErrorCodeInternal, "receipt integrity conflict"))
		case ReceiptAdmitted:
		default:
			return CommandDecision{}, ErrInvalidCommandContext
		}
		if signerErr != nil {
			return CommandDecision{}, signerErr
		}

		authorization, authorizationErr := service.lockedAuthorization.AuthorizeLocked(locked, authentication, policy)
		if authorizationErr != nil {
			return service.rollbackDecision(request, locked, authentication, policy, authorizationErr)
		}
		if !authorizationMatchesCommand(authorization, authentication, policy, request.Spec, locked) {
			return CommandDecision{}, ErrInvalidApplicationContract
		}
		commit, transitionErr := transition(locked, authorization, authentication, policy)
		if transitionErr != nil {
			return service.rollbackDecision(request, locked, authentication, policy, transitionErr)
		}
		audit, auditErr := NewAuditIntent(
			request.Spec.Operation(), AuditCommandApplied, request.Spec.RequestFingerprint(), CommandAppliedAuditDetail(),
		)
		if auditErr != nil {
			return CommandDecision{}, auditErr
		}
		audit = bindCommandAuditContext(audit, request, authentication)
		planningInput, planningErr := NewEffectPlanningInput(request.Spec.CommandID(), commit.facts)
		if planningErr != nil {
			return CommandDecision{}, planningErr
		}
		effects, planningErr := service.effects.PlanEffects(planningInput)
		if planningErr != nil {
			return CommandDecision{}, planningErr
		}
		return ApplyCommand(locked, commit, audit, effects)
	})
	if err := ValidateCommandTransactionResult(transaction, transactionErr); err != nil {
		return CommandExecution{}, err
	}
	if transactionErr != nil {
		return CommandExecution{}, transactionErr
	}
	if !transactionMatchesDecision(request.Spec, transaction, expectedDecision) {
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	return service.finishCommand(ctx, transaction, signer)
}

func authorizationMatchesCommand(
	authorization domain.IdentityAuthorization,
	authentication AuthenticationEvidence,
	policy PreparedPolicy,
	spec CommandSpec,
	locked CommandContext,
) bool {
	if authentication.principal != spec.authorship.principal ||
		authorization.PrincipalID() != authentication.principal ||
		authorization.AuthorityID() != spec.authorityID || authorization.AuthorityEpoch() != spec.requestedEpoch ||
		authorization.PolicyRevision() != policy.revision || !authorshipGuardsMatch(spec) {
		return false
	}
	authorityTime, present := locked.AuthorityTime()
	if !present || !authorization.EvaluatedAt().Equal(authorityTime) {
		return false
	}
	authorizationScope := spec.guards.admissionScope
	switch authorizationScope.Kind() {
	case domain.ScopeKindInstallation:
		if authorization.InstallationID().String() != authorizationScope.ID() || !authorization.WorkspaceID().IsZero() {
			return false
		}
	case domain.ScopeKindWorkspace:
		if authorization.WorkspaceID().String() != authorizationScope.ID() || authorization.InstallationID().IsZero() {
			return false
		}
	default:
		return false
	}
	device, _, hasDevice := authorization.AuthenticatedDevice()
	return hasDevice == authentication.hasDevice && (!hasDevice || device == authentication.device)
}

func authorshipGuardsMatch(spec CommandSpec) bool {
	if !spec.authorship.hasActor {
		return true
	}
	var actor, session bool
	for _, guard := range spec.guards.evidence {
		if guard.kind != EvidenceLifecycleStatus {
			continue
		}
		actor = actor || guard.targetKind == string(domain.AggregateKindActor) &&
			guard.targetID == spec.authorship.actor.String()
		session = session || guard.targetKind == string(domain.AggregateKindActorSession) &&
			guard.targetID == spec.authorship.actorSession.String()
	}
	return actor && session
}

func authenticatedAuditSubject(authentication AuthenticationEvidence, spec CommandSpec) AuditSubject {
	subject := AuditSubject{kind: AuditSubjectAttributed, principal: authentication.principal}
	if authentication.hasDevice {
		subject.device, subject.hasDevice = authentication.device, true
	}
	if spec.authorship.hasActor {
		subject.actor, subject.actorSession, subject.hasActor =
			spec.authorship.actor, spec.authorship.actorSession, true
	}
	return subject
}

func bindCommandAuditContext(
	audit AuditIntent,
	request CommandRequest,
	authentication AuthenticationEvidence,
) AuditIntent {
	audit.invocation.requestID = &request.Audit.requestID
	audit.invocation.traceID = &request.Audit.traceID
	audit.timing.serverReceivedTime = ptrTime(request.Audit.serverReceived)
	if request.Audit.hasClientTime {
		audit.timing.clientTime = ptrTime(request.Audit.clientTime)
	}
	audit.subject = authenticatedAuditSubject(authentication, request.Spec)
	audit.provenance = AuditProvenance{
		sourceAuthority:    authentication.provenance.sourceAuthority,
		federationEnvelope: cloneCanonicalIdentifier(authentication.provenance.federationEnvelope),
	}
	return audit
}

// BindCommandAuditContext attaches trusted transport and authentication
// evidence to a command audit seed before the transaction finalizes it.
func BindCommandAuditContext(
	audit AuditIntent,
	spec CommandSpec,
	request AuditRequestContext,
	authentication AuthenticationEvidence,
) (AuditIntent, error) {
	if spec.commandID.IsZero() || audit.operation != spec.operation || audit.fingerprint != spec.requestFingerprint ||
		!validAuditRequestContext(request) || !validAuditProvenanceEvidence(authentication.provenance) ||
		authentication.principal != spec.authorship.principal {
		return AuditIntent{}, ErrInvalidApplicationContract
	}
	return bindCommandAuditContext(audit, CommandRequest{Spec: spec, Audit: request}, authentication), nil
}

func transactionMatchesDecision(
	spec CommandSpec,
	execution CommandTransactionExecution,
	decision CommandDecision,
) bool {
	switch execution.kind {
	case CommandTransactionCommitted:
		return decision.kind == CommandDecisionApplied && receiptMatchesCommittedSpec(execution.receipt, spec)
	case CommandTransactionReplayed:
		if decision.kind != CommandDecisionReplay || execution.disclosure != decision.disclosure {
			return false
		}
		if execution.disclosure == ReplayDiscloseAppliedOnly {
			return execution.appliedOnly == decision.appliedOnly
		}
		return sameReceiptSnapshot(execution.receipt, decision.replay)
	case CommandTransactionRejected:
		return decision.kind == CommandDecisionRollback && execution.rejection == decision.rejection &&
			sameCommandDenialSpec(execution.denialAudit, decision.denialAudit)
	case CommandTransactionIndeterminate:
		return decision.kind == CommandDecisionApplied
	default:
		return false
	}
}

func receiptMatchesCommittedSpec(receipt ReceiptSnapshot, spec CommandSpec) bool {
	return receipt.receiptID == spec.receiptID && receipt.commandID == spec.commandID &&
		receipt.identity == spec.receiptIdentity && receipt.requestFingerprint == spec.requestFingerprint &&
		receipt.capsuleRequirement == spec.recoveryCapsule.requirement
}

func sameReceiptSnapshot(left, right ReceiptSnapshot) bool {
	return left.receiptID == right.receiptID && left.commandID == right.commandID && left.identity == right.identity &&
		left.requestFingerprint == right.requestFingerprint && left.result.responseDigest == right.result.responseDigest &&
		left.authorityID == right.authorityID && left.authorityEpoch == right.authorityEpoch &&
		left.guardDigest == right.guardDigest && left.events == right.events &&
		left.capsuleRequirement == right.capsuleRequirement && left.hasRecoveryCapsule == right.hasRecoveryCapsule &&
		(!left.hasRecoveryCapsule || (left.recoveryCapsule.digest == right.recoveryCapsule.digest &&
			left.recoveryCapsule.resultDigest == right.recoveryCapsule.resultDigest &&
			left.recoveryCapsule.keyID == right.recoveryCapsule.keyID &&
			bytes.Equal(left.recoveryCapsule.canonical, right.recoveryCapsule.canonical)))
}

func sameCommandDenialSpec(left, right SecuritySpec) bool {
	if left.operation == "" && right.operation == "" {
		return true
	}
	return left.operation == SecurityRecordCommandDenial && right.operation == SecurityRecordCommandDenial &&
		left.scope == right.scope && left.authorityID == right.authorityID && left.epoch == right.epoch &&
		left.admission == right.admission && left.commandDenial.operation == right.commandDenial.operation &&
		left.commandDenial.operationMajor == right.commandDenial.operationMajor &&
		left.commandDenial.class == right.commandDenial.class && left.commandDenial.reason == right.commandDenial.reason &&
		left.commandDenial.requestFingerprint == right.commandDenial.requestFingerprint &&
		left.commandDenial.denialFingerprint == right.commandDenial.denialFingerprint &&
		left.commandDenial.subject == right.commandDenial.subject && left.commandDenial.policy == right.commandDenial.policy &&
		left.commandDenial.hasPolicy == right.commandDenial.hasPolicy &&
		left.commandDenial.correlation == right.commandDenial.correlation &&
		left.hasAuditContext == right.hasAuditContext && left.auditRequest == right.auditRequest &&
		left.provenance.sourceAuthority == right.provenance.sourceAuthority &&
		canonicalIdentifierEqual(left.provenance.federationEnvelope, right.provenance.federationEnvelope)
}

func canonicalIdentifierEqual(left, right *CanonicalIdentifier) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func (service *OrchestrationService) executeBootstrapCommand(
	ctx context.Context,
	request CommandRequest,
	authentication AuthenticationEvidence,
	transition func(CommandContext) (OperationCommit, error),
) (CommandExecution, error) {
	policy, err := service.policy.PreparePolicy(ctx, request.Policy)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: policy preparation: %w", ErrOrchestrationDependency, err)
	}
	signer, signerErr := service.prepareSigner(ctx, request.Spec)
	var expectedDecision CommandDecision
	transaction, transactionErr := service.uow.ExecuteCommand(ctx, request.Spec, func(locked CommandContext) (decision CommandDecision, decisionErr error) {
		defer func() {
			if decisionErr == nil {
				expectedDecision = decision
			}
		}()
		switch locked.ReceiptResolution().Kind() {
		case ReceiptExactReplay:
			disclosure, disclosureErr := service.replayDisclosure.AuthorizeReplay(locked, authentication, policy)
			if disclosureErr != nil {
				return service.rollbackDecision(request, locked, authentication, policy, disclosureErr)
			}
			return ReplayCommand(locked, disclosure)
		case ReceiptCommandIDConflict:
			return RollbackCommand(locked, mustCommandError(domain.ErrorCodeCommandIDReused, "command identity was reused"))
		case ReceiptIdempotencyConflict:
			return RollbackCommand(locked, mustCommandError(domain.ErrorCodeIdempotencyKeyReused, "idempotency identity was reused"))
		case ReceiptInProgress:
			return RollbackCommand(locked, mustCommandError(domain.ErrorCodeCommandInProgress, "command is in progress"))
		case ReceiptIntegrityConflict:
			return RollbackCommand(locked, mustCommandError(domain.ErrorCodeInternal, "receipt integrity conflict"))
		case ReceiptAdmitted:
		default:
			return CommandDecision{}, ErrInvalidCommandContext
		}
		if signerErr != nil {
			return CommandDecision{}, signerErr
		}
		commit, transitionErr := transition(locked)
		if transitionErr != nil {
			return service.rollbackDecision(request, locked, authentication, policy, transitionErr)
		}
		audit, auditErr := NewAuditIntent(
			request.Spec.Operation(), AuditCommandApplied, request.Spec.RequestFingerprint(), CommandAppliedAuditDetail(),
		)
		if auditErr != nil {
			return CommandDecision{}, auditErr
		}
		audit = bindCommandAuditContext(audit, request, authentication)
		planningInput, planningErr := NewEffectPlanningInput(request.Spec.CommandID(), commit.facts)
		if planningErr != nil {
			return CommandDecision{}, planningErr
		}
		effects, planningErr := service.effects.PlanEffects(planningInput)
		if planningErr != nil {
			return CommandDecision{}, planningErr
		}
		return ApplyCommand(locked, commit, audit, effects)
	})
	if err := ValidateCommandTransactionResult(transaction, transactionErr); err != nil {
		return CommandExecution{}, err
	}
	if transactionErr != nil {
		return CommandExecution{}, transactionErr
	}
	if !transactionMatchesDecision(request.Spec, transaction, expectedDecision) {
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	return service.finishCommand(ctx, transaction, signer)
}

func validateCommandRequest(request CommandRequest, expected CommandOperation) error {
	if request.Spec.CommandOperation() != expected || request.Authentication.Operation != expected ||
		request.Policy.Operation != expected || request.Authentication.Scope != request.Spec.Scope() ||
		request.Policy.Scope != request.Spec.Scope() || !validAuditRequestContext(request.Audit) ||
		!commandHashViewMatches(expected, request.HashView) {
		return ErrInvalidCommandSpec
	}
	fingerprint, err := NewProductionCanonicalCodec().HashCommand(request.HashView)
	if err != nil || fingerprint != request.Spec.RequestFingerprint() {
		return ErrInvalidCommandSpec
	}
	command, ok := commandHashContextOf(request.HashView)
	if !ok || !commandContextMatches(request, command) {
		return ErrInvalidCommandSpec
	}
	return nil
}

func commandHashContextOf(view CommandHashView) (commandHashContextWire, bool) {
	switch value := view.(type) {
	case bootstrapInstallationCommandHashView:
		return value.Command, true
	case registerPrincipalCommandHashView:
		return value.Command, true
	case createWorkspaceCommandHashView:
		return value.Command, true
	case inviteWorkspaceMemberCommandHashView:
		return value.Command, true
	case acceptWorkspaceMembershipCommandHashView:
		return value.Command, true
	case createActorCommandHashView:
		return value.Command, true
	case proposeActorDelegationCommandHashView:
		return value.Command, true
	case activateActorDelegationCommandHashView:
		return value.Command, true
	case beginDevicePairingCommandHashView:
		return value.Command, true
	case pairDeviceCommandHashView:
		return value.Command, true
	case startActorSessionCommandHashView:
		return value.Command, true
	default:
		return commandHashContextWire{}, false
	}
}

func commandContextMatches(request CommandRequest, command commandHashContextWire) bool {
	spec := request.Spec
	authorship := spec.Authorship()
	if command.ScopeKind != StreamScopeKind(spec.Scope().Kind()) || command.ScopeID.String() != spec.Scope().ID() ||
		command.PrincipalID == nil || command.PrincipalID.String() != authorship.PrincipalID().String() ||
		command.CorrelationID.String() != spec.CorrelationID().String() {
		return false
	}
	client := spec.ReceiptIdentity().ClientInstanceID().String()
	if (command.ClientInstanceID == nil) != (client == "") || command.ClientInstanceID != nil && command.ClientInstanceID.String() != client {
		return false
	}
	attribution, attributed := authorship.ActorAttribution()
	if attributed {
		if command.ActorID == nil || command.ActorSessionID == nil ||
			command.ActorID.String() != attribution.ActorID().String() ||
			command.ActorSessionID.String() != attribution.ActorSessionID().String() {
			return false
		}
	} else if command.ActorID != nil || command.ActorSessionID != nil {
		return false
	}
	cause, caused := spec.CausationEventID()
	if caused {
		if command.CausationEventID == nil || command.CausationEventID.String() != cause.String() {
			return false
		}
	} else if command.CausationEventID != nil {
		return false
	}
	capabilities, err := canonicalStringSet(request.ProtocolCapabilities)
	return err == nil && slices.Equal(command.ProtocolCapabilities, capabilities)
}

type resourceBinding uint8

const (
	resourceAuthorization resourceBinding = iota + 1
	resourceReference
	resourceMutation
)

func expectedResourceMatches(spec CommandSpec, resource CommandExpectedResource, kind domain.AggregateKind, binding resourceBinding) bool {
	if !validCommandResource(resource) {
		return false
	}
	matchRef := func(ref domain.AggregateRef) bool {
		return ref.Kind() == kind && ref.ID() == resource.ID.String() && ref.Version().Uint64() == resource.ExpectedVersion
	}
	switch binding {
	case resourceAuthorization:
		for _, ref := range spec.Guards().Authorization() {
			if matchRef(ref) {
				return true
			}
		}
	case resourceReference:
		for _, ref := range spec.Guards().References() {
			if matchRef(ref) {
				return true
			}
		}
	case resourceMutation:
		for _, expectation := range spec.Guards().Mutations() {
			version, present := expectation.Version()
			if present && expectation.Target().Kind() == kind && expectation.Target().ID() == resource.ID.String() &&
				version.Uint64() == resource.ExpectedVersion {
				return true
			}
		}
	}
	return false
}

func mutationTargetMatches(spec CommandSpec, id string, kind domain.AggregateKind, expectationKind domain.ExpectationKind) bool {
	for _, expectation := range spec.Guards().Mutations() {
		if expectation.Kind() == expectationKind && expectation.Target().Kind() == kind && expectation.Target().ID() == id {
			return true
		}
	}
	return false
}

func challengeMatches(spec CommandSpec, wire CommandCeremony, challenge domain.CeremonyChallenge, creation domain.CeremonyCreationExpectation) bool {
	expectedCreation, err := domain.ExpectCeremonyAbsent(challenge.ID())
	if err != nil || creation != expectedCreation || wire.ID.String() != challenge.ID().String() ||
		!wire.ExpiresAt.Time().Equal(challenge.ExpiresAt()) || wire.ProofDigest.String() != Digest(challenge.ProofDigest()).String() {
		return false
	}
	for _, claim := range spec.Guards().Ceremonies() {
		if claim.Kind() == CeremonyReserveAbsent && claim.challenge == challenge {
			return true
		}
	}
	return false
}

func proofMatches(spec CommandSpec, wire CommandCeremony, proof domain.CeremonyProof) bool {
	if wire.ID.String() != proof.ChallengeID().String() || wire.ProofDigest.String() != Digest(proof.ProofDigest()).String() {
		return false
	}
	for _, claim := range spec.Guards().Ceremonies() {
		if claim.Kind() == CeremonyConsumeEmbedded && claim.ID() == proof.ChallengeID() &&
			claim.Purpose() == proof.Purpose() && claim.ProofFingerprint() == proof.ProofDigest() {
			return true
		}
	}
	return false
}

func capabilitySetMatches(wire []string, set domain.CapabilitySet) bool {
	canonical, err := canonicalCapabilitySet(capabilityStrings(set))
	return err == nil && slices.Equal(wire, canonical)
}

func (service *OrchestrationService) prepareSigner(
	ctx context.Context,
	spec CommandSpec,
) (PreparedRecoveryCapsuleSigner, error) {
	if spec.RecoveryCapsule().Requirement() == RecoveryCapsuleNotApplicable {
		return nil, nil
	}
	signer, err := service.signers.PrepareRecoveryCapsuleSigner(ctx, spec.RecoveryCapsule().KeyID())
	if err != nil {
		return nil, fmt.Errorf("%w: signer preparation: %w", ErrOrchestrationDependency, err)
	}
	plan, err := PrepareRecoveryCapsulePlan(signer)
	if err != nil || plan.KeyID() != spec.RecoveryCapsule().KeyID() {
		return nil, ErrInvalidCommandSpec
	}
	return signer, nil
}

func (service *OrchestrationService) rollbackDecision(
	request CommandRequest,
	locked CommandContext,
	authentication AuthenticationEvidence,
	policy PreparedPolicy,
	cause error,
) (CommandDecision, error) {
	var rejection *domain.CommandError
	if !errors.As(cause, &rejection) {
		return CommandDecision{}, cause
	}
	if !requiresDenialAudit(rejection) {
		return RollbackCommand(locked, rejection)
	}
	security, err := service.denialPolicy.DenialFollowUp(locked, authentication, policy, rejection)
	if err != nil {
		return CommandDecision{}, err
	}
	security, err = bindSecurityAuditContext(security, request.Audit, authentication.provenance)
	if err != nil {
		return CommandDecision{}, err
	}
	return RollbackCommandWithSecurityAudit(locked, rejection, security)
}

func (service *OrchestrationService) finishCommand(
	ctx context.Context,
	transaction CommandTransactionExecution,
	signer PreparedRecoveryCapsuleSigner,
) (CommandExecution, error) {
	switch transaction.Kind() {
	case CommandTransactionIndeterminate:
		identity, _ := transaction.RetryIdentity()
		return CommandExecution{kind: CommandIndeterminate, retry: identity}, nil
	case CommandTransactionRejected:
		rejection, _ := transaction.Rejection()
		if denial, present := transaction.DenialAudit(); present {
			if err := service.executeCommandDenial(ctx, denial); err != nil {
				return CommandExecution{}, err
			}
		}
		return RejectedCommandExecution(rejection)
	case CommandTransactionCommitted, CommandTransactionReplayed:
	default:
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	receipt, full := transaction.Receipt()
	if !full {
		appliedOnly, _ := transaction.AppliedOnlyReceipt()
		return CommandExecution{kind: CommandReplayed, appliedOnly: appliedOnly, disclosure: ReplayDiscloseAppliedOnly}, nil
	}
	var capsule *RecoveryCapsuleEnvelope
	if draft, required := receipt.RecoveryCapsule(); required {
		plan := receipt.Result().RecoveryCapsulePlan()
		selectedSigner := signer
		if isNilInterface(selectedSigner) || selectedSigner.KeyID() != plan.KeyID() {
			var err error
			selectedSigner, err = service.signers.PrepareRecoveryCapsuleSigner(ctx, plan.KeyID())
			if err != nil {
				return CommittedCapsulePendingCommandExecution(receipt)
			}
		}
		envelope, err := SignRecoveryCapsule(ctx, plan, selectedSigner, draft)
		if err != nil {
			return CommittedCapsulePendingCommandExecution(receipt)
		}
		capsule = &envelope
	}
	if transaction.Kind() == CommandTransactionCommitted {
		return AppliedCommandExecution(receipt, capsule)
	}
	disclosure, _ := transaction.ReplayDisclosure()
	return ReplayedCommandExecution(receipt, disclosure, capsule)
}

func (service *OrchestrationService) executeCommandDenial(ctx context.Context, spec SecuritySpec) error {
	execution, err := service.uow.ExecuteSecurity(ctx, spec, func(locked SecurityContext) (SecurityDecision, error) {
		admission, present := locked.DenialAdmission()
		if !present {
			return SecurityDecision{}, ErrInvalidSecurityContext
		}
		switch admission.Kind() {
		case DenialSuppressDuplicate, DenialSuppressSaturated, DenialSuppressScopeSaturated:
			return SuppressCommandDenialSecurity(locked)
		case DenialAdmitDistinct, DenialAdmitSaturation, DenialAdmitScopeSaturation:
			operation, fingerprint, ok := ExpectedSecurityAudit(spec)
			if !ok {
				return SecurityDecision{}, ErrInvalidSecuritySpec
			}
			name, nameErr := domain.NewOperationName(operation)
			detail, detailErr := SecurityDeniedAuditDetail(spec.commandDenial.reason)
			if nameErr != nil || detailErr != nil {
				return SecurityDecision{}, ErrInvalidSecuritySpec
			}
			audit, auditErr := NewAuditIntent(name, AuditSecurityDenied, fingerprint, detail)
			if auditErr != nil {
				return SecurityDecision{}, auditErr
			}
			return AuditCommandDenialSecurity(locked, audit)
		default:
			return SecurityDecision{}, ErrInvalidSecurityContext
		}
	})
	if validationErr := ValidateSecurityExecutionResult(execution, err); validationErr != nil {
		return validationErr
	}
	if err != nil {
		return err
	}
	if execution.Kind() != SecurityCommandDenialAudited && execution.Kind() != SecurityCommandDenialSuppressed {
		return ErrInvalidSecurityExecution
	}
	return nil
}

func commandHashViewMatches(operation CommandOperation, view CommandHashView) bool {
	switch operation {
	case CommandBootstrapInstallation:
		_, ok := view.(bootstrapInstallationCommandHashView)
		return ok
	case CommandRegisterPrincipal:
		_, ok := view.(registerPrincipalCommandHashView)
		return ok
	case CommandCreateWorkspace:
		_, ok := view.(createWorkspaceCommandHashView)
		return ok
	case CommandInviteWorkspaceMember:
		_, ok := view.(inviteWorkspaceMemberCommandHashView)
		return ok
	case CommandAcceptWorkspaceMembership:
		_, ok := view.(acceptWorkspaceMembershipCommandHashView)
		return ok
	case CommandCreateActor:
		_, ok := view.(createActorCommandHashView)
		return ok
	case CommandProposeActorDelegation:
		_, ok := view.(proposeActorDelegationCommandHashView)
		return ok
	case CommandActivateActorDelegation:
		_, ok := view.(activateActorDelegationCommandHashView)
		return ok
	case CommandBeginDevicePairing:
		_, ok := view.(beginDevicePairingCommandHashView)
		return ok
	case CommandPairDevice:
		_, ok := view.(pairDeviceCommandHashView)
		return ok
	case CommandStartActorSession:
		_, ok := view.(startActorSessionCommandHashView)
		return ok
	default:
		return false
	}
}

func mustCommandError(code domain.ErrorCode, message string) *domain.CommandError {
	rejection, err := domain.NewCommandError(code, message, nil)
	if err != nil {
		panic(err)
	}
	return rejection
}

func lockedState[T any](locked CommandContext, id interface{ String() string }) (T, error) {
	var zero T
	for _, state := range locked.States() {
		if state.Target().ID() != id.String() {
			continue
		}
		value, ok := state.Value().(T)
		if ok {
			return value, nil
		}
	}
	return zero, ErrInvalidCommandContext
}

type BootstrapInstallationRequest struct {
	CommandRequest
	ProofEvidence           BootstrapProofEvidence
	GenerationAuthorization domain.BootstrapGenerationAuthorization
	InvitationID            domain.InvitationID
	PrincipalID             domain.PrincipalID
	PrincipalDisplayName    domain.DisplayName
	DeviceID                domain.DeviceID
	DeviceDisplayName       domain.DisplayName
	DevicePublicKey         domain.PublicKeyReference
	OwnerGrantID            domain.GrantID
	OwnerCapabilities       domain.CapabilitySet
}

func (service *OrchestrationService) BootstrapInstallation(ctx context.Context, request BootstrapInstallationRequest) (CommandExecution, error) {
	if err := validateBootstrapInstallationRequest(request); err != nil {
		return CommandExecution{}, err
	}
	verification, err := service.bootstrapProofs.VerifyBootstrapProof(ctx, request.ProofEvidence)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: bootstrap proof: %w", ErrOrchestrationDependency, err)
	}
	if verification.Decision() == ProofCryptographicallyRejected {
		return service.rejectBootstrap(ctx, request, verification.attempt)
	}
	proof, valid := verification.decision.Verified()
	if !valid {
		return CommandExecution{}, ErrInvalidApplicationContract
	}
	view, ok := request.HashView.(bootstrapInstallationCommandHashView)
	transcript := proof.TranscriptFingerprint()
	spki := proof.DeviceSPKIFingerprint().Bytes()
	if !ok || view.Body.ApprovedTranscript.String() != hex.EncodeToString(transcript[:]) ||
		view.Body.DeviceSPKIFingerprint.String() != hex.EncodeToString(spki[:]) ||
		proof.InvitationID() != request.InvitationID || proof.InstallationID().String() != request.Spec.Scope().ID() ||
		proof.PrincipalID() != request.PrincipalID || proof.PrincipalDisplayName() != request.PrincipalDisplayName ||
		proof.DeviceID() != request.DeviceID || proof.DeviceDisplayName() != request.DeviceDisplayName ||
		proof.DevicePublicKey() != request.DevicePublicKey || proof.OwnerGrantID() != request.OwnerGrantID ||
		!capabilitySetMatches(view.Body.OwnerGrantCapabilities, proof.OwnerCapabilities()) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	provenance, err := NewAuditProvenanceEvidence(request.Spec.AuthorityID(), nil)
	if err != nil {
		return CommandExecution{}, ErrInvalidApplicationContract
	}
	bootstrapIdentity, err := NewAuthenticationEvidence(proof.PrincipalID(), ptrDevice(proof.DeviceID()), provenance)
	if err != nil {
		return CommandExecution{}, ErrInvalidApplicationContract
	}
	return service.executeBootstrapCommand(ctx, request.CommandRequest, bootstrapIdentity,
		func(locked CommandContext) (OperationCommit, error) {
			invitation, stateErr := lockedState[domain.InstallationInvitationState](locked, request.InvitationID)
			if stateErr != nil {
				return OperationCommit{}, stateErr
			}
			at, _ := locked.AuthorityTime()
			result, transitionErr := domain.BootstrapInstallation(domain.BootstrapInstallationInput{
				Invitation: invitation, ExpectedInvitationVersion: invitation.Version(),
				CurrentGeneration: request.GenerationAuthorization.CurrentGeneration(), GenerationAuthorization: request.GenerationAuthorization,
				PrincipalID: request.PrincipalID, PrincipalDisplayName: request.PrincipalDisplayName,
				DeviceID: request.DeviceID, DeviceDisplayName: request.DeviceDisplayName, DevicePublicKey: request.DevicePublicKey,
				OwnerGrantID: request.OwnerGrantID, OwnerGrantCapabilities: request.OwnerCapabilities,
				Proof: proof, AttemptFingerprint: request.Spec.RequestFingerprint(), EvaluatedAt: at,
			})
			if transitionErr != nil {
				return OperationCommit{}, transitionErr
			}
			return BootstrapInstallationCommit(locked, result)
		})
}

func ptrDevice(value domain.DeviceID) *domain.DeviceID { return &value }

func validateBootstrapInstallationRequest(request BootstrapInstallationRequest) error {
	if err := validateCommandRequest(request.CommandRequest, CommandBootstrapInstallation); err != nil {
		return err
	}
	view, ok := request.HashView.(bootstrapInstallationCommandHashView)
	spec := request.Spec
	if !ok || !request.ProofEvidence.valid() || view.Body.InstallationID.String() != spec.Scope().ID() ||
		!expectedResourceMatches(spec, view.Body.Invitation, domain.AggregateKindInvitation, resourceMutation) ||
		view.Body.Invitation.ID.String() != request.InvitationID.String() ||
		view.Body.BootstrapGenerationID.String() != request.GenerationAuthorization.CurrentGeneration().String() ||
		view.Body.PrincipalID.String() != request.PrincipalID.String() ||
		view.Body.PrincipalDisplayName != request.PrincipalDisplayName.String() ||
		view.Body.DeviceID.String() != request.DeviceID.String() || view.Body.DeviceDisplayName != request.DeviceDisplayName.String() ||
		view.Body.DevicePublicKeyReference != request.DevicePublicKey.String() ||
		view.Body.OwnerGrantID.String() != request.OwnerGrantID.String() ||
		!capabilitySetMatches(view.Body.OwnerGrantCapabilities, request.OwnerCapabilities) ||
		!mutationTargetMatches(spec, request.PrincipalID.String(), domain.AggregateKindPrincipal, domain.ExpectationMustNotExist) ||
		!mutationTargetMatches(spec, request.DeviceID.String(), domain.AggregateKindDevice, domain.ExpectationMustNotExist) ||
		!mutationTargetMatches(spec, request.OwnerGrantID.String(), domain.AggregateKindGrant, domain.ExpectationMustNotExist) {
		return ErrInvalidCommandSpec
	}
	for _, evidence := range spec.Guards().Evidence() {
		generation, present := evidence.BootstrapGeneration()
		if present && generation == request.GenerationAuthorization.CurrentGeneration() {
			return nil
		}
	}
	return ErrInvalidCommandSpec
}

func (service *OrchestrationService) rejectBootstrap(
	ctx context.Context,
	request BootstrapInstallationRequest,
	attempt BootstrapAttempt,
) (CommandExecution, error) {
	var invitationExpectation domain.AggregateExpectation
	for _, expectation := range request.Spec.Guards().Mutations() {
		if expectation.Target().Kind() == domain.AggregateKindInvitation && expectation.Target().ID() == request.InvitationID.String() {
			invitationExpectation = expectation
			break
		}
	}
	security, err := RecordBootstrapDenialSecurity(
		request.Spec.Scope(), request.Spec.AuthorityID(), request.Spec.RequestedEpoch(),
		request.Spec.Guards().AdmissionGeneration(), invitationExpectation, attempt,
	)
	if err != nil {
		return CommandExecution{}, err
	}
	provenance, err := NewAuditProvenanceEvidence(request.Spec.AuthorityID(), nil)
	if err != nil {
		return CommandExecution{}, ErrInvalidApplicationContract
	}
	security, err = bindSecurityAuditContext(security, request.Audit, provenance)
	if err != nil {
		return CommandExecution{}, err
	}
	execution, executionErr := service.uow.ExecuteSecurity(ctx, security, func(locked SecurityContext) (SecurityDecision, error) {
		if locked.AttemptResolution().Kind() == SecurityAttemptReplay {
			return ReplayBootstrapDenialSecurity(locked)
		}
		result, transitionErr := domain.RejectBootstrapProof(domain.RejectBootstrapProofInput{
			Invitation: locked.Invitation(), ExpectedInvitationVersion: locked.Invitation().Version(),
			CurrentGeneration:       request.GenerationAuthorization.CurrentGeneration(),
			GenerationAuthorization: request.GenerationAuthorization,
			AttemptFingerprint:      attempt.Fingerprint(), EvaluatedAt: locked.AuthorityTime(),
		})
		if transitionErr != nil {
			var rejection *domain.CommandError
			if errors.As(transitionErr, &rejection) {
				return RollbackSecurity(locked, rejection)
			}
			return SecurityDecision{}, transitionErr
		}
		operation, fingerprint, ok := ExpectedSecurityAudit(security)
		name, nameErr := domain.NewOperationName(operation)
		detail, detailErr := SecurityDeniedAuditDetail("bootstrap_proof_rejected")
		if !ok || nameErr != nil || detailErr != nil {
			return SecurityDecision{}, ErrInvalidSecuritySpec
		}
		audit, auditErr := NewAuditIntent(name, AuditSecurityDenied, fingerprint, detail)
		if auditErr != nil {
			return SecurityDecision{}, auditErr
		}
		return DenyBootstrapSecurity(locked, result.Invitation(), audit)
	})
	if validationErr := ValidateSecurityExecutionResult(execution, executionErr); validationErr != nil {
		return CommandExecution{}, validationErr
	}
	if executionErr != nil {
		return CommandExecution{}, executionErr
	}
	if execution.Kind() != SecurityDenialCommitted && execution.Kind() != SecurityDenialReplayed {
		return CommandExecution{}, ErrInvalidSecurityExecution
	}
	return RejectedCommandExecution(mustCommandError(domain.ErrorCodeUnauthenticated, "bootstrap proof rejected"))
}

type RegisterPrincipalRequest struct {
	CommandRequest
	RegistrarID        domain.PrincipalID
	PrincipalID        domain.PrincipalID
	Kind               domain.PrincipalKind
	DisplayName        domain.DisplayName
	PublicKeyReference domain.PublicKeyReference
}

func (service *OrchestrationService) RegisterPrincipal(ctx context.Context, request RegisterPrincipalRequest) (CommandExecution, error) {
	view, ok := request.HashView.(registerPrincipalCommandHashView)
	if err := validateCommandRequest(request.CommandRequest, CommandRegisterPrincipal); err != nil || !ok ||
		!expectedResourceMatches(request.Spec, view.Body.Registrar, domain.AggregateKindPrincipal, resourceAuthorization) ||
		view.Body.Registrar.ID.String() != request.RegistrarID.String() || view.Body.PrincipalID.String() != request.PrincipalID.String() ||
		view.Body.Kind != string(request.Kind) || view.Body.DisplayName != request.DisplayName.String() ||
		view.Body.PublicKeyReference != request.PublicKeyReference.String() ||
		!mutationTargetMatches(request.Spec, request.PrincipalID.String(), domain.AggregateKindPrincipal, domain.ExpectationMustNotExist) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	return service.executeCommand(ctx, request.CommandRequest, CommandRegisterPrincipal,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			registrar, err := lockedState[domain.PrincipalState](locked, request.RegistrarID)
			if err != nil {
				return OperationCommit{}, err
			}
			result, err := domain.RegisterPrincipal(domain.RegisterPrincipalInput{
				Authorization: authorization, Registrar: registrar, ExpectedRegistrarVersion: registrar.Version(),
				PrincipalID: request.PrincipalID, Kind: request.Kind, DisplayName: request.DisplayName,
				PublicKeyReference: request.PublicKeyReference,
			})
			if err != nil {
				return OperationCommit{}, err
			}
			return RegisterPrincipalCommit(locked, result)
		})
}

type CreateWorkspaceRequest struct {
	CommandRequest
	OwnerID             domain.PrincipalID
	InstallationGrantID domain.GrantID
	WorkspaceID         domain.WorkspaceID
	Alias               domain.WorkspaceAlias
	DiscoveryLocator    domain.DiscoveryLocator
	OwnerMembershipID   domain.MembershipID
	OwnerCapabilities   domain.CapabilitySet
}

func (service *OrchestrationService) CreateWorkspace(ctx context.Context, request CreateWorkspaceRequest) (CommandExecution, error) {
	view, ok := request.HashView.(createWorkspaceCommandHashView)
	if err := validateCommandRequest(request.CommandRequest, CommandCreateWorkspace); err != nil || !ok ||
		!expectedResourceMatches(request.Spec, view.Body.Owner, domain.AggregateKindPrincipal, resourceAuthorization) ||
		!expectedResourceMatches(request.Spec, view.Body.InstallationGrant, domain.AggregateKindGrant, resourceAuthorization) ||
		view.Body.Owner.ID.String() != request.OwnerID.String() || view.Body.InstallationGrant.ID.String() != request.InstallationGrantID.String() ||
		view.Body.WorkspaceID.String() != request.WorkspaceID.String() || view.Body.Alias != request.Alias.String() ||
		view.Body.DiscoveryLocator != request.DiscoveryLocator.String() || view.Body.OwnerMembershipID.String() != request.OwnerMembershipID.String() ||
		!capabilitySetMatches(view.Body.OwnerCapabilities, request.OwnerCapabilities) ||
		!mutationTargetMatches(request.Spec, request.WorkspaceID.String(), domain.AggregateKindWorkspace, domain.ExpectationMustNotExist) ||
		!mutationTargetMatches(request.Spec, request.OwnerMembershipID.String(), domain.AggregateKindMembership, domain.ExpectationMustNotExist) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	return service.executeCommand(ctx, request.CommandRequest, CommandCreateWorkspace,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			owner, err := lockedState[domain.PrincipalState](locked, request.OwnerID)
			if err != nil {
				return OperationCommit{}, err
			}
			grant, err := lockedState[domain.GrantState](locked, request.InstallationGrantID)
			if err != nil {
				return OperationCommit{}, err
			}
			result, err := domain.CreateWorkspace(domain.CreateWorkspaceInput{
				Authorization: authorization, Owner: owner, ExpectedOwnerVersion: owner.Version(),
				InstallationGrant: grant, ExpectedGrantVersion: grant.Version(), WorkspaceID: request.WorkspaceID,
				Alias: request.Alias, DiscoveryLocator: request.DiscoveryLocator,
				OwnerMembershipID: request.OwnerMembershipID, OwnerCapabilities: request.OwnerCapabilities,
			})
			if err != nil {
				return OperationCommit{}, err
			}
			return CreateWorkspaceCommit(locked, result)
		})
}

type InviteWorkspaceMemberRequest struct {
	CommandRequest
	AdministratorID, PrincipalID domain.PrincipalID
	WorkspaceID                  domain.WorkspaceID
	MembershipID                 domain.MembershipID
	Capabilities                 domain.CapabilitySet
	Challenge                    domain.CeremonyChallenge
	ChallengeCreation            domain.CeremonyCreationExpectation
}

func (service *OrchestrationService) InviteWorkspaceMember(ctx context.Context, request InviteWorkspaceMemberRequest) (CommandExecution, error) {
	view, ok := request.HashView.(inviteWorkspaceMemberCommandHashView)
	if err := validateCommandRequest(request.CommandRequest, CommandInviteWorkspaceMember); err != nil || !ok ||
		!expectedResourceMatches(request.Spec, view.Body.Administrator, domain.AggregateKindPrincipal, resourceAuthorization) ||
		!expectedResourceMatches(request.Spec, view.Body.Workspace, domain.AggregateKindWorkspace, resourceAuthorization) ||
		!expectedResourceMatches(request.Spec, view.Body.Principal, domain.AggregateKindPrincipal, resourceReference) ||
		view.Body.Administrator.ID.String() != request.AdministratorID.String() || view.Body.Workspace.ID.String() != request.WorkspaceID.String() ||
		view.Body.Principal.ID.String() != request.PrincipalID.String() || view.Body.MembershipID.String() != request.MembershipID.String() ||
		!capabilitySetMatches(view.Body.Capabilities, request.Capabilities) || !challengeMatches(request.Spec, view.Body.Challenge, request.Challenge, request.ChallengeCreation) ||
		!mutationTargetMatches(request.Spec, request.MembershipID.String(), domain.AggregateKindMembership, domain.ExpectationMustNotExist) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	return service.executeCommand(ctx, request.CommandRequest, CommandInviteWorkspaceMember,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			administrator, err := lockedState[domain.PrincipalState](locked, request.AdministratorID)
			if err != nil {
				return OperationCommit{}, err
			}
			workspace, err := lockedState[domain.WorkspaceState](locked, request.WorkspaceID)
			if err != nil {
				return OperationCommit{}, err
			}
			principal, err := lockedState[domain.PrincipalState](locked, request.PrincipalID)
			if err != nil {
				return OperationCommit{}, err
			}
			result, err := domain.InviteWorkspaceMember(domain.InviteWorkspaceMemberInput{
				Authorization: authorization, Administrator: administrator, ExpectedAdministratorVersion: administrator.Version(),
				Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(), Principal: principal,
				ExpectedPrincipalVersion: principal.Version(), MembershipID: request.MembershipID,
				Capabilities: request.Capabilities, Challenge: request.Challenge, ChallengeCreation: request.ChallengeCreation,
			})
			if err != nil {
				return OperationCommit{}, err
			}
			return InviteWorkspaceMemberCommit(locked, result)
		})
}

type AcceptWorkspaceMembershipRequest struct {
	CommandRequest
	WorkspaceID   domain.WorkspaceID
	PrincipalID   domain.PrincipalID
	MembershipID  domain.MembershipID
	ProofEvidence CeremonyProofEvidence
}

func (service *OrchestrationService) AcceptWorkspaceMembership(ctx context.Context, request AcceptWorkspaceMembershipRequest) (CommandExecution, error) {
	view, ok := request.HashView.(acceptWorkspaceMembershipCommandHashView)
	if err := validateCommandRequest(request.CommandRequest, CommandAcceptWorkspaceMembership); err != nil || !ok ||
		!expectedResourceMatches(request.Spec, view.Body.Workspace, domain.AggregateKindWorkspace, resourceReference) ||
		!expectedResourceMatches(request.Spec, view.Body.Principal, domain.AggregateKindPrincipal, resourceAuthorization) ||
		!expectedResourceMatches(request.Spec, view.Body.Membership, domain.AggregateKindMembership, resourceMutation) ||
		view.Body.Workspace.ID.String() != request.WorkspaceID.String() || view.Body.Principal.ID.String() != request.PrincipalID.String() ||
		view.Body.Membership.ID.String() != request.MembershipID.String() || !request.ProofEvidence.valid() {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	verification, err := service.ceremonyProofs.VerifyMembershipAcceptance(ctx, request.ProofEvidence)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: membership acceptance proof: %w", ErrOrchestrationDependency, err)
	}
	proof, valid := verification.Verified()
	if !valid {
		subject, rejected := verification.RejectionSubject()
		if !rejected {
			return CommandExecution{}, ErrInvalidApplicationContract
		}
		return service.executeProofDenial(ctx, request.CommandRequest, subject)
	}
	if proof.Purpose() != domain.CeremonyPurposeMembershipAcceptance || proof.PrincipalID() != request.PrincipalID ||
		!proof.DeviceID().IsZero() || !proofMatches(request.Spec, view.Body.Proof, proof) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	return service.executeCommand(ctx, request.CommandRequest, CommandAcceptWorkspaceMembership,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			workspace, err := lockedState[domain.WorkspaceState](locked, request.WorkspaceID)
			if err != nil {
				return OperationCommit{}, err
			}
			principal, err := lockedState[domain.PrincipalState](locked, request.PrincipalID)
			if err != nil {
				return OperationCommit{}, err
			}
			membership, err := lockedState[domain.MembershipState](locked, request.MembershipID)
			if err != nil {
				return OperationCommit{}, err
			}
			result, err := domain.AcceptWorkspaceMembership(domain.AcceptWorkspaceMembershipInput{
				Authorization: authorization, Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(),
				Principal: principal, ExpectedPrincipalVersion: principal.Version(), Membership: membership,
				ExpectedMembershipVersion: membership.Version(), Proof: proof,
			})
			if err != nil {
				return OperationCommit{}, err
			}
			return AcceptWorkspaceMembershipCommit(locked, result)
		})
}

type CreateActorRequest struct {
	CommandRequest
	AdministratorID domain.PrincipalID
	WorkspaceID     domain.WorkspaceID
	ActorID         domain.ActorID
	Kind            domain.ActorKind
	Profile         domain.ActorProfile
}

func (service *OrchestrationService) CreateActor(ctx context.Context, request CreateActorRequest) (CommandExecution, error) {
	view, ok := request.HashView.(createActorCommandHashView)
	if err := validateCommandRequest(request.CommandRequest, CommandCreateActor); err != nil || !ok ||
		!expectedResourceMatches(request.Spec, view.Body.Administrator, domain.AggregateKindPrincipal, resourceAuthorization) ||
		!expectedResourceMatches(request.Spec, view.Body.Workspace, domain.AggregateKindWorkspace, resourceAuthorization) ||
		view.Body.Administrator.ID.String() != request.AdministratorID.String() || view.Body.Workspace.ID.String() != request.WorkspaceID.String() ||
		view.Body.ActorID.String() != request.ActorID.String() || view.Body.Kind != string(request.Kind) ||
		view.Body.DisplayName != request.Profile.DisplayName().String() ||
		!mutationTargetMatches(request.Spec, request.ActorID.String(), domain.AggregateKindActor, domain.ExpectationMustNotExist) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	return service.executeCommand(ctx, request.CommandRequest, CommandCreateActor,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			administrator, err := lockedState[domain.PrincipalState](locked, request.AdministratorID)
			if err != nil {
				return OperationCommit{}, err
			}
			workspace, err := lockedState[domain.WorkspaceState](locked, request.WorkspaceID)
			if err != nil {
				return OperationCommit{}, err
			}
			result, err := domain.CreateActor(domain.CreateActorInput{Authorization: authorization,
				Administrator: administrator, ExpectedAdministratorVersion: administrator.Version(), Workspace: workspace,
				ExpectedWorkspaceVersion: workspace.Version(), ActorID: request.ActorID, Kind: request.Kind, Profile: request.Profile})
			if err != nil {
				return OperationCommit{}, err
			}
			return CreateActorCommit(locked, result)
		})
}

type ProposeActorDelegationRequest struct {
	CommandRequest
	AdministratorID, PrincipalID domain.PrincipalID
	WorkspaceID                  domain.WorkspaceID
	ActorID                      domain.ActorID
	MembershipID                 domain.MembershipID
	DelegationID                 domain.ActorDelegationID
	Capabilities                 domain.CapabilitySet
	Challenge                    domain.CeremonyChallenge
	ChallengeCreation            domain.CeremonyCreationExpectation
}

func (service *OrchestrationService) ProposeActorDelegation(ctx context.Context, request ProposeActorDelegationRequest) (CommandExecution, error) {
	view, ok := request.HashView.(proposeActorDelegationCommandHashView)
	if err := validateCommandRequest(request.CommandRequest, CommandProposeActorDelegation); err != nil || !ok ||
		!expectedResourceMatches(request.Spec, view.Body.Administrator, domain.AggregateKindPrincipal, resourceAuthorization) ||
		!expectedResourceMatches(request.Spec, view.Body.Workspace, domain.AggregateKindWorkspace, resourceAuthorization) ||
		!expectedResourceMatches(request.Spec, view.Body.Principal, domain.AggregateKindPrincipal, resourceReference) ||
		!expectedResourceMatches(request.Spec, view.Body.Actor, domain.AggregateKindActor, resourceReference) ||
		!expectedResourceMatches(request.Spec, view.Body.Membership, domain.AggregateKindMembership, resourceReference) ||
		view.Body.Administrator.ID.String() != request.AdministratorID.String() || view.Body.Workspace.ID.String() != request.WorkspaceID.String() ||
		view.Body.Principal.ID.String() != request.PrincipalID.String() || view.Body.Actor.ID.String() != request.ActorID.String() ||
		view.Body.Membership.ID.String() != request.MembershipID.String() || view.Body.DelegationID.String() != request.DelegationID.String() ||
		!capabilitySetMatches(view.Body.Capabilities, request.Capabilities) || !challengeMatches(request.Spec, view.Body.Challenge, request.Challenge, request.ChallengeCreation) ||
		!mutationTargetMatches(request.Spec, request.DelegationID.String(), domain.AggregateKindActorDelegation, domain.ExpectationMustNotExist) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	return service.executeCommand(ctx, request.CommandRequest, CommandProposeActorDelegation,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			administrator, err := lockedState[domain.PrincipalState](locked, request.AdministratorID)
			if err != nil {
				return OperationCommit{}, err
			}
			workspace, err := lockedState[domain.WorkspaceState](locked, request.WorkspaceID)
			if err != nil {
				return OperationCommit{}, err
			}
			principal, err := lockedState[domain.PrincipalState](locked, request.PrincipalID)
			if err != nil {
				return OperationCommit{}, err
			}
			actor, err := lockedState[domain.ActorState](locked, request.ActorID)
			if err != nil {
				return OperationCommit{}, err
			}
			membership, err := lockedState[domain.MembershipState](locked, request.MembershipID)
			if err != nil {
				return OperationCommit{}, err
			}
			result, err := domain.ProposeActorDelegation(domain.ProposeActorDelegationInput{
				Authorization: authorization, Administrator: administrator, ExpectedAdministratorVersion: administrator.Version(),
				Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(), Principal: principal,
				ExpectedPrincipalVersion: principal.Version(), Actor: actor, ExpectedActorVersion: actor.Version(),
				Membership: membership, ExpectedMembershipVersion: membership.Version(), DelegationID: request.DelegationID,
				Capabilities: request.Capabilities, Challenge: request.Challenge, ChallengeCreation: request.ChallengeCreation,
			})
			if err != nil {
				return OperationCommit{}, err
			}
			return ProposeActorDelegationCommit(locked, result)
		})
}

type ActivateActorDelegationRequest struct {
	CommandRequest
	WorkspaceID              domain.WorkspaceID
	PrincipalID              domain.PrincipalID
	ActorID                  domain.ActorID
	MembershipID             domain.MembershipID
	DelegationID             domain.ActorDelegationID
	ProofEvidence            CeremonyProofEvidence
	SessionStartChallenge    domain.CeremonyChallenge
	SessionChallengeCreation domain.CeremonyCreationExpectation
}

func (service *OrchestrationService) ActivateActorDelegation(ctx context.Context, request ActivateActorDelegationRequest) (CommandExecution, error) {
	view, ok := request.HashView.(activateActorDelegationCommandHashView)
	if err := validateCommandRequest(request.CommandRequest, CommandActivateActorDelegation); err != nil || !ok ||
		!expectedResourceMatches(request.Spec, view.Body.Workspace, domain.AggregateKindWorkspace, resourceReference) ||
		!expectedResourceMatches(request.Spec, view.Body.Principal, domain.AggregateKindPrincipal, resourceAuthorization) ||
		!expectedResourceMatches(request.Spec, view.Body.Actor, domain.AggregateKindActor, resourceReference) ||
		!expectedResourceMatches(request.Spec, view.Body.Membership, domain.AggregateKindMembership, resourceReference) ||
		!expectedResourceMatches(request.Spec, view.Body.Delegation, domain.AggregateKindActorDelegation, resourceMutation) ||
		view.Body.Workspace.ID.String() != request.WorkspaceID.String() || view.Body.Principal.ID.String() != request.PrincipalID.String() ||
		view.Body.Actor.ID.String() != request.ActorID.String() || view.Body.Membership.ID.String() != request.MembershipID.String() ||
		view.Body.Delegation.ID.String() != request.DelegationID.String() || !request.ProofEvidence.valid() ||
		!challengeMatches(request.Spec, view.Body.SessionStartChallenge, request.SessionStartChallenge, request.SessionChallengeCreation) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	verification, err := service.ceremonyProofs.VerifyDelegationActivation(ctx, request.ProofEvidence)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: delegation activation proof: %w", ErrOrchestrationDependency, err)
	}
	proof, valid := verification.Verified()
	if !valid {
		subject, rejected := verification.RejectionSubject()
		if !rejected {
			return CommandExecution{}, ErrInvalidApplicationContract
		}
		return service.executeProofDenial(ctx, request.CommandRequest, subject)
	}
	if proof.Purpose() != domain.CeremonyPurposeDelegationActivation || proof.PrincipalID() != request.PrincipalID ||
		!proof.DeviceID().IsZero() || !proofMatches(request.Spec, view.Body.ActivationProof, proof) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	return service.executeCommand(ctx, request.CommandRequest, CommandActivateActorDelegation,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			workspace, err := lockedState[domain.WorkspaceState](locked, request.WorkspaceID)
			if err != nil {
				return OperationCommit{}, err
			}
			principal, err := lockedState[domain.PrincipalState](locked, request.PrincipalID)
			if err != nil {
				return OperationCommit{}, err
			}
			actor, err := lockedState[domain.ActorState](locked, request.ActorID)
			if err != nil {
				return OperationCommit{}, err
			}
			membership, err := lockedState[domain.MembershipState](locked, request.MembershipID)
			if err != nil {
				return OperationCommit{}, err
			}
			delegation, err := lockedState[domain.ActorDelegationState](locked, request.DelegationID)
			if err != nil {
				return OperationCommit{}, err
			}
			result, err := domain.ActivateActorDelegation(domain.ActivateActorDelegationInput{
				Authorization: authorization, Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(),
				Principal: principal, ExpectedPrincipalVersion: principal.Version(), Actor: actor, ExpectedActorVersion: actor.Version(),
				Membership: membership, ExpectedMembershipVersion: membership.Version(), Delegation: delegation,
				ExpectedDelegationVersion: delegation.Version(), Proof: proof,
				SessionStartChallenge: request.SessionStartChallenge, SessionChallengeCreation: request.SessionChallengeCreation,
			})
			if err != nil {
				return OperationCommit{}, err
			}
			return ActivateActorDelegationCommit(locked, result)
		})
}

type BeginDevicePairingRequest struct {
	CommandRequest
	PrincipalID        domain.PrincipalID
	DeviceID           domain.DeviceID
	DisplayName        domain.DisplayName
	PublicKeyReference domain.PublicKeyReference
	Challenge          domain.CeremonyChallenge
	ChallengeCreation  domain.CeremonyCreationExpectation
}

func (service *OrchestrationService) BeginDevicePairing(ctx context.Context, request BeginDevicePairingRequest) (CommandExecution, error) {
	view, ok := request.HashView.(beginDevicePairingCommandHashView)
	if err := validateCommandRequest(request.CommandRequest, CommandBeginDevicePairing); err != nil || !ok ||
		!expectedResourceMatches(request.Spec, view.Body.Principal, domain.AggregateKindPrincipal, resourceAuthorization) ||
		view.Body.Principal.ID.String() != request.PrincipalID.String() || view.Body.DeviceID.String() != request.DeviceID.String() ||
		view.Body.DisplayName != request.DisplayName.String() || view.Body.PublicKeyReference != request.PublicKeyReference.String() ||
		!challengeMatches(request.Spec, view.Body.Challenge, request.Challenge, request.ChallengeCreation) ||
		!mutationTargetMatches(request.Spec, request.DeviceID.String(), domain.AggregateKindDevice, domain.ExpectationMustNotExist) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	return service.executeCommand(ctx, request.CommandRequest, CommandBeginDevicePairing,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			principal, err := lockedState[domain.PrincipalState](locked, request.PrincipalID)
			if err != nil {
				return OperationCommit{}, err
			}
			result, err := domain.BeginDevicePairing(domain.BeginDevicePairingInput{
				Authorization: authorization, Principal: principal, ExpectedPrincipalVersion: principal.Version(),
				DeviceID: request.DeviceID, DisplayName: request.DisplayName, PublicKeyReference: request.PublicKeyReference,
				Challenge: request.Challenge, ChallengeCreation: request.ChallengeCreation,
			})
			if err != nil {
				return OperationCommit{}, err
			}
			return BeginDevicePairingCommit(locked, result)
		})
}

type PairDeviceRequest struct {
	CommandRequest
	PrincipalID           domain.PrincipalID
	DeviceID              domain.DeviceID
	ExpectedTrustRevision domain.Version
	ProofEvidence         CeremonyProofEvidence
}

func (service *OrchestrationService) PairDevice(ctx context.Context, request PairDeviceRequest) (CommandExecution, error) {
	view, ok := request.HashView.(pairDeviceCommandHashView)
	if err := validateCommandRequest(request.CommandRequest, CommandPairDevice); err != nil || !ok ||
		!expectedResourceMatches(request.Spec, view.Body.Principal, domain.AggregateKindPrincipal, resourceAuthorization) ||
		!expectedResourceMatches(request.Spec, view.Body.Device, domain.AggregateKindDevice, resourceMutation) ||
		view.Body.Principal.ID.String() != request.PrincipalID.String() || view.Body.Device.ID.String() != request.DeviceID.String() ||
		view.Body.ExpectedTrustRevision != request.ExpectedTrustRevision.Uint64() || !request.ProofEvidence.valid() ||
		!evidenceRevisionMatches(request.Spec, request.DeviceID.String(), request.ExpectedTrustRevision) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	decision, err := service.pairingRedemptions.VerifyPairingRedemption(ctx, request.ProofEvidence)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: pairing redemption: %w", ErrOrchestrationDependency, err)
	}
	verification, valid := decision.Verified()
	if !valid {
		subject, rejected := decision.RejectionSubject()
		if !rejected {
			return CommandExecution{}, ErrInvalidApplicationContract
		}
		return service.executeProofDenial(ctx, request.CommandRequest, subject)
	}
	pairing, proof := verification.Authorization(), verification.Proof()
	credential := pairing.Credential()
	spki := credential.SPKIFingerprint().Bytes()
	transcript := credential.TranscriptFingerprint()
	if pairing.AuthorityID() != request.Spec.AuthorityID() || pairing.AuthorityEpoch() != request.Spec.RequestedEpoch() ||
		pairing.InstallationID().String() != request.Spec.Scope().ID() || pairing.PrincipalID() != request.PrincipalID ||
		pairing.DeviceID() != request.DeviceID || proof.Purpose() != domain.CeremonyPurposeDevicePairing ||
		proof.PrincipalID() != request.PrincipalID || proof.DeviceID() != request.DeviceID ||
		!proofMatches(request.Spec, view.Body.Proof, proof) ||
		view.Body.CredentialPublicKey != credential.PublicKeyReference().String() ||
		view.Body.CredentialSPKIDigest.String() != hex.EncodeToString(spki[:]) ||
		view.Body.CredentialTranscript.String() != hex.EncodeToString(transcript[:]) {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	authenticationDecision, err := service.authentication.PrepareAuthentication(ctx, request.Authentication)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: authentication preparation: %w", ErrOrchestrationDependency, err)
	}
	policy, err := service.policy.PreparePolicy(ctx, request.Policy)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: policy preparation: %w", ErrOrchestrationDependency, err)
	}
	if pairing.PolicyRevision() != policy.Revision() {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	authentication, valid := authenticationDecision.Evidence()
	if !valid {
		rejection, subject, rejected := authenticationDecision.Rejection()
		if !rejected {
			return CommandExecution{}, ErrInvalidApplicationContract
		}
		return service.executePreTransactionDenial(
			ctx, request.CommandRequest, policy, rejection, subject, authenticationDecision.provenance(),
		)
	}
	return service.executePreparedCommand(ctx, request.CommandRequest, authentication, policy,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			principal, err := lockedState[domain.PrincipalState](locked, request.PrincipalID)
			if err != nil {
				return OperationCommit{}, err
			}
			device, err := lockedState[domain.DeviceState](locked, request.DeviceID)
			if err != nil {
				return OperationCommit{}, err
			}
			authorityTime, _ := locked.AuthorityTime()
			result, err := domain.PairDevice(domain.PairDeviceInput{
				Authorization: pairing, CurrentAuthorization: authorization, AuthorityTime: authorityTime,
				Principal: principal, ExpectedPrincipalVersion: principal.Version(), Device: device,
				ExpectedDeviceVersion: device.Version(), ExpectedTrustRevision: request.ExpectedTrustRevision,
				Proof: proof,
			})
			if err != nil {
				return OperationCommit{}, err
			}
			return PairDeviceCommit(locked, result)
		})
}

func evidenceRevisionMatches(spec CommandSpec, targetID string, revision domain.Version) bool {
	for _, evidence := range spec.Guards().Evidence() {
		value, present := evidence.Revision()
		if present && evidence.TargetKind() == string(domain.AggregateKindDevice) && evidence.TargetID() == targetID && value == revision {
			return true
		}
	}
	return false
}

type StartActorSessionRequest struct {
	CommandRequest
	SessionID             domain.ActorSessionID
	ClientInstanceID      domain.ClientInstanceID
	ClientMetadata        domain.ClientMetadata
	WorkspaceID           domain.WorkspaceID
	PrincipalID           domain.PrincipalID
	MembershipID          domain.MembershipID
	ActorID               domain.ActorID
	DelegationID          domain.ActorDelegationID
	GrantIDs              []domain.GrantID
	StartAuthorityKind    domain.SessionStartAuthorityKind
	DeviceID              domain.DeviceID
	ExpectedDeviceVersion domain.Version
	ExpectedDeviceTrust   domain.Version
	HandoffProofEvidence  CeremonyProofEvidence
	AbsoluteExpiry        time.Time
}

func (service *OrchestrationService) StartActorSession(
	ctx context.Context,
	request StartActorSessionRequest,
) (CommandExecution, error) {
	if err := validateStartActorSessionRequest(request); err != nil {
		return CommandExecution{}, err
	}
	view, ok := request.HashView.(startActorSessionCommandHashView)
	var handoffProof domain.CeremonyProof
	if request.StartAuthorityKind == domain.SessionStartByHandoff {
		verification, err := service.ceremonyProofs.VerifyActorSessionHandoff(ctx, request.HandoffProofEvidence)
		if err != nil {
			return CommandExecution{}, fmt.Errorf("%w: actor session handoff proof: %w", ErrOrchestrationDependency, err)
		}
		var valid bool
		handoffProof, valid = verification.Verified()
		if !valid {
			subject, rejected := verification.RejectionSubject()
			if !rejected {
				return CommandExecution{}, ErrInvalidApplicationContract
			}
			return service.executeProofDenial(ctx, request.CommandRequest, subject)
		}
		if !ok || handoffProof.Purpose() != domain.CeremonyPurposeActorSessionStart ||
			handoffProof.PrincipalID() != request.PrincipalID || !handoffProof.DeviceID().IsZero() ||
			!standaloneProofMatches(request.Spec, *view.Body.HandoffProof, handoffProof) {
			return CommandExecution{}, ErrInvalidCommandSpec
		}
	}
	presentation, err := service.presentations.PreparePresentationCredential(ctx, CommandStartActorSession)
	if err != nil {
		return CommandExecution{}, fmt.Errorf("%w: presentation credential: %w", ErrOrchestrationDependency, err)
	}
	digest := presentation.Digest().Bytes()
	if !ok || presentation.IsZero() || view.Body.PresentationReference != presentation.Reference().String() ||
		view.Body.PresentationDigest.String() != hex.EncodeToString(digest[:]) ||
		view.Body.PresentationAudience != presentation.Audience().String() ||
		view.Body.PresentationVersion != presentation.Version() {
		return CommandExecution{}, ErrInvalidCommandSpec
	}
	return service.executeCommand(ctx, request.CommandRequest, CommandStartActorSession,
		func(locked CommandContext, authorization domain.IdentityAuthorization, _ AuthenticationEvidence, _ PreparedPolicy) (OperationCommit, error) {
			workspace, err := lockedState[domain.WorkspaceState](locked, request.WorkspaceID)
			if err != nil {
				return OperationCommit{}, err
			}
			principal, err := lockedState[domain.PrincipalState](locked, request.PrincipalID)
			if err != nil {
				return OperationCommit{}, err
			}
			membership, err := lockedState[domain.MembershipState](locked, request.MembershipID)
			if err != nil {
				return OperationCommit{}, err
			}
			actor, err := lockedState[domain.ActorState](locked, request.ActorID)
			if err != nil {
				return OperationCommit{}, err
			}
			delegation, err := lockedState[domain.ActorDelegationState](locked, request.DelegationID)
			if err != nil {
				return OperationCommit{}, err
			}
			grants := make([]domain.GrantRevision, 0, len(request.GrantIDs))
			for _, id := range request.GrantIDs {
				grant, grantErr := lockedState[domain.GrantState](locked, id)
				if grantErr != nil {
					return OperationCommit{}, grantErr
				}
				revision, revisionErr := domain.NewGrantRevision(grant, grant.Version())
				if revisionErr != nil {
					return OperationCommit{}, revisionErr
				}
				grants = append(grants, revision)
			}
			var start domain.SessionStartAuthority
			switch request.StartAuthorityKind {
			case domain.SessionStartByTrustedDevice:
				device, deviceErr := lockedState[domain.DeviceState](locked, request.DeviceID)
				if deviceErr != nil {
					return OperationCommit{}, deviceErr
				}
				start, err = domain.TrustedDeviceSessionStart(device, request.ExpectedDeviceVersion, request.ExpectedDeviceTrust)
			case domain.SessionStartByHandoff:
				ceremonies := locked.StandaloneCeremonies()
				if len(ceremonies) != 1 {
					return OperationCommit{}, ErrInvalidCommandContext
				}
				start, err = domain.HandoffSessionStart(ceremonies[0], handoffProof)
			default:
				err = ErrInvalidCommandSpec
			}
			if err != nil {
				return OperationCommit{}, err
			}
			result, err := domain.StartActorSession(domain.StartActorSessionInput{
				Authorization: authorization, SessionID: request.SessionID, ClientInstanceID: request.ClientInstanceID,
				ClientMetadata: request.ClientMetadata, Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(),
				Principal: principal, ExpectedPrincipalVersion: principal.Version(), Membership: membership,
				ExpectedMembershipVersion: membership.Version(), Actor: actor, ExpectedActorVersion: actor.Version(),
				Delegation: delegation, ExpectedDelegationVersion: delegation.Version(), Grants: grants,
				StartAuthority: start, AbsoluteExpiry: request.AbsoluteExpiry, PresentationCredential: presentation,
			})
			if err != nil {
				return OperationCommit{}, err
			}
			return StartActorSessionCommit(locked, result)
		})
}

func validateStartActorSessionRequest(request StartActorSessionRequest) error {
	if err := validateCommandRequest(request.CommandRequest, CommandStartActorSession); err != nil {
		return err
	}
	view, ok := request.HashView.(startActorSessionCommandHashView)
	if !ok || view.Body.SessionID.String() != request.SessionID.String() ||
		view.Command.ClientInstanceID == nil || view.Command.ClientInstanceID.String() != request.ClientInstanceID.String() ||
		view.Body.ClientName != request.ClientMetadata.Name() || view.Body.ClientVersion != request.ClientMetadata.Version() ||
		!sessionResourceMatches(request, view.Body.Workspace, request.WorkspaceID.String(), domain.AggregateKindWorkspace, resourceAuthorization) ||
		!sessionResourceMatches(request, view.Body.Principal, request.PrincipalID.String(), domain.AggregateKindPrincipal, resourceAuthorization) ||
		!sessionResourceMatches(request, view.Body.Membership, request.MembershipID.String(), domain.AggregateKindMembership, resourceAuthorization) ||
		!sessionResourceMatches(request, view.Body.Actor, request.ActorID.String(), domain.AggregateKindActor, resourceAuthorization) ||
		!sessionResourceMatches(request, view.Body.Delegation, request.DelegationID.String(), domain.AggregateKindActorDelegation, resourceAuthorization) ||
		view.Body.StartAuthorityKind != string(request.StartAuthorityKind) || !view.Body.AbsoluteExpiry.Time().Equal(request.AbsoluteExpiry) ||
		!mutationTargetMatches(request.Spec, request.SessionID.String(), domain.AggregateKindActorSession, domain.ExpectationMustNotExist) {
		return ErrInvalidCommandSpec
	}
	if len(view.Body.Grants) != len(request.GrantIDs) {
		return ErrInvalidCommandSpec
	}
	for index, grant := range view.Body.Grants {
		if grant.ID.String() != request.GrantIDs[index].String() || !expectedResourceMatches(request.Spec, grant, domain.AggregateKindGrant, resourceReference) {
			return ErrInvalidCommandSpec
		}
	}
	switch request.StartAuthorityKind {
	case domain.SessionStartByTrustedDevice:
		if view.Body.Device == nil || view.Body.ExpectedDeviceTrust == nil || view.Body.HandoffProof != nil ||
			len(request.HandoffProofEvidence.opaque) != 0 ||
			view.Body.Device.ID.String() != request.DeviceID.String() || view.Body.Device.ExpectedVersion != request.ExpectedDeviceVersion.Uint64() ||
			*view.Body.ExpectedDeviceTrust != request.ExpectedDeviceTrust.Uint64() ||
			!expectedResourceMatches(request.Spec, *view.Body.Device, domain.AggregateKindDevice, resourceReference) ||
			!evidenceRevisionMatches(request.Spec, request.DeviceID.String(), request.ExpectedDeviceTrust) {
			return ErrInvalidCommandSpec
		}
	case domain.SessionStartByHandoff:
		if view.Body.Device != nil || view.Body.ExpectedDeviceTrust != nil || view.Body.HandoffProof == nil ||
			!request.HandoffProofEvidence.valid() {
			return ErrInvalidCommandSpec
		}
	default:
		return ErrInvalidCommandSpec
	}
	return nil
}

func sessionResourceMatches(request StartActorSessionRequest, resource CommandExpectedResource, id string, kind domain.AggregateKind, binding resourceBinding) bool {
	return resource.ID.String() == id && expectedResourceMatches(request.Spec, resource, kind, binding)
}

func standaloneProofMatches(spec CommandSpec, wire CommandCeremony, proof domain.CeremonyProof) bool {
	if wire.ID.String() != proof.ChallengeID().String() || wire.ProofDigest.String() != Digest(proof.ProofDigest()).String() {
		return false
	}
	for _, claim := range spec.Guards().Ceremonies() {
		if claim.Kind() == CeremonyConsumeStandalone && claim.ID() == proof.ChallengeID() &&
			claim.Purpose() == proof.Purpose() && claim.ProofFingerprint() == proof.ProofDigest() {
			return true
		}
	}
	return false
}
