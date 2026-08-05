package application

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

type orchestrationTrap struct {
	inCallback bool
	order      []string
}

func (trap *orchestrationTrap) external(name string) {
	if trap.inCallback {
		panic(name + " called in transaction callback")
	}
	trap.order = append(trap.order, name)
}

type orchestrationAuthentication struct {
	trap               *orchestrationTrap
	authority          domain.AuthorityID
	principal          domain.PrincipalID
	federationEnvelope *string
}

func (preparer orchestrationAuthentication) PrepareAuthentication(
	ctx context.Context,
	request AuthenticationRequest,
) (AuthenticationDecision, error) {
	preparer.trap.external("authentication")
	if err := ctx.Err(); err != nil {
		return AuthenticationDecision{}, err
	}
	authority := preparer.authority
	if authority.IsZero() {
		authority, _ = domain.ParseAuthorityID(applicationUUID(2))
	}
	provenance, err := NewAuditProvenanceEvidence(authority, preparer.federationEnvelope)
	if err != nil {
		return AuthenticationDecision{}, err
	}
	request.provenance = provenance
	if !preparer.principal.IsZero() {
		request.principal = preparer.principal
	}
	evidence, err := NewAuthenticationEvidence(request)
	if err != nil {
		return AuthenticationDecision{}, err
	}
	return ValidAuthentication(evidence)
}

type orchestrationRejectedAuthentication struct{ trap *orchestrationTrap }

func (preparer orchestrationRejectedAuthentication) PrepareAuthentication(
	_ context.Context,
	_ AuthenticationRequest,
) (AuthenticationDecision, error) {
	preparer.trap.external("authentication")
	rejection := mustCommandError(domain.ErrorCodeUnauthenticated, "credential rejected")
	subject, err := UnattributedDenialSource(DigestBytes([]byte("authentication source")))
	if err != nil {
		return AuthenticationDecision{}, err
	}
	authority, _ := domain.ParseAuthorityID(applicationUUID(2))
	provenance, err := NewAuditProvenanceEvidence(authority, nil)
	if err != nil {
		return AuthenticationDecision{}, err
	}
	return RejectedAuthentication(rejection, subject, provenance)
}

func orchestrationAuditContext(t *testing.T) AuditRequestContext {
	t.Helper()
	value, err := NewAuditRequestContext(
		applicationUUID(90), applicationUUID(91), time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type orchestrationPolicy struct {
	trap     *orchestrationTrap
	revision domain.PolicyRevision
}

func (preparer orchestrationPolicy) PreparePolicy(
	context.Context,
	PolicyPreparationRequest,
) (PreparedPolicy, error) {
	preparer.trap.external("policy")
	revision := preparer.revision
	if revision.String() == "" {
		revision, _ = domain.NewPolicyRevision("policy-1")
	}
	return NewPreparedPolicy(revision, DigestBytes([]byte("prepared policy")))
}

type orchestrationSignerLookup struct {
	trap      *orchestrationTrap
	signer    testCapsuleSigner
	signers   map[string]testCapsuleSigner
	requested []string
	lookup    int
	signs     int
	lookupErr error
	signErr   error
}

func (lookup *orchestrationSignerLookup) PrepareRecoveryCapsuleSigner(
	_ context.Context,
	keyID string,
) (PreparedRecoveryCapsuleSigner, error) {
	lookup.trap.external("signer_lookup")
	lookup.lookup++
	lookup.requested = append(lookup.requested, keyID)
	if lookup.lookupErr != nil {
		return nil, lookup.lookupErr
	}
	signer := lookup.signer
	if selected, ok := lookup.signers[keyID]; ok {
		signer = selected
	}
	return orchestrationSigner{lookup: lookup, signer: signer}, nil
}

type orchestrationSigner struct {
	lookup *orchestrationSignerLookup
	signer testCapsuleSigner
}

func (signer orchestrationSigner) KeyID() string { return signer.signer.KeyID() }
func (signer orchestrationSigner) Ed25519PublicKey() ed25519.PublicKey {
	return signer.signer.Ed25519PublicKey()
}
func (signer orchestrationSigner) SignRecoveryCapsule(ctx context.Context, message []byte) ([]byte, error) {
	signer.lookup.trap.external("sign")
	signer.lookup.signs++
	if signer.lookup.signErr != nil {
		return nil, signer.lookup.signErr
	}
	return signer.signer.SignRecoveryCapsule(ctx, message)
}

type orchestrationBootstrapVerifier struct {
	trap  *orchestrationTrap
	proof domain.BootstrapProof
}

type orchestrationCeremonyVerifier struct {
	trap       *orchestrationTrap
	membership domain.CeremonyProof
	delegation domain.CeremonyProof
	handoff    domain.CeremonyProof
}

func (verifier orchestrationCeremonyVerifier) VerifyMembershipAcceptance(
	context.Context,
	CeremonyProofEvidence,
) (CeremonyProofVerification, error) {
	verifier.trap.external("membership_proof")
	return ValidCeremonyProof(verifier.membership)
}

func (verifier orchestrationCeremonyVerifier) VerifyDelegationActivation(
	context.Context,
	CeremonyProofEvidence,
) (CeremonyProofVerification, error) {
	verifier.trap.external("delegation_proof")
	return ValidCeremonyProof(verifier.delegation)
}

func (verifier orchestrationCeremonyVerifier) VerifyActorSessionHandoff(
	context.Context,
	CeremonyProofEvidence,
) (CeremonyProofVerification, error) {
	verifier.trap.external("handoff_proof")
	return ValidCeremonyProof(verifier.handoff)
}

type orchestrationPairingVerifier struct {
	trap         *orchestrationTrap
	verification PairingRedemptionVerification
}

func (verifier orchestrationPairingVerifier) VerifyPairingRedemption(
	context.Context,
	CeremonyProofEvidence,
) (PairingRedemptionDecision, error) {
	verifier.trap.external("pairing_redemption")
	return ValidPairingRedemption(verifier.verification)
}

func (verifier orchestrationBootstrapVerifier) VerifyBootstrapProof(
	context.Context,
	BootstrapProofEvidence,
) (BootstrapProofVerification, error) {
	verifier.trap.external("bootstrap_proof")
	return VerifiedBootstrapProof(verifier.proof), nil
}

type orchestrationAuthorizer struct {
	calls             int
	rejection         *domain.CommandError
	principalOverride domain.PrincipalID
	installation      domain.InstallationID
	trap              *orchestrationTrap
	policy            domain.PolicyRevision
	capabilities      domain.CapabilitySet
	assurance         domain.AssuranceClass
}

func (authorizer *orchestrationAuthorizer) AuthorizeLocked(
	locked CommandContext,
	_ AuthenticationEvidence,
	_ PreparedPolicy,
) (domain.IdentityAuthorization, error) {
	authorizer.calls++
	if authorizer.trap != nil {
		authorizer.trap.order = append(authorizer.trap.order, "authorization")
	}
	if authorizer.rejection != nil {
		return domain.IdentityAuthorization{}, authorizer.rejection
	}
	principal, _ := domain.ParsePrincipalID(applicationUUID(5))
	if !authorizer.principalOverride.IsZero() {
		principal = authorizer.principalOverride
	}
	installation := authorizer.installation
	if installation.IsZero() {
		installation, _ = domain.ParseInstallationID(locked.Spec().Scope().ID())
	}
	capabilities := authorizer.capabilities
	if capabilities.IsZero() {
		capabilities, _ = domain.NewCapabilitySet(domain.InstallationOwnerCapability())
	}
	policy := authorizer.policy
	if policy.String() == "" {
		policy, _ = domain.NewPolicyRevision("policy-1")
	}
	assurance := authorizer.assurance
	if assurance.String() == "" {
		assurance, _ = domain.NewAssuranceClass("strong")
	}
	var (
		value domain.IdentityAuthorization
		err   error
	)
	if locked.Spec().Guards().AdmissionScope().Kind() == domain.ScopeKindWorkspace {
		workspace, _ := domain.ParseWorkspaceID(locked.Spec().Scope().ID())
		value, err = domain.NewWorkspaceIdentityAuthorization(
			locked.Spec().AuthorityID(), locked.Spec().RequestedEpoch(), installation, workspace, principal,
			capabilities, policy, assurance, locked.TimeEvidence().Value(), domain.MaxActorSessionLifetime,
		)
	} else {
		value, err = domain.NewIdentityAuthorization(
			locked.Spec().AuthorityID(), locked.Spec().RequestedEpoch(), installation, principal,
			capabilities, policy, assurance, locked.TimeEvidence().Value(), domain.MaxActorSessionLifetime,
		)
	}
	return value, err
}

type orchestrationReplay struct{ disclosure ReplayDisclosure }

func (replay orchestrationReplay) AuthorizeReplay(
	CommandContext,
	AuthenticationEvidence,
	PreparedPolicy,
) (ReplayDisclosure, error) {
	return replay.disclosure, nil
}

type orchestrationReplayRejection struct{ rejection *domain.CommandError }

func (replay orchestrationReplayRejection) AuthorizeReplay(
	CommandContext,
	AuthenticationEvidence,
	PreparedPolicy,
) (ReplayDisclosure, error) {
	return "", replay.rejection
}

type orchestrationDenialPolicy struct{ calls int }

func (policy *orchestrationDenialPolicy) DenialFollowUp(
	locked CommandContext,
	authentication AuthenticationEvidence,
	prepared PreparedPolicy,
	rejection *domain.CommandError,
) (SecuritySpec, error) {
	policy.calls++
	class := DenialAuthorization
	if locked.ReceiptResolution().Kind() == ReceiptExactReplay {
		class = DenialResultDisclosure
	}
	subject, _ := AttributedDenialSubject(authentication.PrincipalID(), nil)
	draft, err := NewCommandDenialDraft(
		locked.Spec().Operation(), locked.Spec().OperationMajor(), class, "policy_denied",
		locked.Spec().RequestFingerprint(), subject, ptrPolicy(prepared.Revision()), locked.Spec().CorrelationID(),
	)
	if err != nil {
		return SecuritySpec{}, err
	}
	return RecordCommandDenialSecurity(
		locked.Spec().Scope(), locked.Spec().AuthorityID(), locked.Spec().RequestedEpoch(),
		locked.Spec().Guards().AdmissionGeneration(), draft,
	)
}

func ptrPolicy(value domain.PolicyRevision) *domain.PolicyRevision { return &value }

type orchestrationEffects struct{ trap *orchestrationTrap }

func (planner orchestrationEffects) PlanEffects(EffectPlanningInput) (EffectSet, error) {
	if planner.trap != nil {
		planner.trap.order = append(planner.trap.order, "effects")
	}
	return NewEffectSet()
}

type orchestrationPresentations struct {
	trap    *orchestrationTrap
	binding domain.PresentationCredentialBinding
}

func (preparer orchestrationPresentations) PreparePresentationCredential(
	context.Context,
	PresentationCredentialRequest,
) (domain.PresentationCredentialBinding, error) {
	preparer.trap.external("presentation")
	return preparer.binding, nil
}

type orchestrationDelivery struct{}

func (orchestrationDelivery) DeliverPresentationCredential(context.Context, string, []byte) error {
	return nil
}

func orchestrationPreparationRequests(
	t *testing.T,
	operation CommandOperation,
	scope domain.AuthorityScope,
	principal domain.PrincipalID,
	principalRevision domain.Version,
	authority domain.AuthorityID,
) (AuthenticationRequest, PolicyPreparationRequest) {
	t.Helper()
	provenance, err := NewAuditProvenanceEvidence(authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	audience, err := domain.NewCredentialAudience("blackbird:test")
	if err != nil {
		t.Fatal(err)
	}
	authentication, err := NewAuthenticationRequest(AuthenticationRequestParams{
		Operation: operation, Scope: scope, PrincipalID: principal, PrincipalRevision: principalRevision,
		ChannelBinding: DigestBytes([]byte("orchestration channel binding")), Audience: audience,
		AuditProvenance: provenance, VerifiedAt: time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	revision, _ := domain.NewPolicyRevision("policy-1")
	policy, err := NewPolicyPreparationRequest(authentication, revision, DigestBytes([]byte("prepared policy")))
	if err != nil {
		t.Fatal(err)
	}
	return authentication, policy
}

type orchestrationUOWMode uint8

const (
	orchestrationIndeterminate orchestrationUOWMode = iota + 1
	orchestrationRejected
	orchestrationReplayOnly
	orchestrationCommitted
)

type strictOrchestrationUOW struct {
	t                 *testing.T
	trap              *orchestrationTrap
	mode              orchestrationUOWMode
	contexts          []CommandContext
	replayReceipt     ReceiptSnapshot
	replayAccess      ReplayDisclosure
	callbackCalls     int
	writes            int
	securityCalls     int
	specs             []CommandSpec
	decisions         []CommandDecision
	securitySpecs     []SecuritySpec
	securityDecisions []SecurityDecision
	denialAdmission   DenialAdmissionKind
	securityErr       error
	callbackErr       error
	callbackErrors    []error
}

func (unit *strictOrchestrationUOW) ExecuteCommand(
	_ context.Context,
	spec CommandSpec,
	decide func(CommandContext) (CommandDecision, error),
) (CommandTransactionExecution, error) {
	unit.specs = append(unit.specs, spec)
	for _, locked := range unit.contexts {
		unit.trap.order = append(unit.trap.order, "callback")
		unit.trap.inCallback = true
		decision, err := decide(locked)
		unit.callbackErrors = append(unit.callbackErrors, err)
		unit.trap.inCallback = false
		unit.callbackCalls++
		if unit.callbackErr != nil {
			err = unit.callbackErr
		}
		if err != nil {
			unit.trap.order = append(unit.trap.order, "rollback")
			return CommandTransactionExecution{}, err
		}
		unit.decisions = append(unit.decisions, decision)
		switch decision.Kind() {
		case CommandDecisionApplied:
			unit.writes += len(decision.Writes())
			if unit.mode == orchestrationCommitted {
				return unit.commitExecution(spec, locked, decision)
			}
		case CommandDecisionRollback:
			unit.trap.order = append(unit.trap.order, "rollback")
			rejection, _ := decision.Rejection()
			denial, _ := decision.DenialAudit()
			return RejectedCommandTransactionExecution(rejection, denial)
		case CommandDecisionReplay:
			return ReplayedCommandTransactionExecution(unit.replayReceipt, unit.replayAccess)
		}
	}
	if unit.mode == orchestrationIndeterminate {
		return IndeterminateCommandTransactionExecution(spec)
	}
	return CommandTransactionExecution{}, ErrInvalidCommandExecution
}

func (unit *strictOrchestrationUOW) commitExecution(
	spec CommandSpec,
	locked CommandContext,
	decision CommandDecision,
) (CommandTransactionExecution, error) {
	if err := materializeRecordedDecision(spec, locked, decision); err != nil {
		return CommandTransactionExecution{}, err
	}
	first, _ := domain.NewStreamPosition(1)
	last, _ := domain.NewStreamPosition(uint64(len(decision.Facts())))
	digest, _ := domain.NewStreamDigest([32]byte{91, byte(len(decision.Facts()))})
	result, err := NewProductionCanonicalCodec().MaterializeReceiptResult(decision.ResultPlan(), first, last, digest)
	if err != nil {
		return CommandTransactionExecution{}, err
	}
	events, err := NewEventRange(first, last, uint16(len(decision.Facts())))
	if err != nil {
		return CommandTransactionExecution{}, err
	}
	var draft *RecoveryCapsuleDraft
	if spec.RecoveryCapsule().Requirement() == RecoveryCapsuleRequired {
		draft = mustCapsuleDraft(unit.t, result, spec.CommandID(), spec.OperationMajor(), spec.RecoveryCapsule().KeyID())
	}
	receipt, err := NewReceiptSnapshot(ReceiptSnapshotParams{
		ReceiptID: spec.ReceiptID(), CommandID: spec.CommandID(), Identity: spec.ReceiptIdentity(),
		RequestFingerprint: spec.RequestFingerprint(), Result: result, AuthorityID: spec.AuthorityID(),
		AuthorityEpoch: spec.RequestedEpoch(), GuardDigest: locked.GuardEvidence().Digest(), Events: events,
		EventCursor:        EventCursor{value: "bbec1_orchestration_fixture"},
		CapsuleRequirement: spec.RecoveryCapsule().Requirement(), RecoveryCapsule: draft,
	})
	if err != nil {
		return CommandTransactionExecution{}, err
	}
	unit.trap.order = append(unit.trap.order, "commit")
	return CommittedCommandTransactionExecution(receipt)
}

func materializeRecordedDecision(spec CommandSpec, locked CommandContext, decision CommandDecision) error {
	codec := NewProductionCanonicalCodec()
	previous, _ := domain.NewStreamDigest([32]byte{1})
	schema, _ := domain.NewEventSchemaVersion(1)
	for index, intent := range decision.Facts() {
		payload, err := codec.MaterializeIdentityFactPayload(intent.Fact())
		if err != nil {
			return fmt.Errorf("materialize fact %d: %w", index, err)
		}
		position, _ := domain.NewStreamPosition(uint64(index + 1))
		placeholderEvent, _ := domain.NewEventDigest([32]byte{2})
		placeholderStream, _ := domain.NewStreamDigest([32]byte{3})
		params := domain.EventEnvelopeParams{
			EventID: intent.EventID(), CommandID: spec.CommandID(), AuthorityID: spec.AuthorityID(),
			AuthorityEpoch: spec.RequestedEpoch(), Scope: spec.Scope(), StreamPosition: position,
			PreviousStreamDigest: previous, EventDigest: placeholderEvent, StreamDigest: placeholderStream,
			Aggregate: intent.Fact().Origin(), EventIndex: uint16(index), EventType: intent.Fact().Type(),
			SchemaVersion: schema, Payload: payload, PrincipalID: spec.Authorship().PrincipalID(),
			AuthorizationDigest: locked.GuardEvidence().Digest(), CommandReceiptID: spec.ReceiptID(),
			CorrelationID: spec.CorrelationID(), RecordedAt: locked.TimeEvidence().Value(),
		}
		if attribution, present := spec.Authorship().ActorAttribution(); present {
			actorSession := attribution.ActorSessionID()
			params.ActorSessionID = &actorSession
		}
		if causation, present := spec.CausationEventID(); present {
			params.CausationEventID = &causation
		}
		unverified, err := domain.NewEventEnvelope(params, permissiveEventVerifier{})
		if err != nil {
			return fmt.Errorf("construct event %d: %w", index, err)
		}
		view, err := eventSemanticView(unverified)
		if err != nil {
			return fmt.Errorf(
				"event view %d type=%s origin=%s/%s scope=%s/%s: %w", index, intent.Fact().Type(),
				intent.Fact().Origin().Kind(), intent.Fact().Origin().ID(), spec.Scope().Kind(), spec.Scope().ID(), err,
			)
		}
		params.EventDigest, err = codec.HashEvent(view)
		if err != nil {
			return fmt.Errorf("hash event %d: %w", index, err)
		}
		params.StreamDigest, err = codec.ChainStreamDigest(previous, position, params.EventDigest)
		if err != nil {
			return fmt.Errorf("chain event %d: %w", index, err)
		}
		materialized, err := codec.MaterializeEvent(params)
		if err != nil {
			return fmt.Errorf("verify event %d: %w", index, err)
		}
		previous = materialized.StreamDigest()
	}
	audit, err := NewAuditEntryViewV1(AuditEntryParams{
		ChainScopeID: spec.Scope(), Sequence: 1, AuthorityID: spec.AuthorityID(),
		AuthorityEpoch: spec.RequestedEpoch(), RecordedAt: locked.TimeEvidence().Value(), Intent: decision.Audit(),
	})
	if err != nil {
		return fmt.Errorf("materialize audit: %w", err)
	}
	_, _, err = codec.EncodeAuditEntry(audit)
	if err != nil {
		return fmt.Errorf("encode audit: %w", err)
	}
	return nil
}

func (unit *strictOrchestrationUOW) ExecuteSecurity(
	_ context.Context,
	spec SecuritySpec,
	decide func(SecurityContext) (SecurityDecision, error),
) (SecurityExecution, error) {
	unit.securityCalls++
	unit.securitySpecs = append(unit.securitySpecs, spec)
	unit.trap.order = append(unit.trap.order, "security")
	authorityTime := unit.contexts[0].TimeEvidence().Value()
	admissionKind := unit.denialAdmission
	if admissionKind == "" {
		admissionKind = DenialSuppressDuplicate
	}
	var distinct uint8
	var scope uint16
	switch admissionKind {
	case DenialAdmitDistinct:
		distinct, scope = 1, 1
	case DenialAdmitSaturation:
		distinct, scope = uint8(MaxDistinctDenialsPerMinute), 1
	case DenialAdmitScopeSaturation:
		distinct, scope = 1, uint16(MaxDenialEntriesPerScopeMinute)
	}
	admission, _ := NewDenialAdmission(admissionKind, authorityTime, distinct, scope)
	locked, err := NewSecurityContext(
		spec, authorityTime, domain.InstallationInvitationState{}, SecurityAttemptResolution{}, admission,
		unit.contexts[0].GuardEvidence().Digest(),
	)
	if err != nil {
		return SecurityExecution{}, err
	}
	unit.trap.inCallback = true
	decision, err := decide(locked)
	unit.trap.inCallback = false
	if unit.securityErr != nil {
		return SecurityExecution{}, unit.securityErr
	}
	if err != nil {
		return SecurityExecution{}, err
	}
	unit.securityDecisions = append(unit.securityDecisions, decision)
	switch decision.Kind() {
	case SecurityDecisionSuppressDenial:
		return CommandDenialSecurityExecution(false), nil
	case SecurityDecisionAuditDenial:
		audit, auditErr := NewAuditEntryViewV1(AuditEntryParams{
			ChainScopeID: spec.scope, Sequence: 1, AuthorityID: spec.authorityID, AuthorityEpoch: spec.epoch,
			RecordedAt: authorityTime, Intent: decision.audit,
		})
		if auditErr != nil {
			return SecurityExecution{}, auditErr
		}
		if _, _, auditErr = NewProductionCanonicalCodec().EncodeAuditEntry(audit); auditErr != nil {
			return SecurityExecution{}, auditErr
		}
		return CommandDenialSecurityExecution(true), nil
	default:
		return SecurityExecution{}, ErrInvalidSecurityDecision
	}
}

func orchestrationFixture(t *testing.T, mode orchestrationUOWMode) (
	*OrchestrationService,
	BootstrapInstallationRequest,
	*strictOrchestrationUOW,
	*orchestrationAuthorizer,
	*orchestrationDenialPolicy,
	*orchestrationSignerLookup,
) {
	t.Helper()
	fixture := buildBootstrapFixture(t)
	contextParams := W0CommandHashContextParams{
		ScopeKind:     StreamScopeInstallation,
		ScopeID:       mustCanonical(t, fixture.scope.ID()),
		PrincipalID:   mustCanonical(t, fixture.input.PrincipalID.String()),
		CorrelationID: mustCanonical(t, fixture.correlation.String()),
	}
	view, err := NewBootstrapInstallationCommandHashView(contextParams, BootstrapInstallationCommandHashParams{
		InstallationID:        mustCanonical(t, fixture.input.Invitation.InstallationID().String()),
		Invitation:            CommandExpectedResource{ID: mustCanonical(t, fixture.input.Invitation.ID().String()), ExpectedVersion: fixture.input.Invitation.Version().Uint64()},
		BootstrapGenerationID: mustCanonical(t, fixture.input.CurrentGeneration.String()),
		ApprovedTranscript:    orchestrationCanonicalFingerprint(t, fixture.input.Proof.TranscriptFingerprint()),
		PrincipalID:           mustCanonical(t, fixture.input.PrincipalID.String()), PrincipalDisplayName: fixture.input.PrincipalDisplayName.String(),
		DeviceID: mustCanonical(t, fixture.input.DeviceID.String()), DeviceDisplayName: fixture.input.DeviceDisplayName.String(),
		DevicePublicKeyReference: fixture.input.DevicePublicKey.String(),
		DeviceSPKIFingerprint:    mustCredentialDigest(t, fixture.input.Proof.DeviceSPKIFingerprint()),
		OwnerGrantID:             mustCanonical(t, fixture.input.OwnerGrantID.String()),
		OwnerGrantCapabilities:   capabilityStrings(fixture.input.OwnerGrantCapabilities),
	})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := NewProductionCanonicalCodec().HashCommand(view)
	fixture.spec.requestFingerprint = fingerprint
	fixture.context.spec = fixture.spec
	trap := &orchestrationTrap{}
	unit := &strictOrchestrationUOW{
		t: t, trap: trap, mode: mode, contexts: []CommandContext{fixture.context}, replayAccess: ReplayDiscloseAppliedOnly,
	}
	authorizer := &orchestrationAuthorizer{trap: trap}
	denial := &orchestrationDenialPolicy{}
	signers := &orchestrationSignerLookup{trap: trap, signer: fixture.capsuleSigner}
	service, err := NewOrchestrationService(OrchestrationDependencies{
		UnitOfWork: unit, Authentication: orchestrationAuthentication{trap: trap}, Policy: orchestrationPolicy{trap: trap},
		LockedAuthorization: authorizer, ReplayDisclosure: orchestrationReplay{ReplayDiscloseAppliedOnly},
		DenialPolicy: denial, SignerLookup: signers, EffectPlanner: orchestrationEffects{trap},
		BootstrapProofs:    orchestrationBootstrapVerifier{trap, fixture.input.Proof},
		CeremonyProofs:     orchestrationCeremonyVerifier{trap: trap},
		PairingRedemptions: orchestrationPairingVerifier{trap: trap},
		Presentations:      orchestrationPresentations{trap: trap},
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := NewBootstrapProofEvidence([]byte("proof"))
	authentication, policy := orchestrationPreparationRequests(
		t, CommandBootstrapInstallation, fixture.scope, fixture.input.PrincipalID,
		domain.InitialVersion(), fixture.spec.AuthorityID(),
	)
	authentication.device, authentication.hasDevice = fixture.input.DeviceID, true
	authentication.deviceRevision = domain.InitialVersion()
	authentication.deviceTrustRevision = domain.InitialVersion()
	authentication.deviceRevokeRevision = domain.InitialVersion()
	authentication.credentialFingerprint = fixture.input.Proof.DeviceSPKIFingerprint()
	policy, _ = NewPolicyPreparationRequest(authentication, policy.PolicyRevision(), policy.PolicyDigest())
	request := BootstrapInstallationRequest{
		CommandRequest: CommandRequest{Spec: fixture.spec, HashView: view,
			Authentication: authentication,
			Policy:         policy,
			Audit:          orchestrationAuditContext(t)},
		ProofEvidence: evidence, GenerationAuthorization: fixture.input.GenerationAuthorization,
		InvitationID: fixture.input.Invitation.ID(), PrincipalID: fixture.input.PrincipalID,
		PrincipalDisplayName: fixture.input.PrincipalDisplayName, DeviceID: fixture.input.DeviceID,
		DeviceDisplayName: fixture.input.DeviceDisplayName, DevicePublicKey: fixture.input.DevicePublicKey,
		OwnerGrantID: fixture.input.OwnerGrantID, OwnerCapabilities: fixture.input.OwnerGrantCapabilities,
	}
	return service, request, unit, authorizer, denial, signers
}

func mustCanonical(t *testing.T, value string) CanonicalIdentifier {
	t.Helper()
	result, err := NewCanonicalIdentifier(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func orchestrationCanonicalFingerprint(t *testing.T, value domain.CommandFingerprint) CanonicalDigest {
	t.Helper()
	result, err := NewCanonicalDigest(Digest(value).String())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustCredentialDigest(t *testing.T, value domain.CredentialDigest) CanonicalDigest {
	t.Helper()
	result, err := NewCanonicalDigest(Digest(value.Bytes()).String())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestBootstrapRetryRechecksLockedStateAndSuppressesPostOutcomeWork(t *testing.T) {
	service, request, unit, authorizer, denial, signers := orchestrationFixture(t, orchestrationIndeterminate)
	unit.contexts = append(unit.contexts, unit.contexts[0])
	execution, err := service.BootstrapInstallation(context.Background(), request)
	if err != nil || execution.Kind() != CommandIndeterminate {
		t.Fatalf("execution=%s error=%v", execution.Kind(), err)
	}
	if authorizer.calls != 0 || unit.callbackCalls != 2 {
		t.Fatalf("authorization=%d callbacks=%d, bootstrap used ordinary authorization", authorizer.calls, unit.callbackCalls)
	}
	if denial.calls != 0 || unit.securityCalls != 0 || signers.signs != 0 {
		t.Fatalf("indeterminate ran denial/signing: denial=%d security=%d signs=%d", denial.calls, unit.securityCalls, signers.signs)
	}
}

func TestBootstrapBypassesOrdinaryAuthenticationAndCurrentAuthorization(t *testing.T) {
	service, request, unit, authorizer, denial, _ := orchestrationFixture(t, orchestrationIndeterminate)
	authorizer.rejection = mustCommandError(domain.ErrorCodeForbidden, "policy denied")
	execution, err := service.BootstrapInstallation(context.Background(), request)
	if err != nil || execution.Kind() != CommandIndeterminate {
		t.Fatalf("execution=%s error=%v", execution.Kind(), err)
	}
	if authorizer.calls != 0 || denial.calls != 0 || unit.securityCalls != 0 {
		t.Fatalf("authorization=%d denial=%d security=%d", authorizer.calls, denial.calls, unit.securityCalls)
	}
	for _, event := range unit.trap.order {
		if event == "authentication" {
			t.Fatalf("bootstrap called ordinary authentication: %v", unit.trap.order)
		}
	}
	proofCall, callback := -1, -1
	for index, event := range unit.trap.order {
		if event == "bootstrap_proof" && proofCall < 0 {
			proofCall = index
		}
		if event == "callback" && callback < 0 {
			callback = index
		}
	}
	if proofCall < 0 || callback <= proofCall {
		t.Fatalf("bootstrap verifier did not precede callback: %v", unit.trap.order)
	}
}

func TestOrchestrationReplayIsWriteFree(t *testing.T) {
	service, request, unit, authorizer, _, signers := orchestrationFixture(t, orchestrationReplayOnly)
	fixture := buildBootstrapFixture(t)
	receipt := bootstrapReceipt(t, fixture)
	receipt.requestFingerprint = request.Spec.RequestFingerprint()
	replay, _ := ReplayReceipt(receipt)
	disclosureTime, _ := ReadOnlyDisclosureTime(fixture.now, fixture.now)
	invitationState, _ := NewIdentityState(fixture.invitation)
	locked, err := NewCommandContext(request.Spec, disclosureTime, []IdentityState{invitationState}, replay, fixture.context.GuardEvidence())
	if err != nil {
		t.Fatal(err)
	}
	unit.contexts = []CommandContext{locked}
	unit.replayReceipt = receipt
	execution, err := service.BootstrapInstallation(context.Background(), request)
	if err != nil || execution.Kind() != CommandReplayed {
		t.Fatalf("execution=%s error=%v", execution.Kind(), err)
	}
	if unit.writes != 0 || authorizer.calls != 0 || signers.signs != 0 {
		t.Fatalf("replay writes=%d authorization=%d signs=%d", unit.writes, authorizer.calls, signers.signs)
	}
}

func TestOrchestrationAppliedOnlyReplayDoesNotRequireCurrentSigner(t *testing.T) {
	service, request, unit, _, _, signers := orchestrationFixture(t, orchestrationReplayOnly)
	signers.lookupErr = errors.New("current key unavailable")
	fixture := buildBootstrapFixture(t)
	receipt := bootstrapReceipt(t, fixture)
	receipt.requestFingerprint = request.Spec.RequestFingerprint()
	replay, _ := ReplayReceipt(receipt)
	disclosureTime, _ := ReadOnlyDisclosureTime(fixture.now, fixture.now)
	invitationState, _ := NewIdentityState(fixture.invitation)
	locked, err := NewCommandContext(
		request.Spec, disclosureTime, []IdentityState{invitationState}, replay, fixture.context.GuardEvidence(),
	)
	if err != nil {
		t.Fatal(err)
	}
	unit.contexts = []CommandContext{locked}
	unit.replayReceipt = receipt

	execution, err := service.BootstrapInstallation(context.Background(), request)
	if err != nil || execution.Kind() != CommandReplayed {
		t.Fatalf("execution=%s error=%v", execution.Kind(), err)
	}
	if unit.writes != 0 || signers.signs != 0 {
		t.Fatalf("writes=%d signs=%d", unit.writes, signers.signs)
	}
}

func TestOrchestrationFullReplayUsesHistoricalReceiptSigner(t *testing.T) {
	service, request, unit, _, _, signers := orchestrationFixture(t, orchestrationReplayOnly)
	fixture := buildBootstrapFixture(t)
	receipt := bootstrapReceipt(t, fixture)
	receipt.requestFingerprint = request.Spec.RequestFingerprint()

	historicalSigner := fixture.capsuleSigner
	currentSigner := newTestCapsuleSigner("ed25519:rotated-current")
	currentPlan, err := PrepareRecoveryCapsulePlan(currentSigner)
	if err != nil {
		t.Fatal(err)
	}
	request.Spec.recoveryCapsule = currentPlan
	signers.signer = currentSigner
	signers.signers = map[string]testCapsuleSigner{
		historicalSigner.KeyID(): historicalSigner,
		currentSigner.KeyID():    currentSigner,
	}
	service.replayDisclosure = orchestrationReplay{ReplayDiscloseResult}
	unit.replayAccess = ReplayDiscloseResult

	replay, _ := ReplayReceipt(receipt)
	disclosureTime, _ := ReadOnlyDisclosureTime(fixture.now, fixture.now)
	invitationState, _ := NewIdentityState(fixture.invitation)
	locked, err := NewCommandContext(
		request.Spec, disclosureTime, []IdentityState{invitationState}, replay, fixture.context.GuardEvidence(),
	)
	if err != nil {
		t.Fatal(err)
	}
	unit.contexts = []CommandContext{locked}
	unit.replayReceipt = receipt

	execution, err := service.BootstrapInstallation(context.Background(), request)
	if err != nil || execution.Kind() != CommandReplayed {
		t.Fatalf("execution=%s error=%v", execution.Kind(), err)
	}
	if unit.writes != 0 || signers.signs != 1 || len(signers.requested) != 2 ||
		signers.requested[0] != currentSigner.KeyID() || signers.requested[1] != historicalSigner.KeyID() {
		t.Fatalf("writes=%d signs=%d requested=%v", unit.writes, signers.signs, signers.requested)
	}
}

func TestOrchestrationRejectsReceiptSubstitutedAfterReplayCallback(t *testing.T) {
	service, request, unit, _, _, _ := orchestrationFixture(t, orchestrationReplayOnly)
	fixture := buildBootstrapFixture(t)
	receipt := bootstrapReceipt(t, fixture)
	receipt.requestFingerprint = request.Spec.RequestFingerprint()
	replay, _ := ReplayReceipt(receipt)
	disclosureTime, _ := ReadOnlyDisclosureTime(fixture.now, fixture.now)
	invitationState, _ := NewIdentityState(fixture.invitation)
	locked, err := NewCommandContext(
		request.Spec, disclosureTime, []IdentityState{invitationState}, replay, fixture.context.GuardEvidence(),
	)
	if err != nil {
		t.Fatal(err)
	}
	unit.contexts = []CommandContext{locked}
	unit.replayReceipt = receipt
	unit.replayReceipt.receiptID, _ = domain.ParseReceiptID(applicationUUID(99))

	if _, err = service.BootstrapInstallation(context.Background(), request); !errors.Is(err, ErrInvalidCommandExecution) {
		t.Fatalf("substituted replay receipt error=%v", err)
	}
}

func TestOrchestrationRejectsAuthorizationForDifferentPrincipal(t *testing.T) {
	service, request, unit, authorizer, _, _ := orchestrationFixture(t, orchestrationIndeterminate)
	authorizer.principalOverride, _ = domain.ParsePrincipalID(applicationUUID(99))
	called := false
	_, err := service.executeCommand(
		context.Background(), request.CommandRequest, CommandBootstrapInstallation,
		func(CommandContext, domain.IdentityAuthorization, AuthenticationEvidence, PreparedPolicy) (OperationCommit, error) {
			called = true
			return OperationCommit{}, nil
		},
	)
	if !errors.Is(err, ErrInvalidApplicationContract) || called || unit.writes != 0 {
		t.Fatalf("error=%v called=%t writes=%d", err, called, unit.writes)
	}
}

func TestOrchestrationRejectsAuthenticationAndAuthorizationForWrongAuthor(t *testing.T) {
	service, request, unit, authorizer, _, _ := orchestrationFixture(t, orchestrationIndeterminate)
	wrongPrincipal, _ := domain.ParsePrincipalID(applicationUUID(99))
	service.authentication = orchestrationAuthentication{
		trap: unit.trap, authority: request.Spec.AuthorityID(), principal: wrongPrincipal,
	}
	authorizer.principalOverride = wrongPrincipal
	called := false
	_, err := service.executeCommand(
		context.Background(), request.CommandRequest, CommandBootstrapInstallation,
		func(CommandContext, domain.IdentityAuthorization, AuthenticationEvidence, PreparedPolicy) (OperationCommit, error) {
			called = true
			return OperationCommit{}, nil
		},
	)
	if !errors.Is(err, ErrInvalidApplicationContract) || called || unit.writes != 0 {
		t.Fatalf("error=%v called=%t writes=%d", err, called, unit.writes)
	}
}

func TestOrchestrationRejectsHashProfileMismatchBeforeExternalPreparation(t *testing.T) {
	service, request, unit, _, _, _ := orchestrationFixture(t, orchestrationIndeterminate)
	request.HashView = registerPrincipalCommandHashView{}
	_, err := service.BootstrapInstallation(context.Background(), request)
	if !errors.Is(err, ErrInvalidCommandSpec) {
		t.Fatalf("error=%v, want invalid command spec", err)
	}
	if len(unit.trap.order) != 0 {
		t.Fatalf("unexpected external calls: %v", unit.trap.order)
	}
}

func TestOrchestrationAuthenticationRejectionUsesOnlySecurityTransaction(t *testing.T) {
	service, request, unit, _, _, _ := orchestrationFixture(t, orchestrationIndeterminate)
	service.authentication = orchestrationRejectedAuthentication{trap: unit.trap}

	execution, err := service.executeCommand(
		context.Background(), request.CommandRequest, CommandBootstrapInstallation,
		func(CommandContext, domain.IdentityAuthorization, AuthenticationEvidence, PreparedPolicy) (OperationCommit, error) {
			t.Fatal("authentication rejection reached ordinary command callback")
			return OperationCommit{}, nil
		},
	)
	if err != nil || execution.Kind() != CommandRejected {
		t.Fatalf("execution=%s error=%v", execution.Kind(), err)
	}
	if unit.callbackCalls != 0 || unit.securityCalls != 1 || unit.writes != 0 {
		t.Fatalf("callbacks=%d security=%d writes=%d", unit.callbackCalls, unit.securityCalls, unit.writes)
	}
}

func TestOrchestrationRejectsLaunderedBootstrapRequestBeforeExternalPreparation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*BootstrapInstallationRequest)
	}{
		{"authentication scope", func(request *BootstrapInstallationRequest) { request.Authentication.scope = domain.AuthorityScope{} }},
		{"policy scope", func(request *BootstrapInstallationRequest) { request.Policy.scope = domain.AuthorityScope{} }},
		{"protocol capabilities", func(request *BootstrapInstallationRequest) { request.ProtocolCapabilities = []string{"laundered"} }},
		{"authorship principal", func(request *BootstrapInstallationRequest) {
			request.Spec.authorship.principal, _ = domain.ParsePrincipalID(applicationUUID(99))
		}},
		{"correlation", func(request *BootstrapInstallationRequest) {
			request.Spec.correlationID, _ = domain.ParseCorrelationID(applicationUUID(99))
		}},
		{"invitation", func(request *BootstrapInstallationRequest) { request.InvitationID = domain.InvitationID{} }},
		{"generation authorization", func(request *BootstrapInstallationRequest) {
			request.GenerationAuthorization = domain.BootstrapGenerationAuthorization{}
		}},
		{"principal", func(request *BootstrapInstallationRequest) { request.PrincipalID = domain.PrincipalID{} }},
		{"principal display name", func(request *BootstrapInstallationRequest) { request.PrincipalDisplayName = domain.DisplayName{} }},
		{"device", func(request *BootstrapInstallationRequest) { request.DeviceID = domain.DeviceID{} }},
		{"device display name", func(request *BootstrapInstallationRequest) { request.DeviceDisplayName = domain.DisplayName{} }},
		{"device public key", func(request *BootstrapInstallationRequest) { request.DevicePublicKey = domain.PublicKeyReference{} }},
		{"owner grant", func(request *BootstrapInstallationRequest) { request.OwnerGrantID = domain.GrantID{} }},
		{"owner capabilities", func(request *BootstrapInstallationRequest) { request.OwnerCapabilities = domain.CapabilitySet{} }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, request, unit, authorizer, denial, signers := orchestrationFixture(t, orchestrationIndeterminate)
			test.mutate(&request)
			_, err := service.BootstrapInstallation(context.Background(), request)
			if !errors.Is(err, ErrInvalidCommandSpec) {
				t.Fatalf("error=%v, want invalid command spec", err)
			}
			if len(unit.trap.order) != 0 || unit.callbackCalls != 0 || unit.securityCalls != 0 ||
				authorizer.calls != 0 || denial.calls != 0 || signers.lookup != 0 {
				t.Fatalf("laundered request reached dependencies: order=%v callbacks=%d security=%d auth=%d denial=%d signers=%d",
					unit.trap.order, unit.callbackCalls, unit.securityCalls, authorizer.calls, denial.calls, signers.lookup)
			}
		})
	}
}

type orchestrationHandlerCase struct {
	name     CommandOperation
	pipeline completedOperationPipeline
	invoke   func(context.Context, *OrchestrationService) (CommandExecution, error)
}

func orchestrationResource(t *testing.T, value any) CommandExpectedResource {
	t.Helper()
	ref := mustStateRef(t, value)
	return CommandExpectedResource{ID: mustCanonical(t, ref.ID()), ExpectedVersion: ref.Version().Uint64()}
}

func orchestrationCeremony(t *testing.T, value domain.CeremonyChallenge) CommandCeremony {
	t.Helper()
	at, err := NewCanonicalInstant(value.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	return CommandCeremony{
		ID: mustCanonical(t, value.ID().String()), ExpiresAt: at,
		ProofDigest: orchestrationCanonicalFingerprint(t, value.ProofDigest()),
	}
}

func orchestrationCommandContext(t *testing.T, pipeline completedOperationPipeline) W0CommandHashContextParams {
	t.Helper()
	authorship := pipeline.spec.Authorship()
	params := W0CommandHashContextParams{
		ScopeKind: StreamScopeKind(pipeline.spec.Scope().Kind()), ScopeID: mustCanonical(t, pipeline.spec.Scope().ID()),
		PrincipalID:      mustCanonical(t, authorship.PrincipalID().String()),
		CorrelationID:    mustCanonical(t, pipeline.spec.CorrelationID().String()),
		ClientInstanceID: mustCanonical(t, pipeline.spec.ReceiptIdentity().ClientInstanceID().String()),
	}
	if attribution, present := authorship.ActorAttribution(); present {
		params.ActorID = mustCanonical(t, attribution.ActorID().String())
		params.ActorSessionID = mustCanonical(t, attribution.ActorSessionID().String())
	}
	return params
}

func orchestrationProof(challenge domain.CeremonyChallenge) domain.CeremonyProof {
	proof, _ := domain.NewCeremonyProof(
		challenge.ID(), challenge.Purpose(), challenge.ProofDigest(), challenge.PrincipalID(), challenge.DeviceID(),
	)
	return proof
}

func orchestrationEvidence(t *testing.T) CeremonyProofEvidence {
	t.Helper()
	evidence, err := NewCeremonyProofEvidence([]byte("strict orchestration proof"))
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func finalizeOrchestrationPipeline(
	t *testing.T,
	pipeline completedOperationPipeline,
	view CommandHashView,
) completedOperationPipeline {
	t.Helper()
	fingerprint, err := NewProductionCanonicalCodec().HashCommand(view)
	if err != nil {
		t.Fatal(err)
	}
	pipeline.spec.requestFingerprint = fingerprint
	pipeline.context.spec = pipeline.spec
	return pipeline
}

func buildOrchestrationHandlerCases(t *testing.T, path operationDomainPath) []orchestrationHandlerCase {
	t.Helper()
	definitions := buildOperationPipelineCases(t, path)
	byOperation := make(map[CommandOperation]completedOperationPipeline, len(definitions))
	for index, definition := range definitions {
		pipeline := completeOperationPipeline(t, path, definition, index)
		byOperation[definition.operation] = pipeline
	}
	evidence := orchestrationEvidence(t)
	owner := path.bootstrap.Principal()
	grant := path.bootstrap.OwnerGrant()
	workspace := path.createdWorkspace.Workspace()
	workload := path.registered.Principal()
	member := path.accepted.Membership()
	actor := path.createdActor.Actor()
	delegation := path.activated.Delegation()
	pendingDevice := path.pairingBegan.Device()

	makeRequest := func(pipeline completedOperationPipeline, view CommandHashView) CommandRequest {
		principalRevision := domain.InitialVersion()
		for _, state := range pipeline.context.States() {
			if principal, ok := state.Value().(domain.PrincipalState); ok && principal.ID() == pipeline.spec.Authorship().PrincipalID() {
				principalRevision = principal.Version()
				break
			}
		}
		authentication, policy := orchestrationPreparationRequests(
			t, pipeline.caseDefinition.operation, pipeline.spec.Scope(), pipeline.spec.Authorship().PrincipalID(),
			principalRevision, pipeline.spec.AuthorityID(),
		)
		return CommandRequest{
			Spec: pipeline.spec, HashView: view,
			Authentication: authentication,
			Policy:         policy,
			Audit:          orchestrationAuditContext(t),
		}
	}
	result := make([]orchestrationHandlerCase, 0, len(definitions))
	for _, definition := range definitions {
		pipeline := byOperation[definition.operation]
		if definition.operation == CommandStartActorSession {
			identity := pipeline.spec.ReceiptIdentity()
			scope, scopeErr := domain.NewIdempotencyScope(
				identity.WorkspaceID(), identity.PrincipalID(), path.sessionStarted.Session().ClientInstanceID(),
				identity.Operation(), identity.Key(),
			)
			if scopeErr != nil {
				t.Fatal(scopeErr)
			}
			pipeline.spec.receiptIdentity, scopeErr = OrdinaryReceiptIdentity(scope)
			if scopeErr != nil {
				t.Fatal(scopeErr)
			}
			pipeline.context.spec = pipeline.spec
		}
		contextParams := orchestrationCommandContext(t, pipeline)
		var view CommandHashView
		var err error
		switch definition.operation {
		case CommandRegisterPrincipal:
			view, err = NewRegisterPrincipalCommandHashView(contextParams, RegisterPrincipalCommandHashParams{
				Registrar: orchestrationResource(t, owner), PrincipalID: mustCanonical(t, workload.ID().String()),
				Kind: string(workload.Kind()), DisplayName: workload.DisplayName().String(),
				PublicKeyReference: workload.PublicKeyReference().String(),
			})
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := RegisterPrincipalRequest{CommandRequest: makeRequest(pipeline, view), RegistrarID: owner.ID(),
				PrincipalID: workload.ID(), Kind: workload.Kind(), DisplayName: workload.DisplayName(), PublicKeyReference: workload.PublicKeyReference()}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.RegisterPrincipal(ctx, request)
				}})
		case CommandCreateWorkspace:
			membership := path.createdWorkspace.OwnerMembership()
			view, err = NewCreateWorkspaceCommandHashView(contextParams, CreateWorkspaceCommandHashParams{
				Owner: orchestrationResource(t, owner), InstallationGrant: orchestrationResource(t, grant),
				WorkspaceID: mustCanonical(t, workspace.ID().String()), Alias: workspace.Alias().String(),
				DiscoveryLocator: workspace.DiscoveryLocator().String(), OwnerMembershipID: mustCanonical(t, membership.ID().String()),
				OwnerCapabilities: capabilityStrings(membership.Capabilities()),
			})
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := CreateWorkspaceRequest{CommandRequest: makeRequest(pipeline, view), OwnerID: owner.ID(), InstallationGrantID: grant.ID(),
				WorkspaceID: workspace.ID(), Alias: workspace.Alias(), DiscoveryLocator: workspace.DiscoveryLocator(),
				OwnerMembershipID: membership.ID(), OwnerCapabilities: membership.Capabilities()}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.CreateWorkspace(ctx, request)
				}})
		case CommandInviteWorkspaceMember:
			invited := path.invited.Membership()
			challenge := invited.AcceptanceChallenge()
			creation, _ := domain.ExpectCeremonyAbsent(challenge.ID())
			view, err = NewInviteWorkspaceMemberCommandHashView(contextParams, InviteWorkspaceMemberCommandHashParams{
				Administrator: orchestrationResource(t, owner), Workspace: orchestrationResource(t, workspace),
				Principal: orchestrationResource(t, workload), MembershipID: mustCanonical(t, invited.ID().String()),
				Capabilities: capabilityStrings(invited.Capabilities()), Challenge: orchestrationCeremony(t, challenge),
			})
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := InviteWorkspaceMemberRequest{CommandRequest: makeRequest(pipeline, view), AdministratorID: owner.ID(), PrincipalID: workload.ID(),
				WorkspaceID: workspace.ID(), MembershipID: invited.ID(), Capabilities: invited.Capabilities(), Challenge: challenge, ChallengeCreation: creation}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.InviteWorkspaceMember(ctx, request)
				}})
		case CommandAcceptWorkspaceMembership:
			invited := path.invited.Membership()
			challenge := invited.AcceptanceChallenge()
			view, err = NewAcceptWorkspaceMembershipCommandHashView(contextParams, AcceptWorkspaceMembershipCommandHashParams{
				Workspace: orchestrationResource(t, workspace), Principal: orchestrationResource(t, workload),
				Membership: orchestrationResource(t, invited), Proof: orchestrationCeremony(t, challenge),
			})
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := AcceptWorkspaceMembershipRequest{CommandRequest: makeRequest(pipeline, view), WorkspaceID: workspace.ID(),
				PrincipalID: workload.ID(), MembershipID: invited.ID(), ProofEvidence: evidence}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.AcceptWorkspaceMembership(ctx, request)
				}})
		case CommandCreateActor:
			view, err = NewCreateActorCommandHashView(contextParams, CreateActorCommandHashParams{
				Administrator: orchestrationResource(t, owner), Workspace: orchestrationResource(t, workspace),
				ActorID: mustCanonical(t, actor.ID().String()), Kind: string(actor.Kind()), DisplayName: actor.Profile().DisplayName().String(),
			})
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := CreateActorRequest{CommandRequest: makeRequest(pipeline, view), AdministratorID: owner.ID(), WorkspaceID: workspace.ID(),
				ActorID: actor.ID(), Kind: actor.Kind(), Profile: actor.Profile()}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.CreateActor(ctx, request)
				}})
		case CommandProposeActorDelegation:
			proposed := path.proposed.Delegation()
			challenge := proposed.ActivationChallenge()
			creation, _ := domain.ExpectCeremonyAbsent(challenge.ID())
			view, err = NewProposeActorDelegationCommandHashView(contextParams, ProposeActorDelegationCommandHashParams{
				Administrator: orchestrationResource(t, owner), Workspace: orchestrationResource(t, workspace), Principal: orchestrationResource(t, workload),
				Actor: orchestrationResource(t, actor), Membership: orchestrationResource(t, member), DelegationID: mustCanonical(t, proposed.ID().String()),
				Capabilities: capabilityStrings(proposed.Capabilities()), Challenge: orchestrationCeremony(t, challenge),
			})
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := ProposeActorDelegationRequest{CommandRequest: makeRequest(pipeline, view), AdministratorID: owner.ID(), PrincipalID: workload.ID(),
				WorkspaceID: workspace.ID(), ActorID: actor.ID(), MembershipID: member.ID(), DelegationID: proposed.ID(),
				Capabilities: proposed.Capabilities(), Challenge: challenge, ChallengeCreation: creation}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.ProposeActorDelegation(ctx, request)
				}})
		case CommandActivateActorDelegation:
			proposed := path.proposed.Delegation()
			activation := proposed.ActivationChallenge()
			session := path.activated.SessionStartChallenge()
			creation, _ := domain.ExpectCeremonyAbsent(session.ID())
			view, err = NewActivateActorDelegationCommandHashView(contextParams, ActivateActorDelegationCommandHashParams{
				Workspace: orchestrationResource(t, workspace), Principal: orchestrationResource(t, workload), Actor: orchestrationResource(t, actor),
				Membership: orchestrationResource(t, member), Delegation: orchestrationResource(t, proposed),
				ActivationProof: orchestrationCeremony(t, activation), SessionStartChallenge: orchestrationCeremony(t, session),
			})
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := ActivateActorDelegationRequest{CommandRequest: makeRequest(pipeline, view), WorkspaceID: workspace.ID(), PrincipalID: workload.ID(),
				ActorID: actor.ID(), MembershipID: member.ID(), DelegationID: proposed.ID(), ProofEvidence: evidence,
				SessionStartChallenge: session, SessionChallengeCreation: creation}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.ActivateActorDelegation(ctx, request)
				}})
		case CommandBeginDevicePairing:
			challenge := pendingDevice.PairingChallenge()
			creation, _ := domain.ExpectCeremonyAbsent(challenge.ID())
			view, err = NewBeginDevicePairingCommandHashView(contextParams, BeginDevicePairingCommandHashParams{
				Principal: orchestrationResource(t, owner), DeviceID: mustCanonical(t, pendingDevice.ID().String()),
				DisplayName: pendingDevice.DisplayName().String(), PublicKeyReference: pendingDevice.PublicKeyReference().String(),
				Challenge: orchestrationCeremony(t, challenge),
			})
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := BeginDevicePairingRequest{CommandRequest: makeRequest(pipeline, view), PrincipalID: owner.ID(), DeviceID: pendingDevice.ID(),
				DisplayName: pendingDevice.DisplayName(), PublicKeyReference: pendingDevice.PublicKeyReference(), Challenge: challenge, ChallengeCreation: creation}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.BeginDevicePairing(ctx, request)
				}})
		case CommandPairDevice:
			challenge := pendingDevice.PairingChallenge()
			credential := path.paired.Device().CredentialBinding()
			spki := credential.SPKIFingerprint().Bytes()
			transcript := credential.TranscriptFingerprint()
			view, err = NewPairDeviceCommandHashView(contextParams, PairDeviceCommandHashParams{
				Principal: orchestrationResource(t, owner), Device: orchestrationResource(t, pendingDevice),
				ExpectedTrustRevision: pendingDevice.TrustRevision().Uint64(), Proof: orchestrationCeremony(t, challenge),
				CredentialPublicKey: credential.PublicKeyReference().String(), CredentialSPKIDigest: mustCredentialDigest(t, credential.SPKIFingerprint()),
				CredentialTranscript: orchestrationCanonicalFingerprint(t, transcript),
			})
			_ = spki
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := PairDeviceRequest{CommandRequest: makeRequest(pipeline, view), PrincipalID: owner.ID(), DeviceID: pendingDevice.ID(),
				ExpectedTrustRevision: pendingDevice.TrustRevision(), ProofEvidence: evidence}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.PairDevice(ctx, request)
				}})
		case CommandStartActorSession:
			session := path.sessionStarted.Session()
			challenge := path.activated.SessionStartChallenge()
			presentation := session.PresentationCredential()
			digest := presentation.Digest().Bytes()
			instant, _ := NewCanonicalInstant(path.now.Add(8 * time.Hour))
			proof := orchestrationCeremony(t, challenge)
			view, err = NewStartActorSessionCommandHashView(contextParams, StartActorSessionCommandHashParams{
				SessionID: mustCanonical(t, session.ID().String()), ClientName: session.ClientMetadata().Name(), ClientVersion: session.ClientMetadata().Version(),
				Workspace: orchestrationResource(t, workspace), Principal: orchestrationResource(t, workload), Membership: orchestrationResource(t, member),
				Actor: orchestrationResource(t, actor), Delegation: orchestrationResource(t, delegation), StartAuthorityKind: string(domain.SessionStartByHandoff),
				HandoffProof: &proof, AbsoluteExpiry: instant, PresentationReference: presentation.Reference().String(),
				PresentationDigest: mustCredentialDigest(t, presentation.Digest()), PresentationAudience: presentation.Audience().String(),
				PresentationVersion: presentation.Version(),
			})
			_ = digest
			pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
			request := StartActorSessionRequest{CommandRequest: makeRequest(pipeline, view), SessionID: session.ID(), ClientInstanceID: session.ClientInstanceID(),
				ClientMetadata: session.ClientMetadata(), WorkspaceID: workspace.ID(), PrincipalID: workload.ID(), MembershipID: member.ID(), ActorID: actor.ID(),
				DelegationID: delegation.ID(), StartAuthorityKind: domain.SessionStartByHandoff, HandoffProofEvidence: evidence, AbsoluteExpiry: path.now.Add(8 * time.Hour),
				PresentationDeliveryReference: "orchestration-session", PresentationDelivery: orchestrationDelivery{}}
			result = append(result, orchestrationHandlerCase{definition.operation, pipeline,
				func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
					return service.StartActorSession(ctx, request)
				}})
		}
		if err != nil {
			t.Fatalf("%s hash view: %v", definition.operation, err)
		}
	}
	return result
}

func TestAllElevenOrchestrationHandlersCommitExactRecordedShape(t *testing.T) {
	t.Run(string(CommandBootstrapInstallation), func(t *testing.T) {
		service, request, unit, _, _, _ := orchestrationFixture(t, orchestrationCommitted)
		execution, err := service.BootstrapInstallation(context.Background(), request)
		if err != nil || execution.Kind() != CommandApplied {
			t.Fatalf("execution=%s error=%v", execution.Kind(), err)
		}
		fixture := buildBootstrapFixture(t)
		assertOrchestrationDecisionShape(t, unit, fixture.commit, request.Spec)
	})

	path := buildOperationDomainPath(t)
	for _, testCase := range buildOrchestrationHandlerCases(t, path) {
		t.Run(string(testCase.name), func(t *testing.T) {
			trap := &orchestrationTrap{}
			unit := &strictOrchestrationUOW{
				t: t, trap: trap, mode: orchestrationCommitted, contexts: []CommandContext{testCase.pipeline.context},
			}
			service := orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult)

			execution, err := testCase.invoke(context.Background(), service)
			if err != nil || execution.Kind() != CommandApplied {
				t.Fatalf("execution=%s error=%v callbacks=%v order=%v", execution.Kind(), err, unit.callbackErrors, trap.order)
			}
			assertOrchestrationDecisionShape(t, unit, testCase.pipeline.commit, testCase.pipeline.spec)
			assertExternalOrdering(t, testCase.name, trap.order)
		})
	}
}

func TestObserveWorkRefOrchestrationCommitsExactRecordedShape(t *testing.T) {
	t.Parallel()

	path := buildOperationDomainPath(t)
	adapterID, _ := domain.ParsePrincipalID(applicationUUID(719))
	adapterName, _ := domain.NewDisplayName("Beads adapter")
	adapterKey, _ := domain.NewPublicKeyReference("keyref:beads-adapter")
	ownerAuthorization, err := domain.NewIdentityAuthorization(
		path.authority, path.epoch, path.installation, path.bootstrap.Principal().ID(), path.ownerCaps,
		path.policy, path.assurance, path.now, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	registeredAdapter, err := domain.RegisterPrincipal(domain.RegisterPrincipalInput{
		Authorization: ownerAuthorization, Registrar: path.bootstrap.Principal(),
		ExpectedRegistrarVersion: path.bootstrap.Principal().Version(), PrincipalID: adapterID,
		Kind: domain.PrincipalKindService, DisplayName: adapterName, PublicKeyReference: adapterKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := registeredAdapter.Principal()
	workspace := path.createdWorkspace.Workspace()
	workspaceScope, _ := domain.WorkspaceScope(workspace.ID())
	workReferenceID, _ := domain.ParseWorkReferenceID(applicationUUID(720))
	namespace, _ := domain.NewOpaqueProviderValue("beads")
	objectID, _ := domain.NewOpaqueProviderValue("bd-fam.2.2")
	locator, _ := domain.NewOpaqueProviderValue("beads://blackmail/bd-fam.2.2")
	providerVersion, _ := domain.NewOpaqueProviderValue("beads-v7")
	fields, _ := domain.NewEventPayload([]byte(`{"priority":1,"status":"in_progress"}`))
	observation, err := domain.NewProviderObservation(
		namespace, objectID, locator, providerVersion, fields, adapter.ID(), path.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := domain.NewWorkspaceIdentityAuthorization(
		path.authority, path.epoch, path.installation, workspace.ID(), adapter.ID(), path.memberCaps,
		path.policy, path.assurance, path.now, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := domain.ObserveWorkRef(domain.ObserveWorkRefInput{
		Authorization: authorization, Adapter: adapter, ExpectedAdapterVersion: adapter.Version(),
		Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(), WorkReferenceID: workReferenceID,
		Observation: observation,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorship, _ := AuthorityAuthorship(adapter.ID())
	authorityGuard, _ := CurrentAuthorityEpochGuard(workspaceScope, path.authority, path.epoch)
	policyGuard, _ := PolicyRevisionGuard(workspaceScope, path.policy)
	workReferenceAbsent, _ := domain.ExpectAggregateAbsent(workReferenceID)
	testCase := operationPipelineCase{
		operation: CommandObserveWorkRef, scope: workspaceScope, admission: workspaceScope,
		principal: adapter.ID(), authorship: authorship,
		authorization: []IdentityState{mustIdentityState(t, adapter), mustIdentityState(t, workspace)},
		disclosure:    []domain.AggregateTarget{mustTarget(t, adapter), mustTarget(t, workspace)},
		mutations:     []domain.AggregateExpectation{workReferenceAbsent},
		evidence:      []EvidenceGuard{authorityGuard, policyGuard}, facts: observed.Facts(),
		commit: func(context CommandContext) (OperationCommit, error) {
			return ObserveWorkRefCommit(context, observed)
		},
	}
	pipeline := completeOperationPipeline(t, path, testCase, 42)
	view, err := NewObserveWorkRefCommandHashView(orchestrationCommandContext(t, pipeline), ObserveWorkRefCommandHashParams{
		Adapter: orchestrationResource(t, adapter), Workspace: orchestrationResource(t, workspace),
		WorkReferenceID: mustCanonical(t, workReferenceID.String()), ProviderNamespace: namespace.String(),
		ProviderObjectID: objectID.String(), ProviderLocator: locator.String(), ProviderVersion: providerVersion.String(),
		SelectedFields: fields, AdapterPrincipalID: mustCanonical(t, adapter.ID().String()), ObservedAt: path.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	pipeline = finalizeOrchestrationPipeline(t, pipeline, view)
	authentication, policy := orchestrationPreparationRequests(
		t, CommandObserveWorkRef, workspaceScope, adapter.ID(), adapter.Version(), path.authority,
	)
	request := ObserveWorkRefRequest{
		CommandRequest: CommandRequest{Spec: pipeline.spec, HashView: view, Authentication: authentication,
			Policy: policy, Audit: orchestrationAuditContext(t)},
		AdapterID: adapter.ID(), WorkspaceID: workspace.ID(), WorkReferenceID: workReferenceID,
		Observation: observation,
	}
	trap := &orchestrationTrap{}
	unit := &strictOrchestrationUOW{
		t: t, trap: trap, mode: orchestrationCommitted, contexts: []CommandContext{pipeline.context},
	}
	handlerCase := orchestrationHandlerCase{
		name: CommandObserveWorkRef, pipeline: pipeline,
		invoke: func(ctx context.Context, service *OrchestrationService) (CommandExecution, error) {
			return service.ObserveWorkRef(ctx, request)
		},
	}
	execution, err := handlerCase.invoke(
		context.Background(), orchestrationMatrixService(t, path, handlerCase, unit, ReplayDiscloseResult),
	)
	if err != nil || execution.Kind() != CommandApplied || len(unit.decisions) != 1 ||
		len(unit.decisions[0].Writes()) != 1 || len(unit.decisions[0].Facts()) != 1 {
		t.Fatalf("execution=%s error=%v decisions=%d", execution.Kind(), err, len(unit.decisions))
	}
	state, ok := unit.decisions[0].Writes()[0].Value().(domain.WorkReferenceState)
	if !ok || state.ID() != workReferenceID || state.Observation().ProviderVersion() != providerVersion {
		t.Fatalf("work reference write=%#v", unit.decisions[0].Writes())
	}
}

func TestOrchestrationCarriesFederatedAuthenticationProvenanceIntoAudit(t *testing.T) {
	path := buildOperationDomainPath(t)
	testCase := buildOrchestrationHandlerCases(t, path)[0]
	if testCase.name != CommandRegisterPrincipal {
		t.Fatalf("first matrix operation=%s", testCase.name)
	}
	trap := &orchestrationTrap{}
	unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationCommitted,
		contexts: []CommandContext{testCase.pipeline.context}}
	service := orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult)
	remoteAuthority, _ := domain.ParseAuthorityID(applicationUUID(300))
	envelope := "federation-envelope-300"
	authentication := service.authentication.(orchestrationAuthentication)
	authentication.authority, authentication.federationEnvelope = remoteAuthority, &envelope
	service.authentication = authentication
	execution, err := testCase.invoke(context.Background(), service)
	if err != nil || execution.Kind() != CommandApplied || len(unit.decisions) != 1 {
		t.Fatalf("execution=%s error=%v decisions=%d", execution.Kind(), err, len(unit.decisions))
	}
	audit := unit.decisions[0].Audit()
	if audit.provenance.sourceAuthority != remoteAuthority || audit.provenance.federationEnvelope == nil ||
		audit.provenance.federationEnvelope.String() != envelope {
		t.Fatal("federated authentication provenance was not retained")
	}
}

func orchestrationMatrixService(
	t *testing.T,
	path operationDomainPath,
	testCase orchestrationHandlerCase,
	unit *strictOrchestrationUOW,
	disclosure ReplayDisclosure,
) *OrchestrationService {
	t.Helper()
	trap := unit.trap
	pending := path.pairingBegan.Device()
	pairingProof := orchestrationProof(pending.PairingChallenge())
	pairingAuthorization, err := domain.NewPairingRedemptionAuthorization(
		path.authority, path.epoch, path.installation, pending.PrincipalID(), pending.ID(),
		path.policy, path.assurance, path.now, pairingProof.ChallengeID(), pairingProof.ProofDigest(),
		path.paired.Device().CredentialBinding(),
	)
	if err != nil {
		t.Fatal(err)
	}
	pairingVerification, err := NewPairingRedemptionVerification(pairingAuthorization, pairingProof)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := path.memberCaps
	if testCase.pipeline.caseDefinition.principal == path.bootstrap.Principal().ID() {
		capabilities = path.ownerCaps
	}
	service, err := NewOrchestrationService(OrchestrationDependencies{
		UnitOfWork: unit,
		Authentication: orchestrationAuthentication{trap: trap, authority: path.authority,
			principal: testCase.pipeline.caseDefinition.principal},
		Policy: orchestrationPolicy{trap: trap, revision: path.policy},
		LockedAuthorization: &orchestrationAuthorizer{
			trap: trap, installation: path.installation, policy: path.policy, capabilities: capabilities,
			principalOverride: testCase.pipeline.caseDefinition.principal, assurance: path.assurance,
		},
		ReplayDisclosure: orchestrationReplay{disclosure}, DenialPolicy: &orchestrationDenialPolicy{},
		SignerLookup: &orchestrationSignerLookup{
			trap: trap, signer: newTestCapsuleSigner(testCase.pipeline.spec.RecoveryCapsule().KeyID()),
		},
		EffectPlanner:   orchestrationEffects{trap},
		BootstrapProofs: orchestrationBootstrapVerifier{trap: trap},
		CeremonyProofs: orchestrationCeremonyVerifier{
			trap: trap, membership: orchestrationProof(path.invited.Membership().AcceptanceChallenge()),
			delegation: orchestrationProof(path.proposed.Delegation().ActivationChallenge()),
			handoff:    orchestrationProof(path.activated.SessionStartChallenge()),
		},
		PairingRedemptions: orchestrationPairingVerifier{trap: trap, verification: pairingVerification},
		Presentations:      orchestrationPresentations{trap: trap, binding: path.sessionStarted.Session().PresentationCredential()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestAllOrdinaryOrchestrationHandlersAdversarialOutcomes(t *testing.T) {
	path := buildOperationDomainPath(t)
	for _, testCase := range buildOrchestrationHandlerCases(t, path) {
		t.Run(string(testCase.name), func(t *testing.T) {
			t.Run("indeterminate retry purity", func(t *testing.T) {
				trap := &orchestrationTrap{}
				unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationIndeterminate,
					contexts: []CommandContext{testCase.pipeline.context, testCase.pipeline.context}}
				execution, err := testCase.invoke(context.Background(), orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult))
				if err != nil || execution.Kind() != CommandIndeterminate || unit.callbackCalls != 2 || len(unit.decisions) != 2 ||
					!reflect.DeepEqual(unit.decisions[0], unit.decisions[1]) || positionOf(trap.order, "sign") >= 0 {
					t.Fatalf("execution=%s error=%v callbacks=%d decisions=%d order=%v", execution.Kind(), err, unit.callbackCalls, len(unit.decisions), trap.order)
				}
			})

			t.Run("callback error rollback", func(t *testing.T) {
				trap := &orchestrationTrap{}
				callbackErr := errors.New("storage callback failed")
				unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationCommitted,
					contexts: []CommandContext{testCase.pipeline.context}, callbackErr: callbackErr}
				_, err := testCase.invoke(context.Background(), orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult))
				if !errors.Is(err, callbackErr) || positionOf(trap.order, "rollback") < 0 || positionOf(trap.order, "sign") >= 0 {
					t.Fatalf("error=%v order=%v", err, trap.order)
				}
			})

			t.Run("cancellation", func(t *testing.T) {
				trap := &orchestrationTrap{}
				unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationCommitted, contexts: []CommandContext{testCase.pipeline.context}}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				_, err := testCase.invoke(ctx, orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult))
				if !errors.Is(err, context.Canceled) || unit.callbackCalls != 0 || unit.writes != 0 {
					t.Fatalf("error=%v callbacks=%d writes=%d order=%v", err, unit.callbackCalls, unit.writes, trap.order)
				}
			})

			t.Run("authentication rejection uses fresh security audit only", func(t *testing.T) {
				trap := &orchestrationTrap{}
				unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationRejected,
					contexts: []CommandContext{testCase.pipeline.context}, denialAdmission: DenialAdmitDistinct}
				service := orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult)
				service.authentication = orchestrationRejectedAuthentication{trap: trap}
				execution, err := testCase.invoke(context.Background(), service)
				if err != nil || execution.Kind() != CommandRejected || unit.callbackCalls != 0 || unit.writes != 0 ||
					unit.securityCalls != 1 || len(unit.securityDecisions) != 1 ||
					unit.securityDecisions[0].Kind() != SecurityDecisionAuditDenial {
					t.Fatalf("execution=%s error=%v callbacks=%d writes=%d security=%d", execution.Kind(), err,
						unit.callbackCalls, unit.writes, unit.securityCalls)
				}
			})

			t.Run("applied-only replay", func(t *testing.T) {
				receipt := testCase.pipeline.receipt
				receipt.requestFingerprint = testCase.pipeline.spec.RequestFingerprint()
				locked := testCase.pipeline.context
				locked.resolution, _ = ReplayReceipt(receipt)
				trap := &orchestrationTrap{}
				unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationReplayOnly,
					contexts: []CommandContext{locked}, replayReceipt: receipt, replayAccess: ReplayDiscloseAppliedOnly}
				execution, err := testCase.invoke(context.Background(), orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseAppliedOnly))
				if err != nil || execution.Kind() != CommandReplayed || unit.writes != 0 || positionOf(trap.order, "authorization") >= 0 ||
					positionOf(trap.order, "effects") >= 0 || positionOf(trap.order, "sign") >= 0 {
					t.Fatalf("execution=%s error=%v writes=%d order=%v", execution.Kind(), err, unit.writes, trap.order)
				}
			})

			t.Run("full replay returns exact receipt", func(t *testing.T) {
				receipt := testCase.pipeline.receipt
				receipt.requestFingerprint = testCase.pipeline.spec.RequestFingerprint()
				locked := testCase.pipeline.context
				locked.resolution, _ = ReplayReceipt(receipt)
				trap := &orchestrationTrap{}
				unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationReplayOnly,
					contexts: []CommandContext{locked}, replayReceipt: receipt, replayAccess: ReplayDiscloseResult}
				service := orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult)
				execution, err := testCase.invoke(context.Background(), service)
				returned, full := execution.Receipt()
				signers := service.signers.(*orchestrationSignerLookup)
				wantSigns := 0
				if testCase.pipeline.spec.RecoveryCapsule().Requirement() == RecoveryCapsuleRequired {
					wantSigns = 1
				}
				if err != nil || execution.Kind() != CommandReplayed || !full || !sameReceiptSnapshot(returned, receipt) ||
					unit.writes != 0 || signers.signs != wantSigns || positionOf(trap.order, "authorization") >= 0 ||
					positionOf(trap.order, "effects") >= 0 {
					t.Fatalf("execution=%s error=%v full=%t writes=%d signs=%d order=%v",
						execution.Kind(), err, full, unit.writes, signers.signs, trap.order)
				}
			})

			if testCase.pipeline.spec.RecoveryCapsule().Requirement() == RecoveryCapsuleRequired {
				t.Run("post-commit signer failure retains committed receipt", func(t *testing.T) {
					trap := &orchestrationTrap{}
					unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationCommitted,
						contexts: []CommandContext{testCase.pipeline.context}}
					service := orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult)
					service.signers.(*orchestrationSignerLookup).signErr = errors.New("capsule signer unavailable")
					execution, err := testCase.invoke(context.Background(), service)
					_, hasReceipt := execution.Receipt()
					if err != nil || execution.Kind() != CommandCommittedCapsulePending || !hasReceipt || unit.writes == 0 ||
						positionOf(trap.order, "commit") < 0 || positionOf(trap.order, "sign") <= positionOf(trap.order, "commit") {
						t.Fatalf("execution=%s error=%v receipt=%t writes=%d order=%v",
							execution.Kind(), err, hasReceipt, unit.writes, trap.order)
					}
				})
			}

			t.Run("replay disclosure denial audits after rollback", func(t *testing.T) {
				receipt := testCase.pipeline.receipt
				receipt.requestFingerprint = testCase.pipeline.spec.RequestFingerprint()
				locked := testCase.pipeline.context
				locked.resolution, _ = ReplayReceipt(receipt)
				trap := &orchestrationTrap{}
				unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationRejected,
					contexts: []CommandContext{locked}, denialAdmission: DenialAdmitDistinct}
				service := orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult)
				service.replayDisclosure = orchestrationReplayRejection{
					rejection: mustCommandError(domain.ErrorCodeForbidden, "replay disclosure denied"),
				}
				execution, err := testCase.invoke(context.Background(), service)
				if err != nil || execution.Kind() != CommandRejected || unit.writes != 0 || unit.securityCalls != 1 ||
					len(unit.securityDecisions) != 1 || unit.securityDecisions[0].Kind() != SecurityDecisionAuditDenial ||
					positionOf(trap.order, "security") <= positionOf(trap.order, "rollback") {
					t.Fatalf("execution=%s error=%v writes=%d security=%d order=%v",
						execution.Kind(), err, unit.writes, unit.securityCalls, trap.order)
				}
			})

			t.Run("denial rolls back before security transaction", func(t *testing.T) {
				trap := &orchestrationTrap{}
				unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationRejected,
					contexts: []CommandContext{testCase.pipeline.context}, denialAdmission: DenialAdmitDistinct}
				service := orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult)
				service.lockedAuthorization.(*orchestrationAuthorizer).rejection = mustCommandError(domain.ErrorCodeForbidden, "strict denial")
				execution, err := testCase.invoke(context.Background(), service)
				if err != nil || execution.Kind() != CommandRejected || unit.writes != 0 || unit.securityCalls != 1 ||
					len(unit.securityDecisions) != 1 || unit.securityDecisions[0].Kind() != SecurityDecisionAuditDenial ||
					positionOf(trap.order, "rollback") < 0 || positionOf(trap.order, "security") <= positionOf(trap.order, "rollback") {
					t.Fatalf("execution=%s error=%v writes=%d security=%d order=%v", execution.Kind(), err, unit.writes, unit.securityCalls, trap.order)
				}
			})

			t.Run("denial audit failure is fail closed", func(t *testing.T) {
				trap := &orchestrationTrap{}
				securityErr := errors.New("security audit commit failed")
				unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationRejected,
					contexts: []CommandContext{testCase.pipeline.context}, denialAdmission: DenialAdmitDistinct,
					securityErr: securityErr}
				service := orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult)
				service.lockedAuthorization.(*orchestrationAuthorizer).rejection = mustCommandError(domain.ErrorCodeForbidden, "strict denial")
				_, err := testCase.invoke(context.Background(), service)
				if !errors.Is(err, securityErr) || unit.writes != 0 || unit.securityCalls != 1 ||
					positionOf(trap.order, "security") <= positionOf(trap.order, "rollback") {
					t.Fatalf("error=%v writes=%d security=%d order=%v", err, unit.writes, unit.securityCalls, trap.order)
				}
			})

			for _, conflict := range []struct {
				kind ReceiptResolutionKind
				code domain.ErrorCode
			}{
				{ReceiptCommandIDConflict, domain.ErrorCodeCommandIDReused},
				{ReceiptIdempotencyConflict, domain.ErrorCodeIdempotencyKeyReused},
				{ReceiptInProgress, domain.ErrorCodeCommandInProgress},
				{ReceiptIntegrityConflict, domain.ErrorCodeInternal},
			} {
				t.Run(string(conflict.kind), func(t *testing.T) {
					locked := testCase.pipeline.context
					locked.resolution, _ = ConflictReceipt(conflict.kind, testCase.pipeline.spec.ReceiptID())
					trap := &orchestrationTrap{}
					unit := &strictOrchestrationUOW{t: t, trap: trap, mode: orchestrationRejected, contexts: []CommandContext{locked}}
					execution, err := testCase.invoke(context.Background(), orchestrationMatrixService(t, path, testCase, unit, ReplayDiscloseResult))
					rejection, rejected := execution.Rejection()
					if err != nil || execution.Kind() != CommandRejected || !rejected || rejection.Code() != conflict.code ||
						unit.writes != 0 || unit.securityCalls != 0 {
						t.Fatalf("execution=%s error=%v rejection=%v writes=%d security=%d", execution.Kind(), err, rejection, unit.writes, unit.securityCalls)
					}
				})
			}
		})
	}
}

func positionOf(order []string, name string) int {
	for index, event := range order {
		if event == name {
			return index
		}
	}
	return -1
}

func assertOrchestrationDecisionShape(
	t *testing.T,
	unit *strictOrchestrationUOW,
	expected OperationCommit,
	spec CommandSpec,
) {
	t.Helper()
	if unit.callbackCalls != 1 || len(unit.specs) != 1 || len(unit.decisions) != 1 || unit.securityCalls != 0 {
		t.Fatalf("callbacks=%d specs=%d decisions=%d security=%d", unit.callbackCalls, len(unit.specs), len(unit.decisions), unit.securityCalls)
	}
	decision := unit.decisions[0]
	if decision.Kind() != CommandDecisionApplied || !reflect.DeepEqual(decision.Writes(), expected.writes) ||
		!reflect.DeepEqual(decision.Facts(), expected.facts) || !reflect.DeepEqual(decision.CeremonyTransitions(), expected.ceremonies) {
		t.Fatalf("decision shape writes=%d/%d facts=%d/%d ceremonies=%d/%d",
			len(decision.Writes()), len(expected.writes), len(decision.Facts()), len(expected.facts),
			len(decision.CeremonyTransitions()), len(expected.ceremonies))
	}
	audit := decision.Audit()
	if audit.Operation() != spec.Operation() || audit.Outcome() != AuditCommandApplied ||
		audit.Fingerprint() != spec.RequestFingerprint() || audit.Detail().Kind() != AuditDetailCommandApplied {
		t.Fatalf("audit operation=%s outcome=%s detail=%s", audit.Operation(), audit.Outcome(), audit.Detail().Kind())
	}
	if audit.invocation.requestID == nil || audit.invocation.requestID.String() != applicationUUID(90) ||
		audit.invocation.traceID == nil || audit.invocation.traceID.String() != applicationUUID(91) ||
		audit.timing.serverReceivedTime == nil ||
		!audit.timing.serverReceivedTime.Equal(time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)) ||
		audit.timing.clientTime != nil || audit.provenance.sourceAuthority != spec.AuthorityID() ||
		audit.provenance.federationEnvelope != nil || audit.subject.principal != spec.Authorship().PrincipalID() {
		t.Fatal("audit lost trusted request, timing, provenance, or subject attribution")
	}
	expectWorkload := false
	for _, state := range unit.contexts[0].States() {
		principal, ok := state.Value().(domain.PrincipalState)
		if ok && principal.ID() == spec.Authorship().PrincipalID() &&
			(principal.Kind() == domain.PrincipalKindWorkload || principal.Kind() == domain.PrincipalKindService) {
			expectWorkload = true
		}
	}
	expectDelegations := 0
	for _, ref := range append(spec.Guards().Authorization(), spec.Guards().References()...) {
		if ref.Target().Kind() == domain.AggregateKindActorDelegation {
			expectDelegations++
		}
	}
	expectDevice := spec.CommandOperation() == CommandBootstrapInstallation
	if audit.subject.hasWorkload != expectWorkload ||
		(expectWorkload && audit.subject.workload != spec.Authorship().PrincipalID()) ||
		audit.subject.hasDevice != expectDevice || len(audit.subject.delegations) != expectDelegations ||
		audit.subject.hasActor != spec.Authorship().hasActor {
		t.Fatalf("audit subject device=%t workload=%t actor=%t delegations=%d",
			audit.subject.hasDevice, audit.subject.hasWorkload, audit.subject.hasActor, len(audit.subject.delegations))
	}
	expectRevisions := make(map[string]struct{})
	for _, ref := range append(spec.Guards().Authorization(), spec.Guards().References()...) {
		expectRevisions[string(ref.Target().Kind())+"\x00"+ref.Target().ID()] = struct{}{}
	}
	for _, expectation := range spec.Guards().Mutations() {
		if _, present := expectation.Version(); present {
			expectRevisions[string(expectation.Target().Kind())+"\x00"+expectation.Target().ID()] = struct{}{}
		}
	}
	expectRevocations := 0
	for _, guard := range unit.contexts[0].GuardEvidence().Observed() {
		if guard.Kind() == EvidenceLifecycleStatus {
			if _, present := expectRevisions[guard.TargetKind()+"\x00"+guard.TargetID()]; present {
				expectRevocations++
			}
		}
	}
	if len(audit.authorization.revocations) != expectRevocations {
		t.Fatalf("audit revocation revisions=%d, want %d", len(audit.authorization.revocations), expectRevocations)
	}
	if len(decision.Effects().Intents()) != 0 {
		t.Fatalf("effects=%v, want exact empty planned set", decision.Effects().Intents())
	}
	plan := decision.ResultPlan()
	if plan.Operation() != spec.CommandOperation() || plan.CommandID() != spec.CommandID() ||
		plan.CommandFingerprint() != spec.RequestFingerprint() || len(plan.EventIDs()) != len(expected.facts) ||
		len(plan.Resources()) != len(expected.writes)-invitationWriteCount(expected.writes) {
		t.Fatalf("result plan operation=%s events=%d resources=%d", plan.Operation(), len(plan.EventIDs()), len(plan.Resources()))
	}
}

func invitationWriteCount(writes []IdentityState) int {
	for _, write := range writes {
		if write.Kind() == StateInstallationInvitation {
			return 1
		}
	}
	return 0
}

func assertExternalOrdering(t *testing.T, operation CommandOperation, order []string) {
	t.Helper()
	position := func(name string) int {
		for index, event := range order {
			if event == name {
				return index
			}
		}
		return -1
	}
	callback, commit := position("callback"), position("commit")
	if callback < 0 || commit <= callback || position("authentication") < 0 || position("policy") < 0 {
		t.Fatalf("invalid preparation/transaction order: %v", order)
	}
	if signer := position("signer_lookup"); signer >= 0 && signer > callback {
		t.Fatalf("signer lookup happened in/post callback: %v", order)
	}
	if sign := position("sign"); sign >= 0 && sign <= commit {
		t.Fatalf("signing did not follow durable commit: %v", order)
	}
	if operation == CommandStartActorSession && position("presentation") > position("authentication") {
		t.Fatalf("presentation must be prepared before command authentication: %v", order)
	}
}

type queryServiceStore struct{ calls int }

func (store *queryServiceStore) GetContext(context.Context, ContextGetQuery) (ContextPage, error) {
	store.calls++
	return ContextPage{}, errors.New("query store sentinel")
}

func (store *queryServiceStore) SyncEvents(context.Context, EventsSyncQuery) (EventsPage, error) {
	store.calls++
	return EventsPage{}, errors.New("query store sentinel")
}

type queryCheckpointIDs struct{ calls int }

func (source *queryCheckpointIDs) NewCheckpointID() (CheckpointID, error) {
	source.calls++
	return NewCheckpointID("checkpoint:application-query-test")
}

type expiringContextStore struct {
	cursors []EventCursor
}

func (store *expiringContextStore) GetContext(_ context.Context, query ContextGetQuery) (ContextPage, error) {
	store.cursors = append(store.cursors, query.Cursor())
	if !query.Cursor().IsZero() {
		rejection, _ := domain.NewCommandError(domain.ErrorCodeCursorExpired, "expired", nil)
		return ContextPage{}, rejection
	}
	return ContextPage{}, nil
}

func (*expiringContextStore) SyncEvents(context.Context, EventsSyncQuery) (EventsPage, error) {
	return EventsPage{}, nil
}

func TestQueryServiceFallsBackToCheckpointForExpiredContextCursor(t *testing.T) {
	principal, _ := domain.ParsePrincipalID(applicationUUID(982))
	session, _ := domain.ParseActorSessionID(applicationUUID(983))
	subject, _ := NewQuerySubject(principal, session)
	cursor, _ := NewEventCursor("bbec1_expired")
	store := &expiringContextStore{}
	ids := &queryCheckpointIDs{}
	service, err := NewQueryService(store, ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.GetContext(context.Background(), subject, cursor, 32); err != nil {
		t.Fatal(err)
	}
	if ids.calls != 1 || len(store.cursors) != 2 || store.cursors[0] != cursor || !store.cursors[1].IsZero() {
		t.Fatalf("checkpoint fallback ids=%d cursors=%v", ids.calls, store.cursors)
	}
}

func TestQueryServiceValidatesBoundsAndCancellationBeforeDependencies(t *testing.T) {
	principal, _ := domain.ParsePrincipalID(applicationUUID(980))
	session, _ := domain.ParseActorSessionID(applicationUUID(981))
	subject, err := NewQuerySubject(principal, session)
	if err != nil {
		t.Fatal(err)
	}
	store := &queryServiceStore{}
	ids := &queryCheckpointIDs{}
	service, err := NewQueryService(store, ids)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = service.GetContext(cancelled, subject, EventCursor{}, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation error=%v", err)
	}
	if _, err = service.SyncEvents(cancelled, subject, EventCursor{}, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("event cancellation error=%v", err)
	}
	if store.calls != 0 || ids.calls != 0 {
		t.Fatalf("cancelled query called dependencies store=%d ids=%d", store.calls, ids.calls)
	}
	if _, err = service.SyncEvents(context.Background(), subject, EventCursor{}, 0); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("zero event bound error=%v", err)
	}
	if _, err = service.SyncEvents(context.Background(), subject, EventCursor{}, MaxQueryPageSize+1); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("oversized event bound error=%v", err)
	}
	if _, err = service.GetContext(context.Background(), subject, EventCursor{}, 0); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("zero context bound error=%v", err)
	}
	if _, err = service.GetContext(context.Background(), subject, EventCursor{}, MaxQueryPageSize+1); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("oversized context bound error=%v", err)
	}
	if store.calls != 0 {
		t.Fatalf("invalid bounded query reached store %d times", store.calls)
	}
}
