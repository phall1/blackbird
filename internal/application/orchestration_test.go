package application

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

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

type orchestrationAuthentication struct{ trap *orchestrationTrap }

func (preparer orchestrationAuthentication) PrepareAuthentication(
	_ context.Context,
	request AuthenticationRequest,
) (AuthenticationDecision, error) {
	preparer.trap.external("authentication")
	evidence, err := NewAuthenticationEvidence(requestPrincipal(request), nil)
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
	return RejectedAuthentication(rejection, subject)
}

func requestPrincipal(request AuthenticationRequest) domain.PrincipalID {
	principal, _ := domain.ParsePrincipalID(applicationUUID(5))
	return principal
}

type orchestrationPolicy struct{ trap *orchestrationTrap }

func (preparer orchestrationPolicy) PreparePolicy(
	context.Context,
	PolicyPreparationRequest,
) (PreparedPolicy, error) {
	preparer.trap.external("policy")
	revision, _ := domain.NewPolicyRevision("policy-1")
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
	return signer.signer.SignRecoveryCapsule(ctx, message)
}

type orchestrationBootstrapVerifier struct {
	trap  *orchestrationTrap
	proof domain.BootstrapProof
}

type orchestrationCeremonyVerifier struct{ trap *orchestrationTrap }

func (verifier orchestrationCeremonyVerifier) VerifyMembershipAcceptance(
	context.Context,
	CeremonyProofEvidence,
) (CeremonyProofVerification, error) {
	verifier.trap.external("membership_proof")
	return CeremonyProofVerification{}, ErrInvalidApplicationContract
}

func (verifier orchestrationCeremonyVerifier) VerifyDelegationActivation(
	context.Context,
	CeremonyProofEvidence,
) (CeremonyProofVerification, error) {
	verifier.trap.external("delegation_proof")
	return CeremonyProofVerification{}, ErrInvalidApplicationContract
}

func (verifier orchestrationCeremonyVerifier) VerifyActorSessionHandoff(
	context.Context,
	CeremonyProofEvidence,
) (CeremonyProofVerification, error) {
	verifier.trap.external("handoff_proof")
	return CeremonyProofVerification{}, ErrInvalidApplicationContract
}

type orchestrationPairingVerifier struct{ trap *orchestrationTrap }

func (verifier orchestrationPairingVerifier) VerifyPairingRedemption(
	context.Context,
	CeremonyProofEvidence,
) (PairingRedemptionDecision, error) {
	verifier.trap.external("pairing_redemption")
	return PairingRedemptionDecision{}, ErrInvalidApplicationContract
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
}

func (authorizer *orchestrationAuthorizer) AuthorizeLocked(
	locked CommandContext,
	_ AuthenticationEvidence,
	_ PreparedPolicy,
) (domain.IdentityAuthorization, error) {
	authorizer.calls++
	if authorizer.rejection != nil {
		return domain.IdentityAuthorization{}, authorizer.rejection
	}
	principal, _ := domain.ParsePrincipalID(applicationUUID(5))
	if !authorizer.principalOverride.IsZero() {
		principal = authorizer.principalOverride
	}
	installation, _ := domain.ParseInstallationID(locked.Spec().Scope().ID())
	capabilities, _ := domain.NewCapabilitySet(domain.InstallationOwnerCapability())
	policy, _ := domain.NewPolicyRevision("policy-1")
	assurance, _ := domain.NewAssuranceClass("strong")
	value, _ := domain.NewIdentityAuthorization(
		locked.Spec().AuthorityID(), locked.Spec().RequestedEpoch(), installation, principal,
		capabilities, policy, assurance, locked.TimeEvidence().Value(), domain.MaxActorSessionLifetime,
	)
	return value, nil
}

type orchestrationReplay struct{ disclosure ReplayDisclosure }

func (replay orchestrationReplay) AuthorizeReplay(
	CommandContext,
	AuthenticationEvidence,
	PreparedPolicy,
) (ReplayDisclosure, error) {
	return replay.disclosure, nil
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

type orchestrationEffects struct{}

func (orchestrationEffects) PlanEffects(EffectPlanningInput) (EffectSet, error) {
	return NewEffectSet()
}

type orchestrationPresentations struct{ trap *orchestrationTrap }

func (preparer orchestrationPresentations) PreparePresentationCredential(
	context.Context,
	CommandOperation,
) (domain.PresentationCredentialBinding, error) {
	preparer.trap.external("presentation")
	return domain.PresentationCredentialBinding{}, nil
}

type orchestrationUOWMode uint8

const (
	orchestrationIndeterminate orchestrationUOWMode = iota + 1
	orchestrationRejected
	orchestrationReplayOnly
)

type strictOrchestrationUOW struct {
	trap          *orchestrationTrap
	mode          orchestrationUOWMode
	contexts      []CommandContext
	replayReceipt ReceiptSnapshot
	replayAccess  ReplayDisclosure
	callbackCalls int
	writes        int
	securityCalls int
}

func (unit *strictOrchestrationUOW) ExecuteCommand(
	_ context.Context,
	spec CommandSpec,
	decide func(CommandContext) (CommandDecision, error),
) (CommandTransactionExecution, error) {
	for _, locked := range unit.contexts {
		unit.trap.order = append(unit.trap.order, "callback")
		unit.trap.inCallback = true
		decision, err := decide(locked)
		unit.trap.inCallback = false
		unit.callbackCalls++
		if err != nil {
			unit.trap.order = append(unit.trap.order, "rollback")
			return CommandTransactionExecution{}, err
		}
		switch decision.Kind() {
		case CommandDecisionApplied:
			unit.writes += len(decision.Writes())
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

func (unit *strictOrchestrationUOW) ExecuteSecurity(
	_ context.Context,
	spec SecuritySpec,
	decide func(SecurityContext) (SecurityDecision, error),
) (SecurityExecution, error) {
	unit.securityCalls++
	unit.trap.order = append(unit.trap.order, "security")
	authorityTime := unit.contexts[0].TimeEvidence().Value()
	admission, _ := NewDenialAdmission(DenialSuppressDuplicate, authorityTime, 0, 0)
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
	if err != nil || decision.Kind() != SecurityDecisionSuppressDenial {
		return SecurityExecution{}, err
	}
	return CommandDenialSecurityExecution(false), nil
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
		trap: trap, mode: mode, contexts: []CommandContext{fixture.context}, replayAccess: ReplayDiscloseAppliedOnly,
	}
	authorizer := &orchestrationAuthorizer{}
	denial := &orchestrationDenialPolicy{}
	signers := &orchestrationSignerLookup{trap: trap, signer: fixture.capsuleSigner}
	service, err := NewOrchestrationService(OrchestrationDependencies{
		UnitOfWork: unit, Authentication: orchestrationAuthentication{trap}, Policy: orchestrationPolicy{trap},
		LockedAuthorization: authorizer, ReplayDisclosure: orchestrationReplay{ReplayDiscloseAppliedOnly},
		DenialPolicy: denial, SignerLookup: signers, EffectPlanner: orchestrationEffects{},
		BootstrapProofs:    orchestrationBootstrapVerifier{trap, fixture.input.Proof},
		CeremonyProofs:     orchestrationCeremonyVerifier{trap},
		PairingRedemptions: orchestrationPairingVerifier{trap},
		Presentations:      orchestrationPresentations{trap},
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := NewBootstrapProofEvidence([]byte("proof"))
	request := BootstrapInstallationRequest{
		CommandRequest: CommandRequest{Spec: fixture.spec, HashView: view,
			Authentication: AuthenticationRequest{Operation: CommandBootstrapInstallation, Scope: fixture.scope},
			Policy:         PolicyPreparationRequest{Operation: CommandBootstrapInstallation, Scope: fixture.scope}},
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
		{"authentication scope", func(request *BootstrapInstallationRequest) { request.Authentication.Scope = domain.AuthorityScope{} }},
		{"policy scope", func(request *BootstrapInstallationRequest) { request.Policy.Scope = domain.AuthorityScope{} }},
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
