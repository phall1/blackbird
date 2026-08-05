package application

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

func applicationUUID(index int) string {
	return fmt.Sprintf("01b8e094-9888-7000-8000-%012x", index)
}

type bootstrapFixture struct {
	now           time.Time
	scope         domain.AuthorityScope
	authority     domain.AuthorityID
	epoch         domain.AuthorityEpoch
	command       domain.CommandID
	receipt       domain.ReceiptID
	correlation   domain.CorrelationID
	invitation    domain.InstallationInvitationState
	input         domain.BootstrapInstallationInput
	attempt       BootstrapAttempt
	result        domain.BootstrapInstallationResult
	spec          CommandSpec
	context       CommandContext
	commit        OperationCommit
	decision      CommandDecision
	resultRecord  ResultEnvelope
	capsuleSigner testCapsuleSigner
}

type testCapsuleSigner struct {
	keyID      string
	privateKey ed25519.PrivateKey
}

type invalidSignatureSigner struct{ testCapsuleSigner }

func (invalidSignatureSigner) SignRecoveryCapsule(context.Context, []byte) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

func (signer testCapsuleSigner) KeyID() string { return signer.keyID }
func (signer testCapsuleSigner) Ed25519PublicKey() ed25519.PublicKey {
	publicKey, _ := signer.privateKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), publicKey...)
}
func (signer testCapsuleSigner) SignRecoveryCapsule(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(signer.privateKey, message), nil
}

func newTestCapsuleSigner(keyID string) testCapsuleSigner {
	seed := sha256.Sum256([]byte(keyID))
	return testCapsuleSigner{keyID: keyID, privateKey: ed25519.NewKeyFromSeed(seed[:])}
}

func mustParseIDs(t *testing.T) (
	domain.InstallationID,
	domain.AuthorityID,
	domain.AuthorityEpoch,
	domain.InvitationID,
	domain.PrincipalID,
	domain.DeviceID,
	domain.GrantID,
) {
	t.Helper()
	installation, err := domain.ParseInstallationID(applicationUUID(1))
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := domain.ParseAuthorityID(applicationUUID(2))
	epoch, _ := domain.ParseAuthorityEpoch(applicationUUID(3))
	invitation, _ := domain.ParseInvitationID(applicationUUID(4))
	principal, _ := domain.ParsePrincipalID(applicationUUID(5))
	device, _ := domain.ParseDeviceID(applicationUUID(6))
	grant, _ := domain.ParseGrantID(applicationUUID(7))
	return installation, authority, epoch, invitation, principal, device, grant
}

func buildBootstrapFixture(t *testing.T) bootstrapFixture {
	t.Helper()
	now := time.Date(2026, time.August, 4, 12, 0, 0, 123456000, time.UTC)
	installationID, authorityID, epoch, invitationID, principalID, deviceID, grantID := mustParseIDs(t)
	commandID, _ := domain.ParseCommandID(applicationUUID(8))
	receiptID, _ := domain.ParseReceiptID(applicationUUID(9))
	correlationID, _ := domain.ParseCorrelationID(applicationUUID(10))
	generation, _ := domain.ParseBootstrapGenerationID(applicationUUID(11))
	installationKey, _ := domain.NewPublicKeyReference("keyref:installation")
	deviceKey, _ := domain.NewPublicKeyReference("keyref:device")
	deviceSPKIBytes := [32]byte{3}
	deviceSPKI, _ := domain.NewCredentialDigest(deviceSPKIBytes)
	principalName, _ := domain.NewDisplayName("Owner")
	deviceName, _ := domain.NewDisplayName("Owner device")
	verifier := domain.FingerprintCommand([]byte("invitation verifier"))
	transcript := domain.FingerprintCommand([]byte("approved transcript"))
	invitation, err := domain.NewInstallationInvitation(
		invitationID, installationID, installationKey, verifier, now, generation,
	)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := domain.NewCapabilitySet(
		domain.InstallationOwnerCapability(), domain.IdentityAdminCapability(),
		domain.WorkspaceCreateCapability(), domain.MembershipAdminCapability(),
		domain.ActorAdminCapability(), domain.DelegationAdminCapability(),
		domain.DevicePairCapability(), domain.WorkspaceOwnerCapability(),
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := domain.NewBootstrapProof(domain.BootstrapProofParams{
		InvitationID: invitationID, InstallationID: installationID, InstallationKey: installationKey,
		InvitationEvidence: verifier, TranscriptFingerprint: transcript,
		ClientNonceDigest: domain.FingerprintCommand([]byte("client nonce")),
		ServerNonceDigest: domain.FingerprintCommand([]byte("server nonce")),
		Protocol:          domain.PairingProtocolV1, Role: domain.BootstrapRoleInstallationOwner,
		PrincipalID: principalID, PrincipalDisplayName: principalName,
		DeviceID: deviceID, DeviceDisplayName: deviceName, DevicePublicKey: deviceKey,
		DeviceSPKIFingerprint: deviceSPKI,
		OwnerGrantID:          grantID, OwnerCapabilities: capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewBootstrapAttempt(
		invitationID, proof.TranscriptFingerprint(), proof.ClientNonceDigest(), proof.ServerNonceDigest(),
		domain.FingerprintCommand([]byte("bootstrap channel binding")),
		domain.FingerprintCommand([]byte("presented bootstrap proof")),
	)
	if err != nil {
		t.Fatal(err)
	}
	generationAuthorization, _ := domain.SameBootstrapGeneration(generation)
	input := domain.BootstrapInstallationInput{
		Invitation: invitation, ExpectedInvitationVersion: invitation.Version(),
		CurrentGeneration: generation, GenerationAuthorization: generationAuthorization,
		PrincipalID: principalID, PrincipalDisplayName: principalName,
		DeviceID: deviceID, DeviceDisplayName: deviceName, DevicePublicKey: deviceKey,
		OwnerGrantID: grantID, OwnerGrantCapabilities: capabilities, Proof: proof,
		AttemptFingerprint: attempt.Fingerprint(), EvaluatedAt: now.Add(time.Minute),
	}
	result, err := domain.BootstrapInstallation(input)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := domain.InstallationScope(installationID)
	operation, _ := domain.NewOperationName("installation.bootstrap.v1")
	key, _ := domain.NewIdempotencyKey("bootstrap-retry")
	provisioningScope, _ := domain.NewProvisioningIdempotencyScope(scope, transcript, operation, key)
	receiptIdentity, _ := ProvisioningReceiptIdentity(provisioningScope)
	commitSet, _ := domain.BootstrapInstallationCommitSet(
		principalID, deviceID, grantID, invitationID, invitation.Version(),
	)
	generationNumber, _ := NewGuardGeneration(1)
	authorityGuard, _ := CurrentAuthorityEpochGuard(scope, authorityID, epoch)
	bootstrapGuard, _ := BootstrapGenerationGuard(scope, generation)
	invitationTarget, _ := domain.NewAggregateTarget(invitationID)
	invitationStatus, _ := LifecycleStatusGuard(invitationTarget, string(domain.InstallationInvitationPending))
	guardPlan, err := NewCommandGuardPlan(CommandGuardPlanParams{
		AdmissionScope: scope, AdmissionGeneration: generationNumber,
		Evidence:   []EvidenceGuard{authorityGuard, bootstrapGuard, invitationStatus},
		Disclosure: []domain.AggregateTarget{invitationTarget}, Mutations: commitSet.Expectations(),
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := result.Facts()
	expectations := make([]FactExpectation, len(facts))
	for index, fact := range facts {
		eventID, _ := domain.ParseEventID(applicationUUID(20 + index))
		expectations[index], err = NewFactExpectation(eventID, fact.Type(), fact.Origin())
		if err != nil {
			t.Fatal(err)
		}
	}
	authorship, _ := ProvisioningAuthorship(principalID)
	major, _ := NewOperationMajor(1)
	capsuleSigner := newTestCapsuleSigner("ed25519:test-owner")
	capsulePlan, _ := PrepareRecoveryCapsulePlan(capsuleSigner)
	requestFingerprint := domain.FingerprintCommand([]byte("canonical bootstrap command"))
	spec, err := NewCommandSpec(CommandSpecParams{
		Scope: scope, AuthorityID: authorityID, RequestedEpoch: epoch,
		CommandID: commandID, ReceiptID: receiptID, Operation: operation, OperationMajor: major,
		ReceiptIdentity: receiptIdentity, RequestFingerprint: requestFingerprint,
		Authorship: authorship, CorrelationID: correlationID, AuthorityTimeClass: AuthorityTimeOrdinary,
		RecoveryCapsule: capsulePlan,
		Guards:          guardPlan, ExpectedFacts: expectations,
	})
	if err != nil {
		t.Fatal(err)
	}
	invitationState, _ := NewIdentityState(invitation)
	evidence, _ := NewAppliedGuardEvidence(guardPlan, guardPlan.Evidence())
	commandTime, _ := PersistedCommandAuthorityTime(now.Add(time.Minute))
	commandContext, err := NewCommandContext(spec, commandTime, []IdentityState{invitationState}, AdmitReceipt(), evidence)
	if err != nil {
		t.Fatal(err)
	}
	firstPosition, _ := domain.NewStreamPosition(1)
	lastPosition, _ := domain.NewStreamPosition(3)
	streamDigestBytes := [32]byte{2}
	streamDigest, _ := domain.NewStreamDigest(streamDigestBytes)
	audit, _ := NewAuditIntent(operation, AuditCommandApplied, requestFingerprint, CommandAppliedAuditDetail())
	auditRequest, _ := NewAuditRequestContext(
		"request-bootstrap-1", "trace-bootstrap-1", now.Add(30*time.Second), ptrTestTime(now),
	)
	audit.invocation.requestID = &auditRequest.requestID
	audit.invocation.traceID = &auditRequest.traceID
	audit.timing.serverReceivedTime = ptrTime(auditRequest.serverReceived)
	audit.timing.clientTime = ptrTime(auditRequest.clientTime)
	audit.subject = AuditSubject{
		kind: AuditSubjectAttributed, principal: principalID, device: deviceID, hasDevice: true,
	}
	audit.provenance = AuditProvenance{sourceAuthority: authorityID}
	commit, err := BootstrapInstallationCommit(commandContext, result)
	if err != nil {
		t.Fatal(err)
	}
	effects, _ := NewEffectSet()
	decision, err := ApplyCommand(commandContext, commit, audit, effects)
	if err != nil {
		t.Fatal(err)
	}
	resultEnvelope, err := NewProductionCanonicalCodec().MaterializeReceiptResult(
		decision.ResultPlan(), firstPosition, lastPosition, streamDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	return bootstrapFixture{
		now: now, scope: scope, authority: authorityID, epoch: epoch, command: commandID,
		receipt: receiptID, correlation: correlationID, invitation: invitation,
		input: input, attempt: attempt, result: result, spec: spec, context: commandContext, commit: commit, decision: decision,
		resultRecord: resultEnvelope, capsuleSigner: capsuleSigner,
	}
}

func ptrTestTime(value time.Time) *time.Time { return &value }

func TestValidateCommandDecisionRejectsCrossContextSubstitution(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	if err := ValidateCommandDecision(fixture.context, fixture.decision); err != nil {
		t.Fatalf("exact command decision rejected: %v", err)
	}
	evidence, err := NewAppliedGuardEvidence(fixture.spec.Guards(), fixture.spec.Guards().Evidence())
	if err != nil {
		t.Fatal(err)
	}
	commandTime, err := PersistedCommandAuthorityTime(fixture.now.Add(2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := NewIdentityState(fixture.invitation)
	if err != nil {
		t.Fatal(err)
	}
	substituted, err := NewCommandContext(
		fixture.spec, commandTime, []IdentityState{invitation}, AdmitReceipt(), evidence,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCommandDecision(substituted, fixture.decision); !errors.Is(err, ErrInvalidCommandDecision) {
		t.Fatalf("cross-context command decision accepted: %v", err)
	}
}

func testSecurityAuditContext(
	t *testing.T,
	spec SecuritySpec,
	fixture bootstrapFixture,
) SecuritySpec {
	t.Helper()
	request, err := NewAuditRequestContext(
		"request-security-1", "trace-security-1", fixture.now, ptrTestTime(fixture.now.Add(-time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := NewAuditProvenanceEvidence(fixture.authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := bindSecurityAuditContext(spec, request, provenance)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func TestAuditRequestContextAndFederationProvenanceAreClosed(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	clientTime := fixture.now.Add(-time.Second)
	request, err := NewAuditRequestContext(
		"request-audit-1", "trace-audit-1", fixture.now, &clientTime,
	)
	if err != nil || request.RequestID() != "request-audit-1" || request.TraceID() != "trace-audit-1" ||
		!request.ServerReceivedAt().Equal(fixture.now) {
		t.Fatalf("audit request=%+v error=%v", request, err)
	}
	if authenticated, present := request.AuthenticatedClientAt(); !present || !authenticated.Equal(clientTime) {
		t.Fatalf("authenticated client time=%v present=%t", authenticated, present)
	}
	for _, invalid := range []struct {
		request string
		trace   string
		at      time.Time
	}{
		{"", "trace-audit-1", fixture.now},
		{"Request-Audit-1", "trace-audit-1", fixture.now},
		{"request-audit-1", "", fixture.now},
		{"request-audit-1", "trace-audit-1", time.Time{}},
	} {
		if _, invalidErr := NewAuditRequestContext(invalid.request, invalid.trace, invalid.at, nil); invalidErr == nil {
			t.Fatalf("accepted invalid audit request: %+v", invalid)
		}
	}

	remoteAuthority, _ := domain.ParseAuthorityID(applicationUUID(700))
	envelope := "federation-envelope-1"
	provenance, err := NewAuditProvenanceEvidence(remoteAuthority, &envelope)
	if err != nil || provenance.SourceAuthorityID() != remoteAuthority {
		t.Fatalf("provenance=%+v error=%v", provenance, err)
	}
	if retained, present := provenance.FederationEnvelopeID(); !present || retained != envelope {
		t.Fatalf("federation envelope=%q present=%t", retained, present)
	}
	intent := fixture.decision.Audit()
	if !intent.finalized {
		t.Fatal("bootstrap decision omitted audit")
	}
	intent.provenance = AuditProvenance{
		sourceAuthority: remoteAuthority, federationEnvelope: cloneCanonicalIdentifier(provenance.federationEnvelope),
	}
	if _, err = NewAuditEntryViewV1(AuditEntryParams{
		ChainScopeID: fixture.scope, Sequence: 1, AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		RecordedAt: fixture.now, Intent: intent,
	}); err != nil {
		t.Fatalf("federated source authority rejected: %v", err)
	}
}

func mustIdentityState(t *testing.T, value any) IdentityState {
	t.Helper()
	state, err := NewIdentityState(value)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func mustCapsuleDraft(
	t *testing.T,
	result ResultEnvelope,
	commandID domain.CommandID,
	operationMajor OperationMajor,
	keyID string,
) *RecoveryCapsuleDraft {
	t.Helper()
	capsulePlan := result.RecoveryCapsulePlan()
	if capsulePlan.KeyID() != keyID {
		t.Fatal("result retained a different prepared capsule key")
	}
	view, err := NewW0RecoveryCapsuleView(result, commandID, operationMajor, capsulePlan)
	if err != nil {
		t.Fatal(err)
	}
	document, err := NewProductionCanonicalCodec().EncodeRecoveryCapsule(view)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := NewRecoveryCapsuleDraft(result, document, keyID)
	if err != nil {
		t.Fatal(err)
	}
	return &draft
}

func bootstrapReceipt(t *testing.T, fixture bootstrapFixture) ReceiptSnapshot {
	t.Helper()
	first, _ := domain.NewStreamPosition(1)
	last, _ := domain.NewStreamPosition(3)
	events, _ := NewEventRange(first, last, 3)
	receipt, err := NewReceiptSnapshot(ReceiptSnapshotParams{
		ReceiptID: fixture.receipt, CommandID: fixture.command, Identity: fixture.spec.ReceiptIdentity(),
		RequestFingerprint: fixture.spec.RequestFingerprint(), Result: fixture.resultRecord,
		AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		GuardDigest: fixture.context.GuardEvidence().Digest(), Events: events,
		EventCursor:        EventCursor{value: "bbec1_application_fixture"},
		CapsuleRequirement: RecoveryCapsuleRequired,
		RecoveryCapsule: mustCapsuleDraft(
			t, fixture.resultRecord, fixture.command, fixture.spec.OperationMajor(),
			fixture.spec.RecoveryCapsule().KeyID(),
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestCommandContractAcceptsExactBootstrapShapeAndOwnsCopies(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	if fixture.decision.Kind() != CommandDecisionApplied || len(fixture.decision.Writes()) != 4 ||
		len(fixture.decision.Facts()) != 3 || len(fixture.decision.Effects().Intents()) != 0 {
		t.Fatalf("unexpected applied decision shape")
	}
	writes := fixture.decision.Writes()
	writes[0] = IdentityState{}
	if fixture.decision.Writes()[0].Target().IsZero() {
		t.Fatal("decision exposed mutable write slice")
	}
	bytes := fixture.resultRecord.CanonicalBytes()
	bytes[0] = 'x'
	if fixture.resultRecord.CanonicalBytes()[0] == 'x' {
		t.Fatal("result exposed mutable canonical bytes")
	}
	if got := len(fixture.spec.Guards().CreateAbsences()); got != 3 {
		t.Fatalf("create absences = %d, want 3", got)
	}
}

func TestAppliedDecisionDerivesImmutableReceiptResultPlan(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	plan := fixture.decision.ResultPlan()
	if plan.Operation() != CommandBootstrapInstallation || plan.CommandID() != fixture.command ||
		plan.OperationMajor() != fixture.spec.OperationMajor() || plan.AuthorityID() != fixture.authority ||
		plan.AuthorityEpoch() != fixture.epoch || plan.Scope() != fixture.scope ||
		plan.CommandFingerprint() != fixture.spec.RequestFingerprint() ||
		plan.CapsuleRequirement() != RecoveryCapsuleRequired ||
		plan.RecoveryCapsulePlan().KeyID() != fixture.spec.RecoveryCapsule().KeyID() {
		t.Fatal("receipt result plan did not retain exact command provenance")
	}
	if len(plan.Resources()) != 3 || len(plan.EventIDs()) != 3 {
		t.Fatal("receipt result plan omitted committed resources or event identities")
	}
	plan.resources = nil
	plan.eventIDs = nil
	plan.capsulePlan = RecoveryCapsulePlan{}
	retained := fixture.decision.ResultPlan()
	if len(retained.Resources()) != 3 || len(retained.EventIDs()) != 3 ||
		retained.RecoveryCapsulePlan().KeyID() == "" {
		t.Fatal("decision result plan was mutated through its accessor")
	}
	first, _ := domain.NewStreamPosition(1)
	wrongLast, _ := domain.NewStreamPosition(2)
	digestBytes := [32]byte{9}
	streamDigest, _ := domain.NewStreamDigest(digestBytes)
	if _, err := NewProductionCanonicalCodec().MaterializeReceiptResult(
		retained, first, wrongLast, streamDigest,
	); err == nil {
		t.Fatal("materialized a receipt with the wrong catalog event range")
	}
}

func TestReplayBindingPreservesOriginalCommandAndAcceptedAuthority(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	retrySpec := fixture.spec
	retryCommand, _ := domain.ParseCommandID(applicationUUID(93))
	retrySpec.commandID = retryCommand
	retrySigner := newTestCapsuleSigner("ed25519:rotated-current")
	retrySpec.recoveryCapsule, _ = PrepareRecoveryCapsulePlan(retrySigner)
	acceptedAuthority, _ := domain.ParseAuthorityID(applicationUUID(94))
	acceptedEpoch, _ := domain.ParseAuthorityEpoch(applicationUUID(95))
	first, _ := domain.NewStreamPosition(1)
	last, _ := domain.NewStreamPosition(3)
	events, _ := NewEventRange(first, last, 3)
	streamDigestBytes := [32]byte{2}
	streamDigest, _ := domain.NewStreamDigest(streamDigestBytes)
	resultPlan := fixture.decision.ResultPlan()
	binding, err := NewReceiptResultReplayBinding(retrySpec, ReceiptResultReplayBindingParams{
		OriginalCommandID: fixture.command, AcceptedAuthorityID: acceptedAuthority,
		AcceptedAuthorityEpoch: acceptedEpoch, GuardDigest: fixture.context.GuardEvidence().Digest(),
		AcceptedAt: resultPlan.AcceptedAt(), Resources: resultPlan.Resources(),
		IssuedCeremonies: resultPlan.IssuedCeremonies(), EventIDs: resultPlan.EventIDs(),
		Events: events, FinalStreamDigest: streamDigest,
		RecoveryCapsulePlan: fixture.spec.RecoveryCapsule(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if binding.OriginalCommandID() != fixture.command || binding.OriginalCommandID() == retryCommand ||
		binding.AuthorityID() != acceptedAuthority || binding.AuthorityEpoch() != acceptedEpoch {
		t.Fatal("replay binding replaced original receipt provenance with current routing provenance")
	}
	if binding.RecoveryCapsulePlan().KeyID() != fixture.spec.RecoveryCapsule().KeyID() ||
		binding.RecoveryCapsulePlan().KeyID() == retrySpec.RecoveryCapsule().KeyID() {
		t.Fatal("replay binding replaced the receipt's historical capsule key with the retry key")
	}
	verificationBinding, err := NewReceiptResultReplayBinding(retrySpec, ReceiptResultReplayBindingParams{
		OriginalCommandID: fixture.command, AcceptedAuthorityID: fixture.authority,
		AcceptedAuthorityEpoch: fixture.epoch, GuardDigest: fixture.context.GuardEvidence().Digest(),
		AcceptedAt: resultPlan.AcceptedAt(), Resources: resultPlan.Resources(),
		IssuedCeremonies: resultPlan.IssuedCeremonies(), EventIDs: resultPlan.EventIDs(),
		Events: events, FinalStreamDigest: streamDigest,
		RecoveryCapsulePlan: fixture.spec.RecoveryCapsule(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedResult, err := NewProductionCanonicalCodec().VerifyReceiptResult(
		fixture.resultRecord.CanonicalBytes(), fixture.resultRecord.ResponseDigest(), verificationBinding,
	)
	if err != nil || verifiedResult.ResponseDigest() != fixture.resultRecord.ResponseDigest() {
		t.Fatalf("replacement-command replay verification failed: %v", err)
	}
	draft := mustCapsuleDraft(
		t, fixture.resultRecord, fixture.command, fixture.spec.OperationMajor(),
		fixture.spec.RecoveryCapsule().KeyID(),
	)
	verifiedDocument, err := NewProductionCanonicalCodec().VerifyRecoveryCapsule(
		draft.CanonicalBytes(), draft.Digest(), verifiedResult, verificationBinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRecoveryCapsuleDraft(
		verifiedResult, verifiedDocument, fixture.spec.RecoveryCapsule().KeyID(),
	); err != nil {
		t.Fatalf("verified replay capsule did not reconstruct: %v", err)
	}
	shortLast, _ := domain.NewStreamPosition(2)
	shortRange, _ := NewEventRange(first, shortLast, 2)
	if _, err := NewReceiptResultReplayBinding(retrySpec, ReceiptResultReplayBindingParams{
		OriginalCommandID: fixture.command, AcceptedAuthorityID: acceptedAuthority,
		AcceptedAuthorityEpoch: acceptedEpoch, GuardDigest: fixture.context.GuardEvidence().Digest(),
		AcceptedAt: resultPlan.AcceptedAt(), Resources: resultPlan.Resources(),
		IssuedCeremonies: resultPlan.IssuedCeremonies(), EventIDs: resultPlan.EventIDs(),
		Events: shortRange, FinalStreamDigest: streamDigest,
		RecoveryCapsulePlan: fixture.spec.RecoveryCapsule(),
	}); !errors.Is(err, ErrInvalidApplicationContract) {
		t.Fatalf("replay binding accepted wrong operation event count: %v", err)
	}
}

func TestW0OperationCatalogIsClosedAndComplete(t *testing.T) {
	t.Parallel()
	want := []CommandOperation{
		CommandBootstrapInstallation, CommandRegisterPrincipal, CommandCreateWorkspace,
		CommandInviteWorkspaceMember, CommandAcceptWorkspaceMembership, CommandCreateActor,
		CommandProposeActorDelegation, CommandActivateActorDelegation, CommandBeginDevicePairing,
		CommandPairDevice, CommandStartActorSession,
	}
	if len(operationContracts) != len(want) {
		t.Fatalf("catalog entries=%d, want=%d", len(operationContracts), len(want))
	}
	for _, operation := range want {
		contract, exists := operationContracts[operation]
		if !exists || contract.operation != operation || len(contract.facts) == 0 ||
			len(contract.mutations) == 0 || len(contract.evidenceMinimums) == 0 {
			t.Fatalf("incomplete operation contract %q", operation)
		}
	}
	if operationContracts[CommandAcceptWorkspaceMembership].recovery != RecoveryCapsuleNotApplicable ||
		operationContracts[CommandPairDevice].recovery != RecoveryCapsuleNotApplicable ||
		operationContracts[CommandStartActorSession].authorship != AuthorshipAuthority ||
		operationContracts[CommandStartActorSession].attribution != attributionForbidden {
		t.Fatal("catalog security profile drift")
	}
}

func TestW0OperationCatalogExactSecurityProfiles(t *testing.T) {
	t.Parallel()
	type expectedContract struct {
		receipt        ReceiptIdentityKind
		scope          domain.ScopeKind
		authorship     AuthorshipClass
		attribution    attributionPolicy
		recovery       RecoveryCapsuleRequirement
		timeClass      AuthorityTimeClass
		facts          []domain.EventType
		mutations      map[domain.AggregateKind]domain.ExpectationKind
		reads          map[domain.AggregateKind]int
		variableReads  map[domain.AggregateKind]bool
		referenceReads map[domain.AggregateKind]int
		disclosure     map[domain.AggregateKind]int
		ceremonies     []ceremonyContract
		evidence       map[EvidenceGuardKind]int
		genesis        bool
	}
	want := map[CommandOperation]expectedContract{
		CommandBootstrapInstallation: {
			receipt: ReceiptIdentityProvisioning, scope: domain.ScopeKindInstallation,
			authorship: AuthorshipProvisioning, attribution: attributionForbidden,
			recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeOrdinary,
			facts: []domain.EventType{domain.EventTypeInstallationBootstrapped, domain.EventTypePrincipalRegistered, domain.EventTypeDevicePaired},
			mutations: map[domain.AggregateKind]domain.ExpectationKind{
				domain.AggregateKindInvitation: domain.ExpectationExpectedVersion,
				domain.AggregateKindPrincipal:  domain.ExpectationMustNotExist,
				domain.AggregateKindDevice:     domain.ExpectationMustNotExist,
				domain.AggregateKindGrant:      domain.ExpectationMustNotExist,
			},
			disclosure: map[domain.AggregateKind]int{domain.AggregateKindInvitation: 1},
			evidence:   map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidenceBootstrapGeneration: 1, EvidenceLifecycleStatus: 1},
		},
		CommandRegisterPrincipal: {
			receipt: ReceiptIdentityInstallationAdmin, scope: domain.ScopeKindInstallation,
			authorship: AuthorshipAuthority, attribution: attributionForbidden,
			recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeOrdinary,
			facts:      []domain.EventType{domain.EventTypePrincipalRegistered},
			mutations:  map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindPrincipal: domain.ExpectationMustNotExist},
			reads:      map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindGrant: 1},
			disclosure: map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 2},
			evidence:   map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 2, EvidenceCapabilityCeiling: 1},
		},
		CommandCreateWorkspace: {
			receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
			authorship: AuthorshipAuthority, attribution: attributionForbidden,
			recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeOrdinary,
			facts:      []domain.EventType{domain.EventTypeWorkspaceCreated, domain.EventTypeWorkspaceMemberInvited, domain.EventTypeWorkspaceMembershipAccepted},
			mutations:  map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindWorkspace: domain.ExpectationMustNotExist, domain.AggregateKindMembership: domain.ExpectationMustNotExist},
			reads:      map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindGrant: 1},
			disclosure: map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1},
			evidence:   map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 2, EvidenceCapabilityCeiling: 1},
			genesis:    true,
		},
		CommandInviteWorkspaceMember: {
			receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
			authorship: AuthorshipWorkspaceAdmin, attribution: attributionForbidden,
			recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeIssuesExpiringAuthority,
			facts:          []domain.EventType{domain.EventTypeWorkspaceMemberInvited},
			mutations:      map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindMembership: domain.ExpectationMustNotExist},
			reads:          map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 2},
			referenceReads: map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1},
			disclosure:     map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1, domain.AggregateKindMembership: 1},
			ceremonies:     []ceremonyContract{{kind: CeremonyReserveAbsent, purpose: domain.CeremonyPurposeMembershipAcceptance}},
			evidence:       map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 3, EvidenceCapabilityCeiling: 1},
		},
		CommandAcceptWorkspaceMembership: {
			receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
			authorship: AuthorshipAuthority, attribution: attributionForbidden,
			recovery: RecoveryCapsuleNotApplicable, timeClass: AuthorityTimeOrdinary,
			facts:          []domain.EventType{domain.EventTypeWorkspaceMembershipAccepted},
			mutations:      map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindMembership: domain.ExpectationExpectedVersion},
			reads:          map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 1},
			referenceReads: map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1},
			disclosure:     map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1, domain.AggregateKindMembership: 1},
			ceremonies:     []ceremonyContract{{kind: CeremonyConsumeEmbedded, purpose: domain.CeremonyPurposeMembershipAcceptance}},
			evidence:       map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 3},
		},
		CommandCreateActor: {
			receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
			authorship: AuthorshipWorkspaceAdmin, attribution: attributionOptional,
			recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeOrdinary,
			facts:      []domain.EventType{domain.EventTypeActorCreated},
			mutations:  map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindActor: domain.ExpectationMustNotExist},
			reads:      map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 1},
			disclosure: map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1, domain.AggregateKindActor: 1},
			evidence:   map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 2},
		},
		CommandProposeActorDelegation: {
			receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
			authorship: AuthorshipWorkspaceAdmin, attribution: attributionOptional,
			recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeIssuesExpiringAuthority,
			facts:          []domain.EventType{domain.EventTypeActorDelegationProposed},
			mutations:      map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindActorDelegation: domain.ExpectationMustNotExist},
			reads:          map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 2, domain.AggregateKindActor: 1, domain.AggregateKindMembership: 1},
			referenceReads: map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindActor: 1, domain.AggregateKindMembership: 1},
			disclosure:     map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1, domain.AggregateKindActorDelegation: 1},
			ceremonies:     []ceremonyContract{{kind: CeremonyReserveAbsent, purpose: domain.CeremonyPurposeDelegationActivation}},
			evidence:       map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 5, EvidenceCapabilityCeiling: 1},
		},
		CommandActivateActorDelegation: {
			receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
			authorship: AuthorshipAuthority, attribution: attributionForbidden,
			recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeIssuesExpiringAuthority,
			facts:          []domain.EventType{domain.EventTypeActorDelegationActivated},
			mutations:      map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindActorDelegation: domain.ExpectationExpectedVersion},
			reads:          map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 1, domain.AggregateKindActor: 1, domain.AggregateKindMembership: 1},
			referenceReads: map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1, domain.AggregateKindActor: 1, domain.AggregateKindMembership: 1},
			disclosure:     map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1, domain.AggregateKindActorDelegation: 1},
			ceremonies:     []ceremonyContract{{kind: CeremonyConsumeEmbedded, purpose: domain.CeremonyPurposeDelegationActivation}, {kind: CeremonyReserveAbsent, purpose: domain.CeremonyPurposeActorSessionStart}},
			evidence:       map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 5, EvidenceCapabilityCeiling: 1},
		},
		CommandBeginDevicePairing: {
			receipt: ReceiptIdentityInstallationAdmin, scope: domain.ScopeKindInstallation,
			authorship: AuthorshipAuthority, attribution: attributionForbidden,
			recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeIssuesExpiringAuthority,
			facts:      []domain.EventType{domain.EventTypeDevicePairingBegan},
			mutations:  map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindDevice: domain.ExpectationMustNotExist},
			reads:      map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindGrant: 1},
			disclosure: map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindDevice: 1},
			ceremonies: []ceremonyContract{{kind: CeremonyReserveAbsent, purpose: domain.CeremonyPurposeDevicePairing}},
			evidence:   map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 2, EvidenceCapabilityCeiling: 1},
		},
		CommandPairDevice: {
			receipt: ReceiptIdentityInstallationAdmin, scope: domain.ScopeKindInstallation,
			authorship: AuthorshipAuthority, attribution: attributionForbidden,
			recovery: RecoveryCapsuleNotApplicable, timeClass: AuthorityTimeOrdinary,
			facts:      []domain.EventType{domain.EventTypeDevicePaired},
			mutations:  map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindDevice: domain.ExpectationExpectedVersion},
			reads:      map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1},
			disclosure: map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindDevice: 1},
			ceremonies: []ceremonyContract{{kind: CeremonyConsumeEmbedded, purpose: domain.CeremonyPurposeDevicePairing}},
			evidence:   map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 2, EvidenceDeviceTrustRevision: 1},
		},
		CommandStartActorSession: {
			receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
			authorship: AuthorshipAuthority, attribution: attributionForbidden,
			recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeIssuesExpiringAuthority,
			facts:         []domain.EventType{domain.EventTypeActorSessionStarted},
			mutations:     map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindActorSession: domain.ExpectationMustNotExist},
			reads:         map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1, domain.AggregateKindMembership: 1, domain.AggregateKindActor: 1, domain.AggregateKindActorDelegation: 1},
			variableReads: map[domain.AggregateKind]bool{domain.AggregateKindGrant: true, domain.AggregateKindDevice: true},
			disclosure:    map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1, domain.AggregateKindActorSession: 1},
			evidence:      map[EvidenceGuardKind]int{EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1, EvidenceLifecycleStatus: 5, EvidenceCapabilityCeiling: 2, EvidenceResourceConstraint: 1},
		},
	}
	if len(want) != len(operationContracts) {
		t.Fatalf("expected catalog size=%d, got=%d", len(want), len(operationContracts))
	}
	for operation, expected := range want {
		actual, exists := operationContracts[operation]
		if !exists || actual.operation != operation || actual.receipt != expected.receipt ||
			actual.scope != expected.scope || actual.authorship != expected.authorship ||
			actual.attribution != expected.attribution || actual.recovery != expected.recovery ||
			actual.timeClass != expected.timeClass || actual.genesis != expected.genesis ||
			!equalEventTypes(actual.facts, expected.facts) || !equalExpectationKinds(actual.mutations, expected.mutations) ||
			!equalIntMap(actual.reads, expected.reads) || !equalBoolMap(actual.variableReads, expected.variableReads) ||
			!equalIntMap(actual.referenceReads, expected.referenceReads) || !equalIntMap(actual.disclosure, expected.disclosure) ||
			!equalCeremonyContracts(actual.ceremonies, expected.ceremonies) || !equalEvidenceMinimums(actual.evidenceMinimums, expected.evidence) {
			t.Fatalf("catalog security profile drift for %q: %#v", operation, actual)
		}
	}
}

func equalEventTypes(left, right []domain.EventType) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalExpectationKinds(left, right map[domain.AggregateKind]domain.ExpectationKind) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func equalIntMap[K comparable](left, right map[K]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func equalBoolMap[K comparable](left, right map[K]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func equalCeremonyContracts(left, right []ceremonyContract) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalEvidenceMinimums(left, right map[EvidenceGuardKind]int) bool {
	return equalIntMap(left, right)
}

func TestActorAttributionIsAnIndivisiblePair(t *testing.T) {
	t.Parallel()
	_, _, _, _, principal, _, _ := mustParseIDs(t)
	actor, _ := domain.ParseActorID(applicationUUID(92))
	session, _ := domain.ParseActorSessionID(applicationUUID(93))
	if _, err := NewActorAttribution(actor, domain.ActorSessionID{}); !errors.Is(err, ErrInvalidCommandSpec) {
		t.Fatalf("partial attribution error=%v", err)
	}
	attribution, err := NewActorAttribution(actor, session)
	if err != nil {
		t.Fatal(err)
	}
	authorship, err := WorkspaceAdminAuthorship(principal, &attribution)
	got, ok := authorship.ActorAttribution()
	if err != nil || !ok || got.ActorID() != actor || got.ActorSessionID() != session {
		t.Fatalf("attribution=%+v ok=%t error=%v", got, ok, err)
	}
}

func TestSealedInterfacesRejectTypedNilAndMutableFactPointers(t *testing.T) {
	t.Parallel()
	var signer *testCapsuleSigner
	if _, err := PrepareRecoveryCapsulePlan(signer); !errors.Is(err, ErrInvalidCommandSpec) {
		t.Fatalf("typed-nil signer error=%v", err)
	}
	fixture := buildBootstrapFixture(t)
	fact := fixture.result.Facts()[0].(domain.InstallationBootstrappedFact)
	eventID := fixture.spec.ExpectedFacts()[0].EventID()
	if _, err := NewFactIntent(eventID, &fact); !errors.Is(err, ErrInvalidCommandDecision) {
		t.Fatalf("mutable fact pointer error=%v", err)
	}
}

func TestCommandContextRejectsUndeclaredState(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	invitation := mustIdentityState(t, fixture.invitation)
	extra := mustIdentityState(t, fixture.result.Principal())
	if _, err := NewCommandContext(
		fixture.spec, fixture.context.TimeEvidence(), []IdentityState{invitation, extra},
		AdmitReceipt(), fixture.context.GuardEvidence(),
	); !errors.Is(err, ErrInvalidCommandContext) {
		t.Fatalf("undeclared state error=%v", err)
	}
}

func TestCommandDecisionRejectsEveryShapeMismatch(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	tests := []struct {
		name   string
		mutate func([]IdentityState, []FactIntent) ([]IdentityState, []FactIntent)
	}{
		{name: "missing write", mutate: func(writes []IdentityState, facts []FactIntent) ([]IdentityState, []FactIntent) {
			return writes[1:], facts
		}},
		{name: "missing fact", mutate: func(writes []IdentityState, facts []FactIntent) ([]IdentityState, []FactIntent) {
			return writes, facts[1:]
		}},
		{name: "wrong event id", mutate: func(writes []IdentityState, facts []FactIntent) ([]IdentityState, []FactIntent) {
			wrongID, _ := domain.ParseEventID(applicationUUID(99))
			facts[0], _ = NewFactIntent(wrongID, facts[0].Fact())
			return writes, facts
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writes := fixture.decision.Writes()
			facts := fixture.decision.Facts()
			writes, facts = test.mutate(writes, facts)
			commit := fixture.commit
			commit.writes, commit.facts = writes, facts
			_, err := ApplyCommand(
				fixture.context, commit, fixture.decision.Audit(), fixture.decision.Effects(),
			)
			if !errors.Is(err, ErrInvalidCommandDecision) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestIJSONBoundsAndBoundedPayloads(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		value uint64
		valid bool
	}{
		{value: MaxCanonicalInteger - 1, valid: true},
		{value: MaxCanonicalInteger, valid: true},
		{value: MaxCanonicalInteger + 1, valid: false},
		{value: 0, valid: false},
	} {
		_, err := NewGuardGeneration(test.value)
		if (err == nil) != test.valid {
			t.Errorf("generation %d error=%v valid=%t", test.value, err, test.valid)
		}
	}
	for _, size := range []int{MaxReceiptResultBytes - 100, MaxReceiptResultBytes, MaxReceiptResultBytes + 1} {
		canonical := []byte(strings.Repeat("x", size))
		document := ReceiptResultDocument{document: canonicalDocument{
			canonical: canonical, digest: DigestBytes(canonical),
		}, operation: CommandBootstrapInstallation}
		_, err := NewResultEnvelope(document)
		if !errors.Is(err, ErrInvalidApplicationContract) {
			t.Errorf("forged result size %d error=%v", size, err)
		}
	}
	eventID, _ := domain.ParseEventID(applicationUUID(101))
	major, _ := NewOperationMajor(1)
	for _, size := range []int{MaxEffectMetadataBytes - 1, MaxEffectMetadataBytes, MaxEffectMetadataBytes + 1} {
		_, err := NewEffectIntent(eventID, "projection", major, "destination", 0, []byte(strings.Repeat("x", size)))
		if (err == nil) != (size <= MaxEffectMetadataBytes) {
			t.Errorf("effect size %d error=%v", size, err)
		}
	}
}

func TestQueryDTOViewsRetainCompleteDeterministicData(t *testing.T) {
	t.Parallel()
	_, authority, epoch, _, principal, _, _ := mustParseIDs(t)
	workspace, _ := domain.ParseWorkspaceID(applicationUUID(140))
	actor, _ := domain.ParseActorID(applicationUUID(141))
	session, _ := domain.ParseActorSessionID(applicationUUID(142))
	command, _ := domain.ParseCommandID(applicationUUID(143))
	eventID, _ := domain.ParseEventID(applicationUUID(144))
	causation, _ := domain.ParseEventID(applicationUUID(145))
	correlation, _ := domain.ParseCorrelationID(applicationUUID(146))
	subject, _ := NewQuerySubject(principal, session)
	checkpointID, _ := NewCheckpointID("checkpoint:test")
	cursor, _ := NewEventCursor("bbec1_after")
	query, err := NewContextGetQuery(subject, checkpointID, cursor, MaxQueryPageSize)
	if err != nil || query.Cursor() != cursor || query.Limit() != MaxQueryPageSize {
		t.Fatalf("context query=%+v error=%v", query, err)
	}
	if _, err = NewContextGetQuery(subject, checkpointID, cursor, 0); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("zero context limit error=%v", err)
	}
	recordKinds := []ContextRecordKind{
		ContextRecordActor, ContextRecordDelegation, ContextRecordMembership, ContextRecordPrincipal,
		ContextRecordSession, ContextRecordWorkspace,
	}
	records := make([]ContextRecord, 0, len(recordKinds))
	for index, kind := range recordKinds {
		id := applicationUUID(150 + index)
		if kind == ContextRecordWorkspace {
			id = workspace.String()
		}
		record, recordErr := NewTypedContextRecord(ContextRecordParams{
			Kind: kind, ID: id, Version: domain.InitialVersion(), LifecycleState: ContextStateActive,
			CanonicalPayload: []byte(`{"status":"active"}`),
		})
		if recordErr != nil {
			t.Fatalf("new %s context record: %v", kind, recordErr)
		}
		records = append(records, record)
	}
	checkpoint, err := NewContextCheckpoint(ContextCheckpointParams{
		CheckpointID: checkpointID, AuthorityID: authority, AuthorityEpoch: epoch, ThroughCursor: cursor,
		ProjectionVersion: 1, ServerTime: time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC),
		Session: AuthorizedSessionView{session: session}, Records: records,
	})
	if err != nil || checkpoint.AuthorityID() != authority || checkpoint.AuthorityEpoch() != epoch ||
		checkpoint.ProjectionVersion() != 1 || checkpoint.ServerTime().IsZero() {
		t.Fatalf("context checkpoint=%+v error=%v", checkpoint, err)
	}
	checkpointPage, err := NewContextCheckpointPage(checkpoint, cursor)
	if err != nil || checkpointPage.HeadCursor() != cursor || checkpointPage.NextCursor() != cursor {
		t.Fatalf("checkpoint page=%+v error=%v", checkpointPage, err)
	}

	scope, _ := domain.WorkspaceScope(workspace)
	position, _ := domain.NewStreamPosition(7)
	aggregate, _ := domain.NewAggregateRef(workspace, domain.InitialVersion())
	eventVersion, _ := domain.NewEventSchemaVersion(1)
	occurred := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	payload := []byte(`{"workspace_id":"fixture"}`)
	event, err := NewSyncedEvent(SyncedEventParams{
		EventID: eventID, EventType: domain.EventTypeWorkspaceCreated, EventVersion: eventVersion,
		AuthorityID: authority, AuthorityEpoch: epoch, Scope: scope, OriginPosition: position,
		Aggregate: aggregate, PrincipalID: principal, ActorID: &actor, ActorSessionID: &session,
		CommandID: command, CausationID: &causation, CorrelationID: correlation,
		OccurredAt: occurred, RecordedAt: occurred.Add(time.Second), Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 'x'
	if event.AuthorityID() != authority || event.AuthorityEpoch() != epoch || event.Scope() != scope ||
		event.OriginPosition() != position || event.EventVersion() != eventVersion ||
		event.PrincipalID() != principal || event.CommandID() != command || event.CorrelationID() != correlation ||
		!event.OccurredAt().Equal(occurred) || event.Payload()[0] != '{' ||
		event.ActorID() == nil || *event.ActorID() != actor || event.ActorSessionID() == nil ||
		*event.ActorSessionID() != session || event.CausationID() == nil || *event.CausationID() != causation {
		t.Fatal("synced event omitted or aliased canonical envelope data")
	}
	head, _ := NewEventCursor("bbec1_head")
	page, err := NewEventsPage(AuthorizedSessionView{session: session}, cursor, head, head, []SyncedEvent{event}, false)
	if err != nil || page.HeadCursor() != head {
		t.Fatalf("events page=%+v error=%v", page, err)
	}
	invalid := SyncedEventParams{EventID: eventID}
	if _, err = NewSyncedEvent(invalid); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("incomplete event error=%v", err)
	}
	target, _ := domain.NewAggregateTarget(workspace)
	if _, err = NewContextDelta(eventID, ContextDeltaUpsert, target, domain.InitialVersion(), []byte(`[]`), head); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("non-object context delta error=%v", err)
	}
}

func TestContextRecordTypedProjectionIsClosedImmutableAndComplete(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind  ContextRecordKind
		state ContextLifecycleState
	}{
		{ContextRecordWorkspace, ContextStateArchived},
		{ContextRecordPrincipal, ContextStateDisabled},
		{ContextRecordActor, ContextStateRetired},
		{ContextRecordMembership, ContextStateInvited},
		{ContextRecordDelegation, ContextStateProposed},
		{ContextRecordSession, ContextStateExpired},
		{ContextRecordDevice, ContextStateTrusted},
		{ContextRecordGrant, ContextStateRevoked},
		{ContextRecordCollaborator, ContextStateSuspended},
	}
	for index, test := range tests {
		payload := []byte(`{"status":"` + string(test.state) + `","value":"canonical"}`)
		record, err := NewTypedContextRecord(ContextRecordParams{
			Kind: test.kind, ID: applicationUUID(180 + index), Version: domain.InitialVersion(),
			LifecycleState: test.state, CanonicalPayload: payload,
		})
		if err != nil {
			t.Fatalf("NewTypedContextRecord(%s, %s): %v", test.kind, test.state, err)
		}
		payload[0] = 'x'
		first := record.CanonicalPayload()
		first[0] = 'x'
		if record.Kind() != test.kind || record.ID() == "" || record.Version() != domain.InitialVersion() ||
			record.LifecycleState() != test.state || record.CanonicalPayload()[0] != '{' {
			t.Fatalf("record %s omitted or aliased projection data", test.kind)
		}
	}

	for _, test := range []struct {
		kind  ContextRecordKind
		state ContextLifecycleState
	}{
		{ContextRecordWorkspace, ContextStateRevoked},
		{ContextRecordPrincipal, ContextStateArchived},
		{ContextRecordActor, ContextStateExpired},
		{ContextRecordMembership, ContextStateRetired},
		{ContextRecordDelegation, ContextStateEnded},
		{ContextRecordSession, ContextStateInvited},
		{ContextRecordDevice, ContextStateEnded},
		{ContextRecordGrant, ContextStateTrusted},
	} {
		_, err := NewTypedContextRecord(ContextRecordParams{
			Kind: test.kind, ID: applicationUUID(200), Version: domain.InitialVersion(),
			LifecycleState: test.state, CanonicalPayload: []byte(`{"status":"active"}`),
		})
		if !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("NewTypedContextRecord(%s, %s) error = %v", test.kind, test.state, err)
		}
	}
}

func TestContextCheckpointNormalizesCompleteRecordOrdering(t *testing.T) {
	t.Parallel()
	_, authority, epoch, _, _, _, _ := mustParseIDs(t)
	session, _ := domain.ParseActorSessionID(applicationUUID(229))
	checkpointID, _ := NewCheckpointID("checkpoint:ordering")
	cursor, _ := NewEventCursor("bbcc1_ordering")
	kinds := []ContextRecordKind{
		ContextRecordWorkspace, ContextRecordSession, ContextRecordPrincipal, ContextRecordMembership,
		ContextRecordDelegation, ContextRecordCollaborator, ContextRecordActor, ContextRecordCollaborator,
	}
	records := make([]ContextRecord, 0, len(kinds))
	for index, kind := range kinds {
		record, err := NewTypedContextRecord(ContextRecordParams{
			Kind: kind, ID: applicationUUID(230 - index), Version: domain.InitialVersion(),
			LifecycleState: ContextStateActive, CanonicalPayload: []byte(`{"status":"active"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	checkpoint, err := NewContextCheckpoint(ContextCheckpointParams{
		CheckpointID: checkpointID, AuthorityID: authority, AuthorityEpoch: epoch, ThroughCursor: cursor,
		ProjectionVersion: 1, ServerTime: time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		Session: AuthorizedSessionView{session: session}, Records: records,
	})
	if err != nil {
		t.Fatal(err)
	}
	ordered := checkpoint.Records()
	for index := 1; index < len(ordered); index++ {
		if ordered[index-1].Kind() > ordered[index].Kind() ||
			ordered[index-1].Kind() == ordered[index].Kind() && ordered[index-1].ID() >= ordered[index].ID() {
			t.Fatalf("records are not deterministically ordered: %+v", ordered)
		}
	}
	records[0].canonical[0] = 'x'
	ordered[0].canonical[0] = 'x'
	if checkpoint.Records()[0].CanonicalPayload()[0] != '{' {
		t.Fatal("checkpoint records alias constructor or accessor storage")
	}
}

func TestReceiptIdentityVariantsAreClosedAndEpochIndependent(t *testing.T) {
	t.Parallel()
	installation, _, _, _, principal, _, _ := mustParseIDs(t)
	workspace, _ := domain.ParseWorkspaceID(applicationUUID(110))
	client, _ := domain.ParseClientInstanceID(applicationUUID(111))
	operation, _ := domain.NewOperationName("principal.register.v1")
	key, _ := domain.NewIdempotencyKey("identity-key")
	ordinaryScope, _ := domain.NewIdempotencyScope(workspace, principal, client, operation, key)
	ordinary, err := OrdinaryReceiptIdentity(ordinaryScope)
	if err != nil || ordinary.Kind() != ReceiptIdentityOrdinary || ordinary.PrincipalID() != principal {
		t.Fatalf("ordinary identity=%+v error=%v", ordinary, err)
	}
	admin, err := InstallationAdminReceiptIdentity(installation, principal, client, operation, key)
	if err != nil || admin.Kind() != ReceiptIdentityInstallationAdmin || admin.InstallationID() != installation {
		t.Fatalf("admin identity=%+v error=%v", admin, err)
	}
	// Neither constructor accepts authority ID or epoch. Successor routing can
	// therefore retain the exact same secondary identity by construction.
	if ordinary.Operation() != operation || admin.Operation() != operation {
		t.Fatal("operation major identity drifted")
	}
}

func TestCeremonyClaimsDeclareGlobalAbsenceAndOneUseCAS(t *testing.T) {
	t.Parallel()
	ceremonyID, _ := domain.ParseCeremonyID(applicationUUID(120))
	membershipID, _ := domain.ParseMembershipID(applicationUUID(121))
	proof := domain.FingerprintCommand([]byte("ceremony proof"))
	absent, _ := domain.ExpectAggregateAbsent(membershipID)
	owner := absent.Target()
	workspaceID, _ := domain.ParseWorkspaceID(applicationUUID(122))
	principalID, _ := domain.ParsePrincipalID(applicationUUID(123))
	expiresAt := time.Date(2026, time.August, 4, 12, 5, 0, 0, time.UTC)
	matching, _ := domain.NewMembershipAcceptanceChallenge(
		ceremonyID, proof, expiresAt, workspaceID, membershipID, principalID,
	)
	reserve, err := ReserveCeremony(matching, owner)
	if err != nil {
		t.Fatal(err)
	}
	generation, _ := NewGuardGeneration(1)
	installation, _, _, _, _, _, _ := mustParseIDs(t)
	scope, _ := domain.InstallationScope(installation)
	if _, err = NewCommandGuardPlan(CommandGuardPlanParams{
		AdmissionScope: scope, AdmissionGeneration: generation,
		Disclosure: []domain.AggregateTarget{owner},
		Mutations:  []domain.AggregateExpectation{absent},
		Ceremonies: []CeremonyClaim{reserve, reserve},
	}); !errors.Is(err, ErrInvalidGuardPlan) {
		t.Fatalf("duplicate global ceremony error=%v", err)
	}
	versioned, _ := domain.ExpectAggregateVersion(membershipID, domain.InitialVersion())
	ownerRef, _ := domain.NewAggregateRef(membershipID, domain.InitialVersion())
	consume, _ := ConsumeEmbeddedCeremony(
		ceremonyID, domain.CeremonyPurposeMembershipAcceptance, proof, ownerRef,
	)
	plan, err := NewCommandGuardPlan(CommandGuardPlanParams{
		AdmissionScope: scope, AdmissionGeneration: generation,
		Disclosure: []domain.AggregateTarget{owner},
		Mutations:  []domain.AggregateExpectation{versioned}, Ceremonies: []CeremonyClaim{consume},
	})
	if err != nil || len(plan.Ceremonies()) != 1 {
		t.Fatalf("embedded ceremony plan error=%v", err)
	}
	standalone, err := ConsumeStandaloneCeremony(
		ceremonyID, domain.CeremonyPurposeActorSessionStart, proof,
	)
	if err != nil || standalone.Kind() != CeremonyConsumeStandalone {
		t.Fatalf("standalone ceremony=%+v error=%v", standalone, err)
	}
	if !storedIssuedCeremoniesMatchSpec([]domain.CeremonyChallenge{matching}, []CeremonyClaim{reserve}) {
		t.Fatal("exact stored ceremony did not match its reservation")
	}
	wrongExpiry, _ := domain.NewMembershipAcceptanceChallenge(
		ceremonyID, proof, expiresAt.Add(time.Second), workspaceID, membershipID, principalID,
	)
	wrongMembershipID, _ := domain.ParseMembershipID(applicationUUID(124))
	wrongOwner, _ := domain.NewMembershipAcceptanceChallenge(
		ceremonyID, proof, expiresAt, workspaceID, wrongMembershipID, principalID,
	)
	for _, challenge := range []domain.CeremonyChallenge{wrongExpiry, wrongOwner} {
		if storedIssuedCeremoniesMatchSpec([]domain.CeremonyChallenge{challenge}, []CeremonyClaim{reserve}) {
			t.Fatal("stored ceremony mismatch passed exact replay binding")
		}
	}
}

func TestEffectLogicalIdentityExcludesCausingEvent(t *testing.T) {
	t.Parallel()
	first, _ := domain.ParseEventID(applicationUUID(130))
	second, _ := domain.ParseEventID(applicationUUID(131))
	major, _ := NewOperationMajor(1)
	left, _ := NewEffectIntent(first, "projection", major, "same-destination", 0, []byte(`{"a":1}`))
	right, _ := NewEffectIntent(second, "projection", major, "same-destination", 0, []byte(`{"a":2}`))
	if _, err := NewEffectSet(left, right); !errors.Is(err, ErrInvalidApplicationContract) {
		t.Fatalf("duplicate logical effect error=%v", err)
	}
}

func TestReceiptResolutionDistinguishesReplayAndConflicts(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	first, _ := domain.NewStreamPosition(1)
	last, _ := domain.NewStreamPosition(3)
	eventRange, _ := NewEventRange(first, last, 3)
	receipt, err := NewReceiptSnapshot(ReceiptSnapshotParams{
		ReceiptID: fixture.receipt, CommandID: fixture.command, Identity: fixture.spec.ReceiptIdentity(),
		RequestFingerprint: fixture.spec.RequestFingerprint(), Result: fixture.resultRecord,
		AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		GuardDigest: fixture.context.GuardEvidence().Digest(), Events: eventRange,
		EventCursor:        EventCursor{value: "bbec1_application_fixture"},
		CapsuleRequirement: RecoveryCapsuleRequired,
		RecoveryCapsule: mustCapsuleDraft(
			t, fixture.resultRecord, fixture.command, fixture.spec.OperationMajor(),
			fixture.spec.RecoveryCapsule().KeyID(),
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	replay, _ := ReplayReceipt(receipt)
	disclosureTime, _ := ReadOnlyDisclosureTime(fixture.now.Add(2*time.Minute), fixture.now.Add(time.Minute))
	context, err := NewCommandContext(
		fixture.spec, disclosureTime, []IdentityState{mustIdentityState(t, fixture.result.Invitation())},
		replay, fixture.context.GuardEvidence(),
	)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := ReplayCommand(context, ReplayDiscloseAppliedOnly)
	if err != nil || decision.Kind() != CommandDecisionReplay {
		t.Fatalf("replay decision=%v error=%v", decision.Kind(), err)
	}
	if _, _, exposed := decision.Replay(); exposed {
		t.Fatal("applied-only replay exposed full receipt")
	}
	redacted, ok := decision.AppliedOnlyReplay()
	if !ok || redacted.ReceiptID() != fixture.receipt {
		t.Fatal("applied-only replay omitted minimal identity")
	}
	execution, err := ReplayedCommandExecution(receipt, ReplayDiscloseAppliedOnly, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, exposed := execution.Receipt(); exposed {
		t.Fatal("applied-only execution exposed full receipt")
	}
	if _, ok = execution.AppliedOnlyReceipt(); !ok {
		t.Fatal("applied-only execution omitted redacted receipt")
	}
	replacementID, _ := domain.ParseCommandID(applicationUUID(102))
	replacementSpec := fixture.spec
	replacementSpec.commandID = replacementID
	if _, replacementErr := NewCommandContext(
		replacementSpec, disclosureTime, []IdentityState{mustIdentityState(t, fixture.result.Invitation())},
		replay, fixture.context.GuardEvidence(),
	); replacementErr != nil {
		t.Fatalf("secondary-identity replay with replacement command ID: %v", replacementErr)
	}
	conflicts := []struct {
		kind ReceiptResolutionKind
		code domain.ErrorCode
	}{
		{ReceiptCommandIDConflict, domain.ErrorCodeCommandIDReused},
		{ReceiptIdempotencyConflict, domain.ErrorCodeIdempotencyKeyReused},
		{ReceiptInProgress, domain.ErrorCodeCommandInProgress},
	}
	for _, conflict := range conflicts {
		resolution, _ := ConflictReceipt(conflict.kind, fixture.receipt)
		conflictContext, contextErr := NewCommandContext(
			fixture.spec, disclosureTime, nil, resolution, fixture.context.GuardEvidence(),
		)
		if contextErr != nil {
			t.Fatal(contextErr)
		}
		rejection, _ := domain.NewCommandError(conflict.code, "receipt conflict", nil)
		if _, decisionErr := RollbackCommand(conflictContext, rejection); decisionErr != nil {
			t.Errorf("%s decision error: %v", conflict.kind, decisionErr)
		}
	}
}

func TestReceiptSnapshotRejectsMetadataOutsideSealedResult(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	first, _ := domain.NewStreamPosition(1)
	last, _ := domain.NewStreamPosition(3)
	events, _ := NewEventRange(first, last, 3)
	draft := mustCapsuleDraft(
		t, fixture.resultRecord, fixture.command, fixture.spec.OperationMajor(),
		fixture.spec.RecoveryCapsule().KeyID(),
	)
	valid := ReceiptSnapshotParams{
		ReceiptID: fixture.receipt, CommandID: fixture.command, Identity: fixture.spec.ReceiptIdentity(),
		RequestFingerprint: fixture.spec.RequestFingerprint(), Result: fixture.resultRecord,
		AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		GuardDigest: fixture.context.GuardEvidence().Digest(), Events: events,
		EventCursor:        EventCursor{value: "bbec1_application_fixture"},
		CapsuleRequirement: RecoveryCapsuleRequired, RecoveryCapsule: draft,
	}
	receipt, err := NewReceiptSnapshot(valid)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := CommittedCapsulePendingCommandExecution(receipt)
	if err != nil {
		t.Fatal(err)
	}
	view, resultCursor, ok := execution.ResultView()
	if !ok || resultCursor != valid.EventCursor || view.AcceptedAt().IsZero() || len(view.Resources()) != 3 {
		t.Fatalf("command execution result ok=%t cursor=%q accepted=%s resources=%d", ok,
			resultCursor.String(), view.AcceptedAt(), len(view.Resources()))
	}
	otherAuthority, _ := domain.ParseAuthorityID(applicationUUID(91))
	otherFingerprint := domain.FingerprintCommand([]byte("different-command"))
	otherGuardBytes := [32]byte{92}
	otherGuard, _ := domain.NewAuthorizationDigest(otherGuardBytes)
	wrongLast, _ := domain.NewStreamPosition(2)
	wrongEvents, _ := NewEventRange(first, wrongLast, 2)
	mutations := []func(*ReceiptSnapshotParams){
		func(params *ReceiptSnapshotParams) { params.EventCursor = EventCursor{} },
		func(params *ReceiptSnapshotParams) { params.AuthorityID = otherAuthority },
		func(params *ReceiptSnapshotParams) { params.RequestFingerprint = otherFingerprint },
		func(params *ReceiptSnapshotParams) { params.GuardDigest = otherGuard },
		func(params *ReceiptSnapshotParams) { params.Events = wrongEvents },
		func(params *ReceiptSnapshotParams) {
			copy := *params.RecoveryCapsule
			copy.keyID = "wrong-key"
			params.RecoveryCapsule = &copy
		},
		func(params *ReceiptSnapshotParams) {
			copy := *params.RecoveryCapsule
			copy.resultDigest = DigestBytes([]byte("different-result"))
			params.RecoveryCapsule = &copy
		},
	}
	for index, mutate := range mutations {
		params := valid
		mutate(&params)
		if _, err := NewReceiptSnapshot(params); !errors.Is(err, ErrInvalidApplicationContract) {
			t.Fatalf("metadata mismatch %d accepted: %v", index, err)
		}
	}
}

func TestSecurityDenialIsCommittedDataNotCallbackError(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	invalidInput := fixture.input
	wrongDevice, _ := domain.ParseDeviceID(applicationUUID(500))
	invalidInput.DeviceID = wrongDevice
	rejected, err := domain.BootstrapInstallation(invalidInput)
	if err != nil || rejected.Outcome() != domain.BootstrapInstallationProofRejected {
		t.Fatalf("domain denial outcome=%s error=%v", rejected.Outcome(), err)
	}
	invitationTarget, _ := domain.ExpectAggregateVersion(fixture.invitation.ID(), fixture.invitation.Version())
	generation, _ := NewGuardGeneration(1)
	spec, err := RecordBootstrapDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch, generation,
		invitationTarget, fixture.attempt,
	)
	if err != nil {
		t.Fatal(err)
	}
	spec = testSecurityAuditContext(t, spec, fixture)
	if !spec.RequiresReservedAdmission() {
		t.Fatal("bootstrap denial did not require reserved security admission")
	}
	guardDigest := fixture.context.GuardEvidence().Digest()
	securityContext, err := NewSecurityContext(
		spec, fixture.now.Add(time.Minute), fixture.invitation, FreshSecurityAttempt(), DenialAdmission{}, guardDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	operation, _ := domain.NewOperationName("installation.bootstrap.v1")
	deniedDetail, _ := SecurityDeniedAuditDetail("proof_rejected")
	audit, _ := NewAuditIntent(
		operation, AuditSecurityDenied, invalidInput.AttemptFingerprint, deniedDetail,
	)
	decision, err := DenyBootstrapSecurity(securityContext, rejected.Invitation(), audit)
	if err != nil || decision.Kind() != SecurityDecisionDeny {
		t.Fatalf("security decision=%s error=%v", decision.Kind(), err)
	}
	if err := ValidateSecurityDecision(securityContext, decision); err != nil {
		t.Fatalf("valid locked decision rejected: %v", err)
	}
	substitutedContext, err := NewSecurityContext(
		spec, fixture.now.Add(2*time.Minute), fixture.invitation, FreshSecurityAttempt(), DenialAdmission{}, guardDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecurityDecision(substitutedContext, decision); !errors.Is(err, ErrInvalidSecurityDecision) {
		t.Fatalf("cross-context decision accepted: %v", err)
	}
	record, ok := decision.Denial()
	if !ok || record.InvitationVersion().Uint64() != 2 {
		t.Fatalf("security denial record=%+v ok=%t", record, ok)
	}
	replayResolution, _ := ReplaySecurityAttempt(record)
	replayContext, err := NewSecurityContext(
		spec, fixture.now.Add(2*time.Minute), rejected.Invitation(), replayResolution, DenialAdmission{}, guardDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayDecision, err := ReplayBootstrapDenialSecurity(replayContext)
	if err != nil || replayDecision.Kind() != SecurityDecisionReplay {
		t.Fatalf("denial replay decision=%s error=%v", replayDecision.Kind(), err)
	}
	if err := ValidateSecurityDecision(replayContext, replayDecision); err != nil {
		t.Fatalf("valid replay decision rejected: %v", err)
	}
}

func TestSecuritySpecificationVariantsAreClosed(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	generation, _ := NewGuardGeneration(1)
	initialization, err := InitializeInstallationSecurity(
		fixture.scope, fixture.authority, fixture.epoch, generation,
		fixture.invitation, DigestBytes([]byte("database initialization guard")),
	)
	if err != nil || initialization.Operation() != SecurityInitializeInstallation {
		t.Fatalf("initialization spec=%s error=%v", initialization.Operation(), err)
	}
	oldGeneration := fixture.invitation.BootstrapGenerationID()
	newGeneration, _ := domain.ParseBootstrapGenerationID(applicationUUID(140))
	rotation, err := RotateBootstrapGenerationSecurity(
		fixture.scope, fixture.authority, fixture.epoch, generation, oldGeneration, newGeneration,
	)
	if err != nil || rotation.Operation() != SecurityRotateBootstrapGeneration {
		t.Fatalf("rotation spec=%s error=%v", rotation.Operation(), err)
	}
	expectation, _ := domain.ExpectAggregateVersion(fixture.invitation.ID(), fixture.invitation.Version())
	resume, err := ResumeBootstrapGenerationSecurity(
		fixture.scope, fixture.authority, fixture.epoch, generation, expectation,
		oldGeneration, newGeneration, domain.FingerprintCommand([]byte("verified human resume approval")),
	)
	if err != nil || resume.Operation() != SecurityResumeBootstrapGeneration {
		t.Fatalf("resume spec=%s error=%v", resume.Operation(), err)
	}
	if initialization.RequiresReservedAdmission() || rotation.RequiresReservedAdmission() || resume.RequiresReservedAdmission() {
		t.Fatal("non-denial security operations used denial reserved lane")
	}
}

func TestProductionCanonicalFingerprintsAreDerivedAndMutationSensitive(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)

	baselineEvidence, err := NewAppliedGuardEvidence(fixture.spec.Guards(), fixture.spec.Guards().Evidence())
	if err != nil {
		t.Fatal(err)
	}
	changedPlan := fixture.spec.Guards()
	changedPlan.admissionGeneration, _ = NewGuardGeneration(changedPlan.admissionGeneration.Uint64() + 1)
	changedEvidence, err := NewAppliedGuardEvidence(changedPlan, changedPlan.Evidence())
	if err != nil {
		t.Fatal(err)
	}
	if baselineEvidence.Digest() == changedEvidence.Digest() {
		t.Fatal("admission generation mutation did not change authorization digest")
	}

	major, _ := NewOperationMajor(1)
	subject, _ := UnattributedDenialSource(DigestBytes([]byte("canonical source")))
	baselineDraft, err := NewCommandDenialDraft(
		fixture.spec.Operation(), major, DenialAuthentication, "credential_rejected",
		fixture.spec.RequestFingerprint(), subject, nil, fixture.correlation,
	)
	if err != nil {
		t.Fatal(err)
	}
	baselineSpec, err := RecordCommandDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch,
		fixture.spec.Guards().AdmissionGeneration(), baselineDraft,
	)
	if err != nil {
		t.Fatal(err)
	}
	changedDraft := baselineDraft
	changedDraft.reason = "credential_stale"
	changedSpec, err := RecordCommandDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch,
		fixture.spec.Guards().AdmissionGeneration(), changedDraft,
	)
	if err != nil {
		t.Fatal(err)
	}
	baselineDenial, _ := baselineSpec.CommandDenial()
	changedDenial, _ := changedSpec.CommandDenial()
	if baselineDenial.DenialFingerprint() == changedDenial.DenialFingerprint() {
		t.Fatal("safe denial reason mutation did not change denial fingerprint")
	}
	forgedDraft := baselineDraft
	forgedDraft.denialFingerprint = DigestBytes([]byte("caller supplied denial fingerprint"))
	if _, err = RecordCommandDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch,
		fixture.spec.Guards().AdmissionGeneration(), forgedDraft,
	); !errors.Is(err, ErrInvalidSecuritySpec) {
		t.Fatalf("accepted caller-supplied denial fingerprint: %v", err)
	}

	proof := fixture.input.Proof
	changedAttempt, err := NewBootstrapAttempt(
		fixture.invitation.ID(), proof.TranscriptFingerprint(), proof.ClientNonceDigest(),
		proof.ServerNonceDigest(), domain.FingerprintCommand([]byte("different channel binding")),
		domain.FingerprintCommand([]byte("presented bootstrap proof")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.attempt.Fingerprint() == changedAttempt.Fingerprint() {
		t.Fatal("channel-binding mutation did not change bootstrap attempt fingerprint")
	}
	otherInvitation, _ := domain.ParseInvitationID(applicationUUID(141))
	wrongInvitationAttempt, err := NewBootstrapAttempt(
		otherInvitation, proof.TranscriptFingerprint(), proof.ClientNonceDigest(), proof.ServerNonceDigest(),
		domain.FingerprintCommand([]byte("bootstrap channel binding")),
		domain.FingerprintCommand([]byte("presented bootstrap proof")),
	)
	if err != nil {
		t.Fatal(err)
	}
	expectation, _ := domain.ExpectAggregateVersion(fixture.invitation.ID(), fixture.invitation.Version())
	if _, err = RecordBootstrapDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch,
		fixture.spec.Guards().AdmissionGeneration(), expectation, wrongInvitationAttempt,
	); !errors.Is(err, ErrInvalidSecuritySpec) {
		t.Fatalf("accepted bootstrap fingerprint for another invitation: %v", err)
	}
}

func TestOrdinaryDenialAuditIsSeparateBoundedAndFailClosed(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	major, _ := NewOperationMajor(1)
	subject, _ := UnattributedDenialSource(DigestBytes([]byte("keyed channel source")))
	draft, err := NewCommandDenialDraft(
		fixture.spec.Operation(), major, DenialAuthentication, "credential_rejected",
		fixture.spec.RequestFingerprint(), subject, nil, fixture.correlation,
	)
	if err != nil {
		t.Fatal(err)
	}
	denialSpec, err := RecordCommandDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch,
		fixture.spec.Guards().AdmissionGeneration(), draft,
	)
	if err != nil {
		t.Fatal(err)
	}
	denialSpec = testSecurityAuditContext(t, denialSpec, fixture)
	if !denialSpec.RequiresReservedAdmission() {
		t.Fatal("ordinary denial did not require reserved security admission")
	}
	admission, err := NewDenialAdmission(DenialAdmitDistinct, fixture.now, 19, 999)
	if err != nil {
		t.Fatal(err)
	}
	securityContext, err := NewSecurityContext(
		denialSpec, fixture.now, domain.InstallationInvitationState{},
		SecurityAttemptResolution{}, admission, fixture.context.GuardEvidence().Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	deniedDetail, _ := SecurityDeniedAuditDetail("credential_rejected")
	audit, _ := NewAuditIntent(
		fixture.spec.Operation(), AuditSecurityDenied, fixture.spec.RequestFingerprint(),
		deniedDetail,
	)
	auditDecision, err := AuditCommandDenialSecurity(securityContext, audit)
	if err != nil {
		t.Fatal(err)
	}
	auditRecord, ok := auditDecision.CommandDenialAudit()
	if !ok || auditRecord.Variant() != CommandDenialAuditDetail ||
		auditRecord.MinuteBucket() != fixture.now.Unix()/60 {
		t.Fatal("denial detail audit was not structurally typed")
	}
	rejection, _ := domain.NewCommandError(domain.ErrorCodeUnauthenticated, "authentication failed", nil)
	if _, err = RollbackCommand(fixture.context, rejection); !errors.Is(err, ErrInvalidCommandDecision) {
		t.Fatalf("authentication rejection without required audit error=%v", err)
	}
	decision, err := RollbackCommandWithSecurityAudit(fixture.context, rejection, denialSpec)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decision.DenialAudit(); !ok {
		t.Fatal("rollback did not retain mandatory denial audit")
	}
	wrongProvenance := denialSpec
	wrongProvenance.epoch, _ = domain.ParseAuthorityEpoch(applicationUUID(610))
	if _, err = RollbackCommandWithSecurityAudit(
		fixture.context, rejection, wrongProvenance,
	); !errors.Is(err, ErrInvalidCommandDecision) {
		t.Fatalf("mismatched denial provenance error=%v", err)
	}

	for _, test := range []struct {
		kind         DenialAdmissionKind
		distinct     uint8
		scopeEntries uint16
		writes       bool
	}{
		{DenialAdmitSaturation, 20, 999, true},
		{DenialAdmitScopeSaturation, 0, 1000, true},
		{DenialSuppressDuplicate, 1, 1, false},
		{DenialSuppressSaturated, 20, 1, false},
		{DenialSuppressScopeSaturated, 0, 1000, false},
	} {
		admission, admissionErr := NewDenialAdmission(test.kind, fixture.now, test.distinct, test.scopeEntries)
		if admissionErr != nil {
			t.Errorf("%s admission: %v", test.kind, admissionErr)
			continue
		}
		commandContext, contextErr := NewSecurityContext(
			denialSpec, fixture.now, domain.InstallationInvitationState{},
			SecurityAttemptResolution{}, admission, fixture.context.GuardEvidence().Digest(),
		)
		if contextErr != nil {
			t.Errorf("%s context: %v", test.kind, contextErr)
			continue
		}
		if test.writes {
			_, contextErr = AuditCommandDenialSecurity(commandContext, audit)
		} else {
			_, contextErr = SuppressCommandDenialSecurity(commandContext)
		}
		if contextErr != nil {
			t.Errorf("%s decision: %v", test.kind, contextErr)
		}
	}
	if _, err = NewDenialAdmission(DenialAdmitDistinct, fixture.now, 0, 1000); !errors.Is(err, ErrInvalidSecurityContext) {
		t.Fatalf("detail beyond scope ceiling error=%v", err)
	}
}

func TestReplayTimeIsStructurallyReadOnly(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	first, _ := domain.NewStreamPosition(1)
	last, _ := domain.NewStreamPosition(3)
	events, _ := NewEventRange(first, last, 3)
	draft := mustCapsuleDraft(
		t, fixture.resultRecord, fixture.command, fixture.spec.OperationMajor(),
		fixture.spec.RecoveryCapsule().KeyID(),
	)
	receipt, _ := NewReceiptSnapshot(ReceiptSnapshotParams{
		ReceiptID: fixture.receipt, CommandID: fixture.command, Identity: fixture.spec.ReceiptIdentity(),
		RequestFingerprint: fixture.spec.RequestFingerprint(), Result: fixture.resultRecord,
		AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		GuardDigest: fixture.context.GuardEvidence().Digest(), Events: events,
		EventCursor:        EventCursor{value: "bbec1_application_fixture"},
		CapsuleRequirement: RecoveryCapsuleRequired, RecoveryCapsule: draft,
	})
	replay, _ := ReplayReceipt(receipt)
	writeTime, _ := PersistedCommandAuthorityTime(fixture.now)
	if _, err := NewCommandContext(
		fixture.spec, writeTime, nil, replay, fixture.context.GuardEvidence(),
	); !errors.Is(err, ErrInvalidCommandContext) {
		t.Fatalf("replay accepted write time: %v", err)
	}
	readOnlyTime, _ := ReadOnlyDisclosureTime(fixture.now, fixture.now.Add(time.Minute))
	if got := readOnlyTime.Value(); !got.Equal(fixture.now.Add(time.Minute)) {
		t.Fatalf("disclosure time=%s", got)
	}
	if _, err := NewCommandContext(
		fixture.spec, readOnlyTime, []IdentityState{mustIdentityState(t, fixture.result.Invitation())},
		replay, fixture.context.GuardEvidence(),
	); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryCapsulePlanDraftSigningAndPendingOutcome(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	plan := fixture.spec.RecoveryCapsule()
	if plan.Requirement() != RecoveryCapsuleRequired || plan.KeyID() == "" {
		t.Fatal("retryable create lacks required prepared capsule signer")
	}
	draft := mustCapsuleDraft(
		t, fixture.resultRecord, fixture.command, fixture.spec.OperationMajor(), plan.KeyID(),
	)
	envelope, err := SignRecoveryCapsule(context.Background(), plan, fixture.capsuleSigner, *draft)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Schema() != RecoveryCapsuleEnvelopeSchema ||
		envelope.Algorithm() != "Ed25519" || envelope.SigningKeyID() != plan.KeyID() ||
		strings.Contains(envelope.SignatureBase64URL(), "=") || len(envelope.DigestHex()) != 64 {
		t.Fatalf("invalid signed capsule envelope")
	}
	if _, err = SignRecoveryCapsule(
		context.Background(), plan, invalidSignatureSigner{fixture.capsuleSigner}, *draft,
	); !errors.Is(err, ErrInvalidApplicationContract) {
		t.Fatalf("unverified signer result error=%v", err)
	}
	oversized := []byte(strings.Repeat("x", MaxRecoveryCapsuleBytes+1))
	if _, err = NewRecoveryCapsuleDraft(fixture.resultRecord, RecoveryCapsuleDocument{
		document:     canonicalDocument{canonical: oversized, digest: DigestBytes(oversized)},
		resultDigest: fixture.resultRecord.ResponseDigest(), signingKeyID: plan.KeyID(),
	}, plan.KeyID()); !errors.Is(err, ErrInvalidApplicationContract) {
		t.Fatalf("oversized capsule draft error=%v", err)
	}
	first, _ := domain.NewStreamPosition(1)
	last, _ := domain.NewStreamPosition(3)
	events, _ := NewEventRange(first, last, 3)
	receipt, _ := NewReceiptSnapshot(ReceiptSnapshotParams{
		ReceiptID: fixture.receipt, CommandID: fixture.command, Identity: fixture.spec.ReceiptIdentity(),
		RequestFingerprint: fixture.spec.RequestFingerprint(), Result: fixture.resultRecord,
		AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		GuardDigest: fixture.context.GuardEvidence().Digest(), Events: events,
		EventCursor:        EventCursor{value: "bbec1_application_fixture"},
		CapsuleRequirement: RecoveryCapsuleRequired, RecoveryCapsule: draft,
	})
	pending, err := CommittedCapsulePendingCommandExecution(receipt)
	if err != nil || pending.Kind() != CommandCommittedCapsulePending {
		t.Fatalf("pending execution=%s error=%v", pending.Kind(), err)
	}
	if _, err = AppliedCommandExecution(receipt, nil); !errors.Is(err, ErrInvalidCommandExecution) {
		t.Fatalf("required capsule bypass error=%v", err)
	}
	applied, err := AppliedCommandExecution(receipt, &envelope)
	if err != nil || applied.Kind() != CommandApplied {
		t.Fatalf("signed applied execution=%s error=%v", applied.Kind(), err)
	}
	if NotApplicableRecoveryCapsulePlan().Requirement() != RecoveryCapsuleNotApplicable {
		t.Fatal("not-applicable capsule variant not closed")
	}
	if _, err = NewReceiptSnapshot(ReceiptSnapshotParams{
		ReceiptID: fixture.receipt, CommandID: fixture.command, Identity: fixture.spec.ReceiptIdentity(),
		RequestFingerprint: fixture.spec.RequestFingerprint(), Result: fixture.resultRecord,
		AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		GuardDigest: fixture.context.GuardEvidence().Digest(), Events: events,
		EventCursor:        EventCursor{value: "bbec1_application_fixture"},
		CapsuleRequirement: RecoveryCapsuleNotApplicable, RecoveryCapsule: draft,
	}); !errors.Is(err, ErrInvalidApplicationContract) {
		t.Fatalf("not-applicable receipt accepted capsule: %v", err)
	}
}

type recordingUnitOfWork struct{ commits int }

func (unit *recordingUnitOfWork) ExecuteCommand(
	ctx context.Context,
	spec CommandSpec,
	decide func(CommandContext) (CommandDecision, error),
) (execution CommandTransactionExecution, err error) {
	_ = ctx
	_ = spec
	defer func() {
		if recovered := recover(); recovered != nil {
			execution = CommandTransactionExecution{}
			err = ErrInvalidCommandDecision
		}
	}()
	decision, err := decide(CommandContext{})
	if err != nil {
		return CommandTransactionExecution{}, err
	}
	if decision.kind != CommandDecisionApplied && decision.kind != CommandDecisionReplay &&
		decision.kind != CommandDecisionRollback {
		return CommandTransactionExecution{}, ErrInvalidCommandDecision
	}
	if decision.Kind() == CommandDecisionApplied {
		unit.commits++
	}
	return CommandTransactionExecution{}, nil
}

func (*recordingUnitOfWork) ExecuteSecurity(
	context.Context,
	SecuritySpec,
	func(SecurityContext) (SecurityDecision, error),
) (SecurityExecution, error) {
	return SecurityExecution{}, nil
}

func TestUnitOfWorkCallbackErrorAlwaysRequestsRollback(t *testing.T) {
	t.Parallel()
	var unit UnitOfWork = &recordingUnitOfWork{}
	rollback := errors.New("transition failed")
	_, err := unit.ExecuteCommand(context.Background(), CommandSpec{}, func(CommandContext) (CommandDecision, error) {
		return CommandDecision{}, rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("error = %v, want callback error", err)
	}
	if unit.(*recordingUnitOfWork).commits != 0 {
		t.Fatal("callback error committed")
	}
}

func TestUnitOfWorkRejectsZeroDecisionAndPanic(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		decide func(CommandContext) (CommandDecision, error)
	}{
		{name: "zero", decide: func(CommandContext) (CommandDecision, error) {
			return CommandDecision{}, nil
		}},
		{name: "panic", decide: func(CommandContext) (CommandDecision, error) {
			panic("boom")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			unit := &recordingUnitOfWork{}
			if _, err := unit.ExecuteCommand(context.Background(), CommandSpec{}, test.decide); !errors.Is(err, ErrInvalidCommandDecision) {
				t.Fatalf("decision error=%v", err)
			}
			if unit.commits != 0 {
				t.Fatal("invalid callback committed")
			}
		})
	}
}

func TestCommandTransactionExecutionErrorMatrixAndRetryIdentity(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	receipt := bootstrapReceipt(t, fixture)
	rejection, _ := domain.NewCommandError(domain.ErrorCodeInvalidArgument, "invalid", nil)
	committed, _ := CommittedCommandTransactionExecution(receipt)
	replayed, _ := ReplayedCommandTransactionExecution(receipt, ReplayDiscloseResult)
	rejected, _ := RejectedCommandTransactionExecution(rejection, SecuritySpec{})
	mandatoryDenial, _ := domain.NewCommandError(domain.ErrorCodeForbidden, "denied", nil)
	if _, err := RejectedCommandTransactionExecution(mandatoryDenial, SecuritySpec{}); !errors.Is(err, ErrInvalidCommandExecution) {
		t.Fatalf("mandatory denial without security follow-up error=%v", err)
	}
	mixedCommitted := committed
	mixedCommitted.rejection = rejection
	if err := ValidateCommandTransactionResult(mixedCommitted, nil); !errors.Is(err, ErrInvalidCommandExecution) {
		t.Fatalf("mixed committed/rejected union error=%v", err)
	}
	indeterminate, err := IndeterminateCommandTransactionExecution(fixture.spec)
	if err != nil {
		t.Fatal(err)
	}
	retry, ok := indeterminate.RetryIdentity()
	if !ok || retry.CommandID() != fixture.command || retry.ReceiptID() != fixture.receipt ||
		retry.ReceiptIdentity() != fixture.spec.ReceiptIdentity() ||
		retry.RequestFingerprint() != fixture.spec.RequestFingerprint() {
		t.Fatal("indeterminate outcome lost stable command retry identity")
	}
	final, err := IndeterminateCommandExecution(fixture.spec)
	finalRetry, finalHasRetry := final.RetryIdentity()
	if err != nil || !finalHasRetry || finalRetry != retry {
		t.Fatal("post-transaction indeterminate outcome lost stable command retry identity")
	}
	operational := errors.New("commit acknowledgement lost")
	tests := []struct {
		name      string
		execution CommandTransactionExecution
		err       error
		valid     bool
	}{
		{name: "pre-outcome failure", err: operational, valid: true},
		{name: "domain rejection through error", err: rejection},
		{name: "committed", execution: committed, valid: true},
		{name: "replayed", execution: replayed, valid: true},
		{name: "rejected", execution: rejected, valid: true},
		{name: "indeterminate", execution: indeterminate, valid: true},
		{name: "zero success"},
		{name: "committed with error", execution: committed, err: operational},
		{name: "replayed with error", execution: replayed, err: operational},
		{name: "rejected with error", execution: rejected, err: operational},
		{name: "indeterminate with error", execution: indeterminate, err: operational},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCommandTransactionResult(test.execution, test.err)
			if (err == nil) != test.valid {
				t.Fatalf("validation error=%v valid=%t", err, test.valid)
			}
		})
	}
}

func TestSecurityExecutionErrorMatrixRetainsOperation(t *testing.T) {
	t.Parallel()
	rejection, _ := domain.NewCommandError(domain.ErrorCodeForbidden, "denied", nil)
	applied, _ := AppliedSecurityExecution(SecurityRotateBootstrapGeneration)
	rejected, err := RejectedSecurityExecution(SecurityRecordCommandDenial, rejection)
	if err != nil || rejected.Operation() != SecurityRecordCommandDenial {
		t.Fatalf("rejected operation=%q error=%v", rejected.Operation(), err)
	}
	indeterminate, err := IndeterminateSecurityExecution(SecurityResumeBootstrapGeneration)
	if err != nil || indeterminate.Operation() != SecurityResumeBootstrapGeneration {
		t.Fatalf("indeterminate operation=%q error=%v", indeterminate.Operation(), err)
	}
	mixedApplied := applied
	mixedApplied.rejection = rejection
	if err := ValidateSecurityExecutionResult(mixedApplied, nil); !errors.Is(err, ErrInvalidSecurityExecution) {
		t.Fatalf("mixed applied/rejected security union error=%v", err)
	}
	operational := errors.New("commit acknowledgement lost")
	tests := []struct {
		name      string
		execution SecurityExecution
		err       error
		valid     bool
	}{
		{name: "pre-outcome failure", err: operational, valid: true},
		{name: "domain rejection through error", err: rejection},
		{name: "applied", execution: applied, valid: true},
		{name: "rejected", execution: rejected, valid: true},
		{name: "indeterminate", execution: indeterminate, valid: true},
		{name: "zero success"},
		{name: "applied with error", execution: applied, err: operational},
		{name: "rejected with error", execution: rejected, err: operational},
		{name: "indeterminate with error", execution: indeterminate, err: operational},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSecurityExecutionResult(test.execution, test.err)
			if (err == nil) != test.valid {
				t.Fatalf("validation error=%v valid=%t", err, test.valid)
			}
		})
	}
}

func TestValidProofRejectsNilAndZeroEvidence(t *testing.T) {
	t.Parallel()
	if decision := ValidProof[*int](nil); decision.Kind() == ProofValid {
		t.Fatal("nil proof evidence accepted")
	}
	if decision := ValidProof(0); decision.Kind() == ProofValid {
		t.Fatal("zero proof evidence accepted")
	}
	value := 1
	if decision := ValidProof(&value); decision.Kind() != ProofValid {
		t.Fatal("non-zero proof evidence rejected")
	}
}

type operationDomainPath struct {
	now              time.Time
	installation     domain.InstallationID
	authority        domain.AuthorityID
	epoch            domain.AuthorityEpoch
	policy           domain.PolicyRevision
	assurance        domain.AssuranceClass
	ownerCaps        domain.CapabilitySet
	memberCaps       domain.CapabilitySet
	bootstrap        domain.BootstrapInstallationResult
	registered       domain.RegisterPrincipalResult
	createdWorkspace domain.CreateWorkspaceResult
	invited          domain.InviteWorkspaceMemberResult
	accepted         domain.AcceptWorkspaceMembershipResult
	createdActor     domain.CreateActorResult
	proposed         domain.ProposeActorDelegationResult
	activated        domain.ActivateActorDelegationResult
	pairingBegan     domain.BeginDevicePairingResult
	paired           domain.PairDeviceResult
	sessionStarted   domain.StartActorSessionResult
}

func buildOperationDomainPath(t *testing.T) operationDomainPath {
	t.Helper()
	fixture := buildBootstrapFixture(t)
	now := fixture.now.Add(5 * time.Minute)
	installation, _, _, _, _, _, _ := mustParseIDs(t)
	policy, _ := domain.NewPolicyRevision("policy:matrix:v1")
	assurance, _ := domain.NewAssuranceClass("matrix-strong")
	ownerCaps := fixture.result.OwnerGrant().Capabilities()
	memberCaps, _ := domain.NewCapabilitySet(domain.WorkspaceOwnerCapability())
	workspaceOwnerCaps, _ := domain.NewCapabilitySet(
		domain.WorkspaceOwnerCapability(), domain.MembershipAdminCapability(),
		domain.ActorAdminCapability(), domain.DelegationAdminCapability(),
		domain.DevicePairCapability(),
	)
	ownerAuth, err := domain.NewIdentityAuthorization(
		fixture.authority, fixture.epoch, installation, fixture.result.Principal().ID(), ownerCaps,
		policy, assurance, now, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	workloadID, _ := domain.ParsePrincipalID(applicationUUID(201))
	workloadName, _ := domain.NewDisplayName("Matrix workload")
	workloadKey, _ := domain.NewPublicKeyReference("keyref:matrix-workload")
	registered, err := domain.RegisterPrincipal(domain.RegisterPrincipalInput{
		Authorization: ownerAuth, Registrar: fixture.result.Principal(),
		ExpectedRegistrarVersion: fixture.result.Principal().Version(), PrincipalID: workloadID,
		Kind: domain.PrincipalKindWorkload, DisplayName: workloadName, PublicKeyReference: workloadKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := domain.ParseWorkspaceID(applicationUUID(202))
	ownerMembershipID, _ := domain.ParseMembershipID(applicationUUID(203))
	alias, _ := domain.NewWorkspaceAlias("matrix-workspace")
	discovery, _ := domain.NewDiscoveryLocator("workspace://matrix")
	createdWorkspace, err := domain.CreateWorkspace(domain.CreateWorkspaceInput{
		Authorization: ownerAuth, Owner: fixture.result.Principal(),
		ExpectedOwnerVersion: fixture.result.Principal().Version(),
		InstallationGrant:    fixture.result.OwnerGrant(), ExpectedGrantVersion: fixture.result.OwnerGrant().Version(),
		WorkspaceID: workspaceID, Alias: alias, DiscoveryLocator: discovery,
		OwnerMembershipID: ownerMembershipID, OwnerCapabilities: workspaceOwnerCaps,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerWorkspaceAuth, err := domain.NewWorkspaceIdentityAuthorization(
		fixture.authority, fixture.epoch, installation, workspaceID, fixture.result.Principal().ID(),
		ownerCaps, policy, assurance, now, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	membershipID, _ := domain.ParseMembershipID(applicationUUID(204))
	membershipCeremonyID, _ := domain.ParseCeremonyID(applicationUUID(205))
	membershipProofDigest := domain.FingerprintCommand([]byte("matrix membership proof"))
	membershipChallenge, _ := domain.NewMembershipAcceptanceChallenge(
		membershipCeremonyID, membershipProofDigest, now.Add(time.Hour), workspaceID, membershipID, workloadID,
	)
	membershipCreation, _ := domain.ExpectCeremonyAbsent(membershipCeremonyID)
	invited, err := domain.InviteWorkspaceMember(domain.InviteWorkspaceMemberInput{
		Authorization: ownerWorkspaceAuth, Administrator: fixture.result.Principal(),
		ExpectedAdministratorVersion: fixture.result.Principal().Version(),
		Workspace:                    createdWorkspace.Workspace(), ExpectedWorkspaceVersion: createdWorkspace.Workspace().Version(),
		Principal: registered.Principal(), ExpectedPrincipalVersion: registered.Principal().Version(),
		MembershipID: membershipID, Capabilities: memberCaps, Challenge: membershipChallenge,
		ChallengeCreation: membershipCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	workloadAuth, err := domain.NewWorkspaceIdentityAuthorization(
		fixture.authority, fixture.epoch, installation, workspaceID, workloadID, memberCaps,
		policy, assurance, now, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	membershipProof, _ := domain.NewCeremonyProof(
		membershipCeremonyID, domain.CeremonyPurposeMembershipAcceptance,
		membershipProofDigest, workloadID, domain.DeviceID{},
	)
	accepted, err := domain.AcceptWorkspaceMembership(domain.AcceptWorkspaceMembershipInput{
		Authorization: workloadAuth, Workspace: createdWorkspace.Workspace(),
		ExpectedWorkspaceVersion: createdWorkspace.Workspace().Version(), Principal: registered.Principal(),
		ExpectedPrincipalVersion: registered.Principal().Version(), Membership: invited.Membership(),
		ExpectedMembershipVersion: invited.Membership().Version(), Proof: membershipProof,
	})
	if err != nil {
		t.Fatal(err)
	}
	actorID, _ := domain.ParseActorID(applicationUUID(206))
	actorName, _ := domain.NewDisplayName("Matrix agent")
	actorProfile, _ := domain.NewActorProfile(actorName)
	createdActor, err := domain.CreateActor(domain.CreateActorInput{
		Authorization: ownerWorkspaceAuth, Administrator: fixture.result.Principal(),
		ExpectedAdministratorVersion: fixture.result.Principal().Version(),
		Workspace:                    createdWorkspace.Workspace(), ExpectedWorkspaceVersion: createdWorkspace.Workspace().Version(),
		ActorID: actorID, Kind: domain.ActorKindAgent, Profile: actorProfile,
	})
	if err != nil {
		t.Fatal(err)
	}
	delegationID, _ := domain.ParseActorDelegationID(applicationUUID(207))
	delegationCeremonyID, _ := domain.ParseCeremonyID(applicationUUID(208))
	delegationProofDigest := domain.FingerprintCommand([]byte("matrix delegation proof"))
	delegationChallenge, _ := domain.NewDelegationActivationChallenge(
		delegationCeremonyID, delegationProofDigest, now.Add(time.Hour), workspaceID,
		delegationID, workloadID, actorID,
	)
	delegationCreation, _ := domain.ExpectCeremonyAbsent(delegationCeremonyID)
	delegationCaps, _ := domain.NewCapabilitySet(domain.WorkspaceOwnerCapability())
	proposed, err := domain.ProposeActorDelegation(domain.ProposeActorDelegationInput{
		Authorization: ownerWorkspaceAuth, Administrator: fixture.result.Principal(),
		ExpectedAdministratorVersion: fixture.result.Principal().Version(),
		Workspace:                    createdWorkspace.Workspace(), ExpectedWorkspaceVersion: createdWorkspace.Workspace().Version(),
		Principal: registered.Principal(), ExpectedPrincipalVersion: registered.Principal().Version(),
		Actor: createdActor.Actor(), ExpectedActorVersion: createdActor.Actor().Version(),
		Membership: accepted.Membership(), ExpectedMembershipVersion: accepted.Membership().Version(),
		DelegationID: delegationID, Capabilities: delegationCaps, Challenge: delegationChallenge,
		ChallengeCreation: delegationCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	delegationProof, _ := domain.NewCeremonyProof(
		delegationCeremonyID, domain.CeremonyPurposeDelegationActivation,
		delegationProofDigest, workloadID, domain.DeviceID{},
	)
	sessionCeremonyID, _ := domain.ParseCeremonyID(applicationUUID(209))
	sessionProofDigest := domain.FingerprintCommand([]byte("matrix session proof"))
	sessionChallenge, _ := domain.NewSessionStartChallenge(
		sessionCeremonyID, sessionProofDigest, now.Add(time.Hour), workspaceID,
		delegationID, workloadID, actorID,
	)
	sessionCreation, _ := domain.ExpectCeremonyAbsent(sessionCeremonyID)
	activated, err := domain.ActivateActorDelegation(domain.ActivateActorDelegationInput{
		Authorization: workloadAuth, Workspace: createdWorkspace.Workspace(),
		ExpectedWorkspaceVersion: createdWorkspace.Workspace().Version(), Principal: registered.Principal(),
		ExpectedPrincipalVersion: registered.Principal().Version(), Actor: createdActor.Actor(),
		ExpectedActorVersion: createdActor.Actor().Version(), Membership: accepted.Membership(),
		ExpectedMembershipVersion: accepted.Membership().Version(), Delegation: proposed.Delegation(),
		ExpectedDelegationVersion: proposed.Delegation().Version(), Proof: delegationProof,
		SessionStartChallenge: sessionChallenge, SessionChallengeCreation: sessionCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	pairingDeviceID, _ := domain.ParseDeviceID(applicationUUID(210))
	pairingCeremonyID, _ := domain.ParseCeremonyID(applicationUUID(211))
	pairingProofDigest := domain.FingerprintCommand([]byte("matrix pairing proof"))
	pairingChallenge, _ := domain.NewDevicePairingChallenge(
		pairingCeremonyID, pairingProofDigest, now.Add(time.Hour), installation,
		fixture.result.Principal().ID(), pairingDeviceID,
	)
	pairingCreation, _ := domain.ExpectCeremonyAbsent(pairingCeremonyID)
	pairingName, _ := domain.NewDisplayName("Matrix paired device")
	pairingKey, _ := domain.NewPublicKeyReference("keyref:matrix-paired-device")
	pairingBegan, err := domain.BeginDevicePairing(domain.BeginDevicePairingInput{
		Authorization: ownerAuth, Principal: fixture.result.Principal(),
		ExpectedPrincipalVersion: fixture.result.Principal().Version(), DeviceID: pairingDeviceID,
		DisplayName: pairingName, PublicKeyReference: pairingKey, Challenge: pairingChallenge,
		ChallengeCreation: pairingCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	pairingProof, _ := domain.NewCeremonyProof(
		pairingCeremonyID, domain.CeremonyPurposeDevicePairing,
		pairingProofDigest, fixture.result.Principal().ID(), pairingDeviceID,
	)
	spki, _ := domain.NewCredentialDigest([32]byte(domain.FingerprintCommand([]byte("matrix pairing spki"))))
	credential, _ := domain.NewDeviceCredentialBinding(pairingKey, spki, pairingProofDigest)
	pairingAuth, err := domain.NewPairingRedemptionAuthorization(
		fixture.authority, fixture.epoch, installation, fixture.result.Principal().ID(), pairingDeviceID,
		policy, assurance, now, pairingCeremonyID, pairingProofDigest, credential,
	)
	if err != nil {
		t.Fatal(err)
	}
	paired, err := domain.PairDevice(domain.PairDeviceInput{
		Authorization: pairingAuth, CurrentAuthorization: ownerAuth, AuthorityTime: now,
		Principal:                fixture.result.Principal(),
		ExpectedPrincipalVersion: fixture.result.Principal().Version(), Device: pairingBegan.Device(),
		ExpectedDeviceVersion: pairingBegan.Device().Version(),
		ExpectedTrustRevision: pairingBegan.Device().TrustRevision(), Proof: pairingProof,
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionProof, _ := domain.NewCeremonyProof(
		sessionCeremonyID, domain.CeremonyPurposeActorSessionStart,
		sessionProofDigest, workloadID, domain.DeviceID{},
	)
	handoff, _ := domain.HandoffSessionStart(sessionChallenge, sessionProof)
	sessionID, _ := domain.ParseActorSessionID(applicationUUID(212))
	clientID, _ := domain.ParseClientInstanceID(applicationUUID(213))
	clientMetadata, _ := domain.NewClientMetadata("matrix-agent", "1.0.0")
	credentialReference, _ := domain.NewCredentialReference("credential-ref:matrix-session")
	credentialAudience, _ := domain.NewCredentialAudience("blackbird:matrix")
	presentationDigest, _ := domain.NewCredentialDigest([32]byte(domain.FingerprintCommand([]byte("matrix presentation"))))
	presentation, _ := domain.NewPresentationCredentialBinding(
		presentationDigest, credentialReference, credentialAudience, domain.PresentationCredentialVersion,
	)
	sessionStarted, err := domain.StartActorSession(domain.StartActorSessionInput{
		Authorization: workloadAuth, SessionID: sessionID, ClientInstanceID: clientID,
		ClientMetadata: clientMetadata, Workspace: createdWorkspace.Workspace(),
		ExpectedWorkspaceVersion: createdWorkspace.Workspace().Version(), Principal: registered.Principal(),
		ExpectedPrincipalVersion: registered.Principal().Version(), Membership: accepted.Membership(),
		ExpectedMembershipVersion: accepted.Membership().Version(), Actor: createdActor.Actor(),
		ExpectedActorVersion: createdActor.Actor().Version(), Delegation: activated.Delegation(),
		ExpectedDelegationVersion: activated.Delegation().Version(), StartAuthority: handoff,
		AbsoluteExpiry: now.Add(8 * time.Hour), PresentationCredential: presentation,
	})
	if err != nil {
		t.Fatal(err)
	}
	return operationDomainPath{
		now: now, installation: installation, authority: fixture.authority, epoch: fixture.epoch,
		policy: policy, assurance: assurance, ownerCaps: ownerCaps, memberCaps: memberCaps,
		bootstrap: fixture.result, registered: registered, createdWorkspace: createdWorkspace,
		invited: invited, accepted: accepted, createdActor: createdActor, proposed: proposed,
		activated: activated, pairingBegan: pairingBegan, paired: paired, sessionStarted: sessionStarted,
	}
}

type operationPipelineCase struct {
	operation     CommandOperation
	scope         domain.AuthorityScope
	admission     domain.AuthorityScope
	principal     domain.PrincipalID
	authorship    CommandAuthorship
	authorization []IdentityState
	references    []IdentityState
	mutatedPrior  []IdentityState
	disclosure    []domain.AggregateTarget
	mutations     []domain.AggregateExpectation
	ceremonies    []CeremonyClaim
	standalone    []domain.CeremonyChallenge
	genesis       *ScopeGenesisAbsence
	evidence      []EvidenceGuard
	facts         []domain.IdentityFact
	commit        func(CommandContext) (OperationCommit, error)
}

func mustStateRef(t *testing.T, value any) domain.AggregateRef {
	t.Helper()
	ref, err := identityStateRef(mustIdentityState(t, value))
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func mustTarget(t *testing.T, value any) domain.AggregateTarget {
	t.Helper()
	target := mustIdentityState(t, value).Target()
	if target.IsZero() {
		t.Fatal("zero aggregate target")
	}
	return target
}

func mustAbsentTarget(t *testing.T, id any) domain.AggregateExpectation {
	t.Helper()
	var (
		expectation domain.AggregateExpectation
		err         error
	)
	switch value := id.(type) {
	case domain.WorkspaceID:
		expectation, err = domain.ExpectAggregateAbsent(value)
	case domain.PrincipalID:
		expectation, err = domain.ExpectAggregateAbsent(value)
	case domain.DeviceID:
		expectation, err = domain.ExpectAggregateAbsent(value)
	case domain.MembershipID:
		expectation, err = domain.ExpectAggregateAbsent(value)
	case domain.ActorID:
		expectation, err = domain.ExpectAggregateAbsent(value)
	case domain.ActorDelegationID:
		expectation, err = domain.ExpectAggregateAbsent(value)
	case domain.ActorSessionID:
		expectation, err = domain.ExpectAggregateAbsent(value)
	default:
		t.Fatalf("unsupported absent target %T", id)
	}
	if err != nil {
		t.Fatal(err)
	}
	return expectation
}

func mustExpectedState(t *testing.T, value any) domain.AggregateExpectation {
	t.Helper()
	var (
		expectation domain.AggregateExpectation
		err         error
	)
	switch state := value.(type) {
	case domain.MembershipState:
		expectation, err = domain.ExpectAggregateVersion(state.ID(), state.Version())
	case domain.ActorDelegationState:
		expectation, err = domain.ExpectAggregateVersion(state.ID(), state.Version())
	case domain.DeviceState:
		expectation, err = domain.ExpectAggregateVersion(state.ID(), state.Version())
	default:
		t.Fatalf("unsupported expected-version state %T", value)
	}
	if err != nil {
		t.Fatal(err)
	}
	return expectation
}

func mustLifecycle(t *testing.T, value any) EvidenceGuard {
	t.Helper()
	state := mustIdentityState(t, value)
	guard, err := LifecycleStatusGuard(state.Target(), identityStateStatus(state))
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func mustCeiling(t *testing.T, value any, label string) EvidenceGuard {
	t.Helper()
	guard, err := CapabilityCeilingGuard(mustTarget(t, value), DigestBytes([]byte("ceiling:"+label)))
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func mustConstraint(t *testing.T, target domain.AggregateTarget, label string) EvidenceGuard {
	t.Helper()
	guard, err := ResourceConstraintGuard(target, DigestBytes([]byte("constraint:"+label)))
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func mustReserve(t *testing.T, challenge domain.CeremonyChallenge, owner domain.AggregateTarget) CeremonyClaim {
	t.Helper()
	claim, err := ReserveCeremony(challenge, owner)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func mustConsumeEmbedded(t *testing.T, challenge domain.CeremonyChallenge, owner any) CeremonyClaim {
	t.Helper()
	claim, err := ConsumeEmbeddedCeremony(
		challenge.ID(), challenge.Purpose(), challenge.ProofDigest(), mustStateRef(t, owner),
	)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func buildOperationPipelineCases(t *testing.T, path operationDomainPath) []operationPipelineCase {
	t.Helper()
	installationScope, _ := domain.InstallationScope(path.installation)
	workspaceScope, _ := domain.WorkspaceScope(path.createdWorkspace.Workspace().ID())
	authorityAtInstall, _ := CurrentAuthorityEpochGuard(installationScope, path.authority, path.epoch)
	policyAtInstall, _ := PolicyRevisionGuard(installationScope, path.policy)
	authorityAtWorkspace, _ := CurrentAuthorityEpochGuard(workspaceScope, path.authority, path.epoch)
	policyAtWorkspace, _ := PolicyRevisionGuard(workspaceScope, path.policy)
	owner := path.bootstrap.Principal()
	grant := path.bootstrap.OwnerGrant()
	workspace := path.createdWorkspace.Workspace()
	ownerMembership := path.createdWorkspace.OwnerMembership()
	workload := path.registered.Principal()
	invited := path.invited.Membership()
	member := path.accepted.Membership()
	actor := path.createdActor.Actor()
	proposed := path.proposed.Delegation()
	activated := path.activated.Delegation()
	pendingDevice := path.pairingBegan.Device()
	ownerAuthorship, _ := AuthorityAuthorship(owner.ID())
	ownerAdminAuthorship, _ := WorkspaceAdminAuthorship(owner.ID(), nil)
	workloadAuthorship, _ := AuthorityAuthorship(workload.ID())
	newWorkspaceID := workspace.ID()
	newMembershipID := invited.ID()
	newActorID := actor.ID()
	newDelegationID := proposed.ID()
	newDeviceID := pendingDevice.ID()
	newSessionID := path.sessionStarted.Session().ID()
	genesis, _ := AbsentScopeGenesis(workspaceScope, path.authority, path.epoch)
	invitationChallenge := invited.AcceptanceChallenge()
	delegationChallenge := proposed.ActivationChallenge()
	sessionChallenge := path.activated.SessionStartChallenge()
	pairingChallenge := pendingDevice.PairingChallenge()
	standaloneClaim, _ := ConsumeStandaloneCeremony(
		sessionChallenge.ID(), sessionChallenge.Purpose(), sessionChallenge.ProofDigest(),
	)
	pairTrust, _ := DeviceTrustRevisionGuard(pendingDevice.ID(), pendingDevice.TrustRevision())
	return []operationPipelineCase{
		{
			operation: CommandRegisterPrincipal, scope: installationScope, admission: installationScope,
			principal: owner.ID(), authorship: ownerAuthorship,
			authorization: []IdentityState{mustIdentityState(t, owner), mustIdentityState(t, grant)},
			disclosure:    []domain.AggregateTarget{mustTarget(t, owner), mustTarget(t, workload)},
			mutations:     []domain.AggregateExpectation{mustAbsentTarget(t, workload.ID())},
			evidence:      []EvidenceGuard{authorityAtInstall, policyAtInstall, mustLifecycle(t, owner), mustLifecycle(t, grant), mustCeiling(t, grant, "register")},
			facts:         path.registered.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return RegisterPrincipalCommit(context, path.registered)
			},
		},
		{
			operation: CommandCreateWorkspace, scope: workspaceScope, admission: installationScope,
			principal: owner.ID(), authorship: ownerAuthorship,
			authorization: []IdentityState{mustIdentityState(t, owner), mustIdentityState(t, grant)},
			disclosure:    []domain.AggregateTarget{mustTarget(t, owner), mustTarget(t, workspace)},
			mutations: []domain.AggregateExpectation{
				mustAbsentTarget(t, newWorkspaceID), mustAbsentTarget(t, ownerMembership.ID()),
			},
			genesis:  &genesis,
			evidence: []EvidenceGuard{authorityAtInstall, policyAtInstall, mustLifecycle(t, owner), mustLifecycle(t, grant), mustCeiling(t, grant, "workspace")},
			facts:    path.createdWorkspace.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return CreateWorkspaceCommit(context, path.createdWorkspace)
			},
		},
		{
			operation: CommandInviteWorkspaceMember, scope: workspaceScope, admission: workspaceScope,
			principal: owner.ID(), authorship: ownerAdminAuthorship,
			authorization: []IdentityState{mustIdentityState(t, owner), mustIdentityState(t, workspace)},
			references:    []IdentityState{mustIdentityState(t, workload)},
			disclosure:    []domain.AggregateTarget{mustTarget(t, owner), mustTarget(t, workspace), mustTarget(t, invited)},
			mutations:     []domain.AggregateExpectation{mustAbsentTarget(t, newMembershipID)},
			ceremonies:    []CeremonyClaim{mustReserve(t, invitationChallenge, mustTarget(t, invited))},
			evidence:      []EvidenceGuard{authorityAtWorkspace, policyAtWorkspace, mustLifecycle(t, owner), mustLifecycle(t, workspace), mustLifecycle(t, workload), mustCeiling(t, owner, "invite")},
			facts:         path.invited.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return InviteWorkspaceMemberCommit(context, path.invited)
			},
		},
		{
			operation: CommandAcceptWorkspaceMembership, scope: workspaceScope, admission: workspaceScope,
			principal: workload.ID(), authorship: workloadAuthorship,
			authorization: []IdentityState{mustIdentityState(t, workload)},
			references:    []IdentityState{mustIdentityState(t, workspace)}, mutatedPrior: []IdentityState{mustIdentityState(t, invited)},
			disclosure: []domain.AggregateTarget{mustTarget(t, workload), mustTarget(t, workspace), mustTarget(t, invited)},
			mutations:  []domain.AggregateExpectation{mustExpectedState(t, invited)},
			ceremonies: []CeremonyClaim{mustConsumeEmbedded(t, invitationChallenge, invited)},
			evidence:   []EvidenceGuard{authorityAtWorkspace, policyAtWorkspace, mustLifecycle(t, workload), mustLifecycle(t, workspace), mustLifecycle(t, invited)},
			facts:      path.accepted.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return AcceptWorkspaceMembershipCommit(context, path.accepted)
			},
		},
		{
			operation: CommandCreateActor, scope: workspaceScope, admission: workspaceScope,
			principal: owner.ID(), authorship: ownerAdminAuthorship,
			authorization: []IdentityState{mustIdentityState(t, owner), mustIdentityState(t, workspace)},
			disclosure:    []domain.AggregateTarget{mustTarget(t, owner), mustTarget(t, workspace), mustTarget(t, actor)},
			mutations:     []domain.AggregateExpectation{mustAbsentTarget(t, newActorID)},
			evidence:      []EvidenceGuard{authorityAtWorkspace, policyAtWorkspace, mustLifecycle(t, owner), mustLifecycle(t, workspace)},
			facts:         path.createdActor.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return CreateActorCommit(context, path.createdActor)
			},
		},
		{
			operation: CommandProposeActorDelegation, scope: workspaceScope, admission: workspaceScope,
			principal: owner.ID(), authorship: ownerAdminAuthorship,
			authorization: []IdentityState{mustIdentityState(t, owner), mustIdentityState(t, workspace)},
			references:    []IdentityState{mustIdentityState(t, workload), mustIdentityState(t, actor), mustIdentityState(t, member)},
			disclosure:    []domain.AggregateTarget{mustTarget(t, owner), mustTarget(t, workspace), mustTarget(t, proposed)},
			mutations:     []domain.AggregateExpectation{mustAbsentTarget(t, newDelegationID)},
			ceremonies:    []CeremonyClaim{mustReserve(t, delegationChallenge, mustTarget(t, proposed))},
			evidence:      []EvidenceGuard{authorityAtWorkspace, policyAtWorkspace, mustLifecycle(t, owner), mustLifecycle(t, workspace), mustLifecycle(t, workload), mustLifecycle(t, actor), mustLifecycle(t, member), mustCeiling(t, member, "delegation")},
			facts:         path.proposed.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return ProposeActorDelegationCommit(context, path.proposed)
			},
		},
		{
			operation: CommandActivateActorDelegation, scope: workspaceScope, admission: workspaceScope,
			principal: workload.ID(), authorship: workloadAuthorship,
			authorization: []IdentityState{mustIdentityState(t, workload)},
			references:    []IdentityState{mustIdentityState(t, workspace), mustIdentityState(t, actor), mustIdentityState(t, member)},
			mutatedPrior:  []IdentityState{mustIdentityState(t, proposed)},
			disclosure:    []domain.AggregateTarget{mustTarget(t, workload), mustTarget(t, workspace), mustTarget(t, proposed)},
			mutations:     []domain.AggregateExpectation{mustExpectedState(t, proposed)},
			ceremonies: []CeremonyClaim{
				mustConsumeEmbedded(t, delegationChallenge, proposed),
				mustReserve(t, sessionChallenge, mustTarget(t, proposed)),
			},
			evidence: []EvidenceGuard{authorityAtWorkspace, policyAtWorkspace, mustLifecycle(t, workload), mustLifecycle(t, workspace), mustLifecycle(t, actor), mustLifecycle(t, member), mustLifecycle(t, proposed), mustCeiling(t, member, "activation")},
			facts:    path.activated.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return ActivateActorDelegationCommit(context, path.activated)
			},
		},
		{
			operation: CommandBeginDevicePairing, scope: installationScope, admission: installationScope,
			principal: owner.ID(), authorship: ownerAuthorship,
			authorization: []IdentityState{mustIdentityState(t, owner), mustIdentityState(t, grant)},
			disclosure:    []domain.AggregateTarget{mustTarget(t, owner), mustTarget(t, pendingDevice)},
			mutations:     []domain.AggregateExpectation{mustAbsentTarget(t, newDeviceID)},
			ceremonies:    []CeremonyClaim{mustReserve(t, pairingChallenge, mustTarget(t, pendingDevice))},
			evidence:      []EvidenceGuard{authorityAtInstall, policyAtInstall, mustLifecycle(t, owner), mustLifecycle(t, grant), mustCeiling(t, grant, "pairing")},
			facts:         path.pairingBegan.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return BeginDevicePairingCommit(context, path.pairingBegan)
			},
		},
		{
			operation: CommandPairDevice, scope: installationScope, admission: installationScope,
			principal: owner.ID(), authorship: ownerAuthorship,
			authorization: []IdentityState{mustIdentityState(t, owner)},
			mutatedPrior:  []IdentityState{mustIdentityState(t, pendingDevice)},
			disclosure:    []domain.AggregateTarget{mustTarget(t, owner), mustTarget(t, pendingDevice)},
			mutations:     []domain.AggregateExpectation{mustExpectedState(t, pendingDevice)},
			ceremonies:    []CeremonyClaim{mustConsumeEmbedded(t, pairingChallenge, pendingDevice)},
			evidence:      []EvidenceGuard{authorityAtInstall, policyAtInstall, mustLifecycle(t, owner), mustLifecycle(t, pendingDevice), pairTrust},
			facts:         path.paired.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return PairDeviceCommit(context, path.paired)
			},
		},
		{
			operation: CommandStartActorSession, scope: workspaceScope, admission: workspaceScope,
			principal: workload.ID(), authorship: workloadAuthorship,
			authorization: []IdentityState{
				mustIdentityState(t, workload), mustIdentityState(t, workspace), mustIdentityState(t, member),
				mustIdentityState(t, actor), mustIdentityState(t, activated),
			},
			disclosure: []domain.AggregateTarget{mustTarget(t, workload), mustTarget(t, workspace), mustTarget(t, path.sessionStarted.Session())},
			mutations:  []domain.AggregateExpectation{mustAbsentTarget(t, newSessionID)},
			ceremonies: []CeremonyClaim{standaloneClaim}, standalone: []domain.CeremonyChallenge{sessionChallenge},
			evidence: []EvidenceGuard{
				authorityAtWorkspace, policyAtWorkspace, mustLifecycle(t, workload), mustLifecycle(t, workspace),
				mustLifecycle(t, member), mustLifecycle(t, actor), mustLifecycle(t, activated),
				mustCeiling(t, member, "session-membership"), mustCeiling(t, activated, "session-delegation"),
				mustConstraint(t, mustTarget(t, path.sessionStarted.Session()), "session"),
			},
			facts: path.sessionStarted.Facts(),
			commit: func(context CommandContext) (OperationCommit, error) {
				return StartActorSessionCommit(context, path.sessionStarted)
			},
		},
	}
}

type completedOperationPipeline struct {
	caseDefinition operationPipelineCase
	spec           CommandSpec
	context        CommandContext
	commit         OperationCommit
	decision       CommandDecision
	result         ResultEnvelope
	receipt        ReceiptSnapshot
}

func TestAllW0OperationsCompleteTheRealApplicationPipeline(t *testing.T) {
	path := buildOperationDomainPath(t)
	bootstrap := buildBootstrapFixture(t)
	t.Run(string(CommandBootstrapInstallation), func(t *testing.T) {
		events := mustEventRangeForFacts(t, len(bootstrap.result.Facts()))
		draft := mustCapsuleDraft(
			t, bootstrap.resultRecord, bootstrap.command, bootstrap.spec.OperationMajor(),
			bootstrap.spec.RecoveryCapsule().KeyID(),
		)
		receipt, err := NewReceiptSnapshot(ReceiptSnapshotParams{
			ReceiptID: bootstrap.receipt, CommandID: bootstrap.command,
			Identity: bootstrap.spec.ReceiptIdentity(), RequestFingerprint: bootstrap.spec.RequestFingerprint(),
			Result: bootstrap.resultRecord, AuthorityID: bootstrap.authority, AuthorityEpoch: bootstrap.epoch,
			GuardDigest: bootstrap.context.GuardEvidence().Digest(), Events: events,
			EventCursor:        EventCursor{value: "bbec1_application_fixture"},
			CapsuleRequirement: RecoveryCapsuleRequired, RecoveryCapsule: draft,
		})
		if err != nil || receipt.Result().ResponseDigest() != bootstrap.resultRecord.ResponseDigest() {
			t.Fatalf("bootstrap receipt pipeline failed: %v", err)
		}
	})

	cases := buildOperationPipelineCases(t, path)
	if len(cases) != len(operationContracts)-1 {
		t.Fatalf("non-bootstrap pipeline cases=%d, want=%d", len(cases), len(operationContracts)-1)
	}
	completed := make([]completedOperationPipeline, 0, len(cases))
	for index, testCase := range cases {
		t.Run(string(testCase.operation), func(t *testing.T) {
			pipeline := completeOperationPipeline(t, path, testCase, index)
			completed = append(completed, pipeline)
			if pipeline.decision.Kind() != CommandDecisionApplied ||
				pipeline.result.Operation() != testCase.operation ||
				pipeline.receipt.Result().ResponseDigest() != pipeline.result.ResponseDigest() ||
				len(pipeline.decision.Facts()) != len(testCase.facts) ||
				len(pipeline.result.CanonicalBytes()) == 0 {
				t.Fatal("pipeline did not retain its exact applied result")
			}
			wrongLast, _ := domain.NewStreamPosition(uint64(len(testCase.facts) + 1))
			first, _ := domain.NewStreamPosition(1)
			digest, _ := domain.NewStreamDigest([32]byte{88})
			if _, err := NewProductionCanonicalCodec().MaterializeReceiptResult(
				pipeline.decision.ResultPlan(), first, wrongLast, digest,
			); err == nil {
				t.Fatalf("wrong event shape materialization error=%v", err)
			}
			badCommit := pipeline.commit
			badCommit.facts = nil
			if _, err := ApplyCommand(
				pipeline.context, badCommit, pipeline.decision.Audit(), pipeline.decision.Effects(),
			); !errors.Is(err, ErrInvalidCommandDecision) {
				t.Fatalf("fact-shape mutation error=%v", err)
			}
			badSpecParams := commandSpecParamsFromPipeline(pipeline)
			badSpecParams.Guards.disclosure = badSpecParams.Guards.disclosure[:len(badSpecParams.Guards.disclosure)-1]
			if _, err := NewCommandSpec(badSpecParams); !errors.Is(err, ErrInvalidCommandSpec) {
				t.Fatalf("disclosure-shape mutation error=%v", err)
			}
		})
	}
	for index := range completed {
		next := completed[(index+1)%len(completed)]
		crossOperationCommit := completed[index].commit
		crossOperationCommit.operation = next.caseDefinition.operation
		if _, err := ApplyCommand(
			completed[index].context, crossOperationCommit,
			completed[index].decision.Audit(), completed[index].decision.Effects(),
		); !errors.Is(err, ErrInvalidCommandDecision) {
			t.Fatalf("%s accepted commit tagged as %s: %v",
				completed[index].caseDefinition.operation, next.caseDefinition.operation, err)
		}
	}
}

func TestVersionedCommitRejectsResultComputedFromAlternateLockedState(t *testing.T) {
	path := buildOperationDomainPath(t)
	var pairingCase operationPipelineCase
	pairingIndex := -1
	for index, testCase := range buildOperationPipelineCases(t, path) {
		if testCase.operation == CommandPairDevice {
			pairingCase = testCase
			pairingIndex = index
			break
		}
	}
	if pairingIndex < 0 {
		t.Fatal("pair-device pipeline case is missing")
	}
	pipeline := completeOperationPipeline(t, path, pairingCase, pairingIndex)
	locked := path.pairingBegan.Device()
	alternateName, _ := domain.NewDisplayName("Laundered device")
	alternateKey, _ := domain.NewPublicKeyReference("keyref:laundered-device")
	alternate, err := domain.RehydrateDevice(domain.DeviceRehydrationParams{
		ID: locked.ID(), InstallationID: locked.InstallationID(), PrincipalID: locked.PrincipalID(),
		DisplayName: alternateName, PublicKeyReference: alternateKey, Status: locked.Status(),
		Version: locked.Version(), TrustRevision: locked.TrustRevision(), RevocationRevision: locked.RevocationRevision(),
		PairingChallenge: locked.PairingChallenge(),
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge := locked.PairingChallenge()
	proof, _ := domain.NewCeremonyProof(
		challenge.ID(), challenge.Purpose(), challenge.ProofDigest(), locked.PrincipalID(), locked.ID(),
	)
	spki, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("laundered device spki")))
	credential, _ := domain.NewDeviceCredentialBinding(alternateKey, spki, challenge.ProofDigest())
	authorization, _ := domain.NewPairingRedemptionAuthorization(
		path.authority, path.epoch, path.installation, locked.PrincipalID(), locked.ID(),
		path.policy, path.assurance, path.now, challenge.ID(), challenge.ProofDigest(), credential,
	)
	currentAuthorization, _ := domain.NewIdentityAuthorization(
		path.authority, path.epoch, path.installation, locked.PrincipalID(), path.ownerCaps,
		path.policy, path.assurance, path.now, domain.MaxActorSessionLifetime,
	)
	laundered, err := domain.PairDevice(domain.PairDeviceInput{
		Authorization: authorization, CurrentAuthorization: currentAuthorization, AuthorityTime: path.now,
		Principal:                path.bootstrap.Principal(),
		ExpectedPrincipalVersion: path.bootstrap.Principal().Version(), Device: alternate,
		ExpectedDeviceVersion: alternate.Version(), ExpectedTrustRevision: alternate.TrustRevision(), Proof: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = PairDeviceCommit(pipeline.context, laundered); !errors.Is(err, ErrInvalidCommandDecision) {
		t.Fatalf("alternate-state result was accepted: %v", err)
	}
}

func completeOperationPipeline(
	t *testing.T,
	path operationDomainPath,
	testCase operationPipelineCase,
	index int,
) completedOperationPipeline {
	t.Helper()
	operation, _ := domain.NewOperationName(string(testCase.operation))
	major, _ := NewOperationMajor(1)
	commandID, _ := domain.ParseCommandID(applicationUUID(300 + index*10))
	receiptID, _ := domain.ParseReceiptID(applicationUUID(301 + index*10))
	correlationID, _ := domain.ParseCorrelationID(applicationUUID(302 + index*10))
	clientID, _ := domain.ParseClientInstanceID(applicationUUID(303 + index*10))
	key, _ := domain.NewIdempotencyKey(fmt.Sprintf("matrix-%02d", index))
	var receiptIdentity ReceiptIdentity
	var err error
	contract, cataloged := commandContract(testCase.operation)
	if !cataloged {
		t.Fatalf("uncataloged operation %s", testCase.operation)
	}
	switch contract.receipt {
	case ReceiptIdentityOrdinary:
		workspaceID, parseErr := domain.ParseWorkspaceID(testCase.scope.ID())
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		idempotency, scopeErr := domain.NewIdempotencyScope(
			workspaceID, testCase.principal, clientID, operation, key,
		)
		if scopeErr != nil {
			t.Fatal(scopeErr)
		}
		receiptIdentity, err = OrdinaryReceiptIdentity(idempotency)
	case ReceiptIdentityInstallationAdmin:
		receiptIdentity, err = InstallationAdminReceiptIdentity(
			path.installation, testCase.principal, clientID, operation, key,
		)
	default:
		t.Fatalf("unexpected receipt identity for %s", testCase.operation)
	}
	if err != nil {
		t.Fatal(err)
	}
	authorization := make([]domain.AggregateRef, len(testCase.authorization))
	for refIndex, state := range testCase.authorization {
		authorization[refIndex], err = identityStateRef(state)
		if err != nil {
			t.Fatal(err)
		}
	}
	references := make([]domain.AggregateRef, len(testCase.references))
	for refIndex, state := range testCase.references {
		references[refIndex], err = identityStateRef(state)
		if err != nil {
			t.Fatal(err)
		}
	}
	generation, _ := NewGuardGeneration(uint64(index + 10))
	guardPlan, err := NewCommandGuardPlan(CommandGuardPlanParams{
		AdmissionScope: testCase.admission, AdmissionGeneration: generation,
		Evidence: testCase.evidence, Authorization: authorization, References: references,
		Disclosure: testCase.disclosure, Mutations: testCase.mutations,
		Ceremonies: testCase.ceremonies, Genesis: testCase.genesis,
	})
	if err != nil {
		t.Fatalf("guard plan: %v", err)
	}
	factExpectations := make([]FactExpectation, len(testCase.facts))
	for factIndex, fact := range testCase.facts {
		eventID, _ := domain.ParseEventID(applicationUUID(400 + index*10 + factIndex))
		factExpectations[factIndex], err = NewFactExpectation(eventID, fact.Type(), fact.Origin())
		if err != nil {
			t.Fatal(err)
		}
	}
	recovery := NotApplicableRecoveryCapsulePlan()
	if contract.recovery == RecoveryCapsuleRequired {
		recovery, err = PrepareRecoveryCapsulePlan(newTestCapsuleSigner("ed25519:matrix:" + string(testCase.operation)))
		if err != nil {
			t.Fatal(err)
		}
	}
	fingerprint := domain.FingerprintCommand([]byte("matrix-command:" + string(testCase.operation)))
	specParams := CommandSpecParams{
		Scope: testCase.scope, AuthorityID: path.authority, RequestedEpoch: path.epoch,
		CommandID: commandID, ReceiptID: receiptID, Operation: operation, OperationMajor: major,
		ReceiptIdentity: receiptIdentity, RequestFingerprint: fingerprint, Authorship: testCase.authorship,
		CorrelationID: correlationID, AuthorityTimeClass: contract.timeClass,
		RecoveryCapsule: recovery, Guards: guardPlan, ExpectedFacts: factExpectations,
	}
	spec, err := NewCommandSpec(specParams)
	if err != nil {
		t.Fatalf("command spec: %v", err)
	}
	appliedEvidence, err := NewAppliedGuardEvidence(guardPlan, guardPlan.Evidence())
	if err != nil {
		t.Fatal(err)
	}
	states := append([]IdentityState(nil), testCase.authorization...)
	states = append(states, testCase.references...)
	states = append(states, testCase.mutatedPrior...)
	commandTime, _ := PersistedCommandAuthorityTime(path.now)
	var commandContext CommandContext
	if len(testCase.standalone) == 0 {
		commandContext, err = NewCommandContext(spec, commandTime, states, AdmitReceipt(), appliedEvidence)
	} else {
		commandContext, err = NewCommandContextWithStandaloneCeremonies(
			spec, commandTime, states, testCase.standalone, AdmitReceipt(), appliedEvidence,
		)
	}
	if err != nil {
		t.Fatalf("command context: %v", err)
	}
	commit, err := testCase.commit(commandContext)
	if err != nil {
		t.Fatalf("operation commit: %v", err)
	}
	audit, err := NewAuditIntent(operation, AuditCommandApplied, fingerprint, CommandAppliedAuditDetail())
	if err != nil {
		t.Fatal(err)
	}
	effects, _ := NewEffectSet()
	decision, err := ApplyCommand(commandContext, commit, audit, effects)
	if err != nil {
		t.Fatalf("apply: %v (resolution=%v operation=%v audit_outcome=%v audit_operation=%v audit_fingerprint=%v writes=%v facts=%v ceremonies=%v effects=%v)",
			err,
			commandContext.resolution.kind == ReceiptAdmitted,
			commit.operation == commandContext.spec.commandOperation,
			audit.outcome == AuditCommandApplied,
			audit.operation == commandContext.spec.operation,
			audit.fingerprint == commandContext.spec.requestFingerprint,
			writesMatchPlan(commit.writes, commandContext.spec.guards.mutations),
			factsMatchPlan(commit.facts, commandContext.spec.expectedFacts),
			ceremonyTransitionsMatchPlan(commit.ceremonies, commandContext.spec.guards.ceremonies),
			effectsReferToFacts(effects, commit.facts),
		)
	}
	if err := ValidateCommandDecision(commandContext, decision); err != nil {
		t.Fatalf("validate decision: %v", err)
	}
	first, _ := domain.NewStreamPosition(1)
	last, _ := domain.NewStreamPosition(uint64(len(testCase.facts)))
	finalDigestBytes := [32]byte{byte(index + 1), 77}
	finalDigest, _ := domain.NewStreamDigest(finalDigestBytes)
	result, err := NewProductionCanonicalCodec().MaterializeReceiptResult(
		decision.ResultPlan(), first, last, finalDigest,
	)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	events := mustEventRangeForFacts(t, len(testCase.facts))
	var capsuleDraft *RecoveryCapsuleDraft
	if recovery.Requirement() == RecoveryCapsuleRequired {
		capsuleDraft = mustCapsuleDraft(t, result, commandID, major, recovery.KeyID())
	}
	receipt, err := NewReceiptSnapshot(ReceiptSnapshotParams{
		ReceiptID: receiptID, CommandID: commandID, Identity: receiptIdentity,
		RequestFingerprint: fingerprint, Result: result, AuthorityID: path.authority,
		AuthorityEpoch: path.epoch, GuardDigest: appliedEvidence.Digest(), Events: events,
		EventCursor:        EventCursor{value: "bbec1_application_fixture"},
		CapsuleRequirement: recovery.Requirement(), RecoveryCapsule: capsuleDraft,
	})
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	return completedOperationPipeline{
		caseDefinition: testCase, spec: spec, context: commandContext, commit: commit,
		decision: decision, result: result, receipt: receipt,
	}
}

func mustEventRangeForFacts(t *testing.T, count int) EventRange {
	t.Helper()
	first, _ := domain.NewStreamPosition(1)
	last, _ := domain.NewStreamPosition(uint64(count))
	events, err := NewEventRange(first, last, uint16(count))
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func commandSpecParamsFromPipeline(pipeline completedOperationPipeline) CommandSpecParams {
	return CommandSpecParams{
		Scope: pipeline.spec.Scope(), AuthorityID: pipeline.spec.AuthorityID(),
		RequestedEpoch: pipeline.spec.RequestedEpoch(), CommandID: pipeline.spec.CommandID(),
		ReceiptID: pipeline.spec.ReceiptID(), Operation: pipeline.spec.Operation(),
		OperationMajor: pipeline.spec.OperationMajor(), ReceiptIdentity: pipeline.spec.ReceiptIdentity(),
		RequestFingerprint: pipeline.spec.RequestFingerprint(), Authorship: pipeline.spec.Authorship(),
		CorrelationID: pipeline.spec.CorrelationID(), AuthorityTimeClass: pipeline.spec.AuthorityTimeClass(),
		RecoveryCapsule: pipeline.spec.RecoveryCapsule(), Guards: pipeline.spec.Guards(),
		ExpectedFacts: pipeline.spec.ExpectedFacts(),
	}
}
