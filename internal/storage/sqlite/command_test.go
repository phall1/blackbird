package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

func TestOpenStoreComposesAsProductionUnitOfWork(t *testing.T) {
	store := openConformanceStore(t)
	var unit application.UnitOfWork = store
	if unit != store {
		t.Fatal("Open did not return the production UnitOfWork implementation")
	}
}

type commandTestSigner struct {
	private ed25519.PrivateKey
}

func (signer commandTestSigner) KeyID() string { return "ed25519:sqlite-command-test" }
func (signer commandTestSigner) Ed25519PublicKey() ed25519.PublicKey {
	public, _ := signer.private.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), public...)
}
func (signer commandTestSigner) SignRecoveryCapsule(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, message), nil
}

func TestExecuteCommandPersistsBootstrapAtomicallyAndReplaysExactly(t *testing.T) {
	t.Parallel()
	store := openSecurityStore(t)
	security := newSecurityFixture(t)
	initializeSecurityFixture(t, store, security)
	spec, decide, _ := newBootstrapCommand(t, security)

	execution, err := store.ExecuteCommand(context.Background(), spec, decide)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Kind() != application.CommandTransactionCommitted {
		t.Fatalf("execution kind=%q", execution.Kind())
	}
	assertCommandRowCounts(t, store, map[string]int{
		"installation_invitations": 1,
		"principals":               1,
		"device_registrations":     1,
		"grants":                   1,
		"command_receipts":         1,
		"domain_events":            3,
		"audit_entries":            2,
		"outbox_jobs":              1,
	})
	var capsuleRequired int
	var capsule, capsuleDigest, capsulePublic []byte
	if err := store.db.QueryRow(`SELECT capsule_required, recovery_capsule_canonical,
		recovery_capsule_digest, recovery_capsule_public_key FROM command_receipts WHERE command_id = ?`,
		spec.CommandID().String()).Scan(&capsuleRequired, &capsule, &capsuleDigest, &capsulePublic); err != nil {
		t.Fatal(err)
	}
	if capsuleRequired != 1 || len(capsule) == 0 || len(capsuleDigest) != sha256.Size || len(capsulePublic) != ed25519.PublicKeySize {
		t.Fatalf("invalid persisted capsule required=%d canonical=%d digest=%d public=%d",
			capsuleRequired, len(capsule), len(capsuleDigest), len(capsulePublic))
	}
	var outboxCommand string
	var outboxMetadataDigest []byte
	if err := store.db.QueryRow(`SELECT command_id, metadata_digest FROM outbox_jobs`).Scan(
		&outboxCommand, &outboxMetadataDigest,
	); err != nil {
		t.Fatal(err)
	}
	if outboxCommand != spec.CommandID().String() || len(outboxMetadataDigest) != sha256.Size {
		t.Fatalf("invalid outbox identity command=%q metadata_digest=%d", outboxCommand, len(outboxMetadataDigest))
	}
	var revocationRevision uint64
	var credentialActivatedAt int64
	if err := store.db.QueryRow(`SELECT revocation_revision, credential_activated_at_us
		FROM device_registrations`).Scan(&revocationRevision, &credentialActivatedAt); err != nil {
		t.Fatal(err)
	}
	if revocationRevision != 1 || credentialActivatedAt <= 0 {
		t.Fatalf("device credential metadata revision=%d activated_at=%d", revocationRevision, credentialActivatedAt)
	}
	var nextSequence, nextAudit int
	if err := store.db.QueryRow(`SELECT next_sequence, next_audit_sequence FROM authority_streams
		WHERE scope_kind = ? AND scope_id = ? AND authority_epoch = ?`,
		string(spec.Scope().Kind()), spec.Scope().ID(), spec.RequestedEpoch().String()).Scan(&nextSequence, &nextAudit); err != nil {
		t.Fatal(err)
	}
	if nextSequence != 4 || nextAudit != 3 {
		t.Fatalf("stream cursors=(%d,%d), want (4,3)", nextSequence, nextAudit)
	}

	replay, err := store.ExecuteCommand(context.Background(), spec, func(locked application.CommandContext) (application.CommandDecision, error) {
		return application.ReplayCommand(locked, application.ReplayDiscloseResult)
	})
	if err != nil {
		t.Fatal(err)
	}
	if replay.Kind() != application.CommandTransactionReplayed {
		t.Fatalf("replay kind=%q", replay.Kind())
	}
	assertCommandRowCounts(t, store, map[string]int{
		"command_receipts": 1,
		"domain_events":    3,
		"audit_entries":    2,
	})
}

func TestExecuteCommandPersistsRegisterPrincipalAfterBootstrap(t *testing.T) {
	t.Parallel()
	store := openSecurityStore(t)
	security := newSecurityFixture(t)
	initializeSecurityFixture(t, store, security)
	bootstrapSpec, bootstrapDecide, bootstrap := newBootstrapCommand(t, security)
	if execution, err := store.ExecuteCommand(context.Background(), bootstrapSpec, bootstrapDecide); err != nil ||
		execution.Kind() != application.CommandTransactionCommitted {
		t.Fatalf("bootstrap execution=%q error=%v", execution.Kind(), err)
	}

	spec, decide, registered := newRegisterPrincipalCommand(t, security, bootstrap)
	execution, err := store.ExecuteCommand(context.Background(), spec, decide)
	if err != nil || execution.Kind() != application.CommandTransactionCommitted {
		t.Fatalf("register execution=%q error=%v", execution.Kind(), err)
	}

	var installationID, kind, displayName, publicKey, status string
	var version uint64
	if err := store.db.QueryRow(`SELECT installation_id, kind, display_name,
		public_key_reference, status, version FROM principals WHERE principal_id = ?`,
		registered.Principal().ID().String()).Scan(
		&installationID, &kind, &displayName, &publicKey, &status, &version,
	); err != nil {
		t.Fatal(err)
	}
	principal := registered.Principal()
	if installationID != principal.InstallationID().String() || kind != string(principal.Kind()) ||
		displayName != principal.DisplayName().String() || publicKey != principal.PublicKeyReference().String() ||
		status != string(principal.Status()) || version != principal.Version().Uint64() {
		t.Fatal("registered principal did not round-trip through normalized state")
	}
	assertCommandRowCounts(t, store, map[string]int{
		"principals":       2,
		"command_receipts": 2,
		"domain_events":    4,
		"audit_entries":    3,
	})
	var operation, eventType, originID string
	if err := store.db.QueryRow(`SELECT receipt.operation, event.event_type, event.aggregate_id
		FROM domain_events AS event JOIN command_receipts AS receipt USING (receipt_id)
		WHERE event.command_id = ?`, spec.CommandID().String()).Scan(&operation, &eventType, &originID); err != nil {
		t.Fatal(err)
	}
	if operation != spec.Operation().String() || eventType != string(domain.EventTypePrincipalRegistered) ||
		originID != principal.ID().String() {
		t.Fatalf("register event operation=%q type=%q origin=%q", operation, eventType, originID)
	}
	var nextSequence, nextAudit uint64
	if err := store.db.QueryRow(`SELECT next_sequence, next_audit_sequence FROM authority_streams
		WHERE scope_kind = ? AND scope_id = ? AND authority_epoch = ?`, string(security.scope.Kind()),
		security.scope.ID(), security.epoch.String()).Scan(&nextSequence, &nextAudit); err != nil {
		t.Fatal(err)
	}
	if nextSequence != 5 || nextAudit != 4 {
		t.Fatalf("installation stream cursors=(%d,%d), want (5,4)", nextSequence, nextAudit)
	}

	replay, err := store.ExecuteCommand(context.Background(), spec, func(locked application.CommandContext) (application.CommandDecision, error) {
		return application.ReplayCommand(locked, application.ReplayDiscloseResult)
	})
	if err != nil || replay.Kind() != application.CommandTransactionReplayed {
		t.Fatalf("register replay=%q error=%v", replay.Kind(), err)
	}
	assertCommandRowCounts(t, store, map[string]int{
		"principals": 2, "command_receipts": 2, "domain_events": 4, "audit_entries": 3,
	})
}

func TestExecuteCommandReceiptConflictsRollbackWithoutCallingAppliedPath(t *testing.T) {
	t.Parallel()
	store := openSecurityStore(t)
	security := newSecurityFixture(t)
	initializeSecurityFixture(t, store, security)
	spec, decide, _ := newBootstrapCommand(t, security)
	if _, err := store.ExecuteCommand(context.Background(), spec, decide); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		spec application.CommandSpec
		code domain.ErrorCode
	}{
		{
			name: "command ID reused with another fingerprint",
			spec: cloneBootstrapSpec(t, spec, spec.CommandID(), spec.ReceiptID(),
				domain.FingerprintCommand([]byte("conflicting command fingerprint"))),
			code: domain.ErrorCodeCommandIDReused,
		},
		{
			name: "idempotency identity reused with another fingerprint",
			spec: cloneBootstrapSpec(t, spec, mustCommandID(t, 90), mustReceiptID(t, 91),
				domain.FingerprintCommand([]byte("conflicting idempotency fingerprint"))),
			code: domain.ErrorCodeIdempotencyKeyReused,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			execution, err := store.ExecuteCommand(context.Background(), test.spec, func(locked application.CommandContext) (application.CommandDecision, error) {
				called = true
				rejection, rejectionErr := domain.NewCommandError(test.code, "receipt conflict", nil)
				if rejectionErr != nil {
					return application.CommandDecision{}, rejectionErr
				}
				return application.RollbackCommand(locked, rejection)
			})
			if err != nil || execution.Kind() != application.CommandTransactionRejected {
				t.Fatalf("conflict execution=%q error=%v", execution.Kind(), err)
			}
			if !called {
				t.Fatal("receipt conflict was not disclosed to the decision callback")
			}
			assertCommandRowCounts(t, store, map[string]int{
				"principals": 1, "command_receipts": 1, "domain_events": 3, "audit_entries": 2,
			})
		})
	}
}

func newBootstrapCommand(
	t *testing.T,
	fixture securityFixture,
) (application.CommandSpec, func(application.CommandContext) (application.CommandDecision, error), domain.BootstrapInstallationResult) {
	t.Helper()
	principalID, _ := domain.ParsePrincipalID(commandTestUUID(1))
	deviceID, _ := domain.ParseDeviceID(commandTestUUID(2))
	grantID, _ := domain.ParseGrantID(commandTestUUID(3))
	commandID, _ := domain.ParseCommandID(commandTestUUID(4))
	receiptID, _ := domain.ParseReceiptID(commandTestUUID(5))
	correlationID, _ := domain.ParseCorrelationID(commandTestUUID(6))
	principalName, _ := domain.NewDisplayName("SQLite owner")
	deviceName, _ := domain.NewDisplayName("SQLite owner device")
	deviceKey, _ := domain.NewPublicKeyReference("keyref:sqlite-command-device")
	spki, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("sqlite command device SPKI")))
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
		InvitationID: fixture.invitation.ID(), InstallationID: fixture.invitation.InstallationID(),
		InstallationKey: fixture.invitation.InstallationPublicKey(), InvitationEvidence: fixture.invitation.InvitationVerifier(),
		TranscriptFingerprint: domain.FingerprintCommand([]byte("sqlite approved transcript")),
		ClientNonceDigest:     domain.FingerprintCommand([]byte("sqlite client nonce")),
		ServerNonceDigest:     domain.FingerprintCommand([]byte("sqlite server nonce")),
		Protocol:              domain.PairingProtocolV1, Role: domain.BootstrapRoleInstallationOwner,
		PrincipalID: principalID, PrincipalDisplayName: principalName, DeviceID: deviceID,
		DeviceDisplayName: deviceName, DevicePublicKey: deviceKey, DeviceSPKIFingerprint: spki,
		OwnerGrantID: grantID, OwnerCapabilities: capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	generationAuthorization, _ := domain.SameBootstrapGeneration(fixture.generationA)
	input := func(invitation domain.InstallationInvitationState, evaluatedAt time.Time) domain.BootstrapInstallationInput {
		return domain.BootstrapInstallationInput{
			Invitation: invitation, ExpectedInvitationVersion: invitation.Version(), CurrentGeneration: fixture.generationA,
			GenerationAuthorization: generationAuthorization, PrincipalID: principalID, PrincipalDisplayName: principalName,
			DeviceID: deviceID, DeviceDisplayName: deviceName, DevicePublicKey: deviceKey, OwnerGrantID: grantID,
			OwnerGrantCapabilities: capabilities, Proof: proof,
			AttemptFingerprint: domain.FingerprintCommand([]byte("sqlite bootstrap attempt")), EvaluatedAt: evaluatedAt,
		}
	}
	preview, err := domain.BootstrapInstallation(input(fixture.invitation, time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	operation, _ := domain.NewOperationName("installation.bootstrap.v1")
	idempotency, _ := domain.NewIdempotencyKey("sqlite-bootstrap-retry")
	identityScope, _ := domain.NewProvisioningIdempotencyScope(fixture.scope, proof.TranscriptFingerprint(), operation, idempotency)
	receiptIdentity, _ := application.ProvisioningReceiptIdentity(identityScope)
	commitSet, _ := domain.BootstrapInstallationCommitSet(principalID, deviceID, grantID, fixture.invitation.ID(), fixture.invitation.Version())
	authorityGuard, _ := application.CurrentAuthorityEpochGuard(fixture.scope, fixture.authority, fixture.epoch)
	generationGuard, _ := application.BootstrapGenerationGuard(fixture.scope, fixture.generationA)
	invitationTarget, _ := domain.NewAggregateTarget(fixture.invitation.ID())
	statusGuard, _ := application.LifecycleStatusGuard(invitationTarget, string(domain.InstallationInvitationPending))
	guardPlan, err := application.NewCommandGuardPlan(application.CommandGuardPlanParams{
		AdmissionScope: fixture.scope, AdmissionGeneration: fixture.admission,
		Evidence:   []application.EvidenceGuard{authorityGuard, generationGuard, statusGuard},
		Disclosure: []domain.AggregateTarget{invitationTarget}, Mutations: commitSet.Expectations(),
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := make([]application.FactExpectation, len(preview.Facts()))
	for index, fact := range preview.Facts() {
		eventID, _ := domain.ParseEventID(commandTestUUID(20 + index))
		expected[index], err = application.NewFactExpectation(eventID, fact.Type(), fact.Origin())
		if err != nil {
			t.Fatal(err)
		}
	}
	seed := sha256.Sum256([]byte("sqlite command capsule signer"))
	capsulePlan, err := application.PrepareRecoveryCapsulePlan(commandTestSigner{private: ed25519.NewKeyFromSeed(seed[:])})
	if err != nil {
		t.Fatal(err)
	}
	authorship, _ := application.ProvisioningAuthorship(principalID)
	major, _ := application.NewOperationMajor(1)
	spec, err := application.NewCommandSpec(application.CommandSpecParams{
		Scope: fixture.scope, AuthorityID: fixture.authority, RequestedEpoch: fixture.epoch,
		CommandID: commandID, ReceiptID: receiptID, Operation: operation, OperationMajor: major,
		ReceiptIdentity: receiptIdentity, RequestFingerprint: domain.FingerprintCommand([]byte("sqlite bootstrap command")),
		Authorship: authorship, CorrelationID: correlationID, AuthorityTimeClass: application.AuthorityTimeOrdinary,
		RecoveryCapsule: capsulePlan, Guards: guardPlan, ExpectedFacts: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	decide := func(locked application.CommandContext) (application.CommandDecision, error) {
		state, found := locked.State(invitationTarget)
		if !found {
			return application.CommandDecision{}, fmt.Errorf("invitation not loaded")
		}
		invitation, ok := state.Value().(domain.InstallationInvitationState)
		if !ok {
			return application.CommandDecision{}, fmt.Errorf("loaded invitation has type %T", state.Value())
		}
		authorityTime, found := locked.AuthorityTime()
		if !found {
			return application.CommandDecision{}, fmt.Errorf("persisted authority time absent")
		}
		result, err := domain.BootstrapInstallation(input(invitation, authorityTime))
		if err != nil {
			return application.CommandDecision{}, err
		}
		commit, err := application.BootstrapInstallationCommit(locked, result)
		if err != nil {
			return application.CommandDecision{}, err
		}
		audit, err := application.NewAuditIntent(operation, application.AuditCommandApplied,
			spec.RequestFingerprint(), application.CommandAppliedAuditDetail())
		if err != nil {
			return application.CommandDecision{}, err
		}
		auditRequest, err := application.NewAuditRequestContext(
			"sqlite-bootstrap-request", "sqlite-bootstrap-trace", authorityTime, nil,
		)
		if err != nil {
			return application.CommandDecision{}, err
		}
		provenance, err := application.NewAuditProvenanceEvidence(fixture.authority, nil)
		if err != nil {
			return application.CommandDecision{}, err
		}
		authentication, err := application.NewAuthenticationEvidence(principalID, &deviceID, provenance)
		if err != nil {
			return application.CommandDecision{}, err
		}
		audit, err = application.BindCommandAuditContext(audit, spec, auditRequest, authentication)
		if err != nil {
			return application.CommandDecision{}, err
		}
		effect, err := application.NewEffectIntent(
			spec.ExpectedFacts()[0].EventID(), "sqlite_test_handler", major, "sqlite-test-destination", 0,
			[]byte(`{"schema":"blackbird.sqlite-test-effect.v1"}`),
		)
		if err != nil {
			return application.CommandDecision{}, err
		}
		effects, err := application.NewEffectSet(effect)
		if err != nil {
			return application.CommandDecision{}, err
		}
		return application.ApplyCommand(locked, commit, audit, effects)
	}
	return spec, decide, preview
}

func newRegisterPrincipalCommand(
	t *testing.T,
	fixture securityFixture,
	bootstrap domain.BootstrapInstallationResult,
) (application.CommandSpec, func(application.CommandContext) (application.CommandDecision, error), domain.RegisterPrincipalResult) {
	t.Helper()
	owner := bootstrap.Principal()
	grant := bootstrap.OwnerGrant()
	principalID, _ := domain.ParsePrincipalID(commandTestUUID(60))
	displayName, _ := domain.NewDisplayName("SQLite workload")
	publicKey, _ := domain.NewPublicKeyReference("keyref:sqlite-command-workload")
	policy, _ := domain.NewPolicyRevision("policy:sqlite-command:v1")
	assurance, _ := domain.NewAssuranceClass("sqlite-command-strong")
	evaluatedAt := time.Now().UTC()
	authorization, err := domain.NewIdentityAuthorization(
		fixture.authority, fixture.epoch, fixture.invitation.InstallationID(), owner.ID(),
		grant.Capabilities(), policy, assurance, evaluatedAt, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	input := func(registrar domain.PrincipalState) domain.RegisterPrincipalInput {
		return domain.RegisterPrincipalInput{
			Authorization: authorization, Registrar: registrar, ExpectedRegistrarVersion: registrar.Version(),
			PrincipalID: principalID, Kind: domain.PrincipalKindWorkload, DisplayName: displayName,
			PublicKeyReference: publicKey,
		}
	}
	preview, err := domain.RegisterPrincipal(input(owner))
	if err != nil {
		t.Fatal(err)
	}
	ownerRef, _ := domain.NewAggregateRef(owner.ID(), owner.Version())
	grantRef, _ := domain.NewAggregateRef(grant.ID(), grant.Version())
	ownerTarget, _ := domain.NewAggregateTarget(owner.ID())
	principalTarget, _ := domain.NewAggregateTarget(principalID)
	grantTarget, _ := domain.NewAggregateTarget(grant.ID())
	principalAbsent, _ := domain.ExpectAggregateAbsent(principalID)
	authorityGuard, _ := application.CurrentAuthorityEpochGuard(fixture.scope, fixture.authority, fixture.epoch)
	policyGuard, _ := application.PolicyRevisionGuard(fixture.scope, policy)
	ownerStatus, _ := application.LifecycleStatusGuard(ownerTarget, string(owner.Status()))
	grantStatus, _ := application.LifecycleStatusGuard(grantTarget, string(grant.Status()))
	ceiling, _ := application.CapabilityCeilingGuard(grantTarget, application.DigestBytes([]byte("sqlite register ceiling")))
	guardPlan, err := application.NewCommandGuardPlan(application.CommandGuardPlanParams{
		AdmissionScope: fixture.scope, AdmissionGeneration: fixture.admission,
		Evidence:      []application.EvidenceGuard{authorityGuard, policyGuard, ownerStatus, grantStatus, ceiling},
		Authorization: []domain.AggregateRef{ownerRef, grantRef},
		Disclosure:    []domain.AggregateTarget{ownerTarget, principalTarget},
		Mutations:     []domain.AggregateExpectation{principalAbsent},
	})
	if err != nil {
		t.Fatal(err)
	}
	operation, _ := domain.NewOperationName(string(application.CommandRegisterPrincipal))
	clientID, _ := domain.ParseClientInstanceID(commandTestUUID(61))
	idempotency, _ := domain.NewIdempotencyKey("sqlite-register-workload")
	receiptIdentity, err := application.InstallationAdminReceiptIdentity(
		fixture.invitation.InstallationID(), owner.ID(), clientID, operation, idempotency,
	)
	if err != nil {
		t.Fatal(err)
	}
	eventID, _ := domain.ParseEventID(commandTestUUID(62))
	fact := preview.Facts()[0]
	expected, err := application.NewFactExpectation(eventID, fact.Type(), fact.Origin())
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("sqlite register capsule signer"))
	capsulePlan, err := application.PrepareRecoveryCapsulePlan(commandTestSigner{private: ed25519.NewKeyFromSeed(seed[:])})
	if err != nil {
		t.Fatal(err)
	}
	authorship, _ := application.AuthorityAuthorship(owner.ID())
	major, _ := application.NewOperationMajor(1)
	commandID, receiptID := mustCommandID(t, 63), mustReceiptID(t, 64)
	correlationID, _ := domain.ParseCorrelationID(commandTestUUID(65))
	fingerprint := domain.FingerprintCommand([]byte("sqlite register command"))
	spec, err := application.NewCommandSpec(application.CommandSpecParams{
		Scope: fixture.scope, AuthorityID: fixture.authority, RequestedEpoch: fixture.epoch,
		CommandID: commandID, ReceiptID: receiptID, Operation: operation, OperationMajor: major,
		ReceiptIdentity: receiptIdentity, RequestFingerprint: fingerprint, Authorship: authorship,
		CorrelationID: correlationID, AuthorityTimeClass: application.AuthorityTimeOrdinary,
		RecoveryCapsule: capsulePlan, Guards: guardPlan, ExpectedFacts: []application.FactExpectation{expected},
	})
	if err != nil {
		t.Fatal(err)
	}
	decide := func(locked application.CommandContext) (application.CommandDecision, error) {
		state, found := locked.State(ownerTarget)
		if !found {
			return application.CommandDecision{}, fmt.Errorf("registrar not loaded")
		}
		registrar, ok := state.Value().(domain.PrincipalState)
		if !ok {
			return application.CommandDecision{}, fmt.Errorf("loaded registrar has type %T", state.Value())
		}
		result, transitionErr := domain.RegisterPrincipal(input(registrar))
		if transitionErr != nil {
			return application.CommandDecision{}, transitionErr
		}
		commit, commitErr := application.RegisterPrincipalCommit(locked, result)
		if commitErr != nil {
			return application.CommandDecision{}, commitErr
		}
		audit, auditErr := application.NewAuditIntent(
			operation, application.AuditCommandApplied, fingerprint, application.CommandAppliedAuditDetail(),
		)
		if auditErr != nil {
			return application.CommandDecision{}, auditErr
		}
		authorityTime, found := locked.AuthorityTime()
		if !found {
			return application.CommandDecision{}, fmt.Errorf("persisted authority time absent")
		}
		request, auditErr := application.NewAuditRequestContext(
			"sqlite-register-request", "sqlite-register-trace", authorityTime, nil,
		)
		if auditErr != nil {
			return application.CommandDecision{}, auditErr
		}
		provenance, auditErr := application.NewAuditProvenanceEvidence(fixture.authority, nil)
		if auditErr != nil {
			return application.CommandDecision{}, auditErr
		}
		authentication, auditErr := application.NewAuthenticationEvidence(owner.ID(), nil, provenance)
		if auditErr != nil {
			return application.CommandDecision{}, auditErr
		}
		audit, auditErr = application.BindCommandAuditContext(audit, spec, request, authentication)
		if auditErr != nil {
			return application.CommandDecision{}, auditErr
		}
		effects, _ := application.NewEffectSet()
		return application.ApplyCommand(locked, commit, audit, effects)
	}
	return spec, decide, preview
}

func cloneBootstrapSpec(
	t *testing.T,
	spec application.CommandSpec,
	commandID domain.CommandID,
	receiptID domain.ReceiptID,
	fingerprint domain.CommandFingerprint,
) application.CommandSpec {
	t.Helper()
	cloned, err := application.NewCommandSpec(application.CommandSpecParams{
		Scope: spec.Scope(), AuthorityID: spec.AuthorityID(), RequestedEpoch: spec.RequestedEpoch(),
		CommandID: commandID, ReceiptID: receiptID, Operation: spec.Operation(), OperationMajor: spec.OperationMajor(),
		ReceiptIdentity: spec.ReceiptIdentity(), RequestFingerprint: fingerprint, Authorship: spec.Authorship(),
		CorrelationID: spec.CorrelationID(), AuthorityTimeClass: spec.AuthorityTimeClass(),
		RecoveryCapsule: spec.RecoveryCapsule(), Guards: spec.Guards(), ExpectedFacts: spec.ExpectedFacts(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func mustCommandID(t *testing.T, index int) domain.CommandID {
	t.Helper()
	id, err := domain.ParseCommandID(commandTestUUID(index))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustReceiptID(t *testing.T, index int) domain.ReceiptID {
	t.Helper()
	id, err := domain.ParseReceiptID(commandTestUUID(index))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertCommandRowCounts(t *testing.T, store *Store, expected map[string]int) {
	t.Helper()
	for table, want := range expected {
		var count int
		if err := store.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s rows=%d, want %d", table, count, want)
		}
	}
}

func commandTestUUID(index int) string {
	return fmt.Sprintf("01b8e094-9888-7000-8000-%012x", 0x500+index)
}
