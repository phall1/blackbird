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

type productionCommandStep struct {
	operation     application.CommandOperation
	scope         domain.AuthorityScope
	admission     domain.AuthorityScope
	principal     domain.PrincipalID
	authorship    application.CommandAuthorship
	authorization []any
	references    []any
	disclosure    []any
	mutations     []domain.AggregateExpectation
	ceremonies    []application.CeremonyClaim
	genesis       *application.ScopeGenesisAbsence
	evidence      []application.EvidenceGuard
	facts         []domain.IdentityFact
	result        any
	resolveResult func(time.Time) (any, error)
	recovery      bool
	timeClass     application.AuthorityTimeClass
}

func TestExecuteCommandPersistsRemainingW0ProductionAggregatePath(t *testing.T) {
	store := openSecurityStore(t)
	security := newSecurityFixture(t)
	initializeSecurityFixture(t, store, security)
	bootstrapSpec, bootstrapDecide, bootstrap := newBootstrapCommand(t, security)
	mustExecuteProductionCommand(t, store, bootstrapSpec, bootstrapDecide)
	registerSpec, registerDecide, registered := newRegisterPrincipalCommand(t, security, bootstrap)
	mustExecuteProductionCommand(t, store, registerSpec, registerDecide)

	now := time.Now().UTC().Truncate(time.Microsecond)
	policy, _ := domain.NewPolicyRevision("policy:sqlite-production-path:v1")
	assurance, _ := domain.NewAssuranceClass("sqlite-production-strong")
	owner, grant, workload := bootstrap.Principal(), bootstrap.OwnerGrant(), registered.Principal()
	ownerAuthorization, err := domain.NewIdentityAuthorization(
		security.authority, security.epoch, security.invitation.InstallationID(), owner.ID(), grant.Capabilities(),
		policy, assurance, now, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := domain.ParseWorkspaceID(commandTestUUID(100))
	ownerMembershipID, _ := domain.ParseMembershipID(commandTestUUID(101))
	alias, _ := domain.NewWorkspaceAlias("sqlite-production-path")
	discovery, _ := domain.NewDiscoveryLocator("workspace://sqlite-production-path")
	workspaceCapabilities, _ := domain.NewCapabilitySet(
		domain.WorkspaceOwnerCapability(), domain.MembershipAdminCapability(), domain.ActorAdminCapability(),
		domain.DelegationAdminCapability(), domain.DevicePairCapability(),
	)
	createdWorkspace, err := domain.CreateWorkspace(domain.CreateWorkspaceInput{
		Authorization: ownerAuthorization, Owner: owner, ExpectedOwnerVersion: owner.Version(),
		InstallationGrant: grant, ExpectedGrantVersion: grant.Version(), WorkspaceID: workspaceID,
		Alias: alias, DiscoveryLocator: discovery, OwnerMembershipID: ownerMembershipID,
		OwnerCapabilities: workspaceCapabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	workspace := createdWorkspace.Workspace()
	workspaceScope, _ := domain.WorkspaceScope(workspace.ID())
	ownerWorkspaceAuthorization, err := domain.NewWorkspaceIdentityAuthorization(
		security.authority, security.epoch, security.invitation.InstallationID(), workspace.ID(), owner.ID(),
		grant.Capabilities(), policy, assurance, now, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	ownerAuthorship, _ := application.AuthorityAuthorship(owner.ID())
	ownerAdminAuthorship, _ := application.WorkspaceAdminAuthorship(owner.ID(), nil)
	workloadAuthorship, _ := application.AuthorityAuthorship(workload.ID())
	workspaceGenesis, _ := application.AbsentScopeGenesis(workspaceScope, security.authority, security.epoch)

	pairedDeviceID, _ := domain.ParseDeviceID(commandTestUUID(102))
	pairingCeremonyID, _ := domain.ParseCeremonyID(commandTestUUID(103))
	pairingDigest := domain.FingerprintCommand([]byte("sqlite production pairing proof"))
	pairingChallenge, _ := domain.NewDevicePairingChallenge(
		pairingCeremonyID, pairingDigest, now.Add(time.Hour), security.invitation.InstallationID(), owner.ID(), pairedDeviceID,
	)
	pairingCreation, _ := domain.ExpectCeremonyAbsent(pairingCeremonyID)
	pairedDeviceName, _ := domain.NewDisplayName("SQLite production paired device")
	pairedDeviceKey, _ := domain.NewPublicKeyReference("keyref:sqlite-production-paired-device")
	pairingBegan, err := domain.BeginDevicePairing(domain.BeginDevicePairingInput{
		Authorization: ownerAuthorization, Principal: owner, ExpectedPrincipalVersion: owner.Version(),
		DeviceID: pairedDeviceID, DisplayName: pairedDeviceName, PublicKeyReference: pairedDeviceKey,
		Challenge: pairingChallenge, ChallengeCreation: pairingCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	pairingProof, _ := domain.NewCeremonyProof(
		pairingCeremonyID, domain.CeremonyPurposeDevicePairing, pairingDigest, owner.ID(), pairedDeviceID,
	)
	pairedSPKI, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("sqlite production paired spki")))
	pairedCredential, _ := domain.NewDeviceCredentialBinding(pairedDeviceKey, pairedSPKI, pairingDigest)
	pairingRedemption, err := domain.NewPairingRedemptionAuthorization(
		security.authority, security.epoch, security.invitation.InstallationID(), owner.ID(), pairedDeviceID,
		policy, assurance, now, pairingCeremonyID, pairingDigest, pairedCredential,
	)
	if err != nil {
		t.Fatal(err)
	}
	paired, err := domain.PairDevice(domain.PairDeviceInput{
		Authorization: pairingRedemption, CurrentAuthorization: ownerAuthorization, AuthorityTime: now,
		Principal: owner, ExpectedPrincipalVersion: owner.Version(), Device: pairingBegan.Device(),
		ExpectedDeviceVersion: pairingBegan.Device().Version(), ExpectedTrustRevision: pairingBegan.Device().TrustRevision(),
		Proof: pairingProof,
	})
	if err != nil {
		t.Fatal(err)
	}

	memberCapabilities, _ := domain.NewCapabilitySet(domain.WorkspaceOwnerCapability())
	membershipID, _ := domain.ParseMembershipID(commandTestUUID(104))
	membershipCeremonyID, _ := domain.ParseCeremonyID(commandTestUUID(105))
	membershipDigest := domain.FingerprintCommand([]byte("sqlite production membership proof"))
	membershipChallenge, _ := domain.NewMembershipAcceptanceChallenge(
		membershipCeremonyID, membershipDigest, now.Add(time.Hour), workspace.ID(), membershipID, workload.ID(),
	)
	membershipCreation, _ := domain.ExpectCeremonyAbsent(membershipCeremonyID)
	invited, err := domain.InviteWorkspaceMember(domain.InviteWorkspaceMemberInput{
		Authorization: ownerWorkspaceAuthorization, Administrator: owner, ExpectedAdministratorVersion: owner.Version(),
		Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(), Principal: workload,
		ExpectedPrincipalVersion: workload.Version(), MembershipID: membershipID, Capabilities: memberCapabilities,
		Challenge: membershipChallenge, ChallengeCreation: membershipCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	workloadAuthorization, err := domain.NewWorkspaceIdentityAuthorization(
		security.authority, security.epoch, security.invitation.InstallationID(), workspace.ID(), workload.ID(),
		memberCapabilities, policy, assurance, now, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	membershipProof, _ := domain.NewCeremonyProof(
		membershipCeremonyID, domain.CeremonyPurposeMembershipAcceptance, membershipDigest, workload.ID(), domain.DeviceID{},
	)
	accepted, err := domain.AcceptWorkspaceMembership(domain.AcceptWorkspaceMembershipInput{
		Authorization: workloadAuthorization, Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(),
		Principal: workload, ExpectedPrincipalVersion: workload.Version(), Membership: invited.Membership(),
		ExpectedMembershipVersion: invited.Membership().Version(), Proof: membershipProof,
	})
	if err != nil {
		t.Fatal(err)
	}

	actorID, _ := domain.ParseActorID(commandTestUUID(106))
	actorName, _ := domain.NewDisplayName("SQLite production actor")
	actorProfile, _ := domain.NewActorProfile(actorName)
	createdActor, err := domain.CreateActor(domain.CreateActorInput{
		Authorization: ownerWorkspaceAuthorization, Administrator: owner, ExpectedAdministratorVersion: owner.Version(),
		Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(), ActorID: actorID,
		Kind: domain.ActorKindAgent, Profile: actorProfile,
	})
	if err != nil {
		t.Fatal(err)
	}

	delegationID, _ := domain.ParseActorDelegationID(commandTestUUID(107))
	delegationCeremonyID, _ := domain.ParseCeremonyID(commandTestUUID(108))
	delegationDigest := domain.FingerprintCommand([]byte("sqlite production delegation proof"))
	delegationChallenge, _ := domain.NewDelegationActivationChallenge(
		delegationCeremonyID, delegationDigest, now.Add(time.Hour), workspace.ID(), delegationID, workload.ID(), actorID,
	)
	delegationCreation, _ := domain.ExpectCeremonyAbsent(delegationCeremonyID)
	proposed, err := domain.ProposeActorDelegation(domain.ProposeActorDelegationInput{
		Authorization: ownerWorkspaceAuthorization, Administrator: owner, ExpectedAdministratorVersion: owner.Version(),
		Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(), Principal: workload,
		ExpectedPrincipalVersion: workload.Version(), Actor: createdActor.Actor(),
		ExpectedActorVersion: createdActor.Actor().Version(), Membership: accepted.Membership(),
		ExpectedMembershipVersion: accepted.Membership().Version(), DelegationID: delegationID,
		Capabilities: memberCapabilities, Challenge: delegationChallenge, ChallengeCreation: delegationCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	delegationProof, _ := domain.NewCeremonyProof(
		delegationCeremonyID, domain.CeremonyPurposeDelegationActivation, delegationDigest, workload.ID(), domain.DeviceID{},
	)
	sessionCeremonyID, _ := domain.ParseCeremonyID(commandTestUUID(109))
	sessionDigest := domain.FingerprintCommand([]byte("sqlite production session proof"))
	sessionChallenge, _ := domain.NewSessionStartChallenge(
		sessionCeremonyID, sessionDigest, now.Add(time.Hour), workspace.ID(), delegationID, workload.ID(), actorID,
	)
	sessionCreation, _ := domain.ExpectCeremonyAbsent(sessionCeremonyID)
	activated, err := domain.ActivateActorDelegation(domain.ActivateActorDelegationInput{
		Authorization: workloadAuthorization, Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(),
		Principal: workload, ExpectedPrincipalVersion: workload.Version(), Actor: createdActor.Actor(),
		ExpectedActorVersion: createdActor.Actor().Version(), Membership: accepted.Membership(),
		ExpectedMembershipVersion: accepted.Membership().Version(), Delegation: proposed.Delegation(),
		ExpectedDelegationVersion: proposed.Delegation().Version(), Proof: delegationProof,
		SessionStartChallenge: sessionChallenge, SessionChallengeCreation: sessionCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionProof, _ := domain.NewCeremonyProof(
		sessionCeremonyID, domain.CeremonyPurposeActorSessionStart, sessionDigest, workload.ID(), domain.DeviceID{},
	)
	handoff, _ := domain.HandoffSessionStart(sessionChallenge, sessionProof)
	sessionID, _ := domain.ParseActorSessionID(commandTestUUID(110))
	sessionClientID, _ := domain.ParseClientInstanceID(commandTestUUID(111))
	clientMetadata, _ := domain.NewClientMetadata("sqlite-production-agent", "1.0.0")
	credentialReference, _ := domain.NewCredentialReference("credential-ref:sqlite-production-session")
	credentialAudience, _ := domain.NewCredentialAudience("blackbird:sqlite-production")
	presentationDigest, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("sqlite production presentation")))
	presentation, _ := domain.NewPresentationCredentialBinding(
		presentationDigest, credentialReference, credentialAudience, domain.PresentationCredentialVersion,
	)
	sessionStarted, err := domain.StartActorSession(domain.StartActorSessionInput{
		Authorization: workloadAuthorization, SessionID: sessionID, ClientInstanceID: sessionClientID,
		ClientMetadata: clientMetadata, Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(),
		Principal: workload, ExpectedPrincipalVersion: workload.Version(), Membership: accepted.Membership(),
		ExpectedMembershipVersion: accepted.Membership().Version(), Actor: createdActor.Actor(),
		ExpectedActorVersion: createdActor.Actor().Version(), Delegation: activated.Delegation(),
		ExpectedDelegationVersion: activated.Delegation().Version(), StartAuthority: handoff,
		AbsoluteExpiry: now.Add(8 * time.Hour), PresentationCredential: presentation,
	})
	if err != nil {
		t.Fatal(err)
	}

	installationAuthority := mustAuthorityEvidence(t, security.scope, security.authority, security.epoch)
	installationPolicy := mustPolicyEvidence(t, security.scope, policy)
	workspaceAuthority := mustAuthorityEvidence(t, workspaceScope, security.authority, security.epoch)
	workspacePolicy := mustPolicyEvidence(t, workspaceScope, policy)
	steps := []productionCommandStep{
		{
			operation: application.CommandCreateWorkspace, scope: workspaceScope, admission: security.scope,
			principal: owner.ID(), authorship: ownerAuthorship, authorization: []any{owner, grant},
			disclosure: []any{owner, workspace}, mutations: []domain.AggregateExpectation{
				mustAbsentExpectation(t, workspace.ID()), mustAbsentExpectation(t, createdWorkspace.OwnerMembership().ID()),
			}, genesis: &workspaceGenesis, evidence: []application.EvidenceGuard{
				installationAuthority, installationPolicy, mustLifecycleEvidence(t, owner), mustLifecycleEvidence(t, grant),
				mustCeilingEvidence(t, grant, "workspace-create"),
			}, facts: createdWorkspace.Facts(), result: createdWorkspace, recovery: true,
		},
		{
			operation: application.CommandBeginDevicePairing, scope: security.scope, admission: security.scope,
			principal: owner.ID(), authorship: ownerAuthorship, authorization: []any{owner, grant},
			disclosure: []any{owner, pairingBegan.Device()}, mutations: []domain.AggregateExpectation{mustAbsentExpectation(t, pairedDeviceID)},
			ceremonies: []application.CeremonyClaim{mustReserveCeremony(t, pairingChallenge, pairingBegan.Device())},
			evidence: []application.EvidenceGuard{installationAuthority, installationPolicy, mustLifecycleEvidence(t, owner),
				mustLifecycleEvidence(t, grant), mustCeilingEvidence(t, grant, "pairing")},
			facts: pairingBegan.Facts(), result: pairingBegan, recovery: true,
			timeClass: application.AuthorityTimeIssuesExpiringAuthority,
		},
		{
			operation: application.CommandPairDevice, scope: security.scope, admission: security.scope,
			principal: owner.ID(), authorship: ownerAuthorship, authorization: []any{owner},
			disclosure: []any{owner, pairingBegan.Device()}, mutations: []domain.AggregateExpectation{mustVersionExpectation(t, pairingBegan.Device())},
			ceremonies: []application.CeremonyClaim{mustConsumeCeremony(t, pairingChallenge, pairingBegan.Device())},
			evidence: []application.EvidenceGuard{installationAuthority, installationPolicy, mustLifecycleEvidence(t, owner),
				mustLifecycleEvidence(t, pairingBegan.Device()), mustTrustEvidence(t, pairingBegan.Device())},
			facts: paired.Facts(), result: paired,
		},
		{
			operation: application.CommandInviteWorkspaceMember, scope: workspaceScope, admission: workspaceScope,
			principal: owner.ID(), authorship: ownerAdminAuthorship, authorization: []any{owner, workspace}, references: []any{workload},
			disclosure: []any{owner, workspace, invited.Membership()}, mutations: []domain.AggregateExpectation{mustAbsentExpectation(t, membershipID)},
			ceremonies: []application.CeremonyClaim{mustReserveCeremony(t, membershipChallenge, invited.Membership())},
			evidence: []application.EvidenceGuard{workspaceAuthority, workspacePolicy, mustLifecycleEvidence(t, owner),
				mustLifecycleEvidence(t, workspace), mustLifecycleEvidence(t, workload), mustCeilingEvidence(t, owner, "membership")},
			facts: invited.Facts(), result: invited, recovery: true, timeClass: application.AuthorityTimeIssuesExpiringAuthority,
		},
		{
			operation: application.CommandAcceptWorkspaceMembership, scope: workspaceScope, admission: workspaceScope,
			principal: workload.ID(), authorship: workloadAuthorship, authorization: []any{workload}, references: []any{workspace},
			disclosure: []any{workload, workspace, invited.Membership()}, mutations: []domain.AggregateExpectation{mustVersionExpectation(t, invited.Membership())},
			ceremonies: []application.CeremonyClaim{mustConsumeCeremony(t, membershipChallenge, invited.Membership())},
			evidence: []application.EvidenceGuard{workspaceAuthority, workspacePolicy, mustLifecycleEvidence(t, workload),
				mustLifecycleEvidence(t, workspace), mustLifecycleEvidence(t, invited.Membership())},
			facts: accepted.Facts(), result: accepted,
		},
		{
			operation: application.CommandCreateActor, scope: workspaceScope, admission: workspaceScope,
			principal: owner.ID(), authorship: ownerAdminAuthorship, authorization: []any{owner, workspace},
			disclosure: []any{owner, workspace, createdActor.Actor()}, mutations: []domain.AggregateExpectation{mustAbsentExpectation(t, actorID)},
			evidence: []application.EvidenceGuard{workspaceAuthority, workspacePolicy, mustLifecycleEvidence(t, owner), mustLifecycleEvidence(t, workspace)},
			facts:    createdActor.Facts(), result: createdActor, recovery: true,
		},
		{
			operation: application.CommandProposeActorDelegation, scope: workspaceScope, admission: workspaceScope,
			principal: owner.ID(), authorship: ownerAdminAuthorship, authorization: []any{owner, workspace},
			references: []any{workload, createdActor.Actor(), accepted.Membership()}, disclosure: []any{owner, workspace, proposed.Delegation()},
			mutations:  []domain.AggregateExpectation{mustAbsentExpectation(t, delegationID)},
			ceremonies: []application.CeremonyClaim{mustReserveCeremony(t, delegationChallenge, proposed.Delegation())},
			evidence: []application.EvidenceGuard{workspaceAuthority, workspacePolicy, mustLifecycleEvidence(t, owner),
				mustLifecycleEvidence(t, workspace), mustLifecycleEvidence(t, workload), mustLifecycleEvidence(t, createdActor.Actor()),
				mustLifecycleEvidence(t, accepted.Membership()), mustCeilingEvidence(t, accepted.Membership(), "delegation")},
			facts: proposed.Facts(), result: proposed, recovery: true, timeClass: application.AuthorityTimeIssuesExpiringAuthority,
		},
		{
			operation: application.CommandActivateActorDelegation, scope: workspaceScope, admission: workspaceScope,
			principal: workload.ID(), authorship: workloadAuthorship, authorization: []any{workload},
			references: []any{workspace, createdActor.Actor(), accepted.Membership()}, disclosure: []any{workload, workspace, proposed.Delegation()},
			mutations: []domain.AggregateExpectation{mustVersionExpectation(t, proposed.Delegation())},
			ceremonies: []application.CeremonyClaim{mustConsumeCeremony(t, delegationChallenge, proposed.Delegation()),
				mustReserveCeremony(t, sessionChallenge, proposed.Delegation())},
			evidence: []application.EvidenceGuard{workspaceAuthority, workspacePolicy, mustLifecycleEvidence(t, workload),
				mustLifecycleEvidence(t, workspace), mustLifecycleEvidence(t, createdActor.Actor()), mustLifecycleEvidence(t, accepted.Membership()),
				mustLifecycleEvidence(t, proposed.Delegation()), mustCeilingEvidence(t, accepted.Membership(), "activation")},
			facts: activated.Facts(), result: activated, recovery: true, timeClass: application.AuthorityTimeIssuesExpiringAuthority,
		},
		{
			operation: application.CommandStartActorSession, scope: workspaceScope, admission: workspaceScope,
			principal: workload.ID(), authorship: workloadAuthorship,
			authorization: []any{workload, workspace, accepted.Membership(), createdActor.Actor(), activated.Delegation()},
			disclosure:    []any{workload, workspace, sessionStarted.Session()}, mutations: []domain.AggregateExpectation{mustAbsentExpectation(t, sessionID)},
			ceremonies: []application.CeremonyClaim{mustConsumeStandaloneCeremony(t, sessionChallenge)},
			evidence: []application.EvidenceGuard{workspaceAuthority, workspacePolicy, mustLifecycleEvidence(t, workload),
				mustLifecycleEvidence(t, workspace), mustLifecycleEvidence(t, accepted.Membership()), mustLifecycleEvidence(t, createdActor.Actor()),
				mustLifecycleEvidence(t, activated.Delegation()), mustCeilingEvidence(t, accepted.Membership(), "session-membership"),
				mustCeilingEvidence(t, activated.Delegation(), "session-delegation"), mustConstraintEvidence(t, sessionStarted.Session(), "session")},
			facts: sessionStarted.Facts(), recovery: true,
			resolveResult: func(authorityTime time.Time) (any, error) {
				authorization, err := domain.NewWorkspaceIdentityAuthorization(
					security.authority, security.epoch, security.invitation.InstallationID(), workspace.ID(), workload.ID(),
					memberCapabilities, policy, assurance, authorityTime, domain.MaxActorSessionLifetime,
				)
				if err != nil {
					return nil, err
				}
				return domain.StartActorSession(domain.StartActorSessionInput{
					Authorization: authorization, SessionID: sessionID, ClientInstanceID: sessionClientID,
					ClientMetadata: clientMetadata, Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(),
					Principal: workload, ExpectedPrincipalVersion: workload.Version(), Membership: accepted.Membership(),
					ExpectedMembershipVersion: accepted.Membership().Version(), Actor: createdActor.Actor(),
					ExpectedActorVersion: createdActor.Actor().Version(), Delegation: activated.Delegation(),
					ExpectedDelegationVersion: activated.Delegation().Version(), StartAuthority: handoff,
					AbsoluteExpiry: authorityTime.Add(8 * time.Hour), PresentationCredential: presentation,
				})
			},
			timeClass: application.AuthorityTimeIssuesExpiringAuthority,
		},
	}

	for index, step := range steps {
		t.Run(string(step.operation), func(t *testing.T) {
			spec := newProductionCommandSpec(t, security, step, index)
			execution := executeProductionStep(t, store, spec, step, index)
			if execution.Kind() != application.CommandTransactionCommitted {
				t.Fatalf("execution kind=%q", execution.Kind())
			}
			receipt, present := execution.Receipt()
			if !present || receipt.CommandID() != spec.CommandID() ||
				receipt.Result().Operation() != step.operation || receipt.Events().Count() != uint16(len(step.facts)) {
				t.Fatal("committed execution did not expose the expected receipt and event range")
			}
			var receiptRows, eventRows, auditRows int
			if err := store.db.QueryRow(`SELECT count(*) FROM command_receipts WHERE command_id = ?`, spec.CommandID().String()).Scan(&receiptRows); err != nil {
				t.Fatal(err)
			}
			if err := store.db.QueryRow(`SELECT count(*) FROM domain_events WHERE command_id = ?`, spec.CommandID().String()).Scan(&eventRows); err != nil {
				t.Fatal(err)
			}
			if err := store.db.QueryRow(`SELECT count(*) FROM audit_entries`).Scan(&auditRows); err != nil {
				t.Fatal(err)
			}
			if receiptRows != 1 || eventRows != len(step.facts) || auditRows != index+4 {
				t.Fatalf("persisted command rows receipt=%d events=%d total_audit=%d", receiptRows, eventRows, auditRows)
			}
			replay, err := store.ExecuteCommand(context.Background(), spec, func(locked application.CommandContext) (application.CommandDecision, error) {
				return application.ReplayCommand(locked, application.ReplayDiscloseResult)
			})
			if err != nil || replay.Kind() != application.CommandTransactionReplayed {
				t.Fatalf("replay kind=%q error=%v", replay.Kind(), err)
			}
			replayedReceipt, present := replay.Receipt()
			if !present || replayedReceipt.CommandID() != receipt.CommandID() ||
				replayedReceipt.Result().ResponseDigest() != receipt.Result().ResponseDigest() {
				t.Fatal("replay did not return the original committed receipt")
			}
		})
	}

	assertCommandRowCounts(t, store, map[string]int{
		"workspaces": 1, "workspace_memberships": 2, "actors": 1, "actor_delegations": 1,
		"actor_sessions": 1, "device_registrations": 2, "ceremony_challenges": 4,
		"command_receipts": 11, "domain_events": 15, "audit_entries": 12,
	})
	var membershipStatus, delegationStatus, sessionStatus string
	var membershipVersion, delegationVersion, sessionVersion uint64
	if err := store.db.QueryRow(`SELECT status, version FROM workspace_memberships WHERE membership_id = ?`, membershipID.String()).Scan(&membershipStatus, &membershipVersion); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT status, version FROM actor_delegations WHERE delegation_id = ?`, delegationID.String()).Scan(&delegationStatus, &delegationVersion); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT status, version FROM actor_sessions WHERE session_id = ?`, sessionID.String()).Scan(&sessionStatus, &sessionVersion); err != nil {
		t.Fatal(err)
	}
	if membershipStatus != string(domain.MembershipActive) || membershipVersion != 2 ||
		delegationStatus != string(domain.DelegationActive) || delegationVersion != 2 ||
		sessionStatus != string(domain.ActorSessionActive) || sessionVersion != 1 {
		t.Fatalf("normalized lifecycle membership=(%s,%d) delegation=(%s,%d) session=(%s,%d)",
			membershipStatus, membershipVersion, delegationStatus, delegationVersion, sessionStatus, sessionVersion)
	}
	var pending, consumed int
	if err := store.db.QueryRow(`SELECT count(*) FROM ceremony_challenges WHERE status = 'pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT count(*) FROM ceremony_challenges WHERE status = 'consumed'`).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || consumed != 4 {
		t.Fatalf("ceremonies pending=%d consumed=%d", pending, consumed)
	}
	var nextEvents, nextAudit uint64
	if err := store.db.QueryRow(`SELECT next_sequence, next_audit_sequence FROM authority_streams WHERE scope_kind = 'workspace' AND scope_id = ?`, workspace.ID().String()).Scan(&nextEvents, &nextAudit); err != nil {
		t.Fatal(err)
	}
	if nextEvents != 10 || nextAudit != 8 {
		t.Fatalf("workspace stream cursors=(%d,%d), want (10,8)", nextEvents, nextAudit)
	}
	var clientName, clientVersion, credentialRef, audience string
	var issuedAt, expiresAt int64
	if err := store.db.QueryRow(`SELECT client_name, client_version, presentation_credential_reference,
		presentation_credential_audience, issued_at_us, expires_at_us FROM actor_sessions WHERE session_id = ?`, sessionID.String()).Scan(
		&clientName, &clientVersion, &credentialRef, &audience, &issuedAt, &expiresAt,
	); err != nil {
		t.Fatal(err)
	}
	if clientName != clientMetadata.Name() || clientVersion != clientMetadata.Version() ||
		credentialRef != credentialReference.String() || audience != credentialAudience.String() || issuedAt <= 0 || expiresAt <= issuedAt {
		t.Fatal("actor session fields did not round-trip through normalized storage")
	}
}

func mustExecuteProductionCommand(
	t *testing.T,
	store *Store,
	spec application.CommandSpec,
	decide func(application.CommandContext) (application.CommandDecision, error),
) application.CommandTransactionExecution {
	t.Helper()
	execution, err := store.ExecuteCommand(context.Background(), spec, decide)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Kind() != application.CommandTransactionCommitted {
		t.Fatalf("execution kind=%q, want committed", execution.Kind())
	}
	return execution
}

func newProductionCommandSpec(
	t *testing.T,
	security securityFixture,
	step productionCommandStep,
	index int,
) application.CommandSpec {
	t.Helper()
	operation, err := domain.NewOperationName(string(step.operation))
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := domain.ParseClientInstanceID(commandTestUUID(220 + index*10))
	if err != nil {
		t.Fatal(err)
	}
	key, err := domain.NewIdempotencyKey(fmt.Sprintf("sqlite-production-%02d", index))
	if err != nil {
		t.Fatal(err)
	}
	var receiptIdentity application.ReceiptIdentity
	if step.scope.Kind() == domain.ScopeKindInstallation {
		receiptIdentity, err = application.InstallationAdminReceiptIdentity(
			security.invitation.InstallationID(), step.principal, clientID, operation, key,
		)
	} else {
		workspaceID, parseErr := domain.ParseWorkspaceID(step.scope.ID())
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		idempotency, scopeErr := domain.NewIdempotencyScope(workspaceID, step.principal, clientID, operation, key)
		if scopeErr != nil {
			t.Fatal(scopeErr)
		}
		receiptIdentity, err = application.OrdinaryReceiptIdentity(idempotency)
	}
	if err != nil {
		t.Fatal(err)
	}
	authorization := productionAggregateRefs(t, step.authorization)
	references := productionAggregateRefs(t, step.references)
	disclosure := productionAggregateTargets(t, step.disclosure)
	guardPlan, err := application.NewCommandGuardPlan(application.CommandGuardPlanParams{
		AdmissionScope: step.admission, AdmissionGeneration: security.admission,
		Evidence: step.evidence, Authorization: authorization, References: references,
		Disclosure: disclosure, Mutations: step.mutations, Ceremonies: step.ceremonies, Genesis: step.genesis,
	})
	if err != nil {
		t.Fatalf("guard plan for %s: %v", step.operation, err)
	}
	expectedFacts := make([]application.FactExpectation, len(step.facts))
	for factIndex, fact := range step.facts {
		eventID, parseErr := domain.ParseEventID(commandTestUUID(300 + index*10 + factIndex))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		expectedFacts[factIndex], err = application.NewFactExpectation(eventID, fact.Type(), fact.Origin())
		if err != nil {
			t.Fatal(err)
		}
	}
	recovery := application.NotApplicableRecoveryCapsulePlan()
	if step.recovery {
		seed := sha256.Sum256([]byte("sqlite production capsule:" + string(step.operation)))
		recovery, err = application.PrepareRecoveryCapsulePlan(commandTestSigner{private: ed25519.NewKeyFromSeed(seed[:])})
		if err != nil {
			t.Fatal(err)
		}
	}
	major, _ := application.NewOperationMajor(1)
	commandID := mustCommandID(t, 221+index*10)
	receiptID := mustReceiptID(t, 222+index*10)
	correlationID, err := domain.ParseCorrelationID(commandTestUUID(223 + index*10))
	if err != nil {
		t.Fatal(err)
	}
	timeClass := step.timeClass
	if timeClass == "" {
		timeClass = application.AuthorityTimeOrdinary
	}
	spec, err := application.NewCommandSpec(application.CommandSpecParams{
		Scope: step.scope, AuthorityID: security.authority, RequestedEpoch: security.epoch,
		CommandID: commandID, ReceiptID: receiptID, Operation: operation, OperationMajor: major,
		ReceiptIdentity:    receiptIdentity,
		RequestFingerprint: domain.FingerprintCommand([]byte("sqlite production command:" + string(step.operation))),
		Authorship:         step.authorship, CorrelationID: correlationID, AuthorityTimeClass: timeClass,
		RecoveryCapsule: recovery, Guards: guardPlan, ExpectedFacts: expectedFacts,
	})
	if err != nil {
		t.Fatalf("command spec for %s: %v", step.operation, err)
	}
	return spec
}

func executeProductionStep(
	t *testing.T,
	store *Store,
	spec application.CommandSpec,
	step productionCommandStep,
	index int,
) application.CommandTransactionExecution {
	t.Helper()
	return mustExecuteProductionCommand(t, store, spec, func(locked application.CommandContext) (application.CommandDecision, error) {
		var (
			commit application.OperationCommit
			err    error
		)
		authorityTime, present := locked.AuthorityTime()
		if !present {
			return application.CommandDecision{}, fmt.Errorf("persisted authority time absent")
		}
		result := step.result
		if step.resolveResult != nil {
			result, err = step.resolveResult(authorityTime)
			if err != nil {
				return application.CommandDecision{}, fmt.Errorf("resolve %s result: %w", step.operation, err)
			}
		}
		switch result := result.(type) {
		case domain.CreateWorkspaceResult:
			commit, err = application.CreateWorkspaceCommit(locked, result)
		case domain.BeginDevicePairingResult:
			commit, err = application.BeginDevicePairingCommit(locked, result)
		case domain.PairDeviceResult:
			commit, err = application.PairDeviceCommit(locked, result)
		case domain.InviteWorkspaceMemberResult:
			commit, err = application.InviteWorkspaceMemberCommit(locked, result)
		case domain.AcceptWorkspaceMembershipResult:
			commit, err = application.AcceptWorkspaceMembershipCommit(locked, result)
		case domain.CreateActorResult:
			commit, err = application.CreateActorCommit(locked, result)
		case domain.ProposeActorDelegationResult:
			commit, err = application.ProposeActorDelegationCommit(locked, result)
		case domain.ActivateActorDelegationResult:
			commit, err = application.ActivateActorDelegationCommit(locked, result)
		case domain.StartActorSessionResult:
			commit, err = application.StartActorSessionCommit(locked, result)
		default:
			return application.CommandDecision{}, fmt.Errorf("unsupported production result %T", result)
		}
		if err != nil {
			return application.CommandDecision{}, fmt.Errorf("commit %s: %w", step.operation, err)
		}
		audit, err := application.NewAuditIntent(
			spec.Operation(), application.AuditCommandApplied, spec.RequestFingerprint(), application.CommandAppliedAuditDetail(),
		)
		if err != nil {
			return application.CommandDecision{}, err
		}
		request, err := application.NewAuditRequestContext(
			fmt.Sprintf("sqlite-production-request-%02d", index),
			fmt.Sprintf("sqlite-production-trace-%02d", index), authorityTime, nil,
		)
		if err != nil {
			return application.CommandDecision{}, err
		}
		provenance, err := application.NewAuditProvenanceEvidence(spec.AuthorityID(), nil)
		if err != nil {
			return application.CommandDecision{}, err
		}
		authentication, err := application.NewAuthenticationEvidence(step.principal, nil, provenance)
		if err != nil {
			return application.CommandDecision{}, err
		}
		audit, err = application.BindCommandAuditContext(audit, spec, request, authentication)
		if err != nil {
			return application.CommandDecision{}, err
		}
		effects, err := application.NewEffectSet()
		if err != nil {
			return application.CommandDecision{}, err
		}
		decision, err := application.ApplyCommand(locked, commit, audit, effects)
		if err != nil {
			return application.CommandDecision{}, fmt.Errorf("apply %s: %w", step.operation, err)
		}
		if err := application.ValidateCommandDecision(locked, decision); err != nil {
			return application.CommandDecision{}, fmt.Errorf("validate %s: %w", step.operation, err)
		}
		return decision, nil
	})
}

func productionAggregateRefs(t *testing.T, values []any) []domain.AggregateRef {
	t.Helper()
	refs := make([]domain.AggregateRef, len(values))
	for index, value := range values {
		state, err := application.NewIdentityState(value)
		if err != nil {
			t.Fatal(err)
		}
		refs[index], err = productionAggregateRef(value, state.Version())
		if err != nil {
			t.Fatal(err)
		}
	}
	return refs
}

func productionAggregateTargets(t *testing.T, values []any) []domain.AggregateTarget {
	t.Helper()
	targets := make([]domain.AggregateTarget, len(values))
	for index, value := range values {
		state, err := application.NewIdentityState(value)
		if err != nil {
			t.Fatal(err)
		}
		targets[index] = state.Target()
	}
	return targets
}

func mustAbsentExpectation(t *testing.T, id any) domain.AggregateExpectation {
	t.Helper()
	var (
		expectation domain.AggregateExpectation
		err         error
	)
	switch id := id.(type) {
	case domain.WorkspaceID:
		expectation, err = domain.ExpectAggregateAbsent(id)
	case domain.MembershipID:
		expectation, err = domain.ExpectAggregateAbsent(id)
	case domain.DeviceID:
		expectation, err = domain.ExpectAggregateAbsent(id)
	case domain.ActorID:
		expectation, err = domain.ExpectAggregateAbsent(id)
	case domain.ActorDelegationID:
		expectation, err = domain.ExpectAggregateAbsent(id)
	case domain.ActorSessionID:
		expectation, err = domain.ExpectAggregateAbsent(id)
	default:
		t.Fatalf("unsupported aggregate identifier %T", id)
	}
	if err != nil {
		t.Fatal(err)
	}
	return expectation
}

func mustVersionExpectation(t *testing.T, value any) domain.AggregateExpectation {
	t.Helper()
	state, err := application.NewIdentityState(value)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := productionAggregateRef(value, state.Version())
	if err != nil {
		t.Fatal(err)
	}
	switch value := value.(type) {
	case domain.PrincipalState:
		return mustExpectedVersion(t, value.ID(), ref.Version())
	case domain.DeviceState:
		return mustExpectedVersion(t, value.ID(), ref.Version())
	case domain.GrantState:
		return mustExpectedVersion(t, value.ID(), ref.Version())
	case domain.WorkspaceState:
		return mustExpectedVersion(t, value.ID(), ref.Version())
	case domain.MembershipState:
		return mustExpectedVersion(t, value.ID(), ref.Version())
	case domain.ActorState:
		return mustExpectedVersion(t, value.ID(), ref.Version())
	case domain.ActorDelegationState:
		return mustExpectedVersion(t, value.ID(), ref.Version())
	case domain.ActorSessionState:
		return mustExpectedVersion(t, value.ID(), ref.Version())
	default:
		t.Fatalf("unsupported versioned aggregate %T", value)
		return domain.AggregateExpectation{}
	}
}

func mustAuthorityEvidence(t *testing.T, scope domain.AuthorityScope, authority domain.AuthorityID, epoch domain.AuthorityEpoch) application.EvidenceGuard {
	t.Helper()
	guard, err := application.CurrentAuthorityEpochGuard(scope, authority, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func mustPolicyEvidence(t *testing.T, scope domain.AuthorityScope, policy domain.PolicyRevision) application.EvidenceGuard {
	t.Helper()
	guard, err := application.PolicyRevisionGuard(scope, policy)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func mustLifecycleEvidence(t *testing.T, value any) application.EvidenceGuard {
	t.Helper()
	state, err := application.NewIdentityState(value)
	if err != nil {
		t.Fatal(err)
	}
	var status string
	switch value := value.(type) {
	case domain.PrincipalState:
		status = string(value.Status())
	case domain.DeviceState:
		status = string(value.Status())
	case domain.GrantState:
		status = string(value.Status())
	case domain.WorkspaceState:
		status = string(value.Status())
	case domain.MembershipState:
		status = string(value.Status())
	case domain.ActorState:
		status = string(value.Status())
	case domain.ActorDelegationState:
		status = string(value.Status())
	case domain.ActorSessionState:
		status = string(value.Status())
	default:
		t.Fatalf("unsupported lifecycle state %T", value)
	}
	guard, err := application.LifecycleStatusGuard(state.Target(), status)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func mustTrustEvidence(t *testing.T, device domain.DeviceState) application.EvidenceGuard {
	t.Helper()
	guard, err := application.DeviceTrustRevisionGuard(device.ID(), device.TrustRevision())
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func mustCeilingEvidence(t *testing.T, value any, label string) application.EvidenceGuard {
	t.Helper()
	state, err := application.NewIdentityState(value)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := application.CapabilityCeilingGuard(state.Target(), application.DigestBytes([]byte(label)))
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func mustConstraintEvidence(t *testing.T, value any, label string) application.EvidenceGuard {
	t.Helper()
	state, err := application.NewIdentityState(value)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := application.ResourceConstraintGuard(state.Target(), application.DigestBytes([]byte(label)))
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func mustReserveCeremony(t *testing.T, challenge domain.CeremonyChallenge, owner any) application.CeremonyClaim {
	t.Helper()
	state, err := application.NewIdentityState(owner)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := application.ReserveCeremony(challenge, state.Target())
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func mustConsumeCeremony(t *testing.T, challenge domain.CeremonyChallenge, owner any) application.CeremonyClaim {
	t.Helper()
	state, err := application.NewIdentityState(owner)
	if err != nil {
		t.Fatal(err)
	}
	ownerRef, err := productionAggregateRef(owner, state.Version())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := application.ConsumeEmbeddedCeremony(
		challenge.ID(), challenge.Purpose(), challenge.ProofDigest(), ownerRef,
	)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func productionAggregateRef(value any, version domain.Version) (domain.AggregateRef, error) {
	switch value := value.(type) {
	case domain.InstallationInvitationState:
		return domain.NewAggregateRef(value.ID(), version)
	case domain.PrincipalState:
		return domain.NewAggregateRef(value.ID(), version)
	case domain.DeviceState:
		return domain.NewAggregateRef(value.ID(), version)
	case domain.GrantState:
		return domain.NewAggregateRef(value.ID(), version)
	case domain.WorkspaceState:
		return domain.NewAggregateRef(value.ID(), version)
	case domain.MembershipState:
		return domain.NewAggregateRef(value.ID(), version)
	case domain.ActorState:
		return domain.NewAggregateRef(value.ID(), version)
	case domain.ActorDelegationState:
		return domain.NewAggregateRef(value.ID(), version)
	case domain.ActorSessionState:
		return domain.NewAggregateRef(value.ID(), version)
	default:
		return domain.AggregateRef{}, fmt.Errorf("unsupported aggregate state %T", value)
	}
}

func mustExpectedVersion[ID interface {
	domain.PrincipalID | domain.DeviceID | domain.GrantID | domain.WorkspaceID | domain.MembershipID |
		domain.ActorID | domain.ActorDelegationID | domain.ActorSessionID
}](t *testing.T, id ID, version domain.Version) domain.AggregateExpectation {
	t.Helper()
	var (
		expectation domain.AggregateExpectation
		err         error
	)
	switch id := any(id).(type) {
	case domain.PrincipalID:
		expectation, err = domain.ExpectAggregateVersion(id, version)
	case domain.DeviceID:
		expectation, err = domain.ExpectAggregateVersion(id, version)
	case domain.GrantID:
		expectation, err = domain.ExpectAggregateVersion(id, version)
	case domain.WorkspaceID:
		expectation, err = domain.ExpectAggregateVersion(id, version)
	case domain.MembershipID:
		expectation, err = domain.ExpectAggregateVersion(id, version)
	case domain.ActorID:
		expectation, err = domain.ExpectAggregateVersion(id, version)
	case domain.ActorDelegationID:
		expectation, err = domain.ExpectAggregateVersion(id, version)
	case domain.ActorSessionID:
		expectation, err = domain.ExpectAggregateVersion(id, version)
	}
	if err != nil {
		t.Fatal(err)
	}
	return expectation
}

func mustConsumeStandaloneCeremony(t *testing.T, challenge domain.CeremonyChallenge) application.CeremonyClaim {
	t.Helper()
	claim, err := application.ConsumeStandaloneCeremony(challenge.ID(), challenge.Purpose(), challenge.ProofDigest())
	if err != nil {
		t.Fatal(err)
	}
	return claim
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
