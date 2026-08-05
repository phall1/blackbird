package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

type authenticationFixture struct {
	workspaceScope domain.AuthorityScope
	policy         domain.PolicyRevision
	assurance      domain.AssuranceClass
	owner          domain.PrincipalState
	ownerDevice    domain.DeviceState
	pairedSPKI     domain.CredentialDigest
	workload       domain.PrincipalState
	session        domain.ActorSessionState
	audience       domain.CredentialAudience
	authority      domain.AuthorityID
	epoch          domain.AuthorityEpoch
}

func buildAuthenticationFixture(t *testing.T, store *Store, security securityFixture) authenticationFixture {
	t.Helper()
	initializeSecurityFixture(t, store, security)
	bootstrapSpec, bootstrapDecide, bootstrap := newBootstrapCommand(t, security)
	mustExecuteProductionCommand(t, store, bootstrapSpec, bootstrapDecide)
	registerSpec, registerDecide, registered := newRegisterPrincipalCommand(t, security, bootstrap)
	mustExecuteProductionCommand(t, store, registerSpec, registerDecide)

	now := time.Now().UTC().Truncate(time.Microsecond)
	policy, _ := domain.NewPolicyRevision("policy:authentication-resolver:v1")
	assurance, _ := domain.NewAssuranceClass("authentication-resolver-strong")
	owner, grant, workload := bootstrap.Principal(), bootstrap.OwnerGrant(), registered.Principal()
	ownerAuthorization, err := domain.NewIdentityAuthorization(
		security.authority, security.epoch, security.invitation.InstallationID(), owner.ID(), grant.Capabilities(),
		policy, assurance, now, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := domain.ParseWorkspaceID(security.uuid(400))
	ownerMembershipID, _ := domain.ParseMembershipID(security.uuid(401))
	alias, _ := domain.NewWorkspaceAlias("authentication-resolver")
	discovery, _ := domain.NewDiscoveryLocator("workspace://authentication-resolver")
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

	pairedDeviceID, _ := domain.ParseDeviceID(security.uuid(402))
	pairingCeremonyID, _ := domain.ParseCeremonyID(security.uuid(403))
	pairingDigest := domain.FingerprintCommand([]byte("authentication resolver pairing proof"))
	pairingChallenge, _ := domain.NewDevicePairingChallenge(
		pairingCeremonyID, pairingDigest, now.Add(time.Hour), security.invitation.InstallationID(), owner.ID(), pairedDeviceID,
	)
	pairingCreation, _ := domain.ExpectCeremonyAbsent(pairingCeremonyID)
	pairedDeviceName, _ := domain.NewDisplayName("Authentication resolver paired device")
	pairedDeviceKey, _ := domain.NewPublicKeyReference("keyref:authentication-resolver-paired-device")
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
	pairedSPKI, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("authentication resolver paired spki")))
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
	membershipID, _ := domain.ParseMembershipID(security.uuid(404))
	membershipCeremonyID, _ := domain.ParseCeremonyID(security.uuid(405))
	membershipDigest := domain.FingerprintCommand([]byte("authentication resolver membership proof"))
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

	actorID, _ := domain.ParseActorID(security.uuid(406))
	actorName, _ := domain.NewDisplayName("Authentication resolver actor")
	actorProfile, _ := domain.NewActorProfile(actorName)
	createdActor, err := domain.CreateActor(domain.CreateActorInput{
		Authorization: ownerWorkspaceAuthorization, Administrator: owner, ExpectedAdministratorVersion: owner.Version(),
		Workspace: workspace, ExpectedWorkspaceVersion: workspace.Version(), ActorID: actorID,
		Kind: domain.ActorKindAgent, Profile: actorProfile,
	})
	if err != nil {
		t.Fatal(err)
	}

	delegationID, _ := domain.ParseActorDelegationID(security.uuid(407))
	delegationCeremonyID, _ := domain.ParseCeremonyID(security.uuid(408))
	delegationDigest := domain.FingerprintCommand([]byte("authentication resolver delegation proof"))
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
	sessionCeremonyID, _ := domain.ParseCeremonyID(security.uuid(409))
	sessionDigest := domain.FingerprintCommand([]byte("authentication resolver session proof"))
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
	sessionID, _ := domain.ParseActorSessionID(security.uuid(410))
	sessionClientID, _ := domain.ParseClientInstanceID(security.uuid(411))
	clientMetadata, _ := domain.NewClientMetadata("authentication-resolver-agent", "1.0.0")
	credentialReference, _ := domain.NewCredentialReference("credential-ref:authentication-resolver-session")
	credentialAudience, _ := domain.NewCredentialAudience("blackbird:authentication-resolver")
	presentationDigest, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("authentication resolver presentation")))
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
		spec := newProductionCommandSpec(t, security, step, index+20)
		if execution := executeProductionStep(t, store, spec, step, index+20); execution.Kind() != application.CommandTransactionCommitted {
			t.Fatalf("step %s kind=%q, want committed", step.operation, execution.Kind())
		}
	}
	return authenticationFixture{
		workspaceScope: workspaceScope, policy: policy, assurance: assurance, owner: owner,
		ownerDevice: paired.Device(), pairedSPKI: pairedSPKI, workload: workload, session: sessionStarted.Session(),
		audience: credentialAudience, authority: security.authority, epoch: security.epoch,
	}
}

func deviceAuthenticationLookup(t *testing.T, fixture authenticationFixture) application.AuthenticationLookup {
	t.Helper()
	deviceID := fixture.ownerDevice.ID()
	lookup, err := application.NewAuthenticationLookup(application.AuthenticationLookupParams{
		PrincipalID: fixture.owner.ID(), DeviceID: &deviceID,
		CredentialFingerprint: fixture.pairedSPKI, RequiredAudience: fixture.audience, AuthorityEpoch: fixture.epoch,
	})
	if err != nil {
		t.Fatal(err)
	}
	return lookup
}

func sessionAuthenticationLookup(t *testing.T, fixture authenticationFixture) application.AuthenticationLookup {
	t.Helper()
	sessionID := fixture.session.ID()
	lookup, err := application.NewAuthenticationLookup(application.AuthenticationLookupParams{
		PrincipalID: fixture.workload.ID(), ActorSessionID: &sessionID,
		RequiredAudience: fixture.audience, AuthorityEpoch: fixture.epoch,
	})
	if err != nil {
		t.Fatal(err)
	}
	return lookup
}

func TestResolveAuthenticationResolvesDurableSessionAndDeviceSnapshots(t *testing.T) {
	store := openSecurityStore(t)
	security := newSecurityFixture(t)
	fixture := buildAuthenticationFixture(t, store, security)

	sessionState, err := store.ResolveAuthentication(context.Background(), sessionAuthenticationLookup(t, fixture))
	if err != nil {
		t.Fatalf("resolve session authentication: %v", err)
	}
	if sessionState.Principal().ID() != fixture.workload.ID() {
		t.Fatalf("session principal=%s, want %s", sessionState.Principal().ID(), fixture.workload.ID())
	}
	session, present := sessionState.ActorSession()
	if !present || session == nil || session.ID() != fixture.session.ID() {
		t.Fatalf("resolved actor session=%v present=%v, want %s", session, present, fixture.session.ID())
	}
	if device, present := sessionState.Device(); present || device != nil {
		t.Fatalf("session authentication unexpectedly bound a device")
	}
	if sessionState.SourceAuthorityID() != fixture.authority {
		t.Fatalf("session source authority=%s, want %s", sessionState.SourceAuthorityID(), fixture.authority)
	}
	if sessionState.VerifiedAt().IsZero() {
		t.Fatal("session authentication has a zero verified time")
	}

	deviceState, err := store.ResolveAuthentication(context.Background(), deviceAuthenticationLookup(t, fixture))
	if err != nil {
		t.Fatalf("resolve device authentication: %v", err)
	}
	if deviceState.Principal().ID() != fixture.owner.ID() {
		t.Fatalf("device principal=%s, want %s", deviceState.Principal().ID(), fixture.owner.ID())
	}
	device, present := deviceState.Device()
	if !present || device == nil || device.ID() != fixture.ownerDevice.ID() {
		t.Fatalf("resolved device=%v present=%v, want %s", device, present, fixture.ownerDevice.ID())
	}
	if session, present := deviceState.ActorSession(); present || session != nil {
		t.Fatalf("device authentication unexpectedly bound an actor session")
	}
	if deviceState.SourceAuthorityID() != fixture.authority {
		t.Fatalf("device source authority=%s, want %s", deviceState.SourceAuthorityID(), fixture.authority)
	}
}

func TestResolveAuthenticationRejectsMismatchedOrStaleIdentity(t *testing.T) {
	store := openSecurityStore(t)
	security := newSecurityFixture(t)
	fixture := buildAuthenticationFixture(t, store, security)

	sessionLookup := func(mutate func(*application.AuthenticationLookupParams)) application.AuthenticationLookup {
		t.Helper()
		sessionID := fixture.session.ID()
		params := application.AuthenticationLookupParams{
			PrincipalID: fixture.workload.ID(), ActorSessionID: &sessionID,
			RequiredAudience: fixture.audience, AuthorityEpoch: fixture.epoch,
		}
		if mutate != nil {
			mutate(&params)
		}
		lookup, err := application.NewAuthenticationLookup(params)
		if err != nil {
			t.Fatal(err)
		}
		return lookup
	}
	rejectedSession := func(t *testing.T, name string, lookup application.AuthenticationLookup, code domain.ErrorCode) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			_, err := store.ResolveAuthentication(context.Background(), lookup)
			var rejection *domain.CommandError
			if !errors.As(err, &rejection) {
				t.Fatalf("resolve error=%v, want CommandError %s", err, code)
			}
			if rejection.Code() != code {
				t.Fatalf("rejection code=%s, want %s", rejection.Code(), code)
			}
		})
	}

	otherEpoch, _ := domain.NewAuthorityEpoch()
	rejectedSession(t, "session audience mismatch", sessionLookup(func(params *application.AuthenticationLookupParams) {
		otherAudience, _ := domain.NewCredentialAudience("blackbird:other-ingress")
		params.RequiredAudience = otherAudience
	}), domain.ErrorCodeForbidden)
	rejectedSession(t, "session epoch mismatch", sessionLookup(func(params *application.AuthenticationLookupParams) {
		params.AuthorityEpoch = otherEpoch
	}), domain.ErrorCodeUnauthenticated)
	rejectedSession(t, "session principal mismatch", sessionLookup(func(params *application.AuthenticationLookupParams) {
		params.PrincipalID = fixture.owner.ID()
	}), domain.ErrorCodeUnauthenticated)
	rejectedSession(t, "session identity missing", sessionLookup(func(params *application.AuthenticationLookupParams) {
		unknown, _ := domain.ParseActorSessionID(security.uuid(999))
		params.ActorSessionID = &unknown
	}), domain.ErrorCodeUnauthenticated)

	deviceLookup := func(mutate func(*application.AuthenticationLookupParams)) application.AuthenticationLookup {
		t.Helper()
		deviceID := fixture.ownerDevice.ID()
		params := application.AuthenticationLookupParams{
			PrincipalID: fixture.owner.ID(), DeviceID: &deviceID,
			CredentialFingerprint: fixture.pairedSPKI, RequiredAudience: fixture.audience, AuthorityEpoch: fixture.epoch,
		}
		if mutate != nil {
			mutate(&params)
		}
		lookup, err := application.NewAuthenticationLookup(params)
		if err != nil {
			t.Fatal(err)
		}
		return lookup
	}
	rejectedDevice := func(t *testing.T, name string, lookup application.AuthenticationLookup, code domain.ErrorCode) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			_, err := store.ResolveAuthentication(context.Background(), lookup)
			var rejection *domain.CommandError
			if !errors.As(err, &rejection) {
				t.Fatalf("resolve error=%v, want CommandError %s", err, code)
			}
			if rejection.Code() != code {
				t.Fatalf("rejection code=%s, want %s", rejection.Code(), code)
			}
		})
	}
	rejectedDevice(t, "device credential rejected", deviceLookup(func(params *application.AuthenticationLookupParams) {
		wrong, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("wrong device spki")))
		params.CredentialFingerprint = wrong
	}), domain.ErrorCodeUnauthenticated)
	rejectedDevice(t, "device identity missing", deviceLookup(func(params *application.AuthenticationLookupParams) {
		unknown, _ := domain.ParseDeviceID(security.uuid(998))
		params.DeviceID = &unknown
	}), domain.ErrorCodeUnauthenticated)

	unknownPrincipal, _ := domain.ParsePrincipalID(security.uuid(997))
	rejectedDevice(t, "principal identity missing", deviceLookup(func(params *application.AuthenticationLookupParams) {
		params.PrincipalID = unknownPrincipal
	}), domain.ErrorCodeUnauthenticated)

	t.Run("device suspended", func(t *testing.T) {
		if _, err := store.pool.Exec(context.Background(), `UPDATE device_registrations SET status = 'suspended' WHERE device_id = $1`, fixture.ownerDevice.ID().String()); err != nil {
			t.Fatal(err)
		}
		_, err := store.ResolveAuthentication(context.Background(), deviceLookup(nil))
		var rejection *domain.CommandError
		if !errors.As(err, &rejection) || rejection.Code() != domain.ErrorCodeForbidden {
			t.Fatalf("suspended device error=%v, want CommandError %s", err, domain.ErrorCodeForbidden)
		}
	})
}

func TestVerifyGrantCurrencyRejectsMissingRevokedStaleOrExpired(t *testing.T) {
	store := openSecurityStore(t)
	security := newSecurityFixture(t)
	initializeSecurityFixture(t, store, security)
	bootstrapSpec, bootstrapDecide, bootstrap := newBootstrapCommand(t, security)
	mustExecuteProductionCommand(t, store, bootstrapSpec, bootstrapDecide)
	grant := bootstrap.OwnerGrant()
	bound, err := domain.NewAggregateRef(grant.ID(), grant.Version())
	if err != nil {
		t.Fatal(err)
	}
	verifiedAt := time.Now().UTC().Truncate(time.Microsecond)

	verify := func(t *testing.T, wantRejected bool) {
		t.Helper()
		tx, beginErr := store.pool.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		err := verifyGrantCurrency(context.Background(), tx, bound, verifiedAt)
		if !wantRejected {
			if err != nil {
				t.Fatalf("verify grant currency: %v", err)
			}
			return
		}
		var rejection *domain.CommandError
		if !errors.As(err, &rejection) || rejection.Code() != domain.ErrorCodeForbidden {
			t.Fatalf("verify grant currency error=%v, want Forbidden", err)
		}
	}

	t.Run("current", func(t *testing.T) { verify(t, false) })
	t.Run("stale", func(t *testing.T) {
		if _, err := store.pool.Exec(context.Background(), `UPDATE grants SET version = version + 1 WHERE grant_id = $1`, grant.ID().String()); err != nil {
			t.Fatal(err)
		}
		verify(t, true)
	})
	t.Run("revoked", func(t *testing.T) {
		if _, err := store.pool.Exec(context.Background(), `UPDATE grants SET status = 'revoked' WHERE grant_id = $1`, grant.ID().String()); err != nil {
			t.Fatal(err)
		}
		verify(t, true)
	})
	t.Run("expired", func(t *testing.T) {
		if _, err := store.pool.Exec(context.Background(), `UPDATE grants SET expires_at_us = 1 WHERE grant_id = $1`, grant.ID().String()); err != nil {
			t.Fatal(err)
		}
		verify(t, true)
	})
	t.Run("missing", func(t *testing.T) {
		missing, parseErr := domain.ParseGrantID(security.uuid(996))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		ref, refErr := domain.NewAggregateRef(missing, grant.Version())
		if refErr != nil {
			t.Fatal(refErr)
		}
		tx, beginErr := store.pool.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		err := verifyGrantCurrency(context.Background(), tx, ref, verifiedAt)
		var rejection *domain.CommandError
		if !errors.As(err, &rejection) || rejection.Code() != domain.ErrorCodeForbidden {
			t.Fatalf("verify missing grant error=%v, want Forbidden", err)
		}
	})
}
