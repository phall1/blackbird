package domain

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func identityUUID(index int) string {
	return fmt.Sprintf("01b8e094-9888-7000-8000-%012x", index)
}

func testCapability(t *testing.T, value string) Capability {
	t.Helper()
	capability, err := NewCapability(value)
	if err != nil {
		t.Fatal(err)
	}
	return capability
}

func testCapabilities(t *testing.T, capabilities ...Capability) CapabilitySet {
	t.Helper()
	set, err := NewCapabilitySet(capabilities...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func ownerCapabilitySet(t *testing.T, additional ...Capability) CapabilitySet {
	t.Helper()
	capabilities := []Capability{
		capabilityInstallationOwner, capabilityIdentityAdmin, capabilityWorkspaceCreate,
		capabilityMembershipAdmin, capabilityActorAdmin, capabilityDelegationAdmin,
		capabilityDevicePair, capabilityWorkspaceOwner,
	}
	capabilities = append(capabilities, additional...)
	return testCapabilities(t, capabilities...)
}

func workspaceOwnerCapabilitySet(t *testing.T, additional ...Capability) CapabilitySet {
	t.Helper()
	capabilities := []Capability{
		capabilityWorkspaceOwner, capabilityMembershipAdmin, capabilityActorAdmin,
		capabilityDelegationAdmin, capabilityDevicePair,
	}
	capabilities = append(capabilities, additional...)
	return testCapabilities(t, capabilities...)
}

func testBootstrapMaterials(
	t *testing.T,
	invitationID InvitationID,
	installationID InstallationID,
	principalID PrincipalID,
	principalName DisplayName,
	deviceID DeviceID,
	deviceName DisplayName,
	deviceKey PublicKeyReference,
	grantID GrantID,
	capabilities CapabilitySet,
	verifier CommandFingerprint,
	issuedAt time.Time,
) (InstallationInvitationState, BootstrapProof, BootstrapGenerationAuthorization) {
	t.Helper()
	installationKey, err := NewPublicKeyReference("keyref:installation")
	if err != nil {
		t.Fatal(err)
	}
	generation, err := ParseBootstrapGenerationID(identityUUID(900))
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := NewInstallationInvitation(
		invitationID, installationID, installationKey, verifier, issuedAt, generation,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := NewBootstrapProof(BootstrapProofParams{
		InvitationID:          invitationID,
		InstallationID:        installationID,
		InstallationKey:       installationKey,
		InvitationEvidence:    verifier,
		TranscriptFingerprint: FingerprintCommand([]byte("bound bootstrap transcript")),
		ClientNonceDigest:     FingerprintCommand([]byte("bootstrap client nonce")),
		ServerNonceDigest:     FingerprintCommand([]byte("bootstrap server nonce")),
		Protocol:              PairingProtocolV1,
		Role:                  BootstrapRoleInstallationOwner,
		PrincipalID:           principalID,
		PrincipalDisplayName:  principalName,
		DeviceID:              deviceID,
		DeviceDisplayName:     deviceName,
		DevicePublicKey:       deviceKey,
		OwnerGrantID:          grantID,
		OwnerCapabilities:     capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := SameBootstrapGeneration(generation)
	if err != nil {
		t.Fatal(err)
	}
	return invitation, proof, authorization
}

func requireFactTypes(t *testing.T, facts []IdentityFact, expected ...EventType) {
	t.Helper()
	if len(facts) != len(expected) {
		t.Fatalf("fact count = %d, want %d", len(facts), len(expected))
	}
	for index, eventType := range expected {
		if facts[index].Type() != eventType {
			t.Fatalf("fact %d = %s, want %s", index, facts[index].Type(), eventType)
		}
	}
}

func ceremonyRehydrationParams(challenge CeremonyChallenge) CeremonyChallengeRehydrationParams {
	return CeremonyChallengeRehydrationParams{
		ID: challenge.ID(), Purpose: challenge.Purpose(), ProofDigest: challenge.ProofDigest(),
		ExpiresAt: challenge.ExpiresAt(), Status: challenge.Status(),
		InstallationID: challenge.InstallationID(), WorkspaceID: challenge.WorkspaceID(),
		PrincipalID: challenge.PrincipalID(), MembershipID: challenge.MembershipID(),
		ActorID: challenge.ActorID(), DelegationID: challenge.DelegationID(), DeviceID: challenge.DeviceID(),
	}
}

func TestRehydrateCeremonyChallengeRoundTripsEveryPurposeAndLifecycle(t *testing.T) {
	fixture := buildIdentityPath(t)
	deviceID, _ := ParseDeviceID(identityUUID(300))
	membershipID, _ := ParseMembershipID(identityUUID(301))
	ceremonyIDs := make([]CeremonyID, 4)
	for index := range ceremonyIDs {
		ceremonyIDs[index], _ = ParseCeremonyID(identityUUID(302 + index))
	}
	digest := FingerprintCommand([]byte("persisted challenge proof"))
	membership, _ := NewMembershipAcceptanceChallenge(
		ceremonyIDs[0], digest, fixture.now.Add(time.Minute), fixture.workspace.ID(), membershipID, fixture.workload.ID(),
	)
	delegation, _ := NewDelegationActivationChallenge(
		ceremonyIDs[1], digest, fixture.now.Add(time.Minute), fixture.workspace.ID(), fixture.delegation.ID(),
		fixture.workload.ID(), fixture.actor.ID(),
	)
	device, _ := NewDevicePairingChallenge(
		ceremonyIDs[2], digest, fixture.now.Add(time.Minute), fixture.installationID, fixture.workload.ID(), deviceID,
	)
	session, _ := NewSessionStartChallenge(
		ceremonyIDs[3], digest, fixture.now.Add(time.Minute), fixture.workspace.ID(), fixture.delegation.ID(),
		fixture.workload.ID(), fixture.actor.ID(),
	)
	for _, challenge := range []CeremonyChallenge{membership, delegation, device, session} {
		for _, lifecycle := range []CeremonyChallenge{challenge, challenge.consume()} {
			rehydrated, err := RehydrateCeremonyChallenge(ceremonyRehydrationParams(lifecycle))
			if err != nil || rehydrated != lifecycle {
				t.Fatalf("purpose %q status %q did not round trip: state=%#v error=%v", lifecycle.Purpose(), lifecycle.Status(), rehydrated, err)
			}
		}
	}
}

func TestRehydrateEveryIdentityStateRoundTripsTransitionState(t *testing.T) {
	fixture := buildIdentityPath(t)

	invitationID, _ := ParseInvitationID(identityUUID(310))
	installationKey, _ := NewPublicKeyReference("keyref:rehydrated-installation")
	generation, _ := ParseBootstrapGenerationID(identityUUID(311))
	invitation, err := NewInstallationInvitation(
		invitationID, fixture.installationID, installationKey,
		FingerprintCommand([]byte("rehydrated invitation")), fixture.now, generation,
	)
	if err != nil {
		t.Fatal(err)
	}
	rehydratedInvitation, err := RehydrateInstallationInvitation(InstallationInvitationRehydrationParams{
		ID: invitation.ID(), InstallationID: invitation.InstallationID(),
		InstallationPublicKey: invitation.InstallationPublicKey(), InvitationVerifier: invitation.InvitationVerifier(),
		BootstrapGenerationID: invitation.BootstrapGenerationID(), ExpiresAt: invitation.ExpiresAt(),
		FailedAttempts: invitation.FailedAttempts(), Status: invitation.Status(), Version: invitation.Version(),
	})
	if err != nil || rehydratedInvitation != invitation {
		t.Fatalf("invitation did not round trip: state=%#v error=%v", rehydratedInvitation, err)
	}

	principal, err := RehydratePrincipal(PrincipalRehydrationParams{
		ID: fixture.workload.ID(), InstallationID: fixture.workload.InstallationID(), Kind: fixture.workload.Kind(),
		DisplayName: fixture.workload.DisplayName(), PublicKeyReference: fixture.workload.PublicKeyReference(),
		Status: fixture.workload.Status(), Version: fixture.workload.Version(),
	})
	if err != nil || principal != fixture.workload {
		t.Fatalf("principal did not round trip: state=%#v error=%v", principal, err)
	}

	deviceID, _ := ParseDeviceID(identityUUID(312))
	deviceName, _ := NewDisplayName("Rehydrated Device")
	deviceKey, _ := NewPublicKeyReference("keyref:rehydrated-device")
	deviceCeremonyID, _ := ParseCeremonyID(identityUUID(313))
	deviceDigest := FingerprintCommand([]byte("rehydrated device proof"))
	deviceChallenge, _ := NewDevicePairingChallenge(
		deviceCeremonyID, deviceDigest, fixture.now.Add(time.Minute), fixture.installationID, fixture.owner.ID(), deviceID,
	)
	deviceCreation, _ := ExpectCeremonyAbsent(deviceCeremonyID)
	began, err := BeginDevicePairing(BeginDevicePairingInput{
		Authorization: fixture.ownerAuth, Principal: fixture.owner, ExpectedPrincipalVersion: fixture.owner.Version(),
		DeviceID: deviceID, DisplayName: deviceName, PublicKeyReference: deviceKey,
		Challenge: deviceChallenge, ChallengeCreation: deviceCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceProof, _ := NewCeremonyProof(
		deviceCeremonyID, CeremonyPurposeDevicePairing, deviceDigest, fixture.owner.ID(), deviceID,
	)
	paired, err := PairDevice(PairDeviceInput{
		Principal: fixture.owner, ExpectedPrincipalVersion: fixture.owner.Version(),
		Device: began.Device(), ExpectedDeviceVersion: began.Device().Version(), Proof: deviceProof, EvaluatedAt: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	rehydratedDevice, err := RehydrateDevice(DeviceRehydrationParams{
		ID: paired.Device().ID(), InstallationID: paired.Device().InstallationID(),
		PrincipalID: paired.Device().PrincipalID(), DisplayName: paired.Device().DisplayName(),
		PublicKeyReference: paired.Device().PublicKeyReference(), Status: paired.Device().Status(),
		Version: paired.Device().Version(), TrustRevision: paired.Device().TrustRevision(),
		PairingChallenge: paired.Device().PairingChallenge(),
	})
	if err != nil || rehydratedDevice != paired.Device() {
		t.Fatalf("device did not round trip: state=%#v error=%v", rehydratedDevice, err)
	}

	rehydratedGrant, err := RehydrateGrant(GrantRehydrationParams{
		ID: fixture.ownerGrant.ID(), InstallationID: fixture.ownerGrant.InstallationID(),
		WorkspaceID: fixture.ownerGrant.WorkspaceID(), PrincipalID: fixture.ownerGrant.PrincipalID(),
		Status: fixture.ownerGrant.Status(), Version: fixture.ownerGrant.Version(),
		Capabilities: fixture.ownerGrant.Capabilities(),
	})
	if err != nil || rehydratedGrant.ID() != fixture.ownerGrant.ID() ||
		!rehydratedGrant.Capabilities().Equal(fixture.ownerGrant.Capabilities()) {
		t.Fatalf("grant did not round trip: state=%#v error=%v", rehydratedGrant, err)
	}

	rehydratedWorkspace, err := RehydrateWorkspace(WorkspaceRehydrationParams{
		ID: fixture.workspace.ID(), InstallationID: fixture.workspace.InstallationID(),
		AuthorityID: fixture.workspace.AuthorityID(), AuthorityEpoch: fixture.workspace.AuthorityEpoch(),
		Alias: fixture.workspace.Alias(), DiscoveryLocator: fixture.workspace.DiscoveryLocator(),
		PolicyRevision: fixture.workspace.PolicyRevision(), Status: fixture.workspace.Status(), Version: fixture.workspace.Version(),
	})
	if err != nil || rehydratedWorkspace != fixture.workspace {
		t.Fatalf("workspace did not round trip: state=%#v error=%v", rehydratedWorkspace, err)
	}

	rehydratedMembership, err := RehydrateMembership(MembershipRehydrationParams{
		ID: fixture.membership.ID(), WorkspaceID: fixture.membership.WorkspaceID(), PrincipalID: fixture.membership.PrincipalID(),
		Status: fixture.membership.Status(), Version: fixture.membership.Version(),
		Capabilities: fixture.membership.Capabilities(), AcceptanceChallenge: fixture.membership.AcceptanceChallenge(),
	})
	if err != nil || rehydratedMembership.ID() != fixture.membership.ID() ||
		!rehydratedMembership.Capabilities().Equal(fixture.membership.Capabilities()) ||
		rehydratedMembership.AcceptanceChallenge() != fixture.membership.AcceptanceChallenge() {
		t.Fatalf("membership did not round trip: state=%#v error=%v", rehydratedMembership, err)
	}

	rehydratedActor, err := RehydrateActor(ActorRehydrationParams{
		ID: fixture.actor.ID(), WorkspaceID: fixture.actor.WorkspaceID(), Kind: fixture.actor.Kind(),
		Profile: fixture.actor.Profile(), Status: fixture.actor.Status(), Version: fixture.actor.Version(),
	})
	if err != nil || rehydratedActor != fixture.actor {
		t.Fatalf("actor did not round trip: state=%#v error=%v", rehydratedActor, err)
	}

	rehydratedDelegation, err := RehydrateActorDelegation(ActorDelegationRehydrationParams{
		ID: fixture.delegation.ID(), WorkspaceID: fixture.delegation.WorkspaceID(),
		PrincipalID: fixture.delegation.PrincipalID(), ActorID: fixture.delegation.ActorID(),
		MembershipID: fixture.delegation.MembershipID(), Status: fixture.delegation.Status(),
		Version: fixture.delegation.Version(), Capabilities: fixture.delegation.Capabilities(),
		ActivationChallenge: fixture.delegation.ActivationChallenge(),
	})
	if err != nil || rehydratedDelegation.ID() != fixture.delegation.ID() ||
		!rehydratedDelegation.Capabilities().Equal(fixture.delegation.Capabilities()) ||
		rehydratedDelegation.ActivationChallenge() != fixture.delegation.ActivationChallenge() {
		t.Fatalf("delegation did not round trip: state=%#v error=%v", rehydratedDelegation, err)
	}

	sessionResult, err := StartActorSession(baseSessionInput(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	rehydratedSession, err := RehydrateActorSession(ActorSessionRehydrationParams{
		ID: sessionResult.Session().ID(), ClientInstanceID: sessionResult.Session().ClientInstanceID(),
		ClientMetadata: sessionResult.Session().ClientMetadata(), Status: sessionResult.Session().Status(),
		Version: sessionResult.Session().Version(), Binding: sessionResult.Session().Binding(),
		Capabilities: sessionResult.Session().Capabilities(),
	})
	if err != nil || rehydratedSession.ID() != sessionResult.Session().ID() ||
		!equalSessionBindings(rehydratedSession.Binding(), sessionResult.Session().Binding()) ||
		!rehydratedSession.Capabilities().Equal(sessionResult.Session().Capabilities()) {
		t.Fatalf("actor session did not round trip: state=%#v error=%v", rehydratedSession, err)
	}
}

func TestRehydrationAcceptsEverySupportedIdentityLifecycleValue(t *testing.T) {
	fixture := buildIdentityPath(t)
	invitationID, _ := ParseInvitationID(identityUUID(330))
	installationKey, _ := NewPublicKeyReference("keyref:lifecycle-installation")
	generation, _ := ParseBootstrapGenerationID(identityUUID(331))
	for _, lifecycle := range []struct {
		status   InstallationInvitationStatus
		failures uint8
		version  uint64
	}{
		{InstallationInvitationPending, 2, 3},
		{InstallationInvitationConsumed, 2, 4},
		{InstallationInvitationExhausted, MaxBootstrapFailedAttempts, 6},
	} {
		version := mustVersion(t, lifecycle.version)
		state, err := RehydrateInstallationInvitation(InstallationInvitationRehydrationParams{
			ID: invitationID, InstallationID: fixture.installationID, InstallationPublicKey: installationKey,
			InvitationVerifier: FingerprintCommand([]byte("lifecycle invitation")), BootstrapGenerationID: generation,
			ExpiresAt: fixture.now.Add(time.Minute), FailedAttempts: lifecycle.failures,
			Status: lifecycle.status, Version: version,
		})
		if err != nil || state.Status() != lifecycle.status || state.FailedAttempts() != lifecycle.failures {
			t.Fatalf("invitation lifecycle %q rejected: state=%#v error=%v", lifecycle.status, state, err)
		}
	}

	for _, kind := range []PrincipalKind{PrincipalKindHuman, PrincipalKindWorkload, PrincipalKindService} {
		for _, status := range []PrincipalStatus{PrincipalActive, PrincipalSuspended, PrincipalDisabled} {
			publicKey := fixture.workload.PublicKeyReference()
			version := InitialVersion()
			if kind == PrincipalKindHuman {
				publicKey = PublicKeyReference{}
			}
			if status != PrincipalActive {
				version = mustVersion(t, 2)
			}
			state, err := RehydratePrincipal(PrincipalRehydrationParams{
				ID: fixture.workload.ID(), InstallationID: fixture.installationID, Kind: kind,
				DisplayName: fixture.workload.DisplayName(), PublicKeyReference: publicKey,
				Status: status, Version: version,
			})
			if err != nil || state.Kind() != kind || state.Status() != status {
				t.Fatalf("principal kind %q status %q rejected: state=%#v error=%v", kind, status, state, err)
			}
		}
	}

	deviceID, _ := ParseDeviceID(identityUUID(332))
	deviceName, _ := NewDisplayName("Lifecycle Device")
	deviceKey, _ := NewPublicKeyReference("keyref:lifecycle-device")
	deviceCeremonyID, _ := ParseCeremonyID(identityUUID(333))
	deviceChallenge, _ := NewDevicePairingChallenge(
		deviceCeremonyID, FingerprintCommand([]byte("lifecycle device")), fixture.now.Add(time.Minute),
		fixture.installationID, fixture.workload.ID(), deviceID,
	)
	for _, status := range []DeviceStatus{DevicePending, DeviceTrusted, DeviceSuspended, DeviceRevoked} {
		pairing := CeremonyChallenge{}
		version := InitialVersion()
		if status == DevicePending {
			pairing = deviceChallenge
		}
		if status == DeviceSuspended || status == DeviceRevoked {
			version = mustVersion(t, 2)
		}
		state, err := RehydrateDevice(DeviceRehydrationParams{
			ID: deviceID, InstallationID: fixture.installationID, PrincipalID: fixture.workload.ID(),
			DisplayName: deviceName, PublicKeyReference: deviceKey, Status: status,
			Version: version, TrustRevision: InitialVersion(), PairingChallenge: pairing,
		})
		if err != nil || state.Status() != status {
			t.Fatalf("device lifecycle %q rejected: state=%#v error=%v", status, state, err)
		}
	}

	for _, status := range []GrantStatus{GrantActive, GrantRevoked} {
		version := InitialVersion()
		if status == GrantRevoked {
			version = mustVersion(t, 2)
		}
		state, err := RehydrateGrant(GrantRehydrationParams{
			ID: fixture.ownerGrant.ID(), InstallationID: fixture.installationID, PrincipalID: fixture.owner.ID(),
			Status: status, Version: version, Capabilities: fixture.ownerGrant.Capabilities(),
		})
		if err != nil || state.Status() != status {
			t.Fatalf("grant lifecycle %q rejected: state=%#v error=%v", status, state, err)
		}
	}

	for _, status := range []WorkspaceStatus{WorkspaceActive, WorkspaceSuspended, WorkspaceArchived} {
		version := InitialVersion()
		if status != WorkspaceActive {
			version = mustVersion(t, 2)
		}
		state, err := RehydrateWorkspace(WorkspaceRehydrationParams{
			ID: fixture.workspace.ID(), InstallationID: fixture.installationID,
			AuthorityID: fixture.authorityID, AuthorityEpoch: fixture.epoch, Alias: fixture.workspace.Alias(),
			PolicyRevision: fixture.policy, Status: status, Version: version,
		})
		if err != nil || state.Status() != status || !state.DiscoveryLocator().valueIsZero() {
			t.Fatalf("workspace lifecycle %q rejected: state=%#v error=%v", status, state, err)
		}
	}

	membershipID, _ := ParseMembershipID(identityUUID(334))
	membershipCeremonyID, _ := ParseCeremonyID(identityUUID(335))
	membershipChallenge, _ := NewMembershipAcceptanceChallenge(
		membershipCeremonyID, FingerprintCommand([]byte("lifecycle membership")), fixture.now.Add(time.Minute),
		fixture.workspace.ID(), membershipID, fixture.workload.ID(),
	)
	for _, status := range []MembershipStatus{
		MembershipInvited, MembershipActive, MembershipSuspended, MembershipRevoked,
	} {
		acceptance := membershipChallenge.consume()
		version := mustVersion(t, 2)
		if status == MembershipInvited {
			acceptance = membershipChallenge
			version = InitialVersion()
		}
		state, err := RehydrateMembership(MembershipRehydrationParams{
			ID: membershipID, WorkspaceID: fixture.workspace.ID(), PrincipalID: fixture.workload.ID(),
			Status: status, Version: version, Capabilities: fixture.membership.Capabilities(),
			AcceptanceChallenge: acceptance,
		})
		if err != nil || state.Status() != status {
			t.Fatalf("membership lifecycle %q rejected: state=%#v error=%v", status, state, err)
		}
	}

	for _, kind := range []ActorKind{ActorKindHuman, ActorKindAgent, ActorKindAutomation, ActorKindService} {
		for _, status := range []ActorStatus{ActorActive, ActorSuspended, ActorRetired} {
			version := InitialVersion()
			if status != ActorActive {
				version = mustVersion(t, 2)
			}
			state, err := RehydrateActor(ActorRehydrationParams{
				ID: fixture.actor.ID(), WorkspaceID: fixture.workspace.ID(), Kind: kind,
				Profile: fixture.actor.Profile(), Status: status, Version: version,
			})
			if err != nil || state.Kind() != kind || state.Status() != status {
				t.Fatalf("actor kind %q status %q rejected: state=%#v error=%v", kind, status, state, err)
			}
		}
	}

	for _, status := range []DelegationStatus{
		DelegationProposed, DelegationActive, DelegationSuspended, DelegationRevoked,
	} {
		activation := fixture.delegation.ActivationChallenge()
		if status == DelegationProposed {
			activation.status = CeremonyPending
		}
		state, err := RehydrateActorDelegation(ActorDelegationRehydrationParams{
			ID: fixture.delegation.ID(), WorkspaceID: fixture.workspace.ID(), PrincipalID: fixture.workload.ID(),
			ActorID: fixture.actor.ID(), MembershipID: fixture.membership.ID(), Status: status,
			Version: fixture.delegation.Version(), Capabilities: fixture.delegation.Capabilities(),
			ActivationChallenge: activation,
		})
		if err != nil || state.Status() != status {
			t.Fatalf("delegation lifecycle %q rejected: state=%#v error=%v", status, state, err)
		}
	}

	sessionResult, err := StartActorSession(baseSessionInput(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []ActorSessionStatus{
		ActorSessionActive, ActorSessionEnded, ActorSessionRevoked, ActorSessionExpired,
	} {
		version := InitialVersion()
		if status != ActorSessionActive {
			version = mustVersion(t, 2)
		}
		state, rehydrationErr := RehydrateActorSession(ActorSessionRehydrationParams{
			ID: sessionResult.Session().ID(), ClientInstanceID: sessionResult.Session().ClientInstanceID(),
			ClientMetadata: sessionResult.Session().ClientMetadata(), Status: status,
			Version: version, Binding: sessionResult.Session().Binding(),
			Capabilities: sessionResult.Session().Capabilities(),
		})
		if rehydrationErr != nil || state.Status() != status {
			t.Fatalf("session lifecycle %q rejected: state=%#v error=%v", status, state, rehydrationErr)
		}
	}
}

func TestRehydrationRejectsImpossibleInvitationCeremonyAndPrincipalStates(t *testing.T) {
	fixture := buildIdentityPath(t)
	invitationID, _ := ParseInvitationID(identityUUID(320))
	installationKey, _ := NewPublicKeyReference("keyref:invalid-state-installation")
	generation, _ := ParseBootstrapGenerationID(identityUUID(321))
	invitationBase := InstallationInvitationRehydrationParams{
		ID: invitationID, InstallationID: fixture.installationID, InstallationPublicKey: installationKey,
		InvitationVerifier: FingerprintCommand([]byte("invitation verifier")), BootstrapGenerationID: generation,
		ExpiresAt: fixture.now.Add(time.Minute), Status: InstallationInvitationPending, Version: InitialVersion(),
	}
	invitationCases := []struct {
		name   string
		mutate func(*InstallationInvitationRehydrationParams)
	}{
		{"pending at failure ceiling", func(params *InstallationInvitationRehydrationParams) {
			params.FailedAttempts = MaxBootstrapFailedAttempts
			params.Version = mustVersion(t, 6)
		}},
		{"consumed without success version", func(params *InstallationInvitationRehydrationParams) {
			params.Status = InstallationInvitationConsumed
		}},
		{"exhausted below failure ceiling", func(params *InstallationInvitationRehydrationParams) {
			params.Status = InstallationInvitationExhausted
		}},
		{"unknown status", func(params *InstallationInvitationRehydrationParams) { params.Status = "unknown" }},
		{"zero expiry", func(params *InstallationInvitationRehydrationParams) { params.ExpiresAt = time.Time{} }},
		{"malformed public key", func(params *InstallationInvitationRehydrationParams) {
			params.InstallationPublicKey = PublicKeyReference{value: " padded "}
		}},
	}
	for _, test := range invitationCases {
		t.Run("invitation/"+test.name, func(t *testing.T) {
			params := invitationBase
			test.mutate(&params)
			state, err := RehydrateInstallationInvitation(params)
			if !errors.Is(err, ErrInvalidIdentityState) || !state.IsZero() {
				t.Fatalf("state=%#v error=%v", state, err)
			}
		})
	}

	challengeCases := []struct {
		name   string
		mutate func(*CeremonyChallengeRehydrationParams)
	}{
		{"extraneous device", func(params *CeremonyChallengeRehydrationParams) {
			params.DeviceID, _ = ParseDeviceID(identityUUID(322))
		}},
		{"missing actor", func(params *CeremonyChallengeRehydrationParams) { params.ActorID = ActorID{} }},
		{"unknown status", func(params *CeremonyChallengeRehydrationParams) { params.Status = "unknown" }},
		{"unknown purpose", func(params *CeremonyChallengeRehydrationParams) { params.Purpose = "unknown" }},
	}
	for _, test := range challengeCases {
		t.Run("ceremony/"+test.name, func(t *testing.T) {
			params := ceremonyRehydrationParams(fixture.sessionChallenge)
			test.mutate(&params)
			state, err := RehydrateCeremonyChallenge(params)
			if !errors.Is(err, ErrInvalidCeremonyChallenge) || !state.IsZero() {
				t.Fatalf("state=%#v error=%v", state, err)
			}
		})
	}

	principalBase := PrincipalRehydrationParams{
		ID: fixture.workload.ID(), InstallationID: fixture.installationID, Kind: PrincipalKindWorkload,
		DisplayName: fixture.workload.DisplayName(), PublicKeyReference: fixture.workload.PublicKeyReference(),
		Status: PrincipalActive, Version: InitialVersion(),
	}
	principalCases := []struct {
		name   string
		mutate func(*PrincipalRehydrationParams)
	}{
		{"workload without key", func(params *PrincipalRehydrationParams) {
			params.PublicKeyReference = PublicKeyReference{}
		}},
		{"malformed display name", func(params *PrincipalRehydrationParams) {
			params.DisplayName = DisplayName{value: " padded "}
		}},
		{"unknown kind", func(params *PrincipalRehydrationParams) { params.Kind = "unknown" }},
		{"unknown status", func(params *PrincipalRehydrationParams) { params.Status = "unknown" }},
		{"zero version", func(params *PrincipalRehydrationParams) { params.Version = Version{} }},
		{"suspended at creation version", func(params *PrincipalRehydrationParams) {
			params.Status = PrincipalSuspended
		}},
	}
	for _, test := range principalCases {
		t.Run("principal/"+test.name, func(t *testing.T) {
			params := principalBase
			test.mutate(&params)
			state, err := RehydratePrincipal(params)
			if !errors.Is(err, ErrInvalidIdentityState) || !state.IsZero() {
				t.Fatalf("state=%#v error=%v", state, err)
			}
		})
	}
}

func TestRehydrationRejectsImpossibleDeviceGrantAndWorkspaceStates(t *testing.T) {
	fixture := buildIdentityPath(t)
	deviceID, _ := ParseDeviceID(identityUUID(323))
	deviceName, _ := NewDisplayName("Persisted Device")
	deviceKey, _ := NewPublicKeyReference("keyref:persisted-device")
	deviceCeremonyID, _ := ParseCeremonyID(identityUUID(324))
	deviceChallenge, _ := NewDevicePairingChallenge(
		deviceCeremonyID, FingerprintCommand([]byte("device proof")), fixture.now.Add(time.Minute),
		fixture.installationID, fixture.workload.ID(), deviceID,
	)
	deviceBase := DeviceRehydrationParams{
		ID: deviceID, InstallationID: fixture.installationID, PrincipalID: fixture.workload.ID(),
		DisplayName: deviceName, PublicKeyReference: deviceKey, Status: DevicePending,
		Version: InitialVersion(), TrustRevision: InitialVersion(), PairingChallenge: deviceChallenge,
	}
	deviceCases := []struct {
		name   string
		mutate func(*DeviceRehydrationParams)
	}{
		{"pending without pairing", func(params *DeviceRehydrationParams) {
			params.PairingChallenge = CeremonyChallenge{}
		}},
		{"trusted with pending pairing", func(params *DeviceRehydrationParams) { params.Status = DeviceTrusted }},
		{"cross principal pairing", func(params *DeviceRehydrationParams) { params.PrincipalID = fixture.owner.ID() }},
		{"trust newer than aggregate", func(params *DeviceRehydrationParams) {
			params.TrustRevision = mustVersion(t, 2)
		}},
		{"unknown status", func(params *DeviceRehydrationParams) { params.Status = "unknown" }},
		{"suspended at creation version", func(params *DeviceRehydrationParams) {
			params.Status = DeviceSuspended
			params.PairingChallenge = CeremonyChallenge{}
		}},
		{"consumed pairing without trust advance", func(params *DeviceRehydrationParams) {
			params.Status = DeviceTrusted
			params.Version = mustVersion(t, 2)
			params.PairingChallenge = params.PairingChallenge.consume()
		}},
	}
	for _, test := range deviceCases {
		t.Run("device/"+test.name, func(t *testing.T) {
			params := deviceBase
			test.mutate(&params)
			state, err := RehydrateDevice(params)
			if !errors.Is(err, ErrInvalidIdentityState) || !state.IsZero() {
				t.Fatalf("state=%#v error=%v", state, err)
			}
		})
	}

	badCapability := CapabilitySet{values: []Capability{{value: "*"}}}
	grantCases := []GrantRehydrationParams{
		{
			ID: fixture.ownerGrant.ID(), InstallationID: fixture.installationID, PrincipalID: fixture.owner.ID(),
			Status: GrantActive, Version: InitialVersion(), Capabilities: badCapability,
		},
		{
			ID: fixture.ownerGrant.ID(), InstallationID: fixture.installationID, PrincipalID: fixture.owner.ID(),
			Status: "unknown", Version: InitialVersion(), Capabilities: fixture.ownerGrant.Capabilities(),
		},
		{
			ID: fixture.ownerGrant.ID(), InstallationID: fixture.installationID, PrincipalID: PrincipalID{},
			Status: GrantActive, Version: InitialVersion(), Capabilities: fixture.ownerGrant.Capabilities(),
		},
		{
			ID: fixture.ownerGrant.ID(), InstallationID: fixture.installationID, PrincipalID: fixture.owner.ID(),
			Status: GrantRevoked, Version: InitialVersion(), Capabilities: fixture.ownerGrant.Capabilities(),
		},
	}
	for index, params := range grantCases {
		state, err := RehydrateGrant(params)
		if !errors.Is(err, ErrInvalidIdentityState) || !state.IsZero() {
			t.Fatalf("grant case %d: state=%#v error=%v", index, state, err)
		}
	}

	workspaceBase := WorkspaceRehydrationParams{
		ID: fixture.workspace.ID(), InstallationID: fixture.installationID, AuthorityID: fixture.authorityID,
		AuthorityEpoch: fixture.epoch, Alias: fixture.workspace.Alias(), DiscoveryLocator: fixture.workspace.DiscoveryLocator(),
		PolicyRevision: fixture.policy, Status: WorkspaceActive, Version: InitialVersion(),
	}
	workspaceCases := []struct {
		name   string
		mutate func(*WorkspaceRehydrationParams)
	}{
		{"malformed discovery", func(params *WorkspaceRehydrationParams) {
			params.DiscoveryLocator = DiscoveryLocator{value: " padded "}
		}},
		{"malformed alias", func(params *WorkspaceRehydrationParams) {
			params.Alias = WorkspaceAlias{value: " padded "}
		}},
		{"missing authority", func(params *WorkspaceRehydrationParams) { params.AuthorityID = AuthorityID{} }},
		{"unknown status", func(params *WorkspaceRehydrationParams) { params.Status = "unknown" }},
		{"zero version", func(params *WorkspaceRehydrationParams) { params.Version = Version{} }},
		{"archived at creation version", func(params *WorkspaceRehydrationParams) { params.Status = WorkspaceArchived }},
	}
	for _, test := range workspaceCases {
		t.Run("workspace/"+test.name, func(t *testing.T) {
			params := workspaceBase
			test.mutate(&params)
			state, err := RehydrateWorkspace(params)
			if !errors.Is(err, ErrInvalidIdentityState) || !state.IsZero() {
				t.Fatalf("state=%#v error=%v", state, err)
			}
		})
	}
}

func TestRehydrationRejectsImpossibleMembershipActorDelegationAndSessionStates(t *testing.T) {
	fixture := buildIdentityPath(t)
	badCapability := CapabilitySet{values: []Capability{{value: "*"}}}
	membershipBase := MembershipRehydrationParams{
		ID: fixture.membership.ID(), WorkspaceID: fixture.workspace.ID(), PrincipalID: fixture.workload.ID(),
		Status: MembershipActive, Version: fixture.membership.Version(), Capabilities: fixture.membership.Capabilities(),
		AcceptanceChallenge: fixture.membership.AcceptanceChallenge(),
	}
	membershipCases := []struct {
		name   string
		mutate func(*MembershipRehydrationParams)
	}{
		{"active with pending challenge", func(params *MembershipRehydrationParams) {
			params.AcceptanceChallenge.status = CeremonyPending
		}},
		{"invited with consumed challenge", func(params *MembershipRehydrationParams) { params.Status = MembershipInvited }},
		{"cross membership challenge", func(params *MembershipRehydrationParams) { params.ID = fixture.ownerMembership.ID() }},
		{"invalid capabilities", func(params *MembershipRehydrationParams) { params.Capabilities = badCapability }},
		{"invited without challenge", func(params *MembershipRehydrationParams) {
			params.Status = MembershipInvited
			params.AcceptanceChallenge = CeremonyChallenge{}
		}},
		{"suspended at creation version", func(params *MembershipRehydrationParams) {
			params.Status = MembershipSuspended
			params.Version = InitialVersion()
		}},
	}
	for _, test := range membershipCases {
		t.Run("membership/"+test.name, func(t *testing.T) {
			params := membershipBase
			test.mutate(&params)
			state, err := RehydrateMembership(params)
			if !errors.Is(err, ErrInvalidIdentityState) || !state.IsZero() {
				t.Fatalf("state=%#v error=%v", state, err)
			}
		})
	}

	actorCases := []ActorRehydrationParams{
		{
			ID: fixture.actor.ID(), WorkspaceID: fixture.workspace.ID(), Kind: fixture.actor.Kind(),
			Profile: ActorProfile{displayName: DisplayName{value: "\n"}}, Status: ActorActive, Version: InitialVersion(),
		},
		{
			ID: fixture.actor.ID(), WorkspaceID: fixture.workspace.ID(), Kind: "unknown",
			Profile: fixture.actor.Profile(), Status: ActorActive, Version: InitialVersion(),
		},
		{
			ID: fixture.actor.ID(), WorkspaceID: fixture.workspace.ID(), Kind: fixture.actor.Kind(),
			Profile: fixture.actor.Profile(), Status: "unknown", Version: InitialVersion(),
		},
		{
			ID: fixture.actor.ID(), WorkspaceID: fixture.workspace.ID(), Kind: fixture.actor.Kind(),
			Profile: fixture.actor.Profile(), Status: ActorSuspended, Version: InitialVersion(),
		},
	}
	for index, params := range actorCases {
		state, err := RehydrateActor(params)
		if !errors.Is(err, ErrInvalidIdentityState) || !state.IsZero() {
			t.Fatalf("actor case %d: state=%#v error=%v", index, state, err)
		}
	}

	delegationBase := ActorDelegationRehydrationParams{
		ID: fixture.delegation.ID(), WorkspaceID: fixture.workspace.ID(), PrincipalID: fixture.workload.ID(),
		ActorID: fixture.actor.ID(), MembershipID: fixture.membership.ID(), Status: DelegationActive,
		Version: fixture.delegation.Version(), Capabilities: fixture.delegation.Capabilities(),
		ActivationChallenge: fixture.delegation.ActivationChallenge(),
	}
	delegationCases := []struct {
		name   string
		mutate func(*ActorDelegationRehydrationParams)
	}{
		{"active with pending activation", func(params *ActorDelegationRehydrationParams) {
			params.ActivationChallenge.status = CeremonyPending
		}},
		{"proposed with consumed activation", func(params *ActorDelegationRehydrationParams) {
			params.Status = DelegationProposed
		}},
		{"cross actor activation", func(params *ActorDelegationRehydrationParams) { params.ActorID = ActorID{} }},
		{"missing membership", func(params *ActorDelegationRehydrationParams) { params.MembershipID = MembershipID{} }},
		{"invalid capabilities", func(params *ActorDelegationRehydrationParams) { params.Capabilities = badCapability }},
		{"active at creation version", func(params *ActorDelegationRehydrationParams) {
			params.Version = InitialVersion()
		}},
	}
	for _, test := range delegationCases {
		t.Run("delegation/"+test.name, func(t *testing.T) {
			params := delegationBase
			test.mutate(&params)
			state, err := RehydrateActorDelegation(params)
			if !errors.Is(err, ErrInvalidIdentityState) || !state.IsZero() {
				t.Fatalf("state=%#v error=%v", state, err)
			}
		})
	}

	sessionResult, err := StartActorSession(baseSessionInput(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	sessionBase := ActorSessionRehydrationParams{
		ID: sessionResult.Session().ID(), ClientInstanceID: sessionResult.Session().ClientInstanceID(),
		ClientMetadata: sessionResult.Session().ClientMetadata(), Status: ActorSessionActive,
		Version: InitialVersion(), Binding: sessionResult.Session().Binding(), Capabilities: sessionResult.Session().Capabilities(),
	}
	sessionCases := []struct {
		name   string
		mutate func(*ActorSessionRehydrationParams)
	}{
		{"zero client", func(params *ActorSessionRehydrationParams) { params.ClientInstanceID = ClientInstanceID{} }},
		{"malformed metadata", func(params *ActorSessionRehydrationParams) {
			params.ClientMetadata = ClientMetadata{name: " bad ", version: "1"}
		}},
		{"unknown status", func(params *ActorSessionRehydrationParams) { params.Status = "unknown" }},
		{"invalid capabilities", func(params *ActorSessionRehydrationParams) { params.Capabilities = badCapability }},
		{"invalid binding", func(params *ActorSessionRehydrationParams) { params.Binding.membership = AggregateRef{} }},
		{"malformed binding assurance", func(params *ActorSessionRehydrationParams) {
			params.Binding.assurance = AssuranceClass{value: "Invalid"}
		}},
		{"ended at creation version", func(params *ActorSessionRehydrationParams) {
			params.Status = ActorSessionEnded
		}},
	}
	for _, test := range sessionCases {
		t.Run("session/"+test.name, func(t *testing.T) {
			params := sessionBase
			test.mutate(&params)
			state, err := RehydrateActorSession(params)
			if !errors.Is(err, ErrInvalidIdentityState) || !state.IsZero() {
				t.Fatalf("state=%#v error=%v", state, err)
			}
		})
	}
}

type identityPathFixture struct {
	now                time.Time
	authorityID        AuthorityID
	epoch              AuthorityEpoch
	installationID     InstallationID
	policy             PolicyRevision
	assurance          AssuranceClass
	ownerAuth          IdentityAuthorization
	ownerWorkspaceAuth IdentityAuthorization
	owner              PrincipalState
	ownerGrant         GrantState
	workspace          WorkspaceState
	ownerMembership    MembershipState
	workload           PrincipalState
	membership         MembershipState
	actor              ActorState
	delegation         ActorDelegationState
	sessionChallenge   CeremonyChallenge
	workRead           Capability
	workWrite          Capability
}

func buildIdentityPath(t *testing.T) identityPathFixture {
	t.Helper()
	now := time.Date(2026, 8, 4, 16, 0, 0, 0, time.UTC)
	authorityID, _ := ParseAuthorityID(identityUUID(1))
	epoch, _ := ParseAuthorityEpoch(identityUUID(2))
	installationID, _ := ParseInstallationID(identityUUID(3))
	invitationID, _ := ParseInvitationID(identityUUID(4))
	ownerID, _ := ParsePrincipalID(identityUUID(5))
	ownerDeviceID, _ := ParseDeviceID(identityUUID(6))
	ownerGrantID, _ := ParseGrantID(identityUUID(7))
	workRead := testCapability(t, "work:read")
	workWrite := testCapability(t, "work:write")
	ownerCapabilities := ownerCapabilitySet(t, workRead, workWrite)
	workspaceOwnerCapabilities := workspaceOwnerCapabilitySet(t, workRead, workWrite)
	transcript := FingerprintCommand([]byte("bootstrap transcript"))
	ownerName, _ := NewDisplayName("Alice")
	deviceName, _ := NewDisplayName("Alice Cockpit")
	deviceKey, _ := NewPublicKeyReference("keyref:alice-device:cockpit")
	invitation, proof, generationAuthorization := testBootstrapMaterials(
		t, invitationID, installationID, ownerID, ownerName, ownerDeviceID, deviceName,
		deviceKey, ownerGrantID, ownerCapabilities, transcript, now,
	)
	bootstrap, err := BootstrapInstallation(BootstrapInstallationInput{
		Invitation: invitation, ExpectedInvitationVersion: invitation.Version(),
		CurrentGeneration: generationAuthorization.CurrentGeneration(), GenerationAuthorization: generationAuthorization,
		PrincipalID: ownerID, PrincipalDisplayName: ownerName,
		DeviceID: ownerDeviceID, DeviceDisplayName: deviceName, DevicePublicKey: deviceKey,
		OwnerGrantID: ownerGrantID, OwnerGrantCapabilities: ownerCapabilities, Proof: proof, EvaluatedAt: now,
		AttemptFingerprint: FingerprintCommand([]byte("bootstrap attempt")),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireFactTypes(t, bootstrap.Facts(),
		EventTypeInstallationBootstrapped, EventTypePrincipalRegistered, EventTypeDevicePaired)

	policy, _ := NewPolicyRevision("local-policy:1")
	assurance, _ := NewAssuranceClass("strong-factor")
	ownerAuth, err := NewIdentityAuthorization(
		authorityID, epoch, installationID, ownerID, ownerCapabilities, policy, assurance, now, MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := ParseWorkspaceID(identityUUID(8))
	ownerMembershipID, _ := ParseMembershipID(identityUUID(9))
	alias, _ := NewWorkspaceAlias("blackbird-proof")
	discovery, _ := NewDiscoveryLocator("workspace://blackbird-proof")
	workspaceResult, err := CreateWorkspace(CreateWorkspaceInput{
		Authorization: ownerAuth, Owner: bootstrap.Principal(), ExpectedOwnerVersion: bootstrap.Principal().Version(),
		InstallationGrant: bootstrap.OwnerGrant(), ExpectedGrantVersion: bootstrap.OwnerGrant().Version(),
		WorkspaceID: workspaceID, Alias: alias, DiscoveryLocator: discovery,
		OwnerMembershipID: ownerMembershipID, OwnerCapabilities: workspaceOwnerCapabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireFactTypes(t, workspaceResult.Facts(),
		EventTypeWorkspaceCreated, EventTypeWorkspaceMemberInvited, EventTypeWorkspaceMembershipAccepted)
	ownerWorkspaceAuth, err := NewWorkspaceIdentityAuthorization(
		authorityID, epoch, installationID, workspaceID, ownerID, ownerCapabilities,
		policy, assurance, now, MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}

	workloadID, _ := ParsePrincipalID(identityUUID(10))
	workloadName, _ := NewDisplayName("Agent A")
	workloadKey, _ := NewPublicKeyReference("keyref:agent-a")
	registered, err := RegisterPrincipal(RegisterPrincipalInput{
		Authorization: ownerAuth, Registrar: bootstrap.Principal(), ExpectedRegistrarVersion: bootstrap.Principal().Version(),
		PrincipalID: workloadID, Kind: PrincipalKindWorkload, DisplayName: workloadName,
		PublicKeyReference: workloadKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireFactTypes(t, registered.Facts(), EventTypePrincipalRegistered)

	membershipID, _ := ParseMembershipID(identityUUID(11))
	membershipCeremonyID, _ := ParseCeremonyID(identityUUID(12))
	membershipDigest := FingerprintCommand([]byte("membership proof"))
	membershipChallenge, _ := NewMembershipAcceptanceChallenge(
		membershipCeremonyID, membershipDigest, now.Add(time.Minute), workspaceID, membershipID, workloadID,
	)
	membershipCreation, _ := ExpectCeremonyAbsent(membershipCeremonyID)
	memberCapabilities := testCapabilities(t, workRead, workWrite)
	invited, err := InviteWorkspaceMember(InviteWorkspaceMemberInput{
		Authorization: ownerWorkspaceAuth, Administrator: bootstrap.Principal(), ExpectedAdministratorVersion: bootstrap.Principal().Version(),
		Workspace: workspaceResult.Workspace(), ExpectedWorkspaceVersion: workspaceResult.Workspace().Version(),
		Principal: registered.Principal(), ExpectedPrincipalVersion: registered.Principal().Version(),
		MembershipID: membershipID, Capabilities: memberCapabilities, Challenge: membershipChallenge,
		ChallengeCreation: membershipCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireFactTypes(t, invited.Facts(), EventTypeWorkspaceMemberInvited)
	workloadAuth, _ := NewWorkspaceIdentityAuthorization(
		authorityID, epoch, installationID, workspaceID, workloadID, memberCapabilities,
		policy, assurance, now, MaxActorSessionLifetime,
	)
	membershipProof, _ := NewCeremonyProof(
		membershipCeremonyID, CeremonyPurposeMembershipAcceptance, membershipDigest, workloadID, DeviceID{},
	)
	accepted, err := AcceptWorkspaceMembership(AcceptWorkspaceMembershipInput{
		Authorization: workloadAuth, Principal: registered.Principal(), ExpectedPrincipalVersion: registered.Principal().Version(),
		Workspace: workspaceResult.Workspace(), ExpectedWorkspaceVersion: workspaceResult.Workspace().Version(),
		Membership: invited.Membership(), ExpectedMembershipVersion: invited.Membership().Version(), Proof: membershipProof,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireFactTypes(t, accepted.Facts(), EventTypeWorkspaceMembershipAccepted)

	actorID, _ := ParseActorID(identityUUID(13))
	actorName, _ := NewDisplayName("Agent A")
	actorProfile, _ := NewActorProfile(actorName)
	createdActor, err := CreateActor(CreateActorInput{
		Authorization: ownerWorkspaceAuth, Administrator: bootstrap.Principal(), ExpectedAdministratorVersion: bootstrap.Principal().Version(),
		Workspace: workspaceResult.Workspace(), ExpectedWorkspaceVersion: workspaceResult.Workspace().Version(),
		ActorID: actorID, Kind: ActorKindAgent, Profile: actorProfile,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireFactTypes(t, createdActor.Facts(), EventTypeActorCreated)

	delegationID, _ := ParseActorDelegationID(identityUUID(14))
	delegationCeremonyID, _ := ParseCeremonyID(identityUUID(15))
	delegationDigest := FingerprintCommand([]byte("delegation proof"))
	delegationChallenge, _ := NewDelegationActivationChallenge(
		delegationCeremonyID, delegationDigest, now.Add(time.Minute), workspaceID, delegationID, workloadID, actorID,
	)
	delegationCreation, _ := ExpectCeremonyAbsent(delegationCeremonyID)
	delegationCapabilities := testCapabilities(t, workRead)
	proposed, err := ProposeActorDelegation(ProposeActorDelegationInput{
		Authorization: ownerWorkspaceAuth, Administrator: bootstrap.Principal(), ExpectedAdministratorVersion: bootstrap.Principal().Version(),
		Workspace: workspaceResult.Workspace(), ExpectedWorkspaceVersion: workspaceResult.Workspace().Version(),
		Principal: registered.Principal(), ExpectedPrincipalVersion: registered.Principal().Version(),
		Actor: createdActor.Actor(), ExpectedActorVersion: createdActor.Actor().Version(),
		Membership: accepted.Membership(), ExpectedMembershipVersion: accepted.Membership().Version(),
		DelegationID: delegationID, Capabilities: delegationCapabilities, Challenge: delegationChallenge,
		ChallengeCreation: delegationCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireFactTypes(t, proposed.Facts(), EventTypeActorDelegationProposed)
	delegationProof, _ := NewCeremonyProof(
		delegationCeremonyID, CeremonyPurposeDelegationActivation, delegationDigest, workloadID, DeviceID{},
	)
	sessionCeremonyID, _ := ParseCeremonyID(identityUUID(16))
	sessionDigest := FingerprintCommand([]byte("session proof"))
	sessionChallenge, _ := NewSessionStartChallenge(
		sessionCeremonyID, sessionDigest, now.Add(time.Minute), workspaceID, delegationID, workloadID, actorID,
	)
	sessionCreation, _ := ExpectCeremonyAbsent(sessionCeremonyID)
	activated, err := ActivateActorDelegation(ActivateActorDelegationInput{
		Authorization: workloadAuth, Principal: registered.Principal(), ExpectedPrincipalVersion: registered.Principal().Version(),
		Workspace: workspaceResult.Workspace(), ExpectedWorkspaceVersion: workspaceResult.Workspace().Version(),
		Actor: createdActor.Actor(), ExpectedActorVersion: createdActor.Actor().Version(),
		Membership: accepted.Membership(), ExpectedMembershipVersion: accepted.Membership().Version(),
		Delegation: proposed.Delegation(), ExpectedDelegationVersion: proposed.Delegation().Version(),
		Proof: delegationProof, SessionStartChallenge: sessionChallenge, SessionChallengeCreation: sessionCreation,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireFactTypes(t, activated.Facts(), EventTypeActorDelegationActivated)

	return identityPathFixture{
		now: now, authorityID: authorityID, epoch: epoch, installationID: installationID,
		policy: policy, assurance: assurance, ownerAuth: ownerAuth, ownerWorkspaceAuth: ownerWorkspaceAuth,
		owner:      bootstrap.Principal(),
		ownerGrant: bootstrap.OwnerGrant(), workspace: workspaceResult.Workspace(),
		ownerMembership: workspaceResult.OwnerMembership(), workload: registered.Principal(),
		membership: accepted.Membership(), actor: createdActor.Actor(), delegation: activated.Delegation(),
		sessionChallenge: activated.SessionStartChallenge(), workRead: workRead, workWrite: workWrite,
	}
}

func TestBootstrapInstallationAtomicFactsAndOrigins(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	installationID, _ := ParseInstallationID(identityUUID(20))
	invitationID, _ := ParseInvitationID(identityUUID(21))
	principalID, _ := ParsePrincipalID(identityUUID(22))
	deviceID, _ := ParseDeviceID(identityUUID(23))
	grantID, _ := ParseGrantID(identityUUID(24))
	digest := FingerprintCommand([]byte("bootstrap"))
	principalName, _ := NewDisplayName("Alice")
	deviceName, _ := NewDisplayName("Cockpit")
	deviceKey, _ := NewPublicKeyReference("keyref:cockpit")
	capabilities := ownerCapabilitySet(t)
	invitation, proof, generationAuthorization := testBootstrapMaterials(
		t, invitationID, installationID, principalID, principalName, deviceID, deviceName,
		deviceKey, grantID, capabilities, digest, now,
	)

	result, err := BootstrapInstallation(BootstrapInstallationInput{
		Invitation: invitation, ExpectedInvitationVersion: invitation.Version(),
		CurrentGeneration: generationAuthorization.CurrentGeneration(), GenerationAuthorization: generationAuthorization,
		PrincipalID: principalID, PrincipalDisplayName: principalName,
		DeviceID: deviceID, DeviceDisplayName: deviceName, DevicePublicKey: deviceKey,
		OwnerGrantID: grantID, OwnerGrantCapabilities: capabilities, Proof: proof, EvaluatedAt: now,
		AttemptFingerprint: FingerprintCommand([]byte("bootstrap attempt")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Invitation().Status() != InstallationInvitationConsumed || result.Invitation().Version().Uint64() != 2 ||
		result.Principal().Status() != PrincipalActive || result.Device().Status() != DeviceTrusted ||
		result.OwnerGrant().Status() != GrantActive {
		t.Fatalf("incomplete bootstrap result: %#v", result)
	}
	facts := result.Facts()
	wantTypes := []EventType{EventTypeInstallationBootstrapped, EventTypePrincipalRegistered, EventTypeDevicePaired}
	if len(facts) != len(wantTypes) {
		t.Fatalf("facts = %d, want %d", len(facts), len(wantTypes))
	}
	for index, expected := range wantTypes {
		if facts[index].Type() != expected {
			t.Errorf("fact %d = %s, want %s", index, facts[index].Type(), expected)
		}
	}
	if facts[0].Origin().Kind() != AggregateKindInvitation || facts[0].Origin().Version().Uint64() != 2 ||
		facts[1].Origin().Kind() != AggregateKindPrincipal || facts[1].Origin().Version().Uint64() != 1 ||
		facts[2].Origin().Kind() != AggregateKindDevice || facts[2].Origin().Version().Uint64() != 1 {
		t.Fatalf("bootstrap origins are incorrect: %#v", facts)
	}
	facts[0] = nil
	if result.Facts()[0] == nil {
		t.Fatal("result leaked mutable fact slice")
	}
}

func TestBootstrapInstallationRejectsConsumedExpiredAndWrongProofWithoutPartialOutcome(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	installationID, _ := ParseInstallationID(identityUUID(30))
	invitationID, _ := ParseInvitationID(identityUUID(31))
	principalID, _ := ParsePrincipalID(identityUUID(32))
	deviceID, _ := ParseDeviceID(identityUUID(33))
	grantID, _ := ParseGrantID(identityUUID(34))
	digest := FingerprintCommand([]byte("right"))
	name, _ := NewDisplayName("Name")
	key, _ := NewPublicKeyReference("keyref:value")
	capabilities := ownerCapabilitySet(t)
	invitation, proof, generationAuthorization := testBootstrapMaterials(
		t, invitationID, installationID, principalID, name, deviceID, name, key,
		grantID, capabilities, digest, now,
	)
	base := BootstrapInstallationInput{
		Invitation: invitation, ExpectedInvitationVersion: invitation.Version(), PrincipalID: principalID,
		CurrentGeneration: generationAuthorization.CurrentGeneration(), GenerationAuthorization: generationAuthorization,
		PrincipalDisplayName: name, DeviceID: deviceID,
		DeviceDisplayName: name, DevicePublicKey: key, OwnerGrantID: grantID, Proof: proof, EvaluatedAt: now,
		OwnerGrantCapabilities: capabilities,
		AttemptFingerprint:     FingerprintCommand([]byte("bootstrap attempt")),
	}
	tests := []struct {
		name          string
		mutate        func(*BootstrapInstallationInput)
		match         error
		proofRejected bool
	}{
		{"consumed", func(input *BootstrapInstallationInput) { input.Invitation.status = InstallationInvitationConsumed }, ErrStateConflict, false},
		{"expired", func(input *BootstrapInstallationInput) { input.EvaluatedAt = input.Invitation.ExpiresAt() }, ErrStateConflict, false},
		{"stale", func(input *BootstrapInstallationInput) { input.ExpectedInvitationVersion = mustVersion(t, 2) }, ErrStaleVersion, false},
		{"wrong proof", func(input *BootstrapInstallationInput) {
			input.Proof.invitationEvidence = FingerprintCommand([]byte("wrong"))
		}, nil, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.mutate(&input)
			result, err := BootstrapInstallation(input)
			if !errors.Is(err, test.match) {
				t.Fatalf("error = %v, want %v", err, test.match)
			}
			if test.proofRejected && (result.Outcome() != BootstrapInstallationProofRejected ||
				result.Invitation().FailedAttempts() != 1 || result.Invitation().Version().Uint64() != 2) {
				t.Fatalf("proof rejection was not recorded: %#v", result)
			}
			if !result.Principal().IsZero() || !result.Device().IsZero() || !result.OwnerGrant().IsZero() || len(result.Facts()) != 0 {
				t.Fatalf("rejection returned a partial outcome: %#v", result)
			}
		})
	}
}

func TestBootstrapInvitationLifetimeAttemptsExhaustionAndCAS(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	installationID, _ := ParseInstallationID(identityUUID(170))
	invitationID, _ := ParseInvitationID(identityUUID(171))
	principalID, _ := ParsePrincipalID(identityUUID(172))
	deviceID, _ := ParseDeviceID(identityUUID(173))
	grantID, _ := ParseGrantID(identityUUID(174))
	name, _ := NewDisplayName("Bootstrap Owner")
	deviceName, _ := NewDisplayName("Bootstrap Device")
	deviceKey, _ := NewPublicKeyReference("keyref:bootstrap-device")
	capabilities := ownerCapabilitySet(t)
	verifier := FingerprintCommand([]byte("invitation verifier"))
	invitation, proof, generationAuthorization := testBootstrapMaterials(
		t, invitationID, installationID, principalID, name, deviceID, deviceName,
		deviceKey, grantID, capabilities, verifier, now,
	)
	if got := invitation.ExpiresAt().Sub(now); got != BootstrapInvitationLifetime {
		t.Fatalf("invitation lifetime = %v, want %v", got, BootstrapInvitationLifetime)
	}
	proof.invitationEvidence = FingerprintCommand([]byte("wrong verifier"))
	base := BootstrapInstallationInput{
		CurrentGeneration: generationAuthorization.CurrentGeneration(), GenerationAuthorization: generationAuthorization,
		PrincipalID: principalID, PrincipalDisplayName: name,
		DeviceID: deviceID, DeviceDisplayName: deviceName, DevicePublicKey: deviceKey,
		OwnerGrantID: grantID, OwnerGrantCapabilities: capabilities, Proof: proof,
		AttemptFingerprint: FingerprintCommand([]byte("canonical failed attempt")), EvaluatedAt: now,
	}

	current := invitation
	for attempt := 1; attempt <= MaxBootstrapFailedAttempts; attempt++ {
		candidate := base
		candidate.AttemptFingerprint = FingerprintCommand([]byte(fmt.Sprintf("canonical failed attempt %d", attempt)))
		candidate.Invitation = current
		candidate.ExpectedInvitationVersion = current.Version()
		result, err := BootstrapInstallation(candidate)
		if err != nil {
			t.Fatalf("attempt %d returned error instead of accepted denial: %v", attempt, err)
		}
		wantStatus := InstallationInvitationPending
		if attempt == MaxBootstrapFailedAttempts {
			wantStatus = InstallationInvitationExhausted
		}
		if result.Outcome() != BootstrapInstallationProofRejected ||
			result.Invitation().FailedAttempts() != uint8(attempt) ||
			result.Invitation().Version().Uint64() != uint64(attempt+1) ||
			result.Invitation().Status() != wantStatus || !result.Principal().IsZero() ||
			!result.Device().IsZero() || !result.OwnerGrant().IsZero() || len(result.Facts()) != 0 {
			t.Fatalf("attempt %d produced invalid denial: %#v", attempt, result)
		}
		rejection, ok := result.Rejection()
		if !ok || rejection.InvitationID() != invitationID ||
			rejection.InvitationVersion() != result.Invitation().Version() ||
			rejection.AttemptFingerprint() != candidate.AttemptFingerprint {
			t.Fatalf("attempt %d lost security audit evidence: %#v", attempt, rejection)
		}
		current = result.Invitation()
	}

	afterExhaustion := base
	afterExhaustion.Invitation = current
	afterExhaustion.ExpectedInvitationVersion = current.Version()
	if result, err := BootstrapInstallation(afterExhaustion); !errors.Is(err, ErrStateConflict) ||
		!result.Invitation().IsZero() || result.Outcome() != "" {
		t.Fatalf("post-exhaustion attempt mutated state: %#v, %v", result, err)
	}

	first := base
	first.Invitation = invitation
	first.ExpectedInvitationVersion = invitation.Version()
	firstResult, err := BootstrapInstallation(first)
	if err != nil {
		t.Fatal(err)
	}
	staleConcurrent := first
	staleConcurrent.Invitation = firstResult.Invitation()
	if result, err := BootstrapInstallation(staleConcurrent); !errors.Is(err, ErrStaleVersion) ||
		!result.Invitation().IsZero() || firstResult.Invitation().FailedAttempts() != 1 {
		t.Fatalf("concurrent failed attempt did not serialize once: %#v, %v", result, err)
	}
}

func TestBootstrapRestartRequiresAuthorityBoundResume(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	installationID, _ := ParseInstallationID(identityUUID(180))
	invitationID, _ := ParseInvitationID(identityUUID(181))
	principalID, _ := ParsePrincipalID(identityUUID(182))
	deviceID, _ := ParseDeviceID(identityUUID(183))
	grantID, _ := ParseGrantID(identityUUID(184))
	name, _ := NewDisplayName("Restart Owner")
	deviceKey, _ := NewPublicKeyReference("keyref:restart-device")
	capabilities := ownerCapabilitySet(t)
	invitation, proof, _ := testBootstrapMaterials(
		t, invitationID, installationID, principalID, name, deviceID, name, deviceKey,
		grantID, capabilities, FingerprintCommand([]byte("restart verifier")), now,
	)
	currentGeneration, _ := ParseBootstrapGenerationID(identityUUID(185))
	restarted, _ := SameBootstrapGeneration(currentGeneration)
	base := BootstrapInstallationInput{
		Invitation: invitation, ExpectedInvitationVersion: invitation.Version(),
		CurrentGeneration: currentGeneration, GenerationAuthorization: restarted,
		PrincipalID: principalID, PrincipalDisplayName: name,
		DeviceID: deviceID, DeviceDisplayName: name, DevicePublicKey: deviceKey,
		OwnerGrantID: grantID, OwnerGrantCapabilities: capabilities, Proof: proof,
		AttemptFingerprint: FingerprintCommand([]byte("restart attempt")), EvaluatedAt: now,
	}
	if result, err := BootstrapInstallation(base); !errors.Is(err, ErrStateConflict) || !result.Invitation().IsZero() {
		t.Fatalf("restart reused invitation without approval: %#v, %v", result, err)
	}
	approval, err := NewVerifiedBootstrapResumeApproval(
		invitationID, installationID, invitation.BootstrapGenerationID(), currentGeneration,
		FingerprintCommand([]byte("authority-bound resume approval")),
	)
	if err != nil {
		t.Fatal(err)
	}
	otherInvitation, _ := ParseInvitationID(identityUUID(186))
	otherInstallation, _ := ParseInstallationID(identityUUID(187))
	otherPrevious, _ := ParseBootstrapGenerationID(identityUUID(188))
	otherCurrent, _ := ParseBootstrapGenerationID(identityUUID(189))
	resumeMutations := []struct {
		name   string
		mutate func(*VerifiedBootstrapResumeApproval)
	}{
		{"wrong invitation", func(value *VerifiedBootstrapResumeApproval) { value.invitationID = otherInvitation }},
		{"wrong installation", func(value *VerifiedBootstrapResumeApproval) { value.installationID = otherInstallation }},
		{"wrong previous generation", func(value *VerifiedBootstrapResumeApproval) { value.previousGeneration = otherPrevious }},
		{"wrong current generation", func(value *VerifiedBootstrapResumeApproval) { value.currentGeneration = otherCurrent }},
	}
	for _, mutation := range resumeMutations {
		t.Run(mutation.name, func(t *testing.T) {
			altered := approval
			mutation.mutate(&altered)
			authorization, authorizationErr := ResumeBootstrapInvitation(altered)
			if authorizationErr != nil {
				t.Fatal(authorizationErr)
			}
			candidate := base
			candidate.GenerationAuthorization = authorization
			if rejected, transitionErr := BootstrapInstallation(candidate); !errors.Is(transitionErr, ErrStateConflict) || !rejected.Invitation().IsZero() {
				t.Fatalf("altered resume accepted: %#v, %v", rejected, transitionErr)
			}
		})
	}
	base.GenerationAuthorization, err = ResumeBootstrapInvitation(approval)
	if err != nil {
		t.Fatal(err)
	}
	result, err := BootstrapInstallation(base)
	if err != nil || result.Outcome() != BootstrapInstallationCompleted ||
		result.Invitation().Status() != InstallationInvitationConsumed {
		t.Fatalf("authorized resume failed: %#v, %v", result, err)
	}
}

func TestBootstrapTranscriptBoundFieldMutationsRecordDenial(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	installationID, _ := ParseInstallationID(identityUUID(190))
	invitationID, _ := ParseInvitationID(identityUUID(191))
	principalID, _ := ParsePrincipalID(identityUUID(192))
	deviceID, _ := ParseDeviceID(identityUUID(193))
	grantID, _ := ParseGrantID(identityUUID(194))
	name, _ := NewDisplayName("Bound Owner")
	otherName, _ := NewDisplayName("Altered")
	deviceKey, _ := NewPublicKeyReference("keyref:bound-device")
	otherKey, _ := NewPublicKeyReference("keyref:altered")
	capabilities := ownerCapabilitySet(t)
	invitation, proof, generationAuthorization := testBootstrapMaterials(
		t, invitationID, installationID, principalID, name, deviceID, name, deviceKey,
		grantID, capabilities, FingerprintCommand([]byte("bound verifier")), now,
	)
	otherInstallation, _ := ParseInstallationID(identityUUID(195))
	otherPrincipal, _ := ParsePrincipalID(identityUUID(196))
	otherDevice, _ := ParseDeviceID(identityUUID(197))
	otherGrant, _ := ParseGrantID(identityUUID(198))
	mutations := []struct {
		name   string
		mutate func(*BootstrapInstallationInput)
	}{
		{"invitation evidence", func(input *BootstrapInstallationInput) {
			input.Proof.invitationEvidence = FingerprintCommand([]byte("altered"))
		}},
		{"installation id", func(input *BootstrapInstallationInput) { input.Proof.installationID = otherInstallation }},
		{"installation key", func(input *BootstrapInstallationInput) { input.Proof.installationKey = otherKey }},
		{"client nonce", func(input *BootstrapInstallationInput) { input.Proof.clientNonceDigest = CommandFingerprint{} }},
		{"server nonce", func(input *BootstrapInstallationInput) { input.Proof.serverNonceDigest = CommandFingerprint{} }},
		{"protocol", func(input *BootstrapInstallationInput) { input.Proof.protocol = PairingProtocol("altered") }},
		{"role", func(input *BootstrapInstallationInput) { input.Proof.role = BootstrapRole("altered") }},
		{"principal id", func(input *BootstrapInstallationInput) { input.Proof.principalID = otherPrincipal }},
		{"principal name", func(input *BootstrapInstallationInput) { input.Proof.principalDisplayName = otherName }},
		{"device id", func(input *BootstrapInstallationInput) { input.Proof.deviceID = otherDevice }},
		{"device name", func(input *BootstrapInstallationInput) { input.Proof.deviceDisplayName = otherName }},
		{"device key", func(input *BootstrapInstallationInput) { input.Proof.devicePublicKey = otherKey }},
		{"grant id", func(input *BootstrapInstallationInput) { input.Proof.ownerGrantID = otherGrant }},
		{"grant capabilities", func(input *BootstrapInstallationInput) {
			input.OwnerGrantCapabilities = ownerCapabilitySet(t, testCapability(t, "altered:capability"))
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			input := BootstrapInstallationInput{
				Invitation: invitation, ExpectedInvitationVersion: invitation.Version(),
				CurrentGeneration: generationAuthorization.CurrentGeneration(), GenerationAuthorization: generationAuthorization,
				PrincipalID: principalID, PrincipalDisplayName: name,
				DeviceID: deviceID, DeviceDisplayName: name, DevicePublicKey: deviceKey,
				OwnerGrantID: grantID, OwnerGrantCapabilities: capabilities, Proof: proof,
				AttemptFingerprint: FingerprintCommand([]byte("mutation attempt")), EvaluatedAt: now,
			}
			mutation.mutate(&input)
			result, err := BootstrapInstallation(input)
			if err != nil || result.Outcome() != BootstrapInstallationProofRejected ||
				result.Invitation().FailedAttempts() != 1 || !result.Principal().IsZero() || len(result.Facts()) != 0 {
				t.Fatalf("mutation was not an accepted authenticated denial: %#v, %v", result, err)
			}
		})
	}
}

func TestFullProvisioningPathProducesExactTypedFacts(t *testing.T) {
	fixture := buildIdentityPath(t)
	if fixture.workspace.Status() != WorkspaceActive || fixture.ownerMembership.Status() != MembershipActive ||
		fixture.workload.Status() != PrincipalActive || fixture.membership.Status() != MembershipActive ||
		fixture.actor.Status() != ActorActive || fixture.delegation.Status() != DelegationActive ||
		fixture.sessionChallenge.Status() != CeremonyPending {
		t.Fatalf("provisioning path incomplete: %#v", fixture)
	}
	if fixture.membership.AcceptanceChallenge().Status() != CeremonyConsumed ||
		fixture.delegation.ActivationChallenge().Status() != CeremonyConsumed {
		t.Fatal("one-use provisioning ceremonies were not consumed")
	}
}

func baseSessionInput(t *testing.T, fixture identityPathFixture) StartActorSessionInput {
	t.Helper()
	proof, _ := NewCeremonyProof(
		fixture.sessionChallenge.ID(), CeremonyPurposeActorSessionStart,
		fixture.sessionChallenge.ProofDigest(), fixture.workload.ID(), DeviceID{},
	)
	authority, _ := HandoffSessionStart(fixture.sessionChallenge, proof)
	sessionID, _ := ParseActorSessionID(identityUUID(40))
	clientID, _ := ParseClientInstanceID(identityUUID(41))
	client, _ := NewClientMetadata("blackbird-agent", "1.0.0")
	return StartActorSessionInput{
		Authorization: fixtureIdentityAuthorization(t, fixture, fixture.workload.ID(), testCapabilities(t, fixture.workRead, fixture.workWrite)),
		SessionID:     sessionID, ClientInstanceID: clientID, ClientMetadata: client,
		Workspace: fixture.workspace, ExpectedWorkspaceVersion: fixture.workspace.Version(),
		Principal: fixture.workload, ExpectedPrincipalVersion: fixture.workload.Version(),
		Membership: fixture.membership, ExpectedMembershipVersion: fixture.membership.Version(),
		Actor: fixture.actor, ExpectedActorVersion: fixture.actor.Version(),
		Delegation: fixture.delegation, ExpectedDelegationVersion: fixture.delegation.Version(),
		StartAuthority: authority, AbsoluteExpiry: fixture.now.Add(8 * time.Hour),
	}
}

func fixtureIdentityAuthorization(
	t *testing.T,
	fixture identityPathFixture,
	principalID PrincipalID,
	capabilities CapabilitySet,
) IdentityAuthorization {
	t.Helper()
	authorization, err := NewWorkspaceIdentityAuthorization(
		fixture.authorityID, fixture.epoch, fixture.installationID, fixture.workspace.ID(), principalID,
		capabilities, fixture.policy, fixture.assurance, fixture.now, MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func fixtureDeviceIdentityAuthorization(
	t *testing.T,
	fixture identityPathFixture,
	principalID PrincipalID,
	capabilities CapabilitySet,
	device DeviceState,
) IdentityAuthorization {
	t.Helper()
	authorization, err := NewDeviceBoundWorkspaceIdentityAuthorization(
		fixture.authorityID, fixture.epoch, fixture.installationID, fixture.workspace.ID(), principalID,
		capabilities, fixture.policy, fixture.assurance, fixture.now, MaxActorSessionLifetime,
		device.ID(), device.TrustRevision(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func TestStartActorSessionHandoffIsAtomicAndNarrowed(t *testing.T) {
	fixture := buildIdentityPath(t)
	input := baseSessionInput(t, fixture)
	grantID, _ := ParseGrantID(identityUUID(42))
	grant := GrantState{
		id: grantID, installationID: fixture.installationID, workspaceID: fixture.workspace.ID(),
		principalID: fixture.workload.ID(), status: GrantActive, version: InitialVersion(),
		capabilities: testCapabilities(t, fixture.workRead, fixture.workWrite),
	}
	revision, _ := NewGrantRevision(grant, grant.Version())
	input.Grants = []GrantRevision{revision}

	result, err := StartActorSession(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Session().Status() != ActorSessionActive || result.Session().Version() != InitialVersion() ||
		!result.Session().Capabilities().Equal(testCapabilities(t, fixture.workRead)) {
		t.Fatalf("session state = %#v", result.Session())
	}
	consumed, ok := result.ConsumedHandoff()
	if !ok || consumed.Status() != CeremonyConsumed {
		t.Fatalf("consumed handoff = %#v, %v", consumed, ok)
	}
	facts := result.Facts()
	if len(facts) != 1 || facts[0].Type() != EventTypeActorSessionStarted ||
		facts[0].Origin().Kind() != AggregateKindActorSession || facts[0].Origin().Version() != InitialVersion() {
		t.Fatalf("session facts = %#v", facts)
	}
	fact := facts[0].(ActorSessionStartedFact)
	if fact.ClientInstanceID() != input.ClientInstanceID || fact.ClientMetadata() != input.ClientMetadata ||
		!fact.Capabilities().Equal(testCapabilities(t, fixture.workRead)) {
		t.Fatalf("session fact lost client or capability metadata: %#v", fact)
	}
}

func TestStartActorSessionTrustedDeviceDoesNotConsumeHandoff(t *testing.T) {
	fixture := buildIdentityPath(t)
	input := baseSessionInput(t, fixture)
	deviceID, _ := ParseDeviceID(identityUUID(43))
	name, _ := NewDisplayName("Trusted Device")
	key, _ := NewPublicKeyReference("keyref:trusted")
	device := DeviceState{
		id: deviceID, installationID: fixture.installationID, principalID: fixture.workload.ID(),
		displayName: name, publicKey: key, status: DeviceTrusted, version: mustVersion(t, 3), trustRevision: mustVersion(t, 2),
	}
	authority, _ := TrustedDeviceSessionStart(device, device.Version(), device.TrustRevision())
	input.Authorization = fixtureDeviceIdentityAuthorization(
		t, fixture, fixture.workload.ID(), testCapabilities(t, fixture.workRead, fixture.workWrite), device,
	)
	input.StartAuthority = authority
	result, err := StartActorSession(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, consumed := result.ConsumedHandoff(); consumed {
		t.Fatal("trusted-device start consumed a handoff")
	}
	deviceRevision, present := result.Session().Binding().DeviceRevision()
	if !present || deviceRevision.ID() != device.ID().String() || deviceRevision.Version() != device.Version() {
		t.Fatalf("device revision = %#v, %v", deviceRevision, present)
	}
}

func TestStartActorSessionAdverseMatrixReturnsNoPartialOutcome(t *testing.T) {
	fixture := buildIdentityPath(t)
	tests := []struct {
		name   string
		mutate func(*StartActorSessionInput)
		match  error
	}{
		{"stale membership", func(input *StartActorSessionInput) { input.ExpectedMembershipVersion = InitialVersion() }, ErrStaleVersion},
		{"revoked membership", func(input *StartActorSessionInput) { input.Membership.status = MembershipRevoked }, ErrStateConflict},
		{"cross workspace actor", func(input *StartActorSessionInput) {
			input.Actor.workspaceID, _ = ParseWorkspaceID(identityUUID(90))
		}, ErrStateConflict},
		{"cross workspace authorization", func(input *StartActorSessionInput) {
			input.Authorization.workspaceID, _ = ParseWorkspaceID(identityUUID(92))
		}, ErrStateConflict},
		{"cross principal delegation", func(input *StartActorSessionInput) {
			input.Delegation.principalID, _ = ParsePrincipalID(identityUUID(91))
		}, ErrStateConflict},
		{"revoked delegation", func(input *StartActorSessionInput) { input.Delegation.status = DelegationRevoked }, ErrStateConflict},
		{"service principal", func(input *StartActorSessionInput) { input.Principal.kind = PrincipalKindService }, ErrForbidden},
		{"expired handoff", func(input *StartActorSessionInput) {
			input.StartAuthority.challenge.expiresAt = fixture.now
		}, ErrUnauthenticated},
		{"wrong purpose", func(input *StartActorSessionInput) {
			input.StartAuthority.challenge.purpose = CeremonyPurposeDevicePairing
		}, ErrUnauthenticated},
		{"consumed handoff", func(input *StartActorSessionInput) {
			input.StartAuthority.challenge.status = CeremonyConsumed
		}, ErrUnauthenticated},
		{"existing terminal session", func(input *StartActorSessionInput) {
			input.Session = ActorSessionState{id: input.SessionID, status: ActorSessionRevoked, version: InitialVersion()}
		}, ErrStateConflict},
		{"existing active session", func(input *StartActorSessionInput) {
			input.Session = ActorSessionState{id: input.SessionID, status: ActorSessionActive, version: InitialVersion()}
		}, ErrStateConflict},
		{"lifetime exceeds authorization", func(input *StartActorSessionInput) {
			input.AbsoluteExpiry = input.Authorization.EvaluatedAt().Add(MaxActorSessionLifetime + time.Second)
		}, ErrInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := baseSessionInput(t, fixture)
			test.mutate(&input)
			result, err := StartActorSession(input)
			if !errors.Is(err, test.match) {
				t.Fatalf("error = %v, want %v", err, test.match)
			}
			if !result.Session().IsZero() || len(result.Facts()) != 0 {
				t.Fatalf("rejection returned partial result: %#v", result)
			}
		})
	}

	input := baseSessionInput(t, fixture)
	input.Session = ActorSessionState{id: input.SessionID, status: ActorSessionActive, version: InitialVersion()}
	_, err := StartActorSession(input)
	var commandError *CommandError
	if !errors.As(err, &commandError) {
		t.Fatalf("active session error = %v", err)
	}
	if kind, ok := commandError.ConflictKind(); !ok || kind != ConflictState {
		t.Fatalf("active session conflict = %v, %v", kind, ok)
	}
	input.Session.status = ActorSessionEnded
	_, err = StartActorSession(input)
	if !errors.As(err, &commandError) {
		t.Fatalf("terminal session error = %v", err)
	}
	if kind, ok := commandError.ConflictKind(); !ok || kind != ConflictSessionTerminal {
		t.Fatalf("terminal session conflict = %v, %v", kind, ok)
	}

	input = baseSessionInput(t, fixture)
	input.Grants = make([]GrantRevision, MaxSessionGrantRevisions+1)
	for index := range input.Grants {
		grantID, _ := ParseGrantID(identityUUID(2000 + index))
		grant := GrantState{
			id: grantID, installationID: fixture.installationID, workspaceID: fixture.workspace.ID(),
			principalID: fixture.workload.ID(), status: GrantActive, version: InitialVersion(),
			capabilities: testCapabilities(t, fixture.workRead),
		}
		input.Grants[index], _ = NewGrantRevision(grant, grant.Version())
	}
	if result, err := StartActorSession(input); !errors.Is(err, ErrInvalidArgument) || !result.Session().IsZero() {
		t.Fatalf("unbounded session grants result = %#v, %v", result, err)
	}
}

func TestRevokedDeviceAndGrantRejectSession(t *testing.T) {
	fixture := buildIdentityPath(t)
	input := baseSessionInput(t, fixture)
	deviceID, _ := ParseDeviceID(identityUUID(50))
	device := DeviceState{
		id: deviceID, installationID: fixture.installationID, principalID: fixture.workload.ID(),
		status: DeviceRevoked, version: InitialVersion(), trustRevision: InitialVersion(),
	}
	deviceAuthority, _ := TrustedDeviceSessionStart(device, device.Version(), device.TrustRevision())
	input.StartAuthority = deviceAuthority
	if result, err := StartActorSession(input); !errors.Is(err, ErrUnauthenticated) || !result.Session().IsZero() {
		t.Fatalf("revoked device result = %#v, %v", result, err)
	}

	input = baseSessionInput(t, fixture)
	grantID, _ := ParseGrantID(identityUUID(51))
	grant := GrantState{
		id: grantID, installationID: fixture.installationID, workspaceID: fixture.workspace.ID(),
		principalID: fixture.workload.ID(), status: GrantRevoked, version: InitialVersion(),
		capabilities: testCapabilities(t, fixture.workRead),
	}
	revision, _ := NewGrantRevision(grant, grant.Version())
	input.Grants = []GrantRevision{revision}
	if result, err := StartActorSession(input); !errors.Is(err, ErrForbidden) || !result.Session().IsZero() {
		t.Fatalf("revoked grant result = %#v, %v", result, err)
	}
}

func TestCeremonyPurposeExpiryPrincipalAndReplayGuards(t *testing.T) {
	fixture := buildIdentityPath(t)
	base := fixture.membership
	base.status = MembershipInvited
	base.version = InitialVersion()
	base.acceptance.status = CeremonyPending
	proof, _ := NewCeremonyProof(
		base.acceptance.ID(), CeremonyPurposeMembershipAcceptance, base.acceptance.ProofDigest(), fixture.workload.ID(), DeviceID{},
	)
	workloadAuth := fixtureIdentityAuthorization(t, fixture, fixture.workload.ID(), testCapabilities(t, fixture.workRead))
	input := AcceptWorkspaceMembershipInput{
		Authorization: workloadAuth, Principal: fixture.workload, ExpectedPrincipalVersion: fixture.workload.Version(),
		Workspace: fixture.workspace, ExpectedWorkspaceVersion: fixture.workspace.Version(),
		Membership: base, ExpectedMembershipVersion: base.Version(), Proof: proof,
	}
	tests := []struct {
		name   string
		mutate func(*AcceptWorkspaceMembershipInput)
		match  error
	}{
		{"wrong purpose", func(input *AcceptWorkspaceMembershipInput) { input.Proof.purpose = CeremonyPurposeDevicePairing }, ErrStateConflict},
		{"expired", func(input *AcceptWorkspaceMembershipInput) { input.Membership.acceptance.expiresAt = fixture.now }, ErrStateConflict},
		{"consumed", func(input *AcceptWorkspaceMembershipInput) { input.Membership.acceptance.status = CeremonyConsumed }, ErrStateConflict},
		{"malformed retained binding", func(input *AcceptWorkspaceMembershipInput) {
			input.Membership.acceptance.workspaceID, _ = ParseWorkspaceID(identityUUID(98))
		}, ErrStateConflict},
		{"stale workspace policy", func(input *AcceptWorkspaceMembershipInput) {
			input.Workspace.policy, _ = NewPolicyRevision("local-policy:changed")
		}, ErrStateConflict},
		{"wrong principal", func(input *AcceptWorkspaceMembershipInput) {
			input.Proof.principalID, _ = ParsePrincipalID(identityUUID(99))
		}, ErrForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := input
			test.mutate(&candidate)
			result, err := AcceptWorkspaceMembership(candidate)
			if !errors.Is(err, test.match) || !result.Membership().IsZero() || len(result.Facts()) != 0 {
				t.Fatalf("result = %#v, error = %v", result, err)
			}
		})
	}
}

func TestCeremonyIssuanceRejectsConsumedChallenges(t *testing.T) {
	fixture := buildIdentityPath(t)

	membershipID, _ := ParseMembershipID(identityUUID(210))
	membershipCeremonyID, _ := ParseCeremonyID(identityUUID(211))
	membershipChallenge, _ := NewMembershipAcceptanceChallenge(
		membershipCeremonyID, FingerprintCommand([]byte("consumed membership")), fixture.now.Add(time.Minute),
		fixture.workspace.ID(), membershipID, fixture.workload.ID(),
	)
	membershipChallenge.status = CeremonyConsumed
	membershipCreation, _ := ExpectCeremonyAbsent(membershipCeremonyID)
	if result, err := InviteWorkspaceMember(InviteWorkspaceMemberInput{
		Authorization: fixture.ownerWorkspaceAuth, Administrator: fixture.owner,
		ExpectedAdministratorVersion: fixture.owner.Version(), Workspace: fixture.workspace,
		ExpectedWorkspaceVersion: fixture.workspace.Version(), Principal: fixture.workload,
		ExpectedPrincipalVersion: fixture.workload.Version(), MembershipID: membershipID,
		Capabilities: testCapabilities(t, fixture.workRead), Challenge: membershipChallenge,
		ChallengeCreation: membershipCreation,
	}); !errors.Is(err, ErrStateConflict) || !result.Membership().IsZero() {
		t.Fatalf("consumed membership challenge result = %#v, %v", result, err)
	}

	delegationID, _ := ParseActorDelegationID(identityUUID(212))
	delegationCeremonyID, _ := ParseCeremonyID(identityUUID(213))
	delegationChallenge, _ := NewDelegationActivationChallenge(
		delegationCeremonyID, FingerprintCommand([]byte("consumed delegation")), fixture.now.Add(time.Minute),
		fixture.workspace.ID(), delegationID, fixture.workload.ID(), fixture.actor.ID(),
	)
	delegationChallenge.status = CeremonyConsumed
	delegationCreation, _ := ExpectCeremonyAbsent(delegationCeremonyID)
	if result, err := ProposeActorDelegation(ProposeActorDelegationInput{
		Authorization: fixture.ownerWorkspaceAuth, Administrator: fixture.owner,
		ExpectedAdministratorVersion: fixture.owner.Version(), Workspace: fixture.workspace,
		ExpectedWorkspaceVersion: fixture.workspace.Version(), Principal: fixture.workload,
		ExpectedPrincipalVersion: fixture.workload.Version(), Actor: fixture.actor,
		ExpectedActorVersion: fixture.actor.Version(), Membership: fixture.membership,
		ExpectedMembershipVersion: fixture.membership.Version(), DelegationID: delegationID,
		Capabilities: testCapabilities(t, fixture.workRead), Challenge: delegationChallenge,
		ChallengeCreation: delegationCreation,
	}); !errors.Is(err, ErrStateConflict) || !result.Delegation().IsZero() {
		t.Fatalf("consumed delegation challenge result = %#v, %v", result, err)
	}

	proposed := fixture.delegation
	proposed.status = DelegationProposed
	proposed.activation.status = CeremonyPending
	activationProof, _ := NewCeremonyProof(
		proposed.activation.ID(), CeremonyPurposeDelegationActivation, proposed.activation.ProofDigest(),
		fixture.workload.ID(), DeviceID{},
	)
	consumedSession := fixture.sessionChallenge
	consumedSession.status = CeremonyConsumed
	sessionCreation, _ := ExpectCeremonyAbsent(consumedSession.ID())
	if result, err := ActivateActorDelegation(ActivateActorDelegationInput{
		Authorization: fixtureIdentityAuthorization(t, fixture, fixture.workload.ID(), testCapabilities(t, fixture.workRead)),
		Workspace:     fixture.workspace, ExpectedWorkspaceVersion: fixture.workspace.Version(),
		Principal: fixture.workload, ExpectedPrincipalVersion: fixture.workload.Version(),
		Actor: fixture.actor, ExpectedActorVersion: fixture.actor.Version(),
		Membership: fixture.membership, ExpectedMembershipVersion: fixture.membership.Version(),
		Delegation: proposed, ExpectedDelegationVersion: proposed.Version(), Proof: activationProof,
		SessionStartChallenge: consumedSession, SessionChallengeCreation: sessionCreation,
	}); !errors.Is(err, ErrStateConflict) || !result.Delegation().IsZero() {
		t.Fatalf("consumed session challenge result = %#v, %v", result, err)
	}
	activeSession := consumedSession
	activeSession.status = CeremonyPending
	disabledActor := fixture.actor
	disabledActor.status = ActorSuspended
	if result, err := ActivateActorDelegation(ActivateActorDelegationInput{
		Authorization: fixtureIdentityAuthorization(t, fixture, fixture.workload.ID(), testCapabilities(t, fixture.workRead)),
		Workspace:     fixture.workspace, ExpectedWorkspaceVersion: fixture.workspace.Version(),
		Principal: fixture.workload, ExpectedPrincipalVersion: fixture.workload.Version(),
		Actor: disabledActor, ExpectedActorVersion: disabledActor.Version(),
		Membership: fixture.membership, ExpectedMembershipVersion: fixture.membership.Version(),
		Delegation: proposed, ExpectedDelegationVersion: proposed.Version(), Proof: activationProof,
		SessionStartChallenge: activeSession, SessionChallengeCreation: sessionCreation,
	}); !errors.Is(err, ErrStateConflict) || !result.Delegation().IsZero() {
		t.Fatalf("disabled actor activation result = %#v, %v", result, err)
	}
	narrowedMembership := fixture.membership
	narrowedMembership.capabilities = testCapabilities(t, fixture.workWrite)
	narrowedMembership.version = mustVersion(t, fixture.membership.Version().Uint64()+1)
	if result, err := ActivateActorDelegation(ActivateActorDelegationInput{
		Authorization: fixtureIdentityAuthorization(
			t, fixture, fixture.workload.ID(), testCapabilities(t, fixture.workRead, fixture.workWrite),
		),
		Workspace: fixture.workspace, ExpectedWorkspaceVersion: fixture.workspace.Version(),
		Principal: fixture.workload, ExpectedPrincipalVersion: fixture.workload.Version(),
		Actor: fixture.actor, ExpectedActorVersion: fixture.actor.Version(),
		Membership: narrowedMembership, ExpectedMembershipVersion: narrowedMembership.Version(),
		Delegation: proposed, ExpectedDelegationVersion: proposed.Version(), Proof: activationProof,
		SessionStartChallenge: activeSession, SessionChallengeCreation: sessionCreation,
	}); !errors.Is(err, ErrForbidden) || !result.Delegation().IsZero() || len(result.Facts()) != 0 {
		t.Fatalf("narrowed membership activation result = %#v, %v", result, err)
	}
}

func TestCapabilityAndResultInputsAreImmutable(t *testing.T) {
	first := testCapability(t, "work:read")
	second := testCapability(t, "work:write")
	input := []Capability{first, second}
	set, err := NewCapabilitySet(input...)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = Capability{}
	returned := set.Values()
	returned[0] = Capability{}
	if !set.Contains(first) || !set.Contains(second) {
		t.Fatal("capability set leaked mutable slice storage")
	}
	if _, err := NewCapability("work:*"); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("wildcard capability error = %v", err)
	}
	tooMany := make([]Capability, MaxIdentityCapabilities+1)
	for index := range tooMany {
		tooMany[index] = testCapability(t, fmt.Sprintf("bounded:%d", index))
	}
	if _, err := NewCapabilitySet(tooMany...); !errors.Is(err, ErrInvalidCapabilitySet) {
		t.Fatalf("unbounded capability set error = %v", err)
	}
}

func TestCreateWorkspaceOptionalDiscoveryAndCapabilityCeilings(t *testing.T) {
	fixture := buildIdentityPath(t)
	newInput := func(index int) CreateWorkspaceInput {
		workspaceID, _ := ParseWorkspaceID(identityUUID(index))
		membershipID, _ := ParseMembershipID(identityUUID(index + 1))
		alias, _ := NewWorkspaceAlias(fmt.Sprintf("workspace-%d", index))
		return CreateWorkspaceInput{
			Authorization: fixture.ownerAuth, Owner: fixture.owner, ExpectedOwnerVersion: fixture.owner.Version(),
			InstallationGrant: fixture.ownerGrant, ExpectedGrantVersion: fixture.ownerGrant.Version(),
			WorkspaceID: workspaceID, Alias: alias, OwnerMembershipID: membershipID,
			OwnerCapabilities: fixture.ownerMembership.Capabilities(),
		}
	}
	result, err := CreateWorkspace(newInput(110))
	if err != nil {
		t.Fatalf("optional discovery locator rejected: %v", err)
	}
	if result.Workspace().DiscoveryLocator().String() != "" {
		t.Fatal("absent discovery locator was manufactured")
	}

	extra := testCapability(t, "workspace:export")
	t.Run("authorization ceiling", func(t *testing.T) {
		input := newInput(112)
		input.OwnerCapabilities = workspaceOwnerCapabilitySet(t, fixture.workRead, fixture.workWrite, extra)
		if result, err := CreateWorkspace(input); !errors.Is(err, ErrForbidden) || !result.Workspace().IsZero() {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})
	t.Run("grant ceiling", func(t *testing.T) {
		input := newInput(114)
		input.OwnerCapabilities = workspaceOwnerCapabilitySet(t, fixture.workRead, fixture.workWrite, extra)
		authorizationValues := fixture.ownerAuth.Capabilities().Values()
		authorizationValues = append(authorizationValues, extra)
		authorizationCapabilities := testCapabilities(t, authorizationValues...)
		input.Authorization, _ = NewIdentityAuthorization(
			fixture.authorityID, fixture.epoch, fixture.installationID, fixture.owner.ID(),
			authorizationCapabilities, fixture.policy, fixture.assurance, fixture.now, MaxActorSessionLifetime,
		)
		if result, err := CreateWorkspace(input); !errors.Is(err, ErrForbidden) || !result.Workspace().IsZero() {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})
}

func TestSessionCapabilitiesAreNarrowedByEvaluatedAuthorization(t *testing.T) {
	fixture := buildIdentityPath(t)
	input := baseSessionInput(t, fixture)
	input.Delegation.capabilities = testCapabilities(t, fixture.workRead, fixture.workWrite)
	input.Authorization = fixtureIdentityAuthorization(t, fixture, fixture.workload.ID(), testCapabilities(t, fixture.workRead))
	result, err := StartActorSession(input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Session().Capabilities().Equal(testCapabilities(t, fixture.workRead)) {
		t.Fatalf("effective capabilities = %#v", result.Session().Capabilities())
	}
}

func TestSessionBindsExplicitDeviceTrustRevision(t *testing.T) {
	fixture := buildIdentityPath(t)
	input := baseSessionInput(t, fixture)
	deviceID, _ := ParseDeviceID(identityUUID(120))
	device := DeviceState{
		id: deviceID, installationID: fixture.installationID, principalID: fixture.workload.ID(),
		status: DeviceTrusted, version: mustVersion(t, 5), trustRevision: mustVersion(t, 3),
	}
	authority, _ := TrustedDeviceSessionStart(device, device.Version(), device.TrustRevision())
	input.Authorization = fixtureDeviceIdentityAuthorization(
		t, fixture, fixture.workload.ID(), testCapabilities(t, fixture.workRead, fixture.workWrite), device,
	)
	input.StartAuthority = authority
	result, err := StartActorSession(input)
	if err != nil {
		t.Fatal(err)
	}
	trustRevision, present := result.Session().Binding().DeviceTrustRevision()
	if !present || trustRevision != device.TrustRevision() || trustRevision == device.Version() {
		t.Fatalf("trust revision = %v, %v; device version = %v", trustRevision, present, device.Version())
	}
	otherDeviceID, _ := ParseDeviceID(identityUUID(121))
	otherDevice := device
	otherDevice.id = otherDeviceID
	substituted, _ := TrustedDeviceSessionStart(otherDevice, otherDevice.Version(), otherDevice.TrustRevision())
	input.Session = ActorSessionState{}
	input.StartAuthority = substituted
	if result, err := StartActorSession(input); !errors.Is(err, ErrUnauthenticated) || !result.Session().IsZero() {
		t.Fatalf("substituted device result = %#v, error = %v", result, err)
	}

	stale, _ := TrustedDeviceSessionStart(device, device.Version(), mustVersion(t, 2))
	input.Session = ActorSessionState{}
	input.StartAuthority = stale
	if result, err := StartActorSession(input); !errors.Is(err, ErrStaleVersion) || !result.Session().IsZero() {
		t.Fatalf("stale trust result = %#v, error = %v", result, err)
	}
}

func TestVersionOverflowRejectsIdentityMutationsAtomically(t *testing.T) {
	fixture := buildIdentityPath(t)
	maximum := mustVersion(t, ^uint64(0))

	t.Run("installation invitation", func(t *testing.T) {
		installationID, _ := ParseInstallationID(identityUUID(130))
		invitationID, _ := ParseInvitationID(identityUUID(131))
		principalID, _ := ParsePrincipalID(identityUUID(132))
		deviceID, _ := ParseDeviceID(identityUUID(133))
		grantID, _ := ParseGrantID(identityUUID(134))
		digest := FingerprintCommand([]byte("overflow bootstrap"))
		name, _ := NewDisplayName("Overflow")
		key, _ := NewPublicKeyReference("keyref:overflow")
		capabilities := ownerCapabilitySet(t)
		invitation, proof, generationAuthorization := testBootstrapMaterials(
			t, invitationID, installationID, principalID, name, deviceID, name, key,
			grantID, capabilities, digest, fixture.now,
		)
		invitation.version = maximum
		result, err := BootstrapInstallation(BootstrapInstallationInput{
			Invitation: invitation, ExpectedInvitationVersion: maximum,
			CurrentGeneration: generationAuthorization.CurrentGeneration(), GenerationAuthorization: generationAuthorization,
			PrincipalID: principalID, PrincipalDisplayName: name,
			DeviceID: deviceID, DeviceDisplayName: name, DevicePublicKey: key,
			OwnerGrantID: grantID, OwnerGrantCapabilities: capabilities, Proof: proof, EvaluatedAt: fixture.now,
			AttemptFingerprint: FingerprintCommand([]byte("overflow attempt")),
		})
		if !errors.Is(err, ErrVersionOverflow) || !result.Principal().IsZero() || len(result.Facts()) != 0 {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})

	t.Run("membership acceptance", func(t *testing.T) {
		membership := fixture.membership
		membership.status = MembershipInvited
		membership.version = maximum
		membership.acceptance.status = CeremonyPending
		proof, _ := NewCeremonyProof(
			membership.acceptance.ID(), CeremonyPurposeMembershipAcceptance,
			membership.acceptance.ProofDigest(), fixture.workload.ID(), DeviceID{},
		)
		result, err := AcceptWorkspaceMembership(AcceptWorkspaceMembershipInput{
			Authorization: fixtureIdentityAuthorization(t, fixture, fixture.workload.ID(), testCapabilities(t, fixture.workRead)),
			Principal:     fixture.workload, ExpectedPrincipalVersion: fixture.workload.Version(),
			Workspace: fixture.workspace, ExpectedWorkspaceVersion: fixture.workspace.Version(),
			Membership: membership, ExpectedMembershipVersion: maximum, Proof: proof,
		})
		if !errors.Is(err, ErrVersionOverflow) || !result.Membership().IsZero() || len(result.Facts()) != 0 {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})

	t.Run("device pairing", func(t *testing.T) {
		deviceID, _ := ParseDeviceID(identityUUID(135))
		ceremonyID, _ := ParseCeremonyID(identityUUID(136))
		digest := FingerprintCommand([]byte("overflow pairing"))
		challenge, _ := NewDevicePairingChallenge(
			ceremonyID, digest, fixture.now.Add(time.Minute), fixture.installationID, fixture.workload.ID(), deviceID,
		)
		device := DeviceState{
			id: deviceID, installationID: fixture.installationID, principalID: fixture.workload.ID(),
			status: DevicePending, version: maximum, trustRevision: maximum, pairing: challenge,
		}
		proof, _ := NewCeremonyProof(ceremonyID, CeremonyPurposeDevicePairing, digest, fixture.workload.ID(), deviceID)
		result, err := PairDevice(PairDeviceInput{
			Principal: fixture.workload, ExpectedPrincipalVersion: fixture.workload.Version(),
			Device: device, ExpectedDeviceVersion: maximum, Proof: proof, EvaluatedAt: fixture.now,
		})
		if !errors.Is(err, ErrVersionOverflow) || !result.Device().IsZero() || len(result.Facts()) != 0 {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})
}

func TestBeginAndPairDeviceSuccessFacts(t *testing.T) {
	fixture := buildIdentityPath(t)
	deviceID, _ := ParseDeviceID(identityUUID(140))
	ceremonyID, _ := ParseCeremonyID(identityUUID(141))
	digest := FingerprintCommand([]byte("phone pairing"))
	challenge, _ := NewDevicePairingChallenge(
		ceremonyID, digest, fixture.now.Add(time.Minute), fixture.installationID, fixture.owner.ID(), deviceID,
	)
	name, _ := NewDisplayName("Alice Phone")
	key, _ := NewPublicKeyReference("keyref:alice-phone")
	creation, _ := ExpectCeremonyAbsent(ceremonyID)
	began, err := BeginDevicePairing(BeginDevicePairingInput{
		Authorization: fixture.ownerAuth, Principal: fixture.owner, ExpectedPrincipalVersion: fixture.owner.Version(),
		DeviceID: deviceID, DisplayName: name, PublicKeyReference: key,
		Challenge: challenge, ChallengeCreation: creation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if began.Device().Status() != DevicePending || began.Device().Version() != InitialVersion() ||
		began.Device().TrustRevision() != InitialVersion() || began.Device().DisplayName() != name ||
		began.Device().PublicKeyReference() != key {
		t.Fatalf("pending device = %#v", began.Device())
	}
	beginFacts := began.Facts()
	if len(beginFacts) != 1 || beginFacts[0].Type() != EventTypeDevicePairingBegan ||
		beginFacts[0].Origin().Kind() != AggregateKindDevice || beginFacts[0].Origin().Version() != InitialVersion() {
		t.Fatalf("begin facts = %#v", beginFacts)
	}

	proof, _ := NewCeremonyProof(ceremonyID, CeremonyPurposeDevicePairing, digest, fixture.owner.ID(), deviceID)
	paired, err := PairDevice(PairDeviceInput{
		Principal: fixture.owner, ExpectedPrincipalVersion: fixture.owner.Version(),
		Device: began.Device(), ExpectedDeviceVersion: began.Device().Version(), Proof: proof, EvaluatedAt: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if paired.Device().Status() != DeviceTrusted || paired.Device().Version().Uint64() != 2 ||
		paired.Device().TrustRevision().Uint64() != 2 || paired.Device().PairingChallenge().Status() != CeremonyConsumed {
		t.Fatalf("paired device = %#v", paired.Device())
	}
	pairFacts := paired.Facts()
	if len(pairFacts) != 1 || pairFacts[0].Type() != EventTypeDevicePaired ||
		pairFacts[0].Origin().Kind() != AggregateKindDevice || pairFacts[0].Origin().Version().Uint64() != 2 {
		t.Fatalf("pair facts = %#v", pairFacts)
	}
	pairedFact := pairFacts[0].(DevicePairedFact)
	if pairedFact.TrustRevision().Uint64() != 2 || pairedFact.TranscriptFingerprint() != digest {
		t.Fatalf("paired fact = %#v", pairedFact)
	}
}

func TestBeginDevicePairingAdverseMatrixIsAtomic(t *testing.T) {
	fixture := buildIdentityPath(t)
	deviceID, _ := ParseDeviceID(identityUUID(150))
	ceremonyID, _ := ParseCeremonyID(identityUUID(151))
	digest := FingerprintCommand([]byte("pairing begin"))
	challenge, _ := NewDevicePairingChallenge(
		ceremonyID, digest, fixture.now.Add(time.Minute), fixture.installationID, fixture.owner.ID(), deviceID,
	)
	name, _ := NewDisplayName("Phone")
	key, _ := NewPublicKeyReference("keyref:phone")
	creation, _ := ExpectCeremonyAbsent(ceremonyID)
	base := BeginDevicePairingInput{
		Authorization: fixture.ownerAuth, Principal: fixture.owner, ExpectedPrincipalVersion: fixture.owner.Version(),
		DeviceID: deviceID, DisplayName: name, PublicKeyReference: key,
		Challenge: challenge, ChallengeCreation: creation,
	}
	tests := []struct {
		name   string
		mutate func(*BeginDevicePairingInput)
		match  error
	}{
		{"existing", func(input *BeginDevicePairingInput) {
			input.Device = DeviceState{id: deviceID, status: DeviceRevoked, version: InitialVersion()}
		}, ErrStateConflict},
		{"stale principal", func(input *BeginDevicePairingInput) { input.ExpectedPrincipalVersion = mustVersion(t, 2) }, ErrStaleVersion},
		{"revoked principal", func(input *BeginDevicePairingInput) { input.Principal.status = PrincipalDisabled }, ErrForbidden},
		{"cross principal", func(input *BeginDevicePairingInput) {
			input.Challenge.principalID, _ = ParsePrincipalID(identityUUID(152))
		}, ErrStateConflict},
		{"wrong purpose", func(input *BeginDevicePairingInput) {
			input.Challenge.purpose = CeremonyPurposeMembershipAcceptance
		}, ErrStateConflict},
		{"expired", func(input *BeginDevicePairingInput) { input.Challenge.expiresAt = fixture.now }, ErrStateConflict},
		{"consumed", func(input *BeginDevicePairingInput) { input.Challenge.status = CeremonyConsumed }, ErrStateConflict},
		{"mismatched creation", func(input *BeginDevicePairingInput) {
			otherID, _ := ParseCeremonyID(identityUUID(153))
			input.ChallengeCreation, _ = ExpectCeremonyAbsent(otherID)
		}, ErrInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.mutate(&input)
			result, err := BeginDevicePairing(input)
			if !errors.Is(err, test.match) || !result.Device().IsZero() || len(result.Facts()) != 0 {
				t.Fatalf("result = %#v, error = %v", result, err)
			}
		})
	}
}

func TestPairDeviceAdverseMatrixIsAtomic(t *testing.T) {
	fixture := buildIdentityPath(t)
	deviceID, _ := ParseDeviceID(identityUUID(160))
	ceremonyID, _ := ParseCeremonyID(identityUUID(161))
	digest := FingerprintCommand([]byte("pairing redeem"))
	challenge, _ := NewDevicePairingChallenge(
		ceremonyID, digest, fixture.now.Add(time.Minute), fixture.installationID, fixture.owner.ID(), deviceID,
	)
	device := DeviceState{
		id: deviceID, installationID: fixture.installationID, principalID: fixture.owner.ID(),
		status: DevicePending, version: InitialVersion(), trustRevision: InitialVersion(), pairing: challenge,
	}
	proof, _ := NewCeremonyProof(ceremonyID, CeremonyPurposeDevicePairing, digest, fixture.owner.ID(), deviceID)
	base := PairDeviceInput{
		Principal: fixture.owner, ExpectedPrincipalVersion: fixture.owner.Version(),
		Device: device, ExpectedDeviceVersion: device.Version(), Proof: proof, EvaluatedAt: fixture.now,
	}
	tests := []struct {
		name   string
		mutate func(*PairDeviceInput)
		match  error
	}{
		{"stale", func(input *PairDeviceInput) { input.ExpectedDeviceVersion = mustVersion(t, 2) }, ErrStaleVersion},
		{"revoked", func(input *PairDeviceInput) { input.Device.status = DeviceRevoked }, ErrStateConflict},
		{"replayed", func(input *PairDeviceInput) {
			input.Device.status = DeviceTrusted
			input.Device.pairing.status = CeremonyConsumed
		}, ErrStateConflict},
		{"cross principal", func(input *PairDeviceInput) {
			input.Proof.principalID, _ = ParsePrincipalID(identityUUID(162))
		}, ErrForbidden},
		{"wrong purpose", func(input *PairDeviceInput) { input.Proof.purpose = CeremonyPurposeMembershipAcceptance }, ErrStateConflict},
		{"expired", func(input *PairDeviceInput) { input.Device.pairing.expiresAt = fixture.now }, ErrStateConflict},
		{"malformed retained binding", func(input *PairDeviceInput) {
			input.Device.pairing.installationID, _ = ParseInstallationID(identityUUID(163))
		}, ErrStateConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.mutate(&input)
			result, err := PairDevice(input)
			if !errors.Is(err, test.match) || !result.Device().IsZero() || len(result.Facts()) != 0 {
				t.Fatalf("result = %#v, error = %v", result, err)
			}
		})
	}
}
