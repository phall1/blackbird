package contracts

import (
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// These result validators run on every W0 response the HTTP and MCP transports
// emit, so they are the last place a wrong terminal state or a mismatched
// ceremony purpose is caught before a client acts on it. Each one pins two
// bindings its neighbours do not share: the single resource state the operation
// is allowed to report, and — where the command issues a ceremony — the one
// purpose that ceremony may carry.

func w0ResultMetadata(t *testing.T, operation string) CommandResultMetadataDTO {
	t.Helper()
	return w1TestResultMetadata(t, operation, 1)
}

func w0IssuedCeremony(t *testing.T, purpose domain.CeremonyPurpose) IssuedCeremonyDTO {
	t.Helper()
	return IssuedCeremonyDTO{
		CeremonyID: mustParseCeremonyID(t, idCeremony),
		Purpose:    string(purpose),
		ExpiresAt:  time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour),
	}
}

func validDevicePairingBeginResult(t *testing.T) DevicePairingBeginResultDTO {
	t.Helper()
	return DevicePairingBeginResultDTO{
		CommandResultMetadataDTO: w0ResultMetadata(t, OperationDevicePairingBegin),
		Resource: DevicePairingBeginResourceDTO{
			InstallationID: mustParseInstallationID(t, idInstallation),
			DeviceID:       mustParseDeviceID(t, idDevice),
			DeviceState:    string(domain.DevicePending),
			// A device that has only begun pairing is pending, never trusted.
			ResourceVersion: domain.InitialVersion(),
			Challenge:       w0IssuedCeremony(t, domain.CeremonyPurposeDevicePairing),
		},
	}
}

func validDevicePairResult(t *testing.T) DevicePairResultDTO {
	t.Helper()
	return DevicePairResultDTO{
		CommandResultMetadataDTO: w0ResultMetadata(t, OperationDevicePair),
		Resource: DevicePairResourceDTO{
			InstallationID:  mustParseInstallationID(t, idInstallation),
			DeviceID:        mustParseDeviceID(t, idDevice),
			DeviceState:     string(domain.DeviceTrusted),
			ResourceVersion: domain.InitialVersion(),
			TrustRevision:   domain.InitialVersion(),
		},
	}
}

func validWorkspaceMemberInviteResult(t *testing.T) WorkspaceMemberInviteResultDTO {
	t.Helper()
	return WorkspaceMemberInviteResultDTO{
		CommandResultMetadataDTO: w0ResultMetadata(t, OperationWorkspaceMemberInvite),
		Resource: WorkspaceMemberInviteResourceDTO{
			WorkspaceID:     mustParseWorkspaceID(t, idWorkspace),
			MembershipID:    mustParseMembershipID(t, idMembership),
			MembershipState: string(domain.MembershipInvited),
			ResourceVersion: domain.InitialVersion(),
			Challenge:       w0IssuedCeremony(t, domain.CeremonyPurposeMembershipAcceptance),
		},
	}
}

func validWorkspaceMembershipAcceptResult(t *testing.T) WorkspaceMembershipAcceptResultDTO {
	t.Helper()
	return WorkspaceMembershipAcceptResultDTO{
		CommandResultMetadataDTO: w0ResultMetadata(t, OperationWorkspaceMembershipAccept),
		Resource: WorkspaceMembershipAcceptResourceDTO{
			WorkspaceID:     mustParseWorkspaceID(t, idWorkspace),
			MembershipID:    mustParseMembershipID(t, idMembership),
			MembershipState: string(domain.MembershipActive),
			ResourceVersion: domain.InitialVersion(),
		},
	}
}

func validActorCreateResult(t *testing.T) ActorCreateResultDTO {
	t.Helper()
	return ActorCreateResultDTO{
		CommandResultMetadataDTO: w0ResultMetadata(t, OperationActorCreate),
		Resource: ActorCreateResourceDTO{
			WorkspaceID:     mustParseWorkspaceID(t, idWorkspace),
			ActorID:         mustParseActorID(t, idActor),
			ActorState:      string(domain.ActorActive),
			ResourceVersion: domain.InitialVersion(),
		},
	}
}

func validActorDelegationProposeResult(t *testing.T) ActorDelegationProposeResultDTO {
	t.Helper()
	return ActorDelegationProposeResultDTO{
		CommandResultMetadataDTO: w0ResultMetadata(t, OperationActorDelegationPropose),
		Resource: ActorDelegationProposeResourceDTO{
			WorkspaceID:     mustParseWorkspaceID(t, idWorkspace),
			DelegationID:    mustParseActorDelegationID(t, idDelegation),
			DelegationState: string(domain.DelegationProposed),
			ResourceVersion: domain.InitialVersion(),
			Challenge:       w0IssuedCeremony(t, domain.CeremonyPurposeDelegationActivation),
		},
	}
}

func validActorDelegationActivateResult(t *testing.T) ActorDelegationActivateResultDTO {
	t.Helper()
	return ActorDelegationActivateResultDTO{
		CommandResultMetadataDTO: w0ResultMetadata(t, OperationActorDelegationActivate),
		Resource: ActorDelegationActivateResourceDTO{
			WorkspaceID:           mustParseWorkspaceID(t, idWorkspace),
			DelegationID:          mustParseActorDelegationID(t, idDelegation),
			DelegationState:       string(domain.DelegationActive),
			ResourceVersion:       domain.InitialVersion(),
			SessionStartChallenge: w0IssuedCeremony(t, domain.CeremonyPurposeActorSessionStart),
		},
	}
}

func validSessionStartResult(t *testing.T) SessionStartResultDTO {
	t.Helper()
	return SessionStartResultDTO{
		CommandResultMetadataDTO: w0ResultMetadata(t, OperationSessionStart),
		Resource: SessionStartResourceDTO{
			WorkspaceID:     mustParseWorkspaceID(t, idWorkspace),
			ActorSessionID:  mustParseActorSessionID(t, idSession),
			SessionState:    string(domain.ActorSessionActive),
			ResourceVersion: domain.InitialVersion(),
			AbsoluteExpiry:  time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour),
		},
	}
}

// TestW0ResultsAdmitTheirOwnWellFormedResult proves every W0 result the daemon
// can build passes the validator the HTTP and MCP transports run over it before
// it reaches a client, so a rejection below is a real binding rather than a
// fixture that was never valid.
func TestW0ResultsAdmitTheirOwnWellFormedResult(t *testing.T) {
	t.Parallel()

	results := map[string]func(*testing.T) interface{ Validate() error }{
		"device pairing begin":        func(t *testing.T) interface{ Validate() error } { return validDevicePairingBeginResult(t) },
		"device pair":                 func(t *testing.T) interface{ Validate() error } { return validDevicePairResult(t) },
		"workspace member invite":     func(t *testing.T) interface{ Validate() error } { return validWorkspaceMemberInviteResult(t) },
		"workspace membership accept": func(t *testing.T) interface{ Validate() error } { return validWorkspaceMembershipAcceptResult(t) },
		"actor create":                func(t *testing.T) interface{ Validate() error } { return validActorCreateResult(t) },
		"actor delegation propose":    func(t *testing.T) interface{ Validate() error } { return validActorDelegationProposeResult(t) },
		"actor delegation activate":   func(t *testing.T) interface{ Validate() error } { return validActorDelegationActivateResult(t) },
		"session start":               func(t *testing.T) interface{ Validate() error } { return validSessionStartResult(t) },
	}

	for name, build := range results {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := build(t).Validate(); err != nil {
				t.Fatalf("a well-formed result was rejected: %v", err)
			}
		})
	}
}

// TestW0ResultsPinTheirTerminalState is the binding that stops one
// command's success from being read as another's. Each case substitutes a
// state that is legal for the aggregate but wrong for the operation that
// reported it — the shape a confused or hostile daemon response would take.
func TestW0ResultsPinTheirTerminalState(t *testing.T) {
	t.Parallel()

	t.Run("pairing begin refuses an already trusted device", func(t *testing.T) {
		t.Parallel()
		result := validDevicePairingBeginResult(t)
		result.Resource.DeviceState = string(domain.DeviceTrusted)
		rejects(t, "trusted on begin", result.Validate(), "resource.device_state")
	})

	t.Run("device pair refuses a still pending device", func(t *testing.T) {
		t.Parallel()
		result := validDevicePairResult(t)
		result.Resource.DeviceState = string(domain.DevicePending)
		rejects(t, "pending on pair", result.Validate(), "resource.device_state")
	})

	t.Run("invite refuses an already active membership", func(t *testing.T) {
		t.Parallel()
		result := validWorkspaceMemberInviteResult(t)
		result.Resource.MembershipState = string(domain.MembershipActive)
		rejects(t, "active on invite", result.Validate(), "resource.membership_state")
	})

	t.Run("accept refuses a still invited membership", func(t *testing.T) {
		t.Parallel()
		result := validWorkspaceMembershipAcceptResult(t)
		result.Resource.MembershipState = string(domain.MembershipInvited)
		rejects(t, "invited on accept", result.Validate(), "resource.membership_state")
	})

	t.Run("propose refuses an already active delegation", func(t *testing.T) {
		t.Parallel()
		result := validActorDelegationProposeResult(t)
		result.Resource.DelegationState = string(domain.DelegationActive)
		rejects(t, "active on propose", result.Validate(), "resource.delegation_state")
	})

	t.Run("activate refuses a merely proposed delegation", func(t *testing.T) {
		t.Parallel()
		result := validActorDelegationActivateResult(t)
		result.Resource.DelegationState = string(domain.DelegationProposed)
		rejects(t, "proposed on activate", result.Validate(), "resource.delegation_state")
	})
}

// TestW0ResultsPinTheirCeremonyPurpose swaps each issued ceremony for a
// purpose that is valid in the domain but belongs to a different command. A
// client that acted on one of these would redeem a challenge against the wrong
// ceremony entirely, so the purpose literal is the check that matters most.
func TestW0ResultsPinTheirCeremonyPurpose(t *testing.T) {
	t.Parallel()

	t.Run("pairing challenge may not carry a delegation purpose", func(t *testing.T) {
		t.Parallel()
		result := validDevicePairingBeginResult(t)
		result.Resource.Challenge = w0IssuedCeremony(t, domain.CeremonyPurposeDelegationActivation)
		rejects(t, "delegation purpose on pairing", result.Validate(), "resource.challenge.purpose")
	})

	t.Run("invite challenge may not carry a pairing purpose", func(t *testing.T) {
		t.Parallel()
		result := validWorkspaceMemberInviteResult(t)
		result.Resource.Challenge = w0IssuedCeremony(t, domain.CeremonyPurposeDevicePairing)
		rejects(t, "pairing purpose on invite", result.Validate(), "resource.challenge.purpose")
	})

	t.Run("propose challenge may not carry a session start purpose", func(t *testing.T) {
		t.Parallel()
		result := validActorDelegationProposeResult(t)
		result.Resource.Challenge = w0IssuedCeremony(t, domain.CeremonyPurposeActorSessionStart)
		rejects(t, "session purpose on propose", result.Validate(), "resource.challenge.purpose")
	})

	t.Run("activate challenge may not carry a membership purpose", func(t *testing.T) {
		t.Parallel()
		result := validActorDelegationActivateResult(t)
		result.Resource.SessionStartChallenge = w0IssuedCeremony(t, domain.CeremonyPurposeMembershipAcceptance)
		rejects(t, "membership purpose on activate", result.Validate(), "resource.session_start_challenge.purpose")
	})

	t.Run("a purpose outside the stable set is refused", func(t *testing.T) {
		t.Parallel()
		result := validDevicePairingBeginResult(t)
		result.Resource.Challenge.Purpose = "arbitrary_purpose"
		rejects(t, "unknown purpose", result.Validate(), "resource.challenge.purpose")
	})
}
