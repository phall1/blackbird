package contracts

import (
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// These result decoders are what the CLI and the shipped plugin clients use to
// read a daemon response, so they are the last place a wrong terminal state or
// a mismatched ceremony purpose can be caught before a client acts on it. Each
// one pins two bindings its neighbours do not share: the single resource state
// the operation is allowed to report, and — where the command issues a ceremony
// — the one purpose that ceremony may carry.

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

// TestW0ResultDecodersAdmitWellFormedResults proves each decoder round-trips
// its own result and hands back the resource a caller acts on.
func TestW0ResultDecodersAdmitWellFormedResults(t *testing.T) {
	t.Parallel()

	t.Run("device pairing begin", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeDevicePairingBeginResult(mustMarshal(t, validDevicePairingBeginResult(t)))
		if err != nil {
			t.Fatalf("DecodeDevicePairingBeginResult() error = %v", err)
		}
		if decoded.Resource.DeviceState != string(domain.DevicePending) ||
			decoded.Resource.Challenge.Purpose != string(domain.CeremonyPurposeDevicePairing) {
			t.Fatalf("decoded = %#v", decoded.Resource)
		}
	})

	t.Run("device pair", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeDevicePairResult(mustMarshal(t, validDevicePairResult(t)))
		if err != nil {
			t.Fatalf("DecodeDevicePairResult() error = %v", err)
		}
		if decoded.Resource.DeviceState != string(domain.DeviceTrusted) {
			t.Fatalf("decoded = %#v", decoded.Resource)
		}
	})

	t.Run("workspace member invite", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeWorkspaceMemberInviteResult(mustMarshal(t, validWorkspaceMemberInviteResult(t)))
		if err != nil {
			t.Fatalf("DecodeWorkspaceMemberInviteResult() error = %v", err)
		}
		if decoded.Resource.MembershipState != string(domain.MembershipInvited) {
			t.Fatalf("decoded = %#v", decoded.Resource)
		}
	})

	t.Run("workspace membership accept", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeWorkspaceMembershipAcceptResult(mustMarshal(t, validWorkspaceMembershipAcceptResult(t)))
		if err != nil {
			t.Fatalf("DecodeWorkspaceMembershipAcceptResult() error = %v", err)
		}
		if decoded.Resource.MembershipState != string(domain.MembershipActive) {
			t.Fatalf("decoded = %#v", decoded.Resource)
		}
	})

	t.Run("actor create", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeActorCreateResult(mustMarshal(t, validActorCreateResult(t)))
		if err != nil {
			t.Fatalf("DecodeActorCreateResult() error = %v", err)
		}
		if decoded.Resource.ActorID.String() != idActor {
			t.Fatalf("decoded = %#v", decoded.Resource)
		}
	})

	t.Run("actor delegation propose", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeActorDelegationProposeResult(mustMarshal(t, validActorDelegationProposeResult(t)))
		if err != nil {
			t.Fatalf("DecodeActorDelegationProposeResult() error = %v", err)
		}
		if decoded.Resource.DelegationState != string(domain.DelegationProposed) {
			t.Fatalf("decoded = %#v", decoded.Resource)
		}
	})

	t.Run("actor delegation activate", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeActorDelegationActivateResult(mustMarshal(t, validActorDelegationActivateResult(t)))
		if err != nil {
			t.Fatalf("DecodeActorDelegationActivateResult() error = %v", err)
		}
		if decoded.Resource.SessionStartChallenge.Purpose != string(domain.CeremonyPurposeActorSessionStart) {
			t.Fatalf("decoded = %#v", decoded.Resource)
		}
	})

	t.Run("session start", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeSessionStartResult(mustMarshal(t, validSessionStartResult(t)))
		if err != nil {
			t.Fatalf("DecodeSessionStartResult() error = %v", err)
		}
		if decoded.Resource.ActorSessionID.String() != idSession {
			t.Fatalf("decoded = %#v", decoded.Resource)
		}
	})
}

// TestW0ResultDecodersPinTheirTerminalState is the binding that stops one
// command's success from being read as another's. Each case substitutes a
// state that is legal for the aggregate but wrong for the operation that
// reported it — the shape a confused or hostile daemon response would take.
func TestW0ResultDecodersPinTheirTerminalState(t *testing.T) {
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

// TestW0ResultDecodersPinTheirCeremonyPurpose swaps each issued ceremony for a
// purpose that is valid in the domain but belongs to a different command. A
// client that acted on one of these would redeem a challenge against the wrong
// ceremony entirely, so the purpose literal is the check that matters most.
func TestW0ResultDecodersPinTheirCeremonyPurpose(t *testing.T) {
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

// TestW0ResultDecodersRequireAnExplicitIdempotentReplay covers the one contract
// a Go zero value cannot express. `idempotent_replay` defaults to false when
// absent, which is indistinguishable from a daemon that genuinely reported a
// first execution — so the decoder demands the member be present rather than
// inferred. Only the decoders enforce this; Validate alone does not.
func TestW0ResultDecodersRequireAnExplicitIdempotentReplay(t *testing.T) {
	t.Parallel()

	decoders := map[string]struct {
		decode func([]byte) error
		valid  func(*testing.T) any
	}{
		"device pairing begin": {
			decode: func(data []byte) error { _, err := DecodeDevicePairingBeginResult(data); return err },
			valid:  func(t *testing.T) any { return validDevicePairingBeginResult(t) },
		},
		"device pair": {
			decode: func(data []byte) error { _, err := DecodeDevicePairResult(data); return err },
			valid:  func(t *testing.T) any { return validDevicePairResult(t) },
		},
		"workspace member invite": {
			decode: func(data []byte) error { _, err := DecodeWorkspaceMemberInviteResult(data); return err },
			valid:  func(t *testing.T) any { return validWorkspaceMemberInviteResult(t) },
		},
		"workspace membership accept": {
			decode: func(data []byte) error { _, err := DecodeWorkspaceMembershipAcceptResult(data); return err },
			valid:  func(t *testing.T) any { return validWorkspaceMembershipAcceptResult(t) },
		},
		"actor create": {
			decode: func(data []byte) error { _, err := DecodeActorCreateResult(data); return err },
			valid:  func(t *testing.T) any { return validActorCreateResult(t) },
		},
		"actor delegation propose": {
			decode: func(data []byte) error { _, err := DecodeActorDelegationProposeResult(data); return err },
			valid:  func(t *testing.T) any { return validActorDelegationProposeResult(t) },
		},
		"actor delegation activate": {
			decode: func(data []byte) error { _, err := DecodeActorDelegationActivateResult(data); return err },
			valid:  func(t *testing.T) any { return validActorDelegationActivateResult(t) },
		},
		"session start": {
			decode: func(data []byte) error { _, err := DecodeSessionStartResult(data); return err },
			valid:  func(t *testing.T) any { return validSessionStartResult(t) },
		},
	}

	for name, decoder := range decoders {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded := mustMarshal(t, decoder.valid(t))
			if err := decoder.decode(encoded); err != nil {
				t.Fatalf("a well-formed result was rejected: %v", err)
			}
			if err := decoder.decode(mustRemoveJSONField(t, encoded, `,"idempotent_replay":false`)); err == nil {
				t.Fatal("decode() accepted a result with no idempotent_replay member")
			}
		})
	}
}
