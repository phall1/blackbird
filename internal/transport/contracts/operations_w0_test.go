package contracts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// The identity-plane decoders below are the fail-closed boundary between
// untrusted transport input and the application layer: every field the
// application later trusts is admitted here or nowhere. They had no tests, so
// this file pins both halves of each contract — that a well-formed request
// survives decoding intact, and that each decoder's own validation rejects the
// field it alone is responsible for.

const (
	idCeremony = "01b8e094-9888-7000-8000-000000000060"
	// A syntactically valid lowercase SHA-256 digest. The value is arbitrary;
	// only its shape is under test.
	proofHashHex = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
)

func fixtureCeremonyReference(t *testing.T) CeremonyReferenceDTO {
	t.Helper()
	return CeremonyReferenceDTO{
		CeremonyID: mustParseCeremonyID(t, idCeremony),
		ExpiresAt:  fixtureTime.Add(time.Hour),
		ProofHash:  proofHashHex,
	}
}

func mustParseCeremonyID(t *testing.T, value string) domain.CeremonyID {
	t.Helper()
	id, err := domain.ParseCeremonyID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func fixtureWorkspaceMemberInviteRequest(t *testing.T) WorkspaceMemberInviteRequestDTO {
	t.Helper()
	return WorkspaceMemberInviteRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaWorkspaceMemberInviteCommand, OperationWorkspaceMemberInvite,
			"req-invite-1", "invite-key-1"),
		ClientInstanceID: mustParseClientInstanceID(t, idClient),
		ExpectedVersions: WorkspaceMemberInviteExpectedVersionsDTO{
			Administrator: domain.InitialVersion(), Workspace: domain.InitialVersion(), Principal: domain.InitialVersion(),
		},
		Body: WorkspaceMemberInviteBodyDTO{
			WorkspaceID:     mustParseWorkspaceID(t, idWorkspace),
			AdministratorID: mustParsePrincipalID(t, idPrincipal),
			PrincipalID:     mustParsePrincipalID(t, idPrincipal),
			MembershipID:    mustParseMembershipID(t, idMembership),
			Capabilities:    []string{"workspace:read"},
			Challenge:       fixtureCeremonyReference(t),
		},
	}
}

func fixtureWorkspaceMembershipAcceptRequest(t *testing.T) WorkspaceMembershipAcceptRequestDTO {
	t.Helper()
	return WorkspaceMembershipAcceptRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaWorkspaceMembershipAcceptCommand, OperationWorkspaceMembershipAccept,
			"req-accept-1", "accept-key-1"),
		ClientInstanceID: mustParseClientInstanceID(t, idClient),
		ExpectedVersions: WorkspaceMembershipAcceptExpectedVersionsDTO{
			Workspace: domain.InitialVersion(), Principal: domain.InitialVersion(), Membership: domain.InitialVersion(),
		},
		Body: WorkspaceMembershipAcceptBodyDTO{
			WorkspaceID:  mustParseWorkspaceID(t, idWorkspace),
			PrincipalID:  mustParsePrincipalID(t, idPrincipal),
			MembershipID: mustParseMembershipID(t, idMembership),
			Proof:        fixtureCeremonyReference(t),
		},
	}
}

func fixtureActorCreateRequest(t *testing.T) ActorCreateRequestDTO {
	t.Helper()
	return ActorCreateRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaActorCreateCommand, OperationActorCreate,
			"req-actor-1", "actor-key-1"),
		ClientInstanceID: mustParseClientInstanceID(t, idClient),
		ExpectedVersions: ActorCreateExpectedVersionsDTO{
			Administrator: domain.InitialVersion(), Workspace: domain.InitialVersion(),
		},
		Body: ActorCreateBodyDTO{
			WorkspaceID:     mustParseWorkspaceID(t, idWorkspace),
			AdministratorID: mustParsePrincipalID(t, idPrincipal),
			ActorID:         mustParseActorID(t, idActor),
			Kind:            ActorKindAgent,
			DisplayName:     "Proof Agent",
		},
	}
}

func fixtureActorDelegationProposeRequest(t *testing.T) ActorDelegationProposeRequestDTO {
	t.Helper()
	return ActorDelegationProposeRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaActorDelegationProposeCommand, OperationActorDelegationPropose,
			"req-propose-1", "propose-key-1"),
		ClientInstanceID: mustParseClientInstanceID(t, idClient),
		ExpectedVersions: ActorDelegationProposeExpectedVersionsDTO{
			Administrator: domain.InitialVersion(), Workspace: domain.InitialVersion(),
			Principal: domain.InitialVersion(), Actor: domain.InitialVersion(), Membership: domain.InitialVersion(),
		},
		Body: ActorDelegationProposeBodyDTO{
			WorkspaceID:     mustParseWorkspaceID(t, idWorkspace),
			AdministratorID: mustParsePrincipalID(t, idPrincipal),
			PrincipalID:     mustParsePrincipalID(t, idPrincipal),
			ActorID:         mustParseActorID(t, idActor),
			MembershipID:    mustParseMembershipID(t, idMembership),
			DelegationID:    mustParseActorDelegationID(t, idDelegation),
			Capabilities:    []string{"workspace:read"},
			Challenge:       fixtureCeremonyReference(t),
		},
	}
}

func fixtureActorDelegationActivateRequest(t *testing.T) ActorDelegationActivateRequestDTO {
	t.Helper()
	return ActorDelegationActivateRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaActorDelegationActivateCommand, OperationActorDelegationActivate,
			"req-activate-1", "activate-key-1"),
		ClientInstanceID: mustParseClientInstanceID(t, idClient),
		ExpectedVersions: ActorDelegationActivateExpectedVersionsDTO{
			Workspace: domain.InitialVersion(), Principal: domain.InitialVersion(), Actor: domain.InitialVersion(),
			Membership: domain.InitialVersion(), Delegation: domain.InitialVersion(),
		},
		Body: ActorDelegationActivateBodyDTO{
			WorkspaceID:           mustParseWorkspaceID(t, idWorkspace),
			PrincipalID:           mustParsePrincipalID(t, idPrincipal),
			ActorID:               mustParseActorID(t, idActor),
			MembershipID:          mustParseMembershipID(t, idMembership),
			DelegationID:          mustParseActorDelegationID(t, idDelegation),
			ActivationProof:       fixtureCeremonyReference(t),
			SessionStartChallenge: fixtureCeremonyReference(t),
		},
	}
}

func fixtureDevicePairingBeginRequest(t *testing.T) DevicePairingBeginRequestDTO {
	t.Helper()
	return DevicePairingBeginRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaDevicePairingBeginCommand, OperationDevicePairingBegin,
			"req-pairing-1", "pairing-key-1"),
		ClientInstanceID: mustParseClientInstanceID(t, idClient),
		ExpectedVersions: DevicePairingBeginExpectedVersionsDTO{Principal: domain.InitialVersion()},
		Body: DevicePairingBeginBodyDTO{
			InstallationID:     mustParseInstallationID(t, idInstallation),
			PrincipalID:        mustParsePrincipalID(t, idPrincipal),
			DeviceID:           mustParseDeviceID(t, idDevice),
			DisplayName:        "Proof Laptop",
			PublicKeyReference: "vault://device/proof",
			Challenge:          fixtureCeremonyReference(t),
		},
	}
}

func fixtureDevicePairRequest(t *testing.T) DevicePairRequestDTO {
	t.Helper()
	return DevicePairRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaDevicePairCommand, OperationDevicePair,
			"req-pair-1", "pair-key-1"),
		ClientInstanceID: mustParseClientInstanceID(t, idClient),
		ExpectedVersions: DevicePairExpectedVersionsDTO{
			Principal: domain.InitialVersion(), Device: domain.InitialVersion(), DeviceTrust: domain.InitialVersion(),
		},
		Body: DevicePairBodyDTO{
			InstallationID: mustParseInstallationID(t, idInstallation),
			PrincipalID:    mustParsePrincipalID(t, idPrincipal),
			DeviceID:       mustParseDeviceID(t, idDevice),
			Proof:          fixtureCeremonyReference(t),
		},
	}
}

// TestW0OrdinaryDecodersAdmitWellFormedRequests proves each decoder accepts its
// own fixture and preserves the identifiers the application layer reads back.
// A decoder that silently zeroed a body field would still "succeed", so the
// assertions read fields rather than only the error.
func TestW0OrdinaryDecodersAdmitWellFormedRequests(t *testing.T) {
	t.Parallel()

	t.Run("workspace member invite", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeWorkspaceMemberInviteRequest(mustMarshal(t, fixtureWorkspaceMemberInviteRequest(t)))
		if err != nil {
			t.Fatalf("DecodeWorkspaceMemberInviteRequest() error = %v", err)
		}
		if decoded.Body.MembershipID.String() != idMembership || decoded.Body.Challenge.ProofHash != proofHashHex ||
			decoded.Operation != OperationWorkspaceMemberInvite {
			t.Fatalf("decoded = %#v", decoded)
		}
	})

	t.Run("workspace membership accept", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeWorkspaceMembershipAcceptRequest(mustMarshal(t, fixtureWorkspaceMembershipAcceptRequest(t)))
		if err != nil {
			t.Fatalf("DecodeWorkspaceMembershipAcceptRequest() error = %v", err)
		}
		if decoded.Body.WorkspaceID.String() != idWorkspace || decoded.Body.Proof.CeremonyID.String() != idCeremony {
			t.Fatalf("decoded = %#v", decoded)
		}
	})

	t.Run("actor create", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeActorCreateRequest(mustMarshal(t, fixtureActorCreateRequest(t)))
		if err != nil {
			t.Fatalf("DecodeActorCreateRequest() error = %v", err)
		}
		if decoded.Body.ActorID.String() != idActor || decoded.Body.Kind != ActorKindAgent ||
			decoded.Body.DisplayName != "Proof Agent" {
			t.Fatalf("decoded = %#v", decoded)
		}
	})

	t.Run("actor delegation propose", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeActorDelegationProposeRequest(mustMarshal(t, fixtureActorDelegationProposeRequest(t)))
		if err != nil {
			t.Fatalf("DecodeActorDelegationProposeRequest() error = %v", err)
		}
		if decoded.Body.DelegationID.String() != idDelegation || len(decoded.Body.Capabilities) != 1 {
			t.Fatalf("decoded = %#v", decoded)
		}
	})

	t.Run("actor delegation activate", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeActorDelegationActivateRequest(mustMarshal(t, fixtureActorDelegationActivateRequest(t)))
		if err != nil {
			t.Fatalf("DecodeActorDelegationActivateRequest() error = %v", err)
		}
		if decoded.Body.DelegationID.String() != idDelegation ||
			decoded.Body.SessionStartChallenge.CeremonyID.String() != idCeremony {
			t.Fatalf("decoded = %#v", decoded)
		}
	})

	t.Run("device pairing begin", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeDevicePairingBeginRequest(mustMarshal(t, fixtureDevicePairingBeginRequest(t)))
		if err != nil {
			t.Fatalf("DecodeDevicePairingBeginRequest() error = %v", err)
		}
		if decoded.Body.DeviceID.String() != idDevice || decoded.Body.PublicKeyReference != "vault://device/proof" {
			t.Fatalf("decoded = %#v", decoded)
		}
	})

	t.Run("device pair", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeDevicePairRequest(mustMarshal(t, fixtureDevicePairRequest(t)))
		if err != nil {
			t.Fatalf("DecodeDevicePairRequest() error = %v", err)
		}
		if decoded.Body.DeviceID.String() != idDevice || decoded.Body.Proof.ProofHash != proofHashHex {
			t.Fatalf("decoded = %#v", decoded)
		}
	})
}

// mustRemoveJSONField deletes an exact `"field":value,` fragment and insists
// the deletion happened. Without that guard a fragment that stopped matching —
// after a field is renamed or reordered — would leave the payload valid, and
// the case would quietly assert nothing.
func mustRemoveJSONField(t *testing.T, data []byte, exact string) []byte {
	t.Helper()
	reduced := removeJSONField(data, exact)
	if len(reduced) == len(data) {
		t.Fatalf("fragment %q not present, so the case would test nothing", exact)
	}
	// The result must still parse. A removal that broke the document would be
	// rejected by the JSON decoder, and the case would credit that rejection to
	// the validation rule it meant to exercise.
	if !json.Valid(reduced) {
		t.Fatalf("removing %q produced malformed JSON: %s", exact, reduced)
	}
	return reduced
}

// TestW0OrdinaryDecodersRejectMalformedRequests exercises the branch each
// decoder owns. Every case alters exactly one field of an otherwise valid
// request, so a rejection can only come from the rule named in the case.
//
// Cases that need a field to be *absent* delete it from the encoded JSON rather
// than zeroing the struct: the domain identifier types refuse to marshal when
// zero, so a zeroed struct fails at the encoder and never reaches the decoder
// under test.
func TestW0OrdinaryDecodersRejectMalformedRequests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		decode  func([]byte) error
		payload func(*testing.T) []byte
	}{
		{
			name:   "invite rejects an operation the metadata does not match",
			decode: func(data []byte) error { _, err := DecodeWorkspaceMemberInviteRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureWorkspaceMemberInviteRequest(t)
				request.Operation = OperationActorCreate
				return mustMarshal(t, request)
			},
		},
		{
			name:   "invite rejects an empty capability set",
			decode: func(data []byte) error { _, err := DecodeWorkspaceMemberInviteRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureWorkspaceMemberInviteRequest(t)
				request.Body.Capabilities = nil
				return mustMarshal(t, request)
			},
		},
		{
			name:   "invite rejects duplicate capabilities",
			decode: func(data []byte) error { _, err := DecodeWorkspaceMemberInviteRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureWorkspaceMemberInviteRequest(t)
				request.Body.Capabilities = []string{"workspace:read", "workspace:read"}
				return mustMarshal(t, request)
			},
		},
		{
			name:   "invite rejects a challenge proof hash that is not lowercase hex",
			decode: func(data []byte) error { _, err := DecodeWorkspaceMemberInviteRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureWorkspaceMemberInviteRequest(t)
				request.Body.Challenge.ProofHash = strings.ToUpper(proofHashHex)
				return mustMarshal(t, request)
			},
		},
		{
			name:   "invite rejects a missing membership id",
			decode: func(data []byte) error { _, err := DecodeWorkspaceMemberInviteRequest(data); return err },
			payload: func(t *testing.T) []byte {
				return mustRemoveJSONField(t, mustMarshal(t, fixtureWorkspaceMemberInviteRequest(t)),
					`"membership_id":"`+idMembership+`",`)
			},
		},
		{
			name:   "accept rejects a proof with no expiry",
			decode: func(data []byte) error { _, err := DecodeWorkspaceMembershipAcceptRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureWorkspaceMembershipAcceptRequest(t)
				request.Body.Proof.ExpiresAt = time.Time{}
				return mustMarshal(t, request)
			},
		},
		{
			name:   "accept rejects a non-UTC expiry",
			decode: func(data []byte) error { _, err := DecodeWorkspaceMembershipAcceptRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureWorkspaceMembershipAcceptRequest(t)
				request.Body.Proof.ExpiresAt = fixtureTime.In(time.FixedZone("UTC+2", 2*60*60))
				return mustMarshal(t, request)
			},
		},
		{
			name:   "accept rejects a missing expected membership version",
			decode: func(data []byte) error { _, err := DecodeWorkspaceMembershipAcceptRequest(data); return err },
			payload: func(t *testing.T) []byte {
				return mustRemoveJSONField(t, mustMarshal(t, fixtureWorkspaceMembershipAcceptRequest(t)),
					`,"membership":1`)
			},
		},
		{
			name:   "actor create rejects a kind outside the stable set",
			decode: func(data []byte) error { _, err := DecodeActorCreateRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureActorCreateRequest(t)
				request.Body.Kind = "sentient"
				return mustMarshal(t, request)
			},
		},
		{
			name:   "actor create rejects an empty display name",
			decode: func(data []byte) error { _, err := DecodeActorCreateRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureActorCreateRequest(t)
				request.Body.DisplayName = ""
				return mustMarshal(t, request)
			},
		},
		{
			name:   "actor create rejects an oversized display name",
			decode: func(data []byte) error { _, err := DecodeActorCreateRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureActorCreateRequest(t)
				request.Body.DisplayName = strings.Repeat("a", maxDisplayNameBytes+1)
				return mustMarshal(t, request)
			},
		},
		{
			name:   "actor create rejects a missing client instance id",
			decode: func(data []byte) error { _, err := DecodeActorCreateRequest(data); return err },
			payload: func(t *testing.T) []byte {
				return mustRemoveJSONField(t, mustMarshal(t, fixtureActorCreateRequest(t)),
					`"client_instance_id":"`+idClient+`",`)
			},
		},
		{
			name:   "delegation propose rejects a missing delegation id",
			decode: func(data []byte) error { _, err := DecodeActorDelegationProposeRequest(data); return err },
			payload: func(t *testing.T) []byte {
				return mustRemoveJSONField(t, mustMarshal(t, fixtureActorDelegationProposeRequest(t)),
					`"delegation_id":"`+idDelegation+`",`)
			},
		},
		{
			name:   "delegation propose rejects a challenge with no ceremony",
			decode: func(data []byte) error { _, err := DecodeActorDelegationProposeRequest(data); return err },
			payload: func(t *testing.T) []byte {
				return mustRemoveJSONField(t, mustMarshal(t, fixtureActorDelegationProposeRequest(t)),
					`"ceremony_id":"`+idCeremony+`",`)
			},
		},
		{
			name:   "delegation activate rejects a malformed activation proof",
			decode: func(data []byte) error { _, err := DecodeActorDelegationActivateRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureActorDelegationActivateRequest(t)
				request.Body.ActivationProof.ProofHash = "not-a-digest"
				return mustMarshal(t, request)
			},
		},
		{
			// The session-start challenge is validated only after the activation
			// proof passes, so a valid proof is the only way to reach it.
			name:   "delegation activate rejects a malformed session start challenge",
			decode: func(data []byte) error { _, err := DecodeActorDelegationActivateRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureActorDelegationActivateRequest(t)
				request.Body.SessionStartChallenge.ProofHash = "not-a-digest"
				return mustMarshal(t, request)
			},
		},
		{
			name:   "pairing begin rejects a missing public key reference",
			decode: func(data []byte) error { _, err := DecodeDevicePairingBeginRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureDevicePairingBeginRequest(t)
				request.Body.PublicKeyReference = ""
				return mustMarshal(t, request)
			},
		},
		{
			name:   "pairing begin rejects a missing device id",
			decode: func(data []byte) error { _, err := DecodeDevicePairingBeginRequest(data); return err },
			payload: func(t *testing.T) []byte {
				return mustRemoveJSONField(t, mustMarshal(t, fixtureDevicePairingBeginRequest(t)),
					`"device_id":"`+idDevice+`",`)
			},
		},
		{
			name:   "pairing begin rejects a schema that names another command",
			decode: func(data []byte) error { _, err := DecodeDevicePairingBeginRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureDevicePairingBeginRequest(t)
				request.Schema = SchemaDevicePairCommand
				return mustMarshal(t, request)
			},
		},
		{
			name:   "device pair rejects a missing device trust version",
			decode: func(data []byte) error { _, err := DecodeDevicePairRequest(data); return err },
			payload: func(t *testing.T) []byte {
				return mustRemoveJSONField(t, mustMarshal(t, fixtureDevicePairRequest(t)),
					`,"device_trust":1`)
			},
		},
		{
			name:   "device pair rejects a proof hash of the wrong length",
			decode: func(data []byte) error { _, err := DecodeDevicePairRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := fixtureDevicePairRequest(t)
				request.Body.Proof.ProofHash = proofHashHex[:63]
				return mustMarshal(t, request)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.decode(test.payload(t)); err == nil {
				t.Fatal("decode() error = nil, want a rejection")
			}
		})
	}
}

// TestW0OrdinaryDecodersRejectMalformedJSON covers the decode step ahead of
// validation. These decoders must refuse unknown fields and wrong JSON kinds
// rather than silently ignoring them, which is what keeps a client that
// invents a field from believing the daemon honoured it.
func TestW0OrdinaryDecodersRejectMalformedJSON(t *testing.T) {
	t.Parallel()

	decoders := map[string]struct {
		decode func([]byte) error
		valid  func(*testing.T) any
	}{
		"workspace member invite": {
			decode: func(data []byte) error { _, err := DecodeWorkspaceMemberInviteRequest(data); return err },
			valid:  func(t *testing.T) any { return fixtureWorkspaceMemberInviteRequest(t) },
		},
		"workspace membership accept": {
			decode: func(data []byte) error { _, err := DecodeWorkspaceMembershipAcceptRequest(data); return err },
			valid:  func(t *testing.T) any { return fixtureWorkspaceMembershipAcceptRequest(t) },
		},
		"actor create": {
			decode: func(data []byte) error { _, err := DecodeActorCreateRequest(data); return err },
			valid:  func(t *testing.T) any { return fixtureActorCreateRequest(t) },
		},
		"actor delegation propose": {
			decode: func(data []byte) error { _, err := DecodeActorDelegationProposeRequest(data); return err },
			valid:  func(t *testing.T) any { return fixtureActorDelegationProposeRequest(t) },
		},
		"actor delegation activate": {
			decode: func(data []byte) error { _, err := DecodeActorDelegationActivateRequest(data); return err },
			valid:  func(t *testing.T) any { return fixtureActorDelegationActivateRequest(t) },
		},
		"device pairing begin": {
			decode: func(data []byte) error { _, err := DecodeDevicePairingBeginRequest(data); return err },
			valid:  func(t *testing.T) any { return fixtureDevicePairingBeginRequest(t) },
		},
		"device pair": {
			decode: func(data []byte) error { _, err := DecodeDevicePairRequest(data); return err },
			valid:  func(t *testing.T) any { return fixtureDevicePairRequest(t) },
		},
	}

	for name, decoder := range decoders {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded := mustMarshal(t, decoder.valid(t))
			for caseName, data := range map[string][]byte{
				"unknown field": addTopLevelJSONField(encoded, `"smuggled":true`),
				"not an object": []byte(`["not","an","object"]`),
				"truncated":     encoded[:len(encoded)/2],
				"empty":         nil,
			} {
				if err := decoder.decode(data); err == nil {
					t.Fatalf("%s: decode() error = nil, want a rejection", caseName)
				}
			}
		})
	}
}

// w1ObserveUpdateDTO turns the shared observation fixture into an update of an
// existing work reference. The fixture itself is a first observation, which the
// test below covers separately.
func w1ObserveUpdateDTO(t *testing.T, fixture authenticationFixture, adapter domain.PrincipalID) WorkRefObserveRequestDTO {
	t.Helper()
	request := workRefObserveTestDTO(t, fixture, adapter)
	current := domain.InitialVersion()
	request.ExpectedVersions.WorkReference = &current
	// An update must name the provider version it believes it is replacing.
	request.Body.PreviousProviderVersion = "etag-a0"
	return request
}

// TestW1RequestDecodersAdmitWellFormedRequests reaches the exported decoders
// for the work plane. The handler tests exercise these commands end to end but
// call Values() directly, so the Decode* entry points — the ones an HTTP or MCP
// caller actually reaches — were never executed. This is the same ingress that
// needed repairing once already on this branch.
func TestW1RequestDecodersAdmitWellFormedRequests(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	adapter, err := domain.NewPrincipalID()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("work ref observe", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeWorkRefObserveRequest(mustMarshal(t, w1ObserveUpdateDTO(t, fixture, adapter)))
		if err != nil {
			t.Fatalf("DecodeWorkRefObserveRequest() error = %v", err)
		}
		if decoded.Operation != OperationWorkRefObserve {
			t.Fatalf("operation = %q", decoded.Operation)
		}
	})

	t.Run("objective and work create", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeObjectiveAndWorkCreateRequest(mustMarshal(t, objectiveAndWorkCreateTestDTO(t, fixture)))
		if err != nil {
			t.Fatalf("DecodeObjectiveAndWorkCreateRequest() error = %v", err)
		}
		if decoded.Operation != OperationObjectiveAndWorkCreate {
			t.Fatalf("operation = %q", decoded.Operation)
		}
	})

	t.Run("run plan with bindings", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeRunPlanWithBindingsRequest(mustMarshal(t, runPlanWithBindingsTestDTO(t, fixture)))
		if err != nil {
			t.Fatalf("DecodeRunPlanWithBindingsRequest() error = %v", err)
		}
		if decoded.Operation != OperationRunPlanWithBindings {
			t.Fatalf("operation = %q", decoded.Operation)
		}
	})

	t.Run("run join", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeRunJoinRequest(mustMarshal(t, runJoinTestDTO(t, fixture)))
		if err != nil {
			t.Fatalf("DecodeRunJoinRequest() error = %v", err)
		}
		if decoded.Operation != OperationRunJoin {
			t.Fatalf("operation = %q", decoded.Operation)
		}
	})

	t.Run("run start", func(t *testing.T) {
		t.Parallel()
		decoded, err := DecodeRunStartRequest(mustMarshal(t, runStartTestDTO(t, fixture)))
		if err != nil {
			t.Fatalf("DecodeRunStartRequest() error = %v", err)
		}
		if decoded.Operation != OperationRunStart {
			t.Fatalf("operation = %q", decoded.Operation)
		}
	})
}

// TestW1RequestDecodersRejectMalformedRequests proves each work-plane decoder
// runs its own assembly step rather than only unmarshalling. Every case leaves
// the JSON well formed and breaks one contract the decoder is responsible for.
func TestW1RequestDecodersRejectMalformedRequests(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	adapter, err := domain.NewPrincipalID()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		decode  func([]byte) error
		payload func(*testing.T) []byte
	}{
		{
			name:   "observe rejects an operation that names another command",
			decode: func(data []byte) error { _, err := DecodeWorkRefObserveRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := w1ObserveUpdateDTO(t, fixture, adapter)
				request.Operation = OperationRunStart
				return mustMarshal(t, request)
			},
		},
		{
			name:   "observe rejects an empty provider namespace",
			decode: func(data []byte) error { _, err := DecodeWorkRefObserveRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := w1ObserveUpdateDTO(t, fixture, adapter)
				request.Body.ProviderNamespace = ""
				return mustMarshal(t, request)
			},
		},
		{
			name:   "observe rejects a non-UTC observation instant",
			decode: func(data []byte) error { _, err := DecodeWorkRefObserveRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := w1ObserveUpdateDTO(t, fixture, adapter)
				request.Body.ObservedAt = request.Body.ObservedAt.In(time.FixedZone("UTC+2", 2*60*60))
				return mustMarshal(t, request)
			},
		},
		{
			name:   "objective create rejects a schema that names another command",
			decode: func(data []byte) error { _, err := DecodeObjectiveAndWorkCreateRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := objectiveAndWorkCreateTestDTO(t, fixture)
				request.Schema = SchemaRunStartCommand
				return mustMarshal(t, request)
			},
		},
		{
			name:   "run plan rejects an operation that names another command",
			decode: func(data []byte) error { _, err := DecodeRunPlanWithBindingsRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := runPlanWithBindingsTestDTO(t, fixture)
				request.Operation = OperationRunJoin
				return mustMarshal(t, request)
			},
		},
		{
			name:   "run join rejects an operation that names another command",
			decode: func(data []byte) error { _, err := DecodeRunJoinRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := runJoinTestDTO(t, fixture)
				request.Operation = OperationRunStart
				return mustMarshal(t, request)
			},
		},
		{
			name:   "run start rejects an operation that names another command",
			decode: func(data []byte) error { _, err := DecodeRunStartRequest(data); return err },
			payload: func(t *testing.T) []byte {
				request := runStartTestDTO(t, fixture)
				request.Operation = OperationRunJoin
				return mustMarshal(t, request)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.decode(test.payload(t)); err == nil {
				t.Fatal("decode() error = nil, want a rejection")
			}
		})
	}
}

// TestWorkRefObserveCreateSurvivesJSON is the regression for a defect these
// decoder tests uncovered: a first observation was expressible in Go and
// accepted by Values(), but could not be encoded. expected_versions.
// work_reference was a non-pointer domain.Version, and domain.Version refuses
// to marshal a zero value, so every Go client failed at the encoder while a
// hand-written payload omitting the member was accepted. Handler tests never
// caught it because they pass the struct in-process and never encode it.
//
// The field is now a pointer, so absence — not a zero value — selects create.
func TestWorkRefObserveCreateSurvivesJSON(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	adapter, err := domain.NewPrincipalID()
	if err != nil {
		t.Fatal(err)
	}
	create := workRefObserveTestDTO(t, fixture, adapter)
	if create.ExpectedVersions.WorkReference != nil {
		t.Fatal("the shared fixture is no longer a first observation, so this test proves nothing")
	}

	encoded := mustMarshal(t, create)
	decoded, err := DecodeWorkRefObserveRequest(encoded)
	if err != nil {
		t.Fatalf("a first observation did not survive JSON: %v", err)
	}
	if decoded.ExpectedVersions.WorkReference != nil {
		t.Fatalf("work_reference = %v, want nil to select the create path", decoded.ExpectedVersions.WorkReference)
	}
	values, err := decoded.Values()
	if err != nil {
		t.Fatalf("Values() rejected a decoded first observation: %v", err)
	}
	if !values.ExpectedWorkReferenceVersion.IsZero() {
		t.Fatalf("ExpectedWorkReferenceVersion = %v, want the zero version for a create",
			values.ExpectedWorkReferenceVersion)
	}

	// Omitting the member entirely is what pre-pointer clients had to hand-write,
	// and it must keep selecting create rather than becoming a decode error.
	omitted := mustRemoveJSONField(t, encoded, `,"work_reference":null`)
	fromOmitted, err := DecodeWorkRefObserveRequest(omitted)
	if err != nil {
		t.Fatalf("an omitted work_reference was rejected: %v", err)
	}
	if fromOmitted.ExpectedVersions.WorkReference != nil {
		t.Fatal("an omitted work_reference did not select the create path")
	}

	// A create may not also claim to supersede a provider version.
	conflicting := workRefObserveTestDTO(t, fixture, adapter)
	conflicting.Body.PreviousProviderVersion = "etag-a0"
	if _, err := DecodeWorkRefObserveRequest(mustMarshal(t, conflicting)); err == nil {
		t.Fatal("a create carrying previous_provider_version was accepted")
	}

	// An update must still pin a usable version.
	zero := workRefObserveTestDTO(t, fixture, adapter)
	unusable := domain.Version{}
	zero.ExpectedVersions.WorkReference = &unusable
	if _, err := zero.Values(); err == nil {
		t.Fatal("a present but unusable work_reference was treated as a create")
	}
}
