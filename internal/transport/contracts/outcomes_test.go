package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

func TestCommandResultsStrictBoundary(t *testing.T) {
	t.Parallel()

	bootstrap := fixtureBootstrapResult(t)
	if _, err := DecodeInstallationBootstrapResult(mustMarshal(t, bootstrap)); err != nil {
		t.Fatalf("DecodeInstallationBootstrapResult() error = %v", err)
	}
	workspace := fixtureWorkspaceResult(t)
	if _, err := DecodeWorkspaceCreateResult(mustMarshal(t, workspace)); err != nil {
		t.Fatalf("DecodeWorkspaceCreateResult() error = %v", err)
	}
	additive := addTopLevelJSONField(mustMarshal(t, workspace), `"future_optional":true`)
	if _, err := DecodeWorkspaceCreateResult(additive); err != nil {
		t.Fatalf("additive output field error = %v, want nil", err)
	}
	wrongKind := bytes.Replace(
		mustMarshal(t, workspace),
		[]byte(`"resource_version":1`),
		[]byte(`"resource_version":"1"`),
		1,
	)
	if _, err := DecodeWorkspaceCreateResult(wrongKind); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("wrong kind error = %v, want ErrInvalidJSON", err)
	}
	if _, err := DecodeInstallationBootstrapResult(bytes.Repeat([]byte("x"), MaxOutcomeJSONBytes+1)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversize error = %v, want ErrPayloadTooLarge", err)
	}

	missingReplay := removeJSONField(mustMarshal(t, workspace), `"idempotent_replay":false,`)
	if _, err := DecodeWorkspaceCreateResult(missingReplay); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("missing replay member error = %v, want ErrInvalidContract", err)
	}
	wrongInitial := workspace
	wrongInitial.ResourceVersion = mustVersion(t, 2)
	if err := wrongInitial.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("workspace initial version error = %v, want ErrInvalidContract", err)
	}
	wrongInvitation := bootstrap
	wrongInvitation.ResourceVersions.Invitation = domain.InitialVersion()
	if err := wrongInvitation.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("invitation advanced version error = %v, want ErrInvalidContract", err)
	}
	wrongMembership := workspace
	wrongMembership.Resource.MembershipVersion = mustVersion(t, 2)
	if err := wrongMembership.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("membership initial version error = %v, want ErrInvalidContract", err)
	}
	for name, mutate := range map[string]func(*InstallationBootstrapResultDTO){
		"principal": func(value *InstallationBootstrapResultDTO) { value.ResourceVersions.Principal = mustVersion(t, 2) },
		"device":    func(value *InstallationBootstrapResultDTO) { value.ResourceVersions.Device = mustVersion(t, 2) },
		"grant":     func(value *InstallationBootstrapResultDTO) { value.ResourceVersions.Grant = mustVersion(t, 2) },
	} {
		t.Run("bootstrap initial "+name, func(t *testing.T) {
			value := bootstrap
			mutate(&value)
			if err := value.Validate(); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("Validate() error = %v, want ErrInvalidContract", err)
			}
		})
	}
}

func TestTypedErrorStrictBoundaryAndJSONStability(t *testing.T) {
	t.Parallel()

	correlation := mustParseCorrelationID(t, idCorrelation)
	expected := domain.InitialVersion()
	actual := mustVersion(t, 2)
	result := ErrorDTO{
		Schema:        SchemaError,
		RequestID:     "req-error-1",
		Code:          domain.ErrorCodeStaleVersion,
		Category:      domain.ErrorCategoryConflict,
		Message:       "The workspace changed since it was read.",
		Retryable:     true,
		RetryAfterMS:  nil,
		CorrelationID: &correlation,
		Details: ErrorDetailsDTO{
			DomainConflict: domain.ConflictVersion,
			Aggregate: &AggregateConflictDTO{
				Type:            domain.AggregateKindWorkspace,
				ID:              idWorkspace,
				ExpectedVersion: &expected,
				ActualVersion:   &actual,
			},
		},
	}
	encoded := mustMarshal(t, result)
	if _, err := DecodeError(encoded); err != nil {
		t.Fatalf("DecodeError() error = %v", err)
	}
	want := `{"schema":"blackbird.error/1","request_id":"req-error-1","code":"STALE_VERSION","category":"conflict","message":"The workspace changed since it was read.","retryable":true,"retry_after_ms":null,"correlation_id":"` + idCorrelation + `","details":{"domain_conflict":"VersionConflict","aggregate":{"type":"workspace","id":"` + idWorkspace + `","expected_version":1,"actual_version":2}}}`
	if string(encoded) != want {
		t.Fatalf("JSON changed\n got: %s\nwant: %s", encoded, want)
	}

	wrongCategory := bytes.Replace(encoded, []byte(`"category":"conflict"`), []byte(`"category":"validation"`), 1)
	if _, err := DecodeError(wrongCategory); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("category error = %v, want ErrInvalidContract", err)
	}
	additiveDetails := bytes.Replace(encoded, []byte(`"details":{`), []byte(`"details":{"future_safe":true,`), 1)
	if _, err := DecodeError(additiveDetails); err != nil {
		t.Fatalf("additive details error = %v, want nil", err)
	}
	duplicateDetails := bytes.Replace(encoded, []byte(`"details":{`), []byte(`"details":{"domain_conflict":"VersionConflict",`), 1)
	if _, err := DecodeError(duplicateDetails); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("duplicate details error = %v, want ErrInvalidJSON", err)
	}
	missingActual := result
	missingActual.Details.Aggregate = &AggregateConflictDTO{
		Type:            domain.AggregateKindWorkspace,
		ID:              idWorkspace,
		ExpectedVersion: &expected,
	}
	if err := missingActual.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("missing actual version error = %v, want ErrInvalidContract", err)
	}
}

func TestErrorCodeSpecificDetailsRejectAmbiguity(t *testing.T) {
	t.Parallel()

	base := func(code domain.ErrorCode) ErrorDTO {
		category, _ := code.Category()
		return ErrorDTO{
			Schema:    SchemaError,
			RequestID: "req-error-specific",
			Code:      code,
			Category:  category,
			Message:   "Safe failure.",
			Retryable: code.DefaultRetryable(),
		}
	}
	delay := uint32(250)
	inProgress := base(domain.ErrorCodeCommandInProgress)
	inProgress.RetryAfterMS = &delay
	inProgress.Details = ErrorDetailsDTO{Recovery: RecoveryRetryAfterDelay, IdempotencyKey: "retry-key"}
	if err := inProgress.Validate(); err != nil {
		t.Fatalf("valid COMMAND_IN_PROGRESS error = %v", err)
	}

	authorityConflict := base(domain.ErrorCodeStateConflict)
	authorityConflict.Details = ErrorDetailsDTO{
		DomainConflict: domain.ConflictAuthorityMismatch,
		ResourceScope:  &ResourceScopeDTO{Type: domain.AggregateKindWorkspace, ID: idWorkspace},
		CurrentAuthority: &AuthorityRouteDTO{
			AuthorityID:    mustParseAuthorityID(t, idAuthority),
			AuthorityEpoch: mustParseAuthorityEpoch(t, idEpoch),
			TransitionRef:  "transfer-42",
		},
	}
	if err := authorityConflict.Validate(); err != nil {
		t.Fatalf("valid AuthorityMismatch error = %v", err)
	}

	referenceConflict := base(domain.ErrorCodeStateConflict)
	referenceConflict.Details = ErrorDetailsDTO{
		DomainConflict: domain.ConflictReference,
		Aggregate:      &AggregateConflictDTO{Type: domain.AggregateKindWorkspace, ID: idWorkspace},
	}
	if err := referenceConflict.Validate(); err != nil {
		t.Fatalf("valid ReferenceConflict error = %v", err)
	}

	terminalConflict := base(domain.ErrorCodeStateConflict)
	terminalConflict.Details = ErrorDetailsDTO{
		DomainConflict: domain.ConflictSessionTerminal,
		Aggregate:      &AggregateConflictDTO{Type: domain.AggregateKindActorSession, ID: idSession},
		CurrentState:   "ended",
	}
	if err := terminalConflict.Validate(); err != nil {
		t.Fatalf("valid SessionTerminalConflict error = %v", err)
	}

	authz := base(domain.ErrorCodeCapabilityRequired)
	authz.Details = ErrorDetailsDTO{
		DeniedCapability: "workspace:admin",
		ResourceScope:    &ResourceScopeDTO{Type: domain.AggregateKindWorkspace, ID: idWorkspace},
	}
	if err := authz.Validate(); err != nil {
		t.Fatalf("valid capability error = %v", err)
	}

	tests := []struct {
		name  string
		value ErrorDTO
	}{
		{name: "missing retry delay", value: func() ErrorDTO {
			value := inProgress
			value.RetryAfterMS = nil
			return value
		}()},
		{name: "zero retry delay", value: func() ErrorDTO {
			value := inProgress
			zero := uint32(0)
			value.RetryAfterMS = &zero
			return value
		}()},
		{name: "unbounded retry delay", value: func() ErrorDTO {
			value := inProgress
			tooLong := MaxRetryAfterMS + 1
			value.RetryAfterMS = &tooLong
			return value
		}()},
		{name: "unexpected retry delay", value: func() ErrorDTO {
			value := referenceConflict
			value.RetryAfterMS = &delay
			return value
		}()},
		{name: "wrong retry posture", value: func() ErrorDTO {
			value := inProgress
			value.Retryable = false
			return value
		}()},
		{name: "wrong conflict mapping", value: func() ErrorDTO {
			value := referenceConflict
			value.Details.DomainConflict = domain.ConflictVersion
			return value
		}()},
		{name: "missing state evidence", value: func() ErrorDTO {
			value := terminalConflict
			value.Details.CurrentState = ""
			return value
		}()},
		{name: "missing authority target", value: func() ErrorDTO {
			value := authorityConflict
			value.Details.ResourceScope = nil
			return value
		}()},
		{name: "future conflict lacks W0 schema", value: func() ErrorDTO {
			value := referenceConflict
			value.Details.DomainConflict = domain.ConflictLease
			return value
		}()},
		{name: "lease code unavailable", value: func() ErrorDTO {
			value := base(domain.ErrorCodeLeaseConflict)
			value.Details.DomainConflict = domain.ConflictLease
			return value
		}()},
		{name: "lease scope conflict unavailable", value: func() ErrorDTO {
			value := base(domain.ErrorCodeInvalidArgument)
			value.Details.DomainConflict = domain.ConflictLeaseScope
			return value
		}()},
		{name: "missing authz scope", value: func() ErrorDTO {
			value := authz
			value.Details.ResourceScope = nil
			return value
		}()},
		{name: "not found cannot carry current version", value: func() ErrorDTO {
			value := base(domain.ErrorCodeNotFound)
			actual := domain.InitialVersion()
			value.Details.Aggregate = &AggregateConflictDTO{
				Type:          domain.AggregateKindWorkspace,
				ID:            idWorkspace,
				ActualVersion: &actual,
			}
			return value
		}()},
		{name: "unknown recovery action", value: func() ErrorDTO {
			value := inProgress
			value.Details.Recovery = "eventually"
			return value
		}()},
		{name: "forbidden unrelated detail", value: func() ErrorDTO {
			value := inProgress
			value.Details.Dependency = "postgres"
			return value
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.value.Validate(); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("Validate() error = %v, want ErrInvalidContract", err)
			}
		})
	}

	encoded := mustMarshal(t, inProgress)
	missingMembers := []struct {
		name  string
		exact string
	}{
		{name: "retryable", exact: `"retryable":true,`},
		{name: "retry_after_ms", exact: `"retry_after_ms":250,`},
		{name: "details", exact: `,"details":{"recovery":"retry_after_delay","idempotency_key":"retry-key"}`},
	}
	for _, member := range missingMembers {
		mutated := removeJSONField(encoded, member.exact)
		if _, err := DecodeError(mutated); err == nil {
			t.Fatalf("DecodeError() accepted missing required member %s", member.name)
		}
	}
}

func TestW02EventsStrictTypedPayloads(t *testing.T) {
	t.Parallel()

	installationID := mustParseInstallationID(t, idInstallation)
	workspaceID := mustParseWorkspaceID(t, idWorkspace)
	principalID := mustParsePrincipalID(t, idPrincipal)
	actorID := mustParseActorID(t, idActor)
	sessionID := mustParseActorSessionID(t, idSession)

	installation := fixtureEvent(
		t,
		EventTypeInstallationBootstrapped,
		domain.AggregateKindInvitation,
		idInvitation,
		&installationID,
		nil,
		InstallationBootstrappedPayloadDTO{
			InstallationID:           installationID,
			InvitationID:             mustParseInvitationID(t, idInvitation),
			PrincipalID:              principalID,
			DeviceID:                 mustParseDeviceID(t, idDevice),
			InstallationOwnerGrantID: mustParseGrantID(t, idGrant),
			TranscriptHash:           strings.Repeat("a", 64),
		},
	)
	installation.Aggregate.Version = mustVersion(t, 2)
	if _, err := DecodeInstallationBootstrappedEvent(mustMarshal(t, installation)); err != nil {
		t.Fatalf("DecodeInstallationBootstrappedEvent() error = %v", err)
	}

	principal := fixtureEvent(
		t,
		EventTypePrincipalRegistered,
		domain.AggregateKindPrincipal,
		idPrincipal,
		&installationID,
		nil,
		PrincipalRegisteredPayloadDTO{PrincipalID: principalID, Kind: PrincipalKindHuman, DisplayName: "Alice"},
	)
	if _, err := DecodePrincipalRegisteredEvent(mustMarshal(t, principal)); err != nil {
		t.Fatalf("DecodePrincipalRegisteredEvent() error = %v", err)
	}

	device := fixtureEvent(
		t,
		EventTypeDevicePaired,
		domain.AggregateKindDevice,
		idDevice,
		&installationID,
		nil,
		DevicePairedPayloadDTO{
			DeviceID:       mustParseDeviceID(t, idDevice),
			PrincipalID:    principalID,
			DisplayName:    "Alice Cockpit",
			TranscriptHash: strings.Repeat("a", 64),
		},
	)
	if _, err := DecodeDevicePairedEvent(mustMarshal(t, device)); err != nil {
		t.Fatalf("DecodeDevicePairedEvent() error = %v", err)
	}

	pairingBegan := fixtureEvent(
		t,
		EventTypeDevicePairingBegan,
		domain.AggregateKindDevice,
		idDevice,
		&installationID,
		nil,
		DevicePairingBeganPayloadDTO{
			DeviceID:           mustParseDeviceID(t, idDevice),
			PrincipalID:        principalID,
			CeremonyID:         CeremonyIDDTO(idEventTwo),
			DisplayName:        "Alice Phone",
			PublicKeyReference: "thumbprint:phone-key-1",
		},
	)
	if _, err := DecodeDevicePairingBeganEvent(mustMarshal(t, pairingBegan)); err != nil {
		t.Fatalf("DecodeDevicePairingBeganEvent() error = %v", err)
	}

	workspace := fixtureEvent(
		t,
		EventTypeWorkspaceCreated,
		domain.AggregateKindWorkspace,
		idWorkspace,
		nil,
		&workspaceID,
		WorkspaceCreatedPayloadDTO{
			WorkspaceID:     workspaceID,
			Alias:           "Proof Workspace",
			HomeAuthorityID: mustParseAuthorityID(t, idAuthority),
			AuthorityEpoch:  mustParseAuthorityEpoch(t, idEpoch),
			PolicyRevision:  "policy-w0.2",
		},
	)
	if _, err := DecodeWorkspaceCreatedEvent(mustMarshal(t, workspace)); err != nil {
		t.Fatalf("DecodeWorkspaceCreatedEvent() error = %v", err)
	}

	membershipID := mustParseMembershipID(t, idMembership)
	invited := fixtureEvent(
		t,
		EventTypeWorkspaceMemberInvited,
		domain.AggregateKindMembership,
		idMembership,
		nil,
		&workspaceID,
		WorkspaceMemberInvitedPayloadDTO{
			WorkspaceID:       workspaceID,
			MembershipID:      membershipID,
			PrincipalID:       principalID,
			CapabilityCeiling: []string{"workspace:admin"},
		},
	)
	if _, err := DecodeWorkspaceMemberInvitedEvent(mustMarshal(t, invited)); err != nil {
		t.Fatalf("DecodeWorkspaceMemberInvitedEvent() error = %v", err)
	}

	accepted := fixtureEvent(
		t,
		EventTypeWorkspaceMembershipAccepted,
		domain.AggregateKindMembership,
		idMembership,
		nil,
		&workspaceID,
		WorkspaceMembershipAcceptedPayloadDTO{WorkspaceID: workspaceID, MembershipID: membershipID, PrincipalID: principalID},
	)
	if _, err := DecodeWorkspaceMembershipAcceptedEvent(mustMarshal(t, accepted)); err != nil {
		t.Fatalf("DecodeWorkspaceMembershipAcceptedEvent() error = %v", err)
	}

	createdActor := fixtureEvent(
		t,
		EventTypeActorCreated,
		domain.AggregateKindActor,
		idActor,
		nil,
		&workspaceID,
		ActorCreatedPayloadDTO{
			ActorID:     actorID,
			WorkspaceID: workspaceID,
			Kind:        ActorKindHuman,
			DisplayName: "Alice",
		},
	)
	if _, err := DecodeActorCreatedEvent(mustMarshal(t, createdActor)); err != nil {
		t.Fatalf("DecodeActorCreatedEvent() error = %v", err)
	}

	recipientID := mustParsePrincipalID(t, idClient)
	proposed := fixtureEvent(
		t,
		EventTypeActorDelegationProposed,
		domain.AggregateKindActorDelegation,
		idDelegation,
		nil,
		&workspaceID,
		ActorDelegationProposedPayloadDTO{
			DelegationID: mustParseActorDelegationID(t, idDelegation),
			WorkspaceID:  workspaceID,
			PrincipalID:  recipientID,
			ActorID:      actorID,
			CeremonyID:   CeremonyIDDTO(idEventTwo),
		},
	)
	if _, err := DecodeActorDelegationProposedEvent(mustMarshal(t, proposed)); err != nil {
		t.Fatalf("DecodeActorDelegationProposedEvent() error = %v", err)
	}

	activated := fixtureEvent(
		t,
		EventTypeActorDelegationActivated,
		domain.AggregateKindActorDelegation,
		idDelegation,
		nil,
		&workspaceID,
		ActorDelegationActivatedPayloadDTO{
			DelegationID:           mustParseActorDelegationID(t, idDelegation),
			PrincipalID:            principalID,
			ActorID:                actorID,
			SessionStartCeremonyID: CeremonyIDDTO(idEventThree),
		},
	)
	activated.Aggregate.Version = mustVersion(t, 2)
	if _, err := DecodeActorDelegationActivatedEvent(mustMarshal(t, activated)); err != nil {
		t.Fatalf("DecodeActorDelegationActivatedEvent() error = %v", err)
	}

	started := fixtureEvent(
		t,
		EventTypeActorSessionStarted,
		domain.AggregateKindActorSession,
		idSession,
		nil,
		&workspaceID,
		ActorSessionStartedPayloadDTO{
			ActorSessionID:        sessionID,
			WorkspaceID:           workspaceID,
			PrincipalID:           principalID,
			ActorID:               actorID,
			MembershipID:          membershipID,
			MembershipVersion:     domain.InitialVersion(),
			DelegationID:          mustParseActorDelegationID(t, idDelegation),
			DelegationVersion:     domain.InitialVersion(),
			DeviceID:              pointer(mustParseDeviceID(t, idDevice)),
			DeviceVersion:         pointer(domain.InitialVersion()),
			DeviceTrustRevision:   pointer(domain.InitialVersion()),
			GrantRevisions:        []GrantRevisionDTO{{GrantID: mustParseGrantID(t, idGrant), Version: domain.InitialVersion()}},
			ClientInstanceID:      mustParseClientInstanceID(t, idClient),
			PolicyRevision:        "policy-w0.2",
			AssuranceClass:        "paired_device",
			EffectiveCapabilities: []string{"context:read"},
			IssuedAt:              fixtureTime,
			AbsoluteExpiry:        fixtureTime.Add(time.Hour),
		},
	)
	started.PrincipalID = principalID
	started.ActorID = &actorID
	started.ActorSessionID = &sessionID
	if _, err := DecodeActorSessionStartedEvent(mustMarshal(t, started)); err != nil {
		t.Fatalf("DecodeActorSessionStartedEvent() error = %v", err)
	}

	wrongBootstrapScope := installation
	wrongInstallationID := mustParseInstallationID(t, idWorkspace)
	wrongBootstrapScope.InstallationID = &wrongInstallationID
	if _, err := DecodeInstallationBootstrappedEvent(mustMarshalEventUnchecked(t, wrongBootstrapScope)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("bootstrap scope mismatch error = %v, want ErrInvalidContract", err)
	}
	ordinaryPrincipalRegistration := principal
	ordinaryPrincipalRegistration.PrincipalID = mustParsePrincipalID(t, idActor)
	ordinaryPrincipalRegistration.Payload.Kind = PrincipalKindWorkload
	if _, err := DecodePrincipalRegisteredEvent(mustMarshal(t, ordinaryPrincipalRegistration)); err != nil {
		t.Fatalf("ordinary principal registrar attribution error = %v, want nil", err)
	}
	unknownPrincipalKind := principal
	unknownPrincipalKind.Payload.Kind = "robot"
	if _, err := DecodePrincipalRegisteredEvent(mustMarshalEventUnchecked(t, unknownPrincipalKind)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("unknown principal kind error = %v, want ErrInvalidContract", err)
	}
	wrongDeviceAttribution := device
	wrongDeviceAttribution.PrincipalID = mustParsePrincipalID(t, idActor)
	if _, err := DecodeDevicePairedEvent(mustMarshalEventUnchecked(t, wrongDeviceAttribution)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("device attribution mismatch error = %v, want ErrInvalidContract", err)
	}
	ordinaryDevicePairing := device
	ordinaryDevicePairing.Aggregate.Version = mustVersion(t, 2)
	if _, err := DecodeDevicePairedEvent(mustMarshal(t, ordinaryDevicePairing)); err != nil {
		t.Fatalf("ordinary DevicePaired@2 error = %v, want nil", err)
	}
	wrongWorkspaceScope := workspace
	wrongWorkspaceID := mustParseWorkspaceID(t, idInvitation)
	wrongWorkspaceScope.WorkspaceID = &wrongWorkspaceID
	if _, err := DecodeWorkspaceCreatedEvent(mustMarshalEventUnchecked(t, wrongWorkspaceScope)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("workspace scope mismatch error = %v, want ErrInvalidContract", err)
	}
	ordinaryMembershipAcceptance := accepted
	ordinaryMembershipAcceptance.Aggregate.Version = mustVersion(t, 2)
	if _, err := DecodeWorkspaceMembershipAcceptedEvent(mustMarshal(t, ordinaryMembershipAcceptance)); err != nil {
		t.Fatalf("ordinary WorkspaceMembershipAccepted@2 error = %v, want nil", err)
	}
	authorityFacts := []struct {
		name   string
		value  []byte
		decode func([]byte) error
	}{
		{name: "installation bootstrapped", value: mustMarshal(t, installation), decode: func(data []byte) error {
			_, err := DecodeInstallationBootstrappedEvent(data)
			return err
		}},
		{name: "principal registered", value: mustMarshal(t, principal), decode: func(data []byte) error {
			_, err := DecodePrincipalRegisteredEvent(data)
			return err
		}},
		{name: "device pairing began", value: mustMarshal(t, pairingBegan), decode: func(data []byte) error {
			_, err := DecodeDevicePairingBeganEvent(data)
			return err
		}},
		{name: "device paired", value: mustMarshal(t, device), decode: func(data []byte) error {
			_, err := DecodeDevicePairedEvent(data)
			return err
		}},
		{name: "workspace created", value: mustMarshal(t, workspace), decode: func(data []byte) error {
			_, err := DecodeWorkspaceCreatedEvent(data)
			return err
		}},
		{name: "workspace member invited", value: mustMarshal(t, invited), decode: func(data []byte) error {
			_, err := DecodeWorkspaceMemberInvitedEvent(data)
			return err
		}},
		{name: "workspace membership accepted", value: mustMarshal(t, accepted), decode: func(data []byte) error {
			_, err := DecodeWorkspaceMembershipAcceptedEvent(data)
			return err
		}},
	}
	for _, fact := range authorityFacts {
		t.Run(fact.name+" rejects actor authorship", func(t *testing.T) {
			withActor := addTopLevelJSONField(
				fact.value,
				`"actor_id":"`+idActor+`","actor_session_id":"`+idSession+`"`,
			)
			if err := fact.decode(withActor); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("error = %v, want ErrInvalidContract", err)
			}
		})
	}
	for name, encoded := range map[string][]byte{
		"device pairing began": mustMarshal(t, pairingBegan),
		"actor created":        mustMarshal(t, createdActor),
		"delegation proposed":  mustMarshal(t, proposed),
		"delegation activated": mustMarshal(t, activated),
	} {
		if _, err := DecodeEventEnvelope(encoded); err != nil {
			t.Fatalf("generic known %s error = %v", name, err)
		}
	}

	wrongPairingOrigin := pairingBegan
	wrongPairingOrigin.Aggregate.Version = mustVersion(t, 2)
	if _, err := DecodeDevicePairingBeganEvent(mustMarshalEventUnchecked(t, wrongPairingOrigin)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("DevicePairingBegan wrong origin error = %v, want ErrInvalidContract", err)
	}
	wrongPairingAttribution := pairingBegan
	wrongPairingAttribution.PrincipalID = mustParsePrincipalID(t, idActor)
	if _, err := DecodeDevicePairingBeganEvent(mustMarshalEventUnchecked(t, wrongPairingAttribution)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("DevicePairingBegan wrong attribution error = %v, want ErrInvalidContract", err)
	}
	wrongActorKind := createdActor
	wrongActorKind.Payload.Kind = "robot"
	if _, err := DecodeActorCreatedEvent(mustMarshalEventUnchecked(t, wrongActorKind)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("ActorCreated wrong kind error = %v, want ErrInvalidContract", err)
	}
	distinctAuthorActor := createdActor
	distinctAuthorActor.ActorID = pointer(mustParseActorID(t, idPrincipal))
	distinctAuthorActor.ActorSessionID = pointer(mustParseActorSessionID(t, idClient))
	if _, err := DecodeActorCreatedEvent(mustMarshal(t, distinctAuthorActor)); err != nil {
		t.Fatalf("ActorCreated distinct author actor error = %v, want nil", err)
	}
	distinctProposalAuthor := proposed
	distinctProposalAuthor.ActorID = pointer(mustParseActorID(t, idPrincipal))
	distinctProposalAuthor.ActorSessionID = pointer(mustParseActorSessionID(t, idClient))
	if _, err := DecodeActorDelegationProposedEvent(mustMarshal(t, distinctProposalAuthor)); err != nil {
		t.Fatalf("ActorDelegationProposed distinct author actor error = %v, want nil", err)
	}
	distinctActivationAuthor := activated
	distinctActivationAuthor.ActorID = pointer(mustParseActorID(t, idPrincipal))
	distinctActivationAuthor.ActorSessionID = pointer(mustParseActorSessionID(t, idClient))
	if _, err := DecodeActorDelegationActivatedEvent(mustMarshal(t, distinctActivationAuthor)); err != nil {
		t.Fatalf("ActorDelegationActivated distinct author actor error = %v, want nil", err)
	}
	wrongProposalScope := proposed
	wrongProposalScope.WorkspaceID = &wrongWorkspaceID
	if _, err := DecodeActorDelegationProposedEvent(mustMarshalEventUnchecked(t, wrongProposalScope)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("ActorDelegationProposed wrong scope error = %v, want ErrInvalidContract", err)
	}
	wrongActivationVersion := activated
	wrongActivationVersion.Aggregate.Version = domain.InitialVersion()
	if _, err := DecodeActorDelegationActivatedEvent(mustMarshalEventUnchecked(t, wrongActivationVersion)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("ActorDelegationActivated wrong version error = %v, want ErrInvalidContract", err)
	}
	wrongActivationPrincipal := activated
	wrongActivationPrincipal.PrincipalID = mustParsePrincipalID(t, idActor)
	if _, err := DecodeActorDelegationActivatedEvent(mustMarshalEventUnchecked(t, wrongActivationPrincipal)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("ActorDelegationActivated wrong principal error = %v, want ErrInvalidContract", err)
	}
	wrongCeremony := activated
	wrongCeremony.Payload.SessionStartCeremonyID = "not-a-uuid"
	if _, err := DecodeActorDelegationActivatedEvent(mustMarshalEventUnchecked(t, wrongCeremony)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("ActorDelegationActivated wrong ceremony error = %v, want ErrInvalidContract", err)
	}
	sessionWithoutActor := createdActor
	sessionWithoutActor.ActorSessionID = pointer(mustParseActorSessionID(t, idSession))
	if _, err := DecodeActorCreatedEvent(mustMarshalEventUnchecked(t, sessionWithoutActor)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("session without author actor error = %v, want ErrInvalidContract", err)
	}
	actorWithoutSession := createdActor
	actorWithoutSession.ActorID = pointer(mustParseActorID(t, idPrincipal))
	if _, err := DecodeActorCreatedEvent(mustMarshalEventUnchecked(t, actorWithoutSession)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("actor without author session error = %v, want ErrInvalidContract", err)
	}

	startedAmbiguities := []struct {
		name string
		edit func(ActorSessionStartedEventDTO) ActorSessionStartedEventDTO
	}{
		{name: "principal attribution", edit: func(value ActorSessionStartedEventDTO) ActorSessionStartedEventDTO {
			value.PrincipalID = mustParsePrincipalID(t, idActor)
			return value
		}},
		{name: "actor attribution", edit: func(value ActorSessionStartedEventDTO) ActorSessionStartedEventDTO {
			value.ActorID = pointer(mustParseActorID(t, idPrincipal))
			return value
		}},
		{name: "session attribution", edit: func(value ActorSessionStartedEventDTO) ActorSessionStartedEventDTO {
			value.ActorSessionID = pointer(mustParseActorSessionID(t, idActor))
			return value
		}},
		{name: "missing paired device version", edit: func(value ActorSessionStartedEventDTO) ActorSessionStartedEventDTO {
			value.Payload.DeviceVersion = nil
			return value
		}},
		{name: "missing device trust revision", edit: func(value ActorSessionStartedEventDTO) ActorSessionStartedEventDTO {
			value.Payload.DeviceTrustRevision = nil
			return value
		}},
		{name: "unsorted grants", edit: func(value ActorSessionStartedEventDTO) ActorSessionStartedEventDTO {
			value.Payload.GrantRevisions = []GrantRevisionDTO{
				{GrantID: mustParseGrantID(t, idGrant), Version: domain.InitialVersion()},
				{GrantID: mustParseGrantID(t, idInvitation), Version: domain.InitialVersion()},
			}
			return value
		}},
	}
	for _, test := range startedAmbiguities {
		t.Run("actor session "+test.name, func(t *testing.T) {
			if _, err := DecodeActorSessionStartedEvent(mustMarshalEventUnchecked(t, test.edit(started))); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("error = %v, want ErrInvalidContract", err)
			}
		})
	}

	additivePayload := bytes.Replace(
		mustMarshal(t, installation),
		[]byte(`"payload":{`),
		[]byte(`"payload":{"secret":"forbidden",`),
		1,
	)
	if _, err := DecodeInstallationBootstrappedEvent(additivePayload); err != nil {
		t.Fatalf("additive payload error = %v, want nil", err)
	}
	wrongKind := bytes.Replace(
		mustMarshal(t, installation),
		[]byte(`"event_version":1`),
		[]byte(`"event_version":"1"`),
		1,
	)
	if _, err := DecodeInstallationBootstrappedEvent(wrongKind); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("wrong event kind error = %v, want ErrInvalidJSON", err)
	}
	nullExtensions := bytes.Replace(mustMarshal(t, installation), []byte(`"extensions":{}`), []byte(`"extensions":null`), 1)
	if _, err := DecodeInstallationBootstrappedEvent(nullExtensions); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("null extensions error = %v, want ErrInvalidContract", err)
	}
}

func TestEventJSONFieldStability(t *testing.T) {
	t.Parallel()

	installationID := mustParseInstallationID(t, idInstallation)
	event := fixtureEvent(
		t,
		EventTypeInstallationBootstrapped,
		domain.AggregateKindInvitation,
		idInvitation,
		&installationID,
		nil,
		InstallationBootstrappedPayloadDTO{
			InstallationID:           installationID,
			InvitationID:             mustParseInvitationID(t, idInvitation),
			PrincipalID:              mustParsePrincipalID(t, idPrincipal),
			DeviceID:                 mustParseDeviceID(t, idDevice),
			InstallationOwnerGrantID: mustParseGrantID(t, idGrant),
			TranscriptHash:           strings.Repeat("a", 64),
		},
	)
	event.Aggregate.Version = mustVersion(t, 2)
	encoded := string(mustMarshal(t, event))
	want := `{"schema":"blackbird.event_envelope/1","event_id":"` + idEventOne + `","event_type":"blackbird.installation.bootstrapped","event_version":1,"authority_id":"` + idAuthority + `","authority_epoch":"` + idEpoch + `","installation_id":"` + idInstallation + `","origin_position":1,"aggregate":{"type":"invitation","id":"` + idInvitation + `","version":2},"principal_id":"` + idPrincipal + `","command_id":"` + idCommand + `","correlation_id":"` + idCorrelation + `","occurred_at":"2026-08-04T12:00:00.123Z","recorded_at":"2026-08-04T12:00:00.123Z","payload":{"installation_id":"` + idInstallation + `","invitation_id":"` + idInvitation + `","principal_id":"` + idPrincipal + `","device_id":"` + idDevice + `","installation_owner_grant_id":"` + idGrant + `","transcript_hash":"` + strings.Repeat("a", 64) + `"},"extensions":{}}`
	if encoded != want {
		t.Fatalf("JSON changed\n got: %s\nwant: %s", encoded, want)
	}
}

func TestEventEnvelopeForwardCompatibilityAndAmbiguityRejection(t *testing.T) {
	t.Parallel()

	installationID := mustParseInstallationID(t, idInstallation)
	principalID := mustParsePrincipalID(t, idPrincipal)
	event := fixtureEvent(
		t,
		"blackbird.future.fact",
		domain.AggregateKindInvitation,
		idInvitation,
		&installationID,
		nil,
		map[string]string{"future": "retained"},
	)
	event.EventVersion = 2
	event.Aggregate.Version = mustVersion(t, 2)
	event.Aggregate.Type = domain.AggregateKind("future_widget")
	event.Aggregate.ID = "future-widget-42"
	encoded := mustMarshal(t, event)
	raw, err := DecodeEventEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeEventEnvelope(unknown) error = %v", err)
	}
	if raw.EventType != "blackbird.future.fact" || !bytes.Contains(raw.Payload, []byte(`"future":"retained"`)) {
		t.Fatalf("raw unknown event was not retained: %#v", raw)
	}

	knownUnsupported := bytes.Replace(encoded, []byte("blackbird.future.fact"), []byte(EventTypeInstallationBootstrapped), 1)
	if _, err := DecodeEventEnvelope(knownUnsupported); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("known unsupported major error = %v, want ErrInvalidContract", err)
	}
	for _, knownType := range []string{
		EventTypeDevicePairingBegan,
		EventTypeActorCreated,
		EventTypeActorDelegationProposed,
		EventTypeActorDelegationActivated,
	} {
		unsupported := bytes.Replace(encoded, []byte("blackbird.future.fact"), []byte(knownType), 1)
		if _, err := DecodeEventEnvelope(unsupported); !errors.Is(err, ErrInvalidContract) {
			t.Fatalf("known %s unsupported major error = %v, want ErrInvalidContract", knownType, err)
		}
		knownButGated := bytes.Replace(unsupported, []byte(`"event_version":2`), []byte(`"event_version":1`), 1)
		if _, err := DecodeEventEnvelope(knownButGated); !errors.Is(err, ErrInvalidContract) {
			t.Fatalf("known %s gated v1 error = %v, want ErrInvalidContract", knownType, err)
		}
	}

	missingExtensions := bytes.Replace(encoded, []byte(`,"extensions":{}`), nil, 1)
	if _, err := DecodeEventEnvelope(missingExtensions); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("missing extensions error = %v, want ErrInvalidContract", err)
	}
	duplicatePayload := bytes.Replace(encoded, []byte(`"payload":{"future":"retained"}`), []byte(`"payload":{"future":"one","future":"two"}`), 1)
	if _, err := DecodeEventEnvelope(duplicatePayload); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("duplicate payload error = %v, want ErrInvalidJSON", err)
	}

	bootstrap := fixtureEvent(
		t,
		EventTypeInstallationBootstrapped,
		domain.AggregateKindInvitation,
		idInvitation,
		&installationID,
		nil,
		InstallationBootstrappedPayloadDTO{
			InstallationID:           installationID,
			InvitationID:             mustParseInvitationID(t, idInvitation),
			PrincipalID:              principalID,
			DeviceID:                 mustParseDeviceID(t, idDevice),
			InstallationOwnerGrantID: mustParseGrantID(t, idGrant),
			TranscriptHash:           strings.Repeat("a", 64),
		},
	)
	bootstrap.Aggregate.Version = mustVersion(t, 2)
	bootstrap.PrincipalID = mustParsePrincipalID(t, idActor)
	if _, err := DecodeInstallationBootstrappedEvent(mustMarshalEventUnchecked(t, bootstrap)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("bootstrap attribution mismatch error = %v, want ErrInvalidContract", err)
	}
}

func TestIJSONIntegerBoundsAcrossTransportPaths(t *testing.T) {
	t.Parallel()

	maximum := strconv.FormatUint(domain.MaxCanonicalInteger, 10)
	unsafe := strconv.FormatUint(domain.MaxCanonicalInteger+1, 10)
	installationID := mustParseInstallationID(t, idInstallation)
	known := fixtureEvent(
		t,
		EventTypeInstallationBootstrapped,
		domain.AggregateKindInvitation,
		idInvitation,
		&installationID,
		nil,
		InstallationBootstrappedPayloadDTO{
			InstallationID:           installationID,
			InvitationID:             mustParseInvitationID(t, idInvitation),
			PrincipalID:              mustParsePrincipalID(t, idPrincipal),
			DeviceID:                 mustParseDeviceID(t, idDevice),
			InstallationOwnerGrantID: mustParseGrantID(t, idGrant),
			TranscriptHash:           strings.Repeat("a", 64),
		},
	)
	known.Aggregate.Version = mustVersion(t, 2)
	known.OriginPosition = mustStreamPosition(t, domain.MaxCanonicalInteger)
	knownAtMaximum := mustMarshal(t, known)
	if _, err := DecodeInstallationBootstrappedEvent(knownAtMaximum); err != nil {
		t.Fatalf("known event at maximum error = %v", err)
	}
	if _, err := DecodeEventEnvelope(knownAtMaximum); err != nil {
		t.Fatalf("raw known event at maximum error = %v", err)
	}
	knownPastMaximum := bytes.Replace(
		knownAtMaximum,
		[]byte(`"origin_position":`+maximum),
		[]byte(`"origin_position":`+unsafe),
		1,
	)
	if _, err := DecodeInstallationBootstrappedEvent(knownPastMaximum); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("known event past maximum error = %v, want ErrInvalidJSON", err)
	}
	if _, err := DecodeEventEnvelope(knownPastMaximum); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("raw known event past maximum error = %v, want ErrInvalidJSON", err)
	}

	unknown := fixtureEvent(
		t,
		"blackbird.future.integer_fact",
		domain.AggregateKindInvitation,
		idInvitation,
		&installationID,
		nil,
		map[string]any{"future_integer": domain.MaxCanonicalInteger},
	)
	unknown.EventVersion = 2
	unknown.Aggregate.Type = domain.AggregateKind("future_widget")
	unknown.Aggregate.ID = "future-widget-maximum"
	unknown.Aggregate.Version = mustVersion(t, domain.MaxCanonicalInteger)
	unknown.OriginPosition = mustStreamPosition(t, domain.MaxCanonicalInteger)
	unknownAtMaximum := mustMarshal(t, unknown)
	raw, err := DecodeEventEnvelope(unknownAtMaximum)
	if err != nil {
		t.Fatalf("unknown event at maximum error = %v", err)
	}
	if _, err := json.Marshal(raw); err != nil {
		t.Fatalf("retained raw event at maximum marshal error = %v", err)
	}

	unsafeUnknownPayload := bytes.Replace(
		unknownAtMaximum,
		[]byte(`"future_integer":`+maximum),
		[]byte(`"future_integer":`+unsafe),
		1,
	)
	if _, err := DecodeEventEnvelope(unsafeUnknownPayload); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("unknown payload past maximum error = %v, want ErrInvalidJSON", err)
	}
	unsafeUnknownExtensions := bytes.Replace(
		unknownAtMaximum,
		[]byte(`"extensions":{}`),
		[]byte(`"extensions":{"future_integer":`+unsafe+`}`),
		1,
	)
	if _, err := DecodeEventEnvelope(unsafeUnknownExtensions); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("unknown extensions past maximum error = %v, want ErrInvalidJSON", err)
	}
	unsafeKnownAdditivePayload := bytes.Replace(
		knownAtMaximum,
		[]byte(`"payload":{`),
		[]byte(`"payload":{"future_integer":`+unsafe+`,`),
		1,
	)
	safeKnownAdditivePayload := bytes.Replace(
		knownAtMaximum,
		[]byte(`"payload":{`),
		[]byte(`"payload":{"future_integer":`+maximum+`,`),
		1,
	)
	if _, err := DecodeInstallationBootstrappedEvent(safeKnownAdditivePayload); err != nil {
		t.Fatalf("known additive payload at maximum error = %v", err)
	}
	if _, err := DecodeInstallationBootstrappedEvent(unsafeKnownAdditivePayload); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("known additive payload past maximum error = %v, want ErrInvalidJSON", err)
	}
	safeAdditiveOutcome := addTopLevelJSONField(
		mustMarshal(t, fixtureWorkspaceResult(t)),
		`"future_integer":`+maximum,
	)
	if _, err := DecodeWorkspaceCreateResult(safeAdditiveOutcome); err != nil {
		t.Fatalf("discarded additive output at maximum error = %v", err)
	}
	unsafeAdditiveOutcome := addTopLevelJSONField(
		mustMarshal(t, fixtureWorkspaceResult(t)),
		`"future_integer":`+unsafe,
	)
	if _, err := DecodeWorkspaceCreateResult(unsafeAdditiveOutcome); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("discarded additive output past maximum error = %v, want ErrInvalidJSON", err)
	}
	negativeAdditiveOutcome := addTopLevelJSONField(
		mustMarshal(t, fixtureWorkspaceResult(t)),
		`"future_integer":-1`,
	)
	if _, err := DecodeWorkspaceCreateResult(negativeAdditiveOutcome); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("discarded negative additive output error = %v, want ErrInvalidJSON", err)
	}

	unsafeGeneric := unknown
	unsafeGeneric.Payload = map[string]any{"future_integer": domain.MaxCanonicalInteger + 1}
	if _, err := json.Marshal(unsafeGeneric); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("direct generic event marshal error = %v, want ErrInvalidJSON", err)
	}
	raw.Payload = json.RawMessage(`{"future_integer":` + unsafe + `}`)
	if _, err := json.Marshal(raw); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("direct raw event marshal error = %v, want ErrInvalidJSON", err)
	}
	raw.Payload = json.RawMessage(`{"future_integer":` + maximum + `}`)
	raw.Extensions = json.RawMessage(`{"future_integer":` + unsafe + `}`)
	if _, err := json.Marshal(raw); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("direct raw event extensions marshal error = %v, want ErrInvalidJSON", err)
	}
	invalidEnvelope := known
	invalidEnvelope.PrincipalID = mustParsePrincipalID(t, idActor)
	if _, err := json.Marshal(invalidEnvelope); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("direct semantically invalid event marshal error = %v, want ErrInvalidContract", err)
	}

	for _, representation := range []string{
		unsafe,
		unsafe + ".0",
		"9.007199254740992e15",
		"-" + unsafe,
		"-1",
		"1e309",
	} {
		t.Run("opaque number "+representation, func(t *testing.T) {
			candidate := bytes.Replace(
				unknownAtMaximum,
				[]byte(`"future_integer":`+maximum),
				[]byte(`"future_integer":`+representation),
				1,
			)
			if _, err := DecodeEventEnvelope(candidate); !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("error = %v, want ErrInvalidJSON", err)
			}
		})
	}
}

func fixtureBootstrapResult(t *testing.T) InstallationBootstrapResultDTO {
	t.Helper()
	return InstallationBootstrapResultDTO{
		CommandResultMetadataDTO: fixtureResultMetadata(t, OperationInstallationBootstrap, idEventOne, idEventTwo, idEventThree),
		Resource: InstallationBootstrapResourceDTO{
			InstallationID:           mustParseInstallationID(t, idInstallation),
			InvitationID:             mustParseInvitationID(t, idInvitation),
			InvitationState:          StateConsumed,
			PrincipalID:              mustParsePrincipalID(t, idPrincipal),
			PrincipalState:           StateActive,
			DeviceID:                 mustParseDeviceID(t, idDevice),
			DeviceState:              StateTrusted,
			InstallationOwnerGrantID: mustParseGrantID(t, idGrant),
			TranscriptHash:           strings.Repeat("a", 64),
		},
		ResourceVersions: InstallationBootstrapVersionsDTO{
			Invitation: mustVersion(t, 2),
			Principal:  domain.InitialVersion(),
			Device:     domain.InitialVersion(),
			Grant:      domain.InitialVersion(),
		},
	}
}

func fixtureWorkspaceResult(t *testing.T) WorkspaceCreateResultDTO {
	t.Helper()
	return WorkspaceCreateResultDTO{
		CommandResultMetadataDTO: fixtureResultMetadata(t, OperationWorkspaceCreate, idEventOne, idEventTwo, idEventThree),
		Resource: WorkspaceCreateResourceDTO{
			InstallationID:    mustParseInstallationID(t, idInstallation),
			WorkspaceID:       mustParseWorkspaceID(t, idWorkspace),
			WorkspaceState:    StateActive,
			Alias:             "Proof Workspace",
			OwnerPrincipalID:  mustParsePrincipalID(t, idPrincipal),
			OwnerMembershipID: mustParseMembershipID(t, idMembership),
			MembershipState:   StateActive,
			MembershipVersion: domain.InitialVersion(),
			AuthorityID:       mustParseAuthorityID(t, idAuthority),
			AuthorityEpoch:    mustParseAuthorityEpoch(t, idEpoch),
			PolicyRevision:    "policy-w0.2",
		},
		ResourceVersion: domain.InitialVersion(),
	}
}

func fixtureResultMetadata(t *testing.T, operation string, eventIDs ...string) CommandResultMetadataDTO {
	t.Helper()
	parsed := make([]domain.EventID, 0, len(eventIDs))
	for _, eventID := range eventIDs {
		parsed = append(parsed, mustParseEventID(t, eventID))
	}
	return CommandResultMetadataDTO{
		Schema:          SchemaCommandResult,
		RequestID:       "req-result-1",
		Operation:       operation,
		EventCursor:     "bbec1_fixture",
		EmittedEventIDs: parsed,
		AcceptedAt:      fixtureTime,
	}
}

func fixtureEvent[Payload any](
	t *testing.T,
	eventType string,
	aggregateKind domain.AggregateKind,
	aggregateID string,
	installationID *domain.InstallationID,
	workspaceID *domain.WorkspaceID,
	payload Payload,
) EventEnvelopeDTO[Payload] {
	t.Helper()
	correlation := mustParseCorrelationID(t, idCorrelation)
	return EventEnvelopeDTO[Payload]{
		Schema:         SchemaEventEnvelope,
		EventID:        mustParseEventID(t, idEventOne),
		EventType:      eventType,
		EventVersion:   1,
		AuthorityID:    mustParseAuthorityID(t, idAuthority),
		AuthorityEpoch: mustParseAuthorityEpoch(t, idEpoch),
		InstallationID: installationID,
		WorkspaceID:    workspaceID,
		OriginPosition: mustStreamPosition(t, 1),
		Aggregate:      EventAggregateDTO{Type: aggregateKind, ID: aggregateID, Version: domain.InitialVersion()},
		CommandID:      mustParseCommandID(t, idCommand),
		PrincipalID:    mustParsePrincipalID(t, idPrincipal),
		CorrelationID:  correlation,
		OccurredAt:     fixtureTime,
		RecordedAt:     fixtureTime,
		Payload:        payload,
		Extensions:     EmptyExtensionsDTO{},
	}
}

func mustVersion(t *testing.T, value uint64) domain.Version {
	t.Helper()
	version, err := domain.NewVersion(value)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func mustStreamPosition(t *testing.T, value uint64) domain.StreamPosition {
	t.Helper()
	position, err := domain.NewStreamPosition(value)
	if err != nil {
		t.Fatal(err)
	}
	return position
}

func mustMarshalEventUnchecked[Payload any](t *testing.T, event EventEnvelopeDTO[Payload]) []byte {
	t.Helper()
	type eventEnvelopeWire EventEnvelopeDTO[Payload]
	return mustMarshal(t, eventEnvelopeWire(event))
}

func pointer[T any](value T) *T { return &value }

func TestErrorJSONRejectsTrailingValueAndMissingRequired(t *testing.T) {
	t.Parallel()

	missing := []byte(`{"schema":"blackbird.error/1"}`)
	if _, err := DecodeError(missing); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("missing field error = %v, want ErrInvalidContract", err)
	}
	trailing, _ := json.Marshal(ErrorDTO{})
	trailing = append(trailing, []byte(` {}`)...)
	if _, err := DecodeError(trailing); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("trailing value error = %v, want ErrInvalidJSON", err)
	}
}
