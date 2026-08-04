package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

const (
	idInstallation = "01b8e094-9888-7000-8000-00000000004a"
	idInvitation   = "01b8e094-9888-7000-8000-00000000004b"
	idPrincipal    = "01b8e094-9888-7000-8000-000000000004"
	idDevice       = "01b8e094-9888-7000-8000-000000000006"
	idGrant        = "01b8e094-9888-7000-8000-00000000004c"
	idWorkspace    = "01b8e094-9888-7000-8000-000000000002"
	idMembership   = "01b8e094-9888-7000-8000-00000000004d"
	idActor        = "01b8e094-9888-7000-8000-000000000005"
	idDelegation   = "01b8e094-9888-7000-8000-000000000029"
	idSession      = "01b8e094-9888-7000-8000-00000000001f"
	idAuthority    = "01b8e094-9888-7000-8000-000000000003"
	idEpoch        = "01b8e094-9888-7000-8000-000000000015"
	idCommand      = "01b8e094-9888-7000-8000-00000000004e"
	idCorrelation  = "01b8e094-9888-7000-8000-000000000001"
	idClient       = "01b8e094-9888-7000-8000-00000000004f"
	idEventOne     = "01b8e094-9888-7000-8000-000000000050"
	idEventTwo     = "01b8e094-9888-7000-8000-000000000051"
	idEventThree   = "01b8e094-9888-7000-8000-000000000052"
)

var fixtureTime = time.Date(2026, 8, 4, 12, 0, 0, 123_000_000, time.UTC)

func TestInstallationBootstrapRequestStrictBoundary(t *testing.T) {
	t.Parallel()

	request := fixtureInstallationBootstrapRequest(t)
	encoded := mustMarshal(t, request)
	decoded, err := DecodeInstallationBootstrapRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeInstallationBootstrapRequest() error = %v", err)
	}
	values, err := decoded.Values()
	if err != nil {
		t.Fatalf("Values() error = %v", err)
	}
	if values.CommitSet.Kind() != domain.CommitSetBootstrapInstallation {
		t.Fatalf("CommitSet.Kind() = %q", values.CommitSet.Kind())
	}
	if got := len(values.CommitSet.Expectations()); got != 4 {
		t.Fatalf("CommitSet expectations = %d, want 4", got)
	}

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "required schema", data: removeJSONField(encoded, `"schema":"`+SchemaInstallationBootstrapCommand+`",`), want: ErrInvalidContract},
		{name: "unknown", data: addTopLevelJSONField(encoded, `"future":true`), want: ErrInvalidJSON},
		{name: "wrong JSON kind", data: bytes.Replace(encoded, []byte(`"installation_id":"`+idInstallation+`"`), []byte(`"installation_id":42`), 1), want: ErrInvalidJSON},
		{name: "oversize", data: bytes.Repeat([]byte("x"), MaxCommandJSONBytes+1), want: ErrPayloadTooLarge},
		{name: "wrong schema", data: bytes.Replace(encoded, []byte(SchemaInstallationBootstrapCommand), []byte(SchemaSessionStartCommand), 1), want: ErrInvalidContract},
		{name: "noncanonical digest", data: bytes.Replace(encoded, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("A", 64)), 1), want: ErrInvalidContract},
		{name: "required correlation", data: removeJSONField(encoded, `"correlation_id":"`+idCorrelation+`",`), want: ErrInvalidContract},
		{name: "invalid utf8", data: append([]byte(`{"schema":"`), 0xff), want: ErrInvalidJSON},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, gotErr := DecodeInstallationBootstrapRequest(test.data)
			if !errors.Is(gotErr, test.want) {
				t.Fatalf("error = %v, want errors.Is(%v)", gotErr, test.want)
			}
		})
	}
}

func TestWorkspaceCreateRequestStrictBoundary(t *testing.T) {
	t.Parallel()

	request := fixtureWorkspaceCreateRequest(t)
	encoded := mustMarshal(t, request)
	decoded, err := DecodeWorkspaceCreateRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeWorkspaceCreateRequest() error = %v", err)
	}
	values, err := decoded.Values()
	if err != nil {
		t.Fatalf("Values() error = %v", err)
	}
	if values.CommitSet.Kind() != domain.CommitSetCreateWorkspaceOwner {
		t.Fatalf("CommitSet.Kind() = %q", values.CommitSet.Kind())
	}
	if values.PolicyRevision.String() != "policy-w0.2" {
		t.Fatalf("PolicyRevision = %q", values.PolicyRevision.String())
	}
	if values.ClientInstanceID.String() != idClient {
		t.Fatalf("ClientInstanceID = %q, want %q", values.ClientInstanceID, idClient)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{name: "required alias", data: bytes.Replace(encoded, []byte(`"alias":"Proof Workspace"`), []byte(`"alias":""`), 1)},
		{name: "unknown nested", data: bytes.Replace(encoded, []byte(`"policy_revision":"policy-w0.2"`), []byte(`"policy_revision":"policy-w0.2","owner":true`), 1)},
		{name: "wrong JSON kind", data: bytes.Replace(encoded, []byte(`"owner_principal":1`), []byte(`"owner_principal":"1"`), 1)},
		{name: "oversize alias", data: bytes.Replace(encoded, []byte("Proof Workspace"), []byte(strings.Repeat("a", maxDisplayNameBytes+1)), 1)},
		{name: "missing client instance", data: removeJSONField(encoded, `"client_instance_id":"`+idClient+`",`)},
		{name: "duplicate top level", data: addTopLevelJSONField(encoded, `"schema":"`+SchemaWorkspaceCreateCommand+`"`)},
		{name: "duplicate nested", data: bytes.Replace(encoded, []byte(`"workspace_id":"`+idWorkspace+`"`), []byte(`"workspace_id":"`+idWorkspace+`","workspace_id":"`+idWorkspace+`"`), 1)},
		{name: "lone surrogate", data: bytes.Replace(encoded, []byte("Proof Workspace"), []byte(`bad\ud800text`), 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, gotErr := DecodeWorkspaceCreateRequest(test.data); gotErr == nil {
				t.Fatal("DecodeWorkspaceCreateRequest() error = nil")
			}
		})
	}
}

func TestSessionStartRequestStrictBoundaryAndNormalization(t *testing.T) {
	t.Parallel()

	request := fixtureSessionStartRequest(t)
	request.Body.Client.Capabilities = []string{"resource_notify.v1", "context_delta.v1"}
	encoded := mustMarshal(t, request)
	decoded, err := DecodeSessionStartRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSessionStartRequest() error = %v", err)
	}
	values, err := decoded.Values()
	if err != nil {
		t.Fatalf("Values() error = %v", err)
	}
	if got, want := values.Capabilities, []string{"context_delta.v1", "resource_notify.v1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Capabilities = %#v, want %#v", got, want)
	}

	tests := []struct {
		name string
		edit func(SessionStartRequestDTO) SessionStartRequestDTO
	}{
		{name: "required actor", edit: func(value SessionStartRequestDTO) SessionStartRequestDTO {
			value.Body.ActorID = domain.ActorID{}
			return value
		}},
		{name: "paired device revision", edit: func(value SessionStartRequestDTO) SessionStartRequestDTO {
			value.ExpectedVersions.Device = nil
			return value
		}},
		{name: "duplicate grant", edit: func(value SessionStartRequestDTO) SessionStartRequestDTO {
			value.ExpectedVersions.Grants = append(value.ExpectedVersions.Grants, value.ExpectedVersions.Grants[0])
			return value
		}},
		{name: "unsorted grants", edit: func(value SessionStartRequestDTO) SessionStartRequestDTO {
			value.ExpectedVersions.Grants = []GrantRevisionDTO{
				{GrantID: mustParseGrantID(t, idGrant), Version: domain.InitialVersion()},
				{GrantID: mustParseGrantID(t, idInvitation), Version: domain.InitialVersion()},
			}
			return value
		}},
		{name: "duplicate capability", edit: func(value SessionStartRequestDTO) SessionStartRequestDTO {
			value.Body.Client.Capabilities = []string{"context_delta.v1", "context_delta.v1"}
			return value
		}},
		{name: "bad client version", edit: func(value SessionStartRequestDTO) SessionStartRequestDTO {
			value.Body.Client.Version = "bad version"
			return value
		}},
		{name: "zero causation", edit: func(value SessionStartRequestDTO) SessionStartRequestDTO {
			value.CausationID = &domain.EventID{}
			return value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, gotErr := test.edit(request).Values(); gotErr == nil {
				t.Fatal("Values() error = nil")
			}
		})
	}

	unknown := addTopLevelJSONField(encoded, `"unexpected":{}`)
	if _, err := DecodeSessionStartRequest(unknown); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("unknown field error = %v, want ErrInvalidJSON", err)
	}
	wrongKind := bytes.Replace(encoded, []byte(`"actor_session_id":"`+idSession+`"`), []byte(`"actor_session_id":{}`), 1)
	if _, err := DecodeSessionStartRequest(wrongKind); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("wrong kind error = %v, want ErrInvalidJSON", err)
	}
}

func TestWireIdentifierFieldsRetainConcreteDomainTypes(t *testing.T) {
	t.Parallel()

	workspaceType := reflect.TypeFor[domain.WorkspaceID]()
	principalType := reflect.TypeFor[domain.PrincipalID]()
	actorType := reflect.TypeFor[domain.ActorID]()
	if workspaceType == principalType || workspaceType == actorType || principalType == actorType {
		t.Fatal("concrete domain identifier types unexpectedly collapse")
	}

	workspaceField, ok := reflect.TypeFor[WorkspaceCreateBodyDTO]().FieldByName("WorkspaceID")
	if !ok || workspaceField.Type != workspaceType {
		t.Fatalf("WorkspaceID field type = %v, want %v", workspaceField.Type, workspaceType)
	}
	principalField, ok := reflect.TypeFor[WorkspaceCreateBodyDTO]().FieldByName("OwnerPrincipalID")
	if !ok || principalField.Type != principalType {
		t.Fatalf("OwnerPrincipalID field type = %v, want %v", principalField.Type, principalType)
	}
	actorField, ok := reflect.TypeFor[SessionStartBodyDTO]().FieldByName("ActorID")
	if !ok || actorField.Type != actorType {
		t.Fatalf("ActorID field type = %v, want %v", actorField.Type, actorType)
	}
}

func TestInstallationBootstrapRequestJSONFieldStability(t *testing.T) {
	t.Parallel()

	encoded := string(mustMarshal(t, fixtureInstallationBootstrapRequest(t)))
	want := `{"schema":"blackbird.command.installation_bootstrap/1","request_id":"req-bootstrap-1","command_id":"` + idCommand + `","operation":"installation.bootstrap.v1","idempotency_key":"bootstrap-key-1","authority_id":"` + idAuthority + `","authority_epoch":"` + idEpoch + `","deadline":"2026-08-04T12:01:00Z","correlation_id":"` + idCorrelation + `","expected_versions":{"invitation":1},"body":{"installation_id":"` + idInstallation + `","invitation_id":"` + idInvitation + `","principal":{"principal_id":"` + idPrincipal + `","kind":"human","display_name":"Alice"},"device":{"device_id":"` + idDevice + `","display_name":"Alice Cockpit","public_key_spki":"ZWQyNTUxOS1zcGtp"},"installation_owner_grant_id":"` + idGrant + `","pairing":{"protocol":"blackbird.pair/v1","transcript_hash":"` + strings.Repeat("a", 64) + `"}}}`
	if encoded != want {
		t.Fatalf("JSON changed\n got: %s\nwant: %s", encoded, want)
	}
}

func fixtureInstallationBootstrapRequest(t *testing.T) InstallationBootstrapRequestDTO {
	t.Helper()
	return InstallationBootstrapRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaInstallationBootstrapCommand, OperationInstallationBootstrap, "req-bootstrap-1", "bootstrap-key-1"),
		ExpectedVersions:   InstallationBootstrapExpectedVersionsDTO{Invitation: domain.InitialVersion()},
		Body: InstallationBootstrapBodyDTO{
			InstallationID: mustParseInstallationID(t, idInstallation),
			InvitationID:   mustParseInvitationID(t, idInvitation),
			Principal: BootstrapPrincipalDTO{
				PrincipalID: mustParsePrincipalID(t, idPrincipal),
				Kind:        PrincipalKindHuman,
				DisplayName: "Alice",
			},
			Device: BootstrapDeviceDTO{
				DeviceID:      mustParseDeviceID(t, idDevice),
				DisplayName:   "Alice Cockpit",
				PublicKeySPKI: "ZWQyNTUxOS1zcGtp",
			},
			InstallationOwnerGrantID: mustParseGrantID(t, idGrant),
			Pairing:                  ApprovedPairingTranscriptRefDTO{Protocol: PairingProtocolV1, TranscriptHash: strings.Repeat("a", 64)},
		},
	}
}

func fixtureWorkspaceCreateRequest(t *testing.T) WorkspaceCreateRequestDTO {
	t.Helper()
	return WorkspaceCreateRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaWorkspaceCreateCommand, OperationWorkspaceCreate, "req-workspace-1", "workspace-key-1"),
		ClientInstanceID:   mustParseClientInstanceID(t, idClient),
		ExpectedVersions:   WorkspaceCreateExpectedVersionsDTO{OwnerPrincipal: domain.InitialVersion()},
		Body: WorkspaceCreateBodyDTO{
			InstallationID:    mustParseInstallationID(t, idInstallation),
			WorkspaceID:       mustParseWorkspaceID(t, idWorkspace),
			OwnerPrincipalID:  mustParsePrincipalID(t, idPrincipal),
			OwnerMembershipID: mustParseMembershipID(t, idMembership),
			Alias:             "Proof Workspace",
			DiscoveryLocator:  "/proof/workspace",
			PolicyRevision:    "policy-w0.2",
		},
	}
}

func fixtureSessionStartRequest(t *testing.T) SessionStartRequestDTO {
	t.Helper()
	device := mustParseDeviceID(t, idDevice)
	deviceVersion := domain.InitialVersion()
	return SessionStartRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaSessionStartCommand, OperationSessionStart, "req-session-1", "session-key-1"),
		ExpectedVersions: SessionStartExpectedVersionsDTO{
			Membership: domain.InitialVersion(),
			Delegation: domain.InitialVersion(),
			Device:     &deviceVersion,
			Grants:     []GrantRevisionDTO{{GrantID: mustParseGrantID(t, idGrant), Version: domain.InitialVersion()}},
		},
		Body: SessionStartBodyDTO{
			WorkspaceID:    mustParseWorkspaceID(t, idWorkspace),
			ActorSessionID: mustParseActorSessionID(t, idSession),
			ActorID:        mustParseActorID(t, idActor),
			MembershipID:   mustParseMembershipID(t, idMembership),
			DelegationID:   mustParseActorDelegationID(t, idDelegation),
			DeviceID:       &device,
			Client: SessionClientDTO{
				InstanceID:   mustParseClientInstanceID(t, idClient),
				Name:         "phux-runner",
				Version:      "1.0.0",
				Capabilities: []string{"context_delta.v1", "resource_notify.v1"},
			},
		},
	}
}

func fixtureMetadata(t *testing.T, schema, operation, requestID, key string) CommandMetadataDTO {
	t.Helper()
	correlation := mustParseCorrelationID(t, idCorrelation)
	return CommandMetadataDTO{
		Schema:         schema,
		RequestID:      requestID,
		CommandID:      mustParseCommandID(t, idCommand),
		Operation:      operation,
		IdempotencyKey: key,
		AuthorityID:    mustParseAuthorityID(t, idAuthority),
		AuthorityEpoch: mustParseAuthorityEpoch(t, idEpoch),
		Deadline:       time.Date(2026, 8, 4, 12, 1, 0, 0, time.UTC),
		CorrelationID:  correlation,
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return encoded
}

func removeJSONField(data []byte, exact string) []byte {
	return []byte(strings.Replace(string(data), exact, "", 1))
}

func addTopLevelJSONField(data []byte, field string) []byte {
	result := append([]byte(nil), data[:len(data)-1]...)
	result = append(result, ',')
	result = append(result, field...)
	return append(result, '}')
}

func mustParseInstallationID(t *testing.T, value string) domain.InstallationID {
	t.Helper()
	id, err := domain.ParseInstallationID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseInvitationID(t *testing.T, value string) domain.InvitationID {
	t.Helper()
	id, err := domain.ParseInvitationID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParsePrincipalID(t *testing.T, value string) domain.PrincipalID {
	t.Helper()
	id, err := domain.ParsePrincipalID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseDeviceID(t *testing.T, value string) domain.DeviceID {
	t.Helper()
	id, err := domain.ParseDeviceID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseGrantID(t *testing.T, value string) domain.GrantID {
	t.Helper()
	id, err := domain.ParseGrantID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseWorkspaceID(t *testing.T, value string) domain.WorkspaceID {
	t.Helper()
	id, err := domain.ParseWorkspaceID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseMembershipID(t *testing.T, value string) domain.MembershipID {
	t.Helper()
	id, err := domain.ParseMembershipID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseActorID(t *testing.T, value string) domain.ActorID {
	t.Helper()
	id, err := domain.ParseActorID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseActorDelegationID(t *testing.T, value string) domain.ActorDelegationID {
	t.Helper()
	id, err := domain.ParseActorDelegationID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseActorSessionID(t *testing.T, value string) domain.ActorSessionID {
	t.Helper()
	id, err := domain.ParseActorSessionID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseAuthorityID(t *testing.T, value string) domain.AuthorityID {
	t.Helper()
	id, err := domain.ParseAuthorityID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseAuthorityEpoch(t *testing.T, value string) domain.AuthorityEpoch {
	t.Helper()
	id, err := domain.ParseAuthorityEpoch(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseCommandID(t *testing.T, value string) domain.CommandID {
	t.Helper()
	id, err := domain.ParseCommandID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseCorrelationID(t *testing.T, value string) domain.CorrelationID {
	t.Helper()
	id, err := domain.ParseCorrelationID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseClientInstanceID(t *testing.T, value string) domain.ClientInstanceID {
	t.Helper()
	id, err := domain.ParseClientInstanceID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func mustParseEventID(t *testing.T, value string) domain.EventID {
	t.Helper()
	id, err := domain.ParseEventID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
