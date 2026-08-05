package contracts

import (
	"bytes"
	"crypto/sha256"
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

func TestAuthenticationEvidenceIsSealedTypedAndComplete(t *testing.T) {
	t.Parallel()
	principal := mustParsePrincipalID(t, idPrincipal)
	device := mustParseDeviceID(t, idDevice)
	session := mustParseActorSessionID(t, idSession)
	authority := mustParseAuthorityID(t, idAuthority)
	binding, err := NewChannelBindingDigest(strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("NewChannelBindingDigest() error = %v", err)
	}
	audience, err := NewAuthenticationAudience("blackbird-product-api")
	if err != nil {
		t.Fatalf("NewAuthenticationAudience() error = %v", err)
	}
	envelopeID := "federation-envelope/v1"
	provenance, err := NewAuthenticationAuditProvenance(authority, &envelopeID)
	if err != nil {
		t.Fatalf("NewAuthenticationAuditProvenance() error = %v", err)
	}
	principalRevision, _ := domain.NewVersion(2)
	deviceRevision, _ := domain.NewVersion(3)
	trustRevision, _ := domain.NewVersion(4)
	revocationRevision, _ := domain.NewVersion(5)
	sessionRevision, _ := domain.NewVersion(6)
	credentialFingerprint, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("public credential identity")))
	grantOne, _ := domain.NewAggregateRef(mustParseGrantID(t, idGrant), domain.InitialVersion())
	grantTwo, _ := domain.NewAggregateRef(mustParseGrantID(t, idInvitation), principalRevision)
	inputGrants := []domain.AggregateRef{grantOne, grantTwo}
	verifiedAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	evidence, err := NewAuthenticationEvidence(AuthenticationEvidenceParams{
		PrincipalID: principal, PrincipalRevision: principalRevision,
		DeviceID: &device, DeviceRevision: deviceRevision, DeviceTrustRevision: trustRevision,
		DeviceRevocationRevision: revocationRevision, CredentialFingerprint: credentialFingerprint,
		ActorSessionID: &session, ActorSessionRevision: sessionRevision, GrantRevisions: inputGrants,
		ChannelBinding: binding, Audience: audience, AuditProvenance: provenance, VerifiedAt: verifiedAt,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationEvidence() error = %v", err)
	}
	inputGrants[0] = domain.AggregateRef{}
	gotDevice, hasDevice := evidence.DeviceID()
	gotDeviceRevision, hasDeviceRevision := evidence.DeviceRevision()
	gotTrustRevision, hasTrustRevision := evidence.DeviceTrustRevision()
	gotRevocationRevision, hasRevocationRevision := evidence.DeviceRevocationRevision()
	gotFingerprint, hasFingerprint := evidence.CredentialFingerprint()
	gotSession, hasSession := evidence.ActorSessionID()
	gotSessionRevision, hasSessionRevision := evidence.ActorSessionRevision()
	gotEnvelope, hasEnvelope := evidence.AuditProvenance().FederationEnvelopeID()
	if !evidence.Valid() || evidence.PrincipalID() != principal || !hasDevice || gotDevice != device ||
		evidence.PrincipalRevision() != principalRevision || !hasDeviceRevision || gotDeviceRevision != deviceRevision ||
		!hasTrustRevision || gotTrustRevision != trustRevision || !hasRevocationRevision || gotRevocationRevision != revocationRevision ||
		!hasFingerprint || gotFingerprint != credentialFingerprint || !hasSession || gotSession != session ||
		!hasSessionRevision || gotSessionRevision != sessionRevision || evidence.ChannelBindingDigest() != binding ||
		evidence.Audience() != audience || evidence.AuditProvenance().SourceAuthorityID() != authority ||
		!hasEnvelope || gotEnvelope != envelopeID || evidence.VerifiedAt() != verifiedAt {
		t.Fatalf("authentication evidence accessors lost trusted values: %#v", evidence)
	}
	wantGrants := []domain.AggregateRef{grantTwo, grantOne}
	if grants := evidence.GrantRevisions(); !reflect.DeepEqual(grants, wantGrants) {
		t.Fatalf("GrantRevisions() = %#v, want canonical %#v", grants, wantGrants)
	} else {
		grants[0] = domain.AggregateRef{}
		if !reflect.DeepEqual(evidence.GrantRevisions(), wantGrants) {
			t.Fatal("GrantRevisions() exposed mutable evidence storage")
		}
	}
	if (AuthenticationEvidence{}).Valid() {
		t.Fatal("zero AuthenticationEvidence is valid")
	}
}

func TestAuthenticationEvidenceConstructorsRejectInvalidValues(t *testing.T) {
	t.Parallel()
	principal := mustParsePrincipalID(t, idPrincipal)
	authority := mustParseAuthorityID(t, idAuthority)
	binding, _ := NewChannelBindingDigest(strings.Repeat("a", 64))
	audience, _ := NewAuthenticationAudience("blackbird-product-api")
	provenance, _ := NewAuthenticationAuditProvenance(authority, nil)
	verifiedAt := time.Now().Add(-time.Minute)
	valid := AuthenticationEvidenceParams{
		PrincipalID: principal, PrincipalRevision: domain.InitialVersion(), ChannelBinding: binding,
		Audience: audience, AuditProvenance: provenance, VerifiedAt: verifiedAt,
	}

	if _, err := NewChannelBindingDigest(strings.Repeat("A", 64)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("uppercase channel binding error = %v, want ErrInvalidContract", err)
	}
	if _, err := NewChannelBindingDigest(strings.Repeat("0", 64)); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("zero channel binding error = %v, want ErrInvalidContract", err)
	}
	if _, err := NewAuthenticationAudience(" bearer-secret "); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("invalid audience error = %v, want ErrInvalidContract", err)
	}
	if _, err := NewAuthenticationAuditProvenance(domain.AuthorityID{}, nil); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("zero authority error = %v, want ErrInvalidContract", err)
	}

	tests := []struct {
		name string
		edit func(*AuthenticationEvidenceParams)
	}{
		{name: "zero principal", edit: func(params *AuthenticationEvidenceParams) { params.PrincipalID = domain.PrincipalID{} }},
		{name: "zero principal revision", edit: func(params *AuthenticationEvidenceParams) { params.PrincipalRevision = domain.Version{} }},
		{name: "zero verified at", edit: func(params *AuthenticationEvidenceParams) { params.VerifiedAt = time.Time{} }},
		{name: "device facts without device", edit: func(params *AuthenticationEvidenceParams) { params.DeviceRevision = domain.InitialVersion() }},
		{name: "session revision without session", edit: func(params *AuthenticationEvidenceParams) { params.ActorSessionRevision = domain.InitialVersion() }},
		{name: "zero grant", edit: func(params *AuthenticationEvidenceParams) { params.GrantRevisions = []domain.AggregateRef{{}} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := valid
			test.edit(&params)
			if _, err := NewAuthenticationEvidence(params); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("error = %v, want ErrInvalidContract", err)
			}
		})
	}
}

func TestAuthenticationEvidenceRejectsInconsistentOptionalAndGrantEvidence(t *testing.T) {
	t.Parallel()
	principal := mustParsePrincipalID(t, idPrincipal)
	device := mustParseDeviceID(t, idDevice)
	session := mustParseActorSessionID(t, idSession)
	authority := mustParseAuthorityID(t, idAuthority)
	binding, _ := NewChannelBindingDigest(strings.Repeat("c", 64))
	audience, _ := NewAuthenticationAudience("blackbird-product-api")
	provenance, _ := NewAuthenticationAuditProvenance(authority, nil)
	fingerprint, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("credential fingerprint")))
	grant, _ := domain.NewAggregateRef(mustParseGrantID(t, idGrant), domain.InitialVersion())
	crossKind, _ := domain.NewAggregateRef(principal, domain.InitialVersion())
	base := AuthenticationEvidenceParams{
		PrincipalID: principal, PrincipalRevision: domain.InitialVersion(), DeviceID: &device,
		DeviceRevision: domain.InitialVersion(), DeviceTrustRevision: domain.InitialVersion(),
		DeviceRevocationRevision: domain.InitialVersion(), CredentialFingerprint: fingerprint,
		ActorSessionID: &session, ActorSessionRevision: domain.InitialVersion(), GrantRevisions: []domain.AggregateRef{grant},
		ChannelBinding: binding, Audience: audience, AuditProvenance: provenance, VerifiedAt: time.Now().Add(-time.Minute),
	}
	tests := []struct {
		name string
		edit func(*AuthenticationEvidenceParams)
	}{
		{name: "zero device", edit: func(params *AuthenticationEvidenceParams) { params.DeviceID = &domain.DeviceID{} }},
		{name: "missing device revision", edit: func(params *AuthenticationEvidenceParams) { params.DeviceRevision = domain.Version{} }},
		{name: "missing trust revision", edit: func(params *AuthenticationEvidenceParams) { params.DeviceTrustRevision = domain.Version{} }},
		{name: "missing revocation revision", edit: func(params *AuthenticationEvidenceParams) { params.DeviceRevocationRevision = domain.Version{} }},
		{name: "missing credential fingerprint", edit: func(params *AuthenticationEvidenceParams) { params.CredentialFingerprint = domain.CredentialDigest{} }},
		{name: "zero actor session", edit: func(params *AuthenticationEvidenceParams) { params.ActorSessionID = &domain.ActorSessionID{} }},
		{name: "missing actor session revision", edit: func(params *AuthenticationEvidenceParams) { params.ActorSessionRevision = domain.Version{} }},
		{name: "duplicate grant", edit: func(params *AuthenticationEvidenceParams) {
			params.GrantRevisions = []domain.AggregateRef{grant, grant}
		}},
		{name: "cross-kind grant", edit: func(params *AuthenticationEvidenceParams) { params.GrantRevisions = []domain.AggregateRef{crossKind} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := base
			test.edit(&params)
			if _, err := NewAuthenticationEvidence(params); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("error = %v, want ErrInvalidContract", err)
			}
		})
	}
}

func TestAuthenticationEvidenceValidRejectsForgedInternalState(t *testing.T) {
	t.Parallel()
	principal := mustParsePrincipalID(t, idPrincipal)
	authority := mustParseAuthorityID(t, idAuthority)
	binding, _ := NewChannelBindingDigest(strings.Repeat("d", 64))
	audience, _ := NewAuthenticationAudience("blackbird-product-api")
	provenance, _ := NewAuthenticationAuditProvenance(authority, nil)
	evidence, err := NewAuthenticationEvidence(AuthenticationEvidenceParams{
		PrincipalID: principal, PrincipalRevision: domain.InitialVersion(), ChannelBinding: binding,
		Audience: audience, AuditProvenance: provenance, VerifiedAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	forged := evidence
	forged.hasDevice = true
	if forged.Valid() {
		t.Fatal("forged device presence is valid")
	}
	forged = evidence
	forged.hasActorSession = true
	if forged.Valid() {
		t.Fatal("forged actor-session presence is valid")
	}
	forged = evidence
	forged.verifiedAt = time.Time{}
	if forged.Valid() {
		t.Fatal("forged zero verification timestamp is valid")
	}
}

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

func TestW0OperationInventoryIsClosedAndStable(t *testing.T) {
	t.Parallel()

	want := []string{
		"installation.bootstrap.v1",
		"principal.register.v1",
		"pairing.challenge.issue.v1",
		"pairing.challenge.redeem.v1",
		"workspace.create.v1",
		"workspace_member.invite.v1",
		"workspace_membership.accept.v1",
		"actor.create.v1",
		"actor_delegation.propose.v1",
		"actor_delegation.activate.v1",
		"session.start.v1",
	}
	got := W0OperationInventory()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("W0OperationInventory() = %#v, want %#v", got, want)
	}
	got[0] = "mutated"
	if W0OperationInventory()[0] != want[0] {
		t.Fatal("W0OperationInventory() returned mutable catalog storage")
	}
}

func TestPrincipalRegisterRequestStrictBoundaryAndGolden(t *testing.T) {
	t.Parallel()

	request := PrincipalRegisterRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaPrincipalRegisterCommand, OperationPrincipalRegister, "req-principal-1", "principal-key-1"),
		ClientInstanceID:   mustParseClientInstanceID(t, idClient),
		ExpectedVersions:   PrincipalRegisterExpectedVersionsDTO{Registrar: domain.InitialVersion()},
		Body: PrincipalRegisterBodyDTO{
			InstallationID: mustParseInstallationID(t, idInstallation), RegistrarID: mustParsePrincipalID(t, idPrincipal),
			PrincipalID: mustParsePrincipalID(t, idActor), Kind: PrincipalKindWorkload,
			DisplayName: "Build Agent", PublicKeyReference: "thumbprint:build-agent-1",
		},
	}
	encoded := mustMarshal(t, request)
	if _, err := DecodePrincipalRegisterRequest(encoded); err != nil {
		t.Fatalf("DecodePrincipalRegisterRequest() error = %v", err)
	}
	want := `{"schema":"blackbird.command.principal_register/1","request_id":"req-principal-1","command_id":"` + idCommand + `","operation":"principal.register.v1","idempotency_key":"principal-key-1","authority_id":"` + idAuthority + `","authority_epoch":"` + idEpoch + `","deadline":"2026-08-04T12:01:00Z","causation_id":null,"correlation_id":"` + idCorrelation + `","client_instance_id":"` + idClient + `","expected_versions":{"registrar":1},"body":{"installation_id":"` + idInstallation + `","registrar_id":"` + idPrincipal + `","principal_id":"` + idActor + `","kind":"workload","display_name":"Build Agent","public_key_reference":"thumbprint:build-agent-1"}}`
	if string(encoded) != want {
		t.Fatalf("JSON changed\n got: %s\nwant: %s", encoded, want)
	}
	duplicate := addTopLevelJSONField(encoded, `"operation":"principal.register.v1"`)
	if _, err := DecodePrincipalRegisterRequest(duplicate); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("duplicate error = %v, want ErrInvalidJSON", err)
	}
	additive := addTopLevelJSONField(encoded, `"future":true`)
	if _, err := DecodePrincipalRegisterRequest(additive); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("additive request error = %v, want ErrInvalidJSON", err)
	}
}

func TestInstallationBootstrapRequestJSONFieldStability(t *testing.T) {
	t.Parallel()

	encoded := string(mustMarshal(t, fixtureInstallationBootstrapRequest(t)))
	want := `{"schema":"blackbird.command.installation_bootstrap/1","request_id":"req-bootstrap-1","command_id":"` + idCommand + `","operation":"installation.bootstrap.v1","idempotency_key":"bootstrap-key-1","authority_id":"` + idAuthority + `","authority_epoch":"` + idEpoch + `","deadline":"2026-08-04T12:01:00Z","causation_id":null,"correlation_id":"` + idCorrelation + `","expected_versions":{"invitation":1},"body":{"installation_id":"` + idInstallation + `","invitation_id":"` + idInvitation + `","bootstrap_generation_id":"` + idEventThree + `","principal":{"principal_id":"` + idPrincipal + `","kind":"human","display_name":"Alice"},"device":{"device_id":"` + idDevice + `","display_name":"Alice Cockpit","public_key_spki":"ZWQyNTUxOS1zcGtp"},"installation_owner_grant_id":"` + idGrant + `","owner_capabilities":["workspace:admin"],"pairing":{"protocol":"blackbird.pair/v1","transcript_hash":"` + strings.Repeat("a", 64) + `"}}}`
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
			InstallationID:        mustParseInstallationID(t, idInstallation),
			InvitationID:          mustParseInvitationID(t, idInvitation),
			BootstrapGenerationID: mustParseBootstrapGenerationID(t, idEventThree),
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
			OwnerCapabilities:        []string{"workspace:admin"},
			Pairing:                  ApprovedPairingTranscriptRefDTO{Protocol: PairingProtocolV1, TranscriptHash: strings.Repeat("a", 64)},
		},
	}
}

func fixtureWorkspaceCreateRequest(t *testing.T) WorkspaceCreateRequestDTO {
	t.Helper()
	return WorkspaceCreateRequestDTO{
		CommandMetadataDTO: fixtureMetadata(t, SchemaWorkspaceCreateCommand, OperationWorkspaceCreate, "req-workspace-1", "workspace-key-1"),
		ClientInstanceID:   mustParseClientInstanceID(t, idClient),
		ExpectedVersions: WorkspaceCreateExpectedVersionsDTO{
			OwnerPrincipal: domain.InitialVersion(), InstallationGrant: domain.InitialVersion(),
		},
		Body: WorkspaceCreateBodyDTO{
			InstallationID:      mustParseInstallationID(t, idInstallation),
			WorkspaceID:         mustParseWorkspaceID(t, idWorkspace),
			OwnerPrincipalID:    mustParsePrincipalID(t, idPrincipal),
			InstallationGrantID: mustParseGrantID(t, idGrant),
			OwnerMembershipID:   mustParseMembershipID(t, idMembership),
			Alias:               "Proof Workspace",
			DiscoveryLocator:    "/proof/workspace",
			PolicyRevision:      "policy-w0.2",
			OwnerCapabilities:   []string{"workspace:admin"},
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
			Workspace:   domain.InitialVersion(),
			Principal:   domain.InitialVersion(),
			Membership:  domain.InitialVersion(),
			Actor:       domain.InitialVersion(),
			Delegation:  domain.InitialVersion(),
			Device:      &deviceVersion,
			DeviceTrust: &deviceVersion,
			Grants:      []GrantRevisionDTO{{GrantID: mustParseGrantID(t, idGrant), Version: domain.InitialVersion()}},
		},
		Body: SessionStartBodyDTO{
			WorkspaceID:        mustParseWorkspaceID(t, idWorkspace),
			PrincipalID:        mustParsePrincipalID(t, idPrincipal),
			ActorSessionID:     mustParseActorSessionID(t, idSession),
			ActorID:            mustParseActorID(t, idActor),
			MembershipID:       mustParseMembershipID(t, idMembership),
			DelegationID:       mustParseActorDelegationID(t, idDelegation),
			DeviceID:           &device,
			StartAuthorityKind: "trusted_device",
			AbsoluteExpiry:     fixtureTime.Add(time.Hour),
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
func mustParseBootstrapGenerationID(t *testing.T, value string) domain.BootstrapGenerationID {
	t.Helper()
	id, err := domain.ParseBootstrapGenerationID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
