package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/phall1/blackbird/internal/domain"
)

type allProfileView struct {
	Count    uint64               `json:"count"`
	Label    string               `json:"label"`
	Optional *CanonicalIdentifier `json:"optional"`
}

func (allProfileView) canonicalView()              {}
func (allProfileView) commandHashView()            {}
func (allProfileView) authorizationGuardHashView() {}
func (allProfileView) receiptResultHashView()      {}
func (allProfileView) recoveryCapsuleHashView()    {}
func (allProfileView) commandDenialHashView()      {}
func (allProfileView) bootstrapAttemptHashView()   {}
func (allProfileView) eventSemanticHashView()      {}
func (allProfileView) streamGenesisHashView()      {}
func (allProfileView) auditEntryHashView()         {}

type paddedReceiptView struct {
	Padding string `json:"padding"`
}

func (paddedReceiptView) canonicalView()         {}
func (paddedReceiptView) receiptResultHashView() {}

type paddedCapsuleView struct {
	Padding string `json:"padding"`
}

func (paddedCapsuleView) canonicalView()           {}
func (paddedCapsuleView) recoveryCapsuleHashView() {}

type omittedCommandView struct {
	Optional *string `json:"optional,omitempty"`
}

func (omittedCommandView) canonicalView()   {}
func (omittedCommandView) commandHashView() {}

type interfaceCommandView struct {
	Value any `json:"value"`
}

func (interfaceCommandView) canonicalView()   {}
func (interfaceCommandView) commandHashView() {}

type floatCommandView struct {
	Value float64 `json:"value"`
}

func (floatCommandView) canonicalView()   {}
func (floatCommandView) commandHashView() {}

type byteCommandView struct {
	Value []byte `json:"value"`
}

func (byteCommandView) canonicalView()   {}
func (byteCommandView) commandHashView() {}

type signedCommandView struct {
	Value int64 `json:"value"`
}

func (signedCommandView) canonicalView()   {}
func (signedCommandView) commandHashView() {}

type mapCommandView map[string]any

func (mapCommandView) canonicalView()   {}
func (mapCommandView) commandHashView() {}

type permissiveEventVerifier struct{}

func (permissiveEventVerifier) VerifyEventDigests(domain.EventEnvelope) error { return nil }

func TestRFC8785MatchesOfficialVectorAndBlackbirdRejectsUnsafeInteger(t *testing.T) {
	t.Parallel()

	// RFC 8785 section 3.2.2, also retained by the RFC editor's reference
	// implementation. This covers ECMAScript number serialization, control
	// escaping, Unicode emission, literal spelling, and property sorting.
	input := []byte(`{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`)
	expected := []byte(`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`)

	canonical, err := jcs.Transform(input)
	if err != nil {
		t.Fatalf("RFC 8785 official vector: %v", err)
	}
	if !bytes.Equal(canonical, expected) {
		t.Fatalf("official vector mismatch:\n got %s\nwant %s", canonical, expected)
	}
	if _, err = canonicalizeStrict(input, MaxCanonicalJSONBytes, MaxCanonicalJSONDepth); !errors.Is(err, ErrCanonicalNumber) {
		t.Fatalf("Blackbird unsafe-integer error = %v", err)
	}
}

func TestCanonicalizeStrictMatchesUpstreamAndIndependentVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "gowebpki upstream structures",
			input: `{
  "1": {"f": {"f": "hi","F": 5} ,"\n": 56.0},
  "10": { }, "": "empty", "a": { },
  "111": [ {"e": "yes","E": "no" } ], "A": { }
}`,
			expected: `{"":"empty","1":{"\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}`,
		},
		{
			name:     "independent ECMAScript UTF-16 ordering oracle",
			input:    `{"é":1,"😀":3,"aa":4,"\u0061":2}`,
			expected: `{"a":2,"aa":4,"é":1,"😀":3}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			canonical, err := canonicalizeStrict(
				[]byte(test.input), MaxCanonicalJSONBytes, MaxCanonicalJSONDepth,
			)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(canonical) != test.expected {
				t.Fatalf("got %s, want %s", canonical, test.expected)
			}
		})
	}
}

func TestStrictJSONRejectsAmbiguousOrInvalidInputs(t *testing.T) {
	t.Parallel()

	tooDeep := strings.Repeat("[", MaxCanonicalJSONDepth+1) + "0" +
		strings.Repeat("]", MaxCanonicalJSONDepth+1)
	tests := []struct {
		name  string
		input []byte
		want  error
	}{
		{name: "duplicate key", input: []byte(`{"a":1,"a":2}`), want: ErrCanonicalJSON},
		{name: "escaped duplicate key", input: []byte(`{"a":1,"\u0061":2}`), want: ErrCanonicalJSON},
		{name: "invalid UTF-8", input: []byte{'{', '"', 0xff, '"', ':', '1', '}'}, want: ErrCanonicalJSON},
		{name: "unpaired high surrogate", input: []byte(`{"a":"\ud800"}`), want: ErrCanonicalJSON},
		{name: "unpaired low surrogate", input: []byte(`{"a":"\udc00"}`), want: ErrCanonicalJSON},
		{name: "reversed surrogate pair", input: []byte(`{"a":"\udc00\ud800"}`), want: ErrCanonicalJSON},
		{name: "trailing value", input: []byte(`{"a":1} {"b":2}`), want: ErrCanonicalJSON},
		{name: "unsafe integer", input: []byte(`{"a":9007199254740992}`), want: ErrCanonicalNumber},
		{name: "negative unsafe integer", input: []byte(`{"a":-9007199254740992}`), want: ErrCanonicalNumber},
		{name: "unsafe exponent integer", input: []byte(`{"a":1e21}`), want: ErrCanonicalNumber},
		{name: "non-finite exponent", input: []byte(`{"a":1e999}`), want: ErrCanonicalNumber},
		{name: "excessive depth", input: []byte(tooDeep), want: ErrCanonicalLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := canonicalizeStrict(test.input, MaxCanonicalJSONBytes, MaxCanonicalJSONDepth)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestStrictJSONDepthAndSizeBoundaries(t *testing.T) {
	t.Parallel()

	atDepth := strings.Repeat("[", MaxCanonicalJSONDepth) + "0" + strings.Repeat("]", MaxCanonicalJSONDepth)
	if _, err := canonicalizeStrict([]byte(atDepth), MaxCanonicalJSONBytes, MaxCanonicalJSONDepth); err != nil {
		t.Fatalf("exact depth: %v", err)
	}

	base := `{"padding":""}`
	exact := `{"padding":"` + strings.Repeat("x", MaxCanonicalJSONBytes-len(base)) + `"}`
	if len(exact) != MaxCanonicalJSONBytes {
		t.Fatalf("test fixture is %d bytes", len(exact))
	}
	if _, err := canonicalizeStrict([]byte(exact), MaxCanonicalJSONBytes, MaxCanonicalJSONDepth); err != nil {
		t.Fatalf("exact size: %v", err)
	}
	if _, err := canonicalizeStrict(append([]byte(exact), ' '), MaxCanonicalJSONBytes, MaxCanonicalJSONDepth); !errors.Is(err, ErrCanonicalLimit) {
		t.Fatalf("plus one got %v", err)
	}
}

func TestTypedHashViewSchemaRejectsUnreviewedShapes(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	tests := []struct {
		name string
		view CommandHashView
	}{
		{name: "map", view: mapCommandView{"value": 1}},
		{name: "interface", view: interfaceCommandView{Value: "x"}},
		{name: "omitempty", view: omittedCommandView{}},
		{name: "float", view: floatCommandView{Value: 1.25}},
		{name: "bytes", view: byteCommandView{Value: []byte("x")}},
		{name: "signed integer", view: signedCommandView{Value: 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := codec.HashCommand(test.view); !errors.Is(err, ErrCanonicalSchema) {
				t.Fatalf("got %v, want schema rejection", err)
			}
		})
	}
}

func TestTypedViewUsesExplicitNullAndSafeIntegerBound(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	canonical, err := codec.EncodeCanonical(allProfileView{
		Count: MaxCanonicalInteger,
		Label: "safe",
	})
	if err != nil {
		t.Fatalf("encode maximum: %v", err)
	}
	want := `{"count":9007199254740991,"label":"safe","optional":null}`
	if string(canonical) != want {
		t.Fatalf("got %s, want %s", canonical, want)
	}
	if _, err := codec.EncodeCanonical(allProfileView{Count: MaxCanonicalInteger + 1, Label: "unsafe"}); !errors.Is(err, ErrCanonicalNumber) {
		t.Fatalf("above maximum got %v", err)
	}
}

func TestProfileByteLimitsAndSealedDocuments(t *testing.T) {
	t.Parallel()

	for _, size := range []int{MaxReceiptResultBytes - 1, MaxReceiptResultBytes} {
		view := paddedReceiptView{Padding: strings.Repeat("x", size-len(`{"padding":""}`))}
		document, err := newCanonicalDocument(receiptResultDomain, view, MaxReceiptResultBytes)
		if err != nil {
			t.Fatalf("receipt size %d: %v", size, err)
		}
		if len(document.canonicalBytes()) != size || document.isZero() || document.digest.IsZero() {
			t.Fatalf("invalid sealed receipt at size %d", size)
		}
		returned := document.canonicalBytes()
		returned[0] = '['
		if document.canonicalBytes()[0] != '{' {
			t.Fatal("sealed receipt exposed mutable canonical bytes")
		}
	}
	overReceipt := paddedReceiptView{
		Padding: strings.Repeat("x", MaxReceiptResultBytes+1-len(`{"padding":""}`)),
	}
	if _, err := newCanonicalDocument(receiptResultDomain, overReceipt, MaxReceiptResultBytes); !errors.Is(err, ErrCanonicalLimit) {
		t.Fatalf("oversize receipt got %v", err)
	}

	for _, size := range []int{MaxRecoveryCapsuleBytes - 1, MaxRecoveryCapsuleBytes} {
		view := paddedCapsuleView{Padding: strings.Repeat("x", size-len(`{"padding":""}`))}
		document, err := newCanonicalDocument(recoveryCapsuleDomain, view, MaxRecoveryCapsuleBytes)
		if err != nil {
			t.Fatalf("capsule size %d: %v", size, err)
		}
		if len(document.canonicalBytes()) != size || document.isZero() || document.digest.IsZero() {
			t.Fatalf("invalid sealed capsule at size %d", size)
		}
	}
	overCapsule := paddedCapsuleView{
		Padding: strings.Repeat("x", MaxRecoveryCapsuleBytes+1-len(`{"padding":""}`)),
	}
	if _, err := newCanonicalDocument(recoveryCapsuleDomain, overCapsule, MaxRecoveryCapsuleBytes); !errors.Is(err, ErrCanonicalLimit) {
		t.Fatalf("oversize capsule got %v", err)
	}
}

func TestCanonicalScalarValidationAndTimestampNormalization(t *testing.T) {
	t.Parallel()

	if _, err := NewCanonicalIdentifier("019ABCDE"); !errors.Is(err, ErrCanonicalIdentifier) {
		t.Fatalf("uppercase ID got %v", err)
	}
	if _, err := NewCanonicalIdentifier("-bad"); !errors.Is(err, ErrCanonicalIdentifier) {
		t.Fatalf("leading punctuation got %v", err)
	}
	if _, err := NewCanonicalDigest(strings.Repeat("A", 64)); !errors.Is(err, ErrCanonicalIdentifier) {
		t.Fatalf("uppercase digest got %v", err)
	}
	if _, err := NewCanonicalDigest(strings.Repeat("0", 64)); !errors.Is(err, ErrCanonicalIdentifier) {
		t.Fatalf("zero digest got %v", err)
	}

	instant, err := ParseCanonicalInstant("2026-08-04T08:00:00.123-04:00")
	if err != nil {
		t.Fatalf("parse offset instant: %v", err)
	}
	if instant.String() != "2026-08-04T12:00:00.123000Z" {
		t.Fatalf("got %q", instant.String())
	}
	if _, err := NewCanonicalInstant(time.Date(2026, 8, 4, 12, 0, 0, 123_000_001, time.UTC)); !errors.Is(err, ErrCanonicalInstant) {
		t.Fatalf("sub-microsecond instant got %v", err)
	}
	boundaryZone := time.FixedZone("boundary", 14*60*60)
	if _, err := NewCanonicalInstant(time.Date(1, 1, 1, 1, 0, 0, 0, boundaryZone)); !errors.Is(err, ErrCanonicalInstant) {
		t.Fatalf("UTC year-zero normalization got %v", err)
	}
}

func TestW0CommandHashViewsGoldensMutationsAndExclusions(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	id := func(index int) CanonicalIdentifier { return mustCanonicalID(t, codecUUID(index)) }
	digest := func(character byte) CanonicalDigest { return mustCanonicalDigest(t, character) }
	instant, _ := ParseCanonicalInstant("2026-08-05T12:30:00.123000Z")
	resource := func(index int) CommandExpectedResource {
		return CommandExpectedResource{ID: id(index), ExpectedVersion: uint64(index)}
	}
	ceremony := func(index int, character byte) CommandCeremony {
		return CommandCeremony{ID: id(index), ExpiresAt: instant, ProofDigest: digest(character)}
	}
	context := func(kind StreamScopeKind) W0CommandHashContextParams {
		return W0CommandHashContextParams{
			ScopeKind: kind, ScopeID: id(1), PrincipalID: id(2), ClientInstanceID: id(3),
			CorrelationID: id(4), CausationEventID: id(5),
			ProtocolCapabilities: []string{"batch-v1", "receipts-v1"},
		}
	}

	tests := []struct {
		name       string
		view       CommandHashView
		mutated    CommandHashView
		wantDigest string
	}{
		{
			name: "bootstrap installation",
			view: mustCommandHashView(NewBootstrapInstallationCommandHashView(context(StreamScopeInstallation), BootstrapInstallationCommandHashParams{
				InstallationID: id(1), Invitation: resource(6), BootstrapGenerationID: id(7), ApprovedTranscript: digest('1'),
				PrincipalID: id(2), PrincipalDisplayName: "Alice", DeviceID: id(8), DeviceDisplayName: "Alice phone",
				DevicePublicKeyReference: "key://device/8", DeviceSPKIFingerprint: digest('2'), OwnerGrantID: id(9),
				OwnerGrantCapabilities: []string{"identity_admin", "installation_owner"},
			})),
			mutated: mustCommandHashView(NewBootstrapInstallationCommandHashView(context(StreamScopeInstallation), BootstrapInstallationCommandHashParams{
				InstallationID: id(1), Invitation: resource(6), BootstrapGenerationID: id(7), ApprovedTranscript: digest('1'),
				PrincipalID: id(2), PrincipalDisplayName: "Alice changed", DeviceID: id(8), DeviceDisplayName: "Alice phone",
				DevicePublicKeyReference: "key://device/8", DeviceSPKIFingerprint: digest('2'), OwnerGrantID: id(9),
				OwnerGrantCapabilities: []string{"identity_admin", "installation_owner"},
			})),
			wantDigest: "eb415e8c43d95c283b157e13efd0ed3da52ebf6203ec1688e3d52a775e349cfc",
		},
		{
			name: "register principal",
			view: mustCommandHashView(NewRegisterPrincipalCommandHashView(context(StreamScopeInstallation), RegisterPrincipalCommandHashParams{
				Registrar: resource(2), PrincipalID: id(10), Kind: string(domain.PrincipalKindService),
				DisplayName: "Indexer", PublicKeyReference: "key://principal/10",
			})),
			mutated: mustCommandHashView(NewRegisterPrincipalCommandHashView(context(StreamScopeInstallation), RegisterPrincipalCommandHashParams{
				Registrar: resource(2), PrincipalID: id(11), Kind: string(domain.PrincipalKindService),
				DisplayName: "Indexer", PublicKeyReference: "key://principal/10",
			})),
			wantDigest: "c2fed84f6ba41bfb6958515e8cda965f276a5a9008d12504bb620664255d7cc3",
		},
		{
			name: "create workspace",
			view: mustCommandHashView(NewCreateWorkspaceCommandHashView(context(StreamScopeWorkspace), CreateWorkspaceCommandHashParams{
				Owner: resource(2), InstallationGrant: resource(12), WorkspaceID: id(1), Alias: "acme",
				DiscoveryLocator: "blackbird://workspace/acme", OwnerMembershipID: id(13),
				OwnerCapabilities: []string{"actor_admin", "workspace_owner"},
			})),
			mutated: mustCommandHashView(NewCreateWorkspaceCommandHashView(context(StreamScopeWorkspace), CreateWorkspaceCommandHashParams{
				Owner: resource(2), InstallationGrant: resource(12), WorkspaceID: id(1), Alias: "acme-2",
				DiscoveryLocator: "blackbird://workspace/acme", OwnerMembershipID: id(13),
				OwnerCapabilities: []string{"actor_admin", "workspace_owner"},
			})),
			wantDigest: "96dea4406a20515186398c4286322f4c2f48dbe1a6a7a9cca78c9d41be8290fb",
		},
		{
			name: "invite workspace member",
			view: mustCommandHashView(NewInviteWorkspaceMemberCommandHashView(context(StreamScopeWorkspace), InviteWorkspaceMemberCommandHashParams{
				Administrator: resource(2), Workspace: resource(1), Principal: resource(14), MembershipID: id(15),
				Capabilities: []string{"actor_use", "artifact_read"}, Challenge: ceremony(16, '3'),
			})),
			mutated: mustCommandHashView(NewInviteWorkspaceMemberCommandHashView(context(StreamScopeWorkspace), InviteWorkspaceMemberCommandHashParams{
				Administrator: resource(2), Workspace: resource(1), Principal: resource(14), MembershipID: id(15),
				Capabilities: []string{"actor_use", "artifact_write"}, Challenge: ceremony(16, '3'),
			})),
			wantDigest: "de6e7ea7fec627ab56cf2fd64a789193787e55903cfe9e3247ded66223602600",
		},
		{
			name: "accept workspace membership",
			view: mustCommandHashView(NewAcceptWorkspaceMembershipCommandHashView(context(StreamScopeWorkspace), AcceptWorkspaceMembershipCommandHashParams{
				Workspace: resource(1), Principal: resource(14), Membership: resource(15), Proof: ceremony(16, '3'),
			})),
			mutated: mustCommandHashView(NewAcceptWorkspaceMembershipCommandHashView(context(StreamScopeWorkspace), AcceptWorkspaceMembershipCommandHashParams{
				Workspace: resource(1), Principal: resource(14), Membership: resource(15), Proof: ceremony(17, '3'),
			})),
			wantDigest: "3626a2e36618db662633878d248ef529b7a617563bf65b0f194134fcfaa2021a",
		},
		{
			name: "create actor",
			view: mustCommandHashView(NewCreateActorCommandHashView(context(StreamScopeWorkspace), CreateActorCommandHashParams{
				Administrator: resource(2), Workspace: resource(1), ActorID: id(18), Kind: string(domain.ActorKindAgent), DisplayName: "Researcher",
			})),
			mutated: mustCommandHashView(NewCreateActorCommandHashView(context(StreamScopeWorkspace), CreateActorCommandHashParams{
				Administrator: resource(2), Workspace: resource(1), ActorID: id(18), Kind: string(domain.ActorKindAgent), DisplayName: "Writer",
			})),
			wantDigest: "6392c97cb4338d6f530d061c626479489b5cb37f5ffe74aed6e9bd470c372035",
		},
		{
			name: "propose actor delegation",
			view: mustCommandHashView(NewProposeActorDelegationCommandHashView(context(StreamScopeWorkspace), ProposeActorDelegationCommandHashParams{
				Administrator: resource(2), Workspace: resource(1), Principal: resource(14), Actor: resource(18),
				Membership: resource(15), DelegationID: id(19), Capabilities: []string{"actor_use"}, Challenge: ceremony(20, '4'),
			})),
			mutated: mustCommandHashView(NewProposeActorDelegationCommandHashView(context(StreamScopeWorkspace), ProposeActorDelegationCommandHashParams{
				Administrator: resource(2), Workspace: resource(1), Principal: resource(14), Actor: resource(18),
				Membership: resource(15), DelegationID: id(21), Capabilities: []string{"actor_use"}, Challenge: ceremony(20, '4'),
			})),
			wantDigest: "4ef0c40121b07c2fc297c528e73fe9558be7c0dc277c93663044596b4203e0f1",
		},
		{
			name: "activate actor delegation",
			view: mustCommandHashView(NewActivateActorDelegationCommandHashView(context(StreamScopeWorkspace), ActivateActorDelegationCommandHashParams{
				Workspace: resource(1), Principal: resource(14), Actor: resource(18), Membership: resource(15),
				Delegation: resource(19), ActivationProof: ceremony(20, '4'), SessionStartChallenge: ceremony(22, '5'),
			})),
			mutated: mustCommandHashView(NewActivateActorDelegationCommandHashView(context(StreamScopeWorkspace), ActivateActorDelegationCommandHashParams{
				Workspace: resource(1), Principal: resource(14), Actor: resource(18), Membership: resource(15),
				Delegation: resource(19), ActivationProof: ceremony(20, '4'), SessionStartChallenge: ceremony(22, '6'),
			})),
			wantDigest: "83b28f1e99897c19f9a81942d0fef91aed9d7c90084452f05dba51be1bd8775a",
		},
		{
			name: "begin device pairing",
			view: mustCommandHashView(NewBeginDevicePairingCommandHashView(context(StreamScopeInstallation), BeginDevicePairingCommandHashParams{
				Principal: resource(2), DeviceID: id(23), DisplayName: "Tablet", PublicKeyReference: "key://device/23", Challenge: ceremony(24, '7'),
			})),
			mutated: mustCommandHashView(NewBeginDevicePairingCommandHashView(context(StreamScopeInstallation), BeginDevicePairingCommandHashParams{
				Principal: resource(2), DeviceID: id(23), DisplayName: "Laptop", PublicKeyReference: "key://device/23", Challenge: ceremony(24, '7'),
			})),
			wantDigest: "0f2645cbd1944294d2b1c193fd3db9f1096a751fcbcab37e364004d12e237d9b",
		},
		{
			name: "pair device",
			view: mustCommandHashView(NewPairDeviceCommandHashView(context(StreamScopeInstallation), PairDeviceCommandHashParams{
				Principal: resource(2), Device: resource(23), ExpectedTrustRevision: 2, Proof: ceremony(24, '7'),
				CredentialPublicKey: "key://device/23", CredentialSPKIDigest: digest('8'), CredentialTranscript: digest('9'),
			})),
			mutated: mustCommandHashView(NewPairDeviceCommandHashView(context(StreamScopeInstallation), PairDeviceCommandHashParams{
				Principal: resource(2), Device: resource(23), ExpectedTrustRevision: 3, Proof: ceremony(24, '7'),
				CredentialPublicKey: "key://device/23", CredentialSPKIDigest: digest('8'), CredentialTranscript: digest('9'),
			})),
			wantDigest: "ab417c0f4156034d846fc546c28a61000693b3a7125dd91106c68f516622a3af",
		},
	}

	trustedDevice := resource(23)
	trustRevision := uint64(2)
	sessionBase := StartActorSessionCommandHashParams{
		SessionID: id(25), ClientName: "blackbird-cli", ClientVersion: "1.0.0", Workspace: resource(1),
		Principal: resource(14), Membership: resource(15), Actor: resource(18), Delegation: resource(19),
		Grants: []CommandExpectedResource{resource(26), resource(27)}, StartAuthorityKind: string(domain.SessionStartByTrustedDevice),
		Device: &trustedDevice, ExpectedDeviceTrust: &trustRevision, AbsoluteExpiry: instant,
		PresentationReference: "credential://presentation/1", PresentationDigest: digest('a'),
		PresentationAudience: "blackbird", PresentationVersion: 1,
	}
	sessionMutation := sessionBase
	sessionMutation.ClientVersion = "1.0.1"
	tests = append(tests, struct {
		name       string
		view       CommandHashView
		mutated    CommandHashView
		wantDigest string
	}{
		name:       "start actor session",
		view:       mustCommandHashView(NewStartActorSessionCommandHashView(context(StreamScopeWorkspace), sessionBase)),
		mutated:    mustCommandHashView(NewStartActorSessionCommandHashView(context(StreamScopeWorkspace), sessionMutation)),
		wantDigest: "80d7ba831d2fc8019e2e218f23cf3705f68eeb7cb581e9eedd70f686f7725c8b",
	})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			canonical, err := codec.EncodeCanonical(test.view)
			if err != nil {
				t.Fatal(err)
			}
			for _, excluded := range []string{
				"authority_id", "authority_epoch", "command_id", "request_id", "receipt_id", "idempotency_key",
				"deadline", "retry_count", "network_route", "response_format",
			} {
				if bytes.Contains(canonical, []byte(`"`+excluded+`"`)) {
					t.Fatalf("excluded metadata %q entered %s", excluded, canonical)
				}
			}
			fingerprint, err := codec.HashCommand(test.view)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantDigest == "" {
				t.Fatalf("retain command golden %q: %s", test.name, hex.EncodeToString(fingerprint[:]))
			}
			if got := hex.EncodeToString(fingerprint[:]); got != test.wantDigest {
				t.Fatalf("command golden changed: got %s, want %s", got, test.wantDigest)
			}
			mutated, err := codec.HashCommand(test.mutated)
			if err != nil || mutated == fingerprint {
				t.Fatalf("one-field mutation did not change fingerprint: %x, %v", mutated, err)
			}
		})
	}
}

func mustCommandHashView(view CommandHashView, err error) CommandHashView {
	if err != nil {
		panic(err)
	}
	return view
}

func TestObserveWorkRefCommandHashProfile(t *testing.T) {
	t.Parallel()

	id := func(index int) CanonicalIdentifier { return mustCanonicalID(t, codecUUID(index)) }
	resource := func(index int) CommandExpectedResource {
		return CommandExpectedResource{ID: id(index), ExpectedVersion: uint64(index)}
	}
	fields, err := domain.NewEventPayload([]byte(`{"status":"open","priority":1}`))
	if err != nil {
		t.Fatal(err)
	}
	context := W0CommandHashContextParams{
		ScopeKind: StreamScopeWorkspace, ScopeID: id(1), PrincipalID: id(2), ClientInstanceID: id(3),
		CorrelationID: id(4), ProtocolCapabilities: []string{"receipts-v1"},
	}
	base := ObserveWorkRefCommandHashParams{
		Adapter: resource(2), Workspace: resource(1), WorkReferenceID: id(30), ProviderNamespace: "beads",
		ProviderObjectID: "bd-fam.2.2", ProviderLocator: "beads://blackmail/bd-fam.2.2", ProviderVersion: "beads-v7",
		SelectedFields: fields, AdapterPrincipalID: id(2), ObservedAt: time.Date(2026, 8, 5, 12, 30, 0, 123_000_000, time.UTC),
	}
	create := mustCommandHashView(NewObserveWorkRefCommandHashView(context, base))
	createFingerprint, err := NewProductionCanonicalCodec().HashCommand(create)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(createFingerprint[:]), "45f6c8e5a178ad943c39991468675bf8b26fd8ad7d0748e48cbb2d005c43cdb1"; got != want {
		t.Fatalf("observe create golden changed: got %s, want %s", got, want)
	}

	expected := uint64(1)
	update := base
	update.ExpectedWorkReferenceVersion = &expected
	update.ProviderVersion = "beads-v8"
	update.PreviousProviderVersion = "beads-v7"
	updateFingerprint, err := NewProductionCanonicalCodec().HashCommand(
		mustCommandHashView(NewObserveWorkRefCommandHashView(context, update)),
	)
	if err != nil || updateFingerprint == createFingerprint {
		t.Fatalf("update fingerprint=%x error=%v", updateFingerprint, err)
	}

	reordered, _ := domain.NewEventPayload([]byte(`{"priority":1,"status":"open"}`))
	canonicalEquivalent := base
	canonicalEquivalent.SelectedFields = reordered
	equivalentFingerprint, err := NewProductionCanonicalCodec().HashCommand(
		mustCommandHashView(NewObserveWorkRefCommandHashView(context, canonicalEquivalent)),
	)
	if err != nil || equivalentFingerprint != createFingerprint {
		t.Fatalf("selected field canonicalization changed fingerprint: %x, %v", equivalentFingerprint, err)
	}

	invalid := []ObserveWorkRefCommandHashParams{base, base, base}
	invalid[0].ExpectedWorkReferenceVersion = &expected
	invalid[1].PreviousProviderVersion = "beads-v6"
	invalid[2].AdapterPrincipalID = id(5)
	for index, candidate := range invalid {
		if _, err := NewObserveWorkRefCommandHashView(context, candidate); !errors.Is(err, ErrCanonicalProfile) {
			t.Fatalf("invalid case %d error=%v", index, err)
		}
	}
}

func TestW0CommandHashViewsHashEveryStructuralField(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	for _, fixture := range commandHashViewFixtures(t) {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			baseline, err := codec.HashCommand(fixture.view)
			if err != nil {
				t.Fatalf("baseline: %v", err)
			}
			paths := commandHashLeafPaths(reflect.ValueOf(fixture.view), nil, nil)
			if len(paths) == 0 {
				t.Fatal("view has no hash fields")
			}
			for _, path := range paths {
				path := path
				t.Run(path.name, func(t *testing.T) {
					candidate := cloneCommandHashValue(reflect.ValueOf(fixture.view))
					mutateCommandHashPath(t, candidate, path.fields)
					mutatedView, ok := candidate.Interface().(CommandHashView)
					if !ok {
						t.Fatalf("cloned %T is not a command hash view", candidate.Interface())
					}
					fingerprint, hashErr := codec.HashCommand(mutatedView)
					if hashErr != nil {
						t.Fatalf("hash mutation: %v", hashErr)
					}
					if fingerprint == baseline {
						t.Fatal("field mutation did not change fingerprint")
					}
				})
			}
		})
	}
}

func TestW0CommandHashDomainProfileRejectionsAndBounds(t *testing.T) {
	t.Parallel()

	id := func(index int) CanonicalIdentifier { return mustCanonicalID(t, codecUUID(index)) }
	digest := func(character byte) CanonicalDigest { return mustCanonicalDigest(t, character) }
	instant, _ := ParseCanonicalInstant("2026-08-05T12:30:00.123000Z")
	resource := func(index int) CommandExpectedResource {
		return CommandExpectedResource{ID: id(index), ExpectedVersion: uint64(index)}
	}
	ceremony := CommandCeremony{ID: id(20), ExpiresAt: instant, ProofDigest: digest('4')}
	installationContext := W0CommandHashContextParams{
		ScopeKind: StreamScopeInstallation, ScopeID: id(1), PrincipalID: id(2), ClientInstanceID: id(3),
		CorrelationID: id(4), ProtocolCapabilities: []string{"batch-v1", "receipts-v1"},
	}
	workspaceContext := installationContext
	workspaceContext.ScopeKind = StreamScopeWorkspace

	assertProfileError := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, ErrCanonicalProfile) {
			t.Fatalf("got %v, want canonical profile rejection", err)
		}
	}

	principal := RegisterPrincipalCommandHashParams{
		Registrar: resource(2), PrincipalID: id(10), Kind: string(domain.PrincipalKindService),
		DisplayName: "Indexer", PublicKeyReference: "key://principal/10",
	}
	invalidPrincipal := principal
	invalidPrincipal.Kind = "robot"
	_, err := NewRegisterPrincipalCommandHashView(installationContext, invalidPrincipal)
	assertProfileError(t, err)

	actor := CreateActorCommandHashParams{
		Administrator: resource(2), Workspace: resource(1), ActorID: id(18),
		Kind: string(domain.ActorKindAgent), DisplayName: "Researcher",
	}
	invalidActor := actor
	invalidActor.Kind = "robot"
	_, err = NewCreateActorCommandHashView(workspaceContext, invalidActor)
	assertProfileError(t, err)

	for _, capabilities := range [][]string{{"Uppercase"}, {"valid", "valid"}} {
		candidate := workspaceContext
		candidate.ProtocolCapabilities = capabilities
		_, err = NewCreateActorCommandHashView(candidate, actor)
		assertProfileError(t, err)
	}
	for _, capabilities := range [][]string{{"bad capability"}, {"actor_use", "actor_use"}} {
		_, err = NewInviteWorkspaceMemberCommandHashView(workspaceContext, InviteWorkspaceMemberCommandHashParams{
			Administrator: resource(2), Workspace: resource(1), Principal: resource(14), MembershipID: id(15),
			Capabilities: capabilities, Challenge: ceremony,
		})
		assertProfileError(t, err)
	}

	beginPairing := BeginDevicePairingCommandHashParams{
		Principal: resource(2), DeviceID: id(23), DisplayName: strings.Repeat("d", 256),
		PublicKeyReference: strings.Repeat("k", 256), Challenge: ceremony,
	}
	if _, err = NewBeginDevicePairingCommandHashView(installationContext, beginPairing); err != nil {
		t.Fatalf("exact display/public-key bounds: %v", err)
	}
	tooLongDisplay := beginPairing
	tooLongDisplay.DisplayName += "d"
	_, err = NewBeginDevicePairingCommandHashView(installationContext, tooLongDisplay)
	assertProfileError(t, err)
	tooLongKey := beginPairing
	tooLongKey.PublicKeyReference += "k"
	_, err = NewBeginDevicePairingCommandHashView(installationContext, tooLongKey)
	assertProfileError(t, err)

	workspace := CreateWorkspaceCommandHashParams{
		Owner: resource(2), InstallationGrant: resource(12), WorkspaceID: id(1),
		Alias: strings.Repeat("a", 256), DiscoveryLocator: strings.Repeat("l", 4096),
		OwnerMembershipID: id(13), OwnerCapabilities: []string{"workspace_owner"},
	}
	if _, err = NewCreateWorkspaceCommandHashView(workspaceContext, workspace); err != nil {
		t.Fatalf("exact alias/locator bounds: %v", err)
	}
	tooLongAlias := workspace
	tooLongAlias.Alias += "a"
	_, err = NewCreateWorkspaceCommandHashView(workspaceContext, tooLongAlias)
	assertProfileError(t, err)
	tooLongLocator := workspace
	tooLongLocator.DiscoveryLocator += "l"
	_, err = NewCreateWorkspaceCommandHashView(workspaceContext, tooLongLocator)
	assertProfileError(t, err)

	device := resource(23)
	trust := uint64(2)
	session := StartActorSessionCommandHashParams{
		SessionID: id(25), ClientName: strings.Repeat("c", 128), ClientVersion: strings.Repeat("v", 128),
		Workspace: resource(1), Principal: resource(14), Membership: resource(15), Actor: resource(18),
		Delegation: resource(19), Grants: []CommandExpectedResource{resource(26)},
		StartAuthorityKind: string(domain.SessionStartByTrustedDevice), Device: &device, ExpectedDeviceTrust: &trust,
		AbsoluteExpiry: instant, PresentationReference: strings.Repeat("r", 256), PresentationDigest: digest('a'),
		PresentationAudience: strings.Repeat("p", 256), PresentationVersion: domain.PresentationCredentialVersion,
	}
	if _, err = NewStartActorSessionCommandHashView(workspaceContext, session); err != nil {
		t.Fatalf("exact client/presentation bounds: %v", err)
	}
	for name, mutate := range map[string]func(*StartActorSessionCommandHashParams){
		"client name":            func(value *StartActorSessionCommandHashParams) { value.ClientName += "c" },
		"client version":         func(value *StartActorSessionCommandHashParams) { value.ClientVersion += "v" },
		"presentation reference": func(value *StartActorSessionCommandHashParams) { value.PresentationReference += "r" },
		"presentation audience":  func(value *StartActorSessionCommandHashParams) { value.PresentationAudience += "p" },
	} {
		t.Run(name+" above bound", func(t *testing.T) {
			candidate := session
			mutate(&candidate)
			_, candidateErr := NewStartActorSessionCommandHashView(workspaceContext, candidate)
			assertProfileError(t, candidateErr)
		})
	}

	for name, mutate := range map[string]func(*StartActorSessionCommandHashParams){
		"zero resource version": func(value *StartActorSessionCommandHashParams) { value.Workspace.ExpectedVersion = 0 },
		"unsafe resource version": func(value *StartActorSessionCommandHashParams) {
			value.Workspace.ExpectedVersion = MaxCanonicalInteger + 1
		},
		"zero trust version": func(value *StartActorSessionCommandHashParams) { zero := uint64(0); value.ExpectedDeviceTrust = &zero },
		"unsafe trust version": func(value *StartActorSessionCommandHashParams) {
			unsafe := uint64(MaxCanonicalInteger + 1)
			value.ExpectedDeviceTrust = &unsafe
		},
		"trusted device missing device": func(value *StartActorSessionCommandHashParams) { value.Device = nil },
		"trusted device with handoff":   func(value *StartActorSessionCommandHashParams) { value.HandoffProof = &ceremony },
		"handoff with device union": func(value *StartActorSessionCommandHashParams) {
			value.StartAuthorityKind = string(domain.SessionStartByHandoff)
			value.HandoffProof = &ceremony
		},
		"handoff missing proof": func(value *StartActorSessionCommandHashParams) {
			value.StartAuthorityKind = string(domain.SessionStartByHandoff)
			value.Device, value.ExpectedDeviceTrust = nil, nil
		},
		"unsupported presentation version": func(value *StartActorSessionCommandHashParams) { value.PresentationVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := session
			mutate(&candidate)
			_, candidateErr := NewStartActorSessionCommandHashView(workspaceContext, candidate)
			assertProfileError(t, candidateErr)
		})
	}
}

func TestW0ProtocolCapabilityNormalizationAndFingerprintMembership(t *testing.T) {
	t.Parallel()

	id := func(index int) CanonicalIdentifier { return mustCanonicalID(t, codecUUID(index)) }
	context := W0CommandHashContextParams{
		ScopeKind: StreamScopeWorkspace, ScopeID: id(1), PrincipalID: id(2), ClientInstanceID: id(3),
		CorrelationID: id(4), ProtocolCapabilities: []string{"batch-v1", "receipts-v1"},
	}
	commandFor := func(capabilities []string) commandHashContextWire {
		candidate := context
		candidate.ProtocolCapabilities = capabilities
		command, err := commandHashContext(CommandCreateActor, candidate)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	body := commandHashViewFixtures(t)[5].view.(createActorCommandHashView).Body
	base := createActorCommandHashView{Command: commandFor([]string{"batch-v1", "receipts-v1"}), Body: body}
	reordered := createActorCommandHashView{Command: commandFor([]string{"receipts-v1", "batch-v1"}), Body: body}
	added := createActorCommandHashView{Command: commandFor([]string{"batch-v1", "receipts-v1", "streaming-v1"}), Body: body}
	removed := createActorCommandHashView{Command: commandFor([]string{"batch-v1"}), Body: body}
	codec := NewProductionCanonicalCodec()
	baseline, _ := codec.HashCommand(base)
	reorderedFingerprint, _ := codec.HashCommand(reordered)
	addedFingerprint, _ := codec.HashCommand(added)
	removedFingerprint, _ := codec.HashCommand(removed)
	if reorderedFingerprint != baseline {
		t.Fatal("equivalent protocol capability ordering changed fingerprint")
	}
	if addedFingerprint == baseline || removedFingerprint == baseline {
		t.Fatal("protocol capability membership change did not change fingerprint")
	}
}

func TestW0CommandHashContextExclusionsAreStructural(t *testing.T) {
	t.Parallel()

	contextType := reflect.TypeFor[W0CommandHashContextParams]()
	wantFields := []string{
		"ScopeKind", "ScopeID", "PrincipalID", "ClientInstanceID", "ActorID", "ActorSessionID",
		"CorrelationID", "CausationEventID", "ProtocolCapabilities",
	}
	if contextType.NumField() != len(wantFields) {
		t.Fatalf("context field count = %d, want %d", contextType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if got := contextType.Field(index).Name; got != want {
			t.Fatalf("context field %d = %q, want %q", index, got, want)
		}
	}
	for _, excluded := range []string{
		"AuthorityID", "AuthorityEpoch", "CommandID", "RequestID", "ReceiptID", "IdempotencyKey",
		"Deadline", "RetryCount", "NetworkRoute", "ResponseFormat",
	} {
		if _, present := contextType.FieldByName(excluded); present {
			t.Fatalf("excluded transport field %q became representable", excluded)
		}
	}
}

type commandHashFixture struct {
	name string
	view CommandHashView
}

func commandHashViewFixtures(t *testing.T) []commandHashFixture {
	t.Helper()
	id := func(index int) CanonicalIdentifier { return mustCanonicalID(t, codecUUID(index)) }
	digest := func(character byte) CanonicalDigest { return mustCanonicalDigest(t, character) }
	instant, _ := ParseCanonicalInstant("2026-08-05T12:30:00.123000Z")
	resource := func(index int) CommandExpectedResource {
		return CommandExpectedResource{ID: id(index), ExpectedVersion: uint64(index)}
	}
	ceremony := func(index int, character byte) CommandCeremony {
		return CommandCeremony{ID: id(index), ExpiresAt: instant, ProofDigest: digest(character)}
	}
	context := func(kind StreamScopeKind) W0CommandHashContextParams {
		return W0CommandHashContextParams{
			ScopeKind: kind, ScopeID: id(1), PrincipalID: id(2), ClientInstanceID: id(3),
			CorrelationID: id(4), CausationEventID: id(5),
			ProtocolCapabilities: []string{"batch-v1", "receipts-v1"},
		}
	}
	trustedDevice := resource(23)
	trustRevision := uint64(2)
	trustedSession := StartActorSessionCommandHashParams{
		SessionID: id(25), ClientName: "blackbird-cli", ClientVersion: "1.0.0", Workspace: resource(1),
		Principal: resource(14), Membership: resource(15), Actor: resource(18), Delegation: resource(19),
		Grants: []CommandExpectedResource{resource(26), resource(27)}, StartAuthorityKind: string(domain.SessionStartByTrustedDevice),
		Device: &trustedDevice, ExpectedDeviceTrust: &trustRevision, AbsoluteExpiry: instant,
		PresentationReference: "credential://presentation/1", PresentationDigest: digest('a'),
		PresentationAudience: "blackbird", PresentationVersion: domain.PresentationCredentialVersion,
	}
	handoffSession := trustedSession
	handoffSession.StartAuthorityKind = string(domain.SessionStartByHandoff)
	handoffSession.Device = nil
	handoffSession.ExpectedDeviceTrust = nil
	handoffProof := ceremony(28, 'b')
	handoffSession.HandoffProof = &handoffProof

	return []commandHashFixture{
		{name: "bootstrap installation", view: mustCommandHashView(NewBootstrapInstallationCommandHashView(
			context(StreamScopeInstallation), BootstrapInstallationCommandHashParams{
				InstallationID: id(1), Invitation: resource(6), BootstrapGenerationID: id(7), ApprovedTranscript: digest('1'),
				PrincipalID: id(2), PrincipalDisplayName: "Alice", DeviceID: id(8), DeviceDisplayName: "Alice phone",
				DevicePublicKeyReference: "key://device/8", DeviceSPKIFingerprint: digest('2'), OwnerGrantID: id(9),
				OwnerGrantCapabilities: []string{"identity_admin", "installation_owner"},
			}))},
		{name: "register principal", view: mustCommandHashView(NewRegisterPrincipalCommandHashView(
			context(StreamScopeInstallation), RegisterPrincipalCommandHashParams{
				Registrar: resource(2), PrincipalID: id(10), Kind: string(domain.PrincipalKindService),
				DisplayName: "Indexer", PublicKeyReference: "key://principal/10",
			}))},
		{name: "create workspace", view: mustCommandHashView(NewCreateWorkspaceCommandHashView(
			context(StreamScopeWorkspace), CreateWorkspaceCommandHashParams{
				Owner: resource(2), InstallationGrant: resource(12), WorkspaceID: id(1), Alias: "acme",
				DiscoveryLocator: "blackbird://workspace/acme", OwnerMembershipID: id(13),
				OwnerCapabilities: []string{"actor_admin", "workspace_owner"},
			}))},
		{name: "invite workspace member", view: mustCommandHashView(NewInviteWorkspaceMemberCommandHashView(
			context(StreamScopeWorkspace), InviteWorkspaceMemberCommandHashParams{
				Administrator: resource(2), Workspace: resource(1), Principal: resource(14), MembershipID: id(15),
				Capabilities: []string{"actor_use", "artifact_read"}, Challenge: ceremony(16, '3'),
			}))},
		{name: "accept workspace membership", view: mustCommandHashView(NewAcceptWorkspaceMembershipCommandHashView(
			context(StreamScopeWorkspace), AcceptWorkspaceMembershipCommandHashParams{
				Workspace: resource(1), Principal: resource(14), Membership: resource(15), Proof: ceremony(16, '3'),
			}))},
		{name: "create actor", view: mustCommandHashView(NewCreateActorCommandHashView(
			context(StreamScopeWorkspace), CreateActorCommandHashParams{
				Administrator: resource(2), Workspace: resource(1), ActorID: id(18),
				Kind: string(domain.ActorKindAgent), DisplayName: "Researcher",
			}))},
		{name: "propose actor delegation", view: mustCommandHashView(NewProposeActorDelegationCommandHashView(
			context(StreamScopeWorkspace), ProposeActorDelegationCommandHashParams{
				Administrator: resource(2), Workspace: resource(1), Principal: resource(14), Actor: resource(18),
				Membership: resource(15), DelegationID: id(19), Capabilities: []string{"actor_use"}, Challenge: ceremony(20, '4'),
			}))},
		{name: "activate actor delegation", view: mustCommandHashView(NewActivateActorDelegationCommandHashView(
			context(StreamScopeWorkspace), ActivateActorDelegationCommandHashParams{
				Workspace: resource(1), Principal: resource(14), Actor: resource(18), Membership: resource(15),
				Delegation: resource(19), ActivationProof: ceremony(20, '4'), SessionStartChallenge: ceremony(22, '5'),
			}))},
		{name: "begin device pairing", view: mustCommandHashView(NewBeginDevicePairingCommandHashView(
			context(StreamScopeInstallation), BeginDevicePairingCommandHashParams{
				Principal: resource(2), DeviceID: id(23), DisplayName: "Tablet",
				PublicKeyReference: "key://device/23", Challenge: ceremony(24, '7'),
			}))},
		{name: "pair device", view: mustCommandHashView(NewPairDeviceCommandHashView(
			context(StreamScopeInstallation), PairDeviceCommandHashParams{
				Principal: resource(2), Device: resource(23), ExpectedTrustRevision: 2, Proof: ceremony(24, '7'),
				CredentialPublicKey: "key://device/23", CredentialSPKIDigest: digest('8'), CredentialTranscript: digest('9'),
			}))},
		{name: "start actor session trusted device", view: mustCommandHashView(NewStartActorSessionCommandHashView(
			context(StreamScopeWorkspace), trustedSession))},
		{name: "start actor session handoff", view: mustCommandHashView(NewStartActorSessionCommandHashView(
			context(StreamScopeWorkspace), handoffSession))},
	}
}

type commandHashFieldPath struct {
	name   string
	fields []int
}

func commandHashLeafPaths(value reflect.Value, fields []int, names []string) []commandHashFieldPath {
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return []commandHashFieldPath{{name: strings.Join(names, "."), fields: append([]int(nil), fields...)}}
		}
		value = value.Elem()
	}
	if isCommandHashScalar(value.Type()) || value.Kind() != reflect.Struct {
		return []commandHashFieldPath{{name: strings.Join(names, "."), fields: append([]int(nil), fields...)}}
	}
	paths := make([]commandHashFieldPath, 0)
	for index := range value.NumField() {
		paths = append(paths, commandHashLeafPaths(
			value.Field(index), append(fields, index), append(names, value.Type().Field(index).Name),
		)...)
	}
	return paths
}

func isCommandHashScalar(valueType reflect.Type) bool {
	return valueType == reflect.TypeFor[CanonicalIdentifier]() ||
		valueType == reflect.TypeFor[CanonicalDigest]() ||
		valueType == reflect.TypeFor[CanonicalInstant]()
}

func cloneCommandHashValue(value reflect.Value) reflect.Value {
	if isCommandHashScalar(value.Type()) {
		return value
	}
	switch value.Kind() {
	case reflect.Interface:
		clone := cloneCommandHashValue(value.Elem())
		result := reflect.New(value.Type()).Elem()
		result.Set(clone)
		return result
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		result := reflect.New(value.Type().Elem())
		result.Elem().Set(cloneCommandHashValue(value.Elem()))
		return result
	case reflect.Struct:
		result := reflect.New(value.Type()).Elem()
		for index := range value.NumField() {
			result.Field(index).Set(cloneCommandHashValue(value.Field(index)))
		}
		return result
	case reflect.Slice:
		result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for index := range value.Len() {
			result.Index(index).Set(cloneCommandHashValue(value.Index(index)))
		}
		return result
	default:
		return value
	}
}

func mutateCommandHashPath(t *testing.T, root reflect.Value, fields []int) {
	t.Helper()
	value := root
	for index, field := range fields {
		for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
			value = value.Elem()
		}
		value = value.Field(field)
		if index == len(fields)-1 {
			mutateCommandHashValue(t, value)
			return
		}
	}
}

func mutateCommandHashValue(t *testing.T, value reflect.Value) {
	t.Helper()
	if value.Type() == reflect.TypeFor[CanonicalIdentifier]() {
		value.Set(reflect.ValueOf(mustCanonicalID(t, codecUUID(98))))
		return
	}
	if value.Type() == reflect.TypeFor[CanonicalDigest]() {
		value.Set(reflect.ValueOf(mustCanonicalDigest(t, 'f')))
		return
	}
	if value.Type() == reflect.TypeFor[CanonicalInstant]() {
		instant, _ := ParseCanonicalInstant("2026-08-06T12:30:00.123000Z")
		value.Set(reflect.ValueOf(instant))
		return
	}
	if value.Type() == reflect.TypeFor[StreamScopeKind]() {
		if value.Interface().(StreamScopeKind) == StreamScopeInstallation {
			value.SetString(string(StreamScopeWorkspace))
		} else {
			value.SetString(string(StreamScopeInstallation))
		}
		return
	}
	switch value.Kind() {
	case reflect.String:
		value.SetString(value.String() + "-mutation")
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value.SetUint(value.Uint() + 1)
	case reflect.Slice:
		mutated := reflect.MakeSlice(value.Type(), value.Len(), value.Len()+1)
		reflect.Copy(mutated, value)
		switch value.Type().Elem() {
		case reflect.TypeFor[string]():
			mutated = reflect.Append(mutated, reflect.ValueOf("mutation-v1"))
		case reflect.TypeFor[CommandExpectedResource]():
			mutated = reflect.Append(mutated, reflect.ValueOf(CommandExpectedResource{
				ID: mustCanonicalID(t, codecUUID(97)), ExpectedVersion: 97,
			}))
		default:
			t.Fatalf("unsupported command hash slice %s", value.Type())
		}
		value.Set(mutated)
	case reflect.Pointer:
		if !value.IsNil() {
			mutateCommandHashValue(t, value.Elem())
			return
		}
		switch value.Type().Elem() {
		case reflect.TypeFor[CanonicalIdentifier]():
			identifier := mustCanonicalID(t, codecUUID(96))
			value.Set(reflect.ValueOf(&identifier))
		case reflect.TypeFor[CommandExpectedResource]():
			resource := CommandExpectedResource{ID: mustCanonicalID(t, codecUUID(95)), ExpectedVersion: 95}
			value.Set(reflect.ValueOf(&resource))
		case reflect.TypeFor[CommandCeremony]():
			instant, _ := ParseCanonicalInstant("2026-08-07T12:30:00.123000Z")
			ceremony := CommandCeremony{ID: mustCanonicalID(t, codecUUID(94)), ExpiresAt: instant, ProofDigest: mustCanonicalDigest(t, 'e')}
			value.Set(reflect.ValueOf(&ceremony))
		case reflect.TypeFor[uint64]():
			number := uint64(94)
			value.Set(reflect.ValueOf(&number))
		default:
			t.Fatalf("unsupported command hash pointer %s", value.Type())
		}
	default:
		t.Fatalf("unsupported command hash field %s", value.Type())
	}
}

type receiptFixture struct {
	authority     domain.AuthorityID
	epoch         domain.AuthorityEpoch
	installation  domain.InstallationID
	workspace     domain.WorkspaceID
	principal     domain.PrincipalID
	device        domain.DeviceID
	grant         domain.GrantID
	membership    domain.MembershipID
	actor         domain.ActorID
	delegation    domain.ActorDelegationID
	session       domain.ActorSessionID
	client        domain.ClientInstanceID
	acceptedAt    time.Time
	authorization domain.AuthorizationDigest
	finalStream   domain.StreamDigest
}

func TestW0ReceiptResultCatalogAcceptsExactlyElevenSemanticShapes(t *testing.T) {
	t.Parallel()

	fixture := newReceiptFixture(t)
	tests := []struct {
		operation       W0ReceiptOperation
		resourceKinds   []domain.AggregateKind
		eventCount      int
		ceremonyPurpose domain.CeremonyPurpose
		capsuleRequired bool
		sessionRequired bool
		wantDigest      string
	}{
		{ReceiptOperationInstallationBootstrap, []domain.AggregateKind{domain.AggregateKindPrincipal, domain.AggregateKindDevice, domain.AggregateKindGrant}, 3, "", true, false, "776348629562c93f072b4d078ec5c322aa652284c72c7577784457bf152961e4"},
		{ReceiptOperationPrincipalRegister, []domain.AggregateKind{domain.AggregateKindPrincipal}, 1, "", true, false, "a68e1e69da8da56eb759745e9e4f83bc5d38ee69fa2bae388a0912b7fe309e34"},
		{ReceiptOperationDevicePairingBegin, []domain.AggregateKind{domain.AggregateKindDevice}, 1, domain.CeremonyPurposeDevicePairing, true, false, "b8422a9f314be087a6f6b709fbe95aef42f22ee90ac0867c39030c7a90c1d843"},
		{ReceiptOperationDevicePair, []domain.AggregateKind{domain.AggregateKindDevice}, 1, "", false, false, "b0031162bda6be266612faa34f58c4e3dc9ff68dfff46b50cf0f44625fd9596e"},
		{ReceiptOperationWorkspaceCreate, []domain.AggregateKind{domain.AggregateKindWorkspace, domain.AggregateKindMembership}, 3, "", true, false, "6f6cafd9ed1d7a0098ce49c841015f7cbe2207421b0d0bcf2d7f517fa9ab14c8"},
		{ReceiptOperationWorkspaceMemberInvite, []domain.AggregateKind{domain.AggregateKindMembership}, 1, domain.CeremonyPurposeMembershipAcceptance, true, false, "3ddfb4f50bd1885c952a8f2e5bbec24af5fcbc15e764d5053af7b71d47645775"},
		{ReceiptOperationWorkspaceMembershipAccept, []domain.AggregateKind{domain.AggregateKindMembership}, 1, "", false, false, "de3fb97bd04f34aedd44769a422cb2e0d1526301722eacc4b92cac47c68f9cb0"},
		{ReceiptOperationActorCreate, []domain.AggregateKind{domain.AggregateKindActor}, 1, "", true, false, "11572421b8573d3e4fa81fc9899c0a0b6cf619643afae38a3449d0d0539db898"},
		{ReceiptOperationActorDelegationPropose, []domain.AggregateKind{domain.AggregateKindActorDelegation}, 1, domain.CeremonyPurposeDelegationActivation, true, false, "97b907a9dbbefe47648be77231a0945906c8308f813002523b44c4fb85a9b3b5"},
		{ReceiptOperationActorDelegationActivate, []domain.AggregateKind{domain.AggregateKindActorDelegation}, 1, domain.CeremonyPurposeActorSessionStart, true, false, "d07d43c6899e768f8cd00f6b41ef666b3fab71a3c905c08a79293672c5752bf0"},
		{ReceiptOperationActorSessionStart, []domain.AggregateKind{domain.AggregateKindActorSession}, 1, "", true, true, "6cb4b53f77faf41ed40e2f6696c3203eb0f80cfbe41a3d034f2ad31351fc66b0"},
	}
	codec := NewProductionCanonicalCodec()
	for _, test := range tests {
		t.Run(string(test.operation), func(t *testing.T) {
			params := fixture.paramsFor(t, test.operation, test.resourceKinds, test.eventCount, test.ceremonyPurpose)
			view, err := NewW0ReceiptResultView(params)
			if err != nil {
				t.Fatalf("construct result: %v", err)
			}
			if view.wire.CapsuleRequired != test.capsuleRequired ||
				(view.wire.SessionBinding != nil) != test.sessionRequired {
				t.Fatalf("catalog flags are wrong: %#v", view.wire)
			}
			document, err := codec.EncodeReceiptResult(view)
			if err != nil {
				t.Fatalf("encode result: %v", err)
			}
			if document.IsZero() || len(document.CanonicalBytes()) > MaxReceiptResultBytes {
				t.Fatal("invalid sealed result document")
			}
			if document.Operation() != test.operation {
				t.Fatalf("document operation %q, want %q", document.Operation(), test.operation)
			}
			if got := document.Digest().String(); got != test.wantDigest {
				t.Fatalf("receipt result golden for %s: got %s, want %s", test.operation, got, test.wantDigest)
			}
			mutatedView := view
			mutatedView.wire.AcceptedAt, _ = ParseCanonicalInstant("2026-08-04T12:00:01.123000Z")
			mutated, err := codec.EncodeReceiptResult(mutatedView)
			if err != nil || mutated.Digest() == document.Digest() {
				t.Fatalf("one-field receipt mutation for %s was not bound: %v", test.operation, err)
			}
			canonical := string(document.CanonicalBytes())
			for _, forbidden := range []string{`"replay"`, `"request_id"`, `"capsule_digest"`, `"signature"`} {
				if strings.Contains(canonical, forbidden) {
					t.Fatalf("persisted semantic result contains %s: %s", forbidden, canonical)
				}
			}
		})
	}
	if len(tests) != 11 {
		t.Fatalf("catalog has %d test operations", len(tests))
	}
}

func TestReceiptResultCatalogCannotDriftFromCommandCatalog(t *testing.T) {
	t.Parallel()

	if len(operationContracts) != 11 {
		t.Fatalf("command catalog has %d operations", len(operationContracts))
	}
	for operation, command := range operationContracts {
		result, exists := receiptCatalog(operation)
		if !exists {
			t.Fatalf("missing receipt catalog for %q", operation)
		}
		if result.scopeKind != command.scope || result.eventCount != len(command.facts) ||
			result.capsuleRequired != (command.recovery == RecoveryCapsuleRequired) {
			t.Fatalf("catalog drift for %q: result=%#v command=%#v", operation, result, command)
		}
		issuedPurposes := make([]domain.CeremonyPurpose, 0, len(command.ceremonies))
		for _, ceremony := range command.ceremonies {
			if ceremony.kind == CeremonyReserveAbsent {
				issuedPurposes = append(issuedPurposes, ceremony.purpose)
			}
		}
		if len(issuedPurposes) != len(result.ceremonyPurpose) {
			t.Fatalf("issued ceremony count drift for %q", operation)
		}
		for index := range issuedPurposes {
			if issuedPurposes[index] != result.ceremonyPurpose[index] {
				t.Fatalf("issued ceremony drift for %q", operation)
			}
		}
		for _, kind := range result.resourceKinds {
			if _, mutated := command.mutations[kind]; !mutated {
				t.Fatalf("result resource %q is not committed by %q", kind, operation)
			}
		}
	}
}

func TestW0ReceiptResultRejectsCatalogDrift(t *testing.T) {
	t.Parallel()

	fixture := newReceiptFixture(t)
	base := fixture.paramsFor(
		t, ReceiptOperationDevicePairingBegin,
		[]domain.AggregateKind{domain.AggregateKindDevice}, 1, domain.CeremonyPurposeDevicePairing,
	)
	tests := []struct {
		name   string
		mutate func(*W0ReceiptResultParams)
	}{
		{name: "wrong scope", mutate: func(params *W0ReceiptResultParams) {
			params.Scope, _ = domain.WorkspaceScope(fixture.workspace)
		}},
		{name: "missing resource", mutate: func(params *W0ReceiptResultParams) { params.Resources = nil }},
		{name: "wrong resource", mutate: func(params *W0ReceiptResultParams) {
			params.Resources = []domain.AggregateRef{mustAggregateRef(t, fixture.principal, domain.InitialVersion())}
		}},
		{name: "missing ceremony", mutate: func(params *W0ReceiptResultParams) { params.IssuedCeremonies = nil }},
		{name: "wrong ceremony purpose", mutate: func(params *W0ReceiptResultParams) {
			challenge, _ := domain.NewMembershipAcceptanceChallenge(
				mustCeremonyID(t), domain.FingerprintCommand([]byte("membership")), fixture.acceptedAt.Add(time.Minute),
				fixture.workspace, fixture.membership, fixture.principal,
			)
			params.IssuedCeremonies = []domain.CeremonyChallenge{challenge}
		}},
		{name: "event count", mutate: func(params *W0ReceiptResultParams) { params.EventIDs = nil }},
		{name: "noncontiguous range", mutate: func(params *W0ReceiptResultParams) {
			params.LastEventPosition, _ = domain.NewStreamPosition(params.FirstEventPosition.Uint64() + 1)
		}},
		{name: "unexpected session", mutate: func(params *W0ReceiptResultParams) {
			params.SessionBinding = fixture.sessionBinding(t)
			params.SessionClient = fixture.client
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Resources = append([]domain.AggregateRef(nil), base.Resources...)
			candidate.IssuedCeremonies = append([]domain.CeremonyChallenge(nil), base.IssuedCeremonies...)
			candidate.EventIDs = append([]domain.EventID(nil), base.EventIDs...)
			test.mutate(&candidate)
			if _, err := NewW0ReceiptResultView(candidate); !errors.Is(err, ErrCanonicalProfile) {
				t.Fatalf("got %v, want catalog rejection", err)
			}
		})
	}
}

func TestReceiptResultDigestIsAcyclicAndMutationComplete(t *testing.T) {
	t.Parallel()

	fixture := newReceiptFixture(t)
	params := fixture.paramsFor(
		t, ReceiptOperationWorkspaceCreate,
		[]domain.AggregateKind{domain.AggregateKindWorkspace, domain.AggregateKindMembership}, 3, "",
	)
	codec := NewProductionCanonicalCodec()
	baseView, err := NewW0ReceiptResultView(params)
	if err != nil {
		t.Fatalf("base result: %v", err)
	}
	base, err := codec.EncodeReceiptResult(baseView)
	if err != nil {
		t.Fatalf("base document: %v", err)
	}
	if strings.Contains(string(base.CanonicalBytes()), "capsule_digest") {
		t.Fatal("receipt result digest would be cyclic through capsule digest")
	}
	if forged := (ReceiptResultDocument{document: base.document}); !forged.IsZero() {
		t.Fatal("receipt document without a cataloged operation was trusted")
	}

	mutations := []func(*W0ReceiptResultView){
		func(view *W0ReceiptResultView) {
			view.wire.AuthorityID = mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000071")
		},
		func(view *W0ReceiptResultView) {
			view.wire.AuthorityEpoch = mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000072")
		},
		func(view *W0ReceiptResultView) {
			view.wire.AcceptedAt, _ = ParseCanonicalInstant("2026-08-04T12:00:01Z")
		},
		func(view *W0ReceiptResultView) { view.wire.CommandFingerprint = mustCanonicalDigest(t, '7') },
		func(view *W0ReceiptResultView) { view.wire.AuthorizationDigest = mustCanonicalDigest(t, '8') },
		func(view *W0ReceiptResultView) { view.wire.Resources[0].Version++ },
		func(view *W0ReceiptResultView) {
			view.wire.Events.EventIDs[0] = mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000073")
		},
		func(view *W0ReceiptResultView) { view.wire.Events.FinalStreamDigest = mustCanonicalDigest(t, '9') },
	}
	for index, mutate := range mutations {
		candidate := baseView
		candidate.wire.Resources = append([]receiptResourceWire(nil), baseView.wire.Resources...)
		candidate.wire.Events.EventIDs = append([]CanonicalIdentifier(nil), baseView.wire.Events.EventIDs...)
		mutate(&candidate)
		document, mutationErr := codec.EncodeReceiptResult(candidate)
		if mutationErr != nil {
			t.Fatalf("valid mutation %d: %v", index, mutationErr)
		}
		if document.Digest() == base.Digest() {
			t.Fatalf("semantic field mutation %d did not change receipt digest", index)
		}
	}

	// The capsule-required bit is derived from the operation catalog and has
	// no caller input. Attempted post-construction drift fails before hashing.
	tampered := baseView
	tampered.wire.CapsuleRequired = false
	if _, err := codec.EncodeReceiptResult(tampered); !errors.Is(err, ErrCanonicalEncoding) {
		t.Fatalf("tampered capsule policy got %v", err)
	}
}

func TestReceiptResultReadViewIsTypedSealedAndImmutable(t *testing.T) {
	t.Parallel()
	fixture := newReceiptFixture(t)
	params := fixture.paramsFor(
		t, ReceiptOperationWorkspaceCreate,
		[]domain.AggregateKind{domain.AggregateKindWorkspace, domain.AggregateKindMembership}, 3, "",
	)
	document, err := NewProductionCanonicalCodec().EncodeReceiptResult(mustReceiptResultView(t, params))
	if err != nil {
		t.Fatal(err)
	}
	view, ok := document.ResultView()
	if !ok || view.Operation() != params.Operation || view.AuthorityID() != params.AuthorityID ||
		view.AuthorityEpoch() != params.AuthorityEpoch || view.Scope() != params.Scope ||
		!view.AcceptedAt().Equal(params.AcceptedAt) || view.FirstEventPosition() != params.FirstEventPosition ||
		view.LastEventPosition() != params.LastEventPosition || view.FinalStreamDigest() != params.FinalStreamDigest ||
		len(view.Resources()) != len(params.Resources) || len(view.EventIDs()) != len(params.EventIDs) ||
		!view.CapsuleRequired() {
		t.Fatal("receipt result read view omitted canonical mapping data")
	}
	resources := view.Resources()
	events := view.EventIDs()
	resources[0] = domain.AggregateRef{}
	events[0] = domain.EventID{}
	second, ok := document.ResultView()
	if !ok || second.Resources()[0].IsZero() || second.EventIDs()[0].IsZero() {
		t.Fatal("receipt result read view exposed mutable internals")
	}
	if _, ok := (ReceiptResultDocument{}).ResultView(); ok {
		t.Fatal("zero receipt document exposed a result view")
	}
}

func TestReceiptResultReadViewCoversAllW0CommandResults(t *testing.T) {
	t.Parallel()
	fixture := newReceiptFixture(t)
	tests := []struct {
		operation W0ReceiptOperation
		resources []domain.AggregateKind
		events    int
		ceremony  domain.CeremonyPurpose
		session   bool
	}{
		{ReceiptOperationInstallationBootstrap, []domain.AggregateKind{domain.AggregateKindPrincipal, domain.AggregateKindDevice, domain.AggregateKindGrant}, 3, "", false},
		{ReceiptOperationPrincipalRegister, []domain.AggregateKind{domain.AggregateKindPrincipal}, 1, "", false},
		{ReceiptOperationDevicePairingBegin, []domain.AggregateKind{domain.AggregateKindDevice}, 1, domain.CeremonyPurposeDevicePairing, false},
		{ReceiptOperationDevicePair, []domain.AggregateKind{domain.AggregateKindDevice}, 1, "", false},
		{ReceiptOperationWorkspaceCreate, []domain.AggregateKind{domain.AggregateKindWorkspace, domain.AggregateKindMembership}, 3, "", false},
		{ReceiptOperationWorkspaceMemberInvite, []domain.AggregateKind{domain.AggregateKindMembership}, 1, domain.CeremonyPurposeMembershipAcceptance, false},
		{ReceiptOperationWorkspaceMembershipAccept, []domain.AggregateKind{domain.AggregateKindMembership}, 1, "", false},
		{ReceiptOperationActorCreate, []domain.AggregateKind{domain.AggregateKindActor}, 1, "", false},
		{ReceiptOperationActorDelegationPropose, []domain.AggregateKind{domain.AggregateKindActorDelegation}, 1, domain.CeremonyPurposeDelegationActivation, false},
		{ReceiptOperationActorDelegationActivate, []domain.AggregateKind{domain.AggregateKindActorDelegation}, 1, domain.CeremonyPurposeActorSessionStart, false},
		{ReceiptOperationActorSessionStart, []domain.AggregateKind{domain.AggregateKindActorSession}, 1, "", true},
	}
	codec := NewProductionCanonicalCodec()
	for _, test := range tests {
		t.Run(string(test.operation), func(t *testing.T) {
			params := fixture.paramsFor(t, test.operation, test.resources, test.events, test.ceremony)
			document, err := codec.EncodeReceiptResult(mustReceiptResultView(t, params))
			if err != nil {
				t.Fatal(err)
			}
			persisted := document.CanonicalBytes()
			verified, err := codec.VerifyReceiptResult(
				persisted, document.Digest(), receiptReplayBindingForParams(t, params),
			)
			if err != nil {
				t.Fatalf("verify persisted result: %v", err)
			}
			view, ok := verified.ResultView()
			if !ok || view.Operation() != test.operation || view.AuthorityID() != params.AuthorityID ||
				view.AuthorityEpoch() != params.AuthorityEpoch || view.Scope() != params.Scope ||
				!view.AcceptedAt().Equal(params.AcceptedAt) ||
				!reflect.DeepEqual(view.Resources(), params.Resources) ||
				!reflect.DeepEqual(view.IssuedCeremonies(), params.IssuedCeremonies) ||
				view.FirstEventPosition() != params.FirstEventPosition ||
				view.LastEventPosition() != params.LastEventPosition ||
				!reflect.DeepEqual(view.EventIDs(), params.EventIDs) ||
				view.FinalStreamDigest() != params.FinalStreamDigest ||
				view.CapsuleRequired() != document.wire.CapsuleRequired {
				t.Fatal("persisted receipt did not rehydrate its complete typed result view")
			}
			binding, client, presentation, hasSession := view.Session()
			if hasSession != test.session || hasSession != (!client.IsZero() && !presentation.IsZero()) ||
				(hasSession && (!reflect.DeepEqual(binding, *params.SessionBinding) ||
					client != params.SessionClient || presentation != params.PresentationCredential)) {
				t.Fatal("session result view drift")
			}
		})
	}
}

func TestVerifyReceiptResultRejectsMalformedAndCrossBoundWire(t *testing.T) {
	t.Parallel()
	fixture := newReceiptFixture(t)
	params := fixture.paramsFor(
		t, ReceiptOperationWorkspaceCreate,
		[]domain.AggregateKind{domain.AggregateKindWorkspace, domain.AggregateKindMembership}, 3, "",
	)
	codec := NewProductionCanonicalCodec()
	document, err := codec.EncodeReceiptResult(mustReceiptResultView(t, params))
	if err != nil {
		t.Fatal(err)
	}
	binding := receiptReplayBindingForParams(t, params)
	malformed := bytes.Replace(
		document.CanonicalBytes(),
		[]byte(`"scope_id":"`+params.Scope.ID()+`"`),
		[]byte(`"scope_id":"not-a-uuid"`), 1,
	)
	if _, err := codec.VerifyReceiptResult(malformed, document.Digest(), binding); err == nil {
		t.Fatal("malformed typed scope identifier was accepted")
	}

	forgedView := mustReceiptResultView(t, params)
	forgedView.wire.Resources = append([]receiptResourceWire(nil), forgedView.wire.Resources...)
	forgedView.wire.Resources[0].ID = mustCanonicalID(t, fixture.actor.String())
	forged, err := codec.EncodeReceiptResult(forgedView)
	if err != nil {
		t.Fatalf("encode cross-bound wire fixture: %v", err)
	}
	if _, err := codec.VerifyReceiptResult(forged.CanonicalBytes(), forged.Digest(), binding); err == nil {
		t.Fatal("workspace resource forged from an actor identifier was accepted")
	}
}

func receiptReplayBindingForParams(t *testing.T, params W0ReceiptResultParams) ReceiptResultReplayBinding {
	t.Helper()
	operation, err := domain.NewOperationName(string(params.Operation))
	if err != nil {
		t.Fatal(err)
	}
	commandID, err := domain.ParseCommandID(codecUUID(900))
	if err != nil {
		t.Fatal(err)
	}
	major, err := NewOperationMajor(1)
	if err != nil {
		t.Fatal(err)
	}
	events, err := NewEventRange(params.FirstEventPosition, params.LastEventPosition, uint16(len(params.EventIDs)))
	if err != nil {
		t.Fatal(err)
	}
	requirement := RecoveryCapsuleNotApplicable
	if catalog, exists := receiptCatalog(params.Operation); exists && catalog.capsuleRequired {
		requirement = RecoveryCapsuleRequired
	}
	plan := ReceiptResultPlan{
		operation: params.Operation, commandID: commandID, operationMajor: major,
		authorityID: params.AuthorityID, authorityEpoch: params.AuthorityEpoch, scope: params.Scope,
		acceptedAt: params.AcceptedAt, commandFingerprint: params.CommandFingerprint,
		authorizationDigest: params.AuthorizationDigest,
		resources:           append([]domain.AggregateRef(nil), params.Resources...),
		issuedCeremonies:    append([]domain.CeremonyChallenge(nil), params.IssuedCeremonies...),
		eventIDs:            append([]domain.EventID(nil), params.EventIDs...),
		capsulePlan:         RecoveryCapsulePlan{requirement: requirement},
		sessionClient:       params.SessionClient, presentation: params.PresentationCredential,
		hasSession: params.SessionBinding != nil,
	}
	if params.SessionBinding != nil {
		plan.sessionBinding = *params.SessionBinding
	}
	return ReceiptResultReplayBinding{
		originalCommandID: commandID, operation: params.Operation, operationMajor: major,
		identity:           ReceiptIdentity{scope: params.Scope, operation: operation},
		requestFingerprint: params.CommandFingerprint, authorityID: params.AuthorityID,
		authorityEpoch: params.AuthorityEpoch, guardDigest: params.AuthorizationDigest,
		events: events, finalStreamDigest: params.FinalStreamDigest,
		capsulePlan: RecoveryCapsulePlan{requirement: requirement}, expectedPlan: plan,
	}
}

func mustReceiptResultView(t *testing.T, params W0ReceiptResultParams) W0ReceiptResultView {
	t.Helper()
	view, err := NewW0ReceiptResultView(params)
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func TestReceiptResultCeremonyAndSessionFieldsAreHashed(t *testing.T) {
	t.Parallel()

	fixture := newReceiptFixture(t)
	codec := NewProductionCanonicalCodec()
	inviteParams := fixture.paramsFor(
		t, ReceiptOperationWorkspaceMemberInvite,
		[]domain.AggregateKind{domain.AggregateKindMembership}, 1, domain.CeremonyPurposeMembershipAcceptance,
	)
	invite, err := NewW0ReceiptResultView(inviteParams)
	if err != nil {
		t.Fatalf("invite result: %v", err)
	}
	inviteDocument, _ := codec.EncodeReceiptResult(invite)
	ceremonyMutations := []func(*W0ReceiptResultView){
		func(view *W0ReceiptResultView) {
			view.wire.IssuedCeremonies[0].ID = mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000074")
		},
		func(view *W0ReceiptResultView) {
			view.wire.IssuedCeremonies[0].ExpiresAt, _ = ParseCanonicalInstant("2026-08-04T12:02:00Z")
		},
	}
	for index, mutate := range ceremonyMutations {
		candidate := invite
		candidate.wire.IssuedCeremonies = append([]receiptCeremonyWire(nil), invite.wire.IssuedCeremonies...)
		mutate(&candidate)
		document, mutationErr := codec.EncodeReceiptResult(candidate)
		if mutationErr != nil || document.Digest() == inviteDocument.Digest() {
			t.Fatalf("ceremony mutation %d: digest=%s err=%v", index, document.Digest(), mutationErr)
		}
	}

	sessionParams := fixture.paramsFor(
		t, ReceiptOperationActorSessionStart,
		[]domain.AggregateKind{domain.AggregateKindActorSession}, 1, "",
	)
	session, err := NewW0ReceiptResultView(sessionParams)
	if err != nil {
		t.Fatalf("session result: %v", err)
	}
	sessionDocument, _ := codec.EncodeReceiptResult(session)
	candidate := session
	bindingCopy := *session.wire.SessionBinding
	bindingCopy.ClientInstanceID = mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000075")
	candidate.wire.SessionBinding = &bindingCopy
	document, mutationErr := codec.EncodeReceiptResult(candidate)
	if mutationErr != nil || document.Digest() == sessionDocument.Digest() {
		t.Fatalf("session client mutation: digest=%s err=%v", document.Digest(), mutationErr)
	}

	crossLinked := session
	wrongDigest := *session.wire.SessionBinding
	wrongDigest.BindingDigest = mustCanonicalDigest(t, '9')
	crossLinked.wire.SessionBinding = &wrongDigest
	if _, err := codec.EncodeReceiptResult(crossLinked); !errors.Is(err, ErrCanonicalEncoding) {
		t.Fatalf("cross-linked session binding got %v", err)
	}

	missingCredential := sessionParams
	missingCredential.PresentationCredential = domain.PresentationCredentialBinding{}
	if _, err := NewW0ReceiptResultView(missingCredential); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("session without presentation credential got %v", err)
	}
	changedCredential := sessionParams
	digest, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("different presentation credential")))
	reference := sessionParams.PresentationCredential.Reference()
	audience := sessionParams.PresentationCredential.Audience()
	changedCredential.PresentationCredential, _ = domain.NewPresentationCredentialBinding(
		digest, reference, audience, domain.PresentationCredentialVersion,
	)
	changedView, err := NewW0ReceiptResultView(changedCredential)
	if err != nil || changedView.sessionBindingDigest == session.sessionBindingDigest {
		t.Fatalf("presentation credential did not bind session receipt: digest=%s error=%v", changedView.sessionBindingDigest, err)
	}
}

func TestSessionReceiptWithMaximumGrantSnapshotFitsTwoKiB(t *testing.T) {
	t.Parallel()

	fixture := newReceiptFixture(t)
	params := fixture.paramsFor(
		t, ReceiptOperationActorSessionStart,
		[]domain.AggregateKind{domain.AggregateKindActorSession}, 1, "",
	)
	base := params.SessionBinding
	grants := make([]domain.AggregateRef, 0, domain.MaxSessionGrantRevisions)
	for range domain.MaxSessionGrantRevisions {
		grantID, err := domain.NewGrantID()
		if err != nil {
			t.Fatal(err)
		}
		grants = append(grants, mustAggregateRef(t, grantID, domain.InitialVersion()))
	}
	binding, err := domain.NewSessionBinding(
		base.AuthorityID(), base.AuthorityEpoch(), base.WorkspaceID(), base.PrincipalID(), base.ActorID(),
		base.MembershipRevision(), base.DelegationRevision(), nil, domain.Version{}, grants,
		base.PolicyRevision(), base.AssuranceClass(), base.IssuedAt(), base.AbsoluteExpiry(),
	)
	if err != nil {
		t.Fatalf("maximum-grant session binding: %v", err)
	}
	params.SessionBinding = &binding
	view, err := NewW0ReceiptResultView(params)
	if err != nil {
		t.Fatalf("maximum-grant receipt view: %v", err)
	}
	document, err := NewProductionCanonicalCodec().EncodeReceiptResult(view)
	if err != nil {
		t.Fatalf("maximum-grant receipt: %v", err)
	}
	if size := len(document.CanonicalBytes()); size > MaxReceiptResultBytes {
		t.Fatalf("maximum-grant receipt is %d bytes, exceeds %d", size, MaxReceiptResultBytes)
	}
	if bytes.Contains(document.CanonicalBytes(), []byte(`"grants"`)) ||
		!bytes.Contains(document.CanonicalBytes(), []byte(`"binding_digest"`)) {
		t.Fatal("receipt must bind the full session snapshot by digest without embedding grants")
	}
}

func TestRecoveryCapsuleClosedProfileBindingAndMutations(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	plan, result := deterministicCapsulePlan(t, codec)
	view, err := NewW0RecoveryCapsuleView(
		result, plan.CommandID(), plan.OperationMajor(), plan.RecoveryCapsulePlan(),
	)
	if err != nil {
		t.Fatalf("capsule view: %v", err)
	}
	document, err := codec.EncodeRecoveryCapsule(view)
	if err != nil {
		t.Fatalf("capsule document: %v", err)
	}
	if !document.MatchesResult(result.ReceiptDocument()) || document.ResultDigest() != result.ResponseDigest() ||
		document.SigningKeyID() != plan.RecoveryCapsulePlan().KeyID() {
		t.Fatal("capsule lost its result or signing-key binding")
	}
	canonical := document.CanonicalBytes()
	wantCanonical := []byte(`{"accepted_at":"2026-08-04T12:00:00.123000Z","authority_epoch":"0198a0a0-0000-7000-8000-000000000002","authority_id":"0198a0a0-0000-7000-8000-000000000001","command_id":"0198a0a0-0000-7000-8000-000000000007","destination_snapshots":[],"effects":[],"events":{"count":3,"event_ids":["0198a0a0-0000-7000-8000-000000000008","0198a0a0-0000-7000-8000-000000000009","0198a0a0-0000-7000-8000-000000000010"],"final_stream_digest":"3685b956b18399ad2f8eccc018dd835a67a2c5758ab557e0160ebd64527d8942","first_position":41,"last_position":43},"operation":"installation.bootstrap.v1","operation_major":1,"receipt_result_digest":"a0b0f14c3fa8cbd1f74a4e3be7eee0ca39651b84fafbfb78123391653cff64c1","recipient_snapshots":[],"request_digest":"86ef5348582e42e7b7f57f66598de3ea1be1a0007cfddbba92a295fab613998e","resources":[{"id":"0198a0a0-0000-7000-8000-000000000004","kind":"principal","version":1},{"id":"0198a0a0-0000-7000-8000-000000000005","kind":"device_registration","version":1},{"id":"0198a0a0-0000-7000-8000-000000000006","kind":"grant","version":1}],"schema":"blackbird.recovery-capsule-draft/v1","scope_id":"0198a0a0-0000-7000-8000-000000000003","scope_kind":"installation","signing_key_id":"capsule-key-w0-1"}`)
	if !bytes.Equal(canonical, wantCanonical) {
		t.Fatalf("capsule golden changed:\n got %s\nwant %s", canonical, wantCanonical)
	}
	for _, forbidden := range [][]byte{[]byte(`"capsule_digest"`), []byte(`"signature"`)} {
		if bytes.Contains(canonical, forbidden) {
			t.Fatalf("cyclic or post-commit field entered capsule draft: %s", forbidden)
		}
	}

	mutations := []func(*W0RecoveryCapsuleView){
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.Schema = "blackbird.recovery-capsule-draft/v2" },
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.Operation = string(ReceiptOperationActorCreate) },
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.OperationMajor++ },
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.CommandID = mustCanonicalID(t, codecUUID(20)) },
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.AuthorityID = mustCanonicalID(t, codecUUID(21)) },
		func(candidate *W0RecoveryCapsuleView) {
			candidate.wire.AuthorityEpoch = mustCanonicalID(t, codecUUID(22))
		},
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.ScopeKind = string(domain.ScopeKindWorkspace) },
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.ScopeID = mustCanonicalID(t, codecUUID(23)) },
		func(candidate *W0RecoveryCapsuleView) {
			candidate.wire.AcceptedAt, _ = ParseCanonicalInstant("2026-08-04T12:00:01.123000Z")
		},
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.SigningKeyID = "capsule-key-w0-2" },
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.Resources[0].Version++ },
		func(candidate *W0RecoveryCapsuleView) {
			candidate.wire.RecipientSnapshots = append(candidate.wire.RecipientSnapshots, mustCanonicalDigest(t, '5'))
		},
		func(candidate *W0RecoveryCapsuleView) {
			candidate.wire.DestinationSnapshots = append(candidate.wire.DestinationSnapshots, mustCanonicalDigest(t, '6'))
		},
		func(candidate *W0RecoveryCapsuleView) {
			candidate.wire.Effects = append(candidate.wire.Effects, recoveryCapsuleEffectWire{})
		},
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.RequestDigest = mustCanonicalDigest(t, '8') },
		func(candidate *W0RecoveryCapsuleView) {
			candidate.wire.ReceiptResultDigest = mustCanonicalDigest(t, '9')
		},
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.Events.FirstPosition++ },
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.Events.LastPosition++ },
		func(candidate *W0RecoveryCapsuleView) { candidate.wire.Events.Count-- },
		func(candidate *W0RecoveryCapsuleView) {
			candidate.wire.Events.EventIDs[0] = mustCanonicalID(t, codecUUID(24))
		},
		func(candidate *W0RecoveryCapsuleView) {
			candidate.wire.Events.FinalStreamDigest = mustCanonicalDigest(t, '7')
		},
	}
	for index, mutate := range mutations {
		candidate := view
		candidate.wire.Resources = append([]receiptResourceWire(nil), view.wire.Resources...)
		candidate.wire.Events.EventIDs = append([]CanonicalIdentifier(nil), view.wire.Events.EventIDs...)
		mutate(&candidate)
		mutated, mutationErr := codec.EncodeRecoveryCapsule(candidate)
		if mutationErr == nil && mutated.Digest() == document.Digest() {
			t.Fatalf("capsule mutation %d did not reject or change digest", index)
		}
	}

	verifiedResult, err := codec.VerifyReceiptResult(
		result.CanonicalBytes(), result.ResponseDigest(), replayBindingFromPlan(t, plan, result),
	)
	if err != nil {
		t.Fatalf("verify retained result: %v", err)
	}
	verifiedCapsule, err := codec.VerifyRecoveryCapsule(
		canonical, document.Digest(), verifiedResult, replayBindingFromPlan(t, plan, result),
	)
	if err != nil || !verifiedCapsule.MatchesResult(verifiedResult.ReceiptDocument()) {
		t.Fatalf("verify retained capsule: %v", err)
	}
}

func replayBindingFromPlan(
	t *testing.T,
	plan ReceiptResultPlan,
	result ResultEnvelope,
) ReceiptResultReplayBinding {
	t.Helper()
	operation, err := domain.NewOperationName(string(plan.Operation()))
	if err != nil {
		t.Fatal(err)
	}
	wire := result.ReceiptDocument().wire
	first, _ := domain.NewStreamPosition(wire.Events.FirstPosition)
	last, _ := domain.NewStreamPosition(wire.Events.LastPosition)
	events, err := NewEventRange(first, last, wire.Events.Count)
	if err != nil {
		t.Fatal(err)
	}
	finalBytes, _ := hex.DecodeString(wire.Events.FinalStreamDigest.String())
	var finalArray [sha256.Size]byte
	copy(finalArray[:], finalBytes)
	finalDigest, _ := domain.NewStreamDigest(finalArray)
	return ReceiptResultReplayBinding{
		originalCommandID: plan.CommandID(), operation: plan.Operation(), operationMajor: plan.OperationMajor(),
		identity:           ReceiptIdentity{scope: plan.Scope(), operation: operation},
		requestFingerprint: plan.CommandFingerprint(), authorityID: plan.AuthorityID(),
		authorityEpoch: plan.AuthorityEpoch(), guardDigest: plan.AuthorizationDigest(),
		events: events, finalStreamDigest: finalDigest, capsulePlan: plan.RecoveryCapsulePlan(),
		expectedPlan: cloneReceiptResultPlan(plan),
	}
}

func deterministicCapsulePlan(t *testing.T, codec ProductionCanonicalCodec) (ReceiptResultPlan, ResultEnvelope) {
	t.Helper()
	authority, _ := domain.ParseAuthorityID(codecUUID(1))
	epoch, _ := domain.ParseAuthorityEpoch(codecUUID(2))
	installation, _ := domain.ParseInstallationID(codecUUID(3))
	principal, _ := domain.ParsePrincipalID(codecUUID(4))
	device, _ := domain.ParseDeviceID(codecUUID(5))
	grant, _ := domain.ParseGrantID(codecUUID(6))
	commandID, _ := domain.ParseCommandID(codecUUID(7))
	eventOne, _ := domain.ParseEventID(codecUUID(8))
	eventTwo, _ := domain.ParseEventID(codecUUID(9))
	eventThree, _ := domain.ParseEventID(codecUUID(10))
	scope, _ := domain.InstallationScope(installation)
	major, _ := NewOperationMajor(1)
	authorization, _ := domain.NewAuthorizationDigest(sha256.Sum256([]byte("capsule authorization")))
	resources := []domain.AggregateRef{
		mustAggregateRef(t, principal, domain.InitialVersion()),
		mustAggregateRef(t, device, domain.InitialVersion()),
		mustAggregateRef(t, grant, domain.InitialVersion()),
	}
	plan := ReceiptResultPlan{
		operation: ReceiptOperationInstallationBootstrap, commandID: commandID, operationMajor: major,
		authorityID: authority, authorityEpoch: epoch, scope: scope,
		acceptedAt:          time.Date(2026, 8, 4, 12, 0, 0, 123_000_000, time.UTC),
		commandFingerprint:  domain.FingerprintCommand([]byte("capsule request")),
		authorizationDigest: authorization, resources: resources,
		eventIDs:    []domain.EventID{eventOne, eventTwo, eventThree},
		capsulePlan: RecoveryCapsulePlan{requirement: RecoveryCapsuleRequired, keyID: "capsule-key-w0-1"},
	}
	first, _ := domain.NewStreamPosition(41)
	last, _ := domain.NewStreamPosition(43)
	finalDigest, _ := domain.NewStreamDigest(sha256.Sum256([]byte("capsule final stream")))
	result, err := codec.MaterializeReceiptResult(plan, first, last, finalDigest)
	if err != nil {
		t.Fatalf("materialize deterministic result: %v", err)
	}
	return plan, result
}

func codecUUID(index int) string {
	return fmt.Sprintf("0198a0a0-0000-7000-8000-%012d", index)
}

func TestBootstrapAttemptMutationAndGoldenVector(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	id := mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000001")
	digests := []CanonicalDigest{
		mustCanonicalDigest(t, '1'), mustCanonicalDigest(t, '2'), mustCanonicalDigest(t, '3'),
		mustCanonicalDigest(t, '4'), mustCanonicalDigest(t, '5'),
	}
	base, err := NewBootstrapAttemptViewV1(id, digests[0], digests[1], digests[2], digests[3], digests[4])
	if err != nil {
		t.Fatalf("new attempt: %v", err)
	}
	baseline, err := codec.HashBootstrapAttempt(base)
	if err != nil {
		t.Fatalf("hash attempt: %v", err)
	}
	if baseline.String() != "274a2f33cbc0bc66ea7786b8bfe9167a9f716527dd7ef41faffcedb70b5b7d33" {
		t.Fatalf("bootstrap golden changed: %s", baseline.String())
	}

	mutations := []func(*BootstrapAttemptViewV1){
		func(view *BootstrapAttemptViewV1) {
			view.InvitationID = mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000002")
		},
		func(view *BootstrapAttemptViewV1) { view.TranscriptHash = mustCanonicalDigest(t, 'a') },
		func(view *BootstrapAttemptViewV1) { view.ClientNonceDigest = mustCanonicalDigest(t, 'b') },
		func(view *BootstrapAttemptViewV1) { view.ServerNonceDigest = mustCanonicalDigest(t, 'c') },
		func(view *BootstrapAttemptViewV1) { view.ChannelBindingDigest = mustCanonicalDigest(t, 'd') },
		func(view *BootstrapAttemptViewV1) { view.PresentedProofDigest = mustCanonicalDigest(t, 'e') },
	}
	for index, mutate := range mutations {
		candidate := base
		mutate(&candidate)
		digest, hashErr := codec.HashBootstrapAttempt(candidate)
		if hashErr != nil {
			t.Fatalf("mutation %d: %v", index, hashErr)
		}
		if digest == baseline {
			t.Fatalf("mutation %d did not change digest", index)
		}
	}
}

func TestProductionGuardDenialAndCapsuleCompositionGoldens(t *testing.T) {
	t.Parallel()

	fixture := buildBootstrapFixture(t)
	evidence, err := NewAppliedGuardEvidence(fixture.spec.Guards(), fixture.spec.Guards().Evidence())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := evidence.Digest().String(), "f341b7e664572cd63048d88f628f3a7e078462c54a6d58ecd109d3b60f5024be"; got != want {
		t.Fatalf("actual guard-set golden: got %s, want %s", got, want)
	}
	changedPlan := fixture.spec.Guards()
	changedPlan.admissionGeneration, _ = NewGuardGeneration(changedPlan.admissionGeneration.Uint64() + 1)
	changedEvidence, err := NewAppliedGuardEvidence(changedPlan, changedPlan.Evidence())
	if err != nil || changedEvidence.Digest() == evidence.Digest() {
		t.Fatalf("one-field guard mutation was not bound: %v", err)
	}

	major, _ := NewOperationMajor(1)
	subject, _ := UnattributedDenialSource(DigestBytes([]byte("codec denial source")))
	draft, err := NewCommandDenialDraft(
		fixture.spec.Operation(), major, DenialAuthentication, "credential_rejected",
		fixture.spec.RequestFingerprint(), subject, nil, fixture.correlation,
	)
	if err != nil {
		t.Fatal(err)
	}
	denialSpec, err := RecordCommandDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch,
		fixture.spec.Guards().AdmissionGeneration(), draft,
	)
	if err != nil {
		t.Fatal(err)
	}
	denial, _ := denialSpec.CommandDenial()
	if got, want := denial.DenialFingerprint().String(), "26c68f93ed1856b5436cbdde12043040297703a5e7c9a1eb16138ff18de1cfbd"; got != want {
		t.Fatalf("command-denial draft golden: got %s, want %s", got, want)
	}
	changedDraft := draft
	changedDraft.reason = "credential_stale"
	changedSpec, err := RecordCommandDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch,
		fixture.spec.Guards().AdmissionGeneration(), changedDraft,
	)
	changedDenial, _ := changedSpec.CommandDenial()
	if err != nil || changedDenial.DenialFingerprint() == denial.DenialFingerprint() {
		t.Fatalf("one-field command-denial mutation was not bound: %v", err)
	}

	capsule := mustCapsuleDraft(
		t, fixture.resultRecord, fixture.command, fixture.spec.OperationMajor(), fixture.spec.RecoveryCapsule().KeyID(),
	)
	message, err := RecoveryCapsuleSigningMessage(capsule.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(message), "626c61636b626972642d7265636f766572792d63617073756c652d7369676e61747572652f7631006effb009718c33f23eca608ea7635b569aef6ccfe62fe51d645d93cd7dd6f23a"; got != want {
		t.Fatalf("capsule signature-input golden: got %s, want %s", got, want)
	}
	envelope, err := SignRecoveryCapsule(
		context.Background(), fixture.spec.RecoveryCapsule(), fixture.capsuleSigner, *capsule,
	)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Draft().Digest() != capsule.Digest() || envelope.Draft().ResultDigest() != fixture.resultRecord.ResponseDigest() ||
		envelope.Schema() != RecoveryCapsuleEnvelopeSchema || envelope.Algorithm() != RecoveryCapsuleSignatureAlgorithm ||
		envelope.SigningKeyID() != capsule.KeyID() {
		t.Fatal("capsule envelope lost draft, result, schema, algorithm, or key binding")
	}
	if got, want := envelope.SignatureBase64URL(), "oYIQykc7wJGhIG_xpQYbqmHMlfNb092VjzoSVsqT-HZTQbg_lHco8ON_7zc1NIQaCJAdetnCeGN95xnyFSFoAQ"; got != want {
		t.Fatalf("capsule envelope signature golden: got %s, want %s", got, want)
	}
	message[0] ^= 1
	if bytes.Equal(message, mustSigningMessage(t, capsule.Digest())) {
		t.Fatal("signature-input mutation was not observable")
	}
}

func mustSigningMessage(t *testing.T, digest Digest) []byte {
	t.Helper()
	message, err := RecoveryCapsuleSigningMessage(digest)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func TestDomainSeparatedProfilesAndStreamGoldens(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	view := allProfileView{Count: 7, Label: "same typed bytes"}
	command, err := codec.HashCommand(view)
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	authorization, err := codec.HashAuthorizationGuards(view)
	if err != nil {
		t.Fatalf("authorization: %v", err)
	}
	receipt, err := codec.hashTyped(receiptResultDomain, view, MaxReceiptResultBytes)
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	capsule, err := codec.hashTyped(recoveryCapsuleDomain, view, MaxRecoveryCapsuleBytes)
	if err != nil {
		t.Fatalf("capsule: %v", err)
	}
	denial, err := codec.HashCommandDenial(view)
	if err != nil {
		t.Fatalf("denial: %v", err)
	}
	bootstrap, err := codec.HashBootstrapAttempt(view)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	event, err := codec.HashEvent(view)
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	audit, err := codec.HashAuditEntry(view)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	encoded := []string{
		hex.EncodeToString(command[:]), authorization.String(), receipt.String(), capsule.String(),
		denial.String(), bootstrap.String(), event.String(), audit.String(),
	}
	wantEncoded := []string{
		"911e1d8a90ddf2dc7fda7604e01b1d3d2edad446a160447b9280baa6210211bb",
		"00abbaa57da6f702e48404031caa2bdabdf4e4f01664f16f0d68cdd7525ba363",
		"8de22752dd5835b30e7035aadb5a813896ead6900e6548df046851f087c4c879",
		"9fe52e1b8db13e9d11210b02c711998c89dd11ede96f416095f3842d8e2c0b30",
		"ff21c7bd36727ef307b035927077176bbde0f5265595cfcbb96af9ba071b1ef4",
		"06adae692c0994a3060e5c9b6be2cda403ec964a33aa58bb778bd2f3ef2a0c36",
		"5cfd8176edb94b2067c3f888b8228a1c5bd7bc43f6abe2e3685a48bd0dc20fde",
		"9422e683e96ff7185ee9565c04eabfe675be039b70f489cad7f6196310e7d683",
	}
	seen := make(map[string]struct{}, len(encoded))
	for index, digest := range encoded {
		if digest != wantEncoded[index] {
			t.Fatalf("profile %d golden changed: got %s, want %s", index, digest, wantEncoded[index])
		}
		if _, duplicate := seen[digest]; duplicate {
			t.Fatalf("domain separation collision for %s", digest)
		}
		seen[digest] = struct{}{}
	}

	authorityID := mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000010")
	epoch := mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000011")
	scopeID := mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000012")
	genesisView, err := NewStreamGenesisViewV1(authorityID, epoch, StreamScopeWorkspace, scopeID, nil)
	if err != nil {
		t.Fatalf("genesis view: %v", err)
	}
	canonical, err := codec.EncodeCanonical(genesisView)
	if err != nil {
		t.Fatalf("encode genesis: %v", err)
	}
	wantCanonical := `{"authority_epoch":"0198a0a0-0000-7000-8000-000000000011","authority_id":"0198a0a0-0000-7000-8000-000000000010","predecessor_transition_digest":null,"scope_id":"0198a0a0-0000-7000-8000-000000000012","scope_kind":"workspace"}`
	if string(canonical) != wantCanonical {
		t.Fatalf("genesis bytes:\n got %s\nwant %s", canonical, wantCanonical)
	}
	genesis, err := codec.HashStreamGenesis(genesisView)
	if err != nil {
		t.Fatalf("hash genesis: %v", err)
	}
	if genesis.String() != "665b9fbbe69e87d7bd53f9228af1533858139769a09ff2adb082bd2bce982ea9" {
		t.Fatalf("genesis golden changed: %s", genesis.String())
	}
	predecessor := mustCanonicalDigest(t, 'f')
	genesisMutations := []func(*StreamGenesisViewV1){
		func(view *StreamGenesisViewV1) {
			view.AuthorityID = mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000020")
		},
		func(view *StreamGenesisViewV1) {
			view.AuthorityEpoch = mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000021")
		},
		func(view *StreamGenesisViewV1) { view.ScopeKind = StreamScopeInstallation },
		func(view *StreamGenesisViewV1) {
			view.ScopeID = mustCanonicalID(t, "0198a0a0-0000-7000-8000-000000000022")
		},
		func(view *StreamGenesisViewV1) { view.PredecessorTransitionDigest = &predecessor },
	}
	for index, mutate := range genesisMutations {
		candidate := genesisView
		mutate(&candidate)
		mutated, mutationErr := codec.HashStreamGenesis(candidate)
		if mutationErr != nil {
			t.Fatalf("genesis mutation %d: %v", index, mutationErr)
		}
		if mutated == genesis {
			t.Fatalf("genesis mutation %d did not change digest", index)
		}
	}

	position, _ := domain.NewStreamPosition(1)
	eventDigest, _ := domain.NewEventDigest(sha256.Sum256([]byte("event golden")))
	chained, err := codec.ChainStreamDigest(genesis, position, eventDigest)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if chained.String() != "093aaf789ef3c93d713d3ae963c2d68eb69d32287443eb6a6448920d8dca5d3a" {
		t.Fatalf("chain golden changed: %s", chained.String())
	}
	if codec.AuditGenesisPreviousHash() != [sha256.Size]byte{} {
		t.Fatal("audit genesis is not the all-zero predecessor")
	}
}

func TestValidateCanonicalBytesRequiresCanonicalRepresentation(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	if err := codec.ValidateCanonicalBytes([]byte(`{"a":1,"b":2}`), MaxCanonicalJSONBytes); err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	if err := codec.ValidateCanonicalBytes([]byte(`{ "b":2, "a":1 }`), MaxCanonicalJSONBytes); !errors.Is(err, ErrCanonicalEncoding) {
		t.Fatalf("noncanonical bytes got %v", err)
	}
}

func TestProductionEventSemanticMaterializationAndVerification(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	eventID, _ := domain.ParseEventID(codecUUID(101))
	commandID, _ := domain.ParseCommandID(codecUUID(102))
	authorityID, _ := domain.ParseAuthorityID(codecUUID(103))
	epoch, _ := domain.ParseAuthorityEpoch(codecUUID(104))
	workspaceID, _ := domain.ParseWorkspaceID(codecUUID(105))
	membershipID, _ := domain.ParseMembershipID(codecUUID(106))
	principalID, _ := domain.ParsePrincipalID(codecUUID(107))
	receiptID, _ := domain.ParseReceiptID(codecUUID(108))
	correlationID, _ := domain.ParseCorrelationID(codecUUID(109))
	scope, _ := domain.WorkspaceScope(workspaceID)
	aggregate := mustAggregateRef(t, membershipID, domain.InitialVersion())
	position, _ := domain.NewStreamPosition(7)
	schema, _ := domain.NewEventSchemaVersion(1)
	payload, err := domain.NewEventPayload([]byte(`{"membership_id":"0198a0a0-0000-7000-8000-000000000106","principal_id":"0198a0a0-0000-7000-8000-000000000107","workspace_id":"0198a0a0-0000-7000-8000-000000000105"}`))
	if err != nil {
		t.Fatal(err)
	}
	previous, _ := domain.NewStreamDigest(sha256.Sum256([]byte("event previous")))
	placeholderEvent, _ := domain.NewEventDigest(sha256.Sum256([]byte("event placeholder")))
	placeholderStream, _ := domain.NewStreamDigest(sha256.Sum256([]byte("stream placeholder")))
	authorization, _ := domain.NewAuthorizationDigest(sha256.Sum256([]byte("event authorization")))
	params := domain.EventEnvelopeParams{
		EventID: eventID, CommandID: commandID, AuthorityID: authorityID, AuthorityEpoch: epoch,
		Scope: scope, StreamPosition: position, PreviousStreamDigest: previous,
		EventDigest: placeholderEvent, StreamDigest: placeholderStream, Aggregate: aggregate,
		EventType: domain.EventTypeWorkspaceMembershipAccepted, SchemaVersion: schema, Payload: payload,
		PrincipalID: principalID, AuthorizationDigest: authorization, CommandReceiptID: receiptID,
		CorrelationID: correlationID, RecordedAt: time.Date(2026, 8, 5, 12, 0, 0, 123_000_000, time.UTC),
	}
	unverified, err := domain.NewEventEnvelope(params, permissiveEventVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	view, err := eventSemanticView(unverified)
	if err != nil {
		t.Fatal(err)
	}
	eventDigest, err := codec.HashEvent(view)
	if err != nil {
		t.Fatal(err)
	}
	streamDigest, err := codec.ChainStreamDigest(previous, position, eventDigest)
	if err != nil {
		t.Fatal(err)
	}
	params.EventDigest = eventDigest
	params.StreamDigest = streamDigest
	trusted, err := codec.MaterializeEvent(params)
	if err != nil {
		t.Fatalf("production verifier rejected valid event: %v", err)
	}
	if trusted.EventDigest() != eventDigest || trusted.StreamDigest() != streamDigest {
		t.Fatal("trusted event lost verified digests")
	}
	autoParams := params
	autoParams.EventDigest = domain.EventDigest{}
	autoParams.StreamDigest = domain.StreamDigest{}
	automaticallyMaterialized, err := codec.MaterializeIdentityEvent(autoParams)
	if err != nil {
		t.Fatalf("production materialization failed: %v", err)
	}
	if automaticallyMaterialized.EventDigest() != eventDigest || automaticallyMaterialized.StreamDigest() != streamDigest {
		t.Fatal("production materialization computed different digests")
	}
	if _, err := codec.MaterializeIdentityEvent(params); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("production materialization accepted caller-supplied digests: %v", err)
	}
	params.EventDigest = placeholderEvent
	if _, err := codec.MaterializeEvent(params); !errors.Is(err, domain.ErrEventDigestVerification) {
		t.Fatalf("semantic digest tamper got %v", err)
	}
	params.EventDigest = eventDigest
	params.StreamDigest = placeholderStream
	if _, err := codec.MaterializeEvent(params); !errors.Is(err, domain.ErrEventDigestVerification) {
		t.Fatalf("stream digest tamper got %v", err)
	}

	params.StreamDigest = streamDigest
	schema2, _ := domain.NewEventSchemaVersion(2)
	params.SchemaVersion = schema2
	schemaEvent, err := domain.NewEventEnvelope(params, permissiveEventVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = eventSemanticView(schemaEvent); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("unsupported event schema got %v", err)
	}

	params.SchemaVersion = schema
	otherMembership, _ := domain.ParseMembershipID(codecUUID(110))
	params.Aggregate = mustAggregateRef(t, otherMembership, domain.InitialVersion())
	originEvent, err := domain.NewEventEnvelope(params, permissiveEventVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = eventSemanticView(originEvent); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("payload/aggregate mismatch got %v", err)
	}

	otherWorkspace, _ := domain.ParseWorkspaceID(codecUUID(111))
	params.Aggregate = aggregate
	params.Scope, _ = domain.WorkspaceScope(otherWorkspace)
	scopeEvent, err := domain.NewEventEnvelope(params, permissiveEventVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = eventSemanticView(scopeEvent); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("payload/scope mismatch got %v", err)
	}
}

func TestProductionCompositionCannotSubstitutePermissiveEventVerifier(t *testing.T) {
	t.Parallel()

	params := validProductionEventParams(t)
	if _, err := domain.NewEventEnvelope(params, permissiveEventVerifier{}); err != nil {
		t.Fatalf("permissive domain test seam rejected fixture: %v", err)
	}
	if _, err := NewProductionCanonicalCodec().MaterializeEvent(params); !errors.Is(err, domain.ErrEventDigestVerification) {
		t.Fatalf("production construction boundary accepted permissive digests: %v", err)
	}
}

func validProductionEventParams(t *testing.T) domain.EventEnvelopeParams {
	t.Helper()
	eventID, _ := domain.ParseEventID(codecUUID(301))
	commandID, _ := domain.ParseCommandID(codecUUID(302))
	authorityID, _ := domain.ParseAuthorityID(codecUUID(303))
	epoch, _ := domain.ParseAuthorityEpoch(codecUUID(304))
	workspaceID, _ := domain.ParseWorkspaceID(codecUUID(305))
	membershipID, _ := domain.ParseMembershipID(codecUUID(306))
	principalID, _ := domain.ParsePrincipalID(codecUUID(307))
	receiptID, _ := domain.ParseReceiptID(codecUUID(308))
	correlationID, _ := domain.ParseCorrelationID(codecUUID(309))
	scope, _ := domain.WorkspaceScope(workspaceID)
	position, _ := domain.NewStreamPosition(1)
	schema, _ := domain.NewEventSchemaVersion(1)
	payload, _ := domain.NewEventPayload([]byte(fmt.Sprintf(
		`{"membership_id":%q,"principal_id":%q,"workspace_id":%q}`,
		membershipID.String(), principalID.String(), workspaceID.String(),
	)))
	previous, _ := domain.NewStreamDigest(sha256.Sum256([]byte("production composition predecessor")))
	eventDigest, _ := domain.NewEventDigest(sha256.Sum256([]byte("permissive semantic digest")))
	streamDigest, _ := domain.NewStreamDigest(sha256.Sum256([]byte("permissive stream digest")))
	authorization, _ := domain.NewAuthorizationDigest(sha256.Sum256([]byte("production composition authorization")))
	return domain.EventEnvelopeParams{
		EventID: eventID, CommandID: commandID, AuthorityID: authorityID, AuthorityEpoch: epoch,
		Scope: scope, StreamPosition: position, PreviousStreamDigest: previous,
		EventDigest: eventDigest, StreamDigest: streamDigest,
		Aggregate: mustAggregateRef(t, membershipID, domain.InitialVersion()),
		EventType: domain.EventTypeWorkspaceMembershipAccepted, SchemaVersion: schema, Payload: payload,
		PrincipalID: principalID, AuthorizationDigest: authorization, CommandReceiptID: receiptID,
		CorrelationID: correlationID, RecordedAt: time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC),
	}
}

func TestW0IdentityFactPayloadRetainedGoldensAndMutations(t *testing.T) {
	t.Parallel()

	path := buildOperationDomainPath(t)
	results := [][]domain.IdentityFact{
		path.bootstrap.Facts(), path.registered.Facts(), path.createdWorkspace.Facts(), path.invited.Facts(),
		path.accepted.Facts(), path.createdActor.Facts(), path.proposed.Facts(), path.activated.Facts(),
		path.pairingBegan.Facts(), path.paired.Facts(), path.sessionStarted.Facts(),
	}
	facts := make(map[domain.EventType]domain.IdentityFact, 11)
	for _, result := range results {
		for _, fact := range result {
			facts[fact.Type()] = fact
		}
	}
	want := map[domain.EventType]string{
		domain.EventTypeInstallationBootstrapped:    `{"device_id":"01b8e094-9888-7000-8000-000000000006","grant_id":"01b8e094-9888-7000-8000-000000000007","installation_id":"01b8e094-9888-7000-8000-000000000001","invitation_id":"01b8e094-9888-7000-8000-000000000004","principal_id":"01b8e094-9888-7000-8000-000000000005","transcript_fingerprint":"d3d4fd8c6dd4628838f1cfa3580434d0b7743e49cc1603f058aa7b13102ddd62"}`,
		domain.EventTypePrincipalRegistered:         `{"display_name":"Matrix workload","installation_id":"01b8e094-9888-7000-8000-000000000001","kind":"workload","principal_id":"01b8e094-9888-7000-8000-0000000000c9","public_key_reference":"keyref:matrix-workload"}`,
		domain.EventTypeDevicePairingBegan:          `{"ceremony_id":"01b8e094-9888-7000-8000-0000000000d3","device_id":"01b8e094-9888-7000-8000-0000000000d2","display_name":"Matrix paired device","installation_id":"01b8e094-9888-7000-8000-000000000001","principal_id":"01b8e094-9888-7000-8000-000000000005","public_key_reference":"keyref:matrix-paired-device"}`,
		domain.EventTypeDevicePaired:                `{"credential_activated_at":"2026-08-04T12:05:00.123456Z","credential_algorithm":"ed25519-spki-sha256-v1","credential_transcript_fingerprint":"a9045e7f47d07506ccc5cfb3dab496061f03a332f1ae90027e76f84482efdbb0","device_id":"01b8e094-9888-7000-8000-0000000000d2","display_name":"Matrix paired device","installation_id":"01b8e094-9888-7000-8000-000000000001","principal_id":"01b8e094-9888-7000-8000-000000000005","public_key_reference":"keyref:matrix-paired-device","revocation_revision":1,"spki_fingerprint":"fbe1adfd69025abac14d242cadf1693a09a2e548cd22926fe5afa8e59a1204e6","transcript_fingerprint":"a9045e7f47d07506ccc5cfb3dab496061f03a332f1ae90027e76f84482efdbb0","trust_revision":2}`,
		domain.EventTypeWorkspaceCreated:            `{"alias":"matrix-workspace","authority_epoch":"01b8e094-9888-7000-8000-000000000003","authority_id":"01b8e094-9888-7000-8000-000000000002","discovery_locator":"workspace://matrix","policy_revision":"policy:matrix:v1","workspace_id":"01b8e094-9888-7000-8000-0000000000ca"}`,
		domain.EventTypeWorkspaceMemberInvited:      `{"capabilities":["workspace:owner"],"ceremony_id":"01b8e094-9888-7000-8000-0000000000cd","membership_id":"01b8e094-9888-7000-8000-0000000000cc","principal_id":"01b8e094-9888-7000-8000-0000000000c9","workspace_id":"01b8e094-9888-7000-8000-0000000000ca"}`,
		domain.EventTypeWorkspaceMembershipAccepted: `{"membership_id":"01b8e094-9888-7000-8000-0000000000cc","principal_id":"01b8e094-9888-7000-8000-0000000000c9","workspace_id":"01b8e094-9888-7000-8000-0000000000ca"}`,
		domain.EventTypeActorCreated:                `{"actor_id":"01b8e094-9888-7000-8000-0000000000ce","display_name":"Matrix agent","kind":"agent","workspace_id":"01b8e094-9888-7000-8000-0000000000ca"}`,
		domain.EventTypeActorDelegationProposed:     `{"actor_id":"01b8e094-9888-7000-8000-0000000000ce","ceremony_id":"01b8e094-9888-7000-8000-0000000000d0","delegation_id":"01b8e094-9888-7000-8000-0000000000cf","principal_id":"01b8e094-9888-7000-8000-0000000000c9","workspace_id":"01b8e094-9888-7000-8000-0000000000ca"}`,
		domain.EventTypeActorDelegationActivated:    `{"actor_id":"01b8e094-9888-7000-8000-0000000000ce","delegation_id":"01b8e094-9888-7000-8000-0000000000cf","principal_id":"01b8e094-9888-7000-8000-0000000000c9","session_start_ceremony_id":"01b8e094-9888-7000-8000-0000000000d1","workspace_id":"01b8e094-9888-7000-8000-0000000000ca"}`,
		domain.EventTypeActorSessionStarted:         `{"binding_digest":"5d24033b6f989eb36518c69c92e77e4467a3fe83ebc0f44c4a630b80e9b56e1c","capabilities":["workspace:owner"],"client_instance_id":"01b8e094-9888-7000-8000-0000000000d5","client_name":"matrix-agent","client_version":"1.0.0","presentation_credential_audience":"blackbird:matrix","presentation_credential_digest":"da08299fd7e136e50b525d31f7baafd565369992279752b6561a6cae1ca57e6b","presentation_credential_reference":"credential-ref:matrix-session","presentation_credential_version":1,"session_id":"01b8e094-9888-7000-8000-0000000000d4","workspace_id":"01b8e094-9888-7000-8000-0000000000ca"}`,
	}
	if len(facts) != len(want) {
		t.Fatalf("production path produced %d distinct W0 fact payloads, want %d", len(facts), len(want))
	}
	codec := NewProductionCanonicalCodec()
	for eventType, expected := range want {
		fact := facts[eventType]
		t.Run(string(eventType), func(t *testing.T) {
			payload, err := codec.MaterializeIdentityFactPayload(fact)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(payload.Bytes()); got != expected {
				t.Fatalf("fact payload golden: got %s, want %s", got, expected)
			}
			view, err := identityFactPayloadView(fact)
			if err != nil {
				t.Fatal(err)
			}
			mutated := mutateIdentityFactPayloadView(t, view)
			canonical, err := codec.EncodeCanonical(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(canonical, payload.Bytes()) {
				t.Fatal("one-field fact payload mutation did not change canonical bytes")
			}
		})
	}
}

func TestBootstrapAndWorkspaceOwnerFactPayloadGoldens(t *testing.T) {
	t.Parallel()
	codec := NewProductionCanonicalCodec()
	fixture := buildBootstrapFixture(t)
	principalPayload, err := codec.MaterializeIdentityFactPayload(fixture.result.Facts()[1])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(principalPayload.Bytes()), `{"display_name":"Owner","installation_id":"01b8e094-9888-7000-8000-000000000001","kind":"human","principal_id":"01b8e094-9888-7000-8000-000000000005","public_key_reference":null}`; got != want {
		t.Fatalf("bootstrap human-principal payload:\n got %s\nwant %s", got, want)
	}
	path := buildOperationDomainPath(t)
	ownerMembershipPayload, err := codec.MaterializeIdentityFactPayload(path.createdWorkspace.Facts()[1])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(ownerMembershipPayload.Bytes()), `{"capabilities":["actor:admin","delegation:admin","device:pair","membership:admin","workspace:owner"],"ceremony_id":null,"membership_id":"01b8e094-9888-7000-8000-0000000000cb","principal_id":"01b8e094-9888-7000-8000-000000000005","workspace_id":"01b8e094-9888-7000-8000-0000000000ca"}`; got != want {
		t.Fatalf("workspace-owner membership payload:\n got %s\nwant %s", got, want)
	}
}

func mutateIdentityFactPayloadView(t *testing.T, view IdentityFactPayloadView) IdentityFactPayloadView {
	t.Helper()
	mutatedID := mustCanonicalID(t, codecUUID(399))
	switch value := view.(type) {
	case identityPayloadInstallationBootstrapped:
		value.InstallationID = mutatedID
		return value
	case identityPayloadPrincipalRegistered:
		value.InstallationID = mutatedID
		return value
	case identityPayloadDevicePairingBegan:
		value.InstallationID = mutatedID
		return value
	case identityPayloadDevicePaired:
		value.InstallationID = mutatedID
		return value
	case identityPayloadWorkspaceCreated:
		value.WorkspaceID = mutatedID
		return value
	case identityPayloadWorkspaceMemberInvited:
		value.WorkspaceID = mutatedID
		return value
	case identityPayloadWorkspaceMembershipAccepted:
		value.WorkspaceID = mutatedID
		return value
	case identityPayloadActorCreated:
		value.WorkspaceID = mutatedID
		return value
	case identityPayloadActorDelegationProposed:
		value.WorkspaceID = mutatedID
		return value
	case identityPayloadActorDelegationActivated:
		value.WorkspaceID = mutatedID
		return value
	case identityPayloadActorSessionStarted:
		value.WorkspaceID = mutatedID
		return value
	default:
		t.Fatalf("unreviewed identity payload view %T", view)
		return nil
	}
}

func TestIdentityFactMaterializationRejectsTypedNil(t *testing.T) {
	t.Parallel()
	var fact *domain.InstallationBootstrappedFact
	if _, err := NewProductionCanonicalCodec().MaterializeIdentityFactPayload(fact); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("typed-nil fact error = %v", err)
	}
}

func TestAuditEntryGoldenAndAdversarialVerification(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	fixture := buildBootstrapFixture(t)
	authority, epoch, scope := fixture.authority, fixture.epoch, fixture.scope
	intent := fixture.decision.Audit()
	view, err := NewAuditEntryViewV1(AuditEntryParams{
		ChainScopeID: scope, Sequence: 1, AuthorityID: authority, AuthorityEpoch: epoch,
		RecordedAt: time.Date(2026, 8, 5, 12, 30, 0, 456_000_000, time.UTC), Intent: intent,
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical, digest, err := codec.EncodeAuditEntry(view)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := `{"action":"installation.bootstrap.v1","approval_evidence_digests":[],"audit_sequence":1,"authority_epoch":"01b8e094-9888-7000-8000-000000000003","authority_id":"01b8e094-9888-7000-8000-000000000002","authorization":{"admission_generation":1,"authorization_revisions":[],"device_trust_revision":null,"effective_grants":[],"guard_digest":"f341b7e664572cd63048d88f628f3a7e078462c54a6d58ecd109d3b60f5024be","new_bootstrap_generation_id":null,"old_bootstrap_generation_id":null,"policy_revision":null,"revocation_revisions":[]},"chain_scope_id":"01b8e094-9888-7000-8000-000000000001","command_fingerprint":"6e228eb595f60330181357cf513caa2054f587f1e2917d3db4c231f65cb6df61","invocation":{"command_id":"01b8e094-9888-7000-8000-000000000008","correlation_id":"01b8e094-9888-7000-8000-00000000000a","kind":"command","receipt_id":"01b8e094-9888-7000-8000-000000000009","receipt_identity_digest":"7e6facf044f61d2c13d47b81fbd348dfc7db4caa689e5236b95b1c3e881bac20","request_id":null,"security_operation":null,"trace_id":null},"outcome":"command_applied","previous_entry_hash":"0000000000000000000000000000000000000000000000000000000000000000","provenance":{"federation_envelope_id":null,"source_authority_id":"01b8e094-9888-7000-8000-000000000002"},"recorded_at":"2026-08-05T12:30:00.456000Z","resources":[{"after_version":1,"before_version":null,"id":"01b8e094-9888-7000-8000-000000000006","kind":"device_registration"},{"after_version":1,"before_version":null,"id":"01b8e094-9888-7000-8000-000000000007","kind":"grant"},{"after_version":2,"before_version":1,"id":"01b8e094-9888-7000-8000-000000000004","kind":"invitation"},{"after_version":1,"before_version":null,"id":"01b8e094-9888-7000-8000-000000000005","kind":"principal"}],"safe_reason":null,"schema":"blackbird.audit.entry/v1","subject":{"actor_id":null,"actor_session_id":null,"delegation_chain":[],"device_id":null,"kind":"attributed","principal_id":"01b8e094-9888-7000-8000-000000000005","unattributed_source_digest":null,"workload_id":null},"timing":{"authenticated_client_at":null,"persisted_authority_at":"2026-08-04T12:01:00.123456Z","server_received_at":null}}`
	wantCanonical = strings.NewReplacer(
		`"revocation_revisions":[]`, `"revocation_revisions":[{"id":"01b8e094-9888-7000-8000-000000000004","kind":"invitation","version":1}]`,
		`"request_id":null`, `"request_id":"request-bootstrap-1"`,
		`"trace_id":null`, `"trace_id":"trace-bootstrap-1"`,
		`"device_id":null`, `"device_id":"01b8e094-9888-7000-8000-000000000006"`,
		`"authenticated_client_at":null`, `"authenticated_client_at":"2026-08-04T12:00:00.123456Z"`,
		`"server_received_at":null`, `"server_received_at":"2026-08-04T12:00:30.123456Z"`,
	).Replace(wantCanonical)
	if string(canonical) != wantCanonical {
		t.Fatalf("audit canonical golden changed:\n got %s\nwant %s", canonical, wantCanonical)
	}
	if digest.String() != "ef509869f94b0e66d0bd47e2cfbeaa39642a4615a4f74f9c0c8a80144ff3e224" {
		t.Fatalf("audit digest golden changed: %s", digest.String())
	}
	if err := codec.VerifyAuditEntry(Digest{}, canonical, digest); err != nil {
		t.Fatalf("verify audit genesis: %v", err)
	}
	wrongPrevious := DigestBytes([]byte("wrong predecessor"))
	if err := codec.VerifyAuditEntry(wrongPrevious, canonical, digest); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("wrong predecessor got %v", err)
	}
	if err := codec.VerifyAuditEntry(Digest{}, canonical, DigestBytes([]byte("wrong digest"))); !errors.Is(err, ErrCanonicalEncoding) {
		t.Fatalf("wrong digest got %v", err)
	}
	noncanonical := append([]byte(" "), canonical...)
	if err := codec.VerifyAuditEntry(Digest{}, noncanonical, digest); err == nil {
		t.Fatal("noncanonical retained audit entry was accepted")
	}

	mutatedIntent := intent
	mutatedGuardBytes := [sha256.Size]byte{99}
	mutatedIntent.authorization.guardDigest, _ = domain.NewAuthorizationDigest(mutatedGuardBytes)
	mutatedView, err := NewAuditEntryViewV1(AuditEntryParams{
		ChainScopeID: scope, Sequence: 1, AuthorityID: authority, AuthorityEpoch: epoch,
		RecordedAt: time.Date(2026, 8, 5, 12, 30, 0, 456_000_000, time.UTC), Intent: mutatedIntent,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, mutatedDigest, err := codec.EncodeAuditEntry(mutatedView)
	if err != nil || mutatedDigest == digest {
		t.Fatalf("one-field audit evidence mutation was not bound: %v", err)
	}
	otherDevice, _ := domain.ParseDeviceID(codecUUID(230))
	otherAuthority, _ := domain.ParseAuthorityID(codecUUID(231))
	otherEnvelope, _ := NewCanonicalIdentifier("federation-envelope-2")
	mutations := []struct {
		name   string
		mutate func(*AuditIntent)
	}{
		{"request_id", func(value *AuditIntent) {
			changed, _ := NewCanonicalIdentifier("request-bootstrap-2")
			value.invocation.requestID = &changed
		}},
		{"trace_id", func(value *AuditIntent) {
			changed, _ := NewCanonicalIdentifier("trace-bootstrap-2")
			value.invocation.traceID = &changed
		}},
		{"server_received_at", func(value *AuditIntent) {
			value.timing.serverReceivedTime = ptrTime(fixture.now.Add(31 * time.Second))
		}},
		{"authenticated_client_at", func(value *AuditIntent) {
			value.timing.clientTime = ptrTime(fixture.now.Add(-time.Second))
		}},
		{"authenticated_device", func(value *AuditIntent) { value.subject.device = otherDevice }},
		{"source_authority", func(value *AuditIntent) {
			value.provenance.sourceAuthority = otherAuthority
			value.provenance.federationEnvelope = &otherEnvelope
		}},
		{"federation_envelope", func(value *AuditIntent) {
			value.provenance.sourceAuthority = otherAuthority
			value.provenance.federationEnvelope = &otherEnvelope
		}},
	}
	for _, mutation := range mutations {
		mutated := intent
		mutation.mutate(&mutated)
		mutatedView, mutationErr := NewAuditEntryViewV1(AuditEntryParams{
			ChainScopeID: scope, Sequence: 1, AuthorityID: authority, AuthorityEpoch: epoch,
			RecordedAt: time.Date(2026, 8, 5, 12, 30, 0, 456_000_000, time.UTC), Intent: mutated,
		})
		if mutationErr != nil {
			t.Fatalf("%s mutation view: %v", mutation.name, mutationErr)
		}
		_, mutationDigest, mutationErr := codec.EncodeAuditEntry(mutatedView)
		if mutationErr != nil || mutationDigest == digest {
			t.Fatalf("%s mutation was not bound: %v", mutation.name, mutationErr)
		}
	}
	invalidProvenance := intent
	invalidProvenance.provenance.sourceAuthority = otherAuthority
	if _, err := NewAuditEntryViewV1(AuditEntryParams{
		ChainScopeID: scope, Sequence: 1, AuthorityID: authority, AuthorityEpoch: epoch,
		RecordedAt: time.Date(2026, 8, 5, 12, 30, 0, 456_000_000, time.UTC), Intent: invalidProvenance,
	}); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("remote source without federation envelope accepted: %v", err)
	}

	securityOperation := string(SecurityRecordCommandDenial)
	union := view
	union.Invocation.SecurityOperation = &securityOperation
	if _, _, err = codec.EncodeAuditEntry(union); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("mixed command/security invocation union error = %v", err)
	}
	withSecret := bytes.Replace(canonical, []byte(`"safe_reason":null`), []byte(`"access_token":"secret","safe_reason":null`), 1)
	withSecret, err = jcs.Transform(withSecret)
	if err != nil {
		t.Fatal(err)
	}
	if err = codec.VerifyAuditEntry(Digest{}, withSecret, digest); !errors.Is(err, ErrCanonicalSchema) {
		t.Fatalf("secret-bearing audit extension error = %v", err)
	}

	second, err := NewAuditEntryViewV1(AuditEntryParams{
		ChainScopeID: scope, Sequence: 2, AuthorityID: authority, AuthorityEpoch: epoch,
		RecordedAt: time.Date(2026, 8, 5, 12, 31, 0, 456_000_000, time.UTC), Intent: intent,
		PreviousEntryHash: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondCanonical, secondDigest, err := codec.EncodeAuditEntry(second)
	if err != nil || codec.VerifyAuditEntry(digest, secondCanonical, secondDigest) != nil {
		t.Fatalf("valid second chain entry failed: %v", err)
	}
	if _, err = NewAuditEntryViewV1(AuditEntryParams{
		ChainScopeID: scope, Sequence: 2, AuthorityID: authority, AuthorityEpoch: epoch,
		RecordedAt: time.Date(2026, 8, 5, 12, 31, 0, 456_000_000, time.UTC), Intent: intent,
	}); !errors.Is(err, ErrCanonicalProfile) {
		t.Fatalf("non-genesis zero predecessor error = %v", err)
	}
}

func TestSecurityDenialAuditEntryGolden(t *testing.T) {
	t.Parallel()
	fixture := buildBootstrapFixture(t)
	invalidInput := fixture.input
	invalidInput.DeviceID, _ = domain.ParseDeviceID(codecUUID(190))
	rejected, err := domain.BootstrapInstallation(invalidInput)
	if err != nil || rejected.Outcome() != domain.BootstrapInstallationProofRejected {
		t.Fatalf("bootstrap rejection: %v", err)
	}
	expectation, _ := domain.ExpectAggregateVersion(fixture.invitation.ID(), fixture.invitation.Version())
	generation, _ := NewGuardGeneration(1)
	spec, err := RecordBootstrapDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch, generation, expectation, fixture.attempt,
	)
	if err != nil {
		t.Fatal(err)
	}
	spec = testSecurityAuditContext(t, spec, fixture)
	context, err := NewSecurityContext(
		spec, fixture.now.Add(time.Minute), fixture.invitation, FreshSecurityAttempt(), DenialAdmission{},
		fixture.context.GuardEvidence().Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	operation, fingerprint, _ := ExpectedSecurityAudit(spec)
	name, _ := domain.NewOperationName(operation)
	detail, _ := SecurityDeniedAuditDetail("bootstrap_proof_rejected")
	seed, _ := NewAuditIntent(name, AuditSecurityDenied, fingerprint, detail)
	decision, err := DenyBootstrapSecurity(context, rejected.Invitation(), seed)
	if err != nil {
		t.Fatal(err)
	}
	intent, ok := decision.Audit()
	if !ok {
		t.Fatal("security denial omitted audit intent")
	}
	view, err := NewAuditEntryViewV1(AuditEntryParams{
		ChainScopeID: fixture.scope, Sequence: 1, AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		RecordedAt: fixture.now.Add(time.Minute), Intent: intent,
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical, digest, err := NewProductionCanonicalCodec().EncodeAuditEntry(view)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := `{"action":"installation.bootstrap.v1","approval_evidence_digests":[],"audit_sequence":1,"authority_epoch":"01b8e094-9888-7000-8000-000000000003","authority_id":"01b8e094-9888-7000-8000-000000000002","authorization":{"admission_generation":1,"authorization_revisions":[],"device_trust_revision":null,"effective_grants":[],"guard_digest":"f341b7e664572cd63048d88f628f3a7e078462c54a6d58ecd109d3b60f5024be","new_bootstrap_generation_id":null,"old_bootstrap_generation_id":null,"policy_revision":null,"revocation_revisions":[]},"chain_scope_id":"01b8e094-9888-7000-8000-000000000001","command_fingerprint":"9cffe0456302ab253d281a341e3c3717f51a066f054e26edb22f0abbe469c39b","invocation":{"command_id":null,"correlation_id":null,"kind":"security","receipt_id":null,"receipt_identity_digest":null,"request_id":null,"security_operation":"record_bootstrap_denial","trace_id":null},"outcome":"security_denied","previous_entry_hash":"0000000000000000000000000000000000000000000000000000000000000000","provenance":{"federation_envelope_id":null,"source_authority_id":"01b8e094-9888-7000-8000-000000000002"},"recorded_at":"2026-08-04T12:01:00.123456Z","resources":[{"after_version":2,"before_version":1,"id":"01b8e094-9888-7000-8000-000000000004","kind":"invitation"}],"safe_reason":"bootstrap_proof_rejected","schema":"blackbird.audit.entry/v1","subject":{"actor_id":null,"actor_session_id":null,"delegation_chain":[],"device_id":null,"kind":"unattributed","principal_id":null,"unattributed_source_digest":"9cffe0456302ab253d281a341e3c3717f51a066f054e26edb22f0abbe469c39b","workload_id":null},"timing":{"authenticated_client_at":null,"persisted_authority_at":"2026-08-04T12:01:00.123456Z","server_received_at":null}}`
	wantCanonical = strings.NewReplacer(
		`"request_id":null`, `"request_id":"request-security-1"`,
		`"trace_id":null`, `"trace_id":"trace-security-1"`,
		`"authenticated_client_at":null`, `"authenticated_client_at":"2026-08-04T11:59:59.123456Z"`,
		`"server_received_at":null`, `"server_received_at":"2026-08-04T12:00:00.123456Z"`,
	).Replace(wantCanonical)
	if string(canonical) != wantCanonical {
		t.Fatalf("security denial canonical golden changed:\n got %s\nwant %s", canonical, wantCanonical)
	}
	if digest.String() != "cd6d172d0dcbb13b90fc0449fc0d4e765c0ac5a1a4e630e9ef0d7672b9331150" {
		t.Fatalf("security denial digest golden changed: %s", digest.String())
	}
}

func TestCanonicalIntegerBoundary(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	for _, value := range []uint64{MaxCanonicalInteger - 1, MaxCanonicalInteger} {
		if _, err := codec.HashCommand(allProfileView{Count: value, Label: "boundary"}); err != nil {
			t.Fatalf("value %d: %v", value, err)
		}
	}
	if _, err := codec.HashCommand(allProfileView{Count: MaxCanonicalInteger + 1, Label: "boundary"}); !errors.Is(err, ErrCanonicalNumber) {
		t.Fatalf("above boundary got %v", err)
	}
}

func FuzzCanonicalizeStrictNeverPanics(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":"\ud800"}`))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = canonicalizeStrict(raw, MaxCanonicalJSONBytes, MaxCanonicalJSONDepth)
	})
}

func newReceiptFixture(t *testing.T) receiptFixture {
	t.Helper()
	authority, _ := domain.ParseAuthorityID(codecUUID(401))
	epoch, _ := domain.ParseAuthorityEpoch(codecUUID(402))
	installation, _ := domain.ParseInstallationID(codecUUID(403))
	workspace, _ := domain.ParseWorkspaceID(codecUUID(404))
	principal, _ := domain.ParsePrincipalID(codecUUID(405))
	device, _ := domain.ParseDeviceID(codecUUID(406))
	grant, _ := domain.ParseGrantID(codecUUID(407))
	membership, _ := domain.ParseMembershipID(codecUUID(408))
	actor, _ := domain.ParseActorID(codecUUID(409))
	delegation, _ := domain.ParseActorDelegationID(codecUUID(410))
	session, _ := domain.ParseActorSessionID(codecUUID(411))
	client, _ := domain.ParseClientInstanceID(codecUUID(412))
	authorization, _ := domain.NewAuthorizationDigest(sha256.Sum256([]byte("receipt authorization")))
	finalStream, _ := domain.NewStreamDigest(sha256.Sum256([]byte("receipt final stream")))
	return receiptFixture{
		authority: authority, epoch: epoch, installation: installation, workspace: workspace,
		principal: principal, device: device, grant: grant, membership: membership,
		actor: actor, delegation: delegation, session: session, client: client,
		acceptedAt:    time.Date(2026, 8, 4, 12, 0, 0, 123_000_000, time.UTC),
		authorization: authorization, finalStream: finalStream,
	}
}

func (fixture receiptFixture) paramsFor(
	t *testing.T,
	operation W0ReceiptOperation,
	resourceKinds []domain.AggregateKind,
	eventCount int,
	ceremonyPurpose domain.CeremonyPurpose,
) W0ReceiptResultParams {
	t.Helper()
	catalog, exists := receiptCatalog(operation)
	if !exists {
		t.Fatalf("missing operation catalog %q", operation)
	}
	var scope domain.AuthorityScope
	if catalog.scopeKind == domain.ScopeKindInstallation {
		scope, _ = domain.InstallationScope(fixture.installation)
	} else {
		scope, _ = domain.WorkspaceScope(fixture.workspace)
	}
	resources := make([]domain.AggregateRef, 0, len(resourceKinds))
	for _, kind := range resourceKinds {
		resources = append(resources, fixture.resource(t, kind))
	}
	events := make([]domain.EventID, 0, eventCount)
	for index := range eventCount {
		eventID, _ := domain.ParseEventID(codecUUID(500 + index))
		events = append(events, eventID)
	}
	first, _ := domain.NewStreamPosition(100)
	last, _ := domain.NewStreamPosition(99 + uint64(eventCount))
	params := W0ReceiptResultParams{
		Operation: operation, AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		Scope: scope, AcceptedAt: fixture.acceptedAt,
		CommandFingerprint:  domain.FingerprintCommand([]byte(operation)),
		AuthorizationDigest: fixture.authorization, Resources: resources,
		FirstEventPosition: first, LastEventPosition: last, EventIDs: events,
		FinalStreamDigest: fixture.finalStream,
	}
	if ceremonyPurpose.Valid() {
		params.IssuedCeremonies = []domain.CeremonyChallenge{fixture.ceremony(t, ceremonyPurpose)}
	}
	if operation == ReceiptOperationActorSessionStart {
		params.SessionBinding = fixture.sessionBinding(t)
		params.SessionClient = fixture.client
		digest, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("receipt presentation credential")))
		reference, _ := domain.NewCredentialReference("credential-ref:receipt-session")
		audience, _ := domain.NewCredentialAudience("blackbird:receipt-session")
		params.PresentationCredential, _ = domain.NewPresentationCredentialBinding(
			digest, reference, audience, domain.PresentationCredentialVersion,
		)
	}
	return params
}

func (fixture receiptFixture) resource(t *testing.T, kind domain.AggregateKind) domain.AggregateRef {
	t.Helper()
	version := domain.InitialVersion()
	switch kind {
	case domain.AggregateKindWorkspace:
		return mustAggregateRef(t, fixture.workspace, version)
	case domain.AggregateKindPrincipal:
		return mustAggregateRef(t, fixture.principal, version)
	case domain.AggregateKindDevice:
		return mustAggregateRef(t, fixture.device, version)
	case domain.AggregateKindMembership:
		return mustAggregateRef(t, fixture.membership, version)
	case domain.AggregateKindActor:
		return mustAggregateRef(t, fixture.actor, version)
	case domain.AggregateKindActorDelegation:
		return mustAggregateRef(t, fixture.delegation, version)
	case domain.AggregateKindActorSession:
		return mustAggregateRef(t, fixture.session, version)
	case domain.AggregateKindGrant:
		return mustAggregateRef(t, fixture.grant, version)
	default:
		t.Fatalf("unsupported receipt resource kind %q", kind)
		return domain.AggregateRef{}
	}
}

func (fixture receiptFixture) ceremony(t *testing.T, purpose domain.CeremonyPurpose) domain.CeremonyChallenge {
	t.Helper()
	purposeIndex := map[domain.CeremonyPurpose]int{
		domain.CeremonyPurposeMembershipAcceptance: 601,
		domain.CeremonyPurposeDelegationActivation: 602,
		domain.CeremonyPurposeDevicePairing:        603,
		domain.CeremonyPurposeActorSessionStart:    604,
	}[purpose]
	id, _ := domain.ParseCeremonyID(codecUUID(purposeIndex))
	proof := domain.FingerprintCommand([]byte("receipt ceremony " + string(purpose)))
	expiresAt := fixture.acceptedAt.Add(time.Minute)
	var (
		challenge domain.CeremonyChallenge
		err       error
	)
	switch purpose {
	case domain.CeremonyPurposeMembershipAcceptance:
		challenge, err = domain.NewMembershipAcceptanceChallenge(
			id, proof, expiresAt, fixture.workspace, fixture.membership, fixture.principal,
		)
	case domain.CeremonyPurposeDelegationActivation:
		challenge, err = domain.NewDelegationActivationChallenge(
			id, proof, expiresAt, fixture.workspace, fixture.delegation, fixture.principal, fixture.actor,
		)
	case domain.CeremonyPurposeDevicePairing:
		challenge, err = domain.NewDevicePairingChallenge(
			id, proof, expiresAt, fixture.installation, fixture.principal, fixture.device,
		)
	case domain.CeremonyPurposeActorSessionStart:
		challenge, err = domain.NewSessionStartChallenge(
			id, proof, expiresAt, fixture.workspace, fixture.delegation, fixture.principal, fixture.actor,
		)
	default:
		t.Fatalf("unsupported receipt ceremony purpose %q", purpose)
	}
	if err != nil {
		t.Fatalf("new receipt ceremony: %v", err)
	}
	return challenge
}

func (fixture receiptFixture) sessionBinding(t *testing.T) *domain.SessionBinding {
	t.Helper()
	membership := mustAggregateRef(t, fixture.membership, domain.InitialVersion())
	delegation := mustAggregateRef(t, fixture.delegation, domain.InitialVersion())
	policy, err := domain.NewPolicyRevision("policy-receipt-1")
	if err != nil {
		t.Fatalf("new policy revision: %v", err)
	}
	assurance, err := domain.NewAssuranceClass("hardware")
	if err != nil {
		t.Fatalf("new assurance class: %v", err)
	}
	binding, err := domain.NewSessionBinding(
		fixture.authority, fixture.epoch, fixture.workspace, fixture.principal, fixture.actor,
		membership, delegation, nil, domain.Version{}, nil, policy, assurance,
		fixture.acceptedAt, fixture.acceptedAt.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("new session binding: %v", err)
	}
	return &binding
}

func mustAggregateRef(t *testing.T, identifier any, version domain.Version) domain.AggregateRef {
	t.Helper()
	var (
		ref domain.AggregateRef
		err error
	)
	switch id := identifier.(type) {
	case domain.WorkspaceID:
		ref, err = domain.NewAggregateRef(id, version)
	case domain.PrincipalID:
		ref, err = domain.NewAggregateRef(id, version)
	case domain.DeviceID:
		ref, err = domain.NewAggregateRef(id, version)
	case domain.MembershipID:
		ref, err = domain.NewAggregateRef(id, version)
	case domain.ActorID:
		ref, err = domain.NewAggregateRef(id, version)
	case domain.ActorDelegationID:
		ref, err = domain.NewAggregateRef(id, version)
	case domain.ActorSessionID:
		ref, err = domain.NewAggregateRef(id, version)
	case domain.GrantID:
		ref, err = domain.NewAggregateRef(id, version)
	default:
		t.Fatalf("unsupported aggregate ID %T", identifier)
	}
	if err != nil {
		t.Fatalf("new aggregate ref: %v", err)
	}
	return ref
}

func mustCeremonyID(t *testing.T) domain.CeremonyID {
	t.Helper()
	id, err := domain.NewCeremonyID()
	if err != nil {
		t.Fatalf("new ceremony ID: %v", err)
	}
	return id
}

func mustCanonicalID(t *testing.T, text string) CanonicalIdentifier {
	t.Helper()
	identifier, err := NewCanonicalIdentifier(text)
	if err != nil {
		t.Fatalf("canonical ID %q: %v", text, err)
	}
	return identifier
}

func mustCanonicalDigest(t *testing.T, character byte) CanonicalDigest {
	t.Helper()
	digest, err := NewCanonicalDigest(strings.Repeat(string(character), 64))
	if err != nil {
		t.Fatalf("canonical digest %q: %v", character, err)
	}
	return digest
}
