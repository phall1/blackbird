package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	}{
		{ReceiptOperationInstallationBootstrap, []domain.AggregateKind{domain.AggregateKindPrincipal, domain.AggregateKindDevice, domain.AggregateKindGrant}, 3, "", true, false},
		{ReceiptOperationPrincipalRegister, []domain.AggregateKind{domain.AggregateKindPrincipal}, 1, "", true, false},
		{ReceiptOperationDevicePairingBegin, []domain.AggregateKind{domain.AggregateKindDevice}, 1, domain.CeremonyPurposeDevicePairing, true, false},
		{ReceiptOperationDevicePair, []domain.AggregateKind{domain.AggregateKindDevice}, 1, "", false, false},
		{ReceiptOperationWorkspaceCreate, []domain.AggregateKind{domain.AggregateKindWorkspace, domain.AggregateKindMembership}, 3, "", true, false},
		{ReceiptOperationWorkspaceMemberInvite, []domain.AggregateKind{domain.AggregateKindMembership}, 1, domain.CeremonyPurposeMembershipAcceptance, true, false},
		{ReceiptOperationWorkspaceMembershipAccept, []domain.AggregateKind{domain.AggregateKindMembership}, 1, "", false, false},
		{ReceiptOperationActorCreate, []domain.AggregateKind{domain.AggregateKindActor}, 1, "", true, false},
		{ReceiptOperationActorDelegationPropose, []domain.AggregateKind{domain.AggregateKindActorDelegation}, 1, domain.CeremonyPurposeDelegationActivation, true, false},
		{ReceiptOperationActorDelegationActivate, []domain.AggregateKind{domain.AggregateKindActorDelegation}, 1, domain.CeremonyPurposeActorSessionStart, true, false},
		{ReceiptOperationActorSessionStart, []domain.AggregateKind{domain.AggregateKindActorSession}, 1, "", true, true},
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
	params.EventDigest = placeholderEvent
	if _, err := codec.MaterializeEvent(params); !errors.Is(err, domain.ErrEventDigestVerification) {
		t.Fatalf("semantic digest tamper got %v", err)
	}
	params.EventDigest = eventDigest
	params.StreamDigest = placeholderStream
	if _, err := codec.MaterializeEvent(params); !errors.Is(err, domain.ErrEventDigestVerification) {
		t.Fatalf("stream digest tamper got %v", err)
	}
}

func TestAuditEntryGoldenAndAdversarialVerification(t *testing.T) {
	t.Parallel()

	codec := NewProductionCanonicalCodec()
	authority, _ := domain.ParseAuthorityID(codecUUID(111))
	epoch, _ := domain.ParseAuthorityEpoch(codecUUID(112))
	installation, _ := domain.ParseInstallationID(codecUUID(113))
	scope, _ := domain.InstallationScope(installation)
	operation, _ := domain.NewOperationName(string(CommandRegisterPrincipal))
	intent, err := NewAuditIntent(
		operation, AuditCommandApplied, domain.FingerprintCommand([]byte("audit command")), CommandAppliedAuditDetail(),
	)
	if err != nil {
		t.Fatal(err)
	}
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
	wantCanonical := `{"action":"principal.register.v1","audit_sequence":1,"authority_epoch":"0198a0a0-0000-7000-8000-000000000112","authority_id":"0198a0a0-0000-7000-8000-000000000111","chain_scope_id":"0198a0a0-0000-7000-8000-000000000113","command_fingerprint":"8014e7cf00337fb9652679a3a38ba9564f2019844be1256ea20d6025c38cea94","detail":{"kind":"command_applied","reason":null},"outcome":"command_applied","previous_entry_hash":"0000000000000000000000000000000000000000000000000000000000000000","recorded_at":"2026-08-05T12:30:00.456000Z","schema":"blackbird.audit.entry/v1"}`
	if string(canonical) != wantCanonical {
		t.Fatalf("audit canonical golden changed:\n got %s\nwant %s", canonical, wantCanonical)
	}
	if digest.String() != "0b3b7a6d2e41fe3ff74e93a3d68a5b8d738c7ab8173c55665c400f0bafcd8578" {
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
	authority, _ := domain.NewAuthorityID()
	epoch, _ := domain.NewAuthorityEpoch()
	installation, _ := domain.NewInstallationID()
	workspace, _ := domain.NewWorkspaceID()
	principal, _ := domain.NewPrincipalID()
	device, _ := domain.NewDeviceID()
	grant, _ := domain.NewGrantID()
	membership, _ := domain.NewMembershipID()
	actor, _ := domain.NewActorID()
	delegation, _ := domain.NewActorDelegationID()
	session, _ := domain.NewActorSessionID()
	client, _ := domain.NewClientInstanceID()
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
	for range eventCount {
		eventID, _ := domain.NewEventID()
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
	id := mustCeremonyID(t)
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
