package domain

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
)

const validUUIDV7 = "01b8e094-9888-7000-8000-000000000001"

type identifierBoundary interface {
	fmt.Stringer
	encoding.TextMarshaler
	json.Marshaler
	Kind() IdentifierKind
	IsZero() bool
}

var (
	_ identifierBoundary = InstallationID{}
	_ identifierBoundary = AuthorityID{}
	_ identifierBoundary = WorkspaceID{}
	_ identifierBoundary = PrincipalID{}
	_ identifierBoundary = DeviceID{}
	_ identifierBoundary = MembershipID{}
	_ identifierBoundary = ActorID{}
	_ identifierBoundary = ActorDelegationID{}
	_ identifierBoundary = ActorSessionID{}
	_ identifierBoundary = GrantID{}
	_ identifierBoundary = InvitationID{}
	_ identifierBoundary = CeremonyID{}
	_ identifierBoundary = BootstrapGenerationID{}
	_ identifierBoundary = CommandID{}
	_ identifierBoundary = ReceiptID{}
	_ identifierBoundary = EventID{}
	_ identifierBoundary = CorrelationID{}
	_ identifierBoundary = ClientInstanceID{}
	_ identifierBoundary = AuthorityEpoch{}

	_ encoding.TextUnmarshaler = (*InstallationID)(nil)
	_ encoding.TextUnmarshaler = (*AuthorityID)(nil)
	_ encoding.TextUnmarshaler = (*WorkspaceID)(nil)
	_ encoding.TextUnmarshaler = (*PrincipalID)(nil)
	_ encoding.TextUnmarshaler = (*DeviceID)(nil)
	_ encoding.TextUnmarshaler = (*MembershipID)(nil)
	_ encoding.TextUnmarshaler = (*ActorID)(nil)
	_ encoding.TextUnmarshaler = (*ActorDelegationID)(nil)
	_ encoding.TextUnmarshaler = (*ActorSessionID)(nil)
	_ encoding.TextUnmarshaler = (*GrantID)(nil)
	_ encoding.TextUnmarshaler = (*InvitationID)(nil)
	_ encoding.TextUnmarshaler = (*CeremonyID)(nil)
	_ encoding.TextUnmarshaler = (*BootstrapGenerationID)(nil)
	_ encoding.TextUnmarshaler = (*CommandID)(nil)
	_ encoding.TextUnmarshaler = (*ReceiptID)(nil)
	_ encoding.TextUnmarshaler = (*EventID)(nil)
	_ encoding.TextUnmarshaler = (*CorrelationID)(nil)
	_ encoding.TextUnmarshaler = (*ClientInstanceID)(nil)
	_ encoding.TextUnmarshaler = (*AuthorityEpoch)(nil)
)

func TestAllIdentifierKindsStrictlyRoundTrip(t *testing.T) {
	parsers := map[IdentifierKind]func(string) (identifierBoundary, error){
		IdentifierKindInstallation:    func(value string) (identifierBoundary, error) { return ParseInstallationID(value) },
		IdentifierKindAuthority:       func(value string) (identifierBoundary, error) { return ParseAuthorityID(value) },
		IdentifierKindWorkspace:       func(value string) (identifierBoundary, error) { return ParseWorkspaceID(value) },
		IdentifierKindPrincipal:       func(value string) (identifierBoundary, error) { return ParsePrincipalID(value) },
		IdentifierKindDevice:          func(value string) (identifierBoundary, error) { return ParseDeviceID(value) },
		IdentifierKindMembership:      func(value string) (identifierBoundary, error) { return ParseMembershipID(value) },
		IdentifierKindActor:           func(value string) (identifierBoundary, error) { return ParseActorID(value) },
		IdentifierKindActorDelegation: func(value string) (identifierBoundary, error) { return ParseActorDelegationID(value) },
		IdentifierKindActorSession:    func(value string) (identifierBoundary, error) { return ParseActorSessionID(value) },
		IdentifierKindGrant:           func(value string) (identifierBoundary, error) { return ParseGrantID(value) },
		IdentifierKindInvitation:      func(value string) (identifierBoundary, error) { return ParseInvitationID(value) },
		IdentifierKindCeremony:        func(value string) (identifierBoundary, error) { return ParseCeremonyID(value) },
		IdentifierKindBootstrapGeneration: func(value string) (identifierBoundary, error) {
			return ParseBootstrapGenerationID(value)
		},
		IdentifierKindCommand:        func(value string) (identifierBoundary, error) { return ParseCommandID(value) },
		IdentifierKindReceipt:        func(value string) (identifierBoundary, error) { return ParseReceiptID(value) },
		IdentifierKindEvent:          func(value string) (identifierBoundary, error) { return ParseEventID(value) },
		IdentifierKindCorrelation:    func(value string) (identifierBoundary, error) { return ParseCorrelationID(value) },
		IdentifierKindClientInstance: func(value string) (identifierBoundary, error) { return ParseClientInstanceID(value) },
		IdentifierKindAuthorityEpoch: func(value string) (identifierBoundary, error) { return ParseAuthorityEpoch(value) },
	}

	for kind, parse := range parsers {
		t.Run(string(kind), func(t *testing.T) {
			identifier, err := parse(validUUIDV7)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if identifier.Kind() != kind || identifier.String() != validUUIDV7 || identifier.IsZero() {
				t.Fatalf("unexpected identifier: kind=%q text=%q zero=%v", identifier.Kind(), identifier, identifier.IsZero())
			}
			text, err := identifier.MarshalText()
			if err != nil || string(text) != validUUIDV7 {
				t.Fatalf("text round trip: %q, %v", text, err)
			}
			encoded, err := json.Marshal(identifier)
			if err != nil || string(encoded) != `"`+validUUIDV7+`"` {
				t.Fatalf("json round trip: %s, %v", encoded, err)
			}
			jsonTarget := reflect.New(reflect.TypeOf(identifier))
			if err := json.Unmarshal(encoded, jsonTarget.Interface()); err != nil {
				t.Fatalf("JSON unmarshal: %v", err)
			}
			jsonRoundTrip := jsonTarget.Elem().Interface().(identifierBoundary)
			if jsonRoundTrip.Kind() != kind || jsonRoundTrip.String() != validUUIDV7 {
				t.Fatalf("JSON decoded wrong identifier: %v", jsonRoundTrip)
			}
			textTarget := reflect.New(reflect.TypeOf(identifier))
			unmarshaler := textTarget.Interface().(encoding.TextUnmarshaler)
			if err := unmarshaler.UnmarshalText(text); err != nil {
				t.Fatalf("text unmarshal: %v", err)
			}
			textRoundTrip := textTarget.Elem().Interface().(identifierBoundary)
			if textRoundTrip.Kind() != kind || textRoundTrip.String() != validUUIDV7 {
				t.Fatalf("text decoded wrong identifier: %v", textRoundTrip)
			}
		})
	}
}

func TestIdentifierRejectsMalformedAndNonCanonicalUUIDs(t *testing.T) {
	tests := []struct {
		value string
		cause error
	}{
		{"", ErrInvalidIdentifier},
		{"01B8E094-9888-7000-8000-000000000001", ErrInvalidIdentifier},
		{"01b8e094988870008000000000000001", ErrInvalidIdentifier},
		{"01b8e094-9888-4000-8000-000000000001", ErrInvalidIdentifier},
		{"01b8e094-9888-7000-4000-000000000001", ErrInvalidIdentifier},
		{"00000000-0000-0000-0000-000000000000", ErrZeroIdentifier},
	}
	for _, test := range tests {
		_, err := ParseWorkspaceID(test.value)
		if !errors.Is(err, test.cause) {
			t.Errorf("ParseWorkspaceID(%q) error = %v, want %v", test.value, err, test.cause)
		}
		var identifier WorkspaceID
		if err := json.Unmarshal([]byte(`"`+test.value+`"`), &identifier); !errors.Is(err, test.cause) {
			t.Errorf("JSON %q error = %v, want %v", test.value, err, test.cause)
		}
	}

	for _, encoded := range []string{`null`, `7`, `{}`, `"not-an-id"`} {
		var identifier WorkspaceID
		if err := json.Unmarshal([]byte(encoded), &identifier); !errors.Is(err, ErrInvalidIdentifier) {
			t.Errorf("JSON %s error = %v", encoded, err)
		}
	}
	if _, err := json.Marshal(WorkspaceID{}); !errors.Is(err, ErrZeroIdentifier) {
		t.Fatalf("zero JSON error = %v", err)
	}
}

func TestIdentifierKindsAreNominallyDistinct(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeFor[InstallationID](), reflect.TypeFor[AuthorityID](),
		reflect.TypeFor[WorkspaceID](), reflect.TypeFor[PrincipalID](),
		reflect.TypeFor[DeviceID](), reflect.TypeFor[MembershipID](),
		reflect.TypeFor[ActorID](), reflect.TypeFor[ActorDelegationID](),
		reflect.TypeFor[ActorSessionID](), reflect.TypeFor[GrantID](),
		reflect.TypeFor[InvitationID](), reflect.TypeFor[CeremonyID](), reflect.TypeFor[CommandID](),
		reflect.TypeFor[BootstrapGenerationID](),
		reflect.TypeFor[ReceiptID](), reflect.TypeFor[EventID](),
		reflect.TypeFor[CorrelationID](), reflect.TypeFor[ClientInstanceID](),
		reflect.TypeFor[AuthorityEpoch](),
	}
	seen := make(map[reflect.Type]struct{}, len(types))
	for _, identifierType := range types {
		if _, duplicate := seen[identifierType]; duplicate {
			t.Fatalf("duplicate concrete identifier type %v", identifierType)
		}
		seen[identifierType] = struct{}{}
	}
}

func TestAuthorityEpochEqualityOnly(t *testing.T) {
	epoch, err := ParseAuthorityEpoch(validUUIDV7)
	if err != nil {
		t.Fatal(err)
	}
	same, _ := ParseAuthorityEpoch(validUUIDV7)
	other, err := NewAuthorityEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if !epoch.Equal(same) || epoch.Equal(other) {
		t.Fatal("epoch equality semantics are incorrect")
	}
}

func TestVersionCheckedSuccessorAndRoundTrips(t *testing.T) {
	version := InitialVersion()
	next, err := version.Next()
	if err != nil || next.Uint64() != 2 {
		t.Fatalf("next = %v, %v", next, err)
	}
	encoded, err := json.Marshal(next)
	if err != nil || string(encoded) != "2" {
		t.Fatalf("marshal = %s, %v", encoded, err)
	}
	var decoded Version
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != next {
		t.Fatalf("unmarshal = %v, %v", decoded, err)
	}
	maximum, err := NewVersion(math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := maximum.Next(); !errors.Is(err, ErrVersionOverflow) {
		t.Fatalf("overflow error = %v", err)
	}
	for _, text := range []string{"", "0", "01", "+1", "-1"} {
		if _, err := ParseVersion(text); !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("ParseVersion(%q) = %v", text, err)
		}
	}
	if _, err := (Version{}).Next(); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("zero successor error = %v", err)
	}
}
