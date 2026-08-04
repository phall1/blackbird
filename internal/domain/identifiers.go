package domain

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const uuidTextLength = 36

var (
	ErrInvalidIdentifier = errors.New("invalid identifier")
	ErrZeroIdentifier    = errors.New("zero identifier")
)

// IdentifierKind identifies a domain ID's semantic type. It is diagnostic
// metadata only; callers must still use the corresponding concrete Go type.
type IdentifierKind string

const (
	IdentifierKindInstallation        IdentifierKind = "installation"
	IdentifierKindAuthority           IdentifierKind = "authority"
	IdentifierKindWorkspace           IdentifierKind = "workspace"
	IdentifierKindPrincipal           IdentifierKind = "principal"
	IdentifierKindDevice              IdentifierKind = "device"
	IdentifierKindMembership          IdentifierKind = "membership"
	IdentifierKindActor               IdentifierKind = "actor"
	IdentifierKindActorDelegation     IdentifierKind = "actor_delegation"
	IdentifierKindActorSession        IdentifierKind = "actor_session"
	IdentifierKindGrant               IdentifierKind = "grant"
	IdentifierKindInvitation          IdentifierKind = "invitation"
	IdentifierKindCeremony            IdentifierKind = "ceremony"
	IdentifierKindBootstrapGeneration IdentifierKind = "bootstrap_generation"
	IdentifierKindCommand             IdentifierKind = "command"
	IdentifierKindReceipt             IdentifierKind = "receipt"
	IdentifierKindEvent               IdentifierKind = "event"
	IdentifierKindCorrelation         IdentifierKind = "correlation"
	IdentifierKindClientInstance      IdentifierKind = "client_instance"
)

// IdentifierError reports a failed typed-ID boundary without weakening the
// concrete ID type that was requested.
type IdentifierError struct {
	Kind  IdentifierKind
	Value string
	cause error
}

func (e *IdentifierError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s %q: %v", e.Kind, e.Value, e.cause)
}

func (e *IdentifierError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type uuidV7 [16]byte

func (id uuidV7) isZero() bool { return id == uuidV7{} }

func (id uuidV7) string() string {
	if id.isZero() {
		return ""
	}

	var text [uuidTextLength]byte
	hex.Encode(text[0:8], id[0:4])
	text[8] = '-'
	hex.Encode(text[9:13], id[4:6])
	text[13] = '-'
	hex.Encode(text[14:18], id[6:8])
	text[18] = '-'
	hex.Encode(text[19:23], id[8:10])
	text[23] = '-'
	hex.Encode(text[24:36], id[10:16])
	return string(text[:])
}

func parseUUIDV7(text string) (uuidV7, error) {
	if len(text) != uuidTextLength || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return uuidV7{}, ErrInvalidIdentifier
	}

	var compact [32]byte
	copy(compact[0:8], text[0:8])
	copy(compact[8:12], text[9:13])
	copy(compact[12:16], text[14:18])
	copy(compact[16:20], text[19:23])
	copy(compact[20:32], text[24:36])

	// Canonical Blackbird identifiers are lowercase. Rejecting alternate text
	// forms keeps fingerprints and language-neutral fixtures byte-stable.
	for _, character := range compact {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return uuidV7{}, ErrInvalidIdentifier
		}
	}

	var id uuidV7
	if _, err := hex.Decode(id[:], compact[:]); err != nil {
		return uuidV7{}, ErrInvalidIdentifier
	}
	if id.isZero() {
		return uuidV7{}, ErrZeroIdentifier
	}
	if id[6]>>4 != 0x7 || id[8]>>6 != 0x2 {
		return uuidV7{}, ErrInvalidIdentifier
	}
	return id, nil
}

func generateUUIDV7(now time.Time, random io.Reader) (uuidV7, error) {
	milliseconds := now.UnixMilli()
	if milliseconds < 0 || milliseconds >= 1<<48 {
		return uuidV7{}, ErrInvalidIdentifier
	}

	var id uuidV7
	if _, err := io.ReadFull(random, id[6:]); err != nil {
		return uuidV7{}, fmt.Errorf("generate uuidv7 randomness: %w", err)
	}
	for index := 5; index >= 0; index-- {
		id[index] = byte(milliseconds)
		milliseconds >>= 8
	}
	id[6] = (id[6] & 0x0f) | 0x70
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

type identifierMarker interface {
	identifierKind() IdentifierKind
}

type typedID[Marker identifierMarker] struct {
	value uuidV7
	_     Marker
}

func identifierKindOf[Marker identifierMarker]() IdentifierKind {
	var marker Marker
	return marker.identifierKind()
}

func parseTypedID[Marker identifierMarker](text string) (typedID[Marker], error) {
	value, err := parseUUIDV7(text)
	if err != nil {
		return typedID[Marker]{}, &IdentifierError{
			Kind:  identifierKindOf[Marker](),
			Value: text,
			cause: err,
		}
	}
	return typedID[Marker]{value: value}, nil
}

func newTypedID[Marker identifierMarker]() (typedID[Marker], error) {
	value, err := generateUUIDV7(time.Now(), rand.Reader)
	if err != nil {
		return typedID[Marker]{}, &IdentifierError{
			Kind:  identifierKindOf[Marker](),
			Value: "",
			cause: err,
		}
	}
	return typedID[Marker]{value: value}, nil
}

func (id typedID[Marker]) Kind() IdentifierKind { return identifierKindOf[Marker]() }

func (id typedID[Marker]) IsZero() bool { return id.value.isZero() }

func (id typedID[Marker]) String() string { return id.value.string() }

func (id typedID[Marker]) MarshalText() ([]byte, error) {
	if id.IsZero() {
		return nil, &IdentifierError{Kind: id.Kind(), cause: ErrZeroIdentifier}
	}
	return []byte(id.String()), nil
}

func (id *typedID[Marker]) UnmarshalText(text []byte) error {
	if id == nil {
		return &IdentifierError{Kind: identifierKindOf[Marker](), Value: string(text), cause: ErrInvalidIdentifier}
	}
	parsed, err := parseTypedID[Marker](string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id typedID[Marker]) MarshalJSON() ([]byte, error) {
	text, err := id.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(text))
}

func (id *typedID[Marker]) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return &IdentifierError{Kind: identifierKindOf[Marker](), Value: string(data), cause: ErrInvalidIdentifier}
	}
	return id.UnmarshalText([]byte(text))
}

type installationIDMarker struct{}
type authorityIDMarker struct{}
type workspaceIDMarker struct{}
type principalIDMarker struct{}
type deviceIDMarker struct{}
type membershipIDMarker struct{}
type actorIDMarker struct{}
type actorDelegationIDMarker struct{}
type actorSessionIDMarker struct{}
type grantIDMarker struct{}
type invitationIDMarker struct{}
type ceremonyIDMarker struct{}
type bootstrapGenerationIDMarker struct{}
type commandIDMarker struct{}
type receiptIDMarker struct{}
type eventIDMarker struct{}
type correlationIDMarker struct{}
type clientInstanceIDMarker struct{}

func (installationIDMarker) identifierKind() IdentifierKind    { return IdentifierKindInstallation }
func (authorityIDMarker) identifierKind() IdentifierKind       { return IdentifierKindAuthority }
func (workspaceIDMarker) identifierKind() IdentifierKind       { return IdentifierKindWorkspace }
func (principalIDMarker) identifierKind() IdentifierKind       { return IdentifierKindPrincipal }
func (deviceIDMarker) identifierKind() IdentifierKind          { return IdentifierKindDevice }
func (membershipIDMarker) identifierKind() IdentifierKind      { return IdentifierKindMembership }
func (actorIDMarker) identifierKind() IdentifierKind           { return IdentifierKindActor }
func (actorDelegationIDMarker) identifierKind() IdentifierKind { return IdentifierKindActorDelegation }
func (actorSessionIDMarker) identifierKind() IdentifierKind    { return IdentifierKindActorSession }
func (grantIDMarker) identifierKind() IdentifierKind           { return IdentifierKindGrant }
func (invitationIDMarker) identifierKind() IdentifierKind      { return IdentifierKindInvitation }
func (ceremonyIDMarker) identifierKind() IdentifierKind        { return IdentifierKindCeremony }
func (bootstrapGenerationIDMarker) identifierKind() IdentifierKind {
	return IdentifierKindBootstrapGeneration
}
func (commandIDMarker) identifierKind() IdentifierKind        { return IdentifierKindCommand }
func (receiptIDMarker) identifierKind() IdentifierKind        { return IdentifierKindReceipt }
func (eventIDMarker) identifierKind() IdentifierKind          { return IdentifierKindEvent }
func (correlationIDMarker) identifierKind() IdentifierKind    { return IdentifierKindCorrelation }
func (clientInstanceIDMarker) identifierKind() IdentifierKind { return IdentifierKindClientInstance }

// The unique marker embedded in every wrapper makes both implicit assignment
// and explicit cross-kind conversion fail at compile time.
type InstallationID struct{ typedID[installationIDMarker] }
type AuthorityID struct{ typedID[authorityIDMarker] }
type WorkspaceID struct{ typedID[workspaceIDMarker] }
type PrincipalID struct{ typedID[principalIDMarker] }
type DeviceID struct{ typedID[deviceIDMarker] }
type MembershipID struct{ typedID[membershipIDMarker] }
type ActorID struct{ typedID[actorIDMarker] }
type ActorDelegationID struct {
	typedID[actorDelegationIDMarker]
}
type ActorSessionID struct{ typedID[actorSessionIDMarker] }
type GrantID struct{ typedID[grantIDMarker] }
type InvitationID struct{ typedID[invitationIDMarker] }
type CeremonyID struct{ typedID[ceremonyIDMarker] }
type BootstrapGenerationID struct {
	typedID[bootstrapGenerationIDMarker]
}
type CommandID struct{ typedID[commandIDMarker] }
type ReceiptID struct{ typedID[receiptIDMarker] }
type EventID struct{ typedID[eventIDMarker] }
type CorrelationID struct{ typedID[correlationIDMarker] }
type ClientInstanceID struct {
	typedID[clientInstanceIDMarker]
}

func ParseInstallationID(text string) (InstallationID, error) {
	id, err := parseTypedID[installationIDMarker](text)
	return InstallationID{typedID: id}, err
}
func ParseAuthorityID(text string) (AuthorityID, error) {
	id, err := parseTypedID[authorityIDMarker](text)
	return AuthorityID{typedID: id}, err
}
func ParseWorkspaceID(text string) (WorkspaceID, error) {
	id, err := parseTypedID[workspaceIDMarker](text)
	return WorkspaceID{typedID: id}, err
}
func ParsePrincipalID(text string) (PrincipalID, error) {
	id, err := parseTypedID[principalIDMarker](text)
	return PrincipalID{typedID: id}, err
}
func ParseDeviceID(text string) (DeviceID, error) {
	id, err := parseTypedID[deviceIDMarker](text)
	return DeviceID{typedID: id}, err
}
func ParseMembershipID(text string) (MembershipID, error) {
	id, err := parseTypedID[membershipIDMarker](text)
	return MembershipID{typedID: id}, err
}
func ParseActorID(text string) (ActorID, error) {
	id, err := parseTypedID[actorIDMarker](text)
	return ActorID{typedID: id}, err
}
func ParseActorDelegationID(text string) (ActorDelegationID, error) {
	id, err := parseTypedID[actorDelegationIDMarker](text)
	return ActorDelegationID{typedID: id}, err
}
func ParseActorSessionID(text string) (ActorSessionID, error) {
	id, err := parseTypedID[actorSessionIDMarker](text)
	return ActorSessionID{typedID: id}, err
}
func ParseGrantID(text string) (GrantID, error) {
	id, err := parseTypedID[grantIDMarker](text)
	return GrantID{typedID: id}, err
}
func ParseInvitationID(text string) (InvitationID, error) {
	id, err := parseTypedID[invitationIDMarker](text)
	return InvitationID{typedID: id}, err
}
func ParseCeremonyID(text string) (CeremonyID, error) {
	id, err := parseTypedID[ceremonyIDMarker](text)
	return CeremonyID{typedID: id}, err
}
func ParseBootstrapGenerationID(text string) (BootstrapGenerationID, error) {
	id, err := parseTypedID[bootstrapGenerationIDMarker](text)
	return BootstrapGenerationID{typedID: id}, err
}
func ParseCommandID(text string) (CommandID, error) {
	id, err := parseTypedID[commandIDMarker](text)
	return CommandID{typedID: id}, err
}
func ParseReceiptID(text string) (ReceiptID, error) {
	id, err := parseTypedID[receiptIDMarker](text)
	return ReceiptID{typedID: id}, err
}
func ParseEventID(text string) (EventID, error) {
	id, err := parseTypedID[eventIDMarker](text)
	return EventID{typedID: id}, err
}
func ParseCorrelationID(text string) (CorrelationID, error) {
	id, err := parseTypedID[correlationIDMarker](text)
	return CorrelationID{typedID: id}, err
}
func ParseClientInstanceID(text string) (ClientInstanceID, error) {
	id, err := parseTypedID[clientInstanceIDMarker](text)
	return ClientInstanceID{typedID: id}, err
}

func NewInstallationID() (InstallationID, error) {
	id, err := newTypedID[installationIDMarker]()
	return InstallationID{typedID: id}, err
}
func NewAuthorityID() (AuthorityID, error) {
	id, err := newTypedID[authorityIDMarker]()
	return AuthorityID{typedID: id}, err
}
func NewWorkspaceID() (WorkspaceID, error) {
	id, err := newTypedID[workspaceIDMarker]()
	return WorkspaceID{typedID: id}, err
}
func NewPrincipalID() (PrincipalID, error) {
	id, err := newTypedID[principalIDMarker]()
	return PrincipalID{typedID: id}, err
}
func NewDeviceID() (DeviceID, error) {
	id, err := newTypedID[deviceIDMarker]()
	return DeviceID{typedID: id}, err
}
func NewMembershipID() (MembershipID, error) {
	id, err := newTypedID[membershipIDMarker]()
	return MembershipID{typedID: id}, err
}
func NewActorID() (ActorID, error) {
	id, err := newTypedID[actorIDMarker]()
	return ActorID{typedID: id}, err
}
func NewActorDelegationID() (ActorDelegationID, error) {
	id, err := newTypedID[actorDelegationIDMarker]()
	return ActorDelegationID{typedID: id}, err
}
func NewActorSessionID() (ActorSessionID, error) {
	id, err := newTypedID[actorSessionIDMarker]()
	return ActorSessionID{typedID: id}, err
}
func NewGrantID() (GrantID, error) {
	id, err := newTypedID[grantIDMarker]()
	return GrantID{typedID: id}, err
}
func NewInvitationID() (InvitationID, error) {
	id, err := newTypedID[invitationIDMarker]()
	return InvitationID{typedID: id}, err
}
func NewCeremonyID() (CeremonyID, error) {
	id, err := newTypedID[ceremonyIDMarker]()
	return CeremonyID{typedID: id}, err
}
func NewBootstrapGenerationID() (BootstrapGenerationID, error) {
	id, err := newTypedID[bootstrapGenerationIDMarker]()
	return BootstrapGenerationID{typedID: id}, err
}
func NewCommandID() (CommandID, error) {
	id, err := newTypedID[commandIDMarker]()
	return CommandID{typedID: id}, err
}
func NewReceiptID() (ReceiptID, error) {
	id, err := newTypedID[receiptIDMarker]()
	return ReceiptID{typedID: id}, err
}
func NewEventID() (EventID, error) {
	id, err := newTypedID[eventIDMarker]()
	return EventID{typedID: id}, err
}
func NewCorrelationID() (CorrelationID, error) {
	id, err := newTypedID[correlationIDMarker]()
	return CorrelationID{typedID: id}, err
}
func NewClientInstanceID() (ClientInstanceID, error) {
	id, err := newTypedID[clientInstanceIDMarker]()
	return ClientInstanceID{typedID: id}, err
}
