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
	IdentifierKindWorkReference       IdentifierKind = "work_reference"
	IdentifierKindObjective           IdentifierKind = "objective"
	IdentifierKindWorkUnit            IdentifierKind = "work_unit"
	IdentifierKindRun                 IdentifierKind = "run"
	IdentifierKindRunParticipation    IdentifierKind = "run_participation"
	IdentifierKindRuntimeBinding      IdentifierKind = "runtime_binding"
	IdentifierKindRuntimeEndpoint     IdentifierKind = "runtime_endpoint"
	IdentifierKindConversation        IdentifierKind = "conversation"
	IdentifierKindMessage             IdentifierKind = "message"
	IdentifierKindLease               IdentifierKind = "lease"
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

type authorityIDMarker struct{}
type observationIDMarker struct{}

func (authorityIDMarker) identifierKind() IdentifierKind   { return "authority" }
func (observationIDMarker) identifierKind() IdentifierKind { return "observation" }

type AuthorityID struct{ typedID[authorityIDMarker] }

// ObservationID names one stored model call or span.
type ObservationID struct{ typedID[observationIDMarker] }

func NewObservationID() (ObservationID, error) {
	id, err := newTypedID[observationIDMarker]()
	return ObservationID{typedID: id}, err
}

func ParseAuthorityID(text string) (AuthorityID, error) {
	id, err := parseTypedID[authorityIDMarker](text)
	return AuthorityID{typedID: id}, err
}
func NewAuthorityID() (AuthorityID, error) {
	id, err := newTypedID[authorityIDMarker]()
	return AuthorityID{typedID: id}, err
}

type workspaceIDMarker struct{}

func (workspaceIDMarker) identifierKind() IdentifierKind { return "workspace" }

type WorkspaceID struct{ typedID[workspaceIDMarker] }

func ParseWorkspaceID(text string) (WorkspaceID, error) {
	id, err := parseTypedID[workspaceIDMarker](text)
	return WorkspaceID{typedID: id}, err
}
func NewWorkspaceID() (WorkspaceID, error) {
	id, err := newTypedID[workspaceIDMarker]()
	return WorkspaceID{typedID: id}, err
}

type actorIDMarker struct{}

func (actorIDMarker) identifierKind() IdentifierKind { return "actor" }

type ActorID struct{ typedID[actorIDMarker] }

func ParseActorID(text string) (ActorID, error) {
	id, err := parseTypedID[actorIDMarker](text)
	return ActorID{typedID: id}, err
}
func NewActorID() (ActorID, error) {
	id, err := newTypedID[actorIDMarker]()
	return ActorID{typedID: id}, err
}

type actorSessionIDMarker struct{}

func (actorSessionIDMarker) identifierKind() IdentifierKind { return "actor_session" }

type ActorSessionID struct{ typedID[actorSessionIDMarker] }

func ParseActorSessionID(text string) (ActorSessionID, error) {
	id, err := parseTypedID[actorSessionIDMarker](text)
	return ActorSessionID{typedID: id}, err
}
func NewActorSessionID() (ActorSessionID, error) {
	id, err := newTypedID[actorSessionIDMarker]()
	return ActorSessionID{typedID: id}, err
}

type runIDMarker struct{}

func (runIDMarker) identifierKind() IdentifierKind { return "run" }

type RunID struct{ typedID[runIDMarker] }

func ParseRunID(text string) (RunID, error) {
	id, err := parseTypedID[runIDMarker](text)
	return RunID{typedID: id}, err
}
func NewRunID() (RunID, error) { id, err := newTypedID[runIDMarker](); return RunID{typedID: id}, err }

type conversationIDMarker struct{}

func (conversationIDMarker) identifierKind() IdentifierKind { return "conversation" }

type ConversationID struct{ typedID[conversationIDMarker] }

func ParseConversationID(text string) (ConversationID, error) {
	id, err := parseTypedID[conversationIDMarker](text)
	return ConversationID{typedID: id}, err
}
func NewConversationID() (ConversationID, error) {
	id, err := newTypedID[conversationIDMarker]()
	return ConversationID{typedID: id}, err
}

type messageIDMarker struct{}

func (messageIDMarker) identifierKind() IdentifierKind { return "message" }

type MessageID struct{ typedID[messageIDMarker] }

func ParseMessageID(text string) (MessageID, error) {
	id, err := parseTypedID[messageIDMarker](text)
	return MessageID{typedID: id}, err
}
func NewMessageID() (MessageID, error) {
	id, err := newTypedID[messageIDMarker]()
	return MessageID{typedID: id}, err
}

type leaseIDMarker struct{}

func (leaseIDMarker) identifierKind() IdentifierKind { return "lease" }

type LeaseID struct{ typedID[leaseIDMarker] }

func ParseLeaseID(text string) (LeaseID, error) {
	id, err := parseTypedID[leaseIDMarker](text)
	return LeaseID{typedID: id}, err
}
func NewLeaseID() (LeaseID, error) {
	id, err := newTypedID[leaseIDMarker]()
	return LeaseID{typedID: id}, err
}
