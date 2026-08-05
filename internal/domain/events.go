package domain

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// EventEnvelopeSchema is the canonical internal journal envelope named by
	// ADR-0004. Public delta codecs may use a different transport schema.
	EventEnvelopeSchema  = "blackbird.event/v1"
	MaxEventPayloadBytes = 64 * 1024
	MaxEventPayloadDepth = 64
)

var (
	ErrInvalidDigest           = errors.New("invalid event digest")
	ErrInvalidEventType        = errors.New("invalid event type")
	ErrInvalidEventSchema      = errors.New("invalid event schema version")
	ErrInvalidEventPayload     = errors.New("invalid event payload")
	ErrEventPayloadTooLarge    = errors.New("event payload exceeds maximum size")
	ErrInvalidStreamPosition   = errors.New("invalid stream position")
	ErrStreamPositionOverflow  = errors.New("stream position overflow")
	ErrInvalidEventEnvelope    = errors.New("invalid event envelope")
	ErrEventDigestVerification = errors.New("event digest verification failed")
	ErrInvalidEventBatch       = errors.New("invalid committed event batch")
)

type digestMarker interface{ digestName() string }

type digestValue[Marker digestMarker] struct {
	value [32]byte
	_     Marker
}

func digestNameOf[Marker digestMarker]() string {
	var marker Marker
	return marker.digestName()
}

func newDigest[Marker digestMarker](value [32]byte) (digestValue[Marker], error) {
	if value == [32]byte{} {
		return digestValue[Marker]{}, fmt.Errorf("%w: zero %s", ErrInvalidDigest, digestNameOf[Marker]())
	}
	return digestValue[Marker]{value: value}, nil
}

func parseDigest[Marker digestMarker](text string) (digestValue[Marker], error) {
	if len(text) != hex.EncodedLen(32) {
		return digestValue[Marker]{}, fmt.Errorf("%w: %s", ErrInvalidDigest, digestNameOf[Marker]())
	}
	for _, character := range text {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return digestValue[Marker]{}, fmt.Errorf("%w: %s", ErrInvalidDigest, digestNameOf[Marker]())
		}
	}
	var value [32]byte
	if _, err := hex.Decode(value[:], []byte(text)); err != nil {
		return digestValue[Marker]{}, fmt.Errorf("%w: %s", ErrInvalidDigest, digestNameOf[Marker]())
	}
	return newDigest[Marker](value)
}

func (digest digestValue[Marker]) IsZero() bool { return digest.value == [32]byte{} }

func (digest digestValue[Marker]) Bytes() [32]byte { return digest.value }

func (digest digestValue[Marker]) String() string {
	if digest.IsZero() {
		return ""
	}
	return hex.EncodeToString(digest.value[:])
}

func (digest digestValue[Marker]) MarshalText() ([]byte, error) {
	if digest.IsZero() {
		return nil, ErrInvalidDigest
	}
	return []byte(digest.String()), nil
}

func (digest *digestValue[Marker]) UnmarshalText(text []byte) error {
	if digest == nil {
		return ErrInvalidDigest
	}
	parsed, err := parseDigest[Marker](string(text))
	if err != nil {
		return err
	}
	*digest = parsed
	return nil
}

func (digest digestValue[Marker]) MarshalJSON() ([]byte, error) {
	text, err := digest.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(text))
}

func (digest *digestValue[Marker]) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return ErrInvalidDigest
	}
	return digest.UnmarshalText([]byte(text))
}

type eventDigestMarker struct{}
type streamDigestMarker struct{}
type authorizationDigestMarker struct{}

func (eventDigestMarker) digestName() string         { return "event digest" }
func (streamDigestMarker) digestName() string        { return "stream digest" }
func (authorizationDigestMarker) digestName() string { return "authorization digest" }

type EventDigest struct{ digestValue[eventDigestMarker] }
type StreamDigest struct {
	digestValue[streamDigestMarker]
}
type AuthorizationDigest struct {
	digestValue[authorizationDigestMarker]
}

func NewEventDigest(value [32]byte) (EventDigest, error) {
	digest, err := newDigest[eventDigestMarker](value)
	return EventDigest{digestValue: digest}, err
}

func ParseEventDigest(text string) (EventDigest, error) {
	digest, err := parseDigest[eventDigestMarker](text)
	return EventDigest{digestValue: digest}, err
}

func NewStreamDigest(value [32]byte) (StreamDigest, error) {
	digest, err := newDigest[streamDigestMarker](value)
	return StreamDigest{digestValue: digest}, err
}

func ParseStreamDigest(text string) (StreamDigest, error) {
	digest, err := parseDigest[streamDigestMarker](text)
	return StreamDigest{digestValue: digest}, err
}

func NewAuthorizationDigest(value [32]byte) (AuthorizationDigest, error) {
	digest, err := newDigest[authorizationDigestMarker](value)
	return AuthorizationDigest{digestValue: digest}, err
}

func ParseAuthorizationDigest(text string) (AuthorizationDigest, error) {
	digest, err := parseDigest[authorizationDigestMarker](text)
	return AuthorizationDigest{digestValue: digest}, err
}

type EventType string

const (
	EventTypeInstallationBootstrapped    EventType = "InstallationBootstrapped"
	EventTypePrincipalRegistered         EventType = "PrincipalRegistered"
	EventTypeDevicePairingBegan          EventType = "DevicePairingBegan"
	EventTypeDevicePaired                EventType = "DevicePaired"
	EventTypeDeviceCredentialRotated     EventType = "DeviceCredentialRotated"
	EventTypeDeviceRevoked               EventType = "DeviceRevoked"
	EventTypeWorkspaceCreated            EventType = "WorkspaceCreated"
	EventTypeWorkspaceMemberInvited      EventType = "WorkspaceMemberInvited"
	EventTypeWorkspaceMembershipAccepted EventType = "WorkspaceMembershipAccepted"
	EventTypeActorCreated                EventType = "ActorCreated"
	EventTypeActorDelegationProposed     EventType = "ActorDelegationProposed"
	EventTypeActorDelegationActivated    EventType = "ActorDelegationActivated"
	EventTypeActorSessionStarted         EventType = "ActorSessionStarted"
)

func (eventType EventType) Valid() bool {
	switch eventType {
	case EventTypeInstallationBootstrapped,
		EventTypePrincipalRegistered,
		EventTypeDevicePairingBegan,
		EventTypeDevicePaired,
		EventTypeDeviceCredentialRotated,
		EventTypeDeviceRevoked,
		EventTypeWorkspaceCreated,
		EventTypeWorkspaceMemberInvited,
		EventTypeWorkspaceMembershipAccepted,
		EventTypeActorCreated,
		EventTypeActorDelegationProposed,
		EventTypeActorDelegationActivated,
		EventTypeActorSessionStarted:
		return true
	default:
		return false
	}
}

type EventSchemaVersion struct{ value uint16 }

func NewEventSchemaVersion(value uint16) (EventSchemaVersion, error) {
	if value == 0 {
		return EventSchemaVersion{}, ErrInvalidEventSchema
	}
	return EventSchemaVersion{value: value}, nil
}

func (version EventSchemaVersion) Uint16() uint16 { return version.value }
func (version EventSchemaVersion) IsZero() bool   { return version.value == 0 }

type StreamPosition struct{ value uint64 }

func NewStreamPosition(value uint64) (StreamPosition, error) {
	if value == 0 || value > MaxCanonicalInteger {
		return StreamPosition{}, ErrInvalidStreamPosition
	}
	return StreamPosition{value: value}, nil
}

func ParseStreamPosition(text string) (StreamPosition, error) {
	if text == "" || text[0] == '+' || text[0] == '-' || (len(text) > 1 && text[0] == '0') {
		return StreamPosition{}, ErrInvalidStreamPosition
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return StreamPosition{}, fmt.Errorf("%w: %q", ErrInvalidStreamPosition, text)
	}
	return NewStreamPosition(value)
}

func (position StreamPosition) Uint64() uint64 { return position.value }
func (position StreamPosition) IsZero() bool   { return position.value == 0 }
func (position StreamPosition) Valid() bool {
	return position.value > 0 && position.value <= MaxCanonicalInteger
}

func (position StreamPosition) Next() (StreamPosition, error) {
	if !position.Valid() {
		return StreamPosition{}, ErrInvalidStreamPosition
	}
	if position.value == MaxCanonicalInteger {
		return StreamPosition{}, ErrStreamPositionOverflow
	}
	return StreamPosition{value: position.value + 1}, nil
}

func (position StreamPosition) MarshalText() ([]byte, error) {
	if !position.Valid() {
		return nil, ErrInvalidStreamPosition
	}
	return strconv.AppendUint(nil, position.value, 10), nil
}

func (position *StreamPosition) UnmarshalText(text []byte) error {
	if position == nil {
		return ErrInvalidStreamPosition
	}
	parsed, err := ParseStreamPosition(string(text))
	if err != nil {
		return err
	}
	*position = parsed
	return nil
}

func (position StreamPosition) MarshalJSON() ([]byte, error) {
	if !position.Valid() {
		return nil, ErrInvalidStreamPosition
	}
	return strconv.AppendUint(nil, position.value, 10), nil
}

func (position *StreamPosition) UnmarshalJSON(data []byte) error {
	if position == nil {
		return ErrInvalidStreamPosition
	}
	var value uint64
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidStreamPosition, data)
	}
	parsed, err := NewStreamPosition(value)
	if err != nil {
		return err
	}
	*position = parsed
	return nil
}

// EventPayload owns bounded I-JSON object bytes. It rejects duplicate object
// keys (after escape decoding) and values outside finite IEEE-754 range. RFC
// 8785 serialization and event-specific schema validation belong to the codec
// that verifies and constructs an envelope.
type EventPayload struct{ object []byte }

func NewEventPayload(object []byte) (EventPayload, error) {
	if len(object) > MaxEventPayloadBytes {
		return EventPayload{}, ErrEventPayloadTooLarge
	}
	trimmed := strings.TrimSpace(string(object))
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' ||
		!utf8.ValidString(trimmed) || !validJSONStringSurrogates([]byte(trimmed)) {
		return EventPayload{}, ErrInvalidEventPayload
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.UseNumber()
	if err := validateIJSONValue(decoder, true, 1); err != nil {
		return EventPayload{}, fmt.Errorf("%w: %v", ErrInvalidEventPayload, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return EventPayload{}, ErrInvalidEventPayload
	}
	return EventPayload{object: append([]byte(nil), trimmed...)}, nil
}

func validateIJSONValue(decoder *json.Decoder, requireObject bool, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case json.Delim:
		if depth > MaxEventPayloadDepth {
			return ErrInvalidEventPayload
		}
		switch value {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidEventPayload
				}
				if _, duplicate := keys[key]; duplicate {
					return fmt.Errorf("duplicate object key %q", key)
				}
				keys[key] = struct{}{}
				if err := validateIJSONValue(decoder, false, depth+1); err != nil {
					return err
				}
			}
			closing, closingErr := decoder.Token()
			if closingErr != nil || closing != json.Delim('}') {
				return ErrInvalidEventPayload
			}
			return nil
		case '[':
			if requireObject {
				return ErrInvalidEventPayload
			}
			for decoder.More() {
				if err := validateIJSONValue(decoder, false, depth+1); err != nil {
					return err
				}
			}
			closing, closingErr := decoder.Token()
			if closingErr != nil || closing != json.Delim(']') {
				return ErrInvalidEventPayload
			}
			return nil
		default:
			return ErrInvalidEventPayload
		}
	case json.Number:
		if requireObject {
			return ErrInvalidEventPayload
		}
		number, parseErr := strconv.ParseFloat(value.String(), 64)
		if parseErr != nil || math.IsInf(number, 0) || math.IsNaN(number) ||
			number < 0 || math.Trunc(number) != number || number > float64(MaxCanonicalInteger) {
			return ErrInvalidEventPayload
		}
		return nil
	case string, bool, nil:
		if requireObject {
			return ErrInvalidEventPayload
		}
		return nil
	default:
		return ErrInvalidEventPayload
	}
}

func validJSONStringSurrogates(data []byte) bool {
	inString := false
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(data) {
				continue
			}
			index++
			if data[index] != 'u' {
				continue
			}
			if index+4 >= len(data) {
				return false
			}
			unit, err := strconv.ParseUint(string(data[index+1:index+5]), 16, 16)
			if err != nil {
				return false
			}
			index += 4
			switch {
			case unit >= 0xd800 && unit <= 0xdbff:
				if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
					return false
				}
				low, lowErr := strconv.ParseUint(string(data[index+3:index+7]), 16, 16)
				if lowErr != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				index += 6
			case unit >= 0xdc00 && unit <= 0xdfff:
				return false
			}
		}
	}
	return true
}

func (payload EventPayload) IsZero() bool  { return len(payload.object) == 0 }
func (payload EventPayload) Bytes() []byte { return append([]byte(nil), payload.object...) }

func (payload EventPayload) MarshalJSON() ([]byte, error) {
	if payload.IsZero() {
		return nil, ErrInvalidEventPayload
	}
	return payload.Bytes(), nil
}

// EventEnvelopeParams is constructor input only. EventEnvelope retains values
// immutably and exposes copies for reference-backed fields.
type EventEnvelopeParams struct {
	EventID              EventID
	CommandID            CommandID
	AuthorityID          AuthorityID
	AuthorityEpoch       AuthorityEpoch
	Scope                AuthorityScope
	StreamPosition       StreamPosition
	PreviousStreamDigest StreamDigest
	EventDigest          EventDigest
	StreamDigest         StreamDigest
	Aggregate            AggregateRef
	EventIndex           uint16
	EventType            EventType
	SchemaVersion        EventSchemaVersion
	Payload              EventPayload
	PrincipalID          PrincipalID
	ActorSessionID       *ActorSessionID
	AuthorizationDigest  AuthorizationDigest
	CommandReceiptID     ReceiptID
	CausationEventID     *EventID
	CorrelationID        CorrelationID
	RecordedAt           time.Time
}

type EventEnvelope struct {
	eventID              EventID
	commandID            CommandID
	authorityID          AuthorityID
	authorityEpoch       AuthorityEpoch
	scope                AuthorityScope
	streamPosition       StreamPosition
	previousStreamDigest StreamDigest
	eventDigest          EventDigest
	streamDigest         StreamDigest
	aggregate            AggregateRef
	eventIndex           uint16
	eventType            EventType
	schemaVersion        EventSchemaVersion
	payload              EventPayload
	principalID          PrincipalID
	actorSessionID       ActorSessionID
	hasActorSession      bool
	authorizationDigest  AuthorizationDigest
	commandReceiptID     ReceiptID
	causationEventID     EventID
	hasCausationEvent    bool
	correlationID        CorrelationID
	recordedAt           time.Time
}

// EventDigestVerifier is the mandatory trust boundary implemented by the
// canonical RFC 8785 event codec. The interface ensures verification is
// invoked during construction; composition tests must still prove production
// wiring supplies the reviewed verifier rather than a permissive substitute.
type EventDigestVerifier interface {
	VerifyEventDigests(EventEnvelope) error
}

func NewEventEnvelope(params EventEnvelopeParams, verifier EventDigestVerifier) (EventEnvelope, error) {
	if verifier == nil || nilEventDigestVerifier(verifier) {
		return EventEnvelope{}, ErrEventDigestVerification
	}
	envelope, err := newUnverifiedEventEnvelope(params)
	if err != nil {
		return EventEnvelope{}, err
	}
	if err := verifier.VerifyEventDigests(envelope); err != nil {
		return EventEnvelope{}, fmt.Errorf("%w: %w", ErrEventDigestVerification, err)
	}
	return envelope, nil
}

func nilEventDigestVerifier(verifier EventDigestVerifier) bool {
	value := reflect.ValueOf(verifier)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func newUnverifiedEventEnvelope(params EventEnvelopeParams) (EventEnvelope, error) {
	if params.EventID.IsZero() || params.CommandID.IsZero() || params.AuthorityID.IsZero() ||
		params.AuthorityEpoch.IsZero() || params.Scope.IsZero() || !params.StreamPosition.Valid() ||
		params.PreviousStreamDigest.IsZero() || params.EventDigest.IsZero() || params.StreamDigest.IsZero() ||
		params.Aggregate.IsZero() || !params.EventType.Valid() || params.SchemaVersion.IsZero() ||
		params.Payload.IsZero() || params.PrincipalID.IsZero() || params.AuthorizationDigest.IsZero() ||
		params.CommandReceiptID.IsZero() || params.CorrelationID.IsZero() || params.RecordedAt.IsZero() {
		return EventEnvelope{}, ErrInvalidEventEnvelope
	}

	envelope := EventEnvelope{
		eventID:              params.EventID,
		commandID:            params.CommandID,
		authorityID:          params.AuthorityID,
		authorityEpoch:       params.AuthorityEpoch,
		scope:                params.Scope,
		streamPosition:       params.StreamPosition,
		previousStreamDigest: params.PreviousStreamDigest,
		eventDigest:          params.EventDigest,
		streamDigest:         params.StreamDigest,
		aggregate:            params.Aggregate,
		eventIndex:           params.EventIndex,
		eventType:            params.EventType,
		schemaVersion:        params.SchemaVersion,
		payload:              EventPayload{object: params.Payload.Bytes()},
		principalID:          params.PrincipalID,
		authorizationDigest:  params.AuthorizationDigest,
		commandReceiptID:     params.CommandReceiptID,
		correlationID:        params.CorrelationID,
		recordedAt:           params.RecordedAt.UTC(),
	}
	if params.ActorSessionID != nil {
		if params.ActorSessionID.IsZero() {
			return EventEnvelope{}, ErrInvalidEventEnvelope
		}
		envelope.actorSessionID = *params.ActorSessionID
		envelope.hasActorSession = true
	}
	if params.CausationEventID != nil {
		if params.CausationEventID.IsZero() || *params.CausationEventID == params.EventID {
			return EventEnvelope{}, ErrInvalidEventEnvelope
		}
		envelope.causationEventID = *params.CausationEventID
		envelope.hasCausationEvent = true
	}
	return envelope, nil
}

func (event EventEnvelope) EventID() EventID                   { return event.eventID }
func (event EventEnvelope) CommandID() CommandID               { return event.commandID }
func (event EventEnvelope) AuthorityID() AuthorityID           { return event.authorityID }
func (event EventEnvelope) AuthorityEpoch() AuthorityEpoch     { return event.authorityEpoch }
func (event EventEnvelope) Scope() AuthorityScope              { return event.scope }
func (event EventEnvelope) StreamPosition() StreamPosition     { return event.streamPosition }
func (event EventEnvelope) PreviousStreamDigest() StreamDigest { return event.previousStreamDigest }
func (event EventEnvelope) EventDigest() EventDigest           { return event.eventDigest }
func (event EventEnvelope) StreamDigest() StreamDigest         { return event.streamDigest }
func (event EventEnvelope) Aggregate() AggregateRef            { return event.aggregate }
func (event EventEnvelope) EventIndex() uint16                 { return event.eventIndex }
func (event EventEnvelope) EventType() EventType               { return event.eventType }
func (event EventEnvelope) SchemaVersion() EventSchemaVersion  { return event.schemaVersion }
func (event EventEnvelope) Payload() EventPayload {
	return EventPayload{object: event.payload.Bytes()}
}
func (event EventEnvelope) PrincipalID() PrincipalID { return event.principalID }
func (event EventEnvelope) AuthorizationDigest() AuthorizationDigest {
	return event.authorizationDigest
}
func (event EventEnvelope) CommandReceiptID() ReceiptID  { return event.commandReceiptID }
func (event EventEnvelope) CorrelationID() CorrelationID { return event.correlationID }
func (event EventEnvelope) RecordedAt() time.Time        { return event.recordedAt }

func (event EventEnvelope) ActorSessionID() (ActorSessionID, bool) {
	return event.actorSessionID, event.hasActorSession
}

func (event EventEnvelope) CausationEventID() (EventID, bool) {
	return event.causationEventID, event.hasCausationEvent
}

func (event EventEnvelope) MarshalJSON() ([]byte, error) {
	if event.eventID.IsZero() || !event.streamPosition.Valid() || event.aggregate.IsZero() || event.payload.IsZero() {
		return nil, ErrInvalidEventEnvelope
	}
	var actorSessionID *ActorSessionID
	if event.hasActorSession {
		actorSessionID = &event.actorSessionID
	}
	var causationEventID *EventID
	if event.hasCausationEvent {
		causationEventID = &event.causationEventID
	}
	return json.Marshal(struct {
		Schema               string              `json:"schema"`
		EventID              EventID             `json:"event_id"`
		CommandID            CommandID           `json:"command_id"`
		AuthorityID          AuthorityID         `json:"authority_id"`
		AuthorityEpoch       AuthorityEpoch      `json:"authority_epoch"`
		ScopeKind            ScopeKind           `json:"scope_kind"`
		ScopeID              string              `json:"scope_id"`
		StreamSequence       uint64              `json:"stream_sequence"`
		PreviousStreamDigest StreamDigest        `json:"previous_stream_digest"`
		EventDigest          EventDigest         `json:"event_digest"`
		StreamDigest         StreamDigest        `json:"stream_digest"`
		AggregateKind        AggregateKind       `json:"aggregate_kind"`
		AggregateID          string              `json:"aggregate_id"`
		AggregateVersion     uint64              `json:"aggregate_version"`
		EventIndex           uint16              `json:"event_index"`
		EventType            EventType           `json:"event_type"`
		EventSchema          uint16              `json:"event_schema"`
		Payload              EventPayload        `json:"payload"`
		PrincipalID          PrincipalID         `json:"principal_id"`
		ActorSessionID       *ActorSessionID     `json:"actor_session_id,omitempty"`
		AuthorizationDigest  AuthorizationDigest `json:"authorization_digest"`
		CommandReceiptID     ReceiptID           `json:"command_receipt_id"`
		CausationEventID     *EventID            `json:"causation_event_id,omitempty"`
		CorrelationID        CorrelationID       `json:"correlation_id"`
		RecordedAt           time.Time           `json:"recorded_at"`
	}{
		Schema:               EventEnvelopeSchema,
		EventID:              event.eventID,
		CommandID:            event.commandID,
		AuthorityID:          event.authorityID,
		AuthorityEpoch:       event.authorityEpoch,
		ScopeKind:            event.scope.Kind(),
		ScopeID:              event.scope.ID(),
		StreamSequence:       event.streamPosition.Uint64(),
		PreviousStreamDigest: event.previousStreamDigest,
		EventDigest:          event.eventDigest,
		StreamDigest:         event.streamDigest,
		AggregateKind:        event.aggregate.Kind(),
		AggregateID:          event.aggregate.ID(),
		AggregateVersion:     event.aggregate.Version().Uint64(),
		EventIndex:           event.eventIndex,
		EventType:            event.eventType,
		EventSchema:          event.schemaVersion.Uint16(),
		Payload:              event.payload,
		PrincipalID:          event.principalID,
		ActorSessionID:       actorSessionID,
		AuthorizationDigest:  event.authorizationDigest,
		CommandReceiptID:     event.commandReceiptID,
		CausationEventID:     causationEventID,
		CorrelationID:        event.correlationID,
		RecordedAt:           event.recordedAt,
	})
}

// CommittedEventBatch enforces same-command identity, attribution, ordering,
// and represented digest-chain continuity. Cryptographic correctness remains
// the verifier trust boundary's responsibility.
type CommittedEventBatch struct{ events []EventEnvelope }

func NewCommittedEventBatch(events []EventEnvelope) (CommittedEventBatch, error) {
	if len(events) == 0 || len(events) > int(^uint16(0))+1 {
		return CommittedEventBatch{}, ErrInvalidEventBatch
	}
	cloned := append([]EventEnvelope(nil), events...)
	first := cloned[0]
	seenEventIDs := make(map[EventID]struct{}, len(cloned))
	for index, event := range cloned {
		if event.eventID.IsZero() || !event.streamPosition.Valid() || event.aggregate.IsZero() ||
			event.commandID != first.commandID ||
			event.authorityID != first.authorityID || !event.authorityEpoch.Equal(first.authorityEpoch) ||
			event.scope != first.scope || event.commandReceiptID != first.commandReceiptID ||
			event.correlationID != first.correlationID || event.principalID != first.principalID ||
			event.hasActorSession != first.hasActorSession || event.actorSessionID != first.actorSessionID ||
			event.authorizationDigest != first.authorizationDigest ||
			event.hasCausationEvent != first.hasCausationEvent || event.causationEventID != first.causationEventID ||
			event.eventIndex != uint16(index) {
			return CommittedEventBatch{}, ErrInvalidEventBatch
		}
		if _, duplicate := seenEventIDs[event.eventID]; duplicate {
			return CommittedEventBatch{}, ErrInvalidEventBatch
		}
		seenEventIDs[event.eventID] = struct{}{}
		if index > 0 {
			previous := cloned[index-1]
			expectedPosition, err := previous.streamPosition.Next()
			if err != nil || event.streamPosition != expectedPosition || event.previousStreamDigest != previous.streamDigest {
				return CommittedEventBatch{}, ErrInvalidEventBatch
			}
		}
	}
	return CommittedEventBatch{events: cloned}, nil
}

func (batch CommittedEventBatch) Events() []EventEnvelope {
	return append([]EventEnvelope(nil), batch.events...)
}

func (batch CommittedEventBatch) FirstPosition() (StreamPosition, bool) {
	if len(batch.events) == 0 {
		return StreamPosition{}, false
	}
	return batch.events[0].streamPosition, true
}

func (batch CommittedEventBatch) LastPosition() (StreamPosition, bool) {
	if len(batch.events) == 0 {
		return StreamPosition{}, false
	}
	return batch.events[len(batch.events)-1].streamPosition, true
}

func (version EventSchemaVersion) String() string {
	return strconv.FormatUint(uint64(version.value), 10)
}
