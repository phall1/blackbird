package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func digestBytes(seed byte) [32]byte {
	var value [32]byte
	value[0] = seed
	return value
}

type testDigestVerifier func(EventEnvelope) error

func (verify testDigestVerifier) VerifyEventDigests(event EventEnvelope) error { return verify(event) }

var acceptEventDigests = testDigestVerifier(func(EventEnvelope) error { return nil })

func validEnvelopeParams(t *testing.T) EventEnvelopeParams {
	t.Helper()
	eventID, _ := ParseEventID("01b8e094-9888-7000-8000-000000000001")
	commandID, _ := ParseCommandID("01b8e094-9888-7000-8000-000000000002")
	authorityID, _ := ParseAuthorityID("01b8e094-9888-7000-8000-000000000003")
	epoch, _ := ParseAuthorityEpoch("01b8e094-9888-7000-8000-000000000004")
	workspaceID, _ := ParseWorkspaceID("01b8e094-9888-7000-8000-000000000005")
	scope, _ := WorkspaceScope(workspaceID)
	position, _ := NewStreamPosition(41)
	previousDigest, _ := NewStreamDigest(digestBytes(1))
	eventDigest, _ := NewEventDigest(digestBytes(2))
	streamDigest, _ := NewStreamDigest(digestBytes(3))
	actorID, _ := ParseActorID("01b8e094-9888-7000-8000-000000000006")
	aggregate, _ := NewAggregateRef(actorID, mustVersion(t, 7))
	schema, _ := NewEventSchemaVersion(1)
	payload, _ := NewEventPayload([]byte(`{"actor_kind":"agent"}`))
	principalID, _ := ParsePrincipalID("01b8e094-9888-7000-8000-000000000007")
	actorSessionID, _ := ParseActorSessionID("01b8e094-9888-7000-8000-000000000008")
	authorizationDigest, _ := NewAuthorizationDigest(digestBytes(4))
	receiptID, _ := ParseReceiptID("01b8e094-9888-7000-8000-000000000009")
	causationID, _ := ParseEventID("01b8e094-9888-7000-8000-00000000000a")
	correlationID, _ := ParseCorrelationID("01b8e094-9888-7000-8000-00000000000b")
	return EventEnvelopeParams{
		EventID:              eventID,
		CommandID:            commandID,
		AuthorityID:          authorityID,
		AuthorityEpoch:       epoch,
		Scope:                scope,
		StreamPosition:       position,
		PreviousStreamDigest: previousDigest,
		EventDigest:          eventDigest,
		StreamDigest:         streamDigest,
		Aggregate:            aggregate,
		EventIndex:           0,
		EventType:            EventTypeActorCreated,
		SchemaVersion:        schema,
		Payload:              payload,
		PrincipalID:          principalID,
		ActorSessionID:       &actorSessionID,
		AuthorizationDigest:  authorizationDigest,
		CommandReceiptID:     receiptID,
		CausationEventID:     &causationID,
		CorrelationID:        correlationID,
		RecordedAt:           time.Date(2026, 8, 4, 12, 0, 0, 123, time.FixedZone("source", -4*60*60)),
	}
}

func TestW0EventVocabularyIsClosed(t *testing.T) {
	eventTypes := []EventType{
		EventTypeInstallationBootstrapped,
		EventTypePrincipalRegistered,
		EventTypeDevicePairingBegan,
		EventTypeDevicePaired,
		EventTypeWorkspaceCreated,
		EventTypeWorkspaceMemberInvited,
		EventTypeWorkspaceMembershipAccepted,
		EventTypeActorCreated,
		EventTypeActorDelegationProposed,
		EventTypeActorDelegationActivated,
		EventTypeActorSessionStarted,
	}
	for _, eventType := range eventTypes {
		if !eventType.Valid() {
			t.Errorf("cataloged W0 event %q is invalid", eventType)
		}
	}
	if EventType("ContextCheckpointCreated").Valid() {
		t.Fatal("non-W0/query-only fact entered the W0 event vocabulary")
	}
}

func TestEventPayloadIsBoundedObjectAndImmutable(t *testing.T) {
	source := []byte(` {"value":1} `)
	payload, err := NewEventPayload(source)
	if err != nil {
		t.Fatal(err)
	}
	source[2] = 'X'
	returned := payload.Bytes()
	returned[2] = 'Y'
	if string(payload.Bytes()) != `{"value":1}` {
		t.Fatalf("payload storage mutated: %s", payload.Bytes())
	}
	for _, invalid := range [][]byte{nil, []byte(`null`), []byte(`[]`), []byte(`{"broken"`)} {
		if _, err := NewEventPayload(invalid); !errors.Is(err, ErrInvalidEventPayload) {
			t.Errorf("payload %q error = %v", invalid, err)
		}
	}
	for _, nonIJSON := range [][]byte{
		[]byte(`{"duplicate":1,"duplicate":2}`),
		[]byte(`{"duplicate":1,"\u0064uplicate":2}`),
		[]byte("{\"invalid\":\"\xff\"}"),
		[]byte(`{"overflow":1e999}`),
		[]byte(`{"unsafe_integer":9007199254740992}`),
		[]byte(`{"unsafe_decimal_integer":9007199254740992.0}`),
		[]byte(`{"unsafe_exponent_integer":9.007199254740992e15}`),
		[]byte(`{"unpaired_surrogate":"\ud800"}`),
	} {
		if _, err := NewEventPayload(nonIJSON); !errors.Is(err, ErrInvalidEventPayload) {
			t.Errorf("non-I-JSON payload %q error = %v", nonIJSON, err)
		}
	}
	if _, err := NewEventPayload(bytes.Repeat([]byte{'x'}, MaxEventPayloadBytes+1)); !errors.Is(err, ErrEventPayloadTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestDigestTypesAreStrictAndNonInterchangeable(t *testing.T) {
	eventDigest, err := NewEventDigest(digestBytes(0xab))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEventDigest(eventDigest.String())
	if err != nil || parsed != eventDigest {
		t.Fatalf("parse = %v, %v", parsed, err)
	}
	encoded, err := json.Marshal(eventDigest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded EventDigest
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != eventDigest {
		t.Fatalf("round trip = %v, %v", decoded, err)
	}
	if _, err := ParseEventDigest(strings.ToUpper(eventDigest.String())); !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("uppercase digest error = %v", err)
	}
	if _, err := NewStreamDigest([32]byte{}); !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("zero digest error = %v", err)
	}
}

func TestEventEnvelopeOwnsCompleteInternalVocabulary(t *testing.T) {
	params := validEnvelopeParams(t)
	envelope, err := NewEventEnvelope(params, acceptEventDigests)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.EventID() != params.EventID || envelope.CommandID() != params.CommandID ||
		envelope.AuthorityID() != params.AuthorityID || !envelope.AuthorityEpoch().Equal(params.AuthorityEpoch) ||
		envelope.Scope() != params.Scope || envelope.Aggregate() != params.Aggregate ||
		envelope.PrincipalID() != params.PrincipalID || envelope.CommandReceiptID() != params.CommandReceiptID ||
		envelope.CorrelationID() != params.CorrelationID || envelope.RecordedAt().Location() != time.UTC {
		t.Fatalf("envelope dropped required fields: %#v", envelope)
	}
	if actorSession, ok := envelope.ActorSessionID(); !ok || actorSession != *params.ActorSessionID {
		t.Fatalf("actor session = %v, %v", actorSession, ok)
	}
	if cause, ok := envelope.CausationEventID(); !ok || cause != *params.CausationEventID {
		t.Fatalf("causation = %v, %v", cause, ok)
	}
	returnedPayload := envelope.Payload().Bytes()
	returnedPayload[0] = 'X'
	if envelope.Payload().Bytes()[0] != '{' {
		t.Fatal("envelope payload leaked mutable storage")
	}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"schema", "event_id", "command_id", "authority_id", "authority_epoch",
		"scope_kind", "scope_id", "stream_sequence", "previous_stream_digest",
		"event_digest", "stream_digest", "aggregate_kind", "aggregate_id",
		"aggregate_version", "event_index", "event_type", "event_schema", "payload",
		"principal_id", "actor_session_id", "authorization_digest", "command_receipt_id",
		"causation_event_id", "correlation_id", "recorded_at",
	} {
		if _, present := decoded[field]; !present {
			t.Errorf("marshal omitted %q", field)
		}
	}
	if string(decoded["schema"]) != `"`+EventEnvelopeSchema+`"` {
		t.Fatalf("schema = %s", decoded["schema"])
	}
}

func TestEventEnvelopeRejectsInvalidRequiredAndSelfCausation(t *testing.T) {
	if _, err := NewEventEnvelope(validEnvelopeParams(t), nil); !errors.Is(err, ErrEventDigestVerification) {
		t.Fatalf("missing verifier error = %v", err)
	}
	rejected := testDigestVerifier(func(EventEnvelope) error { return errors.New("digest mismatch") })
	if _, err := NewEventEnvelope(validEnvelopeParams(t), rejected); !errors.Is(err, ErrEventDigestVerification) {
		t.Fatalf("digest mismatch error = %v", err)
	}
	params := validEnvelopeParams(t)
	params.CommandID = CommandID{}
	if _, err := NewEventEnvelope(params, acceptEventDigests); !errors.Is(err, ErrInvalidEventEnvelope) {
		t.Fatalf("missing command error = %v", err)
	}
	params = validEnvelopeParams(t)
	params.CausationEventID = &params.EventID
	if _, err := NewEventEnvelope(params, acceptEventDigests); !errors.Is(err, ErrInvalidEventEnvelope) {
		t.Fatalf("self-causation error = %v", err)
	}
}

func TestCommittedEventBatchEnforcesCommandOrderAndDigestChain(t *testing.T) {
	firstParams := validEnvelopeParams(t)
	first, err := NewEventEnvelope(firstParams, acceptEventDigests)
	if err != nil {
		t.Fatal(err)
	}
	secondParams := firstParams
	secondParams.EventID, _ = ParseEventID("01b8e094-9888-7000-8000-00000000000c")
	secondParams.EventIndex = 1
	secondParams.StreamPosition, _ = first.StreamPosition().Next()
	secondParams.PreviousStreamDigest = first.StreamDigest()
	secondParams.EventDigest, _ = NewEventDigest(digestBytes(5))
	secondParams.StreamDigest, _ = NewStreamDigest(digestBytes(6))
	secondParams.EventType = EventTypeActorDelegationProposed
	second, err := NewEventEnvelope(secondParams, acceptEventDigests)
	if err != nil {
		t.Fatal(err)
	}

	input := []EventEnvelope{first, second}
	batch, err := NewCommittedEventBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = EventEnvelope{}
	events := batch.Events()
	events[0] = EventEnvelope{}
	if batch.Events()[0].EventID() != first.EventID() {
		t.Fatal("batch leaked mutable event slice storage")
	}
	if start, ok := batch.FirstPosition(); !ok || start != first.StreamPosition() {
		t.Fatalf("first position = %v, %v", start, ok)
	}
	if end, ok := batch.LastPosition(); !ok || end != second.StreamPosition() {
		t.Fatalf("last position = %v, %v", end, ok)
	}

	broken := secondParams
	broken.EventIndex = 2
	brokenEvent, _ := NewEventEnvelope(broken, acceptEventDigests)
	if _, err := NewCommittedEventBatch([]EventEnvelope{first, brokenEvent}); !errors.Is(err, ErrInvalidEventBatch) {
		t.Fatalf("broken index error = %v", err)
	}
	duplicateID := secondParams
	duplicateID.EventID = first.EventID()
	duplicateEvent, _ := NewEventEnvelope(duplicateID, acceptEventDigests)
	if _, err := NewCommittedEventBatch([]EventEnvelope{first, duplicateEvent}); !errors.Is(err, ErrInvalidEventBatch) {
		t.Fatalf("duplicate event ID error = %v", err)
	}
	changedAuthorization := secondParams
	changedAuthorization.AuthorizationDigest, _ = NewAuthorizationDigest(digestBytes(9))
	changedAuthorizationEvent, _ := NewEventEnvelope(changedAuthorization, acceptEventDigests)
	if _, err := NewCommittedEventBatch([]EventEnvelope{first, changedAuthorizationEvent}); !errors.Is(err, ErrInvalidEventBatch) {
		t.Fatalf("changed authorization context error = %v", err)
	}
}
