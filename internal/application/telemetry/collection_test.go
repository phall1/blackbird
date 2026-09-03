package telemetry_test

import (
	"context"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

func collectorAttribution(t *testing.T) telemetry.Attribution {
	t.Helper()
	attribution, err := telemetry.CollectorAttribution(domain.HarnessClaudeCode, "/proj")
	if err != nil {
		t.Fatalf("CollectorAttribution() error = %v", err)
	}
	return attribution
}

func collectedModelCall(harness domain.Harness, key string) domain.ModelCall {
	return domain.ModelCall{
		DedupeKey: key, Harness: harness, Provider: "anthropic", Model: "m",
		Operation: domain.ModelOperationChat, Outcome: domain.ObservedOutcomeOK,
		StartedAt: time.Date(2026, time.September, 2, 5, 0, 0, 0, time.UTC),
	}
}

func TestCollectorAttributionIsStableDistinctAndUnregistered(t *testing.T) {
	t.Parallel()
	first := collectorAttribution(t)
	second := collectorAttribution(t)
	// Determinism is what lets a restart, a rebuilt database, or a machine move
	// re-offer a record and have the dedupe index collapse it. Minted per
	// process, every restart would duplicate history instead.
	if first.ActorID != second.ActorID || first.SessionID != second.SessionID {
		t.Fatalf("collector identity is not deterministic: %v vs %v", first.ActorID, second.ActorID)
	}
	if first.ActorID.IsZero() || first.SessionID.IsZero() {
		t.Fatal("collector identity is zero")
	}
	if first.ActorID.String() == first.SessionID.String() {
		t.Error("actor and session derived to the same value")
	}
	other, err := telemetry.CollectorAttribution(domain.HarnessOpenCode, "/proj")
	if err != nil {
		t.Fatalf("CollectorAttribution(opencode) error = %v", err)
	}
	if other.ActorID == first.ActorID {
		t.Error("two harnesses share a collector actor; one ledger could adopt the other's records")
	}
	if first.ProjectKey != "/proj" {
		t.Errorf("project key = %q, want the ledger's own", first.ProjectKey)
	}
	// The identifier must satisfy the domain's parser: the store's actor_id is a
	// canonical 36-character identifier, and a value that merely looked like one
	// would fail at write time, where nothing is returned to anybody.
	if _, err := domain.ParseActorID(first.ActorID.String()); err != nil {
		t.Errorf("collector actor does not parse as a canonical identifier: %v", err)
	}
}

func TestCollectorAttributionRefusesWhatItCannotAttribute(t *testing.T) {
	t.Parallel()
	if _, err := telemetry.CollectorAttribution("gpt-cli", "/proj"); err == nil {
		t.Error("an unknown harness produced an attribution")
	}
	if _, err := telemetry.CollectorAttribution(domain.HarnessClaudeCode, ""); err == nil {
		t.Error("a missing project key produced an attribution")
	}
}

func TestCollectedHarnessesIsAnExplicitSet(t *testing.T) {
	t.Parallel()
	set := telemetry.NewCollectedHarnesses(domain.HarnessClaudeCode)
	if !set.Collects(domain.HarnessClaudeCode) || set.Collects(domain.HarnessPi) {
		t.Fatalf("set = %v", set)
	}
	if telemetry.NewCollectedHarnesses() != nil {
		t.Error("an empty set should be nil so a sink can skip the check entirely")
	}
}

func TestObservationSourceNamesItself(t *testing.T) {
	t.Parallel()
	if telemetry.SourcePushed.String() != "pushed" {
		t.Errorf("SourcePushed = %q", telemetry.SourcePushed)
	}
	if telemetry.SourceCollected.String() != "collected" {
		t.Errorf("SourceCollected = %q", telemetry.SourceCollected)
	}
}

// TestPushedCallsForACollectedHarnessAreDroppedAtTheOnlyDoor is the
// double-counting test. Both mechanisms reach the store through Offer and
// nothing else, so this assertion is the whole of the guarantee.
func TestPushedCallsForACollectedHarnessAreDroppedAtTheOnlyDoor(t *testing.T) {
	t.Parallel()
	store := &recordingTelemetryStore{}
	sink := telemetry.NewSink(store, telemetry.SinkConfig{
		Collected: telemetry.NewCollectedHarnesses(domain.HarnessClaudeCode),
		Coalesce:  time.Millisecond,
	})

	pushed := telemetry.Envelope{
		Attribution: collectorAttribution(t),
		ModelCalls: []domain.ModelCall{
			collectedModelCall(domain.HarnessClaudeCode, "msg_1"),
			collectedModelCall(domain.HarnessOpenCode, "oc_1"),
		},
		Spans: []domain.Span{{
			DedupeKey: "build-1", Harness: domain.HarnessClaudeCode, Kind: domain.SpanKindBuild,
			Name: "make check", Outcome: domain.ObservedOutcomeOK,
			StartedAt: time.Date(2026, time.September, 2, 5, 0, 0, 0, time.UTC),
		}},
	}
	if !sink.Offer(pushed) {
		t.Fatal("Offer() refused a pushed envelope")
	}
	collected := telemetry.Envelope{
		Attribution: collectorAttribution(t),
		ModelCalls:  []domain.ModelCall{collectedModelCall(domain.HarnessClaudeCode, "msg_1")},
		Source:      telemetry.SourceCollected,
	}
	if !sink.Offer(collected) {
		t.Fatal("Offer() refused a collected envelope")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go sink.Run(ctx)
	_ = sink.Close()

	stats := sink.Stats()
	if stats.DroppedSuperseded != 1 {
		t.Errorf("dropped superseded = %d, want the one pushed claude-code call", stats.DroppedSuperseded)
	}
	claude, opencode, spans := storedShape(store)
	if claude != 1 {
		t.Errorf("claude-code model calls stored = %d, want exactly the collected copy", claude)
	}
	if opencode != 1 {
		t.Errorf("opencode model calls stored = %d; a harness this daemon does not collect keeps pushing",
			opencode)
	}
	if spans != 1 {
		t.Errorf("spans stored = %d; a token collector supersedes tokens, not timing", spans)
	}
}

// storedShape counts what actually reached the store, by harness, so the test
// asserts the durable result rather than the sink's own bookkeeping.
func storedShape(store *recordingTelemetryStore) (claude, opencode, spans int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, batch := range store.batches {
		for _, envelope := range batch {
			spans += len(envelope.Spans)
			for _, call := range envelope.ModelCalls {
				switch call.Harness {
				case domain.HarnessClaudeCode:
					claude++
				case domain.HarnessOpenCode:
					opencode++
				case domain.HarnessPi, domain.HarnessUnknown:
				}
			}
		}
	}
	return claude, opencode, spans
}

func TestASinkWithoutCollectionAdmitsEverything(t *testing.T) {
	t.Parallel()
	sink := telemetry.NewSink(&recordingTelemetryStore{}, telemetry.SinkConfig{})
	envelope := telemetry.Envelope{
		Attribution: collectorAttribution(t),
		ModelCalls:  []domain.ModelCall{collectedModelCall(domain.HarnessClaudeCode, "msg_1")},
	}
	if !sink.Offer(envelope) {
		t.Fatal("Offer() refused")
	}
	if stats := sink.Stats(); stats.Accepted != 1 || stats.DroppedSuperseded != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestAnEnvelopeEmptiedByThePartitionIsNotAFailure(t *testing.T) {
	t.Parallel()
	sink := telemetry.NewSink(&recordingTelemetryStore{}, telemetry.SinkConfig{
		Collected: telemetry.NewCollectedHarnesses(domain.HarnessClaudeCode),
	})
	envelope := telemetry.Envelope{
		Attribution: collectorAttribution(t),
		ModelCalls:  []domain.ModelCall{collectedModelCall(domain.HarnessClaudeCode, "msg_1")},
	}
	// The adapter is told its request was accepted, because it was: this daemon
	// already has those observations. Reporting a failure would send a
	// well-behaved adapter into a retry loop over data it must not send.
	if !sink.Offer(envelope) {
		t.Fatal("Offer() reported a failure for a fully superseded envelope")
	}
	if stats := sink.Stats(); stats.Accepted != 0 || stats.DroppedSuperseded != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}
