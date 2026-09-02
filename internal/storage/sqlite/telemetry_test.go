package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

func telemetryEnvelope(t *testing.T, store *Store, project, agent string,
	calls []domain.ModelCall, spans []domain.Span) application.TelemetryEnvelope {
	t.Helper()
	session, _, err := store.RegisterLocalAgent(context.Background(), project, agent, "")
	if err != nil {
		t.Fatal(err)
	}
	return application.TelemetryEnvelope{
		Attribution: application.TelemetryAttribution{
			ProjectKey: session.ProjectKey,
			ActorID:    session.ActorID,
			SessionID:  session.ActorSessionID,
		},
		ModelCalls: calls,
		Spans:      spans,
		ReceivedAt: time.Now().UTC(),
	}
}

func sampleModelCall(dedupe string) domain.ModelCall {
	return domain.ModelCall{
		DedupeKey: dedupe,
		Harness:   domain.HarnessClaudeCode,
		Provider:  "anthropic",
		Model:     "claude-opus-5",
		Operation: domain.ModelOperationChat,
		Usage: domain.TokenUsage{
			UncachedInput: 2, CacheRead: 26354, CacheWrite: 23947, Output: 1469,
			Reasoning: 298, ReasoningReported: true,
		},
		Outcome:   domain.ObservedOutcomeOK,
		StartedAt: time.Now().UTC(),
		Duration:  4210 * time.Millisecond, DurationKnown: true,
	}
}

func TestAppendTelemetryIsIdempotentOnDedupeKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	envelope := telemetryEnvelope(t, store, "/workspace/telemetry", "alice",
		[]domain.ModelCall{sampleModelCall("msg_01ABC")}, nil)

	// The same observation arriving twice is the expected result of an emitter
	// retrying or re-scanning a transcript, not a fault.
	for range 3 {
		if err := store.AppendTelemetry(ctx, []application.TelemetryEnvelope{envelope}); err != nil {
			t.Fatal(err)
		}
	}

	var rows int
	if err := store.db.QueryRowContext(ctx,
		"SELECT count(*) FROM telemetry_model_calls WHERE dedupe_key = ?", "msg_01ABC").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("stored rows=%d, want 1 after three identical submissions", rows)
	}

	var uncached, cacheRead, cacheWrite, output, reasoning int64
	if err := store.db.QueryRowContext(ctx, `SELECT uncached_input_tokens, cache_read_tokens,
		cache_write_tokens, output_tokens, reasoning_tokens FROM telemetry_model_calls`).
		Scan(&uncached, &cacheRead, &cacheWrite, &output, &reasoning); err != nil {
		t.Fatal(err)
	}
	if uncached != 2 || cacheRead != 26354 || cacheWrite != 23947 || output != 1469 || reasoning != 298 {
		t.Fatalf("token classes=%d/%d/%d/%d/%d, want the disjoint values as submitted",
			uncached, cacheRead, cacheWrite, output, reasoning)
	}
}

// Two agents can legitimately observe the same upstream identifier, so the
// dedupe index is scoped to the actor rather than global.
func TestAppendTelemetryScopesDedupeToTheActor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	first := telemetryEnvelope(t, store, "/workspace/scoped", "alice",
		[]domain.ModelCall{sampleModelCall("shared")}, nil)
	second := telemetryEnvelope(t, store, "/workspace/scoped", "bob",
		[]domain.ModelCall{sampleModelCall("shared")}, nil)

	if err := store.AppendTelemetry(ctx, []application.TelemetryEnvelope{first, second}); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := store.db.QueryRowContext(ctx,
		"SELECT count(*) FROM telemetry_model_calls").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("stored rows=%d, want 2 for one key observed by two actors", rows)
	}
}

// Reasoning is optional, and "not reported" must stay distinguishable from
// "reported as zero" or every average over the column is wrong.
func TestAppendTelemetryKeepsUnreportedReasoningNull(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	call := sampleModelCall("no-reasoning")
	call.Usage.Reasoning = 0
	call.Usage.ReasoningReported = false
	envelope := telemetryEnvelope(t, store, "/workspace/reasoning", "alice", []domain.ModelCall{call}, nil)
	if err := store.AppendTelemetry(ctx, []application.TelemetryEnvelope{envelope}); err != nil {
		t.Fatal(err)
	}
	var reasoning *int64
	if err := store.db.QueryRowContext(ctx,
		"SELECT reasoning_tokens FROM telemetry_model_calls").Scan(&reasoning); err != nil {
		t.Fatal(err)
	}
	if reasoning != nil {
		t.Fatalf("reasoning_tokens=%d, want NULL when the harness does not report it", *reasoning)
	}
}

func TestAppendTelemetryStoresSpans(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	span := domain.Span{
		DedupeKey: "build-1", Harness: domain.HarnessPi, Kind: domain.SpanKindBuild,
		Name: "make check", Outcome: domain.ObservedOutcomeError, ErrorKind: "exit_status",
		StartedAt: time.Now().UTC(), Duration: 92 * time.Second, DurationKnown: true,
	}
	envelope := telemetryEnvelope(t, store, "/workspace/spans", "alice", nil, []domain.Span{span})
	if err := store.AppendTelemetry(ctx, []application.TelemetryEnvelope{envelope}); err != nil {
		t.Fatal(err)
	}
	var name, outcome string
	var duration int64
	if err := store.db.QueryRowContext(ctx,
		"SELECT name, outcome, duration_ms FROM telemetry_spans").Scan(&name, &outcome, &duration); err != nil {
		t.Fatal(err)
	}
	if name != "make check" || outcome != "error" || duration != 92000 {
		t.Fatalf("span=%q/%q/%dms, want the submitted values", name, outcome, duration)
	}
}

// Retention is measured from the daemon's clock, so an adapter reporting a call
// that started in the far future cannot make its row immortal.
func TestSweepTelemetryUsesTheDaemonClockNotTheReportedStart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	call := sampleModelCall("future-clock")
	call.StartedAt = time.Now().UTC().Add(365 * 24 * time.Hour)
	envelope := telemetryEnvelope(t, store, "/workspace/sweep", "alice", []domain.ModelCall{call}, nil)
	envelope.ReceivedAt = time.Now().UTC().Add(-90 * 24 * time.Hour)
	if err := store.AppendTelemetry(ctx, []application.TelemetryEnvelope{envelope}); err != nil {
		t.Fatal(err)
	}

	deleted, err := store.SweepTelemetry(ctx, time.Now().UTC().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted=%d, want 1 row swept on its recorded time", deleted)
	}
}

func TestSweepTelemetryRequiresACutoff(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	if _, err := store.SweepTelemetry(context.Background(), time.Time{}); err == nil {
		t.Fatal("sweeping with a zero cutoff must fail rather than delete everything")
	}
}

func TestAppendTelemetryAcceptsAnEmptyBatch(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	if err := store.AppendTelemetry(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}
