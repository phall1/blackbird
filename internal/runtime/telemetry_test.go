package runtime

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

func openTelemetryStore(t *testing.T) *sqlite.Store {
	t.Helper()
	store, err := sqlite.Open(context.Background(), sqlite.Config{
		Path: filepath.Join(t.TempDir(), "telemetry.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func telemetryObservation(t *testing.T, store *sqlite.Store) telemetry.Envelope {
	t.Helper()
	session, _, err := store.RegisterLocalAgent(context.Background(), "/workspace/observed", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	return telemetry.Envelope{
		Attribution: telemetry.Attribution{
			ProjectKey: session.ProjectKey, ActorID: session.ActorID, SessionID: session.ActorSessionID,
		},
		ModelCalls: []domain.ModelCall{{
			DedupeKey: "msg_end_to_end", Harness: domain.HarnessClaudeCode, Provider: "anthropic",
			Model: "claude-opus-5", Operation: domain.ModelOperationChat,
			Usage:     domain.TokenUsage{UncachedInput: 2, CacheRead: 26354, CacheWrite: 23947, Output: 1469},
			Outcome:   domain.ObservedOutcomeOK,
			StartedAt: time.Now().UTC(),
		}},
		ReceivedAt: time.Now().UTC(),
	}
}

// The whole path, end to end: an offered observation reaches SQLite through the
// drain, and Stop's bounded flush is what guarantees it before the store closes.
func TestTelemetryWorkerDrainsToStorage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := openTelemetryStore(t)
	worker := newTelemetryWorker(store, slog.New(slog.DiscardHandler), nil)
	if err := worker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !worker.sink.Offer(telemetryObservation(t, store)) {
		t.Fatal("a fresh sink must accept")
	}
	if err := worker.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if stats := worker.sink.Stats(); stats.Written != 1 || stats.WriteFailures != 0 {
		t.Fatalf("stats=%+v, want one observation written", stats)
	}
}

// Stopping twice happens on any shutdown path that both cancels and stops.
func TestTelemetryWorkerStopIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	worker := newTelemetryWorker(openTelemetryStore(t), slog.New(slog.DiscardHandler), nil)
	if err := worker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := worker.Stop(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTelemetryWorkerRefusesASecondStart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	worker := newTelemetryWorker(openTelemetryStore(t), slog.New(slog.DiscardHandler), nil)
	if err := worker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Stop(ctx) }()
	if err := worker.Start(ctx); err == nil {
		t.Fatal("a second Start would create a second writer")
	}
}

// Stopping a worker that never started is what happens when composition fails
// partway, and it must not deadlock on channels that were never made.
func TestTelemetryWorkerStopBeforeStartIsANoOp(t *testing.T) {
	t.Parallel()
	worker := newTelemetryWorker(openTelemetryStore(t), slog.New(slog.DiscardHandler), nil)
	if err := worker.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTelemetrySweepDeletesExpiredObservations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := openTelemetryStore(t)
	worker := newTelemetryWorker(store, slog.New(slog.DiscardHandler), nil)
	envelope := telemetryObservation(t, store)
	envelope.ReceivedAt = time.Now().UTC().Add(-90 * 24 * time.Hour)
	if err := store.AppendTelemetry(ctx, []telemetry.Envelope{envelope}); err != nil {
		t.Fatal(err)
	}
	worker.sweepOnce(ctx)
	remaining, err := store.SweepTelemetry(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("rows left after the sweep=%d, want the expired row already gone", remaining)
	}
}
