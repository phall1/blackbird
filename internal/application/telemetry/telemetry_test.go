package telemetry_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

type recordingTelemetryStore struct {
	mu        sync.Mutex
	batches   [][]telemetry.Envelope
	appended  atomic.Int64
	failWith  error
	panicWith string
	release   chan struct{}
}

func (store *recordingTelemetryStore) AppendTelemetry(_ context.Context,
	batch []telemetry.Envelope) error {
	if store.panicWith != "" {
		panic(store.panicWith)
	}
	if store.release != nil {
		<-store.release
	}
	store.mu.Lock()
	store.batches = append(store.batches, batch)
	store.mu.Unlock()
	store.appended.Add(int64(len(batch)))
	return store.failWith
}

func (store *recordingTelemetryStore) SweepTelemetry(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (store *recordingTelemetryStore) batchCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.batches)
}

func sampleEnvelope() telemetry.Envelope {
	return telemetry.Envelope{
		ModelCalls: []domain.ModelCall{{
			DedupeKey: "k", Harness: domain.HarnessPi, Provider: "anthropic", Model: "m",
			Operation: domain.ModelOperationChat, Outcome: domain.ObservedOutcomeOK,
			StartedAt: time.Now().UTC(), Duration: time.Second, DurationKnown: true,
		}},
		ReceivedAt: time.Now().UTC(),
	}
}

// The plane's whole promise is that ingest cannot apply backpressure. A sink
// whose drain is not running must still answer immediately, forever.
func TestOfferNeverBlocksWhenTheQueueIsFull(t *testing.T) {
	t.Parallel()
	sink := telemetry.NewSink(&recordingTelemetryStore{},
		telemetry.SinkConfig{QueueDepth: 2})

	done := make(chan struct{})
	var accepted, dropped int
	go func() {
		defer close(done)
		for range 5000 {
			if sink.Offer(sampleEnvelope()) {
				accepted++
			} else {
				dropped++
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Offer blocked with a full queue and no drain; ingest can stall coordination")
	}
	if accepted != 2 {
		t.Fatalf("accepted=%d, want exactly the queue depth", accepted)
	}
	if dropped != 4998 {
		t.Fatalf("dropped=%d, want the remainder counted rather than hidden", dropped)
	}
	if stats := sink.Stats(); stats.DroppedFull != 4998 {
		t.Fatalf("DroppedFull=%d, want 4998", stats.DroppedFull)
	}
}

// A store that fails every write must be invisible to the caller. Nothing
// upstream of the drain is entitled to change behaviour because a token count
// did not land.
func TestWriteFailuresNeverReachTheCaller(t *testing.T) {
	t.Parallel()
	store := &recordingTelemetryStore{failWith: errors.New("disk is gone")}
	sink := telemetry.NewSink(store, telemetry.SinkConfig{Coalesce: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sink.Run(ctx)

	for range 10 {
		if !sink.Offer(sampleEnvelope()) {
			t.Fatal("Offer reported a failure the caller must never see")
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	stats := sink.Stats()
	if stats.WriteFailures == 0 {
		t.Fatal("write failures must be counted, not merely swallowed")
	}
	if stats.Written != 0 {
		t.Fatalf("Written=%d, want zero when every write failed", stats.Written)
	}
}

// Batching is what keeps the promise concrete: N observations must not cost N
// trips through the shared write arbiter.
func TestDrainBatchesRatherThanWritingPerEnvelope(t *testing.T) {
	t.Parallel()
	store := &recordingTelemetryStore{release: make(chan struct{})}
	sink := telemetry.NewSink(store, telemetry.SinkConfig{
		QueueDepth: 64, BatchSize: 32, Coalesce: 50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sink.Run(ctx)

	for range 32 {
		sink.Offer(sampleEnvelope())
	}
	close(store.release)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if got := store.appended.Load(); got != 32 {
		t.Fatalf("appended envelopes=%d, want all 32 written", got)
	}
	if batches := store.batchCount(); batches >= 32 {
		t.Fatalf("write transactions=%d for 32 envelopes; batching did not coalesce", batches)
	}
}

// A clean stop should not throw away what was already accepted.
func TestCloseFlushesWhatWasAlreadyQueued(t *testing.T) {
	t.Parallel()
	store := &recordingTelemetryStore{}
	sink := telemetry.NewSink(store, telemetry.SinkConfig{
		QueueDepth: 16, Coalesce: time.Hour,
	})
	for range 8 {
		sink.Offer(sampleEnvelope())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	go sink.Run(ctx)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if got := store.appended.Load(); got != 8 {
		t.Fatalf("flushed=%d, want the 8 already accepted", got)
	}
}

func TestOfferAfterCloseIsRefusedAndCounted(t *testing.T) {
	t.Parallel()
	sink := telemetry.NewSink(&recordingTelemetryStore{}, telemetry.SinkConfig{})
	go sink.Run(context.Background())
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if sink.Offer(sampleEnvelope()) {
		t.Fatal("a closed sink must refuse rather than queue")
	}
	if stats := sink.Stats(); stats.DroppedClosed != 1 {
		t.Fatalf("DroppedClosed=%d, want 1", stats.DroppedClosed)
	}
}

// A defect in the observation plane must stop observation, not the daemon.
func TestDrainRecoversFromAPanickingStore(t *testing.T) {
	t.Parallel()
	sink := telemetry.NewSink(&recordingTelemetryStore{panicWith: "storage exploded"},
		telemetry.SinkConfig{Coalesce: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		sink.Run(ctx)
	}()
	sink.Offer(sampleEnvelope())
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("a panicking store left the drain wedged")
	}
	// Offer still answers after the drain is gone, because a caller has no way
	// to know it went and no useful response if it did.
	sink.Offer(sampleEnvelope())
}

// An empty submission is a no-op rather than a queue slot.
func TestOfferIgnoresEmptyEnvelopes(t *testing.T) {
	t.Parallel()
	sink := telemetry.NewSink(&recordingTelemetryStore{},
		telemetry.SinkConfig{QueueDepth: 1})
	for range 100 {
		if !sink.Offer(telemetry.Envelope{}) {
			t.Fatal("an empty envelope must never consume a queue slot")
		}
	}
	if stats := sink.Stats(); stats.Accepted != 0 || stats.DroppedFull != 0 {
		t.Fatalf("stats=%+v, want an empty envelope to count as nothing", stats)
	}
}

// The window and the reply size are decided in one place so the transport
// cannot widen either, whatever a caller sends.
func TestSpendQueryNormalizationClampsWindowAndLimit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	defaulted := telemetry.SpendQuery{Dimension: telemetry.SpendByModel}.Normalized(now)
	if defaulted.Limit != telemetry.DefaultSpendGroups {
		t.Fatalf("limit=%d, want the default", defaulted.Limit)
	}
	if !defaulted.Since.Equal(now.Add(-telemetry.DefaultSpendWindow)) {
		t.Fatalf("since=%s, want the default window", defaulted.Since)
	}

	// A caller asking for the whole history is clamped rather than refused: the
	// answer it gets is still useful, which a rejection would not be.
	wide := telemetry.SpendQuery{
		Dimension: telemetry.SpendByModel,
		Since:     now.Add(-365 * 24 * time.Hour),
		Limit:     5000,
	}.Normalized(now)
	if !wide.Since.Equal(now.Add(-telemetry.MaxSpendWindow)) {
		t.Fatalf("since=%s, want the window clamped to the maximum", wide.Since)
	}
	if wide.Limit != telemetry.DefaultSpendGroups {
		t.Fatalf("limit=%d, want an over-large limit brought back to the default", wide.Limit)
	}

	// A reasonable explicit request survives untouched.
	kept := telemetry.SpendQuery{
		Dimension: telemetry.SpendBySpanName, Since: now.Add(-2 * time.Hour), Limit: 25,
	}.Normalized(now)
	if !kept.Since.Equal(now.Add(-2*time.Hour)) || kept.Limit != 25 {
		t.Fatalf("query=%+v, want an in-bounds request preserved", kept)
	}
}

func TestSpendDimensionSeparatesTokenAndSpanTables(t *testing.T) {
	t.Parallel()
	for _, dimension := range []telemetry.SpendDimension{
		telemetry.SpendByModel, telemetry.SpendByAgent, telemetry.SpendByHarness,
	} {
		if !dimension.Valid() || dimension.Spans() {
			t.Fatalf("%q must be a valid model-call dimension", dimension)
		}
	}
	for _, dimension := range []telemetry.SpendDimension{
		telemetry.SpendBySpanKind, telemetry.SpendBySpanName,
	} {
		if !dimension.Valid() || !dimension.Spans() {
			t.Fatalf("%q must be a valid span dimension", dimension)
		}
	}
	if telemetry.SpendDimension("vibes").Valid() {
		t.Fatal("the dimension set is closed because each value is a column expression")
	}
}

func TestSpendGroupBilledInputExcludesOutput(t *testing.T) {
	t.Parallel()
	group := telemetry.SpendGroup{UncachedInput: 2, CacheRead: 26354, CacheWrite: 23947, Output: 1469}
	if group.BilledInput() != 50303 {
		t.Fatalf("BilledInput=%d, want the three input classes and not output", group.BilledInput())
	}
}
