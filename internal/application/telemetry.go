package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// The observation plane's one hard rule (ADR-0001) is that telemetry may never
// make a coordination write fail. That is a structural property here, not a
// try/catch:
//
//   - Offer never blocks. A full queue drops and counts, so an ingest burst
//     cannot apply backpressure to anything.
//   - The drain goroutine is the only writer, and it batches, so N observations
//     cost one trip through the SQLite write arbiter instead of N. A lease
//     acquire never waits behind more than one bounded telemetry transaction.
//   - Telemetry never shares a transaction with coordination and never takes
//     the security write lane.
//   - A write error is counted and dropped. It is never returned to a caller,
//     because no caller has anything useful to do with it.
//   - Every bound is explicit and finite, so a buggy adapter degrades its own
//     observability and nothing else.

// ErrTelemetryUnavailable reports that the sink is closed. It exists so a
// caller can distinguish "not recorded" from "recorded", and never so a caller
// can retry: the correct response to a closed sink is to carry on.
var ErrTelemetryUnavailable = errors.New("telemetry sink is closed")

const (
	// MaxTelemetryEventsPerEnvelope bounds one submission. An adapter with more
	// than this splits, which keeps a single request from monopolizing a batch.
	MaxTelemetryEventsPerEnvelope = 128
	// DefaultTelemetryQueueDepth is measured in envelopes, not events, because
	// an envelope is what one HTTP request produces and therefore what the
	// transport's body limit already bounds.
	DefaultTelemetryQueueDepth = 256
	// DefaultTelemetryBatchSize bounds one write transaction. Larger batches
	// amortize the fsync better but hold the write arbiter longer, and holding
	// it longer is the thing this plane is forbidden from doing.
	DefaultTelemetryBatchSize = 32
	// DefaultTelemetryCoalesce is how long the drain waits for a batch to fill
	// before writing what it has. It trades observation freshness -- which
	// nothing is waiting on -- for fewer durable commits.
	DefaultTelemetryCoalesce = 250 * time.Millisecond
	// DefaultTelemetryFlushBudget bounds the shutdown drain. A clean stop
	// should not lose the last few observations, and must not delay the
	// daemon's exit to save them.
	DefaultTelemetryFlushBudget = 2 * time.Second
)

// TelemetryAttribution is taken from the caller's authenticated session, never
// from a request body. An adapter therefore cannot attribute its spend to
// another agent, which is the only security property this plane needs.
type TelemetryAttribution struct {
	ProjectKey string
	ActorID    domain.ActorID
	SessionID  domain.ActorSessionID
}

// TelemetryEnvelope is one adapter submission: the observations from one agent
// in one request.
type TelemetryEnvelope struct {
	Attribution TelemetryAttribution
	ModelCalls  []domain.ModelCall
	Spans       []domain.Span
	// ReceivedAt is the daemon's clock, and it is what retention is measured
	// from. An adapter's clock decides when a call started; it does not get to
	// decide how long this daemon keeps the row.
	ReceivedAt time.Time
}

func (envelope TelemetryEnvelope) Len() int {
	return len(envelope.ModelCalls) + len(envelope.Spans)
}

// TelemetryStore is the durable half. Implementations must write telemetry in
// its own transaction, must be idempotent on (actor, dedupe key), and must not
// participate in any coordination transaction.
type TelemetryStore interface {
	AppendTelemetry(context.Context, []TelemetryEnvelope) error
	SweepTelemetry(context.Context, time.Time) (int64, error)
}

// TelemetrySinkStats is the plane's self-report. Drops are counted rather than
// hidden: a plane that silently loses data is worse than no plane, because it
// invites conclusions from a sample nobody knows is partial.
type TelemetrySinkStats struct {
	Accepted      uint64
	DroppedFull   uint64
	DroppedClosed uint64
	Written       uint64
	WriteFailures uint64
	Batches       uint64
}

type TelemetrySinkConfig struct {
	QueueDepth  int
	BatchSize   int
	Coalesce    time.Duration
	FlushBudget time.Duration
	Logger      *slog.Logger
}

func (config TelemetrySinkConfig) withDefaults() TelemetrySinkConfig {
	if config.QueueDepth <= 0 {
		config.QueueDepth = DefaultTelemetryQueueDepth
	}
	if config.BatchSize <= 0 {
		config.BatchSize = DefaultTelemetryBatchSize
	}
	if config.Coalesce <= 0 {
		config.Coalesce = DefaultTelemetryCoalesce
	}
	if config.FlushBudget <= 0 {
		config.FlushBudget = DefaultTelemetryFlushBudget
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.DiscardHandler)
	}
	return config
}

// TelemetrySink is the bounded, non-blocking buffer between ingest and storage.
type TelemetrySink struct {
	store  TelemetryStore
	config TelemetrySinkConfig
	queue  chan TelemetryEnvelope

	closeOnce sync.Once
	closed    chan struct{}
	done      chan struct{}

	accepted      atomic.Uint64
	droppedFull   atomic.Uint64
	droppedClosed atomic.Uint64
	written       atomic.Uint64
	writeFailures atomic.Uint64
	batches       atomic.Uint64
}

func NewTelemetrySink(store TelemetryStore, config TelemetrySinkConfig) *TelemetrySink {
	config = config.withDefaults()
	return &TelemetrySink{
		store:  store,
		config: config,
		queue:  make(chan TelemetryEnvelope, config.QueueDepth),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Offer hands an envelope to the drain without ever blocking. It reports
// whether the observations were queued; a false result means they were dropped,
// which is a normal outcome under load and never an error the caller should
// act on.
func (sink *TelemetrySink) Offer(envelope TelemetryEnvelope) bool {
	if envelope.Len() == 0 {
		return true
	}
	select {
	case <-sink.closed:
		sink.droppedClosed.Add(1)
		return false
	default:
	}
	select {
	case sink.queue <- envelope:
		sink.accepted.Add(uint64(envelope.Len()))
		return true
	default:
		sink.droppedFull.Add(1)
		return false
	}
}

// Run drains the queue until ctx is cancelled or Close is called, then makes one
// bounded attempt to flush what is left. It owns the only write path, so it is
// started exactly once.
func (sink *TelemetrySink) Run(ctx context.Context) {
	defer close(sink.done)
	defer sink.recoverDrain()
	for {
		select {
		case <-ctx.Done():
			sink.flushRemaining()
			return
		case <-sink.closed:
			sink.flushRemaining()
			return
		case first := <-sink.queue:
			sink.write(ctx, sink.collect(ctx, first))
		}
	}
}

// collect greedily fills a batch from whatever is already queued, waiting no
// longer than the coalesce window for more.
func (sink *TelemetrySink) collect(ctx context.Context, first TelemetryEnvelope) []TelemetryEnvelope {
	batch := make([]TelemetryEnvelope, 0, sink.config.BatchSize)
	batch = append(batch, first)
	timer := time.NewTimer(sink.config.Coalesce)
	defer timer.Stop()
	for len(batch) < sink.config.BatchSize {
		select {
		case next := <-sink.queue:
			batch = append(batch, next)
		case <-timer.C:
			return batch
		case <-ctx.Done():
			return batch
		case <-sink.closed:
			return batch
		}
	}
	return batch
}

// write is where a failure stops. Nothing above this line learns that a write
// went wrong, because nothing above this line is entitled to change behaviour
// when it does.
func (sink *TelemetrySink) write(ctx context.Context, batch []TelemetryEnvelope) {
	if len(batch) == 0 {
		return
	}
	sink.batches.Add(1)
	var events uint64
	for _, envelope := range batch {
		events += uint64(envelope.Len())
	}
	if err := sink.store.AppendTelemetry(ctx, batch); err != nil {
		sink.writeFailures.Add(1)
		sink.config.Logger.Warn("telemetry batch dropped",
			"error", err, "envelopes", len(batch), "events", events)
		return
	}
	sink.written.Add(events)
}

// flushRemaining makes one bounded attempt at whatever is still queued, on a
// fresh context because the one that just ended is why we are here.
func (sink *TelemetrySink) flushRemaining() {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), sink.config.FlushBudget)
	defer cancel()
	for {
		batch := make([]TelemetryEnvelope, 0, sink.config.BatchSize)
		for len(batch) < sink.config.BatchSize {
			select {
			case envelope := <-sink.queue:
				batch = append(batch, envelope)
				continue
			default:
			}
			break
		}
		if len(batch) == 0 {
			return
		}
		sink.write(ctx, batch)
		if ctx.Err() != nil {
			return
		}
	}
}

// recoverDrain keeps a defect in this plane from taking the daemon down with
// it. A panicking drain stops observing; it does not stop coordinating.
func (sink *TelemetrySink) recoverDrain() {
	if recovered := recover(); recovered != nil {
		sink.config.Logger.Error("telemetry drain panicked and stopped", "panic", recovered)
	}
}

// Close stops accepting, waits for the drain's bounded flush, and is safe to
// call more than once.
func (sink *TelemetrySink) Close() error {
	sink.closeOnce.Do(func() { close(sink.closed) })
	<-sink.done
	return nil
}

func (sink *TelemetrySink) Stats() TelemetrySinkStats {
	return TelemetrySinkStats{
		Accepted:      sink.accepted.Load(),
		DroppedFull:   sink.droppedFull.Load(),
		DroppedClosed: sink.droppedClosed.Load(),
		Written:       sink.written.Load(),
		WriteFailures: sink.writeFailures.Load(),
		Batches:       sink.batches.Load(),
	}
}

// The read half of the observation plane.
//
// The plane is written by adapters and read by agents, and those are different
// jobs with different risks. Ingest must never block coordination; a rollup is
// an ordinary bounded read that answers one question -- where did the tokens
// and the time go -- for one project, over one window, grouped one way.
//
// It is deliberately a rollup and never a row feed. An agent asking what it
// spent wants a handful of totals it can act on, not a page of observations it
// has to add up in context; returning rows would spend more tokens reporting
// spend than the answer is worth.

// SpendDimension is the closed set of groupings the plane answers. It is closed
// because each value is a column expression, and an open one would either be a
// SQL injection surface or a switch pretending not to be.
type SpendDimension string

const (
	// SpendByModel answers "which models is this project's budget going to".
	SpendByModel SpendDimension = "model"
	// SpendByAgent attributes spend to the agent that incurred it.
	SpendByAgent SpendDimension = "agent"
	// SpendByHarness separates Claude Code, OpenCode, and Pi.
	SpendByHarness SpendDimension = "harness"
	// SpendBySpanKind and SpendBySpanName read the span table instead, which is
	// where "what is actually slow" is answered. Spans carry no tokens, so a
	// span grouping reports duration and leaves the token totals at zero.
	SpendBySpanKind SpendDimension = "span_kind"
	SpendBySpanName SpendDimension = "span_name"
)

func (dimension SpendDimension) Valid() bool {
	switch dimension {
	case SpendByModel, SpendByAgent, SpendByHarness, SpendBySpanKind, SpendBySpanName:
		return true
	default:
		return false
	}
}

// Spans reports whether this dimension reads the span table rather than the
// model-call table.
func (dimension SpendDimension) Spans() bool {
	return dimension == SpendBySpanKind || dimension == SpendBySpanName
}

const (
	// DefaultSpendWindow is the window a caller that names none gets. A day is
	// the span of a working session, which is the question agents actually ask.
	DefaultSpendWindow = 24 * time.Hour
	// MaxSpendWindow bounds the scan. Retention is longer than this, so a
	// caller wanting the whole history is asking for a report no agent reads.
	MaxSpendWindow = 30 * 24 * time.Hour
	// DefaultSpendGroups and MaxSpendGroups bound the reply. The long tail of a
	// group-by is noise, and an unbounded reply lands in a model's context.
	DefaultSpendGroups = 10
	MaxSpendGroups     = 50
)

// SpendQuery selects one rollup. ProjectKey is not a field: the report is
// always the caller's own project, taken from the authenticated session, so
// this can never read across into another workspace.
type SpendQuery struct {
	Dimension SpendDimension
	// Since bounds the window on started_at -- when the work happened, which is
	// what the caller is asking about, rather than when this daemon recorded it.
	Since time.Time
	// MineOnly narrows to the calling agent, which is how an agent asks what it
	// personally has spent rather than what the project has.
	MineOnly bool
	Limit    uint16
}

// Normalized fills defaults and clamps bounds. It is the single place the
// window and the reply size are decided, so the transport cannot widen either.
func (query SpendQuery) Normalized(now time.Time) SpendQuery {
	if query.Limit == 0 || query.Limit > MaxSpendGroups {
		query.Limit = DefaultSpendGroups
	}
	earliest := now.Add(-MaxSpendWindow)
	if query.Since.IsZero() {
		query.Since = now.Add(-DefaultSpendWindow)
	}
	if query.Since.Before(earliest) {
		query.Since = earliest
	}
	return query
}

func (query SpendQuery) Validate() error {
	if !query.Dimension.Valid() {
		return fmt.Errorf("%w: unknown spend dimension %q", ErrInvalidCoordination, query.Dimension)
	}
	return nil
}

// SpendGroup is one row of a rollup. Token totals are zero for a span
// dimension, because a span has no tokens rather than because they are unknown.
type SpendGroup struct {
	// Key is the model, agent name, harness, span kind, or span name. An
	// observation whose agent has since been deleted groups under an empty key
	// rather than disappearing: the spend happened either way.
	Key           string
	Observations  uint64
	UncachedInput uint64
	CacheRead     uint64
	CacheWrite    uint64
	Output        uint64
	Reasoning     uint64
	// MeasuredDurations counts the observations that carried a duration at all.
	// Claude Code reports none, so a mean taken over Observations rather than
	// this would report every Claude call as instant.
	MeasuredDurations uint64
	TotalDurationMS   uint64
	MaxDurationMS     uint64
}

// BilledInput is what a provider invoices as input: the three disjoint input
// classes summed. It is derived so no caller has to know which classes exist.
func (group SpendGroup) BilledInput() uint64 {
	return group.UncachedInput + group.CacheRead + group.CacheWrite
}

// SpendReport is the whole answer. Totals covers the window, not merely the
// groups returned, so a truncated report still reports honest totals.
type SpendReport struct {
	Dimension SpendDimension
	Since     time.Time
	Groups    []SpendGroup
	Totals    SpendGroup
	// Truncated says the window held more groups than Limit. Without it a
	// caller cannot tell a complete report from the top of a long tail.
	Truncated bool
}

// TelemetryReader is the read port. It is separate from TelemetryStore because
// the write path is a fail-open sink with its own failure rules and the read
// path is an ordinary query -- and because a daemon may compose one without the
// other, in which case the agent-facing tool is simply not registered.
type TelemetryReader interface {
	SpendReport(context.Context, LocalAgentSession, SpendQuery) (SpendReport, error)
}
