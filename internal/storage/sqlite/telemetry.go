package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

var _ application.TelemetryStore = (*Store)(nil)

const (
	insertModelCallSQL = `INSERT INTO telemetry_model_calls (
		observation_id, dedupe_key, project_key, actor_id, session_id, harness, harness_session,
		provider, model, operation, uncached_input_tokens, cache_read_tokens, cache_write_tokens,
		output_tokens, reasoning_tokens, outcome, error_kind, started_at_us, duration_ms,
		recorded_at_us, phux_terminal, raw_usage
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT (actor_id, dedupe_key) DO NOTHING`

	insertSpanSQL = `INSERT INTO telemetry_spans (
		span_id, dedupe_key, project_key, actor_id, session_id, harness, harness_session,
		kind, name, outcome, error_kind, started_at_us, duration_ms, recorded_at_us,
		phux_terminal, attributes
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT (actor_id, dedupe_key) DO NOTHING`
)

// AppendTelemetry writes one drained batch in a single transaction on the
// ordinary write lane.
//
// It takes the ordinary lane deliberately: the security lane exists so identity
// work can preempt bulk writes, and an observation has no claim on it. Batching
// is what keeps this honest -- one transaction per batch rather than per event
// means a coordination write waits behind at most one bounded telemetry commit,
// no matter how hard an adapter is reporting.
//
// Conflicts on (actor, dedupe key) are ignored rather than reported. A duplicate
// is the expected result of an emitter retrying or re-scanning, not a fault, and
// the whole point of the index is that the emitter need not know which it did.
func (store *Store) AppendTelemetry(ctx context.Context, batch []application.TelemetryEnvelope) error {
	if len(batch) == 0 {
		return nil
	}
	return store.withImmediate(ctx, func(tx *sql.Tx) error {
		modelCalls, err := tx.PrepareContext(ctx, insertModelCallSQL)
		if err != nil {
			return fmt.Errorf("prepare telemetry model call insert: %w", err)
		}
		defer func() { _ = modelCalls.Close() }()
		spans, err := tx.PrepareContext(ctx, insertSpanSQL)
		if err != nil {
			return fmt.Errorf("prepare telemetry span insert: %w", err)
		}
		defer func() { _ = spans.Close() }()
		for _, envelope := range batch {
			if err := appendEnvelope(ctx, modelCalls, spans, envelope); err != nil {
				return err
			}
		}
		return nil
	})
}

func appendEnvelope(ctx context.Context, modelCalls, spans *sql.Stmt,
	envelope application.TelemetryEnvelope) error {
	recordedAt := envelope.ReceivedAt
	if recordedAt.IsZero() {
		recordedAt = time.Now().UTC()
	}
	recordedAtUS := recordedAt.UnixMicro()
	for _, call := range envelope.ModelCalls {
		id, err := domain.NewObservationID()
		if err != nil {
			return fmt.Errorf("mint telemetry observation id: %w", err)
		}
		if _, err := modelCalls.ExecContext(ctx, id.String(), call.DedupeKey,
			envelope.Attribution.ProjectKey, envelope.Attribution.ActorID.String(),
			envelope.Attribution.SessionID.String(), string(call.Harness),
			nullableText(call.HarnessSession), call.Provider, call.Model, string(call.Operation),
			int64(call.Usage.UncachedInput), int64(call.Usage.CacheRead), int64(call.Usage.CacheWrite),
			int64(call.Usage.Output), nullableReasoning(call.Usage), string(call.Outcome),
			nullableText(call.ErrorKind), call.StartedAt.UnixMicro(),
			nullableDuration(call.Duration, call.DurationKnown),
			recordedAtUS, nullableText(call.PhuxTerminal), nullableText(call.RawUsage),
		); err != nil {
			return fmt.Errorf("insert telemetry model call: %w", err)
		}
	}
	for _, span := range envelope.Spans {
		id, err := domain.NewObservationID()
		if err != nil {
			return fmt.Errorf("mint telemetry observation id: %w", err)
		}
		if _, err := spans.ExecContext(ctx, id.String(), span.DedupeKey,
			envelope.Attribution.ProjectKey, envelope.Attribution.ActorID.String(),
			envelope.Attribution.SessionID.String(), string(span.Harness),
			nullableText(span.HarnessSession), string(span.Kind), span.Name, string(span.Outcome),
			nullableText(span.ErrorKind), span.StartedAt.UnixMicro(),
			nullableDuration(span.Duration, span.DurationKnown),
			recordedAtUS, nullableText(span.PhuxTerminal), nullableText(span.Attributes),
		); err != nil {
			return fmt.Errorf("insert telemetry span: %w", err)
		}
	}
	return nil
}

// SweepTelemetry deletes observations recorded before the cutoff and reports how
// many rows went. Retention is measured from recorded_at_us -- the daemon's own
// clock at the moment it accepted the row -- because started_at_us comes from an
// adapter, and an adapter with a clock set to next year must not thereby make
// its rows immortal.
func (store *Store) SweepTelemetry(ctx context.Context, before time.Time) (int64, error) {
	if before.IsZero() {
		return 0, fmt.Errorf("%w: telemetry sweep needs a cutoff", application.ErrInvalidCoordination)
	}
	cutoff := before.UnixMicro()
	var deleted int64
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		for _, statement := range []string{
			"DELETE FROM telemetry_model_calls WHERE recorded_at_us < ?",
			"DELETE FROM telemetry_spans WHERE recorded_at_us < ?",
		} {
			result, err := tx.ExecContext(ctx, statement, cutoff)
			if err != nil {
				return fmt.Errorf("sweep telemetry: %w", err)
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("count swept telemetry: %w", err)
			}
			deleted += affected
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// nullableText keeps an absent optional field NULL rather than empty string, so
// "not reported" and "reported as empty" stay distinguishable in the column.
func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// nullableDuration keeps an unmeasured latency NULL rather than zero, so a
// source that reports usage without timing cannot pull a latency average down.
func nullableDuration(duration time.Duration, known bool) any {
	if !known {
		return nil
	}
	return duration.Milliseconds()
}

// nullableReasoning preserves the difference between a model that reported zero
// reasoning tokens and a harness that does not report them at all.
func nullableReasoning(usage domain.TokenUsage) any {
	if !usage.ReasoningReported {
		return nil
	}
	return int64(usage.Reasoning)
}
