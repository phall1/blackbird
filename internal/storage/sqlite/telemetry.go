package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/application/coordination"
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
		return 0, fmt.Errorf("%w: telemetry sweep needs a cutoff", coordination.ErrInvalidCoordination)
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

var _ application.TelemetryReader = (*Store)(nil)

// spendShape is the SQL a dimension resolves to. Every field is a literal from
// the closed dimension set below, never caller text, so the assembled statement
// has no injection surface and the parameters carry all the untrusted values.
type spendShape struct {
	table    string
	groupBy  string
	join     string
	orderBy  string
	hasToken bool
}

func spendShapeFor(dimension application.SpendDimension) (spendShape, bool) {
	// Model-call dimensions rank by tokens because the question is where the
	// budget went; span dimensions rank by total duration because the question
	// is where the time went. Each is the obviously right order for its table,
	// and offering a choice would be a knob nobody sets correctly.
	const tokenOrder = `SUM(uncached_input_tokens) + SUM(cache_read_tokens) +
		SUM(cache_write_tokens) + SUM(output_tokens) DESC`
	const durationOrder = `COALESCE(SUM(duration_ms), 0) DESC`
	switch dimension {
	case application.SpendByModel:
		return spendShape{table: "telemetry_model_calls calls", groupBy: "calls.model",
			orderBy: tokenOrder, hasToken: true}, true
	case application.SpendByHarness:
		return spendShape{table: "telemetry_model_calls calls", groupBy: "calls.harness",
			orderBy: tokenOrder, hasToken: true}, true
	case application.SpendByAgent:
		// LEFT JOIN, and the name coalesces to empty: an agent row can be gone
		// while its spend remains, and dropping the spend would quietly change
		// the totals rather than the labels.
		return spendShape{table: "telemetry_model_calls calls",
			join:    "LEFT JOIN coordination_agents agents ON agents.actor_id = calls.actor_id",
			groupBy: "COALESCE(agents.agent_name, '')", orderBy: tokenOrder, hasToken: true}, true
	case application.SpendBySpanKind:
		return spendShape{table: "telemetry_spans calls", groupBy: "calls.kind", orderBy: durationOrder}, true
	case application.SpendBySpanName:
		return spendShape{table: "telemetry_spans calls", groupBy: "calls.name", orderBy: durationOrder}, true
	default:
		return spendShape{}, false
	}
}

// tokenColumns are the summed token classes, or literal zeros for a span
// dimension. A span has no tokens; reporting zero is the truth rather than a
// missing value, which is why the shape carries no nullability here.
func (shape spendShape) tokenColumns() string {
	if !shape.hasToken {
		return "0, 0, 0, 0, 0"
	}
	return `COALESCE(SUM(uncached_input_tokens), 0), COALESCE(SUM(cache_read_tokens), 0),
		COALESCE(SUM(cache_write_tokens), 0), COALESCE(SUM(output_tokens), 0),
		COALESCE(SUM(reasoning_tokens), 0)`
}

// durationColumns count only the observations that carried a duration.
// COUNT over a nullable column skips NULLs, which is exactly the distinction
// this plane needs: Claude Code reports no latency at all, and averaging over
// the row count instead would report every one of its calls as instant.
const spendDurationColumns = `COUNT(duration_ms), COALESCE(SUM(duration_ms), 0), COALESCE(MAX(duration_ms), 0)`

// SpendReport answers where a project's tokens and time went over one window.
//
// The project is the session's, always. Like the reservations projection, the
// caller does not get to name a scope: an agent reads its own workspace or
// nothing, and MineOnly narrows further to the caller itself.
func (store *Store) SpendReport(ctx context.Context, session coordination.LocalAgentSession,
	query application.SpendQuery) (application.SpendReport, error) {
	if session.ProjectKey == "" || session.ActorID.String() == "" {
		return application.SpendReport{}, coordination.ErrInvalidCoordination
	}
	if err := query.Validate(); err != nil {
		return application.SpendReport{}, err
	}
	query = query.Normalized(time.Now().UTC())
	shape, ok := spendShapeFor(query.Dimension)
	if !ok {
		return application.SpendReport{}, coordination.ErrInvalidCoordination
	}

	filter := "WHERE calls.project_key = ? AND calls.started_at_us >= ?"
	arguments := []any{session.ProjectKey, query.Since.UnixMicro()}
	if query.MineOnly {
		filter += " AND calls.actor_id = ?"
		arguments = append(arguments, session.ActorID.String())
	}

	report := application.SpendReport{Dimension: query.Dimension, Since: query.Since}
	totals, err := store.spendTotals(ctx, shape, filter, arguments)
	if err != nil {
		return application.SpendReport{}, err
	}
	report.Totals = totals
	groups, truncated, err := store.spendGroups(ctx, shape, filter, arguments, query.Limit)
	if err != nil {
		return application.SpendReport{}, err
	}
	report.Groups = groups
	report.Truncated = truncated
	return report, nil
}

// spendTotals aggregates the whole window rather than the returned groups, so a
// truncated report still states honest totals instead of the sum of its visible
// rows.
func (store *Store) spendTotals(ctx context.Context, shape spendShape, filter string,
	arguments []any) (application.SpendGroup, error) {
	statement := "SELECT COUNT(*), " + shape.tokenColumns() + ", " + spendDurationColumns +
		" FROM " + shape.table + " " + shape.join + " " + filter
	var totals application.SpendGroup
	if err := store.db.QueryRowContext(ctx, statement, arguments...).Scan(&totals.Observations,
		&totals.UncachedInput, &totals.CacheRead, &totals.CacheWrite, &totals.Output, &totals.Reasoning,
		&totals.MeasuredDurations, &totals.TotalDurationMS, &totals.MaxDurationMS); err != nil {
		return application.SpendGroup{}, fmt.Errorf("aggregate telemetry totals: %w", err)
	}
	return totals, nil
}

// spendGroups reads one more row than asked for, which is how truncation is
// detected without a second counting query.
func (store *Store) spendGroups(ctx context.Context, shape spendShape, filter string,
	arguments []any, limit uint16) ([]application.SpendGroup, bool, error) {
	statement := "SELECT " + shape.groupBy + " AS group_key, COUNT(*), " + shape.tokenColumns() + ", " +
		spendDurationColumns + " FROM " + shape.table + " " + shape.join + " " + filter +
		" GROUP BY group_key ORDER BY " + shape.orderBy + ", group_key ASC LIMIT ?"
	rows, err := store.db.QueryContext(ctx, statement, append(append([]any{}, arguments...), int64(limit)+1)...)
	if err != nil {
		return nil, false, fmt.Errorf("group telemetry spend: %w", err)
	}
	defer func() { _ = rows.Close() }()
	groups := make([]application.SpendGroup, 0, limit)
	truncated := false
	for rows.Next() {
		if len(groups) == int(limit) {
			truncated = true
			break
		}
		var group application.SpendGroup
		if err := rows.Scan(&group.Key, &group.Observations, &group.UncachedInput, &group.CacheRead,
			&group.CacheWrite, &group.Output, &group.Reasoning, &group.MeasuredDurations,
			&group.TotalDurationMS, &group.MaxDurationMS); err != nil {
			return nil, false, fmt.Errorf("read telemetry spend group: %w", err)
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("group telemetry spend: %w", err)
	}
	return groups, truncated, nil
}
