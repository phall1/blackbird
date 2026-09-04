package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

func spendCall(dedupe, model string, harness domain.Harness, usage domain.TokenUsage,
	started time.Time, duration time.Duration, measured bool) domain.ModelCall {
	return domain.ModelCall{
		DedupeKey: dedupe, Harness: harness, Provider: "anthropic", Model: model,
		Operation: domain.ModelOperationChat, Usage: usage, Outcome: domain.ObservedOutcomeOK,
		StartedAt: started, Duration: duration, DurationKnown: measured,
	}
}

func spendSession(t *testing.T, store *Store, project, agent string) coordination.LocalAgentSession {
	t.Helper()
	session, _, err := store.RegisterLocalAgent(context.Background(), project, agent, "")
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func appendFor(t *testing.T, store *Store, session coordination.LocalAgentSession,
	calls []domain.ModelCall, spans []domain.Span) {
	t.Helper()
	envelope := telemetry.Envelope{
		Attribution: telemetry.Attribution{
			ProjectKey: session.ProjectKey, ActorID: session.ActorID, SessionID: session.ActorSessionID,
		},
		ModelCalls: calls, Spans: spans, ReceivedAt: time.Now().UTC(),
	}
	if err := store.AppendTelemetry(context.Background(), []telemetry.Envelope{envelope}); err != nil {
		t.Fatal(err)
	}
}

func groupByKey(report telemetry.SpendReport, key string) (telemetry.SpendGroup, bool) {
	for _, group := range report.Groups {
		if group.Key == key {
			return group, true
		}
	}
	return telemetry.SpendGroup{}, false
}

func TestSpendReportGroupsByModelAndRanksBySpend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := spendSession(t, store, "/workspace/spend", "alice")
	now := time.Now().UTC()
	appendFor(t, store, session, []domain.ModelCall{
		spendCall("a", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 10, CacheRead: 1000, CacheWrite: 500, Output: 200}, now, 0, false),
		spendCall("b", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 5, CacheRead: 100, CacheWrite: 0, Output: 50}, now, 0, false),
		spendCall("c", "claude-haiku-4-5", domain.HarnessPi,
			domain.TokenUsage{UncachedInput: 1, CacheRead: 2, CacheWrite: 0, Output: 3}, now, time.Second, true),
	}, nil)

	report, err := store.SpendReport(ctx, session, telemetry.SpendQuery{Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Groups) != 2 {
		t.Fatalf("groups=%d, want one per model", len(report.Groups))
	}
	// Largest spender first: the report exists to be read top-down.
	if report.Groups[0].Key != "claude-opus-5" {
		t.Fatalf("first group=%q, want the biggest spender", report.Groups[0].Key)
	}
	opus := report.Groups[0]
	if opus.Observations != 2 || opus.UncachedInput != 15 || opus.CacheRead != 1100 ||
		opus.CacheWrite != 500 || opus.Output != 250 {
		t.Fatalf("opus totals=%+v", opus)
	}
	// Billed input is the three disjoint input classes, never output.
	if opus.BilledInput() != 1615 {
		t.Fatalf("billed input=%d, want 15+1100+500", opus.BilledInput())
	}
	// Totals cover the window rather than the returned groups.
	if report.Totals.Observations != 3 || report.Totals.Output != 253 {
		t.Fatalf("totals=%+v, want every observation in the window", report.Totals)
	}
}

// Claude Code reports no latency at all. Counting its calls as measured would
// make every mean latency wrong in the same direction.
func TestSpendReportCountsOnlyMeasuredDurations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := spendSession(t, store, "/workspace/durations", "alice")
	now := time.Now().UTC()
	appendFor(t, store, session, []domain.ModelCall{
		spendCall("unmeasured-1", "claude-opus-5", domain.HarnessClaudeCode, domain.TokenUsage{Output: 1}, now, 0, false),
		spendCall("unmeasured-2", "claude-opus-5", domain.HarnessClaudeCode, domain.TokenUsage{Output: 1}, now, 0, false),
		spendCall("measured", "claude-opus-5", domain.HarnessClaudeCode, domain.TokenUsage{Output: 1},
			now, 4*time.Second, true),
	}, nil)

	report, err := store.SpendReport(ctx, session, telemetry.SpendQuery{Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	group := report.Groups[0]
	if group.Observations != 3 {
		t.Fatalf("observations=%d, want all three counted", group.Observations)
	}
	if group.MeasuredDurations != 1 {
		t.Fatalf("measured=%d, want only the one that carried a duration", group.MeasuredDurations)
	}
	if group.TotalDurationMS != 4000 || group.MaxDurationMS != 4000 {
		t.Fatalf("durations=%d/%d, want the single measurement", group.TotalDurationMS, group.MaxDurationMS)
	}
}

// A report must never reach across workspaces, and must never be steerable
// there by anything the caller sends.
func TestSpendReportIsScopedToTheCallersProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	mine := spendSession(t, store, "/workspace/mine", "alice")
	theirs := spendSession(t, store, "/workspace/theirs", "bob")
	now := time.Now().UTC()
	appendFor(t, store, mine, []domain.ModelCall{
		spendCall("mine", "m", domain.HarnessPi, domain.TokenUsage{Output: 7}, now, 0, false),
	}, nil)
	appendFor(t, store, theirs, []domain.ModelCall{
		spendCall("theirs", "m", domain.HarnessPi, domain.TokenUsage{Output: 900}, now, 0, false),
	}, nil)

	report, err := store.SpendReport(ctx, mine, telemetry.SpendQuery{Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals.Output != 7 {
		t.Fatalf("output=%d, want only this project's spend", report.Totals.Output)
	}
}

func TestSpendReportMineOnlyNarrowsToTheCaller(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	alice := spendSession(t, store, "/workspace/shared", "alice")
	bob := spendSession(t, store, "/workspace/shared", "bob")
	now := time.Now().UTC()
	appendFor(t, store, alice, []domain.ModelCall{
		spendCall("a", "m", domain.HarnessPi, domain.TokenUsage{Output: 10}, now, 0, false),
	}, nil)
	appendFor(t, store, bob, []domain.ModelCall{
		spendCall("b", "m", domain.HarnessPi, domain.TokenUsage{Output: 90}, now, 0, false),
	}, nil)

	whole, err := store.SpendReport(ctx, alice, telemetry.SpendQuery{Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	if whole.Totals.Output != 100 {
		t.Fatalf("project output=%d, want both agents", whole.Totals.Output)
	}
	own, err := store.SpendReport(ctx, alice,
		telemetry.SpendQuery{Dimension: telemetry.SpendByModel, MineOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if own.Totals.Output != 10 {
		t.Fatalf("own output=%d, want only the caller's", own.Totals.Output)
	}
}

func TestSpendReportGroupsByAgentName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	alice := spendSession(t, store, "/workspace/agents", "alice")
	bob := spendSession(t, store, "/workspace/agents", "bob")
	now := time.Now().UTC()
	appendFor(t, store, alice, []domain.ModelCall{
		spendCall("a", "m", domain.HarnessPi, domain.TokenUsage{Output: 10}, now, 0, false),
	}, nil)
	appendFor(t, store, bob, []domain.ModelCall{
		spendCall("b", "m", domain.HarnessPi, domain.TokenUsage{Output: 90}, now, 0, false),
	}, nil)

	report, err := store.SpendReport(ctx, alice, telemetry.SpendQuery{Dimension: telemetry.SpendByAgent})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Groups) != 2 || report.Groups[0].Key != "bob" {
		t.Fatalf("groups=%+v, want bob first as the larger spender", report.Groups)
	}
	if _, ok := groupByKey(report, "alice"); !ok {
		t.Fatal("alice must appear in an agent rollup of her own project")
	}
}

// Spans answer where the wall clock goes and carry no tokens. Reporting zero
// there is the truth, not a missing value.
func TestSpendReportGroupsSpansByTotalDuration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := spendSession(t, store, "/workspace/spans", "alice")
	now := time.Now().UTC()
	span := func(dedupe, name string, duration time.Duration) domain.Span {
		return domain.Span{
			DedupeKey: dedupe, Harness: domain.HarnessPi, Kind: domain.SpanKindBuild, Name: name,
			Outcome: domain.ObservedOutcomeOK, StartedAt: now, Duration: duration, DurationKnown: true,
		}
	}
	appendFor(t, store, session, nil, []domain.Span{
		span("s1", "make check", 90*time.Second),
		span("s2", "make check", 100*time.Second),
		span("s3", "go build", 3*time.Second),
	})

	report, err := store.SpendReport(ctx, session, telemetry.SpendQuery{Dimension: telemetry.SpendBySpanName})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Groups) != 2 || report.Groups[0].Key != "make check" {
		t.Fatalf("groups=%+v, want the slowest activity first", report.Groups)
	}
	slowest := report.Groups[0]
	if slowest.TotalDurationMS != 190000 || slowest.MaxDurationMS != 100000 {
		t.Fatalf("durations=%d/%d", slowest.TotalDurationMS, slowest.MaxDurationMS)
	}
	if slowest.Output != 0 || slowest.BilledInput() != 0 {
		t.Fatalf("span group carries tokens=%+v, want zero", slowest)
	}
}

// The window is a filter on when the work happened, not on when the daemon
// recorded it: the caller is asking about their own recent activity.
func TestSpendReportWindowExcludesOlderWork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := spendSession(t, store, "/workspace/window", "alice")
	now := time.Now().UTC()
	appendFor(t, store, session, []domain.ModelCall{
		spendCall("recent", "m", domain.HarnessPi, domain.TokenUsage{Output: 5}, now, 0, false),
		spendCall("old", "m", domain.HarnessPi, domain.TokenUsage{Output: 500}, now.Add(-72*time.Hour), 0, false),
	}, nil)

	report, err := store.SpendReport(ctx, session, telemetry.SpendQuery{Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals.Output != 5 {
		t.Fatalf("default window output=%d, want only the last day", report.Totals.Output)
	}
	wide, err := store.SpendReport(ctx, session, telemetry.SpendQuery{
		Dimension: telemetry.SpendByModel, Since: now.Add(-96 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if wide.Totals.Output != 505 {
		t.Fatalf("wide window output=%d, want both", wide.Totals.Output)
	}
}

// Truncation has to be visible, or the top of a long tail reads as the whole
// picture. Totals stay honest across it.
func TestSpendReportReportsTruncationWithHonestTotals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := spendSession(t, store, "/workspace/truncate", "alice")
	now := time.Now().UTC()
	calls := make([]domain.ModelCall, 0, 5)
	for index := range 5 {
		calls = append(calls, spendCall(
			"k"+string(rune('a'+index)), "model-"+string(rune('a'+index)),
			domain.HarnessPi, domain.TokenUsage{Output: uint64(index + 1)}, now, 0, false))
	}
	appendFor(t, store, session, calls, nil)

	report, err := store.SpendReport(ctx, session,
		telemetry.SpendQuery{Dimension: telemetry.SpendByModel, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Groups) != 2 || !report.Truncated {
		t.Fatalf("groups=%d truncated=%v, want a capped, flagged report", len(report.Groups), report.Truncated)
	}
	if report.Totals.Output != 15 {
		t.Fatalf("totals=%d, want every model in the window, not just the two returned", report.Totals.Output)
	}
}

func TestSpendReportRejectsAnUnknownDimension(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	session := spendSession(t, store, "/workspace/bad", "alice")
	if _, err := store.SpendReport(context.Background(), session,
		telemetry.SpendQuery{Dimension: "vibes"}); err == nil {
		t.Fatal("an unknown dimension must be rejected rather than silently defaulted")
	}
}

func TestSpendReportIsEmptyRatherThanFailingWithNoData(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	session := spendSession(t, store, "/workspace/empty", "alice")
	report, err := store.SpendReport(context.Background(), session,
		telemetry.SpendQuery{Dimension: telemetry.SpendByHarness})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Groups) != 0 || report.Totals.Observations != 0 || report.Truncated {
		t.Fatalf("report=%+v, want an empty but valid report", report)
	}
}

// TestAdminSpendReportAnswersForANamedProject is the operator's entry, and the
// assertion that matters is scope: the report covers the project it was asked
// about and ONLY that project, because the caller holds no registration in it
// and the route is how an external coordinator answers "what did this
// repository cost" across repos it does not belong to.
func TestAdminSpendReportAnswersForANamedProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	watched := spendSession(t, store, "/workspace/watched", "alice")
	other := spendSession(t, store, "/workspace/other", "bob")
	now := time.Now().UTC()
	appendFor(t, store, watched, []domain.ModelCall{
		spendCall("w1", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 10, CacheRead: 100, Output: 50}, now, 0, false),
	}, nil)
	appendFor(t, store, other, []domain.ModelCall{
		spendCall("o1", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 999, Output: 999}, now, 0, false),
	}, nil)

	report, err := store.AdminSpendReport(ctx, telemetry.AdminSpendQuery{
		ProjectKey: "/workspace/watched", Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals.Observations != 1 || report.Totals.Output != 50 {
		t.Fatalf("totals=%+v, want only the named project's spend", report.Totals)
	}
}

// TestAdminSpendReportRefusesAnUnknownProject is the typo rule: a project this
// daemon has never seen is not an empty report, because an empty report would
// say "this project spent nothing", which is a claim about a project rather
// than about a name.
func TestAdminSpendReportRefusesAnUnknownProject(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	_, err := store.AdminSpendReport(context.Background(), telemetry.AdminSpendQuery{
		ProjectKey: "/workspace/never-seen", Dimension: telemetry.SpendByModel})
	var commandErr *domain.CommandError
	if !errors.As(err, &commandErr) || commandErr.Code() != domain.ErrorCodeNotFound {
		t.Fatalf("err=%v, want not-found for a project this daemon has never seen", err)
	}
}

// TestAdminSpendReportSharesTheAgentReportWindow is the drift guard: the two
// entry points must answer the same window identically, or the operator's
// number and the agent's number about the same work disagree and nobody can
// say which is wrong.
func TestAdminSpendReportSharesTheAgentReportWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := spendSession(t, store, "/workspace/shared", "alice")
	now := time.Now().UTC()
	appendFor(t, store, session, []domain.ModelCall{
		spendCall("s1", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 7, CacheRead: 70, CacheWrite: 30, Output: 20}, now, 0, false),
	}, nil)

	agent, err := store.SpendReport(ctx, session, telemetry.SpendQuery{Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.AdminSpendReport(ctx, telemetry.AdminSpendQuery{
		ProjectKey: "/workspace/shared", Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	if agent.Totals != admin.Totals {
		t.Fatalf("agent totals=%+v, admin totals=%+v — the two entries disagree about the same window",
			agent.Totals, admin.Totals)
	}
}
