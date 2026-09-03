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

// costFixture is one project with a holder and a blocked agent. Both are real
// registrations, so every identity the report joins on is minted by the same
// code the daemon runs rather than written into the tables by the test.
type costFixture struct {
	store   *Store
	holder  coordination.LocalAgentSession
	blocked coordination.LocalAgentSession
}

func newCostFixture(t *testing.T, project string) costFixture {
	t.Helper()
	ctx := context.Background()
	store := newCoordinationStore(t)
	holder, _, err := store.RegisterLocalAgent(ctx, project, "holder", "")
	if err != nil {
		t.Fatal(err)
	}
	blocked, _, err := store.RegisterLocalAgent(ctx, project, "blocked", "")
	if err != nil {
		t.Fatal(err)
	}
	return costFixture{store: store, holder: holder, blocked: blocked}
}

// expireLease slides a whole lease into the past so it has already reached its
// deadline without being released -- exactly what an agent that walks away
// leaves behind. It moves BOTH stamps rather than only the deadline, because a
// lease whose deadline is dragged back to its acquisition would report a hold
// of zero and quietly flatten the held-time diagnostic this report exists to
// give.
//
// Elapsing real time instead would put a sleep in a suite that runs with -race
// and -shuffle, and a flaky clock is a worse fixture than an explicit one.
func expireLease(t *testing.T, store *Store, lease coordination.Lease) {
	t.Helper()
	// SQLite evaluates every assignment against the row as it was, so both
	// expressions read the original acquisition stamp: the lease ends up held
	// from an hour ago until a minute ago.
	const (
		back = int64(time.Hour / time.Microsecond)
		over = int64(time.Minute / time.Microsecond)
	)
	if _, err := store.db.ExecContext(context.Background(),
		`UPDATE leases SET acquired_at_us = acquired_at_us - ?, expires_at_us = acquired_at_us - ?
		WHERE lease_id = ?`, back, over, lease.ID().String()); err != nil {
		t.Fatal(err)
	}
}

// TestCostReportJoinsContentionToTheBlockedAgentsOwnSpend is the join the whole
// plane exists for. The journal knows who was refused; telemetry_model_calls
// knows what that same actor_id spent. Nothing but the owner of both ledgers
// can put them in one row, and before the refusal fact existed there was no row
// to put them in.
func TestCostReportJoinsContentionToTheBlockedAgentsOwnSpend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-join")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/admin.go")
	contentionFlush(t, fixture.store)

	appendFor(t, fixture.store, fixture.blocked, []domain.ModelCall{
		spendCall("blocked-1", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 10, CacheRead: 900, CacheWrite: 90, Output: 300},
			time.Now().UTC(), 0, false),
	}, nil)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Contention.Refusals != 2 {
		t.Fatalf("refusals=%d, want both denied claims recorded", report.Contention.Refusals)
	}
	if len(report.Contention.Agents) != 1 {
		t.Fatalf("agents=%d, want the one refused agent", len(report.Contention.Agents))
	}
	agent := report.Contention.Agents[0]
	if agent.AgentName != "blocked" {
		t.Fatalf("agent=%q, want the refused agent named", agent.AgentName)
	}
	if agent.Refusals != 2 {
		t.Fatalf("agent refusals=%d, want 2", agent.Refusals)
	}
	// The point of the row: the contention and the spend arrive together,
	// keyed on the same actor_id, over the same window.
	if agent.ModelCalls != 1 {
		t.Fatalf("agent model calls=%d, want the blocked agent's own spend joined in", agent.ModelCalls)
	}
	if got, want := agent.BilledInput, uint64(10+900+90); got != want {
		t.Fatalf("billed input=%d, want %d summed across the three input classes", got, want)
	}
	if agent.Output != 300 {
		t.Fatalf("output=%d, want 300", agent.Output)
	}
}

// TestCostReportNamesTheHolderSelectorThatCollided keeps the report pointed at
// the thing a reader can change. A refusal names two selectors; the one worth
// reporting is the holder's, because that is the claim whose owner can narrow
// it. The overlap is read from the recorded fact rather than re-derived, so the
// report cannot disagree with the decision that produced it.
func TestCostReportNamesTheHolderSelectorThatCollided(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-path")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	contentionFlush(t, fixture.store)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Contention.Paths) != 1 {
		t.Fatalf("paths=%d, want the one contended path", len(report.Contention.Paths))
	}
	path := report.Contention.Paths[0]
	if path.Path != "internal/storage" {
		t.Fatalf("path=%q, want the HOLDER's selector rather than the requested one", path.Path)
	}
	if path.Kind != string(coordination.LeaseSelectorSubtree) {
		t.Fatalf("kind=%q, want subtree -- the kind is what tells a reader to claim the file instead", path.Kind)
	}
	if path.Refusals != 1 || path.BlockedAgents != 1 {
		t.Fatalf("refusals=%d agents=%d, want one of each", path.Refusals, path.BlockedAgents)
	}
}

// TestCostReportJoinsAbandonmentToTheRefusalsItCaused is the number that
// decides whether an abandonment mattered. The join is on the blocking lease's
// id, recorded in the refusal itself, so it credits the lease that actually
// stood in the way rather than whichever lease happened to overlap in time.
func TestCostReportJoinsAbandonmentToTheRefusalsItCaused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-abandon")
	lease := acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	contentionFlush(t, fixture.store)
	expireLease(t, fixture.store, lease)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Abandonment.Abandoned != 1 {
		t.Fatalf("abandoned=%d, want the lease that reached its deadline unreleased", report.Abandonment.Abandoned)
	}
	if report.Abandonment.Released != 0 {
		t.Fatalf("released=%d, want none", report.Abandonment.Released)
	}
	if report.Abandonment.RefusalsDuring != 1 {
		t.Fatalf("refusals during abandonment=%d, want the one this lease caused",
			report.Abandonment.RefusalsDuring)
	}
	if len(report.Abandonment.Leases) != 1 {
		t.Fatalf("leases=%d, want the one offender", len(report.Abandonment.Leases))
	}
	offender := report.Abandonment.Leases[0]
	if offender.LeaseID != lease.ID() {
		t.Fatalf("lease=%s, want %s", offender.LeaseID, lease.ID())
	}
	if offender.HolderAgentName != "holder" {
		t.Fatalf("holder=%q, want the agent the action attaches to", offender.HolderAgentName)
	}
	if offender.Refusals != 1 || offender.BlockedAgents != 1 {
		t.Fatalf("refusals=%d agents=%d, want one of each", offender.Refusals, offender.BlockedAgents)
	}
	if offender.ContendedPath != "internal/storage" {
		t.Fatalf("contended path=%q, want the selector that collided", offender.ContendedPath)
	}
	if offender.Mode != coordination.LeaseExclusive {
		t.Fatalf("mode=%q, want exclusive", offender.Mode)
	}
}

// TestCostReportSeparatesAbandonedFromCleanlyReleased is the classification
// this report is forbidden from redefining. A release stamped before the
// deadline is clean; a lease still active past its deadline is abandoned. The
// same predicates back the operator's reservation listing, so the two surfaces
// cannot report different numbers for the same lease.
func TestCostReportSeparatesAbandonedFromCleanlyReleased(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-classify")
	kept := acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/cost.go")
	if _, err := fixture.store.ReleaseLease(ctx, coordination.ChangeLeaseParams{
		WorkspaceID: fixture.holder.WorkspaceID, Holder: fixture.holder.ActorID,
		HolderSession: fixture.holder.ActorSessionID, AuthorityEpoch: fixture.holder.AuthorityEpoch,
		Selectors: kept.Selectors()}); err != nil {
		t.Fatal(err)
	}
	walked := acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/admin.go")
	expireLease(t, fixture.store, walked)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Abandonment.Abandoned != 1 || report.Abandonment.Released != 1 {
		t.Fatalf("abandoned=%d released=%d, want one of each",
			report.Abandonment.Abandoned, report.Abandonment.Released)
	}
	// The held-time comparison is the TTL diagnostic: the abandoned lease held
	// its path to the deadline, the released one only until it was given back.
	if report.Abandonment.ReleasedHeldMS > report.Abandonment.AbandonedHeldMS {
		t.Fatalf("released held %dms >= abandoned held %dms, want the abandoned hold to be the longer one",
			report.Abandonment.ReleasedHeldMS, report.Abandonment.AbandonedHeldMS)
	}
	if report.Abandonment.RefusalsDuring != 0 {
		t.Fatalf("refusals=%d, want none -- an abandonment nobody wanted cost nothing",
			report.Abandonment.RefusalsDuring)
	}
}

// TestCostReportKeepsMailWaitsOutOfTheContentionClock is the distinction that
// keeps the parked total honest. A wait for mail is an idle agent, not a
// blocked one, and folding its parked milliseconds into ParkedMS would report a
// quiet project polling its inbox as a heavily contended one.
func TestCostReportKeepsMailWaitsOutOfTheContentionClock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-mailwait")
	if _, err := fixture.store.AwaitCoordination(ctx, fixture.blocked, coordination.WaitRequest{
		AwaitMail: true, Timeout: 60 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	contentionFlush(t, fixture.store)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Contention.MailWaits != 1 {
		t.Fatalf("mail waits=%d, want the mail-only wait counted as its own kind", report.Contention.MailWaits)
	}
	if report.Contention.PathWaits != 0 {
		t.Fatalf("path waits=%d, want none -- no path was named", report.Contention.PathWaits)
	}
	if report.Contention.ParkedMS != 0 {
		t.Fatalf("parked=%dms, want zero -- an idle mail poll is not contention", report.Contention.ParkedMS)
	}
	if report.Contention.WaitsEndedDeadline != 1 {
		t.Fatalf("deadline waits=%d, want the budget exhaustion recorded", report.Contention.WaitsEndedDeadline)
	}
}

// TestCostReportMeasuresParkedTimeForAPathWait covers the other half: a wait
// that named a path is contention, and its parked milliseconds are MEASURED --
// the daemon stamped both ends against its own clock, so this is the one
// duration in the report that needs no caveat.
func TestCostReportMeasuresParkedTimeForAPathWait(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-pathwait")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")
	if _, err := fixture.store.AwaitCoordination(ctx, fixture.blocked, coordination.WaitRequest{
		Path: "internal/storage/sqlite/cost.go", Timeout: 60 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	contentionFlush(t, fixture.store)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Contention.PathWaits != 1 {
		t.Fatalf("path waits=%d, want the contention wait counted", report.Contention.PathWaits)
	}
	if report.Contention.ParkedMS == 0 {
		t.Fatal("parked=0ms, want the measured wall clock the agent spent blocked")
	}
	if report.Contention.LongestParkMS != report.Contention.ParkedMS {
		t.Fatalf("longest=%dms total=%dms, want them equal for a single wait",
			report.Contention.LongestParkMS, report.Contention.ParkedMS)
	}
	if len(report.Contention.Agents) != 1 || report.Contention.Agents[0].ParkedMS == 0 {
		t.Fatalf("agents=%+v, want the parked time attributed to the waiter", report.Contention.Agents)
	}
}

// TestCostReportRendersAnEmptyWindowAsUnobserved is the discipline the
// collector work already paid for. A report that answers zero when nothing was
// collected invites a reader to conclude a quiet period was an uncontended one,
// which is the single most misleading thing this plane could say.
func TestCostReportRendersAnEmptyWindowAsUnobserved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-empty")

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Contention.Observed() {
		t.Fatal("contention reports observed on an empty window")
	}
	if report.Abandonment.Observed() {
		t.Fatal("abandonment reports observed on an empty window")
	}
	if report.Cache.Observed() {
		t.Fatal("cache reports observed on an empty window")
	}
	if len(report.Contention.Agents) != 0 || len(report.Abandonment.Leases) != 0 {
		t.Fatal("an unobserved section returned rows")
	}
	if !report.Until.After(report.Since) {
		t.Fatalf("since=%s until=%s, want the window stated by the daemon's own clock",
			report.Since, report.Until)
	}
}

// TestCostReportKeepsTheThreeInputClassesApart is why this section exists at
// all. Cache reads run one to two orders of magnitude above uncached input, so
// a report that summed them into a single "input" number would track nothing a
// reader could act on -- and the split cannot be recovered from the sum.
func TestCostReportKeepsTheThreeInputClassesApart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-cache")
	now := time.Now().UTC()
	appendFor(t, fixture.store, fixture.blocked, []domain.ModelCall{
		spendCall("cache-1", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 100, CacheRead: 20000, CacheWrite: 2000, Output: 500}, now, 0, false),
		spendCall("cache-2", "claude-haiku-4-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 50, CacheRead: 0, CacheWrite: 0, Output: 10}, now, 0, false),
	}, nil)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Cache.Observed() || len(report.Cache.Models) != 2 {
		t.Fatalf("models=%d, want one row per model", len(report.Cache.Models))
	}
	opus := report.Cache.Models[0]
	if opus.Model != "claude-opus-5" {
		t.Fatalf("first model=%q, want the largest billed input first", opus.Model)
	}
	if opus.UncachedInput != 100 || opus.CacheRead != 20000 || opus.CacheWrite != 2000 {
		t.Fatalf("input split=%+v, want the three classes reported apart", opus)
	}
	reuse, ok := opus.CacheReuse()
	if !ok || reuse != 10 {
		t.Fatalf("reuse=%v ok=%v, want ten reads per written token", reuse, ok)
	}
	// A model that never wrote a cache entry has NO reuse ratio. Reporting
	// zero would read as "caching is failing" when the truth is that caching
	// was never used, and those want opposite responses.
	haiku := report.Cache.Models[1]
	if _, ok := haiku.CacheReuse(); ok {
		t.Fatal("CacheReuse() answered for a model that wrote no cache; want no answer over a zero denominator")
	}
	if _, ok := haiku.CacheReadShare(); !ok {
		t.Fatal("CacheReadShare() refused a model that did bill input")
	}
}

// TestCostReportMineOnlyNarrowsSpendButNeverAbandonment is the asymmetry that
// makes the agent-facing shape useful. An agent asking what it costs wants its
// own spend and its own contention -- but a lease SOMEONE ELSE abandoned is
// precisely the thing it cannot see from its own side and most needs told.
func TestCostReportMineOnlyNarrowsSpendButNeverAbandonment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-mine")
	walked := acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	contentionFlush(t, fixture.store)
	expireLease(t, fixture.store, walked)
	now := time.Now().UTC()
	appendFor(t, fixture.store, fixture.holder, []domain.ModelCall{
		spendCall("holder-1", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 1, CacheRead: 2, CacheWrite: 3, Output: 4}, now, 0, false),
	}, nil)
	appendFor(t, fixture.store, fixture.blocked, []domain.ModelCall{
		spendCall("blocked-1", "claude-haiku-4-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 10, CacheRead: 20, CacheWrite: 30, Output: 40}, now, 0, false),
	}, nil)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{MineOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Cache.Models) != 1 || report.Cache.Models[0].Model != "claude-haiku-4-5" {
		t.Fatalf("models=%+v, want only the caller's own spend", report.Cache.Models)
	}
	if len(report.Contention.Agents) != 1 || report.Contention.Agents[0].AgentName != "blocked" {
		t.Fatalf("agents=%+v, want only the caller's own contention", report.Contention.Agents)
	}
	// Unnarrowed on purpose: the holder abandoned it, and the caller is the
	// one paying for that.
	if report.Abandonment.Abandoned != 1 {
		t.Fatalf("abandoned=%d, want the other agent's abandonment still reported",
			report.Abandonment.Abandoned)
	}
	if report.Abandonment.Leases[0].HolderAgentName != "holder" {
		t.Fatalf("holder=%q, want the peer who walked away named",
			report.Abandonment.Leases[0].HolderAgentName)
	}
}

// TestCostReportRefusesASessionWithoutAWorkspace keeps the scope rule that
// every read on this store follows: a caller never names the project it is
// asking about, so a session missing the identity that decides the scope is a
// programming error rather than an empty answer.
func TestCostReportRefusesASessionWithoutAWorkspace(t *testing.T) {
	t.Parallel()
	fixture := newCostFixture(t, "/workspace/cost-scope")
	orphan := fixture.blocked
	orphan.WorkspaceID = domain.WorkspaceID{}
	if _, err := fixture.store.CostReport(context.Background(), orphan, telemetry.CostQuery{}); !errors.Is(err, coordination.ErrInvalid) {
		t.Fatalf("CostReport() = %v, want ErrInvalid", err)
	}
}

// TestCostReportTotalsSurviveTruncation keeps the alarming numbers independent
// of how much of the report the caller asked for. A total taken from the
// returned page would shrink with the limit, which would make abandonment look
// cheaper the less of the report you read.
func TestCostReportTotalsSurviveTruncation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-truncate")
	for _, path := range []string{"a/one.go", "a/two.go", "a/three.go"} {
		walked := acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
			coordination.LeaseSelectorExact, path)
		refuseClaim(t, fixture.store, fixture.blocked, path)
		contentionFlush(t, fixture.store)
		expireLease(t, fixture.store, walked)
	}

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Abandonment.Leases) != 1 {
		t.Fatalf("leases=%d, want the limit honoured", len(report.Abandonment.Leases))
	}
	if report.Abandonment.Abandoned != 3 {
		t.Fatalf("abandoned=%d, want all three counted despite the limit", report.Abandonment.Abandoned)
	}
	if report.Abandonment.RefusalsDuring != 3 {
		t.Fatalf("refusals=%d, want every refusal counted despite the limit",
			report.Abandonment.RefusalsDuring)
	}
}

// journalRow is one row read back out of the journal verbatim.
type journalRow struct {
	position                              int64
	workspace, actor, subject, visibility string
	payload                               []byte
}

// readJournalRows is separate from the re-insert below so the cursor is closed
// before any write runs against the same store, rather than held open across
// it.
func readJournalRows(t *testing.T, store *Store, eventType coordination.EventType) []journalRow {
	t.Helper()
	rows, err := store.db.QueryContext(context.Background(), `SELECT position, workspace_id, actor_id,
		subject_id, payload, visibility FROM coordination_events WHERE event_type = ?`, string(eventType))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var read []journalRow
	for rows.Next() {
		var value journalRow
		if err := rows.Scan(&value.position, &value.workspace, &value.actor, &value.subject,
			&value.payload, &value.visibility); err != nil {
			t.Fatal(err)
		}
		read = append(read, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return read
}

// slideEventInto re-stamps one journal row's occurred_at.
//
// It re-inserts rather than updating, because the journal is immutable by
// trigger and the pruner's DELETE is the only mutation the schema allows --
// which is the product behaving correctly, so the fixture works with it rather
// than around it. The payload is the one a REAL refusal produced; only the
// instant moves, which is precisely the variable under test.
func slideEventInto(t *testing.T, store *Store, eventType coordination.EventType, when time.Time) {
	t.Helper()
	ctx := context.Background()
	moved := readJournalRows(t, store, eventType)
	if len(moved) == 0 {
		t.Fatalf("no %s row to slide; the fixture recorded nothing", eventType)
	}
	for _, value := range moved {
		if _, err := store.db.ExecContext(ctx,
			`DELETE FROM coordination_events WHERE position = ?`, value.position); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, `INSERT INTO coordination_events(workspace_id, actor_id,
			event_type, subject_id, occurred_at_us, payload, visibility) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			value.workspace, value.actor, string(eventType), value.subject, when.UnixMicro(),
			value.payload, value.visibility); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCostReportExcludesWorkStampedAfterTheWindowItPublishes is the defect a
// half-open window hides, and it hides it permanently.
//
// The report states an Until and every section used to filter only on `>=
// Since`, so one row stamped in the future was counted in EVERY report from
// then until that date arrived. It is not a hypothetical: started_at_us is
// supplied by the harness that recorded the call and is unclamped at ingest --
// the column's only constraint is that it is positive -- and 0007's own comment
// says an adapter's clock may be wrong, which is exactly why retention is keyed
// on recorded_at_us instead. A window that publishes an edge it does not
// enforce is worse than one that publishes none, because a reader trusts it.
func TestCostReportExcludesWorkStampedAfterTheWindowItPublishes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-window")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	contentionFlush(t, fixture.store)
	// A refusal dated a month out, and a model call to match. Neither happened
	// inside any window a caller can ask for.
	future := time.Now().UTC().Add(30 * 24 * time.Hour)
	slideEventInto(t, fixture.store, coordination.EventLeaseRefused, future)
	appendFor(t, fixture.store, fixture.blocked, []domain.ModelCall{
		spendCall("future-1", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 1, CacheRead: 5_000_000, CacheWrite: 1, Output: 1},
			future, 0, false),
	}, nil)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Contention.Refusals != 0 {
		t.Fatalf("refusals=%d in a window ending %s, want none: the only refusal is dated %s",
			report.Contention.Refusals, report.Until.Format(time.RFC3339), future.Format(time.RFC3339))
	}
	if report.Contention.Observed() {
		t.Fatal("the contention section reports observations from outside its own window")
	}
	for _, model := range report.Cache.Models {
		if model.CacheRead != 0 {
			t.Fatalf("cache economics reports %d cache-read tokens from a call dated %s",
				model.CacheRead, future.Format(time.RFC3339))
		}
	}
	if report.Cache.Observed() {
		t.Fatal("cache economics observed a call stamped after the report's own Until")
	}
	// The spend rollup shares the defect and the fix, so it shares the test:
	// one future-dated call must not appear in a window that ended before it.
	spend, err := fixture.store.SpendReport(ctx, fixture.blocked,
		telemetry.SpendQuery{Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	if spend.Totals.Observations != 0 {
		t.Fatalf("spend counted %d observations in a window ending %s",
			spend.Totals.Observations, spend.Until.Format(time.RFC3339))
	}
	if !spend.Until.After(spend.Since) {
		t.Fatalf("spend window [%s, %s] is not a window", spend.Since, spend.Until)
	}
}

// TestCostReportCountsWorkInsideTheWindow is the other half of the bound: a
// closed window must not become an off-by-one that drops real work. Without
// this the previous test passes just as well against a query that returns
// nothing at all.
func TestCostReportCountsWorkInsideTheWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-window-inside")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	contentionFlush(t, fixture.store)
	appendFor(t, fixture.store, fixture.blocked, []domain.ModelCall{
		spendCall("inside-1", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 7, CacheRead: 11, CacheWrite: 13, Output: 17},
			time.Now().UTC(), 0, false),
	}, nil)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Contention.Refusals != 1 {
		t.Fatalf("refusals=%d, want the one refusal that happened inside the window", report.Contention.Refusals)
	}
	if len(report.Cache.Models) != 1 || report.Cache.Models[0].CacheRead != 11 {
		t.Fatalf("cache economics=%+v, want the one call inside the window", report.Cache.Models)
	}
	spend, err := fixture.store.SpendReport(ctx, fixture.blocked,
		telemetry.SpendQuery{Dimension: telemetry.SpendByModel})
	if err != nil {
		t.Fatal(err)
	}
	if spend.Totals.Observations != 1 {
		t.Fatalf("spend observations=%d, want the one call inside the window", spend.Totals.Observations)
	}
}

// TestCostReportStatesTheContentionFactsItLost is the difference between a
// measurement and a floor.
//
// The recorder drops rather than blocks -- that is required, since a fact may
// never delay the refusal it describes -- and shedding is NOT uniform: it bites
// hardest during a retry storm, which is the exact shape of contention this
// report exists to name. A refusal total built from a silently decimated sample
// reads as precise and is not, so the loss travels with the report or the
// report is misleading.
func TestCostReportStatesTheContentionFactsItLost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-lossy")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	contentionFlush(t, fixture.store)

	clean, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if clean.Recording.Lossy() {
		t.Fatalf("a journal that lost nothing reports Dropped=%d", clean.Recording.Dropped)
	}
	if clean.Recording.Written == 0 {
		t.Fatal("a journal that wrote the refusal reports Written=0")
	}

	// Offer a fact the journal cannot encode. It is refused before it is
	// queued, exactly as an overflowing queue refuses one, and the counter it
	// moves is the same one the report reads.
	fixture.store.contention.RecordClaimRefusal(coordination.ClaimRefusal{})
	lossy, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if !lossy.Recording.Lossy() {
		t.Fatal("the report claims a complete sample after the recorder dropped a fact")
	}
	if lossy.Recording.Dropped != 1 {
		t.Fatalf("Dropped=%d, want the one dropped fact", lossy.Recording.Dropped)
	}
	// The counts themselves are unchanged -- the point is not that the number
	// moves, it is that the reader is told the number is a lower bound.
	if lossy.Contention.Refusals != clean.Contention.Refusals {
		t.Fatalf("refusals changed from %d to %d when only the loss counter moved",
			clean.Contention.Refusals, lossy.Contention.Refusals)
	}
}

// TestCostReportAccountsForEveryWaitByItsEndReason pins the completeness claim
// on the six buckets. With only some of them reported a reader who finds that
// free plus deadline falls short of the wait count has to guess at the
// remainder, and the natural guess -- fold it into deadline -- invents
// abandonments that never happened.
func TestCostReportAccountsForEveryWaitByItsEndReason(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-reasons")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/wait.go")

	// A deadline: a path that never frees.
	blocked, err := fixture.store.AwaitCoordination(ctx, fixture.blocked, coordination.WaitRequest{
		Path: "internal/storage/sqlite/wait.go", Timeout: 200 * time.Millisecond})
	if err != nil || blocked.Reason != coordination.WaitDeadline {
		t.Fatalf("blocked wait reason=%q error=%v", blocked.Reason, err)
	}
	// A path that comes free immediately.
	free, err := fixture.store.AwaitCoordination(ctx, fixture.blocked, coordination.WaitRequest{
		Path: "internal/transport/mcp/mcp.go", Timeout: 5 * time.Second})
	if err != nil || free.Reason != coordination.WaitPathFree {
		t.Fatalf("free wait reason=%q error=%v", free.Reason, err)
	}
	// A caller that walks away, and a daemon that stops. Both cancel the same
	// context and only the CAUSE tells them apart.
	abandoned, cancelAbandoned := context.WithCancelCause(ctx)
	cancelAbandoned(errors.New("client hung up"))
	if _, err := fixture.store.AwaitCoordination(abandoned, fixture.blocked,
		coordination.WaitRequest{Path: "internal/storage/sqlite/wait.go",
			Timeout: time.Second}); err == nil {
		t.Fatal("a cancelled wait returned no error")
	}
	stopping, cancelStopping := context.WithCancelCause(ctx)
	cancelStopping(coordination.ErrDaemonStopping)
	if _, err := fixture.store.AwaitCoordination(stopping, fixture.blocked,
		coordination.WaitRequest{Path: "internal/storage/sqlite/wait.go",
			Timeout: time.Second}); err == nil {
		t.Fatal("a wait cut short by shutdown returned no error")
	}
	// A mail-only wait that finds nothing: also a deadline, and counted as a
	// mail wait rather than a path wait.
	mail, err := fixture.store.AwaitCoordination(ctx, fixture.blocked, coordination.WaitRequest{
		AwaitMail: true, Timeout: 200 * time.Millisecond})
	if err != nil || mail.Reason != coordination.WaitDeadline {
		t.Fatalf("mail wait reason=%q error=%v", mail.Reason, err)
	}
	contentionFlush(t, fixture.store)

	report, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	cost := report.Contention
	if got, want := cost.WaitsAccounted(), cost.PathWaits+cost.MailWaits; got != want {
		t.Fatalf("end reasons account for %d waits but %d were recorded: free=%d mail=%d "+
			"deadline=%d abandoned=%d stopped=%d unknown=%d", got, want, cost.WaitsEndedFree,
			cost.WaitsEndedMail, cost.WaitsEndedDeadline, cost.WaitsEndedAbandoned,
			cost.WaitsEndedStopped, cost.WaitsEndedUnknown)
	}
	if cost.WaitsEndedFree != 1 {
		t.Fatalf("waits ended free=%d, want 1", cost.WaitsEndedFree)
	}
	if cost.WaitsEndedDeadline != 2 {
		t.Fatalf("waits ended on deadline=%d, want the blocked path and the mail poll", cost.WaitsEndedDeadline)
	}
	// The whole reason the two cancellations are separated: a restart must not
	// masquerade as an agent giving up.
	if cost.WaitsEndedAbandoned != 1 {
		t.Fatalf("waits abandoned=%d, want only the caller that walked away", cost.WaitsEndedAbandoned)
	}
	if cost.WaitsEndedStopped != 1 {
		t.Fatalf("waits ended by shutdown=%d, want the one the daemon cut short", cost.WaitsEndedStopped)
	}
	if cost.MailWaits != 1 {
		t.Fatalf("mail waits=%d, want the one mail-only poll", cost.MailWaits)
	}
}

// TestCostReportSaysWhenItsListsWereCut keeps a capped list from reading as a
// complete one. The totals are taken over the whole window and stay honest
// either way, which is exactly why the flag is needed: without it, a reader
// who trusts the totals has no reason to distrust the rows beneath them.
func TestCostReportSaysWhenItsListsWereCut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-truncated")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/cost.go")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/admin.go")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/admin.go")
	contentionFlush(t, fixture.store)

	full, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Contention.Paths) != 2 || full.Contention.Truncated {
		t.Fatalf("an uncapped report has %d paths truncated=%t, want both and false",
			len(full.Contention.Paths), full.Contention.Truncated)
	}

	capped, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(capped.Contention.Paths) != 1 {
		t.Fatalf("a limit of one returned %d paths", len(capped.Contention.Paths))
	}
	if !capped.Contention.Truncated {
		t.Fatal("a cut list did not say it was cut")
	}
	// The totals are over the window, not over the page, so cutting the list
	// must not change them.
	if capped.Contention.Refusals != full.Contention.Refusals {
		t.Fatalf("refusals fell from %d to %d when only the list was capped",
			full.Contention.Refusals, capped.Contention.Refusals)
	}
}

// TestCostReportStatesTheScopeEachSectionUses is the fix for two refusal counts
// in one payload whose ratio can exceed one.
//
// Under mine_only the contention section counts only the caller's own denials
// while the abandonment section stays project-wide -- deliberately, since a
// lease someone ELSE abandoned is the thing a caller cannot see from its own
// side and most needs to be told about. Narrowing RefusalsDuring to match would
// produce a hybrid nobody asked for: abandoned leases from the whole project,
// but only the refusals that happened to hit me. So the scopes differ and the
// report says so, rather than leaving a reader to divide one by the other.
func TestCostReportStatesTheScopeEachSectionUses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/cost-scope")
	other, _, err := fixture.store.RegisterLocalAgent(ctx, "/workspace/cost-scope", "other", "")
	if err != nil {
		t.Fatal(err)
	}
	lease := acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/cost.go")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	refuseClaim(t, fixture.store, other, "internal/storage/sqlite/cost.go")
	contentionFlush(t, fixture.store)
	expireLease(t, fixture.store, lease)

	mine, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{MineOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !mine.MineOnly {
		t.Fatal("a narrowed report does not say it was narrowed")
	}
	if mine.Contention.Refusals != 1 {
		t.Fatalf("contention refusals=%d under mine_only, want only the caller's own", mine.Contention.Refusals)
	}
	// The abandonment half stays project-wide, which is the documented design
	// and the reason the scope has to be stated.
	if mine.Abandonment.RefusalsDuring != 2 {
		t.Fatalf("refusals caused by abandonment=%d, want both agents' -- this section is "+
			"project-wide by design", mine.Abandonment.RefusalsDuring)
	}

	project, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if project.MineOnly {
		t.Fatal("an unnarrowed report claims it was narrowed")
	}
	if project.Contention.Refusals != 2 {
		t.Fatalf("contention refusals=%d project-wide, want both", project.Contention.Refusals)
	}
}

// TestAdminCostReportAnswersForANamedProject is the operator's entry, and the
// point of the test is that it is the SAME computation as the agent's.
//
// Two implementations of "what did contention cost" would drift, and an
// operator's number disagreeing with an agent's about the same window is the
// kind of discrepancy nobody can debug. So both entries route through one set
// of queries and differ only in where the scope comes from.
func TestAdminCostReportAnswersForANamedProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/admin-cost")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")
	refuseClaim(t, fixture.store, fixture.blocked, "internal/storage/sqlite/cost.go")
	contentionFlush(t, fixture.store)
	appendFor(t, fixture.store, fixture.blocked, []domain.ModelCall{
		spendCall("admin-1", "claude-opus-5", domain.HarnessClaudeCode,
			domain.TokenUsage{UncachedInput: 10, CacheRead: 900, CacheWrite: 90, Output: 300},
			time.Now().UTC(), 0, false),
	}, nil)

	admin, err := fixture.store.AdminCostReport(ctx,
		telemetry.AdminCostQuery{ProjectKey: "/workspace/admin-cost"})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := fixture.store.CostReport(ctx, fixture.blocked, telemetry.CostQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if admin.Contention.Refusals != agent.Contention.Refusals {
		t.Fatalf("the operator sees %d refusals where the agent sees %d for the same window",
			admin.Contention.Refusals, agent.Contention.Refusals)
	}
	if admin.MineOnly {
		t.Fatal("an operator report claims a caller scope; an operator has no 'mine'")
	}
	// The operator surface carries the two sections the agent one omits.
	if len(admin.Contention.Agents) != 1 || admin.Contention.Agents[0].ModelCalls != 1 {
		t.Fatalf("agents=%+v, want the spend-against-contention row", admin.Contention.Agents)
	}
	if len(admin.Cache.Models) != 1 || admin.Cache.Models[0].CacheRead != 900 {
		t.Fatalf("cache=%+v, want the per-model input split", admin.Cache.Models)
	}
}

// TestAdminCostReportRefusesAProjectItHasNeverSeen keeps a typo from reading as
// a quiet project. An empty report would be a claim ABOUT that project -- that
// it cost nothing -- rather than a statement that this daemon has no such
// project, and only the second is true.
func TestAdminCostReportRefusesAProjectItHasNeverSeen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newCostFixture(t, "/workspace/admin-cost-missing")
	if _, err := fixture.store.AdminCostReport(ctx,
		telemetry.AdminCostQuery{ProjectKey: "/workspace/never-registered"}); err == nil {
		t.Fatal("an unknown project produced a report instead of an error")
	}
	// A missing project key is a caller error, not an "every project" reading:
	// contention summed across projects adds agents that could never collide.
	if _, err := fixture.store.AdminCostReport(ctx, telemetry.AdminCostQuery{}); !errors.Is(err, coordination.ErrInvalid) {
		t.Fatalf("an unscoped admin cost query error=%v, want ErrInvalid", err)
	}
}
