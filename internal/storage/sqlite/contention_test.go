package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

// contentionFlush waits for everything the store has offered so far to have
// been attempted, so an assertion about a recorded fact is never an assertion
// about how fast a goroutine happens to run.
func contentionFlush(t *testing.T, store *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := store.contention.flush(ctx); err != nil {
		t.Fatal(err)
	}
}

// contentionEvents reads the recorded facts of one type straight out of the
// journal, in position order.
func contentionEvents(t *testing.T, store *Store, eventType coordination.EventType) []recordedFact {
	t.Helper()
	rows, err := store.db.QueryContext(context.Background(), `SELECT position, workspace_id, actor_id,
		subject_id, occurred_at_us, payload, visibility FROM coordination_events
		WHERE event_type = ? ORDER BY position`, string(eventType))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var facts []recordedFact
	for rows.Next() {
		var fact recordedFact
		var payload []byte
		if err := rows.Scan(&fact.position, &fact.workspace, &fact.actor, &fact.subject,
			&fact.occurredAtUS, &payload, &fact.visibility); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(payload, &fact.payload); err != nil {
			t.Fatalf("recorded payload is not a JSON object: %v", err)
		}
		facts = append(facts, fact)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return facts
}

// factRecipients reads who a journal row is addressed to. Visibility is only
// half the claim: a 'recipients' row nobody is addressed on is a fact nobody
// can read, and the sync query matches this table rather than the row's own
// actor_id, so an author that is not its own recipient is invisible to itself.
func factRecipients(t *testing.T, store *Store, position int64) map[string]bool {
	t.Helper()
	rows, err := store.db.QueryContext(context.Background(),
		`SELECT actor_id FROM coordination_event_recipients WHERE position = ?`, position)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	addressed := map[string]bool{}
	for rows.Next() {
		var actor string
		if err := rows.Scan(&actor); err != nil {
			t.Fatal(err)
		}
		addressed[actor] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return addressed
}

type recordedFact struct {
	position     int64
	workspace    string
	actor        string
	subject      string
	occurredAtUS int64
	visibility   string
	payload      map[string]any
}

// TestRefusedClaimRecordsOneFactWithItsWholeConflict is the gap this closes.
// Before it, blackbird_claim answered a conflict with the holder and the expiry
// and then threw all of it away, so the journal could account for every
// acquisition and nothing about what losing one cost. The assertions below are
// the "no second lookup" contract: who was refused, what they asked for, who
// held it, which two selectors actually met, and when the holder was due to
// expire, all in the one row.
func TestRefusedClaimRecordsOneFactWithItsWholeConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/refusal-fact")
	held := acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")

	proposed, err := domain.NewLeaseID()
	if err != nil {
		t.Fatal(err)
	}
	wanted, err := coordination.NewLeaseSelector(coordination.LeaseSelectorExact, "internal/storage/sqlite/wait.go")
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := coordination.NewLeaseSelector(coordination.LeaseSelectorExact, "internal/transport/mcp/mcp.go")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.store.AcquireLease(ctx, coordination.AcquireLeaseParams{LeaseID: proposed,
		WorkspaceID: fixture.waiter.WorkspaceID, Holder: fixture.waiter.ActorID,
		HolderSession: fixture.waiter.ActorSessionID, AuthorityEpoch: fixture.waiter.AuthorityEpoch,
		Mode: coordination.LeaseExclusive, Selectors: []coordination.LeaseSelector{elsewhere, wanted},
		TTL: 7 * time.Minute})
	if !errors.Is(err, domain.ErrLeaseConflict) {
		t.Fatalf("acquire error=%v, want a lease conflict", err)
	}
	contentionFlush(t, fixture.store)

	facts := contentionEvents(t, fixture.store, coordination.EventLeaseRefused)
	if len(facts) != 1 {
		t.Fatalf("recorded %d refusals, want exactly one", len(facts))
	}
	fact := facts[0]
	if fact.workspace != fixture.waiter.WorkspaceID.String() || fact.actor != fixture.waiter.ActorID.String() {
		t.Fatalf("refusal attributed to workspace=%s actor=%s, want the refused agent's", fact.workspace, fact.actor)
	}
	// The subject is the caller's own proposed lease, which is what makes one
	// stubborn agent distinguishable from a retry storm.
	if fact.subject != proposed.String() {
		t.Fatalf("subject=%s, want the proposed lease %s", fact.subject, proposed)
	}
	// Addressed to exactly the two agents involved. Workspace visibility would
	// reach the holder too, and would additionally push every denial into every
	// bystander's stream -- which is worst during the retry storm this fact is
	// most worth recording for.
	if fact.visibility != coordinationVisibilityRecipients {
		t.Fatalf("visibility=%q, want recipients", fact.visibility)
	}
	addressed := factRecipients(t, fixture.store, fact.position)
	if len(addressed) != 2 || !addressed[fixture.waiter.ActorID.String()] ||
		!addressed[fixture.holder.ActorID.String()] {
		t.Fatalf("addressed=%v, want exactly the refused agent and the holder", addressed)
	}
	if fact.occurredAtUS <= 0 {
		t.Fatalf("occurred_at_us=%d", fact.occurredAtUS)
	}
	if fact.payload["refused_session_id"] != fixture.waiter.ActorSessionID.String() {
		t.Fatalf("refused_session_id=%v", fact.payload["refused_session_id"])
	}
	if fact.payload["requested_mode"] != string(coordination.LeaseExclusive) {
		t.Fatalf("requested_mode=%v", fact.payload["requested_mode"])
	}
	if ttl, ok := fact.payload["requested_ttl_ms"].(float64); !ok || int64(ttl) != (7*time.Minute).Milliseconds() {
		t.Fatalf("requested_ttl_ms=%v", fact.payload["requested_ttl_ms"])
	}
	// The whole requested set, not only the selector that lost: an analyst
	// needs to know the agent also wanted a path nobody held.
	requested, ok := fact.payload["requested_selectors"].([]any)
	if !ok || len(requested) != 2 {
		t.Fatalf("requested_selectors=%v", fact.payload["requested_selectors"])
	}
	overlap, ok := fact.payload["overlap"].(map[string]any)
	if !ok {
		t.Fatalf("overlap=%v", fact.payload["overlap"])
	}
	assertSelectorFields(t, "overlap.requested", overlap["requested"],
		string(coordination.LeaseSelectorExact), "internal/storage/sqlite/wait.go")
	assertSelectorFields(t, "overlap.holder", overlap["holder"],
		string(coordination.LeaseSelectorSubtree), "internal/storage")
	holder, ok := fact.payload["holder"].(map[string]any)
	if !ok {
		t.Fatalf("holder=%v", fact.payload["holder"])
	}
	if holder["lease_id"] != held.ID().String() || holder["actor_id"] != fixture.holder.ActorID.String() ||
		holder["mode"] != string(coordination.LeaseExclusive) {
		t.Fatalf("holder=%v, want lease %s held by %s", holder, held.ID(), fixture.holder.ActorID)
	}
	// The deadline is stored as an absolute instant, so the fact stays readable
	// long after the clock that wrote it moved on.
	expires, ok := holder["expires_at_us"].(float64)
	if !ok || int64(expires) != held.ExpiresAt().UnixMicro() {
		t.Fatalf("holder.expires_at_us=%v, want %d", holder["expires_at_us"], held.ExpiresAt().UnixMicro())
	}
}

func assertSelectorFields(t *testing.T, label string, value any, kind, path string) {
	t.Helper()
	selector, ok := value.(map[string]any)
	if !ok || selector["kind"] != kind || selector["path"] != path {
		t.Fatalf("%s=%v, want kind=%s path=%s", label, value, kind, path)
	}
}

// TestRefusedClaimIsVisibleToTheHolderItBlocked proves the visibility choice
// rather than the column, from both sides.
//
// The two agents in the collision must see it: the holder learns from its own
// stream that it is blocking someone, which is what turns a refusal into a
// conversation instead of a mystery, and the refused agent must be able to read
// back its own denial. A bystander must NOT see it, and that half is the reason
// this fact is addressed rather than broadcast -- a retry storm is the case that
// produces refusals fastest, so workspace visibility would spend every agent's
// context on a collision between two others that it can do nothing about.
func TestRefusedClaimIsVisibleToTheHolderItBlocked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/refusal-visibility")
	bystander, _, err := fixture.store.RegisterLocalAgent(ctx, "/workspace/refusal-visibility",
		"bystander", "")
	if err != nil {
		t.Fatal(err)
	}
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/domain/errors.go")
	refuseClaim(t, fixture.store, fixture.waiter, "internal/domain/errors.go")
	contentionFlush(t, fixture.store)

	for _, seen := range []struct {
		name    string
		session coordination.LocalAgentSession
		want    int
	}{
		{name: "holder", session: fixture.holder, want: 1},
		{name: "refused agent", session: fixture.waiter, want: 1},
		{name: "bystander", session: bystander, want: 0},
	} {
		query, err := coordination.NewEventsQuery(seen.session.WorkspaceID, seen.session.ActorID,
			coordination.EventCursor{}, 50)
		if err != nil {
			t.Fatal(err)
		}
		page, err := fixture.store.SyncCoordinationEvents(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		refusals := 0
		for _, event := range page.Events() {
			if event.EventType() == coordination.EventLeaseRefused {
				refusals++
			}
		}
		if refusals != seen.want {
			t.Fatalf("the %s saw %d refusals in its own stream, want %d", seen.name, refusals, seen.want)
		}
	}
}

// TestWaitRecordsOneFactPerWaitWithItsEndReason covers the reason the reason
// exists. A wait that ended because the path came free is coordination working;
// a wait that ended on its deadline is an agent about to abandon work. One
// waited-milliseconds number cannot tell those apart, so each outcome is
// asserted as the distinct recorded reason it is.
func TestWaitRecordsOneFactPerWaitWithItsEndReason(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/wait-fact")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/wait.go")

	// A blocked path that never frees: the deadline outcome.
	blocked, err := fixture.store.AwaitCoordination(ctx, fixture.waiter, coordination.WaitRequest{
		Path: "internal/storage/sqlite/wait.go", Timeout: 300 * time.Millisecond})
	if err != nil || blocked.Reason != coordination.WaitDeadline {
		t.Fatalf("blocked wait reason=%q error=%v", blocked.Reason, err)
	}
	// A free path: the coordination-working outcome.
	free, err := fixture.store.AwaitCoordination(ctx, fixture.waiter, coordination.WaitRequest{
		Path: "internal/transport/mcp/mcp.go", Timeout: 5 * time.Second})
	if err != nil || free.Reason != coordination.WaitPathFree {
		t.Fatalf("free wait reason=%q error=%v", free.Reason, err)
	}
	contentionFlush(t, fixture.store)

	facts := contentionEvents(t, fixture.store, coordination.EventWaitCompleted)
	if len(facts) != 2 {
		t.Fatalf("recorded %d wait facts, want one per wait", len(facts))
	}
	for index, want := range []coordination.WaitReason{coordination.WaitDeadline, coordination.WaitPathFree} {
		fact := facts[index]
		if fact.payload["reason"] != string(want) {
			t.Fatalf("wait %d reason=%v, want %q", index, fact.payload["reason"], want)
		}
		if fact.workspace != fixture.waiter.WorkspaceID.String() || fact.actor != fixture.waiter.ActorID.String() ||
			fact.subject != fixture.waiter.ActorSessionID.String() {
			t.Fatalf("wait %d attributed to %s/%s/%s", index, fact.workspace, fact.actor, fact.subject)
		}
		// A wait is the waiter's own idle time, so it is actor-visible rather
		// than filling every peer's stream with a parked minute.
		if fact.visibility != coordinationVisibilityActor {
			t.Fatalf("wait %d visibility=%q, want actor", index, fact.visibility)
		}
		started, startedOK := fact.payload["started_at_us"].(float64)
		ended, endedOK := fact.payload["ended_at_us"].(float64)
		if !startedOK || !endedOK || started <= 0 || ended < started {
			t.Fatalf("wait %d started=%v ended=%v", index, fact.payload["started_at_us"], fact.payload["ended_at_us"])
		}
		if budget, ok := fact.payload["budget_ms"].(float64); !ok || budget <= 0 {
			t.Fatalf("wait %d budget_ms=%v", index, fact.payload["budget_ms"])
		}
	}
	// The blocked wait names who held the path; the free one has nobody to
	// name, so the field is absent rather than an empty promise.
	blockers, ok := facts[0].payload["blocked_by"].([]any)
	if !ok || len(blockers) != 1 {
		t.Fatalf("blocked wait blocked_by=%v", facts[0].payload["blocked_by"])
	}
	if _, present := facts[1].payload["blocked_by"]; present {
		t.Fatalf("free wait recorded blockers: %v", facts[1].payload["blocked_by"])
	}
	// A path wait carries the path and the mode it intended to take; the mail
	// arm below is what proves those are omitted rather than blank.
	if facts[0].payload["path"] != "internal/storage/sqlite/wait.go" ||
		facts[0].payload["mode"] != string(coordination.LeaseExclusive) {
		t.Fatalf("blocked wait path=%v mode=%v", facts[0].payload["path"], facts[0].payload["mode"])
	}
}

// TestAbandonedWaitIsRecordedAsAbandonedRatherThanAsADeadline is the
// no-fabrication rule applied to the one outcome that tempts a lie. The caller
// went away mid-wait; its budget never ran out. Recording a deadline there
// would invent an expiry that never happened and would count a cancelled turn
// among the agents that ran out of patience.
func TestAbandonedWaitIsRecordedAsAbandonedRatherThanAsADeadline(t *testing.T) {
	t.Parallel()
	fixture := newWaitFixture(t, "/workspace/wait-abandoned")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/domain/telemetry.go")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := fixture.store.AwaitCoordination(ctx, fixture.waiter, coordination.WaitRequest{
		Path: "internal/domain/telemetry.go", Timeout: 30 * time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("await error=%v, want the cancellation", err)
	}
	contentionFlush(t, fixture.store)

	facts := contentionEvents(t, fixture.store, coordination.EventWaitCompleted)
	if len(facts) != 1 {
		t.Fatalf("recorded %d wait facts, want one", len(facts))
	}
	if facts[0].payload["reason"] != string(coordination.WaitAbandoned) {
		t.Fatalf("reason=%v, want %q", facts[0].payload["reason"], coordination.WaitAbandoned)
	}
}

// TestUndeterminedWaitReasonIsRecordedAsNull is the other half of the same
// rule. When the end condition was never evaluated -- a durable read that
// failed mid-poll with the caller still present -- the reason is absent, and
// absent is spelled null. This is the discipline
// telemetry_model_calls.duration_ms already holds: NULL says not measured, a
// value says measured, and the two must never be confusable. Reporting a
// deadline here would manufacture an agent that ran out of patience out of a
// database that ran out of a table.
func TestUndeterminedWaitReasonIsRecordedAsNull(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/wait-unknown")
	// Removing the table the reservation read joins is how the read is made to
	// fail for a reason that is not the caller leaving. Everything above it --
	// the poll, the exit, the record -- is the shipped path.
	if _, err := fixture.store.db.ExecContext(ctx, "DROP TABLE lease_selectors"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.AwaitCoordination(ctx, fixture.waiter, coordination.WaitRequest{
		Path: "internal/storage", Timeout: time.Second}); err == nil {
		t.Fatal("the wait answered from a database that cannot read reservations")
	}
	contentionFlush(t, fixture.store)

	facts := contentionEvents(t, fixture.store, coordination.EventWaitCompleted)
	if len(facts) != 1 {
		t.Fatalf("recorded %d wait facts, want one", len(facts))
	}
	reason, present := facts[0].payload["reason"]
	if !present || reason != nil {
		t.Fatalf("reason=%v present=%v, want an explicit null", reason, present)
	}
}

// TestMailWaitOmitsThePathItNeverWanted keeps a mail-only wait from claiming to
// have been about a path. An empty string there would group, filter and average
// exactly like a real path, so the field is absent instead.
func TestMailWaitOmitsThePathItNeverWanted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/wait-mail")
	result, err := fixture.store.AwaitCoordination(ctx, fixture.waiter, coordination.WaitRequest{
		AwaitMail: true, Timeout: 200 * time.Millisecond})
	if err != nil || result.Reason != coordination.WaitDeadline {
		t.Fatalf("mail wait reason=%q error=%v", result.Reason, err)
	}
	contentionFlush(t, fixture.store)

	facts := contentionEvents(t, fixture.store, coordination.EventWaitCompleted)
	if len(facts) != 1 {
		t.Fatalf("recorded %d wait facts, want one", len(facts))
	}
	if _, present := facts[0].payload["path"]; present {
		t.Fatalf("mail-only wait recorded a path: %v", facts[0].payload["path"])
	}
	if facts[0].payload["await_mail"] != true {
		t.Fatalf("await_mail=%v", facts[0].payload["await_mail"])
	}
}

// TestFailingToRecordDoesNotFailTheOperation is the ADR-0001 rule for this
// journal: the refusal is the product behaviour and the fact is bookkeeping
// about it. A recorder that cannot write must degrade its own record and touch
// nothing else -- so a claim still refuses, a wait still answers, and neither
// path so much as learns that the write failed.
func TestFailingToRecordDoesNotFailTheOperation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/contention-write-failure")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/runtime/runtime.go")

	// Replacing the commit is how the failure is made certain rather than
	// simulated: everything above it is the shipped path.
	broken := errors.New("durable contention write refused")
	fixture.store.contention.stop()
	fixture.store.contention = newContentionJournal(func(context.Context, []contentionFact) error {
		return broken
	})
	go fixture.store.contention.run()

	_, claimErr := fixture.store.AcquireLease(ctx, coordination.AcquireLeaseParams{
		LeaseID: newTestLeaseID(t), WorkspaceID: fixture.waiter.WorkspaceID, Holder: fixture.waiter.ActorID,
		HolderSession: fixture.waiter.ActorSessionID, AuthorityEpoch: fixture.waiter.AuthorityEpoch,
		Mode: coordination.LeaseExclusive, Selectors: []coordination.LeaseSelector{
			testSelector(t, coordination.LeaseSelectorExact, "internal/runtime/runtime.go")}, TTL: time.Minute})
	if !errors.Is(claimErr, domain.ErrLeaseConflict) {
		t.Fatalf("claim error=%v, want the refusal itself", claimErr)
	}
	if errors.Is(claimErr, broken) {
		t.Fatal("the refusal carried the recorder's failure to its caller")
	}
	result, waitErr := fixture.store.AwaitCoordination(ctx, fixture.waiter, coordination.WaitRequest{
		Path: "internal/runtime/runtime.go", Timeout: 150 * time.Millisecond})
	if waitErr != nil || result.Reason != coordination.WaitDeadline {
		t.Fatalf("wait reason=%q error=%v", result.Reason, waitErr)
	}
	contentionFlush(t, fixture.store)

	stats := fixture.store.ContentionStats()
	if stats.Offered != 2 || stats.Written != 0 || stats.WriteFailures == 0 {
		t.Fatalf("stats=%+v, want two facts offered, none written and the failure counted", stats)
	}
	// Nothing landed, and the journal says so rather than leaving a reader to
	// conclude the period was uncontended.
	if facts := contentionEvents(t, fixture.store, coordination.EventLeaseRefused); len(facts) != 0 {
		t.Fatalf("recorded %d refusals through a failing writer", len(facts))
	}
}

// TestClosedContentionJournalStillRefusesClaims covers the shutdown window.
// A store whose journal has stopped is a store that records no contention, and
// that must be indistinguishable to a caller from one that never recorded any.
func TestClosedContentionJournalStillRefusesClaims(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/contention-closed")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/cli/gc.go")
	fixture.store.contention.stop()

	_, err := fixture.store.AcquireLease(ctx, coordination.AcquireLeaseParams{
		LeaseID: newTestLeaseID(t), WorkspaceID: fixture.waiter.WorkspaceID, Holder: fixture.waiter.ActorID,
		HolderSession: fixture.waiter.ActorSessionID, AuthorityEpoch: fixture.waiter.AuthorityEpoch,
		Mode: coordination.LeaseExclusive, Selectors: []coordination.LeaseSelector{
			testSelector(t, coordination.LeaseSelectorExact, "internal/cli/gc.go")}, TTL: time.Minute})
	if !errors.Is(err, domain.ErrLeaseConflict) {
		t.Fatalf("claim error=%v, want the refusal", err)
	}
	if stats := fixture.store.ContentionStats(); stats.DroppedClosed != 1 {
		t.Fatalf("stats=%+v, want the drop counted against a closed journal", stats)
	}
}

// TestSharedClaimsAreNotRefusedAndRecordNothing keeps the journal honest in the
// other direction. Two shared readers over one path is coordination working;
// recording a refusal there would put contention in the record where none
// happened, and a denominator that counts non-events is worse than none.
func TestSharedClaimsAreNotRefusedAndRecordNothing(t *testing.T) {
	t.Parallel()
	fixture := newWaitFixture(t, "/workspace/shared-no-refusal")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseShared,
		coordination.LeaseSelectorExact, "README.md")
	acquireTestLease(t, fixture.store, fixture.waiter, coordination.LeaseShared,
		coordination.LeaseSelectorExact, "README.md")
	contentionFlush(t, fixture.store)

	if facts := contentionEvents(t, fixture.store, coordination.EventLeaseRefused); len(facts) != 0 {
		t.Fatalf("recorded %d refusals for two compatible shared claims", len(facts))
	}
}

// TestContentionFactsArePrunedByTheJournalRetentionPolicy is the reason these
// facts live in coordination_events rather than in a table of their own.
// Migration 0010 made this journal prunable and nothing else in the database
// is; a contention table would have grown forever until someone taught the
// pruner about it.
func TestContentionFactsArePrunedByTheJournalRetentionPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/contention-retention")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "Makefile")
	refuseClaim(t, fixture.store, fixture.waiter, "Makefile")
	contentionFlush(t, fixture.store)

	facts := contentionEvents(t, fixture.store, coordination.EventLeaseRefused)
	if len(facts) != 1 {
		t.Fatalf("recorded %d refusals, want one", len(facts))
	}
	// The pruner is keyed on coordination_events.position and nothing else, so
	// a contention fact is prunable for exactly the same reason every other
	// journal row is: it has a position.
	if _, err := fixture.store.db.ExecContext(ctx,
		`DELETE FROM coordination_events WHERE position <= ?`, facts[0].position); err != nil {
		t.Fatalf("the retention policy cannot reach a contention fact: %v", err)
	}
	if remaining := contentionEvents(t, fixture.store, coordination.EventLeaseRefused); len(remaining) != 0 {
		t.Fatalf("%d refusals survived the prune", len(remaining))
	}
}

func refuseClaim(t *testing.T, store *Store, session coordination.LocalAgentSession, path string) {
	t.Helper()
	_, err := store.AcquireLease(context.Background(), coordination.AcquireLeaseParams{
		LeaseID: newTestLeaseID(t), WorkspaceID: session.WorkspaceID, Holder: session.ActorID,
		HolderSession: session.ActorSessionID, AuthorityEpoch: session.AuthorityEpoch,
		Mode:      coordination.LeaseExclusive,
		Selectors: []coordination.LeaseSelector{testSelector(t, coordination.LeaseSelectorExact, path)},
		TTL:       time.Minute})
	if !errors.Is(err, domain.ErrLeaseConflict) {
		t.Fatalf("acquire %s error=%v, want a lease conflict", path, err)
	}
}

func newTestLeaseID(t *testing.T) domain.LeaseID {
	t.Helper()
	id, err := domain.NewLeaseID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testSelector(t *testing.T, kind coordination.LeaseSelectorKind, path string) coordination.LeaseSelector {
	t.Helper()
	selector, err := coordination.NewLeaseSelector(kind, path)
	if err != nil {
		t.Fatal(err)
	}
	return selector
}

// TestJournalRowsSurviveTheContentionRebuild is the risk migration 0012 carries.
// SQLite cannot widen a CHECK in place, so admitting two event types meant
// rebuilding coordination_events -- and coordination_event_recipients
// REFERENCES it ON DELETE CASCADE, which is one wrong statement away from
// deleting every blind copy's attribution. The position must survive too:
// consumer cursors are positions, and a rebuild that renumbered them would
// silently replay or skip history.
func TestJournalRowsSurviveTheContentionRebuild(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	installLegacyDatabase(t, path, 11)
	database, err := sql.Open("sqlite", databaseURL(Config{Path: path}))
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := domain.ParseWorkspaceID("01b8e094-9888-7000-8000-0000000012a1")
	if err != nil {
		t.Fatal(err)
	}
	author, err := domain.ParseActorID("01b8e094-9888-7000-8000-0000000012a2")
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := domain.ParseActorID("01b8e094-9888-7000-8000-0000000012a3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO coordination_events(position, workspace_id, actor_id,
		event_type, subject_id, occurred_at_us, payload, visibility)
		VALUES (41, ?, ?, 'message.available', 'legacy-recipients', 1, ?, 'recipients')`,
		workspace.String(), author.String(), []byte(`{"legacy":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO coordination_event_recipients(position, actor_id) VALUES (41, ?)`,
		recipient.String()); err != nil {
		t.Fatal(err)
	}
	cursor, err := encodeCoordinationCursor(ctx, database, workspace, recipient, 40)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("climb to the contention rung: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	query, err := coordination.NewEventsQuery(workspace, recipient, cursor, 10)
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.SyncCoordinationEvents(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	events := page.Events()
	if len(events) != 1 || events[0].Position() != 41 || events[0].SubjectID() != "legacy-recipients" {
		t.Fatalf("page=%+v error=%v, want the recipient-visible row at its original position", events, err)
	}
	var recipients int
	if err := store.db.QueryRowContext(ctx,
		`SELECT count(*) FROM coordination_event_recipients WHERE position = 41`).Scan(&recipients); err != nil {
		t.Fatal(err)
	}
	if recipients != 1 {
		t.Fatalf("recipient rows=%d, want the blind copy's attribution intact", recipients)
	}
	// The high-water mark has to come across too, or the next fact reissues a
	// position every consumer cursor has already passed.
	session, _, err := store.RegisterLocalAgent(ctx, "/workspace/rebuilt", "agent", "")
	if err != nil {
		t.Fatal(err)
	}
	acquireTestLease(t, store, session, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/contention.go")
	var head int64
	if err := store.db.QueryRowContext(ctx,
		`SELECT max(position) FROM coordination_events`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if head <= 41 {
		t.Fatalf("next journal position=%d, want it past the migrated high-water mark", head)
	}
}

// TestContentionQueueShedsRatherThanBlocks is the property that makes the
// journal safe on the hot path at all. Once the queue is full the recorder must
// drop and count, because the alternative -- waiting for room -- would put an
// observation's write latency into the refusal it is only describing.
func TestContentionQueueShedsRatherThanBlocks(t *testing.T) {
	t.Parallel()
	fixture := newWaitFixture(t, "/workspace/contention-shed")
	// A journal with no drain running and no store attached, so nothing empties
	// the queue and the only way offer can return is by shedding.
	journal := newContentionJournal(func(context.Context, []contentionFact) error { return nil })

	refusal := coordination.ClaimRefusal{WorkspaceID: fixture.waiter.WorkspaceID,
		RefusedActor: fixture.waiter.ActorID, RefusedSession: fixture.waiter.ActorSessionID,
		ProposedLeaseID: newTestLeaseID(t), RequestedMode: coordination.LeaseExclusive,
		Holder:    coordination.ContentionHolder{LeaseID: newTestLeaseID(t), Actor: fixture.holder.ActorID},
		RefusedAt: time.Now().UTC()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range contentionQueueDepth * 2 {
			journal.RecordClaimRefusal(refusal)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("recording blocked on a full queue")
	}
	stats := journal.stats()
	if stats.Offered != contentionQueueDepth || stats.DroppedFull != contentionQueueDepth {
		t.Fatalf("stats=%+v, want the queue filled and the rest shed", stats)
	}
}

// TestMalformedFactIsDroppedBeforeItCanRollBackABatch keeps one unusable fact
// from costing the sound ones queued beside it. Validating at the insert
// instead would fail the whole transaction, so a single bad row would take a
// batch of good ones with it.
func TestMalformedFactIsDroppedBeforeItCanRollBackABatch(t *testing.T) {
	t.Parallel()
	fixture := newWaitFixture(t, "/workspace/contention-malformed")
	// No holder: nothing this fact could ever say about who was in the way.
	fixture.store.contention.RecordClaimRefusal(coordination.ClaimRefusal{
		WorkspaceID: fixture.waiter.WorkspaceID, RefusedActor: fixture.waiter.ActorID,
		ProposedLeaseID: newTestLeaseID(t), RefusedAt: time.Now().UTC()})
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "go.mod")
	refuseClaim(t, fixture.store, fixture.waiter, "go.mod")
	contentionFlush(t, fixture.store)

	stats := fixture.store.ContentionStats()
	if stats.DroppedInvalid != 1 || stats.Offered != 1 || stats.Written != 1 || stats.WriteFailures != 0 {
		t.Fatalf("stats=%+v, want the malformed fact dropped and the sound one written", stats)
	}
	if facts := contentionEvents(t, fixture.store, coordination.EventLeaseRefused); len(facts) != 1 {
		t.Fatalf("recorded %d refusals, want the sound one", len(facts))
	}
}

// TestRecordedParkIsTheMonotonicDurationNotTheWallClock covers a defect that is
// invisible until the machine's clock moves, and then silently poisons every
// average taken over it.
//
// StartedAt and EndedAt are wall-clock instants -- Go strips the monotonic
// reading from a time.Time the moment UTC() converts it -- so their difference
// measures the wall clock and goes NEGATIVE across an NTP step or a
// suspend/resume. The value returned to the caller has always come from
// time.Since, which is monotonic, so deriving the journalled duration from the
// two stamps also let the recorded park disagree with the reported one. The
// journal takes the monotonic figure, and clamps, because waited_ms lives
// inside a JSON payload where no CHECK constraint can catch a negative.
func TestRecordedParkIsTheMonotonicDurationNotTheWallClock(t *testing.T) {
	t.Parallel()
	workspace, err := domain.NewWorkspaceID()
	if err != nil {
		t.Fatal(err)
	}
	waiter, err := domain.NewActorID()
	if err != nil {
		t.Fatal(err)
	}
	waiterSession, err := domain.NewActorSessionID()
	if err != nil {
		t.Fatal(err)
	}
	session := coordination.WaitObservation{
		WorkspaceID: workspace, Waiter: waiter, WaiterSession: waiterSession,
		// The wall clock stepped BACKWARD by a minute mid-wait, so EndedAt
		// precedes StartedAt. The wait itself really took 1500ms.
		StartedAt: time.Now().UTC(),
		EndedAt:   time.Now().UTC().Add(-time.Minute),
		Waited:    1500 * time.Millisecond,
		Reason:    coordination.WaitDeadline,
	}
	row, err := waitRow(session)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(row.payload, &payload); err != nil {
		t.Fatal(err)
	}
	waited, ok := payload["waited_ms"].(float64)
	if !ok {
		t.Fatalf("waited_ms=%v, want a number", payload["waited_ms"])
	}
	if int64(waited) != 1500 {
		t.Fatalf("waited_ms=%d, want the 1500ms the monotonic clock measured, not the %dms "+
			"between two wall-clock stamps", int64(waited),
			session.EndedAt.Sub(session.StartedAt).Milliseconds())
	}

	// A fact that reached the journal without a stamped duration must record
	// zero rather than something negative: one negative park poisons every sum
	// the cost report takes over the column.
	session.Waited = -time.Second
	row, err = waitRow(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(row.payload, &payload); err != nil {
		t.Fatal(err)
	}
	if waited, _ := payload["waited_ms"].(float64); waited != 0 {
		t.Fatalf("waited_ms=%v for an unmeasured park, want 0", payload["waited_ms"])
	}
}
