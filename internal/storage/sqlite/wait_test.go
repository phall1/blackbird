package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
)

// waitFixture is two agents in one project: the one that holds things and the
// one that has to wait for them.
type waitFixture struct {
	store  *Store
	holder coordination.LocalAgentSession
	waiter coordination.LocalAgentSession
}

func newWaitFixture(t *testing.T, project string) waitFixture {
	t.Helper()
	ctx := context.Background()
	store := newCoordinationStore(t)
	holder, _, err := store.RegisterLocalAgent(ctx, project, "holder", "")
	if err != nil {
		t.Fatal(err)
	}
	waiter, _, err := store.RegisterLocalAgent(ctx, project, "waiter", "")
	if err != nil {
		t.Fatal(err)
	}
	return waitFixture{store: store, holder: holder, waiter: waiter}
}

// TestAwaitCoordinationReturnsWhenTheLeaseIsReleased is the whole point of the
// primitive: an agent refused a lease has no server-to-model channel to be told
// on, so without a bounded wait it can only spin or abandon the work.
func TestAwaitCoordinationReturnsWhenTheLeaseIsReleased(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/wait-release")
	lease := acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")

	released := make(chan struct{})
	go func() {
		defer close(released)
		time.Sleep(50 * time.Millisecond)
		if _, err := fixture.store.ReleaseLease(ctx, coordination.ChangeLeaseParams{WorkspaceID: fixture.holder.WorkspaceID,
			Holder: fixture.holder.ActorID, HolderSession: fixture.holder.ActorSessionID,
			AuthorityEpoch: fixture.holder.AuthorityEpoch, Selectors: lease.Selectors()}); err != nil {
			t.Error(err)
		}
	}()

	started := time.Now()
	result, err := fixture.store.AwaitCoordination(ctx, fixture.waiter, coordination.CoordinationWaitRequest{
		Path: "internal/storage/sqlite/sqlite.go", Timeout: 10 * time.Second})
	<-released
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != coordination.CoordinationWaitPathFree {
		t.Fatalf("reason=%q blockers=%+v, want the path reported free", result.Reason, result.Blockers)
	}
	if len(result.Blockers) != 0 {
		t.Fatalf("blockers=%+v on a free path", result.Blockers)
	}
	// Promptness is the property that decides whether an agent waits or gives
	// up; a wait that notices a release a minute late is a wait nobody uses.
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("noticed the release after %v", elapsed)
	}
	if result.WaitedMS < 0 || result.ObservedAtUS <= 0 {
		t.Fatalf("result=%+v", result)
	}
}

// TestAwaitCoordinationReportsTheDeadlineWithItsBlockers keeps a give-up
// actionable: the caller that ran out of budget is told who is holding the path
// and for how much longer, so its next move is a conversation and not a retry.
func TestAwaitCoordinationReportsTheDeadlineWithItsBlockers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/wait-deadline")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/sqlite.go")

	result, err := fixture.store.AwaitCoordination(ctx, fixture.waiter, coordination.CoordinationWaitRequest{
		Path: "internal/storage/sqlite/sqlite.go", Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != coordination.CoordinationWaitDeadline {
		t.Fatalf("reason=%q, want the deadline", result.Reason)
	}
	if len(result.Blockers) != 1 || result.Blockers[0].HolderAgentName != "holder" ||
		result.Blockers[0].Mode != coordination.LeaseExclusive || result.Blockers[0].ExpiresInMS <= 0 ||
		len(result.Blockers[0].Selectors) != 1 {
		t.Fatalf("blockers=%+v", result.Blockers)
	}
	if result.WaitedMS < 200 {
		t.Fatalf("waited %dms, want roughly the requested budget", result.WaitedMS)
	}
}

// TestAwaitCoordinationReadsConflictTheWayAcquisitionDoes keeps the wait honest
// against the rule AcquireLease applies: a lease the caller already holds is
// never a blocker, and a shared reader is held up only by an exclusive writer.
// Getting either wrong parks an agent behind a lease that would have let it in.
func TestAwaitCoordinationReadsConflictTheWayAcquisitionDoes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, testCase := range []struct {
		name       string
		heldMode   coordination.LeaseMode
		heldBy     func(waitFixture) coordination.LocalAgentSession
		wantedMode coordination.LeaseMode
		wantReason coordination.CoordinationWaitReason
	}{
		{name: "the caller's own lease is not a blocker", heldMode: coordination.LeaseExclusive,
			heldBy:     func(f waitFixture) coordination.LocalAgentSession { return f.waiter },
			wantReason: coordination.CoordinationWaitPathFree},
		{name: "a shared reader waits out nobody but a writer", heldMode: coordination.LeaseShared,
			heldBy:     func(f waitFixture) coordination.LocalAgentSession { return f.holder },
			wantedMode: coordination.LeaseShared, wantReason: coordination.CoordinationWaitPathFree},
		{name: "a shared holder still blocks an exclusive taker", heldMode: coordination.LeaseShared,
			heldBy:     func(f waitFixture) coordination.LocalAgentSession { return f.holder },
			wantedMode: coordination.LeaseExclusive, wantReason: coordination.CoordinationWaitDeadline},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			fixture := newWaitFixture(t, "/workspace/wait-conflict-"+testCase.name)
			acquireTestLease(t, fixture.store, testCase.heldBy(fixture), testCase.heldMode,
				coordination.LeaseSelectorExact, "internal/storage/sqlite/sqlite.go")
			result, err := fixture.store.AwaitCoordination(ctx, fixture.waiter,
				coordination.CoordinationWaitRequest{Path: "internal/storage/sqlite/sqlite.go",
					Mode: testCase.wantedMode, Timeout: 300 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if result.Reason != testCase.wantReason {
				t.Fatalf("reason=%q blockers=%+v, want %q", result.Reason, result.Blockers, testCase.wantReason)
			}
		})
	}
}

// TestAwaitCoordinationWakesOnNewMail covers the other half of the primitive.
// The floor is the mail head at the first poll, so a wait ends on mail that
// arrives during it and not on mail that was already sitting unread.
func TestAwaitCoordinationWakesOnNewMail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/wait-mail")
	seedSnapshotMail(t, fixture.store, fixture.holder, fixture.waiter)

	// Mail that predates the wait must not end it, or an agent with a backlog
	// can never wait for anything again.
	stale, err := fixture.store.AwaitCoordination(ctx, fixture.waiter,
		coordination.CoordinationWaitRequest{AwaitMail: true, Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if stale.Reason != coordination.CoordinationWaitDeadline || stale.PendingDeliveries != 1 {
		t.Fatalf("result=%+v, want the deadline with the backlog reported", stale)
	}

	sent := make(chan struct{})
	go func() {
		defer close(sent)
		time.Sleep(50 * time.Millisecond)
		seedSnapshotMail(t, fixture.store, fixture.holder, fixture.waiter)
	}()
	result, err := fixture.store.AwaitCoordination(ctx, fixture.waiter,
		coordination.CoordinationWaitRequest{AwaitMail: true, Timeout: 10 * time.Second})
	<-sent
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != coordination.CoordinationWaitMailArrived || result.PendingDeliveries != 2 {
		t.Fatalf("result=%+v, want a mail wakeup carrying the pending count", result)
	}
}

// TestBoundedWaitBudgetIsCappedServerSide pins the ceiling. It is checked here
// rather than by running a wait, because the only honest end-to-end assertion
// is a minute long and a test that sleeps a minute gets deleted.
func TestBoundedWaitBudgetIsCappedServerSide(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		requested time.Duration
		want      time.Duration
	}{
		{0, coordination.MaxCoordinationWait},
		{-time.Second, coordination.MaxCoordinationWait},
		{coordination.MaxCoordinationWait + time.Second, coordination.MaxCoordinationWait},
		{time.Hour, coordination.MaxCoordinationWait},
		{5 * time.Second, 5 * time.Second},
		{coordination.MaxCoordinationWait, coordination.MaxCoordinationWait},
	} {
		if got := boundedWaitBudget(testCase.requested); got != testCase.want {
			t.Fatalf("budget for %v = %v, want %v", testCase.requested, got, testCase.want)
		}
	}
}

func TestAwaitCoordinationRejectsRequestsItCannotServe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newWaitFixture(t, "/workspace/wait-invalid")
	for _, testCase := range []struct {
		name    string
		session coordination.LocalAgentSession
		request coordination.CoordinationWaitRequest
	}{
		{"no session", coordination.LocalAgentSession{}, coordination.CoordinationWaitRequest{AwaitMail: true}},
		// A request naming neither condition can only ever sleep out its budget.
		{"no condition", fixture.waiter, coordination.CoordinationWaitRequest{}},
		{"unusable path", fixture.waiter, coordination.CoordinationWaitRequest{Path: " leading-space"}},
		{"unknown mode", fixture.waiter, coordination.CoordinationWaitRequest{Path: "a/b.go", Mode: "sideways"}},
	} {
		_, err := fixture.store.AwaitCoordination(ctx, testCase.session, testCase.request)
		if !errors.Is(err, coordination.ErrInvalidCoordination) {
			t.Fatalf("%s error=%v, want an invalid coordination rejection", testCase.name, err)
		}
	}
}

// TestAwaitCoordinationReportsCancellationAsCancellation keeps a client that
// hung up from looking like a path that is still held.
func TestAwaitCoordinationReportsCancellationAsCancellation(t *testing.T) {
	t.Parallel()
	fixture := newWaitFixture(t, "/workspace/wait-cancel")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "internal/storage/sqlite/sqlite.go")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	_, err := fixture.store.AwaitCoordination(ctx, fixture.waiter, coordination.CoordinationWaitRequest{
		Path: "internal/storage/sqlite/sqlite.go", Timeout: 10 * time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want a cancellation", err)
	}
}

// TestAwaitCoordinationHoldsNoConnectionWhileItWaits is the property that
// decides whether this primitive is safe to expose at all. The daemon reads
// through a bounded connection pool shared by every caller, so
// a wait that kept its connection for the duration of the wait would let a
// handful of parked agents take the whole pool and stall every unrelated read
// on the machine -- turning a convenience into an outage. Polling is what buys
// the property: each poll is its own short snapshot that gives the connection
// straight back, and only the sleep between polls is long.
//
// It is asserted two ways, because either alone is weak. The pool's own
// accounting must be observed completely idle while twice the pool's worth of
// waiters are parked -- a waiter that held its connection would pin InUse at
// the ceiling and never read zero -- and an unrelated reader must still be
// answered promptly, which is the user-visible harm the invariant exists to
// prevent.
func TestAwaitCoordinationHoldsNoConnectionWhileItWaits(t *testing.T) {
	t.Parallel()
	fixture := newWaitFixture(t, "/workspace/wait-pool")
	acquireTestLease(t, fixture.store, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")

	// Deliberately more waiters than the pool has connections: if a wait held
	// one, the pool would be exhausted before the last waiter even started.
	waiters := 2 * fixture.store.readPoolSize
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parked := make(chan struct{}, waiters)
	done := make(chan error, waiters)
	for range waiters {
		go func() {
			parked <- struct{}{}
			_, err := fixture.store.AwaitCoordination(ctx, fixture.waiter,
				coordination.CoordinationWaitRequest{Path: "internal/storage/sqlite/sqlite.go",
					Timeout: coordination.MaxCoordinationWait})
			done <- err
		}()
	}
	for range waiters {
		<-parked
	}
	// Let every waiter get past its first poll and into the sleep that
	// dominates its life.
	time.Sleep(2 * coordination.CoordinationWaitPoll)

	// An unrelated reader must not be queued behind the parked waiters.
	readStarted := time.Now()
	if _, err := fixture.store.AdminOverview(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(readStarted); elapsed > 5*time.Second {
		t.Fatalf("an unrelated read waited %v behind %d parked waiters", elapsed, waiters)
	}

	idle := false
	busiest := 0
	for range 200 {
		stats := fixture.store.db.Stats()
		if stats.InUse > busiest {
			busiest = stats.InUse
		}
		if stats.InUse == 0 {
			idle = true
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !idle {
		t.Fatalf("the read pool was never idle with %d waiters parked (busiest InUse=%d of %d): "+
			"a wait is holding its connection between polls", waiters, busiest, fixture.store.readPoolSize)
	}

	cancel()
	for range waiters {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter ended with %v, want the cancellation", err)
		}
	}
}
