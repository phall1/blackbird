package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

// TestAuthenticateLocalAgentCoalescesTheSessionHeartbeat is the regression that
// pays for itself on every single tool call. Authentication ran inside a BEGIN
// IMMEDIATE for one reason -- stamping last_seen_at_us -- so every read paid a
// durable fullfsync commit and a turn of the daemon-wide write arbiter before
// it read anything.
func TestAuthenticateLocalAgentCoalescesTheSessionHeartbeat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	registered, token, err := store.RegisterLocalAgent(ctx, "/workspace/heartbeat", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	sessionText := registered.ActorSessionID.String()

	first, err := store.AuthenticateLocalAgent(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if first.AgentName != "alice" || first.ActorID != registered.ActorID ||
		first.ActorSessionID != registered.ActorSessionID {
		t.Fatalf("authenticated session=%+v, want the registered one", first)
	}
	flushed := storedLastSeen(t, store, sessionText)

	// The retry is the case that matters: an agent calls a tool, then another,
	// then another, and none of those calls owes the database anything.
	retried, err := store.AuthenticateLocalAgent(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if after := storedLastSeen(t, store, sessionText); after != flushed {
		t.Fatalf("retried authentication wrote last_seen_at_us %d, want the coalesced %d", after, flushed)
	}
	// The caller is still told the truth even though the row was not touched:
	// it is being seen now, and only the durable record is allowed to lag.
	if !retried.LastSeenAt.After(microsTime(flushed)) {
		t.Fatalf("reported last seen=%v, want an instant after the stored %v",
			retried.LastSeenAt, microsTime(flushed))
	}

	// Once the coalescing window has elapsed the next call does write, so the
	// durable row can never fall further behind than one interval.
	store.heartbeats.Lock()
	store.heartbeats.flushed[sessionText] = time.Now().Add(-2 * coordination.LocalAgentHeartbeatInterval)
	store.heartbeats.Unlock()
	if _, err := store.AuthenticateLocalAgent(ctx, token); err != nil {
		t.Fatal(err)
	}
	if after := storedLastSeen(t, store, sessionText); after <= flushed {
		t.Fatalf("last_seen_at_us=%d after the interval elapsed, want later than %d", after, flushed)
	}
}

// TestAuthenticateLocalAgentNeverWaitsOnTheWriteArbiter proves the property the
// coalescing exists for, rather than only its visible effect: with the single
// daemon-wide write lane held by somebody else, authentication still answers.
// Before, every tool call queued behind whatever write was in flight.
func TestAuthenticateLocalAgentNeverWaitsOnTheWriteArbiter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	_, token, err := store.RegisterLocalAgent(ctx, "/workspace/arbiter", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	// Flush the one heartbeat a fresh session owes before the lane is taken, so
	// the measured call is the steady-state one.
	if _, err := store.AuthenticateLocalAgent(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := store.acquireWrite(ctx, false); err != nil {
		t.Fatal(err)
	}
	defer store.releaseWrite()

	answered := make(chan error, 1)
	go func() {
		_, authErr := store.AuthenticateLocalAgent(ctx, token)
		answered <- authErr
	}()
	select {
	case authErr := <-answered:
		if authErr != nil {
			t.Fatal(authErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authentication blocked behind the write arbiter")
	}
}

func TestLocalAgentTokenFailuresNameTheRemedy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	_, token, err := store.RegisterLocalAgent(ctx, "/workspace/tokens", "alice", "")
	if err != nil || token == "" {
		t.Fatalf("register token=%q error=%v", token, err)
	}

	tests := []struct {
		name string
		call func() error
		want string
	}{
		{name: "new agent sent a registration token", call: func() error {
			_, _, err := store.RegisterLocalAgent(ctx, "/workspace/tokens", "bob", token)
			return err
		}, want: "without registration_token"},
		{name: "existing agent sent wrong registration token", call: func() error {
			_, _, err := store.RegisterLocalAgent(ctx, "/workspace/tokens", "alice", "wrong")
			return err
		}, want: "originally returned"},
		{name: "missing agent token", call: func() error {
			_, err := store.AuthenticateLocalAgent(ctx, "")
			return err
		}, want: "blackbird_join"},
		{name: "unknown agent token", call: func() error {
			_, err := store.AuthenticateLocalAgent(ctx, "bbm_nothing")
			return err
		}, want: "start or resume"},
		{name: "oversized agent token", call: func() error {
			_, err := store.AuthenticateLocalAgent(ctx, strings.Repeat("x", maxLocalAgentTokenBytes+1))
			return err
		}, want: "too long"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.call()
			var commandErr *domain.CommandError
			if !errors.As(err, &commandErr) || commandErr.Code() != domain.ErrorCodeUnauthenticated {
				t.Fatalf("error=%v, want an authentication rejection", err)
			}
			if !strings.Contains(commandErr.Message(), testCase.want) {
				t.Fatalf("message=%q, want %q", commandErr.Message(), testCase.want)
			}
		})
	}
}

func storedLastSeen(t *testing.T, store *Store, sessionText string) int64 {
	t.Helper()
	var lastSeen int64
	if err := store.db.QueryRow(`SELECT last_seen_at_us FROM coordination_agent_sessions WHERE session_id = ?`,
		sessionText).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	return lastSeen
}

// TestLocalAgentReservationsAnswerWhoHoldsAPath covers the answer a blocked
// agent could previously only get from the operator's loopback CLI: a lease
// refusal named a conflict without naming who to talk to about it.
func TestLocalAgentReservationsAnswerWhoHoldsAPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	const project = "/workspace/reservations"
	alice, _, err := store.RegisterLocalAgent(ctx, project, "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := store.RegisterLocalAgent(ctx, project, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	lease := acquireTestLease(t, store, alice, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "internal/storage")

	page, err := store.LocalAgentReservations(ctx, bob, coordination.AdminReservationsQuery{
		State: coordination.AdminReservationActive, Path: "internal/storage/sqlite/sqlite.go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Reservations) != 1 {
		t.Fatalf("reservations=%+v, want the one covering the path", page.Reservations)
	}
	held := page.Reservations[0]
	if held.LeaseID != lease.ID() || held.HolderAgentName != "alice" || held.Mode != coordination.LeaseExclusive ||
		held.State != coordination.AdminReservationActive || held.ExpiresInMS <= 0 ||
		len(held.Selectors) != 1 || held.Selectors[0].Path() != "internal/storage" {
		t.Fatalf("held reservation=%+v", held)
	}
	if page.ObservedAtUS <= 0 {
		t.Fatal("page carries no observation instant")
	}

	// The boundary rule the admin query already enforces has to survive the
	// scoping: a sibling path is not a conflict, and reporting one would be the
	// single worst answer this query can give.
	sibling, err := store.LocalAgentReservations(ctx, bob, coordination.AdminReservationsQuery{
		State: coordination.AdminReservationActive, Path: "internal/storagefoo/thing.go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sibling.Reservations) != 0 {
		t.Fatalf("sibling path matched %+v", sibling.Reservations)
	}
}

// TestLocalAgentReservationsCannotReadAnotherWorkspace pins the scoping rule.
// The caller's project key replaces whatever the query carried, so no transport
// can widen this read by forwarding a key the agent typed.
func TestLocalAgentReservationsCannotReadAnotherWorkspace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	alice, _, err := store.RegisterLocalAgent(ctx, "/workspace/one", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	carol, _, err := store.RegisterLocalAgent(ctx, "/workspace/two", "carol", "")
	if err != nil {
		t.Fatal(err)
	}
	acquireTestLease(t, store, alice, coordination.LeaseExclusive, coordination.LeaseSelectorExact, "shared/path.go")

	page, err := store.LocalAgentReservations(ctx, carol, coordination.AdminReservationsQuery{
		ProjectKey: alice.ProjectKey, Path: "shared/path.go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Reservations) != 0 {
		t.Fatalf("cross-workspace read returned %+v", page.Reservations)
	}
	if _, err := store.LocalAgentReservations(ctx, coordination.LocalAgentSession{},
		coordination.AdminReservationsQuery{}); !errors.Is(err, coordination.ErrInvalid) {
		t.Fatalf("unsessioned read error=%v, want an invalid coordination rejection", err)
	}
	if _, err := store.LocalAgentReservations(ctx, carol,
		coordination.AdminReservationsQuery{State: "sideways"}); !errors.Is(err, coordination.ErrInvalid) {
		t.Fatalf("invalid state error=%v, want an invalid coordination rejection", err)
	}
}

// TestOpenConversationIsIdempotentPerSlug covers the failure a compacted agent
// used to walk into: reopening "the auth refactor" minted a second thread while
// its teammates went on replying to the first.
func TestOpenConversationIsIdempotentPerSlug(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	alice, _, err := store.RegisterLocalAgent(ctx, "/workspace/slugs", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	first := openTestConversation(t, store, alice, "the auth refactor", "auth-refactor")
	if first.Slug() != "auth-refactor" {
		t.Fatalf("slug=%q", first.Slug())
	}

	// The reopen proposes a fresh UUID and a different topic, exactly as a
	// restarted agent would. Both are discarded in favour of the stored thread.
	second := openTestConversation(t, store, alice, "auth refactor, take two", "auth-refactor")
	if second.ID() != first.ID() {
		t.Fatalf("reopened conversation=%v, want the existing %v", second.ID(), first.ID())
	}
	if second.Topic() != "the auth refactor" || second.OpenedAt() != first.OpenedAt() {
		t.Fatalf("reopened conversation reported topic=%q opened=%v, want the stored thread's",
			second.Topic(), second.OpenedAt())
	}
	var stored int
	if err := store.db.QueryRow(`SELECT count(*) FROM conversations WHERE workspace_id = ? AND slug = ?`,
		alice.WorkspaceID.String(), "auth-refactor").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("conversations stored for the slug=%d, want one", stored)
	}

	// A different slug is a different thread, and no slug at all keeps the
	// behaviour every existing caller depends on: a fresh thread per call.
	other := openTestConversation(t, store, alice, "the storage rewrite", "storage-rewrite")
	if other.ID() == first.ID() {
		t.Fatal("a different slug reused the conversation")
	}
	anonymous := openTestConversation(t, store, alice, "ad hoc", "")
	repeated := openTestConversation(t, store, alice, "ad hoc", "")
	if anonymous.ID() == repeated.ID() || anonymous.Slug() != "" {
		t.Fatalf("unslugged opens collapsed: %v and %v", anonymous.ID(), repeated.ID())
	}
}

// TestOpenConversationScopesSlugsToTheWorkspace keeps the alternate key from
// leaking across projects: two agents in different workspaces may both call
// their work "auth-refactor" and neither may land in the other's thread.
func TestOpenConversationScopesSlugsToTheWorkspace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	alice, _, err := store.RegisterLocalAgent(ctx, "/workspace/slug-one", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	carol, _, err := store.RegisterLocalAgent(ctx, "/workspace/slug-two", "carol", "")
	if err != nil {
		t.Fatal(err)
	}
	mine := openTestConversation(t, store, alice, "auth refactor", "auth-refactor")
	theirs := openTestConversation(t, store, carol, "auth refactor", "auth-refactor")
	if mine.ID() == theirs.ID() {
		t.Fatal("a slug in one workspace answered an open in another")
	}
}

func TestOpenConversationRejectsAnUnusableSlug(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	alice, _, err := store.RegisterLocalAgent(ctx, "/workspace/slug-invalid", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	conversationID, err := domain.NewConversationID()
	if err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{" leading-space", strings.Repeat("s", coordination.MaxConversationSlugBytes+1)} {
		_, err := store.OpenConversation(ctx, coordination.OpenConversationParams{ConversationID: conversationID,
			WorkspaceID: alice.WorkspaceID, RunID: alice.RunID, OpenedBy: alice.ActorID,
			OpenedBySession: alice.ActorSessionID, Topic: "topic", Slug: slug})
		if !errors.Is(err, coordination.ErrInvalid) {
			t.Fatalf("slug %q error=%v, want an invalid coordination rejection", slug, err)
		}
	}
}

func openTestConversation(t *testing.T, store *Store, session coordination.LocalAgentSession,
	topic, slug string) coordination.Conversation {
	t.Helper()
	conversationID, err := domain.NewConversationID()
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := store.OpenConversation(context.Background(), coordination.OpenConversationParams{
		ConversationID: conversationID, WorkspaceID: session.WorkspaceID, RunID: session.RunID,
		OpenedBy: session.ActorID, OpenedBySession: session.ActorSessionID, Topic: topic, Slug: slug})
	if err != nil {
		t.Fatal(err)
	}
	return conversation
}

func acquireTestLease(t *testing.T, store *Store, session coordination.LocalAgentSession,
	mode coordination.LeaseMode, kind coordination.LeaseSelectorKind, path string) coordination.Lease {
	t.Helper()
	leaseID, err := domain.NewLeaseID()
	if err != nil {
		t.Fatal(err)
	}
	selector, err := coordination.NewLeaseSelector(kind, path)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireLease(context.Background(), coordination.AcquireLeaseParams{LeaseID: leaseID,
		WorkspaceID: session.WorkspaceID, Holder: session.ActorID, HolderSession: session.ActorSessionID,
		AuthorityEpoch: session.AuthorityEpoch, Mode: mode,
		Selectors: []coordination.LeaseSelector{selector}, TTL: 20 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

// TestHeartbeatLedgerGivesTheClaimBackWhenTheWriteFails is the safety property
// behind the coalescing. The claim is taken before the write, so a write that
// does not land must release it -- otherwise one failed flush suppresses the
// heartbeat for a whole interval and the session drifts toward looking stale
// while it is demonstrably alive.
func TestHeartbeatLedgerGivesTheClaimBackWhenTheWriteFails(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	registered, _, err := store.RegisterLocalAgent(context.Background(), "/workspace/ledger", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	sessionText := registered.ActorSessionID.String()
	now := time.Now()

	if !store.claimHeartbeat(sessionText, now) {
		t.Fatal("the first call did not owe a heartbeat")
	}
	if store.claimHeartbeat(sessionText, now.Add(time.Second)) {
		t.Fatal("a second call within the interval owed a heartbeat")
	}
	store.releaseHeartbeat(sessionText)
	if !store.claimHeartbeat(sessionText, now.Add(time.Second)) {
		t.Fatal("a released claim was not retried")
	}
	if !store.claimHeartbeat(sessionText, now.Add(2*coordination.LocalAgentHeartbeatInterval)) {
		t.Fatal("the interval elapsed without owing a heartbeat")
	}
	// A clock that stepped backwards must flush rather than stall: comparing
	// only the gap would treat a future-dated record as permanently fresh.
	if !store.claimHeartbeat(sessionText, now.Add(-time.Hour)) {
		t.Fatal("a backwards clock suppressed the heartbeat indefinitely")
	}

	// A flush that cannot run gives the claim back rather than swallowing it.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.flushLocalHeartbeat(cancelled, sessionText, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("flush error=%v, want the cancellation", err)
	}
	if !store.claimHeartbeat(sessionText, time.Now()) {
		t.Fatal("a failed flush kept its claim")
	}
}
