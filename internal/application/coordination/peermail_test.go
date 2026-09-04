package coordination

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

func TestParsePeerAddressReadsTheGrammarAndRefusesTheRest(t *testing.T) {
	t.Parallel()
	valid := map[string]PeerAddress{
		"reviewer@phalls-mac-mini":        {Agent: "reviewer", Host: "phalls-mac-mini"},
		"reviewer@mini.tail1354da.ts.net": {Agent: "reviewer", Host: "mini.tail1354da.ts.net"},
		"reviewer@100.79.155.27":          {Agent: "reviewer", Host: "100.79.155.27"},
		"reviewer@mini:9000":              {Agent: "reviewer", Host: "mini:9000"},
		// The host half is compared case-insensitively, so two spellings of one
		// machine cannot become two peer actors with two mailboxes.
		"reviewer@Phalls-Mac-Mini": {Agent: "reviewer", Host: "phalls-mac-mini"},
	}
	for text, want := range valid {
		got, err := ParsePeerAddress(text)
		if err != nil {
			t.Fatalf("ParsePeerAddress(%q) = %v", text, err)
		}
		if got != want {
			t.Fatalf("ParsePeerAddress(%q) = %+v, want %+v", text, got, want)
		}
	}
	// Every refusal below is an address that could otherwise be REPAIRED into
	// something, and a repaired address is a message delivered to a machine
	// nobody named.
	for _, text := range []string{
		"reviewer", "@mini", "reviewer@", "reviewer@ ", "reviewer@mini/path",
		"reviewer@http://mini", "reviewer@mini?x=1", "reviewer@a@b", " reviewer@mini",
	} {
		if address, err := ParsePeerAddress(text); err == nil {
			t.Fatalf("ParsePeerAddress(%q) accepted %+v, want a refusal", text, address)
		}
	}
}

func TestIsPeerAddressIsSyntacticRatherThanALookup(t *testing.T) {
	t.Parallel()
	if !IsPeerAddress("reviewer@mini") {
		t.Fatal("a qualified name must be a cross-host address")
	}
	if IsPeerAddress("reviewer") {
		t.Fatal("an unqualified name must still mean an agent on this host")
	}
}

func TestPeerAuthorNameUsesTheVerifiedHost(t *testing.T) {
	t.Parallel()
	if got := PeerAuthorName("implementer", "Phalls-Mac-Mini"); got != "implementer@phalls-mac-mini" {
		t.Fatalf("PeerAuthorName = %q", got)
	}
}

func TestPeerMailBackoffDoublesAndStops(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0).UTC()
	waits := []time.Duration{}
	for attempt := 1; attempt <= MaxPeerMailAttempts; attempt++ {
		waits = append(waits, PeerMailBackoff(now, attempt).Sub(now))
	}
	if waits[0] != PeerMailFirstBackoff {
		t.Fatalf("first wait=%v, want %v", waits[0], PeerMailFirstBackoff)
	}
	for index := 1; index < len(waits); index++ {
		if waits[index] < waits[index-1] {
			t.Fatalf("wait %d (%v) is shorter than wait %d (%v)", index, waits[index], index-1, waits[index-1])
		}
		if waits[index] > PeerMailMaxBackoff {
			t.Fatalf("wait %d = %v, above the ceiling %v", index, waits[index], PeerMailMaxBackoff)
		}
	}
}

// TestPeerMailExhaustedChecksBothBudgets covers the two ways a delivery runs
// out, neither of which implies the other: a peer refusing connections burns
// attempts and no time, and a daemon that was off for a week burns time and no
// attempts.
func TestPeerMailExhaustedChecksBothBudgets(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	fresh := PeerMailEntry{Attempts: 0, QueuedAt: now}
	if PeerMailExhausted(fresh, now) {
		t.Fatal("a fresh entry is not exhausted")
	}
	spent := PeerMailEntry{Attempts: MaxPeerMailAttempts - 1, QueuedAt: now}
	if !PeerMailExhausted(spent, now) {
		t.Fatal("an entry on its last attempt is exhausted")
	}
	stale := PeerMailEntry{Attempts: 0, QueuedAt: now.Add(-PeerMailExpiry - time.Minute)}
	if !PeerMailExhausted(stale, now) {
		t.Fatal("an entry older than the expiry is exhausted whatever its attempt count")
	}
}

// stubPeerMailStore records outcomes and answers claims.
type stubPeerMailStore struct {
	mu        sync.Mutex
	due       []PeerMailEntry
	outcomes  []PeerMailOutcome
	claimErr  error
	settleErr error
}

func (stub *stubPeerMailStore) SendPeerMail(context.Context, LocalAgentSession,
	SendPeerMailParams) (PeerMailSend, error) {
	return PeerMailSend{}, errors.New("not used")
}

func (stub *stubPeerMailStore) ClaimPeerMail(context.Context, time.Time, int) ([]PeerMailEntry, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.claimErr != nil {
		return nil, stub.claimErr
	}
	claimed := stub.due
	stub.due = nil
	return claimed, nil
}

func (stub *stubPeerMailStore) SettlePeerMail(_ context.Context, outcome PeerMailOutcome) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.settleErr != nil {
		return stub.settleErr
	}
	stub.outcomes = append(stub.outcomes, outcome)
	return nil
}

func (stub *stubPeerMailStore) AcceptPeerMail(context.Context,
	AcceptPeerMailParams) (AcceptedPeerMail, error) {
	return AcceptedPeerMail{}, errors.New("not used")
}

func (stub *stubPeerMailStore) settled() []PeerMailOutcome {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return append([]PeerMailOutcome(nil), stub.outcomes...)
}

type stubPeerMailSender struct {
	mu        sync.Mutex
	err       error
	receipt   PeerMailReceipt
	attempts  int
	inflight  int
	peak      int
	shipments [][]string
}

func (stub *stubPeerMailSender) DeliverPeerMail(ctx context.Context, _ PeerMailEntry,
	recipients []string) (PeerMailReceipt, error) {
	stub.mu.Lock()
	stub.attempts++
	stub.shipments = append(stub.shipments, recipients)
	stub.inflight++
	if stub.inflight > stub.peak {
		stub.peak = stub.inflight
	}
	err, receipt := stub.err, stub.receipt
	stub.mu.Unlock()
	// Hold long enough that concurrent attempts overlap, so the fan-out bound
	// is measured rather than assumed.
	select {
	case <-time.After(5 * time.Millisecond):
	case <-ctx.Done():
	}
	stub.mu.Lock()
	stub.inflight--
	stub.mu.Unlock()
	return receipt, err
}

func (stub *stubPeerMailSender) peakInflight() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.peak
}

func peerEntry(t *testing.T, attempts int) PeerMailEntry {
	t.Helper()
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	return PeerMailEntry{MessageID: messageID, Address: PeerAddress{Agent: "reviewer", Host: "mini"},
		State: PeerDeliveryQueued, Attempts: attempts, QueuedAt: time.Now()}
}

func newDispatcher(t *testing.T, store PeerMailStore, sender PeerMailSender) *PeerMailDispatcher {
	t.Helper()
	dispatcher, err := NewPeerMailDispatcher(PeerMailDispatcherDependencies{Store: store, Sender: sender})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

// TestDispatcherReportsTheThreeStatesApart is the property a sender depends on:
// delivered, queued and undeliverable have to be distinguishable, because they
// call for three different responses.
func TestDispatcherReportsTheThreeStatesApart(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		err   error
		entry PeerMailEntry
		want  PeerDeliveryState
	}{
		{"accepted", nil, peerEntry(t, 0), PeerDeliveryDelivered},
		{"refused", fmt.Errorf("%w: no such agent", ErrPeerMailRefused), peerEntry(t, 0), PeerDeliveryUndeliverable},
		{"unreachable", fmt.Errorf("%w: down", ErrPeerMailUnreachable), peerEntry(t, 0), PeerDeliveryQueued},
		{"exhausted", fmt.Errorf("%w: still down", ErrPeerMailUnreachable),
			peerEntry(t, MaxPeerMailAttempts-1), PeerDeliveryUndeliverable},
	}
	for _, testCase := range cases {
		store := &stubPeerMailStore{}
		sender := &stubPeerMailSender{err: testCase.err, receipt: PeerMailReceipt{RemoteMessageID: "peer-id"}}
		dispatcher := newDispatcher(t, store, sender)
		results := dispatcher.Deliver(context.Background(), []PeerMailEntry{testCase.entry})
		if len(results) != 1 || results[0].State != testCase.want {
			t.Fatalf("%s: results=%+v, want state %s", testCase.name, results, testCase.want)
		}
		outcomes := store.settled()
		if len(outcomes) != 1 || outcomes[0].State != testCase.want {
			t.Fatalf("%s: settled=%+v, want state %s", testCase.name, outcomes, testCase.want)
		}
		switch testCase.want {
		case PeerDeliveryDelivered:
			if outcomes[0].RemoteMessageID != "peer-id" || results[0].Detail != "" {
				t.Fatalf("%s: a delivered attempt must carry the receipt and no failure: %+v",
					testCase.name, outcomes[0])
			}
		case PeerDeliveryQueued:
			if outcomes[0].NextAttemptAt.IsZero() {
				t.Fatalf("%s: a requeued entry must name when to try again", testCase.name)
			}
			if outcomes[0].RemoteMessageID != "" {
				t.Fatalf("%s: a failed attempt named a receipt", testCase.name)
			}
		case PeerDeliveryUndeliverable:
			if !outcomes[0].NextAttemptAt.IsZero() {
				t.Fatalf("%s: a terminal entry kept a next attempt", testCase.name)
			}
			if results[0].Detail == "" {
				t.Fatalf("%s: an undeliverable result must say why", testCase.name)
			}
		}
	}
}

// TestDispatcherSettlesEveryAttempt is what keeps a failed attempt from
// repeating forever: no branch may leave an entry unsettled.
func TestDispatcherSettlesEveryAttempt(t *testing.T) {
	t.Parallel()
	store := &stubPeerMailStore{}
	sender := &stubPeerMailSender{}
	dispatcher := newDispatcher(t, store, sender)
	entries := []PeerMailEntry{peerEntry(t, 0), peerEntry(t, 0), peerEntry(t, 0)}
	// An already-terminal entry is skipped rather than re-attempted.
	terminal := peerEntry(t, 1)
	terminal.State = PeerDeliveryDelivered
	entries = append(entries, terminal)

	results := dispatcher.Deliver(context.Background(), entries)
	if len(results) != 4 {
		t.Fatalf("results=%d, want one per entry", len(results))
	}
	if got := len(store.settled()); got != 3 {
		t.Fatalf("settled=%d, want one per deliverable entry", got)
	}
	if results[3].State != PeerDeliveryDelivered {
		t.Fatalf("a terminal entry was re-attempted: %+v", results[3])
	}
}

// TestDispatcherBoundsItsFanOut proves the concurrency ceiling is real. A fleet
// of twenty peers must not open twenty connections here and twenty request
// slots there.
func TestDispatcherBoundsItsFanOut(t *testing.T) {
	t.Parallel()
	store := &stubPeerMailStore{}
	sender := &stubPeerMailSender{}
	dispatcher, err := NewPeerMailDispatcher(PeerMailDispatcherDependencies{
		Store: store, Sender: sender, FanOut: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]PeerMailEntry, 0, 12)
	for range 12 {
		entries = append(entries, peerEntry(t, 0))
	}
	dispatcher.Deliver(context.Background(), entries)
	if peak := sender.peakInflight(); peak > 2 {
		t.Fatalf("peak concurrent attempts=%d, want at most the fan-out of 2", peak)
	}
}

// TestDispatchOnceCountsAFailedClaimRatherThanReturningIt keeps a drain failure
// from ever reaching a coordination write.
func TestDispatchOnceCountsAFailedClaimRatherThanReturningIt(t *testing.T) {
	t.Parallel()
	store := &stubPeerMailStore{claimErr: errors.New("database is busy")}
	dispatcher := newDispatcher(t, store, &stubPeerMailSender{})
	if results := dispatcher.DispatchOnce(context.Background()); results != nil {
		t.Fatalf("results=%+v, want nothing from a failed claim", results)
	}
	if stats := dispatcher.PeerMailStats(); stats.ClaimFailures != 1 || stats.Drains != 1 {
		t.Fatalf("stats=%+v, want the failure counted", stats)
	}
}

// TestDispatcherCountsASettleFailure is the counter that says a delivery may
// have happened twice on the far side, which the receiving host's idempotency
// key exists to absorb.
func TestDispatcherCountsASettleFailure(t *testing.T) {
	t.Parallel()
	store := &stubPeerMailStore{settleErr: errors.New("disk is full")}
	dispatcher := newDispatcher(t, store, &stubPeerMailSender{})
	dispatcher.Deliver(context.Background(), []PeerMailEntry{peerEntry(t, 0)})
	if stats := dispatcher.PeerMailStats(); stats.SettleFailures != 1 || stats.Delivered != 1 {
		t.Fatalf("stats=%+v, want one delivered attempt whose outcome was not recorded", stats)
	}
}

func TestDispatcherStartsAndStopsOnce(t *testing.T) {
	t.Parallel()
	store := &stubPeerMailStore{}
	dispatcher, err := NewPeerMailDispatcher(PeerMailDispatcherDependencies{
		Store: store, Sender: &stubPeerMailSender{}, Interval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := dispatcher.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Start(ctx); err == nil {
		t.Fatal("a second start must be refused rather than run two drains")
	}
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := dispatcher.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	// Stopping twice is not an error: shutdown paths call it unconditionally.
	if err := dispatcher.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
}

func TestNewPeerMailDispatcherRequiresBothPorts(t *testing.T) {
	t.Parallel()
	if _, err := NewPeerMailDispatcher(PeerMailDispatcherDependencies{Sender: &stubPeerMailSender{}}); err == nil {
		t.Fatal("a dispatcher without a store must be a composition error")
	}
	if _, err := NewPeerMailDispatcher(PeerMailDispatcherDependencies{Store: &stubPeerMailStore{}}); err == nil {
		t.Fatal("a dispatcher without a sender would report queued forever while looking composed")
	}
	if _, err := NewPeerMailDispatcher(PeerMailDispatcherDependencies{
		Store: &stubPeerMailStore{}, Sender: &stubPeerMailSender{}, FanOut: -1,
	}); err == nil {
		t.Fatal("a negative bound must be a composition error rather than unbounded")
	}
}

func TestSendPeerMailParamsValidateBoundsTheRemoteRecipients(t *testing.T) {
	t.Parallel()
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	conversationID, err := domain.NewConversationID()
	if err != nil {
		t.Fatal(err)
	}
	base := SendPeerMailParams{MessageID: messageID, ConversationID: conversationID,
		Subject: "s", Body: "b", PeerRecipients: []PeerAddress{{Agent: "reviewer", Host: "mini"}}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	duplicated := base
	duplicated.PeerRecipients = []PeerAddress{{Agent: "reviewer", Host: "mini"}, {Agent: "reviewer", Host: "MINI"}}
	if err := duplicated.Validate(); err == nil {
		t.Fatal("two spellings of one recipient must be refused rather than delivered twice")
	}
	tooMany := base
	tooMany.PeerRecipients = make([]PeerAddress, MaxPeerRecipients+1)
	for index := range tooMany.PeerRecipients {
		tooMany.PeerRecipients[index] = PeerAddress{Agent: fmt.Sprintf("a%d", index), Host: "mini"}
	}
	if err := tooMany.Validate(); err == nil {
		t.Fatal("the remote recipient count must be bounded")
	}
	none := base
	none.PeerRecipients = nil
	if err := none.Validate(); err == nil {
		t.Fatal("a cross-host send with no remote recipient is not one")
	}
}

func TestAcceptPeerMailParamsValidateBoundsEverythingAPeerControls(t *testing.T) {
	t.Parallel()
	base := AcceptPeerMailParams{OriginHost: "mini", ProjectKey: "/repo", ThreadKey: "k",
		FromAgent: "implementer", ToAgents: []string{"reviewer"}, Subject: "s", Body: "b",
		OriginMessageID: "origin"}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AcceptPeerMailParams){
		"no origin host":      func(p *AcceptPeerMailParams) { p.OriginHost = "" },
		"no project":          func(p *AcceptPeerMailParams) { p.ProjectKey = "" },
		"no thread key":       func(p *AcceptPeerMailParams) { p.ThreadKey = "" },
		"qualified sender":    func(p *AcceptPeerMailParams) { p.FromAgent = "implementer@elsewhere" },
		"qualified recipient": func(p *AcceptPeerMailParams) { p.ToAgents = []string{"reviewer@elsewhere"} },
		"no recipients":       func(p *AcceptPeerMailParams) { p.ToAgents = nil },
		"duplicate recipient": func(p *AcceptPeerMailParams) { p.ToAgents = []string{"reviewer", "reviewer"} },
		"empty body":          func(p *AcceptPeerMailParams) { p.Body = "" },
		"no origin id":        func(p *AcceptPeerMailParams) { p.OriginMessageID = "" },
	} {
		params := base
		mutate(&params)
		if err := params.Validate(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestPeerDeliveryStateValidRejectsAnythingElse(t *testing.T) {
	t.Parallel()
	for _, state := range []PeerDeliveryState{PeerDeliveryQueued, PeerDeliveryDelivered, PeerDeliveryUndeliverable} {
		if !state.Valid() {
			t.Fatalf("%q is one of this package's own states", state)
		}
	}
	for _, state := range []PeerDeliveryState{"", "sent", "pending", "QUEUED"} {
		if state.Valid() {
			t.Fatalf("%q was accepted as a delivery state", state)
		}
	}
}

// TestDispatcherSendsOneRequestPerHostPerMessage is the defect this grouping
// exists to prevent. The receiving host keys idempotency on the SENDING host's
// message id, so two separate requests carrying one message id would make the
// second recipient's copy look like a retry of the first -- and that host would
// correctly refuse to append it twice, silently dropping a recipient.
func TestDispatcherSendsOneRequestPerHostPerMessage(t *testing.T) {
	t.Parallel()
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	entries := []PeerMailEntry{
		{MessageID: messageID, Address: PeerAddress{Agent: "reviewer", Host: "mini"},
			State: PeerDeliveryQueued, QueuedAt: time.Now()},
		{MessageID: messageID, Address: PeerAddress{Agent: "builder", Host: "mini"},
			State: PeerDeliveryQueued, QueuedAt: time.Now()},
		// A different host is a different request, and so is a different
		// message to the same host.
		{MessageID: messageID, Address: PeerAddress{Agent: "reviewer", Host: "laptop"},
			State: PeerDeliveryQueued, QueuedAt: time.Now()},
	}
	store := &stubPeerMailStore{}
	sender := &stubPeerMailSender{receipt: PeerMailReceipt{RemoteMessageID: "peer-id"}}
	dispatcher := newDispatcher(t, store, sender)

	results := dispatcher.Deliver(context.Background(), entries)
	if len(results) != 3 {
		t.Fatalf("results=%d, want one per entry", len(results))
	}
	for index, result := range results {
		if result.State != PeerDeliveryDelivered {
			t.Fatalf("result %d = %+v, want every recipient delivered", index, result)
		}
	}
	// Two shipments: both agents on the mini together, the laptop on its own.
	if len(sender.shipments) != 2 {
		t.Fatalf("shipments=%v, want one request per host", sender.shipments)
	}
	sizes := map[int]int{}
	for _, shipment := range sender.shipments {
		sizes[len(shipment)]++
	}
	if sizes[2] != 1 || sizes[1] != 1 {
		t.Fatalf("shipments=%v, want one carrying two recipients and one carrying one", sender.shipments)
	}
	// Every entry is still settled individually, because each is its own row.
	if settled := store.settled(); len(settled) != 3 {
		t.Fatalf("settled=%d, want one outcome per entry", len(settled))
	}
}
