package coordination

import (
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// LocalAgentSnapshot is the state already bound to an agent at the moment it
// registers. Registration rebinds the agent's still-active leases to the new
// session and, without this, says nothing about them: a compacted or restarted
// agent walks away holding an exclusive reservation it has forgotten, and that
// reservation blocks every other agent for the rest of its TTL. The unread
// inbox, the agent's open conversations and the rest of the roster are known in
// the same breath and are equally unrecoverable from the agent's own memory.
//
// Every field follows the admin read models' contract on time: durations are
// computed against the store's own clock inside one snapshot, and instants are
// microseconds since the Unix epoch measured against ObservedAtUS, so a caller
// never compares a stored instant against a clock the daemon does not control.
type LocalAgentSnapshot struct {
	// Reservations is complete rather than paged. Truncating it would hide
	// exactly the abandoned lease this projection exists to surface, and an
	// agent holds a handful of leases, not a page of them.
	Reservations  []LocalAgentReservation
	Inbox         LocalAgentInbox
	Conversations []LocalAgentConversation
	Peers         []ActiveAgent
	ObservedAtUS  int64
}

// MaxLocalAgentSnapshotItems bounds the lists whose full contents an agent can
// fetch for itself. This projection is spent from every client's context window
// on every registration, so it carries enough to know something is waiting and
// stops there; blackbird_read and blackbird_status carry the rest.
const MaxLocalAgentSnapshotItems = 5

// LocalAgentReservation is one lease the registering agent still holds.
// ClaimGenerations are informational counters; renew and release are addressed
// by the exact selector set. ExpiresInMS is signed and may go negative.
type LocalAgentReservation struct {
	LeaseID          domain.LeaseID
	Mode             LeaseMode
	Selectors        []LeaseSelector
	ClaimGenerations map[string]uint64
	ExpiresInMS      int64
}

// LocalAgentInbox summarizes the whole mailbox with counts and shows only the
// most recent pending deliveries, so the counts stay true no matter how many
// items are listed.
type LocalAgentInbox struct {
	UnreadDeliveries  int
	UnackedDeliveries int
	Recent            []LocalAgentInboxItem
}

// LocalAgentInboxItem is one pending delivery attributed to this agent. Message
// bodies are never projected here; the inbox tool serves them.
type LocalAgentInboxItem struct {
	MessageID               domain.MessageID
	ConversationID          domain.ConversationID
	AuthorAgentName         string
	Subject                 string
	Read                    bool
	AcknowledgementRequired bool
	Acknowledged            bool
	SentAtUS                int64
}

// LocalAgentConversation is one open conversation this agent takes part in --
// opened by it, written to by it, or addressed to it. A conversation it has
// never touched is not part of its resumable state.
type LocalAgentConversation struct {
	ConversationID  domain.ConversationID
	Topic           string
	Messages        int
	LastMessageAtUS int64
}

// WaitReason names which of the three things a bounded wait was
// waiting on actually happened. It is returned rather than inferred, because a
// caller that has to compare timestamps to tell "the path came free" from "the
// deadline passed" gets it wrong the moment the two coincide.
type WaitReason string

const (
	// WaitPathFree means no lease conflicting with the requested
	// path and mode is active any more, so an acquisition is worth retrying.
	WaitPathFree WaitReason = "path_free"
	// WaitMailArrived means a delivery addressed to the caller was
	// created after the wait began.
	WaitMailArrived WaitReason = "mail_arrived"
	// WaitDeadline means neither happened before the budget ran
	// out. It is an ordinary outcome, not an error: the caller should decide
	// again rather than be handed a failure it cannot act on.
	WaitDeadline WaitReason = "deadline"
)

const (
	// MaxWait is the ceiling the store imposes on every wait,
	// whatever the caller asks for. A wait is a transport-level hold on an
	// agent's turn, and an unbounded one turns a coordination failure into a
	// hang no client can distinguish from a dead daemon.
	MaxWait = 60 * time.Second
	// WaitPoll is how often a wait re-reads the condition. A wait
	// must not hold a transaction or a pooled connection open across it -- the
	// read pool is a handful of connections for the whole daemon -- so each
	// poll is its own short read snapshot and the connection goes back between
	// them. The interval is the trade between how promptly a released lease is
	// noticed and how many snapshots a parked agent costs; a quarter second
	// bounds notification lag well under a human's reaction time at four cheap
	// reads per second per waiter.
	WaitPoll = 250 * time.Millisecond
)

// WaitRequest is a bounded server-side long poll. MCP gives a model
// no channel it observes between tool calls, so an agent refused a lease can
// otherwise only spin or give up, and giving up is what leaves work undone.
//
// Path and AwaitMail are independent and either may be omitted; a request that
// asks for neither is invalid, because it can only ever return the deadline.
type WaitRequest struct {
	// Path is the path the caller intends to reserve. The wait ends when no
	// active lease conflicts with taking Mode over it, matched on separator
	// boundaries exactly as AdminReservationsQuery.Path is.
	Path string
	// Mode is the lease the caller intends to take, so a shared reader is not
	// held behind another shared reader. Empty means exclusive, the strictest
	// reading and the one that cannot report a path free too early.
	Mode LeaseMode
	// AwaitMail ends the wait when a delivery addressed to the caller appears.
	AwaitMail bool
	// Timeout is clamped to MaxWait; zero asks for the ceiling.
	Timeout time.Duration
}

// WaitResult reports what ended the wait and the evidence for it.
// Blockers carries whatever still conflicts when the reason is the deadline, so
// a caller that gave up knows who to talk to instead of having to ask again.
type WaitResult struct {
	Reason WaitReason
	// Blockers are the reservations conflicting with Path at the moment the
	// wait ended, in the same view type the admin surface uses, so ExpiresInMS
	// is server-computed and the caller never consults its own clock.
	Blockers []AdminReservation
	// PendingDeliveries is the caller's unread delivery count at that moment,
	// which is what makes a mail wakeup actionable without a second call.
	PendingDeliveries int
	WaitedMS          int64
	ObservedAtUS      int64
}
