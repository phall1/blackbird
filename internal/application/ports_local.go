package application

import "github.com/phall1/blackbird/internal/domain"

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
// stops there; blackbird_inbox_fetch and blackbird_thread_fetch carry the rest.
const MaxLocalAgentSnapshotItems = 5

// LocalAgentReservation is one lease the registering agent still holds. It
// carries the lease's fences because a resuming agent that cannot renew or
// release without them can only wait out the TTL, which is the failure the
// snapshot exists to prevent. ExpiresInMS is signed and goes negative once a
// lease is overdue, matching AdminReservation.
type LocalAgentReservation struct {
	LeaseID     domain.LeaseID
	Mode        LeaseMode
	Selectors   []LeaseSelector
	Fences      []Fence
	ExpiresInMS int64
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
