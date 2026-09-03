package coordination

import (
	"context"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// LocalAgentActiveWindow is the liveness horizon for a local agent session.
// Every roster projection, MCP or admin, must agree on it.
const LocalAgentActiveWindow = 5 * time.Minute

// LocalAgentHeartbeatInterval is how far behind the truth a session's durable
// last_seen_at_us is allowed to fall. Authentication is the first statement of
// every tool call, so writing the heartbeat on each one made every read pay a
// durable commit and a turn of the daemon-wide write lock; the store therefore
// coalesces it and flushes at most this often per session.
//
// The value is a tenth of LocalAgentActiveWindow, which is what makes the
// coalescing invisible to every projection that consults it: a session can only
// ever be reported staler than it really is, never fresher, and only by a
// tenth of the horizon that decides the answer. That direction is the one that
// matters for a crash, too. The in-memory flush record is lost with the
// process, so a daemon that dies leaves a durable timestamp at most one
// interval old and the next authentication writes a fresh one -- nothing can
// make a dead session look alive, because nothing writes a heartbeat except a
// call that just succeeded.
const LocalAgentHeartbeatInterval = LocalAgentActiveWindow / 10

// AdminDefaultPageSize is the page size applied when a query leaves Limit at
// its zero value. Callers that reject an explicitly supplied zero do so at
// their own edge; the store treats unset as "default".
const AdminDefaultPageSize = 50

// Admin read models carry timestamps as microseconds since the Unix epoch,
// matching the *_at_us columns they are projected from. Every such column is
// CHECK (... > 0), so a zero field means "absent" and never a real instant.
// Each read model also carries ObservedAtUS, the durable store's own clock at
// the moment of the snapshot, so callers render relative times against one
// origin instead of against their own clock.
func MicrosFromTime(instant time.Time) int64 {
	if instant.IsZero() {
		return 0
	}
	return instant.UnixMicro()
}

func TimeFromMicros(micros int64) time.Time {
	if micros == 0 {
		return time.Time{}
	}
	return time.UnixMicro(micros).UTC()
}

// AdminPageLimit resolves a query limit against the shared bounds: unset means
// AdminDefaultPageSize, anything above MaxQueryPageSize is invalid.
func AdminPageLimit(limit uint16) (uint16, error) {
	switch {
	case limit == 0:
		return AdminDefaultPageSize, nil
	case limit > MaxQueryPageSize:
		return 0, ErrInvalid
	default:
		return limit, nil
	}
}

// AdminIdentity is the daemon's self-description. Build and process fields come
// from the composition root; StorageBackend, DatabasePath, SchemaVersion and
// ObservedAtUS come from AdminStorageIdentity.
type AdminIdentity struct {
	Version        string
	Commit         string
	BuiltAt        string
	PID            int
	StartedAtUS    int64
	UptimeMS       int64
	HTTPAddress    string
	MCPAddress     string
	StorageBackend string
	DatabasePath   string
	SchemaVersion  int
	ObservedAtUS   int64
}

type AdminStorageIdentity struct {
	StorageBackend string
	DatabasePath   string
	SchemaVersion  int
	ObservedAtUS   int64
}

type AdminOverview struct {
	Projects            int
	Agents              int
	ActiveAgents        int
	Conversations       int
	Messages            int
	Deliveries          int
	UnreadDeliveries    int
	UnackedDeliveries   int
	ActiveReservations  int
	ExpiredReservations int
	CoordinationEvents  int
	ObservedAtUS        int64
}

type AdminProject struct {
	ProjectKey    string
	WorkspaceID   domain.WorkspaceID
	RunID         domain.RunID
	Agents        int
	ActiveAgents  int
	Conversations int
	CreatedAtUS   int64
	LastEventAtUS int64
}

type AdminProjectsPage struct {
	Projects     []AdminProject
	ObservedAtUS int64
}

// Every predicate on an admin query is a WHERE clause the store applies before
// LIMIT. A caller that filters the returned page instead renders a silently
// wrong result whenever the head of the unfiltered result set is the wrong
// state: the page comes back empty while matching rows sit behind the limit.
type AdminAgentsQuery struct {
	ProjectKey string
	AgentName  string
	ActiveOnly bool
	Limit      uint16
}

// AdminAgent includes agents that have never opened a session, so a caller can
// render an offline agent. SessionID is zero when no session is open.
type AdminAgent struct {
	ProjectKey        string
	AgentName         string
	ActorID           domain.ActorID
	SessionID         domain.ActorSessionID
	Active            bool
	CreatedAtUS       int64
	StartedAtUS       int64
	LastSeenAtUS      int64
	UnreadDeliveries  int
	UnackedDeliveries int
	ActiveLeases      int
}

type AdminAgentsPage struct {
	Agents       []AdminAgent
	Truncated    bool
	ObservedAtUS int64
}

// AdminReservationState is the derived lifecycle of a lease. The leases table
// stores only 'active' and 'released'; expiry is derived by comparing
// expires_at_us against the store's own clock.
type AdminReservationState string

const (
	AdminReservationAll      AdminReservationState = "all"
	AdminReservationActive   AdminReservationState = "active"
	AdminReservationExpired  AdminReservationState = "expired"
	AdminReservationReleased AdminReservationState = "released"
)

// Normalized maps the zero value to AdminReservationAll so a keyed struct
// literal that omits State selects everything instead of failing validation.
func (state AdminReservationState) Normalized() AdminReservationState {
	if state == "" {
		return AdminReservationAll
	}
	return state
}

func (state AdminReservationState) Valid() bool {
	switch state.Normalized() {
	case AdminReservationAll, AdminReservationActive, AdminReservationExpired, AdminReservationReleased:
		return true
	default:
		return false
	}
}

// AdminReservationModeAny is the wire and CLI spelling of "no mode predicate".
// The query itself carries the zero LeaseMode for it, so every edge agrees on
// one word without widening LeaseMode with a value no lease can hold.
const AdminReservationModeAny = "any"

func ValidAdminReservationMode(mode LeaseMode) bool {
	switch mode {
	case "", LeaseShared, LeaseExclusive:
		return true
	default:
		return false
	}
}

// Path selects reservations whose selectors cover it, matched on separator
// boundaries in both directions: "a/f" covers "a/f" and "a/f/g" but never
// "a/foo". Plain prefix matching would report a lease on a sibling path as a
// conflict, which is the one answer a reservation query must never give.
type AdminReservationsQuery struct {
	ProjectKey string
	AgentName  string
	State      AdminReservationState
	Mode       LeaseMode
	Path       string
	Limit      uint16
}

// AdminReservation is one lease row. Expired and ExpiresInMS are derived
// against the page's ObservedAtUS; ExpiresInMS is signed and goes negative once
// a lease is overdue, so callers never consult their own clock.
type AdminReservation struct {
	LeaseID          domain.LeaseID
	ProjectKey       string
	WorkspaceID      domain.WorkspaceID
	HolderAgentName  string
	HolderActorID    domain.ActorID
	HolderSessionID  domain.ActorSessionID
	Mode             LeaseMode
	State            AdminReservationState
	Expired          bool
	Selectors        []LeaseSelector
	ClaimGenerations map[string]uint64
	AcquiredAtUS     int64
	ExpiresAtUS      int64
	ReleasedAtUS     int64
	ExpiresInMS      int64
}

type AdminReservationsPage struct {
	Reservations []AdminReservation
	Truncated    bool
	ObservedAtUS int64
}

// UnreadOnly and UnackedOnly conjoin: both set selects deliveries that are
// unread and still awaiting an acknowledgement they require. Summaries are
// unaffected, so the per-agent counters keep describing the whole mailbox.
type AdminInboxQuery struct {
	ProjectKey  string
	AgentName   string
	UnreadOnly  bool
	UnackedOnly bool
	Limit       uint16
}

type AdminInboxSummary struct {
	ProjectKey        string
	AgentName         string
	ActorID           domain.ActorID
	UnreadDeliveries  int
	UnackedDeliveries int
	OldestUnreadAtUS  int64
}

// AdminInboxItem is one (message, recipient) delivery attributed to that
// recipient, which is what keeps a blind copy out of every other agent's view.
// Message bodies are never projected.
type AdminInboxItem struct {
	MessageID               domain.MessageID
	ConversationID          domain.ConversationID
	ProjectKey              string
	RecipientAgentName      string
	RecipientActorID        domain.ActorID
	AuthorAgentName         string
	AuthorActorID           domain.ActorID
	Subject                 string
	Kind                    RecipientKind
	Read                    bool
	Acknowledged            bool
	AcknowledgementRequired bool
	SentAtUS                int64
}

type AdminInboxPage struct {
	ProjectKey   string
	Summaries    []AdminInboxSummary
	Pending      []AdminInboxItem
	Truncated    bool
	ObservedAtUS int64
}

type AdminConversationStatus string

const (
	AdminConversationOpen   AdminConversationStatus = "open"
	AdminConversationClosed AdminConversationStatus = "closed"
)

type AdminConversationsQuery struct {
	ProjectKey     string
	ConversationID domain.ConversationID
	OpenOnly       bool
	Limit          uint16
}

type AdminConversation struct {
	ConversationID     domain.ConversationID
	WorkspaceID        domain.WorkspaceID
	ProjectKey         string
	Topic              string
	Status             AdminConversationStatus
	OpenedByAgentName  string
	OpenedByActorID    domain.ActorID
	Messages           int
	Participants       int
	UnreadDeliveries   int
	OpenedAtUS         int64
	LastMessageAtUS    int64
	LastMessageAuthor  string
	LastMessageSubject string
}

type AdminConversationsPage struct {
	Conversations []AdminConversation
	Truncated     bool
	ObservedAtUS  int64
}

type AdminEventsQuery struct {
	ProjectKey string
	AgentName  string
	EventType  EventType
	Limit      uint16
}

// AdminEvent is one row of the coordination journal exactly as stored. The
// journal records one row per (workspace, actor), so a message to three
// recipients appears three times; collapsing them would misreport the journal.
type AdminEvent struct {
	Position     uint64
	ProjectKey   string
	WorkspaceID  domain.WorkspaceID
	AgentName    string
	ActorID      domain.ActorID
	EventType    EventType
	SubjectID    string
	Payload      []byte
	OccurredAtUS int64
}

type AdminEventsPage struct {
	Events       []AdminEvent
	Truncated    bool
	ObservedAtUS int64
}

// ReadinessProbe answers whether durable storage is reachable right now and
// reports the live schema version. Implementations must execute a real query
// per call and must never answer from a cached result.
type ReadinessProbe interface {
	CheckReadiness(context.Context) (int, error)
}

// LocalAdminStore is the cross-agent projection behind the loopback admin
// surface. Reads are point-in-time snapshots against the durable store's own
// clock. ForceReleaseAdminReservation is the one mutation: an authenticated
// operator escape hatch for a lease whose holder is gone. An empty ProjectKey
// means "every project" and an empty AgentName means "every agent".
type LocalAdminStore interface {
	ReadinessProbe
	AdminStorageIdentity(context.Context) (AdminStorageIdentity, error)
	AdminOverview(context.Context) (AdminOverview, error)
	ListAdminProjects(context.Context) (AdminProjectsPage, error)
	ListAdminAgents(context.Context, AdminAgentsQuery) (AdminAgentsPage, error)
	AdminInbox(context.Context, AdminInboxQuery) (AdminInboxPage, error)
	ListAdminConversations(context.Context, AdminConversationsQuery) (AdminConversationsPage, error)
	ListAdminReservations(context.Context, AdminReservationsQuery) (AdminReservationsPage, error)
	ForceReleaseAdminReservation(context.Context, domain.LeaseID) (Lease, error)
	ListAdminEvents(context.Context, AdminEventsQuery) (AdminEventsPage, error)
}
