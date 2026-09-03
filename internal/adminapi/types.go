// Package adminapi defines the authenticated local-admin JSON contract shared
// by the HTTP adapter and CLI client.
package adminapi

import "encoding/json"

type RuntimeMetrics struct {
	Requests       map[string]map[string]int64 `json:"requests"`
	LeaseConflicts int64                       `json:"lease_conflicts"`
	SSEConnections int64                       `json:"sse_connections"`
	DatabaseBytes  int64                       `json:"database_bytes"`
	WALBytes       int64                       `json:"wal_bytes"`
}

type Identity struct {
	Version        string         `json:"version"`
	Commit         string         `json:"commit"`
	BuiltAt        string         `json:"built_at"`
	PID            int            `json:"pid"`
	StartedAt      string         `json:"started_at"`
	UptimeMS       int64          `json:"uptime_ms"`
	HTTPAddress    string         `json:"http_address"`
	MCPAddress     string         `json:"mcp_address"`
	StorageBackend string         `json:"storage_backend"`
	DatabasePath   string         `json:"database_path"`
	SchemaVersion  int            `json:"schema_version"`
	ObservedAt     string         `json:"observed_at"`
	Metrics        RuntimeMetrics `json:"metrics"`
}

type Overview struct {
	Projects            int    `json:"projects"`
	Agents              int    `json:"agents"`
	ActiveAgents        int    `json:"active_agents"`
	Conversations       int    `json:"conversations"`
	Messages            int    `json:"messages"`
	Deliveries          int    `json:"deliveries"`
	UnreadDeliveries    int    `json:"unread_deliveries"`
	UnackedDeliveries   int    `json:"unacked_deliveries"`
	ActiveReservations  int    `json:"active_reservations"`
	ExpiredReservations int    `json:"expired_reservations"`
	CoordinationEvents  int    `json:"coordination_events"`
	ObservedAt          string `json:"observed_at"`
}

type Project struct {
	ProjectKey    string `json:"project_key"`
	WorkspaceID   string `json:"workspace_id"`
	RunID         string `json:"run_id,omitempty"`
	Agents        int    `json:"agents"`
	ActiveAgents  int    `json:"active_agents"`
	Conversations int    `json:"conversations"`
	CreatedAt     string `json:"created_at"`
	LastEventAt   string `json:"last_event_at,omitempty"`
}

type ProjectsPage struct {
	Projects   []Project `json:"projects"`
	ObservedAt string    `json:"observed_at"`
}

type Agent struct {
	ProjectKey        string `json:"project_key"`
	AgentName         string `json:"agent_name"`
	ActorID           string `json:"actor_id"`
	SessionID         string `json:"session_id,omitempty"`
	Active            bool   `json:"active"`
	CreatedAt         string `json:"created_at"`
	StartedAt         string `json:"started_at,omitempty"`
	LastSeenAt        string `json:"last_seen_at,omitempty"`
	UnreadDeliveries  int    `json:"unread_deliveries"`
	UnackedDeliveries int    `json:"unacked_deliveries"`
	ActiveLeases      int    `json:"active_leases"`
}

type AgentsPage struct {
	Agents     []Agent `json:"agents"`
	Truncated  bool    `json:"truncated"`
	ObservedAt string  `json:"observed_at"`
}

type InboxSummary struct {
	ProjectKey        string `json:"project_key"`
	AgentName         string `json:"agent_name"`
	ActorID           string `json:"actor_id"`
	UnreadDeliveries  int    `json:"unread_deliveries"`
	UnackedDeliveries int    `json:"unacked_deliveries"`
	OldestUnreadAt    string `json:"oldest_unread_at,omitempty"`
}

type InboxItem struct {
	MessageID          string `json:"message_id"`
	ConversationID     string `json:"conversation_id"`
	ProjectKey         string `json:"project_key"`
	RecipientAgentName string `json:"recipient_agent_name"`
	RecipientActorID   string `json:"recipient_actor_id"`
	AuthorAgentName    string `json:"author_agent_name,omitempty"`
	AuthorActorID      string `json:"author_actor_id"`
	Subject            string `json:"subject"`
	Kind               string `json:"kind"`
	Read               bool   `json:"read"`
	Acknowledged       bool   `json:"acknowledged"`
	AckRequired        bool   `json:"acknowledgement_required"`
	SentAt             string `json:"sent_at"`
}

type InboxPage struct {
	ProjectKey string         `json:"project_key"`
	Summaries  []InboxSummary `json:"summaries"`
	Pending    []InboxItem    `json:"pending"`
	Truncated  bool           `json:"truncated"`
	ObservedAt string         `json:"observed_at"`
}

type Conversation struct {
	ConversationID     string `json:"conversation_id"`
	WorkspaceID        string `json:"workspace_id"`
	ProjectKey         string `json:"project_key"`
	Topic              string `json:"topic"`
	Status             string `json:"status"`
	OpenedByAgentName  string `json:"opened_by_agent_name,omitempty"`
	OpenedByActorID    string `json:"opened_by_actor_id"`
	Messages           int    `json:"messages"`
	Participants       int    `json:"participants"`
	UnreadDeliveries   int    `json:"unread_deliveries"`
	OpenedAt           string `json:"opened_at"`
	LastMessageAt      string `json:"last_message_at,omitempty"`
	LastMessageAuthor  string `json:"last_message_author,omitempty"`
	LastMessageSubject string `json:"last_message_subject,omitempty"`
}

type ConversationsPage struct {
	Conversations []Conversation `json:"conversations"`
	Truncated     bool           `json:"truncated"`
	ObservedAt    string         `json:"observed_at"`
}

type Selector struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type Reservation struct {
	LeaseID         string     `json:"lease_id"`
	ProjectKey      string     `json:"project_key"`
	WorkspaceID     string     `json:"workspace_id"`
	HolderAgentName string     `json:"holder_agent_name,omitempty"`
	HolderActorID   string     `json:"holder_actor_id"`
	HolderSessionID string     `json:"holder_session_id,omitempty"`
	Mode            string     `json:"mode"`
	State           string     `json:"state"`
	Expired         bool       `json:"expired"`
	Selectors       []Selector `json:"selectors"`
	AcquiredAt      string     `json:"acquired_at"`
	ExpiresAt       string     `json:"expires_at"`
	ReleasedAt      string     `json:"released_at,omitempty"`
	ExpiresInMS     int64      `json:"expires_in_ms"`
}

type ReservationsPage struct {
	Reservations []Reservation `json:"reservations"`
	Truncated    bool          `json:"truncated"`
	ObservedAt   string        `json:"observed_at"`
}

type ReservationRelease struct {
	LeaseID    string `json:"lease_id"`
	ReleasedAt string `json:"released_at"`
	Forced     bool   `json:"forced"`
}

type Event struct {
	Position    uint64          `json:"position"`
	ProjectKey  string          `json:"project_key"`
	WorkspaceID string          `json:"workspace_id"`
	AgentName   string          `json:"agent_name,omitempty"`
	ActorID     string          `json:"actor_id"`
	Type        string          `json:"type"`
	Subject     string          `json:"subject"`
	Payload     json.RawMessage `json:"payload"`
	OccurredAt  string          `json:"occurred_at"`
}

type EventsPage struct {
	Events     []Event `json:"events"`
	Truncated  bool    `json:"truncated"`
	ObservedAt string  `json:"observed_at"`
}

// CostReport is the operator's answer to "what did coordination cost". It is a
// projection of the daemon's report, not a second computation of it: every
// figure here is carried across as the daemon measured it.
//
// The wire form keeps the discipline the report itself keeps. An unobserved
// section is ABSENT and named in Unobserved rather than rendered as zeros,
// because "nothing was contended" and "nothing was recorded" call for opposite
// responses. Recording is present only when the daemon lost contention facts,
// and while it is present every contention count is a floor.
type CostReport struct {
	ProjectKey  string           `json:"project_key"`
	Since       string           `json:"since"`
	Until       string           `json:"until"`
	Unobserved  []string         `json:"unobserved,omitempty"`
	Recording   *CostRecording   `json:"recording_incomplete,omitempty"`
	Contention  *CostContention  `json:"contention,omitempty"`
	Abandonment *CostAbandonment `json:"abandonment,omitempty"`
	Cache       *CostCache       `json:"cache,omitempty"`
}

type CostRecording struct {
	Dropped uint64 `json:"facts_dropped"`
	Written uint64 `json:"facts_written"`
}

type CostContention struct {
	Refusals            uint64             `json:"refusals"`
	PathWaits           uint64             `json:"path_waits"`
	MailWaits           uint64             `json:"mail_waits"`
	WaitsEndedFree      uint64             `json:"waits_ended_free"`
	WaitsEndedMail      uint64             `json:"waits_ended_mail"`
	WaitsEndedDeadline  uint64             `json:"waits_ended_deadline"`
	WaitsEndedAbandoned uint64             `json:"waits_ended_abandoned"`
	WaitsEndedStopped   uint64             `json:"waits_ended_stopped"`
	WaitsEndedUnknown   uint64             `json:"waits_ended_unknown"`
	ParkedMS            uint64             `json:"parked_ms"`
	LongestParkMS       uint64             `json:"longest_park_ms"`
	Agents              []CostBlockedAgent `json:"agents,omitempty"`
	Paths               []CostPath         `json:"contended_paths,omitempty"`
	Truncated           bool               `json:"truncated"`
}

// CostBlockedAgent puts one agent's contention beside one agent's spend. The
// two halves are CO-OCCURRING TOTALS over the same window and the same actor
// id; nothing here claims the tokens were spent because of the contention.
type CostBlockedAgent struct {
	AgentName          string `json:"agent_name,omitempty"`
	ActorID            string `json:"actor_id"`
	Refusals           uint64 `json:"refusals"`
	PathWaits          uint64 `json:"path_waits"`
	WaitsEndedDeadline uint64 `json:"waits_ended_deadline"`
	ParkedMS           uint64 `json:"parked_ms"`
	ModelCalls         uint64 `json:"model_calls"`
	BilledInput        uint64 `json:"billed_input_tokens"`
	Output             uint64 `json:"output_tokens"`
}

type CostPath struct {
	Path          string `json:"path"`
	Kind          string `json:"kind"`
	Refusals      uint64 `json:"refusals"`
	BlockedAgents uint64 `json:"blocked_agents"`
}

type CostAbandonment struct {
	Abandoned       uint64      `json:"abandoned"`
	Released        uint64      `json:"released"`
	AbandonedHeldMS uint64      `json:"abandoned_held_ms"`
	ReleasedHeldMS  uint64      `json:"released_held_ms"`
	RefusalsDuring  uint64      `json:"refusals_caused"`
	Leases          []CostLease `json:"leases,omitempty"`
	Truncated       bool        `json:"truncated"`
}

type CostLease struct {
	LeaseID       string `json:"lease_id"`
	HolderAgent   string `json:"holder_agent_name,omitempty"`
	Mode          string `json:"mode"`
	HeldMS        uint64 `json:"held_ms"`
	Refusals      uint64 `json:"refusals"`
	BlockedAgents uint64 `json:"blocked_agents"`
	ContendedPath string `json:"contended_path,omitempty"`
}

type CostCache struct {
	Models    []CostModel `json:"models"`
	Truncated bool        `json:"truncated"`
}

// CostModel keeps the three input classes apart on the wire for the same reason
// the schema keeps them in separate columns: they are billed at materially
// different rates, and a caller cannot recover the split from a sum.
//
// CacheReadShare and CacheReuse are omitted when their denominator is zero,
// which is why they are pointers. A model that wrote no cache has NO reuse
// ratio; rendering that as 0.0 would say caching is failing when the truth is
// it was never used.
type CostModel struct {
	Model          string   `json:"model"`
	Calls          uint64   `json:"calls"`
	UncachedInput  uint64   `json:"uncached_input_tokens"`
	CacheRead      uint64   `json:"cache_read_tokens"`
	CacheWrite     uint64   `json:"cache_write_tokens"`
	Output         uint64   `json:"output_tokens"`
	CacheReadShare *float64 `json:"cache_read_share,omitempty"`
	CacheReuse     *float64 `json:"cache_reuse,omitempty"`
}
