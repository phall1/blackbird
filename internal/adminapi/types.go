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
