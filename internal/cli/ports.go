package cli

import (
	"context"
	"io"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/install"
)

// BuildInfo is the binary's identity. Version is frozen by the release build's
// --version assertion, so the three fields are carried verbatim.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
}

// DaemonOptions is the daemon's process configuration expressed without any
// reference to the runtime package, so the CLI test binary never links storage
// or transport.
type DaemonOptions struct {
	Storage         string        `json:"storage"`
	SQLitePath      string        `json:"sqlite_path"`
	StateDir        string        `json:"state_dir"`
	HTTPAddress     string        `json:"http_address"`
	MCPAddress      string        `json:"mcp_address"`
	LogLevel        string        `json:"log_level"`
	ShutdownTimeout time.Duration `json:"shutdown_timeout"`
}

type DaemonPort interface {
	Run(ctx context.Context, options DaemonOptions) error
}

// Health is the answer to an unauthenticated /healthz plus /readyz probe pair.
// Reachable distinguishes "the daemon did not answer" from "the daemon answered
// that its storage is down", which is the distinction status exists to make.
type Health struct {
	Reachable     bool   `json:"reachable"`
	Ready         bool   `json:"ready"`
	Version       string `json:"version,omitempty"`
	SchemaVersion int    `json:"schema_version,omitempty"`
	Address       string `json:"address,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type Identity struct {
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	BuiltAt        string `json:"built_at"`
	PID            int    `json:"pid"`
	StartedAt      string `json:"started_at"`
	UptimeMS       int64  `json:"uptime_ms"`
	HTTPAddress    string `json:"http_address"`
	MCPAddress     string `json:"mcp_address"`
	StorageBackend string `json:"storage_backend"`
	DatabasePath   string `json:"database_path"`
	SchemaVersion  int    `json:"schema_version"`
	ObservedAt     string `json:"observed_at"`
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

type InboxSummary struct {
	ProjectKey        string `json:"project_key"`
	AgentName         string `json:"agent_name"`
	ActorID           string `json:"actor_id"`
	UnreadDeliveries  int    `json:"unread_deliveries"`
	UnackedDeliveries int    `json:"unacked_deliveries"`
	OldestUnreadAt    string `json:"oldest_unread_at,omitempty"`
}

// InboxItem is one delivery attributed to its recipient. Message bodies are
// never projected by the admin surface, so the CLI cannot render one.
type InboxItem struct {
	MessageID          string `json:"message_id"`
	ConversationID     string `json:"conversation_id"`
	ProjectKey         string `json:"project_key"`
	RecipientAgentName string `json:"recipient_agent_name"`
	AuthorAgentName    string `json:"author_agent_name,omitempty"`
	Subject            string `json:"subject"`
	Kind               string `json:"kind"`
	Read               bool   `json:"read"`
	Acknowledged       bool   `json:"acknowledged"`
	AckRequired        bool   `json:"acknowledgement_required"`
	SentAt             string `json:"sent_at"`
}

type Inbox struct {
	ProjectKey string         `json:"project_key"`
	Summaries  []InboxSummary `json:"summaries"`
	Pending    []InboxItem    `json:"pending"`
	Truncated  bool           `json:"truncated"`
	ObservedAt string         `json:"observed_at"`
}

type Conversation struct {
	ConversationID     string `json:"conversation_id"`
	ProjectKey         string `json:"project_key"`
	Topic              string `json:"topic"`
	Status             string `json:"status"`
	OpenedByAgentName  string `json:"opened_by_agent_name,omitempty"`
	Messages           int    `json:"messages"`
	Participants       int    `json:"participants"`
	UnreadDeliveries   int    `json:"unread_deliveries"`
	OpenedAt           string `json:"opened_at"`
	LastMessageAt      string `json:"last_message_at,omitempty"`
	LastMessageAuthor  string `json:"last_message_author,omitempty"`
	LastMessageSubject string `json:"last_message_subject,omitempty"`
}

type Selector struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type Reservation struct {
	LeaseID         string     `json:"lease_id"`
	ProjectKey      string     `json:"project_key"`
	HolderAgentName string     `json:"holder_agent_name,omitempty"`
	Mode            string     `json:"mode"`
	State           string     `json:"state"`
	Expired         bool       `json:"expired"`
	Selectors       []Selector `json:"selectors"`
	AcquiredAt      string     `json:"acquired_at"`
	ExpiresAt       string     `json:"expires_at"`
	ReleasedAt      string     `json:"released_at,omitempty"`
	ExpiresInMS     int64      `json:"expires_in_ms"`
}

type Event struct {
	Position    uint64 `json:"position"`
	ProjectKey  string `json:"project_key"`
	AgentName   string `json:"agent_name,omitempty"`
	Type        string `json:"type"`
	Subject     string `json:"subject"`
	OccurredAt  string `json:"occurred_at"`
	PayloadSize int    `json:"payload_bytes"`
}

// Every predicate below is applied by the daemon before its LIMIT. Filtering a
// page after it arrives renders an empty screen whenever the matching rows sit
// behind the limit, so the CLI never does it.
type AgentQuery struct {
	ProjectKey string
	AgentName  string
	ActiveOnly bool
	Limit      int
}

type InboxQuery struct {
	ProjectKey  string
	AgentName   string
	UnreadOnly  bool
	UnackedOnly bool
	Limit       int
}

type ConversationQuery struct {
	ProjectKey     string
	ConversationID string
	OpenOnly       bool
	Limit          int
}

// ReservationModeAny is the wire and flag spelling of "no mode predicate". It
// matches application.AdminReservationModeAny, which the CLI cannot import.
const ReservationModeAny = "any"

type ReservationQuery struct {
	ProjectKey string
	AgentName  string
	State      string
	Mode       string
	Path       string
	Limit      int
}

type EventQuery struct {
	ProjectKey string
	AgentName  string
	Type       string
	Limit      int
}

// Truncated reports that the daemon had more matching rows than the page limit
// allowed. It is carried on every page so no command can show a partial list as
// if it were the whole one.
type AgentsPage struct {
	Agents    []Agent `json:"agents"`
	Truncated bool    `json:"truncated"`
}

type ConversationsPage struct {
	Conversations []Conversation `json:"conversations"`
	Truncated     bool           `json:"truncated"`
}

type ReservationsPage struct {
	Reservations []Reservation `json:"reservations"`
	Truncated    bool          `json:"truncated"`
}

type ReservationRelease struct {
	LeaseID    string `json:"lease_id"`
	ReleasedAt string `json:"released_at"`
	Forced     bool   `json:"forced"`
}

type EventsPage struct {
	Events    []Event `json:"events"`
	Truncated bool    `json:"truncated"`
}

// AdminPort is the authenticated loopback admin surface of a running daemon.
// Reads are GETs; ForceReleaseReservation is the explicit operator mutation. A
// nil AdminPort means the CLI was assembled without a client and every command
// that needs one exits ExitUnavailable.
type AdminPort interface {
	// Health probes liveness and readiness. It returns an error whenever the
	// probe did not complete — nothing answered, or the daemon refused the
	// request — and the Health value still carries what was learned before
	// that, notably the address and Reachable. Callers rely on the error to
	// separate "no daemon answered" from "the daemon answered that it is not
	// ready"; an implementation that folds the failure into Detail and returns
	// nil makes the two indistinguishable.
	Health(ctx context.Context) (Health, error)
	Identity(ctx context.Context) (Identity, error)
	Overview(ctx context.Context) (Overview, error)
	Projects(ctx context.Context) ([]Project, error)
	Agents(ctx context.Context, query AgentQuery) (AgentsPage, error)
	Inbox(ctx context.Context, query InboxQuery) (Inbox, error)
	Conversations(ctx context.Context, query ConversationQuery) (ConversationsPage, error)
	Reservations(ctx context.Context, query ReservationQuery) (ReservationsPage, error)
	ForceReleaseReservation(ctx context.Context, leaseID string) (ReservationRelease, error)
	Events(ctx context.Context, query EventQuery) (EventsPage, error)
}

// Database is what a read-only inspection of the database file reports. It is
// deliberately flat: every field is a fact a doctor check or a status row reads
// without a second round trip.
type Database struct {
	Path                  string `json:"path"`
	Present               bool   `json:"present"`
	Mode                  string `json:"mode,omitempty"`
	SizeBytes             int64  `json:"size_bytes"`
	WALBytes              int64  `json:"wal_bytes"`
	FreeBytes             int64  `json:"free_bytes"`
	PageSize              int64  `json:"page_size"`
	PageCount             int64  `json:"page_count"`
	JournalMode           string `json:"journal_mode,omitempty"`
	FileMode              string `json:"file_mode,omitempty"`
	SchemaVersion         int    `json:"schema_version"`
	ExpectedSchemaVersion int    `json:"expected_schema_version"`
	ApplicationID         int    `json:"application_id"`
	ExpectedApplicationID int    `json:"expected_application_id"`
	Supported             bool   `json:"supported"`
	LedgerComplete        bool   `json:"ledger_complete"`
	CleanShutdown         bool   `json:"clean_shutdown"`
	QuickCheck            string `json:"quick_check,omitempty"`
	ForeignKeyFailures    int    `json:"foreign_key_failures"`
	Projects              int    `json:"projects"`
	Agents                int    `json:"agents"`
	Conversations         int    `json:"conversations"`
	Messages              int    `json:"messages"`
	Events                int    `json:"events"`
	Deliveries            int    `json:"deliveries"`
	UnreadDeliveries      int    `json:"unread_deliveries"`
	UnackedDeliveries     int    `json:"unacked_deliveries"`
	ActiveLeases          int    `json:"active_leases"`
	ExpiredActiveLeases   int    `json:"expired_active_leases"`
	OpenSessions          int    `json:"open_sessions"`
	StaleOpenSessions     int    `json:"stale_open_sessions"`
}

// StorePort opens the database file read-only. Implementations must never
// create it, migrate it, or claim it: an inspection command that writes is the
// defect this layer exists to prevent.
type StorePort interface {
	Inspect(ctx context.Context, path string, deep bool) (Database, error)
}

type ReclaimPlan struct {
	Checkpoint bool `json:"checkpoint"`
	Vacuum     bool `json:"vacuum"`
}

type Reclaimed struct {
	BeforeBytes int64 `json:"before_bytes"`
	AfterBytes  int64 `json:"after_bytes"`
	WALBytes    int64 `json:"wal_bytes"`
}

// MaintenancePort performs the two write operations gc is allowed to request.
// It is optional: a CLI assembled without one reports reclaimable space and
// refuses to mutate.
type MaintenancePort interface {
	Reclaim(ctx context.Context, path string, plan ReclaimPlan) (Reclaimed, error)
}

// ProductPort is the local product installation. It mirrors install.Manager so
// install, update, uninstall, and the service-definition drift check keep the
// behaviour and the output strings they already have.
type ProductPort interface {
	Install(ctx context.Context) (install.Result, error)
	Status(ctx context.Context) (string, error)
	Update(ctx context.Context) (install.UpdateResult, error)
	Uninstall(ctx context.Context) (install.Result, error)
	ServiceArgv() []string
	StateDir() string
}

type LogRequest struct {
	Stream string
	Lines  int
	Follow bool
}

type LogLine struct {
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

type LogPort interface {
	Tail(ctx context.Context, request LogRequest, emit func(LogLine) error) error
}

// Dependencies is everything cmd/blackbird injects. Every port is optional so a
// command can report a missing dependency instead of panicking, and so tests
// supply only what they exercise.
type Dependencies struct {
	Build        BuildInfo
	Defaults     DaemonOptions
	DatabasePath string
	Daemon       DaemonPort
	Admin        AdminPort
	Store        StorePort
	Maintenance  MaintenancePort
	Product      ProductPort
	Logs         LogPort
	Input        io.Reader
	Now          func() time.Time
	Env          render.Env
	Device       render.Device
	WidthProbe   func() (int, bool)
}
