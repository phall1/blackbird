package http

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	stdhttp "net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	PathLocalAdmin              = "/api/v1/local/admin/"
	PathLocalAdminIdentity      = "/api/v1/local/admin/identity"
	PathLocalAdminOverview      = "/api/v1/local/admin/overview"
	PathLocalAdminProjects      = "/api/v1/local/admin/projects"
	PathLocalAdminAgents        = "/api/v1/local/admin/agents"
	PathLocalAdminInbox         = "/api/v1/local/admin/inbox"
	PathLocalAdminConversations = "/api/v1/local/admin/conversations"
	PathLocalAdminReservations  = "/api/v1/local/admin/reservations"
	PathLocalAdminEvents        = "/api/v1/local/admin/events"

	localAdminUnavailable = "durable storage is unavailable"
)

// AdminTokenDigest is the SHA-256 of the loopback admin token. The plaintext is
// minted by the composition root and written only to the handshake file; it
// never enters the transport layer.
type AdminTokenDigest [sha256.Size]byte

func NewAdminTokenDigest(token string) AdminTokenDigest {
	return sha256.Sum256([]byte(token))
}

// LocalIdentity is the build and process half of the daemon's self-description.
// The storage half is read from the admin store on every request so a swapped
// database file cannot be reported from a stale snapshot.
type LocalIdentity struct {
	Version     string
	Commit      string
	BuiltAt     string
	PID         int
	StartedAt   time.Time
	HTTPAddress string
	MCPAddress  string
}

type AdminDependencies struct {
	Admin    application.LocalAdminStore
	Token    AdminTokenDigest
	Identity LocalIdentity
}

type adminHandler struct {
	admin    application.LocalAdminStore
	token    AdminTokenDigest
	identity LocalIdentity
	now      func() time.Time
}

type localAdminIdentity struct {
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

type localAdminOverview struct {
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

type localAdminProject struct {
	ProjectKey    string `json:"project_key"`
	WorkspaceID   string `json:"workspace_id"`
	RunID         string `json:"run_id,omitempty"`
	Agents        int    `json:"agents"`
	ActiveAgents  int    `json:"active_agents"`
	Conversations int    `json:"conversations"`
	CreatedAt     string `json:"created_at"`
	LastEventAt   string `json:"last_event_at,omitempty"`
}

type localAdminProjectsPage struct {
	Projects   []localAdminProject `json:"projects"`
	ObservedAt string              `json:"observed_at"`
}

type localAdminAgent struct {
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

type localAdminAgentsPage struct {
	Agents     []localAdminAgent `json:"agents"`
	Truncated  bool              `json:"truncated"`
	ObservedAt string            `json:"observed_at"`
}

type localAdminInboxSummary struct {
	ProjectKey        string `json:"project_key"`
	AgentName         string `json:"agent_name"`
	ActorID           string `json:"actor_id"`
	UnreadDeliveries  int    `json:"unread_deliveries"`
	UnackedDeliveries int    `json:"unacked_deliveries"`
	OldestUnreadAt    string `json:"oldest_unread_at,omitempty"`
}

type localAdminInboxItem struct {
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

type localAdminInboxPage struct {
	ProjectKey string                   `json:"project_key"`
	Summaries  []localAdminInboxSummary `json:"summaries"`
	Pending    []localAdminInboxItem    `json:"pending"`
	Truncated  bool                     `json:"truncated"`
	ObservedAt string                   `json:"observed_at"`
}

type localAdminConversation struct {
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

type localAdminConversationsPage struct {
	Conversations []localAdminConversation `json:"conversations"`
	Truncated     bool                     `json:"truncated"`
	ObservedAt    string                   `json:"observed_at"`
}

type localAdminSelector struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type localAdminReservation struct {
	LeaseID         string               `json:"lease_id"`
	ProjectKey      string               `json:"project_key"`
	WorkspaceID     string               `json:"workspace_id"`
	HolderAgentName string               `json:"holder_agent_name,omitempty"`
	HolderActorID   string               `json:"holder_actor_id"`
	HolderSessionID string               `json:"holder_session_id,omitempty"`
	Mode            string               `json:"mode"`
	State           string               `json:"state"`
	Expired         bool                 `json:"expired"`
	Selectors       []localAdminSelector `json:"selectors"`
	AcquiredAt      string               `json:"acquired_at"`
	ExpiresAt       string               `json:"expires_at"`
	ReleasedAt      string               `json:"released_at,omitempty"`
	ExpiresInMS     int64                `json:"expires_in_ms"`
}

type localAdminReservationsPage struct {
	Reservations []localAdminReservation `json:"reservations"`
	Truncated    bool                    `json:"truncated"`
	ObservedAt   string                  `json:"observed_at"`
}

type localAdminEvent struct {
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

type localAdminEventsPage struct {
	Events     []localAdminEvent `json:"events"`
	Truncated  bool              `json:"truncated"`
	ObservedAt string            `json:"observed_at"`
}

// NewAdminHandler serves the read-only cross-agent admin projections. It is a
// separate handler from NewLocalHandler so the admin surface is unreachable by
// construction wherever the composition root does not register it, and so an
// admin store can never be served without the token that gates it.
func NewAdminHandler(dependencies AdminDependencies) (stdhttp.Handler, error) {
	if isNil(dependencies.Admin) {
		return nil, errors.New("local admin HTTP transport requires an admin store")
	}
	if dependencies.Token == (AdminTokenDigest{}) {
		return nil, errors.New("local admin HTTP transport requires an admin token digest")
	}
	handler := &adminHandler{admin: dependencies.Admin, token: dependencies.Token,
		identity: dependencies.Identity, now: time.Now}
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("GET "+PathLocalAdminIdentity, handler.describe)
	mux.HandleFunc("GET "+PathLocalAdminOverview, handler.overview)
	mux.HandleFunc("GET "+PathLocalAdminProjects, handler.projects)
	mux.HandleFunc("GET "+PathLocalAdminAgents, handler.agents)
	mux.HandleFunc("GET "+PathLocalAdminInbox, handler.inbox)
	mux.HandleFunc("GET "+PathLocalAdminConversations, handler.conversations)
	mux.HandleFunc("GET "+PathLocalAdminReservations, handler.reservations)
	mux.HandleFunc("GET "+PathLocalAdminEvents, handler.events)
	return localSafety(mux), nil
}

func (handler *adminHandler) describe(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if _, ok := handler.guard(writer, request); !ok {
		return
	}
	storage, err := handler.admin.AdminStorageIdentity(request.Context())
	if err != nil {
		writeLocalProblem(writer, stdhttp.StatusServiceUnavailable, domain.ErrorCodeDependencyUnavailable, localAdminUnavailable)
		return
	}
	uptime := handler.now().Sub(handler.identity.StartedAt).Milliseconds()
	if uptime < 0 {
		uptime = 0
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localAdminIdentity{Version: handler.identity.Version,
		Commit: handler.identity.Commit, BuiltAt: handler.identity.BuiltAt, PID: handler.identity.PID,
		StartedAt: localAdminInstant(application.MicrosFromTime(handler.identity.StartedAt)), UptimeMS: uptime,
		HTTPAddress: handler.identity.HTTPAddress, MCPAddress: handler.identity.MCPAddress,
		StorageBackend: storage.StorageBackend, DatabasePath: storage.DatabasePath,
		SchemaVersion: storage.SchemaVersion, ObservedAt: localAdminInstant(storage.ObservedAtUS)})
}

func (handler *adminHandler) overview(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if _, ok := handler.guard(writer, request); !ok {
		return
	}
	overview, err := handler.admin.AdminOverview(request.Context())
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localAdminOverview{Projects: overview.Projects, Agents: overview.Agents,
		ActiveAgents: overview.ActiveAgents, Conversations: overview.Conversations, Messages: overview.Messages,
		Deliveries: overview.Deliveries, UnreadDeliveries: overview.UnreadDeliveries,
		UnackedDeliveries: overview.UnackedDeliveries, ActiveReservations: overview.ActiveReservations,
		ExpiredReservations: overview.ExpiredReservations, CoordinationEvents: overview.CoordinationEvents,
		ObservedAt: localAdminInstant(overview.ObservedAtUS)})
}

func (handler *adminHandler) projects(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if _, ok := handler.guard(writer, request); !ok {
		return
	}
	page, err := handler.admin.ListAdminProjects(request.Context())
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	projects := make([]localAdminProject, 0, len(page.Projects))
	for _, project := range page.Projects {
		projects = append(projects, localAdminProject{ProjectKey: project.ProjectKey,
			WorkspaceID: project.WorkspaceID.String(), RunID: localAdminID(project.RunID),
			Agents: project.Agents, ActiveAgents: project.ActiveAgents, Conversations: project.Conversations,
			CreatedAt: localAdminInstant(project.CreatedAtUS), LastEventAt: localAdminInstant(project.LastEventAtUS)})
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localAdminProjectsPage{Projects: projects,
		ObservedAt: localAdminInstant(page.ObservedAtUS)})
}

func (handler *adminHandler) agents(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	values, ok := handler.guard(writer, request, "project_key", "agent", "active", "limit")
	if !ok {
		return
	}
	projectKey, ok := localAdminProjectKey(writer, values, false)
	if !ok {
		return
	}
	agentName, ok := localAdminAgentName(writer, values)
	if !ok {
		return
	}
	limit, ok := localAdminLimit(writer, values)
	if !ok {
		return
	}
	activeOnly, ok := localAdminFlag(writer, values, "active")
	if !ok {
		return
	}
	page, err := handler.admin.ListAdminAgents(request.Context(),
		application.AdminAgentsQuery{ProjectKey: projectKey, AgentName: agentName, ActiveOnly: activeOnly,
			Limit: limit})
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	agents := make([]localAdminAgent, 0, len(page.Agents))
	for _, agent := range page.Agents {
		agents = append(agents, localAdminAgent{ProjectKey: agent.ProjectKey, AgentName: agent.AgentName,
			ActorID: agent.ActorID.String(), SessionID: localAdminID(agent.SessionID), Active: agent.Active,
			CreatedAt: localAdminInstant(agent.CreatedAtUS), StartedAt: localAdminInstant(agent.StartedAtUS),
			LastSeenAt: localAdminInstant(agent.LastSeenAtUS), UnreadDeliveries: agent.UnreadDeliveries,
			UnackedDeliveries: agent.UnackedDeliveries, ActiveLeases: agent.ActiveLeases})
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localAdminAgentsPage{Agents: agents, Truncated: page.Truncated,
		ObservedAt: localAdminInstant(page.ObservedAtUS)})
}

func (handler *adminHandler) inbox(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	values, ok := handler.guard(writer, request, "project_key", "agent", "unread", "unacked", "limit")
	if !ok {
		return
	}
	projectKey, ok := localAdminProjectKey(writer, values, true)
	if !ok {
		return
	}
	agentName, ok := localAdminAgentName(writer, values)
	if !ok {
		return
	}
	limit, ok := localAdminLimit(writer, values)
	if !ok {
		return
	}
	unreadOnly, ok := localAdminFlag(writer, values, "unread")
	if !ok {
		return
	}
	unackedOnly, ok := localAdminFlag(writer, values, "unacked")
	if !ok {
		return
	}
	page, err := handler.admin.AdminInbox(request.Context(),
		application.AdminInboxQuery{ProjectKey: projectKey, AgentName: agentName, UnreadOnly: unreadOnly,
			UnackedOnly: unackedOnly, Limit: limit})
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	summaries := make([]localAdminInboxSummary, 0, len(page.Summaries))
	for _, summary := range page.Summaries {
		summaries = append(summaries, localAdminInboxSummary{ProjectKey: summary.ProjectKey,
			AgentName: summary.AgentName, ActorID: summary.ActorID.String(),
			UnreadDeliveries: summary.UnreadDeliveries, UnackedDeliveries: summary.UnackedDeliveries,
			OldestUnreadAt: localAdminInstant(summary.OldestUnreadAtUS)})
	}
	pending := make([]localAdminInboxItem, 0, len(page.Pending))
	for _, item := range page.Pending {
		pending = append(pending, localAdminInboxItem{MessageID: item.MessageID.String(),
			ConversationID: item.ConversationID.String(), ProjectKey: item.ProjectKey,
			RecipientAgentName: item.RecipientAgentName, RecipientActorID: item.RecipientActorID.String(),
			AuthorAgentName: item.AuthorAgentName, AuthorActorID: item.AuthorActorID.String(),
			Subject: item.Subject, Kind: string(item.Kind), Read: item.Read, Acknowledged: item.Acknowledged,
			AckRequired: item.AcknowledgementRequired, SentAt: localAdminInstant(item.SentAtUS)})
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localAdminInboxPage{ProjectKey: page.ProjectKey, Summaries: summaries,
		Pending: pending, Truncated: page.Truncated, ObservedAt: localAdminInstant(page.ObservedAtUS)})
}

func (handler *adminHandler) conversations(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	values, ok := handler.guard(writer, request, "project_key", "conversation_id", "open", "limit")
	if !ok {
		return
	}
	projectKey, ok := localAdminProjectKey(writer, values, false)
	if !ok {
		return
	}
	limit, ok := localAdminLimit(writer, values)
	if !ok {
		return
	}
	openOnly, ok := localAdminFlag(writer, values, "open")
	if !ok {
		return
	}
	var conversationID domain.ConversationID
	if text := values.Get("conversation_id"); text != "" {
		parsed, err := domain.ParseConversationID(text)
		if err != nil {
			writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "query parameters are invalid")
			return
		}
		conversationID = parsed
	}
	page, err := handler.admin.ListAdminConversations(request.Context(),
		application.AdminConversationsQuery{ProjectKey: projectKey, ConversationID: conversationID,
			OpenOnly: openOnly, Limit: limit})
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	conversations := make([]localAdminConversation, 0, len(page.Conversations))
	for _, conversation := range page.Conversations {
		conversations = append(conversations, localAdminConversation{
			ConversationID: conversation.ConversationID.String(), WorkspaceID: conversation.WorkspaceID.String(),
			ProjectKey: conversation.ProjectKey, Topic: conversation.Topic, Status: string(conversation.Status),
			OpenedByAgentName: conversation.OpenedByAgentName, OpenedByActorID: conversation.OpenedByActorID.String(),
			Messages: conversation.Messages, Participants: conversation.Participants,
			UnreadDeliveries: conversation.UnreadDeliveries, OpenedAt: localAdminInstant(conversation.OpenedAtUS),
			LastMessageAt:     localAdminInstant(conversation.LastMessageAtUS),
			LastMessageAuthor: conversation.LastMessageAuthor, LastMessageSubject: conversation.LastMessageSubject})
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localAdminConversationsPage{Conversations: conversations,
		Truncated: page.Truncated, ObservedAt: localAdminInstant(page.ObservedAtUS)})
}

func (handler *adminHandler) reservations(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	values, ok := handler.guard(writer, request, "project_key", "agent", "state", "mode", "path", "limit")
	if !ok {
		return
	}
	projectKey, ok := localAdminProjectKey(writer, values, false)
	if !ok {
		return
	}
	agentName, ok := localAdminAgentName(writer, values)
	if !ok {
		return
	}
	limit, ok := localAdminLimit(writer, values)
	if !ok {
		return
	}
	state := application.AdminReservationState(values.Get("state"))
	if !state.Valid() {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
			fmt.Sprintf("state must be one of %s, %s, %s or %s", application.AdminReservationAll,
				application.AdminReservationActive, application.AdminReservationExpired,
				application.AdminReservationReleased))
		return
	}
	mode, ok := localAdminReservationMode(writer, values)
	if !ok {
		return
	}
	selectorPath, ok := localAdminPath(writer, values)
	if !ok {
		return
	}
	page, err := handler.admin.ListAdminReservations(request.Context(),
		application.AdminReservationsQuery{ProjectKey: projectKey, AgentName: agentName,
			State: state.Normalized(), Mode: mode, Path: selectorPath, Limit: limit})
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	reservations := make([]localAdminReservation, 0, len(page.Reservations))
	for _, reservation := range page.Reservations {
		selectors := make([]localAdminSelector, 0, len(reservation.Selectors))
		for _, selector := range reservation.Selectors {
			selectors = append(selectors, localAdminSelector{Kind: string(selector.Kind()), Path: selector.Path()})
		}
		reservations = append(reservations, localAdminReservation{LeaseID: reservation.LeaseID.String(),
			ProjectKey: reservation.ProjectKey, WorkspaceID: reservation.WorkspaceID.String(),
			HolderAgentName: reservation.HolderAgentName, HolderActorID: reservation.HolderActorID.String(),
			HolderSessionID: localAdminID(reservation.HolderSessionID), Mode: string(reservation.Mode),
			State: string(reservation.State), Expired: reservation.Expired, Selectors: selectors,
			AcquiredAt: localAdminInstant(reservation.AcquiredAtUS),
			ExpiresAt:  localAdminInstant(reservation.ExpiresAtUS),
			ReleasedAt: localAdminInstant(reservation.ReleasedAtUS), ExpiresInMS: reservation.ExpiresInMS})
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localAdminReservationsPage{Reservations: reservations,
		Truncated: page.Truncated, ObservedAt: localAdminInstant(page.ObservedAtUS)})
}

func (handler *adminHandler) events(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	values, ok := handler.guard(writer, request, "project_key", "agent", "type", "limit")
	if !ok {
		return
	}
	projectKey, ok := localAdminProjectKey(writer, values, false)
	if !ok {
		return
	}
	agentName, ok := localAdminAgentName(writer, values)
	if !ok {
		return
	}
	limit, ok := localAdminLimit(writer, values)
	if !ok {
		return
	}
	eventType := application.CoordinationEventType(values.Get("type"))
	if eventType != "" && !eventType.Valid() {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "type is not a coordination event type")
		return
	}
	page, err := handler.admin.ListAdminEvents(request.Context(),
		application.AdminEventsQuery{ProjectKey: projectKey, AgentName: agentName, EventType: eventType, Limit: limit})
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	events := make([]localAdminEvent, 0, len(page.Events))
	for _, event := range page.Events {
		payload := json.RawMessage(event.Payload)
		if len(payload) == 0 {
			payload = json.RawMessage("null")
		}
		events = append(events, localAdminEvent{Position: event.Position, ProjectKey: event.ProjectKey,
			WorkspaceID: event.WorkspaceID.String(), AgentName: event.AgentName, ActorID: event.ActorID.String(),
			Type: string(event.EventType), Subject: event.SubjectID, Payload: payload,
			OccurredAt: localAdminInstant(event.OccurredAtUS)})
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localAdminEventsPage{Events: events, Truncated: page.Truncated,
		ObservedAt: localAdminInstant(page.ObservedAtUS)})
}

func (handler *adminHandler) guard(writer stdhttp.ResponseWriter, request *stdhttp.Request,
	allowed ...string) (url.Values, bool) {
	values := request.URL.Query()
	if !rejectQueryCredentials(writer, values) {
		return nil, false
	}
	if !handler.authenticateAdmin(writer, request) {
		return nil, false
	}
	return localAdminQuery(writer, values, allowed...)
}

// authenticateAdmin repeats the header-shape rules of localHandler.authenticate
// so the two credential surfaces cannot drift. A malformed header and a wrong
// token produce byte-identical responses, so the endpoint is not an oracle.
func (handler *adminHandler) authenticateAdmin(writer stdhttp.ResponseWriter, request *stdhttp.Request) bool {
	value := request.Header.Get("Authorization")
	if len(request.Header.Values("Authorization")) != 1 || len(value) < 8 || !strings.EqualFold(value[:7], "Bearer ") ||
		strings.TrimSpace(value[7:]) != value[7:] || strings.ContainsAny(value[7:], " \t\r\n") {
		return rejectAdmin(writer)
	}
	presented := sha256.Sum256([]byte(value[7:]))
	if subtle.ConstantTimeCompare(presented[:], handler.token[:]) != 1 {
		return rejectAdmin(writer)
	}
	return true
}

func rejectAdmin(writer stdhttp.ResponseWriter) bool {
	writer.Header().Set("WWW-Authenticate", "Bearer")
	writeLocalProblem(writer, stdhttp.StatusUnauthorized, domain.ErrorCodeUnauthenticated,
		"a valid admin bearer token is required")
	return false
}

func localAdminQuery(writer stdhttp.ResponseWriter, values url.Values, allowed ...string) (url.Values, bool) {
	for key, entries := range values {
		if len(entries) != 1 || !slices.Contains(allowed, key) {
			writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "query parameters are invalid")
			return nil, false
		}
	}
	return values, true
}

func localAdminProjectKey(writer stdhttp.ResponseWriter, values url.Values, required bool) (string, bool) {
	key := values.Get("project_key")
	if key == "" {
		if required {
			writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "project_key is required")
			return "", false
		}
		return "", true
	}
	if len(key) > application.MaxCoordinationKeyBytes || !utf8.ValidString(key) {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "project_key is invalid")
		return "", false
	}
	return key, true
}

func localAdminAgentName(writer stdhttp.ResponseWriter, values url.Values) (string, bool) {
	name := values.Get("agent")
	if len(name) > application.MaxCoordinationNameBytes || !utf8.ValidString(name) {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "agent is invalid")
		return "", false
	}
	return name, true
}

// A filter flag is absent or one of the strconv.ParseBool spellings. Anything
// else is rejected rather than read as false, because a filter that silently
// stops filtering returns a page the caller will read as the whole truth.
func localAdminFlag(writer stdhttp.ResponseWriter, values url.Values, name string) (bool, bool) {
	text := values.Get(name)
	if text == "" {
		return false, true
	}
	parsed, err := strconv.ParseBool(text)
	if err != nil {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
			fmt.Sprintf("%s must be true or false", name))
		return false, false
	}
	return parsed, true
}

func localAdminReservationMode(writer stdhttp.ResponseWriter, values url.Values) (application.LeaseMode, bool) {
	text := values.Get("mode")
	if text == "" || text == application.AdminReservationModeAny {
		return "", true
	}
	mode := application.LeaseMode(text)
	if !application.ValidAdminReservationMode(mode) {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
			fmt.Sprintf("mode must be one of %s, %s or %s", application.AdminReservationModeAny,
				application.LeaseShared, application.LeaseExclusive))
		return "", false
	}
	return mode, true
}

func localAdminPath(writer stdhttp.ResponseWriter, values url.Values) (string, bool) {
	selectorPath := values.Get("path")
	if selectorPath == "" {
		return "", true
	}
	if len(selectorPath) > application.MaxLeaseSelectorBytes || !utf8.ValidString(selectorPath) ||
		strings.ContainsRune(selectorPath, 0) || strings.TrimSpace(selectorPath) != selectorPath {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "path is invalid")
		return "", false
	}
	return selectorPath, true
}

func localAdminLimit(writer stdhttp.ResponseWriter, values url.Values) (uint16, bool) {
	text := values.Get("limit")
	if text == "" {
		return 0, true
	}
	parsed, err := strconv.ParseUint(text, 10, 16)
	if err != nil || parsed == 0 || parsed > application.MaxQueryPageSize {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
			fmt.Sprintf("limit must be from 1 through %d", application.MaxQueryPageSize))
		return 0, false
	}
	return uint16(parsed), true
}

func localAdminInstant(micros int64) string {
	if micros == 0 {
		return ""
	}
	return application.TimeFromMicros(micros).Format(time.RFC3339Nano)
}

func localAdminID[ID interface {
	IsZero() bool
	String() string
}](id ID) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}
