// Package mcp exposes the strict transport contracts through the official MCP Go SDK.
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	stdhttp "net/http"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/transport/contracts"
)

const (
	ToolInstallationBootstrap     = "blackbird_installation_bootstrap"
	ToolPrincipalRegister         = "blackbird_register_principal"
	ToolDevicePairingBegin        = "blackbird_begin_device_pairing"
	ToolDevicePair                = "blackbird_pair_device"
	ToolWorkspaceCreate           = "blackbird_create_workspace"
	ToolWorkspaceMemberInvite     = "blackbird_invite_workspace_member"
	ToolWorkspaceMembershipAccept = "blackbird_accept_workspace_membership"
	ToolActorCreate               = "blackbird_create_actor"
	ToolActorDelegationPropose    = "blackbird_propose_actor_delegation"
	ToolActorDelegationActivate   = "blackbird_activate_actor_delegation"
	ToolSessionStart              = "blackbird_start_session"
	ToolWorkRefObserve            = "blackbird_observe_work_ref"
	ToolObjectiveAndWorkCreate    = "blackbird_create_objective_and_work"
	ToolObjectiveActivate         = "blackbird_activate_objective"
	ToolRunPlanWithBindings       = "blackbird_plan_run_with_bindings"
	ToolRunJoin                   = "blackbird_join_run"
	ToolRunStart                  = "blackbird_start_run"
	ToolContextGet                = "blackbird_get_context"
	ToolEventsSync                = "blackbird_sync_events"
	ToolAgentRegister             = "blackbird_agent_register"
	ToolAgentsList                = "blackbird_agents_list"
	ToolConversationOpen          = "blackbird_conversation_open"
	ToolMessageSend               = "blackbird_message_send"
	ToolInboxFetch                = "blackbird_inbox_fetch"
	ToolThreadFetch               = "blackbird_thread_fetch"
	ToolMessageFact               = "blackbird_message_fact"
	ToolReservationAcquire        = "blackbird_reservation_acquire"
	ToolReservationChange         = "blackbird_reservation_change"
	ToolReservationsStatus        = "blackbird_reservations_status"
	ToolWait                      = "blackbird_wait"

	ResourceCurrentContext       = "blackbird://session/current/context"
	ResourceContextDeltas        = "blackbird://session/current/context-deltas{?cursor,limit}"
	ResourceCoordinationProtocol = "blackbird://coordination/protocol"

	mediaTypeJSON                = "application/json"
	mediaTypeMarkdown            = "text/markdown"
	defaultCoordinationPageLimit = 50
	defaultReservationTTLSeconds = 3600
	// maxCoordinationBlockers bounds the holders reported alongside a lease
	// conflict. An agent that has to negotiate with more than a handful of
	// peers at once has a decomposition problem no longer list solves.
	maxCoordinationBlockers = 8
)

// Authenticator establishes verified evidence from the protected MCP channel
// or request context. Tool arguments and resource URIs are never evidence.
type Authenticator interface {
	Authenticate(context.Context, string, string) (contracts.AuthenticationEvidence, *contracts.ErrorDTO, error)
}

// CurrentSessionBinder resolves the durable actor session already bound to
// authenticated evidence. It must not derive the session from an MCP session ID.
type CurrentSessionBinder interface {
	CurrentActorSession(context.Context, contracts.AuthenticationEvidence, string) (domain.ActorSessionID, *contracts.ErrorDTO, error)
}

// MetricsObserver receives bounded operational labels only; tool arguments are
// never metrics because they carry credentials and unbounded user text.
type MetricsObserver interface {
	ObserveRequest(operation, outcome string)
	ObserveLeaseConflict()
}

type Dependencies struct {
	Authenticator             Authenticator
	CurrentSession            CurrentSessionBinder
	InstallationBootstrap     contracts.InstallationBootstrapHandler
	PrincipalRegister         contracts.PrincipalRegisterHandler
	DevicePairingBegin        contracts.DevicePairingBeginHandler
	DevicePair                contracts.DevicePairHandler
	WorkspaceCreate           contracts.WorkspaceCreateHandler
	WorkspaceMemberInvite     contracts.WorkspaceMemberInviteHandler
	WorkspaceMembershipAccept contracts.WorkspaceMembershipAcceptHandler
	ActorCreate               contracts.ActorCreateHandler
	ActorDelegationPropose    contracts.ActorDelegationProposeHandler
	ActorDelegationActivate   contracts.ActorDelegationActivateHandler
	SessionStart              contracts.SessionStartHandler
	WorkRefObserve            contracts.WorkRefObserveHandler
	ObjectiveAndWorkCreate    contracts.ObjectiveAndWorkCreateHandler
	ObjectiveActivate         contracts.ObjectiveActivateHandler
	RunPlanWithBindings       contracts.RunPlanWithBindingsHandler
	RunJoin                   contracts.RunJoinHandler
	RunStart                  contracts.RunStartHandler
	ContextGet                contracts.ContextGetHandler
	EventsSync                contracts.EventsSyncHandler
	Coordination              application.LocalCoordinationStore

	// Logger receives one record per failed tool call: the tool's name and the
	// failure the caller was already given. A nil Logger is silent rather than a
	// composition error, so a test can exercise a tool without a log sink.
	Logger  *slog.Logger
	Metrics MetricsObserver

	// ExposeIdentityPlane registers the W0/W1 identity and work tools on this
	// transport. It defaults to false because MCP carries no place to attach a
	// verified ingress credential, so every one of those tools answers
	// UNAUTHENTICATED while spending roughly ninety percent of the tool-list
	// tokens in each client's context window. The same operations stay fully
	// available over HTTP, where the credential can be attached.
	ExposeIdentityPlane bool
}

// Server embeds the SDK server and adds Blackbird's context-head wake-up API.
type Server struct{ *sdkmcp.Server }

func NewServer(dependencies Dependencies) (*Server, error) {
	if isNil(dependencies.Authenticator) || isNil(dependencies.CurrentSession) ||
		isNil(dependencies.InstallationBootstrap) || isNil(dependencies.PrincipalRegister) ||
		isNil(dependencies.DevicePairingBegin) || isNil(dependencies.DevicePair) ||
		isNil(dependencies.WorkspaceCreate) || isNil(dependencies.WorkspaceMemberInvite) ||
		isNil(dependencies.WorkspaceMembershipAccept) || isNil(dependencies.ActorCreate) ||
		isNil(dependencies.ActorDelegationPropose) || isNil(dependencies.ActorDelegationActivate) ||
		isNil(dependencies.SessionStart) || isNil(dependencies.WorkRefObserve) ||
		isNil(dependencies.ObjectiveAndWorkCreate) || isNil(dependencies.ObjectiveActivate) ||
		isNil(dependencies.RunPlanWithBindings) || isNil(dependencies.RunJoin) || isNil(dependencies.RunStart) ||
		isNil(dependencies.ContextGet) || isNil(dependencies.EventsSync) {
		return nil, errors.New("mcp transport requires every W0/W1 handler, authenticator, and current-session binder")
	}

	sdk := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "blackbird", Version: "v1"}, &sdkmcp.ServerOptions{
		Capabilities: &sdkmcp.ServerCapabilities{},
		PageSize:     64,
	})
	server := &Server{Server: sdk}
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	// One middleware covers every tool on this transport, including the ones the
	// SDK synthesizes a failure result for, and it reads only the tool name and
	// the failure text -- so a bearer token or a message body in the arguments
	// can never reach a log line by way of a new tool nobody remembered to wire.
	sdk.AddReceivingMiddleware(logToolFailures(logger, dependencies.Metrics))
	if dependencies.ExposeIdentityPlane {
		registerIdentityPlaneTools(sdk, dependencies)
	}
	registerResources(sdk, dependencies)
	if !isNil(dependencies.Coordination) {
		registerCoordinationProtocol(sdk)
		registerCoordinationTools(sdk, dependencies.Coordination, logger)
	}
	return server, nil
}

// logToolFailures records the operation and cause behind every failed tool
// call. A typed tool handler's error never reaches the middleware as an error:
// the SDK turns it into a result carrying IsError, so both shapes are checked.
func logToolFailures(logger *slog.Logger, metrics MetricsObserver) sdkmcp.Middleware {
	return func(next sdkmcp.MethodHandler) sdkmcp.MethodHandler {
		return func(ctx context.Context, method string, request sdkmcp.Request) (sdkmcp.Result, error) {
			result, err := next(ctx, method, request)
			call, isCall := request.(*sdkmcp.CallToolRequest)
			if !isCall || call.Params == nil {
				return result, err
			}
			metricOutcome := "ok"
			if err != nil {
				metricOutcome = "error"
				logger.Error("mcp tool failed", slog.String("tool", call.Params.Name), slog.Any("error", err))
			} else if outcome, isToolResult := result.(*sdkmcp.CallToolResult); isToolResult && outcome != nil && outcome.IsError {
				metricOutcome = structuredFailureCode(outcome)
				if metricOutcome == "" {
					metricOutcome = "error"
					logger.Error("mcp tool failed", slog.String("tool", call.Params.Name),
						slog.String("error", toolFailureText(outcome)))
				}
			}
			if metrics != nil {
				metrics.ObserveRequest("mcp "+call.Params.Name, metricOutcome)
				if metricOutcome == string(domain.ErrorCodeLeaseConflict) {
					metrics.ObserveLeaseConflict()
				}
			}
			return result, err
		}
	}
}

// structuredFailureCode identifies a coordination failure that already logged
// its cause chain and returns the bounded outcome label used by metrics. An SDK
// rejection before a handler runs carries no structured payload and falls back
// to the generic error label and log record.
func structuredFailureCode(result *sdkmcp.CallToolResult) string {
	encoded, isJSON := result.StructuredContent.(json.RawMessage)
	if !isJSON {
		return ""
	}
	var failure struct {
		RequestID string `json:"request_id"`
		Code      string `json:"code"`
	}
	if json.Unmarshal(encoded, &failure) != nil || failure.RequestID == "" {
		return ""
	}
	return failure.Code
}

// toolFailureText reads the message the caller was already shown. Structured
// content is deliberately not read: it is the tool's own output shape, and a
// future tool could carry something there that does not belong in a log.
func toolFailureText(result *sdkmcp.CallToolResult) string {
	for _, content := range result.Content {
		if text, ok := content.(*sdkmcp.TextContent); ok {
			return text.Text
		}
	}
	return "tool reported an error with no message"
}

// registerIdentityPlaneTools publishes the W0/W1 ceremonies as MCP tools. Only
// a transport that can carry a verified ingress credential should call it;
// without one every tool here fails authentication before reaching a handler.
func registerIdentityPlaneTools(sdk *sdkmcp.Server, dependencies Dependencies) {
	registerCommand(sdk, ToolInstallationBootstrap, contracts.OperationInstallationBootstrap, dependencies.Authenticator,
		contracts.DecodeInstallationBootstrapRequest, func(value contracts.InstallationBootstrapRequestDTO) time.Time { return value.Deadline },
		dependencies.InstallationBootstrap.HandleInstallationBootstrap, func(value contracts.InstallationBootstrapResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolPrincipalRegister, contracts.OperationPrincipalRegister, dependencies.Authenticator,
		contracts.DecodePrincipalRegisterRequest, func(value contracts.PrincipalRegisterRequestDTO) time.Time { return value.Deadline },
		dependencies.PrincipalRegister.HandlePrincipalRegister, func(value contracts.PrincipalRegisterResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolDevicePairingBegin, contracts.OperationDevicePairingBegin, dependencies.Authenticator,
		contracts.DecodeDevicePairingBeginRequest, func(value contracts.DevicePairingBeginRequestDTO) time.Time { return value.Deadline },
		dependencies.DevicePairingBegin.HandleDevicePairingBegin, func(value contracts.DevicePairingBeginResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolDevicePair, contracts.OperationDevicePair, dependencies.Authenticator,
		contracts.DecodeDevicePairRequest, func(value contracts.DevicePairRequestDTO) time.Time { return value.Deadline },
		dependencies.DevicePair.HandleDevicePair, func(value contracts.DevicePairResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolWorkspaceCreate, contracts.OperationWorkspaceCreate, dependencies.Authenticator,
		contracts.DecodeWorkspaceCreateRequest, func(value contracts.WorkspaceCreateRequestDTO) time.Time { return value.Deadline },
		dependencies.WorkspaceCreate.HandleWorkspaceCreate, func(value contracts.WorkspaceCreateResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolWorkspaceMemberInvite, contracts.OperationWorkspaceMemberInvite, dependencies.Authenticator,
		contracts.DecodeWorkspaceMemberInviteRequest, func(value contracts.WorkspaceMemberInviteRequestDTO) time.Time { return value.Deadline },
		dependencies.WorkspaceMemberInvite.HandleWorkspaceMemberInvite, func(value contracts.WorkspaceMemberInviteResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolWorkspaceMembershipAccept, contracts.OperationWorkspaceMembershipAccept, dependencies.Authenticator,
		contracts.DecodeWorkspaceMembershipAcceptRequest, func(value contracts.WorkspaceMembershipAcceptRequestDTO) time.Time { return value.Deadline },
		dependencies.WorkspaceMembershipAccept.HandleWorkspaceMembershipAccept, func(value contracts.WorkspaceMembershipAcceptResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolActorCreate, contracts.OperationActorCreate, dependencies.Authenticator,
		contracts.DecodeActorCreateRequest, func(value contracts.ActorCreateRequestDTO) time.Time { return value.Deadline },
		dependencies.ActorCreate.HandleActorCreate, func(value contracts.ActorCreateResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolActorDelegationPropose, contracts.OperationActorDelegationPropose, dependencies.Authenticator,
		contracts.DecodeActorDelegationProposeRequest, func(value contracts.ActorDelegationProposeRequestDTO) time.Time { return value.Deadline },
		dependencies.ActorDelegationPropose.HandleActorDelegationPropose, func(value contracts.ActorDelegationProposeResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolActorDelegationActivate, contracts.OperationActorDelegationActivate, dependencies.Authenticator,
		contracts.DecodeActorDelegationActivateRequest, func(value contracts.ActorDelegationActivateRequestDTO) time.Time { return value.Deadline },
		dependencies.ActorDelegationActivate.HandleActorDelegationActivate, func(value contracts.ActorDelegationActivateResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolSessionStart, contracts.OperationSessionStart, dependencies.Authenticator,
		contracts.DecodeSessionStartRequest, func(value contracts.SessionStartRequestDTO) time.Time { return value.Deadline },
		dependencies.SessionStart.HandleSessionStart, func(value contracts.SessionStartResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolWorkRefObserve, contracts.OperationWorkRefObserve, dependencies.Authenticator,
		contracts.DecodeWorkRefObserveRequest, func(value contracts.WorkRefObserveRequestDTO) time.Time { return value.Deadline },
		dependencies.WorkRefObserve.HandleWorkRefObserve, func(value contracts.WorkRefObserveResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolObjectiveAndWorkCreate, contracts.OperationObjectiveAndWorkCreate, dependencies.Authenticator,
		contracts.DecodeObjectiveAndWorkCreateRequest, func(value contracts.ObjectiveAndWorkCreateRequestDTO) time.Time { return value.Deadline },
		dependencies.ObjectiveAndWorkCreate.HandleObjectiveAndWorkCreate, func(value contracts.ObjectiveAndWorkCreateResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolObjectiveActivate, contracts.OperationObjectiveActivate, dependencies.Authenticator,
		contracts.DecodeObjectiveActivateRequest, func(value contracts.ObjectiveActivateRequestDTO) time.Time { return value.Deadline },
		dependencies.ObjectiveActivate.HandleObjectiveActivate, func(value contracts.ObjectiveActivateResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolRunPlanWithBindings, contracts.OperationRunPlanWithBindings, dependencies.Authenticator,
		contracts.DecodeRunPlanWithBindingsRequest, func(value contracts.RunPlanWithBindingsRequestDTO) time.Time { return value.Deadline },
		dependencies.RunPlanWithBindings.HandleRunPlanWithBindings, func(value contracts.RunPlanWithBindingsResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolRunJoin, contracts.OperationRunJoin, dependencies.Authenticator,
		contracts.DecodeRunJoinRequest, func(value contracts.RunJoinRequestDTO) time.Time { return value.Deadline },
		dependencies.RunJoin.HandleRunJoin, func(value contracts.RunJoinResultDTO) error { return value.Validate() })
	registerCommand(sdk, ToolRunStart, contracts.OperationRunStart, dependencies.Authenticator,
		contracts.DecodeRunStartRequest, func(value contracts.RunStartRequestDTO) time.Time { return value.Deadline },
		dependencies.RunStart.HandleRunStart, func(value contracts.RunStartResultDTO) error { return value.Validate() })
	registerQuery(sdk, ToolContextGet, contracts.OperationContextGet, dependencies.Authenticator,
		contracts.DecodeContextGetRequest, dependencies.ContextGet.HandleContextGet, func(value contracts.ContextPageDTO) error { return value.Validate() })
	registerQuery(sdk, ToolEventsSync, contracts.OperationEventsSync, dependencies.Authenticator,
		contracts.DecodeEventsSyncRequest, dependencies.EventsSync.HandleEventsSync, func(value contracts.EventPageDTO) error { return value.Validate() })
}

type registerAgentInput struct {
	ProjectKey        string  `json:"project_key" jsonschema:"Repository or workspace key, preferably its absolute path."`
	AgentName         string  `json:"agent_name" jsonschema:"Stable name for this agent within the repository. Teammates address mail to it and see it as the holder of your reservations, so keep it the same across restarts."`
	RegistrationToken *string `json:"registration_token,omitempty" jsonschema:"Existing token required when restarting a registered name. Every other tool takes this same value as agent_token."`
}

// agentSessionOutput answers a registration with the state registration itself
// rebound. Identifiers alone told a resuming agent nothing it could act on: its
// still-active leases had just been moved onto the new session and went
// unmentioned, so an agent that restarted or was compacted held an exclusive
// reservation it could neither renew nor release, and everyone else waited out
// its TTL. Every duration here is computed by the daemon, so nothing in this
// result has to be compared against the client's own clock.
type agentSessionOutput struct {
	ProjectKey        string                    `json:"project_key"`
	AgentName         string                    `json:"agent_name"`
	WorkspaceID       string                    `json:"workspace_id"`
	ActorID           string                    `json:"actor_id"`
	SessionID         string                    `json:"session_id"`
	RegistrationToken string                    `json:"registration_token,omitempty"`
	HeldReservations  []heldReservationOutput   `json:"held_reservations" jsonschema:"Reservations this agent still holds, now bound to this session. Renew or release each one with the lease_id and fences given here, or it blocks other agents until it expires."`
	Inbox             inboxSummaryOutput        `json:"inbox" jsonschema:"Mailbox counts over the whole inbox, with the most recent pending deliveries; blackbird_inbox_fetch serves the rest."`
	OpenConversations []agentConversationOutput `json:"open_conversations" jsonschema:"Open conversations this agent opened, wrote to, or was addressed in, most recent first."`
	OtherAgents       []agentPeerOutput         `json:"other_agents" jsonschema:"Other agents with a live session in this repository right now."`
}
type heldReservationOutput struct {
	LeaseID     string                     `json:"lease_id"`
	Mode        string                     `json:"mode"`
	Selectors   []reservationSelectorInput `json:"selectors"`
	Fences      []fenceOutput              `json:"fences"`
	ExpiresInMS int64                      `json:"expires_in_ms" jsonschema:"Milliseconds left on this lease, measured by the daemon. Negative means it is already overdue."`
}
type inboxSummaryOutput struct {
	Unread               int               `json:"unread"`
	NeedsAcknowledgement int               `json:"needs_acknowledgement"`
	Recent               []inboxItemOutput `json:"recent"`
}
type inboxItemOutput struct {
	MessageID               string `json:"message_id"`
	ConversationID          string `json:"conversation_id"`
	From                    string `json:"from"`
	Subject                 string `json:"subject"`
	Read                    bool   `json:"read"`
	AcknowledgementRequired bool   `json:"acknowledgement_required"`
	Acknowledged            bool   `json:"acknowledged"`
	SentMSAgo               int64  `json:"sent_ms_ago"`
}
type agentConversationOutput struct {
	ConversationID   string `json:"conversation_id"`
	Topic            string `json:"topic"`
	Messages         int    `json:"messages"`
	LastMessageMSAgo int64  `json:"last_message_ms_ago"`
}
type agentPeerOutput struct {
	Name          string `json:"name"`
	ActorID       string `json:"actor_id"`
	LastSeenMSAgo int64  `json:"last_seen_ms_ago"`
}
type tokenInput struct {
	AgentToken string `json:"agent_token"`
}
type activeAgentOutput struct {
	Name       string `json:"name"`
	ActorID    string `json:"actor_id"`
	SessionID  string `json:"session_id"`
	LastSeenAt string `json:"last_seen_at"`
}
type activeAgentsOutput struct {
	Agents []activeAgentOutput `json:"agents"`
}
type openConversationInput struct {
	AgentToken string `json:"agent_token"`
	Topic      string `json:"topic" jsonschema:"Short subject naming the one work item this conversation covers."`
	Slug       string `json:"slug,omitempty" jsonschema:"Stable name for this conversation, unique per repository. Opening the same slug again returns the conversation that already exists rather than a second one, so an agent that was restarted or compacted can rejoin the thread its teammates are already writing in. Omit it only for a thread nobody has to find again."`
}
type conversationOutput struct {
	ConversationID string `json:"conversation_id"`
	Topic          string `json:"topic" jsonschema:"Topic the conversation was opened with, which is the stored one rather than what this call asked for when reused is true."`
	Slug           string `json:"slug,omitempty"`
	Reused         bool   `json:"reused" jsonschema:"True when this slug already named a conversation and that one was returned. Read the thread with blackbird_thread_fetch before writing to it: it may already carry replies you have never seen."`
	OpenedAt       string `json:"opened_at"`
}
type sendMessageInput struct {
	AgentToken              string   `json:"agent_token"`
	ConversationID          string   `json:"conversation_id" jsonschema:"Conversation returned by blackbird_conversation_open."`
	To                      []string `json:"to" jsonschema:"Recipient agent names as registered, not actor IDs; blackbird_agents_list reports them."`
	Subject                 string   `json:"subject" jsonschema:"One line naming what this message is about."`
	Body                    string   `json:"body" jsonschema:"The message itself. Say what you did, what you need, and which paths are involved; the recipient may have none of your context."`
	ReplyToMessageID        string   `json:"reply_to_message_id,omitempty" jsonschema:"Message this answers, from an inbox or thread fetch. Omit only when starting a new exchange."`
	AcknowledgementRequired bool     `json:"acknowledgement_required,omitempty" jsonschema:"Require the recipient to acknowledge this exact body, not merely read it."`
}
type deliveryOutput struct {
	RecipientActorID string `json:"recipient_actor_id"`
	Kind             string `json:"kind"`
	Read             bool   `json:"read"`
	Acknowledged     bool   `json:"acknowledged"`
}
type messageOutput struct {
	MessageID      string           `json:"message_id"`
	ConversationID string           `json:"conversation_id"`
	AuthorActorID  string           `json:"author_actor_id"`
	Subject        string           `json:"subject"`
	Body           string           `json:"body"`
	BodyDigest     string           `json:"body_digest"`
	ReplyTo        string           `json:"reply_to,omitempty"`
	SentAt         string           `json:"sent_at"`
	Position       uint64           `json:"position"`
	Deliveries     []deliveryOutput `json:"deliveries"`
}
type fetchInboxInput struct {
	AgentToken string `json:"agent_token"`
	UnreadOnly bool   `json:"unread_only,omitempty" jsonschema:"Return only messages this agent has not marked read."`
	After      uint64 `json:"after,omitempty" jsonschema:"Resume after this position, from a previous page's next. Zero starts at the beginning."`
	Limit      uint16 `json:"limit,omitempty"`
}
type fetchThreadInput struct {
	AgentToken     string `json:"agent_token"`
	ConversationID string `json:"conversation_id" jsonschema:"Conversation to read, as returned by blackbird_conversation_open."`
	After          uint64 `json:"after,omitempty" jsonschema:"Resume after this position, from a previous page's next. Zero starts at the beginning."`
	Limit          uint16 `json:"limit,omitempty"`
}
type messagePageOutput struct {
	Messages []messageOutput `json:"messages"`
	Next     uint64          `json:"next"`
	HasMore  bool            `json:"has_more"`
}
type messageFactInput struct {
	AgentToken string `json:"agent_token"`
	MessageID  string `json:"message_id" jsonschema:"Message to record the fact against; it must be visible in this agent's inbox."`
	Kind       string `json:"kind" jsonschema:"read clears this delivery from unread inbox results; acknowledged confirms the exact stored body and also marks it read."`
}
type deliveryFactOutput struct {
	MessageID    string `json:"message_id"`
	Read         bool   `json:"read"`
	Acknowledged bool   `json:"acknowledged"`
}
type reservationSelectorInput struct {
	Kind string `json:"kind" jsonschema:"exact for the one named file, subtree for a directory and everything beneath it."`
	Path string `json:"path" jsonschema:"Repository-relative path the reservation covers."`
}
type reservationAcquireInput struct {
	AgentToken string                     `json:"agent_token"`
	Mode       string                     `json:"mode,omitempty" jsonschema:"shared or exclusive"`
	Selectors  []reservationSelectorInput `json:"selectors" jsonschema:"The paths to claim, narrowest first. Every selector is taken or none is."`
	TTLSeconds uint32                     `json:"ttl_seconds,omitempty"`
}

// fenceOutput is both a result and an argument, so its descriptions have to read
// correctly in either direction.
type fenceOutput struct {
	ConflictKey string `json:"conflict_key" jsonschema:"Opaque key naming one contended path; send it back unchanged when renewing or releasing."`
	Counter     uint64 `json:"counter" jsonschema:"Fencing counter for that key. Renew and release must carry the value from the most recent acquire or renew; a stale one is rejected."`
}
type reservationChangeInput struct {
	AgentToken string        `json:"agent_token"`
	LeaseID    string        `json:"lease_id" jsonschema:"Lease returned by blackbird_reservation_acquire."`
	Fences     []fenceOutput `json:"fences" jsonschema:"The lease's current fences, from the most recent acquire or change."`
	Action     string        `json:"action" jsonschema:"renew extends the reservation and returns replacement fences; release gives it up immediately."`
	TTLSeconds uint32        `json:"ttl_seconds,omitempty" jsonschema:"New lifetime for a renew action. Omit for release."`
}
type reservationOutput struct {
	LeaseID    string                     `json:"lease_id"`
	Mode       string                     `json:"mode"`
	Selectors  []reservationSelectorInput `json:"selectors"`
	Fences     []fenceOutput              `json:"fences"`
	ExpiresAt  string                     `json:"expires_at"`
	ReleasedAt string                     `json:"released_at,omitempty"`
}
type reservationsStatusInput struct {
	AgentToken string `json:"agent_token"`
	Path       string `json:"path,omitempty" jsonschema:"Repository-relative path to ask about. Only leases whose selectors cover it are reported, matched on directory boundaries, so a subtree lease counts for every file under it. Omit to see every active lease in the repository."`
	Limit      uint16 `json:"limit,omitempty"`
}
type reservationsStatusOutput struct {
	Reservations []reservationHolderOutput `json:"reservations" jsonschema:"Leases active right now in this repository, longest remaining first. Your own leases are included; compare holder_agent_name with the name you registered."`
	Truncated    bool                      `json:"truncated" jsonschema:"True when more leases matched than limit returned. Narrow the answer with path rather than raising limit."`
}

// reservationHolderOutput is one active lease seen from outside: who holds it,
// what it covers, and how long it has left. The remaining time is computed by
// the daemon, so a caller with a skewed clock still waits the right amount.
type reservationHolderOutput struct {
	LeaseID         string                     `json:"lease_id"`
	HolderAgentName string                     `json:"holder_agent_name" jsonschema:"Registered name of the agent holding this lease. Address it with blackbird_message_send. Empty only when the holder registered no name, in which case holder_actor_id is its whole identity."`
	HolderActorID   string                     `json:"holder_actor_id"`
	Mode            string                     `json:"mode" jsonschema:"shared or exclusive. A shared lease blocks only an exclusive acquisition; an exclusive one blocks every overlapping acquisition."`
	Selectors       []reservationSelectorInput `json:"selectors" jsonschema:"Paths this lease covers."`
	ExpiresInMS     int64                      `json:"expires_in_ms" jsonschema:"Milliseconds until this lease expires, measured by the daemon. Negative means it is already overdue and the next acquisition will sweep it."`
}
type coordinationWaitInput struct {
	AgentToken     string `json:"agent_token"`
	Path           string `json:"path,omitempty" jsonschema:"Repository-relative path to wait on. The wait ends when no lease held by anyone else conflicts with taking it in mode. Your own leases never block you."`
	Mode           string `json:"mode,omitempty" jsonschema:"The lease you intend to take once the path frees up. shared waits only for exclusive holders to leave; exclusive waits for every overlapping lease. Defaults to exclusive, which never reports a path free earlier than an acquisition would find it."`
	AwaitMail      bool   `json:"await_mail,omitempty" jsonschema:"End the wait when a message addressed to you arrives. Set it alongside path to take whichever happens first, or alone to park until a teammate answers."`
	TimeoutSeconds uint32 `json:"timeout_seconds,omitempty" jsonschema:"How long to wait before giving up and answering deadline. The daemon caps this; a larger value is clamped, not rejected."`
}
type coordinationWaitOutput struct {
	Reason            string                    `json:"reason" jsonschema:"Which condition ended the wait: path_free, mail_arrived, or deadline. Branch on this rather than on the other fields."`
	WaitedMS          int64                     `json:"waited_ms"`
	PendingDeliveries int                       `json:"pending_deliveries" jsonschema:"Unread deliveries in your inbox when the wait ended; read them with blackbird_inbox_fetch."`
	Blockers          []reservationHolderOutput `json:"blockers" jsonschema:"Leases still covering path when the wait ended. Empty on path_free; on deadline these are the holders to negotiate with."`
}

// coordinationFailureOutput is the machine-readable half of a failed
// coordination tool call. The SDK flattens a returned Go error into a bare
// string, which costs an agent everything it could have branched on: a lease
// conflict and an expired token arrive looking identical, so the only strategy
// left is to give up or to retry something that can never succeed. Every field
// here is the daemon's own answer to "what happened and what do I do now".
type coordinationFailureOutput struct {
	RequestID    string                    `json:"request_id" jsonschema:"Identifier for this failure in the daemon's log. Quote it when reporting a Blackbird bug."`
	Code         string                    `json:"code" jsonschema:"Stable failure code, for example LEASE_CONFLICT, UNAUTHENTICATED or NOT_FOUND. Branch on this."`
	Category     string                    `json:"category" jsonschema:"Family the code belongs to: validation, authentication, conflict, contention, capacity, timeout or internal."`
	Message      string                    `json:"message"`
	Retryable    bool                      `json:"retryable" jsonschema:"True when repeating the same call can succeed later. False means the call cannot work as sent; change something first."`
	Conflict     string                    `json:"conflict,omitempty" jsonschema:"Which conflict was detected, when the failure is one. LeaseConflict means someone else holds the path; FenceConflict means your fences are stale, so re-acquire; LeaseTerminalConflict means your lease is gone."`
	RetryAfterMS int64                     `json:"retry_after_ms,omitempty" jsonschema:"How long to wait before retrying, when the daemon can say. On a lease conflict this is the blocking lease's remaining time; blackbird_wait spends it for you."`
	Blockers     []reservationHolderOutput `json:"blockers,omitempty" jsonschema:"Leases that caused a LEASE_CONFLICT: who holds the path and for how much longer. Message a holder, wait with blackbird_wait, or narrow your selectors to a disjoint path."`
}

// blockedError decorates a lease conflict with the reservations that caused it.
// The conflict on its own tells an agent only that it lost the race, which
// leaves retrying blindly as the one available move; the holder and the time
// left are what turn it into a decision.
type blockedError struct {
	cause    error
	blockers []reservationHolderOutput
}

func (blocked *blockedError) Error() string { return blocked.cause.Error() }
func (blocked *blockedError) Unwrap() error { return blocked.cause }

func registerCoordinationTools(server *sdkmcp.Server, store application.LocalCoordinationStore, logger *slog.Logger) {
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolAgentRegister,
		Description: "Call this first. Read blackbird://coordination/protocol for the complete workflow. " +
			"Start or resume a durable local agent session for a repository key and agent name. " +
			"The result reports the state already bound to this agent: the reservations it still holds and " +
			"the time left on each, its unread and unacknowledged mail, its open conversations, and the other " +
			"agents present. A resuming agent must act on the reservations it is handed back."},
		func(ctx context.Context, input registerAgentInput) (agentSessionOutput, error) {
			token := ""
			if input.RegistrationToken != nil {
				token = *input.RegistrationToken
			}
			session, issued, err := store.RegisterLocalAgent(ctx, input.ProjectKey, input.AgentName, token)
			if err != nil {
				return agentSessionOutput{}, err
			}
			snapshot, err := store.LocalAgentSnapshot(ctx, session)
			if err != nil {
				return agentSessionOutput{}, err
			}
			return localAgentSessionOutput(session, issued, snapshot), nil
		})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolAgentsList,
		Description: "List agent sessions active in the caller's repository. Use it to learn the names " +
			"blackbird_message_send addresses; use blackbird_reservations_status to learn what they are holding.",
		InputSchema: coordinationInputSchema[tokenInput]()},
		func(ctx context.Context, input tokenInput) (activeAgentsOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return activeAgentsOutput{}, err
			}
			agents, err := store.ListActiveLocalAgents(ctx, session)
			if err != nil {
				return activeAgentsOutput{}, err
			}
			output := activeAgentsOutput{Agents: make([]activeAgentOutput, 0, len(agents))}
			for _, agent := range agents {
				output.Agents = append(output.Agents, activeAgentOutput{Name: agent.Name, ActorID: agent.ActorID.String(),
					SessionID: agent.SessionID.String(), LastSeenAt: agent.LastSeenAt.Format(time.RFC3339Nano)})
			}
			return output, nil
		})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolConversationOpen,
		Description: "Open a durable conversation in the caller's repository, one per work item. " +
			"Pass a slug to make it findable again: reopening the same slug returns the same conversation " +
			"rather than a second one, which is how an agent that restarted or was compacted rejoins the " +
			"thread instead of stranding every reply its teammates already wrote. Check reused in the result.",
		InputSchema: coordinationInputSchema[openConversationInput]()},
		func(ctx context.Context, input openConversationInput) (conversationOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return conversationOutput{}, err
			}
			id, err := domain.NewConversationID()
			if err != nil {
				return conversationOutput{}, err
			}
			value, err := store.OpenConversation(ctx, application.OpenConversationParams{ConversationID: id,
				WorkspaceID: session.WorkspaceID, RunID: session.RunID, OpenedBy: session.ActorID,
				OpenedBySession: session.ActorSessionID, Topic: input.Topic, Slug: input.Slug})
			if err != nil {
				return conversationOutput{}, err
			}
			// The caller never sees the identifier this call proposed, so the
			// store's "a reused open returns a different ID" signal has to be
			// read here or it reaches nobody.
			return conversationOutput{ConversationID: value.ID().String(), Topic: value.Topic(), Slug: value.Slug(),
				Reused: value.ID() != id, OpenedAt: value.OpenedAt().Format(time.RFC3339Nano)}, nil
		})
	messageInputSchema := coordinationInputSchema[sendMessageInput](func(properties map[string]*jsonschema.Schema) {
		properties["acknowledgement_required"].Default = json.RawMessage("false")
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolMessageSend,
		Description: "Send a durable message to named agents inside a conversation. Set reply_to_message_id " +
			"when continuing an exchange so the thread stays readable as one story; omit it only to raise " +
			"something new. Recipients are the names blackbird_agents_list reports. Set acknowledgement_required " +
			"only when your work cannot proceed until the recipient confirms this exact body -- recording that " +
			"acknowledgement is theirs to do, never yours.",
		InputSchema: messageInputSchema},
		func(ctx context.Context, input sendMessageInput) (messageOutput, error) {
			return sendLocalMessage(ctx, store, input)
		})
	inboxInputSchema := coordinationInputSchema[fetchInboxInput](func(properties map[string]*jsonschema.Schema) {
		properties["unread_only"].Default = json.RawMessage("false")
		properties["after"].Default = json.RawMessage("0")
		setPageLimitSchema(properties["limit"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolInboxFetch,
		Description: "Read the messages addressed to you. Use unread_only for what still needs attention and " +
			"omit it to re-read what you have already handled; page with next from the previous answer. Record " +
			"what you acted on with blackbird_message_fact kind=read, or the same messages come back forever. " +
			"To wait for mail rather than poll for it, use blackbird_wait.",
		InputSchema: inboxInputSchema},
		func(ctx context.Context, input fetchInboxInput) (messagePageOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return messagePageOutput{}, err
			}
			page, err := store.Inbox(ctx, application.InboxQuery{WorkspaceID: session.WorkspaceID, Recipient: session.ActorID,
				After: input.After, Limit: input.Limit, UnreadOnly: input.UnreadOnly})
			if err != nil {
				return messagePageOutput{}, err
			}
			return coordinationPageOutput(page), nil
		})
	threadInputSchema := coordinationInputSchema[fetchThreadInput](func(properties map[string]*jsonschema.Schema) {
		properties["after"].Default = json.RawMessage("0")
		setPageLimitSchema(properties["limit"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolThreadFetch,
		Description: "Read one conversation in order, from a position you pass. Prefer it over " +
			"blackbird_inbox_fetch when you need the context around a message rather than what is waiting for " +
			"you: it shows the whole exchange, including messages addressed to someone else.",
		InputSchema: threadInputSchema},
		func(ctx context.Context, input fetchThreadInput) (messagePageOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return messagePageOutput{}, err
			}
			conversation, err := domain.ParseConversationID(input.ConversationID)
			if err != nil {
				return messagePageOutput{}, application.ErrInvalidCoordination
			}
			page, err := store.Thread(ctx, application.ThreadQuery{WorkspaceID: session.WorkspaceID, ConversationID: conversation,
				Viewer: session.ActorID, After: input.After, Limit: input.Limit})
			if err != nil {
				return messagePageOutput{}, err
			}
			return coordinationPageOutput(page), nil
		})
	registerDeliveryFactTool(server, logger, store)
	registerReservationTools(server, store, logger)
}

// coordinationTool registers one local-coordination tool with the failure path
// every agent-facing tool needs. Handing the SDK a raw Go error flattens it to a
// bare string: the code, the category, the conflict kind and the retry posture
// the domain built are all still in the error and none of them reach the agent,
// which is the difference between "wait for this holder" and "give up". The
// result schema publishes both shapes, so a client can see what a failure looks
// like without provoking one.
func coordinationTool[Input, Output any](server *sdkmcp.Server, logger *slog.Logger, tool *sdkmcp.Tool,
	handle func(context.Context, Input) (Output, error),
) {
	name := tool.Name
	// The concrete Output type would make the SDK infer and publish a full
	// outputSchema for every tool. Results are already serialized into both
	// structuredContent and the text fallback, so advertise only the input
	// contract and keep the repeated result shapes out of every tools/list.
	sdkmcp.AddTool[Input, any](server, tool, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input Input) (*sdkmcp.CallToolResult, any, error) {
		output, err := handle(ctx, input)
		if err == nil {
			return nil, output, nil
		}
		failure := coordinationFailure(newRequestID(), err)
		// The record keeps the cause chain the sanitized message drops, which is
		// the only place a storage-level cause is ever written down.
		logger.Error("mcp coordination tool failed", slog.String("tool", name),
			slog.String("request_id", failure.RequestID), slog.String("code", failure.Code),
			slog.Any("error", err))
		return &sdkmcp.CallToolResult{IsError: true,
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: failure.Code + ": " + failure.Message}}}, failure, nil
	})
}

// coordinationFailure maps a coordination error the way the loopback HTTP
// surface does, so the two transports cannot disagree about what a failure is:
// a domain command error keeps its own code, category, conflict and retry
// posture; an invalid request is an argument failure; anything else is
// internal and says nothing further, because whatever it is was not meant to
// leave the daemon.
func coordinationFailure(requestID string, err error) coordinationFailureOutput {
	failure := coordinationFailureOutput{RequestID: requestID, Code: string(domain.ErrorCodeInternal),
		Category: string(domain.ErrorCategoryInternal), Message: "request could not be completed",
		Retryable: domain.ErrorCodeInternal.DefaultRetryable()}
	var commandError *domain.CommandError
	switch {
	case errors.As(err, &commandError):
		failure.Code, failure.Category = string(commandError.Code()), string(commandError.Category())
		failure.Retryable = commandError.Retryable()
		failure.Message = commandError.Message()
		if failure.Message == "" {
			failure.Message = commandError.Error()
		}
		if conflict, isConflict := commandError.ConflictKind(); isConflict {
			failure.Conflict = string(conflict)
		}
	case errors.Is(err, application.ErrInvalidCoordination):
		failure.Code, failure.Category = string(domain.ErrorCodeInvalidArgument), string(domain.ErrorCategoryValidation)
		failure.Message, failure.Retryable = "coordination request is invalid", false
	}
	var blocked *blockedError
	if errors.As(err, &blocked) {
		failure.Blockers = blocked.blockers
		failure.RetryAfterMS = soonestExpiry(blocked.blockers)
	}
	return failure
}

// soonestExpiry is how long the caller has to wait for the first blocking lease
// to lapse, which is the shortest wait that can possibly clear the conflict. A
// shorter one retries into the same refusal; a longer one idles past the moment
// the path came free. An overdue lease asks for no wait at all: the next
// acquisition sweeps it.
func soonestExpiry(blockers []reservationHolderOutput) int64 {
	soonest := int64(0)
	for _, blocker := range blockers {
		if blocker.ExpiresInMS <= 0 {
			return 0
		}
		if soonest == 0 || blocker.ExpiresInMS < soonest {
			soonest = blocker.ExpiresInMS
		}
	}
	return soonest
}

func sendLocalMessage(ctx context.Context, store application.LocalCoordinationStore, input sendMessageInput) (messageOutput, error) {
	session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
	if err != nil {
		return messageOutput{}, err
	}
	conversation, err := domain.ParseConversationID(input.ConversationID)
	if err != nil {
		return messageOutput{}, application.ErrInvalidCoordination
	}
	actors, err := store.ResolveLocalAgentNames(ctx, session, input.To)
	if err != nil {
		return messageOutput{}, err
	}
	recipients := make([]application.Recipient, 0, len(actors))
	for _, actor := range actors {
		recipient, recipientErr := application.NewRecipient(actor, application.RecipientTo)
		if recipientErr != nil {
			return messageOutput{}, recipientErr
		}
		recipients = append(recipients, recipient)
	}
	messageID, err := domain.NewMessageID()
	if err != nil {
		return messageOutput{}, err
	}
	params := application.SendMessageParams{MessageID: messageID, ConversationID: conversation,
		WorkspaceID: session.WorkspaceID, Author: session.ActorID, AuthorSession: session.ActorSessionID,
		Subject: input.Subject, Body: input.Body, Recipients: recipients,
		AcknowledgementRequired: input.AcknowledgementRequired}
	if input.ReplyToMessageID != "" {
		reply, parseErr := domain.ParseMessageID(input.ReplyToMessageID)
		if parseErr != nil {
			return messageOutput{}, application.ErrInvalidCoordination
		}
		params.ReplyTo = &reply
	}
	message, err := store.SendMessage(ctx, params)
	if err != nil {
		return messageOutput{}, err
	}
	return localMessageOutput(message), nil
}

// localAgentSessionOutput turns every instant in the snapshot into an age
// measured by the daemon. An absolute timestamp would make the client's own
// clock part of the answer, and a compacted agent restarting on a machine whose
// clock has drifted would read a live reservation as long expired.
func localAgentSessionOutput(session application.LocalAgentSession, issued string,
	snapshot application.LocalAgentSnapshot) agentSessionOutput {
	output := agentSessionOutput{ProjectKey: session.ProjectKey, AgentName: session.AgentName,
		WorkspaceID: session.WorkspaceID.String(), ActorID: session.ActorID.String(),
		SessionID: session.ActorSessionID.String(), RegistrationToken: issued,
		HeldReservations: make([]heldReservationOutput, 0, len(snapshot.Reservations)),
		Inbox: inboxSummaryOutput{Unread: snapshot.Inbox.UnreadDeliveries,
			NeedsAcknowledgement: snapshot.Inbox.UnackedDeliveries,
			Recent:               make([]inboxItemOutput, 0, len(snapshot.Inbox.Recent))},
		OpenConversations: make([]agentConversationOutput, 0, len(snapshot.Conversations)),
		OtherAgents:       make([]agentPeerOutput, 0, len(snapshot.Peers))}
	for _, reservation := range snapshot.Reservations {
		held := heldReservationOutput{LeaseID: reservation.LeaseID.String(), Mode: string(reservation.Mode),
			ExpiresInMS: reservation.ExpiresInMS, Selectors: []reservationSelectorInput{}, Fences: []fenceOutput{}}
		for _, selector := range reservation.Selectors {
			held.Selectors = append(held.Selectors, reservationSelectorInput{Kind: string(selector.Kind()), Path: selector.Path()})
		}
		for _, fence := range reservation.Fences {
			held.Fences = append(held.Fences, fenceOutput{ConflictKey: fence.ConflictKey(), Counter: fence.Counter()})
		}
		output.HeldReservations = append(output.HeldReservations, held)
	}
	for _, item := range snapshot.Inbox.Recent {
		output.Inbox.Recent = append(output.Inbox.Recent, inboxItemOutput{MessageID: item.MessageID.String(),
			ConversationID: item.ConversationID.String(), From: item.AuthorAgentName, Subject: item.Subject,
			Read: item.Read, AcknowledgementRequired: item.AcknowledgementRequired, Acknowledged: item.Acknowledged,
			SentMSAgo: elapsedMS(snapshot.ObservedAtUS, item.SentAtUS)})
	}
	for _, conversation := range snapshot.Conversations {
		output.OpenConversations = append(output.OpenConversations, agentConversationOutput{
			ConversationID: conversation.ConversationID.String(), Topic: conversation.Topic,
			Messages:         conversation.Messages,
			LastMessageMSAgo: elapsedMS(snapshot.ObservedAtUS, conversation.LastMessageAtUS)})
	}
	for _, peer := range snapshot.Peers {
		output.OtherAgents = append(output.OtherAgents, agentPeerOutput{Name: peer.Name, ActorID: peer.ActorID.String(),
			LastSeenMSAgo: elapsedMS(snapshot.ObservedAtUS, application.MicrosFromTime(peer.LastSeenAt))})
	}
	return output
}

// elapsedMS reports how long before the snapshot an instant fell. A zero
// instant means "absent" in every projection that feeds this, and reporting the
// whole Unix epoch for it would be worse than reporting nothing.
func elapsedMS(observedAtUS, instantUS int64) int64 {
	if instantUS == 0 {
		return 0
	}
	return (observedAtUS - instantUS) / 1000
}

func coordinationPageOutput(page application.CoordinationPage) messagePageOutput {
	messages := page.Messages()
	result := messagePageOutput{Messages: make([]messageOutput, 0, len(messages)), Next: page.NextCursor(), HasMore: page.HasMore()}
	for _, message := range messages {
		result.Messages = append(result.Messages, localMessageOutput(message))
	}
	return result
}

func localMessageOutput(message application.Message) messageOutput {
	digest := message.Digest()
	result := messageOutput{MessageID: message.ID().String(), ConversationID: message.ConversationID().String(),
		AuthorActorID: message.Author().String(), Subject: message.Subject(), Body: message.Body(), BodyDigest: hex.EncodeToString(digest[:]),
		SentAt: message.SentAt().Format(time.RFC3339Nano), Position: message.Position(), Deliveries: []deliveryOutput{}}
	if reply := message.ReplyTo(); reply != nil {
		result.ReplyTo = reply.String()
	}
	for _, delivery := range message.Deliveries() {
		_, read := delivery.ReadAt()
		_, acknowledged := delivery.AcknowledgedAt()
		result.Deliveries = append(result.Deliveries, deliveryOutput{RecipientActorID: delivery.Recipient().ActorID().String(),
			Kind: string(delivery.Recipient().Kind()), Read: read, Acknowledged: acknowledged})
	}
	return result
}

func registerDeliveryFactTool(server *sdkmcp.Server, logger *slog.Logger,
	store application.LocalCoordinationStore) {
	inputSchema := coordinationInputSchema[messageFactInput](func(properties map[string]*jsonschema.Schema) {
		properties["kind"].Enum = []any{string(application.DeliveryRead), string(application.DeliveryAcknowledged)}
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolMessageFact,
		Description: "Record a fact about your own message delivery. kind=read clears it from unread inbox " +
			"results without promising anything about the body. kind=acknowledged confirms the exact stored body " +
			"when the sender required a commitment and marks it read at the same time. Never record a fact for " +
			"another agent.", InputSchema: inputSchema},
		func(ctx context.Context, input messageFactInput) (deliveryFactOutput, error) {
			kind := application.DeliveryFactKind(input.Kind)
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return deliveryFactOutput{}, err
			}
			messageID, err := domain.ParseMessageID(input.MessageID)
			if err != nil {
				return deliveryFactOutput{}, application.ErrInvalidCoordination
			}
			params := application.RecordDeliveryFactParams{WorkspaceID: session.WorkspaceID, MessageID: messageID,
				Recipient: session.ActorID, ActorSessionID: &session.ActorSessionID, Kind: kind}
			if kind == application.DeliveryAcknowledged {
				// An acknowledgement is a promise about the exact stored body, so the
				// digest is read back from the message rather than taken on trust.
				message, findErr := store.GetVisibleMessage(ctx, session.WorkspaceID, session.ActorID, messageID)
				if findErr != nil {
					return deliveryFactOutput{}, findErr
				}
				params.MessageDigest = message.Digest()
			}
			delivery, err := store.RecordDeliveryFact(ctx, params)
			if err != nil {
				return deliveryFactOutput{}, err
			}
			_, read := delivery.ReadAt()
			_, acknowledged := delivery.AcknowledgedAt()
			return deliveryFactOutput{MessageID: input.MessageID, Read: read, Acknowledged: acknowledged}, nil
		})
}

func registerReservationTools(server *sdkmcp.Server, store application.LocalCoordinationStore, logger *slog.Logger) {
	acquireInputSchema := coordinationInputSchema[reservationAcquireInput](func(properties map[string]*jsonschema.Schema) {
		properties["mode"].Default = json.RawMessage(`"exclusive"`)
		properties["mode"].Enum = []any{string(application.LeaseShared), string(application.LeaseExclusive)}
		setSelectorKindSchema(properties["selectors"].Items.Properties["kind"])
		setTTLSchema(properties["ttl_seconds"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolReservationAcquire,
		Description: "Claim shared or exclusive file reservations before editing, naming the narrowest paths " +
			"that cover the work. A LEASE_CONFLICT failure carries the blocking holders and how long they have " +
			"left: wait for one with blackbird_wait, negotiate with blackbird_message_send, or narrow to a " +
			"disjoint path. Never widen a selector to get past a conflict. Use blackbird_reservation_change to " +
			"release as soon as the edit lands or to renew before the lease expires.",
		InputSchema: acquireInputSchema},
		func(ctx context.Context, input reservationAcquireInput) (reservationOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return reservationOutput{}, err
			}
			selectors := make([]application.LeaseSelector, 0, len(input.Selectors))
			for _, raw := range input.Selectors {
				selector, selectorErr := application.NewLeaseSelector(application.LeaseSelectorKind(raw.Kind), raw.Path)
				if selectorErr != nil {
					return reservationOutput{}, selectorErr
				}
				selectors = append(selectors, selector)
			}
			leaseID, err := domain.NewLeaseID()
			if err != nil {
				return reservationOutput{}, err
			}
			mode := application.LeaseMode(input.Mode)
			lease, err := store.AcquireLease(ctx, application.AcquireLeaseParams{LeaseID: leaseID,
				WorkspaceID: session.WorkspaceID, Holder: session.ActorID, HolderSession: session.ActorSessionID,
				AuthorityEpoch: session.AuthorityEpoch, Mode: mode, Selectors: selectors,
				TTL: time.Duration(input.TTLSeconds) * time.Second})
			if err != nil {
				return reservationOutput{}, describeLeaseConflict(ctx, store, session, mode, selectors, err)
			}
			return localReservationOutput(lease), nil
		})
	changeInputSchema := coordinationInputSchema[reservationChangeInput](func(properties map[string]*jsonschema.Schema) {
		properties["action"].Enum = []any{"renew", "release"}
		setChangeTTLSchema(properties["ttl_seconds"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolReservationChange,
		Description: "Renew or release a reservation you already hold, using the fences from the most recent " +
			"acquire or change. action=renew extends work that outlives its lease and returns replacement fences. " +
			"action=release gives the reservation up immediately and must omit ttl_seconds. A FENCE_REJECTED " +
			"failure means the lease moved on without you: acquire it again rather than retrying.",
		InputSchema: changeInputSchema},
		func(ctx context.Context, input reservationChangeInput) (reservationOutput, error) {
			return changeLocalReservation(ctx, store, input)
		})
	statusInputSchema := coordinationInputSchema[reservationsStatusInput](func(properties map[string]*jsonschema.Schema) {
		setPageLimitSchema(properties["limit"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolReservationsStatus,
		Description: "Report which file reservations are active in this repository right now: the holder's " +
			"agent name, the paths, the mode, and the time left on each lease. This is the answer to \"who is " +
			"blocking me\" -- pass the path you wanted to see only the leases covering it. It reads and returns " +
			"immediately: use blackbird_wait instead when you mean to queue behind a lease, and this when you " +
			"mean to decide whom to talk to or what else to work on first.",
		InputSchema: statusInputSchema},
		func(ctx context.Context, input reservationsStatusInput) (reservationsStatusOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return reservationsStatusOutput{}, err
			}
			page, err := store.LocalAgentReservations(ctx, session, application.AdminReservationsQuery{
				State: application.AdminReservationActive, Path: input.Path, Limit: input.Limit})
			if err != nil {
				return reservationsStatusOutput{}, err
			}
			return reservationsStatusOutput{Reservations: reservationHolders(page.Reservations),
				Truncated: page.Truncated}, nil
		})
	waitInputSchema := coordinationInputSchema[coordinationWaitInput](func(properties map[string]*jsonschema.Schema) {
		properties["await_mail"].Default = json.RawMessage("false")
		properties["mode"].Default = json.RawMessage(`"exclusive"`)
		properties["mode"].Enum = []any{string(application.LeaseShared), string(application.LeaseExclusive)}
		setWaitTimeoutSchema(properties["timeout_seconds"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolWait,
		Description: "Wait until a path stops being reserved, until mail arrives for you, or until the timeout " +
			"-- whichever comes first -- and report which in reason. Prefer it over calling " +
			"blackbird_reservation_acquire again in a loop after a LEASE_CONFLICT, and over re-fetching your " +
			"inbox while a handoff is outstanding. Set path, await_mail, or both; a call that sets neither is " +
			"rejected. On path_free acquire straight away, because another agent may be waiting on the same " +
			"path; on mail_arrived read the inbox; on deadline the blockers are still reported, so message a " +
			"holder or work elsewhere rather than waiting again.",
		InputSchema: waitInputSchema},
		func(ctx context.Context, input coordinationWaitInput) (coordinationWaitOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return coordinationWaitOutput{}, err
			}
			result, err := store.AwaitCoordination(ctx, session, application.CoordinationWaitRequest{
				Path: input.Path, Mode: application.LeaseMode(input.Mode), AwaitMail: input.AwaitMail,
				Timeout: boundedWaitTimeout(input.TimeoutSeconds)})
			if err != nil {
				return coordinationWaitOutput{}, err
			}
			return coordinationWaitOutput{Reason: string(result.Reason), WaitedMS: result.WaitedMS,
				PendingDeliveries: result.PendingDeliveries,
				Blockers:          reservationHolders(result.Blockers)}, nil
		})
}

// boundedWaitTimeout clamps the budget at the transport edge as well as in the
// store. A schema maximum binds only a client that validates against it, and
// this hold is on the daemon's own goroutine and on the caller's turn: a wait
// that outlives the client's request timeout is indistinguishable from a hung
// daemon. Zero, and anything beyond the ceiling, asks for the ceiling.
func boundedWaitTimeout(seconds uint32) time.Duration {
	requested := time.Duration(seconds) * time.Second
	if requested <= 0 || requested > application.MaxCoordinationWait {
		return application.MaxCoordinationWait
	}
	return requested
}

// describeLeaseConflict attaches the holders behind a lease conflict. The
// evidence is best effort by design: the refusal is already the answer, and a
// failed follow-up read must not turn a conflict the caller can act on into an
// internal error it cannot.
func describeLeaseConflict(ctx context.Context, store application.LocalCoordinationStore,
	session application.LocalAgentSession, mode application.LeaseMode, selectors []application.LeaseSelector, cause error) error {
	if !errors.Is(cause, domain.ErrLeaseConflict) {
		return cause
	}
	queryMode := application.LeaseMode("")
	if mode == application.LeaseShared {
		queryMode = application.LeaseExclusive
	}
	blockers := make([]reservationHolderOutput, 0, len(selectors))
	seen := make(map[string]struct{}, len(selectors))
	for _, selector := range selectors {
		page, err := store.LocalAgentReservations(ctx, session, application.AdminReservationsQuery{
			State: application.AdminReservationActive, Mode: queryMode, Path: selector.Path(), Limit: maxCoordinationBlockers})
		if err != nil {
			return cause
		}
		for _, reservation := range page.Reservations {
			// The caller's own leases are never what blocked it: acquisition
			// supersedes those rather than refusing over them.
			if reservation.HolderActorID == session.ActorID {
				continue
			}
			if _, duplicate := seen[reservation.LeaseID.String()]; duplicate {
				continue
			}
			seen[reservation.LeaseID.String()] = struct{}{}
			blockers = append(blockers, reservationHolder(reservation))
			if len(blockers) == maxCoordinationBlockers {
				return &blockedError{cause: cause, blockers: blockers}
			}
		}
	}
	return &blockedError{cause: cause, blockers: blockers}
}

func reservationHolders(reservations []application.AdminReservation) []reservationHolderOutput {
	holders := make([]reservationHolderOutput, 0, len(reservations))
	for _, reservation := range reservations {
		holders = append(holders, reservationHolder(reservation))
	}
	return holders
}

func reservationHolder(reservation application.AdminReservation) reservationHolderOutput {
	holder := reservationHolderOutput{LeaseID: reservation.LeaseID.String(),
		HolderAgentName: reservation.HolderAgentName, HolderActorID: reservation.HolderActorID.String(),
		Mode: string(reservation.Mode), ExpiresInMS: reservation.ExpiresInMS,
		Selectors: make([]reservationSelectorInput, 0, len(reservation.Selectors))}
	for _, selector := range reservation.Selectors {
		holder.Selectors = append(holder.Selectors, reservationSelectorInput{Kind: string(selector.Kind()), Path: selector.Path()})
	}
	return holder
}

// agentTokenDescription names the field's own source. Registration issues the
// value as registration_token and every other tool reads it back as
// agent_token, so without this a first call is a guaranteed schema rejection
// whose message never mentions the other name.
const agentTokenDescription = "The registration_token returned by blackbird_agent_register (same value, different field name)."

func coordinationInputSchema[Input any](configure ...func(map[string]*jsonschema.Schema)) *jsonschema.Schema {
	schema, err := jsonschema.For[Input](nil)
	if err != nil {
		panic(fmt.Sprintf("infer local coordination input schema: %v", err))
	}
	if token, ok := schema.Properties["agent_token"]; ok {
		token.Description = agentTokenDescription
	}
	for _, apply := range configure {
		apply(schema.Properties)
	}
	return schema
}

// setSelectorKindSchema turns the selector kind into a validated enum. As prose
// the field accepted any string, so an invented kind passed the schema and was
// rejected later with no hint that only two values exist.
func setSelectorKindSchema(schema *jsonschema.Schema) {
	schema.Enum = []any{string(application.LeaseSelectorExact), string(application.LeaseSelectorSubtree)}
	schema.Description = "exact reserves the one named file; subtree reserves the directory and everything beneath it. Prefer exact unless the edit genuinely spans a package."
}

func setPageLimitSchema(schema *jsonschema.Schema) {
	schema.Description = "Most entries to return in one answer."
	schema.Default = json.RawMessage(strconv.Itoa(defaultCoordinationPageLimit))
	schema.Minimum = jsonschema.Ptr(float64(1))
	schema.Maximum = jsonschema.Ptr(float64(application.MaxQueryPageSize))
}

func setTTLSchema(schema *jsonschema.Schema) {
	schema.Description = "How long the reservation lasts before it lapses on its own. Prefer a span the work really needs: everything overlapping it waits out the remainder if you abandon it."
	schema.Default = json.RawMessage(strconv.Itoa(defaultReservationTTLSeconds))
	schema.Minimum = jsonschema.Ptr(float64(1))
	schema.Maximum = jsonschema.Ptr(application.MaxLeaseTTL.Seconds())
}

// A combined renew/release input cannot publish a TTL default: SDK defaulting
// would attach it to release calls too, turning every valid release into an
// invalid one. The handler applies the same default only after seeing renew.
func setChangeTTLSchema(schema *jsonschema.Schema) {
	schema.Description = "New lifetime for action=renew; omit it for action=release. An omitted renew uses 3600 seconds."
	schema.Minimum = jsonschema.Ptr(float64(1))
	schema.Maximum = jsonschema.Ptr(application.MaxLeaseTTL.Seconds())
}

// setWaitTimeoutSchema states the ceiling the daemon enforces anyway, so a
// client discovers the bound instead of learning it from a budget that came
// back shorter than it asked for. The schema is documentation, not the guard;
// boundedWaitTimeout is the guard.
func setWaitTimeoutSchema(schema *jsonschema.Schema) {
	ceiling := application.MaxCoordinationWait.Seconds()
	schema.Default = json.RawMessage(strconv.Itoa(int(ceiling)))
	schema.Minimum = jsonschema.Ptr(float64(1))
	schema.Maximum = jsonschema.Ptr(ceiling)
}

func changeLocalReservation(ctx context.Context, store application.LocalCoordinationStore,
	input reservationChangeInput) (reservationOutput, error) {
	if input.Action == "release" && input.TTLSeconds != 0 {
		return reservationOutput{}, application.ErrInvalidCoordination
	}
	if input.Action == "renew" && input.TTLSeconds == 0 {
		input.TTLSeconds = defaultReservationTTLSeconds
	}
	session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
	if err != nil {
		return reservationOutput{}, err
	}
	leaseID, err := domain.ParseLeaseID(input.LeaseID)
	if err != nil {
		return reservationOutput{}, application.ErrInvalidCoordination
	}
	fences := make([]application.Fence, 0, len(input.Fences))
	for _, raw := range input.Fences {
		fence, fenceErr := application.NewFence(raw.ConflictKey, raw.Counter)
		if fenceErr != nil {
			return reservationOutput{}, fenceErr
		}
		fences = append(fences, fence)
	}
	params := application.ChangeLeaseParams{LeaseID: leaseID, HolderSession: session.ActorSessionID,
		AuthorityEpoch: session.AuthorityEpoch, Fences: fences, TTL: time.Duration(input.TTLSeconds) * time.Second}
	var lease application.Lease
	switch input.Action {
	case "renew":
		lease, err = store.RenewLease(ctx, params)
	case "release":
		lease, err = store.ReleaseLease(ctx, params)
	default:
		return reservationOutput{}, application.ErrInvalidCoordination
	}
	if err != nil {
		return reservationOutput{}, err
	}
	return localReservationOutput(lease), nil
}

func localReservationOutput(lease application.Lease) reservationOutput {
	result := reservationOutput{LeaseID: lease.ID().String(), Mode: string(lease.Mode()), ExpiresAt: lease.ExpiresAt().Format(time.RFC3339Nano),
		Selectors: []reservationSelectorInput{}, Fences: []fenceOutput{}}
	for _, selector := range lease.Selectors() {
		result.Selectors = append(result.Selectors, reservationSelectorInput{Kind: string(selector.Kind()), Path: selector.Path()})
	}
	for _, fence := range lease.Fences() {
		result.Fences = append(result.Fences, fenceOutput{ConflictKey: fence.ConflictKey(), Counter: fence.Counter()})
	}
	if released, ok := lease.ReleasedAt(); ok {
		result.ReleasedAt = released.Format(time.RFC3339Nano)
	}
	return result
}

func (server *Server) NotifyContextChanged(ctx context.Context) error {
	return server.ResourceUpdated(ctx, &sdkmcp.ResourceUpdatedNotificationParams{URI: ResourceCurrentContext})
}

// HTTPHandler exposes this server through the official Streamable HTTP
// transport. A nil receiver remains fail-closed through the SDK's nil selector.
func (server *Server) HTTPHandler(options *sdkmcp.StreamableHTTPOptions) stdhttp.Handler {
	return sdkmcp.NewStreamableHTTPHandler(func(*stdhttp.Request) *sdkmcp.Server {
		if server == nil {
			return nil
		}
		return server.Server
	}, options)
}

type operationHandler[Request, Result any] func(context.Context, contracts.AuthenticationEvidence, Request) (Result, *contracts.ErrorDTO, error)

func registerCommand[Request, Result any](server *sdkmcp.Server, name, operation string, authenticator Authenticator,
	decode func([]byte) (Request, error), deadline func(Request) time.Time, handle operationHandler[Request, Result], validate func(Result) error,
) {
	registerTool(server, name, operation, authenticator, decode, deadline, handle, validate)
}

func registerQuery[Request, Result any](server *sdkmcp.Server, name, operation string, authenticator Authenticator,
	decode func([]byte) (Request, error), handle operationHandler[Request, Result], validate func(Result) error,
) {
	registerTool(server, name, operation, authenticator, decode, nil, handle, validate)
}

func registerTool[Request, Result any](server *sdkmcp.Server, name, operation string, authenticator Authenticator,
	decode func([]byte) (Request, error), deadline func(Request) time.Time, handle operationHandler[Request, Result], validate func(Result) error,
) {
	inputSchema, err := jsonschema.ForType(reflect.TypeFor[Request](), contractSchemaOptions())
	if err != nil {
		panic(fmt.Sprintf("infer MCP input schema for %s: %v", operation, err))
	}
	outputSchema, err := jsonschema.ForType(reflect.TypeFor[Result](), contractSchemaOptions())
	if err != nil {
		panic(fmt.Sprintf("infer MCP output schema for %s: %v", operation, err))
	}
	errorSchema, err := jsonschema.ForType(reflect.TypeFor[contracts.ErrorDTO](), contractSchemaOptions())
	if err != nil {
		panic(fmt.Sprintf("infer MCP error schema for %s: %v", operation, err))
	}
	semanticOutputSchema := &jsonschema.Schema{Type: "object", OneOf: []*jsonschema.Schema{outputSchema, errorSchema}}
	server.AddTool(&sdkmcp.Tool{
		Name: name, Description: operation + "; authorized, bounded, idempotent command/query with strict versioned input.",
		InputSchema: inputSchema, OutputSchema: semanticOutputSchema,
	}, func(ctx context.Context, request *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		transportRequestID := newRequestID()
		evidence, failure, authErr := authenticator.Authenticate(ctx, operation, transportRequestID)
		if authErr != nil || evidence.Valid() == (failure != nil) {
			return toolFailure(internalFailure(transportRequestID)), nil
		}
		if failure != nil {
			return toolFailure(checkedFailure(transportRequestID, failure)), nil
		}
		if request == nil || request.Params == nil || len(request.Params.Arguments) > contracts.MaxCommandJSONBytes {
			return toolFailure(invalidSchema(transportRequestID)), nil
		}
		input, decodeErr := decode(request.Params.Arguments)
		if decodeErr != nil {
			return toolFailure(invalidSchema(transportRequestID)), nil
		}
		requestID := requestIDOf(input, transportRequestID)
		if deadline != nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline(input))
			defer cancel()
		}
		result, failure, handleErr := handle(ctx, evidence, input)
		if handleErr != nil || failure != nil {
			if handleErr != nil || failure == nil {
				return toolFailure(internalFailure(requestID)), nil
			}
			return toolFailure(checkedFailure(requestID, failure)), nil
		}
		encoded, encodeErr := json.Marshal(result)
		if encodeErr != nil || len(encoded) > contracts.MaxOutcomeJSONBytes || validate(result) != nil || responseRequestID(result) != requestID {
			return toolFailure(internalFailure(requestID)), nil
		}
		return &sdkmcp.CallToolResult{
			Content:           []sdkmcp.Content{&sdkmcp.TextContent{Text: operation + " succeeded"}},
			StructuredContent: result,
		}, nil
	})
}

const coordinationProtocol = `# Blackbird coordination protocol

1. Call blackbird_agent_register with a repository key and stable agent name. Persist its registration_token. On restart, call it again with that token and act on every reservation, message, and conversation returned in the snapshot. Pass the same value as agent_token to every other tool.
2. Before editing, call blackbird_reservation_acquire with the narrowest exact files or subtree and an honest TTL. Shared claims coexist; an exclusive claim conflicts with every overlap.
3. Use one blackbird_conversation_open slug per work item. Address peers by the names from blackbird_agents_list. Read mail with blackbird_inbox_fetch or blackbird_thread_fetch and record only your own delivery facts with blackbird_message_fact.
4. On LEASE_CONFLICT, never retry blindly or widen the claim. Use the returned blockers or blackbird_reservations_status, then message the holder, narrow to a disjoint path, or call blackbird_wait once and reacquire when it returns path_free.
5. Before expiry, call blackbird_reservation_change with action=renew and the latest fences. As soon as the edit is done, call it with action=release. Always replace saved fences with the newest result.

Failures are structured. Branch on code and retryable; quote request_id in bug reports. Acknowledging a handoff is the recipient's action, never the sender's.
`

// registerCoordinationProtocol exposes the workflow before registration, when
// the caller has no token and project-local instructions may not exist. The
// tool descriptions remain the operation-level reference; this resource only
// supplies their order and the recovery rules that span calls.
func registerCoordinationProtocol(server *sdkmcp.Server) {
	server.AddResource(&sdkmcp.Resource{URI: ResourceCoordinationProtocol, Name: "Blackbird coordination protocol",
		MIMEType: mediaTypeMarkdown, Description: "Start, reserve, communicate, recover from conflicts, and release without relying on repository-local instructions."},
		func(_ context.Context, request *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
			if request == nil || request.Params == nil || request.Params.URI != ResourceCoordinationProtocol {
				return nil, sdkmcp.ResourceNotFoundError("")
			}
			return &sdkmcp.ReadResourceResult{Contents: []*sdkmcp.ResourceContents{{URI: ResourceCoordinationProtocol,
				MIMEType: mediaTypeMarkdown, Text: coordinationProtocol}}}, nil
		})
}

func registerResources(server *sdkmcp.Server, dependencies Dependencies) {
	handler := func(ctx context.Context, request *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
		if request == nil || request.Params == nil || len(request.Params.URI) > 8192 {
			return nil, sdkmcp.ResourceNotFoundError("")
		}
		uri, err := url.Parse(request.Params.URI)
		if err != nil || uri.Scheme != "blackbird" || uri.Host != "session" || uri.Path != "/current/context" && uri.Path != "/current/context-deltas" {
			return nil, sdkmcp.ResourceNotFoundError(request.Params.URI)
		}
		requestID := resourceRequestID(request.Params.URI)
		evidence, failure, authErr := dependencies.Authenticator.Authenticate(ctx, contracts.OperationContextGet, requestID)
		if authErr != nil || evidence.Valid() == (failure != nil) {
			return resourceResult(request.Params.URI, internalFailure(requestID))
		}
		if failure != nil {
			return resourceResult(request.Params.URI, checkedFailure(requestID, failure))
		}
		sessionID, failure, bindErr := dependencies.CurrentSession.CurrentActorSession(ctx, evidence, requestID)
		if bindErr != nil || failure != nil || sessionID.IsZero() {
			if bindErr != nil || failure == nil {
				return resourceResult(request.Params.URI, internalFailure(requestID))
			}
			return resourceResult(request.Params.URI, checkedFailure(requestID, failure))
		}
		limit := uint16(256)
		if rawLimit := uri.Query().Get("limit"); rawLimit != "" {
			parsed, parseErr := strconv.ParseUint(rawLimit, 10, 16)
			if parseErr != nil {
				return resourceResult(request.Params.URI, invalidSchema(requestID))
			}
			limit = uint16(parsed)
		}
		var cursor *string
		if rawCursor := uri.Query().Get("cursor"); rawCursor != "" {
			cursor = &rawCursor
		}
		query := contracts.ContextGetRequestDTO{Schema: contracts.SchemaContextGetRequest, RequestID: requestID,
			Operation: contracts.OperationContextGet, ActorSessionID: sessionID, Cursor: cursor, Limit: limit}
		if err := query.Validate(); err != nil {
			return resourceResult(request.Params.URI, invalidSchema(requestID))
		}
		page, failure, handleErr := dependencies.ContextGet.HandleContextGet(ctx, evidence, query)
		if handleErr != nil || failure != nil || page.Validate() != nil || page.RequestID != requestID {
			if handleErr != nil || failure == nil {
				return resourceResult(request.Params.URI, internalFailure(requestID))
			}
			return resourceResult(request.Params.URI, checkedFailure(requestID, failure))
		}
		return resourceResult(request.Params.URI, page)
	}
	server.AddResource(&sdkmcp.Resource{URI: ResourceCurrentContext, Name: "Blackbird current context", MIMEType: mediaTypeJSON,
		Description: "Bounded authorization-scoped checkpoint at the current durable context head."}, handler)
	server.AddResourceTemplate(&sdkmcp.ResourceTemplate{URITemplate: ResourceContextDeltas, Name: "Blackbird context deltas", MIMEType: mediaTypeJSON,
		Description: "Bounded typed context deltas after an opaque context cursor."}, handler)
}

func toolFailure(failure contracts.ErrorDTO) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{IsError: true,
		Content:           []sdkmcp.Content{&sdkmcp.TextContent{Text: string(failure.Code) + ": " + failure.Message}},
		StructuredContent: failure}
}

func resourceResult(uri string, value any) (*sdkmcp.ReadResourceResult, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > contracts.MaxOutcomeJSONBytes {
		return nil, errors.New("mcp resource result exceeds the bounded contract")
	}
	return &sdkmcp.ReadResourceResult{Contents: []*sdkmcp.ResourceContents{{URI: uri, MIMEType: mediaTypeJSON, Text: string(encoded)}}}, nil
}

func contractSchemaOptions() *jsonschema.ForOptions {
	identifier := &jsonschema.Schema{Type: "string", Pattern: `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`}
	integer := &jsonschema.Schema{Type: "integer", Minimum: jsonschema.Ptr(float64(1)), Maximum: jsonschema.Ptr(float64(domain.MaxCanonicalInteger))}
	types := map[reflect.Type]*jsonschema.Schema{
		reflect.TypeFor[domain.InstallationID]():        identifier,
		reflect.TypeFor[domain.AuthorityID]():           identifier,
		reflect.TypeFor[domain.WorkspaceID]():           identifier,
		reflect.TypeFor[domain.PrincipalID]():           identifier,
		reflect.TypeFor[domain.DeviceID]():              identifier,
		reflect.TypeFor[domain.MembershipID]():          identifier,
		reflect.TypeFor[domain.ActorID]():               identifier,
		reflect.TypeFor[domain.ActorDelegationID]():     identifier,
		reflect.TypeFor[domain.ActorSessionID]():        identifier,
		reflect.TypeFor[domain.GrantID]():               identifier,
		reflect.TypeFor[domain.InvitationID]():          identifier,
		reflect.TypeFor[domain.CeremonyID]():            identifier,
		reflect.TypeFor[domain.BootstrapGenerationID](): identifier,
		reflect.TypeFor[domain.CommandID]():             identifier,
		reflect.TypeFor[domain.ReceiptID]():             identifier,
		reflect.TypeFor[domain.EventID]():               identifier,
		reflect.TypeFor[domain.CorrelationID]():         identifier,
		reflect.TypeFor[domain.ClientInstanceID]():      identifier,
		reflect.TypeFor[domain.WorkReferenceID]():       identifier,
		reflect.TypeFor[domain.ObjectiveID]():           identifier,
		reflect.TypeFor[domain.WorkUnitID]():            identifier,
		reflect.TypeFor[domain.RunID]():                 identifier,
		reflect.TypeFor[domain.RunParticipationID]():    identifier,
		reflect.TypeFor[domain.RuntimeBindingID]():      identifier,
		reflect.TypeFor[domain.RuntimeEndpointID]():     identifier,
		reflect.TypeFor[domain.AuthorityEpoch]():        identifier,
		reflect.TypeFor[domain.Version]():               integer,
		reflect.TypeFor[domain.StreamPosition]():        integer,
	}
	return &jsonschema.ForOptions{TypeSchemas: types}
}

func checkedFailure(requestID string, failure *contracts.ErrorDTO) contracts.ErrorDTO {
	if failure == nil || failure.RequestID != requestID || failure.Validate() != nil {
		return internalFailure(requestID)
	}
	return *failure
}

func invalidSchema(requestID string) contracts.ErrorDTO {
	return contracts.ErrorDTO{Schema: contracts.SchemaError, RequestID: requestID, Code: domain.ErrorCodeInvalidSchema,
		Category: domain.ErrorCategoryValidation, Message: "The request does not match the operation schema.",
		Details: contracts.ErrorDetailsDTO{FieldViolations: []contracts.FieldViolationDTO{{Field: "body", Code: "invalid", Message: "request body does not match the operation schema"}}}}
}

func internalFailure(requestID string) contracts.ErrorDTO {
	return contracts.ErrorDTO{Schema: contracts.SchemaError, RequestID: requestID, Code: domain.ErrorCodeInternal,
		Category: domain.ErrorCategoryInternal, Message: "The request could not be completed.", Retryable: true,
		Details: contracts.ErrorDetailsDTO{Recovery: contracts.RecoveryRetrySameCommand}}
}

func requestIDOf(value any, fallback string) string {
	switch request := value.(type) {
	case contracts.InstallationBootstrapRequestDTO:
		return request.RequestID
	case contracts.PrincipalRegisterRequestDTO:
		return request.RequestID
	case contracts.DevicePairingBeginRequestDTO:
		return request.RequestID
	case contracts.DevicePairRequestDTO:
		return request.RequestID
	case contracts.WorkspaceCreateRequestDTO:
		return request.RequestID
	case contracts.WorkspaceMemberInviteRequestDTO:
		return request.RequestID
	case contracts.WorkspaceMembershipAcceptRequestDTO:
		return request.RequestID
	case contracts.ActorCreateRequestDTO:
		return request.RequestID
	case contracts.ActorDelegationProposeRequestDTO:
		return request.RequestID
	case contracts.ActorDelegationActivateRequestDTO:
		return request.RequestID
	case contracts.SessionStartRequestDTO:
		return request.RequestID
	case contracts.WorkRefObserveRequestDTO:
		return request.RequestID
	case contracts.ObjectiveAndWorkCreateRequestDTO:
		return request.RequestID
	case contracts.ObjectiveActivateRequestDTO:
		return request.RequestID
	case contracts.RunPlanWithBindingsRequestDTO:
		return request.RequestID
	case contracts.RunJoinRequestDTO:
		return request.RequestID
	case contracts.RunStartRequestDTO:
		return request.RequestID
	case contracts.ContextGetRequestDTO:
		return request.RequestID
	case contracts.EventsSyncRequestDTO:
		return request.RequestID
	default:
		return fallback
	}
}

func responseRequestID(value any) string {
	switch response := value.(type) {
	case contracts.InstallationBootstrapResultDTO:
		return response.RequestID
	case contracts.PrincipalRegisterResultDTO:
		return response.RequestID
	case contracts.DevicePairingBeginResultDTO:
		return response.RequestID
	case contracts.DevicePairResultDTO:
		return response.RequestID
	case contracts.WorkspaceCreateResultDTO:
		return response.RequestID
	case contracts.WorkspaceMemberInviteResultDTO:
		return response.RequestID
	case contracts.WorkspaceMembershipAcceptResultDTO:
		return response.RequestID
	case contracts.ActorCreateResultDTO:
		return response.RequestID
	case contracts.ActorDelegationProposeResultDTO:
		return response.RequestID
	case contracts.ActorDelegationActivateResultDTO:
		return response.RequestID
	case contracts.SessionStartResultDTO:
		return response.RequestID
	case contracts.WorkRefObserveResultDTO:
		return response.RequestID
	case contracts.ObjectiveAndWorkCreateResultDTO:
		return response.RequestID
	case contracts.ObjectiveActivateResultDTO:
		return response.RequestID
	case contracts.RunPlanWithBindingsResultDTO:
		return response.RequestID
	case contracts.RunJoinResultDTO:
		return response.RequestID
	case contracts.RunStartResultDTO:
		return response.RequestID
	case contracts.ContextPageDTO:
		return response.RequestID
	case contracts.EventPageDTO:
		return response.RequestID
	default:
		return ""
	}
}

func resourceRequestID(uri string) string {
	var hash uint64 = 1469598103934665603
	for index := 0; index < len(uri); index++ {
		hash ^= uint64(uri[index])
		hash *= 1099511628211
	}
	return fmt.Sprintf("req_mcp_resource_%016x", hash)
}

func newRequestID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "req_mcp_transport_internal"
	}
	return "req_" + hex.EncodeToString(random[:])
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
