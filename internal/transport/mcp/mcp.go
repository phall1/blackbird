// Package mcp exposes the strict transport contracts through the official MCP Go SDK.
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	ToolMessageReply              = "blackbird_message_reply"
	ToolInboxFetch                = "blackbird_inbox_fetch"
	ToolThreadFetch               = "blackbird_thread_fetch"
	ToolMessageMarkRead           = "blackbird_message_mark_read"
	ToolMessageAcknowledge        = "blackbird_message_acknowledge"
	ToolReservationAcquire        = "blackbird_reservation_acquire"
	ToolReservationRenew          = "blackbird_reservation_renew"
	ToolReservationRelease        = "blackbird_reservation_release"

	ResourceCurrentContext = "blackbird://session/current/context"
	ResourceContextDeltas  = "blackbird://session/current/context-deltas{?cursor,limit}"

	mediaTypeJSON                = "application/json"
	defaultCoordinationPageLimit = 50
	defaultReservationTTLSeconds = 3600
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
	registerResources(sdk, dependencies)
	if !isNil(dependencies.Coordination) {
		registerCoordinationTools(sdk, dependencies.Coordination)
	}
	return server, nil
}

type registerAgentInput struct {
	ProjectKey        string  `json:"project_key" jsonschema:"Repository or workspace key, preferably its absolute path."`
	AgentName         string  `json:"agent_name"`
	RegistrationToken *string `json:"registration_token,omitempty" jsonschema:"Existing token required when restarting a registered name."`
}
type agentSessionOutput struct {
	ProjectKey        string `json:"project_key"`
	AgentName         string `json:"agent_name"`
	WorkspaceID       string `json:"workspace_id"`
	ActorID           string `json:"actor_id"`
	SessionID         string `json:"session_id"`
	RegistrationToken string `json:"registration_token,omitempty"`
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
	Topic      string `json:"topic"`
}
type conversationOutput struct {
	ConversationID string `json:"conversation_id"`
	Topic          string `json:"topic"`
	OpenedAt       string `json:"opened_at"`
}
type sendMessageInput struct {
	AgentToken              string   `json:"agent_token"`
	ConversationID          string   `json:"conversation_id"`
	To                      []string `json:"to"`
	Subject                 string   `json:"subject"`
	Body                    string   `json:"body"`
	AcknowledgementRequired bool     `json:"acknowledgement_required,omitempty"`
}
type replyMessageInput struct {
	sendMessageInput
	ReplyToMessageID string `json:"reply_to_message_id"`
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
	UnreadOnly bool   `json:"unread_only,omitempty"`
	After      uint64 `json:"after,omitempty"`
	Limit      uint16 `json:"limit,omitempty"`
}
type fetchThreadInput struct {
	AgentToken     string `json:"agent_token"`
	ConversationID string `json:"conversation_id"`
	After          uint64 `json:"after,omitempty"`
	Limit          uint16 `json:"limit,omitempty"`
}
type messagePageOutput struct {
	Messages []messageOutput `json:"messages"`
	Next     uint64          `json:"next"`
	HasMore  bool            `json:"has_more"`
}
type messageFactInput struct {
	AgentToken string `json:"agent_token"`
	MessageID  string `json:"message_id"`
}
type deliveryFactOutput struct {
	MessageID    string `json:"message_id"`
	Read         bool   `json:"read"`
	Acknowledged bool   `json:"acknowledged"`
}
type reservationSelectorInput struct {
	Kind string `json:"kind" jsonschema:"exact or subtree"`
	Path string `json:"path"`
}
type reservationAcquireInput struct {
	AgentToken string                     `json:"agent_token"`
	Mode       string                     `json:"mode,omitempty" jsonschema:"shared or exclusive"`
	Selectors  []reservationSelectorInput `json:"selectors"`
	TTLSeconds uint32                     `json:"ttl_seconds,omitempty"`
}
type fenceOutput struct {
	ConflictKey string `json:"conflict_key"`
	Counter     uint64 `json:"counter"`
}
type reservationChangeInput struct {
	AgentToken string        `json:"agent_token"`
	LeaseID    string        `json:"lease_id"`
	Fences     []fenceOutput `json:"fences"`
	TTLSeconds uint32        `json:"ttl_seconds,omitempty"`
}
type reservationReleaseInput struct {
	AgentToken string        `json:"agent_token"`
	LeaseID    string        `json:"lease_id"`
	Fences     []fenceOutput `json:"fences"`
}
type reservationOutput struct {
	LeaseID    string                     `json:"lease_id"`
	Mode       string                     `json:"mode"`
	Selectors  []reservationSelectorInput `json:"selectors"`
	Fences     []fenceOutput              `json:"fences"`
	ExpiresAt  string                     `json:"expires_at"`
	ReleasedAt string                     `json:"released_at,omitempty"`
}

func registerCoordinationTools(server *sdkmcp.Server, store application.LocalCoordinationStore) {
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolAgentRegister, Description: "Start or resume a durable local agent session for a repository key and agent name."},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input registerAgentInput) (*sdkmcp.CallToolResult, agentSessionOutput, error) {
			token := ""
			if input.RegistrationToken != nil {
				token = *input.RegistrationToken
			}
			session, issued, err := store.RegisterLocalAgent(ctx, input.ProjectKey, input.AgentName, token)
			if err != nil {
				return nil, agentSessionOutput{}, err
			}
			return nil, agentSessionOutput{ProjectKey: session.ProjectKey, AgentName: session.AgentName,
				WorkspaceID: session.WorkspaceID.String(), ActorID: session.ActorID.String(), SessionID: session.ActorSessionID.String(),
				RegistrationToken: issued}, nil
		})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolAgentsList, Description: "List agent sessions active in the caller's repository."},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input tokenInput) (*sdkmcp.CallToolResult, activeAgentsOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return nil, activeAgentsOutput{}, err
			}
			agents, err := store.ListActiveLocalAgents(ctx, session)
			if err != nil {
				return nil, activeAgentsOutput{}, err
			}
			output := activeAgentsOutput{Agents: make([]activeAgentOutput, 0, len(agents))}
			for _, agent := range agents {
				output.Agents = append(output.Agents, activeAgentOutput{Name: agent.Name, ActorID: agent.ActorID.String(),
					SessionID: agent.SessionID.String(), LastSeenAt: agent.LastSeenAt.Format(time.RFC3339Nano)})
			}
			return nil, output, nil
		})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolConversationOpen, Description: "Open a durable conversation in the caller's repository."},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input openConversationInput) (*sdkmcp.CallToolResult, conversationOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return nil, conversationOutput{}, err
			}
			id, err := domain.NewConversationID()
			if err != nil {
				return nil, conversationOutput{}, err
			}
			value, err := store.OpenConversation(ctx, application.OpenConversationParams{ConversationID: id,
				WorkspaceID: session.WorkspaceID, RunID: session.RunID, OpenedBy: session.ActorID,
				OpenedBySession: session.ActorSessionID, Topic: input.Topic})
			if err != nil {
				return nil, conversationOutput{}, err
			}
			return nil, conversationOutput{ConversationID: value.ID().String(), Topic: value.Topic(), OpenedAt: value.OpenedAt().Format(time.RFC3339Nano)}, nil
		})
	messageInputSchema := coordinationInputSchema[sendMessageInput](func(properties map[string]*jsonschema.Schema) {
		properties["acknowledgement_required"].Default = json.RawMessage("false")
	})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolMessageSend, Description: "Send a durable message to named agents.", InputSchema: messageInputSchema},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input sendMessageInput) (*sdkmcp.CallToolResult, messageOutput, error) {
			value, err := sendLocalMessage(ctx, store, input, "")
			return nil, value, err
		})
	replyInputSchema := coordinationInputSchema[replyMessageInput](func(properties map[string]*jsonschema.Schema) {
		properties["acknowledgement_required"].Default = json.RawMessage("false")
	})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolMessageReply, Description: "Reply to a durable message in its conversation.", InputSchema: replyInputSchema},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input replyMessageInput) (*sdkmcp.CallToolResult, messageOutput, error) {
			value, err := sendLocalMessage(ctx, store, input.sendMessageInput, input.ReplyToMessageID)
			return nil, value, err
		})
	inboxInputSchema := coordinationInputSchema[fetchInboxInput](func(properties map[string]*jsonschema.Schema) {
		properties["unread_only"].Default = json.RawMessage("false")
		properties["after"].Default = json.RawMessage("0")
		setPageLimitSchema(properties["limit"])
	})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolInboxFetch, Description: "Fetch the caller's unread or complete inbox.", InputSchema: inboxInputSchema},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input fetchInboxInput) (*sdkmcp.CallToolResult, messagePageOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return nil, messagePageOutput{}, err
			}
			page, err := store.Inbox(ctx, application.InboxQuery{WorkspaceID: session.WorkspaceID, Recipient: session.ActorID,
				After: input.After, Limit: input.Limit, UnreadOnly: input.UnreadOnly})
			if err != nil {
				return nil, messagePageOutput{}, err
			}
			return nil, coordinationPageOutput(page), nil
		})
	threadInputSchema := coordinationInputSchema[fetchThreadInput](func(properties map[string]*jsonschema.Schema) {
		properties["after"].Default = json.RawMessage("0")
		setPageLimitSchema(properties["limit"])
	})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolThreadFetch, Description: "Fetch visible messages in a conversation.", InputSchema: threadInputSchema},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input fetchThreadInput) (*sdkmcp.CallToolResult, messagePageOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return nil, messagePageOutput{}, err
			}
			conversation, err := domain.ParseConversationID(input.ConversationID)
			if err != nil {
				return nil, messagePageOutput{}, application.ErrInvalidCoordination
			}
			page, err := store.Thread(ctx, application.ThreadQuery{WorkspaceID: session.WorkspaceID, ConversationID: conversation,
				Viewer: session.ActorID, After: input.After, Limit: input.Limit})
			if err != nil {
				return nil, messagePageOutput{}, err
			}
			return nil, coordinationPageOutput(page), nil
		})
	registerDeliveryFactTool(server, ToolMessageMarkRead, application.DeliveryRead, store)
	registerDeliveryFactTool(server, ToolMessageAcknowledge, application.DeliveryAcknowledged, store)
	registerReservationTools(server, store)
}

func sendLocalMessage(ctx context.Context, store application.LocalCoordinationStore, input sendMessageInput, replyText string) (messageOutput, error) {
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
	if replyText != "" {
		reply, parseErr := domain.ParseMessageID(replyText)
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

func registerDeliveryFactTool(server *sdkmcp.Server, name string, kind application.DeliveryFactKind, store application.LocalCoordinationStore) {
	description := "Mark a message read without acknowledging it."
	if kind == application.DeliveryAcknowledged {
		description = "Acknowledge the exact durable message body."
	}
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: name, Description: description},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input messageFactInput) (*sdkmcp.CallToolResult, deliveryFactOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return nil, deliveryFactOutput{}, err
			}
			messageID, err := domain.ParseMessageID(input.MessageID)
			if err != nil {
				return nil, deliveryFactOutput{}, application.ErrInvalidCoordination
			}
			params := application.RecordDeliveryFactParams{WorkspaceID: session.WorkspaceID, MessageID: messageID,
				Recipient: session.ActorID, ActorSessionID: &session.ActorSessionID, Kind: kind}
			if kind == application.DeliveryAcknowledged {
				digest, findErr := findInboxMessageDigest(ctx, store, session, messageID)
				if findErr != nil {
					return nil, deliveryFactOutput{}, findErr
				}
				params.MessageDigest = digest
			}
			delivery, err := store.RecordDeliveryFact(ctx, params)
			if err != nil {
				return nil, deliveryFactOutput{}, err
			}
			_, read := delivery.ReadAt()
			_, acknowledged := delivery.AcknowledgedAt()
			return nil, deliveryFactOutput{MessageID: input.MessageID, Read: read, Acknowledged: acknowledged}, nil
		})
}

func findInboxMessageDigest(ctx context.Context, store application.LocalCoordinationStore, session application.LocalAgentSession,
	want domain.MessageID) (application.Digest, error) {
	var after uint64
	for {
		page, err := store.Inbox(ctx, application.InboxQuery{WorkspaceID: session.WorkspaceID, Recipient: session.ActorID,
			After: after, Limit: 256})
		if err != nil {
			return application.Digest{}, err
		}
		for _, message := range page.Messages() {
			if message.ID() == want {
				return message.Digest(), nil
			}
		}
		if !page.HasMore() {
			return application.Digest{}, errors.New("message is not visible in the agent inbox")
		}
		after = page.NextCursor()
	}
}

func registerReservationTools(server *sdkmcp.Server, store application.LocalCoordinationStore) {
	acquireInputSchema := coordinationInputSchema[reservationAcquireInput](func(properties map[string]*jsonschema.Schema) {
		properties["mode"].Default = json.RawMessage(`"exclusive"`)
		properties["mode"].Enum = []any{string(application.LeaseShared), string(application.LeaseExclusive)}
		setTTLSchema(properties["ttl_seconds"])
	})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolReservationAcquire, Description: "Acquire shared or exclusive exact/subtree file reservations.", InputSchema: acquireInputSchema},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input reservationAcquireInput) (*sdkmcp.CallToolResult, reservationOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return nil, reservationOutput{}, err
			}
			selectors := make([]application.LeaseSelector, 0, len(input.Selectors))
			for _, raw := range input.Selectors {
				selector, selectorErr := application.NewLeaseSelector(application.LeaseSelectorKind(raw.Kind), raw.Path)
				if selectorErr != nil {
					return nil, reservationOutput{}, selectorErr
				}
				selectors = append(selectors, selector)
			}
			leaseID, err := domain.NewLeaseID()
			if err != nil {
				return nil, reservationOutput{}, err
			}
			lease, err := store.AcquireLease(ctx, application.AcquireLeaseParams{LeaseID: leaseID,
				WorkspaceID: session.WorkspaceID, Holder: session.ActorID, HolderSession: session.ActorSessionID,
				AuthorityEpoch: session.AuthorityEpoch, Mode: application.LeaseMode(input.Mode), Selectors: selectors,
				TTL: time.Duration(input.TTLSeconds) * time.Second})
			if err != nil {
				return nil, reservationOutput{}, err
			}
			return nil, localReservationOutput(lease), nil
		})
	renewInputSchema := coordinationInputSchema[reservationChangeInput](func(properties map[string]*jsonschema.Schema) {
		setTTLSchema(properties["ttl_seconds"])
	})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolReservationRenew, Description: "Renew a held file reservation using its current fences.", InputSchema: renewInputSchema},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input reservationChangeInput) (*sdkmcp.CallToolResult, reservationOutput, error) {
			lease, err := changeLocalReservation(ctx, store, input, false)
			return nil, lease, err
		})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: ToolReservationRelease, Description: "Release a held file reservation using its current fences."},
		func(ctx context.Context, _ *sdkmcp.CallToolRequest, input reservationReleaseInput) (*sdkmcp.CallToolResult, reservationOutput, error) {
			lease, err := changeLocalReservation(ctx, store, reservationChangeInput{AgentToken: input.AgentToken,
				LeaseID: input.LeaseID, Fences: input.Fences}, true)
			return nil, lease, err
		})
}

func coordinationInputSchema[Input any](configure func(map[string]*jsonschema.Schema)) *jsonschema.Schema {
	schema, err := jsonschema.For[Input](nil)
	if err != nil {
		panic(fmt.Sprintf("infer local coordination input schema: %v", err))
	}
	configure(schema.Properties)
	return schema
}

func setPageLimitSchema(schema *jsonschema.Schema) {
	schema.Default = json.RawMessage(strconv.Itoa(defaultCoordinationPageLimit))
	schema.Minimum = jsonschema.Ptr(float64(1))
	schema.Maximum = jsonschema.Ptr(float64(application.MaxQueryPageSize))
}

func setTTLSchema(schema *jsonschema.Schema) {
	schema.Default = json.RawMessage(strconv.Itoa(defaultReservationTTLSeconds))
	schema.Minimum = jsonschema.Ptr(float64(1))
	schema.Maximum = jsonschema.Ptr(application.MaxLeaseTTL.Seconds())
}

func changeLocalReservation(ctx context.Context, store application.LocalCoordinationStore, input reservationChangeInput,
	release bool) (reservationOutput, error) {
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
	if release {
		lease, err = store.ReleaseLease(ctx, params)
	} else {
		lease, err = store.RenewLease(ctx, params)
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
