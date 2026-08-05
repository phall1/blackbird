// Package mcp exposes the strict W0 transport contracts through the official MCP Go SDK.
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
	ToolContextGet                = "blackbird_get_context"
	ToolEventsSync                = "blackbird_sync_events"

	ResourceCurrentContext = "blackbird://session/current/context"
	ResourceContextDeltas  = "blackbird://session/current/context-deltas{?cursor,limit}"

	mediaTypeJSON = "application/json"
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
	ContextGet                contracts.ContextGetHandler
	EventsSync                contracts.EventsSyncHandler
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
		isNil(dependencies.SessionStart) || isNil(dependencies.ContextGet) || isNil(dependencies.EventsSync) {
		return nil, errors.New("mcp transport requires every W0 handler, authenticator, and current-session binder")
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
	registerQuery(sdk, ToolContextGet, contracts.OperationContextGet, dependencies.Authenticator,
		contracts.DecodeContextGetRequest, dependencies.ContextGet.HandleContextGet, func(value contracts.ContextPageDTO) error { return value.Validate() })
	registerQuery(sdk, ToolEventsSync, contracts.OperationEventsSync, dependencies.Authenticator,
		contracts.DecodeEventsSyncRequest, dependencies.EventsSync.HandleEventsSync, func(value contracts.EventPageDTO) error { return value.Validate() })
	registerResources(sdk, dependencies)
	return server, nil
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
	semanticOutputSchema := &jsonschema.Schema{OneOf: []*jsonschema.Schema{outputSchema, errorSchema}}
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
