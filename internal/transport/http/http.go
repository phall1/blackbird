// Package http exposes the strict W0 product-API contracts over net/http.
package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	stdhttp "net/http"
	"reflect"
	"time"

	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/transport/contracts"
)

const (
	PathInstallationBootstrap     = "/api/v1/commands/installation.bootstrap"
	PathPrincipalRegister         = "/api/v1/commands/principal.register"
	PathDevicePairingBegin        = "/api/v1/commands/pairing.challenge.issue"
	PathDevicePair                = "/api/v1/commands/pairing.challenge.redeem"
	PathWorkspaceCreate           = "/api/v1/commands/workspace.create"
	PathWorkspaceMemberInvite     = "/api/v1/commands/workspace_member.invite"
	PathWorkspaceMembershipAccept = "/api/v1/commands/workspace_membership.accept"
	PathActorCreate               = "/api/v1/commands/actor.create"
	PathActorDelegationPropose    = "/api/v1/commands/actor_delegation.propose"
	PathActorDelegationActivate   = "/api/v1/commands/actor_delegation.activate"
	PathSessionStart              = "/api/v1/commands/session.start"
	PathContextGet                = "/api/v1/queries/context.get"
	PathEventsSync                = "/api/v1/queries/events.sync"

	mediaTypeJSON    = "application/json"
	mediaTypeProblem = "application/problem+json"
)

// AuthenticationEvidence is verified transport evidence. The HTTP adapter
// passes it through without interpreting it or deriving identity from a body.
type AuthenticationEvidence interface {
	AuthenticationEvidence()
}

// Authenticator verifies channel or request credentials for an allow-listed
// operation. A failure is either a typed safe failure or an internal error,
// never both.
type Authenticator interface {
	Authenticate(context.Context, *stdhttp.Request, string, string) (AuthenticationEvidence, *contracts.ErrorDTO, error)
}

type InstallationBootstrapHandler interface {
	HandleInstallationBootstrap(context.Context, AuthenticationEvidence, contracts.InstallationBootstrapRequestDTO) (contracts.InstallationBootstrapResultDTO, *contracts.ErrorDTO, error)
}
type PrincipalRegisterHandler interface {
	HandlePrincipalRegister(context.Context, AuthenticationEvidence, contracts.PrincipalRegisterRequestDTO) (contracts.PrincipalRegisterResultDTO, *contracts.ErrorDTO, error)
}
type DevicePairingBeginHandler interface {
	HandleDevicePairingBegin(context.Context, AuthenticationEvidence, contracts.DevicePairingBeginRequestDTO) (contracts.DevicePairingBeginResultDTO, *contracts.ErrorDTO, error)
}
type DevicePairHandler interface {
	HandleDevicePair(context.Context, AuthenticationEvidence, contracts.DevicePairRequestDTO) (contracts.DevicePairResultDTO, *contracts.ErrorDTO, error)
}
type WorkspaceCreateHandler interface {
	HandleWorkspaceCreate(context.Context, AuthenticationEvidence, contracts.WorkspaceCreateRequestDTO) (contracts.WorkspaceCreateResultDTO, *contracts.ErrorDTO, error)
}
type WorkspaceMemberInviteHandler interface {
	HandleWorkspaceMemberInvite(context.Context, AuthenticationEvidence, contracts.WorkspaceMemberInviteRequestDTO) (contracts.WorkspaceMemberInviteResultDTO, *contracts.ErrorDTO, error)
}
type WorkspaceMembershipAcceptHandler interface {
	HandleWorkspaceMembershipAccept(context.Context, AuthenticationEvidence, contracts.WorkspaceMembershipAcceptRequestDTO) (contracts.WorkspaceMembershipAcceptResultDTO, *contracts.ErrorDTO, error)
}
type ActorCreateHandler interface {
	HandleActorCreate(context.Context, AuthenticationEvidence, contracts.ActorCreateRequestDTO) (contracts.ActorCreateResultDTO, *contracts.ErrorDTO, error)
}
type ActorDelegationProposeHandler interface {
	HandleActorDelegationPropose(context.Context, AuthenticationEvidence, contracts.ActorDelegationProposeRequestDTO) (contracts.ActorDelegationProposeResultDTO, *contracts.ErrorDTO, error)
}
type ActorDelegationActivateHandler interface {
	HandleActorDelegationActivate(context.Context, AuthenticationEvidence, contracts.ActorDelegationActivateRequestDTO) (contracts.ActorDelegationActivateResultDTO, *contracts.ErrorDTO, error)
}
type SessionStartHandler interface {
	HandleSessionStart(context.Context, AuthenticationEvidence, contracts.SessionStartRequestDTO) (contracts.SessionStartResultDTO, *contracts.ErrorDTO, error)
}
type ContextGetHandler interface {
	HandleContextGet(context.Context, AuthenticationEvidence, contracts.ContextGetRequestDTO) (contracts.ContextPageDTO, *contracts.ErrorDTO, error)
}
type EventsSyncHandler interface {
	HandleEventsSync(context.Context, AuthenticationEvidence, contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error)
}

type Dependencies struct {
	Authenticator             Authenticator
	InstallationBootstrap     InstallationBootstrapHandler
	PrincipalRegister         PrincipalRegisterHandler
	DevicePairingBegin        DevicePairingBeginHandler
	DevicePair                DevicePairHandler
	WorkspaceCreate           WorkspaceCreateHandler
	WorkspaceMemberInvite     WorkspaceMemberInviteHandler
	WorkspaceMembershipAccept WorkspaceMembershipAcceptHandler
	ActorCreate               ActorCreateHandler
	ActorDelegationPropose    ActorDelegationProposeHandler
	ActorDelegationActivate   ActorDelegationActivateHandler
	SessionStart              SessionStartHandler
	ContextGet                ContextGetHandler
	EventsSync                EventsSyncHandler
}

// NewHandler constructs the complete W0 HTTP route set. Dependencies are
// intentionally explicit so a partially composed product API cannot start.
func NewHandler(dependencies Dependencies) (stdhttp.Handler, error) {
	if isNil(dependencies.Authenticator) || isNil(dependencies.InstallationBootstrap) ||
		isNil(dependencies.PrincipalRegister) || isNil(dependencies.DevicePairingBegin) ||
		isNil(dependencies.DevicePair) || isNil(dependencies.WorkspaceCreate) ||
		isNil(dependencies.WorkspaceMemberInvite) || isNil(dependencies.WorkspaceMembershipAccept) ||
		isNil(dependencies.ActorCreate) || isNil(dependencies.ActorDelegationPropose) ||
		isNil(dependencies.ActorDelegationActivate) || isNil(dependencies.SessionStart) ||
		isNil(dependencies.ContextGet) || isNil(dependencies.EventsSync) {
		return nil, errors.New("http transport requires every W0 handler and authenticator")
	}

	mux := stdhttp.NewServeMux()
	commandRoute(mux, PathInstallationBootstrap, contracts.OperationInstallationBootstrap, dependencies.Authenticator,
		contracts.DecodeInstallationBootstrapRequest, func(request contracts.InstallationBootstrapRequestDTO) time.Time { return request.Deadline },
		dependencies.InstallationBootstrap.HandleInstallationBootstrap, func(result contracts.InstallationBootstrapResultDTO) error { return result.Validate() })
	commandRoute(mux, PathPrincipalRegister, contracts.OperationPrincipalRegister, dependencies.Authenticator,
		contracts.DecodePrincipalRegisterRequest, func(request contracts.PrincipalRegisterRequestDTO) time.Time { return request.Deadline },
		dependencies.PrincipalRegister.HandlePrincipalRegister, func(result contracts.PrincipalRegisterResultDTO) error { return result.Validate() })
	commandRoute(mux, PathDevicePairingBegin, contracts.OperationDevicePairingBegin, dependencies.Authenticator,
		contracts.DecodeDevicePairingBeginRequest, func(request contracts.DevicePairingBeginRequestDTO) time.Time { return request.Deadline },
		dependencies.DevicePairingBegin.HandleDevicePairingBegin, func(result contracts.DevicePairingBeginResultDTO) error { return result.Validate() })
	commandRoute(mux, PathDevicePair, contracts.OperationDevicePair, dependencies.Authenticator,
		contracts.DecodeDevicePairRequest, func(request contracts.DevicePairRequestDTO) time.Time { return request.Deadline },
		dependencies.DevicePair.HandleDevicePair, func(result contracts.DevicePairResultDTO) error { return result.Validate() })
	commandRoute(mux, PathWorkspaceCreate, contracts.OperationWorkspaceCreate, dependencies.Authenticator,
		contracts.DecodeWorkspaceCreateRequest, func(request contracts.WorkspaceCreateRequestDTO) time.Time { return request.Deadline },
		dependencies.WorkspaceCreate.HandleWorkspaceCreate, func(result contracts.WorkspaceCreateResultDTO) error { return result.Validate() })
	commandRoute(mux, PathWorkspaceMemberInvite, contracts.OperationWorkspaceMemberInvite, dependencies.Authenticator,
		contracts.DecodeWorkspaceMemberInviteRequest, func(request contracts.WorkspaceMemberInviteRequestDTO) time.Time { return request.Deadline },
		dependencies.WorkspaceMemberInvite.HandleWorkspaceMemberInvite, func(result contracts.WorkspaceMemberInviteResultDTO) error { return result.Validate() })
	commandRoute(mux, PathWorkspaceMembershipAccept, contracts.OperationWorkspaceMembershipAccept, dependencies.Authenticator,
		contracts.DecodeWorkspaceMembershipAcceptRequest, func(request contracts.WorkspaceMembershipAcceptRequestDTO) time.Time { return request.Deadline },
		dependencies.WorkspaceMembershipAccept.HandleWorkspaceMembershipAccept, func(result contracts.WorkspaceMembershipAcceptResultDTO) error { return result.Validate() })
	commandRoute(mux, PathActorCreate, contracts.OperationActorCreate, dependencies.Authenticator,
		contracts.DecodeActorCreateRequest, func(request contracts.ActorCreateRequestDTO) time.Time { return request.Deadline },
		dependencies.ActorCreate.HandleActorCreate, func(result contracts.ActorCreateResultDTO) error { return result.Validate() })
	commandRoute(mux, PathActorDelegationPropose, contracts.OperationActorDelegationPropose, dependencies.Authenticator,
		contracts.DecodeActorDelegationProposeRequest, func(request contracts.ActorDelegationProposeRequestDTO) time.Time { return request.Deadline },
		dependencies.ActorDelegationPropose.HandleActorDelegationPropose, func(result contracts.ActorDelegationProposeResultDTO) error { return result.Validate() })
	commandRoute(mux, PathActorDelegationActivate, contracts.OperationActorDelegationActivate, dependencies.Authenticator,
		contracts.DecodeActorDelegationActivateRequest, func(request contracts.ActorDelegationActivateRequestDTO) time.Time { return request.Deadline },
		dependencies.ActorDelegationActivate.HandleActorDelegationActivate, func(result contracts.ActorDelegationActivateResultDTO) error { return result.Validate() })
	commandRoute(mux, PathSessionStart, contracts.OperationSessionStart, dependencies.Authenticator,
		contracts.DecodeSessionStartRequest, func(request contracts.SessionStartRequestDTO) time.Time { return request.Deadline },
		dependencies.SessionStart.HandleSessionStart, func(result contracts.SessionStartResultDTO) error { return result.Validate() })
	queryRoute(mux, PathContextGet, contracts.OperationContextGet, dependencies.Authenticator,
		contracts.DecodeContextGetRequest, dependencies.ContextGet.HandleContextGet, func(result contracts.ContextPageDTO) error { return result.Validate() })
	queryRoute(mux, PathEventsSync, contracts.OperationEventsSync, dependencies.Authenticator,
		contracts.DecodeEventsSyncRequest, dependencies.EventsSync.HandleEventsSync, func(result contracts.EventPageDTO) error { return result.Validate() })
	return mux, nil
}

type operationHandler[Request, Result any] func(context.Context, AuthenticationEvidence, Request) (Result, *contracts.ErrorDTO, error)

func commandRoute[Request, Result any](
	mux *stdhttp.ServeMux,
	path, operation string,
	authenticator Authenticator,
	decode func([]byte) (Request, error),
	deadline func(Request) time.Time,
	handle operationHandler[Request, Result],
	validate func(Result) error,
) {
	mux.HandleFunc("POST "+path, serveOperation(operation, authenticator, decode, deadline, handle, validate))
}

func queryRoute[Request, Result any](
	mux *stdhttp.ServeMux,
	path, operation string,
	authenticator Authenticator,
	decode func([]byte) (Request, error),
	handle operationHandler[Request, Result],
	validate func(Result) error,
) {
	mux.HandleFunc("POST "+path, serveOperation(operation, authenticator, decode, nil, handle, validate))
}

func serveOperation[Request, Result any](
	operation string,
	authenticator Authenticator,
	decode func([]byte) (Request, error),
	deadline func(Request) time.Time,
	handle operationHandler[Request, Result],
	validate func(Result) error,
) stdhttp.HandlerFunc {
	return func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		requestID := newRequestID()
		if request.Header.Get("Content-Encoding") != "" || !isJSONContentType(request.Header.Get("Content-Type")) {
			writeProblem(writer, invalidSchema(requestID, "content_type", "request must use unencoded application/json"))
			return
		}
		authenticationRequest := request.Clone(request.Context())
		authenticationRequest.Body = nil
		authenticationRequest.GetBody = nil
		evidence, failure, err := authenticator.Authenticate(request.Context(), authenticationRequest, operation, requestID)
		if err != nil || isNil(evidence) == (failure == nil) {
			writeProblem(writer, internalFailure(requestID))
			return
		}
		if failure != nil {
			writeProblem(writer, checkedFailure(requestID, failure))
			return
		}
		body, err := readBody(writer, request)
		if err != nil {
			field := "body"
			message := "request body is invalid JSON"
			if errors.Is(err, contracts.ErrPayloadTooLarge) {
				message = fmt.Sprintf("request body exceeds %d bytes", contracts.MaxCommandJSONBytes)
			}
			writeProblem(writer, invalidSchema(requestID, field, message))
			return
		}
		input, err := decode(body)
		if err != nil {
			writeProblem(writer, invalidSchema(requestID, "body", "request body does not match the operation schema"))
			return
		}
		requestID = requestIDOf(input, requestID)
		ctx := request.Context()
		if deadline != nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline(input))
			defer cancel()
		}
		result, failure, err := handle(ctx, evidence, input)
		if err != nil || failure != nil {
			if err != nil || failure == nil {
				writeProblem(writer, internalFailure(requestID))
				return
			}
			writeProblem(writer, checkedFailure(requestID, failure))
			return
		}
		if err := validate(result); err != nil || responseRequestID(result) != requestID {
			writeProblem(writer, internalFailure(requestID))
			return
		}
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded) > contracts.MaxOutcomeJSONBytes {
			writeProblem(writer, internalFailure(requestID))
			return
		}
		writer.Header().Set("Content-Type", mediaTypeJSON)
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(stdhttp.StatusOK)
		_, _ = writer.Write(encoded)
	}
}

func readBody(writer stdhttp.ResponseWriter, request *stdhttp.Request) ([]byte, error) {
	if request.ContentLength > contracts.MaxCommandJSONBytes {
		return nil, contracts.ErrPayloadTooLarge
	}
	reader := stdhttp.MaxBytesReader(writer, request.Body, contracts.MaxCommandJSONBytes)
	body, err := io.ReadAll(reader)
	if err != nil {
		var tooLarge *stdhttp.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, contracts.ErrPayloadTooLarge
		}
		return nil, err
	}
	return body, nil
}

func isJSONContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	return err == nil && mediaType == mediaTypeJSON && len(parameters) == 0
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

type problemDTO struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	contracts.ErrorDTO
}

func writeProblem(writer stdhttp.ResponseWriter, failure contracts.ErrorDTO) {
	status := statusFor(failure.Code)
	problem := problemDTO{
		Type: "https://blackbird.local/problems/" + string(failure.Code), Title: string(failure.Code),
		Status: status, Detail: failure.Message, ErrorDTO: failure,
	}
	encoded, err := json.Marshal(problem)
	if err != nil {
		stdhttp.Error(writer, "internal server error", stdhttp.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", mediaTypeProblem)
	writer.Header().Set("Cache-Control", "no-store")
	if failure.RetryAfterMS != nil {
		seconds := (*failure.RetryAfterMS + 999) / 1000
		writer.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func checkedFailure(requestID string, failure *contracts.ErrorDTO) contracts.ErrorDTO {
	if failure == nil || failure.RequestID != requestID || failure.Validate() != nil {
		return internalFailure(requestID)
	}
	return *failure
}

func invalidSchema(requestID, field, message string) contracts.ErrorDTO {
	return contracts.ErrorDTO{
		Schema: contracts.SchemaError, RequestID: requestID, Code: domain.ErrorCodeInvalidSchema,
		Category: domain.ErrorCategoryValidation, Message: "The request does not match the operation schema.",
		Details: contracts.ErrorDetailsDTO{FieldViolations: []contracts.FieldViolationDTO{{Field: field, Code: "invalid", Message: message}}},
	}
}

func internalFailure(requestID string) contracts.ErrorDTO {
	return contracts.ErrorDTO{
		Schema: contracts.SchemaError, RequestID: requestID, Code: domain.ErrorCodeInternal,
		Category: domain.ErrorCategoryInternal, Message: "The request could not be completed.", Retryable: true,
		Details: contracts.ErrorDetailsDTO{Recovery: contracts.RecoveryRetrySameCommand},
	}
}

func statusFor(code domain.ErrorCode) int {
	switch code {
	case domain.ErrorCodeInvalidArgument, domain.ErrorCodeCursorInvalid, domain.ErrorCodeCursorScopeMismatch:
		return stdhttp.StatusBadRequest
	case domain.ErrorCodeInvalidSchema:
		return stdhttp.StatusUnprocessableEntity
	case domain.ErrorCodeUnauthenticated, domain.ErrorCodeSessionExpired:
		return stdhttp.StatusUnauthorized
	case domain.ErrorCodeForbidden, domain.ErrorCodeCapabilityRequired:
		return stdhttp.StatusForbidden
	case domain.ErrorCodeNotFound:
		return stdhttp.StatusNotFound
	case domain.ErrorCodeStaleVersion, domain.ErrorCodeStateConflict, domain.ErrorCodeIdempotencyKeyReused,
		domain.ErrorCodeCommandIDReused, domain.ErrorCodeCommandInProgress, domain.ErrorCodeLeaseConflict,
		domain.ErrorCodeLeaseExpired, domain.ErrorCodeFenceRejected:
		return stdhttp.StatusConflict
	case domain.ErrorCodeCursorExpired:
		return stdhttp.StatusGone
	case domain.ErrorCodeRateLimited:
		return stdhttp.StatusTooManyRequests
	case domain.ErrorCodeBackpressure, domain.ErrorCodeDependencyUnavailable:
		return stdhttp.StatusServiceUnavailable
	case domain.ErrorCodeDeadlineExceeded:
		return stdhttp.StatusGatewayTimeout
	default:
		return stdhttp.StatusInternalServerError
	}
}

func newRequestID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "req_transport_internal"
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
