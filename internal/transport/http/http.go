// Package http exposes the strict product-API contracts over net/http.
package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	PathWorkRefObserve            = "/api/v1/commands/work_ref.observe"
	PathObjectiveAndWorkCreate    = "/api/v1/commands/objective_and_work.create"
	PathObjectiveActivate         = "/api/v1/commands/objective.activate"
	PathRunPlanWithBindings       = "/api/v1/commands/run.plan_with_bindings"
	PathRunJoin                   = "/api/v1/commands/run_participation.join"
	PathRunStart                  = "/api/v1/commands/run.start"
	PathContextGet                = "/api/v1/queries/context.get"
	PathEventsSync                = "/api/v1/queries/events.sync"

	mediaTypeJSON    = "application/json"
	mediaTypeProblem = "application/problem+json"

	// headerRequestID lets a caller supply the correlation id this transport
	// would otherwise mint, so a client trace and a daemon log line share one key.
	headerRequestID = "X-Request-Id"
)

// errIncoherentResult names the contract violation of a collaborator that
// returned neither a usable value nor a single typed failure. Logging it beats
// logging a nil error, which reads as a spurious success in the record.
var errIncoherentResult = errors.New("collaborator returned neither a value nor a single typed failure")

type AuthenticationEvidence = contracts.AuthenticationEvidence

// Authenticator verifies channel or request credentials for an allow-listed
// operation. A failure is either a typed safe failure or an internal error,
// never both.
type Authenticator interface {
	Authenticate(context.Context, *stdhttp.Request, string, string) (AuthenticationEvidence, *contracts.ErrorDTO, error)
}

type InstallationBootstrapHandler = contracts.InstallationBootstrapHandler
type PrincipalRegisterHandler = contracts.PrincipalRegisterHandler
type DevicePairingBeginHandler = contracts.DevicePairingBeginHandler
type DevicePairHandler = contracts.DevicePairHandler
type WorkspaceCreateHandler = contracts.WorkspaceCreateHandler
type WorkspaceMemberInviteHandler = contracts.WorkspaceMemberInviteHandler
type WorkspaceMembershipAcceptHandler = contracts.WorkspaceMembershipAcceptHandler
type ActorCreateHandler = contracts.ActorCreateHandler
type ActorDelegationProposeHandler = contracts.ActorDelegationProposeHandler
type ActorDelegationActivateHandler = contracts.ActorDelegationActivateHandler
type SessionStartHandler = contracts.SessionStartHandler
type WorkRefObserveHandler = contracts.WorkRefObserveHandler
type ObjectiveAndWorkCreateHandler = contracts.ObjectiveAndWorkCreateHandler
type ObjectiveActivateHandler = contracts.ObjectiveActivateHandler
type RunPlanWithBindingsHandler = contracts.RunPlanWithBindingsHandler
type RunJoinHandler = contracts.RunJoinHandler
type RunStartHandler = contracts.RunStartHandler
type ContextGetHandler = contracts.ContextGetHandler
type EventsSyncHandler = contracts.EventsSyncHandler

type Dependencies struct {
	// Logger receives the wrapped causes the sanitized wire DTOs must not carry,
	// plus one access record per request. A nil Logger is silent rather than a
	// composition error, so a test can exercise a route without a log sink.
	Logger                    *slog.Logger
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
	WorkRefObserve            WorkRefObserveHandler
	ObjectiveAndWorkCreate    ObjectiveAndWorkCreateHandler
	ObjectiveActivate         ObjectiveActivateHandler
	RunPlanWithBindings       RunPlanWithBindingsHandler
	RunJoin                   RunJoinHandler
	RunStart                  RunStartHandler
	ContextGet                ContextGetHandler
	EventsSync                EventsSyncHandler
}

// NewHandler constructs the complete HTTP route set. Dependencies are
// intentionally explicit so a partially composed product API cannot start.
func NewHandler(dependencies Dependencies) (stdhttp.Handler, error) {
	if isNil(dependencies.Authenticator) || isNil(dependencies.InstallationBootstrap) ||
		isNil(dependencies.PrincipalRegister) || isNil(dependencies.DevicePairingBegin) ||
		isNil(dependencies.DevicePair) || isNil(dependencies.WorkspaceCreate) ||
		isNil(dependencies.WorkspaceMemberInvite) || isNil(dependencies.WorkspaceMembershipAccept) ||
		isNil(dependencies.ActorCreate) || isNil(dependencies.ActorDelegationPropose) ||
		isNil(dependencies.ActorDelegationActivate) || isNil(dependencies.SessionStart) ||
		isNil(dependencies.WorkRefObserve) || isNil(dependencies.ObjectiveAndWorkCreate) ||
		isNil(dependencies.ObjectiveActivate) || isNil(dependencies.RunPlanWithBindings) ||
		isNil(dependencies.RunJoin) || isNil(dependencies.RunStart) ||
		isNil(dependencies.ContextGet) || isNil(dependencies.EventsSync) {
		return nil, errors.New("http transport requires every W0/W1 handler and authenticator")
	}

	logger := dependencies.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	mux := stdhttp.NewServeMux()
	commandRoute(mux, logger, PathInstallationBootstrap, contracts.OperationInstallationBootstrap, dependencies.Authenticator,
		contracts.DecodeInstallationBootstrapRequest, func(request contracts.InstallationBootstrapRequestDTO) time.Time { return request.Deadline },
		dependencies.InstallationBootstrap.HandleInstallationBootstrap, func(result contracts.InstallationBootstrapResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathPrincipalRegister, contracts.OperationPrincipalRegister, dependencies.Authenticator,
		contracts.DecodePrincipalRegisterRequest, func(request contracts.PrincipalRegisterRequestDTO) time.Time { return request.Deadline },
		dependencies.PrincipalRegister.HandlePrincipalRegister, func(result contracts.PrincipalRegisterResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathDevicePairingBegin, contracts.OperationDevicePairingBegin, dependencies.Authenticator,
		contracts.DecodeDevicePairingBeginRequest, func(request contracts.DevicePairingBeginRequestDTO) time.Time { return request.Deadline },
		dependencies.DevicePairingBegin.HandleDevicePairingBegin, func(result contracts.DevicePairingBeginResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathDevicePair, contracts.OperationDevicePair, dependencies.Authenticator,
		contracts.DecodeDevicePairRequest, func(request contracts.DevicePairRequestDTO) time.Time { return request.Deadline },
		dependencies.DevicePair.HandleDevicePair, func(result contracts.DevicePairResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathWorkspaceCreate, contracts.OperationWorkspaceCreate, dependencies.Authenticator,
		contracts.DecodeWorkspaceCreateRequest, func(request contracts.WorkspaceCreateRequestDTO) time.Time { return request.Deadline },
		dependencies.WorkspaceCreate.HandleWorkspaceCreate, func(result contracts.WorkspaceCreateResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathWorkspaceMemberInvite, contracts.OperationWorkspaceMemberInvite, dependencies.Authenticator,
		contracts.DecodeWorkspaceMemberInviteRequest, func(request contracts.WorkspaceMemberInviteRequestDTO) time.Time { return request.Deadline },
		dependencies.WorkspaceMemberInvite.HandleWorkspaceMemberInvite, func(result contracts.WorkspaceMemberInviteResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathWorkspaceMembershipAccept, contracts.OperationWorkspaceMembershipAccept, dependencies.Authenticator,
		contracts.DecodeWorkspaceMembershipAcceptRequest, func(request contracts.WorkspaceMembershipAcceptRequestDTO) time.Time { return request.Deadline },
		dependencies.WorkspaceMembershipAccept.HandleWorkspaceMembershipAccept, func(result contracts.WorkspaceMembershipAcceptResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathActorCreate, contracts.OperationActorCreate, dependencies.Authenticator,
		contracts.DecodeActorCreateRequest, func(request contracts.ActorCreateRequestDTO) time.Time { return request.Deadline },
		dependencies.ActorCreate.HandleActorCreate, func(result contracts.ActorCreateResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathActorDelegationPropose, contracts.OperationActorDelegationPropose, dependencies.Authenticator,
		contracts.DecodeActorDelegationProposeRequest, func(request contracts.ActorDelegationProposeRequestDTO) time.Time { return request.Deadline },
		dependencies.ActorDelegationPropose.HandleActorDelegationPropose, func(result contracts.ActorDelegationProposeResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathActorDelegationActivate, contracts.OperationActorDelegationActivate, dependencies.Authenticator,
		contracts.DecodeActorDelegationActivateRequest, func(request contracts.ActorDelegationActivateRequestDTO) time.Time { return request.Deadline },
		dependencies.ActorDelegationActivate.HandleActorDelegationActivate, func(result contracts.ActorDelegationActivateResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathSessionStart, contracts.OperationSessionStart, dependencies.Authenticator,
		contracts.DecodeSessionStartRequest, func(request contracts.SessionStartRequestDTO) time.Time { return request.Deadline },
		dependencies.SessionStart.HandleSessionStart, func(result contracts.SessionStartResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathWorkRefObserve, contracts.OperationWorkRefObserve, dependencies.Authenticator,
		contracts.DecodeWorkRefObserveRequest, func(request contracts.WorkRefObserveRequestDTO) time.Time { return request.Deadline },
		dependencies.WorkRefObserve.HandleWorkRefObserve, func(result contracts.WorkRefObserveResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathObjectiveAndWorkCreate, contracts.OperationObjectiveAndWorkCreate, dependencies.Authenticator,
		contracts.DecodeObjectiveAndWorkCreateRequest, func(request contracts.ObjectiveAndWorkCreateRequestDTO) time.Time { return request.Deadline },
		dependencies.ObjectiveAndWorkCreate.HandleObjectiveAndWorkCreate, func(result contracts.ObjectiveAndWorkCreateResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathObjectiveActivate, contracts.OperationObjectiveActivate, dependencies.Authenticator,
		contracts.DecodeObjectiveActivateRequest, func(request contracts.ObjectiveActivateRequestDTO) time.Time { return request.Deadline },
		dependencies.ObjectiveActivate.HandleObjectiveActivate, func(result contracts.ObjectiveActivateResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathRunPlanWithBindings, contracts.OperationRunPlanWithBindings, dependencies.Authenticator,
		contracts.DecodeRunPlanWithBindingsRequest, func(request contracts.RunPlanWithBindingsRequestDTO) time.Time { return request.Deadline },
		dependencies.RunPlanWithBindings.HandleRunPlanWithBindings, func(result contracts.RunPlanWithBindingsResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathRunJoin, contracts.OperationRunJoin, dependencies.Authenticator,
		contracts.DecodeRunJoinRequest, func(request contracts.RunJoinRequestDTO) time.Time { return request.Deadline },
		dependencies.RunJoin.HandleRunJoin, func(result contracts.RunJoinResultDTO) error { return result.Validate() })
	commandRoute(mux, logger, PathRunStart, contracts.OperationRunStart, dependencies.Authenticator,
		contracts.DecodeRunStartRequest, func(request contracts.RunStartRequestDTO) time.Time { return request.Deadline },
		dependencies.RunStart.HandleRunStart, func(result contracts.RunStartResultDTO) error { return result.Validate() })
	queryRoute(mux, logger, PathContextGet, contracts.OperationContextGet, dependencies.Authenticator,
		contracts.DecodeContextGetRequest, dependencies.ContextGet.HandleContextGet, func(result contracts.ContextPageDTO) error { return result.Validate() })
	queryRoute(mux, logger, PathEventsSync, contracts.OperationEventsSync, dependencies.Authenticator,
		contracts.DecodeEventsSyncRequest, dependencies.EventsSync.HandleEventsSync, func(result contracts.EventPageDTO) error { return result.Validate() })
	return mux, nil
}

type operationHandler[Request, Result any] func(context.Context, AuthenticationEvidence, Request) (Result, *contracts.ErrorDTO, error)

func commandRoute[Request, Result any](
	mux *stdhttp.ServeMux,
	logger *slog.Logger,
	path, operation string,
	authenticator Authenticator,
	decode func([]byte) (Request, error),
	deadline func(Request) time.Time,
	handle operationHandler[Request, Result],
	validate func(Result) error,
) {
	mux.HandleFunc("POST "+path, serveOperation(logger, operation, authenticator, decode, deadline, handle, validate))
}

func queryRoute[Request, Result any](
	mux *stdhttp.ServeMux,
	logger *slog.Logger,
	path, operation string,
	authenticator Authenticator,
	decode func([]byte) (Request, error),
	handle operationHandler[Request, Result],
	validate func(Result) error,
) {
	mux.HandleFunc("POST "+path, serveOperation(logger, operation, authenticator, decode, nil, handle, validate))
}

func serveOperation[Request, Result any](
	logger *slog.Logger,
	operation string,
	authenticator Authenticator,
	decode func([]byte) (Request, error),
	deadline func(Request) time.Time,
	handle operationHandler[Request, Result],
	validate func(Result) error,
) stdhttp.HandlerFunc {
	return func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		started := time.Now()
		requestID := inboundRequestID(request)
		var outcome domain.ErrorCode
		var actor accessActor
		// The access record is emitted from a defer so every early return is
		// accounted for, and it reads the variables below at emit time so it
		// reports the request id the client was actually answered with.
		defer func() {
			logAccess(logger, operation, requestID, outcome, actor, started)
		}()
		// Routing every rejection through one closure keeps the logged outcome
		// and the client's error code from drifting apart.
		reject := func(failure contracts.ErrorDTO) {
			outcome = failure.Code
			writeProblem(writer, failure)
		}

		if request.Header.Get("Content-Encoding") != "" || !isJSONContentType(request.Header.Get("Content-Type")) {
			reject(invalidSchema(requestID, "content_type", "request must use unencoded application/json"))
			return
		}
		authenticationRequest := request.Clone(request.Context())
		authenticationRequest.Body = nil
		authenticationRequest.GetBody = nil
		evidence, failure, err := authenticator.Authenticate(request.Context(), authenticationRequest, operation, requestID)
		if err != nil || evidence.Valid() == (failure != nil) {
			logOperationFailure(logger, operation, requestID, "authenticate", reportable(err))
			reject(internalFailure(requestID))
			return
		}
		if failure != nil {
			reject(checkedFailure(requestID, failure))
			return
		}
		actor = actorOf(evidence)
		body, err := readBody(writer, request)
		if err != nil {
			message := "request body is invalid JSON"
			if errors.Is(err, contracts.ErrPayloadTooLarge) {
				message = fmt.Sprintf("request body exceeds %d bytes", contracts.MaxCommandJSONBytes)
			}
			logOperationFailure(logger, operation, requestID, "read_body", err)
			reject(invalidSchema(requestID, "body", message))
			return
		}
		input, err := decode(body)
		if err != nil {
			logOperationFailure(logger, operation, requestID, "decode_request", err)
			reject(invalidSchema(requestID, "body", "request body does not match the operation schema"))
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
				logOperationFailure(logger, operation, requestID, "handle", reportable(err))
				reject(internalFailure(requestID))
				return
			}
			reject(checkedFailure(requestID, failure))
			return
		}
		if err := validate(result); err != nil {
			logOperationFailure(logger, operation, requestID, "validate_result", err)
			reject(internalFailure(requestID))
			return
		}
		if carried := responseRequestID(result); carried != requestID {
			logOperationFailure(logger, operation, requestID, "correlate_result",
				fmt.Errorf("result carries request id %q", carried))
			reject(internalFailure(requestID))
			return
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			logOperationFailure(logger, operation, requestID, "encode_result", err)
			reject(internalFailure(requestID))
			return
		}
		if len(encoded) > contracts.MaxOutcomeJSONBytes {
			logOperationFailure(logger, operation, requestID, "encode_result",
				fmt.Errorf("result is %d bytes, over the %d byte outcome limit", len(encoded), contracts.MaxOutcomeJSONBytes))
			reject(internalFailure(requestID))
			return
		}
		writer.Header().Set("Content-Type", mediaTypeJSON)
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(stdhttp.StatusOK)
		if _, err := writer.Write(encoded); err != nil {
			// The status line is already committed, so nothing can be reported to
			// the client. The log is the only place a truncated answer surfaces.
			logOperationFailure(logger, operation, requestID, "write_response", err)
		}
	}
}

// accessActor is the identity portion of an access record. It carries opaque
// identifiers only: the credential fingerprint and channel binding on the
// evidence are secrets and must never reach a log line.
type accessActor struct {
	principalID    string
	actorSessionID string
}

func actorOf(evidence AuthenticationEvidence) accessActor {
	actor := accessActor{principalID: evidence.PrincipalID().String()}
	if session, present := evidence.ActorSessionID(); present {
		actor.actorSessionID = session.String()
	}
	return actor
}

// logAccess emits the one record per request that makes a correlation id worth
// minting: without it the id echoed to the client matches nothing anywhere.
func logAccess(
	logger *slog.Logger,
	operation, requestID string,
	outcome domain.ErrorCode,
	actor accessActor,
	started time.Time,
) {
	attributes := []any{
		slog.String("operation", operation),
		slog.String("request_id", requestID),
		slog.Int64("duration_ms", time.Since(started).Milliseconds()),
	}
	if outcome == "" {
		attributes = append(attributes, slog.String("outcome", "ok"))
	} else {
		attributes = append(attributes, slog.String("outcome", "error"), slog.String("error_code", string(outcome)))
	}
	if actor.principalID != "" {
		attributes = append(attributes, slog.String("principal_id", actor.principalID))
	}
	if actor.actorSessionID != "" {
		attributes = append(attributes, slog.String("actor_session_id", actor.actorSessionID))
	}
	logger.Info("http request", attributes...)
}

// logOperationFailure preserves the wrapped cause the sanitized DTO deliberately
// drops. The client keeps the generic message; the %w chain goes here and only
// here.
func logOperationFailure(logger *slog.Logger, operation, requestID, stage string, err error) {
	logger.Error("http operation failed",
		slog.String("operation", operation), slog.String("request_id", requestID),
		slog.String("stage", stage), slog.Any("error", err))
}

func reportable(err error) error {
	if err == nil {
		return errIncoherentResult
	}
	return err
}

// inboundRequestID prefers a caller-supplied correlation id so a client trace
// and this daemon's log share one key, and mints one otherwise. Acceptance is
// decided by round-tripping the candidate through the error contract's own
// validation, so the size and character rule can never drift from contracts.
func inboundRequestID(request *stdhttp.Request) string {
	supplied := request.Header.Values(headerRequestID)
	if len(supplied) != 1 || internalFailure(supplied[0]).Validate() != nil {
		return newRequestID()
	}
	return supplied[0]
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

// statusFor reports the HTTP status a typed error code is served with. The
// mapping itself lives in the contracts package, which also projects it into the
// published OpenAPI document; keeping a second copy here let the served status
// and the documented status drift apart without either side failing.
func statusFor(code domain.ErrorCode) int {
	return contracts.HTTPStatusForErrorCode(code)
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
