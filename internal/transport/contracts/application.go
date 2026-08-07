package contracts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const queryRetryAfterMS uint32 = 1000

// ApplicationHandler is the transport-neutral production dispatcher shared by
// HTTP and MCP. Query methods dispatch the complete W0 read surface; command
// methods are the proof-bearing ingress seam onto the application
// OrchestrationService. Every dependency is mandatory so a partially composed
// handler fails closed at construction instead of mid-request.
type ApplicationHandler struct {
	queries        *application.QueryService
	commands       W0CommandDispatcher
	assembler      *W0CommandAssembler
	signers        application.RecoveryCapsuleSignerLookup
	capsuleKeyID   string
	serverReceived func() time.Time
}

func NewApplicationHandler(
	queries *application.QueryService,
	commands W0CommandDispatcher,
	assembler *W0CommandAssembler,
	signers application.RecoveryCapsuleSignerLookup,
	capsuleKeyID string,
	serverReceived func() time.Time,
) (*ApplicationHandler, error) {
	if queries == nil || commands == nil || assembler == nil || signers == nil ||
		capsuleKeyID == "" || serverReceived == nil {
		return nil, application.ErrInvalidApplicationContract
	}
	return &ApplicationHandler{
		queries: queries, commands: commands, assembler: assembler, signers: signers,
		capsuleKeyID: capsuleKeyID, serverReceived: serverReceived,
	}, nil
}

func (handler *ApplicationHandler) HandleContextGet(
	ctx context.Context,
	evidence AuthenticationEvidence,
	request ContextGetRequestDTO,
) (ContextPageDTO, *ErrorDTO, error) {
	if handler == nil || handler.queries == nil {
		return ContextPageDTO{}, nil, application.ErrInvalidApplicationContract
	}
	subject, err := querySubject(evidence, request.ActorSessionID)
	if err != nil || request.Validate() != nil {
		return ContextPageDTO{}, nil, application.ErrInvalidApplicationContract
	}
	var cursor application.EventCursor
	if request.Cursor != nil {
		cursor, err = application.NewEventCursor(*request.Cursor)
		if err != nil {
			return ContextPageDTO{}, nil, application.ErrInvalidApplicationContract
		}
	}
	page, err := handler.queries.GetContext(ctx, subject, cursor, request.Limit)
	if err != nil {
		failure, internal := queryErrorDTO(request.RequestID, "context:read", request.ActorSessionID, err)
		return ContextPageDTO{}, failure, internal
	}
	result, err := contextPageDTO(request.RequestID, page)
	if err != nil {
		return ContextPageDTO{}, nil, err
	}
	return result, nil, nil
}

func (handler *ApplicationHandler) HandleEventsSync(
	ctx context.Context,
	evidence AuthenticationEvidence,
	request EventsSyncRequestDTO,
) (EventPageDTO, *ErrorDTO, error) {
	if handler == nil || handler.queries == nil {
		return EventPageDTO{}, nil, application.ErrInvalidApplicationContract
	}
	subject, err := querySubject(evidence, request.ActorSessionID)
	if err != nil || request.Validate() != nil {
		return EventPageDTO{}, nil, application.ErrInvalidApplicationContract
	}
	after, err := application.NewEventCursor(request.AfterCursor)
	if err != nil {
		return EventPageDTO{}, nil, application.ErrInvalidApplicationContract
	}
	page, err := handler.queries.SyncEvents(ctx, subject, after, request.Limit)
	if err != nil {
		failure, internal := queryErrorDTO(request.RequestID, "events:sync", request.ActorSessionID, err)
		return EventPageDTO{}, failure, internal
	}
	result, err := eventPageDTO(request.RequestID, page)
	if err != nil {
		return EventPageDTO{}, nil, err
	}
	return result, nil, nil
}

func querySubject(evidence AuthenticationEvidence, requested domain.ActorSessionID) (application.QuerySubject, error) {
	if !evidence.Valid() {
		return application.QuerySubject{}, application.ErrInvalidApplicationContract
	}
	session, present := evidence.ActorSessionID()
	if !present || session != requested {
		return application.QuerySubject{}, application.ErrInvalidApplicationContract
	}
	return application.NewQuerySubject(evidence.PrincipalID(), session)
}

func contextPageDTO(requestID string, page application.ContextPage) (ContextPageDTO, error) {
	result := ContextPageDTO{
		Schema: SchemaContextPage, RequestID: requestID, Operation: OperationContextGet,
		Deltas: make([]ContextDeltaDTO, 0, len(page.Deltas())), NextCursor: page.NextCursor().String(),
		HeadCursor: page.HeadCursor().String(), HasMore: page.HasMore(),
	}
	if checkpoint, present := page.Checkpoint(); present {
		mapped, err := contextCheckpointDTO(checkpoint)
		if err != nil {
			return ContextPageDTO{}, err
		}
		result.Checkpoint = &mapped
	}
	for _, delta := range page.Deltas() {
		result.Deltas = append(result.Deltas, ContextDeltaDTO{
			Schema: SchemaContextDelta, EventID: delta.EventID(), DeltaType: string(delta.DeltaType()),
			Resource: ResourceScopeDTO{Type: delta.Resource().Kind(), ID: delta.Resource().ID()},
			Version:  delta.Version(), Value: json.RawMessage(delta.Value()), AfterCursor: delta.AfterCursor().String(),
		})
	}
	if err := result.Validate(); err != nil {
		return ContextPageDTO{}, fmt.Errorf("map application context page: %w", err)
	}
	return result, nil
}

func contextCheckpointDTO(checkpoint application.ContextCheckpoint) (ContextCheckpointDTO, error) {
	result := ContextCheckpointDTO{
		Schema: SchemaContextCheckpoint, CheckpointID: ContextCheckpointIDDTO(checkpoint.CheckpointID().String()),
		AuthorityID: checkpoint.AuthorityID(), AuthorityEpoch: checkpoint.AuthorityEpoch(),
		WorkspaceID: checkpoint.Session().WorkspaceID(), Grants: []ContextResourceDTO{},
		Collaborators: []ContextResourceDTO{}, ThroughCursor: checkpoint.ThroughCursor().String(),
		ProjectionVersion: checkpoint.ProjectionVersion(), ServerTime: checkpoint.ServerTime(),
	}
	for _, record := range checkpoint.Records() {
		resource := ContextResourceDTO{ID: record.ID(), Version: record.Version(), State: string(record.LifecycleState())}
		switch record.Kind() {
		case application.ContextRecordWorkspace:
			resource.Type = domain.AggregateKindWorkspace
			result.Workspace = resource
		case application.ContextRecordPrincipal:
			resource.Type = domain.AggregateKindPrincipal
			result.Principal = resource
		case application.ContextRecordActor:
			resource.Type = domain.AggregateKindActor
			result.Actor = resource
		case application.ContextRecordMembership:
			resource.Type = domain.AggregateKindMembership
			result.Membership = resource
		case application.ContextRecordDelegation:
			resource.Type = domain.AggregateKindActorDelegation
			result.Delegation = resource
		case application.ContextRecordSession:
			resource.Type = domain.AggregateKindActorSession
			result.ActorSession = resource
		case application.ContextRecordDevice:
			resource.Type = domain.AggregateKindDevice
			result.Device = &resource
		case application.ContextRecordGrant:
			resource.Type = domain.AggregateKindGrant
			result.Grants = append(result.Grants, resource)
		case application.ContextRecordCollaborator:
			resource.Type = domain.AggregateKindActor
			result.Collaborators = append(result.Collaborators, resource)
		default:
			return ContextCheckpointDTO{}, application.ErrInvalidQuery
		}
	}
	if err := result.Validate(); err != nil {
		return ContextCheckpointDTO{}, fmt.Errorf("map application context checkpoint: %w", err)
	}
	return result, nil
}

func eventPageDTO(requestID string, page application.EventsPage) (EventPageDTO, error) {
	result := EventPageDTO{
		Schema: SchemaEventPage, RequestID: requestID, Operation: OperationEventsSync,
		Events: make([]RawEventEnvelopeDTO, 0, len(page.Events())), NextCursor: page.NextCursor().String(),
		HeadCursor: page.HeadCursor().String(), HasMore: page.HasMore(),
	}
	for _, event := range page.Events() {
		mapped, err := eventDTO(event)
		if err != nil {
			return EventPageDTO{}, err
		}
		result.Events = append(result.Events, mapped)
	}
	if err := result.Validate(); err != nil {
		return EventPageDTO{}, fmt.Errorf("map application event page: %w", err)
	}
	return result, nil
}

func eventDTO(event application.SyncedEvent) (RawEventEnvelopeDTO, error) {
	result := RawEventEnvelopeDTO{
		Schema: SchemaEventEnvelope, EventID: event.EventID(), EventType: string(event.EventType()),
		EventVersion: uint32(event.EventVersion().Uint16()), AuthorityID: event.AuthorityID(), AuthorityEpoch: event.AuthorityEpoch(),
		OriginPosition: event.OriginPosition(), Aggregate: EventAggregateDTO{
			Type: event.AggregateKind(), ID: event.AggregateID(), Version: event.AggregateVersion(),
		},
		PrincipalID: event.PrincipalID(), ActorID: event.ActorID(), ActorSessionID: event.ActorSessionID(),
		CommandID: event.CommandID(), CausationID: event.CausationID(), CorrelationID: event.CorrelationID(),
		OccurredAt: event.OccurredAt(), RecordedAt: event.RecordedAt(), Payload: json.RawMessage(event.Payload()),
		Extensions: json.RawMessage(`{}`),
	}
	switch event.Scope().Kind() {
	case domain.ScopeKindInstallation:
		id, err := domain.ParseInstallationID(event.Scope().ID())
		if err != nil {
			return RawEventEnvelopeDTO{}, err
		}
		result.InstallationID = &id
	case domain.ScopeKindWorkspace:
		id, err := domain.ParseWorkspaceID(event.Scope().ID())
		if err != nil {
			return RawEventEnvelopeDTO{}, err
		}
		result.WorkspaceID = &id
	default:
		return RawEventEnvelopeDTO{}, application.ErrInvalidQuery
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	validated, err := DecodeEventEnvelope(encoded)
	if err != nil {
		return RawEventEnvelopeDTO{}, fmt.Errorf("map application event: %w", err)
	}
	return validated, nil
}

func queryErrorDTO(
	requestID, capability string,
	session domain.ActorSessionID,
	err error,
) (*ErrorDTO, error) {
	var rejection *domain.CommandError
	if !errors.As(err, &rejection) {
		return nil, err
	}
	details := ErrorDetailsDTO{}
	var message string
	switch rejection.Code() {
	case domain.ErrorCodeUnauthenticated:
		message, details.Recovery = "Authentication is required.", RecoveryReauthenticate
	case domain.ErrorCodeSessionExpired:
		message, details.Recovery = "The actor session is no longer active.", RecoveryResumeSession
	case domain.ErrorCodeForbidden, domain.ErrorCodeCapabilityRequired:
		message = "The actor session is not authorized for this query."
		details.DeniedCapability = capability
		details.ResourceScope = &ResourceScopeDTO{Type: domain.AggregateKindActorSession, ID: session.String()}
	case domain.ErrorCodeCursorInvalid:
		message, details.Recovery = "The event cursor is invalid.", RecoveryDiscardCursor
	case domain.ErrorCodeCursorScopeMismatch:
		message, details.Recovery = "The event cursor belongs to another query scope.", RecoveryRestartQuery
	case domain.ErrorCodeCursorExpired:
		message, details.Recovery = "The event cursor is no longer retained.", RecoveryObtainCheckpoint
	case domain.ErrorCodeBackpressure:
		message, details.Recovery = "The query is temporarily capacity constrained.", RecoveryRetryAfterDelay
	default:
		return nil, err
	}
	failure := &ErrorDTO{
		Schema: SchemaError, RequestID: requestID, Code: rejection.Code(), Category: rejection.Category(),
		Message: message, Retryable: rejection.Retryable(), Details: details,
	}
	if rejection.Code() == domain.ErrorCodeBackpressure {
		delay := queryRetryAfterMS
		failure.RetryAfterMS = &delay
	}
	if err := failure.Validate(); err != nil {
		return nil, fmt.Errorf("map application query failure: %w", err)
	}
	return failure, nil
}

var _ ContextGetHandler = (*ApplicationHandler)(nil)
var _ EventsSyncHandler = (*ApplicationHandler)(nil)
