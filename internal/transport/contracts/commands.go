package contracts

import (
	"context"
	"errors"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

// W0CommandDispatcher is the proof-bearing command ingress shared by the HTTP
// and MCP transports. The concrete production implementation is the
// application OrchestrationService; the contract seam keeps the handler
// independently testable without a full security registry.
type W0CommandDispatcher interface {
	BootstrapInstallation(context.Context, application.BootstrapInstallationRequest) (application.CommandExecution, error)
	RegisterPrincipal(context.Context, application.RegisterPrincipalRequest) (application.CommandExecution, error)
	CreateWorkspace(context.Context, application.CreateWorkspaceRequest) (application.CommandExecution, error)
	InviteWorkspaceMember(context.Context, application.InviteWorkspaceMemberRequest) (application.CommandExecution, error)
	AcceptWorkspaceMembership(context.Context, application.AcceptWorkspaceMembershipRequest) (application.CommandExecution, error)
	CreateActor(context.Context, application.CreateActorRequest) (application.CommandExecution, error)
	ProposeActorDelegation(context.Context, application.ProposeActorDelegationRequest) (application.CommandExecution, error)
	ActivateActorDelegation(context.Context, application.ActivateActorDelegationRequest) (application.CommandExecution, error)
	BeginDevicePairing(context.Context, application.BeginDevicePairingRequest) (application.CommandExecution, error)
	PairDevice(context.Context, application.PairDeviceRequest) (application.CommandExecution, error)
	StartActorSession(context.Context, application.StartActorSessionRequest) (application.CommandExecution, error)
}

const commandRetryAfterMS uint32 = 1000

// commandRequestContext is the shared authenticated command context assembled
// by the W0CommandAssembler for one command: the transport-sealed
// authentication request, the policy preparation bound to it, and the audit
// request context. Per-operation spec and hash-view assembly happens on top of
// this context.
type commandRequestContext struct {
	authentication application.AuthenticationRequest
	policy         application.PolicyPreparationRequest
	audit          application.AuditRequestContext
}

func (handler *ApplicationHandler) commandContext(
	evidence AuthenticationEvidence,
	requestID string,
	operation application.CommandOperation,
	scope domain.AuthorityScope,
) (commandRequestContext, error) {
	authentication, err := handler.assembler.AuthenticationRequest(evidence, operation, scope)
	if err != nil {
		return commandRequestContext{}, err
	}
	policy, err := handler.assembler.PolicyPreparationRequest(authentication)
	if err != nil {
		return commandRequestContext{}, err
	}
	audit, err := handler.assembler.AuditRequestContext(requestID, requestID, handler.serverReceived())
	if err != nil {
		return commandRequestContext{}, err
	}
	return commandRequestContext{authentication: authentication, policy: policy, audit: audit}, nil
}

// commandSpecBase captures the shared, operation-independent CommandSpec
// fields. The per-operation guards, facts, recovery plan, and request
// fingerprint fill the remaining slots before NewCommandSpec seals the value.
func commandSpecBase(
	metadata CommandMetadataDTO,
	scope domain.AuthorityScope,
	operation domain.OperationName,
	receiptID domain.ReceiptID,
	receiptIdentity application.ReceiptIdentity,
	authorship application.CommandAuthorship,
	timeClass application.AuthorityTimeClass,
) (application.CommandSpecParams, error) {
	major, err := application.NewOperationMajor(1)
	if err != nil {
		return application.CommandSpecParams{}, err
	}
	return application.CommandSpecParams{
		Scope: scope, AuthorityID: metadata.AuthorityID, RequestedEpoch: metadata.AuthorityEpoch,
		CommandID: metadata.CommandID, ReceiptID: receiptID, Operation: operation, OperationMajor: major,
		ReceiptIdentity: receiptIdentity, Authorship: authorship, CorrelationID: metadata.CorrelationID,
		CausationEventID: metadata.CausationID, AuthorityTimeClass: timeClass,
	}, nil
}

// newCommandFacts assigns a fresh event identity to each expected fact in the
// order the operation contract declares. The origin carries the post-command
// aggregate version, which NewCommandSpec cross-checks against the mutation
// plan.
func newCommandFacts(types []domain.EventType, origins []domain.AggregateRef) ([]application.FactExpectation, error) {
	if len(types) != len(origins) {
		return nil, application.ErrInvalidApplicationContract
	}
	facts := make([]application.FactExpectation, len(types))
	for index, eventType := range types {
		eventID, err := domain.NewEventID()
		if err != nil {
			return nil, err
		}
		fact, err := application.NewFactExpectation(eventID, eventType, origins[index])
		if err != nil {
			return nil, err
		}
		facts[index] = fact
	}
	return facts, nil
}

// commandCapabilitySet converts the validated transport capability list into
// the domain capability set the command transition asserts.
func commandCapabilitySet(values []string) (domain.CapabilitySet, error) {
	capabilities := make([]domain.Capability, len(values))
	for index, value := range values {
		capability, err := domain.NewCapability(value)
		if err != nil {
			return domain.CapabilitySet{}, err
		}
		capabilities[index] = capability
	}
	return domain.NewCapabilitySet(capabilities...)
}

func commandCanonical(text string) (application.CanonicalIdentifier, error) {
	return application.NewCanonicalIdentifier(text)
}

func commandExpectedResource(id string, version domain.Version) (application.CommandExpectedResource, error) {
	canonical, err := commandCanonical(id)
	if err != nil {
		return application.CommandExpectedResource{}, err
	}
	return application.CommandExpectedResource{ID: canonical, ExpectedVersion: version.Uint64()}, nil
}

// HandleWorkspaceCreate is the complete workspace.create command ingress: it
// decodes the DTO, assembles the operation spec and canonical hash view from
// the authenticated context, resolves the recovery-capsule signer, dispatches
// through the OrchestrationService seam, and maps the execution to the typed
// result DTO.
func (handler *ApplicationHandler) HandleWorkspaceCreate(
	ctx context.Context,
	evidence AuthenticationEvidence,
	request WorkspaceCreateRequestDTO,
) (WorkspaceCreateResultDTO, *ErrorDTO, error) {
	if handler == nil || handler.commands == nil || handler.assembler == nil || handler.signers == nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	values, err := request.Values()
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	scope, err := domain.WorkspaceScope(values.WorkspaceID)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	admissionScope, err := domain.InstallationScope(values.InstallationID)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	operation, err := domain.NewOperationName(string(application.CommandCreateWorkspace))
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	key, err := domain.NewIdempotencyKey(values.Metadata.IdempotencyKey)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	idempotency, err := domain.NewIdempotencyScope(values.WorkspaceID, values.OwnerPrincipalID, values.ClientInstanceID, operation, key)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	receiptIdentity, err := application.OrdinaryReceiptIdentity(idempotency)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	authorship, err := application.AuthorityAuthorship(values.OwnerPrincipalID)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	receiptID, err := domain.NewReceiptID()
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	context, err := handler.commandContext(evidence, values.Metadata.RequestID, application.CommandCreateWorkspace, scope)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, err
	}
	signer, err := handler.signers.PrepareRecoveryCapsuleSigner(ctx, handler.capsuleKeyID)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, err
	}
	recovery, err := application.PrepareRecoveryCapsulePlan(signer)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, err
	}
	spec, hash, err := workspaceCreateCommand(values, scope, admissionScope, operation, receiptID, receiptIdentity, authorship, recovery)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, err
	}
	alias, err := domain.NewWorkspaceAlias(values.Alias)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	locator, err := domain.NewDiscoveryLocator(values.DiscoveryLocator)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	capabilities, err := commandCapabilitySet(values.OwnerCapabilities)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	execution, err := handler.commands.CreateWorkspace(ctx, application.CreateWorkspaceRequest{
		CommandRequest: application.CommandRequest{
			Spec: spec, HashView: hash, Authentication: context.authentication,
			Policy: context.policy, Audit: context.audit,
		},
		OwnerID:             values.OwnerPrincipalID,
		InstallationGrantID: values.InstallationGrantID,
		WorkspaceID:         values.WorkspaceID,
		Alias:               alias,
		DiscoveryLocator:    locator,
		OwnerMembershipID:   values.OwnerMembershipID,
		OwnerCapabilities:   capabilities,
	})
	if err != nil {
		return workspaceCreateFailure(values.Metadata.RequestID, values, err)
	}
	if rejection, rejected := execution.Rejection(); rejected {
		return workspaceCreateFailure(values.Metadata.RequestID, values, rejection)
	}
	return workspaceCreateResultDTO(values.Metadata.RequestID, values, execution)
}

func workspaceCreateCommand(
	values WorkspaceCreateValues,
	scope domain.AuthorityScope,
	admissionScope domain.AuthorityScope,
	operation domain.OperationName,
	receiptID domain.ReceiptID,
	receiptIdentity application.ReceiptIdentity,
	authorship application.CommandAuthorship,
	recovery application.RecoveryCapsulePlan,
) (application.CommandSpec, application.CommandHashView, error) {
	genesis, err := application.AbsentScopeGenesis(scope, values.Metadata.AuthorityID, values.Metadata.AuthorityEpoch)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	generation, err := application.NewGuardGeneration(1)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	ownerTarget, err := domain.NewAggregateTarget(values.OwnerPrincipalID)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	grantTarget, err := domain.NewAggregateTarget(values.InstallationGrantID)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	workspaceTarget, err := domain.NewAggregateTarget(values.WorkspaceID)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	ownerRef, err := domain.NewAggregateRef(values.OwnerPrincipalID, values.OwnerVersion)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	grantRef, err := domain.NewAggregateRef(values.InstallationGrantID, values.InstallationGrantVersion)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	authority, err := application.CurrentAuthorityEpochGuard(admissionScope, values.Metadata.AuthorityID, values.Metadata.AuthorityEpoch)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	policy, err := application.PolicyRevisionGuard(admissionScope, values.PolicyRevision)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	ownerLifecycle, err := application.LifecycleStatusGuard(ownerTarget, string(domain.PrincipalActive))
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	grantLifecycle, err := application.LifecycleStatusGuard(grantTarget, string(domain.GrantActive))
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	ceiling, err := application.CapabilityCeilingGuard(grantTarget, application.DigestBytes([]byte("workspace-create")))
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	workspaceAbsent, err := domain.ExpectAggregateAbsent(values.WorkspaceID)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	membershipAbsent, err := domain.ExpectAggregateAbsent(values.OwnerMembershipID)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	guards, err := application.NewCommandGuardPlan(application.CommandGuardPlanParams{
		AdmissionScope: admissionScope, AdmissionGeneration: generation,
		Evidence:      []application.EvidenceGuard{authority, policy, ownerLifecycle, grantLifecycle, ceiling},
		Authorization: []domain.AggregateRef{ownerRef, grantRef},
		Disclosure:    []domain.AggregateTarget{ownerTarget, workspaceTarget},
		Mutations:     []domain.AggregateExpectation{workspaceAbsent, membershipAbsent},
		Genesis:       &genesis,
	})
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	workspaceRef, err := domain.NewAggregateRef(values.WorkspaceID, domain.InitialVersion())
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	membershipRef, err := domain.NewAggregateRef(values.OwnerMembershipID, domain.InitialVersion())
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	facts, err := newCommandFacts(
		[]domain.EventType{domain.EventTypeWorkspaceCreated, domain.EventTypeWorkspaceMemberInvited, domain.EventTypeWorkspaceMembershipAccepted},
		[]domain.AggregateRef{workspaceRef, membershipRef, membershipRef},
	)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	base, err := commandSpecBase(values.Metadata, scope, operation, receiptID, receiptIdentity, authorship, application.AuthorityTimeOrdinary)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	base.Guards, base.ExpectedFacts, base.RecoveryCapsule = guards, facts, recovery
	hash, err := workspaceCreateCommandHashView(values, scope)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	fingerprint, err := application.NewProductionCanonicalCodec().HashCommand(hash)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	base.RequestFingerprint = fingerprint
	spec, err := application.NewCommandSpec(base)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	return spec, hash, nil
}

func workspaceCreateCommandHashView(values WorkspaceCreateValues, scope domain.AuthorityScope) (application.CommandHashView, error) {
	owner, err := commandExpectedResource(values.OwnerPrincipalID.String(), values.OwnerVersion)
	if err != nil {
		return nil, err
	}
	grant, err := commandExpectedResource(values.InstallationGrantID.String(), values.InstallationGrantVersion)
	if err != nil {
		return nil, err
	}
	scopeID, err := commandCanonical(scope.ID())
	if err != nil {
		return nil, err
	}
	principal, err := commandCanonical(values.OwnerPrincipalID.String())
	if err != nil {
		return nil, err
	}
	client, err := commandCanonical(values.ClientInstanceID.String())
	if err != nil {
		return nil, err
	}
	correlation, err := commandCanonical(values.Metadata.CorrelationID.String())
	if err != nil {
		return nil, err
	}
	workspaceID, err := commandCanonical(values.WorkspaceID.String())
	if err != nil {
		return nil, err
	}
	membershipID, err := commandCanonical(values.OwnerMembershipID.String())
	if err != nil {
		return nil, err
	}
	context := application.W0CommandHashContextParams{
		ScopeKind: application.StreamScopeWorkspace, ScopeID: scopeID,
		PrincipalID: principal, ClientInstanceID: client, CorrelationID: correlation,
	}
	if values.Metadata.CausationID != nil {
		causation, causalErr := commandCanonical(values.Metadata.CausationID.String())
		if causalErr != nil {
			return nil, causalErr
		}
		context.CausationEventID = causation
	}
	return application.NewCreateWorkspaceCommandHashView(context, application.CreateWorkspaceCommandHashParams{
		Owner: owner, InstallationGrant: grant, WorkspaceID: workspaceID,
		Alias: values.Alias, DiscoveryLocator: values.DiscoveryLocator,
		OwnerMembershipID: membershipID, OwnerCapabilities: values.OwnerCapabilities,
	})
}

func workspaceCreateFailure(requestID string, values WorkspaceCreateValues, err error) (WorkspaceCreateResultDTO, *ErrorDTO, error) {
	var rejection *domain.CommandError
	if !errors.As(err, &rejection) {
		return WorkspaceCreateResultDTO{}, nil, err
	}
	failure, err := commandRejectionDTO(
		requestID, rejection, values.Metadata,
		"workspace:create", &ResourceScopeDTO{Type: domain.AggregateKindWorkspace, ID: values.WorkspaceID.String()},
	)
	if err != nil {
		return WorkspaceCreateResultDTO{}, nil, err
	}
	return WorkspaceCreateResultDTO{}, failure, nil
}

func workspaceCreateResultDTO(
	requestID string,
	values WorkspaceCreateValues,
	execution application.CommandExecution,
) (WorkspaceCreateResultDTO, *ErrorDTO, error) {
	receipt, ok := execution.Receipt()
	if !ok {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidCommandExecution
	}
	view, cursor, present := execution.ResultView()
	if !present {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidCommandExecution
	}
	events := receipt.Events()
	eventIDs := view.EventIDs()
	if uint16(len(eventIDs)) != events.Count() {
		return WorkspaceCreateResultDTO{}, nil, application.ErrInvalidCommandExecution
	}
	result := WorkspaceCreateResultDTO{
		CommandResultMetadataDTO: CommandResultMetadataDTO{
			Schema: SchemaCommandResult, RequestID: requestID, Operation: OperationWorkspaceCreate,
			EventCursor: cursor.String(), EmittedEventIDs: eventIDs,
			AcceptedAt: view.AcceptedAt(), IdempotentReplay: execution.Kind() == application.CommandReplayed,
		},
		Resource: WorkspaceCreateResourceDTO{
			InstallationID:    values.InstallationID,
			WorkspaceID:       values.WorkspaceID,
			WorkspaceState:    string(domain.WorkspaceActive),
			Alias:             values.Alias,
			OwnerPrincipalID:  values.OwnerPrincipalID,
			OwnerMembershipID: values.OwnerMembershipID,
			MembershipState:   string(domain.MembershipActive),
			MembershipVersion: domain.InitialVersion(),
			AuthorityID:       view.AuthorityID(),
			AuthorityEpoch:    view.AuthorityEpoch(),
			PolicyRevision:    values.PolicyRevision.String(),
		},
		ResourceVersion: domain.InitialVersion(),
	}
	if err := result.Validate(); err != nil {
		return WorkspaceCreateResultDTO{}, nil, err
	}
	return result, nil, nil
}

// commandRejectionDTO maps a rejected command execution to the typed error
// DTO. Only codes whose evidence the transport can derive from the request
// context are mapped; codes that require version/state evidence owned by the
// application layer (STALE_VERSION, STATE_CONFLICT, NOT_FOUND, lease and fence
// rejections) surface as internal failures until the application layer exposes
// the rejection details it holds.
func commandRejectionDTO(
	requestID string,
	rejection *domain.CommandError,
	metadata CommandMetadataDTO,
	deniedCapability string,
	resourceScope *ResourceScopeDTO,
) (*ErrorDTO, error) {
	if rejection == nil {
		return nil, application.ErrInvalidApplicationContract
	}
	failure := &ErrorDTO{
		Schema: SchemaError, RequestID: requestID, Code: rejection.Code(),
		Category: rejection.Category(), Message: commandFailureMessage(rejection.Code()),
		Retryable: rejection.Retryable(),
	}
	switch rejection.Code() {
	case domain.ErrorCodeUnauthenticated:
		failure.Details.Recovery = RecoveryReauthenticate
	case domain.ErrorCodeSessionExpired:
		failure.Details.Recovery = RecoveryResumeSession
	case domain.ErrorCodeForbidden, domain.ErrorCodeCapabilityRequired:
		failure.Details.DeniedCapability = deniedCapability
		failure.Details.ResourceScope = resourceScope
	case domain.ErrorCodeIdempotencyKeyReused:
		failure.Details.DomainConflict = domain.ConflictIdempotency
		failure.Details.IdempotencyKey = metadata.IdempotencyKey
	case domain.ErrorCodeCommandIDReused:
		commandID := metadata.CommandID
		failure.Details.CommandID = &commandID
	case domain.ErrorCodeCommandInProgress:
		failure.Details.Recovery = RecoveryRetryAfterDelay
		failure.Details.IdempotencyKey = metadata.IdempotencyKey
		retryAfter := commandRetryAfterMS
		failure.RetryAfterMS = &retryAfter
	case domain.ErrorCodeRateLimited, domain.ErrorCodeBackpressure:
		failure.Details.Recovery = RecoveryRetryAfterDelay
		retryAfter := commandRetryAfterMS
		failure.RetryAfterMS = &retryAfter
	case domain.ErrorCodeDependencyUnavailable:
		failure.Details.Recovery = RecoveryRetryDependency
		failure.Details.Dependency = "orchestration"
		retryAfter := commandRetryAfterMS
		failure.RetryAfterMS = &retryAfter
	case domain.ErrorCodeDeadlineExceeded:
		failure.Details.Recovery = RecoveryInspectCommandResult
		failure.Details.IdempotencyKey = metadata.IdempotencyKey
	case domain.ErrorCodeInternal:
		failure.Details.Recovery = RecoveryRetrySameCommand
	default:
		return nil, application.ErrInvalidApplicationContract
	}
	if err := failure.Validate(); err != nil {
		return nil, err
	}
	return failure, nil
}

func commandFailureMessage(code domain.ErrorCode) string {
	switch code {
	case domain.ErrorCodeUnauthenticated:
		return "Authentication is required."
	case domain.ErrorCodeSessionExpired:
		return "The authenticated identity is no longer active."
	case domain.ErrorCodeForbidden, domain.ErrorCodeCapabilityRequired:
		return "The identity is not authorized for this command."
	case domain.ErrorCodeIdempotencyKeyReused:
		return "This idempotency key was already accepted for a different command."
	case domain.ErrorCodeCommandIDReused:
		return "This command identity was already accepted."
	case domain.ErrorCodeCommandInProgress:
		return "This command is still being processed."
	case domain.ErrorCodeRateLimited:
		return "The identity is temporarily rate limited."
	case domain.ErrorCodeBackpressure:
		return "The command is temporarily capacity constrained."
	case domain.ErrorCodeDependencyUnavailable:
		return "A required dependency is temporarily unavailable."
	case domain.ErrorCodeDeadlineExceeded:
		return "The command exceeded its deadline."
	case domain.ErrorCodeInternal:
		return "The command failed internally."
	default:
		return "The command failed."
	}
}

var _ WorkspaceCreateHandler = (*ApplicationHandler)(nil)
