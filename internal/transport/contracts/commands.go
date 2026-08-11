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
	ObserveWorkRef(context.Context, application.ObserveWorkRefRequest) (application.CommandExecution, error)
	CreateObjectiveAndWork(context.Context, application.CreateObjectiveAndWorkRequest) (application.CommandExecution, error)
	ActivateObjective(context.Context, application.ActivateObjectiveRequest) (application.CommandExecution, error)
	PlanRunWithBindings(context.Context, application.PlanRunWithBindingsRequest) (application.CommandExecution, error)
	JoinRun(context.Context, application.JoinRunRequest) (application.CommandExecution, error)
	StartRun(context.Context, application.StartRunRequest) (application.CommandExecution, error)
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

// commandPrincipal derives the receipt principal for a W1 command from the
// authenticated evidence. The dispatcher guarantees evidence principal equals
// the authorship principal (adapter for work_ref.observe, workload principal
// for the actor-session work commands).
func commandPrincipal(evidence AuthenticationEvidence) domain.PrincipalID {
	return evidence.PrincipalID()
}

// w1HashContext assembles the semantic hash-view context shared by every W1
// command: workspace scope, evidence principal, client instance, and (for the
// actor-session work commands) the actor/session attribution.
func w1HashContext(
	values CommandMetadataDTO,
	workspaceID domain.WorkspaceID,
	principal domain.PrincipalID,
	client domain.ClientInstanceID,
	actorID domain.ActorID,
	sessionID domain.ActorSessionID,
) (application.W0CommandHashContextParams, error) {
	scopeID, err := commandCanonical(workspaceID.String())
	if err != nil {
		return application.W0CommandHashContextParams{}, err
	}
	principalCanonical, err := commandCanonical(principal.String())
	if err != nil {
		return application.W0CommandHashContextParams{}, err
	}
	clientCanonical, err := commandCanonical(client.String())
	if err != nil {
		return application.W0CommandHashContextParams{}, err
	}
	correlation, err := commandCanonical(values.CorrelationID.String())
	if err != nil {
		return application.W0CommandHashContextParams{}, err
	}
	context := application.W0CommandHashContextParams{
		ScopeKind: application.StreamScopeWorkspace, ScopeID: scopeID,
		PrincipalID: principalCanonical, ClientInstanceID: clientCanonical, CorrelationID: correlation,
	}
	if !actorID.IsZero() {
		actorCanonical, actorErr := commandCanonical(actorID.String())
		if actorErr != nil {
			return application.W0CommandHashContextParams{}, actorErr
		}
		sessionCanonical, sessionErr := commandCanonical(sessionID.String())
		if sessionErr != nil {
			return application.W0CommandHashContextParams{}, sessionErr
		}
		context.ActorID, context.ActorSessionID = actorCanonical, sessionCanonical
	}
	if values.CausationID != nil {
		causation, causalErr := commandCanonical(values.CausationID.String())
		if causalErr != nil {
			return application.W0CommandHashContextParams{}, causalErr
		}
		context.CausationEventID = causation
	}
	return context, nil
}

// HandleWorkRefObserve is the complete work_ref.observe command ingress.
func (handler *ApplicationHandler) HandleWorkRefObserve(
	ctx context.Context,
	evidence AuthenticationEvidence,
	request WorkRefObserveRequestDTO,
) (WorkRefObserveResultDTO, *ErrorDTO, error) {
	if handler == nil || handler.commands == nil || handler.assembler == nil {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	values, err := request.Values()
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	scope, err := domain.WorkspaceScope(values.WorkspaceID)
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	operation, err := domain.NewOperationName(string(application.CommandObserveWorkRef))
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	principal := commandPrincipal(evidence)
	if principal.IsZero() || principal != values.AdapterID {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	key, err := domain.NewIdempotencyKey(values.Metadata.IdempotencyKey)
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	idempotency, err := domain.NewIdempotencyScope(values.WorkspaceID, principal, values.ClientInstanceID, operation, key)
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	receiptIdentity, err := application.OrdinaryReceiptIdentity(idempotency)
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	authorship, err := application.AuthorityAuthorship(principal)
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	receiptID, err := domain.NewReceiptID()
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	context, err := handler.commandContext(evidence, values.Metadata.RequestID, application.CommandObserveWorkRef, scope)
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, err
	}
	spec, hash, err := workRefObserveCommand(values, scope, operation, receiptID, receiptIdentity, authorship, context.policy.PolicyRevision())
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, err
	}
	execution, err := handler.commands.ObserveWorkRef(ctx, application.ObserveWorkRefRequest{
		CommandRequest: application.CommandRequest{
			Spec: spec, HashView: hash, Authentication: context.authentication,
			Policy: context.policy, Audit: context.audit,
		},
		AdapterID:                    values.AdapterID,
		WorkspaceID:                  values.WorkspaceID,
		WorkReferenceID:              values.WorkReferenceID,
		ExpectedWorkReferenceVersion: values.ExpectedWorkReferenceVersion,
		Observation:                  values.Observation,
		PreviousProviderVersion:      values.PreviousProviderVersion,
	})
	if err != nil {
		return workRefObserveFailure(values.Metadata.RequestID, values, err)
	}
	if rejection, rejected := execution.Rejection(); rejected {
		return workRefObserveFailure(values.Metadata.RequestID, values, rejection)
	}
	return workRefObserveResultDTO(values.Metadata.RequestID, values, execution)
}

func workRefObserveCommand(
	values WorkRefObserveValues,
	scope domain.AuthorityScope,
	operation domain.OperationName,
	receiptID domain.ReceiptID,
	receiptIdentity application.ReceiptIdentity,
	authorship application.CommandAuthorship,
	policyRevision domain.PolicyRevision,
) (application.CommandSpec, application.CommandHashView, error) {
	generation, err := application.NewGuardGeneration(1)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	adapterTarget, err := domain.NewAggregateTarget(values.AdapterID)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	workspaceTarget, err := domain.NewAggregateTarget(values.WorkspaceID)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	adapterRef, err := domain.NewAggregateRef(values.AdapterID, values.AdapterVersion)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	workspaceRef, err := domain.NewAggregateRef(values.WorkspaceID, values.WorkspaceVersion)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	authority, err := application.CurrentAuthorityEpochGuard(scope, values.Metadata.AuthorityID, values.Metadata.AuthorityEpoch)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	policy, err := application.PolicyRevisionGuard(scope, policyRevision)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	// The work reference is absent on first observation and pinned to its
	// expected version on subsequent observations.
	var mutation domain.AggregateExpectation
	var postVersion domain.Version
	if values.ExpectedWorkReferenceVersion.IsZero() {
		mutation, err = domain.ExpectAggregateAbsent(values.WorkReferenceID)
		postVersion = domain.InitialVersion()
	} else {
		mutation, err = domain.ExpectAggregateVersion(values.WorkReferenceID, values.ExpectedWorkReferenceVersion)
		if err == nil {
			postVersion, err = values.ExpectedWorkReferenceVersion.Next()
		}
	}
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	guards, err := application.NewCommandGuardPlan(application.CommandGuardPlanParams{
		AdmissionScope: scope, AdmissionGeneration: generation,
		Evidence:      []application.EvidenceGuard{authority, policy},
		Authorization: []domain.AggregateRef{adapterRef, workspaceRef},
		Disclosure:    []domain.AggregateTarget{adapterTarget, workspaceTarget},
		Mutations:     []domain.AggregateExpectation{mutation},
	})
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	workReferenceRef, err := domain.NewAggregateRef(values.WorkReferenceID, postVersion)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	facts, err := newCommandFacts(
		[]domain.EventType{domain.EventTypeWorkRefObserved},
		[]domain.AggregateRef{workReferenceRef},
	)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	base, err := commandSpecBase(values.Metadata, scope, operation, receiptID, receiptIdentity, authorship, application.AuthorityTimeOrdinary)
	if err != nil {
		return application.CommandSpec{}, nil, err
	}
	base.Guards, base.ExpectedFacts, base.RecoveryCapsule = guards, facts, application.NotApplicableRecoveryCapsulePlan()
	hash, err := workRefObserveCommandHashView(values)
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

func workRefObserveCommandHashView(values WorkRefObserveValues) (application.CommandHashView, error) {
	adapter, err := commandExpectedResource(values.AdapterID.String(), values.AdapterVersion)
	if err != nil {
		return nil, err
	}
	workspace, err := commandExpectedResource(values.WorkspaceID.String(), values.WorkspaceVersion)
	if err != nil {
		return nil, err
	}
	workReferenceID, err := commandCanonical(values.WorkReferenceID.String())
	if err != nil {
		return nil, err
	}
	adapterPrincipal, err := commandCanonical(values.AdapterID.String())
	if err != nil {
		return nil, err
	}
	context, err := w1HashContext(values.Metadata, values.WorkspaceID, values.AdapterID, values.ClientInstanceID, domain.ActorID{}, domain.ActorSessionID{})
	if err != nil {
		return nil, err
	}
	params := application.ObserveWorkRefCommandHashParams{
		Adapter: adapter, Workspace: workspace, WorkReferenceID: workReferenceID,
		ProviderNamespace:  values.Observation.Namespace().String(),
		ProviderObjectID:   values.Observation.ObjectID().String(),
		ProviderLocator:    values.Observation.Locator().String(),
		ProviderVersion:    values.Observation.ProviderVersion().String(),
		SelectedFields:     values.Observation.Fields(),
		AdapterPrincipalID: adapterPrincipal, ObservedAt: values.Observation.ObservedAt(),
		PreviousProviderVersion: values.PreviousProviderVersion.String(),
	}
	if !values.ExpectedWorkReferenceVersion.IsZero() {
		expected := values.ExpectedWorkReferenceVersion.Uint64()
		params.ExpectedWorkReferenceVersion = &expected
	}
	return application.NewObserveWorkRefCommandHashView(context, params)
}

func workRefObserveFailure(requestID string, values WorkRefObserveValues, err error) (WorkRefObserveResultDTO, *ErrorDTO, error) {
	var rejection *domain.CommandError
	if !errors.As(err, &rejection) {
		return WorkRefObserveResultDTO{}, nil, err
	}
	failure, err := commandRejectionDTO(
		requestID, rejection, values.Metadata,
		"work_ref:observe", &ResourceScopeDTO{Type: domain.AggregateKindWorkReference, ID: values.WorkReferenceID.String()},
	)
	if err != nil {
		return WorkRefObserveResultDTO{}, nil, err
	}
	return WorkRefObserveResultDTO{}, failure, nil
}

func workRefObserveResultDTO(
	requestID string,
	values WorkRefObserveValues,
	execution application.CommandExecution,
) (WorkRefObserveResultDTO, *ErrorDTO, error) {
	receipt, ok := execution.Receipt()
	if !ok {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidCommandExecution
	}
	view, cursor, present := execution.ResultView()
	if !present {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidCommandExecution
	}
	events := receipt.Events()
	eventIDs := view.EventIDs()
	if uint16(len(eventIDs)) != events.Count() {
		return WorkRefObserveResultDTO{}, nil, application.ErrInvalidCommandExecution
	}
	resourceVersion := domain.InitialVersion()
	if !values.ExpectedWorkReferenceVersion.IsZero() {
		next, err := values.ExpectedWorkReferenceVersion.Next()
		if err != nil {
			return WorkRefObserveResultDTO{}, nil, err
		}
		resourceVersion = next
	}
	result := WorkRefObserveResultDTO{
		CommandResultMetadataDTO: CommandResultMetadataDTO{
			Schema: SchemaCommandResult, RequestID: requestID, Operation: OperationWorkRefObserve,
			EventCursor: cursor.String(), EmittedEventIDs: eventIDs,
			AcceptedAt: view.AcceptedAt(), IdempotentReplay: execution.Kind() == application.CommandReplayed,
		},
		Resource: WorkRefObserveResourceDTO{
			WorkspaceID: values.WorkspaceID, WorkReferenceID: values.WorkReferenceID,
			ResourceVersion: resourceVersion, AdapterPrincipalID: values.AdapterID,
			ProviderNamespace: values.Observation.Namespace().String(),
			ProviderObjectID:  values.Observation.ObjectID().String(),
			ProviderLocator:   values.Observation.Locator().String(),
			ProviderVersion:   values.Observation.ProviderVersion().String(),
			ObservedAt:        values.Observation.ObservedAt(),
		},
	}
	if err := result.Validate(); err != nil {
		return WorkRefObserveResultDTO{}, nil, err
	}
	return result, nil, nil
}

type w1CommandPreparation struct {
	scope      domain.AuthorityScope
	operation  domain.OperationName
	receiptID  domain.ReceiptID
	receipt    application.ReceiptIdentity
	authorship application.CommandAuthorship
	context    commandRequestContext
}

type w1LifecycleEvidence struct {
	target domain.AggregateTarget
	status string
}

func (handler *ApplicationHandler) prepareW1Command(
	evidence AuthenticationEvidence,
	metadata CommandMetadataDTO,
	workspaceID domain.WorkspaceID,
	actorID domain.ActorID,
	actorVersion domain.Version,
	sessionID domain.ActorSessionID,
	sessionVersion domain.Version,
	clientID domain.ClientInstanceID,
	commandOperation application.CommandOperation,
) (w1CommandPreparation, error) {
	if handler == nil || handler.commands == nil || handler.assembler == nil || !evidence.Valid() {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	evidenceSession, present := evidence.ActorSessionID()
	evidenceSessionVersion, versionPresent := evidence.ActorSessionRevision()
	if evidence.PrincipalID().IsZero() || !present || !versionPresent || evidenceSession != sessionID ||
		evidenceSessionVersion != sessionVersion || actorID.IsZero() || !actorVersion.Valid() {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	scope, err := domain.WorkspaceScope(workspaceID)
	if err != nil {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	operation, err := domain.NewOperationName(string(commandOperation))
	if err != nil {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	key, err := domain.NewIdempotencyKey(metadata.IdempotencyKey)
	if err != nil {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	idempotency, err := domain.NewIdempotencyScope(workspaceID, evidence.PrincipalID(), clientID, operation, key)
	if err != nil {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	receipt, err := application.OrdinaryReceiptIdentity(idempotency)
	if err != nil {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	attribution, err := application.NewActorAttribution(actorID, sessionID)
	if err != nil {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	authorship, err := application.WorkAuthorship(evidence.PrincipalID(), attribution)
	if err != nil {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	receiptID, err := domain.NewReceiptID()
	if err != nil {
		return w1CommandPreparation{}, application.ErrInvalidApplicationContract
	}
	requestContext, err := handler.commandContext(evidence, metadata.RequestID, commandOperation, scope)
	if err != nil {
		return w1CommandPreparation{}, err
	}
	return w1CommandPreparation{scope, operation, receiptID, receipt, authorship, requestContext}, nil
}

func w1CommandSpec(
	metadata CommandMetadataDTO,
	prepared w1CommandPreparation,
	actorID domain.ActorID,
	actorVersion domain.Version,
	sessionID domain.ActorSessionID,
	sessionVersion domain.Version,
	references []domain.AggregateRef,
	disclosure []domain.AggregateTarget,
	mutations []domain.AggregateExpectation,
	lifecycle []w1LifecycleEvidence,
	factTypes []domain.EventType,
	factOrigins []domain.AggregateRef,
	hash application.CommandHashView,
) (application.CommandSpec, error) {
	generation, err := application.NewGuardGeneration(1)
	if err != nil {
		return application.CommandSpec{}, err
	}
	actorRef, err := domain.NewAggregateRef(actorID, actorVersion)
	if err != nil {
		return application.CommandSpec{}, err
	}
	sessionRef, err := domain.NewAggregateRef(sessionID, sessionVersion)
	if err != nil {
		return application.CommandSpec{}, err
	}
	authority, err := application.CurrentAuthorityEpochGuard(prepared.scope, metadata.AuthorityID, metadata.AuthorityEpoch)
	if err != nil {
		return application.CommandSpec{}, err
	}
	policy, err := application.PolicyRevisionGuard(prepared.scope, prepared.context.policy.PolicyRevision())
	if err != nil {
		return application.CommandSpec{}, err
	}
	evidenceGuards := []application.EvidenceGuard{authority, policy}
	for _, lifecycleEvidence := range lifecycle {
		guard, guardErr := application.LifecycleStatusGuard(lifecycleEvidence.target, lifecycleEvidence.status)
		if guardErr != nil {
			return application.CommandSpec{}, guardErr
		}
		evidenceGuards = append(evidenceGuards, guard)
	}
	guards, err := application.NewCommandGuardPlan(application.CommandGuardPlanParams{
		AdmissionScope: prepared.scope, AdmissionGeneration: generation,
		Evidence: evidenceGuards, Authorization: []domain.AggregateRef{actorRef, sessionRef},
		References: references, Disclosure: disclosure, Mutations: mutations,
	})
	if err != nil {
		return application.CommandSpec{}, err
	}
	facts, err := newCommandFacts(factTypes, factOrigins)
	if err != nil {
		return application.CommandSpec{}, err
	}
	base, err := commandSpecBase(metadata, prepared.scope, prepared.operation, prepared.receiptID, prepared.receipt, prepared.authorship, application.AuthorityTimeOrdinary)
	if err != nil {
		return application.CommandSpec{}, err
	}
	base.Guards, base.ExpectedFacts, base.RecoveryCapsule = guards, facts, application.NotApplicableRecoveryCapsulePlan()
	base.RequestFingerprint, err = application.NewProductionCanonicalCodec().HashCommand(hash)
	if err != nil {
		return application.CommandSpec{}, err
	}
	return application.NewCommandSpec(base)
}

func w1ExecutionMetadata(requestID, operation string, execution application.CommandExecution, expectedEvents int) (CommandResultMetadataDTO, error) {
	receipt, ok := execution.Receipt()
	if !ok {
		return CommandResultMetadataDTO{}, application.ErrInvalidCommandExecution
	}
	view, cursor, present := execution.ResultView()
	if !present || string(view.Operation()) != operation || len(view.EventIDs()) != expectedEvents ||
		uint16(expectedEvents) != receipt.Events().Count() {
		return CommandResultMetadataDTO{}, application.ErrInvalidCommandExecution
	}
	return CommandResultMetadataDTO{
		Schema: SchemaCommandResult, RequestID: requestID, Operation: operation,
		EventCursor: cursor.String(), EmittedEventIDs: view.EventIDs(), AcceptedAt: view.AcceptedAt(),
		IdempotentReplay: execution.Kind() == application.CommandReplayed,
	}, nil
}

func w1Failure(requestID string, metadata CommandMetadataDTO, capability string, kind domain.AggregateKind, id string, err error) (*ErrorDTO, error) {
	var rejection *domain.CommandError
	if !errors.As(err, &rejection) {
		return nil, err
	}
	return commandRejectionDTO(requestID, rejection, metadata, capability, &ResourceScopeDTO{Type: kind, ID: id})
}

func (handler *ApplicationHandler) HandleObjectiveAndWorkCreate(ctx context.Context, evidence AuthenticationEvidence, request ObjectiveAndWorkCreateRequestDTO) (ObjectiveAndWorkCreateResultDTO, *ErrorDTO, error) {
	values, err := request.Values()
	if err != nil {
		return ObjectiveAndWorkCreateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	prepared, err := handler.prepareW1Command(evidence, values.Metadata, values.WorkspaceID, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, values.ClientInstanceID, application.CommandCreateObjectiveAndWork)
	if err != nil {
		return ObjectiveAndWorkCreateResultDTO{}, nil, err
	}
	session, err := commandExpectedResource(values.ActorSessionID.String(), values.ExpectedSessionVersion)
	if err != nil {
		return ObjectiveAndWorkCreateResultDTO{}, nil, err
	}
	workRef, err := commandExpectedResource(values.WorkReferenceID.String(), values.ExpectedWorkReferenceVersion)
	if err != nil {
		return ObjectiveAndWorkCreateResultDTO{}, nil, err
	}
	hashContext, err := w1HashContext(values.Metadata, values.WorkspaceID, evidence.PrincipalID(), values.ClientInstanceID, values.ActorID, values.ActorSessionID)
	if err != nil {
		return ObjectiveAndWorkCreateResultDTO{}, nil, err
	}
	objectiveID, _ := commandCanonical(values.ObjectiveID.String())
	workUnitID, _ := commandCanonical(values.WorkUnitID.String())
	hash, err := application.NewCreateObjectiveAndWorkCommandHashView(hashContext, application.CreateObjectiveAndWorkCommandHashParams{Session: session, ObjectiveID: objectiveID, ObjectiveTitle: values.ObjectiveTitle, AcceptanceCriteria: values.AcceptanceCriteria, WorkUnitID: workUnitID, WorkUnitTitle: values.WorkUnitTitle, WorkReference: workRef})
	if err != nil {
		return ObjectiveAndWorkCreateResultDTO{}, nil, err
	}
	workRefValue, _ := domain.NewAggregateRef(values.WorkReferenceID, values.ExpectedWorkReferenceVersion)
	objectiveMutation, _ := domain.ExpectAggregateAbsent(values.ObjectiveID)
	workMutation, _ := domain.ExpectAggregateAbsent(values.WorkUnitID)
	objectiveRef, _ := domain.NewAggregateRef(values.ObjectiveID, domain.InitialVersion())
	workUnitRef, _ := domain.NewAggregateRef(values.WorkUnitID, domain.InitialVersion())
	actorTarget, _ := domain.NewAggregateTarget(values.ActorID)
	sessionTarget, _ := domain.NewAggregateTarget(values.ActorSessionID)
	objectiveTarget, _ := domain.NewAggregateTarget(values.ObjectiveID)
	workTarget, _ := domain.NewAggregateTarget(values.WorkUnitID)
	spec, err := w1CommandSpec(values.Metadata, prepared, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, []domain.AggregateRef{workRefValue}, []domain.AggregateTarget{actorTarget, sessionTarget, objectiveTarget, workTarget}, []domain.AggregateExpectation{objectiveMutation, workMutation}, []w1LifecycleEvidence{{actorTarget, string(domain.ActorActive)}, {sessionTarget, string(domain.ActorSessionActive)}}, []domain.EventType{domain.EventTypeObjectiveCreated, domain.EventTypeWorkUnitCreated}, []domain.AggregateRef{objectiveRef, workUnitRef}, hash)
	if err != nil {
		return ObjectiveAndWorkCreateResultDTO{}, nil, err
	}
	execution, err := handler.commands.CreateObjectiveAndWork(ctx, application.CreateObjectiveAndWorkRequest{CommandRequest: application.CommandRequest{Spec: spec, HashView: hash, Authentication: prepared.context.authentication, Policy: prepared.context.policy, Audit: prepared.context.audit}, SessionID: values.ActorSessionID, ObjectiveID: values.ObjectiveID, ObjectiveTitle: values.ObjectiveTitle, AcceptanceCriteria: values.AcceptanceCriteria, WorkUnitID: values.WorkUnitID, WorkUnitTitle: values.WorkUnitTitle, WorkReferenceID: values.WorkReferenceID})
	if err == nil {
		if rejection, rejected := execution.Rejection(); rejected {
			err = rejection
		}
	}
	if err != nil {
		failure, failureErr := w1Failure(values.Metadata.RequestID, values.Metadata, "objective:create", domain.AggregateKindWorkspace, values.WorkspaceID.String(), err)
		return ObjectiveAndWorkCreateResultDTO{}, failure, failureErr
	}
	metadata, err := w1ExecutionMetadata(values.Metadata.RequestID, OperationObjectiveAndWorkCreate, execution, 2)
	if err != nil {
		return ObjectiveAndWorkCreateResultDTO{}, nil, err
	}
	result := ObjectiveAndWorkCreateResultDTO{CommandResultMetadataDTO: metadata, Resource: ObjectiveAndWorkCreateResourceDTO{WorkspaceID: values.WorkspaceID, ObjectiveID: values.ObjectiveID, ObjectiveState: string(domain.ObjectiveDraft), ObjectiveVersion: domain.InitialVersion(), WorkUnitID: values.WorkUnitID, WorkUnitState: string(domain.WorkUnitProposed), WorkUnitVersion: domain.InitialVersion(), WorkReferenceID: values.WorkReferenceID}}
	if err := result.Validate(); err != nil {
		return ObjectiveAndWorkCreateResultDTO{}, nil, err
	}
	return result, nil, nil
}

func (handler *ApplicationHandler) HandleObjectiveActivate(ctx context.Context, evidence AuthenticationEvidence, request ObjectiveActivateRequestDTO) (ObjectiveActivateResultDTO, *ErrorDTO, error) {
	values, err := request.Values()
	if err != nil {
		return ObjectiveActivateResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	prepared, err := handler.prepareW1Command(evidence, values.Metadata, values.WorkspaceID, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, values.ClientInstanceID, application.CommandActivateObjective)
	if err != nil {
		return ObjectiveActivateResultDTO{}, nil, err
	}
	session, _ := commandExpectedResource(values.ActorSessionID.String(), values.ExpectedSessionVersion)
	objective, _ := commandExpectedResource(values.ObjectiveID.String(), values.ExpectedObjectiveVersion)
	hashContext, _ := w1HashContext(values.Metadata, values.WorkspaceID, evidence.PrincipalID(), values.ClientInstanceID, values.ActorID, values.ActorSessionID)
	hash, err := application.NewActivateObjectiveCommandHashView(hashContext, application.ActivateObjectiveCommandHashParams{Session: session, Objective: objective})
	if err != nil {
		return ObjectiveActivateResultDTO{}, nil, err
	}
	mutation, _ := domain.ExpectAggregateVersion(values.ObjectiveID, values.ExpectedObjectiveVersion)
	next, err := values.ExpectedObjectiveVersion.Next()
	if err != nil {
		return ObjectiveActivateResultDTO{}, nil, err
	}
	origin, _ := domain.NewAggregateRef(values.ObjectiveID, next)
	actorTarget, _ := domain.NewAggregateTarget(values.ActorID)
	sessionTarget, _ := domain.NewAggregateTarget(values.ActorSessionID)
	objectiveTarget, _ := domain.NewAggregateTarget(values.ObjectiveID)
	spec, err := w1CommandSpec(values.Metadata, prepared, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, nil, []domain.AggregateTarget{actorTarget, sessionTarget, objectiveTarget}, []domain.AggregateExpectation{mutation}, []w1LifecycleEvidence{{actorTarget, string(domain.ActorActive)}, {sessionTarget, string(domain.ActorSessionActive)}, {objectiveTarget, string(domain.ObjectiveDraft)}}, []domain.EventType{domain.EventTypeObjectiveActivated}, []domain.AggregateRef{origin}, hash)
	if err != nil {
		return ObjectiveActivateResultDTO{}, nil, err
	}
	execution, err := handler.commands.ActivateObjective(ctx, application.ActivateObjectiveRequest{CommandRequest: application.CommandRequest{Spec: spec, HashView: hash, Authentication: prepared.context.authentication, Policy: prepared.context.policy, Audit: prepared.context.audit}, SessionID: values.ActorSessionID, ObjectiveID: values.ObjectiveID})
	if err == nil {
		if rejection, rejected := execution.Rejection(); rejected {
			err = rejection
		}
	}
	if err != nil {
		failure, failureErr := w1Failure(values.Metadata.RequestID, values.Metadata, "objective:activate", domain.AggregateKindWorkspace, values.WorkspaceID.String(), err)
		return ObjectiveActivateResultDTO{}, failure, failureErr
	}
	metadata, err := w1ExecutionMetadata(values.Metadata.RequestID, OperationObjectiveActivate, execution, 1)
	if err != nil {
		return ObjectiveActivateResultDTO{}, nil, err
	}
	result := ObjectiveActivateResultDTO{CommandResultMetadataDTO: metadata, Resource: ObjectiveActivateResourceDTO{WorkspaceID: values.WorkspaceID, ObjectiveID: values.ObjectiveID, ObjectiveState: string(domain.ObjectiveActive), ResourceVersion: next}}
	if err := result.Validate(); err != nil {
		return ObjectiveActivateResultDTO{}, nil, err
	}
	return result, nil, nil
}

func (handler *ApplicationHandler) HandleRunPlanWithBindings(ctx context.Context, evidence AuthenticationEvidence, request RunPlanWithBindingsRequestDTO) (RunPlanWithBindingsResultDTO, *ErrorDTO, error) {
	values, err := request.Values()
	if err != nil {
		return RunPlanWithBindingsResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	prepared, err := handler.prepareW1Command(evidence, values.Metadata, values.WorkspaceID, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, values.ClientInstanceID, application.CommandPlanRunWithBindings)
	if err != nil {
		return RunPlanWithBindingsResultDTO{}, nil, err
	}
	hashContext, err := w1HashContext(values.Metadata, values.WorkspaceID, evidence.PrincipalID(), values.ClientInstanceID, values.ActorID, values.ActorSessionID)
	if err != nil {
		return RunPlanWithBindingsResultDTO{}, nil, err
	}
	operatorSession, _ := commandExpectedResource(values.ActorSessionID.String(), values.ExpectedSessionVersion)
	objective, _ := commandExpectedResource(values.ObjectiveID.String(), values.ExpectedObjectiveVersion)
	workUnit, _ := commandExpectedResource(values.WorkUnitID.String(), values.ExpectedWorkUnitVersion)
	runID, _ := commandCanonical(values.RunID.String())
	wireParticipants := make([]application.CommandRunParticipantPlan, len(values.Participants))
	requestParticipants := make([]application.RunParticipantPlanRequest, len(values.Participants))
	wireBindings := make([]application.CommandRuntimeBindingPlan, len(values.Bindings))
	requestBindings := make([]application.RuntimeBindingPlanRequest, len(values.Bindings))
	references := make([]domain.AggregateRef, 0, 2+2*len(values.Participants))
	objectiveRef, _ := domain.NewAggregateRef(values.ObjectiveID, values.ExpectedObjectiveVersion)
	workUnitRef, _ := domain.NewAggregateRef(values.WorkUnitID, values.ExpectedWorkUnitVersion)
	references = append(references, objectiveRef, workUnitRef)
	mutations := make([]domain.AggregateExpectation, 0, 1+len(values.Participants)+len(values.Bindings))
	runMutation, _ := domain.ExpectAggregateAbsent(values.RunID)
	mutations = append(mutations, runMutation)
	factTypes := []domain.EventType{domain.EventTypeRunPlanned}
	runRef, _ := domain.NewAggregateRef(values.RunID, domain.InitialVersion())
	factOrigins := []domain.AggregateRef{runRef}
	actorTarget, _ := domain.NewAggregateTarget(values.ActorID)
	sessionTarget, _ := domain.NewAggregateTarget(values.ActorSessionID)
	objectiveTarget, _ := domain.NewAggregateTarget(values.ObjectiveID)
	workUnitTarget, _ := domain.NewAggregateTarget(values.WorkUnitID)
	disclosure := []domain.AggregateTarget{actorTarget, sessionTarget, objectiveTarget, workUnitTarget}
	seenDisclosure := map[domain.AggregateTarget]struct{}{actorTarget: {}, sessionTarget: {}, objectiveTarget: {}, workUnitTarget: {}}
	for index, participant := range values.Participants {
		participationID, _ := commandCanonical(participant.ParticipationID.String())
		actor, actorErr := commandExpectedResource(participant.ActorID.String(), participant.ExpectedActorVersion)
		session, sessionErr := commandExpectedResource(participant.SessionID.String(), participant.ExpectedSessionVersion)
		if actorErr != nil || sessionErr != nil {
			return RunPlanWithBindingsResultDTO{}, nil, application.ErrInvalidApplicationContract
		}
		wireParticipants[index] = application.CommandRunParticipantPlan{ParticipationID: participationID, Actor: actor, Session: session, Role: participant.Role}
		requestParticipants[index] = application.RunParticipantPlanRequest{ParticipationID: participant.ParticipationID, ActorID: participant.ActorID, ExpectedActorVersion: participant.ExpectedActorVersion, SessionID: participant.SessionID, ExpectedSessionVersion: participant.ExpectedSessionVersion, Role: participant.Role}
		if participant.ActorID != values.ActorID {
			ref, _ := domain.NewAggregateRef(participant.ActorID, participant.ExpectedActorVersion)
			references = append(references, ref)
		}
		if participant.SessionID != values.ActorSessionID {
			ref, _ := domain.NewAggregateRef(participant.SessionID, participant.ExpectedSessionVersion)
			references = append(references, ref)
		}
		participantTargets := make([]domain.AggregateTarget, 2)
		participantTargets[0], err = domain.NewAggregateTarget(participant.ActorID)
		if err == nil {
			participantTargets[1], err = domain.NewAggregateTarget(participant.SessionID)
		}
		if err != nil {
			return RunPlanWithBindingsResultDTO{}, nil, err
		}
		for _, target := range participantTargets {
			if _, exists := seenDisclosure[target]; !exists {
				disclosure = append(disclosure, target)
				seenDisclosure[target] = struct{}{}
			}
		}
		mutation, _ := domain.ExpectAggregateAbsent(participant.ParticipationID)
		mutations = append(mutations, mutation)
		origin, _ := domain.NewAggregateRef(participant.ParticipationID, domain.InitialVersion())
		factOrigins = append(factOrigins, origin)
		factTypes = append(factTypes, domain.EventTypeRunParticipantInvited)
	}
	for index, binding := range values.Bindings {
		bindingID, _ := commandCanonical(binding.BindingID.String())
		participationID, _ := commandCanonical(binding.ParticipationID.String())
		sessionID, _ := commandCanonical(binding.SessionID.String())
		endpoint, endpointErr := commandExpectedResource(binding.RuntimeEndpointID.String(), binding.ExpectedRuntimeEndpointVersion)
		if endpointErr != nil {
			return RunPlanWithBindingsResultDTO{}, nil, endpointErr
		}
		wireBindings[index] = application.CommandRuntimeBindingPlan{BindingID: bindingID, ParticipationID: participationID, SessionID: sessionID, RuntimeEndpoint: endpoint}
		requestBindings[index] = application.RuntimeBindingPlanRequest{BindingID: binding.BindingID, ParticipationID: binding.ParticipationID, SessionID: binding.SessionID, RuntimeEndpointID: binding.RuntimeEndpointID, ExpectedRuntimeEndpointVersion: binding.ExpectedRuntimeEndpointVersion}
		mutation, _ := domain.ExpectAggregateAbsent(binding.BindingID)
		mutations = append(mutations, mutation)
		origin, _ := domain.NewAggregateRef(binding.BindingID, domain.InitialVersion())
		factOrigins = append(factOrigins, origin)
		factTypes = append(factTypes, domain.EventTypeRuntimeBindingRequested)
	}
	hash, err := application.NewPlanRunWithBindingsCommandHashView(hashContext, application.PlanRunWithBindingsCommandHashParams{OperatorSession: operatorSession, RunID: runID, Objective: objective, WorkUnit: workUnit, Participants: wireParticipants, Bindings: wireBindings})
	if err != nil {
		return RunPlanWithBindingsResultDTO{}, nil, err
	}
	spec, err := w1CommandSpec(values.Metadata, prepared, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, references, disclosure, mutations, []w1LifecycleEvidence{{actorTarget, string(domain.ActorActive)}, {sessionTarget, string(domain.ActorSessionActive)}, {objectiveTarget, string(domain.ObjectiveActive)}, {workUnitTarget, string(domain.WorkUnitProposed)}}, factTypes, factOrigins, hash)
	if err != nil {
		return RunPlanWithBindingsResultDTO{}, nil, err
	}
	execution, err := handler.commands.PlanRunWithBindings(ctx, application.PlanRunWithBindingsRequest{CommandRequest: application.CommandRequest{Spec: spec, HashView: hash, Authentication: prepared.context.authentication, Policy: prepared.context.policy, Audit: prepared.context.audit}, OperatorSessionID: values.ActorSessionID, RunID: values.RunID, ObjectiveID: values.ObjectiveID, WorkUnitID: values.WorkUnitID, Participants: requestParticipants, Bindings: requestBindings})
	if err == nil {
		if rejection, rejected := execution.Rejection(); rejected {
			err = rejection
		}
	}
	if err != nil {
		failure, failureErr := w1Failure(values.Metadata.RequestID, values.Metadata, "run:plan", domain.AggregateKindWorkspace, values.WorkspaceID.String(), err)
		return RunPlanWithBindingsResultDTO{}, failure, failureErr
	}
	metadata, err := w1ExecutionMetadata(values.Metadata.RequestID, OperationRunPlanWithBindings, execution, len(factTypes))
	if err != nil {
		return RunPlanWithBindingsResultDTO{}, nil, err
	}
	participations := make([]RunParticipationResourceDTO, len(values.Participants))
	for index, participant := range values.Participants {
		participations[index] = RunParticipationResourceDTO{ParticipationID: participant.ParticipationID, ActorID: participant.ActorID, Role: participant.Role, ParticipationState: string(domain.RunParticipationInvited), ResourceVersion: domain.InitialVersion()}
	}
	bindings := make([]RuntimeBindingResourceDTO, len(values.Bindings))
	for index, binding := range values.Bindings {
		bindings[index] = RuntimeBindingResourceDTO{BindingID: binding.BindingID, ParticipationID: binding.ParticipationID, SessionID: binding.SessionID, RuntimeEndpointID: binding.RuntimeEndpointID, BindingState: string(domain.RuntimeBindingRequested), ResourceVersion: domain.InitialVersion()}
	}
	result := RunPlanWithBindingsResultDTO{CommandResultMetadataDTO: metadata, Resource: RunPlanWithBindingsResourceDTO{WorkspaceID: values.WorkspaceID, RunID: values.RunID, RunState: string(domain.RunPlanned), RunVersion: domain.InitialVersion(), ObjectiveID: values.ObjectiveID, WorkUnitID: values.WorkUnitID, OperatorID: values.ActorID, Participations: participations, Bindings: bindings}}
	if err := result.Validate(); err != nil {
		return RunPlanWithBindingsResultDTO{}, nil, err
	}
	return result, nil, nil
}

func (handler *ApplicationHandler) HandleRunJoin(ctx context.Context, evidence AuthenticationEvidence, request RunJoinRequestDTO) (RunJoinResultDTO, *ErrorDTO, error) {
	values, err := request.Values()
	if err != nil {
		return RunJoinResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	prepared, err := handler.prepareW1Command(evidence, values.Metadata, values.WorkspaceID, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, values.ClientInstanceID, application.CommandJoinRun)
	if err != nil {
		return RunJoinResultDTO{}, nil, err
	}
	hashContext, _ := w1HashContext(values.Metadata, values.WorkspaceID, evidence.PrincipalID(), values.ClientInstanceID, values.ActorID, values.ActorSessionID)
	session, _ := commandExpectedResource(values.ActorSessionID.String(), values.ExpectedSessionVersion)
	run, _ := commandExpectedResource(values.RunID.String(), values.ExpectedRunVersion)
	participation, _ := commandExpectedResource(values.ParticipationID.String(), values.ExpectedParticipationVersion)
	hash, err := application.NewJoinRunCommandHashView(hashContext, application.JoinRunCommandHashParams{Session: session, Run: run, Participation: participation})
	if err != nil {
		return RunJoinResultDTO{}, nil, err
	}
	runRef, _ := domain.NewAggregateRef(values.RunID, values.ExpectedRunVersion)
	mutation, _ := domain.ExpectAggregateVersion(values.ParticipationID, values.ExpectedParticipationVersion)
	next, err := values.ExpectedParticipationVersion.Next()
	if err != nil {
		return RunJoinResultDTO{}, nil, err
	}
	origin, _ := domain.NewAggregateRef(values.ParticipationID, next)
	actorTarget, _ := domain.NewAggregateTarget(values.ActorID)
	sessionTarget, _ := domain.NewAggregateTarget(values.ActorSessionID)
	runTarget, _ := domain.NewAggregateTarget(values.RunID)
	participationTarget, _ := domain.NewAggregateTarget(values.ParticipationID)
	spec, err := w1CommandSpec(values.Metadata, prepared, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, []domain.AggregateRef{runRef}, []domain.AggregateTarget{actorTarget, sessionTarget, runTarget, participationTarget}, []domain.AggregateExpectation{mutation}, []w1LifecycleEvidence{{actorTarget, string(domain.ActorActive)}, {sessionTarget, string(domain.ActorSessionActive)}, {runTarget, string(domain.RunPlanned)}, {participationTarget, string(domain.RunParticipationInvited)}}, []domain.EventType{domain.EventTypeRunParticipantJoined}, []domain.AggregateRef{origin}, hash)
	if err != nil {
		return RunJoinResultDTO{}, nil, err
	}
	execution, err := handler.commands.JoinRun(ctx, application.JoinRunRequest{CommandRequest: application.CommandRequest{Spec: spec, HashView: hash, Authentication: prepared.context.authentication, Policy: prepared.context.policy, Audit: prepared.context.audit}, SessionID: values.ActorSessionID, RunID: values.RunID, ParticipationID: values.ParticipationID})
	if err == nil {
		if rejection, rejected := execution.Rejection(); rejected {
			err = rejection
		}
	}
	if err != nil {
		failure, failureErr := w1Failure(values.Metadata.RequestID, values.Metadata, "run:join", domain.AggregateKindWorkspace, values.WorkspaceID.String(), err)
		return RunJoinResultDTO{}, failure, failureErr
	}
	metadata, err := w1ExecutionMetadata(values.Metadata.RequestID, OperationRunJoin, execution, 1)
	if err != nil {
		return RunJoinResultDTO{}, nil, err
	}
	result := RunJoinResultDTO{CommandResultMetadataDTO: metadata, Resource: RunJoinResourceDTO{WorkspaceID: values.WorkspaceID, RunID: values.RunID, ParticipationID: values.ParticipationID, ActorID: values.ActorID, SessionID: values.ActorSessionID, ParticipationState: string(domain.RunParticipationActive), ResourceVersion: next}}
	if err := result.Validate(); err != nil {
		return RunJoinResultDTO{}, nil, err
	}
	return result, nil, nil
}

func (handler *ApplicationHandler) HandleRunStart(ctx context.Context, evidence AuthenticationEvidence, request RunStartRequestDTO) (RunStartResultDTO, *ErrorDTO, error) {
	values, err := request.Values()
	if err != nil {
		return RunStartResultDTO{}, nil, application.ErrInvalidApplicationContract
	}
	prepared, err := handler.prepareW1Command(evidence, values.Metadata, values.WorkspaceID, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, values.ClientInstanceID, application.CommandStartRun)
	if err != nil {
		return RunStartResultDTO{}, nil, err
	}
	hashContext, _ := w1HashContext(values.Metadata, values.WorkspaceID, evidence.PrincipalID(), values.ClientInstanceID, values.ActorID, values.ActorSessionID)
	session, _ := commandExpectedResource(values.ActorSessionID.String(), values.ExpectedSessionVersion)
	run, _ := commandExpectedResource(values.RunID.String(), values.ExpectedRunVersion)
	participations := make([]application.CommandExpectedResource, len(values.Participations))
	references := make([]domain.AggregateRef, len(values.Participations))
	requestParticipations := make([]application.StartRunParticipationRequest, len(values.Participations))
	lifecycle := make([]w1LifecycleEvidence, 0, 3+len(values.Participations))
	actorTarget, _ := domain.NewAggregateTarget(values.ActorID)
	sessionTarget, _ := domain.NewAggregateTarget(values.ActorSessionID)
	runTarget, _ := domain.NewAggregateTarget(values.RunID)
	disclosure := []domain.AggregateTarget{actorTarget, sessionTarget, runTarget}
	lifecycle = append(lifecycle, w1LifecycleEvidence{actorTarget, string(domain.ActorActive)}, w1LifecycleEvidence{sessionTarget, string(domain.ActorSessionActive)}, w1LifecycleEvidence{runTarget, string(domain.RunPlanned)})
	for index, participation := range values.Participations {
		participations[index], _ = commandExpectedResource(participation.ParticipationID.String(), participation.ExpectedVersion)
		references[index], _ = domain.NewAggregateRef(participation.ParticipationID, participation.ExpectedVersion)
		requestParticipations[index] = application.StartRunParticipationRequest{ParticipationID: participation.ParticipationID, ExpectedVersion: participation.ExpectedVersion}
		target, _ := domain.NewAggregateTarget(participation.ParticipationID)
		disclosure = append(disclosure, target)
		lifecycle = append(lifecycle, w1LifecycleEvidence{target, string(domain.RunParticipationActive)})
	}
	hash, err := application.NewStartRunCommandHashView(hashContext, application.StartRunCommandHashParams{OperatorSession: session, Run: run, Participations: participations})
	if err != nil {
		return RunStartResultDTO{}, nil, err
	}
	mutation, _ := domain.ExpectAggregateVersion(values.RunID, values.ExpectedRunVersion)
	next, err := values.ExpectedRunVersion.Next()
	if err != nil {
		return RunStartResultDTO{}, nil, err
	}
	origin, _ := domain.NewAggregateRef(values.RunID, next)
	spec, err := w1CommandSpec(values.Metadata, prepared, values.ActorID, values.ExpectedActorVersion, values.ActorSessionID, values.ExpectedSessionVersion, references, disclosure, []domain.AggregateExpectation{mutation}, lifecycle, []domain.EventType{domain.EventTypeRunStarted}, []domain.AggregateRef{origin}, hash)
	if err != nil {
		return RunStartResultDTO{}, nil, err
	}
	execution, err := handler.commands.StartRun(ctx, application.StartRunRequest{CommandRequest: application.CommandRequest{Spec: spec, HashView: hash, Authentication: prepared.context.authentication, Policy: prepared.context.policy, Audit: prepared.context.audit}, OperatorSessionID: values.ActorSessionID, RunID: values.RunID, Participations: requestParticipations})
	if err == nil {
		if rejection, rejected := execution.Rejection(); rejected {
			err = rejection
		}
	}
	if err != nil {
		failure, failureErr := w1Failure(values.Metadata.RequestID, values.Metadata, "run:start", domain.AggregateKindWorkspace, values.WorkspaceID.String(), err)
		return RunStartResultDTO{}, failure, failureErr
	}
	metadata, err := w1ExecutionMetadata(values.Metadata.RequestID, OperationRunStart, execution, 1)
	if err != nil {
		return RunStartResultDTO{}, nil, err
	}
	result := RunStartResultDTO{CommandResultMetadataDTO: metadata, Resource: RunStartResourceDTO{WorkspaceID: values.WorkspaceID, RunID: values.RunID, RunState: string(domain.RunStarting), RunVersion: next, OperatorID: values.ActorID}}
	if err := result.Validate(); err != nil {
		return RunStartResultDTO{}, nil, err
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
var _ WorkRefObserveHandler = (*ApplicationHandler)(nil)
var _ ObjectiveAndWorkCreateHandler = (*ApplicationHandler)(nil)
var _ ObjectiveActivateHandler = (*ApplicationHandler)(nil)
var _ RunPlanWithBindingsHandler = (*ApplicationHandler)(nil)
var _ RunJoinHandler = (*ApplicationHandler)(nil)
var _ RunStartHandler = (*ApplicationHandler)(nil)
