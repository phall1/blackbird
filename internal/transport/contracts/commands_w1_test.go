package contracts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

// w1DispatcherStub observes the W1 work-plane command ingress. It embeds the
// W0 stub so the unrelated dispatch methods keep panicking, and records the
// assembled request for each W1 operation so the handler's full assembly
// surface is observable without the application OrchestrationService.
type w1DispatcherStub struct {
	*workspaceCreateDispatcherStub
	observeWorkRef *application.ObserveWorkRefRequest
	objectiveWork  *application.CreateObjectiveAndWorkRequest
	planRun        *application.PlanRunWithBindingsRequest
	joinRun        *application.JoinRunRequest
	startRun       *application.StartRunRequest
	exec           application.CommandExecution
	err            error
}

func (stub *w1DispatcherStub) ObserveWorkRef(_ context.Context, request application.ObserveWorkRefRequest) (application.CommandExecution, error) {
	copyOfRequest := request
	stub.observeWorkRef = &copyOfRequest
	return stub.exec, stub.err
}

func (stub *w1DispatcherStub) CreateObjectiveAndWork(_ context.Context, request application.CreateObjectiveAndWorkRequest) (application.CommandExecution, error) {
	copyOfRequest := request
	stub.objectiveWork = &copyOfRequest
	return stub.exec, stub.err
}

func (stub *w1DispatcherStub) PlanRunWithBindings(_ context.Context, request application.PlanRunWithBindingsRequest) (application.CommandExecution, error) {
	copyOfRequest := request
	stub.planRun = &copyOfRequest
	return stub.exec, stub.err
}

func (stub *w1DispatcherStub) JoinRun(_ context.Context, request application.JoinRunRequest) (application.CommandExecution, error) {
	copyOfRequest := request
	stub.joinRun = &copyOfRequest
	return stub.exec, stub.err
}

func (stub *w1DispatcherStub) StartRun(_ context.Context, request application.StartRunRequest) (application.CommandExecution, error) {
	copyOfRequest := request
	stub.startRun = &copyOfRequest
	return stub.exec, stub.err
}

// newW1Rejection seals a forbidden rejection so every W1 handler reaches its
// typed-failure mapping instead of the applied-receipt path, which needs a
// materialized receipt only the application layer can produce.
func newW1Rejection(t *testing.T, message string) application.CommandExecution {
	t.Helper()
	rejection, err := domain.NewCommandError(domain.ErrorCodeForbidden, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := application.RejectedCommandExecution(rejection)
	if err != nil {
		t.Fatal(err)
	}
	return execution
}

func newW1TestHandler(t *testing.T, dispatcher *w1DispatcherStub) *ApplicationHandler {
	t.Helper()
	queries, err := application.NewQueryService(commandTestQueryStore{}, commandTestCheckpointSource{})
	if err != nil {
		t.Fatal(err)
	}
	policyRevision, err := domain.NewPolicyRevision("policy:work-plane:v1")
	if err != nil {
		t.Fatal(err)
	}
	assembler := newW0CommandAssembler(t, &stubCommandPolicySource{
		revision: policyRevision, digest: application.DigestBytes([]byte("work plane policy")),
	})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signers := commandTestSignerLookup{signer: commandTestCapsuleSigner{
		keyID: "ed25519:test-capsule-key", private: private, public: public,
	}}
	now := time.Now().UTC()
	handler, err := NewApplicationHandler(
		queries, dispatcher, assembler, signers, "ed25519:test-capsule-key",
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func newW1Dispatcher(t *testing.T, message string) *w1DispatcherStub {
	t.Helper()
	return &w1DispatcherStub{
		workspaceCreateDispatcherStub: &workspaceCreateDispatcherStub{},
		exec:                          newW1Rejection(t, message),
	}
}

// w1TestMetadata builds the shared ordinary-command envelope. Every W1
// operation carries the same metadata contract, so the operation and schema
// are the only per-command inputs.
func w1TestMetadata(t *testing.T, fixture authenticationFixture, schema, operation, requestID, idempotencyKey string) CommandMetadataDTO {
	t.Helper()
	commandID, err := domain.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	correlationID, err := domain.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	return CommandMetadataDTO{
		Schema: schema, RequestID: requestID, CommandID: commandID, Operation: operation,
		IdempotencyKey: idempotencyKey, AuthorityID: fixture.authority, AuthorityEpoch: fixture.epoch,
		Deadline:      time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
		CorrelationID: correlationID,
	}
}

func newTestClientInstanceID(t *testing.T) domain.ClientInstanceID {
	t.Helper()
	clientID, err := domain.NewClientInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	return clientID
}

func workRefObserveTestDTO(t *testing.T, fixture authenticationFixture, adapter domain.PrincipalID) WorkRefObserveRequestDTO {
	t.Helper()
	workReferenceID, err := domain.NewWorkReferenceID()
	if err != nil {
		t.Fatal(err)
	}
	return WorkRefObserveRequestDTO{
		CommandMetadataDTO: w1TestMetadata(t, fixture,
			SchemaWorkRefObserveCommand, OperationWorkRefObserve,
			"req_work_ref_observe", "work-ref-observe-test-key"),
		ClientInstanceID: newTestClientInstanceID(t),
		ExpectedVersions: WorkRefObserveExpectedVersionsDTO{
			Adapter: domain.InitialVersion(), Workspace: domain.InitialVersion(),
		},
		Body: WorkRefObserveBodyDTO{
			AdapterID: adapter, WorkspaceID: fixture.workspace, WorkReferenceID: workReferenceID,
			ProviderNamespace: "github", ProviderObjectID: "issue-1421",
			ProviderLocator: "https://github.com/phall1/blackbird/issues/1421",
			ProviderVersion: "etag-a1", SelectedFields: json.RawMessage(`{"title":"coverage floor","state":"open"}`),
			AdapterPrincipalID: adapter, ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
		},
	}
}

func objectiveAndWorkCreateTestDTO(t *testing.T, fixture authenticationFixture) ObjectiveAndWorkCreateRequestDTO {
	t.Helper()
	objectiveID, err := domain.NewObjectiveID()
	if err != nil {
		t.Fatal(err)
	}
	workUnitID, err := domain.NewWorkUnitID()
	if err != nil {
		t.Fatal(err)
	}
	workReferenceID, err := domain.NewWorkReferenceID()
	if err != nil {
		t.Fatal(err)
	}
	return ObjectiveAndWorkCreateRequestDTO{
		CommandMetadataDTO: w1TestMetadata(t, fixture,
			SchemaObjectiveAndWorkCreateCommand, OperationObjectiveAndWorkCreate,
			"req_objective_and_work_create", "objective-and-work-create-test-key"),
		ClientInstanceID: newTestClientInstanceID(t),
		ExpectedVersions: ObjectiveAndWorkCreateExpectedVersionsDTO{
			Actor: domain.InitialVersion(), ActorSession: fixture.session.Version(),
			WorkReference: domain.InitialVersion(),
		},
		Body: ObjectiveAndWorkCreateBodyDTO{
			WorkspaceID: fixture.workspace, ActorID: fixture.session.Binding().ActorID(),
			ActorSessionID: fixture.session.ID(), ObjectiveID: objectiveID,
			ObjectiveTitle:     "raise the coverage floor",
			AcceptanceCriteria: "total statement coverage clears the CI floor with headroom",
			WorkUnitID:         workUnitID, WorkUnitTitle: "cover the W1 command ingress",
			WorkReferenceID: workReferenceID,
		},
	}
}

func runPlanWithBindingsTestDTO(t *testing.T, fixture authenticationFixture) RunPlanWithBindingsRequestDTO {
	t.Helper()
	runID, err := domain.NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	objectiveID, err := domain.NewObjectiveID()
	if err != nil {
		t.Fatal(err)
	}
	workUnitID, err := domain.NewWorkUnitID()
	if err != nil {
		t.Fatal(err)
	}
	participationID, err := domain.NewRunParticipationID()
	if err != nil {
		t.Fatal(err)
	}
	bindingID, err := domain.NewRuntimeBindingID()
	if err != nil {
		t.Fatal(err)
	}
	endpointID, err := domain.NewRuntimeEndpointID()
	if err != nil {
		t.Fatal(err)
	}
	return RunPlanWithBindingsRequestDTO{
		CommandMetadataDTO: w1TestMetadata(t, fixture,
			SchemaRunPlanWithBindingsCommand, OperationRunPlanWithBindings,
			"req_run_plan_with_bindings", "run-plan-with-bindings-test-key"),
		ClientInstanceID: newTestClientInstanceID(t),
		ExpectedVersions: RunPlanWithBindingsExpectedVersionsDTO{
			Actor: domain.InitialVersion(), ActorSession: fixture.session.Version(),
			Objective: domain.InitialVersion(), WorkUnit: domain.InitialVersion(),
		},
		Body: RunPlanWithBindingsBodyDTO{
			WorkspaceID: fixture.workspace, ActorID: fixture.session.Binding().ActorID(),
			ActorSessionID: fixture.session.ID(), RunID: runID,
			ObjectiveID: objectiveID, WorkUnitID: workUnitID,
			Participants: []RunParticipantPlanDTO{{
				ParticipationID: participationID, ActorID: fixture.session.Binding().ActorID(),
				ExpectedActorVersion: domain.InitialVersion(), SessionID: fixture.session.ID(),
				ExpectedSessionVersion: fixture.session.Version(), Role: "operator",
			}},
			Bindings: []RuntimeBindingPlanDTO{{
				BindingID: bindingID, ParticipationID: participationID, SessionID: fixture.session.ID(),
				RuntimeEndpointID: endpointID, ExpectedRuntimeEndpointVersion: domain.InitialVersion(),
			}},
		},
	}
}

func runJoinTestDTO(t *testing.T, fixture authenticationFixture) RunJoinRequestDTO {
	t.Helper()
	runID, err := domain.NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	participationID, err := domain.NewRunParticipationID()
	if err != nil {
		t.Fatal(err)
	}
	return RunJoinRequestDTO{
		CommandMetadataDTO: w1TestMetadata(t, fixture,
			SchemaRunJoinCommand, OperationRunJoin, "req_run_join", "run-join-test-key"),
		ClientInstanceID: newTestClientInstanceID(t),
		ExpectedVersions: RunJoinExpectedVersionsDTO{
			Actor: domain.InitialVersion(), ActorSession: fixture.session.Version(),
			Run: domain.InitialVersion(), Participation: domain.InitialVersion(),
		},
		Body: RunJoinBodyDTO{
			WorkspaceID: fixture.workspace, ActorID: fixture.session.Binding().ActorID(),
			ActorSessionID: fixture.session.ID(), RunID: runID, ParticipationID: participationID,
		},
	}
}

func runStartTestDTO(t *testing.T, fixture authenticationFixture) RunStartRequestDTO {
	t.Helper()
	runID, err := domain.NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	participationID, err := domain.NewRunParticipationID()
	if err != nil {
		t.Fatal(err)
	}
	return RunStartRequestDTO{
		CommandMetadataDTO: w1TestMetadata(t, fixture,
			SchemaRunStartCommand, OperationRunStart, "req_run_start", "run-start-test-key"),
		ClientInstanceID: newTestClientInstanceID(t),
		ExpectedVersions: RunStartExpectedVersionsDTO{
			Actor: domain.InitialVersion(), ActorSession: fixture.session.Version(),
			Run: domain.InitialVersion(),
		},
		Body: RunStartBodyDTO{
			WorkspaceID: fixture.workspace, ActorID: fixture.session.Binding().ActorID(),
			ActorSessionID: fixture.session.ID(), RunID: runID,
			Participations: []RunStartParticipationDTO{
				{ParticipationID: participationID, ExpectedVersion: domain.InitialVersion()},
			},
		},
	}
}

func TestHandleWorkRefObserveAssemblesProviderObservationCommand(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "work reference observation forbidden")
	handler := newW1TestHandler(t, dispatcher)
	dto := workRefObserveTestDTO(t, fixture, evidence.PrincipalID())

	result, failure, err := handler.HandleWorkRefObserve(context.Background(), evidence, dto)
	if err != nil {
		t.Fatalf("HandleWorkRefObserve error=%v", err)
	}
	if result.Schema != "" || failure == nil || failure.Code != domain.ErrorCodeForbidden {
		t.Fatalf("result=%+v failure=%+v, want typed forbidden rejection", result, failure)
	}
	if failure.Details.DeniedCapability != "work_ref:observe" || failure.Details.ResourceScope == nil ||
		failure.Details.ResourceScope.Type != domain.AggregateKindWorkReference ||
		failure.Details.ResourceScope.ID != dto.Body.WorkReferenceID.String() {
		t.Fatalf("failure evidence=%+v", failure.Details)
	}
	dispatched := dispatcher.observeWorkRef
	if dispatched == nil {
		t.Fatal("work reference observation was not dispatched")
	}
	if dispatched.AdapterID != dto.Body.AdapterID || dispatched.WorkspaceID != dto.Body.WorkspaceID ||
		dispatched.WorkReferenceID != dto.Body.WorkReferenceID {
		t.Fatalf("dispatched identity=%+v", dispatched)
	}
	// A first observation carries no expected version: the command must plan an
	// absence mutation rather than pin a version that does not exist yet.
	if !dispatched.ExpectedWorkReferenceVersion.IsZero() {
		t.Fatalf("expected work reference version=%v, want zero on creation", dispatched.ExpectedWorkReferenceVersion)
	}
	if dispatched.Observation.Namespace().String() != dto.Body.ProviderNamespace ||
		dispatched.Observation.ObjectID().String() != dto.Body.ProviderObjectID ||
		dispatched.Observation.ProviderVersion().String() != dto.Body.ProviderVersion {
		t.Fatalf("dispatched observation=%+v", dispatched.Observation)
	}
	if dispatched.Spec.CommandOperation() != application.CommandObserveWorkRef ||
		dispatched.Spec.Authorship().PrincipalID() != evidence.PrincipalID() {
		t.Fatalf("spec operation/authorship=%s/%s", dispatched.Spec.CommandOperation(), dispatched.Spec.Authorship().PrincipalID())
	}
	fingerprint, hashErr := application.NewProductionCanonicalCodec().HashCommand(dispatched.HashView)
	if hashErr != nil || fingerprint != dispatched.Spec.RequestFingerprint() {
		t.Fatalf("hash fingerprint=%x err=%v spec=%x", fingerprint, hashErr, dispatched.Spec.RequestFingerprint())
	}
}

func TestHandleWorkRefObservePinsExpectedVersionOnSubsequentObservation(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "work reference observation forbidden")
	handler := newW1TestHandler(t, dispatcher)
	dto := workRefObserveTestDTO(t, fixture, evidence.PrincipalID())
	// An update pins the current work reference version and must declare the
	// provider version it supersedes. The version is a pointer because its
	// absence, not a zero value, is what selects the create path.
	current := domain.InitialVersion()
	dto.ExpectedVersions.WorkReference = &current
	dto.Body.PreviousProviderVersion = "etag-a0"

	_, failure, err := handler.HandleWorkRefObserve(context.Background(), evidence, dto)
	if err != nil || failure == nil {
		t.Fatalf("HandleWorkRefObserve failure=%+v err=%v", failure, err)
	}
	dispatched := dispatcher.observeWorkRef
	if dispatched == nil {
		t.Fatal("work reference observation was not dispatched")
	}
	if dispatched.ExpectedWorkReferenceVersion != domain.InitialVersion() {
		t.Fatalf("expected work reference version=%v, want the pinned initial version", dispatched.ExpectedWorkReferenceVersion)
	}
	if dispatched.PreviousProviderVersion.String() != "etag-a0" {
		t.Fatalf("previous provider version=%q", dispatched.PreviousProviderVersion.String())
	}
}

func TestHandleWorkRefObserveRejectsNonAdapterPrincipal(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "work reference observation forbidden")
	handler := newW1TestHandler(t, dispatcher)
	otherAdapter, err := domain.NewPrincipalID()
	if err != nil {
		t.Fatal(err)
	}
	// The adapter identity is provider authority: it must be the authenticated
	// principal, never a principal the caller names in the body.
	dto := workRefObserveTestDTO(t, fixture, otherAdapter)

	_, failure, err := handler.HandleWorkRefObserve(context.Background(), evidence, dto)
	if !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
		t.Fatalf("foreign adapter failure=%v err=%v", failure, err)
	}
	if dispatcher.observeWorkRef != nil {
		t.Fatal("a foreign adapter identity must not dispatch")
	}
}

func TestHandleWorkRefObserveRejectsInvalidRequestAndMissingDependencies(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "work reference observation forbidden")
	handler := newW1TestHandler(t, dispatcher)
	invalidDTO := workRefObserveTestDTO(t, fixture, evidence.PrincipalID())
	invalidDTO.Body.ProviderNamespace = ""

	if _, failure, err := handler.HandleWorkRefObserve(context.Background(), evidence, invalidDTO); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
		t.Fatalf("invalid request failure=%v err=%v", failure, err)
	}
	valid := workRefObserveTestDTO(t, fixture, evidence.PrincipalID())
	empty := &ApplicationHandler{}
	if _, failure, err := empty.HandleWorkRefObserve(context.Background(), evidence, valid); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
		t.Fatalf("empty handler failure=%v err=%v", failure, err)
	}
	var nilHandler *ApplicationHandler
	if _, failure, err := nilHandler.HandleWorkRefObserve(context.Background(), evidence, valid); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
		t.Fatalf("nil handler failure=%v err=%v", failure, err)
	}
}

func TestHandleObjectiveAndWorkCreateAssemblesTwoFactCommand(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "objective creation forbidden")
	handler := newW1TestHandler(t, dispatcher)
	dto := objectiveAndWorkCreateTestDTO(t, fixture)

	result, failure, err := handler.HandleObjectiveAndWorkCreate(context.Background(), evidence, dto)
	if err != nil {
		t.Fatalf("HandleObjectiveAndWorkCreate error=%v", err)
	}
	if result.Schema != "" || failure == nil || failure.Code != domain.ErrorCodeForbidden {
		t.Fatalf("result=%+v failure=%+v, want typed forbidden rejection", result, failure)
	}
	if failure.Details.DeniedCapability != "objective:create" || failure.Details.ResourceScope == nil ||
		failure.Details.ResourceScope.Type != domain.AggregateKindWorkspace ||
		failure.Details.ResourceScope.ID != dto.Body.WorkspaceID.String() {
		t.Fatalf("failure evidence=%+v", failure.Details)
	}
	dispatched := dispatcher.objectiveWork
	if dispatched == nil {
		t.Fatal("objective and work creation was not dispatched")
	}
	if dispatched.ObjectiveID != dto.Body.ObjectiveID || dispatched.WorkUnitID != dto.Body.WorkUnitID ||
		dispatched.WorkReferenceID != dto.Body.WorkReferenceID || dispatched.SessionID != dto.Body.ActorSessionID {
		t.Fatalf("dispatched identity=%+v", dispatched)
	}
	if dispatched.ObjectiveTitle != dto.Body.ObjectiveTitle || dispatched.AcceptanceCriteria != dto.Body.AcceptanceCriteria ||
		dispatched.WorkUnitTitle != dto.Body.WorkUnitTitle {
		t.Fatalf("dispatched narrative=%+v", dispatched)
	}
	// The operation creates an objective and its first work unit, so the spec
	// must declare exactly those two facts.
	if got := len(dispatched.Spec.ExpectedFacts()); got != 2 {
		t.Fatalf("expected facts=%d, want 2", got)
	}
	attribution, present := dispatched.Spec.Authorship().ActorAttribution()
	if !present || attribution.ActorID() != dto.Body.ActorID || attribution.ActorSessionID() != dto.Body.ActorSessionID {
		t.Fatalf("actor attribution=%+v present=%v", attribution, present)
	}
	fingerprint, hashErr := application.NewProductionCanonicalCodec().HashCommand(dispatched.HashView)
	if hashErr != nil || fingerprint != dispatched.Spec.RequestFingerprint() {
		t.Fatalf("hash fingerprint=%x err=%v spec=%x", fingerprint, hashErr, dispatched.Spec.RequestFingerprint())
	}
}

func TestHandleRunPlanWithBindingsAssemblesParticipantsAndBindings(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "run planning forbidden")
	handler := newW1TestHandler(t, dispatcher)
	dto := runPlanWithBindingsTestDTO(t, fixture)

	result, failure, err := handler.HandleRunPlanWithBindings(context.Background(), evidence, dto)
	if err != nil {
		t.Fatalf("HandleRunPlanWithBindings error=%v", err)
	}
	if result.Schema != "" || failure == nil || failure.Code != domain.ErrorCodeForbidden {
		t.Fatalf("result=%+v failure=%+v, want typed forbidden rejection", result, failure)
	}
	if failure.Details.DeniedCapability != "run:plan" || failure.Details.ResourceScope == nil ||
		failure.Details.ResourceScope.Type != domain.AggregateKindWorkspace {
		t.Fatalf("failure evidence=%+v", failure.Details)
	}
	dispatched := dispatcher.planRun
	if dispatched == nil {
		t.Fatal("run planning was not dispatched")
	}
	if dispatched.RunID != dto.Body.RunID || dispatched.ObjectiveID != dto.Body.ObjectiveID ||
		dispatched.WorkUnitID != dto.Body.WorkUnitID || dispatched.OperatorSessionID != dto.Body.ActorSessionID {
		t.Fatalf("dispatched identity=%+v", dispatched)
	}
	if len(dispatched.Participants) != 1 || dispatched.Participants[0].Role != "operator" ||
		dispatched.Participants[0].ParticipationID != dto.Body.Participants[0].ParticipationID {
		t.Fatalf("dispatched participants=%+v", dispatched.Participants)
	}
	if len(dispatched.Bindings) != 1 || dispatched.Bindings[0].BindingID != dto.Body.Bindings[0].BindingID ||
		dispatched.Bindings[0].RuntimeEndpointID != dto.Body.Bindings[0].RuntimeEndpointID {
		t.Fatalf("dispatched bindings=%+v", dispatched.Bindings)
	}
	// One run fact plus one fact per participant and per binding.
	if got := len(dispatched.Spec.ExpectedFacts()); got != 3 {
		t.Fatalf("expected facts=%d, want 3", got)
	}
	fingerprint, hashErr := application.NewProductionCanonicalCodec().HashCommand(dispatched.HashView)
	if hashErr != nil || fingerprint != dispatched.Spec.RequestFingerprint() {
		t.Fatalf("hash fingerprint=%x err=%v spec=%x", fingerprint, hashErr, dispatched.Spec.RequestFingerprint())
	}
}

func TestHandleRunPlanWithBindingsDisclosesForeignParticipantsOnce(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "run planning forbidden")
	handler := newW1TestHandler(t, dispatcher)
	dto := runPlanWithBindingsTestDTO(t, fixture)
	foreignActor, err := domain.NewActorID()
	if err != nil {
		t.Fatal(err)
	}
	foreignSession, err := domain.NewActorSessionID()
	if err != nil {
		t.Fatal(err)
	}
	secondParticipation, err := domain.NewRunParticipationID()
	if err != nil {
		t.Fatal(err)
	}
	// A participant who is neither the operator nor the operator's session adds
	// its own authorization references and disclosure targets.
	dto.Body.Participants = append(dto.Body.Participants, RunParticipantPlanDTO{
		ParticipationID: secondParticipation, ActorID: foreignActor,
		ExpectedActorVersion: domain.InitialVersion(), SessionID: foreignSession,
		ExpectedSessionVersion: domain.InitialVersion(), Role: "implementer",
	})

	if _, failure, err := handler.HandleRunPlanWithBindings(context.Background(), evidence, dto); err != nil || failure == nil {
		t.Fatalf("HandleRunPlanWithBindings failure=%+v err=%v", failure, err)
	}
	dispatched := dispatcher.planRun
	if dispatched == nil || len(dispatched.Participants) != 2 {
		t.Fatalf("dispatched=%+v, want two participants", dispatched)
	}
	// Two participants and one binding now sit under the single run fact.
	if got := len(dispatched.Spec.ExpectedFacts()); got != 4 {
		t.Fatalf("expected facts=%d, want 4", got)
	}
	disclosure := dispatched.Spec.Guards().DisclosureTargets()
	seen := make(map[domain.AggregateTarget]int, len(disclosure))
	for _, target := range disclosure {
		seen[target]++
	}
	for target, count := range seen {
		if count != 1 {
			t.Fatalf("disclosure target %s appeared %d times, want exactly once", target, count)
		}
	}
	foreignActorTarget, err := domain.NewAggregateTarget(foreignActor)
	if err != nil {
		t.Fatal(err)
	}
	if seen[foreignActorTarget] != 1 {
		t.Fatal("a foreign participant actor was not disclosed")
	}
}

func TestHandleRunPlanWithBindingsRejectsDuplicateParticipation(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "run planning forbidden")
	handler := newW1TestHandler(t, dispatcher)
	dto := runPlanWithBindingsTestDTO(t, fixture)
	dto.Body.Participants = append(dto.Body.Participants, dto.Body.Participants[0])

	if _, failure, err := handler.HandleRunPlanWithBindings(context.Background(), evidence, dto); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
		t.Fatalf("duplicate participation failure=%v err=%v", failure, err)
	}
	if dispatcher.planRun != nil {
		t.Fatal("a duplicated participation must not dispatch")
	}
}

func TestHandleRunJoinAssemblesParticipationTransition(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "run join forbidden")
	handler := newW1TestHandler(t, dispatcher)
	dto := runJoinTestDTO(t, fixture)

	result, failure, err := handler.HandleRunJoin(context.Background(), evidence, dto)
	if err != nil {
		t.Fatalf("HandleRunJoin error=%v", err)
	}
	if result.Schema != "" || failure == nil || failure.Code != domain.ErrorCodeForbidden {
		t.Fatalf("result=%+v failure=%+v, want typed forbidden rejection", result, failure)
	}
	if failure.Details.DeniedCapability != "run:join" {
		t.Fatalf("failure evidence=%+v", failure.Details)
	}
	dispatched := dispatcher.joinRun
	if dispatched == nil {
		t.Fatal("run join was not dispatched")
	}
	if dispatched.RunID != dto.Body.RunID || dispatched.ParticipationID != dto.Body.ParticipationID ||
		dispatched.SessionID != dto.Body.ActorSessionID {
		t.Fatalf("dispatched identity=%+v", dispatched)
	}
	if got := len(dispatched.Spec.ExpectedFacts()); got != 1 {
		t.Fatalf("expected facts=%d, want 1", got)
	}
	fingerprint, hashErr := application.NewProductionCanonicalCodec().HashCommand(dispatched.HashView)
	if hashErr != nil || fingerprint != dispatched.Spec.RequestFingerprint() {
		t.Fatalf("hash fingerprint=%x err=%v spec=%x", fingerprint, hashErr, dispatched.Spec.RequestFingerprint())
	}
}

func TestHandleRunStartAssemblesEveryParticipationReference(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "run start forbidden")
	handler := newW1TestHandler(t, dispatcher)
	dto := runStartTestDTO(t, fixture)
	secondParticipation, err := domain.NewRunParticipationID()
	if err != nil {
		t.Fatal(err)
	}
	dto.Body.Participations = append(dto.Body.Participations, RunStartParticipationDTO{
		ParticipationID: secondParticipation, ExpectedVersion: domain.InitialVersion(),
	})

	result, failure, err := handler.HandleRunStart(context.Background(), evidence, dto)
	if err != nil {
		t.Fatalf("HandleRunStart error=%v", err)
	}
	if result.Schema != "" || failure == nil || failure.Code != domain.ErrorCodeForbidden {
		t.Fatalf("result=%+v failure=%+v, want typed forbidden rejection", result, failure)
	}
	if failure.Details.DeniedCapability != "run:start" {
		t.Fatalf("failure evidence=%+v", failure.Details)
	}
	dispatched := dispatcher.startRun
	if dispatched == nil {
		t.Fatal("run start was not dispatched")
	}
	if dispatched.RunID != dto.Body.RunID || dispatched.OperatorSessionID != dto.Body.ActorSessionID ||
		len(dispatched.Participations) != 2 {
		t.Fatalf("dispatched identity=%+v", dispatched)
	}
	// Starting a run emits a single run fact regardless of participation count.
	if got := len(dispatched.Spec.ExpectedFacts()); got != 1 {
		t.Fatalf("expected facts=%d, want 1", got)
	}
	fingerprint, hashErr := application.NewProductionCanonicalCodec().HashCommand(dispatched.HashView)
	if hashErr != nil || fingerprint != dispatched.Spec.RequestFingerprint() {
		t.Fatalf("hash fingerprint=%x err=%v spec=%x", fingerprint, hashErr, dispatched.Spec.RequestFingerprint())
	}
}

// TestW1HandlersRejectMismatchedSessionEvidence pins the shared W1 admission
// rule: the session named in the body must be exactly the session the caller
// authenticated with, at exactly the revision the evidence carries.
func TestW1HandlersRejectMismatchedSessionEvidence(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	foreignSession, err := domain.NewActorSessionID()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("objective and work create", func(t *testing.T) {
		dispatcher := newW1Dispatcher(t, "objective creation forbidden")
		handler := newW1TestHandler(t, dispatcher)
		dto := objectiveAndWorkCreateTestDTO(t, fixture)
		dto.Body.ActorSessionID = foreignSession
		if _, failure, err := handler.HandleObjectiveAndWorkCreate(context.Background(), evidence, dto); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
			t.Fatalf("failure=%v err=%v", failure, err)
		}
		if dispatcher.objectiveWork != nil {
			t.Fatal("mismatched evidence must not dispatch")
		}
	})
	t.Run("run plan with bindings", func(t *testing.T) {
		dispatcher := newW1Dispatcher(t, "run planning forbidden")
		handler := newW1TestHandler(t, dispatcher)
		dto := runPlanWithBindingsTestDTO(t, fixture)
		dto.Body.ActorSessionID = foreignSession
		if _, failure, err := handler.HandleRunPlanWithBindings(context.Background(), evidence, dto); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
			t.Fatalf("failure=%v err=%v", failure, err)
		}
		if dispatcher.planRun != nil {
			t.Fatal("mismatched evidence must not dispatch")
		}
	})
	t.Run("run join", func(t *testing.T) {
		dispatcher := newW1Dispatcher(t, "run join forbidden")
		handler := newW1TestHandler(t, dispatcher)
		dto := runJoinTestDTO(t, fixture)
		dto.Body.ActorSessionID = foreignSession
		if _, failure, err := handler.HandleRunJoin(context.Background(), evidence, dto); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
			t.Fatalf("failure=%v err=%v", failure, err)
		}
		if dispatcher.joinRun != nil {
			t.Fatal("mismatched evidence must not dispatch")
		}
	})
	t.Run("run start", func(t *testing.T) {
		dispatcher := newW1Dispatcher(t, "run start forbidden")
		handler := newW1TestHandler(t, dispatcher)
		dto := runStartTestDTO(t, fixture)
		dto.Body.ActorSessionID = foreignSession
		if _, failure, err := handler.HandleRunStart(context.Background(), evidence, dto); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
			t.Fatalf("failure=%v err=%v", failure, err)
		}
		if dispatcher.startRun != nil {
			t.Fatal("mismatched evidence must not dispatch")
		}
	})
}

// TestW1HandlersRejectInvalidRequestsAndMissingDependencies pins the two
// contract failures every W1 handler shares: an undecodable request and a
// handler assembled without its dispatch dependencies.
func TestW1HandlersRejectInvalidRequestsAndMissingDependencies(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := newW1Dispatcher(t, "forbidden")
	handler := newW1TestHandler(t, dispatcher)
	empty := &ApplicationHandler{}

	t.Run("objective and work create", func(t *testing.T) {
		invalidDTO := objectiveAndWorkCreateTestDTO(t, fixture)
		invalidDTO.Body.ObjectiveTitle = ""
		if _, _, err := handler.HandleObjectiveAndWorkCreate(context.Background(), evidence, invalidDTO); !errors.Is(err, application.ErrInvalidApplicationContract) {
			t.Fatalf("invalid request err=%v", err)
		}
		if _, _, err := empty.HandleObjectiveAndWorkCreate(context.Background(), evidence, objectiveAndWorkCreateTestDTO(t, fixture)); !errors.Is(err, application.ErrInvalidApplicationContract) {
			t.Fatalf("empty handler err=%v", err)
		}
	})
	t.Run("run plan with bindings", func(t *testing.T) {
		invalidDTO := runPlanWithBindingsTestDTO(t, fixture)
		invalidDTO.Body.Bindings = nil
		if _, _, err := handler.HandleRunPlanWithBindings(context.Background(), evidence, invalidDTO); !errors.Is(err, application.ErrInvalidApplicationContract) {
			t.Fatalf("invalid request err=%v", err)
		}
		if _, _, err := empty.HandleRunPlanWithBindings(context.Background(), evidence, runPlanWithBindingsTestDTO(t, fixture)); !errors.Is(err, application.ErrInvalidApplicationContract) {
			t.Fatalf("empty handler err=%v", err)
		}
	})
	t.Run("run join", func(t *testing.T) {
		invalidDTO := runJoinTestDTO(t, fixture)
		invalidDTO.Body.RunID = domain.RunID{}
		if _, _, err := handler.HandleRunJoin(context.Background(), evidence, invalidDTO); !errors.Is(err, application.ErrInvalidApplicationContract) {
			t.Fatalf("invalid request err=%v", err)
		}
		if _, _, err := empty.HandleRunJoin(context.Background(), evidence, runJoinTestDTO(t, fixture)); !errors.Is(err, application.ErrInvalidApplicationContract) {
			t.Fatalf("empty handler err=%v", err)
		}
	})
	t.Run("run start", func(t *testing.T) {
		invalidDTO := runStartTestDTO(t, fixture)
		invalidDTO.Body.RunID = domain.RunID{}
		if _, _, err := handler.HandleRunStart(context.Background(), evidence, invalidDTO); !errors.Is(err, application.ErrInvalidApplicationContract) {
			t.Fatalf("invalid request err=%v", err)
		}
		if _, _, err := empty.HandleRunStart(context.Background(), evidence, runStartTestDTO(t, fixture)); !errors.Is(err, application.ErrInvalidApplicationContract) {
			t.Fatalf("empty handler err=%v", err)
		}
	})
}

// TestW1HandlersSurfaceDispatchErrorsUnmapped pins that a transport error from
// the dispatcher is not laundered into a typed rejection: only domain command
// errors become ErrorDTOs.
func TestW1HandlersSurfaceDispatchErrorsUnmapped(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	transportFailure := errors.New("dispatch transport failure")
	dispatcher := newW1Dispatcher(t, "forbidden")
	dispatcher.err = transportFailure
	handler := newW1TestHandler(t, dispatcher)

	if _, failure, err := handler.HandleObjectiveAndWorkCreate(context.Background(), evidence, objectiveAndWorkCreateTestDTO(t, fixture)); !errors.Is(err, transportFailure) || failure != nil {
		t.Fatalf("objective create failure=%v err=%v", failure, err)
	}
	if _, failure, err := handler.HandleRunPlanWithBindings(context.Background(), evidence, runPlanWithBindingsTestDTO(t, fixture)); !errors.Is(err, transportFailure) || failure != nil {
		t.Fatalf("run plan failure=%v err=%v", failure, err)
	}
	if _, failure, err := handler.HandleRunJoin(context.Background(), evidence, runJoinTestDTO(t, fixture)); !errors.Is(err, transportFailure) || failure != nil {
		t.Fatalf("run join failure=%v err=%v", failure, err)
	}
	if _, failure, err := handler.HandleRunStart(context.Background(), evidence, runStartTestDTO(t, fixture)); !errors.Is(err, transportFailure) || failure != nil {
		t.Fatalf("run start failure=%v err=%v", failure, err)
	}
	if _, failure, err := handler.HandleWorkRefObserve(context.Background(), evidence, workRefObserveTestDTO(t, fixture, evidence.PrincipalID())); !errors.Is(err, transportFailure) || failure != nil {
		t.Fatalf("work ref observe failure=%v err=%v", failure, err)
	}
}

// TestValidateAggregateIDAcceptsEveryWorkPlaneKind pins the resource scopes a
// rejected work-plane command can name. A kind missing here turns a typed
// rejection into an internal error, because commandRejectionDTO validates the
// scope it just derived.
func TestValidateAggregateIDAcceptsEveryWorkPlaneKind(t *testing.T) {
	workReferenceID, err := domain.NewWorkReferenceID()
	if err != nil {
		t.Fatal(err)
	}
	objectiveID, err := domain.NewObjectiveID()
	if err != nil {
		t.Fatal(err)
	}
	workUnitID, err := domain.NewWorkUnitID()
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	participationID, err := domain.NewRunParticipationID()
	if err != nil {
		t.Fatal(err)
	}
	bindingID, err := domain.NewRuntimeBindingID()
	if err != nil {
		t.Fatal(err)
	}
	endpointID, err := domain.NewRuntimeEndpointID()
	if err != nil {
		t.Fatal(err)
	}
	for kind, id := range map[domain.AggregateKind]string{
		domain.AggregateKindWorkReference:    workReferenceID.String(),
		domain.AggregateKindObjective:        objectiveID.String(),
		domain.AggregateKindWorkUnit:         workUnitID.String(),
		domain.AggregateKindRun:              runID.String(),
		domain.AggregateKindRunParticipation: participationID.String(),
		domain.AggregateKindRuntimeBinding:   bindingID.String(),
		domain.AggregateKindRuntimeEndpoint:  endpointID.String(),
	} {
		if err := validateAggregateID(kind, id); err != nil {
			t.Fatalf("aggregate kind %s rejected its own identifier: %v", kind, err)
		}
		if err := validateAggregateID(kind, "not-an-identifier"); err == nil {
			t.Fatalf("aggregate kind %s accepted a malformed identifier", kind)
		}
	}
	if err := validateAggregateID(domain.AggregateKind("unheard_of"), runID.String()); err == nil {
		t.Fatal("an unknown aggregate kind must not validate")
	}
}
