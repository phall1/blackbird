package contracts

import (
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

func w1TestEventIDs(t *testing.T, count int) []domain.EventID {
	t.Helper()
	ids := make([]domain.EventID, count)
	for index := range ids {
		id, err := domain.NewEventID()
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = id
	}
	return ids
}

func w1TestResultMetadata(t *testing.T, operation string, events int) CommandResultMetadataDTO {
	t.Helper()
	return CommandResultMetadataDTO{
		Schema: SchemaCommandResult, RequestID: "req_w1_result", Operation: operation,
		EventCursor: "bbec1_w1_result", EmittedEventIDs: w1TestEventIDs(t, events),
		AcceptedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
}

func w1TestAdvancedVersion(t *testing.T) domain.Version {
	t.Helper()
	next, err := domain.InitialVersion().Next()
	if err != nil {
		t.Fatal(err)
	}
	return next
}

// rejects asserts that a mutated result fails validation, and names the field
// the contract is expected to blame so a silently relocated check is caught.
func rejects(t *testing.T, name string, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: validation accepted an invalid result", name)
	}
	if !strings.Contains(err.Error(), field) {
		t.Fatalf("%s: error %q does not blame %q", name, err, field)
	}
}

func validWorkRefObserveResult(t *testing.T) WorkRefObserveResultDTO {
	t.Helper()
	workspaceID, err := domain.NewWorkspaceID()
	if err != nil {
		t.Fatal(err)
	}
	workReferenceID, err := domain.NewWorkReferenceID()
	if err != nil {
		t.Fatal(err)
	}
	adapterID, err := domain.NewPrincipalID()
	if err != nil {
		t.Fatal(err)
	}
	return WorkRefObserveResultDTO{
		CommandResultMetadataDTO: w1TestResultMetadata(t, OperationWorkRefObserve, 1),
		Resource: WorkRefObserveResourceDTO{
			WorkspaceID: workspaceID, WorkReferenceID: workReferenceID,
			ResourceVersion: domain.InitialVersion(), AdapterPrincipalID: adapterID,
			ProviderNamespace: "github", ProviderObjectID: "issue-1421",
			ProviderLocator: "https://github.com/phall1/blackbird/issues/1421",
			ProviderVersion: "etag-a1", ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
		},
	}
}

func TestWorkRefObserveResultValidation(t *testing.T) {
	if err := validWorkRefObserveResult(t).Validate(); err != nil {
		t.Fatalf("a well-formed observation result was rejected: %v", err)
	}

	missingID := validWorkRefObserveResult(t)
	missingID.Resource.WorkReferenceID = domain.WorkReferenceID{}
	rejects(t, "missing work reference", missingID.Validate(), "resource.work_reference_id")

	missingProvider := validWorkRefObserveResult(t)
	missingProvider.Resource.ProviderLocator = ""
	rejects(t, "missing locator", missingProvider.Validate(), "resource.provider_locator")

	zeroVersion := validWorkRefObserveResult(t)
	zeroVersion.Resource.ResourceVersion = domain.Version{}
	rejects(t, "zero version", zeroVersion.Validate(), "resource.resource_version")

	localTime := validWorkRefObserveResult(t)
	localTime.Resource.ObservedAt = time.Now().In(time.FixedZone("UTC+2", 2*60*60))
	rejects(t, "non-UTC observation", localTime.Validate(), "resource.observed_at")

	wrongEventCount := validWorkRefObserveResult(t)
	wrongEventCount.EmittedEventIDs = w1TestEventIDs(t, 2)
	rejects(t, "wrong event count", wrongEventCount.Validate(), "emitted_event_ids")
}

func validObjectiveAndWorkCreateResult(t *testing.T) ObjectiveAndWorkCreateResultDTO {
	t.Helper()
	workspaceID, err := domain.NewWorkspaceID()
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
	workReferenceID, err := domain.NewWorkReferenceID()
	if err != nil {
		t.Fatal(err)
	}
	return ObjectiveAndWorkCreateResultDTO{
		CommandResultMetadataDTO: w1TestResultMetadata(t, OperationObjectiveAndWorkCreate, 2),
		Resource: ObjectiveAndWorkCreateResourceDTO{
			WorkspaceID: workspaceID, ObjectiveID: objectiveID,
			ObjectiveState: string(domain.ObjectiveDraft), ObjectiveVersion: domain.InitialVersion(),
			WorkUnitID: workUnitID, WorkUnitState: string(domain.WorkUnitProposed),
			WorkUnitVersion: domain.InitialVersion(), WorkReferenceID: workReferenceID,
		},
	}
}

func TestObjectiveAndWorkCreateResultValidation(t *testing.T) {
	if err := validObjectiveAndWorkCreateResult(t).Validate(); err != nil {
		t.Fatalf("a well-formed objective creation result was rejected: %v", err)
	}

	// Creation always lands in the draft lifecycle state; an already-active
	// objective would mean the result described a different command.
	activeObjective := validObjectiveAndWorkCreateResult(t)
	activeObjective.Resource.ObjectiveState = string(domain.ObjectiveActive)
	rejects(t, "active objective", activeObjective.Validate(), "resource.objective_state")

	advancedWorkUnit := validObjectiveAndWorkCreateResult(t)
	advancedWorkUnit.Resource.WorkUnitVersion = w1TestAdvancedVersion(t)
	rejects(t, "advanced work unit", advancedWorkUnit.Validate(), "resource.work_unit_version")

	missingReference := validObjectiveAndWorkCreateResult(t)
	missingReference.Resource.WorkReferenceID = domain.WorkReferenceID{}
	rejects(t, "missing work reference", missingReference.Validate(), "resource.work_reference_id")
}

func validRunPlanWithBindingsResult(t *testing.T) RunPlanWithBindingsResultDTO {
	t.Helper()
	workspaceID, err := domain.NewWorkspaceID()
	if err != nil {
		t.Fatal(err)
	}
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
	operatorID, err := domain.NewActorID()
	if err != nil {
		t.Fatal(err)
	}
	participationID, err := domain.NewRunParticipationID()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := domain.NewActorSessionID()
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
	return RunPlanWithBindingsResultDTO{
		// One run fact, one participant fact, one binding fact.
		CommandResultMetadataDTO: w1TestResultMetadata(t, OperationRunPlanWithBindings, 3),
		Resource: RunPlanWithBindingsResourceDTO{
			WorkspaceID: workspaceID, RunID: runID, RunState: string(domain.RunPlanned),
			RunVersion: domain.InitialVersion(), ObjectiveID: objectiveID,
			WorkUnitID: workUnitID, OperatorID: operatorID,
			Participations: []RunParticipationResourceDTO{{
				ParticipationID: participationID, ActorID: operatorID, Role: "operator",
				ParticipationState: string(domain.RunParticipationInvited),
				ResourceVersion:    domain.InitialVersion(),
			}},
			Bindings: []RuntimeBindingResourceDTO{{
				BindingID: bindingID, ParticipationID: participationID, SessionID: sessionID,
				RuntimeEndpointID: endpointID, BindingState: string(domain.RuntimeBindingRequested),
				ResourceVersion: domain.InitialVersion(),
			}},
		},
	}
}

func TestRunPlanWithBindingsResultValidation(t *testing.T) {
	if err := validRunPlanWithBindingsResult(t).Validate(); err != nil {
		t.Fatalf("a well-formed run plan result was rejected: %v", err)
	}

	startedRun := validRunPlanWithBindingsResult(t)
	startedRun.Resource.RunState = string(domain.RunStarting)
	rejects(t, "started run", startedRun.Validate(), "resource.run_state")

	noParticipants := validRunPlanWithBindingsResult(t)
	noParticipants.Resource.Participations = nil
	// The emitted fact count is derived from the resource shape, so an empty
	// participation list is caught by the metadata check first.
	rejects(t, "no participants", noParticipants.Validate(), "emitted_event_ids")

	noBindings := validRunPlanWithBindingsResult(t)
	noBindings.Resource.Bindings = nil
	rejects(t, "no bindings", noBindings.Validate(), "emitted_event_ids")

	duplicateParticipation := validRunPlanWithBindingsResult(t)
	duplicateParticipation.Resource.Participations = append(
		duplicateParticipation.Resource.Participations,
		duplicateParticipation.Resource.Participations[0],
	)
	duplicateParticipation.EmittedEventIDs = w1TestEventIDs(t, 4)
	rejects(t, "duplicate participation", duplicateParticipation.Validate(), "must not duplicate")

	duplicateBinding := validRunPlanWithBindingsResult(t)
	duplicateBinding.Resource.Bindings = append(
		duplicateBinding.Resource.Bindings, duplicateBinding.Resource.Bindings[0],
	)
	duplicateBinding.EmittedEventIDs = w1TestEventIDs(t, 4)
	rejects(t, "duplicate binding", duplicateBinding.Validate(), "must not duplicate")

	joinedParticipant := validRunPlanWithBindingsResult(t)
	joinedParticipant.Resource.Participations[0].ParticipationState = string(domain.RunParticipationActive)
	rejects(t, "already joined participant", joinedParticipant.Validate(), "participation_state")

	missingRole := validRunPlanWithBindingsResult(t)
	missingRole.Resource.Participations[0].Role = ""
	rejects(t, "missing role", missingRole.Validate(), "role")

	missingEndpoint := validRunPlanWithBindingsResult(t)
	missingEndpoint.Resource.Bindings[0].RuntimeEndpointID = domain.RuntimeEndpointID{}
	rejects(t, "missing runtime endpoint", missingEndpoint.Validate(), "runtime_endpoint_id")

	advancedBinding := validRunPlanWithBindingsResult(t)
	advancedBinding.Resource.Bindings[0].ResourceVersion = w1TestAdvancedVersion(t)
	rejects(t, "advanced binding", advancedBinding.Validate(), "resource_version")

	missingOperator := validRunPlanWithBindingsResult(t)
	missingOperator.Resource.OperatorID = domain.ActorID{}
	rejects(t, "missing operator", missingOperator.Validate(), "resource.operator_id")
}

func validRunJoinResult(t *testing.T) RunJoinResultDTO {
	t.Helper()
	workspaceID, err := domain.NewWorkspaceID()
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
	actorID, err := domain.NewActorID()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := domain.NewActorSessionID()
	if err != nil {
		t.Fatal(err)
	}
	return RunJoinResultDTO{
		CommandResultMetadataDTO: w1TestResultMetadata(t, OperationRunJoin, 1),
		Resource: RunJoinResourceDTO{
			WorkspaceID: workspaceID, RunID: runID, ParticipationID: participationID,
			ActorID: actorID, SessionID: sessionID,
			ParticipationState: string(domain.RunParticipationActive),
			ResourceVersion:    w1TestAdvancedVersion(t),
		},
	}
}

func TestRunJoinResultValidation(t *testing.T) {
	if err := validRunJoinResult(t).Validate(); err != nil {
		t.Fatalf("a well-formed run join result was rejected: %v", err)
	}

	// Joining advances an existing participation, so the initial version can
	// never be the post-command version.
	initialVersion := validRunJoinResult(t)
	initialVersion.Resource.ResourceVersion = domain.InitialVersion()
	rejects(t, "unadvanced participation", initialVersion.Validate(), "resource.resource_version")

	stillInvited := validRunJoinResult(t)
	stillInvited.Resource.ParticipationState = string(domain.RunParticipationInvited)
	rejects(t, "still invited", stillInvited.Validate(), "resource.participation_state")

	missingSession := validRunJoinResult(t)
	missingSession.Resource.SessionID = domain.ActorSessionID{}
	rejects(t, "missing session", missingSession.Validate(), "resource.session_id")
}

func validRunStartResult(t *testing.T) RunStartResultDTO {
	t.Helper()
	workspaceID, err := domain.NewWorkspaceID()
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	operatorID, err := domain.NewActorID()
	if err != nil {
		t.Fatal(err)
	}
	return RunStartResultDTO{
		CommandResultMetadataDTO: w1TestResultMetadata(t, OperationRunStart, 1),
		Resource: RunStartResourceDTO{
			WorkspaceID: workspaceID, RunID: runID, RunState: string(domain.RunStarting),
			RunVersion: w1TestAdvancedVersion(t), OperatorID: operatorID,
		},
	}
}

func TestRunStartResultValidation(t *testing.T) {
	if err := validRunStartResult(t).Validate(); err != nil {
		t.Fatalf("a well-formed run start result was rejected: %v", err)
	}

	stillPlanned := validRunStartResult(t)
	stillPlanned.Resource.RunState = string(domain.RunPlanned)
	rejects(t, "still planned", stillPlanned.Validate(), "resource.run_state")

	unadvanced := validRunStartResult(t)
	unadvanced.Resource.RunVersion = domain.InitialVersion()
	rejects(t, "unadvanced run", unadvanced.Validate(), "resource.run_version")

	missingRun := validRunStartResult(t)
	missingRun.Resource.RunID = domain.RunID{}
	rejects(t, "missing run", missingRun.Validate(), "resource.run_id")

	// A duplicated event identity would let one fact be counted twice.
	duplicateEvent := validRunStartResult(t)
	duplicateEvent.EmittedEventIDs = append(duplicateEvent.EmittedEventIDs, duplicateEvent.EmittedEventIDs[0])
	rejects(t, "duplicate event id", duplicateEvent.Validate(), "emitted_event_ids")
}
