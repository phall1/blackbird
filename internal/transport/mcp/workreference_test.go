package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

type failingWorkReferenceObserver struct{ failure error }

func (observer failingWorkReferenceObserver) ObserveWorkReference(
	context.Context, string, string,
) (coordination.WorkReference, error) {
	return coordination.WorkReference{}, observer.failure
}

func observationServer(t *testing.T, observer coordination.WorkReferenceObserver) *Server {
	t.Helper()
	store, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "observe.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server, err := NewServer(Dependencies{Coordination: store, WorkReferences: observer})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

// TestWorkObservationFailuresStayClassifiable is the difference between an
// agent that installs bd and one that retries an impossible call forever: a
// boundary failure must reach it as a dependency failure carrying the kind,
// never as the generic internal error every unrecognized error collapses into.
func TestWorkObservationFailuresStayClassifiable(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		kind      coordination.WorkObservationErrorKind
		retryable bool
	}{
		{name: "absent", kind: coordination.WorkObservationUnavailable, retryable: true},
		{name: "unsupported", kind: coordination.WorkObservationIncompatible, retryable: false},
		{name: "unusable", kind: coordination.WorkObservationMalformed, retryable: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			observer := failingWorkReferenceObserver{failure: &coordination.WorkObservationError{
				Provider: "beads", Kind: test.kind, Operation: "observe",
				Detail: "the tracker could not answer", Cause: context.Canceled}}
			client, closeMCP := connect(t, observationServer(t, observer))
			defer closeMCP()
			session := callCoord[agentSessionOutput](t, client, ToolJoin,
				registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "alice"})
			failure := callCoordFailure(t, client, ToolStatus,
				statusInput{AgentToken: session.RegistrationToken, ObjectID: "blackbird-a1u.1"})
			if failure.Code != string(domain.ErrorCodeDependencyUnavailable) ||
				failure.Category != string(domain.ErrorCategoryDependency) {
				t.Fatalf("failure = %+v", failure)
			}
			if failure.Dependency == nil || failure.Dependency.Kind != string(test.kind) ||
				failure.Dependency.Provider != "beads" || failure.Dependency.Operation != "observe" ||
				failure.Dependency.Detail != "the tracker could not answer" {
				t.Fatalf("dependency = %+v", failure.Dependency)
			}
			if failure.Retryable != test.retryable {
				t.Fatalf("retryable = %t, want %t", failure.Retryable, test.retryable)
			}
			if !strings.Contains(failure.Message, "beads") || strings.Contains(failure.Message, "context canceled") {
				t.Fatalf("message = %q", failure.Message)
			}
		})
	}
}

// TestWorkObservationOnAMachineWithoutAProvider pins the state a machine with
// no work provider is in. It is a property of the machine, not a mistake by the
// caller, so it must not arrive as an argument failure that sends an agent to
// rewrite a call that was already correct.
func TestWorkObservationOnAMachineWithoutAProvider(t *testing.T) {
	t.Parallel()
	client, closeMCP := connect(t, observationServer(t, nil))
	defer closeMCP()
	session := callCoord[agentSessionOutput](t, client, ToolJoin,
		registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "alice"})
	failure := callCoordFailure(t, client, ToolStatus,
		statusInput{AgentToken: session.RegistrationToken, ObjectID: "blackbird-a1u.1"})
	if failure.Code != string(domain.ErrorCodeDependencyUnavailable) || failure.Dependency == nil ||
		failure.Dependency.Kind != string(coordination.WorkObservationUnavailable) {
		t.Fatalf("failure = %+v / %+v", failure, failure.Dependency)
	}
	// Everything status answers on its own still works on the same machine.
	status := callCoord[statusOutput](t, client, ToolStatus, statusInput{AgentToken: session.RegistrationToken})
	if len(status.Agents) != 1 || status.WorkReference != nil {
		t.Fatalf("status without a provider = %+v", status)
	}
}

// TestWorkObservationToolDocumentsItsOwnMeaning guards the one paragraph an
// agent ever reads about this result. Nothing else tells it that a work
// reference is a point-in-time read of another system's record.
func TestWorkObservationToolDocumentsItsOwnMeaning(t *testing.T) {
	t.Parallel()
	client, closeMCP := connect(t, observationServer(t, testWorkReferenceObserver{}))
	defer closeMCP()
	tools, err := client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	description, schema := "", ""
	for _, tool := range tools.Tools {
		if tool.Name == ToolStatus {
			description = tool.Description
			encoded, marshalErr := json.Marshal(tool.InputSchema)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			schema = string(encoded)
		}
	}
	if !strings.Contains(schema, "issue tracker") || !strings.Contains(schema, "observed_at") {
		t.Errorf("object_id is published without documentation: %s", schema)
	}
	for _, phrase := range []string{"observation", "authority", "observed_at", string(domain.ErrorCodeDependencyUnavailable)} {
		if !strings.Contains(description, phrase) {
			t.Errorf("%s description omits %q: %s", ToolStatus, phrase, description)
		}
	}
}
