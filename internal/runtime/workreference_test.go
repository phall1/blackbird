package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/integration/beads"
)

// fakeTracker writes a stand-in for the bd binary and returns its absolute
// path. The supported version and schema are read from the adapter rather than
// quoted, so raising the supported interface fails the adapter's own probe here
// instead of leaving a test that passes against a version nobody ships.
func fakeTracker(t *testing.T, objectID, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bd")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "--json" ] && [ "$2" = "version" ]; then
  printf '%%s' '{"branch":"v%[1]s","build":"test","schema_version":%[2]d,"version":"%[1]s"}'
  exit 0
fi
%[3]s
printf '%%s' '[{"id":"%[4]s","title":"Finish the beads integration","status":"in_progress","priority":1,"issue_type":"task","assignee":"agent","updated_at":"2026-09-02T10:51:08Z","dependencies":[],"close_reason":"unread by blackbird"}]'
`, beads.SupportedVersion, beads.SupportedSchemaVersion, body, objectID)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func observerFinding(path string) beadsWorkReferenceObserver {
	observer := newBeadsWorkReferenceObserver()
	observer.lookPath = func(string) (string, error) { return path, nil }
	return observer
}

func TestWorkObservationReportsWhatTheTrackerSaysWithoutOwningIt(t *testing.T) {
	t.Parallel()
	project := t.TempDir()
	observer := observerFinding(fakeTracker(t, "blackbird-a1u.1", ""))
	observed, err := observer.ObserveWorkReference(context.Background(), project, "blackbird-a1u.1")
	if err != nil {
		t.Fatalf("ObserveWorkReference() error = %v", err)
	}
	if observed.Provider != beads.ProviderName || observed.Project != project ||
		observed.ObjectID != "blackbird-a1u.1" || observed.Fields.Title != "Finish the beads integration" ||
		observed.Fields.Status != "in_progress" || observed.Fields.IssueType != "task" ||
		observed.Fields.Priority != 1 || observed.Fields.Assignee != "agent" {
		t.Fatalf("observation = %#v", observed)
	}
	// The observation says when it was read and by which binary, which is what
	// keeps a caller from mistaking it for a Blackbird record of the work.
	if observed.ObservedAt.IsZero() || observed.ObservedVersion == "" ||
		observed.Provenance.Version != beads.SupportedVersion || observed.Provenance.BinarySHA256 == "" {
		t.Fatalf("observation provenance = %#v", observed)
	}
}

func TestWorkObservationDegradesCleanlyWhereTheTrackerIsNotInstalled(t *testing.T) {
	t.Parallel()
	observer := newBeadsWorkReferenceObserver()
	looked := 0
	observer.lookPath = func(name string) (string, error) {
		looked++
		if name != beads.ExecutableName {
			t.Errorf("looked up %q", name)
		}
		return "", exec.ErrNotFound
	}
	_, err := observer.ObserveWorkReference(context.Background(), t.TempDir(), "blackbird-a1u.1")
	var failure *coordination.WorkObservationError
	if !errors.As(err, &failure) || failure.Kind != coordination.WorkObservationUnavailable {
		t.Fatalf("ObserveWorkReference() error = %v", err)
	}
	if failure.Provider != beads.ProviderName || !failure.Retryable() || looked != 1 {
		t.Fatalf("failure = %#v after %d lookups", failure, looked)
	}
}

func TestWorkObservationRejectsAProjectKeyThatIsNotARepositoryPath(t *testing.T) {
	t.Parallel()
	observer := newBeadsWorkReferenceObserver()
	observer.lookPath = func(string) (string, error) {
		t.Error("looked for the tracker before validating the project key")
		return "", exec.ErrNotFound
	}
	_, err := observer.ObserveWorkReference(context.Background(), "my-project", "blackbird-a1u.1")
	var failure *coordination.WorkObservationError
	if !errors.As(err, &failure) || failure.Kind != coordination.WorkObservationMalformed {
		t.Fatalf("ObserveWorkReference() error = %v", err)
	}
	if failure.Retryable() {
		t.Fatal("an unusable project key was reported as worth retrying")
	}
}

func TestWorkObservationIsBoundedWhenTheTrackerHangs(t *testing.T) {
	t.Parallel()
	observer := observerFinding(fakeTracker(t, "blackbird-a1u.1", "sleep 30"))
	observer.budget, observer.step = 900*time.Millisecond, 300*time.Millisecond
	started := time.Now()
	_, err := observer.ObserveWorkReference(context.Background(), t.TempDir(), "blackbird-a1u.1")
	elapsed := time.Since(started)
	if !beads.IsErrorKind(err, beads.ErrorUnavailable) {
		t.Fatalf("ObserveWorkReference() error = %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("a hung tracker held the caller for %s", elapsed)
	}
}

func TestWorkObservationComposesItsOwnBoundsAndLookup(t *testing.T) {
	t.Parallel()
	observer := newBeadsWorkReferenceObserver()
	if observer.lookPath == nil || observer.budget != workObservationBudget || observer.step != workObservationStep {
		t.Fatalf("composed observer = %+v", observer)
	}
	// One observation is two bounded executions, so the step must leave room
	// for both inside the budget an agent actually waits.
	if observer.step*2 > observer.budget {
		t.Fatalf("step %s twice exceeds budget %s", observer.step, observer.budget)
	}
}
