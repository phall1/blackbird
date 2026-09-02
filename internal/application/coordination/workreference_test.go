package coordination

import (
	"errors"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/domain"
)

func TestWorkObservationErrorClassifiesEachKind(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		kind      WorkObservationErrorKind
		retryable bool
	}{
		{kind: WorkObservationUnavailable, retryable: true},
		{kind: WorkObservationIncompatible, retryable: false},
		{kind: WorkObservationMalformed, retryable: false},
	} {
		failure := &WorkObservationError{Provider: "beads", Kind: test.kind,
			Operation: "observe", Detail: "the tracker did not answer"}
		if failure.Code() != domain.ErrorCodeDependencyUnavailable {
			t.Errorf("%s code = %s", test.kind, failure.Code())
		}
		if failure.Category() != domain.ErrorCategoryDependency {
			t.Errorf("%s category = %s", test.kind, failure.Category())
		}
		if failure.Retryable() != test.retryable {
			t.Errorf("%s retryable = %t, want %t", test.kind, failure.Retryable(), test.retryable)
		}
		message := failure.Message()
		if !strings.Contains(message, "beads") || !strings.Contains(message, string(test.kind)) ||
			!strings.Contains(message, "the tracker did not answer") {
			t.Errorf("%s message = %q", test.kind, message)
		}
		if !IsWorkObservationKind(failure, test.kind) {
			t.Errorf("%s is not recognized as its own kind", test.kind)
		}
	}
}

func TestWorkObservationErrorCarriesItsCauseWithoutQuotingIt(t *testing.T) {
	t.Parallel()
	cause := errors.New("exec: \"bd\": executable file not found in $PATH")
	failure := &WorkObservationError{Provider: "beads", Kind: WorkObservationUnavailable,
		Operation: "configure", Detail: "the bd work-item tracker is not installed", Cause: cause}
	if !errors.Is(failure, cause) {
		t.Fatal("cause is not reachable through the error chain")
	}
	if strings.Contains(failure.Message(), "$PATH") || strings.Contains(failure.Error(), "$PATH") {
		t.Fatalf("cause leaked into the agent-facing text: %q / %q", failure.Error(), failure.Message())
	}
	if !strings.Contains(failure.Error(), "beads") || !strings.Contains(failure.Error(), "configure") {
		t.Fatalf("Error() = %q", failure.Error())
	}
	if IsWorkObservationKind(cause, WorkObservationUnavailable) {
		t.Fatal("a plain error was classified as a boundary failure")
	}
}

func TestWorkObservationErrorStaysInsideTheDomainMessageBound(t *testing.T) {
	t.Parallel()
	failure := &WorkObservationError{Kind: WorkObservationMalformed, Operation: "observe",
		Detail: strings.Repeat("d", MaxWorkObservationDetail*4)}
	message := failure.Message()
	if _, err := domain.NewCommandError(failure.Code(), message, nil); err != nil {
		t.Fatalf("message of %d bytes is not a valid command message: %v", len(message), err)
	}
	if !strings.HasPrefix(message, "work provider reported") {
		t.Fatalf("unattributed message = %q", message)
	}
	// A boundary failure raised with neither kind nor detail still has to say
	// something an agent can act on rather than an empty sentence.
	empty := &WorkObservationError{Operation: "observe"}
	if _, err := domain.NewCommandError(empty.Code(), empty.Message(), nil); err != nil {
		t.Fatalf("detail-free message is not valid: %v", err)
	}
	if !strings.Contains(empty.Message(), string(WorkObservationUnavailable)) {
		t.Fatalf("kindless message = %q", empty.Message())
	}
}
