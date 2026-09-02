package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

func validCall() domain.ModelCall {
	return domain.ModelCall{
		DedupeKey: "msg_01ABC", Harness: domain.HarnessClaudeCode, Provider: "anthropic",
		Model: "claude-opus-5", Operation: domain.ModelOperationChat,
		Usage:     domain.TokenUsage{UncachedInput: 2, CacheRead: 26354, CacheWrite: 23947, Output: 1469},
		Outcome:   domain.ObservedOutcomeOK,
		StartedAt: time.Now().UTC(), Duration: 4210 * time.Millisecond, DurationKnown: true,
	}
}

// The three input classes are disjoint, so what a provider bills as "input" is
// their sum and nothing in the row can disagree with it.
func TestBilledInputSumsTheDisjointInputClasses(t *testing.T) {
	t.Parallel()
	usage := domain.TokenUsage{UncachedInput: 2, CacheRead: 26354, CacheWrite: 23947, Output: 1469}
	if got := usage.BilledInput(); got != 50303 {
		t.Fatalf("BilledInput=%d, want 50303", got)
	}
}

func TestTokenUsageRejectsReasoningLargerThanOutput(t *testing.T) {
	t.Parallel()
	usage := domain.TokenUsage{Output: 5, Reasoning: 9, ReasoningReported: true}
	err := usage.Validate()
	if !errors.Is(err, domain.ErrInvalidObservation) {
		t.Fatalf("err=%v, want an invalid observation", err)
	}
	if !strings.Contains(err.Error(), "subset of output") {
		t.Fatalf("err=%q, want the subset rule explained", err)
	}
}

// Reporting reasoning tokens without saying they were reported is a
// contradiction the storage layer would otherwise silence into a NULL.
func TestTokenUsageRejectsUnreportedReasoningWithAValue(t *testing.T) {
	t.Parallel()
	usage := domain.TokenUsage{Output: 10, Reasoning: 3}
	if err := usage.Validate(); !errors.Is(err, domain.ErrInvalidObservation) {
		t.Fatalf("err=%v, want an invalid observation", err)
	}
}

func TestTokenUsageAcceptsZeroReasoningWhenReported(t *testing.T) {
	t.Parallel()
	usage := domain.TokenUsage{Output: 10, ReasoningReported: true}
	if err := usage.Validate(); err != nil {
		t.Fatalf("err=%v, want a reported zero to be valid", err)
	}
}

func TestModelCallValidationRejectsEachRequiredField(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*domain.ModelCall){
		"missing dedupe key": func(call *domain.ModelCall) { call.DedupeKey = "" },
		"unknown harness":    func(call *domain.ModelCall) { call.Harness = "emacs" },
		"unknown operation":  func(call *domain.ModelCall) { call.Operation = "summon" },
		"unknown outcome":    func(call *domain.ModelCall) { call.Outcome = "maybe" },
		"missing provider":   func(call *domain.ModelCall) { call.Provider = "" },
		"missing model":      func(call *domain.ModelCall) { call.Model = "" },
		"zero start":         func(call *domain.ModelCall) { call.StartedAt = time.Time{} },
		"negative duration":  func(call *domain.ModelCall) { call.Duration = -time.Second; call.DurationKnown = true },
		"absurd duration":    func(call *domain.ModelCall) { call.Duration = 48 * time.Hour; call.DurationKnown = true },
		"oversized model":    func(call *domain.ModelCall) { call.Model = strings.Repeat("m", 129) },
		"oversized raw":      func(call *domain.ModelCall) { call.RawUsage = strings.Repeat("r", 4097) },
		"oversized dedupe":   func(call *domain.ModelCall) { call.DedupeKey = strings.Repeat("d", 257) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			call := validCall()
			mutate(&call)
			if err := call.Validate(); !errors.Is(err, domain.ErrInvalidObservation) {
				t.Fatalf("err=%v, want an invalid observation", err)
			}
		})
	}
}

func TestModelCallValidationAcceptsAWellFormedCall(t *testing.T) {
	t.Parallel()
	if err := validCall().Validate(); err != nil {
		t.Fatal(err)
	}
}

// A source that cannot measure latency reports none, and that must stay
// distinguishable from one that measured zero.
func TestModelCallAcceptsAnUnmeasuredDuration(t *testing.T) {
	t.Parallel()
	call := validCall()
	call.Duration = 0
	call.DurationKnown = false
	if err := call.Validate(); err != nil {
		t.Fatalf("err=%v, want an unmeasured duration to be valid", err)
	}
}

func TestModelCallRejectsADurationThatWasNotMeasured(t *testing.T) {
	t.Parallel()
	call := validCall()
	call.Duration = time.Second
	call.DurationKnown = false
	if err := call.Validate(); !errors.Is(err, domain.ErrInvalidObservation) {
		t.Fatalf("err=%v, want a duration without a measurement flag rejected", err)
	}
}

func TestSpanValidation(t *testing.T) {
	t.Parallel()
	valid := domain.Span{
		DedupeKey: "build-1", Harness: domain.HarnessPi, Kind: domain.SpanKindBuild,
		Name: "make check", Outcome: domain.ObservedOutcomeOK,
		StartedAt: time.Now().UTC(), Duration: 92 * time.Second, DurationKnown: true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*domain.Span){
		"unknown kind":   func(span *domain.Span) { span.Kind = "vibes" },
		"missing name":   func(span *domain.Span) { span.Name = "" },
		"oversized name": func(span *domain.Span) { span.Name = strings.Repeat("n", 257) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			span := valid
			mutate(&span)
			if err := span.Validate(); !errors.Is(err, domain.ErrInvalidObservation) {
				t.Fatalf("err=%v, want an invalid observation", err)
			}
		})
	}
}

func TestObservationIDsAreDistinctAndTyped(t *testing.T) {
	t.Parallel()
	first, err := domain.NewObservationID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := domain.NewObservationID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("observation ids must be distinct")
	}
	if len(first.String()) != 36 {
		t.Fatalf("observation id %q is not a UUID", first)
	}
}
