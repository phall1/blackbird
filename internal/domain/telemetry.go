package domain

import (
	"errors"
	"fmt"
	"time"
)

// Telemetry is the observation plane described by ADR-0001: what a model call
// cost and how long work took, reported by the harness adapters. These are
// observations, not coordination facts. Nothing here is journaled, nothing is
// immutable, and nothing an agent does with this data can make a lease, a
// message, or a reservation fail.

var ErrInvalidObservation = errors.New("invalid observation")

const (
	// MaxDedupeKeyBytes bounds the idempotency key. Ingest is idempotent on
	// (actor, dedupe key), which is what lets an emitter retry freely.
	MaxDedupeKeyBytes = 256
	// MaxProviderBytes and MaxModelBytes bound attribution strings that come
	// from a harness and are therefore not under this daemon's control.
	MaxProviderBytes = 64
	MaxModelBytes    = 128
	// MaxErrorKindBytes bounds a failure label. It is a classification, never
	// a message: an adapter that puts a provider's prose here will be truncated
	// into uselessness, which is the intended pressure.
	MaxErrorKindBytes = 128
	// MaxHarnessSessionBytes bounds the harness's own conversation id, kept so
	// an observation can be walked back to the transcript that produced it.
	MaxHarnessSessionBytes = 256
	// MaxSpanNameBytes bounds a span's label.
	MaxSpanNameBytes = 256
	// MaxRawUsageBytes bounds the payload an adapter derived its normalized
	// counts from. Keeping it is what makes a normalization bug recoverable
	// rather than silent; bounding it is what stops a harness from deciding how
	// much disk this daemon uses.
	MaxRawUsageBytes = 4096
	// MaxObservedDuration is a full day. A longer span is a broken clock on the
	// reporting side, not a real measurement, and admitting it would poison
	// every average computed over the table.
	MaxObservedDuration = 24 * time.Hour
	// MaxPhuxTerminalBytes bounds the ADR-0001 correlation field: the phux
	// TerminalId this agent was observed running in, when both systems are
	// present. It is an opaque local identifier and never a credential.
	MaxPhuxTerminalBytes = 128
)

// Harness names the agent host that observed a call. It is a closed set because
// an open one turns every typo into a new row in every group-by.
type Harness string

const (
	HarnessClaudeCode Harness = "claude-code"
	HarnessCodex      Harness = "codex"
	HarnessOpenCode   Harness = "opencode"
	HarnessPi         Harness = "pi"
	HarnessUnknown    Harness = "unknown"
)

func (harness Harness) Valid() bool {
	switch harness {
	case HarnessClaudeCode, HarnessCodex, HarnessOpenCode, HarnessPi, HarnessUnknown:
		return true
	default:
		return false
	}
}

// ModelOperation follows the OpenTelemetry GenAI operation vocabulary closely
// enough to be exportable, without adopting its optionality.
type ModelOperation string

const (
	ModelOperationChat       ModelOperation = "chat"
	ModelOperationCompletion ModelOperation = "completion"
	ModelOperationEmbedding  ModelOperation = "embedding"
	ModelOperationOther      ModelOperation = "other"
)

func (operation ModelOperation) Valid() bool {
	switch operation {
	case ModelOperationChat, ModelOperationCompletion, ModelOperationEmbedding, ModelOperationOther:
		return true
	default:
		return false
	}
}

// ObservedOutcome separates a call that failed from one a person or a timeout
// stopped, because the two mean opposite things about the model.
type ObservedOutcome string

const (
	ObservedOutcomeOK      ObservedOutcome = "ok"
	ObservedOutcomeError   ObservedOutcome = "error"
	ObservedOutcomeAborted ObservedOutcome = "aborted"
)

func (outcome ObservedOutcome) Valid() bool {
	switch outcome {
	case ObservedOutcomeOK, ObservedOutcomeError, ObservedOutcomeAborted:
		return true
	default:
		return false
	}
}

// SpanKind classifies the non-model half of where time goes.
type SpanKind string

const (
	SpanKindTool    SpanKind = "tool"
	SpanKindBuild   SpanKind = "build"
	SpanKindTest    SpanKind = "test"
	SpanKindCommand SpanKind = "command"
	SpanKindTurn    SpanKind = "turn"
	SpanKindOther   SpanKind = "other"
)

func (kind SpanKind) Valid() bool {
	switch kind {
	case SpanKindTool, SpanKindBuild, SpanKindTest, SpanKindCommand, SpanKindTurn, SpanKindOther:
		return true
	default:
		return false
	}
}

// TokenUsage holds DISJOINT token classes. This is the whole reason the
// observation plane normalizes rather than storing what a harness happened to
// send: harnesses disagree about what "input" means, and the disagreement is
// invisible in the numbers themselves.
//
// Anthropic reports input_tokens EXCLUDING cache; a live Claude Code transcript
// shows input_tokens=2 beside cache_read=26354. Codex reports a cumulative input
// INCLUDING cache. Summing those as though they were the same quantity
// undercounts one harness and double-counts the other, and nothing about the
// result looks wrong.
//
// So the classes here never overlap:
//
//	UncachedInput  processed fresh, neither served from nor written to cache
//	CacheRead      served from a prompt cache
//	CacheWrite     written into a prompt cache by this call
//	Output         generated
//	Reasoning      the reasoning subset OF Output, never additional to it
//
// What a provider bills as "input" is UncachedInput + CacheRead + CacheWrite.
type TokenUsage struct {
	UncachedInput uint64
	CacheRead     uint64
	CacheWrite    uint64
	Output        uint64
	// Reasoning is a subset of Output. ReasoningReported separates "this model
	// reported zero reasoning tokens" from "this harness does not report them",
	// which are different facts and would otherwise average identically.
	Reasoning         uint64
	ReasoningReported bool
}

// BilledInput is the sum a provider invoices as input. It is derived rather
// than stored so that no row can disagree with its own parts.
func (usage TokenUsage) BilledInput() uint64 {
	return usage.UncachedInput + usage.CacheRead + usage.CacheWrite
}

func (usage TokenUsage) Validate() error {
	for label, value := range map[string]uint64{
		"uncached_input": usage.UncachedInput,
		"cache_read":     usage.CacheRead,
		"cache_write":    usage.CacheWrite,
		"output":         usage.Output,
		"reasoning":      usage.Reasoning,
	} {
		if value > MaxCanonicalInteger {
			return fmt.Errorf("%w: %s tokens exceed the canonical integer bound", ErrInvalidObservation, label)
		}
	}
	if usage.ReasoningReported && usage.Reasoning > usage.Output {
		return fmt.Errorf("%w: reasoning tokens (%d) exceed output tokens (%d); reasoning is a subset of output",
			ErrInvalidObservation, usage.Reasoning, usage.Output)
	}
	if !usage.ReasoningReported && usage.Reasoning != 0 {
		return fmt.Errorf("%w: reasoning tokens present but not reported", ErrInvalidObservation)
	}
	return nil
}

// ModelCall is one observed request to a model.
type ModelCall struct {
	DedupeKey      string
	Harness        Harness
	HarnessSession string
	Provider       string
	Model          string
	Operation      ModelOperation
	Usage          TokenUsage
	Outcome        ObservedOutcome
	ErrorKind      string
	StartedAt      time.Time
	// Duration is optional. DurationKnown separates a source that measured an
	// instant response from one that cannot measure at all -- a Claude Code
	// transcript reports usage without latency, and collapsing that into zero
	// would silently drag every latency statistic toward it.
	Duration      time.Duration
	DurationKnown bool
	PhuxTerminal  string
	RawUsage      string
}

func (call ModelCall) Validate() error {
	if err := validateObservationCommon(call.DedupeKey, call.Harness, call.HarnessSession,
		call.Outcome, call.ErrorKind, call.StartedAt, call.Duration, call.DurationKnown,
		call.PhuxTerminal); err != nil {
		return err
	}
	if !call.Operation.Valid() {
		return fmt.Errorf("%w: unknown model operation %q", ErrInvalidObservation, call.Operation)
	}
	if err := boundedObservationField("provider", call.Provider, MaxProviderBytes, true); err != nil {
		return err
	}
	if err := boundedObservationField("model", call.Model, MaxModelBytes, true); err != nil {
		return err
	}
	if err := boundedObservationField("raw_usage", call.RawUsage, MaxRawUsageBytes, false); err != nil {
		return err
	}
	return call.Usage.Validate()
}

// Span is one observed unit of non-model work: a tool call, a build, a test
// run, or a whole agent turn.
type Span struct {
	DedupeKey      string
	Harness        Harness
	HarnessSession string
	Kind           SpanKind
	Name           string
	Outcome        ObservedOutcome
	ErrorKind      string
	StartedAt      time.Time
	Duration       time.Duration
	DurationKnown  bool
	PhuxTerminal   string
	Attributes     string
}

func (span Span) Validate() error {
	if err := validateObservationCommon(span.DedupeKey, span.Harness, span.HarnessSession,
		span.Outcome, span.ErrorKind, span.StartedAt, span.Duration, span.DurationKnown,
		span.PhuxTerminal); err != nil {
		return err
	}
	if !span.Kind.Valid() {
		return fmt.Errorf("%w: unknown span kind %q", ErrInvalidObservation, span.Kind)
	}
	if err := boundedObservationField("name", span.Name, MaxSpanNameBytes, true); err != nil {
		return err
	}
	return boundedObservationField("attributes", span.Attributes, MaxRawUsageBytes, false)
}

func validateObservationCommon(dedupeKey string, harness Harness, harnessSession string,
	outcome ObservedOutcome, errorKind string, startedAt time.Time, duration time.Duration,
	durationKnown bool, phuxTerminal string) error {
	if err := boundedObservationField("dedupe_key", dedupeKey, MaxDedupeKeyBytes, true); err != nil {
		return err
	}
	if !harness.Valid() {
		return fmt.Errorf("%w: unknown harness %q", ErrInvalidObservation, harness)
	}
	if err := boundedObservationField("harness_session", harnessSession, MaxHarnessSessionBytes, false); err != nil {
		return err
	}
	if !outcome.Valid() {
		return fmt.Errorf("%w: unknown outcome %q", ErrInvalidObservation, outcome)
	}
	if err := boundedObservationField("error_kind", errorKind, MaxErrorKindBytes, false); err != nil {
		return err
	}
	if err := boundedObservationField("phux_terminal", phuxTerminal, MaxPhuxTerminalBytes, false); err != nil {
		return err
	}
	if startedAt.IsZero() {
		return fmt.Errorf("%w: started_at is required", ErrInvalidObservation)
	}
	if durationKnown && (duration < 0 || duration > MaxObservedDuration) {
		return fmt.Errorf("%w: duration %s is outside [0, %s]", ErrInvalidObservation, duration, MaxObservedDuration)
	}
	if !durationKnown && duration != 0 {
		return fmt.Errorf("%w: duration present but not reported as measured", ErrInvalidObservation)
	}
	return nil
}

func boundedObservationField(label, value string, limit int, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%w: %s is required", ErrInvalidObservation, label)
		}
		return nil
	}
	if len(value) > limit {
		return fmt.Errorf("%w: %s is %d bytes, limit %d", ErrInvalidObservation, label, len(value), limit)
	}
	return nil
}
