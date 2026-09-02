package coordination

import (
	"errors"
	"fmt"
	"strings"

	"github.com/phall1/blackbird/internal/domain"
)

// WorkObservationErrorKind classifies a failure at the work-provider boundary.
//
// The kind exists because "the observation did not happen" is three different
// situations for the agent that asked, and only one of them is worth trying
// again: the provider is not installed on this machine, the provider is
// installed but speaks an interface Blackbird does not support, or the provider
// answered with something that does not match the supported schema. Collapsing
// them into one internal error leaves an agent with no move except to retry
// something that can never succeed, which is exactly what the kind prevents.
type WorkObservationErrorKind string

const (
	// WorkObservationUnavailable means the provider could not be invoked at
	// all: absent from the daemon's PATH, not executable, or it did not answer
	// inside the observation budget. Retrying later can succeed, because
	// installing the provider changes the answer.
	WorkObservationUnavailable WorkObservationErrorKind = "dependency_unavailable"
	// WorkObservationIncompatible means the provider ran and identified itself
	// as a version or schema this adapter does not support. Repeating the call
	// cannot help; the provider or Blackbird has to change first.
	WorkObservationIncompatible WorkObservationErrorKind = "dependency_incompatible"
	// WorkObservationMalformed means the request or the provider's answer did
	// not match the supported shape -- an unusable object id on the way in, or
	// a response that does not decode on the way out.
	WorkObservationMalformed WorkObservationErrorKind = "dependency_malformed"
)

// MaxWorkObservationDetail bounds the sanitized detail a boundary failure may
// carry. Detail is authored text describing the boundary, never provider
// output, and the bound keeps it inside the domain's message limit.
const MaxWorkObservationDetail = 256

// WorkObservationError is the transport-neutral failure of an attempt to
// observe provider-owned work. It is the only failure a WorkReferenceObserver
// may return for a boundary problem, and it deliberately carries no provider
// output: Detail is authored by the adapter, so a transport can show it without
// leaking whatever the external binary wrote to its pipes.
//
// Code, Category, Retryable and Message are answered here rather than in each
// transport, so the MCP and HTTP surfaces cannot disagree about what a broken
// work provider is.
type WorkObservationError struct {
	// Provider names the adapter that failed, for example "beads". It may be
	// empty when no provider is composed at all.
	Provider  string
	Kind      WorkObservationErrorKind
	Operation string
	Detail    string
	Cause     error
}

func (e *WorkObservationError) Error() string {
	return fmt.Sprintf("%s %s: %s", e.providerLabel(), e.Operation, e.Kind)
}

func (e *WorkObservationError) Unwrap() error { return e.Cause }

// Code is DEPENDENCY_UNAVAILABLE for every kind: whatever went wrong, the
// dependency did not serve the observation, and the caller's own request was
// well formed. The kind, not the code, is what separates the three situations,
// and a transport publishes it beside the code.
func (e *WorkObservationError) Code() domain.ErrorCode {
	return domain.ErrorCodeDependencyUnavailable
}

// Category follows the code, so a new domain category cannot silently diverge
// from what this error reports.
func (e *WorkObservationError) Category() domain.ErrorCategory {
	category, _ := e.Code().Category()
	return category
}

// Retryable is true only for an unavailable provider. An incompatible or
// malformed provider answers the same way every time, and telling an agent to
// retry it spends its turns on a call that cannot succeed.
func (e *WorkObservationError) Retryable() bool {
	return e.Kind == WorkObservationUnavailable
}

// Message is the sanitized sentence an agent is shown. It names the provider,
// the kind, and the authored detail, and nothing the external process emitted.
func (e *WorkObservationError) Message() string {
	detail := strings.TrimSpace(e.Detail)
	if detail == "" {
		detail = "the work provider could not serve this observation"
	}
	if len(detail) > MaxWorkObservationDetail {
		detail = detail[:MaxWorkObservationDetail]
	}
	kind := e.Kind
	if kind == "" {
		kind = WorkObservationUnavailable
	}
	return fmt.Sprintf("%s reported %s: %s", e.providerLabel(), kind, detail)
}

func (e *WorkObservationError) providerLabel() string {
	if e.Provider == "" {
		return "work provider"
	}
	return "work provider " + e.Provider
}

// IsWorkObservationKind reports whether err is a boundary failure of exactly
// this kind, anywhere in its cause chain.
func IsWorkObservationKind(err error, kind WorkObservationErrorKind) bool {
	var observationError *WorkObservationError
	return errors.As(err, &observationError) && observationError.Kind == kind
}
