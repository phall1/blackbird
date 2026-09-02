package domain

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	ErrUnknownErrorCode    = errors.New("unknown command error code")
	ErrInvalidErrorMessage = errors.New("invalid command error message")
	ErrInvalidConflictKind = errors.New("invalid domain conflict kind")
)

type ErrorCode string

const (
	ErrorCodeInvalidArgument       ErrorCode = "INVALID_ARGUMENT"
	ErrorCodeInvalidSchema         ErrorCode = "INVALID_SCHEMA"
	ErrorCodeUnauthenticated       ErrorCode = "UNAUTHENTICATED"
	ErrorCodeSessionExpired        ErrorCode = "SESSION_EXPIRED"
	ErrorCodeForbidden             ErrorCode = "FORBIDDEN"
	ErrorCodeCapabilityRequired    ErrorCode = "CAPABILITY_REQUIRED"
	ErrorCodeNotFound              ErrorCode = "NOT_FOUND"
	ErrorCodeStaleVersion          ErrorCode = "STALE_VERSION"
	ErrorCodeStateConflict         ErrorCode = "STATE_CONFLICT"
	ErrorCodeIdempotencyKeyReused  ErrorCode = "IDEMPOTENCY_KEY_REUSED"
	ErrorCodeCommandIDReused       ErrorCode = "COMMAND_ID_REUSED"
	ErrorCodeCommandInProgress     ErrorCode = "COMMAND_IN_PROGRESS"
	ErrorCodeLeaseConflict         ErrorCode = "LEASE_CONFLICT"
	ErrorCodeLeaseExpired          ErrorCode = "LEASE_EXPIRED"
	ErrorCodeFenceRejected         ErrorCode = "FENCE_REJECTED"
	ErrorCodeCursorInvalid         ErrorCode = "CURSOR_INVALID"
	ErrorCodeCursorScopeMismatch   ErrorCode = "CURSOR_SCOPE_MISMATCH"
	ErrorCodeCursorExpired         ErrorCode = "CURSOR_EXPIRED"
	ErrorCodeRateLimited           ErrorCode = "RATE_LIMITED"
	ErrorCodeBackpressure          ErrorCode = "BACKPRESSURE"
	ErrorCodeDependencyUnavailable ErrorCode = "DEPENDENCY_UNAVAILABLE"
	ErrorCodeDeadlineExceeded      ErrorCode = "DEADLINE_EXCEEDED"
	ErrorCodeInternal              ErrorCode = "INTERNAL"
)

type ErrorCategory string

const (
	ErrorCategoryValidation     ErrorCategory = "validation"
	ErrorCategoryAuthentication ErrorCategory = "authentication"
	ErrorCategoryAuthorization  ErrorCategory = "authorization"
	ErrorCategoryLookup         ErrorCategory = "lookup"
	ErrorCategoryConflict       ErrorCategory = "conflict"
	ErrorCategoryContention     ErrorCategory = "contention"
	ErrorCategoryCursor         ErrorCategory = "cursor"
	ErrorCategoryCapacity       ErrorCategory = "capacity"
	ErrorCategoryDependency     ErrorCategory = "dependency"
	ErrorCategoryTimeout        ErrorCategory = "timeout"
	ErrorCategoryInternal       ErrorCategory = "internal"
)

func (code ErrorCode) Category() (ErrorCategory, bool) {
	switch code {
	case ErrorCodeInvalidArgument, ErrorCodeInvalidSchema:
		return ErrorCategoryValidation, true
	case ErrorCodeUnauthenticated, ErrorCodeSessionExpired:
		return ErrorCategoryAuthentication, true
	case ErrorCodeForbidden, ErrorCodeCapabilityRequired:
		return ErrorCategoryAuthorization, true
	case ErrorCodeNotFound:
		return ErrorCategoryLookup, true
	case ErrorCodeStaleVersion,
		ErrorCodeStateConflict,
		ErrorCodeIdempotencyKeyReused,
		ErrorCodeCommandIDReused,
		ErrorCodeLeaseConflict,
		ErrorCodeLeaseExpired,
		ErrorCodeFenceRejected:
		return ErrorCategoryConflict, true
	case ErrorCodeCommandInProgress:
		return ErrorCategoryContention, true
	case ErrorCodeCursorInvalid, ErrorCodeCursorScopeMismatch, ErrorCodeCursorExpired:
		return ErrorCategoryCursor, true
	case ErrorCodeRateLimited, ErrorCodeBackpressure:
		return ErrorCategoryCapacity, true
	case ErrorCodeDependencyUnavailable:
		return ErrorCategoryDependency, true
	case ErrorCodeDeadlineExceeded:
		return ErrorCategoryTimeout, true
	case ErrorCodeInternal:
		return ErrorCategoryInternal, true
	default:
		return "", false
	}
}

func (code ErrorCode) Valid() bool {
	_, valid := code.Category()
	return valid
}

// DefaultRetryable reports the stable retry posture of a code. LEASE_CONFLICT
// belongs here because a lease has a bounded TTL: the failure clears on its own
// once the holder's lease expires, so the same request is worth repeating after
// the delay the failure reports. LEASE_EXPIRED and FENCE_REJECTED do not,
// because the caller must re-acquire the lease and refresh its fences first.
func (code ErrorCode) DefaultRetryable() bool {
	switch code {
	case ErrorCodeStaleVersion,
		ErrorCodeCommandInProgress,
		ErrorCodeLeaseConflict,
		ErrorCodeRateLimited,
		ErrorCodeBackpressure,
		ErrorCodeDependencyUnavailable,
		ErrorCodeDeadlineExceeded,
		ErrorCodeInternal:
		return true
	default:
		return false
	}
}

type ConflictKind string

const (
	ConflictAuthorityMismatch    ConflictKind = "AuthorityMismatch"
	ConflictVersion              ConflictKind = "VersionConflict"
	ConflictIdempotency          ConflictKind = "IdempotencyConflict"
	ConflictState                ConflictKind = "StateConflict"
	ConflictReference            ConflictKind = "ReferenceConflict"
	ConflictProviderAuthority    ConflictKind = "ProviderAuthorityConflict"
	ConflictSessionTerminal      ConflictKind = "SessionTerminalConflict"
	ConflictParticipant          ConflictKind = "ParticipantConflict"
	ConflictConversationClosed   ConflictKind = "ConversationClosedConflict"
	ConflictDeliveryFact         ConflictKind = "DeliveryFactConflict"
	ConflictDecisionTerminal     ConflictKind = "DecisionTerminalConflict"
	ConflictDecisionResponse     ConflictKind = "DecisionResponseConflict"
	ConflictAttentionGeneration  ConflictKind = "AttentionGenerationConflict"
	ConflictAttentionResolved    ConflictKind = "AttentionResolvedConflict"
	ConflictLease                ConflictKind = "LeaseConflict"
	ConflictLeaseTerminal        ConflictKind = "LeaseTerminalConflict"
	ConflictFence                ConflictKind = "FenceConflict"
	ConflictLeaseScope           ConflictKind = "LeaseScopeConflict"
	ConflictAcceptance           ConflictKind = "AcceptanceConflict"
	ConflictProviderObservation  ConflictKind = "ProviderObservationConflict"
	ConflictRuntimeObservation   ConflictKind = "RuntimeObservationConflict"
	ConflictArtifactVerification ConflictKind = "ArtifactVerificationConflict"
)

func (kind ConflictKind) Valid() bool {
	switch kind {
	case ConflictAuthorityMismatch,
		ConflictVersion,
		ConflictIdempotency,
		ConflictState,
		ConflictReference,
		ConflictProviderAuthority,
		ConflictSessionTerminal,
		ConflictParticipant,
		ConflictConversationClosed,
		ConflictDeliveryFact,
		ConflictDecisionTerminal,
		ConflictDecisionResponse,
		ConflictAttentionGeneration,
		ConflictAttentionResolved,
		ConflictLease,
		ConflictLeaseTerminal,
		ConflictFence,
		ConflictLeaseScope,
		ConflictAcceptance,
		ConflictProviderObservation,
		ConflictRuntimeObservation,
		ConflictArtifactVerification:
		return true
	default:
		return false
	}
}

// CommandError is the transport-neutral, safe command failure. Storage and
// transport causes can be wrapped for identity without entering its message.
type CommandError struct {
	code      ErrorCode
	category  ErrorCategory
	message   string
	retryable bool
	conflict  ConflictKind
	cause     error
}

func NewCommandError(code ErrorCode, message string, cause error) (*CommandError, error) {
	category, valid := code.Category()
	if !valid {
		return nil, fmt.Errorf("%w: %q", ErrUnknownErrorCode, code)
	}
	if strings.TrimSpace(message) == "" || len(message) > 512 || !utf8.ValidString(message) {
		return nil, ErrInvalidErrorMessage
	}
	return &CommandError{
		code:      code,
		category:  category,
		message:   message,
		retryable: code.DefaultRetryable(),
		cause:     cause,
	}, nil
}

func NewConflictError(code ErrorCode, kind ConflictKind, message string, cause error) (*CommandError, error) {
	if !kind.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidConflictKind, kind)
	}
	expectedCode := kind.errorCode()
	if code != expectedCode {
		return nil, fmt.Errorf("%w: conflict %q requires code %q, got %q", ErrInvalidConflictKind, kind, expectedCode, code)
	}
	err, constructionErr := NewCommandError(code, message, cause)
	if constructionErr != nil {
		return nil, constructionErr
	}
	err.conflict = kind
	return err, nil
}

func (kind ConflictKind) errorCode() ErrorCode {
	switch kind {
	case ConflictVersion:
		return ErrorCodeStaleVersion
	case ConflictIdempotency:
		return ErrorCodeIdempotencyKeyReused
	case ConflictLease:
		return ErrorCodeLeaseConflict
	case ConflictLeaseTerminal:
		return ErrorCodeLeaseExpired
	case ConflictFence:
		return ErrorCodeFenceRejected
	case ConflictLeaseScope:
		return ErrorCodeInvalidArgument
	default:
		return ErrorCodeStateConflict
	}
}

func (e *CommandError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.message == "" {
		return string(e.code)
	}
	return string(e.code) + ": " + e.message
}

func (e *CommandError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *CommandError) Is(target error) bool {
	other, ok := target.(*CommandError)
	if !ok || e == nil || other == nil || other.code == "" {
		return false
	}
	if e.code != other.code {
		return false
	}
	return other.conflict == "" || e.conflict == other.conflict
}

func (e *CommandError) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

func (e *CommandError) Category() ErrorCategory {
	if e == nil {
		return ""
	}
	return e.category
}

// Message exposes the safe, transport-neutral failure text the constructor
// validated. Transports that discard it fall back to a per-code generic string
// and lose the precision the domain already paid for.
func (e *CommandError) Message() string {
	if e == nil {
		return ""
	}
	return e.message
}

func (e *CommandError) Retryable() bool { return e != nil && e.retryable }

func (e *CommandError) ConflictKind() (ConflictKind, bool) {
	if e == nil || e.conflict == "" {
		return "", false
	}
	return e.conflict, true
}

func commandErrorSentinel(code ErrorCode) *CommandError {
	category, _ := code.Category()
	return &CommandError{code: code, category: category, retryable: code.DefaultRetryable()}
}

var (
	ErrInvalidArgument       = commandErrorSentinel(ErrorCodeInvalidArgument)
	ErrInvalidSchema         = commandErrorSentinel(ErrorCodeInvalidSchema)
	ErrUnauthenticated       = commandErrorSentinel(ErrorCodeUnauthenticated)
	ErrSessionExpired        = commandErrorSentinel(ErrorCodeSessionExpired)
	ErrForbidden             = commandErrorSentinel(ErrorCodeForbidden)
	ErrCapabilityRequired    = commandErrorSentinel(ErrorCodeCapabilityRequired)
	ErrNotFound              = commandErrorSentinel(ErrorCodeNotFound)
	ErrStaleVersion          = commandErrorSentinel(ErrorCodeStaleVersion)
	ErrStateConflict         = commandErrorSentinel(ErrorCodeStateConflict)
	ErrIdempotencyKeyReused  = commandErrorSentinel(ErrorCodeIdempotencyKeyReused)
	ErrCommandIDReused       = commandErrorSentinel(ErrorCodeCommandIDReused)
	ErrCommandInProgress     = commandErrorSentinel(ErrorCodeCommandInProgress)
	ErrLeaseConflict         = commandErrorSentinel(ErrorCodeLeaseConflict)
	ErrLeaseExpired          = commandErrorSentinel(ErrorCodeLeaseExpired)
	ErrFenceRejected         = commandErrorSentinel(ErrorCodeFenceRejected)
	ErrCursorInvalid         = commandErrorSentinel(ErrorCodeCursorInvalid)
	ErrCursorScopeMismatch   = commandErrorSentinel(ErrorCodeCursorScopeMismatch)
	ErrCursorExpired         = commandErrorSentinel(ErrorCodeCursorExpired)
	ErrRateLimited           = commandErrorSentinel(ErrorCodeRateLimited)
	ErrBackpressure          = commandErrorSentinel(ErrorCodeBackpressure)
	ErrDependencyUnavailable = commandErrorSentinel(ErrorCodeDependencyUnavailable)
	ErrDeadlineExceeded      = commandErrorSentinel(ErrorCodeDeadlineExceeded)
	ErrInternal              = commandErrorSentinel(ErrorCodeInternal)
)
