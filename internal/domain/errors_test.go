package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestStableErrorCodeCategories(t *testing.T) {
	tests := map[ErrorCode]ErrorCategory{
		ErrorCodeInvalidArgument:       ErrorCategoryValidation,
		ErrorCodeInvalidSchema:         ErrorCategoryValidation,
		ErrorCodeUnauthenticated:       ErrorCategoryAuthentication,
		ErrorCodeSessionExpired:        ErrorCategoryAuthentication,
		ErrorCodeForbidden:             ErrorCategoryAuthorization,
		ErrorCodeCapabilityRequired:    ErrorCategoryAuthorization,
		ErrorCodeNotFound:              ErrorCategoryLookup,
		ErrorCodeStaleVersion:          ErrorCategoryConflict,
		ErrorCodeStateConflict:         ErrorCategoryConflict,
		ErrorCodeIdempotencyKeyReused:  ErrorCategoryConflict,
		ErrorCodeCommandIDReused:       ErrorCategoryConflict,
		ErrorCodeCommandInProgress:     ErrorCategoryContention,
		ErrorCodeLeaseConflict:         ErrorCategoryConflict,
		ErrorCodeLeaseExpired:          ErrorCategoryConflict,
		ErrorCodeFenceRejected:         ErrorCategoryConflict,
		ErrorCodeCursorInvalid:         ErrorCategoryCursor,
		ErrorCodeCursorScopeMismatch:   ErrorCategoryCursor,
		ErrorCodeCursorExpired:         ErrorCategoryCursor,
		ErrorCodeRateLimited:           ErrorCategoryCapacity,
		ErrorCodeBackpressure:          ErrorCategoryCapacity,
		ErrorCodeDependencyUnavailable: ErrorCategoryDependency,
		ErrorCodeDeadlineExceeded:      ErrorCategoryTimeout,
		ErrorCodeInternal:              ErrorCategoryInternal,
	}
	for code, expected := range tests {
		category, valid := code.Category()
		if !valid || category != expected {
			t.Errorf("%s category = %q, %v; want %q", code, category, valid, expected)
		}
	}
	if _, valid := ErrorCode("NOPE").Category(); valid {
		t.Fatal("unknown error code is valid")
	}
}

func TestCommandErrorIdentityAndSafeMessage(t *testing.T) {
	secretCause := errors.New("sql: secret-token")
	commandErr, err := NewCommandError(ErrorCodeCommandIDReused, "command identity was reused", secretCause)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(commandErr, ErrCommandIDReused) || !errors.Is(commandErr, secretCause) {
		t.Fatal("command error identity or cause was lost")
	}
	if strings.Contains(commandErr.Error(), "secret-token") {
		t.Fatal("private cause leaked into safe command message")
	}
	if errors.Is(commandErr, ErrIdempotencyKeyReused) {
		t.Fatal("command-id and idempotency-key reuse were conflated")
	}
	wrapped := fmt.Errorf("outer: %w", commandErr)
	if !errors.Is(wrapped, ErrCommandIDReused) {
		t.Fatal("wrapped code identity was lost")
	}
	if _, err := NewCommandError(ErrorCode("UNKNOWN"), "message", nil); !errors.Is(err, ErrUnknownErrorCode) {
		t.Fatalf("unknown code error = %v", err)
	}
}

func TestConflictKindsEnforceCatalogCodeMapping(t *testing.T) {
	tests := []struct {
		kind ConflictKind
		code ErrorCode
	}{
		{ConflictVersion, ErrorCodeStaleVersion},
		{ConflictIdempotency, ErrorCodeIdempotencyKeyReused},
		{ConflictLease, ErrorCodeLeaseConflict},
		{ConflictLeaseTerminal, ErrorCodeLeaseExpired},
		{ConflictFence, ErrorCodeFenceRejected},
		{ConflictLeaseScope, ErrorCodeInvalidArgument},
		{ConflictAuthorityMismatch, ErrorCodeStateConflict},
		{ConflictReference, ErrorCodeStateConflict},
		{ConflictSessionTerminal, ErrorCodeStateConflict},
	}
	for _, test := range tests {
		commandErr, err := NewConflictError(test.code, test.kind, "cataloged conflict", nil)
		if err != nil {
			t.Errorf("%s/%s: %v", test.kind, test.code, err)
			continue
		}
		if actual, ok := commandErr.ConflictKind(); !ok || actual != test.kind {
			t.Errorf("conflict = %q, %v", actual, ok)
		}
		if !errors.Is(commandErr, commandErrorSentinel(test.code)) {
			t.Errorf("%s lost code identity", test.kind)
		}
		if _, err := NewConflictError(ErrorCodeStateConflict, test.kind, "wrong mapping", nil); test.code != ErrorCodeStateConflict && !errors.Is(err, ErrInvalidConflictKind) {
			t.Errorf("%s accepted invalid STATE_CONFLICT mapping: %v", test.kind, err)
		}
	}
}
