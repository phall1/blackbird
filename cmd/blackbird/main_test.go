package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestExecutePrintsVersion(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := execute(context.Background(), []string{"--version"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("execute() = %d, want %d; stderr=%q", code, exitOK, stderr.String())
	}
	if got, want := stdout.String(), "blackbird version=dev commit=unknown built_at=unknown\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestExecuteRejectsUnexpectedArgument(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	code := execute(context.Background(), []string{"serve"}, ioDiscard{}, &stderr)
	if code != exitUsage {
		t.Fatalf("execute() = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "unexpected argument") {
		t.Fatalf("stderr = %q, want unexpected argument error", stderr.String())
	}
}

func TestExecuteStopsCleanlyOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if code := execute(ctx, nil, ioDiscard{}, ioDiscard{}); code != exitOK {
		t.Fatalf("execute() = %d, want %d", code, exitOK)
	}
}

func TestExecuteReturnsErrorWhenVersionCannotBeWritten(t *testing.T) {
	t.Parallel()

	if code := execute(context.Background(), []string{"--version"}, errorWriter{}, ioDiscard{}); code != exitError {
		t.Fatalf("execute() = %d, want %d", code, exitError)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(value []byte) (int, error) {
	return len(value), nil
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
