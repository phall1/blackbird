package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	blackbirdruntime "github.com/phall1/blackbird/internal/runtime"
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

func TestExecuteInjectsNonSecretConfiguration(t *testing.T) {
	t.Parallel()
	injected := blackbirdruntime.Config{
		Storage: blackbirdruntime.StorageSQLite, SQLitePath: "injected.db",
		HTTPAddress: "127.0.0.1:9000", MCPAddress: "127.0.0.1:9001",
	}
	var got blackbirdruntime.Config
	factory := func(_ blackbirdruntime.BuildInfo, config blackbirdruntime.Config) (daemonRunner, error) {
		got = config
		return cancelledRunner{}, nil
	}
	code := executeConfigured(context.Background(), []string{
		"--storage=postgres", "--http-address=127.0.0.1:9100",
	}, ioDiscard{}, ioDiscard{}, &injected, factory)
	if code != exitOK {
		t.Fatalf("executeConfigured() = %d, want %d", code, exitOK)
	}
	if got.Storage != blackbirdruntime.StoragePostgreSQL || got.SQLitePath != "injected.db" || got.HTTPAddress != "127.0.0.1:9100" {
		t.Fatalf("config = %#v", got)
	}
}

func TestExecuteDoesNotAcceptSecretsOnCommandLine(t *testing.T) {
	t.Parallel()
	for _, argument := range []string{"--dsn=postgres://secret", "--postgres-password=secret", "--migration-dsn=postgres://secret"} {
		var stderr bytes.Buffer
		if code := execute(context.Background(), []string{argument}, ioDiscard{}, &stderr); code != exitUsage {
			t.Fatalf("execute(%q) = %d, want %d", argument, code, exitUsage)
		}
		if !strings.Contains(stderr.String(), "flag provided but not defined") {
			t.Fatalf("stderr for %q = %q", argument, stderr.String())
		}
	}
}

func TestExecuteFailsClosedWithoutHandlerComposition(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := execute(context.Background(), nil, ioDiscard{}, &stderr); code != exitError {
		t.Fatalf("execute() = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), "complete handler composer") {
		t.Fatalf("stderr = %q", stderr.String())
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

type cancelledRunner struct{}

func (cancelledRunner) Run(context.Context) error { return nil }
