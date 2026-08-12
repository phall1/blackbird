package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/install"
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

func TestExecuteDispatchesProductCommands(t *testing.T) {
	t.Parallel()
	tests := []struct {
		command string
		want    string
	}{
		{command: "install", want: "installed service=/service claude=/companion pi=/pi updater=/updater clients=opencode,codex\n"},
		{command: "status", want: "daemon=running installed=true path=/service claude=running installed=true path=/companion pi=running installed=true path=/pi updater=scheduled installed=true paths=/updater interval=6h0m0s\n"},
		{command: "update", want: "updated changed=true before=\"blackbird 1.0.0\" after=\"blackbird 1.1.0\"\n"},
		{command: "uninstall", want: "uninstalled service=/service claude=/companion pi=/pi updater=/updater data=retained\n"},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			manager := &fakeProductManager{}
			code := executeWithManager(context.Background(), []string{test.command}, &stdout, &stderr, nil, nil, manager)
			if code != exitOK || stdout.String() != test.want || stderr.Len() != 0 {
				t.Fatalf("execute = %d, stdout=%q, stderr=%q", code, stdout.String(), stderr.String())
			}
			if manager.called != test.command {
				t.Fatalf("called = %q, want %q", manager.called, test.command)
			}
		})
	}
}

func TestExecuteRejectsProductCommandArguments(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	code := executeWithManager(context.Background(), []string{"install", "extra"}, ioDiscard{}, &stderr, nil, nil, &fakeProductManager{})
	if code != exitUsage || !strings.Contains(stderr.String(), "does not accept arguments") {
		t.Fatalf("execute = %d, stderr=%q", code, stderr.String())
	}
}

func TestSourceBuiltDaemonStartsSQLiteAndServesW0Surfaces(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "blackbird.db")
	httpAddress := availableAddress(t)
	mcpAddress := availableAddress(t)
	command := exec.Command(os.Args[0], "-test.run=TestBlackbirdProcess")
	command.Env = append(os.Environ(),
		"BLACKBIRD_PROCESS_HELPER=1",
		"BLACKBIRD_PROCESS_ARGS=--sqlite-path="+databasePath+"\n--http-address="+httpAddress+"\n--mcp-address="+mcpAddress,
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start blackbird process: %v", err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped && command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
			<-processDone
		}
	})

	httpResponse := awaitRequest(t, processDone, &stderr, "http://"+httpAddress+"/api/v1/commands/workspace.create", func() (*http.Request, error) {
		request, err := http.NewRequest(http.MethodPost, "http://"+httpAddress+"/api/v1/commands/workspace.create", strings.NewReader("{}"))
		if err == nil {
			request.Header.Set("Content-Type", "application/json")
		}
		return request, err
	})
	defer func() { _ = httpResponse.Body.Close() }()
	if httpResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("W0 HTTP status = %d, want %d", httpResponse.StatusCode, http.StatusUnauthorized)
	}

	mcpResponse := awaitRequest(t, processDone, &stderr, "http://"+mcpAddress, func() (*http.Request, error) {
		request, err := http.NewRequest(http.MethodPost, "http://"+mcpAddress,
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}`))
		if err == nil {
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
		}
		return request, err
	})
	defer func() { _ = mcpResponse.Body.Close() }()
	if mcpResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(mcpResponse.Body)
		t.Fatalf("MCP initialize status = %d, want %d; body=%s", mcpResponse.StatusCode, http.StatusOK, body)
	}

	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("interrupt blackbird process: %v", err)
	}
	if err := <-processDone; err != nil {
		t.Fatalf("blackbird process exit: %v; stderr=%s", err, stderr.String())
	}
	stopped = true
	if info, err := os.Stat(databasePath); err != nil || info.Size() == 0 {
		t.Fatalf("SQLite database was not created: info=%v err=%v", info, err)
	}
}

func TestBlackbirdProcess(t *testing.T) {
	if os.Getenv("BLACKBIRD_PROCESS_HELPER") != "1" {
		return
	}
	os.Exit(runMain(strings.Split(os.Getenv("BLACKBIRD_PROCESS_ARGS"), "\n"), os.Stdout, os.Stderr))
}

func availableAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func awaitRequest(
	t *testing.T,
	processDone chan error,
	stderr *bytes.Buffer,
	endpoint string,
	request func() (*http.Request, error),
) *http.Response {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case err := <-processDone:
			processDone <- err
			t.Fatalf("blackbird exited before %s became ready: %v; stderr=%s", endpoint, err, stderr.String())
		default:
		}
		value, err := request()
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(value)
		if err == nil {
			return response
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s did not become ready: %v", endpoint, lastErr)
	return nil
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

type fakeProductManager struct {
	called string
}

func (manager *fakeProductManager) Install(context.Context) (install.Result, error) {
	manager.called = "install"
	return install.Result{ServicePath: "/service", CompanionPath: "/companion", PiCompanionPath: "/pi", UpdaterPaths: []string{"/updater"}, Clients: []string{"opencode", "codex"}}, nil
}

func (manager *fakeProductManager) Status(context.Context) (string, error) {
	manager.called = "status"
	return "daemon=running installed=true path=/service claude=running installed=true path=/companion pi=running installed=true path=/pi updater=scheduled installed=true paths=/updater interval=6h0m0s", nil
}

func (manager *fakeProductManager) Update(context.Context) (install.UpdateResult, error) {
	manager.called = "update"
	return install.UpdateResult{Changed: true, Before: "blackbird 1.0.0", After: "blackbird 1.1.0"}, nil
}

func (manager *fakeProductManager) Uninstall(context.Context) (install.Result, error) {
	manager.called = "uninstall"
	return install.Result{ServicePath: "/service", CompanionPath: "/companion", PiCompanionPath: "/pi", UpdaterPaths: []string{"/updater"}}, nil
}
