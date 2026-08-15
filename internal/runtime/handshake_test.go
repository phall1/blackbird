package runtime

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/install"
)

func TestAdminHandshakeIsOwnerOnlyInsideAnOwnerOnlyDirectory(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, time.August, 15, 9, 41, 2, 113000000, time.UTC)
	worker := newHandshakeTestWorker(t, directory, "bba_first", "127.0.0.1:8080", started)
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode=%v", directoryInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(install.HandshakePath(directory))
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("handshake mode=%v", fileInfo.Mode().Perm())
	}

	record := readHandshakeTestFile(t, install.HandshakePath(directory))
	if record.Schema != handshakeSchema || record.HTTPAddress != "127.0.0.1:8080" || record.Token != "bba_first" ||
		record.PID != os.Getpid() || record.Version != "0.4.0" ||
		record.StartedAt != started.Format(time.RFC3339Nano) {
		t.Fatalf("record=%+v", record)
	}
}

// Binding the HTTP listener is the mutual exclusion and it already happened, so
// a record left behind by any predecessor is stale by construction. Every case
// here wedged the daemon permanently under launchd KeepAlive in some earlier
// revision that tried to arbitrate ownership from the record itself.
func TestAdminHandshakeReplacesAnyRecordLeftBehind(t *testing.T) {
	t.Parallel()
	blackbirdShaped := startBlackbirdHealthServer(t)
	foreign := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("<html>not blackbird</html>"))
	}))
	t.Cleanup(foreign.Close)

	cases := []struct {
		name    string
		pid     int
		address string
	}{
		{name: "pid is dead and the address is closed", pid: deadProcessID(t), address: closedLoopbackAddress(t)},
		{name: "pid recycled onto a root owned process the daemon cannot signal", pid: 1, address: closedLoopbackAddress(t)},
		{name: "pid recycled onto an unrelated live process", pid: os.Getppid(), address: closedLoopbackAddress(t)},
		{name: "an unrelated service now answers on the recorded address", pid: 1, address: strings.TrimPrefix(foreign.URL, "http://")},
		{name: "a blackbird shaped responder answers on the recorded address", pid: 1, address: blackbirdShaped},
		{name: "the record names this daemon's own address", pid: 1, address: "127.0.0.1:8080"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			path := install.HandshakePath(directory)
			writeHandshakeTestFile(t, path, adminHandshake{Schema: handshakeSchema,
				HTTPAddress: testCase.address, Token: "bba_crashed", PID: testCase.pid,
				StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Version: "0.3.0"})

			worker := newHandshakeTestWorker(t, directory, "bba_fresh", "127.0.0.1:8080", time.Now())
			if err := worker.Start(t.Context()); err != nil {
				t.Fatalf("start over a stale record: %v", err)
			}
			if record := readHandshakeTestFile(t, path); record.Token != "bba_fresh" || record.PID != os.Getpid() {
				t.Fatalf("record=%+v", record)
			}
		})
	}
}

// Workers start after the listeners bind, so failing here would take an ingress
// that is already answering and wedge it forever under launchd KeepAlive. A
// state directory left root-owned by a past sudo run, or a full disk, must cost
// discovery only.
func TestAdminHandshakeStartsWithoutADiscoveryRecordItCannotWrite(t *testing.T) {
	t.Parallel()
	blocked := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(blocked, []byte("this is a file"), 0o600); err != nil {
		t.Fatal(err)
	}

	worker := newHandshakeTestWorker(t, filepath.Join(blocked, "state"), "bba_fresh", "127.0.0.1:8080", time.Now())
	if err := worker.Start(t.Context()); err != nil {
		t.Fatalf("start must not fail over an unwritable state directory: %v", err)
	}
	if err := worker.Stop(t.Context()); err != nil {
		t.Fatalf("stop must tolerate a record that was never written: %v", err)
	}
}

func TestAdminHandshakeReplacesAnUnreadableRecord(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := install.HandshakePath(directory)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	worker := newHandshakeTestWorker(t, directory, "bba_fresh", "127.0.0.1:8080", time.Now())
	if err := worker.Start(t.Context()); err != nil {
		t.Fatalf("start over an unreadable record: %v", err)
	}
	if record := readHandshakeTestFile(t, path); record.Token != "bba_fresh" {
		t.Fatalf("record=%+v", record)
	}
}

// A second daemon started for development writes its own record, but on the way
// out it must not unlink one it does not own.
func TestAdminHandshakeStopLeavesAnotherDaemonsRecordInPlace(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := install.HandshakePath(directory)
	worker := newHandshakeTestWorker(t, directory, "bba_ours", "127.0.0.1:8080", time.Now())
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	other := adminHandshake{Schema: handshakeSchema, HTTPAddress: "127.0.0.1:9999", Token: "bba_other",
		PID: os.Getpid(), StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Version: "0.4.0"}
	writeHandshakeTestFile(t, path, other)

	if err := worker.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if record := readHandshakeTestFile(t, path); record != other {
		t.Fatalf("another daemon's record was disturbed: %+v", record)
	}
}

func TestAdminHandshakeStopRemovesOnlyItsOwnRecordAndIsIdempotent(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := install.HandshakePath(directory)
	worker := newHandshakeTestWorker(t, directory, "bba_owned", "127.0.0.1:8080", time.Now())
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		if err := worker.Stop(t.Context()); err != nil {
			t.Fatalf("stop %d: %v", attempt, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stop %d left the record: %v", attempt, err)
		}
	}
}

func TestNewAdminTokenIsUniqueAndDisjointFromAgentTokens(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 64)
	for range 64 {
		token, err := newAdminToken()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(token, adminTokenPrefix) || len(token) != len(adminTokenPrefix)+2*adminTokenBytes {
			t.Fatalf("token=%q", token)
		}
		if _, duplicate := seen[token]; duplicate {
			t.Fatalf("token repeated across starts: %q", token)
		}
		seen[token] = struct{}{}
	}
}

func TestNewAdminHandshakeWorkerResolvesAnExplicitStateDirectory(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	worker, err := newAdminHandshakeWorker(directory, "bba_token", "127.0.0.1:8080", "0.4.0", time.Now(),
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if worker.path != install.HandshakePath(directory) {
		t.Fatalf("path=%q", worker.path)
	}
}

func startBlackbirdHealthServer(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok","version":"0.4.0"}`))
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

func closedLoopbackAddress(t *testing.T) string {
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

// deadProcessID reaps a child so its pid is known not to be running, the state
// a crashed daemon's record is in before the operating system recycles the pid.
func deadProcessID(t *testing.T) int {
	t.Helper()
	command := exec.CommandContext(t.Context(), "/bin/sh", "-c", "exit 0")
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	return command.ProcessState.Pid()
}

func newHandshakeTestWorker(t *testing.T, directory, token, address string, started time.Time) *adminHandshakeWorker {
	t.Helper()
	worker, err := newAdminHandshakeWorker(directory, token, address, "0.4.0", started, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func writeHandshakeTestFile(t *testing.T, path string, record adminHandshake) {
	t.Helper()
	content, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readHandshakeTestFile(t *testing.T, path string) adminHandshake {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record adminHandshake
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	return record
}
