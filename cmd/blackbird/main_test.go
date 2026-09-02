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

	"github.com/phall1/blackbird/internal/cli"
	"github.com/phall1/blackbird/internal/install"
	blackbirdruntime "github.com/phall1/blackbird/internal/runtime"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

func TestExecutePrintsVersion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), []string{"--version"}, &stdout, &stderr)
	if code != cli.ExitOK {
		t.Fatalf("execute() = %d, want %d; stderr=%q", code, cli.ExitOK, stderr.String())
	}
	if got, want := stdout.String(), "blackbird version=dev commit=unknown built_at=unknown\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestExecuteRejectsUnexpectedArgument(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	code := execute(context.Background(), []string{"serve"}, ioDiscard{}, &stderr)
	if code != cli.ExitUsage {
		t.Fatalf("execute() = %d, want %d", code, cli.ExitUsage)
	}
	if !strings.Contains(stderr.String(), "unexpected argument") {
		t.Fatalf("stderr = %q, want an unexpected-argument error", stderr.String())
	}
}

func TestExecuteStopsCleanlyOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if code := execute(ctx, nil, ioDiscard{}, ioDiscard{}); code != cli.ExitOK {
		t.Fatalf("execute() = %d, want %d", code, cli.ExitOK)
	}
}

func TestExecuteReturnsErrorWhenVersionCannotBeWritten(t *testing.T) {
	t.Parallel()

	if code := execute(context.Background(), []string{"--version"}, errorWriter{}, ioDiscard{}); code != cli.ExitError {
		t.Fatalf("execute() = %d, want %d", code, cli.ExitError)
	}
}

// TestExecuteInjectsNonSecretConfiguration keeps the pre-Kong seam working: the
// injected configuration supplies the daemon flag defaults, and an explicit flag
// still wins over the injected value.
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
	if code != cli.ExitOK {
		t.Fatalf("executeConfigured() = %d, want %d", code, cli.ExitOK)
	}
	if got.Storage != blackbirdruntime.StoragePostgreSQL || got.SQLitePath != "injected.db" ||
		got.HTTPAddress != "127.0.0.1:9100" || got.MCPAddress != "127.0.0.1:9001" {
		t.Fatalf("config = %#v", got)
	}
}

// TestLegacyPlistArgvReachesTheDaemon feeds the exact argv the installed launchd
// plist runs. Homebrew swaps the binary before anything rewrites that file, so
// rejecting this argv crash-loops every upgraded machine.
func TestLegacyPlistArgvReachesTheDaemon(t *testing.T) {
	t.Parallel()

	const databasePath = "/Users/phall/.local/share/blackbird/blackbird.db"
	var got blackbirdruntime.Config
	factory := func(_ blackbirdruntime.BuildInfo, config blackbirdruntime.Config) (daemonRunner, error) {
		got = config
		return cancelledRunner{}, nil
	}
	var stderr bytes.Buffer
	code := executeConfigured(context.Background(), []string{"--sqlite-path=" + databasePath},
		ioDiscard{}, &stderr, nil, factory)
	if code != cli.ExitOK {
		t.Fatalf("executeConfigured() = %d, want %d; stderr=%q", code, cli.ExitOK, stderr.String())
	}
	if got.SQLitePath != databasePath {
		t.Fatalf("SQLitePath = %q, want %q", got.SQLitePath, databasePath)
	}
	if !strings.Contains(stderr.String(), "deprecated") {
		t.Fatalf("stderr = %q, want a deprecation notice", stderr.String())
	}
}

// TestInstalledServiceArgvParses is the other half of the same contract: the
// argv the installer writes today must reach the daemon adapter unchanged.
func TestInstalledServiceArgvParses(t *testing.T) {
	t.Parallel()

	manager := install.NewManager(install.Config{
		GOOS: "darwin", HomeDir: t.TempDir(), Executable: "/opt/homebrew/bin/blackbird", UID: 501,
	})
	argv := manager.ServiceArgv()
	if len(argv) < 2 || argv[1] != "daemon" {
		t.Fatalf("ServiceArgv() = %v, want a daemon subcommand", argv)
	}

	var got blackbirdruntime.Config
	factory := func(_ blackbirdruntime.BuildInfo, config blackbirdruntime.Config) (daemonRunner, error) {
		got = config
		return cancelledRunner{}, nil
	}
	var stderr bytes.Buffer
	if code := executeConfigured(context.Background(), argv[1:], ioDiscard{}, &stderr, nil, factory); code != cli.ExitOK {
		t.Fatalf("executeConfigured(%v) = %d; stderr=%q", argv[1:], code, stderr.String())
	}
	if got.StateDir != manager.StateDir() {
		t.Fatalf("StateDir = %q, want %q", got.StateDir, manager.StateDir())
	}
	if want := filepath.Base(got.SQLitePath); want != "blackbird.db" {
		t.Fatalf("SQLitePath = %q", got.SQLitePath)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing for the current argv", stderr.String())
	}
}

func TestExecuteDoesNotAcceptSecretsOnCommandLine(t *testing.T) {
	t.Parallel()

	for _, argument := range []string{"--dsn=postgres://secret", "--postgres-password=secret", "--migration-dsn=postgres://secret"} {
		var stderr bytes.Buffer
		if code := execute(context.Background(), []string{argument}, ioDiscard{}, &stderr); code != cli.ExitUsage {
			t.Fatalf("execute(%q) = %d, want %d", argument, code, cli.ExitUsage)
		}
		if !strings.Contains(stderr.String(), "unknown flag") {
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
		{command: "install", want: "installed service=/service updater=/updater clients=opencode,codex\n"},
		{command: "update", want: "updated changed=true before=\"blackbird 1.0.0\" after=\"blackbird 1.1.0\"\n"},
		{command: "uninstall", want: "uninstalled service=/service updater=/updater data=retained\n"},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			manager := &fakeProductManager{}
			code := executeWithManager(context.Background(), []string{test.command}, &stdout, &stderr, nil, nil, manager)
			if code != cli.ExitOK || stdout.String() != test.want || stderr.Len() != 0 {
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
	code := executeWithManager(context.Background(), []string{"install", "extra"},
		ioDiscard{}, &stderr, nil, nil, &fakeProductManager{})
	if code != cli.ExitUsage {
		t.Fatalf("execute = %d, want %d; stderr=%q", code, cli.ExitUsage, stderr.String())
	}
}

func TestDaemonAdapterTranslatesOptions(t *testing.T) {
	t.Parallel()

	var got blackbirdruntime.Config
	adapter := daemonAdapter{
		build: blackbirdruntime.BuildInfo{Version: "0.4.0"},
		factory: func(_ blackbirdruntime.BuildInfo, config blackbirdruntime.Config) (daemonRunner, error) {
			got = config
			return cancelledRunner{}, nil
		},
	}
	options := cli.DaemonOptions{
		Storage: "sqlite", SQLitePath: "/data/blackbird.db", StateDir: "/state",
		HTTPAddress: "127.0.0.1:1", MCPAddress: "127.0.0.1:2", LogLevel: "debug",
		ShutdownTimeout: 7 * time.Second,
	}
	if err := adapter.Run(context.Background(), options); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	want := blackbirdruntime.Config{
		Storage: blackbirdruntime.StorageSQLite, SQLitePath: "/data/blackbird.db", StateDir: "/state",
		HTTPAddress: "127.0.0.1:1", MCPAddress: "127.0.0.1:2", LogLevel: "debug",
		ShutdownTimeout: 7 * time.Second,
	}
	if got != want {
		t.Fatalf("config = %#v, want %#v", got, want)
	}
}

func TestDaemonAdapterWrapsFactoryFailure(t *testing.T) {
	t.Parallel()

	adapter := daemonAdapter{factory: func(blackbirdruntime.BuildInfo, blackbirdruntime.Config) (daemonRunner, error) {
		return nil, errors.New("bad configuration")
	}}
	err := adapter.Run(context.Background(), cli.DaemonOptions{Storage: "sqlite"})
	if err == nil || !strings.Contains(err.Error(), "construct daemon") {
		t.Fatalf("Run() = %v", err)
	}
}

func TestDefaultDatabasePathIsAbsolute(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg")
	if got, want := defaultDatabasePath(), filepath.Join("/tmp/xdg", "blackbird", "blackbird.db"); got != want {
		t.Fatalf("defaultDatabasePath() = %q, want %q", got, want)
	}
	t.Setenv("XDG_DATA_HOME", "relative")
	if got := defaultDatabasePath(); got != "" && !filepath.IsAbs(got) {
		t.Fatalf("defaultDatabasePath() = %q, want an absolute path", got)
	}
}

func TestHandshakePathTracksTheStateDirectory(t *testing.T) {
	t.Parallel()

	if got := handshakePath(""); got != "" {
		t.Fatalf("handshakePath(\"\") = %q", got)
	}
	if got, want := handshakePath("/state"), install.HandshakePath("/state"); got != want {
		t.Fatalf("handshakePath = %q, want %q", got, want)
	}
	if got := stateDirectory(&fakeProductManager{}); got != "/state/blackbird" {
		t.Fatalf("stateDirectory = %q", got)
	}
}

func TestDeviceOfClassifiesStreams(t *testing.T) {
	t.Parallel()

	if deviceOf(&bytes.Buffer{}) != nil {
		t.Fatal("a buffer is not a device")
	}
	if deviceOf(os.Stdout) == nil {
		t.Fatal("os.Stdout is a device")
	}
}

// TestReaderAdapterInspectsWithoutWriting is the guard against an inspection
// command reopening the database through sqlite.Open, which creates
// directories, applies migrations, and claims the runtime row.
func TestReaderAdapterInspectsWithoutWriting(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := sqlite.Open(context.Background(), sqlite.Config{Path: path})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	facts, err := readerAdapter{}.Inspect(context.Background(), path, true)
	if err != nil {
		t.Fatalf("Inspect() = %v", err)
	}
	if !facts.Present || !facts.Supported {
		t.Fatalf("facts = %#v", facts)
	}
	if facts.SchemaVersion != sqlite.SchemaVersion || facts.ApplicationID != sqlite.ApplicationID {
		t.Fatalf("schema = %d/%d, want %d/%d", facts.SchemaVersion, facts.ApplicationID,
			sqlite.SchemaVersion, sqlite.ApplicationID)
	}
	if facts.QuickCheck != "ok" {
		t.Fatalf("quick check = %q", facts.QuickCheck)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("the reader modified the database file")
	}
}

// TestGCReclaimsSpaceInTheShippedBinary is the regression for --checkpoint and
// --vacuum being dead flags: the assembly point never wired a maintenance port,
// so the shipped binary answered "this binary cannot rewrite the database" and
// exited 4 no matter how large the write-ahead log had grown.
func TestGCReclaimsSpaceInTheShippedBinary(t *testing.T) {
	t.Parallel()

	path := blackbirdDatabase(t)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := executeWithManager(context.Background(),
		[]string{"gc", "--checkpoint", "--vacuum", "--json", "--db", path},
		&stdout, &stderr, nil, nil, &fakeProductManager{})
	if code != cli.ExitOK {
		t.Fatalf("gc = %d, want %d; stderr=%q", code, cli.ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"reclaimed"`) {
		t.Fatalf("stdout = %q, want a reclaimed report", stdout.String())
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() >= before.Size() {
		t.Fatalf("database is %d bytes, want less than %d", after.Size(), before.Size())
	}
	if wal, err := os.Stat(path + "-wal"); err == nil && wal.Size() != 0 {
		t.Fatalf("write-ahead log is %d bytes, want it truncated", wal.Size())
	}
}

func TestDependenciesWireAMaintenancePort(t *testing.T) {
	t.Parallel()

	if dependencies(nil, nil, &fakeProductManager{}, ioDiscard{}).Maintenance == nil {
		t.Fatal("no maintenance port: gc --checkpoint and --vacuum cannot work")
	}
}

func TestMaintenanceAdapterRefusesToWriteWhatIsNotADatabase(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	absent := filepath.Join(directory, "absent.db")
	if _, err := (maintenanceAdapter{}).Reclaim(context.Background(), absent,
		cli.ReclaimPlan{Checkpoint: true}); err == nil {
		t.Fatal("Reclaim() accepted a database that does not exist")
	}
	if _, err := os.Stat(absent); err == nil {
		t.Fatal("Reclaim() created the database it was asked to compact")
	}

	foreign := filepath.Join(directory, "foreign.db")
	if err := os.WriteFile(foreign, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (maintenanceAdapter{}).Reclaim(context.Background(), foreign, cli.ReclaimPlan{Vacuum: true})
	if err == nil {
		t.Fatal("Reclaim() rewrote a file that is not a Blackbird database")
	}
}

// blackbirdDatabase returns a real Blackbird database carrying free pages and an
// uncheckpointed write-ahead log, which is the state gc exists to clean up.
func blackbirdDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := sqlite.Open(context.Background(), sqlite.Config{Path: path})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	database, err := openForMaintenance(context.Background(), path)
	if err != nil {
		t.Fatalf("open for ballast: %v", err)
	}
	defer func() { _ = database.Close() }()
	if _, err := database.ExecContext(context.Background(),
		"CREATE TABLE ballast (id INTEGER PRIMARY KEY, payload TEXT)"); err != nil {
		t.Fatalf("create ballast: %v", err)
	}
	for range 40 {
		if _, err := database.ExecContext(context.Background(),
			"INSERT INTO ballast (payload) SELECT hex(randomblob(4096))"); err != nil {
			t.Fatalf("fill ballast: %v", err)
		}
	}
	if _, err := database.ExecContext(context.Background(), "DROP TABLE ballast"); err != nil {
		t.Fatalf("drop ballast: %v", err)
	}
	return path
}

func TestReaderAdapterReportsAMissingDatabase(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "absent.db")
	facts, err := readerAdapter{}.Inspect(context.Background(), path, false)
	if err != nil {
		t.Fatalf("Inspect() = %v", err)
	}
	if facts.Present {
		t.Fatalf("facts = %#v, want an absent database", facts)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("the reader created the database it was asked to inspect")
	}
}

func TestSourceBuiltDaemonStartsSQLiteAndServesW0Surfaces(t *testing.T) {
	stateDir := t.TempDir()
	databasePath := filepath.Join(t.TempDir(), "blackbird.db")
	httpAddress := availableAddress(t)
	mcpAddress := availableAddress(t)
	command := exec.Command(os.Args[0], "-test.run=TestBlackbirdProcess")
	command.Env = append(os.Environ(),
		"BLACKBIRD_PROCESS_HELPER=1",
		"BLACKBIRD_PROCESS_ARGS=daemon\n--sqlite-path="+databasePath+"\n--state-dir="+stateDir+
			"\n--http-address="+httpAddress+"\n--mcp-address="+mcpAddress,
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

	healthResponse := awaitRequest(t, processDone, &stderr, "http://"+httpAddress+"/healthz", func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, "http://"+httpAddress+"/healthz", nil)
	})
	defer func() { _ = healthResponse.Body.Close() }()
	if healthResponse.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want %d", healthResponse.StatusCode, http.StatusOK)
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
	return install.Result{ServicePath: "/service", UpdaterPaths: []string{"/updater"}, Clients: []string{"opencode", "codex"}}, nil
}

func (manager *fakeProductManager) Status(context.Context) (string, error) {
	manager.called = "status"
	return "daemon=running installed=true path=/service definition=current updater=scheduled " +
		"installed=true paths=/updater interval=6h0m0s", nil
}

func (manager *fakeProductManager) Update(context.Context) (install.UpdateResult, error) {
	manager.called = "update"
	return install.UpdateResult{Changed: true, Before: "blackbird 1.0.0", After: "blackbird 1.1.0"}, nil
}

func (manager *fakeProductManager) Uninstall(context.Context) (install.Result, error) {
	manager.called = "uninstall"
	return install.Result{ServicePath: "/service", UpdaterPaths: []string{"/updater"}}, nil
}

func (manager *fakeProductManager) ServiceArgv() []string {
	return []string{"/opt/homebrew/bin/blackbird", "daemon"}
}

func (manager *fakeProductManager) StateDir() string { return "/state/blackbird" }

// TestBackupAndRestoreRoundTripInTheShippedBinary is the wiring test for
// cli.SnapshotPort. The CLI reaches backup and restore by asserting that
// interface on the maintenance adapter, so an unwired binary does not fail to
// build — both commands simply report they cannot take a snapshot. Only a round
// trip through the real command grammar distinguishes a wired binary from that,
// which is why this test drives the commands rather than the adapter.
func TestBackupAndRestoreRoundTripInTheShippedBinary(t *testing.T) {
	t.Parallel()

	source := blackbirdDatabase(t)
	snapshot := filepath.Join(t.TempDir(), "snapshot.db")

	var stdout, stderr bytes.Buffer
	code := executeWithManager(context.Background(),
		[]string{"backup", "--out", snapshot, "--json", "--db", source},
		&stdout, &stderr, nil, nil, &fakeProductManager{})
	if code != cli.ExitOK {
		t.Fatalf("backup = %d, want %d; stderr=%q", code, cli.ExitOK, stderr.String())
	}

	// The manifest is the half that makes a snapshot restorable at all, so a
	// backup that published only the database file is a failed backup even
	// though the command succeeded.
	manifestPath := sqlite.BackupManifestPath(snapshot)
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("backup published no manifest sidecar: %v", err)
	}
	if !strings.Contains(stdout.String(), `"database_sha256"`) {
		t.Fatalf("stdout = %q, want the snapshot digest", stdout.String())
	}

	restored := filepath.Join(t.TempDir(), "restored.db")
	stdout.Reset()
	stderr.Reset()
	code = executeWithManager(context.Background(),
		[]string{"restore", "--from", snapshot, "--to", restored, "--json", "--db", source},
		&stdout, &stderr, nil, nil, &fakeProductManager{})
	if code != cli.ExitOK {
		t.Fatalf("restore = %d, want %d; stderr=%q", code, cli.ExitOK, stderr.String())
	}
	if _, err := os.Stat(sqlite.BackupManifestPath(restored)); err != nil {
		t.Fatalf("restore published no manifest beside the restored database: %v", err)
	}

	// A restored database that cannot itself be backed up would make recovery a
	// one-way door, so the round trip is only closed if the restored file is a
	// usable source in turn.
	second := filepath.Join(t.TempDir(), "second.db")
	if _, err := sqlite.BackupFile(context.Background(), restored, second); err != nil {
		t.Fatalf("the restored database is not itself backupable: %v", err)
	}
}
