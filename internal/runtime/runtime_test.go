package runtime

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/storage/postgres"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

func TestNewNormalizesBuildInfo(t *testing.T) {
	t.Parallel()

	daemon := New(BuildInfo{})
	got := daemon.BuildInfo()
	want := (BuildInfo{Version: "dev", Commit: "unknown", BuiltAt: "unknown"})
	if got != want {
		t.Fatalf("BuildInfo() = %#v, want %#v", got, want)
	}
}

func TestRunStopsCleanlyWhenContextIsCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := New(BuildInfo{}).Run(ctx); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()
	valid := Config{Storage: StorageSQLite, SQLitePath: "blackbird.db", HTTPAddress: ":8080", MCPAddress: ":8081"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"backend":      func(config *Config) { config.Storage = "memory" },
		"path":         func(config *Config) { config.SQLitePath = "" },
		"http":         func(config *Config) { config.HTTPAddress = "" },
		"mcp":          func(config *Config) { config.MCPAddress = "" },
		"same address": func(config *Config) { config.MCPAddress = config.HTTPAddress },
		"timeout":      func(config *Config) { config.ShutdownTimeout = -time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

// A worker publishes process-wide state, so it must never start in a process
// that lost the address race: its rollback would tear down the state of the
// daemon that actually owns the port.
func TestListenerFailureRollsBackBeforeAnyWorkerStarts(t *testing.T) {
	t.Parallel()
	var events eventLog
	store := &testStore{close: func() { events.add("storage.close") }}
	worker := &testWorker{events: &events}
	listenCalls := atomic.Int32{}
	daemon := newTestDaemon(t, Dependencies{
		OpenSQLite: func(context.Context, sqliteConfig) (Storage, error) { return store, nil },
		Compose: func(context.Context, Storage) (HandlerBundle, error) {
			return HandlerBundle{HTTP: http.HandlerFunc(noopHandler), MCP: http.HandlerFunc(noopHandler), Workers: []Worker{worker}}, nil
		},
		Listen: func(string, string) (net.Listener, error) {
			if listenCalls.Add(1) == 2 {
				return nil, errors.New("bind failed")
			}
			return &testListener{close: func() { events.add("ingress.close") }}, nil
		},
	})
	if err := daemon.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil")
	}
	if got, want := events.values(), []string{"ingress.close", "storage.close"}; !equalStrings(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// A worker that publishes a discovery record is composed from configuration,
// which may ask for port 0. Only the listener knows the reachable address, and
// the worker must hold it before it publishes anything.
func TestWorkersReceiveTheBoundAddressBeforeTheyStart(t *testing.T) {
	t.Parallel()
	for name, testCase := range map[string]struct {
		bound string
		want  string
	}{
		"ephemeral port": {bound: "127.0.0.1:59181", want: "127.0.0.1:59181"},
		"fixed port":     {bound: "127.0.0.1:8080", want: "127.0.0.1:8080"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var events eventLog
			worker := &testAddressWorker{testWorker: testWorker{events: &events}}
			var listenCalls atomic.Int32
			daemon := newTestDaemon(t, Dependencies{
				OpenSQLite: func(context.Context, sqliteConfig) (Storage, error) { return &testStore{}, nil },
				Compose: func(context.Context, Storage) (HandlerBundle, error) {
					return HandlerBundle{
						HTTP: http.HandlerFunc(noopHandler), MCP: http.HandlerFunc(noopHandler),
						Workers: []Worker{worker},
					}, nil
				},
				Listen: func(string, string) (net.Listener, error) {
					if listenCalls.Add(1) == 1 {
						return &testListener{address: testCase.bound}, nil
					}
					return &testListener{address: "127.0.0.1:59182"}, nil
				},
				NewServer: func(string, http.Handler) IngressServer {
					return &testServer{serveErr: errors.New("stop")}
				},
			})
			if err := daemon.Run(context.Background()); err == nil {
				t.Fatal("Run() error = nil")
			}
			if got := worker.addressAtStart(); got != testCase.want {
				t.Fatalf("address at Start() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestWorkerFailureRollsBackInDependencyOrder(t *testing.T) {
	t.Parallel()
	var events eventLog
	store := &testStore{close: func() { events.add("storage.close") }}
	failure := errors.New("worker refused to start")
	worker := &testWorker{events: &events, startErr: failure}
	daemon := newTestDaemon(t, Dependencies{
		OpenSQLite: func(context.Context, sqliteConfig) (Storage, error) { return store, nil },
		Compose: func(context.Context, Storage) (HandlerBundle, error) {
			return HandlerBundle{HTTP: http.HandlerFunc(noopHandler), MCP: http.HandlerFunc(noopHandler), Workers: []Worker{worker}}, nil
		},
		Listen: func(string, string) (net.Listener, error) {
			return &testListener{close: func() { events.add("ingress.close") }}, nil
		},
	})
	if err := daemon.Run(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("Run() error = %v, want %v", err, failure)
	}
	if got, want := events.values(), []string{"worker.start", "ingress.close", "ingress.close", "worker.stop", "storage.close"}; !equalStrings(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestConfigRejectsAnUnparsableLogLevel(t *testing.T) {
	t.Parallel()
	config := Config{Storage: StorageSQLite, SQLitePath: "blackbird.db", HTTPAddress: ":8080", MCPAddress: ":8081", LogLevel: "chatty"}
	if err := config.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
	config.LogLevel = "debug"
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if _, err := NewLogger(config, io.Discard); err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
}

func TestLogLevelFallsBackToTheEnvironmentThenInfo(t *testing.T) {
	t.Setenv(logLevelVariable, "debug")
	level, err := Config{}.logLevel()
	if err != nil || level != slog.LevelDebug {
		t.Fatalf("logLevel() = %v, %v", level, err)
	}
	t.Setenv(logLevelVariable, "not-a-level")
	level, err = Config{}.logLevel()
	if err != nil || level != slog.LevelInfo {
		t.Fatalf("logLevel() = %v, %v", level, err)
	}
}

func TestCancellationDrainsIngressBeforeWorkersAndStorage(t *testing.T) {
	t.Parallel()
	var events eventLog
	ready := make(chan struct{})
	servers := []*testServer{{name: "http", events: &events}, {name: "mcp", events: &events}}
	var serverIndex atomic.Int32
	daemon := newTestDaemon(t, Dependencies{
		OpenSQLite: func(context.Context, sqliteConfig) (Storage, error) {
			return &testStore{close: func() { events.add("storage.close") }}, nil
		},
		Compose: func(context.Context, Storage) (HandlerBundle, error) {
			return HandlerBundle{HTTP: http.HandlerFunc(noopHandler), MCP: http.HandlerFunc(noopHandler), Workers: []Worker{&testWorker{events: &events}}}, nil
		},
		Listen:    func(string, string) (net.Listener, error) { return &testListener{}, nil },
		NewServer: func(string, http.Handler) IngressServer { return servers[int(serverIndex.Add(1))-1] },
		Ready:     func() { close(ready) },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("daemon did not become ready")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := daemon.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown() error = %v", err)
	}
	got := events.values()
	want := []string{"worker.start", "http.shutdown", "mcp.shutdown", "worker.stop", "storage.close"}
	if !equalStrings(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestListenerErrorFailsClosedDuringCancellation(t *testing.T) {
	t.Parallel()
	ready := make(chan struct{})
	serveFailure := errors.New("accept failed")
	servers := []*testServer{{serveErr: serveFailure}, {}}
	var serverIndex atomic.Int32
	daemon := newTestDaemon(t, Dependencies{
		OpenSQLite: func(context.Context, sqliteConfig) (Storage, error) { return &testStore{}, nil },
		Compose: func(context.Context, Storage) (HandlerBundle, error) {
			return HandlerBundle{HTTP: http.HandlerFunc(noopHandler), MCP: http.HandlerFunc(noopHandler)}, nil
		},
		Listen:    func(string, string) (net.Listener, error) { return &testListener{}, nil },
		NewServer: func(string, http.Handler) IngressServer { return servers[int(serverIndex.Add(1))-1] },
		Ready:     func() { close(ready) },
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A pre-cancelled run is a clean no-op and cannot report readiness.
	if err := daemon.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	select {
	case <-ready:
		t.Fatal("ready called for cancelled startup")
	default:
	}

	daemon = newTestDaemon(t, Dependencies{
		OpenSQLite: func(context.Context, sqliteConfig) (Storage, error) { return &testStore{}, nil },
		Compose: func(context.Context, Storage) (HandlerBundle, error) {
			return HandlerBundle{HTTP: http.HandlerFunc(noopHandler), MCP: http.HandlerFunc(noopHandler)}, nil
		},
		Listen:    func(string, string) (net.Listener, error) { return &testListener{}, nil },
		NewServer: func(string, http.Handler) IngressServer { return servers[int(serverIndex.Add(1))-1] },
	})
	if err := daemon.Run(context.Background()); !errors.Is(err, serveFailure) {
		t.Fatalf("Run() error = %v, want %v", err, serveFailure)
	}
}

func TestPostgreSQLUsesSecretSource(t *testing.T) {
	t.Parallel()
	secret := PostgreSQLSecrets{DSN: "postgres://secret", MigrationDSN: "postgres://migration-secret"}
	daemon, err := NewDaemon(BuildInfo{}, Config{
		Storage: StoragePostgreSQL, HTTPAddress: ":1", MCPAddress: ":2",
	}, Dependencies{
		Secrets: testSecrets{value: secret},
		Logger:  slog.New(slog.DiscardHandler),
		Compose: func(context.Context, Storage) (HandlerBundle, error) { return HandlerBundle{}, errors.New("stop") },
		OpenPostgreSQL: func(_ context.Context, config postgresConfig) (Storage, error) {
			if config.DSN != secret.DSN || config.MigrationDSN != secret.MigrationDSN {
				t.Fatalf("PostgreSQL config = %#v", config)
			}
			return &testStore{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	if err := daemon.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil")
	}
}

// Aliases keep lifecycle tests focused on runtime contracts while still
// verifying the concrete production factory signatures.
type sqliteConfig = sqlite.Config
type postgresConfig = postgres.Config

func newTestDaemon(t *testing.T, dependencies Dependencies) *Daemon {
	t.Helper()
	if dependencies.Logger == nil {
		dependencies.Logger = slog.New(slog.DiscardHandler)
	}
	daemon, err := NewDaemon(BuildInfo{}, Config{
		Storage: StorageSQLite, SQLitePath: "unused.db", HTTPAddress: ":1", MCPAddress: ":2", ShutdownTimeout: time.Second,
	}, dependencies)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	return daemon
}

func noopHandler(http.ResponseWriter, *http.Request) {}

type testStore struct {
	once  sync.Once
	close func()
}

func (store *testStore) Close() error {
	store.once.Do(func() {
		if store.close != nil {
			store.close()
		}
	})
	return nil
}

type testWorker struct {
	events   *eventLog
	startErr error
}

func (worker *testWorker) Start(context.Context) error {
	worker.events.add("worker.start")
	return worker.startErr
}

func (worker *testWorker) Stop(context.Context) error { worker.events.add("worker.stop"); return nil }

type testAddressWorker struct {
	testWorker
	mu       sync.Mutex
	address  string
	observed string
}

func (worker *testAddressWorker) SetBoundHTTPAddress(address string) {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	worker.address = address
}

func (worker *testAddressWorker) Start(ctx context.Context) error {
	worker.mu.Lock()
	worker.observed = worker.address
	worker.mu.Unlock()
	return worker.testWorker.Start(ctx)
}

func (worker *testAddressWorker) addressAtStart() string {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.observed
}

type testListener struct {
	once    sync.Once
	address string
	close   func()
}

func (*testListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (listener *testListener) Addr() net.Addr {
	if listener.address == "" {
		return testAddress("test")
	}
	return testAddress(listener.address)
}
func (listener *testListener) Close() error {
	listener.once.Do(func() {
		if listener.close != nil {
			listener.close()
		}
	})
	return nil
}

type testAddress string

func (address testAddress) Network() string { return string(address) }
func (address testAddress) String() string  { return string(address) }

type testServer struct {
	name     string
	events   *eventLog
	serveErr error
	stopped  chan struct{}
	once     sync.Once
	mu       sync.Mutex
}

func (server *testServer) Serve(net.Listener) error {
	if server.serveErr != nil {
		return server.serveErr
	}
	<-server.stopChannel()
	return http.ErrServerClosed
}

func (server *testServer) Shutdown(context.Context) error {
	if server.events != nil {
		server.events.add(server.name + ".shutdown")
	}
	server.once.Do(func() {
		close(server.stopChannel())
	})
	return nil
}

func (server *testServer) stopChannel() chan struct{} {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.stopped == nil {
		server.stopped = make(chan struct{})
	}
	return server.stopped
}

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (log *eventLog) add(event string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.events = append(log.events, event)
}

func (log *eventLog) values() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.events...)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type testSecrets struct{ value PostgreSQLSecrets }

func (source testSecrets) PostgreSQL(context.Context) (PostgreSQLSecrets, error) {
	return source.value, nil
}
