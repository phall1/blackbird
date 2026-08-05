package runtime

import (
	"context"
	"errors"
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

func TestStartupFailureRollsBackInDependencyOrder(t *testing.T) {
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
	if got, want := events.values(), []string{"worker.start", "ingress.close", "worker.stop", "storage.close"}; !equalStrings(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
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

type testWorker struct{ events *eventLog }

func (worker *testWorker) Start(context.Context) error { worker.events.add("worker.start"); return nil }
func (worker *testWorker) Stop(context.Context) error  { worker.events.add("worker.stop"); return nil }

type testListener struct {
	once  sync.Once
	close func()
}

func (*testListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (*testListener) Addr() net.Addr            { return testAddress("test") }
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
