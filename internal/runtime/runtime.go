// Package runtime owns process-level composition and lifecycle.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/phall1/blackbird/internal/storage/postgres"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

const (
	developmentVersion = "dev"
	unknownBuildValue  = "unknown"
	defaultStopTimeout = 30 * time.Second
)

// StorageBackend identifies the durable storage implementation selected at startup.
type StorageBackend string

const (
	StorageSQLite     StorageBackend = "sqlite"
	StoragePostgreSQL StorageBackend = "postgres"
)

// Config contains non-secret process configuration. PostgreSQL credentials are
// deliberately obtained through SecretSource and can never be supplied here.
type Config struct {
	Storage         StorageBackend
	SQLitePath      string
	HTTPAddress     string
	MCPAddress      string
	ShutdownTimeout time.Duration
}

// Validate rejects configurations that cannot safely start a complete daemon.
func (config Config) Validate() error {
	if config.Storage != StorageSQLite && config.Storage != StoragePostgreSQL {
		return fmt.Errorf("storage must be %q or %q", StorageSQLite, StoragePostgreSQL)
	}
	if config.Storage == StorageSQLite && config.SQLitePath == "" {
		return errors.New("SQLite path is required")
	}
	if config.HTTPAddress == "" || config.MCPAddress == "" {
		return errors.New("HTTP and MCP addresses are required")
	}
	if err := validateTCPAddress(config.HTTPAddress); err != nil {
		return fmt.Errorf("HTTP address: %w", err)
	}
	if err := validateTCPAddress(config.MCPAddress); err != nil {
		return fmt.Errorf("MCP address: %w", err)
	}
	if config.HTTPAddress == config.MCPAddress {
		return errors.New("HTTP and MCP addresses must be distinct")
	}
	if config.ShutdownTimeout < 0 {
		return errors.New("shutdown timeout cannot be negative")
	}
	return nil
}

func validateTCPAddress(address string) error {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	_, err = strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return fmt.Errorf("port must be a number from 0 through 65535: %w", err)
	}
	return nil
}

func (config Config) normalized() Config {
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = defaultStopTimeout
	}
	return config
}

// PostgreSQLSecrets is the credential-bearing portion of PostgreSQL startup
// configuration. Implementations should load it from a protected secret source.
type PostgreSQLSecrets struct {
	DSN          string
	MigrationDSN string
}

// SecretSource supplies credentials without exposing them through argv or Config.
type SecretSource interface {
	PostgreSQL(context.Context) (PostgreSQLSecrets, error)
}

// Storage is the narrow process-lifetime contract shared by both durable stores.
type Storage interface {
	Close() error
}

// Worker is started only after complete handler composition and stopped only
// after ingress has drained.
type Worker interface {
	Start(context.Context) error
	Stop(context.Context) error
}

// HandlerBundle is the complete ingress and background-work composition. Both
// handlers are mandatory; runtime never substitutes placeholder handlers.
type HandlerBundle struct {
	HTTP    http.Handler
	MCP     http.Handler
	Workers []Worker
}

// Composer constructs the complete application-facing process graph around an
// opened durable store.
type Composer func(context.Context, Storage) (HandlerBundle, error)

// IngressServer is the narrow lifecycle used by HTTP and MCP servers.
type IngressServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

// Dependencies contains lifecycle seams. Zero-valued storage and network
// factories use their production implementations; Composer is always required.
type Dependencies struct {
	Secrets        SecretSource
	Compose        Composer
	OpenSQLite     func(context.Context, sqlite.Config) (Storage, error)
	OpenPostgreSQL func(context.Context, postgres.Config) (Storage, error)
	Listen         func(string, string) (net.Listener, error)
	NewServer      func(string, http.Handler) IngressServer
	Ready          func()
}

// BuildInfo identifies the executable without implying product capabilities.
type BuildInfo struct {
	Version string
	Commit  string
	BuiltAt string
}

// Normalize replaces omitted build fields with stable development values.
func (info BuildInfo) Normalize() BuildInfo {
	if info.Version == "" {
		info.Version = developmentVersion
	}
	if info.Commit == "" {
		info.Commit = unknownBuildValue
	}
	if info.BuiltAt == "" {
		info.BuiltAt = unknownBuildValue
	}

	return info
}

// Daemon is the process-lifetime shell. Product components are composed here
// as their implementation slices land.
type Daemon struct {
	build        BuildInfo
	config       Config
	dependencies Dependencies

	runMu   sync.Mutex
	running bool

	shutdownOnce sync.Once
	shutdownErr  error
	resourcesMu  sync.Mutex
	servers      []IngressServer
	listeners    []net.Listener
	workers      []Worker
	store        Storage
}

// New returns an identity-only daemon retained for build-info callers. Run
// fails closed because no production composition has been supplied.
func New(build BuildInfo) *Daemon {
	return &Daemon{build: build.Normalize()}
}

// NewDaemon validates process configuration and installs production defaults
// for durable storage, listeners, and net/http servers.
func NewDaemon(build BuildInfo, config Config, dependencies Dependencies) (*Daemon, error) {
	config = config.normalized()
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("runtime configuration: %w", err)
	}
	if dependencies.Compose == nil {
		return nil, errors.New("runtime requires a complete handler composer")
	}
	if config.Storage == StoragePostgreSQL && isNil(dependencies.Secrets) {
		return nil, errors.New("PostgreSQL storage requires a secret source")
	}
	if dependencies.OpenSQLite == nil {
		dependencies.OpenSQLite = func(ctx context.Context, config sqlite.Config) (Storage, error) {
			return sqlite.Open(ctx, config)
		}
	}
	if dependencies.OpenPostgreSQL == nil {
		dependencies.OpenPostgreSQL = func(ctx context.Context, config postgres.Config) (Storage, error) {
			return postgres.Open(ctx, config)
		}
	}
	if dependencies.Listen == nil {
		dependencies.Listen = net.Listen
	}
	if dependencies.NewServer == nil {
		dependencies.NewServer = func(address string, handler http.Handler) IngressServer {
			return &http.Server{
				Addr:              address,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       2 * time.Minute,
			}
		}
	}
	return &Daemon{build: build.Normalize(), config: config, dependencies: dependencies}, nil
}

// BuildInfo returns the daemon's normalized build identity.
func (daemon *Daemon) BuildInfo() BuildInfo {
	return daemon.build
}

// Run starts transactionally, blocks until cancellation or an ingress failure,
// and shuts down in dependency order.
func (daemon *Daemon) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return nil
	}
	daemon.runMu.Lock()
	if daemon.running {
		daemon.runMu.Unlock()
		return errors.New("daemon is already running or has run")
	}
	daemon.running = true
	daemon.runMu.Unlock()
	if daemon.dependencies.Compose == nil {
		return errors.New("daemon has no production composition; use NewDaemon")
	}

	store, err := daemon.openStorage(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("open storage: %w", err)
	}
	if isNil(store) {
		return errors.New("storage factory returned nil")
	}
	daemon.resourcesMu.Lock()
	daemon.store = store
	daemon.resourcesMu.Unlock()
	if ctx.Err() != nil {
		return daemon.Shutdown(context.Background())
	}

	bundle, err := daemon.dependencies.Compose(ctx, store)
	if err != nil {
		shutdownErr := daemon.Shutdown(context.Background())
		if errors.Is(err, context.Canceled) {
			return shutdownErr
		}
		return errors.Join(fmt.Errorf("compose handlers: %w", err), shutdownErr)
	}
	if isNil(bundle.HTTP) || isNil(bundle.MCP) {
		return errors.Join(errors.New("composition must supply complete HTTP and MCP handlers"), daemon.Shutdown(context.Background()))
	}
	if ctx.Err() != nil {
		return daemon.Shutdown(context.Background())
	}
	for index, worker := range bundle.Workers {
		if isNil(worker) {
			return errors.Join(fmt.Errorf("worker %d is nil", index), daemon.Shutdown(context.Background()))
		}
		daemon.resourcesMu.Lock()
		daemon.workers = append(daemon.workers, worker)
		daemon.resourcesMu.Unlock()
		if err := worker.Start(ctx); err != nil {
			shutdownErr := daemon.Shutdown(context.Background())
			if errors.Is(err, context.Canceled) {
				return shutdownErr
			}
			return errors.Join(fmt.Errorf("start worker %d: %w", index, err), shutdownErr)
		}
		if ctx.Err() != nil {
			return daemon.Shutdown(context.Background())
		}
	}

	httpListener, err := daemon.dependencies.Listen("tcp", daemon.config.HTTPAddress)
	if err != nil {
		return errors.Join(fmt.Errorf("listen HTTP: %w", err), daemon.Shutdown(context.Background()))
	}
	if isNil(httpListener) {
		return errors.Join(errors.New("HTTP listener factory returned nil"), daemon.Shutdown(context.Background()))
	}
	daemon.resourcesMu.Lock()
	daemon.listeners = append(daemon.listeners, httpListener)
	daemon.resourcesMu.Unlock()
	mcpListener, err := daemon.dependencies.Listen("tcp", daemon.config.MCPAddress)
	if err != nil {
		return errors.Join(fmt.Errorf("listen MCP: %w", err), daemon.Shutdown(context.Background()))
	}
	if isNil(mcpListener) {
		return errors.Join(errors.New("MCP listener factory returned nil"), daemon.Shutdown(context.Background()))
	}
	daemon.resourcesMu.Lock()
	daemon.listeners = append(daemon.listeners, mcpListener)
	daemon.resourcesMu.Unlock()

	httpServer := daemon.dependencies.NewServer(daemon.config.HTTPAddress, bundle.HTTP)
	mcpServer := daemon.dependencies.NewServer(daemon.config.MCPAddress, bundle.MCP)
	if isNil(httpServer) || isNil(mcpServer) {
		return errors.Join(errors.New("server factory returned nil"), daemon.Shutdown(context.Background()))
	}
	daemon.resourcesMu.Lock()
	daemon.servers = []IngressServer{httpServer, mcpServer}
	daemon.resourcesMu.Unlock()

	serveResults := make(chan error, 2)
	serveStarted := make(chan struct{}, 2)
	go func() {
		serveStarted <- struct{}{}
		serveResults <- normalizeServeError("HTTP", httpServer.Serve(httpListener))
	}()
	go func() {
		serveStarted <- struct{}{}
		serveResults <- normalizeServeError("MCP", mcpServer.Serve(mcpListener))
	}()
	<-serveStarted
	<-serveStarted
	select {
	case serveErr := <-serveResults:
		return errors.Join(serveErr, daemon.Shutdown(context.Background()), <-serveResults)
	default:
	}
	if ctx.Err() != nil {
		shutdownErr := daemon.Shutdown(context.Background())
		first, second := <-serveResults, <-serveResults
		return errors.Join(shutdownErr, first, second)
	}
	if daemon.dependencies.Ready != nil {
		daemon.dependencies.Ready()
	}

	select {
	case <-ctx.Done():
		shutdownErr := daemon.Shutdown(context.Background())
		first, second := <-serveResults, <-serveResults
		return errors.Join(shutdownErr, first, second)
	case serveErr := <-serveResults:
		shutdownErr := daemon.Shutdown(context.Background())
		return errors.Join(serveErr, shutdownErr, <-serveResults)
	}
}

func (daemon *Daemon) openStorage(ctx context.Context) (Storage, error) {
	if daemon.config.Storage == StorageSQLite {
		return daemon.dependencies.OpenSQLite(ctx, sqlite.Config{Path: daemon.config.SQLitePath})
	}
	secrets, err := daemon.dependencies.Secrets.PostgreSQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL secrets: %w", err)
	}
	if secrets.DSN == "" {
		return nil, errors.New("PostgreSQL secret source returned an empty application DSN")
	}
	return daemon.dependencies.OpenPostgreSQL(ctx, postgres.Config{
		DSN: secrets.DSN, MigrationDSN: secrets.MigrationDSN,
	})
}

// Shutdown is safe to call concurrently and more than once.
func (daemon *Daemon) Shutdown(ctx context.Context) error {
	daemon.shutdownOnce.Do(func() {
		stopCtx := ctx
		if daemon.config.ShutdownTimeout > 0 {
			var cancel context.CancelFunc
			stopCtx, cancel = context.WithTimeout(ctx, daemon.config.ShutdownTimeout)
			defer cancel()
		}
		daemon.resourcesMu.Lock()
		servers := append([]IngressServer(nil), daemon.servers...)
		listeners := append([]net.Listener(nil), daemon.listeners...)
		workers := append([]Worker(nil), daemon.workers...)
		store := daemon.store
		daemon.resourcesMu.Unlock()

		var shutdownErr error
		for _, server := range servers {
			shutdownErr = errors.Join(shutdownErr, server.Shutdown(stopCtx))
		}
		for _, listener := range listeners {
			shutdownErr = errors.Join(shutdownErr, ignoreClosed(listener.Close()))
		}
		for index := len(workers) - 1; index >= 0; index-- {
			shutdownErr = errors.Join(shutdownErr, workers[index].Stop(stopCtx))
		}
		if store != nil {
			shutdownErr = errors.Join(shutdownErr, store.Close())
		}
		daemon.shutdownErr = shutdownErr
	})
	return daemon.shutdownErr
}

func normalizeServeError(name string, err error) error {
	if err == nil {
		return fmt.Errorf("%s server stopped unexpectedly", name)
	}
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("%s server: %w", name, err)
}

func ignoreClosed(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map ||
		kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
