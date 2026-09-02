// Package runtime owns process-level composition and lifecycle.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/phall1/blackbird/internal/storage/sqlite"
)

const (
	developmentVersion = "dev"
	unknownBuildValue  = "unknown"
	defaultStopTimeout = 30 * time.Second
	logLevelVariable   = "BLACKBIRD_LOG_LEVEL"
)

// StorageBackend identifies the durable storage implementation selected at startup.
type StorageBackend string

const StorageSQLite StorageBackend = "sqlite"

// Config contains non-secret process configuration. It carries no credentials:
// SQLite is the only backend, and its path is not a secret.
type Config struct {
	Storage         StorageBackend
	SQLitePath      string
	StateDir        string
	HTTPAddress     string
	MCPAddress      string
	LogLevel        string
	ShutdownTimeout time.Duration
}

// Validate rejects configurations that cannot safely start a complete daemon.
func (config Config) Validate() error {
	if config.Storage != StorageSQLite {
		return fmt.Errorf("storage must be %q", StorageSQLite)
	}
	if config.SQLitePath == "" {
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
	if _, err := config.logLevel(); err != nil {
		return err
	}
	return nil
}

// logLevel resolves the configured severity. An unparsable value in the
// environment falls back to the default rather than refusing to start; an
// unparsable value in Config is a configuration error the caller must see.
func (config Config) logLevel() (slog.Level, error) {
	var level slog.Level
	if config.LogLevel == "" {
		if text := os.Getenv(logLevelVariable); text != "" && level.UnmarshalText([]byte(text)) == nil {
			return level, nil
		}
		return slog.LevelInfo, nil
	}
	if err := level.UnmarshalText([]byte(config.LogLevel)); err != nil {
		return slog.LevelInfo, fmt.Errorf("log level %q: %w", config.LogLevel, err)
	}
	return level, nil
}

// NewLogger builds the daemon's structured logger. Output belongs on stderr:
// launchd and systemd both capture it, and stdout carries command output.
func NewLogger(config Config, output io.Writer) (*slog.Logger, error) {
	logger, _, err := NewLeveledLogger(config, output)
	return logger, err
}

// NewLeveledLogger builds the daemon's logger alongside the severity control it
// was built with. The level lives in a slog.LevelVar rather than in
// HandlerOptions because a baked-in level makes raising verbosity cost an edit
// to a launchd plist or systemd unit and a supervised restart — the daemon is
// then a different process, and whatever was being diagnosed is gone.
func NewLeveledLogger(config Config, output io.Writer) (*slog.Logger, *slog.LevelVar, error) {
	level, err := config.logLevel()
	if err != nil {
		return nil, nil, err
	}
	severity := new(slog.LevelVar)
	severity.Set(level)
	return slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{Level: severity})), severity, nil
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

// Storage is the narrow process-lifetime contract of the durable store.
type Storage interface {
	Close() error
}

// Worker is started only after complete handler composition and stopped only
// after ingress has drained.
type Worker interface {
	Start(context.Context) error
	Stop(context.Context) error
}

// BoundAddressReceiver is the optional capability of a Worker that publishes
// this daemon's reachable address. Composition happens before the listener
// binds, so a worker composed from configuration alone would publish the
// request rather than the result — and a configured port of 0 makes that
// request unreachable. Runtime hands over the bound address between bind and
// Start for any worker that implements this.
type BoundAddressReceiver interface {
	SetBoundHTTPAddress(address string)
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
	Logger *slog.Logger
	// LogSeverity is the level control behind Logger. Supplying it alongside a
	// caller-built Logger is what makes SetLogLevel able to move that logger;
	// runtime cannot recover a handler's level control from the handler.
	LogSeverity *slog.LevelVar
	Compose     Composer
	OpenSQLite  func(context.Context, sqlite.Config) (Storage, error)
	Listen      func(string, string) (net.Listener, error)
	NewServer   func(string, http.Handler) IngressServer
	Ready       func()
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
	logger       *slog.Logger
	logSeverity  *slog.LevelVar
	ingress      *ingressDrain

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

// ingressDrain gives every request a process-owned cancellation signal and
// keeps the storage close behind a handler barrier. net/http Shutdown stops new
// connections but deliberately does not cancel active request contexts, so a
// long-lived SSE or wait handler otherwise holds shutdown until its deadline
// and can still touch storage after that deadline expires.
type ingressDrain struct {
	mu       sync.Mutex
	stopping bool
	next     uint64
	cancels  map[uint64]context.CancelFunc
	handlers sync.WaitGroup
}

func newIngressDrain() *ingressDrain {
	return &ingressDrain{cancels: make(map[uint64]context.CancelFunc)}
}

func (drain *ingressDrain) wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithCancel(request.Context())
		drain.mu.Lock()
		if drain.stopping {
			drain.mu.Unlock()
			cancel()
			http.Error(writer, "server is shutting down", http.StatusServiceUnavailable)
			return
		}
		drain.next++
		requestID := drain.next
		drain.cancels[requestID] = cancel
		drain.handlers.Add(1)
		drain.mu.Unlock()
		defer func() {
			drain.mu.Lock()
			delete(drain.cancels, requestID)
			drain.mu.Unlock()
			cancel()
			drain.handlers.Done()
		}()
		handler.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func (drain *ingressDrain) begin() {
	if drain == nil {
		return
	}
	drain.mu.Lock()
	drain.stopping = true
	cancels := make([]context.CancelFunc, 0, len(drain.cancels))
	for _, cancel := range drain.cancels {
		cancels = append(cancels, cancel)
	}
	drain.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (drain *ingressDrain) wait(ctx context.Context) error {
	if drain == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		drain.handlers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// New returns an identity-only daemon retained for build-info callers. Run
// fails closed because no production composition has been supplied.
// newIngressServer builds the daemon's ingress server. It deliberately sets no
// WriteTimeout, and that absence is load-bearing rather than an oversight:
// blackbird_wait holds a single request open for up to
// coordination.MaxCoordinationWait while it parks an agent behind a reservation,
// so any write timeout at or below that ceiling would cut long polls off
// mid-answer. The agent does not see a timeout -- it sees a truncated response
// from what looks like a broken daemon, which is the worst available failure
// for a coordination feature. Read and idle timeouts are safe because neither
// bounds the time spent producing a response.
//
// TestIngressServerAdmitsTheLongPollCeiling enforces this, because a comment
// does not survive a well-meaning hardening pass.
func newIngressServer(address string, handler http.Handler) IngressServer {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

func New(build BuildInfo) *Daemon {
	return &Daemon{build: build.Normalize(), logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
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
	if dependencies.OpenSQLite == nil {
		dependencies.OpenSQLite = func(ctx context.Context, config sqlite.Config) (Storage, error) {
			return sqlite.Open(ctx, config)
		}
	}
	if dependencies.Listen == nil {
		dependencies.Listen = net.Listen
	}
	if dependencies.NewServer == nil {
		dependencies.NewServer = newIngressServer
	}
	severity := dependencies.LogSeverity
	if dependencies.Logger == nil {
		logger, defaultSeverity, err := NewLeveledLogger(config, os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("runtime configuration: %w", err)
		}
		dependencies.Logger = logger
		severity = defaultSeverity
	}
	return &Daemon{
		build: build.Normalize(), config: config, dependencies: dependencies,
		logger: dependencies.Logger.With(
			slog.String("version", build.Normalize().Version),
			slog.Int("pid", os.Getpid()),
		),
		logSeverity: severity,
		ingress:     newIngressDrain(),
	}, nil
}

// SetLogLevel raises or lowers the running daemon's severity and reports
// whether the change took effect. A caller that supplied its own Logger without
// the LevelVar that built it owns that handler's level, and runtime must not
// pretend otherwise.
func (daemon *Daemon) SetLogLevel(level slog.Level) bool {
	if daemon.logSeverity == nil {
		return false
	}
	daemon.logSeverity.Set(level)
	daemon.logger.Info("log level changed", slog.String("level", level.String()))
	return true
}

// LogLevel reports the severity the daemon currently emits at.
func (daemon *Daemon) LogLevel() slog.Level {
	if daemon.logSeverity == nil {
		return slog.LevelInfo
	}
	return daemon.logSeverity.Level()
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
		daemon.logger.Error("daemon is already running or has run")
		return errors.New("daemon is already running or has run")
	}
	daemon.running = true
	daemon.runMu.Unlock()
	if daemon.dependencies.Compose == nil {
		daemon.logger.Error("daemon has no production composition; use NewDaemon")
		return errors.New("daemon has no production composition; use NewDaemon")
	}
	daemon.logger.Info("daemon starting",
		slog.String("commit", daemon.build.Commit), slog.String("built_at", daemon.build.BuiltAt),
		slog.String("storage", string(daemon.config.Storage)), slog.String("database", daemon.config.SQLitePath),
		slog.String("state_dir", daemon.config.StateDir),
		slog.String("http_address", daemon.config.HTTPAddress), slog.String("mcp_address", daemon.config.MCPAddress),
	)

	store, err := daemon.openStorage(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			daemon.logger.Info("startup cancelled while opening storage")
			return nil
		}
		daemon.logger.Error("open storage", slog.Any("error", err))
		return fmt.Errorf("open storage: %w", err)
	}
	if isNil(store) {
		daemon.logger.Error("storage factory returned nil")
		return errors.New("storage factory returned nil")
	}
	daemon.logger.Info("storage opened", slog.String("storage", string(daemon.config.Storage)))
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
			daemon.logger.Info("startup cancelled while composing handlers")
			return shutdownErr
		}
		daemon.logger.Error("compose handlers", slog.Any("error", err))
		return errors.Join(fmt.Errorf("compose handlers: %w", err), shutdownErr)
	}
	if isNil(bundle.HTTP) || isNil(bundle.MCP) {
		daemon.logger.Error("composition supplied incomplete ingress handlers")
		return errors.Join(errors.New("composition must supply complete HTTP and MCP handlers"), daemon.Shutdown(context.Background()))
	}
	if ctx.Err() != nil {
		return daemon.Shutdown(context.Background())
	}

	// Listeners bind before workers start. A worker that publishes process-wide
	// state must never run in a process that lost the address race, or its
	// rollback destroys the state of the daemon that actually holds the port.
	httpListener, err := daemon.bind(daemon.config.HTTPAddress, "HTTP")
	if err != nil {
		return errors.Join(err, daemon.Shutdown(context.Background()))
	}
	mcpListener, err := daemon.bind(daemon.config.MCPAddress, "MCP")
	if err != nil {
		return errors.Join(err, daemon.Shutdown(context.Background()))
	}

	boundHTTPAddress := httpListener.Addr().String()
	for index, worker := range bundle.Workers {
		if isNil(worker) {
			daemon.logger.Error("composition supplied a nil worker", slog.Int("worker", index))
			return errors.Join(fmt.Errorf("worker %d is nil", index), daemon.Shutdown(context.Background()))
		}
		if receiver, ok := worker.(BoundAddressReceiver); ok {
			receiver.SetBoundHTTPAddress(boundHTTPAddress)
		}
		daemon.resourcesMu.Lock()
		daemon.workers = append(daemon.workers, worker)
		daemon.resourcesMu.Unlock()
		if err := worker.Start(ctx); err != nil {
			shutdownErr := daemon.Shutdown(context.Background())
			if errors.Is(err, context.Canceled) {
				return shutdownErr
			}
			daemon.logger.Error("start worker", slog.Int("worker", index), slog.Any("error", err))
			return errors.Join(fmt.Errorf("start worker %d: %w", index, err), shutdownErr)
		}
		if ctx.Err() != nil {
			return daemon.Shutdown(context.Background())
		}
	}

	httpServer := daemon.dependencies.NewServer(daemon.config.HTTPAddress, daemon.ingress.wrap(bundle.HTTP))
	mcpServer := daemon.dependencies.NewServer(daemon.config.MCPAddress, daemon.ingress.wrap(bundle.MCP))
	if isNil(httpServer) || isNil(mcpServer) {
		daemon.logger.Error("server factory returned nil")
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
		daemon.logger.Error("ingress stopped during startup", slog.Any("error", serveErr))
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
	daemon.logger.Info("daemon ready",
		slog.String("http_address", boundHTTPAddress), slog.String("mcp_address", mcpListener.Addr().String()))

	select {
	case <-ctx.Done():
		daemon.logger.Info("shutdown signalled")
		shutdownErr := daemon.Shutdown(context.Background())
		first, second := <-serveResults, <-serveResults
		return errors.Join(shutdownErr, first, second)
	case serveErr := <-serveResults:
		daemon.logger.Error("ingress stopped unexpectedly", slog.Any("error", serveErr))
		shutdownErr := daemon.Shutdown(context.Background())
		return errors.Join(serveErr, shutdownErr, <-serveResults)
	}
}

func (daemon *Daemon) bind(address, name string) (net.Listener, error) {
	listener, err := daemon.dependencies.Listen("tcp", address)
	if err != nil {
		daemon.logger.Error("bind listener", slog.String("ingress", name), slog.String("address", address), slog.Any("error", err))
		return nil, fmt.Errorf("listen %s: %w", name, err)
	}
	if isNil(listener) {
		daemon.logger.Error("listener factory returned nil", slog.String("ingress", name))
		return nil, fmt.Errorf("%s listener factory returned nil", name)
	}
	daemon.resourcesMu.Lock()
	daemon.listeners = append(daemon.listeners, listener)
	daemon.resourcesMu.Unlock()
	daemon.logger.Info("listener bound", slog.String("ingress", name), slog.String("address", listener.Addr().String()))
	return listener, nil
}

func (daemon *Daemon) openStorage(ctx context.Context) (Storage, error) {
	return daemon.dependencies.OpenSQLite(ctx, sqlite.Config{Path: daemon.config.SQLitePath})
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

		daemon.logger.Info("shutdown starting",
			slog.Int("servers", len(servers)), slog.Int("workers", len(workers)))
		var shutdownErr error
		// Cancel request contexts before asking net/http to drain them. Without
		// this, an SSE client can force the entire shutdown timeout because
		// Server.Shutdown does not cancel active handlers.
		daemon.ingress.begin()
		for _, server := range servers {
			shutdownErr = errors.Join(shutdownErr, daemon.logFailure("shut down ingress", server.Shutdown(stopCtx)))
		}
		for _, listener := range listeners {
			shutdownErr = errors.Join(shutdownErr, daemon.logFailure("close listener", ignoreClosed(listener.Close())))
		}
		drainErr := daemon.ingress.wait(stopCtx)
		shutdownErr = errors.Join(shutdownErr, daemon.logFailure("drain ingress handlers", drainErr))
		for index := len(workers) - 1; index >= 0; index-- {
			shutdownErr = errors.Join(shutdownErr, daemon.logFailure("stop worker", workers[index].Stop(stopCtx)))
		}
		if store != nil && drainErr == nil {
			shutdownErr = errors.Join(shutdownErr, daemon.logFailure("close storage", store.Close()))
		}
		daemon.shutdownErr = shutdownErr
		daemon.logger.Info("shutdown complete", slog.Bool("clean", shutdownErr == nil))
	})
	return daemon.shutdownErr
}

func (daemon *Daemon) logFailure(message string, err error) error {
	if err != nil {
		daemon.logger.Error(message, slog.Any("error", err))
	}
	return err
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
