package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/integration/beads"
	httptransport "github.com/phall1/blackbird/internal/transport/http"
	mcptransport "github.com/phall1/blackbird/internal/transport/mcp"
	"github.com/phall1/blackbird/internal/transport/metrics"
)

const mcpSessionTimeout = 30 * time.Minute

type productionStore interface {
	Storage
	coordination.LocalStore
	coordination.LocalAdminStore
}

// NewProductionDaemon constructs the source-built local coordination daemon.
func NewProductionDaemon(build BuildInfo, config Config) (*Daemon, error) {
	if config.Storage == StorageSQLite {
		path, err := filepath.Abs(config.SQLitePath)
		if err != nil {
			return nil, fmt.Errorf("resolve SQLite path: %w", err)
		}
		config.SQLitePath = filepath.Clean(path)
	}
	if config.StateDir != "" {
		path, err := filepath.Abs(config.StateDir)
		if err != nil {
			return nil, fmt.Errorf("resolve state directory: %w", err)
		}
		config.StateDir = filepath.Clean(path)
	}
	logger, severity, err := NewLeveledLogger(config, os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("runtime configuration: %w", err)
	}
	return NewDaemon(build, config, Dependencies{
		Logger: logger, LogSeverity: severity,
		Compose: composeProduction(build.Normalize(), config, logger),
	})
}

func composeProduction(build BuildInfo, config Config, logger *slog.Logger) Composer {
	return func(ctx context.Context, storage Storage) (HandlerBundle, error) {
		return composeProductionBundle(ctx, build, config, logger, storage)
	}
}

func composeProductionBundle(
	_ context.Context,
	build BuildInfo,
	config Config,
	logger *slog.Logger,
	storage Storage,
) (HandlerBundle, error) {
	store, ok := storage.(productionStore)
	if !ok {
		return HandlerBundle{}, errors.New("production storage does not implement local coordination ports")
	}
	metricsRegistry := metrics.New()
	observations, _ := storage.(telemetry.Store)
	var telemetryIngest *telemetryWorker
	if observations != nil {
		telemetryIngest = newTelemetryWorker(observations, logger)
	}
	localHTTPHandler, err := httptransport.NewLocalHandler(httptransport.LocalDependencies{
		Coordination: store, Logger: logger, Telemetry: telemetryOffer(telemetryIngest),
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose local HTTP transport: %w", err)
	}
	token, err := newAdminToken()
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("mint admin token: %w", err)
	}
	started := time.Now().UTC()
	adminHTTPHandler, err := httptransport.NewAdminHandler(httptransport.AdminDependencies{
		Admin: store, Token: httptransport.NewAdminTokenDigest(token), Metrics: metricsRegistry,
		Identity: httptransport.LocalIdentity{
			Version: build.Version, Commit: build.Commit, BuiltAt: build.BuiltAt,
			PID: os.Getpid(), StartedAt: started,
			HTTPAddress: config.HTTPAddress, MCPAddress: config.MCPAddress,
		},
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose admin HTTP transport: %w", err)
	}
	healthHandler, err := httptransport.NewHealthHandler(httptransport.HealthDependencies{
		Readiness: store, Version: build.Version,
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose health HTTP transport: %w", err)
	}
	handshake, err := newAdminHandshakeWorker(config.StateDir, token, config.HTTPAddress, build.Version, started, logger)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose admin handshake: %w", err)
	}
	httpMux := http.NewServeMux()
	httpMux.Handle("GET "+httptransport.PathHealth, healthHandler)
	httpMux.Handle("GET "+httptransport.PathReady, healthHandler)
	httpMux.Handle(httptransport.PathLocalAdmin, adminHTTPHandler)
	httpMux.Handle("/api/v1/local/", localHTTPHandler)
	mcpServer, err := mcptransport.NewServer(mcptransport.Dependencies{
		Logger: logger, Metrics: metricsRegistry, Coordination: store,
		Observations: observationReader(store), WorkReferences: newBeadsWorkReferenceObserver(),
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose MCP transport: %w", err)
	}
	logger.Info("ingress composed",
		slog.String("admin_path", httptransport.PathLocalAdmin),
		slog.String("health_path", httptransport.PathHealth),
		slog.String("readiness_path", httptransport.PathReady))
	return HandlerBundle{
		HTTP:    metricsRegistry.WrapHTTP(httpMux, httptransport.PathLocalCoordinationEventsStream),
		Workers: telemetryWorkers(handshake, telemetryIngest),
		MCP:     mcpServer.HTTPHandler(&sdkmcp.StreamableHTTPOptions{SessionTimeout: mcpSessionTimeout}),
	}, nil
}

// SetBoundHTTPAddress replaces the configured address with the one the HTTP
// listener actually bound.
func (worker *adminHandshakeWorker) SetBoundHTTPAddress(address string) {
	if address != "" {
		worker.handshake.HTTPAddress = address
	}
}

// observationReader returns a nil interface rather than a typed nil when the
// store cannot answer rollups, so the MCP transport's nil check decides whether
// the agent-facing tool exists at all.
func observationReader(store Storage) telemetry.Reader {
	reader, ok := store.(telemetry.Reader)
	if !ok {
		return nil
	}
	return reader
}

func telemetryOffer(worker *telemetryWorker) httptransport.TelemetryOffer {
	if worker == nil {
		return nil
	}
	return worker.sink
}

func telemetryWorkers(handshake Worker, worker *telemetryWorker) []Worker {
	if worker == nil {
		return []Worker{handshake}
	}
	return []Worker{handshake, worker}
}

// workObservationBudget bounds one whole observation, and workObservationStep
// bounds each of the two executions inside it -- the provider probe and the
// read. An observation shells out to a binary this daemon does not control,
// against an issue database that may be cold, while the agent that asked is
// parked on its turn; without a ceiling a wedged provider becomes a daemon that
// looks dead. The budget is what an agent can actually wait for, and the step
// is what keeps one hung execution from spending all of it.
const (
	workObservationBudget = 8 * time.Second
	workObservationStep   = 4 * time.Second
)

// beadsWorkReferenceObserver reads work items owned by the bd tracker. Build it
// with newBeadsWorkReferenceObserver: the zero value carries no lookup and no
// bounds, and a defensive default for either would be code no test on a
// workstation with bd installed and none without could reach the same way.
//
// It makes Blackbird no more authoritative over work than a caller reading bd
// itself: nothing is written, nothing is cached, and every call re-probes the
// binary, so the provenance reported beside an observation describes the binary
// that actually answered rather than one this daemon met at startup.
type beadsWorkReferenceObserver struct {
	// lookPath is injected so this composition asserts the same thing on a
	// workstation with bd installed and one without. It differs from the
	// updater's detection on purpose: the updater schedules a job that runs
	// under another unit's PATH, whereas the daemon is itself the process that
	// will exec bd, so what the daemon can find here is exactly what it can
	// run.
	lookPath func(string) (string, error)
	budget   time.Duration
	step     time.Duration
}

func newBeadsWorkReferenceObserver() beadsWorkReferenceObserver {
	return beadsWorkReferenceObserver{
		lookPath: exec.LookPath, budget: workObservationBudget, step: workObservationStep,
	}
}

// ObserveWorkReference reports what the tracker says about one work item now.
// Every failure it can produce is a typed boundary failure, because "the
// tracker is not installed here" and "the tracker is installed but unsupported"
// lead an agent to different next moves and an internal error leads it to
// neither.
func (observer beadsWorkReferenceObserver) ObserveWorkReference(
	ctx context.Context,
	projectDir string,
	objectID string,
) (coordination.WorkReference, error) {
	if !filepath.IsAbs(projectDir) {
		return coordination.WorkReference{}, beads.DependencyFailure(beads.ErrorMalformed, "configure",
			"this agent registered a project key that is not an absolute repository path, "+
				"so no tracker directory can be derived; register with the repository's absolute path", nil)
	}
	executable, err := observer.lookPath(beads.ExecutableName)
	if err != nil {
		return coordination.WorkReference{}, beads.DependencyFailure(beads.ErrorUnavailable, "configure",
			"the bd work-item tracker is not on this daemon's PATH; "+
				"install it to observe work items on this machine", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return coordination.WorkReference{}, beads.DependencyFailure(beads.ErrorUnavailable, "configure",
			"the bd work-item tracker could not be resolved to an absolute path", err)
	}
	observation, cancel := context.WithTimeout(ctx, observer.budget)
	defer cancel()
	provider, err := beads.New(observation, beads.Config{
		Executable: executable, ProjectDir: projectDir, Project: projectDir, Timeout: observer.step,
	})
	if err != nil {
		return coordination.WorkReference{}, err
	}
	return provider.Observe(observation, objectID)
}
