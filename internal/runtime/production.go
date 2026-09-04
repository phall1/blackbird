package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/integration/beads"
	"github.com/phall1/blackbird/internal/integration/ledger"
	httptransport "github.com/phall1/blackbird/internal/transport/http"
	mcptransport "github.com/phall1/blackbird/internal/transport/mcp"
	"github.com/phall1/blackbird/internal/transport/metrics"
)

const mcpSessionTimeout = 30 * time.Minute

type productionStore interface {
	Storage
	coordination.LocalStore
	coordination.LocalAdminStore
	coordination.PeerMailStore
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
	ctx context.Context,
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
	// The ledger collectors are resolved BEFORE the sink is built, because the
	// sink has to know which harnesses this daemon reads for itself in order to
	// drop the pushed copies of them. That ordering is the anti-double-counting
	// mechanism; see internal/application/telemetry/collection.go.
	collectorSpecs := productionLedgerCollectors()
	var telemetryIngest *telemetryWorker
	var ledgerCollectors *ledgerCollectorWorker
	if observations != nil {
		telemetryIngest = newTelemetryWorker(observations, logger, collectedSpecHarnesses(collectorSpecs))
		collectors, err := newLedgerCollectorWorker(collectorSpecs, telemetryIngest.sink, config.StateDir, logger)
		if err != nil {
			return HandlerBundle{}, fmt.Errorf("compose ledger collectors: %w", err)
		}
		ledgerCollectors = collectors
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
		Cost: costAdminReader(store), Outbox: peerMailQueueReader(store),
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
	// Peering resolves before anything binds. Enabling it on a machine without
	// Tailscale fails here, which is where an operator can still read why.
	admission, peerAddress, err := composePeering(ctx, config, newTailnet(), metricsRegistry, logger)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose tailnet peering: %w", err)
	}
	peerHandler, err := httptransport.NewPeerHandler(httptransport.PeerDependencies{
		Version: build.Version, Address: peerAddress, Enabled: admission.Enabled(),
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose peer HTTP transport: %w", err)
	}
	peerCostHandler, err := httptransport.NewPeerCostHandler(httptransport.PeerCostDependencies{
		Cost: costAdminReader(store), Logger: logger,
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose peer cost HTTP transport: %w", err)
	}
	peerMailHandler, err := httptransport.NewPeerMailHandler(httptransport.PeerMailDependencies{
		Mail: store, Logger: logger,
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose peer mail HTTP transport: %w", err)
	}
	// The outbound half exists only when peering does. A daemon that is not
	// peered can never receive a reply to a name@host recipient, so queueing
	// mail for one would be a promise it cannot keep; with the ports absent the
	// agent-facing send refuses the recipient by name instead, which is an
	// answer the agent can act on.
	var peerMailDispatcher *coordination.PeerMailDispatcher
	if admission.Enabled() {
		peerMailDispatcher, err = coordination.NewPeerMailDispatcher(coordination.PeerMailDispatcherDependencies{
			Store: store, Logger: logger,
			Sender: httptransport.NewPeerMailClient(httptransport.PeerMailClientDependencies{
				Port: addressPort(config.HTTPAddress), Logger: logger,
			}),
		})
		if err != nil {
			return HandlerBundle{}, fmt.Errorf("compose peer mail dispatcher: %w", err)
		}
	}
	handshake, err := newAdminHandshakeWorker(config.StateDir, token, config.HTTPAddress, build.Version, started, logger)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose admin handshake: %w", err)
	}
	httpMux := http.NewServeMux()
	for _, route := range productionHTTPRoutes(healthHandler, peerHandler,
		peerCostHandler, peerMailHandler, adminHTTPHandler, localHTTPHandler) {
		httpMux.Handle(route.pattern, route.handler)
	}
	mcpServer, err := mcptransport.NewServer(mcptransport.Dependencies{
		Logger: logger, Metrics: metricsRegistry, Coordination: store,
		Observations: observationReader(store), WorkReferences: newBeadsWorkReferenceObserver(),
		PeerMailStore:    peerMailSendPort(store, peerMailDispatcher),
		PeerMailDispatch: peerMailDispatch(peerMailDispatcher),
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose MCP transport: %w", err)
	}
	logger.Info("ingress composed",
		slog.String("admin_path", httptransport.PathLocalAdmin),
		slog.String("health_path", httptransport.PathHealth),
		slog.String("readiness_path", httptransport.PathReady))
	workers := telemetryWorkers(handshake, telemetryIngest, ledgerCollectors)
	if peerMailDispatcher != nil {
		workers = append(workers, peerMailDispatcher)
	}
	return HandlerBundle{
		HTTP:          metricsRegistry.WrapHTTP(httpMux, httptransport.PathLocalCoordinationEventsStream),
		Workers:       workers,
		MCP:           mcpServer.HTTPHandler(&sdkmcp.StreamableHTTPOptions{SessionTimeout: mcpSessionTimeout}),
		PeerAdmission: admission,
		PeerAddress:   peerAddress,
	}, nil
}

// productionRoute is one pattern and the handler that serves it.
type productionRoute struct {
	pattern string
	handler http.Handler
}

// productionHTTPRoutes is the daemon's ENTIRE HTTP route table, in one value.
//
// It is a list rather than a sequence of mux.Handle calls so that a test can
// hold the same table the daemon serves and check it against the peer
// partition in peer.go. That cross-check is not decoration: the peer cost route
// was classified peer-reachable and never registered, so every request for it
// fell through to the catch-all and answered 404 -- a route that was in the
// security partition, in the client, and served by nobody. A hand-written test
// table could not catch that, because it agreed with the classifier rather than
// with the mux.
func productionHTTPRoutes(
	health, peer, peerCost, peerMail, admin, local http.Handler,
) []productionRoute {
	return []productionRoute{
		{"GET " + httptransport.PathHealth, health},
		{"GET " + httptransport.PathReady, health},
		{"GET " + httptransport.PathLocalPeer, peer},
		{"GET " + httptransport.PathLocalPeerCost, peerCost},
		{"POST " + httptransport.PathLocalPeerMail, peerMail},
		{httptransport.PathLocalAdmin, admin},
		{"/api/v1/local/", local},
	}
}

// peerMailSendPort and peerMailDispatch return nil INTERFACES rather than typed
// nil pointers when peering is off, because the MCP transport reads a nil port
// as "this daemon cannot send cross-host mail" and refuses a name@host
// recipient by name. A typed nil would pass that check and panic on use.
func peerMailSendPort(
	store coordination.PeerMailStore,
	dispatcher *coordination.PeerMailDispatcher,
) coordination.PeerMailSendPort {
	if dispatcher == nil {
		return nil
	}
	return store
}

func peerMailDispatch(dispatcher *coordination.PeerMailDispatcher) coordination.PeerMailDispatch {
	if dispatcher == nil {
		return nil
	}
	return dispatcher
}

// peerMailQueueReader returns a nil INTERFACE when the store cannot answer the
// outbox, so the admin route reports the capability missing rather than an
// empty queue -- which an operator would read as "nothing is stuck".
func peerMailQueueReader(store Storage) coordination.PeerMailQueueReader {
	reader, ok := store.(coordination.PeerMailQueueReader)
	if !ok {
		return nil
	}
	return reader
}

// addressPort is the port half of a listen address, used as the default port
// for dialling a peer that names none.
func addressPort(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return port
}

// SetBoundHTTPAddress replaces the configured address with the one the HTTP
// listener actually bound.
func (worker *adminHandshakeWorker) SetBoundHTTPAddress(address string) {
	if address != "" {
		worker.handshake.HTTPAddress = address
	}
}

// SetBoundPeerAddress publishes what the peer listener actually bound, and
// publishes the empty string when there is no peer listener. It assigns
// unconditionally, unlike its HTTP counterpart: "no peer address" is the fact
// an operator most needs the record to be able to state, and a version of this
// that skipped the empty case could only ever report peering as on.
func (worker *adminHandshakeWorker) SetBoundPeerAddress(address string) {
	worker.handshake.PeerAddress = address
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

// costAdminReader is the operator half of the same optional capability, and
// returns a nil interface for the same reason: the admin route reads a nil
// dependency as "this daemon cannot answer cost" and says so, which is a
// different answer from a report full of zeros.
func costAdminReader(store Storage) telemetry.CostAdminReader {
	reader, ok := store.(telemetry.CostAdminReader)
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

// telemetryWorkers orders the observation plane behind the handshake. Runtime
// stops workers in reverse, and the order here is the stop order read
// backwards: the ledger collectors stop first so nothing is still offering,
// then the drain flushes into a database that is still open.
func telemetryWorkers(handshake Worker, drain *telemetryWorker, collectors *ledgerCollectorWorker) []Worker {
	workers := []Worker{handshake}
	if drain != nil {
		workers = append(workers, drain)
	}
	if collectors != nil {
		workers = append(workers, collectors)
	}
	return workers
}

// collectedSpecHarnesses names the harnesses the composed collectors own,
// before those collectors exist. It reads the specs rather than the collectors
// because the sink needs the answer first.
//
// A harness is claimed only when its ledger tree is ACTUALLY PRESENT on this
// machine, and that condition is the whole point of the function.
//
// Superseding a push is a claim -- "do not store this, I have it from the
// ledger" -- and a daemon that cannot see the ledger cannot back it. The roots
// are resolved from the daemon's own environment, and the daemon is a per-user
// service: it does not inherit the login shell, so a CLAUDE_CONFIG_DIR or
// CODEX_HOME the user exported in their profile is simply absent here and the
// resolved root points at a directory that does not exist. Claiming the harness
// anyway would drop every pushed observation while collecting none, and both
// halves are silent -- absence is a PASSING probe state by design, and the plane
// counts write failures rather than returning them. Spend would read zero
// forever with nothing anywhere reporting a fault. This is the same shape as
// the updater's LookPathIn lesson: detection must read the environment the work
// will actually run in, and a detector that cannot must not be trusted to
// disable the fallback.
//
// The trade this makes is deliberate. A harness whose tree appears AFTER the
// daemon started stays unclaimed until the next restart, so a push adapter and
// the collector could both observe the window in between. That is a bounded,
// one-time overlap on a machine in transition, visible in the numbers; the
// alternative it replaces is permanent, total, and invisible.
func collectedSpecHarnesses(specs []ledgerCollectorSpec) telemetry.CollectedHarnesses {
	harnesses := make([]domain.Harness, 0, len(specs))
	for _, spec := range specs {
		if present, _ := ledger.RootPresent(spec.root); !present {
			continue
		}
		harnesses = append(harnesses, spec.adapter.Harness())
	}
	return telemetry.NewCollectedHarnesses(harnesses...)
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
