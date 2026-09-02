package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application"
	httptransport "github.com/phall1/blackbird/internal/transport/http"
	mcptransport "github.com/phall1/blackbird/internal/transport/mcp"
	"github.com/phall1/blackbird/internal/transport/metrics"
)

const mcpSessionTimeout = 30 * time.Minute

type productionStore interface {
	Storage
	application.LocalCoordinationStore
	application.LocalAdminStore
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
	telemetry := metrics.New()
	observations, _ := storage.(application.TelemetryStore)
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
		Admin: store, Token: httptransport.NewAdminTokenDigest(token), Metrics: telemetry,
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
		Logger: logger, Metrics: telemetry, Coordination: store,
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose MCP transport: %w", err)
	}
	logger.Info("ingress composed",
		slog.String("admin_path", httptransport.PathLocalAdmin),
		slog.String("health_path", httptransport.PathHealth),
		slog.String("readiness_path", httptransport.PathReady))
	return HandlerBundle{
		HTTP:    telemetry.WrapHTTP(httpMux, httptransport.PathLocalCoordinationEventsStream),
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

func telemetryOffer(worker *telemetryWorker) httptransport.TelemetryOffer {
	if worker == nil {
		return nil
	}
	return worker.sink
}

func telemetryWorkers(handshake Worker, telemetry *telemetryWorker) []Worker {
	if telemetry == nil {
		return []Worker{handshake}
	}
	return []Worker{handshake, telemetry}
}
