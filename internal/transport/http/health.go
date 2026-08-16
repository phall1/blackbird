package http

import (
	"context"
	"errors"
	stdhttp "net/http"
	"sync"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	PathHealth = "/healthz"
	PathReady  = "/readyz"

	localReadinessTimeout   = 2 * time.Second
	localReadinessFreshness = 250 * time.Millisecond
	localReadinessFailure   = "durable storage is unavailable"
)

// HealthDependencies configures the unauthenticated, loopback-gated liveness
// and readiness surface. ProbeFreshness bounds how hard an unauthenticated
// caller can drive the durable store: concurrent probes coalesce and a result
// younger than the window is reused, while every request outside the window
// executes a real query.
type HealthDependencies struct {
	Readiness      application.ReadinessProbe
	Version        string
	ProbeTimeout   time.Duration
	ProbeFreshness time.Duration
}

type healthHandler struct {
	readiness application.ReadinessProbe
	version   string
	timeout   time.Duration
	freshness time.Duration
	now       func() time.Time

	mu       sync.Mutex
	inflight *readinessProbe
	latest   *readinessResult
}

type readinessResult struct {
	schemaVersion int
	err           error
	elapsed       time.Duration
	observedAt    time.Time
}

type readinessProbe struct {
	done   chan struct{}
	result readinessResult
}

type localHealth struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type localReadiness struct {
	Status        string `json:"status"`
	Storage       string `json:"storage"`
	SchemaVersion int    `json:"schema_version"`
	CheckMS       int64  `json:"check_ms"`
}

// NewHealthHandler serves GET /healthz and GET /readyz. Both are
// unauthenticated because the CLI reaches them before it holds a token, so
// neither may disclose a pid, a path, an address, or a storage error.
func NewHealthHandler(dependencies HealthDependencies) (stdhttp.Handler, error) {
	if isNil(dependencies.Readiness) {
		return nil, errors.New("health HTTP transport requires a readiness probe")
	}
	if dependencies.ProbeTimeout < 0 || dependencies.ProbeFreshness < 0 {
		return nil, errors.New("health HTTP transport durations cannot be negative")
	}
	if dependencies.ProbeTimeout == 0 {
		dependencies.ProbeTimeout = localReadinessTimeout
	}
	if dependencies.ProbeFreshness == 0 {
		dependencies.ProbeFreshness = localReadinessFreshness
	}
	handler := &healthHandler{readiness: dependencies.Readiness, version: dependencies.Version,
		timeout: dependencies.ProbeTimeout, freshness: dependencies.ProbeFreshness, now: time.Now}
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("GET "+PathHealth, handler.live)
	mux.HandleFunc("GET "+PathReady, handler.ready)
	return localSafety(mux), nil
}

func (handler *healthHandler) live(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if len(request.URL.Query()) != 0 {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "query parameters are invalid")
		return
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localHealth{Status: "ok", Version: handler.version})
}

func (handler *healthHandler) ready(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if len(request.URL.Query()) != 0 {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "query parameters are invalid")
		return
	}
	result, ok := handler.probe(request.Context())
	if !ok || result.err != nil {
		writeLocalProblem(writer, stdhttp.StatusServiceUnavailable, domain.ErrorCodeDependencyUnavailable, localReadinessFailure)
		return
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localReadiness{Status: "ready", Storage: "ok",
		SchemaVersion: result.schemaVersion, CheckMS: result.elapsed.Milliseconds()})
}

func (handler *healthHandler) probe(ctx context.Context) (readinessResult, bool) {
	handler.mu.Lock()
	if handler.latest != nil && handler.now().Sub(handler.latest.observedAt) < handler.freshness {
		cached := *handler.latest
		handler.mu.Unlock()
		return cached, true
	}
	if pending := handler.inflight; pending != nil {
		handler.mu.Unlock()
		select {
		case <-pending.done:
			return pending.result, true
		case <-ctx.Done():
			return readinessResult{}, false
		}
	}
	pending := &readinessProbe{done: make(chan struct{})}
	handler.inflight = pending
	handler.mu.Unlock()

	// The probe is detached from the leading request so a client that
	// disconnects mid-flight cannot fail the callers coalesced behind it.
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), handler.timeout)
	started := handler.now()
	schemaVersion, err := handler.readiness.CheckReadiness(probeCtx)
	cancel()
	completed := handler.now()
	pending.result = readinessResult{schemaVersion: schemaVersion, err: err,
		elapsed: completed.Sub(started), observedAt: completed}

	handler.mu.Lock()
	result := pending.result
	handler.latest = &result
	handler.inflight = nil
	handler.mu.Unlock()
	close(pending.done)
	return pending.result, true
}
