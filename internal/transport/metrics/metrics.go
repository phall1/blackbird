// Package observability owns the daemon's process-local operational counters.
package metrics

import (
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/phall1/blackbird/internal/adminapi"
)

// Registry is the dependency-free metrics surface for one daemon process.
// Counters are intentionally process-local: status reports them beside the
// process identity whose lifetime they describe.
type Registry struct {
	mu             sync.RWMutex
	requests       map[string]map[string]int64
	leaseConflicts atomic.Int64
	sseConnections atomic.Int64
}

// Snapshot is the authenticated admin wire shape consumed by status -v.
type Snapshot = adminapi.RuntimeMetrics

func New() *Registry { return &Registry{requests: make(map[string]map[string]int64)} }

// ObserveRequest increments one bounded operation/outcome pair.
func (registry *Registry) ObserveRequest(operation, outcome string) {
	if registry == nil || operation == "" || outcome == "" {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	outcomes := registry.requests[operation]
	if outcomes == nil {
		outcomes = make(map[string]int64)
		registry.requests[operation] = outcomes
	}
	outcomes[outcome]++
}

func (registry *Registry) ObserveLeaseConflict() {
	if registry != nil {
		registry.leaseConflicts.Add(1)
	}
}

// TrackSSE increments the live-connection gauge and returns its paired release.
func (registry *Registry) TrackSSE() func() {
	if registry == nil {
		return func() {}
	}
	registry.sseConnections.Add(1)
	return func() { registry.sseConnections.Add(-1) }
}

// Snapshot copies counters and samples file sizes only when an operator asks.
func (registry *Registry) Snapshot(databasePath string) Snapshot {
	result := Snapshot{Requests: make(map[string]map[string]int64)}
	if registry != nil {
		registry.mu.RLock()
		for operation, source := range registry.requests {
			outcomes := make(map[string]int64, len(source))
			for outcome, count := range source {
				outcomes[outcome] = count
			}
			result.Requests[operation] = outcomes
		}
		registry.mu.RUnlock()
		result.LeaseConflicts = registry.leaseConflicts.Load()
		result.SSEConnections = registry.sseConnections.Load()
	}
	result.DatabaseBytes = fileSize(databasePath)
	result.WALBytes = fileSize(databasePath + "-wal")
	return result
}

func fileSize(path string) int64 {
	if path == "" {
		return 0
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// WrapHTTP records one outcome per routed request and the live SSE gauge. The
// route pattern is read after dispatch so path parameters never become labels.
func (registry *Registry) WrapHTTP(handler http.Handler, ssePath string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == ssePath {
			defer registry.TrackSSE()()
		}
		recorder := &statusRecorder{ResponseWriter: writer}
		handler.ServeHTTP(recorder, request)
		pattern := request.Pattern
		if pattern == "" {
			pattern = "unmatched"
		}
		registry.ObserveRequest("http "+pattern, strconv.Itoa(recorder.statusCode()/100)+"xx")
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) WriteHeader(status int) {
	if recorder.status == 0 {
		recorder.status = status
	}
	recorder.ResponseWriter.WriteHeader(status)
}

func (recorder *statusRecorder) Write(data []byte) (int, error) {
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	return recorder.ResponseWriter.Write(data)
}

func (recorder *statusRecorder) Flush() {
	if flusher, ok := recorder.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (recorder *statusRecorder) Unwrap() http.ResponseWriter { return recorder.ResponseWriter }

func (recorder *statusRecorder) statusCode() int {
	if recorder.status == 0 {
		return http.StatusOK
	}
	return recorder.status
}
