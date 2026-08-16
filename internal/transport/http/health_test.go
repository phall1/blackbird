package http

import (
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

type stubReadinessProbe struct {
	calls         atomic.Int64
	schemaVersion int
	err           error
	block         chan struct{}
	entered       chan struct{}
}

func (probe *stubReadinessProbe) CheckReadiness(ctx context.Context) (int, error) {
	probe.calls.Add(1)
	if probe.entered != nil {
		probe.entered <- struct{}{}
	}
	if probe.block != nil {
		select {
		case <-probe.block:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return probe.schemaVersion, probe.err
}

func TestNewHealthHandlerValidatesDependencies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		dependencies HealthDependencies
	}{
		{name: "no probe", dependencies: HealthDependencies{}},
		{name: "nil probe", dependencies: HealthDependencies{Readiness: (*stubReadinessProbe)(nil)}},
		{name: "negative timeout", dependencies: HealthDependencies{Readiness: &stubReadinessProbe{}, ProbeTimeout: -1}},
		{name: "negative freshness", dependencies: HealthDependencies{Readiness: &stubReadinessProbe{}, ProbeFreshness: -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler, err := NewHealthHandler(test.dependencies)
			if err == nil || handler != nil {
				t.Fatalf("handler=%v error=%v", handler, err)
			}
		})
	}
}

func TestHealthzReportsLivenessWithoutTouchingStorage(t *testing.T) {
	t.Parallel()
	probe := &stubReadinessProbe{schemaVersion: 4}
	handler := newHealthTestHandler(t, HealthDependencies{Readiness: probe, Version: "0.4.0"})
	response := serveHealth(handler, PathHealth)
	var health localHealth
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if response.Code != stdhttp.StatusOK || health != (localHealth{Status: "ok", Version: "0.4.0"}) {
		t.Fatalf("status=%d health=%+v", response.Code, health)
	}
	if probe.calls.Load() != 0 {
		t.Fatalf("liveness must not touch storage: calls=%d", probe.calls.Load())
	}
	if strings.Contains(response.Body.String(), "pid") || strings.Contains(response.Body.String(), "path") {
		t.Fatalf("liveness leaked process detail: %s", response.Body.String())
	}
}

func TestReadyzProbesStorageOnEveryRequestOutsideTheFreshnessWindow(t *testing.T) {
	t.Parallel()
	probe := &stubReadinessProbe{schemaVersion: 4}
	handler := newHealthTestHandler(t, HealthDependencies{Readiness: probe, ProbeFreshness: time.Nanosecond})
	for attempt := range 3 {
		response := serveHealth(handler, PathReady)
		var readiness localReadiness
		if err := json.Unmarshal(response.Body.Bytes(), &readiness); err != nil {
			t.Fatal(err)
		}
		if response.Code != stdhttp.StatusOK || readiness.Status != "ready" || readiness.Storage != "ok" ||
			readiness.SchemaVersion != 4 || readiness.CheckMS < 0 {
			t.Fatalf("attempt %d status=%d readiness=%+v", attempt, response.Code, readiness)
		}
	}
	if probe.calls.Load() != 3 {
		t.Fatalf("readiness answered from a cache: calls=%d", probe.calls.Load())
	}
}

func TestReadyzServesAFreshResultAndCoalescesConcurrentProbes(t *testing.T) {
	t.Parallel()
	probe := &stubReadinessProbe{schemaVersion: 4}
	handler := newHealthTestHandler(t, HealthDependencies{Readiness: probe, ProbeFreshness: time.Minute})
	var waiting sync.WaitGroup
	for range 8 {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			if response := serveHealth(handler, PathReady); response.Code != stdhttp.StatusOK {
				t.Errorf("status=%d", response.Code)
			}
		}()
	}
	waiting.Wait()
	if calls := probe.calls.Load(); calls != 1 {
		t.Fatalf("unauthenticated callers amplified into storage: calls=%d", calls)
	}
}

func TestReadyzReportsDependencyUnavailableWithoutLeakingTheStorageError(t *testing.T) {
	t.Parallel()
	probe := &stubReadinessProbe{err: errAdminTestOpaque}
	handler := newHealthTestHandler(t, HealthDependencies{Readiness: probe, ProbeFreshness: time.Nanosecond})
	response := serveHealth(handler, PathReady)
	var problem localProblem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != stdhttp.StatusServiceUnavailable || problem.Code != domain.ErrorCodeDependencyUnavailable ||
		response.Header().Get("Content-Type") != mediaTypeProblem {
		t.Fatalf("status=%d problem=%+v content-type=%q", response.Code, problem, response.Header().Get("Content-Type"))
	}
	if problem.Message != localReadinessFailure || strings.Contains(response.Body.String(), "blackbird.db") {
		t.Fatalf("readiness leaked the storage error: %s", response.Body.String())
	}
}

func TestReadyzHonoursProbeTimeout(t *testing.T) {
	t.Parallel()
	probe := &stubReadinessProbe{schemaVersion: 4, block: make(chan struct{})}
	defer close(probe.block)
	handler := newHealthTestHandler(t, HealthDependencies{Readiness: probe, ProbeTimeout: 20 * time.Millisecond,
		ProbeFreshness: time.Nanosecond})
	response := serveHealth(handler, PathReady)
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatalf("blocked probe status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHealthEndpointsRejectNonLoopbackAndQueryParameters(t *testing.T) {
	t.Parallel()
	handler := newHealthTestHandler(t, HealthDependencies{Readiness: &stubReadinessProbe{schemaVersion: 4},
		ProbeFreshness: time.Nanosecond})
	tests := []struct {
		name       string
		target     string
		remoteAddr string
		status     int
		code       domain.ErrorCode
	}{
		{name: "healthz non-loopback", target: PathHealth, remoteAddr: "192.0.2.1:1234",
			status: stdhttp.StatusForbidden, code: domain.ErrorCodeForbidden},
		{name: "readyz non-loopback", target: PathReady, remoteAddr: "192.0.2.1:1234",
			status: stdhttp.StatusForbidden, code: domain.ErrorCodeForbidden},
		{name: "healthz query", target: PathHealth + "?x=1",
			status: stdhttp.StatusBadRequest, code: domain.ErrorCodeInvalidArgument},
		{name: "readyz query", target: PathReady + "?x=1",
			status: stdhttp.StatusBadRequest, code: domain.ErrorCodeInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := newLocalHTTPRequest(stdhttp.MethodGet, test.target, nil)
			if test.remoteAddr != "" {
				request.RemoteAddr = test.remoteAddr
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var problem localProblem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.status || problem.Code != test.code {
				t.Fatalf("status=%d problem=%+v", response.Code, problem)
			}
			if response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("safety headers=%v", response.Header())
			}
		})
	}
}

func newHealthTestHandler(t *testing.T, dependencies HealthDependencies) stdhttp.Handler {
	t.Helper()
	handler, err := NewHealthHandler(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serveHealth(handler stdhttp.Handler, target string) *httptest.ResponseRecorder {
	request := newLocalHTTPRequest(stdhttp.MethodGet, target, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
