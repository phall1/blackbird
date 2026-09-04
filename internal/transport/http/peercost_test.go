package http

import (
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

func peerCostHandlerFor(t *testing.T, dependencies PeerCostDependencies) stdhttp.Handler {
	t.Helper()
	handler, err := NewPeerCostHandler(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

// verifiedPeerRequest is a request the guard already admitted. Building it here
// rather than running the guard keeps these assertions about the route, and the
// admission itself is asserted in peer_test.go.
func verifiedPeerRequest(target string) *stdhttp.Request {
	request := peerRequest(stdhttp.MethodGet, target)
	return request.WithContext(context.WithValue(request.Context(), peerAdmissionKey{}, theMini()))
}

func servePeerCost(handler stdhttp.Handler, request *stdhttp.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// TestPeerCostServesAVerifiedPeerTheOperatorProjection is the feature working,
// and the assertion that matters is the SHAPE: the peer receives the sections
// the admin route projects, computed by the same reader, so a fleet view and a
// local report cannot disagree about what this host cost.
func TestPeerCostServesAVerifiedPeerTheOperatorProjection(t *testing.T) {
	t.Parallel()

	reader := &stubCostReader{report: telemetry.CostReport{
		Since: time.Unix(1000, 0).UTC(), Until: time.Unix(2000, 0).UTC(),
		Cache: telemetry.CacheEconomics{Models: []telemetry.ModelCacheEconomics{
			{Model: "opus", Calls: 3, UncachedInput: 10, CacheRead: 90, CacheWrite: 5, Output: 7},
		}},
	}}
	handler := peerCostHandlerFor(t, PeerCostDependencies{Cost: reader})
	response := servePeerCost(handler, verifiedPeerRequest(PathLocalPeerCost+"?project_key=/repo&limit=5&since_hours=2"))
	if response.Code != stdhttp.StatusOK {
		t.Fatalf("status=%d, want 200: %s", response.Code, response.Body.String())
	}
	var payload adminapi.CostReport
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ProjectKey != "/repo" {
		t.Fatalf("project_key=%q, want /repo", payload.ProjectKey)
	}
	if payload.Cache == nil || len(payload.Cache.Models) != 1 || payload.Cache.Models[0].CacheRead != 90 {
		t.Fatalf("cache section did not survive the projection: %+v", payload.Cache)
	}
	// An unobserved section is named rather than rendered as zeros, exactly as
	// the operator's own report does it.
	if len(payload.Unobserved) != 2 || payload.Contention != nil || payload.Abandonment != nil {
		t.Fatalf("unobserved sections = %v, contention=%v abandonment=%v; want both absent and named",
			payload.Unobserved, payload.Contention, payload.Abandonment)
	}
	if reader.query.ProjectKey != "/repo" || reader.query.Limit != 5 {
		t.Fatalf("query reached the reader as %+v", reader.query)
	}
	if reader.query.Since.IsZero() {
		t.Fatal("since_hours did not reach the reader")
	}
}

// TestPeerCostRefusesALoopbackCaller is the privilege boundary. The operator's
// cost report is behind the admin token; if this route also answered locally,
// any process on this machine would have an unauthenticated way to read what
// that token gates.
func TestPeerCostRefusesALoopbackCaller(t *testing.T) {
	t.Parallel()

	handler := peerCostHandlerFor(t, PeerCostDependencies{Cost: &stubCostReader{}})
	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalPeerCost+"?project_key=/repo", nil)
	response := servePeerCost(handler, request)
	if response.Code != stdhttp.StatusForbidden {
		t.Fatalf("status=%d for a loopback caller, want 403: %s", response.Code, response.Body.String())
	}
}

// TestPeerCostWithoutAReaderReportsTheMissingCapability keeps a composition
// fact from being read as a fleet fact. An empty report here would say this
// host spent nothing, and a fleet total built on it would be quietly short.
func TestPeerCostWithoutAReaderReportsTheMissingCapability(t *testing.T) {
	t.Parallel()

	handler := peerCostHandlerFor(t, PeerCostDependencies{})
	response := servePeerCost(handler, verifiedPeerRequest(PathLocalPeerCost+"?project_key=/repo"))
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatalf("status=%d without a reader, want 503: %s", response.Code, response.Body.String())
	}
	var problem localProblem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != domain.ErrorCodeDependencyUnavailable {
		t.Fatalf("code=%s, want %s", problem.Code, domain.ErrorCodeDependencyUnavailable)
	}
}

// TestPeerCostRequiresAProject repeats the admin route's scope decision. There
// is no "every project" reading over a host boundary either: a report summed
// across projects adds contention between agents that could never have collided.
func TestPeerCostRequiresAProject(t *testing.T) {
	t.Parallel()

	handler := peerCostHandlerFor(t, PeerCostDependencies{Cost: &stubCostReader{}})
	response := servePeerCost(handler, verifiedPeerRequest(PathLocalPeerCost))
	if response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status=%d for a request naming no project, want 400", response.Code)
	}
}

// TestPeerCostRejectsUnknownQueryParameters keeps the peer surface as narrow as
// the admin one. A parameter this route does not implement must be a refusal
// rather than a silently different report.
func TestPeerCostRejectsUnknownQueryParameters(t *testing.T) {
	t.Parallel()

	handler := peerCostHandlerFor(t, PeerCostDependencies{Cost: &stubCostReader{}})
	for _, target := range []string{
		PathLocalPeerCost + "?project_key=/repo&mine_only=true",
		PathLocalPeerCost + "?project_key=/repo&access_token=secret",
		PathLocalPeerCost + "?project_key=/repo&limit=0",
	} {
		if response := servePeerCost(handler, verifiedPeerRequest(target)); response.Code != stdhttp.StatusBadRequest {
			t.Errorf("status=%d for %s, want 400", response.Code, target)
		}
	}
}

// blockingCostReader parks inside the report so a test can hold connections the
// way a slow or hostile peer would.
type blockingCostReader struct {
	entered chan struct{}
	release chan struct{}
}

func (reader *blockingCostReader) AdminCostReport(ctx context.Context,
	_ telemetry.AdminCostQuery) (telemetry.CostReport, error) {
	reader.entered <- struct{}{}
	select {
	case <-reader.release:
	case <-ctx.Done():
		return telemetry.CostReport{}, ctx.Err()
	}
	return telemetry.CostReport{}, nil
}

// TestPeerCostRefusesRatherThanExhaustingTheReadPool is the bound that makes
// accepting a peer safe at all. Each report holds a connection from a small
// read pool, so an unbounded route would let one peer stall every agent on THIS
// machine. The excess is refused immediately -- not queued, because a queued
// peer holds a slot here and still gets a slow answer.
func TestPeerCostRefusesRatherThanExhaustingTheReadPool(t *testing.T) {
	t.Parallel()

	reader := &blockingCostReader{entered: make(chan struct{}, 8), release: make(chan struct{})}
	handler := peerCostHandlerFor(t, PeerCostDependencies{Cost: reader, MaxInflight: 2})

	var running sync.WaitGroup
	for range 2 {
		running.Add(1)
		go func() {
			defer running.Done()
			servePeerCost(handler, verifiedPeerRequest(PathLocalPeerCost+"?project_key=/repo"))
		}()
	}
	for range 2 {
		select {
		case <-reader.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the first two reports never started")
		}
	}

	response := servePeerCost(handler, verifiedPeerRequest(PathLocalPeerCost+"?project_key=/repo"))
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatalf("status=%d for the third concurrent report, want 503", response.Code)
	}
	var problem localProblem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != domain.ErrorCodeBackpressure {
		t.Fatalf("code=%s, want %s so a caller can tell a busy host from a broken one",
			problem.Code, domain.ErrorCodeBackpressure)
	}
	if response.Header().Get("Retry-After") == "" {
		t.Error("a refusal for concurrency must tell the caller to come back")
	}

	close(reader.release)
	running.Wait()

	// The bound releases: once the reports finish, the next peer is served.
	if response := servePeerCost(handler, verifiedPeerRequest(PathLocalPeerCost+"?project_key=/repo")); response.Code != stdhttp.StatusOK {
		t.Fatalf("status=%d after the inflight reports drained, want 200", response.Code)
	}
}

// TestPeerCostBoundsOneReport proves the deadline is real. A report that never
// returns must not pin a read connection until the client happens to give up.
func TestPeerCostBoundsOneReport(t *testing.T) {
	t.Parallel()

	reader := &blockingCostReader{entered: make(chan struct{}, 1), release: make(chan struct{})}
	handler := peerCostHandlerFor(t, PeerCostDependencies{Cost: reader, Timeout: 20 * time.Millisecond})
	done := make(chan int, 1)
	go func() {
		done <- servePeerCost(handler, verifiedPeerRequest(PathLocalPeerCost+"?project_key=/repo")).Code
	}()
	select {
	case status := <-done:
		if status == stdhttp.StatusOK {
			t.Fatalf("status=%d, want a failure once the report outlived its deadline", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the report outlived its own timeout")
	}
	close(reader.release)
}

// TestPeerCostRefusesNegativeBounds keeps "unbounded" from being spelled with a
// negative number in a composition root.
func TestPeerCostRefusesNegativeBounds(t *testing.T) {
	t.Parallel()

	if _, err := NewPeerCostHandler(PeerCostDependencies{MaxInflight: -1}); err == nil {
		t.Fatal("a negative inflight bound composed without complaint")
	}
	if _, err := NewPeerCostHandler(PeerCostDependencies{Timeout: -time.Second}); err == nil {
		t.Fatal("a negative timeout composed without complaint")
	}
}
