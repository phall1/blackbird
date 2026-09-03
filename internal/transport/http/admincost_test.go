package http

import (
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/application/telemetry"
)

type stubCostReader struct {
	report telemetry.CostReport
	err    error
	query  telemetry.AdminCostQuery
}

func (reader *stubCostReader) AdminCostReport(_ context.Context,
	query telemetry.AdminCostQuery) (telemetry.CostReport, error) {
	reader.query = query
	return reader.report, reader.err
}

func adminCostHandler(t *testing.T, cost telemetry.CostAdminReader) stdhttp.Handler {
	t.Helper()
	handler, err := NewAdminHandler(AdminDependencies{Admin: &stubAdminStore{},
		Token: NewAdminTokenDigest(adminTestToken), Cost: cost})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func getAdminCost(t *testing.T, handler stdhttp.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := newLocalHTTPRequest(stdhttp.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer "+adminTestToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// TestAdminCostRouteRequiresAProject is the scope decision this route exists to
// make explicitly. The agent-facing query carries no project BY CONSTRUCTION --
// an agent reads the workspace it authenticated into or nothing -- so naming
// one is a deliberate choice made here, where the credential is the loopback
// admin token. There is no "every project" reading: contention only exists
// between agents that could have collided.
func TestAdminCostRouteRequiresAProject(t *testing.T) {
	t.Parallel()
	handler := adminCostHandler(t, &stubCostReader{})
	if response := getAdminCost(t, handler, PathLocalAdminCost); response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status=%d for a cost request naming no project, want 400", response.Code)
	}
}

// TestAdminCostRouteReportsAMissingCapabilityRatherThanAnEmptyReport is the
// distinction the whole plane is built on. A daemon composed without an
// observation reader has NO answer; answering with a report of zeros would say
// this project cost nothing, which is a claim about the project rather than
// about the daemon, and the two call for opposite responses.
func TestAdminCostRouteReportsAMissingCapabilityRatherThanAnEmptyReport(t *testing.T) {
	t.Parallel()
	handler := adminCostHandler(t, nil)
	response := getAdminCost(t, handler, PathLocalAdminCost+"?project_key=/repo")
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatalf("status=%d without an observation reader, want 503 rather than an empty report: %s",
			response.Code, response.Body.String())
	}
}

// TestAdminCostRouteProjectsTheWindowAndTheLoss covers the two things a reader
// of this payload has to be able to trust: the window it names, and whether the
// contention counts inside it are complete.
func TestAdminCostRouteProjectsTheWindowAndTheLoss(t *testing.T) {
	t.Parallel()
	reader := &stubCostReader{report: telemetry.CostReport{
		Recording:  telemetry.RecordingHealth{Dropped: 3, Written: 90},
		Contention: telemetry.ContentionCost{Refusals: 4, PathWaits: 1},
	}}
	handler := adminCostHandler(t, reader)
	response := getAdminCost(t, handler, PathLocalAdminCost+"?project_key=/repo&since_hours=6&limit=5")
	if response.Code != stdhttp.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if reader.query.ProjectKey != "/repo" || reader.query.Limit != 5 {
		t.Fatalf("query=%+v, want the project and limit from the request", reader.query)
	}
	if reader.query.Since.IsZero() {
		t.Fatal("since_hours was accepted but produced no window start")
	}
	var payload adminapi.CostReport
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Recording == nil || payload.Recording.Dropped != 3 {
		t.Fatalf("recording=%+v, want the loss carried so the counts read as floors", payload.Recording)
	}
	if payload.Contention == nil || payload.Contention.Refusals != 4 {
		t.Fatalf("contention=%+v, want the observed section", payload.Contention)
	}
	// Abandonment and cache observed nothing, so both are absent and named.
	if payload.Abandonment != nil || payload.Cache != nil {
		t.Fatal("an unobserved section rendered as a struct of zeros")
	}
	named := map[string]bool{}
	for _, section := range payload.Unobserved {
		named[section] = true
	}
	if !named["abandonment"] || !named["cache"] {
		t.Fatalf("unobserved=%v, want both empty sections named", payload.Unobserved)
	}
}

// TestAdminCostRouteRejectsAnUnusableWindow keeps a malformed lookback from
// being silently treated as the default. A window nobody asked for is worse
// than an error, because the report still prints a Since the caller did not
// choose.
func TestAdminCostRouteRejectsAnUnusableWindow(t *testing.T) {
	t.Parallel()
	handler := adminCostHandler(t, &stubCostReader{})
	for _, target := range []string{
		PathLocalAdminCost + "?project_key=/repo&since_hours=0",
		PathLocalAdminCost + "?project_key=/repo&since_hours=soon",
		PathLocalAdminCost + "?project_key=/repo&bogus=1",
	} {
		if response := getAdminCost(t, handler, target); response.Code != stdhttp.StatusBadRequest {
			t.Fatalf("status=%d for %s, want 400", response.Code, target)
		}
	}
}
