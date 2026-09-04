package http

import (
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/application/telemetry"
)

type stubSpendReader struct {
	report telemetry.SpendReport
	err    error
	query  telemetry.AdminSpendQuery
}

func (reader *stubSpendReader) AdminSpendReport(_ context.Context,
	query telemetry.AdminSpendQuery) (telemetry.SpendReport, error) {
	reader.query = query
	return reader.report, reader.err
}

func adminSpendHandler(t *testing.T, spend telemetry.SpendAdminReader) stdhttp.Handler {
	t.Helper()
	handler, err := NewAdminHandler(AdminDependencies{Admin: &stubAdminStore{},
		Token: NewAdminTokenDigest(adminTestToken), Spend: spend})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func getAdminSpend(t *testing.T, handler stdhttp.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := newLocalHTTPRequest(stdhttp.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer "+adminTestToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// TestAdminSpendRouteRequiresAProject is the scope decision this route exists
// to make explicitly. The agent-facing query carries no project BY
// CONSTRUCTION -- an agent reads the workspace it authenticated into or
// nothing -- so naming one is a deliberate choice made here, where the
// credential is the loopback admin token. There is no "every project"
// reading: a rollup summed across projects would add spend by agents that
// never shared a workspace.
func TestAdminSpendRouteRequiresAProject(t *testing.T) {
	t.Parallel()
	handler := adminSpendHandler(t, &stubSpendReader{})
	target := PathLocalAdminSpend + "?dimension=model"
	if response := getAdminSpend(t, handler, target); response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status=%d for a spend request naming no project, want 400", response.Code)
	}
}

// TestAdminSpendRouteRequiresADimension keeps the grouping explicit: the same
// question grouped by model and grouped by agent answers different decisions,
// and a default would let a caller believe it asked one while reading the
// other.
func TestAdminSpendRouteRequiresADimension(t *testing.T) {
	t.Parallel()
	handler := adminSpendHandler(t, &stubSpendReader{})
	target := PathLocalAdminSpend + "?project_key=/workspace/x"
	if response := getAdminSpend(t, handler, target); response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status=%d for a spend request naming no dimension, want 400", response.Code)
	}
}

// TestAdminSpendRouteReportsAMissingCapabilityRatherThanAnEmptyReport is the
// distinction the whole plane is built on. A daemon composed without an
// observation reader cannot say "this project spent nothing" -- it can only
// say it cannot answer, and the difference decides whether a caller fixes its
// daemon or its budget.
func TestAdminSpendRouteReportsAMissingCapabilityRatherThanAnEmptyReport(t *testing.T) {
	t.Parallel()
	handler := adminSpendHandler(t, nil)
	target := PathLocalAdminSpend + "?project_key=/workspace/x&dimension=model"
	if response := getAdminSpend(t, handler, target); response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatalf("status=%d without an observation reader, want 503", response.Code)
	}
}

// TestAdminSpendRouteCarriesTheReportAcross projects the daemon's report onto
// the wire without recomputing it: totals cover the window rather than the
// returned groups, and truncation survives the trip.
func TestAdminSpendRouteCarriesTheReportAcross(t *testing.T) {
	t.Parallel()
	reader := &stubSpendReader{report: telemetry.SpendReport{
		Dimension: telemetry.SpendByModel,
		Since:     time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC),
		Until:     time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
		Totals:    telemetry.SpendGroup{Observations: 9, UncachedInput: 3, CacheRead: 90, CacheWrite: 6, Output: 12},
		Groups: []telemetry.SpendGroup{
			{Key: "claude-opus-5", Observations: 9, UncachedInput: 3, CacheRead: 90, CacheWrite: 6, Output: 12},
		},
		Truncated: true,
	}}
	handler := adminSpendHandler(t, reader)
	target := PathLocalAdminSpend + "?project_key=/workspace/x&dimension=model&since_hours=24"
	response := getAdminSpend(t, handler, target)
	if response.Code != stdhttp.StatusOK {
		t.Fatalf("status=%d, body=%s", response.Code, response.Body.String())
	}
	var payload adminapi.SpendReport
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ProjectKey != "/workspace/x" || payload.Dimension != "model" {
		t.Fatalf("scope=(%q, %q)", payload.ProjectKey, payload.Dimension)
	}
	if payload.Totals.Observations != 9 || payload.Totals.CacheRead != 90 || !payload.Truncated {
		t.Fatalf("payload=%+v, want the report carried across with its truncation", payload)
	}
	if len(payload.Groups) != 1 || payload.Groups[0].Key != "claude-opus-5" {
		t.Fatalf("groups=%+v", payload.Groups)
	}
}
