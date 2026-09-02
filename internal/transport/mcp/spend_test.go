package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

func spendStore(t *testing.T) *sqlite.Store {
	t.Helper()
	store, err := sqlite.Open(context.Background(), sqlite.Config{
		Path: filepath.Join(t.TempDir(), "spend.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func listedTools(t *testing.T, server *Server) map[string]bool {
	t.Helper()
	client, closeMCP := connect(t, server)
	defer closeMCP()
	tools, err := client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	listed := make(map[string]bool, len(tools.Tools))
	for _, tool := range tools.Tools {
		listed[tool.Name] = true
	}
	return listed
}

// A daemon that collects nothing must not spend every client's tool-list budget
// advertising a report it can only answer with zeros.
func TestSpendToolIsAbsentWithoutAnObservationReader(t *testing.T) {
	t.Parallel()
	server, err := NewServer(Dependencies{Coordination: spendStore(t)})
	if err != nil {
		t.Fatal(err)
	}
	if listedTools(t, server)[ToolSpendReport] {
		t.Fatal("the spend tool must not be listed when no reader is composed")
	}
}

func TestSpendToolIsListedWhenAReaderIsComposed(t *testing.T) {
	t.Parallel()
	store := spendStore(t)
	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	if !listedTools(t, server)[ToolSpendReport] {
		t.Fatal("the spend tool must be listed once a reader is composed")
	}
}

func callSpend(t *testing.T, client *sdkmcp.ClientSession, input map[string]any) spendReportOutput {
	t.Helper()
	result, err := client.CallTool(context.Background(),
		&sdkmcp.CallToolParams{Name: ToolSpendReport, Arguments: input})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("spend report failed: %+v", result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var report spendReportOutput
	if err := json.Unmarshal(encoded, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestSpendToolReportsTokensAndDefaultsToModel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := spendStore(t)
	session, token, err := store.RegisterLocalAgent(ctx, "/workspace/spend", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.AppendTelemetry(ctx, []application.TelemetryEnvelope{{
		Attribution: application.TelemetryAttribution{
			ProjectKey: session.ProjectKey, ActorID: session.ActorID, SessionID: session.ActorSessionID,
		},
		ModelCalls: []domain.ModelCall{{
			DedupeKey: "a", Harness: domain.HarnessClaudeCode, Provider: "anthropic",
			Model: "claude-opus-5", Operation: domain.ModelOperationChat,
			Usage:     domain.TokenUsage{UncachedInput: 2, CacheRead: 26354, CacheWrite: 23947, Output: 1469},
			Outcome:   domain.ObservedOutcomeOK,
			StartedAt: now,
		}},
		ReceivedAt: now,
	}}); err != nil {
		t.Fatal(err)
	}

	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	report := callSpend(t, client, map[string]any{"agent_token": token})
	if report.Dimension != string(application.SpendByModel) {
		t.Fatalf("dimension=%q, want the model default", report.Dimension)
	}
	if len(report.Groups) != 1 || report.Groups[0].Key != "claude-opus-5" {
		t.Fatalf("groups=%+v", report.Groups)
	}
	group := report.Groups[0]
	// billed_input is the derived headline: what a provider actually invoices.
	if group.BilledInput != 50303 {
		t.Fatalf("billed_input=%d, want the three input classes summed", group.BilledInput)
	}
	if group.UncachedInput != 2 || group.CacheRead != 26354 || group.CacheWrite != 23947 {
		t.Fatalf("classes=%+v, want them reported separately as well", group)
	}
	// This observation carried no duration, so nothing may claim it was fast.
	if group.MeasuredDurations != 0 || group.TotalDurationMS != 0 {
		t.Fatalf("durations=%+v, want an unmeasured call counted as unmeasured", group)
	}
}

func TestSpendToolRejectsAnUnknownDimension(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := spendStore(t)
	_, token, err := store.RegisterLocalAgent(ctx, "/workspace/spend", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	result, err := client.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: ToolSpendReport, Arguments: map[string]any{"agent_token": token, "dimension": "vibes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("an unknown dimension must be refused rather than silently defaulted")
	}
}

func TestSpendToolRequiresAValidAgentToken(t *testing.T) {
	t.Parallel()
	store := spendStore(t)
	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	result, err := client.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: ToolSpendReport, Arguments: map[string]any{"agent_token": "bbm_not_a_real_token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("spend is scoped by the caller's session, so an unauthenticated call must fail")
	}
}
