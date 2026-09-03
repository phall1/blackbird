package cli

import (
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/adminapi"
)

func costFloat(value float64) *float64 { return &value }

// runCost renders one cost report through the real command and returns what an
// operator would see. Anything the renderer drops is dropped here too, which is
// the point: the discipline these tests assert lives in the drawing, and a test
// that inspected the struct instead would pass over a renderer that printed
// none of it.
func runCost(t *testing.T, report adminapi.CostReport, args ...string) string {
	t.Helper()
	admin := &fakeAdmin{cost: report}
	deps := dependencies(t)
	deps.Admin = admin
	result := runCLI(t, deps, append([]string{"cost"}, args...))
	if result.code != ExitOK {
		t.Fatalf("cost exited %d; stderr=%q", result.code, result.stderr)
	}
	return result.stdout
}

// TestCostRendersAnUnobservedSectionAsAbsentRatherThanZero is the discipline
// the whole report is held to, at the last place it can be lost. A table of
// zeros reads as "nothing is wrong"; a named absence reads as "this daemon has
// no answer", and only the second is true when nothing was collected.
func TestCostRendersAnUnobservedSectionAsAbsentRatherThanZero(t *testing.T) {
	t.Parallel()
	output := runCost(t, adminapi.CostReport{
		ProjectKey: "/repo", Since: "2026-09-03T00:00:00Z", Until: "2026-09-03T01:00:00Z",
		Unobserved: []string{"contention", "abandonment", "cache"},
	}, "/repo")
	if strings.Contains(output, "REFUSALS") {
		t.Fatalf("an unobserved section rendered its table:\n%s", output)
	}
	for _, section := range []string{"contention", "abandonment", "cache"} {
		if !strings.Contains(output, "No "+section+" was recorded") {
			t.Fatalf("output does not name %q as unobserved:\n%s", section, output)
		}
	}
	if !strings.Contains(output, "unknown, not zero") {
		t.Fatalf("output does not say an absent section is unknown rather than zero:\n%s", output)
	}
}

// TestCostStatesTheRecordersLossBeforeTheNumbersItAffects is the finding this
// surface exists to avoid repeating. The contention recorder drops rather than
// blocks, and it drops hardest during a retry storm -- so a refusal total can be
// built from a decimated sample. The operator has to be told before reading it.
func TestCostStatesTheRecordersLossBeforeTheNumbersItAffects(t *testing.T) {
	t.Parallel()
	output := runCost(t, adminapi.CostReport{
		ProjectKey: "/repo", Since: "2026-09-03T00:00:00Z", Until: "2026-09-03T01:00:00Z",
		Recording:  &adminapi.CostRecording{Dropped: 41, Written: 900},
		Contention: &adminapi.CostContention{Refusals: 12},
	}, "/repo")
	if !strings.Contains(output, "FLOOR") {
		t.Fatalf("a lossy report does not say its counts are floors:\n%s", output)
	}
	if !strings.Contains(output, "41") {
		t.Fatalf("a lossy report does not say how much was dropped:\n%s", output)
	}
	loss := strings.Index(output, "FLOOR")
	refusals := strings.Index(output, "refusals")
	if loss < 0 || refusals < 0 || loss > refusals {
		t.Fatalf("the loss is stated after the numbers it qualifies:\n%s", output)
	}
}

// TestCostPrintsNoRatioWhereThereIsNoDenominator keeps the cache section from
// answering a question it has no answer to. A model that wrote no cache has NO
// reuse ratio; printing 0.00 would report caching as failing when the truth is
// that it was never used, and those call for opposite responses.
func TestCostPrintsNoRatioWhereThereIsNoDenominator(t *testing.T) {
	t.Parallel()
	output := runCost(t, adminapi.CostReport{
		ProjectKey: "/repo", Since: "2026-09-03T00:00:00Z", Until: "2026-09-03T01:00:00Z",
		Cache: &adminapi.CostCache{Models: []adminapi.CostModel{
			{Model: "no-cache", Calls: 3, UncachedInput: 100, Output: 20},
			{Model: "warm", Calls: 5, UncachedInput: 10, CacheRead: 900, CacheWrite: 90,
				Output: 30, CacheReadShare: costFloat(0.9), CacheReuse: costFloat(10)},
		}},
	}, "/repo")
	if !strings.Contains(output, "10.00") {
		t.Fatalf("a real reuse ratio was not printed:\n%s", output)
	}
	// The row for the model that never wrote a cache must carry dashes in both
	// ratio columns. A substring search over the whole page would be satisfied
	// by the OTHER row's "10.00", so this reads the row that is under test.
	var uncached string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "no-cache") {
			uncached = line
		}
	}
	if uncached == "" {
		t.Fatalf("the model with no cache is missing from the table:\n%s", output)
	}
	if cells := strings.Fields(uncached); len(cells) < 2 ||
		cells[len(cells)-1] != "-" || cells[len(cells)-2] != "-" {
		t.Fatalf("a model that wrote no cache reported a ratio instead of no answer: %q", uncached)
	}
	if !strings.Contains(output, "never priced") {
		t.Fatalf("the cache table does not say why it carries no money:\n%s", output)
	}
}

// TestCostSendsTheProjectAndWindowItWasAsked keeps the flags wired to the
// query rather than merely accepted.
func TestCostSendsTheProjectAndWindowItWasAsked(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{cost: adminapi.CostReport{ProjectKey: "/repo"}}
	deps := dependencies(t)
	deps.Admin = admin
	if result := runCLI(t, deps, []string{"cost", "/repo", "--since-hours", "48", "--limit", "7"}); result.code != ExitOK {
		t.Fatalf("cost exited %d; stderr=%q", result.code, result.stderr)
	}
	if admin.costQuery.ProjectKey != "/repo" {
		t.Fatalf("project=%q, want the one named on the command line", admin.costQuery.ProjectKey)
	}
	if admin.costQuery.SinceHours != 48 || admin.costQuery.Limit != 7 {
		t.Fatalf("query=%+v, want the window and limit given", admin.costQuery)
	}
}

// TestCostDrawsTheOperatorOnlySections renders the two cuts the AGENT surface
// deliberately omits, which is the whole reason this command exists.
//
// The per-agent table puts contention beside spend so a human can see which
// agent to give a worktree or a narrower scope; the abandoned-lease table names
// the holder to talk to. Both are scheduling decisions about other agents,
// which is why an agent's own tool response does not carry them and why they
// have to be drawn here.
func TestCostDrawsTheOperatorOnlySections(t *testing.T) {
	t.Parallel()
	output := runCost(t, adminapi.CostReport{
		ProjectKey: "/repo", Since: "2026-09-03T00:00:00Z", Until: "2026-09-03T01:00:00Z",
		Contention: &adminapi.CostContention{
			Refusals: 40, PathWaits: 2, WaitsEndedDeadline: 1, ParkedMS: 61000,
			LongestParkMS: 60000,
			Agents: []adminapi.CostBlockedAgent{
				{AgentName: "beta", ActorID: "actor-1", Refusals: 40, PathWaits: 2,
					WaitsEndedDeadline: 1, ParkedMS: 61000, ModelCalls: 12,
					BilledInput: 900000, Output: 4200},
				// The agent record is gone while its facts remain. The
				// contention still happened, so the row must stay.
				{ActorID: "actor-2", Refusals: 1},
			},
			Paths: []adminapi.CostPath{{Path: "internal/storage", Kind: "subtree",
				Refusals: 40, BlockedAgents: 1}},
			Truncated: true,
		},
		Abandonment: &adminapi.CostAbandonment{
			Abandoned: 2, Released: 1, AbandonedHeldMS: 7200000, ReleasedHeldMS: 5000,
			RefusalsDuring: 40,
			Leases: []adminapi.CostLease{{LeaseID: "lease-1", HolderAgent: "alpha",
				Mode: "exclusive", HeldMS: 3600000, Refusals: 40, BlockedAgents: 1,
				ContendedPath: "internal/storage"}},
		},
	}, "/repo")

	for _, want := range []string{
		"beta", "900000", "4200", // spend joined to contention
		"(deregistered)",      // the agent whose record is gone keeps its row
		"internal/storage",    // the holder selector to narrow
		"subtree",             // and its kind, which is the fixable part
		"alpha",               // the holder to talk to about the abandoned lease
		"refusals caused  40", // what the abandonment actually cost
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("operator output is missing %q:\n%s", want, output)
		}
	}
	// A cut list must say it was cut, or a reader treats the visible paths as
	// all of them.
	if !strings.Contains(output, "raise --limit") {
		t.Fatalf("a truncated list did not say so:\n%s", output)
	}
}
