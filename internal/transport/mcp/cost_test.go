package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

func callStatus(t *testing.T, client *sdkmcp.ClientSession, input map[string]any) statusOutput {
	t.Helper()
	result, err := client.CallTool(context.Background(),
		&sdkmcp.CallToolParams{Name: ToolStatus, Arguments: input})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("status failed: %+v", result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var status statusOutput
	if err := json.Unmarshal(encoded, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

// costContention drives one real refusal: the holder takes a subtree, and the
// blocked agent's exact claim inside it is denied. Nothing is written into the
// journal by hand, so what the tool reports is what the product recorded.
func costContention(t *testing.T, store *sqlite.Store, project string) string {
	t.Helper()
	ctx := context.Background()
	holder, _, err := store.RegisterLocalAgent(ctx, project, "holder", "")
	if err != nil {
		t.Fatal(err)
	}
	blocked, token, err := store.RegisterLocalAgent(ctx, project, "blocked", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(ctx, coordination.AcquireLeaseParams{LeaseID: newLeaseID(t),
		WorkspaceID: holder.WorkspaceID, Holder: holder.ActorID, HolderSession: holder.ActorSessionID,
		AuthorityEpoch: holder.AuthorityEpoch, Mode: coordination.LeaseExclusive,
		Selectors: []coordination.LeaseSelector{leaseSelector(t, coordination.LeaseSelectorSubtree,
			"internal/storage")}, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(ctx, coordination.AcquireLeaseParams{LeaseID: newLeaseID(t),
		WorkspaceID: blocked.WorkspaceID, Holder: blocked.ActorID, HolderSession: blocked.ActorSessionID,
		AuthorityEpoch: blocked.AuthorityEpoch, Mode: coordination.LeaseExclusive,
		Selectors: []coordination.LeaseSelector{leaseSelector(t, coordination.LeaseSelectorExact,
			"internal/storage/sqlite/cost.go")}, TTL: time.Hour}); err == nil {
		t.Fatal("the conflicting claim succeeded; the fixture records no refusal")
	}
	return token
}

// awaitContention polls until the refusal has landed in the journal.
//
// This is not test flakiness being papered over -- it is the recorder's design
// showing through. A refusal is decided inside the transaction that is about to
// roll back, so it cannot ride that transaction and is instead queued and
// written by a PACED drain: recording a denial synchronously would put an fsync
// on the claim path, and a retry storm is exactly when that would hurt most. So
// a fact is durable within a coalesce window rather than immediately, and every
// reader of this surface -- including an agent calling status the instant it
// was refused -- has to tolerate that. The tool schema says so.
func awaitContention(t *testing.T, client *sdkmcp.ClientSession, token string) *costReportOutput {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status := callStatus(t, client, map[string]any{"agent_token": token, "cost": true})
		if status.CostReport == nil {
			t.Fatal("status omitted the requested cost report")
		}
		if status.CostReport.Contention != nil {
			return status.CostReport
		}
		if time.Now().After(deadline) {
			t.Fatalf("contention never landed, unobserved=%v", status.CostReport.Unobserved)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCostReportStaysOnTheEightToolSurface is the same rule the spend rollup
// follows. Every tool costs every session a slice of its context on every turn,
// so a new question is answered by a parameter on blackbird_status rather than
// by a ninth tool.
func TestCostReportStaysOnTheEightToolSurface(t *testing.T) {
	t.Parallel()
	store := spendStore(t)
	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	tools := listedTools(t, server)
	if !tools[ToolStatus] || len(tools) != 8 {
		t.Fatalf("tools=%v, want cost folded into the eight-tool status surface", tools)
	}
}

// TestCostReportNamesTheHolderSelectorAndTheLeaseBehindIt is what makes the
// agent surface worth its context. A refused agent already knows it was
// refused; what it cannot otherwise learn is WHICH claim is in the way and of
// what kind, which is the difference between retrying and narrowing a selector.
func TestCostReportNamesTheHolderSelectorAndTheLeaseBehindIt(t *testing.T) {
	t.Parallel()
	store := spendStore(t)
	token := costContention(t, store, "/workspace/mcp-cost")
	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	report := awaitContention(t, client, token)
	if report.Contention.Refusals != 1 {
		t.Fatalf("refusals=%d, want the one denied claim", report.Contention.Refusals)
	}
	if len(report.Contention.Paths) != 1 {
		t.Fatalf("paths=%+v, want the contended path named", report.Contention.Paths)
	}
	path := report.Contention.Paths[0]
	if path.Path != "internal/storage" || path.Kind != string(coordination.LeaseSelectorSubtree) {
		t.Fatalf("path=%+v, want the holder's subtree selector, which is the one to narrow", path)
	}
}

// TestCostReportMarksAnEmptyWindowUnobservedRatherThanZero is the discipline
// the whole plane is held to. A section of zeros reads as "nothing is wrong";
// an absent section named in unobserved reads as "this daemon has no answer",
// and only the second is true when nothing was collected.
func TestCostReportMarksAnEmptyWindowUnobservedRatherThanZero(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := spendStore(t)
	_, token, err := store.RegisterLocalAgent(ctx, "/workspace/mcp-cost-empty", "alone", "")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	status := callStatus(t, client, map[string]any{"agent_token": token, "cost": true})
	if status.CostReport == nil {
		t.Fatal("status omitted the requested cost report")
	}
	if status.CostReport.Contention != nil || status.CostReport.Abandonment != nil {
		t.Fatal("an empty window produced a section of zeros; want the sections absent")
	}
	unobserved := map[string]bool{}
	for _, section := range status.CostReport.Unobserved {
		unobserved[section] = true
	}
	if !unobserved["contention"] || !unobserved["abandonment"] {
		t.Fatalf("unobserved=%v, want both empty sections named so absence cannot read as zero",
			status.CostReport.Unobserved)
	}
}

// TestStatusWithoutCostCarriesNoCostReport keeps the surface honest about its
// context budget: an agent that did not ask what contention cost must not pay
// for the answer on every status call.
func TestStatusWithoutCostCarriesNoCostReport(t *testing.T) {
	t.Parallel()
	store := spendStore(t)
	token := costContention(t, store, "/workspace/mcp-cost-optout")
	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	status := callStatus(t, client, map[string]any{"agent_token": token})
	if status.CostReport != nil {
		t.Fatal("status carried a cost report nobody asked for")
	}
}

// TestCostReportRequiresAnObservationReader keeps a daemon that collects
// nothing from advertising an answer it cannot give. The failure names the
// missing dependency rather than returning an empty report, which would be
// indistinguishable from an uncontended project.
func TestCostReportRequiresAnObservationReader(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := spendStore(t)
	_, token, err := store.RegisterLocalAgent(ctx, "/workspace/mcp-cost-noreader", "alone", "")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Dependencies{Coordination: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	result, err := client.CallTool(ctx, &sdkmcp.CallToolParams{Name: ToolStatus,
		Arguments: map[string]any{"agent_token": token, "cost": true}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("cost answered without an observation reader composed")
	}
}

// TestCostReportSurfacesTheAbandonedLeaseAndWhatItRefused is the other half of
// what an agent can act on. A lease whose holder walked away keeps refusing
// people until its deadline, and the agent being refused cannot see that from
// its own side: it sees a conflict, not that the conflict is a corpse. The
// report names the lease, its holder, and the refusals it actually caused, so
// the response is to message that holder rather than to keep retrying.
func TestCostReportSurfacesTheAbandonedLeaseAndWhatItRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := spendStore(t)
	const project = "/workspace/mcp-cost-abandoned"
	holder, _, err := store.RegisterLocalAgent(ctx, project, "walker", "")
	if err != nil {
		t.Fatal(err)
	}
	blocked, token, err := store.RegisterLocalAgent(ctx, project, "blocked", "")
	if err != nil {
		t.Fatal(err)
	}
	// A short TTL rather than a doctored row: the lease genuinely reaches its
	// deadline unreleased, which is the state the shared classification calls
	// abandoned however the expiry reaper later rewrites its status.
	const ttl = 300 * time.Millisecond
	if _, err := store.AcquireLease(ctx, coordination.AcquireLeaseParams{LeaseID: newLeaseID(t),
		WorkspaceID: holder.WorkspaceID, Holder: holder.ActorID, HolderSession: holder.ActorSessionID,
		AuthorityEpoch: holder.AuthorityEpoch, Mode: coordination.LeaseExclusive,
		Selectors: []coordination.LeaseSelector{leaseSelector(t, coordination.LeaseSelectorSubtree,
			"internal/storage")}, TTL: ttl}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(ctx, coordination.AcquireLeaseParams{LeaseID: newLeaseID(t),
		WorkspaceID: blocked.WorkspaceID, Holder: blocked.ActorID, HolderSession: blocked.ActorSessionID,
		AuthorityEpoch: blocked.AuthorityEpoch, Mode: coordination.LeaseExclusive,
		Selectors: []coordination.LeaseSelector{leaseSelector(t, coordination.LeaseSelectorExact,
			"internal/storage/sqlite/cost.go")}, TTL: time.Hour}); err == nil {
		t.Fatal("the conflicting claim succeeded; the fixture records no refusal")
	}

	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	// Two independent clocks have to pass before the assertion holds: the
	// lease's deadline, and the paced drain that writes the refusal. Polling
	// waits for both rather than guessing at either.
	deadline := time.Now().Add(10 * time.Second)
	var report *costReportOutput
	for {
		status := callStatus(t, client, map[string]any{"agent_token": token, "cost": true})
		if status.CostReport != nil && status.CostReport.Abandonment != nil &&
			status.CostReport.Abandonment.RefusalsDuring > 0 {
			report = status.CostReport
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("abandonment never landed: %+v", status.CostReport)
		}
		time.Sleep(20 * time.Millisecond)
	}

	abandonment := report.Abandonment
	if abandonment.Abandoned != 1 {
		t.Fatalf("abandoned=%d, want the lease that lapsed unreleased", abandonment.Abandoned)
	}
	if len(abandonment.Leases) != 1 {
		t.Fatalf("leases=%+v, want the one offender named", abandonment.Leases)
	}
	offender := abandonment.Leases[0]
	if offender.Holder != "walker" {
		t.Fatalf("holder=%q, want the agent to open a conversation with", offender.Holder)
	}
	if offender.Refusals != 1 || offender.BlockedAgents != 1 {
		t.Fatalf("offender=%+v, want the refusal it caused attributed to it", offender)
	}
	if offender.ContendedPath != "internal/storage" {
		t.Fatalf("contended path=%q, want the selector that actually collided", offender.ContendedPath)
	}
	if offender.Mode != string(coordination.LeaseExclusive) {
		t.Fatalf("mode=%q, want exclusive", offender.Mode)
	}
}

func newLeaseID(t *testing.T) domain.LeaseID {
	t.Helper()
	id, err := domain.NewLeaseID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func leaseSelector(t *testing.T, kind coordination.LeaseSelectorKind, path string) coordination.LeaseSelector {
	t.Helper()
	selector, err := coordination.NewLeaseSelector(kind, path)
	if err != nil {
		t.Fatal(err)
	}
	return selector
}

// TestCostReportStatesItsScopeSoTheTwoRefusalCountsAreNotCompared is the fix
// for the one payload shape a reader can get badly wrong.
//
// contention.refusals and abandonment.refusals_caused are both refusal counts
// and they do not share a scope: under mine_only the first narrows to the
// caller and the second stays project-wide, deliberately, because a lease
// someone else abandoned is what the caller cannot see from its own side.
// Their ratio can therefore exceed one and means nothing, so the payload names
// the scope rather than leaving it to be inferred.
func TestCostReportStatesItsScopeSoTheTwoRefusalCountsAreNotCompared(t *testing.T) {
	t.Parallel()
	store := spendStore(t)
	token := costContention(t, store, "/workspace/mcp-cost-scope")
	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	project := awaitContention(t, client, token)
	if project.Scope != "project" {
		t.Fatalf("scope=%q for an unnarrowed report, want project", project.Scope)
	}
	status := callStatus(t, client, map[string]any{"agent_token": token, "cost": true, "mine_only": true})
	if status.CostReport == nil {
		t.Fatal("status omitted the requested cost report")
	}
	if status.CostReport.Scope != "you" {
		t.Fatalf("scope=%q for a narrowed report, want you", status.CostReport.Scope)
	}
}

// TestCostReportCarriesEveryWaitEndReason keeps the agent surface from showing
// a breakdown that does not add up. free plus deadline falling short of
// path_waits, with no other bucket to explain it, invites the reader to assume
// the remainder timed out -- which invents abandonments that never happened.
func TestCostReportCarriesEveryWaitEndReason(t *testing.T) {
	t.Parallel()
	store := spendStore(t)
	token := costContention(t, store, "/workspace/mcp-cost-reasons")
	server, err := NewServer(Dependencies{Coordination: store, Observations: store})
	if err != nil {
		t.Fatal(err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()
	report := awaitContention(t, client, token)

	encoded, marshalErr := json.Marshal(report.Contention)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"waits_ended_free", "waits_ended_mail", "waits_ended_deadline",
		"waits_ended_abandoned", "waits_ended_stopped", "waits_ended_unknown"} {
		if _, ok := fields[reason]; !ok {
			t.Fatalf("the agent-facing contention payload omits %s, so its buckets cannot sum "+
				"to path_waits + mail_waits: %v", reason, fields)
		}
	}
}
