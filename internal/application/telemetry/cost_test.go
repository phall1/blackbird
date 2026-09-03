package telemetry

import (
	"errors"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
)

// TestCostQueryClampsToTheSameBoundsAsSpend keeps the two reports from
// disagreeing about how far back "recently" reaches. They are read side by side
// on the same surface, and a cost window that outran the spend window would let
// a reader compare contention over a month against tokens over a day without
// anything saying so.
func TestCostQueryClampsToTheSameBoundsAsSpend(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)

	defaulted := CostQuery{}.Normalized(now)
	if got, want := defaulted.Since, now.Add(-DefaultSpendWindow); !got.Equal(want) {
		t.Fatalf("since=%s, want the shared default window %s", got, want)
	}
	if defaulted.Limit != DefaultSpendGroups {
		t.Fatalf("limit=%d, want the shared default", defaulted.Limit)
	}

	ancient := CostQuery{Since: now.Add(-365 * 24 * time.Hour)}.Normalized(now)
	if got, want := ancient.Since, now.Add(-MaxSpendWindow); !got.Equal(want) {
		t.Fatalf("since=%s, want the scan clamped to %s", got, want)
	}

	greedy := CostQuery{Limit: MaxSpendGroups + 1}.Normalized(now)
	if greedy.Limit != DefaultSpendGroups {
		t.Fatalf("limit=%d, want an over-large ask reduced rather than honoured", greedy.Limit)
	}
}

// TestCostQueryValidateRejectsAnOversizedLimit keeps the transport from
// widening a bound the application owns. Normalized clamps, but a caller that
// skips it must still be refused rather than served an unbounded reply.
func TestCostQueryValidateRejectsAnOversizedLimit(t *testing.T) {
	t.Parallel()
	if err := (CostQuery{Limit: MaxSpendGroups + 1}).Validate(); !errors.Is(err, coordination.ErrInvalid) {
		t.Fatalf("Validate() = %v, want ErrInvalid", err)
	}
	if err := (CostQuery{Limit: MaxSpendGroups}).Validate(); err != nil {
		t.Fatalf("Validate() = %v, want the ceiling itself accepted", err)
	}
}

// TestObservedSeparatesAnEmptyWindowFromAQuietOne is the rule the whole report
// hangs on. Zero refusals in a window that recorded nothing is not the same
// claim as zero refusals in a window that recorded plenty, and a reader acting
// on the second when the first is true is acting on a collector outage.
func TestObservedSeparatesAnEmptyWindowFromAQuietOne(t *testing.T) {
	t.Parallel()
	if (ContentionCost{}).Observed() {
		t.Fatal("an empty contention section reports itself observed")
	}
	if !(ContentionCost{MailWaits: 1}).Observed() {
		t.Fatal("a recorded mail wait is an observation even though it is not contention")
	}
	if (AbandonmentCost{}).Observed() {
		t.Fatal("an empty abandonment section reports itself observed")
	}
	if !(AbandonmentCost{Released: 3}).Observed() {
		t.Fatal("clean releases are observations; without them the abandonment rate has no denominator")
	}
	if (CacheEconomics{}).Observed() {
		t.Fatal("an empty cache section reports itself observed")
	}
}

// TestCacheRatiosRefuseAZeroDenominator is the discipline this repository
// already holds for duration_ms, applied to a ratio. A model that wrote no
// cache has NO reuse figure; answering zero would read as "caching is failing"
// when the truth is that caching was never used, and those want opposite
// responses.
func TestCacheRatiosRefuseAZeroDenominator(t *testing.T) {
	t.Parallel()
	silent := ModelCacheEconomics{Model: "claude-haiku-4-5"}
	if _, ok := silent.CacheReuse(); ok {
		t.Fatal("CacheReuse() answered for a model that wrote no cache")
	}
	if _, ok := silent.CacheReadShare(); ok {
		t.Fatal("CacheReadShare() answered for a model that billed no input")
	}

	// The corpus shape this section exists for: cache reads one to two orders
	// of magnitude above uncached input. A report that summed the three input
	// classes would show 20100 and hide all of it.
	busy := ModelCacheEconomics{Model: "claude-opus-5", UncachedInput: 100, CacheRead: 18000, CacheWrite: 2000}
	if got, want := busy.BilledInput(), uint64(20100); got != want {
		t.Fatalf("billed=%d, want %d", got, want)
	}
	reuse, ok := busy.CacheReuse()
	if !ok || reuse != 9 {
		t.Fatalf("reuse=%v ok=%v, want nine reads per written token", reuse, ok)
	}
	share, ok := busy.CacheReadShare()
	if !ok || share < 0.89 || share > 0.90 {
		t.Fatalf("read share=%v ok=%v, want roughly 0.895 of billed input served from cache", share, ok)
	}
}

// TestCacheReuseBelowOneIsRepresentable guards the diagnostic rather than a
// number. A prefix rewritten about as often as it is read makes caching cost
// more than it saves, and the accessor has to be able to say so instead of
// bottoming out at one.
func TestCacheReuseBelowOneIsRepresentable(t *testing.T) {
	t.Parallel()
	churning := ModelCacheEconomics{CacheRead: 500, CacheWrite: 1000}
	reuse, ok := churning.CacheReuse()
	if !ok || reuse != 0.5 {
		t.Fatalf("reuse=%v ok=%v, want a sub-one ratio reported as such", reuse, ok)
	}
}

// TestRecordingHealthReportsALossOfAnyKind is the contract the whole contention
// half of this report leans on. Every count in ContentionCost is a measurement
// when this is false and a FLOOR when it is true, so a reader that cannot ask
// the question cannot know which it is holding.
func TestRecordingHealthReportsALossOfAnyKind(t *testing.T) {
	t.Parallel()
	clean := RecordingHealth{Offered: 100, Written: 100}
	if clean.Lossy() {
		t.Fatal("a recorder that lost nothing reports a loss")
	}
	lossy := RecordingHealth{Offered: 100, Written: 99, Dropped: 1}
	if !lossy.Lossy() {
		t.Fatal("a recorder that dropped a fact reports a complete sample")
	}
}

// TestWaitsAccountedCoversEveryEndReason makes the completeness claim on the
// six buckets checkable rather than aspirational. A reason added to WaitReason
// without a bucket added here breaks this equality instead of quietly leaking
// waits into a total nobody can explain.
func TestWaitsAccountedCoversEveryEndReason(t *testing.T) {
	t.Parallel()
	cost := ContentionCost{
		PathWaits: 15, MailWaits: 6,
		WaitsEndedFree: 1, WaitsEndedMail: 2, WaitsEndedDeadline: 3,
		WaitsEndedAbandoned: 4, WaitsEndedStopped: 5, WaitsEndedUnknown: 6,
	}
	if got, want := cost.WaitsAccounted(), cost.PathWaits+cost.MailWaits; got != want {
		t.Fatalf("WaitsAccounted()=%d, want %d", got, want)
	}
}

// TestAdminCostQueryRequiresAProject is the scope decision stated as a rule.
// The agent query carries no project by construction so an agent can only ever
// read its own workspace; the operator query names one and must refuse to run
// unscoped, because a cost report summed across projects adds contention
// between agents that could never have collided.
func TestAdminCostQueryRequiresAProject(t *testing.T) {
	t.Parallel()
	if err := (AdminCostQuery{}).Validate(); err == nil {
		t.Fatal("an admin cost query with no project validated")
	}
	if err := (AdminCostQuery{ProjectKey: "/repo", Limit: MaxSpendGroups + 1}).Validate(); err == nil {
		t.Fatal("an admin cost query above the page ceiling validated")
	}
	if err := (AdminCostQuery{ProjectKey: "/repo"}).Validate(); err != nil {
		t.Fatalf("a scoped admin cost query did not validate: %v", err)
	}
}

// TestAdminCostQueryShesTheAgentQuerysWindow keeps the two reports from
// disagreeing about how far back "recently" reaches. They are read side by
// side, and a different default in each is a discrepancy nobody can debug.
func TestAdminCostQueryShesTheAgentQuerysWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	admin := AdminCostQuery{ProjectKey: "/repo"}.Normalized(now)
	agent := CostQuery{}.Normalized(now)
	if !admin.Since.Equal(agent.Since) {
		t.Fatalf("admin window starts %s, agent window starts %s", admin.Since, agent.Since)
	}
	if admin.Limit != agent.Limit {
		t.Fatalf("admin limit=%d, agent limit=%d", admin.Limit, agent.Limit)
	}
	// A window older than the ceiling is clamped, not honoured, on both.
	ancient := AdminCostQuery{ProjectKey: "/repo", Since: now.Add(-100 * MaxSpendWindow)}.Normalized(now)
	if ancient.Since.Before(now.Add(-MaxSpendWindow)) {
		t.Fatalf("an ancient window was honoured: %s", ancient.Since)
	}
}
