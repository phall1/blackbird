package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

// The join this plane exists for.
//
// SpendReport answers where the tokens went. It cannot answer what they were
// worth, because worth is a comparison against what the work cost to
// coordinate, and until the journal recorded a refusal and a wait there was
// nothing to compare against: every event it held was a success, so the plane
// could account for everything that worked and nothing for what being blocked
// cost. An observability plane that records only successes cannot compute the
// cost of failure, because the denominator was never written down.
//
// Both halves now carry the same identity -- (project_key, actor_id,
// session_id) on telemetry_model_calls, (workspace_id, actor_id) on
// coordination_events, and holder_actor_id on leases -- in one SQLite file. So
// this is a join rather than a correlation, and nothing but the owner of both
// ledgers can perform it.
//
// Three rules hold everything below, and each one is a rule this repository
// already keeps:
//
//   - A DERIVED figure is never presented as a MEASURED one.
//     telemetry_model_calls.duration_ms is NULL for Claude Code because a
//     transcript records what a call cost and never how long it took, so every
//     wall-clock figure here says in its own name and doc comment whether the
//     daemon stamped it or a reader inferred it. ParkedMS is measured: the
//     daemon stamped both ends of the wait. The token totals beside it are
//     CO-OCCURRING, not causal, and say so.
//
//   - An empty window is EMPTY, not zero. Every section reports whether it
//     observed anything at all, and a caller must render an unobserved section
//     as absent. A cost report that silently answers zero when collection is
//     broken is exactly the failure the collector work spent its effort
//     avoiding, and it is worse than no report because it invites the
//     conclusion that a quiet period was an uncontended one.
//
//   - A number nobody can act on is left out. Every field below has an action
//     attached to it in its doc comment. Where the honest answer is a ratio
//     over a zero denominator, the accessor reports that it has no answer
//     rather than inventing one.
//
// MONEY IS DELIBERATELY ABSENT. Converting tokens to dollars needs a price per
// million tokens per model per token class, and those prices change, differ by
// contract, and are not in this repository. Hardcoding one would produce a
// number that is confidently wrong the month after it is written. A caller that
// wants money multiplies these token classes by a price table it owns -- the
// three input classes must be priced SEPARATELY, since a cache read and an
// uncached input token differ by roughly an order of magnitude and a cache
// write costs more than either.

// CostQuery selects one cost report. Like SpendQuery it carries no project: the
// report is always the caller's own, taken from the authenticated session, so
// it can never read across into another workspace.
type CostQuery struct {
	// Since bounds the window on when the work happened -- a call's
	// started_at, an event's occurred_at, a lease's acquired_at -- rather than
	// on when this daemon recorded it, because that is the question a caller is
	// asking.
	Since time.Time
	// MineOnly narrows the token and contention rollups to the calling agent,
	// which is how an agent asks what IT is costing rather than what the
	// project is. It does not narrow abandonment: a lease someone else
	// abandoned is precisely the thing the caller cannot see from its own side
	// and most needs to be told about.
	MineOnly bool
	Limit    uint16
}

// Normalized fills defaults and clamps bounds against the same window and reply
// ceilings the spend rollup uses, so the two reports cannot disagree about how
// far back "recently" reaches or how much a caller may ask for.
func (query CostQuery) Normalized(now time.Time) CostQuery {
	if query.Limit == 0 || query.Limit > MaxSpendGroups {
		query.Limit = DefaultSpendGroups
	}
	earliest := now.Add(-MaxSpendWindow)
	if query.Since.IsZero() {
		query.Since = now.Add(-DefaultSpendWindow)
	}
	if query.Since.Before(earliest) {
		query.Since = earliest
	}
	return query
}

func (query CostQuery) Validate() error {
	if query.Limit > MaxSpendGroups {
		return fmt.Errorf("%w: cost limit %d exceeds %d", coordination.ErrInvalid, query.Limit, MaxSpendGroups)
	}
	return nil
}

// AdminCostQuery is the operator's cost report, and it names its project
// EXPLICITLY. That is the whole difference from CostQuery and it is a
// deliberate decision made at the admin boundary rather than a field quietly
// added to the agent's query.
//
// CostQuery carries no project by construction: an agent reads the workspace it
// authenticated into or nothing, and that is what makes it impossible for one
// agent's tool call to read across into another project. An operator is a
// different principal with a different credential -- the loopback admin token
// -- and asks about a project it names. Merging the two would give the agent
// query a project field, and a field that exists is a field something will
// eventually populate from a request body.
//
// There is deliberately no MineOnly: an operator has no "mine".
type AdminCostQuery struct {
	// ProjectKey is required. There is no "every project" reading, because a
	// cost report summed across projects would add contention between agents
	// that could never have collided.
	ProjectKey string
	Since      time.Time
	Limit      uint16
}

func (query AdminCostQuery) Validate() error {
	if query.ProjectKey == "" {
		return fmt.Errorf("%w: an admin cost report requires a project key", coordination.ErrInvalid)
	}
	if query.Limit > MaxSpendGroups {
		return fmt.Errorf("%w: cost limit %d exceeds %d", coordination.ErrInvalid, query.Limit, MaxSpendGroups)
	}
	return nil
}

// Normalized shares the agent query's window and page ceilings, so the operator
// report and the agent report cannot disagree about how far back "recently"
// reaches.
func (query AdminCostQuery) Normalized(now time.Time) AdminCostQuery {
	normalized := CostQuery{Since: query.Since, Limit: query.Limit}.Normalized(now)
	query.Since = normalized.Since
	query.Limit = normalized.Limit
	return query
}

// CostAdminReader is the operator half of this plane's read surface. It is its
// own port rather than a method on Reader because the two answer to different
// credentials: Reader is reached with an agent's registration token and is
// confined to that agent's workspace, while this is reached with the loopback
// admin token and names its project. A composition may offer either, both, or
// neither, and the transport that cannot get one simply does not register the
// route.
type CostAdminReader interface {
	AdminCostReport(context.Context, AdminCostQuery) (CostReport, error)
}

// CostReport is the whole answer: what contention cost, what abandonment cost,
// and whether caching is paying for itself. Each section stands alone and each
// reports its own emptiness, because they fail independently -- a project can
// have plenty of telemetry and no contention, or plenty of contention and a
// broken collector, and a reader must be able to tell those apart.
type CostReport struct {
	// Since and Until bound the window as the daemon measured it, so a reader
	// states the window rather than inferring it from its own clock. BOTH edges
	// are enforced in the queries: a row stamped in the future -- and
	// telemetry_model_calls.started_at_us is supplied by an adapter whose clock
	// this daemon does not own -- must not be reported inside a window that
	// ended before it.
	Since time.Time
	Until time.Time
	// MineOnly restates the scope the query asked for, because the sections
	// below do NOT share one and a reader comparing across them has to know
	// that. Contention and Cache narrow to the calling agent when this is set;
	// Abandonment never does, by design. Without this field a reader sees
	// Contention.Refusals counting only its own denials beside
	// Abandonment.RefusalsDuring counting the project's, and reads the pair as
	// a ratio that can exceed one.
	MineOnly bool
	// Recording is how complete the contention half of this report is. It is
	// stated on the report rather than inside ContentionCost because the case
	// that matters most is a section that observed NOTHING while the recorder
	// was dropping facts: an absent section and a decimated one must not read
	// alike.
	Recording   RecordingHealth
	Contention  ContentionCost
	Abandonment AbandonmentCost
	Cache       CacheEconomics
}

// RecordingHealth is the contention recorder's self-report, carried into the
// report that draws conclusions from what it recorded.
//
// A contention fact is an observation that may never fail or delay the
// operation it describes, so the recorder is a bounded non-blocking queue that
// DROPS rather than pushes back. That is the right trade for the hot path and
// the wrong thing to hide from a reader: shedding is not uniform, it happens
// hardest during a retry storm, and a retry storm is exactly the shape of
// contention this report exists to name. A refusal count built from a silently
// decimated sample reads as precise and is not.
//
// So whenever Lossy is true, every count in ContentionCost is a FLOOR.
//
// These figures are cumulative over the DAEMON'S LIFETIME, not over the report
// window -- the recorder counts what it handled, not when. A caller may
// therefore say "at least this much, and some facts were lost since this daemon
// started"; it may not subtract one from the other and call the result a
// window's loss.
type RecordingHealth struct {
	// Offered and Written are facts accepted into the queue and facts committed.
	Offered uint64
	Written uint64
	// Dropped is everything the recorder refused or failed to write: a full
	// queue, a closed journal, a fact that could not be encoded, and a batch
	// whose commit failed. They are summed because the reader's question is
	// "how much am I missing", and every one of them answers it the same way.
	Dropped uint64
}

// Lossy reports whether this daemon has lost at least one contention fact. A
// reader must render every contention count as a lower bound when it is true.
func (health RecordingHealth) Lossy() bool { return health.Dropped > 0 }

// ContentionCost is what being blocked cost, built from the journal's two
// non-success facts.
//
// The counts and the parked milliseconds are MEASURED: the daemon decided each
// refusal and stamped both ends of each wait against its own clock. The token
// totals on each agent are measured too, but their RELATIONSHIP to the
// contention beside them is not -- see BlockedAgent.
type ContentionCost struct {
	// Refusals is claims denied. Above zero means agents are colliding; the
	// Paths list names where, and the action is to narrow that selector or move
	// the second writer to a worktree.
	Refusals uint64
	// PathWaits is bounded waits that named a path -- an agent parked on
	// contention. MailWaits is the mail-only kind, which is an idle agent
	// rather than a blocked one and is counted apart so it cannot inflate the
	// contention story.
	PathWaits uint64
	MailWaits uint64
	// The six WaitsEnded fields are EVERY way a wait can end, and they sum
	// EXACTLY to PathWaits + MailWaits. That completeness is the point: with
	// only some of the buckets reported, a reader who finds that free and
	// deadline do not add up has no way to tell whether the remainder was
	// harmless or the thing worth looking at, and the natural guess -- fold it
	// into deadline -- invents abandonments that never happened.
	//
	// WaitsEndedFree is waits that ended because the path came free: this is
	// coordination working, and needs no action. WaitsEndedMail is a mail
	// wakeup, likewise nothing to act on.
	WaitsEndedFree uint64
	WaitsEndedMail uint64
	// WaitsEndedDeadline is the number that matters -- an agent whose wait
	// burned its whole budget is an agent about to abandon work, and the action
	// is to shorten the holder's TTL or narrow its selectors.
	WaitsEndedDeadline uint64
	// WaitsEndedAbandoned is waits the CALLER walked away from mid-poll. It is
	// a fact about an agent -- a client timeout, a cancelled turn -- and reads
	// alongside WaitsEndedDeadline as the other half of "gave up".
	WaitsEndedAbandoned uint64
	// WaitsEndedStopped is waits THIS DAEMON cut short while shutting down. It
	// is a fact about the process and about nothing else, and it is counted
	// apart precisely so a restart cannot masquerade as a crop of abandonments.
	// A high count here means the daemon restarted under load, not that agents
	// are giving up.
	WaitsEndedStopped uint64
	// WaitsEndedUnknown is waits whose end condition was never determined,
	// recorded with a null reason -- a durable read that failed mid-poll. It is
	// reported rather than folded into deadline because "not determined" and
	// "the budget ran out" are different facts.
	WaitsEndedUnknown uint64
	// ParkedMS is MEASURED wall-clock: the daemon stamped the start and the end
	// of every wait counted in PathWaits. It is the throughput this project
	// lost to serialization, and it is the one duration in this report that
	// needs no caveat.
	ParkedMS uint64
	// LongestParkMS is the worst single park, which separates one pathological
	// hold from a steady drizzle of short ones -- different problems with
	// different fixes.
	LongestParkMS uint64
	// Agents and Paths are the two useful cuts: who was blocked, and by which
	// path. Both are capped at the query's limit and ordered worst-first.
	Agents []BlockedAgent
	Paths  []ContendedPath
	// Truncated says at least one row was cut by the limit. The totals above
	// are taken over the whole window rather than over these rows, so they stay
	// honest either way -- but a reader that treats a capped list as the
	// complete set of contended paths will conclude it has seen them all.
	Truncated bool
}

// Observed reports whether the window held any contention fact at all. A false
// result must render as ABSENT rather than as a row of zeros: zero refusals in
// a window that recorded nothing is not the same claim as zero refusals in a
// window that recorded plenty of other events, and a reader acting on the
// second would be acting on a collector outage.
func (cost ContentionCost) Observed() bool {
	return cost.Refusals > 0 || cost.PathWaits > 0 || cost.MailWaits > 0
}

// WaitsAccounted sums the six end-reason buckets. It exists so the completeness
// claim on those fields is checkable rather than aspirational: it must equal
// PathWaits + MailWaits for every report this store produces, and a bucket
// added to WaitReason without a bucket added here breaks that equality instead
// of quietly leaking waits into a total nobody can explain.
func (cost ContentionCost) WaitsAccounted() uint64 {
	return cost.WaitsEndedFree + cost.WaitsEndedMail + cost.WaitsEndedDeadline +
		cost.WaitsEndedAbandoned + cost.WaitsEndedStopped + cost.WaitsEndedUnknown
}

// BlockedAgent is one agent's contention and one agent's spend over the same
// window.
//
// The two halves are CO-OCCURRING TOTALS, NOT A CAUSAL ATTRIBUTION. Nothing
// here claims these tokens were spent because of that contention, and the
// report deliberately does not attribute tokens to the inside of a parked
// interval: an agent parked in a bounded wait is not calling a model, so such a
// figure would be near zero and would read as "contention is free" -- the
// precise opposite of the truth.
//
// Side by side they are still the most actionable pair in this report. An agent
// that is both expensive and heavily contended is the one to give a worktree
// or a narrower scope, and neither number alone identifies it.
type BlockedAgent struct {
	// AgentName is empty when the agent row is gone while its facts remain.
	// The contention still happened, so it groups under an empty name rather
	// than disappearing.
	AgentName          string
	ActorID            domain.ActorID
	Refusals           uint64
	PathWaits          uint64
	WaitsEndedDeadline uint64
	ParkedMS           uint64
	// ModelCalls, BilledInput and Output are this agent's own spend over the
	// same window, from telemetry_model_calls. Zero across all three means no
	// telemetry was collected for this agent, which is a fact about collection
	// rather than about the agent -- the contention counts beside it are
	// unaffected.
	ModelCalls  uint64
	BilledInput uint64
	Output      uint64
}

// ContendedPath is one path that stood in someone's way, taken from the
// refusal's recorded overlap rather than re-derived. It is the HOLDER's
// selector -- the path that was already claimed -- because that is the one
// whose owner can do something about it.
type ContendedPath struct {
	Path string
	// Kind is exact or subtree. A subtree selector at the top of the list is
	// the most common and most fixable cause of contention in this repository:
	// the action is to claim the file rather than the package.
	Kind string
	// Refusals is how many claims this path denied, and BlockedAgents how many
	// distinct agents it denied them to. One agent refused forty times is a
	// retry loop; four agents refused ten times each is a scope that is too
	// wide, and the two want opposite fixes.
	Refusals      uint64
	BlockedAgents uint64
}

// AbandonmentCost is what leases nobody released cost.
//
// Abandoned and Released are classified by the SAME predicates the operator's
// reservation listing uses -- an explicit release is stamped strictly before
// the deadline because changeLease refuses one after it, while the expiry
// reaper stamps at or after it. There is deliberately no second definition of
// abandonment in this codebase to drift from the first.
type AbandonmentCost struct {
	// Abandoned and Released are counted together because a rate is actionable
	// and a bare count is not: ten abandoned leases out of eleven is a broken
	// handoff habit, and ten out of a thousand is noise.
	Abandoned uint64
	Released  uint64
	// AbandonedHeldMS and ReleasedHeldMS are MEASURED from the leases' own
	// stamps: an abandoned lease held its path from acquisition to its
	// deadline, a released one from acquisition to its release. Comparing the
	// two means per lease is the TTL diagnostic -- when abandoned holds run far
	// longer than released ones, the TTLs are much longer than the work needs
	// and every collision pays the difference.
	AbandonedHeldMS uint64
	ReleasedHeldMS  uint64
	// RefusalsDuring is the number that decides whether any of this mattered.
	// It is an EXACT join, not a time overlap: a refusal records the lease id
	// of the holder that blocked it, so these are refusals those specific
	// abandoned leases caused. An abandoned lease that refused nobody cost
	// nothing and should be ignored.
	//
	// It can only UNDERSTATE. The coordination journal is prunable by age and
	// count, so refusals may have been pruned while the lease row remains;
	// above zero is therefore always real, and zero may mean pruned rather than
	// harmless.
	RefusalsDuring uint64
	// Leases is the worst offenders, ordered by the refusals they caused rather
	// than by how long they were held, because a long hold nobody wanted is not
	// a problem.
	Leases []AbandonedLease
	// Truncated says the list was cut by the limit. RefusalsDuring is summed
	// over every abandoned lease in the window rather than over these rows, so
	// it does not shrink with the limit; this flag is what stops a reader
	// treating the visible leases as all of them.
	Truncated bool
}

// Observed reports whether the window held any completed lease at all, so an
// empty section renders as absent rather than as a clean bill of health.
func (cost AbandonmentCost) Observed() bool {
	return cost.Abandoned > 0 || cost.Released > 0
}

// AbandonedLease is one lease that reached its deadline without being released.
type AbandonedLease struct {
	LeaseID domain.LeaseID
	// HolderAgentName is empty when the agent row is gone. The action attaches
	// to the agent, so an empty name means this row is history rather than
	// something to fix.
	HolderAgentName string
	Mode            coordination.LeaseMode
	// HeldMS is MEASURED: the lease's own acquired and expiry stamps. It is the
	// full window during which this path was unavailable to anyone else,
	// whether or not the holder was still working.
	HeldMS uint64
	// Refusals and BlockedAgents are the exact join described on
	// AbandonmentCost.RefusalsDuring. Above zero, the action is concrete: this
	// agent needs a shorter TTL or an explicit release, which is what the
	// handoff flow exists for.
	Refusals      uint64
	BlockedAgents uint64
	// ContendedPath is one of the holder's selector paths that actually
	// collided, taken from a refusal this lease caused -- the first in
	// lexical order when it caused refusals on several. It is empty when this
	// lease refused nobody, which is the case where there is no path worth
	// naming.
	ContendedPath string
}

// CacheEconomics is the input split, per model, that a single "input tokens"
// number destroys.
//
// The three input classes are billed at materially different rates -- in the
// live corpus cache reads run one to two orders of magnitude above uncached
// input, and a cache write costs more per token than either -- so summing them
// into one figure produces a number that tracks nothing a reader can act on.
// They are reported separately here for the same reason the storage schema
// keeps them in separate columns.
type CacheEconomics struct {
	// Models is ordered by billed input descending, so the model whose prompt
	// handling costs the most comes first.
	Models []ModelCacheEconomics
	// Truncated says at least one model was cut by the limit.
	Truncated bool
}

// Observed reports whether any model call fell in the window. An empty result
// means nothing was collected, not that nothing was spent.
func (cost CacheEconomics) Observed() bool { return len(cost.Models) > 0 }

// ModelCacheEconomics is one model's input split over the window.
type ModelCacheEconomics struct {
	Model         string
	Calls         uint64
	UncachedInput uint64
	CacheRead     uint64
	CacheWrite    uint64
	Output        uint64
}

// BilledInput is the three input classes summed. It is offered only so a caller
// need not know which classes exist; it is never a substitute for the split,
// and a report that shows only this number is the one this type exists to
// prevent.
func (cost ModelCacheEconomics) BilledInput() uint64 {
	return cost.UncachedInput + cost.CacheRead + cost.CacheWrite
}

// CacheReadShare is the fraction of billed input served from cache, and false
// when there was no billed input to take a fraction of. Near one, almost the
// whole prompt is being served from cache and there is nothing to fix. Falling
// over time is the signal that something near the top of the context has become
// unstable.
func (cost ModelCacheEconomics) CacheReadShare() (float64, bool) {
	billed := cost.BilledInput()
	if billed == 0 {
		return 0, false
	}
	return float64(cost.CacheRead) / float64(billed), true
}

// CacheReuse is how many tokens are read back from the cache for each token
// written to it, and false when nothing was written -- which is caching not in
// use rather than caching working badly, and the two must not render alike.
//
// This is the diagnostic worth watching. A cache write costs more per token
// than an uncached input token, so a reuse well above one is caching paying for
// itself many times over, and a reuse near or below one means the prefix is
// being rewritten about as often as it is read: something non-deterministic
// sits near the top of the context, and the caching is costing more than it
// saves. The action is to find and stabilize that prefix.
func (cost ModelCacheEconomics) CacheReuse() (float64, bool) {
	if cost.CacheWrite == 0 {
		return 0, false
	}
	return float64(cost.CacheRead) / float64(cost.CacheWrite), true
}
