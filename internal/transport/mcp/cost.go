package mcp

import (
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
)

// The agent-facing cost surface is deliberately a SUBSET of the report.
//
// Every field on blackbird_status is paid for out of a model's context on the
// turn that reads it, so the question is not "what did we compute" but "what
// would this agent do differently having read it". The cost report answers four
// questions and only two of them have an answer an agent can act on inside the
// turn it is having:
//
//   - Which paths are refusing claims, and of what kind. The action is
//     immediate and concrete: claim the file rather than the package, or move
//     to a worktree. This is carried.
//
//   - Which abandoned leases are still refusing people. The action is
//     immediate: open a conversation with that holder, or wait out a deadline
//     that is already known. This is carried.
//
//   - Cache economics per model. The action -- find and stabilize whatever is
//     making the prompt prefix churn -- is a change to a harness or a
//     configuration, not to this turn's plan. It is NOT carried here; it is on
//     the reader port for the operator surface that asks weekly questions.
//
//   - Spend and contention per agent, across the project. The action is to give
//     some agent a worktree or a narrower scope, which is a human's scheduling
//     decision about other agents. Also NOT carried; an agent asking what IT
//     costs gets that from mine_only on the spend rollup, which already exists
//     and already answers it.
//
// The headline totals are carried because they are what tells an agent whether
// to look at the lists at all.

// costReportOutput is the agent-visible projection. A section is absent when it
// observed nothing, and Unobserved names it explicitly: an absent section must
// never be read as a section full of zeros, because "no contention happened"
// and "no contention was recorded" call for opposite responses and only the
// second one means something is broken.
type costReportOutput struct {
	Since string `json:"since" jsonschema:"Start of the window, on when the work happened rather than when it was recorded."`
	Until string `json:"until" jsonschema:"End of the window, from the daemon's own clock at the moment the report was built. It is enforced, not merely stated: work stamped after it is excluded."`
	// Scope is stated because the two sections below do NOT share one, and the
	// numbers look comparable when they are not.
	Scope string `json:"scope" jsonschema:"Which agents the contention section covers: 'you' when the report was narrowed to the caller, otherwise 'project'. The abandonment section is ALWAYS project-wide, so under scope 'you' its refusals_caused counts denials against every agent while contention.refusals counts only yours -- the two are different populations and their ratio means nothing."`
	// Recording is present only when this daemon has lost contention facts.
	// When it is present every count in the contention section is a FLOOR.
	Recording *recordingHealthOutput `json:"recording_incomplete,omitempty" jsonschema:"Present only when this daemon dropped contention facts. While it is present, every count in the contention section is a LOWER BOUND, not a measurement."`
	// Unobserved names every section that recorded nothing in this window.
	// A named section is EMPTY, not zero. Treat it as "this daemon has no
	// answer" rather than as a clean bill of health.
	Unobserved  []string               `json:"unobserved,omitempty" jsonschema:"Sections that observed nothing in this window and are therefore absent. An absent section is unknown, never zero: it may mean a quiet window or a collector that recorded nothing, and those call for opposite responses."`
	Contention  *contentionCostOutput  `json:"contention,omitempty"`
	Abandonment *abandonmentCostOutput `json:"abandonment,omitempty"`
}

// recordingHealthOutput is the loss the recorder is otherwise silent about.
//
// A contention fact may never fail or delay the operation it describes, so the
// recorder drops rather than pushes back when it cannot keep up. That shedding
// is NOT uniform: it happens hardest during a retry storm, which is exactly the
// shape of contention worth naming, and it would otherwise leave a precise
// looking refusal total built from a sample nobody knows is partial.
type recordingHealthOutput struct {
	Dropped uint64 `json:"facts_dropped" jsonschema:"Contention facts this daemon could not record, cumulative since it started -- NOT confined to this window. Its presence means the contention counts are floors; its size is not a per-window loss and must not be subtracted from anything."`
	Written uint64 `json:"facts_written" jsonschema:"Contention facts committed since this daemon started. Beside facts_dropped it gives the rough scale of the loss."`
}

type contentionCostOutput struct {
	Refusals uint64 `json:"refusals" jsonschema:"Claims denied in this window. Above zero, read contended_paths: that is where to narrow a selector or take a worktree. A LOWER BOUND whenever recording_incomplete is present."`
	// Mail waits are counted apart from path waits and excluded from
	// parked_ms. An idle inbox poll is not contention, and letting it into
	// the parked clock would make a quiet project look heavily contended.
	PathWaits uint64 `json:"path_waits" jsonschema:"Bounded waits that named a path -- an agent parked on contention."`
	MailWaits uint64 `json:"mail_waits" jsonschema:"Bounded waits for mail only. An idle agent rather than a blocked one, which is why these are excluded from parked_ms."`
	// All six end reasons are carried, and they sum exactly to path_waits plus
	// mail_waits. Reporting only some of them leaves a reader who notices the
	// shortfall guessing, and the natural guess -- that the remainder timed out
	// -- invents abandonments that never happened.
	WaitsEndedFree      uint64 `json:"waits_ended_free" jsonschema:"Waits that ended because the path came free. Coordination working; no action."`
	WaitsEndedMail      uint64 `json:"waits_ended_mail" jsonschema:"Waits that ended on mail arriving. No action."`
	WaitsEndedDeadline  uint64 `json:"waits_ended_deadline" jsonschema:"Waits that burned their whole budget. This is the number that matters: an agent whose wait hit its deadline is an agent about to abandon work, and the fix is a shorter TTL or a narrower selector on the holder."`
	WaitsEndedAbandoned uint64 `json:"waits_ended_abandoned" jsonschema:"Waits the CALLER walked away from mid-poll -- a client timeout or a cancelled turn. A fact about an agent."`
	WaitsEndedStopped   uint64 `json:"waits_ended_stopped" jsonschema:"Waits this daemon cut short while restarting. A fact about the PROCESS and about nothing else: it says nothing about any agent or any path, and must never be read as agents giving up."`
	WaitsEndedUnknown   uint64 `json:"waits_ended_unknown" jsonschema:"Waits whose end condition was never evaluated, because a durable read failed mid-poll. Recorded as unknown rather than folded into deadline, since 'not determined' and 'the budget ran out' are different facts."`

	ParkedMS      uint64                `json:"parked_ms" jsonschema:"MEASURED wall clock spent parked on contention -- the daemon stamped both ends of every wait on its monotonic clock. This is throughput the project lost to serialization, and it is not an inference."`
	LongestParkMS uint64                `json:"longest_park_ms" jsonschema:"The worst single park, which separates one pathological hold from a drizzle of short ones."`
	Paths         []contendedPathOutput `json:"contended_paths,omitempty"`
	Truncated     bool                  `json:"truncated,omitempty" jsonschema:"More contended paths existed than the limit allowed. The totals above still cover the whole window; only the list is cut."`
}

type contendedPathOutput struct {
	Path          string `json:"path" jsonschema:"The HOLDER's selector -- the claim already in place -- because that is the one whose owner can narrow it."`
	Kind          string `json:"kind" jsonschema:"exact or subtree. A subtree at the top of this list is the most fixable cause of contention: claim the file rather than the package."`
	Refusals      uint64 `json:"refusals"`
	BlockedAgents uint64 `json:"blocked_agents" jsonschema:"Distinct agents this path refused. One agent refused many times is a retry loop; several agents refused a few times each is a selector that is too wide, and the two want opposite fixes."`
}

type abandonmentCostOutput struct {
	Abandoned       uint64                 `json:"abandoned" jsonschema:"Leases that reached their deadline without being released."`
	Released        uint64                 `json:"released" jsonschema:"Leases released cleanly before their deadline. It is the denominator: ten abandoned out of eleven is a broken handoff habit, ten out of a thousand is noise."`
	AbandonedHeldMS uint64                 `json:"abandoned_held_ms" jsonschema:"MEASURED wall clock those abandoned leases held their paths, from acquisition to deadline."`
	ReleasedHeldMS  uint64                 `json:"released_held_ms" jsonschema:"MEASURED wall clock the released leases held theirs. Abandoned holds running far longer per lease means the TTLs are longer than the work needs."`
	RefusalsDuring  uint64                 `json:"refusals_caused" jsonschema:"Refusals these abandoned leases actually caused, joined on the blocking lease id recorded in each refusal rather than on overlapping time. Zero means the abandonments cost nobody anything. ALWAYS project-wide, even under scope 'you' -- so do not compare it against contention.refusals. It can only UNDERSTATE, because the coordination journal is pruned by age and count."`
	Leases          []abandonedLeaseOutput `json:"leases,omitempty" jsonschema:"Ordered by the refusals each caused, not by how long it was held: a long hold nobody wanted is not a problem."`
	Truncated       bool                   `json:"truncated,omitempty" jsonschema:"More abandoned leases existed than the limit allowed. refusals_caused still covers all of them; only the list is cut."`
}

type abandonedLeaseOutput struct {
	LeaseID       string `json:"lease_id"`
	Holder        string `json:"holder_agent_name,omitempty" jsonschema:"Empty when the agent record is gone, which means this row is history rather than something to act on."`
	Mode          string `json:"mode"`
	HeldMS        uint64 `json:"held_ms" jsonschema:"MEASURED from the lease's own acquisition and deadline stamps: the window during which nobody else could take this path."`
	Refusals      uint64 `json:"refusals"`
	BlockedAgents uint64 `json:"blocked_agents"`
	ContendedPath string `json:"contended_path,omitempty" jsonschema:"One of this lease's selectors that actually collided. Empty when it refused nobody, which is the case where there is nothing to name."`
}

// costReportPayload projects the report onto the agent surface, dropping the
// per-agent and per-model sections for the reasons at the top of this file.
func costReportPayload(report telemetry.CostReport) costReportOutput {
	output := costReportOutput{
		Since: report.Since.Format(time.RFC3339),
		Until: report.Until.Format(time.RFC3339),
		Scope: costScopeLabel(report.MineOnly),
	}
	// Emitted whether or not the contention section is present, because the
	// worst case is precisely a section that observed nothing while the
	// recorder was shedding: absent-and-quiet and absent-and-broken call for
	// opposite responses.
	if report.Recording.Lossy() {
		output.Recording = &recordingHealthOutput{Dropped: report.Recording.Dropped,
			Written: report.Recording.Written}
	}
	if report.Contention.Observed() {
		contention := contentionCostOutput{
			Refusals: report.Contention.Refusals, PathWaits: report.Contention.PathWaits,
			MailWaits: report.Contention.MailWaits, WaitsEndedFree: report.Contention.WaitsEndedFree,
			WaitsEndedMail:      report.Contention.WaitsEndedMail,
			WaitsEndedDeadline:  report.Contention.WaitsEndedDeadline,
			WaitsEndedAbandoned: report.Contention.WaitsEndedAbandoned,
			WaitsEndedStopped:   report.Contention.WaitsEndedStopped,
			WaitsEndedUnknown:   report.Contention.WaitsEndedUnknown,
			ParkedMS:            report.Contention.ParkedMS,
			LongestParkMS:       report.Contention.LongestParkMS,
			Truncated:           report.Contention.Truncated,
		}
		for _, path := range report.Contention.Paths {
			contention.Paths = append(contention.Paths, contendedPathOutput{Path: path.Path,
				Kind: path.Kind, Refusals: path.Refusals, BlockedAgents: path.BlockedAgents})
		}
		output.Contention = &contention
	} else {
		output.Unobserved = append(output.Unobserved, "contention")
	}
	if report.Abandonment.Observed() {
		abandonment := abandonmentCostOutput{
			Abandoned: report.Abandonment.Abandoned, Released: report.Abandonment.Released,
			AbandonedHeldMS: report.Abandonment.AbandonedHeldMS,
			ReleasedHeldMS:  report.Abandonment.ReleasedHeldMS,
			RefusalsDuring:  report.Abandonment.RefusalsDuring,
			Truncated:       report.Abandonment.Truncated,
		}
		for _, lease := range report.Abandonment.Leases {
			abandonment.Leases = append(abandonment.Leases, abandonedLeaseOutput{
				LeaseID: lease.LeaseID.String(), Holder: lease.HolderAgentName,
				Mode: string(lease.Mode), HeldMS: lease.HeldMS, Refusals: lease.Refusals,
				BlockedAgents: lease.BlockedAgents, ContendedPath: lease.ContendedPath})
		}
		output.Abandonment = &abandonment
	} else {
		output.Unobserved = append(output.Unobserved, "abandonment")
	}
	return output
}

// costScopeLabel names who the narrowed sections cover. It is a word rather
// than a boolean because the payload is read by a model, and "scope: you" is
// unambiguous where "mine_only: true" invites the reader to assume it applies
// to the whole report.
func costScopeLabel(mineOnly bool) string {
	if mineOnly {
		return "you"
	}
	return "project"
}
