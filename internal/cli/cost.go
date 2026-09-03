package cli

import (
	"context"
	"strconv"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
)

// The operator's cost report: what coordination cost this project, and what
// that cost in tokens.
//
// It is the half of the report an agent is deliberately NOT shown. An agent
// gets the two things it can act on inside its own turn -- which paths are
// refusing claims, and which abandoned leases are still refusing people -- and
// nothing else, because every field on a tool response is paid for out of that
// turn's context. The per-agent spend-against-contention table and the
// per-model cache economics answer weekly questions about how the project is
// scheduled and how its harnesses are configured, which is a human's decision
// about other agents. This is where those live.
//
// Three renderings below are load-bearing rather than decorative:
//
//   - An unobserved section is printed as ABSENT and named as such. It is never
//     drawn as a table of zeros, because "nothing was contended" and "nothing
//     was recorded" call for opposite responses and only the second means
//     something is broken.
//
//   - A lossy recorder is stated at the top, before any number it affects.
//     While it is present every contention count below is a floor.
//
//   - A ratio with no denominator prints as a dash. A model that wrote no cache
//     has no reuse ratio; printing 0.00 there would say caching is failing when
//     the truth is that it was never used.

type CostCmd struct {
	Project    string        `arg:"" optional:"" placeholder:"PATH" help:"Project key. Defaults to the current directory."`
	SinceHours int           `name:"since-hours" help:"Lookback window in hours. Zero uses the daemon's default."`
	Limit      int           `default:"20" help:"Maximum rows per list."`
	Watch      bool          `help:"Re-render until interrupted."`
	Interval   time.Duration `default:"5s" help:"Re-render interval for --watch."`
}

func (cmd *CostCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	project, err := projectKeyOrWorkingDirectory(cmd.Project)
	if err != nil {
		return err
	}
	limit, err := limitOf("--limit", cmd.Limit)
	if err != nil {
		return err
	}
	return console.loop(ctx, cmd.Watch, cmd.Interval, func(ctx context.Context) (render.View, error) {
		report, err := admin.Cost(ctx, CostQuery{ProjectKey: project,
			SinceHours: cmd.SinceHours, Limit: limit})
		if err != nil {
			return nil, daemonFault(err, "read cost report")
		}
		return newView(report, drawCost), nil
	})
}

func drawCost(doc *render.Document, report CostReport) {
	doc.Heading("Cost")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "project", Value: report.ProjectKey},
		{Key: "window", Value: report.Since + " to " + report.Until},
	}})
	// Stated before every number it qualifies, because a reader who meets the
	// caveat after the totals has already formed a view of them.
	if report.Recording != nil {
		doc.Blank()
		doc.Status(render.StatusWarn, "This daemon dropped "+itoa64(report.Recording.Dropped)+
			" contention facts (writing "+itoa64(report.Recording.Written)+
			"), so every contention count below is a FLOOR, not a measurement.")
	}
	for _, section := range report.Unobserved {
		doc.Blank()
		doc.Status(render.StatusBullet, "No "+section+" was recorded in this window. "+
			"That is unknown, not zero: it may be a quiet window or a collector that recorded nothing.")
	}
	drawCostContention(doc, report.Contention)
	drawCostAbandonment(doc, report.Abandonment)
	drawCostCache(doc, report.Cache)
}

func drawCostContention(doc *render.Document, cost *CostContention) {
	if cost == nil {
		return
	}
	doc.Blank()
	doc.Heading("Contention")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "refusals", Value: itoa64(cost.Refusals), Role: countRole64(cost.Refusals)},
		{Key: "waits", Value: itoa64(cost.PathWaits) + " on a path, " +
			itoa64(cost.MailWaits) + " on mail"},
		// The end reasons account for every wait, so a reader can check the
		// arithmetic rather than wonder what the remainder was.
		{Key: "ended", Value: itoa64(cost.WaitsEndedFree) + " free, " +
			itoa64(cost.WaitsEndedMail) + " mail, " +
			itoa64(cost.WaitsEndedDeadline) + " deadline, " +
			itoa64(cost.WaitsEndedAbandoned) + " abandoned, " +
			itoa64(cost.WaitsEndedStopped) + " daemon stop, " +
			itoa64(cost.WaitsEndedUnknown) + " unknown",
			Role: countRole64(cost.WaitsEndedDeadline)},
		{Key: "parked", Value: render.DurationMicros(1000*int64(cost.ParkedMS)) + " total, " +
			render.DurationMicros(1000*int64(cost.LongestParkMS)) + " worst"},
	}})
	doc.Blank()
	doc.Table(costPathTable(cost))
	drawTruncation(doc, cost.Truncated, len(cost.Paths))
	doc.Blank()
	doc.Table(costAgentTable(cost))
}

// costPathTable names the HOLDER's selector, which is the claim whose owner can
// narrow it. Refusals and distinct blocked agents are both shown because they
// separate the two shapes of contention that want opposite fixes: one agent
// refused forty times is a retry loop, four agents refused ten times each is a
// selector that is too wide.
func costPathTable(cost *CostContention) render.Table {
	table := render.Table{
		Columns: []render.Column{
			{Title: "CONTENDED PATH", Trim: render.TrimLeft},
			{Title: "KIND"},
			{Title: "REFUSALS", Align: render.AlignRight},
			{Title: "AGENTS", Align: render.AlignRight},
		},
		Empty: "No claim was refused in this window.",
	}
	for _, path := range cost.Paths {
		table.Rows = append(table.Rows, render.TextRow(path.Path, path.Kind,
			itoa64(path.Refusals), itoa64(path.BlockedAgents)))
	}
	return table
}

// costAgentTable is the join this whole report exists for, and the reason it is
// on the operator surface rather than the agent one: it names which agent to
// give a worktree or a narrower scope, which is a scheduling decision about
// other agents.
//
// The token columns are CO-OCCURRING with the contention beside them, not
// caused by it. Nothing here claims these tokens were spent because the agent
// was blocked, and the report deliberately does not attribute tokens to the
// inside of a parked interval -- a parked agent is not calling a model, so that
// figure would be near zero and read as "contention is free".
func costAgentTable(cost *CostContention) render.Table {
	table := render.Table{
		Columns: []render.Column{
			{Title: "AGENT", Trim: render.TrimLeft},
			{Title: "REFUSALS", Align: render.AlignRight},
			{Title: "WAITS", Align: render.AlignRight},
			{Title: "DEADLINE", Align: render.AlignRight},
			{Title: "PARKED", Align: render.AlignRight},
			{Title: "CALLS", Align: render.AlignRight},
			{Title: "BILLED IN", Align: render.AlignRight},
			{Title: "OUT", Align: render.AlignRight},
		},
		Empty: "No agent met contention in this window.",
	}
	for _, agent := range cost.Agents {
		name := agent.AgentName
		if name == "" {
			// The agent record is gone while its facts remain. The contention
			// still happened, so the row stays and says so.
			name = "(deregistered)"
		}
		table.Rows = append(table.Rows, render.TextRow(name, itoa64(agent.Refusals),
			itoa64(agent.PathWaits), itoa64(agent.WaitsEndedDeadline),
			render.DurationMicros(1000*int64(agent.ParkedMS)), itoa64(agent.ModelCalls),
			itoa64(agent.BilledInput), itoa64(agent.Output)))
	}
	return table
}

func drawCostAbandonment(doc *render.Document, cost *CostAbandonment) {
	if cost == nil {
		return
	}
	doc.Blank()
	doc.Heading("Abandonment")
	// The pair is reported together because a rate is actionable and a bare
	// count is not: ten abandoned out of eleven is a broken handoff habit, ten
	// out of a thousand is noise.
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "leases", Value: itoa64(cost.Abandoned) + " abandoned, " +
			itoa64(cost.Released) + " released", Role: countRole64(cost.Abandoned)},
		{Key: "held", Value: render.DurationMicros(1000*int64(cost.AbandonedHeldMS)) + " abandoned, " +
			render.DurationMicros(1000*int64(cost.ReleasedHeldMS)) + " released"},
		{Key: "refusals caused", Value: itoa64(cost.RefusalsDuring), Role: countRole64(cost.RefusalsDuring)},
	}})
	doc.Blank()
	table := render.Table{
		Columns: []render.Column{
			{Title: "HOLDER", Trim: render.TrimLeft},
			{Title: "MODE"},
			{Title: "HELD", Align: render.AlignRight},
			{Title: "REFUSALS", Align: render.AlignRight},
			{Title: "AGENTS", Align: render.AlignRight},
			{Title: "PATH", Trim: render.TrimLeft, Role: render.RoleMuted},
		},
		Empty: "No lease reached its deadline unreleased in this window.",
	}
	for _, lease := range cost.Leases {
		holder := lease.HolderAgent
		if holder == "" {
			holder = "(deregistered)"
		}
		table.Rows = append(table.Rows, render.TextRow(holder, lease.Mode,
			render.DurationMicros(1000*int64(lease.HeldMS)), itoa64(lease.Refusals),
			itoa64(lease.BlockedAgents), lease.ContendedPath))
	}
	doc.Table(table)
	drawTruncation(doc, cost.Truncated, len(cost.Leases))
}

// drawCostCache keeps the three input classes in three columns. Summing them
// into one "input" number destroys the only thing the section is for: cache
// reads run one to two orders of magnitude above uncached input and a cache
// write costs more per token than either, so a caller cannot recover the split
// from the sum and cannot price it either.
func drawCostCache(doc *render.Document, cost *CostCache) {
	if cost == nil {
		return
	}
	doc.Blank()
	doc.Heading("Cache economics")
	table := render.Table{
		Columns: []render.Column{
			{Title: "MODEL", Trim: render.TrimLeft},
			{Title: "CALLS", Align: render.AlignRight},
			{Title: "UNCACHED IN", Align: render.AlignRight},
			{Title: "CACHE READ", Align: render.AlignRight},
			{Title: "CACHE WRITE", Align: render.AlignRight},
			{Title: "OUT", Align: render.AlignRight},
			{Title: "READ SHARE", Align: render.AlignRight},
			{Title: "REUSE", Align: render.AlignRight},
		},
		Empty: "No model call was recorded in this window.",
	}
	for _, model := range cost.Models {
		table.Rows = append(table.Rows, render.TextRow(model.Model, itoa64(model.Calls),
			itoa64(model.UncachedInput), itoa64(model.CacheRead), itoa64(model.CacheWrite),
			itoa64(model.Output), costRatio(model.CacheReadShare), costRatio(model.CacheReuse)))
	}
	doc.Table(table)
	drawTruncation(doc, cost.Truncated, len(cost.Models))
	doc.Blank()
	// The money question is asked every time this table is read, so the reason
	// it is unanswerable here is stated where it is asked.
	doc.Wrapped(render.RoleMuted, "Token classes are reported separately and never priced: a price per "+
		"million tokens differs by model, by class and by contract, and none of them live in this "+
		"repository. Multiply these columns by your own price table, and price the three input "+
		"classes separately.")
}

// costRatio prints an absent ratio as a dash rather than as zero. The
// difference is the whole point: no denominator means there is no answer, and a
// 0.00 in this column would be read as caching failing rather than as caching
// never having been used.
func costRatio(value *float64) string {
	if value == nil {
		return "-"
	}
	return strconv.FormatFloat(*value, 'f', 2, 64)
}

func itoa64(value uint64) string { return strconv.FormatUint(value, 10) }

func countRole64(count uint64) render.Role {
	if count > 0 {
		return render.RoleWarn
	}
	return render.RoleInherit
}
