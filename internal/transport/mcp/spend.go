package mcp

import (
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
)

// ToolSpendReport is the observation plane's only agent-facing surface.
//
// One tool, not several. Every tool costs every session a slice of its context
// on every turn, and the plane would happily grow a tool per question -- spend
// by model, by agent, slowest spans -- that a single dimension parameter
// answers just as well. It is also registered only when a telemetry reader is
// composed, so a daemon that collects nothing does not advertise a tool that
// can only answer zero.
const ToolSpendReport = ToolStatus

type spendGroupOutput struct {
	Key          string `json:"key" jsonschema:"The model, agent name, harness, span kind, or span name. Empty means the agent that spent this has since been deleted; the spend still happened."`
	Observations uint64 `json:"observations"`
	// BilledInput leads because it is the number a provider invoices and the
	// one an agent reasons about. The three classes behind it follow, because
	// the split between them is the difference between an expensive prompt and
	// a well-cached one.
	BilledInput   uint64 `json:"billed_input_tokens" jsonschema:"What a provider bills as input: uncached + cache_read + cache_write. Compare it against uncached_input_tokens to see how much caching is actually saving."`
	UncachedInput uint64 `json:"uncached_input_tokens" jsonschema:"Input processed fresh, excluding anything served from or written to cache."`
	CacheRead     uint64 `json:"cache_read_tokens"`
	CacheWrite    uint64 `json:"cache_write_tokens"`
	Output        uint64 `json:"output_tokens"`
	Reasoning     uint64 `json:"reasoning_tokens" jsonschema:"Reasoning tokens, which are a subset of output_tokens rather than additional to them. Zero may mean no reasoning or a harness that does not report it."`
	// Duration fields are separated from the count because not every source
	// measures latency. Claude Code reports none at all, so a mean taken over
	// observations rather than measured_durations would report its calls as
	// instant.
	MeasuredDurations uint64 `json:"measured_durations" jsonschema:"How many of these observations carried a duration. Divide total_duration_ms by this, never by observations: Claude Code reports no latency, so its calls count here as zero."`
	TotalDurationMS   uint64 `json:"total_duration_ms" jsonschema:"Summed duration of the measured observations. This is the bottleneck signal -- the group with the most total time is where the wall clock goes, regardless of how slow any single call was."`
	MaxDurationMS     uint64 `json:"max_duration_ms"`
}

type spendReportOutput struct {
	Dimension string `json:"dimension"`
	Since     string `json:"since"`
	// Until closes the window. It is stated because it is ENFORCED: a call
	// stamped after it is excluded rather than counted, which matters because
	// started_at comes from the harness that recorded the call and this daemon
	// does not own that clock.
	Until     string             `json:"until"`
	Groups    []spendGroupOutput `json:"groups"`
	Totals    spendGroupOutput   `json:"totals" jsonschema:"Totals over the whole window, not merely the groups returned, so they stay honest when truncated is true."`
	Truncated bool               `json:"truncated" jsonschema:"More groups existed than limit allowed. The groups returned are the largest ones."`
}

func spendReportPayload(report telemetry.SpendReport) spendReportOutput {
	groups := make([]spendGroupOutput, 0, len(report.Groups))
	for _, group := range report.Groups {
		groups = append(groups, spendGroupPayload(group))
	}
	return spendReportOutput{
		Dimension: string(report.Dimension),
		Since:     report.Since.Format(time.RFC3339),
		Until:     report.Until.Format(time.RFC3339),
		Groups:    groups,
		Totals:    spendGroupPayload(report.Totals),
		Truncated: report.Truncated,
	}
}

func spendGroupPayload(group telemetry.SpendGroup) spendGroupOutput {
	return spendGroupOutput{
		Key: group.Key, Observations: group.Observations,
		BilledInput: group.BilledInput(), UncachedInput: group.UncachedInput,
		CacheRead: group.CacheRead, CacheWrite: group.CacheWrite,
		Output: group.Output, Reasoning: group.Reasoning,
		MeasuredDurations: group.MeasuredDurations,
		TotalDurationMS:   group.TotalDurationMS, MaxDurationMS: group.MaxDurationMS,
	}
}
