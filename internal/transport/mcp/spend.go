package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application"
)

// ToolSpendReport is the observation plane's only agent-facing surface.
//
// One tool, not several. Every tool costs every session a slice of its context
// on every turn, and the plane would happily grow a tool per question -- spend
// by model, by agent, slowest spans -- that a single dimension parameter
// answers just as well. It is also registered only when a telemetry reader is
// composed, so a daemon that collects nothing does not advertise a tool that
// can only answer zero.
const ToolSpendReport = "blackbird_spend_report"

type spendReportInput struct {
	AgentToken string `json:"agent_token"`
	Dimension  string `json:"dimension,omitempty" jsonschema:"How to group the rollup. model, agent, and harness answer where the tokens went; span_kind and span_name answer where the time went, and report durations with zero tokens because a span has none. Defaults to model."`
	SinceHours uint32 `json:"since_hours,omitempty" jsonschema:"How far back to look. Defaults to 24 and is capped at 720; a larger value is clamped rather than rejected."`
	MineOnly   bool   `json:"mine_only,omitempty" jsonschema:"Report only your own spend rather than the whole project's. This is how you answer what your own session has cost."`
	Limit      uint16 `json:"limit,omitempty" jsonschema:"How many groups to return, largest first. Defaults to 10, capped at 50; the report says whether more existed."`
}

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
	Dimension string             `json:"dimension"`
	Since     string             `json:"since"`
	Groups    []spendGroupOutput `json:"groups"`
	Totals    spendGroupOutput   `json:"totals" jsonschema:"Totals over the whole window, not merely the groups returned, so they stay honest when truncated is true."`
	Truncated bool               `json:"truncated" jsonschema:"More groups existed than limit allowed. The groups returned are the largest ones."`
}

func registerSpendTool(server *sdkmcp.Server, store application.LocalCoordinationStore,
	observations application.TelemetryReader, logger *slog.Logger) {
	schema := coordinationInputSchema[spendReportInput](func(properties map[string]*jsonschema.Schema) {
		properties["dimension"].Default = json.RawMessage(`"model"`)
		properties["dimension"].Enum = []any{
			string(application.SpendByModel), string(application.SpendByAgent),
			string(application.SpendByHarness), string(application.SpendBySpanKind),
			string(application.SpendBySpanName),
		}
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolSpendReport,
		Description: "Report where this project's tokens and time went, grouped and ranked. Use it to answer " +
			"what a session has cost before starting expensive work, which model or agent is consuming the " +
			"budget, and -- with span_kind or span_name -- which activity is actually taking the wall clock. " +
			"It returns totals, never individual calls, because a page of raw observations would cost more " +
			"context than the answer is worth. The report always covers your own project; set mine_only to " +
			"narrow it to yourself. An empty report means nothing was recorded in the window, not that " +
			"nothing was spent.",
		InputSchema: schema},
		func(ctx context.Context, input spendReportInput) (spendReportOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return spendReportOutput{}, err
			}
			query := application.SpendQuery{
				Dimension: application.SpendDimension(input.Dimension),
				MineOnly:  input.MineOnly,
				Limit:     input.Limit,
			}
			if query.Dimension == "" {
				query.Dimension = application.SpendByModel
			}
			if input.SinceHours > 0 {
				query.Since = time.Now().UTC().Add(-time.Duration(input.SinceHours) * time.Hour)
			}
			report, err := observations.SpendReport(ctx, session, query)
			if err != nil {
				return spendReportOutput{}, err
			}
			return spendReportPayload(report), nil
		})
}

func spendReportPayload(report application.SpendReport) spendReportOutput {
	groups := make([]spendGroupOutput, 0, len(report.Groups))
	for _, group := range report.Groups {
		groups = append(groups, spendGroupPayload(group))
	}
	return spendReportOutput{
		Dimension: string(report.Dimension),
		Since:     report.Since.Format(time.RFC3339),
		Groups:    groups,
		Totals:    spendGroupPayload(report.Totals),
		Truncated: report.Truncated,
	}
}

func spendGroupPayload(group application.SpendGroup) spendGroupOutput {
	return spendGroupOutput{
		Key: group.Key, Observations: group.Observations,
		BilledInput: group.BilledInput(), UncachedInput: group.UncachedInput,
		CacheRead: group.CacheRead, CacheWrite: group.CacheWrite,
		Output: group.Output, Reasoning: group.Reasoning,
		MeasuredDurations: group.MeasuredDurations,
		TotalDurationMS:   group.TotalDurationMS, MaxDurationMS: group.MaxDurationMS,
	}
}
