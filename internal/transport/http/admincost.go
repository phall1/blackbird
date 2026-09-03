package http

import (
	stdhttp "net/http"
	"strconv"
	"time"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

// The operator's cost route.
//
// It is a SEPARATE dependency from the admin store, and optional, because a
// daemon composed without an observation reader can still serve every other
// admin projection. When it is absent the route reports the capability missing
// rather than an empty report: an empty report would say this project cost
// nothing, which is a claim about the project instead of about the daemon.
//
// The project is named in the query string and required. That is the scope
// decision the agent-facing query deliberately does not have -- an agent reads
// the workspace it authenticated into or nothing -- and it is made here, at the
// boundary where the credential is the loopback admin token rather than an
// agent registration.

const PathLocalAdminCost = "/api/v1/local/admin/cost"

func (handler *adminHandler) cost(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	values, ok := handler.guard(writer, request, "project_key", "since_hours", "limit")
	if !ok {
		return
	}
	if handler.costs == nil {
		writeLocalProblem(writer, stdhttp.StatusServiceUnavailable, domain.ErrorCodeDependencyUnavailable,
			"this daemon was composed without an observation reader, so it cannot answer cost")
		return
	}
	projectKey, ok := localAdminProjectKey(writer, values, true)
	if !ok {
		return
	}
	limit, ok := localAdminLimit(writer, values)
	if !ok {
		return
	}
	since, ok := localAdminSinceHours(writer, values, handler.now())
	if !ok {
		return
	}
	report, err := handler.costs.AdminCostReport(request.Context(),
		telemetry.AdminCostQuery{ProjectKey: projectKey, Since: since, Limit: limit})
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	writeLocalJSON(writer, stdhttp.StatusOK, adminCostPayload(projectKey, report))
}

// localAdminSinceHours reads the window's start as a lookback rather than an
// absolute instant, so an operator never has to agree with the daemon about
// what time it is. Zero means the service default, which the application layer
// applies -- this handler does not invent one, because two defaults are how the
// CLI and the daemon end up reporting different windows.
func localAdminSinceHours(writer stdhttp.ResponseWriter, values map[string][]string,
	now time.Time) (time.Time, bool) {
	text := ""
	if got := values["since_hours"]; len(got) > 0 {
		text = got[0]
	}
	if text == "" {
		return time.Time{}, true
	}
	hours, err := strconv.ParseUint(text, 10, 32)
	if err != nil || hours == 0 {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
			"since_hours must be a positive whole number of hours")
		return time.Time{}, false
	}
	return now.UTC().Add(-time.Duration(hours) * time.Hour), true
}

// adminCostPayload projects the report onto the wire, keeping every rule the
// report itself keeps: an unobserved section is absent and named, and the
// recorder's loss is carried whether or not any section was observed -- a
// window that recorded nothing while the journal was shedding is exactly the
// case a reader must not read as quiet.
func adminCostPayload(projectKey string, report telemetry.CostReport) adminapi.CostReport {
	payload := adminapi.CostReport{
		ProjectKey: projectKey,
		Since:      report.Since.UTC().Format(time.RFC3339),
		Until:      report.Until.UTC().Format(time.RFC3339),
	}
	if report.Recording.Lossy() {
		payload.Recording = &adminapi.CostRecording{Dropped: report.Recording.Dropped,
			Written: report.Recording.Written}
	}
	if report.Contention.Observed() {
		payload.Contention = adminCostContention(report.Contention)
	} else {
		payload.Unobserved = append(payload.Unobserved, "contention")
	}
	if report.Abandonment.Observed() {
		payload.Abandonment = adminCostAbandonment(report.Abandonment)
	} else {
		payload.Unobserved = append(payload.Unobserved, "abandonment")
	}
	if report.Cache.Observed() {
		payload.Cache = adminCostCache(report.Cache)
	} else {
		payload.Unobserved = append(payload.Unobserved, "cache")
	}
	return payload
}

func adminCostContention(cost telemetry.ContentionCost) *adminapi.CostContention {
	contention := &adminapi.CostContention{
		Refusals: cost.Refusals, PathWaits: cost.PathWaits, MailWaits: cost.MailWaits,
		WaitsEndedFree: cost.WaitsEndedFree, WaitsEndedMail: cost.WaitsEndedMail,
		WaitsEndedDeadline: cost.WaitsEndedDeadline, WaitsEndedAbandoned: cost.WaitsEndedAbandoned,
		WaitsEndedStopped: cost.WaitsEndedStopped, WaitsEndedUnknown: cost.WaitsEndedUnknown,
		ParkedMS: cost.ParkedMS, LongestParkMS: cost.LongestParkMS, Truncated: cost.Truncated,
	}
	for _, agent := range cost.Agents {
		contention.Agents = append(contention.Agents, adminapi.CostBlockedAgent{
			AgentName: agent.AgentName, ActorID: agent.ActorID.String(), Refusals: agent.Refusals,
			PathWaits: agent.PathWaits, WaitsEndedDeadline: agent.WaitsEndedDeadline,
			ParkedMS: agent.ParkedMS, ModelCalls: agent.ModelCalls,
			BilledInput: agent.BilledInput, Output: agent.Output})
	}
	for _, path := range cost.Paths {
		contention.Paths = append(contention.Paths, adminapi.CostPath{Path: path.Path,
			Kind: path.Kind, Refusals: path.Refusals, BlockedAgents: path.BlockedAgents})
	}
	return contention
}

func adminCostAbandonment(cost telemetry.AbandonmentCost) *adminapi.CostAbandonment {
	abandonment := &adminapi.CostAbandonment{
		Abandoned: cost.Abandoned, Released: cost.Released,
		AbandonedHeldMS: cost.AbandonedHeldMS, ReleasedHeldMS: cost.ReleasedHeldMS,
		RefusalsDuring: cost.RefusalsDuring, Truncated: cost.Truncated,
	}
	for _, lease := range cost.Leases {
		abandonment.Leases = append(abandonment.Leases, adminapi.CostLease{
			LeaseID: lease.LeaseID.String(), HolderAgent: lease.HolderAgentName,
			Mode: string(lease.Mode), HeldMS: lease.HeldMS, Refusals: lease.Refusals,
			BlockedAgents: lease.BlockedAgents, ContendedPath: lease.ContendedPath})
	}
	return abandonment
}

// adminCostCache omits a ratio whose denominator is zero rather than sending
// 0.0. A model that wrote no cache has no reuse ratio at all, and a renderer
// given a zero cannot tell "caching is failing" from "caching was never used".
func adminCostCache(cost telemetry.CacheEconomics) *adminapi.CostCache {
	cache := &adminapi.CostCache{Truncated: cost.Truncated}
	for _, model := range cost.Models {
		row := adminapi.CostModel{Model: model.Model, Calls: model.Calls,
			UncachedInput: model.UncachedInput, CacheRead: model.CacheRead,
			CacheWrite: model.CacheWrite, Output: model.Output}
		if share, ok := model.CacheReadShare(); ok {
			row.CacheReadShare = &share
		}
		if reuse, ok := model.CacheReuse(); ok {
			row.CacheReuse = &reuse
		}
		cache.Models = append(cache.Models, row)
	}
	return cache
}
