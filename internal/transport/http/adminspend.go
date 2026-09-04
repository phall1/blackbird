package http

import (
	stdhttp "net/http"
	"time"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

// The operator's spend route.
//
// It is a SEPARATE dependency from the admin store and from the cost reader,
// and optional, for the same reason the cost route is: a daemon composed
// without an observation reader still serves every other admin projection, and
// the route it cannot answer reports the capability missing rather than an
// empty report, because an empty report would say this project spent nothing,
// which is a claim about the project instead of about the daemon.
//
// The project is named in the query string and required -- the scope decision
// the agent-facing query deliberately does not have, made at the boundary
// where the credential is the loopback admin token rather than an agent
// registration. The consumer this route exists for is an external coordinator
// answering "what did this repository cost" without holding an agent
// registration in every project it watches.

const PathLocalAdminSpend = "/api/v1/local/admin/spend"

func (handler *adminHandler) spend(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	values, ok := handler.guard(writer, request, "project_key", "dimension", "since_hours", "limit")
	if !ok {
		return
	}
	if handler.spends == nil {
		writeLocalProblem(writer, stdhttp.StatusServiceUnavailable, domain.ErrorCodeDependencyUnavailable,
			"this daemon was composed without an observation reader, so it cannot answer spend")
		return
	}
	projectKey, ok := localAdminProjectKey(writer, values, true)
	if !ok {
		return
	}
	dimension, ok := localAdminSpendDimension(writer, values)
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
	report, err := handler.spends.AdminSpendReport(request.Context(),
		telemetry.AdminSpendQuery{ProjectKey: projectKey, Dimension: dimension, Since: since, Limit: limit})
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	writeLocalJSON(writer, stdhttp.StatusOK, adminSpendPayload(projectKey, report))
}

// localAdminSpendDimension reads the rollup's grouping. It is required rather
// than defaulted: "where did the budget go" grouped by model and the same
// question grouped by agent answer different decisions, and a default would
// let a caller believe it asked one while reading the other.
func localAdminSpendDimension(writer stdhttp.ResponseWriter,
	values map[string][]string) (telemetry.SpendDimension, bool) {
	text := ""
	if got := values["dimension"]; len(got) > 0 {
		text = got[0]
	}
	dimension := telemetry.SpendDimension(text)
	if !dimension.Valid() {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
			"dimension must be one of model, agent, harness, span_kind, span_name")
		return "", false
	}
	return dimension, true
}

// adminSpendPayload projects the report onto the wire, keeping the rule the
// report itself keeps: totals cover the whole window rather than the returned
// groups, so a truncated report still states honest totals and Truncated says
// when the tail was cut.
func adminSpendPayload(projectKey string, report telemetry.SpendReport) adminapi.SpendReport {
	payload := adminapi.SpendReport{
		ProjectKey: projectKey,
		Dimension:  string(report.Dimension),
		Since:      report.Since.UTC().Format(time.RFC3339),
		Until:      report.Until.UTC().Format(time.RFC3339),
		Totals:     adminSpendGroup(report.Totals),
		Truncated:  report.Truncated,
	}
	for _, group := range report.Groups {
		payload.Groups = append(payload.Groups, adminSpendGroup(group))
	}
	return payload
}

func adminSpendGroup(group telemetry.SpendGroup) adminapi.SpendGroup {
	return adminapi.SpendGroup{
		Key: group.Key, Observations: group.Observations,
		UncachedInput: group.UncachedInput, CacheRead: group.CacheRead,
		CacheWrite: group.CacheWrite, Output: group.Output, Reasoning: group.Reasoning,
		MeasuredDurations: group.MeasuredDurations, TotalDurationMS: group.TotalDurationMS,
		MaxDurationMS: group.MaxDurationMS,
	}
}
