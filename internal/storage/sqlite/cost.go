package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

// The cost report is the one query nothing but this store can answer.
//
// Spend lives in telemetry_model_calls keyed by (project_key, actor_id,
// session_id). Causality lives in coordination_events and leases keyed by
// (workspace_id, actor_id) and holder_actor_id. Those are the SAME identities
// in the SAME SQLite file, so every join below is an equality on a column
// rather than a fuzzy match on a name and a timestamp. That is the whole reason
// the observation plane landed here rather than in a service that would have to
// guess.
//
// Two properties are load-bearing and easy to lose in a later edit:
//
//   - Every payload read goes through CAST(payload AS TEXT). The journal's
//     payload is a BLOB holding JSON TEXT, and SQLite's json_extract treats a
//     bare BLOB argument as JSONB -- a different, binary encoding -- so
//     extracting without the cast silently reads garbage rather than failing.
//
//   - Abandonment is classified by leaseExpiredPredicate and
//     leaseReleasedPredicate from admin.go, never by a copy. A lease's bucket
//     depends on its release stamp against its deadline rather than on its
//     status, because the expiry reaper rewrites status as a side effect of an
//     unrelated acquisition; a second definition here would report a different
//     number from the operator's listing for the same lease.

// costPayload extracts one JSON field from a journal payload. Everything the
// cost report reads from a payload goes through it, so the BLOB-to-TEXT cast
// cannot be forgotten in one place and remembered in another.
func costPayload(path string) string {
	return `json_extract(CAST(events.payload AS TEXT), '` + path + `')`
}

// costContentionFilter selects the journal's two non-success facts for one
// workspace and window. Both the totals and every grouping share it, so a
// grouped row can never cover a different set of events than the totals it is
// compared against.
//
// The window is CLOSED at both ends. A half-open `>= since` filter reports a
// row stamped in the future inside every window that starts before it, forever
// -- so one event with a bad timestamp lands in a "last hour" report that
// genuinely contains nothing, and the report states an Until it does not
// enforce. Every window in this file is bounded above at the same scope.nowUS
// the report publishes as Until.
const costContentionFilter = `WHERE events.workspace_id = ?
	AND events.occurred_at_us >= ? AND events.occurred_at_us <= ?
	AND events.event_type IN ('lease.refused', 'wait.completed')`

// A path wait is a wait that named a path, and it is the only kind that counts
// as contention. A mail-only wait is an idle agent rather than a blocked one,
// and summing its parked milliseconds into the contention total would report a
// quiet project polling for mail as a heavily contended one.
var (
	costIsRefusal   = `events.event_type = 'lease.refused'`
	costIsWait      = `events.event_type = 'wait.completed'`
	costIsPathWait  = `(` + costIsWait + ` AND ` + costPayload("$.path") + ` IS NOT NULL)`
	costIsMailWait  = `(` + costIsWait + ` AND ` + costPayload("$.path") + ` IS NULL)`
	costWaitedMS    = costPayload("$.waited_ms")
	costWaitReason  = costPayload("$.reason")
	costHolderLease = costPayload("$.holder.lease_id")
	// costWaitUnknown is the wait whose end condition was never evaluated. It
	// is the ONLY bucket keyed on a null reason, which is what keeps "not
	// determined" from being read as any of the five determined outcomes.
	costWaitUnknown = `(` + costIsWait + ` AND ` + costWaitReason + ` IS NULL)`
)

// costEndedFor counts one determined wait end-reason. Together with
// costWaitUnknown the six account for every completed wait, which is asserted
// rather than assumed -- see telemetry.ContentionCost.WaitsAccounted. The
// reasons are constants of the coordination plane rather than literals here, so
// a renamed reason breaks the build instead of silently emptying a bucket.
func costEndedFor(reason coordination.WaitReason) string {
	return `(` + costIsWait + ` AND ` + costWaitReason + ` = '` + string(reason) + `')`
}

// CostReport joins spend to the causality underneath it for one project over
// one window.
//
// The project and workspace are the session's, always. Like the spend rollup
// and the reservations projection, a caller does not name a scope: an agent
// reads its own workspace or nothing.
func (store *Store) CostReport(ctx context.Context, session coordination.LocalAgentSession,
	query telemetry.CostQuery) (telemetry.CostReport, error) {
	if session.ProjectKey == "" || session.WorkspaceID.IsZero() || session.ActorID.IsZero() {
		return telemetry.CostReport{}, coordination.ErrInvalid
	}
	if err := query.Validate(); err != nil {
		return telemetry.CostReport{}, err
	}
	now := time.Now().UTC()
	query = query.Normalized(now)
	scope := costScope{
		workspace:  session.WorkspaceID.String(),
		projectKey: session.ProjectKey,
		sinceUS:    query.Since.UnixMicro(),
		nowUS:      timeMicros(now),
		limit:      int64(query.Limit),
	}
	if query.MineOnly {
		scope.actor = session.ActorID.String()
	}

	// The recorder's own counters travel with the report. Every contention
	// count below is a floor whenever it has dropped a fact, and the reader
	// cannot know that from the numbers themselves -- shedding is silent by
	// design, because a fact that could push back on a refusal would defeat the
	// point of recording it.
	return store.costSections(ctx, telemetry.CostReport{Since: query.Since, Until: now,
		MineOnly: query.MineOnly, Recording: store.recordingHealth()}, scope)
}

// AdminCostReport answers the same three questions for an operator, over a
// project it names rather than a session it authenticated into.
//
// It shares every query below with the agent report, deliberately: two
// implementations of "what did contention cost" would drift, and the operator's
// number disagreeing with the agent's about the same window is precisely the
// kind of discrepancy nobody can debug. The only differences are where the
// scope comes from -- a named project resolved to its workspace, instead of the
// session's own -- and that there is no caller to narrow to.
func (store *Store) AdminCostReport(ctx context.Context,
	query telemetry.AdminCostQuery) (telemetry.CostReport, error) {
	if err := query.Validate(); err != nil {
		return telemetry.CostReport{}, err
	}
	if !validLocalCoordinationText(query.ProjectKey, coordination.MaxKeyBytes) {
		return telemetry.CostReport{}, coordination.ErrInvalid
	}
	now := time.Now().UTC()
	query = query.Normalized(now)
	var workspace string
	err := store.db.QueryRowContext(ctx, `SELECT workspace_id FROM coordination_projects
		WHERE project_key = ?`, query.ProjectKey).Scan(&workspace)
	if errors.Is(err, sql.ErrNoRows) {
		// A project this daemon has never seen is not an empty report -- an
		// empty report would say "this project cost nothing", which is a claim
		// about a project rather than about a typo.
		return telemetry.CostReport{}, coordinationError(domain.ErrorCodeNotFound,
			"no such project in this daemon's coordination store")
	}
	if err != nil {
		return telemetry.CostReport{}, fmt.Errorf("resolve admin cost project: %w", err)
	}
	scope := costScope{workspace: workspace, projectKey: query.ProjectKey,
		sinceUS: query.Since.UnixMicro(), nowUS: timeMicros(now), limit: int64(query.Limit)}
	return store.costSections(ctx, telemetry.CostReport{Since: query.Since, Until: now,
		Recording: store.recordingHealth()}, scope)
}

// costSections fills the three sections onto a report whose window and scope
// are already decided. Both entry points route through it, so neither can grow
// a section the other lacks.
func (store *Store) costSections(ctx context.Context, report telemetry.CostReport,
	scope costScope) (telemetry.CostReport, error) {
	var err error
	if report.Contention, err = store.contentionCost(ctx, scope); err != nil {
		return telemetry.CostReport{}, err
	}
	if report.Abandonment, err = store.abandonmentCost(ctx, scope); err != nil {
		return telemetry.CostReport{}, err
	}
	if report.Cache, err = store.cacheEconomics(ctx, scope); err != nil {
		return telemetry.CostReport{}, err
	}
	return report, nil
}

// recordingHealth translates the journal's counters into the report's own
// vocabulary. Every kind of loss is summed into one figure because the reader's
// question is "how much am I missing", and a full queue, a closed journal, an
// unencodable fact and a failed commit all answer it identically.
func (store *Store) recordingHealth() telemetry.RecordingHealth {
	stats := store.ContentionStats()
	return telemetry.RecordingHealth{Offered: stats.Offered, Written: stats.Written,
		Dropped: stats.Lost()}
}

// costScope is everything the three sections share. nowUS is taken once for the
// whole report so the abandonment classification cannot straddle a tick and
// count one lease in two buckets.
type costScope struct {
	workspace  string
	projectKey string
	// actor is empty unless the query asked for the caller only. It narrows
	// contention and cache but never abandonment: a lease someone else
	// abandoned is the thing a caller most needs to be told about and cannot
	// see from its own side.
	actor   string
	sinceUS int64
	nowUS   int64
	limit   int64
}

func (scope costScope) contentionArgs() (string, []any) {
	filter := costContentionFilter
	arguments := []any{scope.workspace, scope.sinceUS, scope.nowUS}
	if scope.actor != "" {
		filter += " AND events.actor_id = ?"
		arguments = append(arguments, scope.actor)
	}
	return filter, arguments
}

func (store *Store) contentionCost(ctx context.Context, scope costScope) (telemetry.ContentionCost, error) {
	filter, arguments := scope.contentionArgs()
	var cost telemetry.ContentionCost
	// COUNT over a conditional expression would count the zeros too, so every
	// tally is a SUM of a boolean. The parked milliseconds sum only over path
	// waits, and MAX likewise, so a long mail poll cannot become the report's
	// worst park.
	statement := `SELECT
		COALESCE(SUM(` + costIsRefusal + `), 0),
		COALESCE(SUM(` + costIsPathWait + `), 0),
		COALESCE(SUM(` + costIsMailWait + `), 0),
		COALESCE(SUM(` + costEndedFor(coordination.WaitPathFree) + `), 0),
		COALESCE(SUM(` + costEndedFor(coordination.WaitMailArrived) + `), 0),
		COALESCE(SUM(` + costEndedFor(coordination.WaitDeadline) + `), 0),
		COALESCE(SUM(` + costEndedFor(coordination.WaitAbandoned) + `), 0),
		COALESCE(SUM(` + costEndedFor(coordination.WaitDaemonStopping) + `), 0),
		COALESCE(SUM(` + costWaitUnknown + `), 0),
		COALESCE(SUM(CASE WHEN ` + costIsPathWait + ` THEN ` + costWaitedMS + ` END), 0),
		COALESCE(MAX(CASE WHEN ` + costIsPathWait + ` THEN ` + costWaitedMS + ` END), 0)
		FROM coordination_events AS events ` + filter
	if err := store.db.QueryRowContext(ctx, statement, arguments...).Scan(&cost.Refusals, &cost.PathWaits,
		&cost.MailWaits, &cost.WaitsEndedFree, &cost.WaitsEndedMail, &cost.WaitsEndedDeadline,
		&cost.WaitsEndedAbandoned, &cost.WaitsEndedStopped, &cost.WaitsEndedUnknown,
		&cost.ParkedMS, &cost.LongestParkMS); err != nil {
		return telemetry.ContentionCost{}, fmt.Errorf("aggregate contention cost: %w", err)
	}
	if !cost.Observed() {
		// Nothing was recorded, so there is nothing to group. Returning here
		// keeps the section's emptiness a single fact rather than an empty
		// slice a reader has to interpret.
		return cost, nil
	}
	agents, agentsTruncated, err := store.blockedAgents(ctx, scope)
	if err != nil {
		return telemetry.ContentionCost{}, err
	}
	cost.Agents = agents
	paths, pathsTruncated, err := store.contendedPaths(ctx, scope)
	if err != nil {
		return telemetry.ContentionCost{}, err
	}
	cost.Paths = paths
	cost.Truncated = agentsTruncated || pathsTruncated
	return cost, nil
}

// blockedAgents is the join the whole report is for: one row per agent carrying
// what contention it met and what it spent, over the same window and keyed on
// the same actor_id.
//
// The spend arrives through a derived table rather than a correlated subquery
// so it is aggregated once for the window instead of once per group, and
// through a LEFT JOIN so an agent with contention and no telemetry keeps its
// contention counts instead of vanishing from the report.
func (store *Store) blockedAgents(ctx context.Context, scope costScope) ([]telemetry.BlockedAgent, bool, error) {
	filter, arguments := scope.contentionArgs()
	// started_at_us is supplied by the adapter that recorded the call, not by
	// this daemon, and nothing clamps it at ingest -- the column's only CHECK is
	// that it is positive. A harness with a skewed clock therefore writes calls
	// dated in the future, and an unbounded window would attribute their tokens
	// to every report from now until that date passes. Bounded at the same
	// instant the report publishes as Until.
	spendFilter := "WHERE project_key = ? AND started_at_us >= ? AND started_at_us <= ?"
	spendArgs := []any{scope.projectKey, scope.sinceUS, scope.nowUS}
	if scope.actor != "" {
		spendFilter += " AND actor_id = ?"
		spendArgs = append(spendArgs, scope.actor)
	}
	statement := `SELECT events.actor_id, COALESCE(agents.agent_name, ''),
		COALESCE(SUM(` + costIsRefusal + `), 0),
		COALESCE(SUM(` + costIsPathWait + `), 0),
		COALESCE(SUM(events.event_type = 'wait.completed' AND ` + costWaitReason + ` = 'deadline'), 0),
		COALESCE(SUM(CASE WHEN ` + costIsPathWait + ` THEN ` + costWaitedMS + ` END), 0),
		COALESCE(MAX(spend.calls), 0), COALESCE(MAX(spend.billed), 0), COALESCE(MAX(spend.output), 0)
		FROM coordination_events AS events
		LEFT JOIN coordination_agents AS agents ON agents.actor_id = events.actor_id
		LEFT JOIN (SELECT actor_id, COUNT(*) AS calls,
			SUM(uncached_input_tokens + cache_read_tokens + cache_write_tokens) AS billed,
			SUM(output_tokens) AS output
			FROM telemetry_model_calls ` + spendFilter + ` GROUP BY actor_id) AS spend
			ON spend.actor_id = events.actor_id
		` + filter + `
		GROUP BY events.actor_id, agents.agent_name
		-- Ranked by how much contention the agent MET -- refusals plus parked
		-- waits -- before how long it was parked. Ordering by parked time first
		-- would bury the agent that never calls wait and simply retries, which
		-- is the commonest shape of contention and the one with the clearest
		-- fix. Spend is never the sort key: this section ranks by what an agent
		-- ran into, not by how expensive it happens to be.
		ORDER BY 3 + 4 DESC, 6 DESC, events.actor_id ASC LIMIT ?`
	// The spend subquery's parameters bind before the outer filter's because
	// the derived table is written before the WHERE clause it joins into. One
	// row beyond the limit is read to detect truncation, the same way the spend
	// rollup does it -- a second counting query would be a second scan.
	all := append(append(append([]any{}, spendArgs...), arguments...), scope.limit+1)
	rows, err := store.db.QueryContext(ctx, statement, all...)
	if err != nil {
		return nil, false, fmt.Errorf("group blocked agents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	agents := make([]telemetry.BlockedAgent, 0, scope.limit)
	truncated := false
	for rows.Next() {
		var agent telemetry.BlockedAgent
		var actorText string
		if err := rows.Scan(&actorText, &agent.AgentName, &agent.Refusals, &agent.PathWaits,
			&agent.WaitsEndedDeadline, &agent.ParkedMS, &agent.ModelCalls, &agent.BilledInput,
			&agent.Output); err != nil {
			return nil, false, fmt.Errorf("read blocked agent: %w", err)
		}
		if int64(len(agents)) == scope.limit {
			truncated = true
			break
		}
		actor, parseErr := domain.ParseActorID(actorText)
		if parseErr != nil {
			return nil, false, fmt.Errorf("parse blocked agent actor: %w", parseErr)
		}
		agent.ActorID = actor
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("group blocked agents: %w", err)
	}
	return agents, truncated, nil
}

// contendedPaths groups refusals by the HOLDER's selector from the recorded
// overlap. The overlap is the pair that actually collided, written down when
// the refusal was decided, so this reads the reason for the refusal rather than
// re-deriving which of the requested and held selectors met -- which would put
// a second implementation of the overlap rule at the far end of the journal.
func (store *Store) contendedPaths(ctx context.Context, scope costScope) ([]telemetry.ContendedPath, bool, error) {
	filter, arguments := scope.contentionArgs()
	statement := `SELECT COALESCE(` + costPayload("$.overlap.holder.path") + `, ''),
		COALESCE(` + costPayload("$.overlap.holder.kind") + `, ''),
		COUNT(*), COUNT(DISTINCT events.actor_id)
		FROM coordination_events AS events ` + filter + ` AND ` + costIsRefusal + `
		GROUP BY 1, 2 ORDER BY 3 DESC, 1 ASC LIMIT ?`
	rows, err := store.db.QueryContext(ctx, statement, append(append([]any{}, arguments...), scope.limit+1)...)
	if err != nil {
		return nil, false, fmt.Errorf("group contended paths: %w", err)
	}
	defer func() { _ = rows.Close() }()
	paths := make([]telemetry.ContendedPath, 0, scope.limit)
	truncated := false
	for rows.Next() {
		var path telemetry.ContendedPath
		if err := rows.Scan(&path.Path, &path.Kind, &path.Refusals, &path.BlockedAgents); err != nil {
			return nil, false, fmt.Errorf("read contended path: %w", err)
		}
		if int64(len(paths)) == scope.limit {
			truncated = true
			break
		}
		paths = append(paths, path)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("group contended paths: %w", err)
	}
	return paths, truncated, nil
}

// costRefusalsByLease is the exact join from an abandoned lease to what it
// refused. A refusal records the blocking lease's id, so this is an equality on
// a key rather than an overlap of two time ranges -- which would have credited
// a lease with refusals caused by whoever held the path before it.
//
// It is deliberately NOT windowed by scope.sinceUS: a lease acquired inside the
// window may have refused someone at any point in its life, and the window
// selects the lease rather than the refusal. The journal is prunable, so this
// count can only understate.
var costRefusalsByLease = `SELECT ` + costHolderLease + ` AS holder_lease,
	COUNT(*) AS refusals, COUNT(DISTINCT events.actor_id) AS blocked,
	MIN(` + costPayload("$.overlap.holder.path") + `) AS contended_path
	FROM coordination_events AS events
	WHERE events.workspace_id = ? AND events.event_type = 'lease.refused'
	GROUP BY holder_lease`

func (store *Store) abandonmentCost(ctx context.Context, scope costScope) (telemetry.AbandonmentCost, error) {
	var cost telemetry.AbandonmentCost
	// Both buckets and both held-time sums come from the shared predicates, so
	// this section and the operator's reservation listing cannot disagree about
	// which leases were abandoned. An abandoned lease held its path to its
	// deadline; a released one to its release stamp.
	statement := `SELECT
		COALESCE(SUM(CASE WHEN ` + leaseExpiredPredicate + ` THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN ` + leaseReleasedPredicate + ` THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN ` + leaseExpiredPredicate + `
			THEN (l.expires_at_us - l.acquired_at_us) / 1000 END), 0),
		COALESCE(SUM(CASE WHEN ` + leaseReleasedPredicate + `
			THEN (l.released_at_us - l.acquired_at_us) / 1000 END), 0)
		FROM leases AS l
		WHERE l.workspace_id = ? AND l.acquired_at_us >= ? AND l.acquired_at_us <= ?`
	if err := store.db.QueryRowContext(ctx, statement, scope.nowUS, scope.nowUS,
		scope.workspace, scope.sinceUS, scope.nowUS).Scan(&cost.Abandoned, &cost.Released,
		&cost.AbandonedHeldMS, &cost.ReleasedHeldMS); err != nil {
		return telemetry.AbandonmentCost{}, fmt.Errorf("aggregate abandonment cost: %w", err)
	}
	if !cost.Observed() {
		return cost, nil
	}
	leases, truncated, err := store.abandonedLeases(ctx, scope)
	if err != nil {
		return telemetry.AbandonmentCost{}, err
	}
	cost.Leases = leases
	cost.Truncated = truncated
	refused, err := store.abandonedRefusalTotal(ctx, scope)
	if err != nil {
		return telemetry.AbandonmentCost{}, err
	}
	cost.RefusalsDuring = refused
	return cost, nil
}

// abandonedLeases returns the worst offenders, and the refusals they caused
// come from a separate total.
//
// The total is summed over ALL abandoned leases in the window rather than over
// the returned page, so a truncated list still reports an honest total -- the
// same rule the spend rollup's totals follow, and the reason it is its own
// statement rather than a sum of the rows below.
//
// Ordering is by refusals caused, not by how long the lease was held. A lease
// held for an hour that blocked nobody cost nothing, and ranking it above one
// that blocked four agents for a minute would sort the report by the wrong
// thing entirely.
func (store *Store) abandonedLeases(ctx context.Context,
	scope costScope) ([]telemetry.AbandonedLease, bool, error) {
	statement := `SELECT l.lease_id, COALESCE(agents.agent_name, ''), l.mode,
		(l.expires_at_us - l.acquired_at_us) / 1000,
		COALESCE(refusals.refusals, 0), COALESCE(refusals.blocked, 0),
		COALESCE(refusals.contended_path, '')
		FROM leases AS l
		LEFT JOIN coordination_agents AS agents ON agents.actor_id = l.holder_actor_id
		LEFT JOIN (` + costRefusalsByLease + `) AS refusals ON refusals.holder_lease = l.lease_id
		WHERE l.workspace_id = ? AND l.acquired_at_us >= ? AND l.acquired_at_us <= ?
			AND ` + leaseExpiredPredicate + `
		ORDER BY 5 DESC, 4 DESC, l.lease_id ASC LIMIT ?`
	// The derived table's parameter binds before the outer filter's, because
	// the join is written before the WHERE clause it feeds.
	arguments := []any{scope.workspace, scope.workspace, scope.sinceUS, scope.nowUS,
		scope.nowUS, scope.limit + 1}
	rows, err := store.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("list abandoned leases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	leases := make([]telemetry.AbandonedLease, 0, scope.limit)
	truncated := false
	for rows.Next() {
		var lease telemetry.AbandonedLease
		var leaseText, modeText string
		if err := rows.Scan(&leaseText, &lease.HolderAgentName, &modeText, &lease.HeldMS,
			&lease.Refusals, &lease.BlockedAgents, &lease.ContendedPath); err != nil {
			return nil, false, fmt.Errorf("read abandoned lease: %w", err)
		}
		if int64(len(leases)) == scope.limit {
			truncated = true
			break
		}
		id, parseErr := domain.ParseLeaseID(leaseText)
		if parseErr != nil {
			return nil, false, fmt.Errorf("parse abandoned lease id: %w", parseErr)
		}
		lease.LeaseID = id
		lease.Mode = coordination.LeaseMode(modeText)
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("list abandoned leases: %w", err)
	}
	return leases, truncated, nil
}

// abandonedRefusalTotal counts every refusal caused by an abandoned lease in
// the window, whether or not that lease made the page. A total taken from the
// page would shrink as the limit shrank, which would make the most alarming
// number in this report an artefact of how much of it the caller asked for.
func (store *Store) abandonedRefusalTotal(ctx context.Context, scope costScope) (uint64, error) {
	statement := `SELECT COALESCE(SUM(refusals.refusals), 0)
		FROM (` + costRefusalsByLease + `) AS refusals
		JOIN leases AS l ON l.lease_id = refusals.holder_lease
		WHERE l.workspace_id = ? AND l.acquired_at_us >= ? AND l.acquired_at_us <= ?
			AND ` + leaseExpiredPredicate
	var total uint64
	if err := store.db.QueryRowContext(ctx, statement, scope.workspace, scope.workspace,
		scope.sinceUS, scope.nowUS, scope.nowUS).Scan(&total); err != nil {
		return 0, fmt.Errorf("total refusals caused by abandonment: %w", err)
	}
	return total, nil
}

// cacheEconomics keeps the three input classes apart, which is the entire point
// of the section. Summing them into one "input" number would hide that cache
// reads run one to two orders of magnitude above uncached input, and a caller
// cannot recover the split from the sum.
func (store *Store) cacheEconomics(ctx context.Context, scope costScope) (telemetry.CacheEconomics, error) {
	filter := "WHERE calls.project_key = ? AND calls.started_at_us >= ? AND calls.started_at_us <= ?"
	arguments := []any{scope.projectKey, scope.sinceUS, scope.nowUS}
	if scope.actor != "" {
		filter += " AND calls.actor_id = ?"
		arguments = append(arguments, scope.actor)
	}
	statement := `SELECT calls.model, COUNT(*),
		COALESCE(SUM(calls.uncached_input_tokens), 0), COALESCE(SUM(calls.cache_read_tokens), 0),
		COALESCE(SUM(calls.cache_write_tokens), 0), COALESCE(SUM(calls.output_tokens), 0)
		FROM telemetry_model_calls AS calls ` + filter + `
		GROUP BY calls.model
		ORDER BY SUM(calls.uncached_input_tokens + calls.cache_read_tokens +
			calls.cache_write_tokens) DESC, calls.model ASC LIMIT ?`
	rows, err := store.db.QueryContext(ctx, statement, append(append([]any{}, arguments...), scope.limit+1)...)
	if err != nil {
		return telemetry.CacheEconomics{}, fmt.Errorf("group cache economics: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var cost telemetry.CacheEconomics
	for rows.Next() {
		var model telemetry.ModelCacheEconomics
		if err := rows.Scan(&model.Model, &model.Calls, &model.UncachedInput, &model.CacheRead,
			&model.CacheWrite, &model.Output); err != nil {
			return telemetry.CacheEconomics{}, fmt.Errorf("read cache economics: %w", err)
		}
		if int64(len(cost.Models)) == scope.limit {
			cost.Truncated = true
			break
		}
		cost.Models = append(cost.Models, model)
	}
	if err := rows.Err(); err != nil {
		return telemetry.CacheEconomics{}, fmt.Errorf("group cache economics: %w", err)
	}
	return cost, nil
}
