package http

import (
	"context"
	"errors"
	"log/slog"
	stdhttp "net/http"
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

// The peer half of the cost report: telemetry crossing a host boundary,
// read-only, in the direction of a union.
//
// This is the ONLY thing a fleet view needs from another machine and it is
// deliberately the whole of it. There is no merge here and there is nothing to
// merge: each daemon computes its own report from its own SQLite file, and the
// caller keeps the answers apart, labelled by the host that gave them. A row
// never changes host, no identity is reconciled across machines, and a peer
// that never answers subtracts nothing from what the others said.
//
// Three decisions on this route are load-bearing.
//
//   - It refuses a LOOPBACK caller. The operator's cost report is behind the
//     admin token; if this route also answered locally, every process on the
//     machine would have an unauthenticated way to read what that token gates.
//     A peer is a different principal with a different credential -- a verified
//     tailnet identity an operator named -- and it gets exactly this one
//     projection and nothing else.
//
//   - It reuses adminCostPayload rather than projecting the report again. The
//     operator's report, the agent's report and a peer's report are then the
//     same sections computed once: an unobserved section is still ABSENT and
//     named, a lossy recorder is still declared, and no reader can be shown a
//     figure another reader would compute differently.
//
//   - It is BOUNDED, and that bound is the point of the file. A cost report is
//     several correlated aggregate queries and each of them holds a connection
//     from a small read pool for as long as it runs. Left unbounded, a peer --
//     slow, hostile, or merely running a loop -- could hold every read
//     connection this daemon has and stall the agents on THIS machine, which
//     would make accepting a peer strictly worse than refusing one. So
//     concurrency is capped well below the pool, the excess is refused
//     immediately with BACKPRESSURE rather than queued, and every accepted
//     request carries a deadline it cannot outlive.
const PathLocalPeerCost = "/api/v1/local/peer/cost"

const (
	// defaultPeerCostInflight is how many peer cost reports may run at once. It
	// is a small constant rather than a fraction of the read pool because the
	// property that matters is a FLOOR of connections left for local work, and
	// a fraction of a pool sized from NumCPU leaves none on a small machine.
	defaultPeerCostInflight = 2
	// defaultPeerCostTimeout bounds one report. It is generous compared with a
	// healthy report and still finite, so a pathological window cannot pin a
	// connection until the client gives up.
	defaultPeerCostTimeout = 15 * time.Second
)

// PeerCostDependencies configures the peer cost route.
type PeerCostDependencies struct {
	// Cost is the same reader the operator's route uses. A nil reader makes the
	// route report the missing capability, exactly as the admin route does: an
	// empty report would be a claim that this host cost nothing, which is a
	// statement about the host rather than about the daemon, and a fleet total
	// built from it would be quietly short.
	Cost telemetry.CostAdminReader
	// MaxInflight caps concurrent reports. Zero takes the default; a negative
	// value is a composition error rather than "unbounded".
	MaxInflight int
	// Timeout bounds one report. Zero takes the default.
	Timeout time.Duration
	Logger  *slog.Logger
}

type peerCostHandler struct {
	costs    telemetry.CostAdminReader
	inflight chan struct{}
	timeout  time.Duration
	logger   *slog.Logger
	now      func() time.Time
}

// NewPeerCostHandler serves GET /api/v1/local/peer/cost to verified peers.
func NewPeerCostHandler(dependencies PeerCostDependencies) (stdhttp.Handler, error) {
	if dependencies.MaxInflight < 0 || dependencies.Timeout < 0 {
		return nil, errors.New("peer cost transport bounds cannot be negative")
	}
	inflight := dependencies.MaxInflight
	if inflight == 0 {
		inflight = defaultPeerCostInflight
	}
	timeout := dependencies.Timeout
	if timeout == 0 {
		timeout = defaultPeerCostTimeout
	}
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	handler := &peerCostHandler{inflight: make(chan struct{}, inflight),
		timeout: timeout, logger: logger, now: time.Now}
	if !isNil(dependencies.Cost) {
		handler.costs = dependencies.Cost
	}
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("GET "+PathLocalPeerCost, handler.report)
	return localSafety(mux), nil
}

func (handler *peerCostHandler) report(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	identity, verified := Peer(request)
	if !verified {
		// A loopback caller lands here, and the refusal names the route it
		// should have used rather than pretending this one does not exist:
		// the operator's report is the same sections behind the admin token.
		writeLocalProblem(writer, stdhttp.StatusForbidden, domain.ErrorCodeForbidden,
			"this route serves verified tailnet peers; read this host's own cost report through the admin API")
		return
	}
	values := request.URL.Query()
	if !rejectQueryCredentials(writer, values) {
		return
	}
	values, ok := localAdminQuery(writer, values, "project_key", "since_hours", "limit")
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
	// Admission is refused rather than queued. A peer that is told to come back
	// retries with its own budget; a peer parked in a queue holds a request
	// slot here AND still gets a slow answer, which is the worst of both.
	select {
	case handler.inflight <- struct{}{}:
		defer func() { <-handler.inflight }()
	default:
		handler.logger.Warn("peer cost report refused for concurrency",
			slog.String("machine_name", identity.MachineName), slog.String("stable_id", identity.StableID),
			slog.Int("limit", cap(handler.inflight)))
		writer.Header().Set("Retry-After", "1")
		writeLocalProblem(writer, stdhttp.StatusServiceUnavailable, domain.ErrorCodeBackpressure,
			"too many peer cost reports are already running on this host")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	report, err := handler.costs.AdminCostReport(ctx,
		telemetry.AdminCostQuery{ProjectKey: projectKey, Since: since, Limit: limit})
	if err != nil {
		handler.logger.Error("peer cost report failed",
			slog.String("machine_name", identity.MachineName), slog.Any("error", err))
		writeLocalError(writer, err)
		return
	}
	writeLocalJSON(writer, stdhttp.StatusOK, adminCostPayload(projectKey, report))
}
