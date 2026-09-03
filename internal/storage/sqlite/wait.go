package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
)

// coordinationWaitBlockers bounds the evidence a wait carries back. The wait's
// own decision does not depend on it -- "nothing conflicts" is len(blockers)==0
// either way -- so this only decides how many holders a caller is told about,
// and a caller that has to talk to more than a handful of agents at once has a
// coordination problem no listing solves.
const coordinationWaitBlockers = 8

// AwaitCoordination parks the caller until the path it wants stops being held,
// until mail addressed to it arrives, or until a bounded budget runs out --
// reporting which of the three happened.
//
// It exists because MCP gives a model no channel it observes between tool
// calls. An agent refused a lease can otherwise only spin on the same tool or
// abandon the work, and abandoning is the expensive failure. A bounded
// server-side long poll is the only shape of "wait" a model on the far side of
// a request/response transport can actually use.
//
// It polls rather than waiting on a condition broadcast, and that is a
// deliberate trade. A broadcast would have to be signalled from every write
// path that could possibly satisfy a waiter, which couples every command in the
// store to this feature and silently stops working the moment a new one forgets
// to signal -- and it would still miss a change made by the CLI's own
// connection or by a restore. Polling asks the database, which is the authority
// either way. What matters is the cost of asking: each poll is its own short
// read-only snapshot that gives its pooled connection straight back, so a
// waiter parked for the full minute holds none of the five daemon-wide read
// connections between polls and never touches the write arbiter at all.
func (store *Store) AwaitCoordination(ctx context.Context, session coordination.LocalAgentSession,
	request coordination.WaitRequest) (coordination.WaitResult, error) {
	mode, err := validateCoordinationWait(session, request)
	if err != nil {
		return coordination.WaitResult{}, err
	}
	budget := boundedWaitBudget(request.Timeout)
	started := time.Now()
	deadline := started.Add(budget)
	// Every exit from the loop below records one fact, because the value of a
	// wait record is the reason it ended and a path that returned without one
	// would leave that reason unknowable. The observation is filled in as the
	// wait proceeds and written by the deferred call, so no exit can forget it
	// -- including the two that return an error rather than a result.
	observation := coordination.WaitObservation{WorkspaceID: session.WorkspaceID, Waiter: session.ActorID,
		WaiterSession: session.ActorSessionID, Path: request.Path, Mode: mode,
		AwaitMail: request.AwaitMail, Budget: budget, StartedAt: started.UTC()}
	defer func() {
		// Waited comes from the monotonic reading `started` still carries;
		// EndedAt is the wall-clock instant. Deriving the duration from the two
		// stored instants instead would measure the wall clock, which can step.
		observation.Waited = time.Since(started)
		observation.EndedAt = time.Now().UTC()
		store.contention.RecordWait(observation)
	}()
	// mailFloor is the caller's mail head at the first poll, so the wait ends
	// on mail that arrives during it rather than on mail that was already
	// sitting there. Deliveries only ever gain rows, so a monotonic head is a
	// sound "something new" test where an unread count is not: reading a
	// message would otherwise look exactly like one arriving.
	mailFloor := int64(-1)
	for {
		state, stateErr := store.coordinationWaitState(ctx, session, request, mode)
		if stateErr != nil {
			observation.Reason = interruptedWaitReason(ctx)
			return coordination.WaitResult{}, stateErr
		}
		if mailFloor < 0 {
			mailFloor = state.mailHead
		}
		result := coordination.WaitResult{Blockers: state.blockers,
			PendingDeliveries: state.unread, ObservedAtUS: state.observedAtUS,
			WaitedMS: time.Since(started).Milliseconds()}
		observation.PendingDeliveries = state.unread
		observation.BlockedBy = contentionHolders(state.blockers)
		switch {
		case request.AwaitMail && state.mailHead > mailFloor:
			result.Reason = coordination.WaitMailArrived
			observation.Reason = result.Reason
			return result, nil
		case request.Path != "" && len(state.blockers) == 0:
			result.Reason = coordination.WaitPathFree
			observation.Reason = result.Reason
			return result, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			result.Reason = coordination.WaitDeadline
			observation.Reason = result.Reason
			return result, nil
		}
		if err := sleepBounded(ctx, min(remaining, coordination.WaitPoll)); err != nil {
			observation.Reason = interruptedWaitReason(ctx)
			return coordination.WaitResult{}, err
		}
	}
}

// interruptedWaitReason separates the three ways a wait can end without
// reaching any of its conditions, and refuses to guess between them.
//
// The cancellation CAUSE is what distinguishes them, and reading it is not
// optional. This daemon's shutdown cancels every in-flight request context
// before draining, so a cancelled context is not evidence that the caller went
// anywhere: without the cause, every restart -- and the updater restarts this
// daemon on a schedule -- would write a crop of abandonment facts about agents
// that were waiting perfectly patiently. The composition root cancels with
// coordination.ErrDaemonStopping precisely so this function can tell the two
// apart.
//
// So: our own shutdown is recorded as such, any other cancellation is the
// caller walking away, and anything else is a durable read that failed mid-poll
// -- the condition at that instant was never evaluated, so the reason is left
// absent and stored as null. Filling any of them in with "deadline" would
// invent a budget that never ran out and would count an agent that is still
// working as one that gave up.
func interruptedWaitReason(ctx context.Context) coordination.WaitReason {
	if ctx.Err() == nil {
		return ""
	}
	if errors.Is(context.Cause(ctx), coordination.ErrDaemonStopping) {
		return coordination.WaitDaemonStopping
	}
	return coordination.WaitAbandoned
}

// contentionHolders reduces the wait's blockers to what the recorded fact
// needs. The admin view carries selectors and claim generations for a caller
// deciding what to do next; the fact needs only who was in the way and until
// when, and a journal row is not the place to duplicate a projection.
func contentionHolders(blockers []coordination.AdminReservation) []coordination.ContentionHolder {
	if len(blockers) == 0 {
		return nil
	}
	if len(blockers) > coordination.MaxContentionHolders {
		blockers = blockers[:coordination.MaxContentionHolders]
	}
	holders := make([]coordination.ContentionHolder, 0, len(blockers))
	for _, blocker := range blockers {
		holders = append(holders, coordination.ContentionHolder{LeaseID: blocker.LeaseID,
			Actor: blocker.HolderActorID, Mode: blocker.Mode,
			ExpiresAt: coordination.TimeFromMicros(blocker.ExpiresAtUS)})
	}
	return holders
}

// boundedWaitBudget clamps what the caller asked for rather than trusting it.
// The ceiling is a property of the daemon's ability to answer at all, not a
// preference the caller may raise: a wait holds an agent's turn, and one that
// outlives a client's own request timeout is indistinguishable from a hung
// daemon. Zero, and anything nonsensical, asks for the ceiling.
func boundedWaitBudget(requested time.Duration) time.Duration {
	if requested <= 0 || requested > coordination.MaxWait {
		return coordination.MaxWait
	}
	return requested
}

// sleepBounded waits out one poll interval without leaving a timer behind, and
// reports a cancelled context as the cancellation it is rather than as a
// deadline the caller would read as "still blocked".
func sleepBounded(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validateCoordinationWait(session coordination.LocalAgentSession,
	request coordination.WaitRequest) (coordination.LeaseMode, error) {
	if session.ProjectKey == "" || session.WorkspaceID.IsZero() || session.ActorID.IsZero() {
		return "", coordination.ErrInvalid
	}
	// A request that names neither condition can only ever return the deadline,
	// which is an expensive way to sleep and never what the caller meant.
	if request.Path == "" && !request.AwaitMail {
		return "", coordination.ErrInvalid
	}
	if request.Path != "" && !validLocalCoordinationText(request.Path, coordination.MaxLeaseSelectorBytes) {
		return "", coordination.ErrInvalid
	}
	// Exclusive is the default because it is the strictest reading: it treats
	// every overlapping lease as a blocker, so an unstated intent can never
	// report a path free earlier than the caller's real acquisition would find
	// it.
	switch request.Mode {
	case "", coordination.LeaseExclusive:
		return coordination.LeaseExclusive, nil
	case coordination.LeaseShared:
		return coordination.LeaseShared, nil
	default:
		return "", coordination.ErrInvalid
	}
}

// coordinationWaitState is one observation of both conditions, taken inside a
// single read snapshot so the blockers, the mail head and the observation
// instant all describe the same moment.
type coordinationWaitState struct {
	blockers     []coordination.AdminReservation
	mailHead     int64
	unread       int
	observedAtUS int64
}

func (store *Store) coordinationWaitState(ctx context.Context, session coordination.LocalAgentSession,
	request coordination.WaitRequest, mode coordination.LeaseMode) (coordinationWaitState, error) {
	var state coordinationWaitState
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, now time.Time) error {
		if request.Path != "" {
			blockers, blockerErr := coordinationWaitBlockersFor(ctx, tx, session, request.Path, mode, timeMicros(now))
			if blockerErr != nil {
				return blockerErr
			}
			state.blockers = blockers
		}
		if !request.AwaitMail {
			return nil
		}
		// The head is the highest message position ever delivered to this
		// actor; the count is what is still unread, which is the number that
		// makes a wakeup actionable without a second call.
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(m.position), 0),
			count(*) FILTER (WHERE d.read_at_us IS NULL)
			FROM message_deliveries AS d JOIN messages AS m USING(message_id)
			WHERE d.recipient_actor_id = ? AND m.workspace_id = ?`,
			session.ActorID.String(), session.WorkspaceID.String()).Scan(&state.mailHead, &state.unread); err != nil {
			return fmt.Errorf("read SQLite coordination wait mail head: %w", err)
		}
		return nil
	})
	if err != nil {
		return coordinationWaitState{}, err
	}
	state.observedAtUS = observed
	return state, nil
}

// coordinationWaitBlockersFor asks the reservation reader the same question the
// operator's CLI asks, with the two predicates a waiter needs and an operator
// does not: the caller's own leases are never blockers -- an agent renewing or
// widening its own reservation would otherwise wait for itself forever -- and a
// shared reader is held up only by an exclusive writer, which is the same rule
// AcquireLease applies when it decides a conflict.
func coordinationWaitBlockersFor(ctx context.Context, tx *sql.Tx, session coordination.LocalAgentSession,
	path string, mode coordination.LeaseMode, nowMicros int64) ([]coordination.AdminReservation, error) {
	query := coordination.AdminReservationsQuery{ProjectKey: session.ProjectKey,
		State: coordination.AdminReservationActive, Path: path, Limit: coordinationWaitBlockers}
	if mode == coordination.LeaseShared {
		query.Mode = coordination.LeaseExclusive
	}
	blockers, _, err := adminReservationRows(ctx, tx, query, coordination.AdminReservationActive,
		coordinationWaitBlockers, nowMicros,
		reservationScope{workspaceID: session.WorkspaceID.String(), excludeHolder: session.ActorID.String()})
	if err != nil {
		return nil, err
	}
	for position := range blockers {
		selectors, selectorErr := adminLeaseSelectors(ctx, tx, blockers[position].LeaseID)
		if selectorErr != nil {
			return nil, selectorErr
		}
		blockers[position].Selectors = selectors
	}
	return blockers, nil
}
