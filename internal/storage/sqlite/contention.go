package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
)

var _ coordination.ContentionRecorder = (*contentionJournal)(nil)
var _ coordination.ContentionReporter = (*Store)(nil)

// The contention journal is buffered, and that is a correctness requirement
// rather than a tuning choice.
//
// A refusal is decided while the daemon-wide write lock is held, inside the
// very transaction that is about to roll back -- so the fact cannot ride that
// transaction, and writing it durably where it is decided would put a second
// fsync on the claim path. Authentication was taken off the durable path to
// lift this daemon from roughly 195 to 15,300 calls per second; a synchronous
// write per denial hands exactly that back, and a retry storm -- the case that
// produces denials fastest -- is precisely when it would hurt most. So the
// facts go through a bounded non-blocking queue and one goroutine batches them,
// the same shape and for the same reason as the telemetry sink.
//
// Everything else follows from the ADR-0001 rule that an observation may never
// fail a coordination write:
//
//   - offer never blocks and never returns an error. A full queue drops and
//     counts.
//
//   - The drain is the only writer, it batches, and it takes the ordinary write
//     lane. A lease acquire waits behind at most one contention commit, and
//     that commit is NOT cheap: this store ships fullfsync on, so one costs
//     what BenchmarkCommitLatency/fullfsync=on reports -- milliseconds, three
//     orders of magnitude above the refusal it is bookkeeping for. That is the
//     whole reason for the pacing below rather than an argument against it: one
//     commit per coalesce window puts a bounded, single-digit-percent duty
//     cycle on the write lane whatever the contention rate, where an unpaced
//     drain would put the same commit behind every batch. Derive both numbers
//     rather than trusting this sentence: run BenchmarkCommitLatency and
//     BenchmarkRefusedClaim in this package.
//
//   - The drain is PACED, so the journal's share of the write lane is bounded
//     by the clock rather than by how hard the daemon is being contended.
//     Batching alone is not enough: a drain that commits as fast as facts
//     arrive commits once per batch, and measured on the refusal benchmark that
//     cost 25 microseconds per denial -- a 44% regression on a path whose whole
//     point is that it does not pay for durability. One commit per coalesce
//     window turns that into noise, and an arrival rate above what the window
//     can carry sheds load at the queue instead of pushing back on the refusal.
//
//   - A malformed fact is dropped before it is queued, so one bad fact cannot
//     roll back a batch of good ones.
//
//   - A write failure is counted and dropped. Nothing above the drain learns
//     about it, because nothing above the drain is entitled to change behaviour
//     when a bookkeeping row does not land.
//
// Shedding is the price of all of that, and it is why ContentionStats is not
// optional bookkeeping. Above the sustained rate one coalesce window carries,
// the queue drops -- and it drops NON-UNIFORMLY, hardest during exactly the
// retry storm a reader most wants counted. A refusal total built from a
// silently decimated sample is worse than no total, because it reads as a
// precise number and invites the conclusion that a quiet report was a quiet
// window. So every reader of these facts has to state the loss beside them:
// CostReport carries these stats through to its own callers, and the
// composition root logs them at shutdown. Neither is decoration.
const (
	// contentionQueueDepth is measured in facts and is one drain pass deep
	// several times over, so an ordinary contention spike is absorbed whole.
	// The queue exists to hold the gap between deciding a refusal and
	// committing it, and a depth that drops during a spike would lose exactly
	// the data the spike is worth recording for.
	contentionQueueDepth = 1024
	// contentionBatchSize bounds one write transaction. Bigger batches amortize
	// the fsync better and hold the write lane longer, and holding it longer is
	// the thing this journal is forbidden from doing. With the pacing below,
	// this is also the journal's sustained capacity per window -- above roughly
	// a thousand contention facts a second it starts shedding, which is orders
	// of magnitude past any rate a real project produces.
	contentionBatchSize = 128
	// contentionCoalesce is both how long the drain waits for a batch to fill
	// and the minimum interval between two contention commits. Nothing is
	// waiting on a contention fact, so freshness is the cheap side of this
	// trade and the write lane is the expensive one.
	contentionCoalesce = 100 * time.Millisecond
	// contentionFlushBudget bounds the drain's final attempt at shutdown. A
	// clean stop should not lose the last few facts and must not delay the
	// daemon's exit to save them.
	contentionFlushBudget = 2 * time.Second
)

// contentionFact is one queued observation. Exactly one member is set; the
// encoding into a journal row happens on the drain rather than on the refused
// caller's goroutine, so the hot path pays a pointer and a channel send.
type contentionFact struct {
	refusal *coordination.ClaimRefusal
	wait    *coordination.WaitObservation
}

// contentionRequest is either a fact to write or a barrier to release. The
// barrier is how a caller waits for everything queued ahead of it to land
// without the drain giving up its position as the only writer.
type contentionRequest struct {
	fact    contentionFact
	barrier chan struct{}
}

type contentionJournal struct {
	commit func(context.Context, []contentionFact) error
	queue  chan contentionRequest

	closeOnce sync.Once
	closed    chan struct{}
	done      chan struct{}

	offered        atomic.Uint64
	written        atomic.Uint64
	droppedFull    atomic.Uint64
	droppedClosed  atomic.Uint64
	droppedInvalid atomic.Uint64
	droppedWrite   atomic.Uint64
	writeFailures  atomic.Uint64
	batches        atomic.Uint64
}

func newContentionJournal(commit func(context.Context, []contentionFact) error) *contentionJournal {
	return &contentionJournal{
		commit: commit,
		queue:  make(chan contentionRequest, contentionQueueDepth),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// startContentionJournal is composed with the store rather than injected,
// because both producers -- AcquireLease and AwaitCoordination -- live here and
// the buffering exists to keep a durable write off this store's own hot path.
// The drain runs until Close, which flushes it while the database is still
// open.
func (store *Store) startContentionJournal() {
	store.contention = newContentionJournal(store.appendContentionFacts)
	go store.contention.run()
}

// ContentionStats reports what the journal did. Drops are surfaced rather than
// hidden: a journal that silently loses refusals would let a reader conclude
// that a quiet period was an uncontended one.
func (store *Store) ContentionStats() coordination.ContentionStats {
	if store.contention == nil {
		return coordination.ContentionStats{}
	}
	return store.contention.stats()
}

func (journal *contentionJournal) RecordClaimRefusal(refusal coordination.ClaimRefusal) {
	journal.offer(contentionFact{refusal: &refusal})
}

func (journal *contentionJournal) RecordWait(observation coordination.WaitObservation) {
	journal.offer(contentionFact{wait: &observation})
}

// offer is the whole of the "an observation cannot fail an operation"
// guarantee: no error return, no blocking send, and a nil journal is a
// deployment that does not record contention rather than a fault.
func (journal *contentionJournal) offer(fact contentionFact) {
	if journal == nil {
		return
	}
	if !fact.recordable() {
		journal.droppedInvalid.Add(1)
		return
	}
	select {
	case <-journal.closed:
		journal.droppedClosed.Add(1)
		return
	default:
	}
	select {
	case journal.queue <- contentionRequest{fact: fact}:
		journal.offered.Add(1)
	default:
		journal.droppedFull.Add(1)
	}
}

func (journal *contentionJournal) run() {
	defer close(journal.done)
	defer journal.recoverDrain()
	for {
		select {
		case <-journal.closed:
			journal.flushRemaining()
			return
		case first := <-journal.queue:
			journal.write(context.Background(), journal.collect(first))
			// Pacing, not throttling: the interval starts after the commit, so
			// the journal can never take two turns of the write lane inside one
			// window however many facts are waiting. A queue that overflows
			// while this runs is the intended relief valve. A close during the
			// interval cuts it short rather than delaying the final flush.
			if !journal.pace() {
				journal.flushRemaining()
				return
			}
		}
	}
}

func (journal *contentionJournal) pace() bool {
	timer := time.NewTimer(contentionCoalesce)
	defer timer.Stop()
	select {
	case <-journal.closed:
		return false
	case <-timer.C:
		return true
	}
}

// collect greedily fills a batch from whatever is already queued, waiting no
// longer than the coalesce window for more.
func (journal *contentionJournal) collect(first contentionRequest) []contentionRequest {
	batch := make([]contentionRequest, 0, contentionBatchSize)
	batch = append(batch, first)
	timer := time.NewTimer(contentionCoalesce)
	defer timer.Stop()
	for len(batch) < contentionBatchSize {
		select {
		case next := <-journal.queue:
			batch = append(batch, next)
		case <-timer.C:
			return batch
		case <-journal.closed:
			return batch
		}
	}
	return batch
}

// write is where a failure stops. Barriers are released whatever happened,
// because a caller waiting for the queue to drain is waiting for the attempt,
// not for a result it has no way to act on.
func (journal *contentionJournal) write(ctx context.Context, batch []contentionRequest) {
	facts := make([]contentionFact, 0, len(batch))
	for _, request := range batch {
		if request.barrier == nil {
			facts = append(facts, request.fact)
		}
	}
	defer func() {
		for _, request := range batch {
			if request.barrier != nil {
				close(request.barrier)
			}
		}
	}()
	if len(facts) == 0 {
		return
	}
	journal.batches.Add(1)
	if err := journal.commit(ctx, facts); err != nil {
		// Both counters move: one batch failed, and every fact in it is gone.
		// The report needs the second number, because a batch is up to
		// contentionBatchSize facts and counting failures would understate the
		// loss by that factor.
		journal.writeFailures.Add(1)
		journal.droppedWrite.Add(uint64(len(facts)))
		return
	}
	journal.written.Add(uint64(len(facts)))
}

// flushRemaining makes one bounded attempt at whatever is still queued, on a
// fresh context because the one that just ended is why we are here.
func (journal *contentionJournal) flushRemaining() {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), contentionFlushBudget)
	defer cancel()
	for {
		batch := make([]contentionRequest, 0, contentionBatchSize)
		for len(batch) < contentionBatchSize {
			select {
			case request := <-journal.queue:
				batch = append(batch, request)
				continue
			default:
			}
			break
		}
		if len(batch) == 0 {
			return
		}
		journal.write(ctx, batch)
		if ctx.Err() != nil {
			return
		}
	}
}

// flush waits for every fact queued before this call to have been attempted. It
// is the drain's own ordering that makes it work, so it needs no second writer
// and no lock; it exists because a test that asserts a fact landed must not
// assert it by sleeping.
func (journal *contentionJournal) flush(ctx context.Context) error {
	if journal == nil {
		return nil
	}
	barrier := make(chan struct{})
	select {
	case journal.queue <- contentionRequest{barrier: barrier}:
	case <-journal.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-barrier:
		return nil
	case <-journal.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (journal *contentionJournal) stop() {
	if journal == nil {
		return
	}
	journal.closeOnce.Do(func() { close(journal.closed) })
	<-journal.done
}

// recoverDrain keeps a defect in this journal from taking the daemon down with
// it. A panicking drain stops recording contention; it does not stop
// coordinating.
//
// The panic is counted rather than logged because this store carries no logger
// and a bookkeeping journal is not a reason to give it one. Counting is enough
// to make the stop visible: a journal whose drain died reports write failures
// it cannot explain and then a rising queue-full count, which is exactly the
// "the sample is partial" signal ContentionStats exists to give.
func (journal *contentionJournal) recoverDrain() {
	if recovered := recover(); recovered != nil {
		journal.writeFailures.Add(1)
	}
}

func (journal *contentionJournal) stats() coordination.ContentionStats {
	return coordination.ContentionStats{
		Offered:        journal.offered.Load(),
		Written:        journal.written.Load(),
		DroppedFull:    journal.droppedFull.Load(),
		DroppedClosed:  journal.droppedClosed.Load(),
		DroppedInvalid: journal.droppedInvalid.Load(),
		DroppedWrite:   journal.droppedWrite.Load(),
		WriteFailures:  journal.writeFailures.Load(),
		Batches:        journal.batches.Load(),
	}
}

// recordable rejects a fact the journal's CHECK constraints would reject
// anyway. Doing it here rather than at the insert is what keeps one malformed
// fact from rolling back a batch of sound ones.
func (fact contentionFact) recordable() bool {
	switch {
	case fact.refusal != nil:
		refusal := fact.refusal
		return !refusal.WorkspaceID.IsZero() && !refusal.RefusedActor.IsZero() &&
			!refusal.ProposedLeaseID.IsZero() && !refusal.Holder.LeaseID.IsZero() &&
			!refusal.Holder.Actor.IsZero() && !refusal.RefusedAt.IsZero()
	case fact.wait != nil:
		wait := fact.wait
		return !wait.WorkspaceID.IsZero() && !wait.Waiter.IsZero() &&
			!wait.WaiterSession.IsZero() && !wait.StartedAt.IsZero() && !wait.EndedAt.IsZero()
	default:
		return false
	}
}

// appendContentionFacts writes one drained batch in a single transaction on the
// ordinary write lane, exactly as the telemetry sink does and for the same
// reason: the security lane exists so identity work can preempt bulk writes,
// and an observation has no claim on it.
func (store *Store) appendContentionFacts(ctx context.Context, facts []contentionFact) error {
	if len(facts) == 0 {
		return nil
	}
	return store.withImmediate(ctx, func(tx *sql.Tx) error {
		insert, err := tx.PrepareContext(ctx, `INSERT INTO coordination_events(workspace_id, actor_id,
			event_type, subject_id, occurred_at_us, payload, visibility) VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare SQLite contention event insert: %w", err)
		}
		defer func() { _ = insert.Close() }()
		address, err := tx.PrepareContext(ctx,
			`INSERT INTO coordination_event_recipients(position, actor_id) VALUES (?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare SQLite contention recipient insert: %w", err)
		}
		defer func() { _ = address.Close() }()
		for _, fact := range facts {
			row, rowErr := contentionRow(fact)
			if rowErr != nil {
				return rowErr
			}
			written, err := insert.ExecContext(ctx, row.workspace, row.actor, string(row.eventType),
				row.subjectID, row.occurredAtUS, row.payload, row.visibility)
			if err != nil {
				return fmt.Errorf("append SQLite contention event: %w", err)
			}
			if len(row.recipients) == 0 {
				continue
			}
			position, err := written.LastInsertId()
			if err != nil {
				return fmt.Errorf("read SQLite contention event position: %w", err)
			}
			for _, recipient := range row.recipients {
				if _, err := address.ExecContext(ctx, position, recipient); err != nil {
					return fmt.Errorf("append SQLite contention event recipient: %w", err)
				}
			}
		}
		return nil
	})
}

type contentionEventRow struct {
	workspace    string
	actor        string
	eventType    coordination.EventType
	subjectID    string
	occurredAtUS int64
	payload      []byte
	visibility   string
	// recipients is the addressee list for a row whose visibility is
	// 'recipients'. It is empty for every other visibility, and the sync query
	// reads it rather than the event's own actor_id -- so a row that names
	// recipients must name ITSELF among them or its own author cannot see it.
	recipients []string
}

func contentionRow(fact contentionFact) (contentionEventRow, error) {
	switch {
	case fact.refusal != nil:
		return refusalRow(*fact.refusal)
	case fact.wait != nil:
		return waitRow(*fact.wait)
	default:
		return contentionEventRow{}, fmt.Errorf("%w: empty contention fact", coordination.ErrInvalid)
	}
}

// refusalRow attributes the fact to the REFUSED agent, not the holder: that is
// the identity whose model calls the refusal is a cost against, and it is the
// same (workspace, actor) pair telemetry_model_calls carries.
//
// Visibility is the two agents involved and nobody else, which is the same
// judgement waitRow makes and for the same reason. The point of recording a
// refusal in a stream at all is that the holder learns it is blocking someone
// and the refused agent has its own denial in order among the acquisitions it
// lost to; both are served by naming exactly those two as recipients. Workspace
// visibility would serve them too, and would additionally push every denial
// into every peer's event stream -- so a retry storm, which is the case that
// produces denials fastest and is precisely when this journal is most active,
// would spend every agent's context telling it about a collision between two
// other agents it can do nothing about. The operator's journal listing reads
// every visibility, so nothing is hidden from the surface that exists to answer
// contention questions, and the cost report reads the table directly.
func refusalRow(refusal coordination.ClaimRefusal) (contentionEventRow, error) {
	requested := make([]map[string]any, 0, len(refusal.RequestedSelectors))
	for _, selector := range refusal.RequestedSelectors {
		requested = append(requested, contentionSelectorFields(selector))
	}
	fields := map[string]any{
		"refused_session_id":  contentionOptionalText(refusal.RefusedSession.String()),
		"requested_mode":      string(refusal.RequestedMode),
		"requested_selectors": requested,
		"requested_ttl_ms":    refusal.RequestedTTL.Milliseconds(),
		// The overlap is the pair that actually collided. Without it a reader
		// has the requested set and the holder's set and has to re-derive which
		// two paths met -- re-implementing the overlap rule at the far end of
		// the journal, where it can drift from the one that decided the answer.
		"overlap": map[string]any{
			"requested": contentionSelectorFields(refusal.RequestedSelector),
			"holder":    contentionSelectorFields(refusal.HolderSelector),
		},
		"holder": contentionHolderFields(refusal.Holder),
	}
	payload, err := coordinationPayload(fields)
	if err != nil {
		return contentionEventRow{}, err
	}
	// The refused agent is listed alongside the holder because the sync query
	// matches a 'recipients' row only through this table, never through the
	// row's own actor_id: an author that is not its own recipient would be the
	// one party unable to read its own fact.
	recipients := []string{refusal.RefusedActor.String()}
	if holder := refusal.Holder.Actor.String(); holder != recipients[0] {
		recipients = append(recipients, holder)
	}
	return contentionEventRow{workspace: refusal.WorkspaceID.String(), actor: refusal.RefusedActor.String(),
		eventType: coordination.EventLeaseRefused, subjectID: refusal.ProposedLeaseID.String(),
		occurredAtUS: timeMicros(refusal.RefusedAt), payload: payload,
		visibility: coordinationVisibilityRecipients, recipients: recipients}, nil
}

// waitRow is actor-visible: a wait is the waiter's own idle time, and there is
// no second party with anything to do about it. That is the one place these two
// facts differ -- a refusal names two agents, a wait names one -- and neither
// reaches an agent that was not involved.
//
// The subject is the waiter's session rather than a minted id: a wait is not a
// durable object, the position is the row's identity, and the session is the
// thing the parked turn actually belonged to.
func waitRow(wait coordination.WaitObservation) (contentionEventRow, error) {
	fields := map[string]any{
		"waiter_session_id": wait.WaiterSession.String(),
		"reason":            contentionOptionalText(string(wait.Reason)),
		"await_mail":        wait.AwaitMail,
		"started_at_us":     timeMicros(wait.StartedAt),
		"ended_at_us":       timeMicros(wait.EndedAt),
		// The MONOTONIC duration, never EndedAt minus StartedAt. Those two are
		// wall-clock instants stripped of their monotonic reading, so their
		// difference goes negative across an NTP step or a suspend -- and it
		// would disagree with the WaitedMS the same wait returned to its caller.
		"waited_ms":          waitedMillis(wait),
		"budget_ms":          wait.Budget.Milliseconds(),
		"pending_deliveries": wait.PendingDeliveries,
	}
	if wait.Path != "" {
		fields["path"] = wait.Path
		fields["mode"] = string(wait.Mode)
	}
	if len(wait.BlockedBy) > 0 {
		holders := make([]map[string]any, 0, len(wait.BlockedBy))
		for _, holder := range wait.BlockedBy {
			holders = append(holders, contentionHolderFields(holder))
		}
		fields["blocked_by"] = holders
	}
	payload, err := coordinationPayload(fields)
	if err != nil {
		return contentionEventRow{}, err
	}
	return contentionEventRow{workspace: wait.WorkspaceID.String(), actor: wait.Waiter.String(),
		eventType: coordination.EventWaitCompleted, subjectID: wait.WaiterSession.String(),
		occurredAtUS: timeMicros(wait.EndedAt), payload: payload,
		visibility: coordinationVisibilityActor}, nil
}

// waitedMillis is the recorded park, clamped at zero. The clamp is belt and
// braces on top of the monotonic reading: a fact reaching this journal from any
// path that did not stamp Waited would otherwise write a negative duration into
// a payload field no CHECK constraint can guard, and one negative park poisons
// every sum the cost report takes over it.
func waitedMillis(wait coordination.WaitObservation) int64 {
	if wait.Waited <= 0 {
		return 0
	}
	return wait.Waited.Milliseconds()
}

func contentionSelectorFields(selector coordination.LeaseSelector) map[string]any {
	return map[string]any{"kind": string(selector.Kind()), "path": selector.Path()}
}

// contentionHolderFields carries the holder's deadline as an absolute instant.
// A remaining duration would be a countdown against the clock that wrote it,
// and this row is read long after that clock moved on.
func contentionHolderFields(holder coordination.ContentionHolder) map[string]any {
	fields := map[string]any{"lease_id": holder.LeaseID.String(), "actor_id": holder.Actor.String(),
		"mode": string(holder.Mode)}
	if !holder.ExpiresAt.IsZero() {
		fields["expires_at_us"] = timeMicros(holder.ExpiresAt)
	}
	return fields
}

// contentionOptionalText encodes an unknown value as JSON null rather than as
// the empty string, so "not determined" stays distinguishable from "determined
// to be nothing". It is the same discipline telemetry_model_calls.duration_ms
// holds for a latency a transcript never measured: NULL says not measured, 0
// says instant, and inventing the second where the first is true poisons every
// average the plane exists to compute.
func contentionOptionalText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
