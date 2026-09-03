package coordination

import (
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// Contention is the half of coordination that used to leave no trace.
//
// Every other fact in the journal is a success: a lease acquired, renewed or
// released, a message delivered, read or acknowledged. So the journal could
// account for everything that worked and nothing about what being blocked
// cost, and the one question this system is uniquely able to answer -- what did
// contention cost -- had no denominator. Token spend already lands in
// telemetry_model_calls under the same (project_key, actor_id, session_id)
// identity coordination uses, so once a refusal and a wait are written down the
// join from "who was blocked, for how long" to "what that agent's model calls
// cost" is direct rather than fuzzy.
//
// Both facts are OBSERVATIONS, never authority. A refusal is the product
// behaviour and it has already happened by the time there is anything to
// record; the record is bookkeeping about it. Every implementation of
// ContentionRecorder must therefore be unable to fail the operation it
// describes: it takes no error return, it may not block, and it may not share a
// transaction with the coordination write it observes.

// ContentionRecorder accepts contention facts and never reports failure.
//
// The absent-recorder case is the nil interface, which every caller must treat
// as "this deployment does not record contention" rather than as an error: a
// store composed without one refuses claims exactly as it always did.
type ContentionRecorder interface {
	// RecordClaimRefusal must not block and must not fail the refusal it
	// describes.
	RecordClaimRefusal(ClaimRefusal)
	// RecordWait must not block and must not fail the wait it describes.
	RecordWait(WaitObservation)
}

// MaxContentionHolders bounds the holders one contention fact names. A waiter
// held up by more agents than this has a coordination problem no longer list
// solves, and the payload has to stay small enough that recording it is never
// the expensive part of being refused.
const MaxContentionHolders = 8

// ClaimRefusal is one denied acquisition, carrying everything a later reader
// needs so that answering "who was blocked by whom, and for how long was that
// holder entitled to hold" costs no second lookup. All of it is already in
// scope where AcquireLease decides the conflict; the point of this type is that
// none of it is thrown away again.
type ClaimRefusal struct {
	WorkspaceID    domain.WorkspaceID
	RefusedActor   domain.ActorID
	RefusedSession domain.ActorSessionID
	// ProposedLeaseID is the lease the refused agent minted for the attempt. It
	// names no durable row -- the acquisition rolled back -- and is recorded as
	// the fact's subject because it is the caller's own handle on the attempt,
	// which is exactly what a retry storm needs to be distinguishable from one
	// stubborn agent.
	ProposedLeaseID    domain.LeaseID
	RequestedMode      LeaseMode
	RequestedSelectors []LeaseSelector
	RequestedTTL       time.Duration
	// RequestedSelector and HolderSelector are the pair that actually
	// overlapped, not the whole requested set intersected with the whole held
	// set. AcquireLease refuses on the first collision it finds, so this pair
	// is the reason for the refusal and the only pair a reader can act on.
	RequestedSelector LeaseSelector
	HolderSelector    LeaseSelector
	Holder            ContentionHolder
	RefusedAt         time.Time
}

// ContentionHolder is one active lease standing in someone's way. ExpiresAt is
// the holder's deadline as an absolute instant rather than a remaining
// duration, because a fact is read long after it is written and a countdown
// stored in a journal is a countdown against the wrong clock.
type ContentionHolder struct {
	LeaseID   domain.LeaseID
	Actor     domain.ActorID
	Mode      LeaseMode
	ExpiresAt time.Time
}

// WaitObservation is one completed bounded wait.
//
// Reason is the whole value of the record. A wait that ended because the path
// came free is coordination working; a wait that ended on its deadline is an
// agent about to abandon work. Collapsing them into one waited-milliseconds
// number would average the success and the failure together and report
// neither, so the reason is recorded rather than inferred -- and where it is
// genuinely not known it is recorded as absent rather than guessed.
type WaitObservation struct {
	WorkspaceID   domain.WorkspaceID
	Waiter        domain.ActorID
	WaiterSession domain.ActorSessionID
	// Path and Mode describe the lease the waiter intended to take, and are
	// empty for a mail-only wait.
	Path      string
	Mode      LeaseMode
	AwaitMail bool
	// Budget is the clamped deadline the wait actually ran under, not what the
	// caller asked for, so a deadline outcome is readable against the budget
	// that produced it.
	Budget    time.Duration
	StartedAt time.Time
	EndedAt   time.Time
	// Waited is how long the wait actually ran, measured on the MONOTONIC
	// clock, and it is the only duration a reader may trust. StartedAt and
	// EndedAt are wall-clock instants -- they answer "when", they survive being
	// stored, and Go strips the monotonic reading from a time.Time the moment
	// it is converted with UTC() -- so subtracting one from the other measures
	// the wall clock rather than the elapsed time and goes NEGATIVE across an
	// NTP step or a suspend. This field is stamped from the same monotonic
	// reading the caller's own WaitedMS comes from, so the journalled duration
	// and the returned one can never disagree.
	Waited time.Duration
	// Reason is the zero WaitReason when the wait's end condition was never
	// evaluated -- a store read that failed mid-poll. That is recorded as null,
	// never as a deadline: "not determined" and "the budget ran out" are
	// different facts, and writing the second one where the first is true would
	// invent an abandonment that never happened.
	Reason WaitReason
	// BlockedBy is whatever still conflicted when the wait ended, capped at
	// MaxContentionHolders. It is empty by construction when the path came
	// free.
	BlockedBy         []ContentionHolder
	PendingDeliveries int
}

// ContentionStats is the recorder's self-report, in the same spirit as the
// observation plane's: a recorder that silently loses facts is worse than none,
// because it invites conclusions from a sample nobody knows is partial.
type ContentionStats struct {
	Offered uint64
	Written uint64
	// DroppedFull counts facts refused because the queue was full, and
	// DroppedInvalid facts refused before they were queued because a row built
	// from them could not satisfy the journal's constraints. Both are losses;
	// neither is ever an error a caller sees.
	DroppedFull    uint64
	DroppedClosed  uint64
	DroppedInvalid uint64
	// DroppedWrite counts FACTS lost to a failed commit, where WriteFailures
	// counts the BATCHES that failed. They are both kept because they answer
	// different questions and one cannot be derived from the other: a batch
	// carries up to a hundred-odd facts, so reading WriteFailures as a loss
	// understates it by that factor, and reading DroppedWrite as a fault count
	// overstates how often the journal is failing.
	DroppedWrite  uint64
	WriteFailures uint64
	Batches       uint64
}

// Lost is every fact this recorder did not write, however it was lost. It is
// the figure a reader needs in order to know that a contention total is a floor;
// the individual counters above are for diagnosing which part of the journal is
// shedding.
func (stats ContentionStats) Lost() uint64 {
	return stats.DroppedFull + stats.DroppedClosed + stats.DroppedInvalid + stats.DroppedWrite
}

// ContentionReporter is the optional capability of a store that records
// contention. The composition root reads it to log what the recorder did, which
// is the only way a drop is ever visible.
type ContentionReporter interface {
	ContentionStats() ContentionStats
}
