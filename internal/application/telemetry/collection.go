package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// Observation ownership: why two mechanisms cannot count the same turn twice.
//
// The plane has two possible ways to learn what a model call cost. An adapter
// inside a harness can PUSH it to POST /api/v1/local/telemetry, which is what
// the OpenCode plugin and the Pi extension do. Or this daemon can COLLECT it by
// reading the ledger the harness already writes to disk.
//
// Collecting is strictly the better mechanism where a ledger exists: it sees
// sessions that ran while the daemon was down, it needs no per-harness
// extension surface -- which matters because most harnesses have no plugin API
// at all -- and it recovers history rather than only the present. Pushing is
// the only mechanism where no ledger exists, and it is the only one that can
// attribute spend to a registered agent, because the push carries that agent's
// registration token and a file on disk carries nothing of the kind.
//
// So the answer is neither "supplement" nor "replace" globally. Ownership is
// per harness, and it is a partition rather than a preference:
//
//	a harness this daemon collects  -> collected observations are admitted,
//	                                   pushed model calls for it are dropped
//	every other harness             -> pushed observations are admitted
//
// The partition is enforced HERE, at Sink.Offer, and not in the transport and
// not by asking adapters to stand down. Offer is the single entry to the only
// writer in the plane; both mechanisms pass through it. That is what makes
// double counting impossible by construction rather than by convention: there
// is no second door, and an adapter that keeps pushing a collected harness
// after an upgrade is harmless rather than silently inflationary.
//
// Dedupe on (actor, dedupe key) does NOT close this hole on its own and must
// not be mistaken for it. A pushed call is attributed to the registered agent
// that posted it, a collected one to the collector's own identity, and two
// different actors carrying the same message id are two rows.

// ObservationSource says which mechanism produced an envelope. The zero value
// is SourcePushed, so a transport that knows nothing about collection -- every
// existing one -- constructs a pushed envelope by doing nothing.
type ObservationSource uint8

const (
	// SourcePushed is an adapter running inside a harness, authenticated as a
	// registered agent.
	SourcePushed ObservationSource = iota
	// SourceCollected is this daemon reading a harness's own on-disk ledger.
	SourceCollected
)

func (source ObservationSource) String() string {
	if source == SourceCollected {
		return "collected"
	}
	return "pushed"
}

// CollectedHarnesses names the harnesses whose model calls this daemon reads
// itself. It is deliberately not a general "which observations do we own" map:
// a collector reads a token ledger and produces model calls, so span ownership
// is untouched and a harness plugin that reports build and test timing keeps
// reporting it after its token push is superseded.
type CollectedHarnesses map[domain.Harness]struct{}

// NewCollectedHarnesses copies the set so a caller cannot mutate a running
// sink's partition after composition.
func NewCollectedHarnesses(harnesses ...domain.Harness) CollectedHarnesses {
	if len(harnesses) == 0 {
		return nil
	}
	set := make(CollectedHarnesses, len(harnesses))
	for _, harness := range harnesses {
		set[harness] = struct{}{}
	}
	return set
}

func (set CollectedHarnesses) Collects(harness domain.Harness) bool {
	_, collected := set[harness]
	return collected
}

// Ingest is the port a collector writes through. It is the sink's own Offer,
// named at the application boundary so an adapter in the integration layer can
// depend on the contract without depending on the concrete sink -- and so a
// collector test can assert what was offered without running a drain.
type Ingest interface {
	Offer(Envelope) bool
}

var _ Ingest = (*Sink)(nil)

// The collector's identity.
//
// Attribution is normally taken from an authenticated session, because a push
// arrives with a registration token and that token is the only reason an
// adapter cannot bill its spend to another agent. A collector has no token: it
// is reading a file, and the file names a harness session rather than a
// Blackbird actor.
//
// Rather than guess a mapping that would sometimes be wrong, the collector
// attributes to a stable synthetic actor derived from the harness name. Three
// properties follow, and all three are wanted:
//
//   - It is DETERMINISTIC, so it survives a restart, a database rebuild, and a
//     machine move with nothing persisted. That is what makes the dedupe index
//     on (actor, dedupe key) collapse a re-scan of a transcript this daemon
//     already read, which is the second line of defence behind the byte
//     watermark.
//   - It is DISTINCT per harness, so one harness's ledger can never adopt
//     another's records.
//   - It resolves to NO registered agent, so a spend-by-agent rollup groups
//     collected spend under an empty key rather than attributing it to whoever
//     happened to be registered. The join is a LEFT JOIN precisely so an
//     observation outlives its agent; a collected row simply never had one.
//     Spend by model, by harness, and in total are all exactly right, and the
//     one dimension that cannot be answered from a file on disk reports that it
//     cannot rather than inventing an answer.
const (
	collectorActorPurpose   = "blackbird.telemetry.collector.actor"
	collectorSessionPurpose = "blackbird.telemetry.collector.session"
)

// collectorEpoch is the fixed timestamp prefix every collector identifier
// carries. A UUIDv7's leading 48 bits are a mint time, and these identifiers
// are not minted at a time -- they are derived from a name. Pinning the prefix
// says so: every collector identity sorts to one instant, which is a visible
// signal that it is synthetic rather than a random-looking lie about when an
// actor first appeared.
var collectorEpoch = time.Date(2026, time.September, 2, 0, 0, 0, 0, time.UTC)

// CollectorAttribution mints the identity a daemon-side collector attributes
// one project's observations to. projectKey is carried through unchanged: it is
// the only part of the attribution a ledger can actually supply, and the
// collector reads it out of the record rather than deriving it from a path.
func CollectorAttribution(harness domain.Harness, projectKey string) (Attribution, error) {
	if !harness.Valid() {
		return Attribution{}, fmt.Errorf("%w: unknown harness %q", domain.ErrInvalidObservation, harness)
	}
	if projectKey == "" {
		return Attribution{}, fmt.Errorf("%w: collected observations need a project key",
			domain.ErrInvalidObservation)
	}
	actor, err := domain.ParseActorID(collectorIdentifier(collectorActorPurpose, harness))
	if err != nil {
		return Attribution{}, fmt.Errorf("derive collector actor: %w", err)
	}
	session, err := domain.ParseActorSessionID(collectorIdentifier(collectorSessionPurpose, harness))
	if err != nil {
		return Attribution{}, fmt.Errorf("derive collector session: %w", err)
	}
	return Attribution{ProjectKey: projectKey, ActorID: actor, SessionID: session}, nil
}

// collectorIdentifier derives one identifier that parses as a canonical
// UUIDv7. The hash fills only the bytes a v7 leaves free; the timestamp prefix
// and the version and variant bits are set to the values the parser requires,
// so this is a well-formed identifier rather than a value that happens to pass.
func collectorIdentifier(purpose string, harness domain.Harness) string {
	digest := sha256.Sum256([]byte(purpose + "\x00" + string(harness)))
	var id [16]byte
	milliseconds := collectorEpoch.UnixMilli()
	for index := 5; index >= 0; index-- {
		id[index] = byte(milliseconds)
		milliseconds >>= 8
	}
	copy(id[6:], digest[:10])
	id[6] = (id[6] & 0x0f) | 0x70
	id[8] = (id[8] & 0x3f) | 0x80

	var text [36]byte
	hex.Encode(text[0:8], id[0:4])
	text[8] = '-'
	hex.Encode(text[9:13], id[4:6])
	text[13] = '-'
	hex.Encode(text[14:18], id[6:8])
	text[18] = '-'
	hex.Encode(text[19:23], id[8:10])
	text[23] = '-'
	hex.Encode(text[24:36], id[10:16])
	return string(text[:])
}
