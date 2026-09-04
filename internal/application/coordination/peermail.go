package coordination

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// Cross-host mail: an agent on one machine addressing an agent on another.
//
// Mail is one of the two things the model lets cross a host boundary, and it
// crosses for the same reason it needs no conflict resolution: a message is
// APPEND-ONLY and each host stays authoritative for its own mailbox. Nothing
// here replicates a database, reconciles an identity, elects anything, or reads
// another host's clock. Two daemons exchange messages the way two people do.
//
// # How a recipient is addressed
//
// An agent name is unique per project ON ONE HOST. Two machines can both run an
// agent called "reviewer" in a checkout at the same absolute path, and they are
// different agents. So a cross-host recipient is written
//
//	reviewer@phalls-mac-mini
//
// and the qualifier is the tailnet host the agent is registered on. Four
// properties make that the right answer rather than merely a syntax:
//
//   - Blackbird mints NO fleet-wide namespace. Tailscale already assigns each
//     node a name unique within the tailnet, both hosts already trust that
//     authority, and the peer guard already VERIFIES it on every inbound
//     request. Qualifying a per-project name with a tailnet host name therefore
//     produces a fleet-unique name without any host having to agree with any
//     other host about anything -- no registry, no leader, no negotiation.
//
//   - The name is resolved by the host that owns it. A sender does not keep a
//     directory of the peer's agents; it hands the peer a bare agent name and
//     the peer resolves it in its own project, which is the only place that
//     name means anything. "No such agent" is then an answer from the
//     authority, not a guess by the sender, which is exactly why it can be
//     reported as permanently undeliverable.
//
//   - The qualifier a RECIPIENT sees is never taken from the payload. When a
//     message arrives, the receiving host writes the machine name its own whois
//     lookup verified, not the one the sender wrote down. A sender calling from
//     "phalls-mac-mini" that claims to be "laptop" is recorded as
//     "author@phalls-mac-mini". A peer can lie about many things; it cannot lie
//     about which node the packets came from, because it is not the one asked.
//
//   - An unqualified name still means exactly what it always meant: an agent on
//     this host, in this project. Nothing that works today changes.
//
// The address separator is reserved: PeerAddressSeparator may not appear in a
// newly registered agent name, so a recipient string is unambiguous by
// construction rather than by a lookup whose answer depends on which agents
// happen to exist.
//
// # What a peer agent is, locally
//
// The remote agent gets a LOCAL actor on each host that talks to it, named
// "agent@machine". It is used in both directions -- as the recipient of mail
// sent to it, and as the author of mail received from it -- so a cross-host
// exchange reads as one ordinary thread in the ordinary inbox, and read marks,
// acknowledgements, threading and the mail wakeup all work without knowing that
// a host boundary was involved. That actor holds a registration-token digest
// that is not the digest of any token, so it authenticates nobody, and its
// session is closed the moment it is created, so it never appears in the active
// roster as though it were running here.
//
// # Delivery
//
// Delivery is best-effort and asynchronous. A send records the message in this
// host's own store first and only then tries the wire, so a peer that is down
// cannot fail a send. Each remote recipient carries its own state:
//
//   - PeerDeliveryDelivered  -- the peer accepted it and named the message id
//     it minted. That id is the peer's, not ours; we store it as a receipt and
//     never as an identity we can resolve.
//   - PeerDeliveryQueued     -- no definitive answer yet. This host will retry.
//   - PeerDeliveryUndeliverable -- the peer answered and refused, or the retry
//     budget ran out. Nothing further will be attempted.
//
// The distinction is the point: a sender told "queued" knows the message is
// durable here and not yet there, and a sender told "undeliverable" knows to
// stop waiting for a reply.

const (
	// PeerAddressSeparator divides the agent name from the host it is
	// registered on.
	PeerAddressSeparator = "@"
	// MaxPeerHostBytes bounds the host half of an address. A DNS name is
	// limited to 253 octets and a tailnet MagicDNS name is far shorter; the
	// bound exists so a hostile address cannot be used to grow a stored row.
	MaxPeerHostBytes = 253
	// MaxPeerRecipients bounds the remote recipients of one message. Each one
	// is an outbound request to a machine this process does not control, so the
	// bound is deliberately far below MaxMessageRecipients.
	MaxPeerRecipients = 8
	// MaxPeerAgentsPerProject bounds how many distinct remote agents a project
	// may know. Every inbound message from an unseen sender mints a local actor
	// for it, and without a ceiling an allowed-but-misbehaving peer could mint
	// rows without end.
	MaxPeerAgentsPerProject = 64
	// PeerThreadKeyBytes is the entropy in a thread key, and
	// MaxPeerThreadKeyBytes bounds the encoded form a peer may send back.
	PeerThreadKeyBytes    = 16
	MaxPeerThreadKeyBytes = 64
)

// The retry budget. Every value here bounds work against a machine this process
// does not control, so each is finite and none of them is configurable by the
// far side.
const (
	// MaxPeerMailAttempts is how many times one delivery is tried before it is
	// declared undeliverable. A queue that retries forever is a queue that
	// hides a broken peer instead of reporting one.
	MaxPeerMailAttempts = 8
	// PeerMailFirstBackoff and PeerMailMaxBackoff bound the exponential wait
	// between attempts.
	PeerMailFirstBackoff = 5 * time.Second
	PeerMailMaxBackoff   = 10 * time.Minute
	// PeerMailExpiry is the wall-clock ceiling on one entry's whole life. It
	// exists because attempts alone do not bound time: a daemon that is stopped
	// for a week would otherwise resume delivering week-old mail as though it
	// were news.
	PeerMailExpiry = 24 * time.Hour
	// PeerMailBatch bounds how many entries one drain claims. The drain holds a
	// connection from a small pool while it reads them.
	PeerMailBatch = 32
	// PeerMailFanOut bounds concurrent outbound requests from one drain. It is
	// small for the same reason the fleet view's fan-out is: each request is an
	// outbound connection here and a request slot on the far side.
	PeerMailFanOut = 4
	// PeerMailAttemptTimeout bounds one delivery attempt from the background
	// drain, and PeerMailInlineTimeout bounds one made on the send path, where
	// an agent's turn is waiting on the answer.
	PeerMailAttemptTimeout = 10 * time.Second
	PeerMailInlineTimeout  = 3 * time.Second
	// PeerMailDispatchInterval is how often the drain looks for due entries.
	PeerMailDispatchInterval = 15 * time.Second
)

// PeerAddress is a recipient on another host.
type PeerAddress struct {
	// Agent is the recipient's name AS REGISTERED ON ITS OWN HOST. This host
	// neither knows nor validates whether it exists; only the far side can
	// answer that.
	Agent string
	// Host is the tailnet host the agent is registered on: a MagicDNS name or a
	// tailnet address, optionally with a port. It is dialled exactly as the
	// fleet cost view dials a --peer, and it is what a receiving host verifies
	// independently rather than believes.
	Host string
}

func (address PeerAddress) String() string {
	return address.Agent + PeerAddressSeparator + address.Host
}

// IsZero reports an address that names nothing.
func (address PeerAddress) IsZero() bool { return address.Agent == "" && address.Host == "" }

// IsPeerAddress reports whether a recipient name is a cross-host address. It is
// a syntactic test on purpose: routing that depended on which agents happen to
// exist locally would send a message to a different machine depending on the
// order two agents registered.
func IsPeerAddress(name string) bool {
	return strings.Contains(name, PeerAddressSeparator)
}

// ParsePeerAddress splits "agent@host". It refuses anything it cannot read
// rather than guessing, because the guess would be a message delivered
// somewhere nobody asked for.
func ParsePeerAddress(name string) (PeerAddress, error) {
	agent, host, found := strings.Cut(name, PeerAddressSeparator)
	if !found {
		return PeerAddress{}, fmt.Errorf("%w: %q is not a cross-host address", ErrInvalid, name)
	}
	if !validPeerAgentName(agent) {
		return PeerAddress{}, fmt.Errorf("%w: %q names no agent before the %q",
			ErrInvalid, name, PeerAddressSeparator)
	}
	normalized, err := normalizePeerHost(host)
	if err != nil {
		return PeerAddress{}, fmt.Errorf("%w: %q: %w", ErrInvalid, name, err)
	}
	return PeerAddress{Agent: agent, Host: normalized}, nil
}

func validPeerAgentName(agent string) bool {
	return agent != "" && agent == strings.TrimSpace(agent) && len(agent) <= MaxNameBytes &&
		!strings.ContainsRune(agent, 0) && !strings.Contains(agent, PeerAddressSeparator)
}

// normalizePeerHost lower-cases the host and rejects everything that is not a
// host: a path, a scheme, a query, whitespace. The port is preserved when one
// is written, because a peer daemon may serve its peer listener anywhere.
func normalizePeerHost(host string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(host))
	if trimmed == "" {
		return "", errors.New("no host follows the separator")
	}
	if len(trimmed) > MaxPeerHostBytes {
		return "", errors.New("host is too long")
	}
	if strings.ContainsAny(trimmed, "/?#\\ \t@") {
		return "", errors.New("host must be a bare tailnet name or address")
	}
	name := trimmed
	if parsed, _, err := net.SplitHostPort(trimmed); err == nil {
		name = parsed
	}
	if strings.Trim(name, "[]") == "" {
		return "", errors.New("host is empty")
	}
	return trimmed, nil
}

// PeerDeliveryState is what this host knows about one remote delivery. The
// three values are exhaustive and they are deliberately not a ladder: queued is
// the only non-terminal one.
type PeerDeliveryState string

const (
	// PeerDeliveryQueued means this host holds the message and the far side has
	// not confirmed it. It is the honest state for every outcome that is not an
	// answer: a refused connection, a timeout, a 5xx, a body this host could
	// not read.
	PeerDeliveryQueued PeerDeliveryState = "queued"
	// PeerDeliveryDelivered means the peer accepted the message and named the
	// id it minted for it.
	PeerDeliveryDelivered PeerDeliveryState = "delivered"
	// PeerDeliveryUndeliverable means no further attempt will be made: the peer
	// answered and refused, or the budget above ran out. A refusal is treated
	// as final because the fixes for one -- register that agent, add this
	// machine to that allow-list, name the project that exists over there --
	// are all operator actions, and retrying against them is a loop that hides
	// the thing an operator has to see.
	PeerDeliveryUndeliverable PeerDeliveryState = "undeliverable"
)

// Valid reports whether a state came from this package.
func (state PeerDeliveryState) Valid() bool {
	switch state {
	case PeerDeliveryQueued, PeerDeliveryDelivered, PeerDeliveryUndeliverable:
		return true
	default:
		return false
	}
}

// SendPeerMailParams is one send that may address both hosts at once. Local and
// remote recipients travel together because they are recipients of ONE message:
// splitting them into two sends would put two different message ids on one
// statement and leave a reader unable to tell they were the same thing said
// once.
type SendPeerMailParams struct {
	MessageID               domain.MessageID
	ConversationID          domain.ConversationID
	Subject                 string
	Body                    string
	ReplyTo                 *domain.MessageID
	AcknowledgementRequired bool
	// LocalRecipients are agent names on this host, resolved exactly as an
	// ordinary send resolves them.
	LocalRecipients []string
	// PeerRecipients are addresses on other hosts. Each becomes a local peer
	// actor and one outbox entry.
	PeerRecipients []PeerAddress
	// PeerProjectKey is the project the remote names are resolved in, on the
	// far side. Empty means "the same project key as mine", which is right
	// whenever both machines check the repository out at the same path and
	// wrong silently otherwise -- so it is stated on the wire rather than
	// assumed by the receiver.
	PeerProjectKey string
}

// Validate refuses a send this package cannot carry out.
func (params SendPeerMailParams) Validate() error {
	if params.MessageID.IsZero() || params.ConversationID.IsZero() ||
		len(params.PeerRecipients) == 0 || len(params.PeerRecipients) > MaxPeerRecipients {
		return ErrInvalid
	}
	if len(params.LocalRecipients)+len(params.PeerRecipients) > MaxMessageRecipients {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(params.PeerRecipients))
	for _, address := range params.PeerRecipients {
		if address.IsZero() {
			return ErrInvalid
		}
		parsed, err := ParsePeerAddress(address.String())
		if err != nil {
			return err
		}
		// The address doubles as a local agent name, so it is bounded by what
		// an agent name may be. Checking it here turns a storage constraint
		// violation deep in a transaction into a refusal that says which
		// recipient was too long.
		if len(parsed.String()) > MaxNameBytes {
			return ErrInvalid
		}
		if _, duplicate := seen[parsed.String()]; duplicate {
			return ErrInvalid
		}
		seen[parsed.String()] = struct{}{}
	}
	if params.PeerProjectKey != "" && len(params.PeerProjectKey) > MaxKeyBytes {
		return ErrInvalid
	}
	return nil
}

// PeerMailSend is what a cross-host send produced HERE. The message is already
// durable at this point; Queued is the work still owed to the wire.
type PeerMailSend struct {
	Message   Message
	ThreadKey string
	Queued    []PeerMailEntry
}

// PeerMailEntry is one remote delivery and everything needed to attempt it,
// read back from this host's own store. The body travels with the entry because
// the drain must not have to hold a second read open per attempt, and it is the
// stored body rather than a copy: an entry is a pointer to a message, not a
// second version of one.
type PeerMailEntry struct {
	MessageID domain.MessageID
	Address   PeerAddress
	// ProjectKey is the project the recipient is resolved in on the far side.
	ProjectKey string
	ThreadKey  string
	Topic      string
	// FromAgent is the sender's name on THIS host, unqualified. The receiving
	// host qualifies it with the machine it verified.
	FromAgent               string
	Subject                 string
	Body                    string
	AcknowledgementRequired bool
	State                   PeerDeliveryState
	Attempts                int
	// LastError is empty when no attempt has failed yet. It is never filled in
	// with a placeholder: "no attempt has failed" and "an attempt failed for a
	// reason we did not record" are different facts.
	LastError string
	// RemoteMessageID is the id the PEER minted, and it is empty until a peer
	// has actually named one. It is a receipt, never an identity this host can
	// resolve.
	RemoteMessageID string
	QueuedAt        time.Time
	// NextAttemptAt is the zero time on a terminal entry.
	NextAttemptAt time.Time
}

// Deliverable reports whether an entry is still owed to the wire.
func (entry PeerMailEntry) Deliverable() bool { return entry.State == PeerDeliveryQueued }

// PeerMailOutcome settles one attempt. It carries the attempt's result rather
// than the resulting state, so the store applies one retry policy instead of
// every caller reimplementing it.
type PeerMailOutcome struct {
	MessageID domain.MessageID
	Address   PeerAddress
	// State is the state the entry reaches. A caller reports queued for
	// "unknown, try again" and the store computes the next attempt time from
	// the attempt count.
	State PeerDeliveryState
	// RemoteMessageID is set only alongside PeerDeliveryDelivered, and only
	// when the peer actually named one.
	RemoteMessageID string
	// Detail is the failure as this host saw it, empty on success.
	Detail        string
	NextAttemptAt time.Time
	SettledAt     time.Time
}

// AcceptPeerMailParams is one message arriving from a verified peer.
//
// OriginHost is supplied by the transport from the identity it VERIFIED, never
// from the request body. Every other field is the peer's claim, and each one is
// bounded and validated here before it reaches storage.
type AcceptPeerMailParams struct {
	OriginHost string
	// ProjectKey is the project on THIS host the recipients are resolved in. A
	// project this host does not have is refused rather than created: minting a
	// project because a remote machine named one would let a peer write into
	// this host's authority.
	ProjectKey string
	// ThreadKey correlates the two hosts' conversations without either of them
	// adopting the other's conversation id. It is opaque and this host treats
	// it as a lookup key and nothing else.
	ThreadKey string
	Topic     string
	// FromAgent is the sender's name on its own host, unqualified. This host
	// stores it as FromAgent + "@" + OriginHost.
	FromAgent               string
	ToAgents                []string
	Subject                 string
	Body                    string
	AcknowledgementRequired bool
	// OriginMessageID is the id the SENDER minted. It is the idempotency key,
	// scoped by OriginHost, so a retry after a lost response appends nothing.
	OriginMessageID string
}

// Validate bounds everything a peer controls.
func (params AcceptPeerMailParams) Validate() error {
	if params.OriginHost == "" || len(params.OriginHost) > MaxPeerHostBytes {
		return ErrInvalid
	}
	if params.ProjectKey == "" || len(params.ProjectKey) > MaxKeyBytes {
		return ErrInvalid
	}
	if params.ThreadKey == "" || len(params.ThreadKey) > MaxPeerThreadKeyBytes {
		return ErrInvalid
	}
	if !validPeerAgentName(params.FromAgent) {
		return ErrInvalid
	}
	// The author is recorded as a local agent named "sender@host", so the two
	// halves together are bounded by what an agent name may be.
	if len(PeerAuthorName(params.FromAgent, params.OriginHost)) > MaxNameBytes {
		return ErrInvalid
	}
	if len(params.ToAgents) == 0 || len(params.ToAgents) > MaxPeerRecipients {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(params.ToAgents))
	for _, agent := range params.ToAgents {
		if !validPeerAgentName(agent) {
			return ErrInvalid
		}
		if _, duplicate := seen[agent]; duplicate {
			return ErrInvalid
		}
		seen[agent] = struct{}{}
	}
	if len(params.Subject) == 0 || len(params.Subject) > MaxMessageSubjectBytes ||
		len(params.Body) == 0 || len(params.Body) > MaxMessageBodyBytes {
		return ErrInvalid
	}
	if len(params.Topic) > MaxMessageSubjectBytes {
		return ErrInvalid
	}
	if params.OriginMessageID == "" || len(params.OriginMessageID) > MaxNameBytes {
		return ErrInvalid
	}
	return nil
}

// PeerAuthorName is the local name a remote sender is recorded under. It is
// built from the VERIFIED origin host, which is why the transport passes the
// identity it resolved rather than the one the payload claimed.
func PeerAuthorName(fromAgent, originHost string) string {
	return fromAgent + PeerAddressSeparator + strings.ToLower(originHost)
}

// AcceptedPeerMail is what this host did with an inbound message. Duplicate is
// true when the idempotency key had already been seen, in which case the ids
// are the ones from the first time and nothing was appended.
type AcceptedPeerMail struct {
	MessageID      domain.MessageID
	ConversationID domain.ConversationID
	Delivered      []string
	Duplicate      bool
}

// PeerMailAcceptor is the narrow port the inbound transport needs: append one
// message that arrived from a verified peer. It is separate from PeerMailStore
// so that the route which accepts a REMOTE write depends on the one operation
// it is allowed to perform, and cannot reach the queue or the send path even by
// accident.
type PeerMailAcceptor interface {
	AcceptPeerMail(context.Context, AcceptPeerMailParams) (AcceptedPeerMail, error)
}

// PeerMailSendPort is the narrow port the agent-facing send needs: record the
// message here and queue what is owed to the wire, in one transaction. The
// message is durable before anything is attempted on the wire, which is what
// makes a peer being down a queued delivery rather than a failed send.
type PeerMailSendPort interface {
	SendPeerMail(context.Context, LocalAgentSession, SendPeerMailParams) (PeerMailSend, error)
}

// PeerMailDispatch is the narrow port that attempts delivery now. It is
// separate from the dispatcher's own type so a transport depends on the one
// operation it performs -- attempting the entries a send just queued -- and
// cannot reach the background loop or the outbox.
type PeerMailDispatch interface {
	Deliver(context.Context, []PeerMailEntry) []PeerMailResult
}

// PeerMailQueueReader is the OPERATOR's read of the outbox. It is separate
// from PeerMailStore because it is a different principal's capability: the
// admin surface reads it, the delivery path never does, and a store that cannot
// answer it composes an admin route that says so rather than one that reports
// an empty queue -- which an operator would read as "nothing is stuck".
type PeerMailQueueReader interface {
	PeerMailQueue(ctx context.Context, projectKey string, limit int) ([]PeerMailEntry, error)
}

// PeerMailStore is the storage port for cross-host mail. Every method is a
// write into or a read of THIS host's own store; none of them reaches another
// machine.
type PeerMailStore interface {
	PeerMailAcceptor
	PeerMailSendPort
	// ClaimPeerMail returns entries due for an attempt, oldest first, bounded
	// by limit. It marks nothing: an entry is settled by SettlePeerMail, so a
	// crash mid-attempt leaves the entry due rather than lost.
	ClaimPeerMail(context.Context, time.Time, int) ([]PeerMailEntry, error)
	// SettlePeerMail applies one attempt's outcome.
	SettlePeerMail(context.Context, PeerMailOutcome) error
}

// The two ways an attempt can fail, and they are the only classification the
// dispatcher makes. An adapter must map every transport outcome onto one of
// them, because a third case would end up defaulting to one of these anyway
// and it is better that the choice is made where the evidence is.
var (
	// ErrPeerMailRefused reports that the peer ANSWERED and said no. It is
	// terminal: the agent does not exist over there, the project does not, this
	// machine is not allowed, or the message was rejected as malformed.
	ErrPeerMailRefused = errors.New("peer refused the message")
	// ErrPeerMailUnreachable reports that no answer was obtained -- the host
	// did not respond, the connection failed, the peer was busy, or the answer
	// could not be read. It is retryable.
	ErrPeerMailUnreachable = errors.New("peer could not be reached")
)

// PeerMailReceipt is what a peer said when it accepted a message.
type PeerMailReceipt struct {
	// RemoteMessageID is the id the peer minted. A peer that names none leaves
	// it empty, and this host stores the absence rather than inventing an id
	// that would look like something it could later resolve.
	RemoteMessageID string
	// Duplicate is the peer reporting that it had already accepted this
	// message. It is a successful delivery: the message is there.
	Duplicate bool
}

// PeerMailSender is the outbound port. Its implementation lives in the
// transport layer and is composed in the composition root; nothing in this
// package knows what a socket is.
type PeerMailSender interface {
	// DeliverPeerMail attempts one delivery and must respect the deadline on
	// the context it is given. It must return an error wrapping
	// ErrPeerMailRefused or ErrPeerMailUnreachable.
	//
	// The second argument is EVERY recipient of this message on that host, not
	// just the entry's own. One message addressed to two agents on one machine
	// is one message there as well as here -- and it has to be, because the
	// receiving host keys idempotency on the sending host's message id: sending
	// it twice would make the second recipient's copy look like a retry of the
	// first and silently drop it.
	DeliverPeerMail(context.Context, PeerMailEntry, []string) (PeerMailReceipt, error)
}

// PeerMailResult is one attempt's outcome, in the shape a caller reports to an
// agent.
type PeerMailResult struct {
	Address PeerAddress
	State   PeerDeliveryState
	// RemoteMessageID is the peer's receipt, empty unless it named one.
	RemoteMessageID string
	// Detail explains a state that is not delivered. It is empty on success and
	// never a placeholder otherwise.
	Detail   string
	Attempts int
}

// PeerMailStats is the dispatcher's self-report, in the same spirit as the
// contention recorder's: a queue that quietly stops draining is worse than one
// that reports it is stuck.
type PeerMailStats struct {
	Attempted     uint64
	Delivered     uint64
	Requeued      uint64
	Undeliverable uint64
	// SettleFailures counts attempts whose OUTCOME could not be recorded. Those
	// entries stay due and will be attempted again, so this is the counter that
	// says a delivery may have happened twice on the far side -- which the
	// receiving host's idempotency key is there to absorb.
	SettleFailures uint64
	ClaimFailures  uint64
	Drains         uint64
}

// PeerMailDispatcherDependencies configures the drain.
type PeerMailDispatcherDependencies struct {
	Store  PeerMailStore
	Sender PeerMailSender
	Logger *slog.Logger
	// Interval is how often the drain looks for due entries. Zero takes
	// PeerMailDispatchInterval; a negative value is a composition error.
	Interval time.Duration
	// AttemptTimeout bounds one background attempt. Zero takes
	// PeerMailAttemptTimeout.
	AttemptTimeout time.Duration
	// FanOut bounds concurrent attempts. Zero takes PeerMailFanOut.
	FanOut int
	// Batch bounds one drain's claim. Zero takes PeerMailBatch.
	Batch int
	Now   func() time.Time
}

// PeerMailDispatcher drains the outbox. It satisfies the composition root's
// worker shape -- Start and Stop -- without importing it, and the same delivery
// path is reachable synchronously through Deliver so that a send can report a
// real per-recipient state instead of always reporting "queued".
type PeerMailDispatcher struct {
	store          PeerMailStore
	sender         PeerMailSender
	logger         *slog.Logger
	interval       time.Duration
	attemptTimeout time.Duration
	fanOut         int
	batch          int
	now            func() time.Time

	mu      sync.Mutex
	cancel  context.CancelFunc
	stopped chan struct{}

	statsMu sync.Mutex
	stats   PeerMailStats
}

// NewPeerMailDispatcher builds the drain. Both ports are required: a dispatcher
// with no sender would report entries as queued forever while looking composed.
func NewPeerMailDispatcher(dependencies PeerMailDispatcherDependencies) (*PeerMailDispatcher, error) {
	if dependencies.Store == nil {
		return nil, errors.New("peer mail dispatcher requires a store")
	}
	if dependencies.Sender == nil {
		return nil, errors.New("peer mail dispatcher requires a sender")
	}
	if dependencies.Interval < 0 || dependencies.AttemptTimeout < 0 ||
		dependencies.FanOut < 0 || dependencies.Batch < 0 {
		return nil, errors.New("peer mail dispatcher bounds cannot be negative")
	}
	dispatcher := &PeerMailDispatcher{
		store: dependencies.Store, sender: dependencies.Sender,
		logger: dependencies.Logger, interval: dependencies.Interval,
		attemptTimeout: dependencies.AttemptTimeout, fanOut: dependencies.FanOut,
		batch: dependencies.Batch, now: dependencies.Now,
	}
	if dispatcher.logger == nil {
		dispatcher.logger = slog.New(slog.DiscardHandler)
	}
	if dispatcher.interval == 0 {
		dispatcher.interval = PeerMailDispatchInterval
	}
	if dispatcher.attemptTimeout == 0 {
		dispatcher.attemptTimeout = PeerMailAttemptTimeout
	}
	if dispatcher.fanOut == 0 {
		dispatcher.fanOut = PeerMailFanOut
	}
	if dispatcher.batch == 0 {
		dispatcher.batch = PeerMailBatch
	}
	if dispatcher.now == nil {
		dispatcher.now = time.Now
	}
	return dispatcher, nil
}

// Start begins draining in the background. It returns as soon as the loop is
// running; a drain never blocks a coordination write, and a failed drain is
// counted and logged rather than returned, because there is no caller to return
// it to.
func (dispatcher *PeerMailDispatcher) Start(ctx context.Context) error {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.cancel != nil {
		return errors.New("peer mail dispatcher is already running")
	}
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopped := make(chan struct{})
	dispatcher.cancel, dispatcher.stopped = cancel, stopped
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(dispatcher.interval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				dispatcher.DispatchOnce(loopCtx)
			}
		}
	}()
	return nil
}

// Stop ends the drain and waits for the in-flight pass, bounded by the caller's
// context. An attempt that is still on the wire when the context expires is
// abandoned rather than waited on: its entry is unsettled, so it stays due and
// is retried on the next start.
func (dispatcher *PeerMailDispatcher) Stop(ctx context.Context) error {
	dispatcher.mu.Lock()
	cancel, stopped := dispatcher.cancel, dispatcher.stopped
	dispatcher.cancel, dispatcher.stopped = nil, nil
	dispatcher.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DispatchOnce claims the entries that are due and attempts each of them.
func (dispatcher *PeerMailDispatcher) DispatchOnce(ctx context.Context) []PeerMailResult {
	dispatcher.count(func(stats *PeerMailStats) { stats.Drains++ })
	entries, err := dispatcher.store.ClaimPeerMail(ctx, dispatcher.now(), dispatcher.batch)
	if err != nil {
		dispatcher.count(func(stats *PeerMailStats) { stats.ClaimFailures++ })
		dispatcher.logger.Warn("peer mail queue could not be read", slog.Any("error", err))
		return nil
	}
	return dispatcher.deliver(ctx, entries, dispatcher.attemptTimeout)
}

// Deliver attempts the named entries now, under the tighter inline timeout. It
// is what turns a send into a real answer: the agent that sent the message
// learns whether the peer took it, without a round of polling.
func (dispatcher *PeerMailDispatcher) Deliver(ctx context.Context, entries []PeerMailEntry) []PeerMailResult {
	return dispatcher.deliver(ctx, entries, PeerMailInlineTimeout)
}

func (dispatcher *PeerMailDispatcher) deliver(
	ctx context.Context,
	entries []PeerMailEntry,
	timeout time.Duration,
) []PeerMailResult {
	results := make([]PeerMailResult, len(entries))
	for index, entry := range entries {
		results[index] = PeerMailResult{Address: entry.Address, State: entry.State, Attempts: entry.Attempts}
	}
	gate := make(chan struct{}, dispatcher.fanOut)
	var group sync.WaitGroup
	for _, shipment := range groupPeerMail(entries) {
		group.Add(1)
		go func() {
			defer group.Done()
			select {
			case gate <- struct{}{}:
				defer func() { <-gate }()
			case <-ctx.Done():
				for _, index := range shipment {
					results[index].Detail = "this daemon stopped before the attempt began"
				}
				return
			}
			dispatcher.attempt(ctx, entries, shipment, results, timeout)
		}()
	}
	group.Wait()
	return results
}

// groupPeerMail collects the deliverable entries that travel together: one
// message, one host, every recipient of it there. Anything already terminal is
// left out entirely rather than grouped and skipped, so a claim that returns a
// settled row costs no attempt.
func groupPeerMail(entries []PeerMailEntry) [][]int {
	order := make([]string, 0, len(entries))
	byKey := make(map[string][]int, len(entries))
	for index, entry := range entries {
		if !entry.Deliverable() {
			continue
		}
		key := entry.MessageID.String() + "\x00" + entry.Address.Host
		if _, present := byKey[key]; !present {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], index)
	}
	shipments := make([][]int, 0, len(order))
	for _, key := range order {
		shipments = append(shipments, byKey[key])
	}
	return shipments
}

// attempt makes one delivery to one host and settles every entry it carried.
// Every branch settles: an attempt whose outcome is not written down is an
// attempt that repeats forever.
func (dispatcher *PeerMailDispatcher) attempt(
	ctx context.Context,
	entries []PeerMailEntry,
	shipment []int,
	results []PeerMailResult,
	timeout time.Duration,
) {
	dispatcher.count(func(stats *PeerMailStats) { stats.Attempted++ })
	first := entries[shipment[0]]
	recipients := make([]string, 0, len(shipment))
	for _, index := range shipment {
		recipients = append(recipients, entries[index].Address.Agent)
	}
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	receipt, err := dispatcher.sender.DeliverPeerMail(attemptCtx, first, recipients)
	for _, index := range shipment {
		entry := entries[index]
		outcome, result := dispatcher.settlement(entry, receipt, err)
		results[index] = result
		if settleErr := dispatcher.store.SettlePeerMail(context.WithoutCancel(ctx), outcome); settleErr != nil {
			dispatcher.count(func(stats *PeerMailStats) { stats.SettleFailures++ })
			dispatcher.logger.Warn("peer mail outcome could not be recorded",
				slog.String("message_id", entry.MessageID.String()),
				slog.String("recipient", entry.Address.String()),
				slog.String("state", string(outcome.State)),
				slog.Any("error", settleErr))
		}
	}
}

// settlement turns one attempt's result into the durable outcome and the
// answer a sender reads. It is a pure function of the entry and the error so
// that every recipient of one shipment is settled identically.
func (dispatcher *PeerMailDispatcher) settlement(
	entry PeerMailEntry,
	receipt PeerMailReceipt,
	err error,
) (PeerMailOutcome, PeerMailResult) {
	outcome := PeerMailOutcome{MessageID: entry.MessageID, Address: entry.Address, SettledAt: dispatcher.now()}
	result := PeerMailResult{Address: entry.Address, Attempts: entry.Attempts + 1}
	switch {
	case err == nil:
		outcome.State, outcome.RemoteMessageID = PeerDeliveryDelivered, receipt.RemoteMessageID
		result.State, result.RemoteMessageID = PeerDeliveryDelivered, receipt.RemoteMessageID
		dispatcher.count(func(stats *PeerMailStats) { stats.Delivered++ })
	case errors.Is(err, ErrPeerMailRefused):
		outcome.State, outcome.Detail = PeerDeliveryUndeliverable, err.Error()
		result.State, result.Detail = PeerDeliveryUndeliverable, err.Error()
		dispatcher.count(func(stats *PeerMailStats) { stats.Undeliverable++ })
	default:
		outcome.State, outcome.Detail = PeerDeliveryQueued, err.Error()
		outcome.NextAttemptAt = PeerMailBackoff(dispatcher.now(), entry.Attempts+1)
		result.State, result.Detail = PeerDeliveryQueued, err.Error()
		if PeerMailExhausted(entry, dispatcher.now()) {
			outcome.State, outcome.NextAttemptAt = PeerDeliveryUndeliverable, time.Time{}
			result.State = PeerDeliveryUndeliverable
			outcome.Detail = "gave up after " + err.Error()
			result.Detail = outcome.Detail
		}
		if outcome.State == PeerDeliveryQueued {
			dispatcher.count(func(stats *PeerMailStats) { stats.Requeued++ })
		} else {
			dispatcher.count(func(stats *PeerMailStats) { stats.Undeliverable++ })
		}
	}
	return outcome, result
}

// PeerMailExhausted reports whether an entry has spent its budget, counting the
// attempt just made. Both bounds are checked because neither implies the other:
// a daemon that was off for a week burns time and no attempts, and a peer that
// refuses connections instantly burns attempts and almost no time.
func PeerMailExhausted(entry PeerMailEntry, now time.Time) bool {
	if entry.Attempts+1 >= MaxPeerMailAttempts {
		return true
	}
	return !entry.QueuedAt.IsZero() && now.Sub(entry.QueuedAt) >= PeerMailExpiry
}

// PeerMailBackoff is when the next attempt becomes due. It doubles from
// PeerMailFirstBackoff and stops at PeerMailMaxBackoff, so a peer that has been
// down for an hour is polled every ten minutes rather than every five seconds.
func PeerMailBackoff(now time.Time, attempts int) time.Time {
	wait := PeerMailFirstBackoff
	for attempt := 1; attempt < attempts && wait < PeerMailMaxBackoff; attempt++ {
		wait *= 2
	}
	if wait > PeerMailMaxBackoff {
		wait = PeerMailMaxBackoff
	}
	return now.Add(wait)
}

// PeerMailStats reports what the drain has done.
func (dispatcher *PeerMailDispatcher) PeerMailStats() PeerMailStats {
	dispatcher.statsMu.Lock()
	defer dispatcher.statsMu.Unlock()
	return dispatcher.stats
}

func (dispatcher *PeerMailDispatcher) count(update func(*PeerMailStats)) {
	dispatcher.statsMu.Lock()
	defer dispatcher.statsMu.Unlock()
	update(&dispatcher.stats)
}
