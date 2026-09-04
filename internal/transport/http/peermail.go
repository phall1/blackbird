package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	stdhttp "net/http"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

// The mail half of the peer surface: the one WRITE another host may perform on
// this one, and the reasons it is safe.
//
// It is a write, and the model allows exactly this write, because it is
// APPEND-ONLY into a mailbox this host stays authoritative for. Everything that
// would make it a replication protocol is absent by construction:
//
//   - The peer proposes no identifiers. The message id, the conversation id and
//     the actor for the sender are all minted HERE. The only value the peer
//     supplies that this host stores as given is its own message id, and that
//     is stored as an idempotency key rather than as anything resolvable.
//   - The peer names no author. It sends its agent's bare name; this host
//     qualifies it with the machine name IT VERIFIED, so the recorded author is
//     a fact about who called rather than a claim in a payload.
//   - The peer creates nothing. A project this host does not have, a recipient
//     it does not have, or one remote sender too many are all refusals, and
//     each of them is reported clearly enough that the sender can mark the
//     delivery permanently undeliverable instead of retrying forever.
//   - Nothing here can touch a claim. Reservations never cross a host boundary
//     -- the resource a lease protects is a path on one machine's disk -- and
//     the route table in peer.go is where that is enforced, by absence.
//
// Everything is bounded, because the far side is a machine this process does
// not control: a body cap below the message body limit plus its envelope, a
// concurrency cap well under the read pool, and a deadline no request can
// outlive. A peer that floods this route is refused with backpressure rather
// than queued, for the same reason the cost route refuses rather than queues.
const PathLocalPeerMail = "/api/v1/local/peer/mail"

const (
	// peerMailMaxBody caps an inbound envelope. A message body is bounded by
	// the domain at 256 KiB and the rest of the envelope is short names, so
	// this is that ceiling plus room for the JSON around it and nothing more.
	peerMailMaxBody = 320 << 10
	// defaultPeerMailInflight is how many inbound messages may be written at
	// once. Each one is a write transaction on the daemon-wide arbiter, so this
	// is deliberately small: a peer must never be able to put local agents
	// behind a queue of remote work.
	defaultPeerMailInflight = 2
	// defaultPeerMailTimeout bounds one acceptance.
	defaultPeerMailTimeout = 10 * time.Second
	// defaultPeerMailPort is where a peer daemon is dialled when an address
	// names no port. It matches the HTTP listener's default, which is the port
	// the peer listener derives its own from.
	defaultPeerMailPort = "8080"
	// peerMailResponseCap bounds what this host will read back from a peer. An
	// acceptance answer is a few hundred bytes; the cap is far above that and
	// still finite, so a hostile peer cannot answer a small request with an
	// endless body.
	peerMailResponseCap = 64 << 10
)

// PeerMailDependencies configures the inbound peer mail route.
type PeerMailDependencies struct {
	// Mail accepts inbound messages. A nil acceptor makes the route report the
	// missing capability rather than disappear, so a peer learns that this
	// daemon does not take mail rather than that the route does not exist --
	// and can therefore tell a build without the feature from a refusal.
	Mail coordination.PeerMailAcceptor
	// MaxInflight caps concurrent acceptances. Zero takes the default; a
	// negative value is a composition error rather than "unbounded".
	MaxInflight int
	// Timeout bounds one acceptance. Zero takes the default.
	Timeout time.Duration
	Logger  *slog.Logger
}

type peerMailHandler struct {
	mail     coordination.PeerMailAcceptor
	inflight chan struct{}
	timeout  time.Duration
	logger   *slog.Logger
}

// peerMailRequest is the wire envelope.
//
// There is deliberately NO origin host field. The one place this host learns
// which machine is calling is its own verified peer identity, and accepting a
// second answer to that question -- even as a hint, even for logging -- would
// create a value a peer controls that looks like one it does not.
type peerMailRequest struct {
	ProjectKey string `json:"project_key"`
	// ThreadKey correlates the sender's conversation with the one this host
	// keeps. It is opaque here.
	ThreadKey string `json:"thread_key"`
	// Topic names the thread if this host has to open one. It is ignored when
	// the key already names a conversation, because that conversation's topic
	// is this host's own.
	Topic string `json:"topic,omitempty"`
	// FromAgent is the sender's name on its own host, unqualified.
	FromAgent string `json:"from_agent"`
	// To are agent names as registered HERE.
	To                      []string `json:"to"`
	Subject                 string   `json:"subject"`
	Body                    string   `json:"body"`
	AcknowledgementRequired bool     `json:"acknowledgement_required,omitempty"`
	// OriginMessageID is the id the sender minted, and the idempotency key.
	OriginMessageID string `json:"origin_message_id"`
}

type peerMailResponse struct {
	// MessageID and ConversationID are the ids THIS host minted. The sender
	// stores the message id as a receipt and must not attempt to resolve it
	// here: it names a row in a database that is not the sender's.
	MessageID      string   `json:"message_id"`
	ConversationID string   `json:"conversation_id"`
	Delivered      []string `json:"delivered"`
	// Duplicate reports that this exact origin message had already been
	// accepted. It is a success: the message is there.
	Duplicate bool `json:"duplicate"`
}

// NewPeerMailHandler serves POST /api/v1/local/peer/mail to verified peers.
func NewPeerMailHandler(dependencies PeerMailDependencies) (stdhttp.Handler, error) {
	if dependencies.MaxInflight < 0 || dependencies.Timeout < 0 {
		return nil, errors.New("peer mail transport bounds cannot be negative")
	}
	inflight := dependencies.MaxInflight
	if inflight == 0 {
		inflight = defaultPeerMailInflight
	}
	timeout := dependencies.Timeout
	if timeout == 0 {
		timeout = defaultPeerMailTimeout
	}
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	handler := &peerMailHandler{inflight: make(chan struct{}, inflight), timeout: timeout, logger: logger}
	if !isNil(dependencies.Mail) {
		handler.mail = dependencies.Mail
	}
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("POST "+PathLocalPeerMail, handler.accept)
	return localSafety(mux), nil
}

func (handler *peerMailHandler) accept(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	identity, verified := Peer(request)
	if !verified {
		// A loopback caller lands here, and it is refused rather than served:
		// mail sent from this machine is sent by an agent holding an agent
		// token, and this route holds none. Serving it locally would be an
		// unauthenticated way to write into any mailbox on this host.
		writeLocalProblem(writer, stdhttp.StatusForbidden, domain.ErrorCodeForbidden,
			"this route serves verified tailnet peers; send mail from this host through the agent API")
		return
	}
	if len(request.URL.Query()) != 0 {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
			"query parameters are invalid")
		return
	}
	if handler.mail == nil {
		writeLocalProblem(writer, stdhttp.StatusServiceUnavailable, domain.ErrorCodeDependencyUnavailable,
			"this daemon was composed without a mailbox, so it cannot accept peer mail")
		return
	}
	var input peerMailRequest
	if err := decodeLocalJSONWithin(writer, request, &input, peerMailMaxBody); err != nil {
		handler.logger.Warn("peer mail envelope was rejected",
			slog.String("machine_name", identity.MachineName), slog.Any("error", err))
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
			"request body is invalid")
		return
	}
	// Admission is refused rather than queued, so a peer that is told to come
	// back retries on its own budget instead of holding a write slot here.
	select {
	case handler.inflight <- struct{}{}:
		defer func() { <-handler.inflight }()
	default:
		handler.logger.Warn("peer mail refused for concurrency",
			slog.String("machine_name", identity.MachineName),
			slog.Int("limit", cap(handler.inflight)))
		writer.Header().Set("Retry-After", "1")
		writeLocalProblem(writer, stdhttp.StatusServiceUnavailable, domain.ErrorCodeBackpressure,
			"too many peer messages are already being accepted on this host")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	accepted, err := handler.mail.AcceptPeerMail(ctx, coordination.AcceptPeerMailParams{
		// The origin host is the VERIFIED machine name, never the payload's.
		OriginHost: identity.MachineName,
		ProjectKey: input.ProjectKey, ThreadKey: input.ThreadKey, Topic: input.Topic,
		FromAgent: input.FromAgent, ToAgents: input.To, Subject: input.Subject, Body: input.Body,
		AcknowledgementRequired: input.AcknowledgementRequired,
		OriginMessageID:         input.OriginMessageID,
	})
	if err != nil {
		handler.logger.Warn("peer mail was not accepted",
			slog.String("machine_name", identity.MachineName),
			slog.String("stable_id", identity.StableID), slog.Any("error", err))
		writeLocalError(writer, err)
		return
	}
	handler.logger.Info("peer mail accepted",
		slog.String("machine_name", identity.MachineName),
		slog.String("message_id", accepted.MessageID.String()),
		slog.Bool("duplicate", accepted.Duplicate))
	writeLocalJSON(writer, stdhttp.StatusOK, peerMailResponse{
		MessageID: accepted.MessageID.String(), ConversationID: accepted.ConversationID.String(),
		Delivered: accepted.Delivered, Duplicate: accepted.Duplicate,
	})
}

// PeerMailClientDependencies configures the outbound half.
type PeerMailClientDependencies struct {
	// HTTP is the client used for every attempt. A nil client takes one that
	// refuses redirects, because a peer answering with a redirect is answering
	// a question nobody asked and following it would deliver mail to a host the
	// operator never named.
	HTTP *stdhttp.Client
	// Port is where a peer is dialled when its address names none.
	Port   string
	Logger *slog.Logger
}

// PeerMailClient delivers one message to one peer daemon.
//
// It carries NO CREDENTIAL of this machine, and that is the property worth
// protecting: a peer authenticates this caller by asking its own tailnet who
// connected, so there is nothing here for a hostile endpoint to capture by
// pretending to be a peer. It speaks exactly one route and reads exactly one
// answer.
type PeerMailClient struct {
	client *stdhttp.Client
	port   string
	logger *slog.Logger
}

// NewPeerMailClient builds the outbound adapter.
func NewPeerMailClient(dependencies PeerMailClientDependencies) *PeerMailClient {
	client := dependencies.HTTP
	if client == nil {
		client = &stdhttp.Client{
			CheckRedirect: func(*stdhttp.Request, []*stdhttp.Request) error {
				return errors.New("a peer must answer directly rather than redirect")
			},
		}
	}
	port := dependencies.Port
	if port == "" {
		port = defaultPeerMailPort
	}
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &PeerMailClient{client: client, port: port, logger: logger}
}

// DeliverPeerMail attempts one delivery.
//
// Every return is classified into the two outcomes the dispatcher acts on, and
// the classification is the whole job: an answer that says no is terminal, and
// an absence of an answer is retryable. Getting that backwards either retries
// forever against a peer that will never accept, or gives up on a peer that was
// merely rebooting.
func (client *PeerMailClient) DeliverPeerMail(
	ctx context.Context,
	entry coordination.PeerMailEntry,
	recipients []string,
) (coordination.PeerMailReceipt, error) {
	if len(recipients) == 0 {
		recipients = []string{entry.Address.Agent}
	}
	address, err := peerMailDialAddress(entry.Address.Host, client.port)
	if err != nil {
		// An address this host cannot even form is not a peer that might come
		// back: it is a name nobody can dial, and retrying it is a loop.
		return coordination.PeerMailReceipt{}, fmt.Errorf("%w: %w", coordination.ErrPeerMailRefused, err)
	}
	payload, err := json.Marshal(peerMailRequest{
		ProjectKey: entry.ProjectKey, ThreadKey: entry.ThreadKey, Topic: entry.Topic,
		FromAgent: entry.FromAgent, To: recipients,
		Subject: entry.Subject, Body: entry.Body,
		AcknowledgementRequired: entry.AcknowledgementRequired,
		OriginMessageID:         entry.MessageID.String(),
	})
	if err != nil {
		return coordination.PeerMailReceipt{}, fmt.Errorf("%w: %w", coordination.ErrPeerMailRefused, err)
	}
	request, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost,
		"http://"+address+PathLocalPeerMail, bytes.NewReader(payload))
	if err != nil {
		return coordination.PeerMailReceipt{}, fmt.Errorf("%w: %w", coordination.ErrPeerMailUnreachable, err)
	}
	request.Header.Set("Content-Type", mediaTypeJSON)
	response, err := client.client.Do(request)
	if err != nil {
		return coordination.PeerMailReceipt{},
			fmt.Errorf("%w: %s did not answer: %w", coordination.ErrPeerMailUnreachable, address, err)
	}
	defer func() { _ = response.Body.Close() }()
	body := io.LimitReader(response.Body, peerMailResponseCap)
	if response.StatusCode != stdhttp.StatusOK {
		return coordination.PeerMailReceipt{}, peerMailStatusError(address, response.StatusCode, body)
	}
	var accepted peerMailResponse
	if err := json.NewDecoder(body).Decode(&accepted); err != nil {
		// The peer may well have stored the message; we simply cannot tell. So
		// this is retryable, and the receiving host's idempotency key is what
		// makes the retry harmless.
		return coordination.PeerMailReceipt{},
			fmt.Errorf("%w: %s answered with a body this host could not read: %w",
				coordination.ErrPeerMailUnreachable, address, err)
	}
	return coordination.PeerMailReceipt{
		RemoteMessageID: accepted.MessageID, Duplicate: accepted.Duplicate,
	}, nil
}

// peerMailStatusError turns a refusal into words that name what has to change,
// and into the one bit the dispatcher needs: terminal, or try again.
func peerMailStatusError(address string, status int, body io.Reader) error {
	detail := problemDetail(body)
	switch status {
	case stdhttp.StatusForbidden:
		return fmt.Errorf("%w: %s does not accept mail from this machine: it is not on that host's "+
			"allowed-peer list, or that host is not serving peers (%s)",
			coordination.ErrPeerMailRefused, address, detail)
	case stdhttp.StatusNotFound:
		return fmt.Errorf("%w: %s has no such project or agent, or serves no peer mail route: %s",
			coordination.ErrPeerMailRefused, address, detail)
	case stdhttp.StatusBadRequest, stdhttp.StatusRequestEntityTooLarge, stdhttp.StatusUnprocessableEntity:
		return fmt.Errorf("%w: %s rejected the message: %s",
			coordination.ErrPeerMailRefused, address, detail)
	default:
		// Everything else -- busy, unavailable, an error on the far side, a
		// status this host does not recognise -- is an absence of an answer
		// about the message itself, so it is retryable.
		return fmt.Errorf("%w: %s answered %d: %s",
			coordination.ErrPeerMailUnreachable, address, status, detail)
	}
}

func problemDetail(body io.Reader) string {
	var problem localProblem
	if err := json.NewDecoder(body).Decode(&problem); err != nil || problem.Message == "" {
		return "no detail"
	}
	if problem.Code == "" {
		return problem.Message
	}
	return string(problem.Code) + ": " + problem.Message
}

// peerMailDialAddress turns a peer address's host half into HOST:PORT. It
// refuses rather than repairs, because a repaired address is a message
// delivered to a machine nobody named.
func peerMailDialAddress(host, defaultPort string) (string, error) {
	if host == "" {
		return "", errors.New("the address names no host")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}
	return net.JoinHostPort(host, defaultPort), nil
}
