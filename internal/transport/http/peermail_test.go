package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	stdhttp "net/http"
	"net/http/httptest"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

// stubAcceptor records what the route handed the application, which is where
// the identity assertion lives: the origin host must be the VERIFIED one.
type stubAcceptor struct {
	mu       sync.Mutex
	received []coordination.AcceptPeerMailParams
	accepted coordination.AcceptedPeerMail
	err      error
	block    chan struct{}
}

func (stub *stubAcceptor) AcceptPeerMail(ctx context.Context,
	params coordination.AcceptPeerMailParams) (coordination.AcceptedPeerMail, error) {
	stub.mu.Lock()
	stub.received = append(stub.received, params)
	block := stub.block
	stub.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return coordination.AcceptedPeerMail{}, ctx.Err()
		}
	}
	return stub.accepted, stub.err
}

func (stub *stubAcceptor) calls() []coordination.AcceptPeerMailParams {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return append([]coordination.AcceptPeerMailParams(nil), stub.received...)
}

func peerMailHandlerFor(t *testing.T, dependencies PeerMailDependencies) stdhttp.Handler {
	t.Helper()
	handler, err := NewPeerMailHandler(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func peerMailEnvelope(t *testing.T, envelope peerMailRequest) *bytes.Reader {
	t.Helper()
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(encoded)
}

func verifiedPeerMailRequest(t *testing.T, envelope peerMailRequest) *stdhttp.Request {
	t.Helper()
	request := httptest.NewRequest(stdhttp.MethodPost, PathLocalPeerMail, peerMailEnvelope(t, envelope))
	request.RemoteAddr = peerRemoteAddress
	request.Host = peerHostHeader
	return request.WithContext(context.WithValue(request.Context(), peerAdmissionKey{}, theMini()))
}

func servePeerMail(handler stdhttp.Handler, request *stdhttp.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func sampleEnvelope() peerMailRequest {
	return peerMailRequest{
		ProjectKey: "/repo", ThreadKey: "abc123", Topic: "peering", FromAgent: "implementer",
		To: []string{"reviewer"}, Subject: "hello", Body: "from another host",
		OriginMessageID: "11111111-1111-4111-8111-111111111111",
	}
}

func acceptedMail(t *testing.T) coordination.AcceptedPeerMail {
	t.Helper()
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	conversationID, err := domain.NewConversationID()
	if err != nil {
		t.Fatal(err)
	}
	return coordination.AcceptedPeerMail{MessageID: messageID, ConversationID: conversationID,
		Delivered: []string{"reviewer"}}
}

// TestPeerMailTakesTheOriginHostFromTheVerifiedIdentity is the identity
// property the whole address scheme rests on. A sender that CLAIMS another
// machine in its payload is still recorded as the machine that connected --
// and the envelope has no field for it at all, so the claim cannot even be
// spelled.
func TestPeerMailTakesTheOriginHostFromTheVerifiedIdentity(t *testing.T) {
	t.Parallel()
	acceptor := &stubAcceptor{accepted: acceptedMail(t)}
	handler := peerMailHandlerFor(t, PeerMailDependencies{Mail: acceptor})

	response := servePeerMail(handler, verifiedPeerMailRequest(t, sampleEnvelope()))
	if response.Code != stdhttp.StatusOK {
		t.Fatalf("status=%d, want 200: %s", response.Code, response.Body.String())
	}
	calls := acceptor.calls()
	if len(calls) != 1 {
		t.Fatalf("acceptor calls=%d, want 1", len(calls))
	}
	if calls[0].OriginHost != theMini().MachineName {
		t.Fatalf("origin host=%q, want the verified %q", calls[0].OriginHost, theMini().MachineName)
	}
	if calls[0].FromAgent != "implementer" || calls[0].ProjectKey != "/repo" {
		t.Fatalf("params=%+v, want the envelope's own fields", calls[0])
	}
	var payload peerMailResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.MessageID == "" || payload.ConversationID == "" {
		t.Fatalf("response=%+v, want the ids this host minted", payload)
	}
	if payload.Duplicate {
		t.Fatal("a first acceptance is not a duplicate")
	}
}

// TestPeerMailRefusesALoopbackCaller keeps this route from being an
// unauthenticated way for any process on this machine to write into any
// mailbox.
func TestPeerMailRefusesALoopbackCaller(t *testing.T) {
	t.Parallel()
	acceptor := &stubAcceptor{accepted: acceptedMail(t)}
	handler := peerMailHandlerFor(t, PeerMailDependencies{Mail: acceptor})

	request := newLocalHTTPRequest(stdhttp.MethodPost, PathLocalPeerMail, peerMailEnvelope(t, sampleEnvelope()))
	response := servePeerMail(handler, request)
	if response.Code != stdhttp.StatusForbidden {
		t.Fatalf("status=%d, want 403 for a loopback caller", response.Code)
	}
	if calls := acceptor.calls(); len(calls) != 0 {
		t.Fatalf("a loopback caller reached the mailbox: %+v", calls)
	}
}

// TestPeerMailReportsAMissingMailboxRatherThanDisappearing lets a sender tell a
// build without the feature from a host that refused it.
func TestPeerMailReportsAMissingMailboxRatherThanDisappearing(t *testing.T) {
	t.Parallel()
	handler := peerMailHandlerFor(t, PeerMailDependencies{})
	response := servePeerMail(handler, verifiedPeerMailRequest(t, sampleEnvelope()))
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", response.Code)
	}
	var problem localProblem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != domain.ErrorCodeDependencyUnavailable {
		t.Fatalf("code=%q, want DEPENDENCY_UNAVAILABLE", problem.Code)
	}
}

// TestPeerMailRefusesRatherThanQueuesExcessConcurrency is the bound that keeps
// a peer from putting this host's own agents behind a queue of remote writes.
func TestPeerMailRefusesRatherThanQueuesExcessConcurrency(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	acceptor := &stubAcceptor{accepted: acceptedMail(t), block: release}
	handler := peerMailHandlerFor(t, PeerMailDependencies{Mail: acceptor, MaxInflight: 1})

	started := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		close(started)
		done <- servePeerMail(handler, verifiedPeerMailRequest(t, sampleEnvelope())).Code
	}()
	<-started
	// Wait until the first request is actually inside the acceptor, so the
	// second one meets a full gate rather than an empty one.
	deadline := time.Now().Add(2 * time.Second)
	for len(acceptor.calls()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	second := sampleEnvelope()
	second.OriginMessageID = "22222222-2222-4222-8222-222222222222"
	response := servePeerMail(handler, verifiedPeerMailRequest(t, second))
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503 backpressure", response.Code)
	}
	if response.Header().Get("Retry-After") == "" {
		t.Fatal("a refused peer was not told when to come back")
	}
	close(release)
	if code := <-done; code != stdhttp.StatusOK {
		t.Fatalf("the admitted request answered %d", code)
	}
}

// TestPeerMailRejectsAnOversizedEnvelope bounds what a peer can make this host
// read.
func TestPeerMailRejectsAnOversizedEnvelope(t *testing.T) {
	t.Parallel()
	acceptor := &stubAcceptor{accepted: acceptedMail(t)}
	handler := peerMailHandlerFor(t, PeerMailDependencies{Mail: acceptor})
	oversized := sampleEnvelope()
	oversized.Body = strings.Repeat("x", peerMailMaxBody+1)

	response := servePeerMail(handler, verifiedPeerMailRequest(t, oversized))
	if response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status=%d, want 400", response.Code)
	}
	if calls := acceptor.calls(); len(calls) != 0 {
		t.Fatalf("an oversized envelope reached the mailbox: %d calls", len(calls))
	}
}

func TestNewPeerMailHandlerRefusesNegativeBounds(t *testing.T) {
	t.Parallel()
	if _, err := NewPeerMailHandler(PeerMailDependencies{MaxInflight: -1}); err == nil {
		t.Fatal("a negative concurrency bound must be a composition error")
	}
	if _, err := NewPeerMailHandler(PeerMailDependencies{Timeout: -time.Second}); err == nil {
		t.Fatal("a negative timeout must be a composition error")
	}
}

func peerMailTestEntry(t *testing.T, host string) coordination.PeerMailEntry {
	t.Helper()
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	return coordination.PeerMailEntry{
		MessageID: messageID, Address: coordination.PeerAddress{Agent: "reviewer", Host: host},
		ProjectKey: "/repo", ThreadKey: "abc123", Topic: "peering", FromAgent: "implementer",
		Subject: "hello", Body: "over the wire", State: coordination.PeerDeliveryQueued,
	}
}

// TestPeerMailClientRoundTrip is the outbound half against a real listener, and
// it asserts the receipt is the id the PEER minted rather than one this host
// invented.
func TestPeerMailClientRoundTrip(t *testing.T) {
	t.Parallel()
	var received peerMailRequest
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		if request.URL.Path != PathLocalPeerMail || request.Method != stdhttp.MethodPost {
			writer.WriteHeader(stdhttp.StatusNotFound)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			writer.WriteHeader(stdhttp.StatusBadRequest)
			return
		}
		writeLocalJSON(writer, stdhttp.StatusOK, peerMailResponse{
			MessageID: "peer-minted-id", ConversationID: "peer-conversation", Delivered: []string{"reviewer"},
		})
	}))
	defer server.Close()

	client := NewPeerMailClient(PeerMailClientDependencies{})
	entry := peerMailTestEntry(t, strings.TrimPrefix(server.URL, "http://"))
	receipt, err := client.DeliverPeerMail(context.Background(), entry, []string{"reviewer"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RemoteMessageID != "peer-minted-id" {
		t.Fatalf("receipt=%q, want the id the peer minted", receipt.RemoteMessageID)
	}
	if received.OriginMessageID != entry.MessageID.String() {
		t.Fatalf("origin id=%q, want this host's own message id", received.OriginMessageID)
	}
	if len(received.To) != 1 || received.To[0] != "reviewer" {
		t.Fatalf("to=%v, want the bare agent name the far side resolves", received.To)
	}
	if strings.Contains(received.FromAgent, coordination.PeerAddressSeparator) {
		t.Fatalf("from=%q, want the sender's unqualified name; the peer qualifies it", received.FromAgent)
	}
}

// TestPeerMailClientClassifiesEveryRefusal is the whole job of the client: an
// answer that says no is terminal, and an absence of an answer is retryable.
// Getting it backwards either loops forever or gives up on a rebooting peer.
func TestPeerMailClientClassifiesEveryRefusal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status int
		want   error
	}{
		{stdhttp.StatusForbidden, coordination.ErrPeerMailRefused},
		{stdhttp.StatusNotFound, coordination.ErrPeerMailRefused},
		{stdhttp.StatusBadRequest, coordination.ErrPeerMailRefused},
		{stdhttp.StatusRequestEntityTooLarge, coordination.ErrPeerMailRefused},
		{stdhttp.StatusServiceUnavailable, coordination.ErrPeerMailUnreachable},
		{stdhttp.StatusInternalServerError, coordination.ErrPeerMailUnreachable},
		{stdhttp.StatusTooManyRequests, coordination.ErrPeerMailUnreachable},
	}
	for _, testCase := range cases {
		server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
			writeLocalProblem(writer, testCase.status, domain.ErrorCodeForbidden, "no")
		}))
		client := NewPeerMailClient(PeerMailClientDependencies{})
		_, err := client.DeliverPeerMail(context.Background(),
			peerMailTestEntry(t, strings.TrimPrefix(server.URL, "http://")), nil)
		if !errors.Is(err, testCase.want) {
			t.Errorf("status %d classified as %v, want %v", testCase.status, err, testCase.want)
		}
		server.Close()
	}
}

// TestPeerMailClientTreatsAnUnreachableHostAsRetryable is the property that
// makes a peer being down a queued delivery rather than a lost one.
func TestPeerMailClientTreatsAnUnreachableHostAsRetryable(t *testing.T) {
	t.Parallel()
	// Port 1 on loopback refuses connections without needing a listener.
	client := NewPeerMailClient(PeerMailClientDependencies{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.DeliverPeerMail(ctx, peerMailTestEntry(t, "127.0.0.1:1"), nil)
	if !errors.Is(err, coordination.ErrPeerMailUnreachable) {
		t.Fatalf("error=%v, want an unreachable peer to be retryable", err)
	}
}

// TestPeerMailClientRefusesAnUnreadableAnswerAsRetryable covers the one case
// where this host genuinely cannot tell: the peer may well have stored the
// message. Retrying is safe because the receiving host's idempotency key
// absorbs it.
func TestPeerMailClientRefusesAnUnreadableAnswerAsRetryable(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.Header().Set("Content-Type", mediaTypeJSON)
		_, _ = writer.Write([]byte("not json"))
	}))
	defer server.Close()
	client := NewPeerMailClient(PeerMailClientDependencies{})
	_, err := client.DeliverPeerMail(context.Background(),
		peerMailTestEntry(t, strings.TrimPrefix(server.URL, "http://")), nil)
	if !errors.Is(err, coordination.ErrPeerMailUnreachable) {
		t.Fatalf("error=%v, want an unreadable answer to stay retryable", err)
	}
}

// TestPeerMailClientRefusesToFollowARedirect stops a peer from sending this
// host's mail to a machine the operator never named.
func TestPeerMailClientRefusesToFollowARedirect(t *testing.T) {
	t.Parallel()
	elsewhere := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writeLocalJSON(writer, stdhttp.StatusOK, peerMailResponse{MessageID: "captured"})
	}))
	defer elsewhere.Close()
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		stdhttp.Redirect(writer, request, elsewhere.URL+PathLocalPeerMail, stdhttp.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client := NewPeerMailClient(PeerMailClientDependencies{})
	receipt, err := client.DeliverPeerMail(context.Background(),
		peerMailTestEntry(t, strings.TrimPrefix(server.URL, "http://")), nil)
	if err == nil {
		t.Fatalf("a redirect was followed and answered %+v", receipt)
	}
}

func TestPeerMailDialAddressAttachesTheDefaultPort(t *testing.T) {
	t.Parallel()
	address, err := peerMailDialAddress("phalls-mac-mini", "8080")
	if err != nil {
		t.Fatal(err)
	}
	if address != "phalls-mac-mini:8080" {
		t.Fatalf("address=%q", address)
	}
	if address, err = peerMailDialAddress("phalls-mac-mini:9000", "8080"); err != nil || address != "phalls-mac-mini:9000" {
		t.Fatalf("address=%q err=%v, want the port the operator wrote to win", address, err)
	}
	if _, err := peerMailDialAddress("", "8080"); err == nil {
		t.Fatal("an empty host must be refused rather than dialled")
	}
}

// TestPeerMailClientCarriesEveryRecipientForOneHost is the wire half of the
// grouping: one message addressed to two agents on one machine is ONE request,
// because the receiving host keys idempotency on the sending host's message id.
func TestPeerMailClientCarriesEveryRecipientForOneHost(t *testing.T) {
	t.Parallel()
	requests := 0
	var received peerMailRequest
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		requests++
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			writer.WriteHeader(stdhttp.StatusBadRequest)
			return
		}
		writeLocalJSON(writer, stdhttp.StatusOK, peerMailResponse{MessageID: "peer-minted"})
	}))
	defer server.Close()

	client := NewPeerMailClient(PeerMailClientDependencies{})
	entry := peerMailTestEntry(t, strings.TrimPrefix(server.URL, "http://"))
	if _, err := client.DeliverPeerMail(context.Background(), entry, []string{"reviewer", "builder"}); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d, want one per host per message", requests)
	}
	if len(received.To) != 2 || received.To[0] != "reviewer" || received.To[1] != "builder" {
		t.Fatalf("to=%v, want both recipients in one envelope", received.To)
	}
}
