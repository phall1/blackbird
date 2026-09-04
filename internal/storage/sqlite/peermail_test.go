package sqlite

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

const peerMailProject = "/workspace/peer-mail"

func peerMailSender(t *testing.T, store *Store, project, name string) coordination.LocalAgentSession {
	t.Helper()
	session, _, err := store.RegisterLocalAgent(context.Background(), project, name, "")
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func peerMailConversation(t *testing.T, store *Store,
	session coordination.LocalAgentSession, topic string) domain.ConversationID {
	t.Helper()
	id, err := domain.NewConversationID()
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := store.OpenConversation(context.Background(), coordination.OpenConversationParams{
		ConversationID: id, WorkspaceID: session.WorkspaceID, RunID: session.RunID,
		OpenedBy: session.ActorID, OpenedBySession: session.ActorSessionID, Topic: topic,
	})
	if err != nil {
		t.Fatal(err)
	}
	return conversation.ID()
}

func peerMailAddress(t *testing.T, text string) coordination.PeerAddress {
	t.Helper()
	address, err := coordination.ParsePeerAddress(text)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

// TestSendPeerMailQueuesOneEntryPerRemoteRecipient is the property the whole
// design rests on: the message is durable HERE before anything is attempted on
// the wire, so a peer being unreachable cannot fail a send.
func TestSendPeerMailQueuesOneEntryPerRemoteRecipient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := peerMailSender(t, store, peerMailProject, "implementer")
	local := peerMailSender(t, store, peerMailProject, "reviewer")
	conversation := peerMailConversation(t, store, session, "the peering seam")
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}

	sent, err := store.SendPeerMail(ctx, session, coordination.SendPeerMailParams{
		MessageID: messageID, ConversationID: conversation,
		Subject: "peer mail", Body: "the outbox is durable before the wire is touched",
		LocalRecipients: []string{"reviewer"},
		PeerRecipients: []coordination.PeerAddress{
			peerMailAddress(t, "reviewer@phalls-mac-mini"),
			peerMailAddress(t, "builder@laptop"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent.Message.ID() != messageID {
		t.Fatalf("message id=%s, want %s", sent.Message.ID(), messageID)
	}
	if len(sent.Queued) != 2 {
		t.Fatalf("queued=%d, want 2", len(sent.Queued))
	}
	if sent.ThreadKey == "" {
		t.Fatal("a cross-host send must mint a thread key")
	}
	// The local recipient is delivered exactly as it always was; the host
	// boundary changes nothing about mail that did not cross one.
	inbox, err := store.Inbox(ctx, mustInboxQuery(t, local))
	if err != nil {
		t.Fatal(err)
	}
	if len(inbox.Messages()) != 1 {
		t.Fatalf("local inbox=%d, want the message that also went to two hosts", len(inbox.Messages()))
	}
	// Three deliveries: one local agent and two peer actors.
	if deliveries := sent.Message.Deliveries(); len(deliveries) != 3 {
		t.Fatalf("deliveries=%d, want 3", len(deliveries))
	}

	entries, err := store.ClaimPeerMail(ctx, time.Now().Add(time.Second), coordination.PeerMailBatch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("due entries=%d, want 2", len(entries))
	}
	for _, entry := range entries {
		if entry.State != coordination.PeerDeliveryQueued || entry.Attempts != 0 {
			t.Fatalf("entry=%+v, want a fresh queued entry", entry)
		}
		if entry.Body != "the outbox is durable before the wire is touched" || entry.Subject != "peer mail" {
			t.Fatalf("entry carried subject=%q body=%q, want the stored message", entry.Subject, entry.Body)
		}
		if entry.Topic != "the peering seam" || entry.FromAgent != "implementer" {
			t.Fatalf("entry topic=%q from=%q, want the joined conversation and author",
				entry.Topic, entry.FromAgent)
		}
		if entry.ProjectKey != peerMailProject {
			t.Fatalf("entry project=%q, want the sender's own project key by default", entry.ProjectKey)
		}
		// Absent facts stay absent. Nothing has failed and no peer has named an
		// id, so neither field may carry a placeholder.
		if entry.LastError != "" || entry.RemoteMessageID != "" {
			t.Fatalf("fresh entry carried last error %q and receipt %q, want both absent",
				entry.LastError, entry.RemoteMessageID)
		}
	}
}

func mustInboxQuery(t *testing.T, session coordination.LocalAgentSession) coordination.InboxQuery {
	t.Helper()
	return coordination.InboxQuery{WorkspaceID: session.WorkspaceID, Recipient: session.ActorID, Limit: 10}
}

// TestPeerAgentAuthenticatesNobodyAndIsNotInTheRoster covers the two properties
// that keep a peer actor from being a way into this host.
func TestPeerAgentAuthenticatesNobodyAndIsNotInTheRoster(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := peerMailSender(t, store, peerMailProject, "implementer")
	conversation := peerMailConversation(t, store, session, "roster")
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SendPeerMail(ctx, session, coordination.SendPeerMailParams{
		MessageID: messageID, ConversationID: conversation, Subject: "s", Body: "b",
		PeerRecipients: []coordination.PeerAddress{peerMailAddress(t, "reviewer@phalls-mac-mini")},
	}); err != nil {
		t.Fatal(err)
	}
	agents, err := store.ListActiveLocalAgents(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	for _, agent := range agents {
		if strings.Contains(agent.Name, coordination.PeerAddressSeparator) {
			t.Fatalf("the active roster names the peer actor %q; a closed session must keep it out", agent.Name)
		}
	}
	// Its token digest is random rather than the digest of anything, so no
	// string authenticates as it. The digest itself is the only value that
	// could, and it is not a token.
	var digest []byte
	if err := store.db.QueryRowContext(ctx, `SELECT registration_token_digest FROM coordination_agents
		WHERE project_key = ? AND agent_name = ?`, peerMailProject,
		"reviewer@phalls-mac-mini").Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if len(digest) != 32 {
		t.Fatalf("peer agent digest length=%d, want 32", len(digest))
	}
	if _, err := store.AuthenticateLocalAgent(ctx, string(digest)); err == nil {
		t.Fatal("a peer actor must authenticate nobody")
	}
}

// TestRegisterLocalAgentReservesTheAddressSeparator keeps the address grammar
// unambiguous by construction rather than by whichever agent registered first.
func TestRegisterLocalAgentReservesTheAddressSeparator(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	_, _, err := store.RegisterLocalAgent(context.Background(), peerMailProject, "reviewer@laptop", "")
	if err == nil {
		t.Fatal("an agent name containing the address separator must be refused")
	}
	var commandError *domain.CommandError
	if !errors.As(err, &commandError) || commandError.Code() != domain.ErrorCodeInvalidArgument {
		t.Fatalf("error=%v, want INVALID_ARGUMENT", err)
	}
}

// TestAcceptPeerMailAppendsIntoThisHostsMailbox is the inbound half: an
// ordinary message, in an ordinary inbox, authored by an actor named for the
// VERIFIED origin host.
func TestAcceptPeerMailAppendsIntoThisHostsMailbox(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	recipient := peerMailSender(t, store, peerMailProject, "reviewer")

	accepted, err := store.AcceptPeerMail(ctx, coordination.AcceptPeerMailParams{
		OriginHost: "phalls-mac-mini", ProjectKey: peerMailProject,
		ThreadKey: "9f1c2b3a4d5e6f708192a3b4c5d6e7f8", Topic: "the peering seam",
		FromAgent: "implementer", ToAgents: []string{"reviewer"},
		Subject: "from the mini", Body: "a message that crossed a host boundary",
		OriginMessageID: "11111111-1111-4111-8111-111111111111",
	})
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Duplicate {
		t.Fatal("the first acceptance is not a duplicate")
	}
	page, err := store.Inbox(ctx, mustInboxQuery(t, recipient))
	if err != nil {
		t.Fatal(err)
	}
	messages := page.Messages()
	if len(messages) != 1 {
		t.Fatalf("inbox=%d, want the message from the peer", len(messages))
	}
	if messages[0].Body() != "a message that crossed a host boundary" {
		t.Fatalf("body=%q", messages[0].Body())
	}
	var authorName string
	if err := store.db.QueryRowContext(ctx, `SELECT agent.agent_name FROM coordination_agents AS agent
		JOIN messages AS message ON message.author_actor_id = agent.actor_id
		WHERE message.message_id = ?`, messages[0].ID().String()).Scan(&authorName); err != nil {
		t.Fatal(err)
	}
	if authorName != "implementer@phalls-mac-mini" {
		t.Fatalf("author=%q, want the sender qualified by the verified host", authorName)
	}
}

// TestAcceptPeerMailIsIdempotentPerOriginMessage is what makes a retry after a
// lost response safe, which is in turn what lets an unsettled attempt be
// retried without a distributed transaction.
func TestAcceptPeerMailIsIdempotentPerOriginMessage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	recipient := peerMailSender(t, store, peerMailProject, "reviewer")
	params := coordination.AcceptPeerMailParams{
		OriginHost: "phalls-mac-mini", ProjectKey: peerMailProject,
		ThreadKey: "9f1c2b3a4d5e6f708192a3b4c5d6e7f8", Topic: "retry",
		FromAgent: "implementer", ToAgents: []string{"reviewer"},
		Subject: "once", Body: "exactly once", OriginMessageID: "22222222-2222-4222-8222-222222222222",
	}
	first, err := store.AcceptPeerMail(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AcceptPeerMail(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate {
		t.Fatal("a repeated origin message id must be reported as a duplicate")
	}
	if second.MessageID != first.MessageID || second.ConversationID != first.ConversationID {
		t.Fatalf("duplicate answered %+v, want the first acceptance %+v", second, first)
	}
	page, err := store.Inbox(ctx, mustInboxQuery(t, recipient))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Messages()) != 1 {
		t.Fatalf("inbox=%d, want exactly one message after two deliveries of it", len(page.Messages()))
	}
}

// TestAcceptPeerMailRefusesWhatThisHostDoesNotHave covers the two refusals that
// keep a peer writing into this host's MAILBOX rather than into its authority.
func TestAcceptPeerMailRefusesWhatThisHostDoesNotHave(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	peerMailSender(t, store, peerMailProject, "reviewer")
	base := coordination.AcceptPeerMailParams{
		OriginHost: "phalls-mac-mini", ProjectKey: peerMailProject, ThreadKey: "abc123",
		FromAgent: "implementer", ToAgents: []string{"reviewer"}, Subject: "s", Body: "b",
		OriginMessageID: "33333333-3333-4333-8333-333333333333",
	}

	unknownProject := base
	unknownProject.ProjectKey = "/workspace/not-checked-out-here"
	if _, err := store.AcceptPeerMail(ctx, unknownProject); !isNotFound(err) {
		t.Fatalf("unknown project error=%v, want NOT_FOUND rather than a created project", err)
	}
	unknownAgent := base
	unknownAgent.ToAgents = []string{"nobody"}
	if _, err := store.AcceptPeerMail(ctx, unknownAgent); !isNotFound(err) {
		t.Fatalf("unknown recipient error=%v, want NOT_FOUND rather than a created agent", err)
	}
}

func isNotFound(err error) bool {
	var commandError *domain.CommandError
	return errors.As(err, &commandError) && commandError.Code() == domain.ErrorCodeNotFound
}

// TestPeerThreadKeyIsScopedToTheWorkspace is the containment property: a key is
// a value a peer sends us, so it must not be able to reach a conversation in a
// project the peer never named.
func TestPeerThreadKeyIsScopedToTheWorkspace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	first := peerMailSender(t, store, "/workspace/one", "reviewer")
	second := peerMailSender(t, store, "/workspace/two", "reviewer")
	key := "5555555555555555aaaaaaaaaaaaaaaa"

	one, err := store.AcceptPeerMail(ctx, coordination.AcceptPeerMailParams{
		OriginHost: "mini", ProjectKey: "/workspace/one", ThreadKey: key, FromAgent: "sender",
		ToAgents: []string{"reviewer"}, Subject: "one", Body: "one",
		OriginMessageID: "44444444-4444-4444-8444-444444444444",
	})
	if err != nil {
		t.Fatal(err)
	}
	two, err := store.AcceptPeerMail(ctx, coordination.AcceptPeerMailParams{
		OriginHost: "mini", ProjectKey: "/workspace/two", ThreadKey: key, FromAgent: "sender",
		ToAgents: []string{"reviewer"}, Subject: "two", Body: "two",
		OriginMessageID: "55555555-5555-4555-8555-555555555555",
	})
	if err != nil {
		t.Fatal(err)
	}
	if one.ConversationID == two.ConversationID {
		t.Fatal("one thread key reached two projects; the lookup must be scoped to the workspace")
	}
	for _, session := range []coordination.LocalAgentSession{first, second} {
		page, pageErr := store.Inbox(ctx, mustInboxQuery(t, session))
		if pageErr != nil {
			t.Fatal(pageErr)
		}
		if len(page.Messages()) != 1 {
			t.Fatalf("project %q inbox=%d, want only its own message",
				session.ProjectKey, len(page.Messages()))
		}
	}
}

// TestPeerThreadKeyKeepsOneExchangeInOneThread is the reason the correlator
// exists at all: a reply carries the key back and lands in the conversation
// this host already has, rather than opening a second one-sided thread.
func TestPeerThreadKeyKeepsOneExchangeInOneThread(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := peerMailSender(t, store, peerMailProject, "implementer")
	conversation := peerMailConversation(t, store, session, "one thread")
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	sent, err := store.SendPeerMail(ctx, session, coordination.SendPeerMailParams{
		MessageID: messageID, ConversationID: conversation, Subject: "out", Body: "out",
		PeerRecipients: []coordination.PeerAddress{peerMailAddress(t, "reviewer@phalls-mac-mini")},
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.AcceptPeerMail(ctx, coordination.AcceptPeerMailParams{
		OriginHost: "phalls-mac-mini", ProjectKey: peerMailProject, ThreadKey: sent.ThreadKey,
		FromAgent: "reviewer", ToAgents: []string{"implementer"}, Subject: "back", Body: "back",
		OriginMessageID: "66666666-6666-4666-8666-666666666666",
	})
	if err != nil {
		t.Fatal(err)
	}
	if accepted.ConversationID != conversation {
		t.Fatalf("reply landed in conversation %s, want the original %s",
			accepted.ConversationID, conversation)
	}
	// And the reply is authored by the same local actor the original was
	// addressed to, so the thread reads as one exchange with one counterpart.
	var authorName string
	if err := store.db.QueryRowContext(ctx, `SELECT agent.agent_name FROM coordination_agents AS agent
		JOIN messages AS message ON message.author_actor_id = agent.actor_id
		WHERE message.message_id = ?`, accepted.MessageID.String()).Scan(&authorName); err != nil {
		t.Fatal(err)
	}
	if authorName != "reviewer@phalls-mac-mini" {
		t.Fatalf("reply author=%q, want the same peer actor the original addressed", authorName)
	}
}

// TestSettlePeerMailRecordsEachOutcomeExactlyOnce walks an entry through all
// three states and asserts the absences that make each of them readable.
func TestSettlePeerMailRecordsEachOutcomeExactlyOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := peerMailSender(t, store, peerMailProject, "implementer")
	conversation := peerMailConversation(t, store, session, "settling")
	address := peerMailAddress(t, "reviewer@phalls-mac-mini")
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SendPeerMail(ctx, session, coordination.SendPeerMailParams{
		MessageID: messageID, ConversationID: conversation, Subject: "s", Body: "b",
		PeerRecipients: []coordination.PeerAddress{address},
	}); err != nil {
		t.Fatal(err)
	}

	later := time.Now().Add(time.Minute)
	if err := store.SettlePeerMail(ctx, coordination.PeerMailOutcome{
		MessageID: messageID, Address: address, State: coordination.PeerDeliveryQueued,
		Detail: "connection refused", NextAttemptAt: later,
	}); err != nil {
		t.Fatal(err)
	}
	entry := onlyQueueEntry(t, store, later.Add(time.Second))
	if entry.State != coordination.PeerDeliveryQueued || entry.Attempts != 1 {
		t.Fatalf("entry=%+v, want a queued entry with one attempt", entry)
	}
	if entry.LastError != "connection refused" {
		t.Fatalf("last error=%q, want the failure that was recorded", entry.LastError)
	}
	if entry.RemoteMessageID != "" {
		t.Fatalf("a failed attempt named a receipt %q", entry.RemoteMessageID)
	}

	if err := store.SettlePeerMail(ctx, coordination.PeerMailOutcome{
		MessageID: messageID, Address: address, State: coordination.PeerDeliveryDelivered,
		RemoteMessageID: "peer-side-id", SettledAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := store.PeerMailQueue(ctx, peerMailProject, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].State != coordination.PeerDeliveryDelivered {
		t.Fatalf("queue=%+v, want one delivered entry", entries)
	}
	if entries[0].RemoteMessageID != "peer-side-id" {
		t.Fatalf("receipt=%q, want the id the peer named", entries[0].RemoteMessageID)
	}
	if !entries[0].NextAttemptAt.IsZero() {
		t.Fatalf("a settled entry kept a next attempt at %v", entries[0].NextAttemptAt)
	}
	// A settle that arrives after the entry is terminal changes nothing.
	if err := store.SettlePeerMail(ctx, coordination.PeerMailOutcome{
		MessageID: messageID, Address: address, State: coordination.PeerDeliveryUndeliverable,
		Detail: "too late", SettledAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	entries, err = store.PeerMailQueue(ctx, peerMailProject, 10)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].State != coordination.PeerDeliveryDelivered {
		t.Fatalf("state=%q, want a terminal entry to stay terminal", entries[0].State)
	}
}

func onlyQueueEntry(t *testing.T, store *Store, now time.Time) coordination.PeerMailEntry {
	t.Helper()
	entries, err := store.ClaimPeerMail(context.Background(), now, coordination.PeerMailBatch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("due entries=%d, want 1", len(entries))
	}
	return entries[0]
}

// TestClaimPeerMailRespectsTheBackoff proves the drain does not spin on an
// entry it has just failed.
func TestClaimPeerMailRespectsTheBackoff(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	session := peerMailSender(t, store, peerMailProject, "implementer")
	conversation := peerMailConversation(t, store, session, "backoff")
	address := peerMailAddress(t, "reviewer@phalls-mac-mini")
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SendPeerMail(ctx, session, coordination.SendPeerMailParams{
		MessageID: messageID, ConversationID: conversation, Subject: "s", Body: "b",
		PeerRecipients: []coordination.PeerAddress{address},
	}); err != nil {
		t.Fatal(err)
	}
	due := time.Now().Add(time.Hour)
	if err := store.SettlePeerMail(ctx, coordination.PeerMailOutcome{
		MessageID: messageID, Address: address, State: coordination.PeerDeliveryQueued,
		Detail: "timeout", NextAttemptAt: due,
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := store.ClaimPeerMail(ctx, due.Add(-time.Minute), coordination.PeerMailBatch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("claimed %d entries before the backoff elapsed", len(entries))
	}
	entries, err = store.ClaimPeerMail(ctx, due.Add(time.Minute), coordination.PeerMailBatch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("claimed %d entries after the backoff elapsed, want 1", len(entries))
	}
}

// TestPeerAgentsAreBoundedPerProject stops an allowed-but-misbehaving peer from
// minting rows without end.
func TestPeerAgentsAreBoundedPerProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	peerMailSender(t, store, peerMailProject, "reviewer")
	var lastErr error
	for index := range coordination.MaxPeerAgentsPerProject + 2 {
		_, lastErr = store.AcceptPeerMail(ctx, coordination.AcceptPeerMailParams{
			OriginHost: "mini", ProjectKey: peerMailProject, ThreadKey: "thread",
			FromAgent: "sender" + strconv.Itoa(index), ToAgents: []string{"reviewer"},
			Subject: "s", Body: "b", OriginMessageID: "origin-" + strconv.Itoa(index),
		})
		if lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatal("a peer must not be able to mint unbounded local actors")
	}
	var commandError *domain.CommandError
	if !errors.As(lastErr, &commandError) || commandError.Code() != domain.ErrorCodeBackpressure {
		t.Fatalf("error=%v, want BACKPRESSURE once the ceiling is reached", lastErr)
	}
}

// TestTruncatePeerDetailKeepsTheTextValid is the difference between a recorded
// failure and an infinitely retried one: a torn rune fails the TEXT write, the
// outcome is never settled, and the entry becomes due again forever.
func TestTruncatePeerDetailKeepsTheTextValid(t *testing.T) {
	t.Parallel()
	// Multi-byte runes arranged so a naive byte cut lands mid-rune.
	long := strings.Repeat("é", 4096)
	truncated := truncatePeerDetail(long)
	if len(truncated) > 2048 {
		t.Fatalf("truncated length=%d, want at most 2048 bytes", len(truncated))
	}
	if !utf8.ValidString(truncated) {
		t.Fatal("truncation tore a rune; the write would fail and the outcome would never be recorded")
	}
	if short := truncatePeerDetail("connection refused"); short != "connection refused" {
		t.Fatalf("a short detail was altered: %q", short)
	}
	if receipt := truncatePeerReceipt(strings.Repeat("ø", 200)); len(receipt) > 128 || !utf8.ValidString(receipt) {
		t.Fatalf("receipt truncation produced %d bytes, valid=%t", len(receipt), utf8.ValidString(receipt))
	}
}

// TestAcceptPeerMailIsIdempotentPerRecipient is the silent-drop this exists to
// prevent. A sender queues one entry per remote recipient and settles them one
// at a time, so a lost response or a failed settle can split one message into
// two requests carrying the same origin id. The second must still deliver to
// the recipient it names.
func TestAcceptPeerMailIsIdempotentPerRecipient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	first := peerMailSender(t, store, peerMailProject, "reviewer")
	second := peerMailSender(t, store, peerMailProject, "builder")
	base := coordination.AcceptPeerMailParams{
		OriginHost: "phalls-mac-mini", ProjectKey: peerMailProject, ThreadKey: "split",
		FromAgent: "implementer", Subject: "split", Body: "one message, two requests",
		OriginMessageID: "77777777-7777-4777-8777-777777777777",
	}
	toFirst := base
	toFirst.ToAgents = []string{"reviewer"}
	one, err := store.AcceptPeerMail(ctx, toFirst)
	if err != nil {
		t.Fatal(err)
	}
	toSecond := base
	toSecond.ToAgents = []string{"builder"}
	two, err := store.AcceptPeerMail(ctx, toSecond)
	if err != nil {
		t.Fatal(err)
	}
	if !two.Duplicate {
		t.Fatal("the same origin id must still be reported as a duplicate message")
	}
	if two.MessageID != one.MessageID {
		t.Fatalf("second acceptance minted a second message %s", two.MessageID)
	}
	for _, session := range []coordination.LocalAgentSession{first, second} {
		page, pageErr := store.Inbox(ctx, mustInboxQuery(t, session))
		if pageErr != nil {
			t.Fatal(pageErr)
		}
		if len(page.Messages()) != 1 {
			t.Fatalf("%s inbox=%d, want the one message addressed to it",
				session.AgentName, len(page.Messages()))
		}
	}
	// And a third request naming a recipient that already has it changes
	// nothing: read and acknowledgement facts belong to the recipient.
	if _, err := store.AcceptPeerMail(ctx, toFirst); err != nil {
		t.Fatal(err)
	}
	var deliveries int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM message_deliveries WHERE message_id = ?`,
		one.MessageID.String()).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 2 {
		t.Fatalf("deliveries=%d, want exactly one per named recipient", deliveries)
	}
}

// TestSettlePeerMailRefusesAReceiptWithoutADelivery keeps a receipt from being
// recorded against an attempt that did not deliver: it names a row on another
// machine, and a receipt beside a failure would be a reference to nothing.
func TestSettlePeerMailRefusesAReceiptWithoutADelivery(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	address := peerMailAddress(t, "reviewer@phalls-mac-mini")
	if err := store.SettlePeerMail(context.Background(), coordination.PeerMailOutcome{
		MessageID: messageID, Address: address, State: coordination.PeerDeliveryUndeliverable,
		RemoteMessageID: "invented", SettledAt: time.Now(),
	}); err == nil {
		t.Fatal("a receipt beside an undeliverable outcome must be refused")
	}
	if err := store.SettlePeerMail(context.Background(), coordination.PeerMailOutcome{
		MessageID: messageID, Address: address, State: coordination.PeerDeliveryQueued,
	}); err == nil {
		t.Fatal("a queued outcome with no next attempt must be refused; the schema has nowhere to put it")
	}
}
