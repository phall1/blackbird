package sqlite

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

func TestAdminThreadScopesAndPagesFullMessagesWithoutChangingFacts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	carol := registerAdminAgent(t, store, adminProjectB, "carol")
	thread := openAdminConversation(t, store, alice, "target")
	other := openAdminConversation(t, store, alice, "other")
	foreign := openAdminConversation(t, store, carol, "foreign")
	first := sendAdminMessage(t, store, alice, thread, "first", true, bob.ActorID, alice.ActorID)
	sendAdminMessage(t, store, alice, other, "other secret", false, bob.ActorID)
	second := sendAdminMessage(t, store, bob, thread, "second", false, alice.ActorID)
	sendAdminMessage(t, store, carol, foreign, "foreign secret", true, carol.ActorID)
	third := sendAdminMessageWithKinds(t, store, alice, thread, "third", true,
		map[domain.ActorID]coordination.RecipientKind{bob.ActorID: coordination.RecipientBcc})
	readAdminDelivery(t, store, alice, second)
	if _, err := store.RecordDeliveryFact(ctx, coordination.RecordDeliveryFactParams{
		WorkspaceID: bob.WorkspaceID, MessageID: first.ID(), Recipient: bob.ActorID,
		ActorSessionID: &bob.ActorSessionID, Kind: coordination.DeliveryAcknowledged,
		MessageDigest: first.Digest(),
	}); err != nil {
		t.Fatal(err)
	}
	before := adminThreadFacts(t, store)
	query := coordination.AdminThreadQuery{ProjectKey: adminProjectA, ConversationID: thread, Limit: 2}
	page, err := store.AdminThread(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if page.ProjectKey != adminProjectA || page.ConversationID != thread || !page.HasMore || page.Next != second.Position() || page.ObservedAtUS <= 0 {
		t.Fatalf("first page=%+v", page)
	}
	want := []coordination.AdminThreadMessage{
		{MessageID: first.ID(), Position: first.Position(), AuthorAgentName: "alice", Subject: first.Subject(), Body: first.Body(), SentAtUS: first.SentAt().UnixMicro()},
		{MessageID: second.ID(), Position: second.Position(), AuthorAgentName: "bob", Subject: second.Subject(), Body: second.Body(), SentAtUS: second.SentAt().UnixMicro()},
	}
	if !reflect.DeepEqual(page.Messages, want) {
		t.Fatalf("messages=%+v want=%+v", page.Messages, want)
	}
	query.After = page.Next
	page, err = store.AdminThread(ctx, query)
	if err != nil || page.HasMore || len(page.Messages) != 1 || page.Next != third.Position() {
		t.Fatalf("second page=%+v err=%v", page, err)
	}
	if page.Messages[0].Body != third.Body() {
		t.Fatalf("blind-copy message body=%q", page.Messages[0].Body)
	}
	query.After = page.Next
	page, err = store.AdminThread(ctx, query)
	if err != nil || page.HasMore || len(page.Messages) != 0 || page.Next != query.After {
		t.Fatalf("empty page=%+v err=%v", page, err)
	}
	query.After, query.Limit = 0, 3
	page, err = store.AdminThread(ctx, query)
	if err != nil || page.HasMore || len(page.Messages) != 3 {
		t.Fatalf("exact-limit page=%+v err=%v", page, err)
	}
	if after := adminThreadFacts(t, store); after != before {
		t.Fatalf("thread read changed delivery, event or activity facts: before=%s after=%s", before, after)
	}
}

func adminThreadFacts(t *testing.T, store *Store) string {
	t.Helper()
	var facts string
	err := store.db.QueryRowContext(context.Background(), `SELECT json_array(
		(SELECT json_group_array(json_array(message_id, recipient_actor_id, recipient_kind,
		acknowledgement_required, available_at_us, read_at_us, acknowledged_at_us,
		acknowledged_by_session_id, hex(acknowledged_message_digest))) FROM message_deliveries),
		(SELECT count(*) FROM coordination_events),
		(SELECT json_group_array(json_array(session_id, last_seen_at_us)) FROM coordination_agent_sessions))`).Scan(&facts)
	if err != nil {
		t.Fatal(err)
	}
	return facts
}

func TestAdminThreadRejectsMissingAndCrossProjectScopes(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	registerAdminAgent(t, store, adminProjectB, "bob")
	thread := openAdminConversation(t, store, alice, "empty")
	missing, err := domain.NewConversationID()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		query coordination.AdminThreadQuery
		want  error
	}{
		{"missing project", coordination.AdminThreadQuery{ConversationID: thread}, coordination.ErrInvalid},
		{"missing conversation", coordination.AdminThreadQuery{ProjectKey: adminProjectA}, coordination.ErrInvalid},
		{"cross project", coordination.AdminThreadQuery{ProjectKey: adminProjectB, ConversationID: thread}, domain.ErrNotFound},
		{"unknown project", coordination.AdminThreadQuery{ProjectKey: "/unknown", ConversationID: thread}, domain.ErrNotFound},
		{"unknown conversation", coordination.AdminThreadQuery{ProjectKey: adminProjectA, ConversationID: missing}, domain.ErrNotFound},
		{"oversized cursor", coordination.AdminThreadQuery{ProjectKey: adminProjectA, ConversationID: thread, After: coordination.AdminThreadMaxPosition + 1}, coordination.ErrInvalid},
		{"oversized limit", coordination.AdminThreadQuery{ProjectKey: adminProjectA, ConversationID: thread, Limit: 257}, coordination.ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := store.AdminThread(context.Background(), test.query); !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
	page, err := store.AdminThread(context.Background(), coordination.AdminThreadQuery{ProjectKey: adminProjectA, ConversationID: thread})
	if err != nil || len(page.Messages) != 0 || page.Next != 0 || page.HasMore {
		t.Fatalf("empty conversation=%+v err=%v", page, err)
	}
}
