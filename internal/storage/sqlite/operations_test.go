package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

func TestCoordinationErrorConstructionFailuresAreReturned(t *testing.T) {
	t.Parallel()

	commandErr := coordinationError(domain.ErrorCode("invented"), "message")
	if commandErr == nil || !errors.Is(commandErr, domain.ErrUnknownErrorCode) ||
		!strings.Contains(commandErr.Error(), "construct coordination error") {
		t.Fatalf("coordination error = %v", commandErr)
	}
	conflictErr := coordinationConflict(domain.ErrorCodeLeaseConflict, domain.ConflictAuthorityMismatch, "message")
	if conflictErr == nil || !errors.Is(conflictErr, domain.ErrInvalidConflictKind) ||
		!strings.Contains(conflictErr.Error(), "construct coordination conflict") {
		t.Fatalf("coordination conflict = %v", conflictErr)
	}
}

func TestCheckpointReportsPassiveAndBoundedTruncate(t *testing.T) {
	t.Parallel()
	store := newOperationStore(t)
	if _, err := store.db.ExecContext(context.Background(), "CREATE TABLE operation_probe (value INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), "INSERT INTO operation_probe VALUES (1)"); err != nil {
		t.Fatal(err)
	}

	passive, err := store.Checkpoint(context.Background(), CheckpointPassive)
	if err != nil {
		t.Fatal(err)
	}
	if passive.Mode != CheckpointPassive || passive.LogFrames < 0 || passive.CheckpointedFrames < 0 ||
		passive.RemainingFrames < 0 || passive.Duration <= 0 || passive.FreeBytes == 0 || passive.OldestReaderKnown {
		t.Fatalf("passive report=%+v", passive)
	}
	if _, err := store.Checkpoint(context.Background(), CheckpointTruncate); err == nil {
		t.Fatal("unbounded truncating checkpoint was accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	truncate, err := store.Checkpoint(ctx, CheckpointTruncate)
	if err != nil {
		t.Fatal(err)
	}
	if truncate.Mode != CheckpointTruncate || truncate.Busy || truncate.RemainingFrames != 0 ||
		truncate.WALBytes != 0 || truncate.Duration <= 0 {
		t.Fatalf("truncate report=%+v", truncate)
	}
	if _, err := store.Checkpoint(context.Background(), CheckpointMode("restart")); err == nil {
		t.Fatal("unknown checkpoint mode was accepted")
	}
}

func TestCoordinationMessagePrivacyAndIndependentFacts(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	workspace := coordinationWorkspace(t, 1)
	run, _ := domain.ParseRunID(coordinationUUID(2))
	author := coordinationActor(t, 3)
	to := coordinationActor(t, 4)
	cc := coordinationActor(t, 5)
	bcc := coordinationActor(t, 6)
	outsider := coordinationActor(t, 7)
	session, _ := domain.ParseActorSessionID(coordinationUUID(8))
	conversationID, _ := domain.ParseConversationID(coordinationUUID(9))
	conversation, err := store.OpenConversation(context.Background(), coordination.OpenConversationParams{
		ConversationID: conversationID, WorkspaceID: workspace, RunID: run, OpenedBy: author,
		OpenedBySession: session, Topic: "daily coordination",
	})
	if err != nil || conversation.ID() != conversationID {
		t.Fatalf("conversation=%v error=%v", conversation.ID(), err)
	}
	recipients := make([]coordination.Recipient, 0, 3)
	for _, value := range []struct {
		actor domain.ActorID
		kind  coordination.RecipientKind
	}{
		{to, coordination.RecipientTo}, {cc, coordination.RecipientCc}, {bcc, coordination.RecipientBcc},
	} {
		recipient, recipientErr := coordination.NewRecipient(value.actor, value.kind)
		if recipientErr != nil {
			t.Fatal(recipientErr)
		}
		recipients = append(recipients, recipient)
	}
	messageID, _ := domain.ParseMessageID(coordinationUUID(10))
	message, err := store.SendMessage(context.Background(), coordination.SendMessageParams{MessageID: messageID,
		ConversationID: conversationID, WorkspaceID: workspace, Author: author, AuthorSession: session,
		Subject: "handoff", Body: "durable body", Recipients: recipients, AcknowledgementRequired: true})
	if err != nil || len(message.Deliveries()) != 3 {
		t.Fatalf("deliveries=%d error=%v", len(message.Deliveries()), err)
	}

	assertVisibleKinds := func(viewer domain.ActorID, want ...coordination.RecipientKind) {
		t.Helper()
		page, queryErr := store.Thread(context.Background(), coordination.ThreadQuery{WorkspaceID: workspace,
			ConversationID: conversationID, Viewer: viewer, Limit: 10})
		if queryErr != nil {
			t.Fatal(queryErr)
		}
		if len(want) == 0 {
			if len(page.Messages()) != 0 {
				t.Fatalf("outsider saw %d messages", len(page.Messages()))
			}
			return
		}
		if len(page.Messages()) != 1 {
			t.Fatalf("viewer %s saw %d messages", viewer, len(page.Messages()))
		}
		got := page.Messages()[0].Deliveries()
		if len(got) != len(want) {
			t.Fatalf("viewer %s deliveries=%d want=%d", viewer, len(got), len(want))
		}
		for index := range want {
			if got[index].Recipient().Kind() != want[index] {
				t.Fatalf("viewer %s kind[%d]=%s want=%s", viewer, index, got[index].Recipient().Kind(), want[index])
			}
		}
	}
	assertVisibleKinds(author, coordination.RecipientBcc, coordination.RecipientCc, coordination.RecipientTo)
	assertVisibleKinds(to, coordination.RecipientCc, coordination.RecipientTo)
	assertVisibleKinds(bcc, coordination.RecipientBcc, coordination.RecipientCc, coordination.RecipientTo)
	assertVisibleKinds(outsider)

	digest := message.Digest()
	ack, err := store.RecordDeliveryFact(context.Background(), coordination.RecordDeliveryFactParams{WorkspaceID: workspace,
		MessageID: messageID, Recipient: bcc, ActorSessionID: &session, Kind: coordination.DeliveryAcknowledged,
		MessageDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ack.AcknowledgedAt(); !ok {
		t.Fatal("acknowledgement was not recorded")
	}
	if _, ok := ack.ReadAt(); ok {
		t.Fatal("acknowledgement implied read")
	}
	read, err := store.RecordDeliveryFact(context.Background(), coordination.RecordDeliveryFactParams{WorkspaceID: workspace,
		MessageID: messageID, Recipient: bcc, ActorSessionID: &session, Kind: coordination.DeliveryRead})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := read.ReadAt(); !ok {
		t.Fatal("read was not recorded")
	}
	if _, ok := read.AcknowledgedAt(); !ok {
		t.Fatal("read regressed acknowledgement")
	}
	readAt, _ := read.ReadAt()
	if availableAt, ok := read.AvailableAt(); !ok || availableAt.After(readAt) {
		t.Fatal("send-time availability was not retained")
	}
	if _, err := store.RecordDeliveryFact(context.Background(), coordination.RecordDeliveryFactParams{WorkspaceID: workspace,
		MessageID: messageID, Recipient: outsider, ActorSessionID: &session, Kind: coordination.DeliveryRead}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("outsider read error=%v", err)
	}
}

func TestCoordinationEventJournalIsPrivateBoundedAuthenticatedAndImmutable(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	workspace := coordinationWorkspace(t, 300)
	author := coordinationActor(t, 301)
	recipient := coordinationActor(t, 302)
	other := coordinationActor(t, 303)
	session, _ := domain.ParseActorSessionID(coordinationUUID(304))
	run, _ := domain.ParseRunID(coordinationUUID(305))
	conversationID, _ := domain.ParseConversationID(coordinationUUID(306))
	if _, err := store.OpenConversation(context.Background(), coordination.OpenConversationParams{ConversationID: conversationID,
		WorkspaceID: workspace, RunID: run, OpenedBy: author, OpenedBySession: session, Topic: "journal"}); err != nil {
		t.Fatal(err)
	}
	to, _ := coordination.NewRecipient(recipient, coordination.RecipientTo)
	for index := 0; index < 2; index++ {
		messageID, _ := domain.ParseMessageID(coordinationUUID(310 + index))
		if _, err := store.SendMessage(context.Background(), coordination.SendMessageParams{MessageID: messageID,
			ConversationID: conversationID, WorkspaceID: workspace, Author: author, AuthorSession: session,
			Subject: "event", Body: "body", Recipients: []coordination.Recipient{to}}); err != nil {
			t.Fatal(err)
		}
	}
	query, _ := coordination.NewCoordinationEventsQuery(workspace, recipient, coordination.CoordinationEventCursor{}, 1)
	first, err := store.SyncCoordinationEvents(context.Background(), query)
	if err != nil || len(first.Events()) != 1 || !first.HasMore() || first.NextCursor().IsZero() ||
		first.Events()[0].EventType() != coordination.CoordinationEventMessageAvailable || first.Events()[0].ActorID() != author {
		t.Fatalf("first coordination page=%+v error=%v", first, err)
	}
	continued, _ := coordination.NewCoordinationEventsQuery(workspace, recipient, first.NextCursor(), 1)
	second, err := store.SyncCoordinationEvents(context.Background(), continued)
	if err != nil || len(second.Events()) != 1 || second.HasMore() || second.Events()[0].Position() <= first.Events()[0].Position() {
		t.Fatalf("second coordination page=%+v error=%v", second, err)
	}
	if len(first.EventCursors()) != 1 || first.EventCursors()[0].IsZero() || len(second.EventCursors()) != 1 {
		t.Fatalf("event cursors first=%+v second=%+v", first.EventCursors(), second.EventCursors())
	}
	consumer, _ := coordination.NewCoordinationConsumerID("pi-extension")
	consumerQuery, _ := coordination.NewCoordinationConsumerEventsQuery(workspace, recipient, consumer, 1)
	consumerFirst, err := store.SyncCoordinationEvents(context.Background(), consumerQuery)
	if err != nil || len(consumerFirst.Events()) != 1 || consumerFirst.Events()[0].Position() != first.Events()[0].Position() {
		t.Fatalf("initial consumer page=%+v error=%v", consumerFirst, err)
	}
	commit, _ := coordination.NewCoordinationConsumerCommit(workspace, recipient, consumer, consumerFirst.EventCursors()[0])
	if err := store.CommitCoordinationConsumer(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	consumerSecond, err := store.SyncCoordinationEvents(context.Background(), consumerQuery)
	if err != nil || len(consumerSecond.Events()) != 1 || consumerSecond.Events()[0].Position() != second.Events()[0].Position() {
		t.Fatalf("advanced consumer page=%+v error=%v", consumerSecond, err)
	}
	commit, _ = coordination.NewCoordinationConsumerCommit(workspace, recipient, consumer, consumerSecond.EventCursors()[0])
	if err := store.CommitCoordinationConsumer(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	// A delayed duplicate acknowledgement cannot move the consumer backwards.
	stale, _ := coordination.NewCoordinationConsumerCommit(workspace, recipient, consumer, consumerFirst.EventCursors()[0])
	if err := store.CommitCoordinationConsumer(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	drained, err := store.SyncCoordinationEvents(context.Background(), consumerQuery)
	if err != nil || len(drained.Events()) != 0 {
		t.Fatalf("drained consumer page=%+v error=%v", drained, err)
	}
	independent, _ := coordination.NewCoordinationConsumerID("opencode")
	independentQuery, _ := coordination.NewCoordinationConsumerEventsQuery(workspace, recipient, independent, 1)
	independentPage, err := store.SyncCoordinationEvents(context.Background(), independentQuery)
	if err != nil || len(independentPage.Events()) != 1 || independentPage.Events()[0].Position() != first.Events()[0].Position() {
		t.Fatalf("independent consumer page=%+v error=%v", independentPage, err)
	}
	wrongScope, _ := coordination.NewCoordinationConsumerCommit(workspace, other, consumer, first.EventCursors()[0])
	if err := store.CommitCoordinationConsumer(context.Background(), wrongScope); err == nil {
		t.Fatal("actor-scoped acknowledgement was accepted for another actor")
	}
	otherQuery, _ := coordination.NewCoordinationEventsQuery(workspace, other, coordination.CoordinationEventCursor{}, 10)
	private, err := store.SyncCoordinationEvents(context.Background(), otherQuery)
	if err != nil || len(private.Events()) != 0 {
		t.Fatalf("other actor events=%d error=%v", len(private.Events()), err)
	}
	scopeMismatch, _ := coordination.NewCoordinationEventsQuery(workspace, other, first.NextCursor(), 1)
	if _, err := store.SyncCoordinationEvents(context.Background(), scopeMismatch); err == nil {
		t.Fatal("actor-scoped cursor was accepted for another actor")
	}
	tampered, _ := coordination.NewCoordinationEventCursor(first.NextCursor().String() + "x")
	tamperedQuery, _ := coordination.NewCoordinationEventsQuery(workspace, recipient, tampered, 1)
	if _, err := store.SyncCoordinationEvents(context.Background(), tamperedQuery); err == nil {
		t.Fatal("tampered coordination cursor was accepted")
	}
	if _, err := store.db.Exec(`UPDATE coordination_events SET event_type = 'message.read'`); err == nil {
		t.Fatal("coordination event update was accepted")
	}
	if _, err := store.db.Exec(`UPDATE coordination_event_recipients SET actor_id = ?`, other.String()); err == nil {
		t.Fatal("coordination event recipient update was accepted")
	}
	if _, err := store.db.Exec(`DELETE FROM coordination_event_recipients`); err != nil {
		t.Fatalf("coordination event recipient retention delete: %v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM coordination_events WHERE position <= ?`, second.Events()[0].Position()); err != nil {
		t.Fatalf("coordination event retention delete: %v", err)
	}
	if _, err := store.db.Exec(`UPDATE coordination_event_retention SET retained_from_position = ? WHERE singleton = 1`,
		second.Events()[0].Position()+1); err != nil {
		t.Fatal(err)
	}
	expired, _ := coordination.NewCoordinationEventsQuery(workspace, recipient, first.NextCursor(), 1)
	if _, err := store.SyncCoordinationEvents(context.Background(), expired); !errors.Is(err, domain.ErrCursorExpired) {
		t.Fatalf("expired cursor error=%v, want CURSOR_EXPIRED", err)
	}
}

func TestCoordinationJournalStoresOneMessageFactForAllRecipients(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	workspace := coordinationWorkspace(t, 330)
	author := coordinationActor(t, 331)
	toActor := coordinationActor(t, 332)
	bccActor := coordinationActor(t, 333)
	outsider := coordinationActor(t, 334)
	session, _ := domain.ParseActorSessionID(coordinationUUID(335))
	run, _ := domain.ParseRunID(coordinationUUID(336))
	conversationID, _ := domain.ParseConversationID(coordinationUUID(337))
	messageID, _ := domain.ParseMessageID(coordinationUUID(338))
	if _, err := store.OpenConversation(context.Background(), coordination.OpenConversationParams{ConversationID: conversationID,
		WorkspaceID: workspace, RunID: run, OpenedBy: author, OpenedBySession: session, Topic: "one fact"}); err != nil {
		t.Fatal(err)
	}
	to, _ := coordination.NewRecipient(toActor, coordination.RecipientTo)
	bcc, _ := coordination.NewRecipient(bccActor, coordination.RecipientBcc)
	message, err := store.SendMessage(context.Background(), coordination.SendMessageParams{MessageID: messageID,
		ConversationID: conversationID, WorkspaceID: workspace, Author: author, AuthorSession: session,
		Subject: "event", Body: "body", Recipients: []coordination.Recipient{to, bcc}, AcknowledgementRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	var events, recipients int
	if err := store.db.QueryRow(`SELECT count(*) FROM coordination_events WHERE subject_id = ?`, messageID.String()).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT count(*) FROM coordination_event_recipients AS recipient
		JOIN coordination_events AS event USING(position) WHERE event.subject_id = ?`, messageID.String()).Scan(&recipients); err != nil {
		t.Fatal(err)
	}
	if events != 1 || recipients != 2 {
		t.Fatalf("message facts=%d recipients=%d, want one fact for two recipients", events, recipients)
	}
	for _, actor := range []domain.ActorID{toActor, bccActor} {
		query, _ := coordination.NewCoordinationEventsQuery(workspace, actor, coordination.CoordinationEventCursor{}, 10)
		page, syncErr := store.SyncCoordinationEvents(context.Background(), query)
		if syncErr != nil || len(page.Events()) != 1 || page.Events()[0].ActorID() != author {
			t.Fatalf("recipient %s page=%+v error=%v", actor, page, syncErr)
		}
		if bytes.Contains(page.Events()[0].Payload(), []byte(toActor.String())) ||
			bytes.Contains(page.Events()[0].Payload(), []byte(bccActor.String())) {
			t.Fatalf("recipient list leaked through message event payload: %s", page.Events()[0].Payload())
		}
	}
	outsiderQuery, _ := coordination.NewCoordinationEventsQuery(workspace, outsider, coordination.CoordinationEventCursor{}, 10)
	outsiderPage, err := store.SyncCoordinationEvents(context.Background(), outsiderQuery)
	if err != nil || len(outsiderPage.Events()) != 0 {
		t.Fatalf("outsider page=%+v error=%v", outsiderPage, err)
	}
	digest := message.Digest()
	if _, err := store.RecordDeliveryFact(context.Background(), coordination.RecordDeliveryFactParams{WorkspaceID: workspace,
		MessageID: messageID, Recipient: toActor, ActorSessionID: &session, Kind: coordination.DeliveryRead}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordDeliveryFact(context.Background(), coordination.RecordDeliveryFactParams{WorkspaceID: workspace,
		MessageID: messageID, Recipient: toActor, ActorSessionID: &session, Kind: coordination.DeliveryAcknowledged,
		MessageDigest: digest}); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT count(*) FROM coordination_events WHERE subject_id = ?`, messageID.String()).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("read/ack duplicated the durable delivery fact: event count=%d", events)
	}
}

func TestCoordinationLeaseReleaseIsWorkspaceVisible(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	workspace := coordinationWorkspace(t, 340)
	holder := coordinationActor(t, 341)
	observer := coordinationActor(t, 342)
	session, _ := domain.ParseActorSessionID(coordinationUUID(343))
	epoch, _ := domain.ParseAuthorityEpoch(coordinationUUID(344))
	selector, _ := coordination.NewLeaseSelector(coordination.LeaseSelectorExact, "src/main.go")
	if _, err := store.db.Exec(`INSERT INTO scope_guards(scope_kind, scope_id, authority_id, authority_epoch,
		write_status, guard_generation, updated_at_us) VALUES ('workspace', ?, ?, ?, 'open', 1, 1)`,
		workspace.String(), coordinationUUID(345), epoch.String()); err != nil {
		t.Fatal(err)
	}
	leaseID, _ := domain.ParseLeaseID(coordinationUUID(346))
	lease, err := store.AcquireLease(context.Background(), coordination.AcquireLeaseParams{LeaseID: leaseID,
		WorkspaceID: workspace, Holder: holder, HolderSession: session, AuthorityEpoch: epoch,
		Mode: coordination.LeaseExclusive, Selectors: []coordination.LeaseSelector{selector}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	query, _ := coordination.NewCoordinationEventsQuery(workspace, observer, coordination.CoordinationEventCursor{}, 10)
	acquired, err := store.SyncCoordinationEvents(context.Background(), query)
	if err != nil || len(acquired.Events()) != 1 || acquired.Events()[0].EventType() != coordination.CoordinationEventLeaseAcquired ||
		acquired.Events()[0].ActorID() != holder {
		t.Fatalf("observer acquired page=%+v error=%v", acquired, err)
	}
	if _, err := store.ReleaseLease(context.Background(), coordination.ChangeLeaseParams{WorkspaceID: workspace,
		Holder: holder, HolderSession: session, AuthorityEpoch: epoch, Selectors: lease.Selectors()}); err != nil {
		t.Fatal(err)
	}
	continued, _ := coordination.NewCoordinationEventsQuery(workspace, observer, acquired.NextCursor(), 10)
	released, err := store.SyncCoordinationEvents(context.Background(), continued)
	if err != nil || len(released.Events()) != 1 || released.Events()[0].EventType() != coordination.CoordinationEventLeaseReleased ||
		released.Events()[0].ActorID() != holder {
		t.Fatalf("observer release page=%+v error=%v", released, err)
	}
}

func TestCoordinationLeaseConcurrencyAndClaimGeneration(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	workspace := coordinationWorkspace(t, 20)
	holder := coordinationActor(t, 21)
	session, _ := domain.ParseActorSessionID(coordinationUUID(22))
	epoch, _ := domain.ParseAuthorityEpoch(coordinationUUID(23))
	selector, _ := coordination.NewLeaseSelector(coordination.LeaseSelectorSubtree, "src/service")
	if _, err := store.db.Exec(`INSERT INTO scope_guards(scope_kind, scope_id, authority_id, authority_epoch,
		write_status, guard_generation, updated_at_us) VALUES ('workspace', ?, ?, ?, 'open', 1, 1)`,
		workspace.String(), coordinationUUID(24), epoch.String()); err != nil {
		t.Fatal(err)
	}

	// Each contender is its own actor. A lease never conflicts with its own
	// holder -- that is what makes a retry safe -- so one actor racing itself
	// would measure nothing but that rule.
	const contenders = 24
	contendingHolders := make([]domain.ActorID, contenders)
	for index := range contenders {
		contendingHolders[index] = coordinationActor(t, 300+index)
	}
	start := make(chan struct{})
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := range contenders {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			leaseID, _ := domain.ParseLeaseID(coordinationUUID(100 + index))
			_, err := store.AcquireLease(context.Background(), coordination.AcquireLeaseParams{LeaseID: leaseID,
				WorkspaceID: workspace, Holder: contendingHolders[index], HolderSession: session, AuthorityEpoch: epoch,
				Mode: coordination.LeaseExclusive, Selectors: []coordination.LeaseSelector{selector}, TTL: time.Hour})
			results <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	winners, conflicts := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, domain.ErrLeaseConflict) {
			conflicts++
		} else {
			t.Fatalf("acquire error=%v", err)
		}
	}
	if winners != 1 || conflicts != contenders-1 {
		t.Fatalf("winners=%d conflicts=%d", winners, conflicts)
	}

	var leaseText string
	if err := store.db.QueryRow(`SELECT lease_id FROM leases WHERE status = 'active'`).Scan(&leaseText); err != nil {
		t.Fatal(err)
	}
	winnerID, _ := domain.ParseLeaseID(leaseText)
	winner, err := loadLease(context.Background(), store.db, winnerID)
	if err != nil {
		t.Fatal(err)
	}
	winnerGeneration := winner.ClaimGeneration(selector)
	if _, err := store.db.Exec(`UPDATE leases SET expires_at_us = acquired_at_us + 1 WHERE lease_id = ?`, winner.ID().String()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	replacementID, _ := domain.ParseLeaseID(coordinationUUID(200))
	replacement, err := store.AcquireLease(context.Background(), coordination.AcquireLeaseParams{LeaseID: replacementID,
		WorkspaceID: workspace, Holder: holder, HolderSession: session, AuthorityEpoch: epoch,
		Mode: coordination.LeaseExclusive, Selectors: []coordination.LeaseSelector{selector}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ClaimGeneration(selector) <= winnerGeneration {
		t.Fatal("replacement claim generation did not advance")
	}
}

func coordinationUUID(index int) string { return fmt.Sprintf("01b8e094-9888-7000-8000-%012x", index) }
func coordinationActor(t *testing.T, index int) domain.ActorID {
	t.Helper()
	value, err := domain.ParseActorID(coordinationUUID(index))
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func coordinationWorkspace(t *testing.T, index int) domain.WorkspaceID {
	t.Helper()
	value, err := domain.ParseWorkspaceID(coordinationUUID(index))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func newCoordinationStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "coordination.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func TestPassiveCheckpointReportsFramesPinnedByLongReader(t *testing.T) {
	t.Parallel()
	store := newOperationStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, "PRAGMA wal_autocheckpoint = 0"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "CREATE TABLE reader_probe (value INTEGER NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "INSERT INTO reader_probe VALUES (0)"); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	if _, err := store.Checkpoint(bounded, CheckpointTruncate); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()

	reader, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Rollback() })
	var initial int
	if err := reader.QueryRowContext(ctx, "SELECT count(*) FROM reader_probe").Scan(&initial); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 64; index++ {
		if _, err := store.db.ExecContext(ctx, "INSERT INTO reader_probe VALUES (?)", index); err != nil {
			t.Fatal(err)
		}
	}

	report, err := store.Checkpoint(ctx, CheckpointPassive)
	if err != nil {
		t.Fatal(err)
	}
	if report.LogFrames <= 0 || report.CheckpointedFrames >= report.LogFrames || report.RemainingFrames <= 0 || report.WALBytes <= 0 {
		t.Fatalf("long-reader checkpoint report=%+v", report)
	}
	var pinned int
	if err := reader.QueryRowContext(ctx, "SELECT count(*) FROM reader_probe").Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if pinned != initial {
		t.Fatalf("reader snapshot advanced from %d rows to %d", initial, pinned)
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	bounded, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()
	released, err := store.Checkpoint(bounded, CheckpointTruncate)
	if err != nil {
		t.Fatal(err)
	}
	if released.Busy || released.RemainingFrames != 0 || released.WALBytes != 0 {
		t.Fatalf("released-reader checkpoint report=%+v", released)
	}
}

func newOperationStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	db, err := sql.Open("sqlite", databaseURL(Config{Path: path}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	store := &Store{db: db, path: path}
	store.writes.changed = make(chan struct{})
	return store
}

// mailFixture is a conversation with one author, one recipient, and one actor
// that is party to nothing, which is what makes the cursor arithmetic below
// observable: the outsider's poll must skip mail it will never be shown.
type mailFixture struct {
	store        *Store
	workspace    domain.WorkspaceID
	conversation domain.ConversationID
	author       domain.ActorID
	session      domain.ActorSessionID
	recipient    domain.ActorID
	outsider     domain.ActorID
	base         int
	sent         int
	positions    []uint64
}

func newMailFixture(t *testing.T, base, messages int) *mailFixture {
	t.Helper()
	fixture := &mailFixture{store: newCoordinationStore(t), workspace: coordinationWorkspace(t, base),
		author: coordinationActor(t, base+1), recipient: coordinationActor(t, base+2),
		outsider: coordinationActor(t, base+3), base: base}
	run, err := domain.ParseRunID(coordinationUUID(base + 4))
	if err != nil {
		t.Fatal(err)
	}
	fixture.session, err = domain.ParseActorSessionID(coordinationUUID(base + 5))
	if err != nil {
		t.Fatal(err)
	}
	fixture.conversation, err = domain.ParseConversationID(coordinationUUID(base + 6))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.OpenConversation(context.Background(), coordination.OpenConversationParams{
		ConversationID: fixture.conversation, WorkspaceID: fixture.workspace, RunID: run, OpenedBy: fixture.author,
		OpenedBySession: fixture.session, Topic: "cursor arithmetic",
	}); err != nil {
		t.Fatal(err)
	}
	for range messages {
		fixture.send(t)
	}
	return fixture
}

func (fixture *mailFixture) send(t *testing.T) coordination.Message {
	t.Helper()
	messageID, err := domain.ParseMessageID(coordinationUUID(fixture.base + 100 + fixture.sent))
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := coordination.NewRecipient(fixture.recipient, coordination.RecipientTo)
	if err != nil {
		t.Fatal(err)
	}
	message, err := fixture.store.SendMessage(context.Background(), coordination.SendMessageParams{
		MessageID: messageID, ConversationID: fixture.conversation, WorkspaceID: fixture.workspace,
		Author: fixture.author, AuthorSession: fixture.session, Subject: "position",
		Body: fmt.Sprintf("message %d", fixture.sent), Recipients: []coordination.Recipient{recipient},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.sent++
	fixture.positions = append(fixture.positions, message.Position())
	return message
}

// TestCoordinationCursorAdvancesPastMailTheViewerCannotSee pins the cost of a
// quiet poll. A page that reached the journal head has judged every message at
// or below it, so returning the cursor it was given makes the next poll rescan
// the whole workspace again -- forever, and over a corpus that only grows.
func TestCoordinationCursorAdvancesPastMailTheViewerCannotSee(t *testing.T) {
	t.Parallel()
	fixture := newMailFixture(t, 400, 4)
	head := fixture.positions[len(fixture.positions)-1]

	for _, testCase := range []struct {
		name        string
		viewer      domain.ActorID
		after       uint64
		limit       uint16
		wantCount   int
		wantHasMore bool
		wantCursor  uint64
	}{
		{name: "a bounded page stops at its last message", viewer: fixture.recipient, limit: 2, wantCount: 2,
			wantHasMore: true, wantCursor: fixture.positions[1]},
		{name: "a final page advances to the journal head", viewer: fixture.recipient, after: fixture.positions[1],
			limit: 2, wantCount: 2, wantCursor: head},
		{name: "an outsider skips the workspace in one poll", viewer: fixture.outsider, limit: 2, wantCursor: head},
		{name: "an exhausted cursor stays at the head", viewer: fixture.recipient, after: head, limit: 2, wantCursor: head},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			page, err := fixture.store.Inbox(context.Background(), coordination.InboxQuery{WorkspaceID: fixture.workspace,
				Recipient: testCase.viewer, After: testCase.after, Limit: testCase.limit})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Messages()) != testCase.wantCount || page.HasMore() != testCase.wantHasMore ||
				page.NextCursor() != testCase.wantCursor {
				t.Fatalf("messages=%d hasMore=%v cursor=%d, want messages=%d hasMore=%v cursor=%d",
					len(page.Messages()), page.HasMore(), page.NextCursor(), testCase.wantCount, testCase.wantHasMore,
					testCase.wantCursor)
			}
		})
	}

	t.Run("a cursor at the head still delivers later mail", func(t *testing.T) {
		later := fixture.send(t)
		page, err := fixture.store.Inbox(context.Background(), coordination.InboxQuery{WorkspaceID: fixture.workspace,
			Recipient: fixture.recipient, After: head, Limit: 4})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Messages()) != 1 || page.Messages()[0].ID() != later.ID() || page.NextCursor() != later.Position() {
			t.Fatalf("page=%d cursor=%d, want the single message at position %d",
				len(page.Messages()), page.NextCursor(), later.Position())
		}
	})
}

// TestThreadCursorAdvancesPastOtherConversations covers the same advance from
// the thread side, where the messages the scan rejects belong to a conversation
// the viewer is reading past rather than to another recipient.
func TestThreadCursorAdvancesPastOtherConversations(t *testing.T) {
	t.Parallel()
	fixture := newMailFixture(t, 500, 2)
	other, err := domain.ParseConversationID(coordinationUUID(fixture.base + 7))
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID(coordinationUUID(fixture.base + 4))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.OpenConversation(context.Background(), coordination.OpenConversationParams{
		ConversationID: other, WorkspaceID: fixture.workspace, RunID: run, OpenedBy: fixture.author,
		OpenedBySession: fixture.session, Topic: "another thread",
	}); err != nil {
		t.Fatal(err)
	}
	fixture.conversation = other
	head := fixture.send(t).Position()

	page, err := fixture.store.Thread(context.Background(), coordination.ThreadQuery{WorkspaceID: fixture.workspace,
		ConversationID: other, Viewer: fixture.recipient, After: fixture.positions[0], Limit: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Messages()) != 1 || page.HasMore() || page.NextCursor() != head {
		t.Fatalf("messages=%d hasMore=%v cursor=%d, want one message and cursor %d",
			len(page.Messages()), page.HasMore(), page.NextCursor(), head)
	}
}

// leaseFixture is a workspace whose lease authority is registered, which is
// what AcquireLease checks before it will hand out anything.
type leaseFixture struct {
	store     *Store
	workspace domain.WorkspaceID
	holder    domain.ActorID
	other     domain.ActorID
	session   domain.ActorSessionID
	epoch     domain.AuthorityEpoch
	base      int
	acquired  int
}

func newLeaseFixture(t *testing.T, base int) *leaseFixture {
	t.Helper()
	fixture := &leaseFixture{store: newCoordinationStore(t), workspace: coordinationWorkspace(t, base),
		holder: coordinationActor(t, base+1), other: coordinationActor(t, base+2), base: base}
	session, err := domain.ParseActorSessionID(coordinationUUID(base + 3))
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := domain.ParseAuthorityEpoch(coordinationUUID(base + 4))
	if err != nil {
		t.Fatal(err)
	}
	fixture.session, fixture.epoch = session, epoch
	if _, err := fixture.store.db.Exec(`INSERT INTO scope_guards(scope_kind, scope_id, authority_id, authority_epoch,
		write_status, guard_generation, updated_at_us) VALUES ('workspace', ?, ?, ?, 'open', 1, 1)`,
		fixture.workspace.String(), coordinationUUID(base+5), epoch.String()); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *leaseFixture) acquire(t *testing.T, holder domain.ActorID, mode coordination.LeaseMode,
	kind coordination.LeaseSelectorKind, path string) (coordination.Lease, error) {
	t.Helper()
	leaseID, err := domain.ParseLeaseID(coordinationUUID(fixture.base + 100 + fixture.acquired))
	if err != nil {
		t.Fatal(err)
	}
	fixture.acquired++
	selector, err := coordination.NewLeaseSelector(kind, path)
	if err != nil {
		t.Fatal(err)
	}
	return fixture.store.AcquireLease(context.Background(), coordination.AcquireLeaseParams{LeaseID: leaseID,
		WorkspaceID: fixture.workspace, Holder: holder, HolderSession: fixture.session, AuthorityEpoch: fixture.epoch,
		Mode: mode, Selectors: []coordination.LeaseSelector{selector}, TTL: time.Hour})
}

func (fixture *leaseFixture) expire(t *testing.T, lease coordination.Lease) {
	t.Helper()
	if _, err := fixture.store.db.Exec(`UPDATE leases SET expires_at_us = acquired_at_us + 1 WHERE lease_id = ?`,
		lease.ID().String()); err != nil {
		t.Fatal(err)
	}
}

func (fixture *leaseFixture) status(t *testing.T, lease coordination.Lease) (string, sql.NullInt64) {
	t.Helper()
	var status string
	var released sql.NullInt64
	if err := fixture.store.db.QueryRow(`SELECT status, released_at_us FROM leases WHERE lease_id = ?`,
		lease.ID().String()).Scan(&status, &released); err != nil {
		t.Fatal(err)
	}
	return status, released
}

func commandMessage(t *testing.T, err error) string {
	t.Helper()
	var commandErr *domain.CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("error=%v is not a command error", err)
	}
	return commandErr.Message()
}

// TestAcquireLeaseReapsExpiredLeases covers the state transition an expired
// lease never had: nothing but an explicit release retired a row, so a crashed
// agent's reservation was scanned by every later acquisition and reported as
// held by every listing.
func TestAcquireLeaseReapsExpiredLeases(t *testing.T) {
	t.Parallel()
	fixture := newLeaseFixture(t, 600)
	stale, err := fixture.acquire(t, fixture.holder, coordination.LeaseExclusive, coordination.LeaseSelectorExact, "src/stale.go")
	if err != nil {
		t.Fatal(err)
	}
	fixture.expire(t, stale)

	// The reaper runs inside an acquisition that does not overlap the corpse,
	// so retiring it cannot be a side effect of resolving a conflict.
	if _, err := fixture.acquire(t, fixture.other, coordination.LeaseExclusive, coordination.LeaseSelectorExact, "src/other.go"); err != nil {
		t.Fatal(err)
	}
	status, released := fixture.status(t, stale)
	if status != "released" || !released.Valid {
		t.Fatalf("stale lease status=%q released=%v, want a released row", status, released)
	}

	// A reaped selector set is no longer an active claim.
	renew := coordination.ChangeLeaseParams{WorkspaceID: fixture.workspace, Holder: fixture.holder,
		HolderSession: fixture.session, AuthorityEpoch: fixture.epoch, Selectors: stale.Selectors(), TTL: time.Hour}
	if _, err := fixture.store.RenewLease(context.Background(), renew); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("renew of a reaped lease error=%v", err)
	}
	renew.TTL = 0
	if _, err := fixture.store.ReleaseLease(context.Background(), renew); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("release of a reaped lease error=%v", err)
	}

	// A live exact selector set can still be released normally.
	live, err := fixture.acquire(t, fixture.holder, coordination.LeaseExclusive, coordination.LeaseSelectorExact, "src/live.go")
	if err != nil {
		t.Fatal(err)
	}
	release := coordination.ChangeLeaseParams{WorkspaceID: fixture.workspace, Holder: fixture.holder,
		HolderSession: fixture.session, AuthorityEpoch: fixture.epoch, Selectors: live.Selectors()}
	if _, err := fixture.store.ReleaseLease(context.Background(), release); err != nil {
		t.Fatalf("release error=%v", err)
	}
}

// TestAcquireLeaseConflictCarriesRecoveryEvidence pins the difference between a
// failure an agent can act on and one it can only retry blindly: it must learn
// who holds the lease, which selector overlapped, and when it frees up.
func TestAcquireLeaseConflictCarriesRecoveryEvidence(t *testing.T) {
	t.Parallel()
	fixture := newLeaseFixture(t, 700)
	held, err := fixture.acquire(t, fixture.holder, coordination.LeaseExclusive, coordination.LeaseSelectorSubtree, "src/service")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.acquire(t, fixture.other, coordination.LeaseExclusive, coordination.LeaseSelectorExact, "src/service/main.go")
	if !errors.Is(err, domain.ErrLeaseConflict) {
		t.Fatalf("overlapping acquire error=%v", err)
	}
	message := commandMessage(t, err)
	for _, want := range []string{held.ID().String(), fixture.holder.String(), "src/service", "subtree", "free in"} {
		if !strings.Contains(message, want) {
			t.Fatalf("conflict message %q omits %q", message, want)
		}
	}
}

// TestAcquireLeaseRetryByItsOwnHolderExtendsInsteadOfConflicting is the
// regression for the commonest acquisition path there is. The overlap scan
// compared selectors and never the holder, so an agent retrying after a timeout
// or a lost response was refused by a reservation it already owned, with no
// recovery but waiting out its own TTL.
func TestAcquireLeaseRetryByItsOwnHolderExtendsInsteadOfConflicting(t *testing.T) {
	t.Parallel()
	fixture := newLeaseFixture(t, 900)
	first, err := fixture.acquire(t, fixture.holder, coordination.LeaseExclusive, coordination.LeaseSelectorExact, "src/main.go")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := fixture.acquire(t, fixture.holder, coordination.LeaseExclusive, coordination.LeaseSelectorExact, "src/main.go")
	if err != nil {
		t.Fatalf("the holder was refused by its own lease: %v", err)
	}
	if !retry.ExpiresAt().After(first.ExpiresAt()) {
		t.Fatalf("retry expires at %s, want a deadline past the original %s", retry.ExpiresAt(), first.ExpiresAt())
	}

	// The superseded lease is retired inside the same acquisition. Leaving it
	// active would reserve the same paths against everyone else for its whole
	// TTL after the agent released the lease it was actually handed.
	status, released := fixture.status(t, first)
	if status != "released" || !released.Valid || released.Int64 >= timeMicros(first.ExpiresAt()) {
		t.Fatalf("superseded lease status=%q released=%v, want an explicit release before its deadline", status, released)
	}
	if _, err := fixture.acquire(t, fixture.other, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "src/main.go"); !errors.Is(err, domain.ErrLeaseConflict) {
		t.Fatalf("another actor was not refused by the retry's lease: %v", err)
	}
}

// TestAcquireLeaseSupersedesOnlyExactSelectorSet pins the path-addressed retry
// rule: neither narrowing nor widening may silently drop a separate claim.
func TestAcquireLeaseSupersedesOnlyExactSelectorSet(t *testing.T) {
	t.Parallel()
	fixture := newLeaseFixture(t, 1000)
	wide, err := fixture.acquire(t, fixture.holder, coordination.LeaseExclusive, coordination.LeaseSelectorSubtree, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.acquire(t, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorExact, "docs/guide.md"); err != nil {
		t.Fatalf("narrowing re-claim was refused by the holder's own subtree lease: %v", err)
	}
	if status, _ := fixture.status(t, wide); status != "active" {
		t.Fatalf("subtree lease status=%q after a narrower re-claim, want it left alone", status)
	}

	// Widening also leaves the distinct exact claim active.
	narrow, err := fixture.acquire(t, fixture.holder, coordination.LeaseShared, coordination.LeaseSelectorExact, "pkg/a.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.acquire(t, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "pkg"); err != nil {
		t.Fatalf("exclusive re-claim over the holder's own shared lease: %v", err)
	}
	if status, _ := fixture.status(t, narrow); status != "active" {
		t.Fatalf("exact lease status=%q after the wider re-claim, want it left alone", status)
	}

	// A shared lease held by somebody else still refuses the same widening, so
	// the holder check narrows nothing but the holder's own reservations.
	if _, err := fixture.acquire(t, fixture.other, coordination.LeaseShared,
		coordination.LeaseSelectorExact, "web/app.ts"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.acquire(t, fixture.holder, coordination.LeaseExclusive,
		coordination.LeaseSelectorSubtree, "web"); !errors.Is(err, domain.ErrLeaseConflict) {
		t.Fatalf("another actor's shared lease did not refuse the exclusive claim: %v", err)
	}
}

// TestLocalAgentSnapshotReportsWhatRegistrationRebound covers the state a
// resuming agent cannot recover on its own. Registration moves the agent's
// live leases onto its new session; reporting only identifiers left a restarted
// agent holding an exclusive reservation it could neither renew nor release.
func TestLocalAgentSnapshotReportsWhatRegistrationRebound(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	const project = "/workspace/snapshot"
	alice, aliceToken, err := store.RegisterLocalAgent(context.Background(), project, "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := store.RegisterLocalAgent(context.Background(), project, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	leaseID, err := domain.NewLeaseID()
	if err != nil {
		t.Fatal(err)
	}
	selector, err := coordination.NewLeaseSelector(coordination.LeaseSelectorSubtree, "internal/storage")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireLease(context.Background(), coordination.AcquireLeaseParams{LeaseID: leaseID,
		WorkspaceID: alice.WorkspaceID, Holder: alice.ActorID, HolderSession: alice.ActorSessionID,
		AuthorityEpoch: alice.AuthorityEpoch, Mode: coordination.LeaseExclusive,
		Selectors: []coordination.LeaseSelector{selector}, TTL: 20 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	conversation, message := seedSnapshotMail(t, store, bob, alice)

	// The restart: the same agent name registers again with its token, which is
	// the moment the leases are rebound and the agent has forgotten them.
	resumed, issued, err := store.RegisterLocalAgent(context.Background(), project, "alice", aliceToken)
	if err != nil {
		t.Fatal(err)
	}
	if issued != "" || resumed.ActorSessionID == alice.ActorSessionID {
		t.Fatalf("resumed session=%v issued=%q, want a new session and no second token", resumed.ActorSessionID, issued)
	}
	snapshot, err := store.LocalAgentSnapshot(context.Background(), resumed)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Reservations) != 1 {
		t.Fatalf("reservations=%+v, want the lease registration just rebound", snapshot.Reservations)
	}
	held := snapshot.Reservations[0]
	if held.LeaseID != lease.ID() || held.Mode != coordination.LeaseExclusive ||
		len(held.Selectors) != 1 || held.Selectors[0].Path() != "internal/storage" {
		t.Fatalf("held reservation = %+v", held)
	}
	if held.ClaimGenerations[selector.Key()] == 0 {
		t.Fatalf("held claim generations = %+v, want informational handoff counter", held.ClaimGenerations)
	}
	if held.ExpiresInMS <= 0 || held.ExpiresInMS > (20*time.Minute).Milliseconds() {
		t.Fatalf("expires_in_ms = %d, want the remaining time on a twenty minute lease", held.ExpiresInMS)
	}
	if snapshot.Inbox.UnreadDeliveries != 1 || snapshot.Inbox.UnackedDeliveries != 1 ||
		len(snapshot.Inbox.Recent) != 1 || snapshot.Inbox.Recent[0].MessageID != message.ID() ||
		snapshot.Inbox.Recent[0].AuthorAgentName != "bob" {
		t.Fatalf("inbox = %+v", snapshot.Inbox)
	}
	if len(snapshot.Conversations) != 1 || snapshot.Conversations[0].ConversationID != conversation.ID() ||
		snapshot.Conversations[0].Messages != 1 {
		t.Fatalf("conversations = %+v", snapshot.Conversations)
	}
	if len(snapshot.Peers) != 1 || snapshot.Peers[0].Name != "bob" {
		t.Fatalf("peers = %+v, want the other agent present in this project", snapshot.Peers)
	}
	if snapshot.ObservedAtUS <= 0 {
		t.Fatal("snapshot carries no observation instant")
	}

	// A released lease leaves the snapshot, so the projection cannot keep
	// telling a resuming agent to clean up something it already cleaned up.
	if _, err := store.ReleaseLease(context.Background(), coordination.ChangeLeaseParams{WorkspaceID: resumed.WorkspaceID,
		Holder: resumed.ActorID, HolderSession: resumed.ActorSessionID, AuthorityEpoch: resumed.AuthorityEpoch,
		Selectors: held.Selectors}); err != nil {
		t.Fatalf("release with the selector set the snapshot handed back: %v", err)
	}
	after, err := store.LocalAgentSnapshot(context.Background(), resumed)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Reservations) != 0 {
		t.Fatalf("reservations after release = %+v", after.Reservations)
	}
}

// seedSnapshotMail sends one acknowledgement-required message from author to
// recipient, which is the shape a resuming agent most needs to be told about.
func seedSnapshotMail(t *testing.T, store *Store, author, recipient coordination.LocalAgentSession,
) (coordination.Conversation, coordination.Message) {
	t.Helper()
	conversationID, err := domain.NewConversationID()
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := store.OpenConversation(context.Background(), coordination.OpenConversationParams{
		ConversationID: conversationID, WorkspaceID: author.WorkspaceID, RunID: author.RunID,
		OpenedBy: author.ActorID, OpenedBySession: author.ActorSessionID, Topic: "handoff"})
	if err != nil {
		t.Fatal(err)
	}
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	to, err := coordination.NewRecipient(recipient.ActorID, coordination.RecipientTo)
	if err != nil {
		t.Fatal(err)
	}
	message, err := store.SendMessage(context.Background(), coordination.SendMessageParams{MessageID: messageID,
		ConversationID: conversationID, WorkspaceID: author.WorkspaceID, Author: author.ActorID,
		AuthorSession: author.ActorSessionID, Subject: "storage rewrite", Body: "please pick this up",
		Recipients: []coordination.Recipient{to}, AcknowledgementRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	return conversation, message
}

// TestEvidenceTextStaysInsideTheMessageBudget guards the interpolation itself:
// a selector path may be thousands of bytes, and an over-long message is
// rejected by the error constructor, which would leave a caller with no text.
func TestEvidenceTextStaysInsideTheMessageBudget(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "short values pass through", value: "src/service/main.go", want: "src/service/main.go"},
		{name: "long values are truncated", value: strings.Repeat("a", maxEvidenceTextBytes+10),
			want: strings.Repeat("a", maxEvidenceTextBytes) + "..."},
		{name: "a split rune is dropped", value: strings.Repeat("é", maxEvidenceTextBytes),
			want: strings.Repeat("é", maxEvidenceTextBytes/2) + "..."},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := evidenceText(testCase.value); got != testCase.want {
				t.Fatalf("evidenceText(%d bytes) = %q, want %q", len(testCase.value), got, testCase.want)
			}
		})
	}
}
