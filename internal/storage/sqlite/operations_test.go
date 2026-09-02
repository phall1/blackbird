package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

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
	conversation, err := store.OpenConversation(context.Background(), application.OpenConversationParams{
		ConversationID: conversationID, WorkspaceID: workspace, RunID: run, OpenedBy: author,
		OpenedBySession: session, Topic: "daily coordination",
	})
	if err != nil || conversation.ID() != conversationID {
		t.Fatalf("conversation=%v error=%v", conversation.ID(), err)
	}
	recipients := make([]application.Recipient, 0, 3)
	for _, value := range []struct {
		actor domain.ActorID
		kind  application.RecipientKind
	}{
		{to, application.RecipientTo}, {cc, application.RecipientCc}, {bcc, application.RecipientBcc},
	} {
		recipient, recipientErr := application.NewRecipient(value.actor, value.kind)
		if recipientErr != nil {
			t.Fatal(recipientErr)
		}
		recipients = append(recipients, recipient)
	}
	messageID, _ := domain.ParseMessageID(coordinationUUID(10))
	message, err := store.SendMessage(context.Background(), application.SendMessageParams{MessageID: messageID,
		ConversationID: conversationID, WorkspaceID: workspace, Author: author, AuthorSession: session,
		Subject: "handoff", Body: "durable body", Recipients: recipients, AcknowledgementRequired: true})
	if err != nil || len(message.Deliveries()) != 3 {
		t.Fatalf("deliveries=%d error=%v", len(message.Deliveries()), err)
	}

	assertVisibleKinds := func(viewer domain.ActorID, want ...application.RecipientKind) {
		t.Helper()
		page, queryErr := store.Thread(context.Background(), application.ThreadQuery{WorkspaceID: workspace,
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
	assertVisibleKinds(author, application.RecipientBcc, application.RecipientCc, application.RecipientTo)
	assertVisibleKinds(to, application.RecipientCc, application.RecipientTo)
	assertVisibleKinds(bcc, application.RecipientBcc, application.RecipientCc, application.RecipientTo)
	assertVisibleKinds(outsider)

	digest := message.Digest()
	ack, err := store.RecordDeliveryFact(context.Background(), application.RecordDeliveryFactParams{WorkspaceID: workspace,
		MessageID: messageID, Recipient: bcc, ActorSessionID: &session, Kind: application.DeliveryAcknowledged,
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
	read, err := store.RecordDeliveryFact(context.Background(), application.RecordDeliveryFactParams{WorkspaceID: workspace,
		MessageID: messageID, Recipient: bcc, ActorSessionID: &session, Kind: application.DeliveryRead})
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
	if _, err := store.RecordDeliveryFact(context.Background(), application.RecordDeliveryFactParams{WorkspaceID: workspace,
		MessageID: messageID, Recipient: outsider, ActorSessionID: &session, Kind: application.DeliveryRead}); !errors.Is(err, domain.ErrForbidden) {
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
	if _, err := store.OpenConversation(context.Background(), application.OpenConversationParams{ConversationID: conversationID,
		WorkspaceID: workspace, RunID: run, OpenedBy: author, OpenedBySession: session, Topic: "journal"}); err != nil {
		t.Fatal(err)
	}
	to, _ := application.NewRecipient(recipient, application.RecipientTo)
	for index := 0; index < 2; index++ {
		messageID, _ := domain.ParseMessageID(coordinationUUID(310 + index))
		if _, err := store.SendMessage(context.Background(), application.SendMessageParams{MessageID: messageID,
			ConversationID: conversationID, WorkspaceID: workspace, Author: author, AuthorSession: session,
			Subject: "event", Body: "body", Recipients: []application.Recipient{to}}); err != nil {
			t.Fatal(err)
		}
	}
	query, _ := application.NewCoordinationEventsQuery(workspace, recipient, application.CoordinationEventCursor{}, 1)
	first, err := store.SyncCoordinationEvents(context.Background(), query)
	if err != nil || len(first.Events()) != 1 || !first.HasMore() || first.NextCursor().IsZero() ||
		first.Events()[0].EventType() != application.CoordinationEventMessageAvailable || first.Events()[0].ActorID() != recipient {
		t.Fatalf("first coordination page=%+v error=%v", first, err)
	}
	continued, _ := application.NewCoordinationEventsQuery(workspace, recipient, first.NextCursor(), 1)
	second, err := store.SyncCoordinationEvents(context.Background(), continued)
	if err != nil || len(second.Events()) != 1 || second.HasMore() || second.Events()[0].Position() <= first.Events()[0].Position() {
		t.Fatalf("second coordination page=%+v error=%v", second, err)
	}
	otherQuery, _ := application.NewCoordinationEventsQuery(workspace, other, application.CoordinationEventCursor{}, 10)
	private, err := store.SyncCoordinationEvents(context.Background(), otherQuery)
	if err != nil || len(private.Events()) != 0 {
		t.Fatalf("other actor events=%d error=%v", len(private.Events()), err)
	}
	scopeMismatch, _ := application.NewCoordinationEventsQuery(workspace, other, first.NextCursor(), 1)
	if _, err := store.SyncCoordinationEvents(context.Background(), scopeMismatch); err == nil {
		t.Fatal("actor-scoped cursor was accepted for another actor")
	}
	tampered, _ := application.NewCoordinationEventCursor(first.NextCursor().String() + "x")
	tamperedQuery, _ := application.NewCoordinationEventsQuery(workspace, recipient, tampered, 1)
	if _, err := store.SyncCoordinationEvents(context.Background(), tamperedQuery); err == nil {
		t.Fatal("tampered coordination cursor was accepted")
	}
	if _, err := store.db.Exec(`UPDATE coordination_events SET event_type = 'message.read'`); err == nil {
		t.Fatal("coordination event update was accepted")
	}
	if _, err := store.db.Exec(`DELETE FROM coordination_events`); err == nil {
		t.Fatal("coordination event delete was accepted")
	}
}

func TestCoordinationLeaseConcurrencyConflictAndFencing(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	workspace := coordinationWorkspace(t, 20)
	holder := coordinationActor(t, 21)
	session, _ := domain.ParseActorSessionID(coordinationUUID(22))
	epoch, _ := domain.ParseAuthorityEpoch(coordinationUUID(23))
	selector, _ := application.NewLeaseSelector(application.LeaseSelectorSubtree, "src/service")
	if _, err := store.db.Exec(`INSERT INTO scope_guards(scope_kind, scope_id, authority_id, authority_epoch,
		write_status, guard_generation, updated_at_us) VALUES ('workspace', ?, ?, ?, 'open', 1, 1)`,
		workspace.String(), coordinationUUID(24), epoch.String()); err != nil {
		t.Fatal(err)
	}

	const contenders = 24
	start := make(chan struct{})
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := range contenders {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			leaseID, _ := domain.ParseLeaseID(coordinationUUID(100 + index))
			_, err := store.AcquireLease(context.Background(), application.AcquireLeaseParams{LeaseID: leaseID,
				WorkspaceID: workspace, Holder: holder, HolderSession: session, AuthorityEpoch: epoch,
				Mode: application.LeaseExclusive, Selectors: []application.LeaseSelector{selector}, TTL: time.Hour})
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
	if err := store.ValidateFence(context.Background(), winner.ID(), epoch, winner.Fences()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE leases SET expires_at_us = acquired_at_us + 1 WHERE lease_id = ?`, winner.ID().String()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	replacementID, _ := domain.ParseLeaseID(coordinationUUID(200))
	replacement, err := store.AcquireLease(context.Background(), application.AcquireLeaseParams{LeaseID: replacementID,
		WorkspaceID: workspace, Holder: holder, HolderSession: session, AuthorityEpoch: epoch,
		Mode: application.LeaseExclusive, Selectors: []application.LeaseSelector{selector}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateFence(context.Background(), winner.ID(), epoch, winner.Fences()); !errors.Is(err, domain.ErrFenceRejected) {
		t.Fatalf("stale fence error=%v", err)
	}
	if err := store.ValidateFence(context.Background(), replacement.ID(), epoch, replacement.Fences()); err != nil {
		t.Fatal(err)
	}
	if replacement.Fences()[0].Counter() <= winner.Fences()[0].Counter() {
		t.Fatal("replacement fence did not advance")
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

func TestFullIntegrityCheckReportsAdministrativeOperation(t *testing.T) {
	t.Parallel()
	store := newOperationStore(t)
	if _, err := store.FullIntegrityCheck(context.Background()); err == nil {
		t.Fatal("unbounded full integrity check was accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	report, err := store.FullIntegrityCheck(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Full || report.Duration <= 0 {
		t.Fatalf("integrity report=%+v", report)
	}
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

func TestQualifyFilesystemReportsOwnershipPermissionsSpaceAndLocks(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "authority")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "blackbird.db")
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newOperationStoreAt(t, path)

	report, err := QualifyFilesystem(path, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	_ = store
	if !report.DatabaseDirectory.Exists || !report.DatabaseDirectory.Directory ||
		!report.Database.Exists || !report.Database.LockVerified || !report.Artifacts.Exists ||
		!report.Artifacts.Directory || !report.SameOwner || !report.Local ||
		report.Database.OwnerUID != uint32(os.Geteuid()) || report.Database.FreeBytes == 0 ||
		report.QualifiedAt.IsZero() {
		t.Fatalf("qualification=%+v", report)
	}
	if report.WAL.Path != path+"-wal" || report.SharedMemory.Path != path+"-shm" {
		t.Fatalf("sidecar paths: wal=%q shm=%q", report.WAL.Path, report.SharedMemory.Path)
	}
	if report.WAL.Exists && report.WAL.Directory || report.SharedMemory.Exists && report.SharedMemory.Directory {
		t.Fatalf("sidecar file types: wal=%+v shm=%+v", report.WAL, report.SharedMemory)
	}
}

func newOperationStore(t *testing.T) *Store {
	t.Helper()
	return newOperationStoreAt(t, filepath.Join(t.TempDir(), "blackbird.db"))
}

func newOperationStoreAt(t *testing.T, path string) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", databaseURL(Config{Path: path, BusyTimeout: defaultBusyTimeout}))
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
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	store := &Store{db: db, path: path}
	store.writes.changed = make(chan struct{})
	return store
}

func TestQualifyFilesystemRejectsUnsafePathsAndPermissions(t *testing.T) {
	t.Parallel()
	if _, err := QualifyFilesystem("relative.db", t.TempDir()); !errors.Is(err, ErrFilesystemQualification) {
		t.Fatalf("relative path error=%v", err)
	}

	root := t.TempDir()
	path := filepath.Join(root, "blackbird.db")
	artifacts := filepath.Join(root, "artifacts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := QualifyFilesystem(path, artifacts); !errors.Is(err, ErrFilesystemQualification) {
		t.Fatalf("unsafe permissions error=%v", err)
	}

	link := filepath.Join(root, "linked.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := QualifyFilesystem(link, artifacts); !errors.Is(err, ErrFilesystemQualification) {
		t.Fatalf("symlink error=%v", err)
	}
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
	if _, err := fixture.store.OpenConversation(context.Background(), application.OpenConversationParams{
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

func (fixture *mailFixture) send(t *testing.T) application.Message {
	t.Helper()
	messageID, err := domain.ParseMessageID(coordinationUUID(fixture.base + 100 + fixture.sent))
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := application.NewRecipient(fixture.recipient, application.RecipientTo)
	if err != nil {
		t.Fatal(err)
	}
	message, err := fixture.store.SendMessage(context.Background(), application.SendMessageParams{
		MessageID: messageID, ConversationID: fixture.conversation, WorkspaceID: fixture.workspace,
		Author: fixture.author, AuthorSession: fixture.session, Subject: "position",
		Body: fmt.Sprintf("message %d", fixture.sent), Recipients: []application.Recipient{recipient},
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
			page, err := fixture.store.Inbox(context.Background(), application.InboxQuery{WorkspaceID: fixture.workspace,
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
		page, err := fixture.store.Inbox(context.Background(), application.InboxQuery{WorkspaceID: fixture.workspace,
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
	if _, err := fixture.store.OpenConversation(context.Background(), application.OpenConversationParams{
		ConversationID: other, WorkspaceID: fixture.workspace, RunID: run, OpenedBy: fixture.author,
		OpenedBySession: fixture.session, Topic: "another thread",
	}); err != nil {
		t.Fatal(err)
	}
	fixture.conversation = other
	head := fixture.send(t).Position()

	page, err := fixture.store.Thread(context.Background(), application.ThreadQuery{WorkspaceID: fixture.workspace,
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

func (fixture *leaseFixture) acquire(t *testing.T, holder domain.ActorID, mode application.LeaseMode,
	kind application.LeaseSelectorKind, path string) (application.Lease, error) {
	t.Helper()
	leaseID, err := domain.ParseLeaseID(coordinationUUID(fixture.base + 100 + fixture.acquired))
	if err != nil {
		t.Fatal(err)
	}
	fixture.acquired++
	selector, err := application.NewLeaseSelector(kind, path)
	if err != nil {
		t.Fatal(err)
	}
	return fixture.store.AcquireLease(context.Background(), application.AcquireLeaseParams{LeaseID: leaseID,
		WorkspaceID: fixture.workspace, Holder: holder, HolderSession: fixture.session, AuthorityEpoch: fixture.epoch,
		Mode: mode, Selectors: []application.LeaseSelector{selector}, TTL: time.Hour})
}

func (fixture *leaseFixture) expire(t *testing.T, lease application.Lease) {
	t.Helper()
	if _, err := fixture.store.db.Exec(`UPDATE leases SET expires_at_us = acquired_at_us + 1 WHERE lease_id = ?`,
		lease.ID().String()); err != nil {
		t.Fatal(err)
	}
}

func (fixture *leaseFixture) status(t *testing.T, lease application.Lease) (string, sql.NullInt64) {
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
	stale, err := fixture.acquire(t, fixture.holder, application.LeaseExclusive, application.LeaseSelectorExact, "src/stale.go")
	if err != nil {
		t.Fatal(err)
	}
	fixture.expire(t, stale)

	// The reaper runs inside an acquisition that does not overlap the corpse,
	// so retiring it cannot be a side effect of resolving a conflict.
	if _, err := fixture.acquire(t, fixture.other, application.LeaseExclusive, application.LeaseSelectorExact, "src/other.go"); err != nil {
		t.Fatal(err)
	}
	status, released := fixture.status(t, stale)
	if status != "released" || !released.Valid {
		t.Fatalf("stale lease status=%q released=%v, want a released row", status, released)
	}

	// A reaped lease is terminal, not idempotently released: its holder must
	// still be told the deadline passed rather than that its release succeeded.
	renew := application.ChangeLeaseParams{LeaseID: stale.ID(), HolderSession: fixture.session,
		AuthorityEpoch: fixture.epoch, Fences: stale.Fences(), TTL: time.Hour}
	if _, err := fixture.store.RenewLease(context.Background(), renew); !errors.Is(err, domain.ErrLeaseExpired) {
		t.Fatalf("renew of a reaped lease error=%v", err)
	}
	renew.TTL = 0
	if _, err := fixture.store.ReleaseLease(context.Background(), renew); !errors.Is(err, domain.ErrLeaseExpired) {
		t.Fatalf("release of a reaped lease error=%v", err)
	}

	// An explicit release stays idempotent, which is what the reaper must not
	// break: it is distinguished by having been stamped before the deadline.
	live, err := fixture.acquire(t, fixture.holder, application.LeaseExclusive, application.LeaseSelectorExact, "src/live.go")
	if err != nil {
		t.Fatal(err)
	}
	release := application.ChangeLeaseParams{LeaseID: live.ID(), HolderSession: fixture.session,
		AuthorityEpoch: fixture.epoch, Fences: live.Fences()}
	for attempt := range 2 {
		if _, err := fixture.store.ReleaseLease(context.Background(), release); err != nil {
			t.Fatalf("release attempt %d error=%v", attempt, err)
		}
	}
}

// TestAcquireLeaseConflictCarriesRecoveryEvidence pins the difference between a
// failure an agent can act on and one it can only retry blindly: it must learn
// who holds the lease, which selector overlapped, and when it frees up.
func TestAcquireLeaseConflictCarriesRecoveryEvidence(t *testing.T) {
	t.Parallel()
	fixture := newLeaseFixture(t, 700)
	held, err := fixture.acquire(t, fixture.holder, application.LeaseExclusive, application.LeaseSelectorSubtree, "src/service")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.acquire(t, fixture.other, application.LeaseExclusive, application.LeaseSelectorExact, "src/service/main.go")
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

// TestValidateFenceSeparatesFailureFromSupersession is the regression that
// matters most: a fence rejection tells an agent to abandon its reservation, so
// a busy database or a cancelled call must never be reported as one.
func TestValidateFenceSeparatesFailureFromSupersession(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name        string
		mutate      func(*testing.T, *leaseFixture, application.Lease)
		supply      func(application.Lease) []application.Fence
		cancel      bool
		wantRejects bool
		wantText    []string
	}{
		{name: "a current fence validates", wantRejects: false},
		{name: "a superseded counter is rejected", wantRejects: true,
			wantText: []string{"superseded", "stands at"},
			mutate: func(t *testing.T, fixture *leaseFixture, lease application.Lease) {
				t.Helper()
				if _, err := fixture.store.db.Exec(`UPDATE lease_fence_counters SET counter = counter + 1
					WHERE workspace_id = ? AND authority_epoch = ?`, fixture.workspace.String(), fixture.epoch.String()); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a missing counter row is rejected", wantRejects: true,
			wantText: []string{"superseded", "no longer has a counter"},
			mutate: func(t *testing.T, fixture *leaseFixture, lease application.Lease) {
				t.Helper()
				if _, err := fixture.store.db.Exec(`DELETE FROM lease_fence_counters WHERE workspace_id = ?
					AND authority_epoch = ?`, fixture.workspace.String(), fixture.epoch.String()); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a fence the caller never held is rejected", wantRejects: true,
			wantText: []string{"stale", "exact:src/elsewhere.go"},
			supply: func(lease application.Lease) []application.Fence {
				fence, _ := application.NewFence("exact:src/elsewhere.go", 1)
				return []application.Fence{fence}
			}},
		{name: "a cancelled call is not a fence rejection", cancel: true, wantRejects: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			fixture := newLeaseFixture(t, 800)
			lease, err := fixture.acquire(t, fixture.holder, application.LeaseExclusive, application.LeaseSelectorExact, "src/fenced.go")
			if err != nil {
				t.Fatal(err)
			}
			if testCase.mutate != nil {
				testCase.mutate(t, fixture, lease)
			}
			fences := lease.Fences()
			if testCase.supply != nil {
				fences = testCase.supply(lease)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if testCase.cancel {
				cancel()
			}
			defer cancel()
			err = fixture.store.ValidateFence(ctx, lease.ID(), fixture.epoch, fences)
			if errors.Is(err, domain.ErrFenceRejected) != testCase.wantRejects {
				t.Fatalf("validation error=%v, want rejection=%v", err, testCase.wantRejects)
			}
			if testCase.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled validation error=%v, want a cancellation", err)
			}
			if !testCase.wantRejects {
				return
			}
			message := commandMessage(t, err)
			for _, want := range testCase.wantText {
				if !strings.Contains(message, want) {
					t.Fatalf("rejection message %q omits %q", message, want)
				}
			}
		})
	}
}

// TestCompareFencesReportsFirstDivergence covers the accessor that turns a bare
// mismatch into something an agent can name: which key moved, and both counters.
func TestCompareFencesReportsFirstDivergence(t *testing.T) {
	t.Parallel()
	fence := func(t *testing.T, key string, counter uint64) application.Fence {
		t.Helper()
		value, err := application.NewFence(key, counter)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, testCase := range []struct {
		name      string
		held      []string
		supplied  []string
		wantEqual bool
		wantKey   string
		wantHeld  uint64
		wantGiven uint64
	}{
		{name: "identical sets match", held: []string{"exact:a", "exact:b"}, supplied: []string{"exact:a", "exact:b"},
			wantEqual: true},
		{name: "order does not matter", held: []string{"exact:b", "exact:a"}, supplied: []string{"exact:a", "exact:b"},
			wantEqual: true},
		{name: "a moved counter names its key", held: []string{"exact:a", "exact:b"}, supplied: []string{"exact:a", "exact:b"},
			wantKey: "exact:b", wantHeld: 2, wantGiven: 9},
		{name: "a fence the caller omitted", held: []string{"exact:a", "exact:b"}, supplied: []string{"exact:a"},
			wantKey: "exact:b", wantHeld: 2},
		{name: "a fence the caller never held", held: []string{"exact:a"}, supplied: []string{"exact:a", "exact:z"},
			wantKey: "exact:z", wantGiven: 26},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			// The counter follows the key rather than the position, so a case
			// can reorder a set without also changing what it holds.
			counterFor := func(key string) uint64 { return uint64(key[len(key)-1]-'a') + 1 }
			held := make([]application.Fence, 0, len(testCase.held))
			for _, key := range testCase.held {
				held = append(held, fence(t, key, counterFor(key)))
			}
			supplied := make([]application.Fence, 0, len(testCase.supplied))
			for _, key := range testCase.supplied {
				counter := counterFor(key)
				if key == testCase.wantKey && testCase.wantGiven != 0 {
					counter = testCase.wantGiven
				}
				supplied = append(supplied, fence(t, key, counter))
			}
			divergence, equal := compareFences(held, supplied)
			if equal != testCase.wantEqual {
				t.Fatalf("equal=%v, want %v", equal, testCase.wantEqual)
			}
			if testCase.wantEqual {
				return
			}
			if divergence.conflictKey != testCase.wantKey || divergence.held != testCase.wantHeld ||
				divergence.supplied != testCase.wantGiven {
				t.Fatalf("divergence=%+v, want key=%q held=%d supplied=%d", divergence, testCase.wantKey,
					testCase.wantHeld, testCase.wantGiven)
			}
		})
	}
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
