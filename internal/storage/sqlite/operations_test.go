package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if _, ok := read.AvailableAt(); ok {
		t.Fatal("read implied availability")
	}
	if _, err := store.RecordDeliveryFact(context.Background(), application.RecordDeliveryFactParams{WorkspaceID: workspace,
		MessageID: messageID, Recipient: outsider, ActorSessionID: &session, Kind: application.DeliveryRead}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("outsider read error=%v", err)
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
