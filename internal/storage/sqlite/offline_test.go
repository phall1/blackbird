package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenReaderRefusesToCreateOrMigrate(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "absent.db")

	if _, err := OpenReader(context.Background(), ReaderConfig{Path: path}); !errors.Is(err, ErrReaderUnavailable) {
		t.Fatalf("absent database error=%v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the reader created %s", path)
	}
}

func TestOpenReaderRejectsUnsafePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	regular := filepath.Join(root, "blackbird.db")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked.db")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "directory.db")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name string
		path string
	}{
		{name: "relative", path: "blackbird.db"},
		{name: "unclean", path: root + "/./blackbird.db"},
		{name: "extensionless", path: filepath.Join(root, "blackbird")},
		{name: "symlink", path: link},
		{name: "directory", path: directory},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := OpenReader(context.Background(),
				ReaderConfig{Path: testCase.path}); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestOpenReaderCannotWrite(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	reader := openTestReader(t, store.path, false)

	for _, testCase := range []struct {
		name      string
		statement string
	}{
		{name: "insert", statement: `INSERT INTO coordination_projects(project_key, workspace_id, run_id,
			authority_id, authority_epoch, created_at_us) VALUES ('x', 'w', 'r', 'a', 'e', 1)`},
		{name: "update", statement: "UPDATE database_runtime SET clean_shutdown = 1 WHERE singleton = 1"},
		{name: "delete", statement: "DELETE FROM database_runtime WHERE singleton = 1"},
		{name: "create table", statement: "CREATE TABLE reader_probe (value INTEGER)"},
		{name: "user version", statement: "PRAGMA user_version = 99"},
		{name: "journal mode", statement: "PRAGMA journal_mode = delete"},
		{name: "vacuum", statement: "VACUUM"},
		{name: "checkpoint", statement: "PRAGMA wal_checkpoint(TRUNCATE)"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := reader.db.ExecContext(context.Background(), testCase.statement); err == nil {
				t.Fatalf("the read-only reader executed %q", testCase.statement)
			}
		})
	}
}

func TestOpenReaderLeavesRuntimeRowUntouched(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	before := readRuntimeRow(t, store)

	reader := openTestReader(t, store.path, false)
	state, err := reader.Runtime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Present || state.CleanShutdown || state.OpenedAt.IsZero() {
		t.Fatalf("runtime state=%+v", state)
	}
	if _, err := reader.Schema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Coordination(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after := readRuntimeRow(t, store); after != before {
		t.Fatalf("the reader rewrote database_runtime: %+v -> %+v", before, after)
	}
}

func TestOpenReaderSeesUncheckpointedWAL(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	if _, err := store.db.ExecContext(context.Background(), "PRAGMA wal_autocheckpoint = 0"); err != nil {
		t.Fatal(err)
	}
	registerAdminAgent(t, store, adminProjectA, "alice")
	registerAdminAgent(t, store, adminProjectA, "bob")

	reader := openTestReader(t, store.path, false)
	if reader.Mode() != ReadModeLive || reader.Path() != store.path {
		t.Fatalf("mode=%q path=%q", reader.Mode(), reader.Path())
	}
	state, err := reader.Coordination(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Agents != 2 || state.Projects != 1 {
		t.Fatalf("the live reader missed uncheckpointed WAL content: %+v", state)
	}
	storage, err := reader.Storage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if storage.WALBytes <= 0 || storage.PageSize <= 0 {
		t.Fatalf("storage=%+v", storage)
	}
	if storage.WALFrames != (storage.WALBytes-walHeaderBytes)/(storage.PageSize+walFrameHeaderBytes) {
		t.Fatalf("derived WAL frames=%d bytes=%d page size=%d", storage.WALFrames, storage.WALBytes, storage.PageSize)
	}
	if storage.JournalMode != "wal" || storage.DatabaseMode.Perm() != 0o600 || storage.FreeBytes == 0 {
		t.Fatalf("storage facts=%+v", storage)
	}
}

// immutable=1 is the fallback of last resort precisely because it bypasses the
// write-ahead log: the same query answers with fewer rows than the live handle.
func TestOpenReaderStaleFallbackBypassesWAL(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	if _, err := store.db.ExecContext(context.Background(), "PRAGMA wal_autocheckpoint = 0"); err != nil {
		t.Fatal(err)
	}
	registerAdminAgent(t, store, adminProjectA, "alice")
	registerAdminAgent(t, store, adminProjectA, "bob")

	reader, err := openReaderMode(context.Background(), store.path, ReadModeStale)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	if reader.Mode() != ReadModeStale {
		t.Fatalf("mode=%q", reader.Mode())
	}
	state, err := reader.Coordination(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Agents != 0 {
		t.Fatalf("a stale read reported WAL-resident agents: %+v", state)
	}
}

func TestOpenReaderDegradesOnSchemaMismatch(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	registerAdminAgent(t, store, adminProjectA, "alice")
	path := copyDatabaseForReader(t, store)
	writable, err := sql.Open("sqlite", databaseURL(Config{Path: path}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writable.ExecContext(context.Background(), "PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}

	reader := openTestReader(t, path, false)
	schema, err := reader.Schema(context.Background())
	if err != nil {
		t.Fatalf("a schema mismatch must degrade, not error: %v", err)
	}
	if schema.Supported || schema.SchemaVersion != 99 || schema.ExpectedVersion != SchemaVersion ||
		schema.ApplicationID != ApplicationID || schema.ExpectedAppID != ApplicationID {
		t.Fatalf("schema=%+v", schema)
	}
	if !schema.ManifestMatches || !schema.LedgerComplete || len(schema.Migrations) != len(migrationIDs) {
		t.Fatalf("ledger facts=%+v", schema)
	}
	if _, err := reader.Runtime(context.Background()); err != nil {
		t.Fatalf("runtime on a mismatched schema: %v", err)
	}
	if _, err := reader.Storage(context.Background()); err != nil {
		t.Fatalf("storage on a mismatched schema: %v", err)
	}
	integrity, err := reader.Integrity(context.Background())
	if err != nil {
		t.Fatalf("integrity on a mismatched schema: %v", err)
	}
	if integrity.QuickCheck != "ok" || len(integrity.ForeignKeyFailures) != 0 {
		t.Fatalf("integrity=%+v", integrity)
	}
}

func TestReaderSchemaOnHealthyDatabase(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	reader := openTestReader(t, store.path, false)

	schema, err := reader.Schema(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !schema.Supported || schema.SchemaVersion != SchemaVersion || schema.ApplicationID != ApplicationID {
		t.Fatalf("schema=%+v", schema)
	}
	if schema.LiveChecksum != schema.ExpectedChecksum || !schema.ManifestMatches || !schema.LedgerComplete {
		t.Fatalf("schema checksums=%+v", schema)
	}
	if schema.ObjectCount == 0 || len(schema.ManifestVersions) == 0 {
		t.Fatalf("schema inventory=%+v", schema)
	}
	for _, row := range schema.Migrations {
		if !row.Matches || row.State != "applied" || row.AppliedAt.IsZero() {
			t.Fatalf("migration row=%+v", row)
		}
	}
}

func TestReaderIntegrityReportsForeignKeyFailures(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	path := copyDatabaseForReader(t, store)
	writable, err := sql.Open("sqlite", databaseURL(Config{Path: path}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writable.ExecContext(context.Background(), "PRAGMA foreign_keys = off"); err != nil {
		t.Fatal(err)
	}
	if _, err := writable.ExecContext(context.Background(), `INSERT INTO message_deliveries(message_id,
		recipient_actor_id, recipient_kind, acknowledgement_required) VALUES (?, ?, 'to', 0)`,
		"01b8e094-9888-7000-8000-0000000000ff", alice.ActorID.String()); err != nil {
		t.Fatal(err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}

	reader := openTestReader(t, path, false)
	integrity, err := reader.Integrity(context.Background())
	if err != nil {
		t.Fatalf("a foreign-key failure must be reported, not returned as an error: %v", err)
	}
	if len(integrity.ForeignKeyFailures) != 1 || integrity.Truncated {
		t.Fatalf("integrity=%+v", integrity)
	}
	if integrity.ForeignKeyFailures[0].Table != "message_deliveries" ||
		integrity.ForeignKeyFailures[0].Parent != "messages" {
		t.Fatalf("failure=%+v", integrity.ForeignKeyFailures[0])
	}
}

func TestReaderCoordinationCountsAndRows(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	registerAdminAgent(t, store, adminProjectB, "carol")
	conversation := openAdminConversation(t, store, alice, "release")
	sendAdminMessage(t, store, alice, conversation, "first", true, bob.ActorID)
	acquireAdminLease(t, store, alice, "docs/live.md")
	stale := acquireAdminLease(t, store, bob, "docs/stale.md")
	expireAdminLease(t, store, stale.ID())
	ageAdminSession(t, store, bob, 48*time.Hour)

	reader := openTestReader(t, store.path, false)
	state, err := reader.Coordination(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Projects != 2 || state.Agents != 3 || state.AgentsInLargestProject != 2 ||
		state.LargestProjectKey != adminProjectA {
		t.Fatalf("registry=%+v", state)
	}
	if state.Conversations != 1 || state.Messages != 1 || state.Events == 0 {
		t.Fatalf("mail=%+v", state)
	}
	if state.Leases != 2 || state.ActiveLeases != 1 || state.ExpiredActiveLeases != 1 {
		t.Fatalf("leases=%+v", state)
	}
	if state.Deliveries != 1 || state.UnreadDeliveries != 1 || state.UnacknowledgedDeliveries != 1 {
		t.Fatalf("deliveries=%+v", state)
	}
	if state.OpenSessions != 3 || state.StaleOpenSessions != 1 {
		t.Fatalf("sessions=%+v", state)
	}
}

func TestOpenReaderDoesNotBlockCheckpoint(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	registerAdminAgent(t, store, adminProjectA, "alice")
	reader := openTestReader(t, store.path, false)

	for _, collect := range []func() error{
		func() error { _, err := reader.Schema(context.Background()); return err },
		func() error { _, err := reader.Runtime(context.Background()); return err },
		func() error { _, err := reader.Storage(context.Background()); return err },
		func() error { _, err := reader.Integrity(context.Background()); return err },
		func() error { _, err := reader.Coordination(context.Background()); return err },
	} {
		if err := collect(); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := store.Checkpoint(ctx, CheckpointTruncate)
	if err != nil {
		t.Fatal(err)
	}
	if report.Busy || report.RemainingFrames != 0 {
		t.Fatalf("the open reader pinned the write-ahead log: %+v", report)
	}
}

func TestReaderCoordinationDegradesWithoutCoordinationTables(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bare.db")
	bare, err := sql.Open("sqlite", databaseURL(Config{Path: path}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.ExecContext(context.Background(), "CREATE TABLE unrelated (value INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err := bare.Close(); err != nil {
		t.Fatal(err)
	}

	reader := openTestReader(t, path, false)
	schema, err := reader.Schema(context.Background())
	if err != nil || schema.Supported || schema.LedgerComplete {
		t.Fatalf("schema=%+v error=%v", schema, err)
	}
	runtime, err := reader.Runtime(context.Background())
	if err != nil || runtime.Present {
		t.Fatalf("runtime=%+v error=%v", runtime, err)
	}
	state, err := reader.Coordination(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state != (CoordinationState{}) {
		t.Fatalf("coordination=%+v", state)
	}
}

func openTestReader(t *testing.T, path string, allowStale bool) *Reader {
	t.Helper()
	reader, err := OpenReader(context.Background(), ReaderConfig{Path: path, AllowStale: allowStale})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	return reader
}

type runtimeRow struct {
	clean  int
	opened int64
	closed sql.NullInt64
}

func readRuntimeRow(t *testing.T, store *Store) runtimeRow {
	t.Helper()
	var row runtimeRow
	if err := store.db.QueryRowContext(context.Background(),
		"SELECT clean_shutdown, opened_at_us, closed_at_us FROM database_runtime WHERE singleton = 1",
	).Scan(&row.clean, &row.opened, &row.closed); err != nil {
		t.Fatal(err)
	}
	return row
}

func copyDatabaseForReader(t *testing.T, store *Store) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := store.Checkpoint(ctx, CheckpointTruncate); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "copy.db")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
