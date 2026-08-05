package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenMigratesOnlyEmptyDatabaseAndReportsPinnedRuntime(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := store.Diagnostics()
	if diagnostics.DriverVersion != DriverVersion || diagnostics.SQLiteVersion != SQLiteVersion ||
		diagnostics.SQLiteSourceID != SQLiteSourceID || diagnostics.ApplicationID != ApplicationID ||
		diagnostics.SchemaVersion != SchemaVersion || diagnostics.JournalMode != "wal" ||
		!diagnostics.ForeignKeys || diagnostics.Synchronous != "2" || diagnostics.TrustedSchema ||
		diagnostics.ExtensionLoading || diagnostics.BusyTimeout != defaultBusyTimeout ||
		!diagnostics.FullFSync || !diagnostics.CheckpointFSync ||
		diagnostics.SchemaChecksum == ([sha256.Size]byte{}) {
		t.Fatalf("diagnostics=%+v", diagnostics)
	}
	diagnostics.CompileOptions[0] = "mutated"
	if store.Diagnostics().CompileOptions[0] == "mutated" {
		t.Fatal("diagnostics compile options alias internal state")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	var tables int
	if err := reopened.db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
	).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 24 {
		t.Fatalf("tables=%d, want 24", tables)
	}
	if err := reopened.IntegrityCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRunsIntegrityGateAfterUncleanExit(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if store.Diagnostics().UncleanCheckRan {
		t.Fatal("fresh database reported an unclean recovery check")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	execRaw(t, path, "UPDATE database_runtime SET clean_shutdown = 0 WHERE singleton = 1")
	reopened, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	if !reopened.Diagnostics().UncleanCheckRan {
		t.Fatal("unclean database did not report its startup integrity gate")
	}
}

func TestOpenRejectsSecondOwnerAndLiveSchemaDrift(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("second owner error=%v", err)
	}
	if _, err := store.db.Exec("DROP INDEX outbox_jobs_ready_idx"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("schema drift error=%v", err)
	}
}

func TestOpenRejectsIdentityChecksumAndConfigurationDrift(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"application id", func(t *testing.T, path string) { execRaw(t, path, "PRAGMA application_id = 1") }},
		{"schema version", func(t *testing.T, path string) { execRaw(t, path, "PRAGMA user_version = 2") }},
		{"migration checksum", func(t *testing.T, path string) {
			execRaw(t, path, "DROP TRIGGER schema_migrations_no_update")
			execRaw(t, path, "UPDATE schema_migrations SET checksum = zeroblob(32)")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "blackbird.db")
			store, err := Open(context.Background(), Config{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, path)
			if _, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrSchemaMismatch) {
				t.Fatalf("error=%v, want schema mismatch", err)
			}
		})
	}
	for _, config := range []Config{
		{}, {Path: "relative.db"}, {Path: filepath.Join(t.TempDir(), "database")},
		{Path: filepath.Join(t.TempDir(), "database.db"), BusyTimeout: maximumBusyTimeout + time.Millisecond},
		{Path: filepath.Join(t.TempDir(), "database.db"), BusyTimeout: time.Microsecond},
	} {
		if _, err := Open(context.Background(), config); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("config=%+v error=%v", config, err)
		}
	}
}

func TestDurabilityHistoryIsAppendOnly(t *testing.T) {
	t.Parallel()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		"UPDATE schema_migrations SET state = 'resumable'",
		"DELETE FROM schema_migrations",
	} {
		if _, err := store.db.ExecContext(context.Background(), statement); err == nil {
			t.Fatalf("immutable history accepted %q", statement)
		}
	}
}

func TestSchemaEnforcesReceiptEventAndAuthorityScopeIdentities(t *testing.T) {
	t.Parallel()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	installationA := "01b8e094-9888-7000-8000-000000000001"
	installationB := "01b8e094-9888-7000-8000-000000000002"
	principalA := "01b8e094-9888-7000-8000-000000000003"
	principalB := "01b8e094-9888-7000-8000-000000000004"
	for _, values := range [][2]string{{installationA, principalA}, {installationB, principalB}} {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO principals(
            principal_id, installation_id, kind, display_name, status, version, created_at_us, updated_at_us
        ) VALUES (?, ?, 'human', 'Owner', 'active', 1, 1, 1)`, values[1], values[0]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO device_registrations(
        device_id, installation_id, principal_id, display_name, credential_algorithm, public_key_reference,
        spki_fingerprint, transcript_fingerprint, trust_revision, status, version, created_at_us, updated_at_us
    ) VALUES (?, ?, ?, 'Wrong scope', 'ed25519', 'keyref:test', zeroblob(32), zeroblob(32), 1, 'active', 1, 1, 1)`,
		"01b8e094-9888-7000-8000-000000000005", installationA, principalB); err == nil {
		t.Fatal("cross-installation device principal accepted")
	}

	workspace := "01b8e094-9888-7000-8000-000000000006"
	epoch := "01b8e094-9888-7000-8000-000000000007"
	insertReceipt := func(receiptID, commandID, principal string) error {
		_, err := store.db.ExecContext(ctx, `INSERT INTO command_receipts(
            receipt_id, command_id, scope_kind, scope_id, authority_epoch, identity_kind, workspace_id,
            principal_id, client_instance_id, operation, idempotency_key, request_fingerprint, result_digest,
            result_canonical, guard_digest, committed_at_us
        ) VALUES (?, ?, 'workspace', ?, ?, 'ordinary_workspace', ?, ?, 'client-1', 'actor.create.v1',
            'same-key', zeroblob(32), zeroblob(32), X'00', zeroblob(32), 1)`,
			receiptID, commandID, workspace, epoch, workspace, principal)
		return err
	}
	if err := insertReceipt("01b8e094-9888-7000-8000-000000000008", "01b8e094-9888-7000-8000-000000000009", principalA); err != nil {
		t.Fatal(err)
	}
	if err := insertReceipt("01b8e094-9888-7000-8000-00000000000a", "01b8e094-9888-7000-8000-00000000000b", principalB); err != nil {
		t.Fatalf("different principal collided on idempotency key: %v", err)
	}
	if err := insertReceipt("01b8e094-9888-7000-8000-00000000000c", "01b8e094-9888-7000-8000-00000000000d", principalA); err == nil {
		t.Fatal("duplicate canonical receipt identity accepted")
	}

	insertEvent := func(eventID string, sequence, index int) error {
		_, err := store.db.ExecContext(ctx, `INSERT INTO domain_events(
            event_id, command_id, receipt_id, authority_id, authority_epoch, scope_kind, scope_id,
            stream_sequence, previous_stream_digest, event_digest, stream_digest, aggregate_kind,
            aggregate_id, aggregate_version, event_index, event_type, event_schema, payload, principal_id,
            authorization_digest, correlation_id, recorded_at_us
        ) VALUES (?, ?, ?, ?, ?, 'workspace', ?, ?, zeroblob(32), zeroblob(32), zeroblob(32), 'actor',
            ?, 2, ?, 'ActorChanged', 1, X'7b7d', ?, zeroblob(32), ?, 1)`,
			eventID, "01b8e094-9888-7000-8000-000000000009", "01b8e094-9888-7000-8000-000000000008",
			installationA, epoch, workspace, sequence, "01b8e094-9888-7000-8000-00000000000e", index,
			principalA, "01b8e094-9888-7000-8000-00000000000f")
		return err
	}
	if err := insertEvent("01b8e094-9888-7000-8000-000000000010", 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := insertEvent("01b8e094-9888-7000-8000-000000000011", 2, 1); err != nil {
		t.Fatalf("second event for one aggregate version rejected: %v", err)
	}
}

func TestWriteLaneSerializesImmediateTransactionsAndRollsBack(t *testing.T) {
	t.Parallel()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})

	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- store.withImmediate(context.Background(), func(tx *sql.Tx) error {
			close(entered)
			<-release
			_, err := tx.Exec("INSERT INTO backup_sessions(backup_id, state, started_at_us) VALUES (?, 'capturing', 1)",
				"01b8e094-9888-7000-8000-000000000001")
			return err
		})
	}()
	<-entered
	var secondEntered atomic.Bool
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- store.withImmediate(context.Background(), func(*sql.Tx) error {
			secondEntered.Store(true)
			return errors.New("rollback sentinel")
		})
	}()
	time.Sleep(20 * time.Millisecond)
	if secondEntered.Load() {
		t.Fatal("second writer entered while first writer held lane")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err == nil || err.Error() != "rollback sentinel" {
		t.Fatalf("second error=%v", err)
	}
	if !secondEntered.Load() {
		t.Fatal("second writer never entered")
	}

	var rows int
	if err := store.db.QueryRow("SELECT count(*) FROM backup_sessions").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d, want committed first write only", rows)
	}
}

func execRaw(t *testing.T, path, statement string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
}
