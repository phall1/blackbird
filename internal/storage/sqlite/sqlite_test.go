package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func execRaw(t *testing.T, path, statement string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
}

func TestInvariantMismatchesNameEveryFailedCheck(t *testing.T) {
	t.Parallel()

	diagnostic := diagnosticInvariantMismatches(Diagnostics{JournalMode: "delete", Synchronous: "1",
		BusyTimeout: -time.Second, TrustedSchema: true, ExtensionLoading: true,
		ApplicationID: -1, SchemaVersion: -1})
	joined := strings.Join(diagnostic, ",")
	for _, name := range []string{"journal_mode", "foreign_keys", "synchronous", "busy_timeout", "trusted_schema",
		"extension_loading", "fullfsync", "checkpoint_fullfsync", "application_id", "user_version"} {
		if !strings.Contains(joined, name+"=") {
			t.Errorf("diagnostic mismatches %q omit %s", joined, name)
		}
	}

	physical := physicalInvariantMismatches("wrong", "wrong", "delete", "1", 0, 1, 1, 0, 0, 2*time.Second)
	joined = strings.Join(physical, ",")
	for _, name := range []string{"sqlite_version", "sqlite_source_id", "journal_mode", "foreign_keys", "synchronous",
		"busy_timeout", "trusted_schema", "fullfsync", "checkpoint_fullfsync"} {
		if !strings.Contains(joined, name+"=") {
			t.Errorf("physical mismatches %q omit %s", joined, name)
		}
	}
}

func TestReadPoolSizeDefaultsToCPUAndAcceptsOverride(t *testing.T) {
	t.Parallel()

	if got := configuredReadPoolSize(Config{}); got != runtime.NumCPU() {
		t.Fatalf("default read pool size=%d, want runtime.NumCPU()=%d", got, runtime.NumCPU())
	}
	const configured = 2
	store, err := Open(context.Background(), Config{
		Path: filepath.Join(t.TempDir(), "pool.db"), ReadPoolSize: configured,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	if store.readPoolSize != configured {
		t.Fatalf("store read pool size=%d, want %d", store.readPoolSize, configured)
	}
	stats := store.db.Stats()
	if stats.MaxOpenConnections != configured {
		t.Fatalf("database max open connections=%d, want %d", stats.MaxOpenConnections, configured)
	}
	// Open verifies every physical connection and keeps the configured number
	// idle, so a larger pool cannot silently skip the per-connection pragmas.
	if stats.OpenConnections != configured {
		t.Fatalf("verified physical connections=%d, want %d", stats.OpenConnections, configured)
	}
}

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
	if tables != 47 {
		t.Fatalf("tables=%d, want 47", tables)
	}
	if err := reopened.IntegrityCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestMigrationLadderChecksumsMatchEmbeddedMigrations pins every rung's schema
// checksum to what the embedded migrations actually produce. A new rung whose
// constant is a guess, or an edit to a migration that already shipped, fails
// here instead of stranding an installed database that can no longer be climbed.
func TestMigrationLadderChecksumsMatchEmbeddedMigrations(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	for index, rung := range migrationLadder {
		version := index + 1
		t.Run(rung.migrationID, func(t *testing.T) {
			path := filepath.Join(directory, "ladder-v"+strconv.Itoa(version)+".db")
			installLegacyDatabase(t, path, version)
			db, err := sql.Open("sqlite", databaseURL(Config{Path: path}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Error(err)
				}
			})
			live, err := schemaChecksum(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if expected := rung.expectedSchema(); live != expected {
				t.Fatalf("schema after %s=%x, ladder records %x", rung.migrationID, live, expected)
			}
		})
	}
}

// TestOpenClimbsMigrationLadderFromEveryKnownVersion covers the reason the ladder
// exists: Homebrew updates often enough that a shelved machine skips versions, so
// every version this build knows must converge on the current one rather than
// only the immediately preceding rung.
func TestOpenClimbsMigrationLadderFromEveryKnownVersion(t *testing.T) {
	t.Parallel()
	for version := 1; version < SchemaVersion; version++ {
		t.Run("v"+strconv.Itoa(version), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "blackbird.db")
			installLegacyDatabase(t, path, version)
			store, err := Open(context.Background(), Config{Path: path})
			if err != nil {
				t.Fatalf("open at user_version=%d: %v", version, err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Error(err)
				}
			})
			if store.Diagnostics().SchemaVersion != SchemaVersion {
				t.Fatalf("schema version=%d, want %d", store.Diagnostics().SchemaVersion, SchemaVersion)
			}
			var migrations, manifests, keys int
			for _, count := range []struct {
				query string
				dest  *int
			}{
				{"SELECT count(*) FROM schema_migrations", &migrations},
				{"SELECT count(*) FROM schema_manifest", &manifests},
				{"SELECT count(*) FROM coordination_event_cursor_keys", &keys},
			} {
				if err := store.db.QueryRow(count.query).Scan(count.dest); err != nil {
					t.Fatal(err)
				}
			}
			// The ledger is append-only, so the climb leaves one manifest row per
			// rung on top of the row the shelved build had already recorded.
			if migrations != len(migrationIDs) || manifests != SchemaVersion-version+1 || keys != 1 {
				t.Fatalf("migration rows=%d manifest rows=%d cursor keys=%d", migrations, manifests, keys)
			}
			if err := store.IntegrityCheck(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenLeavesCurrentSchemaUntouched(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	migrations, manifests, key := schemaLedgerFacts(t, store)
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
	reopenedMigrations, reopenedManifests, reopenedKey := schemaLedgerFacts(t, reopened)
	if reopenedMigrations != migrations || reopenedManifests != manifests || reopenedKey != key {
		t.Fatalf("reopen rewrote the ledger: migrations %d->%d manifest %d->%d key changed=%t",
			migrations, reopenedMigrations, manifests, reopenedManifests, reopenedKey != key)
	}
}

// TestOpenSeparatesUnreadableSchemaDirections keeps downgrade fail-closed while
// naming which direction failed, because the remedies differ: a newer database
// needs a newer Blackbird, and no update can rescue a version off the ladder.
func TestOpenSeparatesUnreadableSchemaDirections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		statement string
		want      error
		reject    error
	}{
		{"newer than binary", "PRAGMA user_version = " + strconv.Itoa(SchemaVersion+1), ErrSchemaFromFuture, ErrSchemaUnknown},
		{"version off the ladder", "PRAGMA user_version = 0", ErrSchemaUnknown, ErrSchemaFromFuture},
		{"foreign application", "PRAGMA application_id = 1", ErrSchemaUnknown, ErrSchemaFromFuture},
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
			execRaw(t, path, test.statement)
			_, err = Open(context.Background(), Config{Path: path})
			if !errors.Is(err, ErrSchemaMismatch) || !errors.Is(err, test.want) || errors.Is(err, test.reject) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}
}

func schemaLedgerFacts(t *testing.T, store *Store) (int, int, string) {
	t.Helper()
	var migrations, manifests int
	var key string
	if err := store.db.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM schema_manifest").Scan(&manifests); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT hex(key) FROM coordination_event_cursor_keys").Scan(&key); err != nil {
		t.Fatal(err)
	}
	return migrations, manifests, key
}

// installLegacyDatabase writes the database a build pinned at version would have
// left behind: the rungs up to that version applied and recorded, and a manifest
// naming only the version it stopped at.
func installLegacyDatabase(t *testing.T, path string, version int) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", databaseURL(Config{Path: path}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, rung := range migrationLadder[:version] {
		body, checksum, migrationErr := migration(rung.migrationID)
		if migrationErr != nil {
			t.Fatal(migrationErr)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			t.Fatal(err)
		}
		if rung.seed != nil {
			if err := rung.seed(ctx, tx); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(migration_id, checksum, applied_at_us, state)
			VALUES (?, ?, CAST(unixepoch('subsec') * 1000000 AS INTEGER), 'applied')`,
			rung.migrationID, checksum[:]); err != nil {
			t.Fatal(err)
		}
	}
	recorded := migrationLadder[version-1].expectedSchema()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_manifest(schema_version, checksum) VALUES (?, ?)`, version, recorded[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA application_id = "+strconv.Itoa(ApplicationID)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(version)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
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
	if _, err := store.db.Exec("DROP INDEX domain_events_aggregate_idx"); err != nil {
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
		// Derived rather than written down: a literal here silently stopped
		// being a drifted version the moment SchemaVersion caught up with it,
		// and the case went on passing while asserting nothing.
		{"schema version", func(t *testing.T, path string) {
			execRaw(t, path, "PRAGMA user_version = "+strconv.Itoa(SchemaVersion+1))
		}},
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
		{Path: filepath.Join(t.TempDir(), "blackbird.db"), ReadPoolSize: -1},
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
    ) VALUES (?, ?, ?, 'Wrong scope', 'ed25519-spki-sha256-v1', 'keyref:test', zeroblob(32), zeroblob(32), 1, 'trusted', 1, 1, 1)`,
		"01b8e094-9888-7000-8000-000000000005", installationA, principalB); err == nil {
		t.Fatal("cross-installation device principal accepted")
	}

	workspace := "01b8e094-9888-7000-8000-000000000006"
	epoch := "01b8e094-9888-7000-8000-000000000007"
	insertReceipt := func(receiptID, commandID, principal string) error {
		_, err := store.db.ExecContext(ctx, `INSERT INTO command_receipts(
			receipt_id, command_id, scope_kind, scope_id, authority_id, authority_epoch, identity_kind, workspace_id,
			principal_id, client_instance_id, operation, operation_major, idempotency_key, request_fingerprint, result_digest,
			result_canonical, first_event_sequence, last_event_sequence, final_stream_digest, guard_digest,
			capsule_required, committed_at_us
		) VALUES (?, ?, 'workspace', ?, ?, ?, 'ordinary_workspace', ?, ?, ?, 'actor.create.v1', 1,
			'same-key', zeroblob(32), zeroblob(32), X'00', 1, 1, zeroblob(32), zeroblob(32), 0, 1)`,
			receiptID, commandID, workspace, installationA, epoch, workspace, principal,
			"01b8e094-9888-7000-8000-000000000012")
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
