package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOnlineBackupRemainsConsistentDuringActiveWALWrites(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root := t.TempDir()
	store, err := Open(ctx, Config{Path: filepath.Join(root, "active-source.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})

	writerDone := make(chan error, 1)
	go func() {
		for index := 1; index <= 250; index++ {
			_, writeErr := store.db.ExecContext(ctx, `INSERT INTO backup_sessions(
				backup_id, state, database_high_water_digest, manifest_digest, started_at_us, completed_at_us
			) VALUES (?, 'retained', zeroblob(32), zeroblob(32), ?, ?)`,
				backupTestUUID(0x700+index), index, index,
			)
			if writeErr != nil {
				writerDone <- writeErr
				return
			}
		}
		writerDone <- nil
	}()

	lastRows := 0
	for index := 0; index < 8; index++ {
		path := filepath.Join(root, fmt.Sprintf("active-backup-%d.db", index))
		manifest, backupErr := store.Backup(ctx, path)
		if backupErr != nil {
			t.Fatal(backupErr)
		}
		if _, verifyErr := VerifyBackup(ctx, path, manifest); verifyErr != nil {
			t.Fatal(verifyErr)
		}
		backupDB, openErr := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
		if openErr != nil {
			t.Fatal(openErr)
		}
		var rows int
		queryErr := backupDB.QueryRowContext(ctx, "SELECT count(*) FROM backup_sessions").Scan(&rows)
		closeErr := backupDB.Close()
		if queryErr != nil || closeErr != nil {
			t.Fatal(errors.Join(queryErr, closeErr))
		}
		if rows < lastRows || rows > 250 {
			t.Fatalf("backup rows=%d after prior high-water=%d", rows, lastRows)
		}
		lastRows = rows
	}
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO backup_sessions(
		backup_id, state, database_high_water_digest, manifest_digest, started_at_us, completed_at_us
	) VALUES (?, 'retained', zeroblob(32), zeroblob(32), 999, 999)`,
		backupTestUUID(0x999)); err != nil {
		t.Fatalf("source was not writable after active backups: %v", err)
	}
}

func backupTestUUID(index int) string {
	return fmt.Sprintf("01b8e094-9888-7000-8000-%012x", index)
}

func TestOnlineBackupManifestAndSealedRestore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	store, err := Open(ctx, Config{Path: filepath.Join(root, "source.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := store.db.ExecContext(ctx, `INSERT INTO writer_control(
        singleton, storage_writer_generation, activation_state, database_role, updated_at_us
      ) VALUES (1, '01b8e094-9888-7000-8000-000000000001', 'active', 'local_authority', 1)`); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(root, "backup.db")
	manifest, err := store.Backup(ctx, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.FormatVersion != backupFormatVersion || manifest.ApplicationID != ApplicationID ||
		manifest.SchemaVersion != SchemaVersion || manifest.SchemaChecksum != expectedSchemaChecksum() ||
		manifest.SQLiteVersion != SQLiteVersion || manifest.SQLiteSourceID != SQLiteSourceID ||
		manifest.DatabaseBytes <= 0 || manifest.DatabaseSHA256 == ([sha256.Size]byte{}) ||
		manifest.CreatedAt.Location() != time.UTC {
		t.Fatalf("manifest=%+v", manifest)
	}
	if _, err := VerifyBackup(ctx, backupPath, manifest); err != nil {
		t.Fatal(err)
	}

	restorePath := filepath.Join(root, "restored.db")
	restored, err := Restore(ctx, backupPath, manifest, restorePath)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSnapshotIdentity(manifest, restored) {
		t.Fatal("restore changed snapshot identity")
	}
	db, err := sql.Open("sqlite", sqliteFileURI(restorePath, true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	var state string
	if err := db.QueryRowContext(ctx, "SELECT activation_state FROM writer_control WHERE singleton = 1").Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "sealed" {
		t.Fatalf("restored activation_state=%q, want sealed", state)
	}
	var runtimeRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM database_runtime
		WHERE singleton = 1 AND clean_shutdown = 1 AND closed_at_us IS NOT NULL`).Scan(&runtimeRows); err != nil {
		t.Fatal(err)
	}
	if runtimeRows != 1 {
		t.Fatalf("valid sealed runtime rows=%d, want 1", runtimeRows)
	}
}

func TestBackupAcceptsFullyPrunedAuthorityStream(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	store, err := Open(ctx, Config{Path: filepath.Join(root, "source.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	head := sha256.Sum256([]byte("retained high-water digest"))
	if _, err := store.db.ExecContext(ctx, `INSERT INTO authority_streams(
		scope_kind, scope_id, authority_id, authority_epoch, next_sequence, retained_from_sequence,
		digest_algorithm, head_digest, next_audit_sequence, audit_head_hash, authority_time_floor_us
	) VALUES ('workspace', ?, ?, ?, 6, 6, 'sha-256', ?, 1, zeroblob(32), 1)`,
		"01b8e094-9888-7000-8000-000000000401", "01b8e094-9888-7000-8000-000000000402",
		"01b8e094-9888-7000-8000-000000000403", head[:],
	); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.Backup(ctx, filepath.Join(root, "pruned.db"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.AuthorityStreams) != 1 || manifest.AuthorityStreams[0].EventHighWater != 5 ||
		manifest.AuthorityStreams[0].RetainedFromSequence != 6 ||
		manifest.AuthorityStreams[0].EventHighWaterDigest != head {
		t.Fatalf("pruned stream manifest=%+v", manifest.AuthorityStreams)
	}
}

func TestBackupRejectsNonFreshTargetsAndTampering(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	store, err := Open(ctx, Config{Path: filepath.Join(root, "source.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})

	if _, err := store.Backup(ctx, "relative.db"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("relative target error=%v", err)
	}
	existing := filepath.Join(root, "existing.db")
	file, err := os.OpenFile(existing, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Backup(ctx, existing); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("existing target error=%v", err)
	}
	staleSidecarTarget := filepath.Join(root, "stale-sidecar.db")
	staleWAL, err := os.OpenFile(staleSidecarTarget+"-wal", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := staleWAL.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Backup(ctx, staleSidecarTarget); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("stale sidecar target error=%v", err)
	}

	backupPath := filepath.Join(root, "backup.db")
	manifest, err := store.Backup(ctx, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, backupPath, manifest, "relative.db"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("relative restore target error=%v", err)
	}
	if _, err := Restore(ctx, backupPath, manifest, existing); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("existing restore target error=%v", err)
	}
	tampered := manifest
	tampered.DatabaseSHA256[0] ^= 0xff
	if _, err := VerifyBackup(ctx, backupPath, tampered); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("tampered manifest error=%v", err)
	}
	if _, err := Restore(ctx, backupPath, tampered, filepath.Join(root, "must-not-publish.db")); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("tampered restore error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "must-not-publish.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid restore published a target: %v", err)
	}

	cancelledPath := filepath.Join(root, "cancelled.db")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Backup(cancelled, cancelledPath); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled backup error=%v", err)
	}
	if _, err := os.Lstat(cancelledPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled backup published a target: %v", err)
	}
	partials, err := filepath.Glob(cancelledPath + ".partial.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(partials) != 1 {
		t.Fatalf("cancelled backup retained partials=%v, want one", partials)
	}
}

func TestBackupCancellationBetweenOnlineCopyStepsRetainsOnlyPartial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	store, err := Open(ctx, Config{Path: filepath.Join(root, "source.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := store.db.ExecContext(ctx, "CREATE TABLE copy_probe (payload BLOB NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 256; index++ {
		if _, err := store.db.ExecContext(ctx, "INSERT INTO copy_probe VALUES (randomblob(4096))"); err != nil {
			t.Fatal(err)
		}
	}

	cancelled, cancel := context.WithCancel(ctx)
	steps := 0
	cancelled = context.WithValue(cancelled, backupStepHookKey{}, func() {
		steps++
		cancel()
	})
	target := filepath.Join(root, "cancelled-mid-copy.db")
	if _, err := store.Backup(cancelled, target); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-copy cancellation error=%v", err)
	}
	if steps != 1 {
		t.Fatalf("completed online copy steps=%d, want 1 before cancellation", steps)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled copy published target: %v", err)
	}
	partials, err := filepath.Glob(target + ".partial.*")
	if err != nil || len(partials) != 1 {
		t.Fatalf("retained partials=%v error=%v, want one", partials, err)
	}
	if _, err := store.db.ExecContext(ctx, "INSERT INTO copy_probe VALUES (X'01')"); err != nil {
		t.Fatalf("source unusable after cancelled copy: %v", err)
	}
}

func TestVerifyBackupRejectsTruncatedAndCorruptDatabaseBytes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	store, err := Open(ctx, Config{Path: filepath.Join(root, "source.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	backupPath := filepath.Join(root, "backup.db")
	manifest, err := store.Backup(ctx, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) < 4096 {
		t.Fatalf("backup unexpectedly small: %d bytes", len(contents))
	}

	truncated := filepath.Join(root, "truncated.db")
	if err := os.WriteFile(truncated, contents[:len(contents)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(root, "corrupt.db")
	corruptContents := append([]byte(nil), contents...)
	corruptContents[0] ^= 0xff
	if err := os.WriteFile(corrupt, corruptContents, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{truncated, corrupt} {
		if _, err := VerifyBackup(ctx, path, manifest); !errors.Is(err, ErrInvalidBackup) {
			t.Fatalf("verify %s error=%v, want invalid backup", filepath.Base(path), err)
		}
		target := path + ".restored"
		if _, err := Restore(ctx, path, manifest, target); !errors.Is(err, ErrInvalidBackup) {
			t.Fatalf("restore %s error=%v, want invalid backup", filepath.Base(path), err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid backup %s published restore target: %v", filepath.Base(path), err)
		}
	}
	if _, err := VerifyBackup(ctx, backupPath, manifest); err != nil {
		t.Fatalf("intact backup no longer verifies: %v", err)
	}
}

func TestBackupPublicationRejectsSidecarCreatedAfterVerification(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	store, err := Open(ctx, Config{Path: filepath.Join(root, "source.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	target := filepath.Join(root, "raced.db")
	ctx = context.WithValue(ctx, backupPublishHookKey{}, func() error {
		return os.WriteFile(target+"-wal", []byte("stale"), 0o600)
	})
	if _, err := store.Backup(ctx, target); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("publication race error=%v, want target exists", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sidecar race published database target: %v", err)
	}
	partials, err := filepath.Glob(target + ".partial.*")
	if err != nil {
		t.Fatal(err)
	}
	retainedDatabase := false
	for _, partial := range partials {
		if !strings.HasSuffix(partial, "-wal") && !strings.HasSuffix(partial, "-shm") {
			retainedDatabase = true
		}
	}
	if !retainedDatabase {
		t.Fatalf("publication race did not retain verified database partial: %v", partials)
	}
}
