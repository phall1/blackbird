package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
