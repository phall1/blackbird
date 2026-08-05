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
