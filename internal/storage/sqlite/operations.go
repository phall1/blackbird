package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
)

var ErrFilesystemQualification = errors.New("SQLite filesystem qualification failed")

type CheckpointMode string

const (
	CheckpointPassive  CheckpointMode = "passive"
	CheckpointTruncate CheckpointMode = "truncate"
)

type CheckpointReport struct {
	Mode               CheckpointMode
	Busy               bool
	BusyStatus         int
	BusyTime           time.Duration
	LogFrames          int
	CheckpointedFrames int
	RemainingFrames    int
	OldestReaderKnown  bool
	OldestReaderAge    time.Duration
	WALBytes           int64
	FreeBytes          uint64
	Duration           time.Duration
}

type IntegrityReport struct {
	Full     bool
	Duration time.Duration
}

type PathQualification struct {
	Path           string
	Exists         bool
	Directory      bool
	OwnerUID       uint32
	Permissions    os.FileMode
	FilesystemType uint64
	FilesystemName string
	FreeBytes      uint64
	LockVerified   bool
}

type FilesystemQualification struct {
	DatabaseDirectory PathQualification
	Database          PathQualification
	WAL               PathQualification
	SharedMemory      PathQualification
	Artifacts         PathQualification
	SameOwner         bool
	Local             bool
	QualifiedAt       time.Time
}

func (store *Store) Checkpoint(ctx context.Context, mode CheckpointMode) (CheckpointReport, error) {
	if mode != CheckpointPassive && mode != CheckpointTruncate {
		return CheckpointReport{}, fmt.Errorf("invalid SQLite checkpoint mode %q", mode)
	}
	if mode == CheckpointTruncate {
		if _, bounded := ctx.Deadline(); !bounded {
			return CheckpointReport{}, errors.New("SQLite truncating checkpoint requires a bounded context")
		}
		if err := store.acquireWrite(ctx, false); err != nil {
			return CheckpointReport{}, err
		}
		defer store.releaseWrite()
	}

	started := time.Now()
	report := CheckpointReport{Mode: mode}
	pragma := "PRAGMA wal_checkpoint(PASSIVE)"
	if mode == CheckpointTruncate {
		pragma = "PRAGMA wal_checkpoint(TRUNCATE)"
	}
	if err := store.db.QueryRowContext(ctx, pragma).Scan(
		&report.BusyStatus, &report.LogFrames, &report.CheckpointedFrames,
	); err != nil {
		return CheckpointReport{}, fmt.Errorf("run SQLite %s checkpoint: %w", mode, err)
	}
	report.Duration = time.Since(started)
	report.Busy = report.BusyStatus != 0
	if report.Busy {
		report.BusyTime = report.Duration
	}
	if report.LogFrames > report.CheckpointedFrames {
		report.RemainingFrames = report.LogFrames - report.CheckpointedFrames
	}
	if info, err := os.Stat(store.path + "-wal"); err == nil {
		report.WALBytes = info.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return CheckpointReport{}, fmt.Errorf("inspect SQLite WAL after checkpoint: %w", err)
	}
	freeBytes, _, _, err := filesystemStats(store.path)
	if err != nil {
		return CheckpointReport{}, fmt.Errorf("inspect SQLite free space after checkpoint: %w", err)
	}
	report.FreeBytes = freeBytes
	return report, nil
}

func (store *Store) FullIntegrityCheck(ctx context.Context) (IntegrityReport, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		return IntegrityReport{Full: true}, errors.New("full SQLite integrity check requires a bounded context")
	}
	if err := store.acquireWrite(ctx, false); err != nil {
		return IntegrityReport{Full: true}, err
	}
	defer store.releaseWrite()

	started := time.Now()
	err := store.IntegrityCheck(ctx)
	report := IntegrityReport{Full: true, Duration: time.Since(started)}
	if err != nil {
		return report, err
	}
	return report, nil
}

func QualifyFilesystem(databasePath, artifactDirectory string) (FilesystemQualification, error) {
	if err := validateQualifiedPath(databasePath); err != nil {
		return FilesystemQualification{}, err
	}
	if err := validateQualifiedPath(artifactDirectory); err != nil {
		return FilesystemQualification{}, err
	}

	databaseDirectory, err := qualifyPath(filepath.Dir(databasePath), true, true)
	if err != nil {
		return FilesystemQualification{}, err
	}
	database, err := qualifyPath(databasePath, false, true)
	if err != nil {
		return FilesystemQualification{}, err
	}
	wal, err := qualifyPath(databasePath+"-wal", false, false)
	if err != nil {
		return FilesystemQualification{}, err
	}
	sharedMemory, err := qualifyPath(databasePath+"-shm", false, false)
	if err != nil {
		return FilesystemQualification{}, err
	}
	artifacts, err := qualifyPath(artifactDirectory, true, true)
	if err != nil {
		return FilesystemQualification{}, err
	}

	owner := uint32(os.Geteuid())
	result := FilesystemQualification{
		DatabaseDirectory: databaseDirectory, Database: database, WAL: wal,
		SharedMemory: sharedMemory, Artifacts: artifacts,
		SameOwner: true, Local: true, QualifiedAt: time.Now().UTC(),
	}
	for _, path := range []PathQualification{databaseDirectory, database, wal, sharedMemory, artifacts} {
		if path.OwnerUID != owner {
			result.SameOwner = false
		}
		if unsupportedFilesystem(path.FilesystemType, path.FilesystemName) {
			result.Local = false
		}
	}
	if !result.SameOwner {
		return result, fmt.Errorf("%w: paths are not owned by effective uid %d", ErrFilesystemQualification, owner)
	}
	if !result.Local {
		return result, fmt.Errorf("%w: network or userspace filesystem is unsupported", ErrFilesystemQualification)
	}
	return result, nil
}

func validateQualifiedPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: path must be absolute and clean: %q", ErrFilesystemQualification, path)
	}
	return nil
}

func qualifyPath(path string, directory, required bool) (PathQualification, error) {
	result := PathQualification{Path: path, Directory: directory}
	info, err := os.Lstat(path)
	exists := err == nil
	if errors.Is(err, os.ErrNotExist) && !required {
		info, err = os.Lstat(filepath.Dir(path))
	}
	if err != nil {
		return result, fmt.Errorf("%w: inspect %q: %v", ErrFilesystemQualification, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return result, fmt.Errorf("%w: symlink is unsupported: %q", ErrFilesystemQualification, path)
	}
	if exists && directory != info.IsDir() {
		return result, fmt.Errorf("%w: unexpected file type: %q", ErrFilesystemQualification, path)
	}
	if !exists && !info.IsDir() {
		return result, fmt.Errorf("%w: sidecar parent is not a directory: %q", ErrFilesystemQualification, path)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return result, fmt.Errorf("%w: path is not regular: %q", ErrFilesystemQualification, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return result, fmt.Errorf("%w: group or other permissions on %q are not allowed", ErrFilesystemQualification, path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return result, fmt.Errorf("%w: ownership unavailable for %q", ErrFilesystemQualification, path)
	}
	result.Exists = exists
	result.OwnerUID = stat.Uid
	result.Permissions = info.Mode().Perm()
	result.FreeBytes, result.FilesystemType, result.FilesystemName, err = filesystemStats(path)
	if err != nil {
		return result, fmt.Errorf("%w: filesystem stats for %q: %v", ErrFilesystemQualification, path, err)
	}
	if required && !directory {
		if err := verifyAdvisoryLocks(path); err != nil {
			return result, err
		}
		result.LockVerified = true
	}
	return result, nil
}

func filesystemStats(path string) (uint64, uint64, string, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		if !errors.Is(err, syscall.ENOENT) {
			return 0, 0, "", err
		}
		if err := syscall.Statfs(filepath.Dir(path), &stat); err != nil {
			return 0, 0, "", err
		}
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), uint64(stat.Type), filesystemName(stat), nil
}

func filesystemName(stat syscall.Statfs_t) string {
	field := reflect.ValueOf(stat).FieldByName("Fstypename")
	if !field.IsValid() || field.Kind() != reflect.Array {
		return ""
	}
	name := make([]byte, 0, field.Len())
	for index := range field.Len() {
		value := byte(field.Index(index).Int())
		if value == 0 {
			break
		}
		name = append(name, value)
	}
	return strings.ToLower(string(name))
}

func verifyAdvisoryLocks(path string) error {
	first, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("%w: open database lock probe: %v", ErrFilesystemQualification, err)
	}
	defer func() { _ = first.Close() }()
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("%w: open competing database lock probe: %v", ErrFilesystemQualification, err)
	}
	defer func() { _ = second.Close() }()
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("%w: acquire advisory lock: %v", ErrFilesystemQualification, err)
	}
	defer func() { _ = syscall.Flock(int(first.Fd()), syscall.LOCK_UN) }()
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		_ = syscall.Flock(int(second.Fd()), syscall.LOCK_UN)
		return fmt.Errorf("%w: filesystem did not enforce competing advisory locks", ErrFilesystemQualification)
	} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		return fmt.Errorf("%w: competing advisory lock returned %v", ErrFilesystemQualification, err)
	}
	return nil
}

func unsupportedFilesystem(filesystemType uint64, filesystemName string) bool {
	switch filesystemName {
	case "nfs", "smbfs", "webdav", "afpfs", "osxfuse", "macfuse":
		return true
	}
	switch filesystemType {
	case 0x6969, 0x517b, 0xff534d42, 0x65735546, 0x9fa0:
		// NFS, SMB, CIFS, FUSE, and procfs are not supported authority storage.
		return true
	default:
		return false
	}
}
