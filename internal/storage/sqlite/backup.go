package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	sqlitedriver "modernc.org/sqlite"
)

const (
	backupFormatVersion = 1
	backupPagesPerStep  = 64
)

var (
	ErrTargetExists  = errors.New("SQLite backup target exists")
	ErrInvalidBackup = errors.New("invalid SQLite backup")
)

// BackupManifest contains only facts derived from a completed database
// snapshot, apart from CreatedAt, which records when that snapshot completed.
type BackupManifest struct {
	FormatVersion    int
	CreatedAt        time.Time
	DatabaseBytes    int64
	DatabaseSHA256   [sha256.Size]byte
	ApplicationID    int
	SchemaVersion    int
	SchemaChecksum   [sha256.Size]byte
	SQLiteVersion    string
	SQLiteSourceID   string
	AuthorityStreams []BackupAuthorityStream
}

// BackupAuthorityStream identifies one authority cursor captured in a backup.
type BackupAuthorityStream struct {
	ScopeKind            string
	ScopeID              string
	AuthorityID          string
	AuthorityEpoch       string
	RetainedFromSequence int64
	EventHighWater       int64
	EventHighWaterDigest [sha256.Size]byte
}

type onlineBackuper interface {
	NewBackup(string) (*sqlitedriver.Backup, error)
}

type onlineRestorer interface {
	NewRestore(string) (*sqlitedriver.Backup, error)
}

type backupStepHookKey struct{}
type backupPublishHookKey struct{}

// Backup creates and verifies an online snapshot without copying the live
// database or WAL files. Failed snapshots remain under an unpublished partial
// name for diagnosis and are never promoted to target.
func (store *Store) Backup(ctx context.Context, target string) (BackupManifest, error) {
	if err := validateFreshTarget(target); err != nil {
		return BackupManifest{}, err
	}
	partial, err := reservePartialTarget(target)
	if err != nil {
		return BackupManifest{}, err
	}
	if err := onlineBackup(ctx, store.db, partial); err != nil {
		return BackupManifest{}, fmt.Errorf("online SQLite backup retained at %s: %w", partial, err)
	}
	if err := os.Chmod(partial, 0o600); err != nil {
		return BackupManifest{}, fmt.Errorf("secure retained SQLite backup %s: %w", partial, err)
	}
	manifest, err := deriveBackupManifest(ctx, partial, time.Now().UTC())
	if err != nil {
		return BackupManifest{}, fmt.Errorf("verify retained SQLite backup %s: %w", partial, err)
	}
	if err := ctx.Err(); err != nil {
		return BackupManifest{}, fmt.Errorf("cancel SQLite backup before publication: %w", err)
	}
	if err := publishPartial(ctx, partial, target); err != nil {
		return BackupManifest{}, err
	}
	return manifest, nil
}

// VerifyBackup re-derives all database facts from the supplied snapshot and
// rejects a manifest assembled from live source state or another file.
func VerifyBackup(ctx context.Context, path string, expected BackupManifest) (BackupManifest, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return BackupManifest{}, fmt.Errorf("%w: backup path must be clean and absolute", ErrInvalidBackup)
	}
	if expected.FormatVersion != backupFormatVersion || expected.CreatedAt.IsZero() ||
		expected.CreatedAt.Location() != time.UTC {
		return BackupManifest{}, fmt.Errorf("%w: unsupported or incomplete manifest", ErrInvalidBackup)
	}
	actual, err := deriveBackupManifest(ctx, path, expected.CreatedAt)
	if err != nil {
		return BackupManifest{}, errors.Join(ErrInvalidBackup, err)
	}
	if !equalBackupManifest(expected, actual) {
		return BackupManifest{}, fmt.Errorf("%w: manifest does not match snapshot", ErrInvalidBackup)
	}
	return actual, nil
}

// Restore verifies a backup before using the driver's online restore API to
// create a fresh database. Every existing writer-control row is sealed before
// the restored target is verified and published; writable activation belongs
// to the later recovery protocol.
func Restore(ctx context.Context, backupPath string, manifest BackupManifest, target string) (BackupManifest, error) {
	verified, err := VerifyBackup(ctx, backupPath, manifest)
	if err != nil {
		return BackupManifest{}, err
	}
	if err := validateFreshTarget(target); err != nil {
		return BackupManifest{}, err
	}
	partial, err := reservePartialTarget(target)
	if err != nil {
		return BackupManifest{}, err
	}
	db, err := openBackupDatabase(partial, false)
	if err != nil {
		return BackupManifest{}, fmt.Errorf("open retained restore partial %s: %w", partial, err)
	}
	if err := onlineRestore(ctx, db, backupPath); err != nil {
		_ = db.Close()
		return BackupManifest{}, fmt.Errorf("online SQLite restore retained at %s: %w", partial, err)
	}
	if err := db.Close(); err != nil {
		return BackupManifest{}, fmt.Errorf("close retained SQLite restore %s: %w", partial, err)
	}
	if err := os.Chmod(partial, 0o600); err != nil {
		return BackupManifest{}, fmt.Errorf("secure retained SQLite restore %s: %w", partial, err)
	}
	unsealed, err := deriveBackupManifest(ctx, partial, verified.CreatedAt)
	if err != nil {
		return BackupManifest{}, fmt.Errorf("verify retained SQLite restore source %s: %w", partial, err)
	}
	if !equalBackupManifest(verified, unsealed) {
		return BackupManifest{}, fmt.Errorf("%w: online restore does not match source snapshot", ErrInvalidBackup)
	}
	db, err = openBackupDatabase(partial, false)
	if err != nil {
		return BackupManifest{}, fmt.Errorf("reopen retained SQLite restore %s for sealing: %w", partial, err)
	}
	if err := sealRestoredDatabase(ctx, db); err != nil {
		_ = db.Close()
		return BackupManifest{}, fmt.Errorf("seal retained SQLite restore %s: %w", partial, err)
	}
	if err := db.Close(); err != nil {
		return BackupManifest{}, fmt.Errorf("close sealed SQLite restore %s: %w", partial, err)
	}
	restored, err := deriveBackupManifest(ctx, partial, verified.CreatedAt)
	if err != nil {
		return BackupManifest{}, fmt.Errorf("verify retained SQLite restore %s: %w", partial, err)
	}
	if !equalSnapshotIdentity(verified, restored) {
		return BackupManifest{}, fmt.Errorf("%w: restored snapshot identity changed", ErrInvalidBackup)
	}
	if err := verifyRestoreSeal(ctx, partial); err != nil {
		return BackupManifest{}, fmt.Errorf("verify retained SQLite restore %s: %w", partial, err)
	}
	if err := ctx.Err(); err != nil {
		return BackupManifest{}, fmt.Errorf("cancel SQLite restore before publication: %w", err)
	}
	if err := publishPartial(ctx, partial, target); err != nil {
		return BackupManifest{}, err
	}
	return restored, nil
}

func onlineBackup(ctx context.Context, db *sql.DB, target string) (finalErr error) {
	connection, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire SQLite backup connection: %w", err)
	}
	defer func() { finalErr = errors.Join(finalErr, connection.Close()) }()
	return connection.Raw(func(driverConnection any) error {
		backuper, ok := driverConnection.(onlineBackuper)
		if !ok {
			return errors.New("modernc SQLite connection does not expose online backup")
		}
		backup, err := backuper.NewBackup(sqliteFileURI(target, false))
		if err != nil {
			return fmt.Errorf("start SQLite online backup: %w", err)
		}
		return stepBackup(ctx, backup)
	})
}

func onlineRestore(ctx context.Context, db *sql.DB, source string) (finalErr error) {
	connection, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire SQLite restore connection: %w", err)
	}
	defer func() { finalErr = errors.Join(finalErr, connection.Close()) }()
	return connection.Raw(func(driverConnection any) error {
		restorer, ok := driverConnection.(onlineRestorer)
		if !ok {
			return errors.New("modernc SQLite connection does not expose online restore")
		}
		restore, err := restorer.NewRestore(sqliteFileURI(source, true))
		if err != nil {
			return fmt.Errorf("start SQLite online restore: %w", err)
		}
		return stepBackup(ctx, restore)
	})
}

func stepBackup(ctx context.Context, backup *sqlitedriver.Backup) (finalErr error) {
	finished := false
	var busySince time.Time
	defer func() {
		if !finished {
			finalErr = errors.Join(finalErr, backup.Finish())
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		more, err := backup.Step(backupPagesPerStep)
		if err != nil {
			message := strings.ToLower(err.Error())
			if strings.Contains(message, "busy") || strings.Contains(message, "locked") {
				if busySince.IsZero() {
					busySince = time.Now()
				} else if time.Since(busySince) >= defaultBusyTimeout {
					return fmt.Errorf("step SQLite online copy after bounded busy retry: %w", err)
				}
				timer := time.NewTimer(time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
					continue
				}
			}
			return fmt.Errorf("step SQLite online copy: %w", err)
		}
		busySince = time.Time{}
		if !more {
			break
		}
		if hook, ok := ctx.Value(backupStepHookKey{}).(func()); ok {
			hook()
		}
	}
	if err := backup.Finish(); err != nil {
		return fmt.Errorf("finish SQLite online copy: %w", err)
	}
	finished = true
	return nil
}

func deriveBackupManifest(ctx context.Context, path string, createdAt time.Time) (result BackupManifest, finalErr error) {
	file, err := os.Open(path)
	if err != nil {
		return BackupManifest{}, fmt.Errorf("open SQLite snapshot for hashing: %w", err)
	}
	hash := sha256.New()
	buffer := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return BackupManifest{}, err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			result.DatabaseBytes += int64(read)
			_, _ = hash.Write(buffer[:read])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			err = readErr
			break
		}
	}
	closeErr := file.Close()
	if err != nil {
		return BackupManifest{}, errors.Join(fmt.Errorf("hash SQLite snapshot: %w", err), closeErr)
	}
	if closeErr != nil {
		return BackupManifest{}, fmt.Errorf("close SQLite snapshot after hashing: %w", closeErr)
	}
	copy(result.DatabaseSHA256[:], hash.Sum(nil))

	db, err := openBackupDatabase(path, true)
	if err != nil {
		return BackupManifest{}, err
	}
	defer func() { finalErr = errors.Join(finalErr, db.Close()) }()
	if err := verifyIntegrity(ctx, db, true); err != nil {
		return BackupManifest{}, err
	}
	if err := db.QueryRowContext(ctx,
		"SELECT sqlite_version(), sqlite_source_id()",
	).Scan(&result.SQLiteVersion, &result.SQLiteSourceID); err != nil {
		return BackupManifest{}, fmt.Errorf("inspect SQLite snapshot engine: %w", err)
	}
	if err := db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&result.ApplicationID); err != nil {
		return BackupManifest{}, fmt.Errorf("inspect SQLite snapshot application id: %w", err)
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&result.SchemaVersion); err != nil {
		return BackupManifest{}, fmt.Errorf("inspect SQLite snapshot schema version: %w", err)
	}
	if result.SQLiteVersion != SQLiteVersion || result.SQLiteSourceID != SQLiteSourceID {
		return BackupManifest{}, fmt.Errorf("%w: snapshot version=%q source_id=%q", ErrEngineMismatch, result.SQLiteVersion, result.SQLiteSourceID)
	}
	if result.ApplicationID != ApplicationID || result.SchemaVersion != SchemaVersion {
		return BackupManifest{}, fmt.Errorf("%w: snapshot application_id=%d user_version=%d", ErrSchemaMismatch, result.ApplicationID, result.SchemaVersion)
	}
	if err := (&Store{db: db}).verifyMigrationLedger(ctx); err != nil {
		return BackupManifest{}, err
	}
	result.SchemaChecksum, err = schemaChecksum(ctx, db)
	if err != nil {
		return BackupManifest{}, err
	}
	result.AuthorityStreams, err = deriveAuthorityStreams(ctx, db)
	if err != nil {
		return BackupManifest{}, err
	}
	result.FormatVersion = backupFormatVersion
	result.CreatedAt = createdAt
	return result, nil
}

func deriveAuthorityStreams(ctx context.Context, db *sql.DB) ([]BackupAuthorityStream, error) {
	rows, err := db.QueryContext(ctx, `SELECT s.scope_kind, s.scope_id, s.authority_id, s.authority_epoch,
        s.retained_from_sequence, s.next_sequence - 1,
        s.head_digest,
        COALESCE((SELECT e.stream_digest FROM domain_events e
          WHERE e.scope_kind = s.scope_kind AND e.scope_id = s.scope_id AND e.authority_epoch = s.authority_epoch
          ORDER BY e.stream_sequence DESC LIMIT 1), zeroblob(32)),
        (SELECT count(*) FROM domain_events e
          WHERE e.scope_kind = s.scope_kind AND e.scope_id = s.scope_id AND e.authority_epoch = s.authority_epoch
            AND e.stream_sequence BETWEEN s.retained_from_sequence AND s.next_sequence - 1)
      FROM authority_streams s ORDER BY s.scope_kind, s.scope_id, s.authority_epoch`)
	if err != nil {
		return nil, fmt.Errorf("read SQLite snapshot authority streams: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var streams []BackupAuthorityStream
	for rows.Next() {
		var stream BackupAuthorityStream
		var headDigest, eventDigest []byte
		var eventCount int64
		if err := rows.Scan(&stream.ScopeKind, &stream.ScopeID, &stream.AuthorityID, &stream.AuthorityEpoch,
			&stream.RetainedFromSequence, &stream.EventHighWater, &headDigest, &eventDigest, &eventCount); err != nil {
			return nil, fmt.Errorf("read SQLite snapshot authority stream: %w", err)
		}
		expectedCount := stream.EventHighWater - stream.RetainedFromSequence + 1
		if stream.RetainedFromSequence > stream.EventHighWater+1 {
			return nil, fmt.Errorf("%w: invalid retained cursor for authority stream %s/%s/%s", ErrSchemaMismatch,
				stream.ScopeKind, stream.ScopeID, stream.AuthorityEpoch)
		}
		emptyRetainedRange := expectedCount == 0
		if eventCount != expectedCount || len(headDigest) != sha256.Size || len(eventDigest) != sha256.Size ||
			(!emptyRetainedRange && !bytes.Equal(headDigest, eventDigest)) {
			return nil, fmt.Errorf("%w: non-contiguous authority stream %s/%s/%s", ErrSchemaMismatch,
				stream.ScopeKind, stream.ScopeID, stream.AuthorityEpoch)
		}
		copy(stream.EventHighWaterDigest[:], headDigest)
		streams = append(streams, stream)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read SQLite snapshot authority streams: %w", err)
	}
	return streams, nil
}

func sealRestoredDatabase(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var writerRows int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM writer_control").Scan(&writerRows); err != nil || writerRows > 1 {
		return errors.Join(errors.New("invalid restored writer-control cardinality"), err)
	}
	if writerRows == 1 {
		result, err := tx.ExecContext(ctx, "UPDATE writer_control SET activation_state = 'sealed' WHERE singleton = 1")
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return errors.Join(errors.New("failed to seal restored writer control"), err)
		}
	}
	result, err := tx.ExecContext(ctx, "UPDATE database_runtime SET clean_shutdown = 1, closed_at_us = CAST(unixepoch('subsec') * 1000000 AS INTEGER) WHERE singleton = 1")
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return errors.Join(errors.New("invalid restored runtime singleton"), err)
	}
	return tx.Commit()
}

func verifyRestoreSeal(ctx context.Context, path string) (finalErr error) {
	db, err := openBackupDatabase(path, true)
	if err != nil {
		return err
	}
	defer func() { finalErr = errors.Join(finalErr, db.Close()) }()
	var writerRows, sealedRows int
	if err := db.QueryRowContext(ctx, "SELECT count(*), count(*) FILTER (WHERE singleton = 1 AND activation_state = 'sealed') FROM writer_control").Scan(&writerRows, &sealedRows); err != nil {
		return err
	}
	if writerRows > 1 || sealedRows != writerRows {
		return errors.New("restored SQLite target is not sealed")
	}
	var runtimeRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM database_runtime
		WHERE singleton = 1 AND clean_shutdown = 1 AND closed_at_us IS NOT NULL`).Scan(&runtimeRows); err != nil {
		return err
	}
	if runtimeRows != 1 {
		return errors.New("restored SQLite runtime marker is invalid")
	}
	return nil
}

func validateFreshTarget(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Ext(path) == "" {
		return fmt.Errorf("%w: target must be a clean absolute database path", ErrInvalidConfiguration)
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("%w: resolve target directory: %v", ErrInvalidConfiguration, err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%w: target parent is not a directory", ErrInvalidConfiguration)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Lstat(candidate); err == nil {
			return ErrTargetExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect SQLite target namespace: %w", err)
		}
	}
	return nil
}

func reservePartialTarget(target string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate SQLite partial name: %w", err)
	}
	partial := fmt.Sprintf("%s.partial.%x", target, nonce)
	file, err := os.OpenFile(partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("reserve SQLite partial target: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close SQLite partial reservation: %w", err)
	}
	return partial, nil
}

func publishPartial(ctx context.Context, partial, target string) error {
	for _, candidate := range []string{target, target + "-wal", target + "-shm"} {
		if _, err := os.Lstat(candidate); err == nil {
			return fmt.Errorf("%w (verified partial retained at %s)", ErrTargetExists, partial)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect SQLite publication namespace: %w", err)
		}
	}
	if err := syncPath(partial); err != nil {
		return fmt.Errorf("sync verified SQLite partial %s: %w", partial, err)
	}
	if hook, ok := ctx.Value(backupPublishHookKey{}).(func() error); ok {
		if err := hook(); err != nil {
			return fmt.Errorf("prepare SQLite publication fault: %w", err)
		}
	}
	for _, sidecar := range []string{target + "-wal", target + "-shm"} {
		if _, err := os.Lstat(sidecar); err == nil {
			return fmt.Errorf("%w (verified partial retained at %s)", ErrTargetExists, partial)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect SQLite publication sidecar: %w", err)
		}
	}
	if err := renameNoReplace(partial, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w (verified partial retained at %s)", ErrTargetExists, partial)
		}
		return fmt.Errorf("publish SQLite target (verified partial retained at %s): %w", partial, err)
	}
	if err := syncPath(filepath.Dir(target)); err != nil {
		return fmt.Errorf("SQLite target published but directory sync failed: %w", err)
	}
	return nil
}

func syncPath(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func openBackupDatabase(path string, readOnly bool) (*sql.DB, error) {
	connector, err := sqlitedriver.NewConnector(sqliteFileURI(path, readOnly))
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func sqliteFileURI(path string, readOnly bool) string {
	return sqliteFileURIWithTimeout(path, readOnly, defaultBusyTimeout)
}

func sqliteFileURIWithTimeout(path string, readOnly bool, busyTimeout time.Duration) string {
	query := url.Values{}
	query.Set("_busy_timeout", strconv.FormatInt(busyTimeout.Milliseconds(), 10))
	query.Set("_foreign_keys", "on")
	query.Set("_dqs", "false")
	query.Add("_pragma", "trusted_schema(OFF)")
	if readOnly {
		query.Set("mode", "ro")
		query.Add("_pragma", "query_only(ON)")
	}
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: query.Encode()}).String()
}

func equalBackupManifest(left, right BackupManifest) bool {
	return left.FormatVersion == right.FormatVersion && left.CreatedAt.Equal(right.CreatedAt) &&
		left.DatabaseBytes == right.DatabaseBytes && left.DatabaseSHA256 == right.DatabaseSHA256 &&
		equalSnapshotIdentity(left, right)
}

func equalSnapshotIdentity(left, right BackupManifest) bool {
	if left.ApplicationID != right.ApplicationID || left.SchemaVersion != right.SchemaVersion ||
		left.SchemaChecksum != right.SchemaChecksum || left.SQLiteVersion != right.SQLiteVersion ||
		left.SQLiteSourceID != right.SQLiteSourceID || len(left.AuthorityStreams) != len(right.AuthorityStreams) {
		return false
	}
	leftStreams := append([]BackupAuthorityStream(nil), left.AuthorityStreams...)
	rightStreams := append([]BackupAuthorityStream(nil), right.AuthorityStreams...)
	sort.Slice(leftStreams, func(i, j int) bool { return authorityStreamKey(leftStreams[i]) < authorityStreamKey(leftStreams[j]) })
	sort.Slice(rightStreams, func(i, j int) bool { return authorityStreamKey(rightStreams[i]) < authorityStreamKey(rightStreams[j]) })
	for index := range leftStreams {
		if leftStreams[index] != rightStreams[index] {
			return false
		}
	}
	return true
}

func authorityStreamKey(stream BackupAuthorityStream) string {
	var key bytes.Buffer
	key.WriteString(stream.ScopeKind)
	key.WriteByte(0)
	key.WriteString(stream.ScopeID)
	key.WriteByte(0)
	key.WriteString(stream.AuthorityEpoch)
	return key.String()
}
