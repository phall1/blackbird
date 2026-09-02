package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sqlitedriver "modernc.org/sqlite"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	ApplicationID             = 0x42424d4c
	SchemaVersion             = 6
	DriverVersion             = "v1.56.0"
	SQLiteVersion             = "3.53.3"
	SQLiteSourceID            = "2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62"
	defaultBusyTimeout        = 5 * time.Second
	maximumBusyTimeout        = 30 * time.Second
	passiveCheckpointInterval = time.Minute
	schemaChecksumHex         = "2d8ee10115bb382ce8068d6d92dbeb62deaf1cf7c9badd1bfba30a3518157806"
	schemaV1ChecksumHex       = "370ba0de329fa9fdf77d027d2ebc85be6747a28bd79ad4ba892fe8884eb3622a"
	schemaV2ChecksumHex       = "2e0c68a7f203a9c245aed614b5586c4136bd2d1a6764fc8ca3f69e89522ba975"
	schemaV3ChecksumHex       = "608aa68c86abf1092ec5900ec2b03aecce9b4d3a5284ab7b7f072be0b3d1df6e"
	schemaV4ChecksumHex       = "78700880f092ecb28b261bcab7fa71d2755062a047d3c4ad51f8c426253f3427"
	schemaV5ChecksumHex       = "3ffd7c6bc3139822119815c2fa417d8ad8fd209b41522d87a9284142274e3cb4"
)

// migrationRung is one step of the upgrade ladder: the embedded migration that
// carries a database to this rung's version, the hex-encoded schema checksum the
// database must hash to once that migration has run, and any state a migration
// cannot express in DDL.
type migrationRung struct {
	migrationID    string
	schemaChecksum string
	seed           func(context.Context, *sql.Tx) error
}

// migrationLadder is the whole upgrade path, rung index k taking a database from
// schema version k to k+1. Every version this build knows therefore converges on
// SchemaVersion by replaying only the rungs it has not run, which is what stops a
// machine that skipped releases from dead-ending on a schema it can never leave.
// The array length is SchemaVersion so that bumping the version without adding a
// rung fails to compile rather than deleting an upgrade path. A new rung must
// also widen the schema_manifest version CHECK, since every rung records the
// version it reached.
var migrationLadder = [SchemaVersion]migrationRung{
	{migrationID: "0001_w0.sql", schemaChecksum: schemaV1ChecksumHex},
	{migrationID: "0002_w2_coordination.sql", schemaChecksum: schemaV2ChecksumHex},
	{migrationID: "0003_local_coordination.sql", schemaChecksum: schemaV3ChecksumHex},
	{migrationID: "0004_coordination_event_journal.sql", schemaChecksum: schemaV4ChecksumHex, seed: seedCoordinationCursorKey},
	{migrationID: "0005_drop_outbox_jobs.sql", schemaChecksum: schemaV5ChecksumHex},
	{migrationID: "0006_conversation_slugs.sql", schemaChecksum: schemaChecksumHex},
}

var migrationIDs = ladderMigrationIDs()

var (
	ErrInvalidConfiguration = errors.New("invalid SQLite configuration")
	ErrEngineMismatch       = errors.New("SQLite engine mismatch")
	ErrSchemaMismatch       = errors.New("SQLite schema mismatch")
	// ErrSchemaFromFuture and ErrSchemaUnknown separate the two directions a
	// version can be wrong, because the remedies are opposite: a database from a
	// newer build is fixed by upgrading Blackbird, while a version no rung
	// describes can only be restored or recreated. Both wrap ErrSchemaMismatch so
	// callers that only care that the schema is unusable keep working.
	ErrSchemaFromFuture    = errors.New("SQLite database was written by a newer Blackbird")
	ErrSchemaUnknown       = errors.New("SQLite schema version is not on the migration ladder")
	ErrCommitIndeterminate = errors.New("SQLite commit outcome is indeterminate")
	errSecurityNoCommit    = errors.New("SQLite security transaction requires rollback")

	//go:embed migrations/*.sql
	migrations embed.FS
	openStores = struct {
		sync.Mutex
		paths map[string]struct{}
	}{paths: make(map[string]struct{})}
)

type Config struct {
	Path string
	// ReadPoolSize bounds concurrent SQLite work. Zero derives the default from
	// runtime.NumCPU so the daemon scales with the machine instead of carrying a
	// fixed process-wide ceiling.
	ReadPoolSize int
}

type Diagnostics struct {
	DriverVersion          string
	DriverVerified         bool
	SQLiteVersion          string
	SQLiteSourceID         string
	CompileOptions         []string
	JournalMode            string
	ForeignKeys            bool
	Synchronous            string
	BusyTimeout            time.Duration
	BackwardClockTolerance time.Duration
	TrustedSchema          bool
	ExtensionLoading       bool
	FullFSync              bool
	CheckpointFSync        bool
	ApplicationID          int
	SchemaVersion          int
	SchemaChecksum         [sha256.Size]byte
	UncleanCheckRan        bool
}

type Store struct {
	db               *sql.DB
	path             string
	readPoolSize     int
	writes           writeArbiter
	heartbeats       heartbeatLedger
	securityLane     chan struct{}
	diagnostics      Diagnostics
	checkpointCancel context.CancelFunc
	checkpointDone   chan struct{}
	closeOnce        sync.Once
	closeErr         error
	releasePath      func()
}

// heartbeatLedger remembers when each open session's liveness was last written
// down, so authentication can skip the write on the overwhelming majority of
// calls. It is deliberately process-local and deliberately forgotten on
// restart: it can only ever suppress a heartbeat, so losing it makes the next
// call write one, and nothing here can make a session look alive.
type heartbeatLedger struct {
	sync.Mutex
	flushed map[string]time.Time
}

var _ application.CoordinationStore = (*Store)(nil)
var _ application.LocalCoordinationStore = (*Store)(nil)

type writeArbiter struct {
	sync.Mutex
	active          bool
	securityWaiting int
	changed         chan struct{}
}

func Open(ctx context.Context, config Config) (*Store, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(config.Path), 0o700); err != nil {
		return nil, fmt.Errorf("%w: create database directory: %v", ErrInvalidConfiguration, err)
	}
	canonicalDirectory, err := filepath.EvalSymlinks(filepath.Dir(config.Path))
	if err != nil {
		return nil, fmt.Errorf("%w: resolve database directory: %v", ErrInvalidConfiguration, err)
	}
	config.Path = filepath.Join(canonicalDirectory, filepath.Base(config.Path))
	if info, err := os.Lstat(config.Path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, fmt.Errorf("%w: database path is not a regular file", ErrInvalidConfiguration)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: inspect database path: %v", ErrInvalidConfiguration, err)
	}
	releasePath, err := claimProcessPath(config.Path)
	if err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			releasePath()
		}
	}()

	dsn := databaseURL(config)
	connector, err := sqlitedriver.NewConnector(dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: construct driver: %v", ErrInvalidConfiguration, err)
	}
	readPoolSize := configuredReadPoolSize(config)
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(readPoolSize)
	db.SetMaxIdleConns(readPoolSize)
	db.SetConnMaxLifetime(0)
	store := &Store{
		db: db, path: config.Path, readPoolSize: readPoolSize,
		securityLane: make(chan struct{}, 1), releasePath: releasePath,
	}
	store.writes.changed = make(chan struct{})
	store.securityLane <- struct{}{}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open SQLite: %w", err)
	}
	if err := os.Chmod(config.Path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: secure database permissions: %v", ErrInvalidConfiguration, err)
	}
	if err := store.initializeOrVerify(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	uncleanCheckRan, err := store.claimRuntime(ctx)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	diagnostics, err := store.inspect(ctx)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.verifyPhysicalConnections(ctx, diagnostics.BusyTimeout); err != nil {
		_ = db.Close()
		return nil, err
	}
	diagnostics.UncleanCheckRan = uncleanCheckRan
	store.diagnostics = diagnostics
	store.startPassiveCheckpoints()
	opened = true
	return store, nil
}

func (store *Store) startPassiveCheckpoints() {
	ctx, cancel := context.WithCancel(context.Background())
	store.checkpointCancel = cancel
	store.checkpointDone = make(chan struct{})
	go func() {
		defer close(store.checkpointDone)
		passiveCheckpointLoop(ctx, passiveCheckpointInterval, func(ctx context.Context) {
			_, _ = store.Checkpoint(ctx, CheckpointPassive)
		})
	}()
}

func passiveCheckpointLoop(ctx context.Context, interval time.Duration, checkpoint func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			checkpoint(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func claimProcessPath(path string) (func(), error) {
	openStores.Lock()
	defer openStores.Unlock()
	if _, present := openStores.paths[path]; present {
		return nil, fmt.Errorf("%w: database already owned by this process", ErrInvalidConfiguration)
	}
	openStores.paths[path] = struct{}{}
	return func() {
		openStores.Lock()
		delete(openStores.paths, path)
		openStores.Unlock()
	}, nil
}

func (store *Store) claimRuntime(ctx context.Context) (bool, error) {
	unclean := false
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		var clean int
		if err := tx.QueryRowContext(ctx,
			"SELECT clean_shutdown FROM database_runtime WHERE singleton = 1",
		).Scan(&clean); err != nil {
			return fmt.Errorf("read SQLite runtime state: %w", err)
		}
		unclean = clean == 0
		if unclean {
			if err := verifyIntegrity(ctx, tx, false); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE database_runtime SET clean_shutdown = 0, opened_at_us = CAST(unixepoch('subsec') * 1000000 AS INTEGER), closed_at_us = NULL WHERE singleton = 1",
		); err != nil {
			return fmt.Errorf("claim SQLite runtime: %w", err)
		}
		return nil
	})
	return unclean, err
}

func verifyIntegrity(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, full bool) error {
	pragma := "PRAGMA quick_check(1)"
	if full {
		pragma = "PRAGMA integrity_check"
	}
	var result string
	if err := query.QueryRowContext(ctx, pragma).Scan(&result); err != nil {
		return fmt.Errorf("run SQLite integrity check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("%w: integrity check=%q", ErrSchemaMismatch, result)
	}
	rows, err := query.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("run SQLite foreign-key check: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		var table string
		var rowID int64
		var parent string
		var constraint sql.NullInt64
		if err := rows.Scan(&table, &rowID, &parent, &constraint); err != nil {
			return fmt.Errorf("run SQLite foreign-key check: %w", err)
		}
		return fmt.Errorf("%w: foreign-key check failed table=%s rowid=%d parent=%s", ErrSchemaMismatch, table, rowID, parent)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("run SQLite foreign-key check: %w", err)
	}
	return nil
}

func validateConfig(config Config) error {
	if config.Path == "" || !filepath.IsAbs(config.Path) || config.ReadPoolSize < 0 {
		return ErrInvalidConfiguration
	}
	clean := filepath.Clean(config.Path)
	if clean != config.Path || filepath.Ext(clean) == "" {
		return ErrInvalidConfiguration
	}
	return nil
}

func configuredReadPoolSize(config Config) int {
	if config.ReadPoolSize > 0 {
		return config.ReadPoolSize
	}
	return runtime.NumCPU()
}

func databaseURL(config Config) string {
	query := url.Values{}
	query.Set("_busy_timeout", strconv.FormatInt(defaultBusyTimeout.Milliseconds(), 10))
	query.Set("_foreign_keys", "on")
	query.Set("_journal_mode", "wal")
	query.Set("_synchronous", "full")
	query.Set("_txlock", "immediate")
	query.Set("_dqs", "false")
	query.Add("_pragma", "trusted_schema(OFF)")
	query.Add("_pragma", "fullfsync(ON)")
	query.Add("_pragma", "checkpoint_fullfsync(ON)")
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(config.Path), RawQuery: query.Encode()}).String()
}

func (store *Store) initializeOrVerify(ctx context.Context) error {
	var applicationID, schemaVersion, objectCount int
	if err := store.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil {
		return fmt.Errorf("inspect SQLite application id: %w", err)
	}
	if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&schemaVersion); err != nil {
		return fmt.Errorf("inspect SQLite schema version: %w", err)
	}
	if err := store.db.QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
	).Scan(&objectCount); err != nil {
		return fmt.Errorf("inspect SQLite schema: %w", err)
	}
	if applicationID == 0 && schemaVersion == 0 && objectCount == 0 {
		if err := store.climbMigrationLadder(ctx, 0); err != nil {
			return err
		}
		return store.verifyMigrationLedger(ctx)
	}
	if applicationID != ApplicationID {
		return fmt.Errorf("%w: %w: application_id=%d want=%d",
			ErrSchemaMismatch, ErrSchemaUnknown, applicationID, ApplicationID)
	}
	switch {
	case schemaVersion > SchemaVersion:
		// Downgrade stays fail-closed: this build cannot know what the newer one
		// wrote, and guessing would corrupt data it cannot even read.
		return fmt.Errorf("%w: %w: user_version=%d, this build understands up to %d",
			ErrSchemaMismatch, ErrSchemaFromFuture, schemaVersion, SchemaVersion)
	case schemaVersion < 1:
		return fmt.Errorf("%w: %w: user_version=%d", ErrSchemaMismatch, ErrSchemaUnknown, schemaVersion)
	case schemaVersion < SchemaVersion:
		if err := store.climbMigrationLadder(ctx, schemaVersion); err != nil {
			return err
		}
	}
	return store.verifyMigrationLedger(ctx)
}

// climbMigrationLadder brings a database at fromVersion up to SchemaVersion in a
// single transaction, so a machine that skipped releases converges in one open
// rather than dead-ending. fromVersion 0 is an empty database; any other value
// must already be exactly the schema that rung left behind, which is proved
// before the first new rung runs.
func (store *Store) climbMigrationLadder(ctx context.Context, fromVersion int) error {
	return store.withImmediate(ctx, func(tx *sql.Tx) error {
		if fromVersion > 0 {
			if err := verifyMigrationLedgerVersion(ctx, tx, migrationIDs[:fromVersion], fromVersion,
				migrationLadder[fromVersion-1].expectedSchema()); err != nil {
				return err
			}
		}
		for offset, rung := range migrationLadder[fromVersion:] {
			if err := applyMigrationRung(ctx, tx, rung, fromVersion+offset+1); err != nil {
				return err
			}
		}
		if fromVersion == 0 {
			if _, err := tx.ExecContext(ctx, "PRAGMA application_id = "+strconv.Itoa(ApplicationID)); err != nil {
				return fmt.Errorf("set SQLite application id: %w", err)
			}
		}
		return nil
	})
}

// applyMigrationRung runs one rung and proves the result before recording it. The
// ledger it writes is append-only by trigger, so every rung a database climbs
// leaves its own row rather than rewriting the previous one.
func applyMigrationRung(ctx context.Context, tx *sql.Tx, rung migrationRung, version int) error {
	body, checksum, err := migration(rung.migrationID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(body)); err != nil {
		return fmt.Errorf("apply SQLite migration %s: %w", rung.migrationID, err)
	}
	if rung.seed != nil {
		if err := rung.seed(ctx, tx); err != nil {
			return err
		}
	}
	liveChecksum, err := schemaChecksum(ctx, tx)
	if err != nil {
		return err
	}
	expectedChecksum := rung.expectedSchema()
	if liveChecksum != expectedChecksum {
		return fmt.Errorf("%w: schema checksum after migration %s=%x want=%x",
			ErrSchemaMismatch, rung.migrationID, liveChecksum, expectedChecksum)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_manifest(schema_version, checksum) VALUES (?, ?)", version, liveChecksum[:],
	); err != nil {
		return fmt.Errorf("record SQLite schema manifest: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations(migration_id, checksum, applied_at_us, state) VALUES (?, ?, CAST(unixepoch('subsec') * 1000000 AS INTEGER), 'applied')",
		rung.migrationID, checksum[:],
	); err != nil {
		return fmt.Errorf("record SQLite migration %s: %w", rung.migrationID, err)
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(version)); err != nil {
		return fmt.Errorf("set SQLite schema version: %w", err)
	}
	return nil
}

// seedCoordinationCursorKey supplies the one row the coordination event journal
// needs and DDL cannot express, so the rung that creates the table also fills it.
func seedCoordinationCursorKey(ctx context.Context, tx *sql.Tx) error {
	key := make([]byte, sha256.Size)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate SQLite coordination cursor key: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO coordination_event_cursor_keys(singleton, key, created_at_us)
		VALUES (1, ?, CAST(unixepoch('subsec') * 1000000 AS INTEGER))`, key); err != nil {
		return fmt.Errorf("initialize SQLite coordination cursor key: %w", err)
	}
	return nil
}

func (rung migrationRung) expectedSchema() [sha256.Size]byte {
	return expectedSchemaChecksumHex(rung.schemaChecksum)
}

func ladderMigrationIDs() []string {
	ids := make([]string, len(migrationLadder))
	for index, rung := range migrationLadder {
		ids[index] = rung.migrationID
	}
	return ids
}

func migration(migrationID string) ([]byte, [sha256.Size]byte, error) {
	body, err := migrations.ReadFile("migrations/" + migrationID)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("read embedded SQLite migration: %w", err)
	}
	return body, sha256.Sum256(body), nil
}

func (store *Store) verifyMigrationLedger(ctx context.Context) error {
	for _, migrationID := range migrationIDs {
		_, expected, err := migration(migrationID)
		if err != nil {
			return err
		}
		var checksum []byte
		var state string
		if err := store.db.QueryRowContext(ctx,
			"SELECT checksum, state FROM schema_migrations WHERE migration_id = ?", migrationID,
		).Scan(&checksum, &state); err != nil {
			return fmt.Errorf("%w: migration ledger: %v", ErrSchemaMismatch, err)
		}
		if !bytes.Equal(checksum, expected[:]) || state != "applied" {
			return fmt.Errorf("%w: migration %s checksum or state", ErrSchemaMismatch, migrationID)
		}
	}
	var migrationCount int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&migrationCount); err != nil || migrationCount != len(migrationIDs) {
		return fmt.Errorf("%w: migration ledger count=%d error=%v", ErrSchemaMismatch, migrationCount, err)
	}
	expectedSchema := expectedSchemaChecksum()
	var recordedSchema []byte
	if err := store.db.QueryRowContext(ctx,
		"SELECT checksum FROM schema_manifest WHERE schema_version = ?", SchemaVersion,
	).Scan(&recordedSchema); err != nil || !bytes.Equal(recordedSchema, expectedSchema[:]) {
		return fmt.Errorf("%w: schema manifest error=%v", ErrSchemaMismatch, err)
	}
	liveSchema, err := schemaChecksum(ctx, store.db)
	if err != nil {
		return err
	}
	if liveSchema != expectedSchema {
		return fmt.Errorf("%w: live schema checksum=%x want=%x", ErrSchemaMismatch, liveSchema, expectedSchema)
	}
	return nil
}

func expectedSchemaChecksum() [sha256.Size]byte {
	return expectedSchemaChecksumHex(schemaChecksumHex)
}

func expectedSchemaChecksumHex(value string) [sha256.Size]byte {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		panic("invalid compiled SQLite schema checksum")
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return result
}

func verifyMigrationLedgerVersion(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, ids []string, version int, expectedSchema [sha256.Size]byte) error {
	for _, migrationID := range ids {
		_, expected, err := migration(migrationID)
		if err != nil {
			return err
		}
		var checksum []byte
		var state string
		if err := query.QueryRowContext(ctx, `SELECT checksum, state FROM schema_migrations WHERE migration_id = ?`,
			migrationID).Scan(&checksum, &state); err != nil || !bytes.Equal(checksum, expected[:]) || state != "applied" {
			return fmt.Errorf("%w: migration %s checksum, state, or presence", ErrSchemaMismatch, migrationID)
		}
	}
	var count int
	if err := query.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil || count != len(ids) {
		return fmt.Errorf("%w: migration ledger count=%d error=%v", ErrSchemaMismatch, count, err)
	}
	var recorded []byte
	if err := query.QueryRowContext(ctx, `SELECT checksum FROM schema_manifest WHERE schema_version = ?`, version).
		Scan(&recorded); err != nil || !bytes.Equal(recorded, expectedSchema[:]) {
		return fmt.Errorf("%w: prior schema manifest error=%v", ErrSchemaMismatch, err)
	}
	live, err := schemaChecksum(ctx, query)
	if err != nil {
		return err
	}
	if live != expectedSchema {
		return fmt.Errorf("%w: prior live schema checksum=%x want=%x", ErrSchemaMismatch, live, expectedSchema)
	}
	return nil
}

func schemaChecksum(ctx context.Context, query interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([sha256.Size]byte, error) {
	rows, err := query.QueryContext(ctx,
		"SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
	)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("read SQLite schema manifest: %w", err)
	}
	defer func() { _ = rows.Close() }()
	hash := sha256.New()
	_, _ = hash.Write([]byte("blackbird.sqlite-schema/v1\x00"))
	for rows.Next() {
		var objectType, name, table, statement string
		if err := rows.Scan(&objectType, &name, &table, &statement); err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("read SQLite schema object: %w", err)
		}
		for _, value := range []string{objectType, name, table, statement} {
			var size [8]byte
			binary.BigEndian.PutUint64(size[:], uint64(len(value)))
			_, _ = hash.Write(size[:])
			_, _ = hash.Write([]byte(value))
		}
	}
	if err := rows.Err(); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("read SQLite schema manifest: %w", err)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func (store *Store) inspect(ctx context.Context) (Diagnostics, error) {
	driverVersion, driverVerified, err := linkedDriverVersion()
	if err != nil {
		return Diagnostics{}, err
	}
	result := Diagnostics{
		DriverVersion: driverVersion, DriverVerified: driverVerified,
		BackwardClockTolerance: time.Duration(backwardClockToleranceMicros) * time.Microsecond,
	}
	var foreignKeys, trustedSchema, extensionLoading, fullFSync, checkpointFSync int
	var busyMilliseconds int64
	if err := store.db.QueryRowContext(ctx,
		"SELECT sqlite_version(), sqlite_source_id(), sqlite_compileoption_used('ENABLE_LOAD_EXTENSION')",
	).Scan(&result.SQLiteVersion, &result.SQLiteSourceID, &extensionLoading); err != nil {
		return Diagnostics{}, fmt.Errorf("inspect SQLite engine: %w", err)
	}
	queries := []struct {
		name string
		dest any
	}{
		{"journal_mode", &result.JournalMode}, {"foreign_keys", &foreignKeys},
		{"synchronous", &result.Synchronous}, {"busy_timeout", &busyMilliseconds},
		{"trusted_schema", &trustedSchema}, {"application_id", &result.ApplicationID},
		{"user_version", &result.SchemaVersion}, {"fullfsync", &fullFSync},
		{"checkpoint_fullfsync", &checkpointFSync},
	}
	for _, query := range queries {
		if err := store.db.QueryRowContext(ctx, "PRAGMA "+query.name).Scan(query.dest); err != nil {
			return Diagnostics{}, fmt.Errorf("inspect SQLite %s: %w", query.name, err)
		}
	}
	rows, err := store.db.QueryContext(ctx, "PRAGMA compile_options")
	if err != nil {
		return Diagnostics{}, fmt.Errorf("inspect SQLite compile options: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var option string
		if err := rows.Scan(&option); err != nil {
			return Diagnostics{}, fmt.Errorf("inspect SQLite compile option: %w", err)
		}
		result.CompileOptions = append(result.CompileOptions, option)
	}
	if err := rows.Err(); err != nil {
		return Diagnostics{}, fmt.Errorf("inspect SQLite compile options: %w", err)
	}
	sort.Strings(result.CompileOptions)
	result.SchemaChecksum = expectedSchemaChecksum()
	result.ForeignKeys = foreignKeys == 1
	result.TrustedSchema = trustedSchema == 1
	result.ExtensionLoading = extensionLoading == 1
	result.FullFSync = fullFSync == 1
	result.CheckpointFSync = checkpointFSync == 1
	result.BusyTimeout = time.Duration(busyMilliseconds) * time.Millisecond
	if result.SQLiteVersion != SQLiteVersion || result.SQLiteSourceID != SQLiteSourceID {
		return Diagnostics{}, fmt.Errorf("%w: version=%q source_id=%q", ErrEngineMismatch, result.SQLiteVersion, result.SQLiteSourceID)
	}
	if mismatches := diagnosticInvariantMismatches(result); len(mismatches) > 0 {
		return Diagnostics{}, fmt.Errorf("%w: %s", ErrSchemaMismatch, strings.Join(mismatches, ", "))
	}
	return result, nil
}

func (store *Store) verifyPhysicalConnections(ctx context.Context, busyTimeout time.Duration) error {
	connections := make([]*sql.Conn, 0, store.readPoolSize)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range store.readPoolSize {
		connection, err := store.db.Conn(ctx)
		if err != nil {
			return fmt.Errorf("acquire SQLite connection for verification: %w", err)
		}
		connections = append(connections, connection)
	}
	for _, connection := range connections {
		var version, sourceID, journalMode, synchronous string
		var foreignKeys, trustedSchema, fullFSync, checkpointFSync int
		var busyMilliseconds int64
		if err := connection.QueryRowContext(ctx,
			"SELECT sqlite_version(), sqlite_source_id()",
		).Scan(&version, &sourceID); err != nil {
			return fmt.Errorf("verify SQLite connection engine: %w", err)
		}
		checks := []struct {
			name string
			dest any
		}{
			{"journal_mode", &journalMode}, {"foreign_keys", &foreignKeys}, {"synchronous", &synchronous},
			{"busy_timeout", &busyMilliseconds}, {"trusted_schema", &trustedSchema}, {"fullfsync", &fullFSync},
			{"checkpoint_fullfsync", &checkpointFSync},
		}
		for _, check := range checks {
			if err := connection.QueryRowContext(ctx, "PRAGMA "+check.name).Scan(check.dest); err != nil {
				return fmt.Errorf("verify SQLite connection %s: %w", check.name, err)
			}
		}
		if mismatches := physicalInvariantMismatches(version, sourceID, journalMode, synchronous, foreignKeys,
			busyMilliseconds, trustedSchema, fullFSync, checkpointFSync, busyTimeout); len(mismatches) > 0 {
			return fmt.Errorf("%w: %s", ErrEngineMismatch, strings.Join(mismatches, ", "))
		}
	}
	return nil
}

func diagnosticInvariantMismatches(result Diagnostics) []string {
	mismatches := make([]string, 0, 10)
	if !strings.EqualFold(result.JournalMode, "wal") {
		mismatches = append(mismatches, invariantMismatch("journal_mode", result.JournalMode, "wal"))
	}
	if !result.ForeignKeys {
		mismatches = append(mismatches, invariantMismatch("foreign_keys", result.ForeignKeys, true))
	}
	if result.Synchronous != "2" {
		mismatches = append(mismatches, invariantMismatch("synchronous", result.Synchronous, "2"))
	}
	if result.BusyTimeout <= 0 || result.BusyTimeout > maximumBusyTimeout {
		mismatches = append(mismatches, fmt.Sprintf("busy_timeout=%s want (0,%s]", result.BusyTimeout, maximumBusyTimeout))
	}
	if result.TrustedSchema {
		mismatches = append(mismatches, invariantMismatch("trusted_schema", result.TrustedSchema, false))
	}
	if result.ExtensionLoading {
		mismatches = append(mismatches, invariantMismatch("extension_loading", result.ExtensionLoading, false))
	}
	if !result.FullFSync {
		mismatches = append(mismatches, invariantMismatch("fullfsync", result.FullFSync, true))
	}
	if !result.CheckpointFSync {
		mismatches = append(mismatches, invariantMismatch("checkpoint_fullfsync", result.CheckpointFSync, true))
	}
	if result.ApplicationID != ApplicationID {
		mismatches = append(mismatches, invariantMismatch("application_id", result.ApplicationID, ApplicationID))
	}
	if result.SchemaVersion != SchemaVersion {
		mismatches = append(mismatches, invariantMismatch("user_version", result.SchemaVersion, SchemaVersion))
	}
	return mismatches
}

func physicalInvariantMismatches(version, sourceID, journalMode, synchronous string,
	foreignKeys int, busyMilliseconds int64, trustedSchema, fullFSync, checkpointFSync int,
	busyTimeout time.Duration) []string {
	mismatches := make([]string, 0, 9)
	checks := []struct {
		name string
		got  any
		want any
		bad  bool
	}{
		{"sqlite_version", version, SQLiteVersion, version != SQLiteVersion},
		{"sqlite_source_id", sourceID, SQLiteSourceID, sourceID != SQLiteSourceID},
		{"journal_mode", journalMode, "wal", !strings.EqualFold(journalMode, "wal")},
		{"foreign_keys", foreignKeys, 1, foreignKeys != 1},
		{"synchronous", synchronous, "2", synchronous != "2"},
		{"busy_timeout", time.Duration(busyMilliseconds) * time.Millisecond, busyTimeout,
			time.Duration(busyMilliseconds)*time.Millisecond != busyTimeout},
		{"trusted_schema", trustedSchema, 0, trustedSchema != 0},
		{"fullfsync", fullFSync, 1, fullFSync != 1},
		{"checkpoint_fullfsync", checkpointFSync, 1, checkpointFSync != 1},
	}
	for _, check := range checks {
		if check.bad {
			mismatches = append(mismatches, invariantMismatch(check.name, check.got, check.want))
		}
	}
	return mismatches
}

func invariantMismatch(name string, got, want any) string {
	return fmt.Sprintf("%s=%v want %v", name, got, want)
}

func linkedDriverVersion() (string, bool, error) {
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return DriverVersion, false, nil
	}
	for _, dependency := range build.Deps {
		if dependency.Path != "modernc.org/sqlite" {
			continue
		}
		version := dependency.Version
		if dependency.Replace != nil {
			version = dependency.Replace.Version
		}
		if version != DriverVersion {
			return "", false, fmt.Errorf("%w: driver version=%q", ErrEngineMismatch, version)
		}
		return version, true, nil
	}
	// Go test binaries can omit dependency records. The exact linked SQLite
	// source ID remains independently enforced above.
	return DriverVersion, false, nil
}

func (store *Store) withImmediate(ctx context.Context, apply func(*sql.Tx) error) error {
	return store.withImmediatePriority(ctx, false, apply)
}

func (store *Store) withImmediatePriority(
	ctx context.Context,
	security bool,
	apply func(*sql.Tx) error,
) error {
	if err := store.acquireWrite(ctx, security); err != nil {
		return err
	}
	defer store.releaseWrite()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin SQLite immediate transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := apply(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		if ctx.Err() == nil && !errors.Is(err, sql.ErrTxDone) {
			return fmt.Errorf("%w: %v", ErrCommitIndeterminate, err)
		}
		return fmt.Errorf("commit SQLite transaction: %w", err)
	}
	return nil
}

func (store *Store) acquireWrite(ctx context.Context, security bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	registered := false
	for {
		store.writes.Lock()
		if security && !registered {
			store.writes.securityWaiting++
			registered = true
		}
		if !store.writes.active && (security || store.writes.securityWaiting == 0) {
			store.writes.active = true
			if security {
				store.writes.securityWaiting--
			}
			store.writes.Unlock()
			return nil
		}
		changed := store.writes.changed
		store.writes.Unlock()
		select {
		case <-ctx.Done():
			if registered {
				store.writes.Lock()
				store.writes.securityWaiting--
				store.signalWriteChange()
				store.writes.Unlock()
			}
			return ctx.Err()
		case <-changed:
		}
	}
}

func (store *Store) releaseWrite() {
	store.writes.Lock()
	store.writes.active = false
	store.signalWriteChange()
	store.writes.Unlock()
}

func (store *Store) signalWriteChange() {
	close(store.writes.changed)
	store.writes.changed = make(chan struct{})
}

// ExecuteSecurity runs the closed security-only transaction family through a
// lane reserved independently from ordinary command admission.
func (store *Store) ExecuteSecurity(
	ctx context.Context,
	spec application.SecuritySpec,
	decide func(application.SecurityContext) (application.SecurityDecision, error),
) (execution application.SecurityExecution, executionErr error) {
	if !spec.Operation().Valid() || decide == nil {
		return application.SecurityExecution{}, application.ErrInvalidSecuritySpec
	}
	select {
	case <-ctx.Done():
		return application.SecurityExecution{}, ctx.Err()
	case <-store.securityLane:
	}
	defer func() { store.securityLane <- struct{}{} }()
	defer func() {
		if recovered := recover(); recovered != nil {
			execution = application.SecurityExecution{}
			executionErr = fmt.Errorf("SQLite security callback panic: %v", recovered)
		}
	}()

	err := store.withImmediatePriority(ctx, true, func(tx *sql.Tx) error {
		locked, state, err := store.lockSecurityContext(ctx, tx, spec)
		if err != nil {
			return err
		}
		decision, err := decide(locked)
		if err != nil {
			return err
		}
		if err := application.ValidateSecurityDecision(locked, decision); err != nil {
			return err
		}
		execution, err = store.applySecurityDecision(ctx, tx, state, decision)
		if err != nil {
			return err
		}
		switch decision.Kind() {
		case application.SecurityDecisionRollback, application.SecurityDecisionReplay,
			application.SecurityDecisionSuppressDenial:
			return errSecurityNoCommit
		default:
			return nil
		}
	})
	if errors.Is(err, errSecurityNoCommit) {
		return execution, nil
	}
	if err != nil {
		return application.SecurityExecution{}, err
	}
	return execution, nil
}

type lockedSecurityState struct {
	spec          application.SecuritySpec
	authorityTime time.Time
	guardDigest   domain.AuthorizationDigest
	invitation    domain.InstallationInvitationState
	stream        securityStream
	admission     application.DenialAdmission
}

type securityStream struct {
	nextAudit uint64
	auditHead application.Digest
	timeFloor int64
}

func (store *Store) lockSecurityContext(
	ctx context.Context,
	tx *sql.Tx,
	spec application.SecuritySpec,
) (application.SecurityContext, lockedSecurityState, error) {
	state := lockedSecurityState{spec: spec}
	var wallMicros int64
	if err := tx.QueryRowContext(ctx, "SELECT CAST(unixepoch('subsec') * 1000000 AS INTEGER)").Scan(&wallMicros); err != nil {
		return application.SecurityContext{}, state, fmt.Errorf("read SQLite authority time: %w", err)
	}

	if spec.Operation() == application.SecurityInitializeInstallation {
		var initialized int
		if err := tx.QueryRowContext(ctx,
			"SELECT count(*) FROM scope_guards WHERE scope_kind = 'installation'",
		).Scan(&initialized); err != nil {
			return application.SecurityContext{}, state, fmt.Errorf("read SQLite initialization guard: %w", err)
		}
		if initialized != 0 {
			return application.SecurityContext{}, state, fmt.Errorf("%w: installation already initialized", application.ErrInvalidSecurityContext)
		}
		state.authorityTime = microsTime(wallMicros)
	} else {
		var authorityID, epoch string
		var generation uint64
		if err := tx.QueryRowContext(ctx, `SELECT authority_id, authority_epoch, guard_generation
			FROM scope_guards WHERE scope_kind = ? AND scope_id = ?`,
			string(spec.Scope().Kind()), spec.Scope().ID(),
		).Scan(&authorityID, &epoch, &generation); err != nil {
			return application.SecurityContext{}, state, fmt.Errorf("lock SQLite security admission: %w", err)
		}
		if authorityID != spec.AuthorityID().String() || epoch != spec.AuthorityEpoch().String() ||
			generation != spec.AdmissionGeneration().Uint64() {
			return application.SecurityContext{}, state, application.ErrInvalidSecurityContext
		}
		var nextAudit int64
		var auditHead []byte
		if err := tx.QueryRowContext(ctx, `SELECT next_audit_sequence, audit_head_hash, authority_time_floor_us
			FROM authority_streams WHERE scope_kind = ? AND scope_id = ? AND authority_epoch = ?`,
			string(spec.Scope().Kind()), spec.Scope().ID(), spec.AuthorityEpoch().String(),
		).Scan(&nextAudit, &auditHead, &state.stream.timeFloor); err != nil {
			return application.SecurityContext{}, state, fmt.Errorf("lock SQLite authority stream: %w", err)
		}
		if nextAudit <= 0 || len(auditHead) != sha256.Size {
			return application.SecurityContext{}, state, application.ErrInvalidSecurityContext
		}
		state.stream.nextAudit = uint64(nextAudit)
		copy(state.stream.auditHead[:], auditHead)
		if wallMicros <= state.stream.timeFloor {
			wallMicros = state.stream.timeFloor + 1
		}
		state.authorityTime = microsTime(wallMicros)
	}

	digestBytes := sha256.Sum256([]byte("blackbird.sqlite-security-guard/v1\x00" +
		string(spec.Operation()) + "\x00" + string(spec.Scope().Kind()) + "\x00" + spec.Scope().ID() + "\x00" +
		spec.AuthorityID().String() + "\x00" + spec.AuthorityEpoch().String() + "\x00" +
		strconv.FormatUint(spec.AdmissionGeneration().Uint64(), 10)))
	guardDigest, err := domain.NewAuthorizationDigest(digestBytes)
	if err != nil {
		return application.SecurityContext{}, state, err
	}
	state.guardDigest = guardDigest

	var attempt application.SecurityAttemptResolution
	switch spec.Operation() {
	case application.SecurityResumeBootstrapGeneration, application.SecurityRecordBootstrapDenial:
		invitation, err := loadInvitation(ctx, tx, spec)
		if err != nil {
			return application.SecurityContext{}, state, err
		}
		state.invitation = invitation
		if spec.Operation() == application.SecurityRecordBootstrapDenial {
			attempt = application.FreshSecurityAttempt()
			fingerprint, _ := spec.AttemptFingerprint()
			expectation, _ := spec.InvitationExpectation()
			var version uint64
			var deniedAt int64
			err = tx.QueryRowContext(ctx, `SELECT occurrence_count, first_recorded_at_us FROM security_denials
				WHERE record_kind = 'bootstrap' AND subject_id = ? AND denial_fingerprint = ? AND bucket = 0`,
				expectation.Target().ID(), fingerprint[:],
			).Scan(&version, &deniedAt)
			if err == nil {
				record, recordErr := application.NewSecurityDenialRecord(
					invitation.ID(), fingerprint, mustVersion(version), microsTime(deniedAt),
				)
				if recordErr != nil {
					return application.SecurityContext{}, state, recordErr
				}
				attempt, err = application.ReplaySecurityAttempt(record)
				if err != nil {
					return application.SecurityContext{}, state, err
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return application.SecurityContext{}, state, fmt.Errorf("resolve SQLite bootstrap denial: %w", err)
			}
		}
	case application.SecurityRecordCommandDenial:
		admission, err := commandDenialAdmission(ctx, tx, spec, state.authorityTime)
		if err != nil {
			return application.SecurityContext{}, state, err
		}
		state.admission = admission
	}

	locked, err := application.NewSecurityContext(
		spec, state.authorityTime, state.invitation, attempt, state.admission, state.guardDigest,
	)
	return locked, state, err
}

func loadInvitation(
	ctx context.Context,
	tx *sql.Tx,
	spec application.SecuritySpec,
) (domain.InstallationInvitationState, error) {
	expectation, present := spec.InvitationExpectation()
	if !present {
		return domain.InstallationInvitationState{}, application.ErrInvalidSecurityContext
	}
	var id, installationID, publicKey, generation, status string
	var verifier []byte
	var failures int
	var expiresMicros, version uint64
	err := tx.QueryRowContext(ctx, `SELECT invitation_id, installation_id, installation_public_key_reference,
		invitation_verifier, bootstrap_generation_id, status, failed_attempts, expires_at_us, version
		FROM installation_invitations WHERE invitation_id = ? AND installation_id = ?`,
		expectation.Target().ID(), spec.Scope().ID(),
	).Scan(&id, &installationID, &publicKey, &verifier, &generation, &status, &failures, &expiresMicros, &version)
	if err != nil {
		return domain.InstallationInvitationState{}, fmt.Errorf("load SQLite invitation: %w", err)
	}
	invitationID, err := domain.ParseInvitationID(id)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	installation, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	key, err := domain.NewPublicKeyReference(publicKey)
	if err != nil || len(verifier) != sha256.Size || failures < 0 || failures > 255 {
		return domain.InstallationInvitationState{}, application.ErrInvalidSecurityContext
	}
	bootstrapGeneration, err := domain.ParseBootstrapGenerationID(generation)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	domainVersion, err := domain.NewVersion(version)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	var fingerprint domain.CommandFingerprint
	copy(fingerprint[:], verifier)
	return domain.RehydrateInstallationInvitation(domain.InstallationInvitationRehydrationParams{
		ID: invitationID, InstallationID: installation, InstallationPublicKey: key,
		InvitationVerifier: fingerprint, BootstrapGenerationID: bootstrapGeneration,
		ExpiresAt: microsTime(int64(expiresMicros)), FailedAttempts: uint8(failures),
		Status: domain.InstallationInvitationStatus(status), Version: domainVersion,
	})
}

func commandDenialAdmission(
	ctx context.Context,
	tx *sql.Tx,
	spec application.SecuritySpec,
	authorityTime time.Time,
) (application.DenialAdmission, error) {
	draft, present := spec.CommandDenial()
	if !present {
		return application.DenialAdmission{}, application.ErrInvalidSecurityContext
	}
	bucket := authorityTime.Unix() / 60
	subjectKind, subjectID := denialSubjectKey(draft.Subject())
	denialFingerprint := draft.DenialFingerprint()
	var duplicate int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM security_denials
		WHERE record_kind = 'command' AND scope_kind = ? AND scope_id = ?
		AND subject_kind = ? AND subject_id = ? AND operation = ? AND operation_major = ?
		AND denial_class = ? AND bucket = ? AND denial_fingerprint = ?`,
		string(spec.Scope().Kind()), spec.Scope().ID(), subjectKind, subjectID, draft.Operation().String(),
		draft.OperationMajor().Uint16(), string(draft.Class()), bucket, denialFingerprint[:],
	).Scan(&duplicate); err != nil {
		return application.DenialAdmission{}, err
	}
	var distinct, scopeEntries int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM security_denials WHERE record_kind = 'command'
		AND scope_kind = ? AND scope_id = ? AND subject_kind = ? AND subject_id = ?
		AND operation = ? AND operation_major = ? AND denial_class = ? AND bucket = ?`,
		string(spec.Scope().Kind()), spec.Scope().ID(), subjectKind, subjectID,
		draft.Operation().String(), draft.OperationMajor().Uint16(), string(draft.Class()), bucket,
	).Scan(&distinct); err != nil {
		return application.DenialAdmission{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM security_denials WHERE record_kind = 'command'
		AND scope_kind = ? AND scope_id = ? AND bucket = ?`,
		string(spec.Scope().Kind()), spec.Scope().ID(), bucket,
	).Scan(&scopeEntries); err != nil {
		return application.DenialAdmission{}, err
	}
	if distinct > application.MaxDistinctDenialsPerMinute {
		distinct = application.MaxDistinctDenialsPerMinute
	}
	if scopeEntries > application.MaxDenialEntriesPerScopeMinute {
		scopeEntries = application.MaxDenialEntriesPerScopeMinute
	}
	kind := application.DenialAdmitDistinct
	switch {
	case duplicate != 0:
		kind = application.DenialSuppressDuplicate
	case scopeEntries == application.MaxDenialEntriesPerScopeMinute:
		var summary int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM security_denials WHERE record_kind = 'command'
			AND scope_kind = ? AND scope_id = ? AND bucket = ? AND reason = 'denial_scope_saturated'`,
			string(spec.Scope().Kind()), spec.Scope().ID(), bucket,
		).Scan(&summary); err != nil {
			return application.DenialAdmission{}, err
		}
		if summary == 0 {
			kind = application.DenialAdmitScopeSaturation
		} else {
			kind = application.DenialSuppressScopeSaturated
		}
	case distinct == application.MaxDistinctDenialsPerMinute:
		var summary int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM security_denials WHERE record_kind = 'command'
			AND scope_kind = ? AND scope_id = ? AND subject_kind = ? AND subject_id = ?
			AND operation = ? AND operation_major = ? AND denial_class = ? AND bucket = ?
			AND reason = 'denial_bucket_saturated'`,
			string(spec.Scope().Kind()), spec.Scope().ID(), subjectKind, subjectID,
			draft.Operation().String(), draft.OperationMajor().Uint16(), string(draft.Class()), bucket,
		).Scan(&summary); err != nil {
			return application.DenialAdmission{}, err
		}
		if summary == 0 {
			kind = application.DenialAdmitSaturation
		} else {
			kind = application.DenialSuppressSaturated
		}
	}
	return application.NewDenialAdmission(kind, authorityTime, uint8(distinct), uint16(scopeEntries))
}

func denialSubjectKey(subject application.DenialSubject) (string, string) {
	if source, present := subject.SourceDigest(); present {
		return string(subject.Kind()), hex.EncodeToString(source[:])
	}
	value := subject.PrincipalID().String()
	if device, present := subject.DeviceID(); present {
		value += ":" + device.String()
	}
	return string(subject.Kind()), value
}

func (store *Store) applySecurityDecision(
	ctx context.Context,
	tx *sql.Tx,
	state lockedSecurityState,
	decision application.SecurityDecision,
) (application.SecurityExecution, error) {
	spec := state.spec
	switch decision.Kind() {
	case application.SecurityDecisionRollback:
		rejection, _ := decision.Rejection()
		return application.RejectedSecurityExecution(spec.Operation(), rejection)
	case application.SecurityDecisionReplay:
		record, _ := decision.Denial()
		return application.ReplayedDenialSecurityExecution(record)
	case application.SecurityDecisionSuppressDenial:
		return application.CommandDenialSecurityExecution(false), nil
	}

	if spec.Operation() == application.SecurityInitializeInstallation {
		if err := store.initializeSecurityState(ctx, tx, state, decision); err != nil {
			return application.SecurityExecution{}, err
		}
		state.stream = securityStream{nextAudit: 1, timeFloor: timeMicros(state.authorityTime)}
	} else {
		if err := store.compareAndSwapSecurityState(ctx, tx, state, decision); err != nil {
			return application.SecurityExecution{}, err
		}
	}
	audit, present := decision.Audit()
	if !present {
		return application.SecurityExecution{}, application.ErrInvalidSecurityDecision
	}
	if err := appendSecurityAudit(ctx, tx, state, audit); err != nil {
		return application.SecurityExecution{}, err
	}

	switch decision.Kind() {
	case application.SecurityDecisionInitialize, application.SecurityDecisionGeneration:
		return application.AppliedSecurityExecution(spec.Operation())
	case application.SecurityDecisionDeny:
		record, _ := decision.Denial()
		return application.CommittedDenialSecurityExecution(record)
	case application.SecurityDecisionAuditDenial:
		return application.CommandDenialSecurityExecution(true), nil
	default:
		return application.SecurityExecution{}, application.ErrInvalidSecurityDecision
	}
}

func (store *Store) initializeSecurityState(
	ctx context.Context,
	tx *sql.Tx,
	state lockedSecurityState,
	decision application.SecurityDecision,
) error {
	spec := state.spec
	invitation, present := decision.Invitation()
	if !present {
		return application.ErrInvalidSecurityDecision
	}
	oldGeneration, newGeneration, generationChange := decision.Generations()
	if generationChange || !oldGeneration.IsZero() || !newGeneration.IsZero() {
		return application.ErrInvalidSecurityDecision
	}
	streamDigest, err := streamGenesis(spec)
	if err != nil {
		return err
	}
	nowMicros := timeMicros(state.authorityTime)
	if _, err := tx.ExecContext(ctx, `INSERT INTO scope_guards(
		scope_kind, scope_id, authority_id, authority_epoch, bootstrap_generation_id,
		write_status, guard_generation, updated_at_us
	) VALUES (?, ?, ?, ?, ?, 'open', ?, ?)`,
		string(spec.Scope().Kind()), spec.Scope().ID(), spec.AuthorityID().String(), spec.AuthorityEpoch().String(),
		invitation.BootstrapGenerationID().String(), spec.AdmissionGeneration().Uint64(), nowMicros,
	); err != nil {
		return fmt.Errorf("insert SQLite installation guard: %w", err)
	}
	streamBytes := streamDigest.Bytes()
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_streams(
		scope_kind, scope_id, authority_id, authority_epoch, next_sequence, retained_from_sequence,
		digest_algorithm, head_digest, next_audit_sequence, audit_head_hash, authority_time_floor_us
	) VALUES (?, ?, ?, ?, 1, 1, 'sha-256', ?, 1, zeroblob(32), ?)`,
		string(spec.Scope().Kind()), spec.Scope().ID(), spec.AuthorityID().String(), spec.AuthorityEpoch().String(),
		streamBytes[:], nowMicros,
	); err != nil {
		return fmt.Errorf("insert SQLite authority stream: %w", err)
	}
	return insertInvitation(ctx, tx, invitation, state.authorityTime)
}

func streamGenesis(spec application.SecuritySpec) (domain.StreamDigest, error) {
	authorityID, err := application.NewCanonicalIdentifier(spec.AuthorityID().String())
	if err != nil {
		return domain.StreamDigest{}, err
	}
	epoch, err := application.NewCanonicalIdentifier(spec.AuthorityEpoch().String())
	if err != nil {
		return domain.StreamDigest{}, err
	}
	scopeID, err := application.NewCanonicalIdentifier(spec.Scope().ID())
	if err != nil {
		return domain.StreamDigest{}, err
	}
	kind := application.StreamScopeInstallation
	if spec.Scope().Kind() == domain.ScopeKindWorkspace {
		kind = application.StreamScopeWorkspace
	}
	view, err := application.NewStreamGenesisViewV1(authorityID, epoch, kind, scopeID, nil)
	if err != nil {
		return domain.StreamDigest{}, err
	}
	return application.NewProductionCanonicalCodec().HashStreamGenesis(view)
}

func insertInvitation(
	ctx context.Context,
	tx *sql.Tx,
	invitation domain.InstallationInvitationState,
	recordedAt time.Time,
) error {
	verifier := invitation.InvitationVerifier()
	createdAt := invitation.ExpiresAt().Add(-domain.BootstrapInvitationLifetime)
	updatedAt := recordedAt
	if createdAt.After(updatedAt) {
		updatedAt = createdAt
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO installation_invitations(
		invitation_id, installation_id, authority_id, authority_epoch, bootstrap_generation_id,
		installation_public_key_reference, invitation_verifier, status, failed_attempts, expires_at_us,
		version, created_at_us, updated_at_us
	) SELECT ?, ?, authority_id, authority_epoch, ?, ?, ?, ?, ?, ?, ?, ?, ?
		FROM scope_guards WHERE scope_kind = 'installation' AND scope_id = ?`,
		invitation.ID().String(), invitation.InstallationID().String(), invitation.BootstrapGenerationID().String(),
		invitation.InstallationPublicKey().String(), verifier[:], string(invitation.Status()), invitation.FailedAttempts(),
		timeMicros(invitation.ExpiresAt()), invitation.Version().Uint64(), timeMicros(createdAt), timeMicros(updatedAt),
		invitation.InstallationID().String(),
	); err != nil {
		return fmt.Errorf("insert SQLite installation invitation: %w", err)
	}
	return nil
}

func (store *Store) compareAndSwapSecurityState(
	ctx context.Context,
	tx *sql.Tx,
	state lockedSecurityState,
	decision application.SecurityDecision,
) error {
	spec := state.spec
	nowMicros := timeMicros(state.authorityTime)
	var result sql.Result
	var err error
	switch decision.Kind() {
	case application.SecurityDecisionGeneration:
		oldGeneration, newGeneration, _ := decision.Generations()
		if spec.Operation() == application.SecurityRotateBootstrapGeneration {
			result, err = tx.ExecContext(ctx, `UPDATE scope_guards SET bootstrap_generation_id = ?, updated_at_us = ?
				WHERE scope_kind = ? AND scope_id = ? AND authority_id = ? AND authority_epoch = ?
				AND guard_generation = ? AND bootstrap_generation_id = ?`,
				newGeneration.String(), nowMicros, string(spec.Scope().Kind()), spec.Scope().ID(),
				spec.AuthorityID().String(), spec.AuthorityEpoch().String(), spec.AdmissionGeneration().Uint64(),
				oldGeneration.String(),
			)
		} else {
			expectation, _ := spec.InvitationExpectation()
			expectedVersion, _ := expectation.Version()
			result, err = tx.ExecContext(ctx, `UPDATE installation_invitations
				SET bootstrap_generation_id = ?, updated_at_us = ?
				WHERE invitation_id = ? AND installation_id = ? AND authority_epoch = ?
				AND bootstrap_generation_id = ? AND version = ?
				AND EXISTS (SELECT 1 FROM scope_guards WHERE scope_kind = ? AND scope_id = ?
					AND authority_id = ? AND authority_epoch = ? AND guard_generation = ?
					AND bootstrap_generation_id = ?)`,
				newGeneration.String(), nowMicros, expectation.Target().ID(), spec.Scope().ID(), spec.AuthorityEpoch().String(),
				oldGeneration.String(), expectedVersion.Uint64(), string(spec.Scope().Kind()), spec.Scope().ID(),
				spec.AuthorityID().String(), spec.AuthorityEpoch().String(), spec.AdmissionGeneration().Uint64(),
				newGeneration.String(),
			)
		}
	case application.SecurityDecisionDeny:
		invitation, _ := decision.Invitation()
		result, err = tx.ExecContext(ctx, `UPDATE installation_invitations
			SET status = ?, failed_attempts = ?, version = ?, updated_at_us = ?
			WHERE invitation_id = ? AND installation_id = ? AND authority_epoch = ? AND version = ?
			AND EXISTS (SELECT 1 FROM scope_guards WHERE scope_kind = ? AND scope_id = ?
				AND authority_id = ? AND authority_epoch = ? AND guard_generation = ?)`,
			string(invitation.Status()), invitation.FailedAttempts(), invitation.Version().Uint64(), nowMicros,
			invitation.ID().String(), invitation.InstallationID().String(), spec.AuthorityEpoch().String(),
			state.invitation.Version().Uint64(), string(spec.Scope().Kind()), spec.Scope().ID(),
			spec.AuthorityID().String(), spec.AuthorityEpoch().String(), spec.AdmissionGeneration().Uint64(),
		)
		if err == nil {
			record, _ := decision.Denial()
			fingerprint := record.AttemptFingerprint()
			_, err = tx.ExecContext(ctx, `INSERT INTO security_denials(
				record_kind, denial_fingerprint, scope_kind, scope_id, subject_kind, subject_id,
				denial_class, reason, bucket, occurrence_count, first_recorded_at_us, last_recorded_at_us
			) VALUES ('bootstrap', ?, ?, ?, 'invitation', ?, 'authentication',
				'bootstrap_proof_rejected', 0, ?, ?, ?)`,
				fingerprint[:], string(spec.Scope().Kind()), spec.Scope().ID(), record.InvitationID().String(),
				record.InvitationVersion().Uint64(), timeMicros(record.DeniedAt()), timeMicros(record.DeniedAt()),
			)
		}
	case application.SecurityDecisionAuditDenial:
		result, err = store.insertCommandDenial(ctx, tx, state, decision)
	default:
		return application.ErrInvalidSecurityDecision
	}
	if err != nil {
		return fmt.Errorf("apply SQLite security decision: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return fmt.Errorf("%w: SQLite security compare-and-swap", application.ErrInvalidSecurityContext)
	}
	return nil
}

func (store *Store) insertCommandDenial(
	ctx context.Context,
	tx *sql.Tx,
	state lockedSecurityState,
	decision application.SecurityDecision,
) (sql.Result, error) {
	record, present := decision.CommandDenialAudit()
	if !present {
		return nil, application.ErrInvalidSecurityDecision
	}
	draft := record.Draft()
	subjectKind, subjectID := denialSubjectKey(draft.Subject())
	reason := draft.SafeReason()
	if record.Variant() == application.CommandDenialAuditSubjectSaturation {
		reason = "denial_bucket_saturated"
	} else if record.Variant() == application.CommandDenialAuditScopeSaturation {
		reason = "denial_scope_saturated"
	}
	fingerprint := draft.DenialFingerprint()
	nowMicros := timeMicros(state.authorityTime)
	return tx.ExecContext(ctx, `INSERT INTO security_denials(
		record_kind, denial_fingerprint, scope_kind, scope_id, subject_kind, subject_id,
		operation, operation_major, denial_class, reason, bucket, occurrence_count,
		first_recorded_at_us, last_recorded_at_us
	) SELECT 'command', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?
	WHERE EXISTS (SELECT 1 FROM scope_guards WHERE scope_kind = ? AND scope_id = ?
		AND authority_id = ? AND authority_epoch = ? AND guard_generation = ?)`,
		fingerprint[:], string(state.spec.Scope().Kind()), state.spec.Scope().ID(), subjectKind, subjectID,
		draft.Operation().String(), draft.OperationMajor().Uint16(), string(draft.Class()), reason,
		record.MinuteBucket(), nowMicros, nowMicros,
		string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.spec.AuthorityID().String(),
		state.spec.AuthorityEpoch().String(), state.spec.AdmissionGeneration().Uint64(),
	)
}

func appendSecurityAudit(
	ctx context.Context,
	tx *sql.Tx,
	state lockedSecurityState,
	intent application.AuditIntent,
) error {
	view, err := application.NewAuditEntryViewV1(application.AuditEntryParams{
		ChainScopeID: state.spec.Scope(), Sequence: state.stream.nextAudit,
		AuthorityID: state.spec.AuthorityID(), AuthorityEpoch: state.spec.AuthorityEpoch(),
		RecordedAt: state.authorityTime, Intent: intent, PreviousEntryHash: state.stream.auditHead,
	})
	if err != nil {
		return fmt.Errorf("materialize SQLite security audit: %w", err)
	}
	canonical, digest, err := application.NewProductionCanonicalCodec().EncodeAuditEntry(view)
	if err != nil {
		return fmt.Errorf("encode SQLite security audit: %w", err)
	}
	if err := application.NewProductionCanonicalCodec().VerifyAuditEntry(state.stream.auditHead, canonical, digest); err != nil {
		return fmt.Errorf("verify SQLite security audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_entries(
		scope_kind, scope_id, audit_sequence, previous_entry_hash, entry_hash, canonical_entry, recorded_at_us
	) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		string(state.spec.Scope().Kind()), state.spec.Scope().ID(), state.stream.nextAudit,
		state.stream.auditHead[:], digest[:], canonical, timeMicros(state.authorityTime),
	); err != nil {
		return fmt.Errorf("insert SQLite security audit: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE authority_streams
		SET next_audit_sequence = next_audit_sequence + 1, audit_head_hash = ?, authority_time_floor_us = ?
		WHERE scope_kind = ? AND scope_id = ? AND authority_epoch = ?
		AND next_audit_sequence = ? AND audit_head_hash = ? AND authority_time_floor_us = ?`,
		digest[:], timeMicros(state.authorityTime), string(state.spec.Scope().Kind()), state.spec.Scope().ID(),
		state.spec.AuthorityEpoch().String(), state.stream.nextAudit, state.stream.auditHead[:], state.stream.timeFloor,
	)
	if err != nil {
		return fmt.Errorf("advance SQLite security audit head: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return fmt.Errorf("%w: SQLite audit-head compare-and-swap", application.ErrInvalidSecurityContext)
	}
	return nil
}

func microsTime(value int64) time.Time {
	return time.UnixMicro(value).UTC()
}

func timeMicros(value time.Time) int64 {
	return value.UTC().UnixMicro()
}

func mustVersion(value uint64) domain.Version {
	version, err := domain.NewVersion(value)
	if err != nil {
		return domain.Version{}
	}
	return version
}

func (store *Store) Diagnostics() Diagnostics {
	result := store.diagnostics
	result.CompileOptions = append([]string(nil), result.CompileOptions...)
	return result
}

func (store *Store) IntegrityCheck(ctx context.Context) error {
	return verifyIntegrity(ctx, store.db, true)
}

func (store *Store) Path() string { return store.path }

func (store *Store) Close() error {
	store.closeOnce.Do(func() {
		store.checkpointCancel()
		<-store.checkpointDone
		ctx, cancel := context.WithTimeout(context.Background(), defaultBusyTimeout)
		defer cancel()
		if err := store.withImmediate(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx,
				"UPDATE database_runtime SET clean_shutdown = 1, closed_at_us = CAST(unixepoch('subsec') * 1000000 AS INTEGER) WHERE singleton = 1",
			); err != nil {
				return fmt.Errorf("release SQLite runtime: %w", err)
			}
			return nil
		}); err != nil {
			store.closeErr = err
		}
		if err := store.db.Close(); err != nil && store.closeErr == nil {
			store.closeErr = err
		}
		store.releasePath()
	})
	return store.closeErr
}
