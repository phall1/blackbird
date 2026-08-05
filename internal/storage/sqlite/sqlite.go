package sqlite

import (
	"bytes"
	"context"
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
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sqlitedriver "modernc.org/sqlite"
)

const (
	ApplicationID       = 0x42424d4c
	SchemaVersion       = 1
	DriverVersion       = "v1.56.0"
	SQLiteVersion       = "3.53.3"
	SQLiteSourceID      = "2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62"
	defaultBusyTimeout  = 5 * time.Second
	maximumBusyTimeout  = 30 * time.Second
	initialMigrationID  = "0001_w0.sql"
	maximumReadPoolSize = 5
	schemaChecksumHex   = "c8649fdd8d9ad175fe0d31cd4bb9fa371e345d7a0d9d802ec77f8fba592e3f7c"
)

var (
	ErrInvalidConfiguration = errors.New("invalid SQLite configuration")
	ErrEngineMismatch       = errors.New("SQLite engine mismatch")
	ErrSchemaMismatch       = errors.New("SQLite schema mismatch")

	//go:embed migrations/*.sql
	migrations embed.FS
	openStores = struct {
		sync.Mutex
		paths map[string]struct{}
	}{paths: make(map[string]struct{})}
)

type Config struct {
	Path        string
	BusyTimeout time.Duration
}

type Diagnostics struct {
	DriverVersion    string
	DriverVerified   bool
	SQLiteVersion    string
	SQLiteSourceID   string
	CompileOptions   []string
	JournalMode      string
	ForeignKeys      bool
	Synchronous      string
	BusyTimeout      time.Duration
	TrustedSchema    bool
	ExtensionLoading bool
	FullFSync        bool
	CheckpointFSync  bool
	ApplicationID    int
	SchemaVersion    int
	SchemaChecksum   [sha256.Size]byte
	UncleanCheckRan  bool
}

type Store struct {
	db          *sql.DB
	path        string
	writeLane   chan struct{}
	diagnostics Diagnostics
	closeOnce   sync.Once
	closeErr    error
	releasePath func()
}

func Open(ctx context.Context, config Config) (*Store, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if config.BusyTimeout == 0 {
		config.BusyTimeout = defaultBusyTimeout
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
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(maximumReadPoolSize)
	db.SetMaxIdleConns(maximumReadPoolSize)
	db.SetConnMaxLifetime(0)
	store := &Store{db: db, path: config.Path, writeLane: make(chan struct{}, 1), releasePath: releasePath}
	store.writeLane <- struct{}{}
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
	opened = true
	return store, nil
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
		return fmt.Errorf("%w: foreign-key check failed", ErrSchemaMismatch)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("run SQLite foreign-key check: %w", err)
	}
	return nil
}

func validateConfig(config Config) error {
	if config.Path == "" || !filepath.IsAbs(config.Path) || config.BusyTimeout < 0 ||
		config.BusyTimeout > maximumBusyTimeout || config.BusyTimeout%time.Millisecond != 0 {
		return ErrInvalidConfiguration
	}
	clean := filepath.Clean(config.Path)
	if clean != config.Path || filepath.Ext(clean) == "" {
		return ErrInvalidConfiguration
	}
	return nil
}

func databaseURL(config Config) string {
	query := url.Values{}
	query.Set("_busy_timeout", strconv.FormatInt(config.BusyTimeout.Milliseconds(), 10))
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
		return store.applyInitialMigration(ctx)
	}
	if applicationID != ApplicationID || schemaVersion != SchemaVersion {
		return fmt.Errorf("%w: application_id=%d user_version=%d", ErrSchemaMismatch, applicationID, schemaVersion)
	}
	return store.verifyMigrationLedger(ctx)
}

func (store *Store) applyInitialMigration(ctx context.Context) error {
	body, checksum, err := initialMigration()
	if err != nil {
		return err
	}
	return store.withImmediate(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("apply SQLite migration %s: %w", initialMigrationID, err)
		}
		liveChecksum, err := schemaChecksum(ctx, tx)
		if err != nil {
			return err
		}
		expectedChecksum := expectedSchemaChecksum()
		if liveChecksum != expectedChecksum {
			return fmt.Errorf("%w: embedded schema checksum=%x want=%x", ErrSchemaMismatch, liveChecksum, expectedChecksum)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_manifest(schema_version, checksum) VALUES (?, ?)", SchemaVersion, liveChecksum[:],
		); err != nil {
			return fmt.Errorf("record SQLite schema manifest: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations(migration_id, checksum, applied_at_us, state) VALUES (?, ?, CAST(unixepoch('subsec') * 1000000 AS INTEGER), 'applied')",
			initialMigrationID, checksum[:],
		); err != nil {
			return fmt.Errorf("record SQLite migration %s: %w", initialMigrationID, err)
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA application_id = "+strconv.Itoa(ApplicationID)); err != nil {
			return fmt.Errorf("set SQLite application id: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(SchemaVersion)); err != nil {
			return fmt.Errorf("set SQLite schema version: %w", err)
		}
		return nil
	})
}

func initialMigration() ([]byte, [sha256.Size]byte, error) {
	body, err := migrations.ReadFile("migrations/" + initialMigrationID)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("read embedded SQLite migration: %w", err)
	}
	return body, sha256.Sum256(body), nil
}

func (store *Store) verifyMigrationLedger(ctx context.Context) error {
	_, expected, err := initialMigration()
	if err != nil {
		return err
	}
	var checksum []byte
	var state string
	if err := store.db.QueryRowContext(ctx,
		"SELECT checksum, state FROM schema_migrations WHERE migration_id = ?", initialMigrationID,
	).Scan(&checksum, &state); err != nil {
		return fmt.Errorf("%w: migration ledger: %v", ErrSchemaMismatch, err)
	}
	if !bytes.Equal(checksum, expected[:]) || state != "applied" {
		return fmt.Errorf("%w: migration %s checksum or state", ErrSchemaMismatch, initialMigrationID)
	}
	var migrationCount int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&migrationCount); err != nil || migrationCount != 1 {
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
	decoded, err := hex.DecodeString(schemaChecksumHex)
	if err != nil || len(decoded) != sha256.Size {
		panic("invalid compiled SQLite schema checksum")
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return result
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
	result := Diagnostics{DriverVersion: driverVersion, DriverVerified: driverVerified}
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
	if !strings.EqualFold(result.JournalMode, "wal") || !result.ForeignKeys || result.Synchronous != "2" ||
		result.BusyTimeout <= 0 || result.BusyTimeout > maximumBusyTimeout || result.TrustedSchema ||
		result.ExtensionLoading || !result.FullFSync || !result.CheckpointFSync ||
		result.ApplicationID != ApplicationID || result.SchemaVersion != SchemaVersion {
		return Diagnostics{}, fmt.Errorf("%w: connection or schema invariants", ErrSchemaMismatch)
	}
	return result, nil
}

func (store *Store) verifyPhysicalConnections(ctx context.Context, busyTimeout time.Duration) error {
	connections := make([]*sql.Conn, 0, maximumReadPoolSize)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range maximumReadPoolSize {
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
		if version != SQLiteVersion || sourceID != SQLiteSourceID || !strings.EqualFold(journalMode, "wal") ||
			foreignKeys != 1 || synchronous != "2" || time.Duration(busyMilliseconds)*time.Millisecond != busyTimeout ||
			trustedSchema != 0 || fullFSync != 1 || checkpointFSync != 1 {
			return fmt.Errorf("%w: physical connection invariants", ErrEngineMismatch)
		}
	}
	return nil
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
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-store.writeLane:
	}
	defer func() { store.writeLane <- struct{}{} }()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin SQLite immediate transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := apply(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit SQLite transaction: %w", err)
	}
	return nil
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
