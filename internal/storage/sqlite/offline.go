package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	sqlitedriver "modernc.org/sqlite"
)

type ReadMode string

const (
	ReadModeLive  ReadMode = "live"
	ReadModeStale ReadMode = "stale"
)

const (
	readerForeignKeyFailureLimit = 20
	readerStaleSessionWindow     = 24 * time.Hour
	walHeaderBytes               = 32
	walFrameHeaderBytes          = 24
)

var ErrReaderUnavailable = errors.New("SQLite reader cannot open the database")

var readerCoordinationTables = [...]string{"coordination_projects", "coordination_agents",
	"coordination_agent_sessions", "conversations", "messages", "message_deliveries", "leases",
	"lease_selectors", "coordination_events"}

type ReaderConfig struct {
	Path       string
	AllowStale bool
}

type Reader struct {
	db   *sql.DB
	path string
	mode ReadMode
}

type SchemaState struct {
	ApplicationID    int
	SchemaVersion    int
	ExpectedVersion  int
	ExpectedAppID    int
	LiveChecksum     [sha256.Size]byte
	ExpectedChecksum [sha256.Size]byte
	ManifestVersions []int
	ManifestMatches  bool
	Migrations       []MigrationRow
	LedgerComplete   bool
	ObjectCount      int
	Supported        bool
}

type MigrationRow struct {
	ID        string
	State     string
	AppliedAt time.Time
	Matches   bool
}

type RuntimeState struct {
	Present       bool
	CleanShutdown bool
	OpenedAt      time.Time
	ClosedAt      time.Time
}

type StorageState struct {
	DatabaseBytes     int64
	DatabaseMode      os.FileMode
	DatabaseUID       uint32
	DirectoryMode     os.FileMode
	DirectoryUID      uint32
	WALBytes          int64
	WALFrames         int64
	SharedMemoryBytes int64
	PageSize          int64
	PageCount         int64
	AutoCheckpoint    int64
	JournalMode       string
	FreeBytes         uint64
}

type IntegrityState struct {
	QuickCheck         string
	ForeignKeyFailures []ForeignKeyFailure
	Truncated          bool
}

type ForeignKeyFailure struct {
	Table  string
	RowID  int64
	Parent string
}

type CoordinationState struct {
	Projects                 int
	Agents                   int
	AgentsInLargestProject   int
	LargestProjectKey        string
	Conversations            int
	Messages                 int
	Events                   int
	Leases                   int
	ActiveLeases             int
	ExpiredActiveLeases      int
	Deliveries               int
	UnreadDeliveries         int
	UnacknowledgedDeliveries int
	OpenSessions             int
	StaleOpenSessions        int
}

// OpenReader opens an existing database for diagnostics only: no directory or
// permission repair, no migration, and no database_runtime claim. The default
// mode is mode=ro plus query_only(ON), never immutable=1 — an immutable handle
// bypasses the write-ahead log and silently reports a database that is behind
// the daemon by the whole uncheckpointed WAL, which is exactly the pathology
// this reader exists to measure. mode=ro is still not a promise that nothing on
// disk changes: SQLite creates and updates the -shm wal-index for any WAL
// reader. What it guarantees is that no database content is written.
func OpenReader(ctx context.Context, config ReaderConfig) (*Reader, error) {
	if err := validateReaderConfig(config); err != nil {
		return nil, err
	}
	info, err := os.Lstat(config.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReaderUnavailable, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: database path is not a regular file", ErrInvalidConfiguration)
	}
	live, liveErr := openReaderMode(ctx, config.Path, ReadModeLive)
	if liveErr == nil {
		return live, nil
	}
	if !config.AllowStale {
		return nil, liveErr
	}
	stale, staleErr := openReaderMode(ctx, config.Path, ReadModeStale)
	if staleErr != nil {
		return nil, errors.Join(liveErr, staleErr)
	}
	return stale, nil
}

func validateReaderConfig(config ReaderConfig) error {
	if config.Path == "" || !filepath.IsAbs(config.Path) {
		return ErrInvalidConfiguration
	}
	if filepath.Clean(config.Path) != config.Path || filepath.Ext(config.Path) == "" {
		return ErrInvalidConfiguration
	}
	return nil
}

func openReaderMode(ctx context.Context, path string, mode ReadMode) (*Reader, error) {
	dsn := sqliteFileURIWithTimeout(path, true, defaultBusyTimeout)
	if mode == ReadModeStale {
		dsn = staleReaderURI(path)
	}
	connector, err := sqlitedriver.NewConnector(dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReaderUnavailable, err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: %v", ErrReaderUnavailable, err)
	}
	return &Reader{db: db, path: path, mode: mode}, nil
}

func staleReaderURI(path string) string {
	query := url.Values{}
	query.Set("immutable", "1")
	query.Set("_dqs", "false")
	query.Add("_pragma", "trusted_schema(OFF)")
	query.Add("_pragma", "query_only(ON)")
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: query.Encode()}).String()
}

func (reader *Reader) Close() error {
	if err := reader.db.Close(); err != nil {
		return fmt.Errorf("close SQLite reader: %w", err)
	}
	return nil
}

func (reader *Reader) Path() string   { return reader.path }
func (reader *Reader) Mode() ReadMode { return reader.mode }

func (reader *Reader) Schema(ctx context.Context) (SchemaState, error) {
	state := SchemaState{ExpectedVersion: SchemaVersion, ExpectedAppID: ApplicationID,
		ExpectedChecksum: expectedSchemaChecksum()}
	for _, probe := range []struct {
		pragma string
		target *int
	}{
		{"PRAGMA application_id", &state.ApplicationID},
		{"PRAGMA user_version", &state.SchemaVersion},
	} {
		if err := reader.db.QueryRowContext(ctx, probe.pragma).Scan(probe.target); err != nil {
			return SchemaState{}, fmt.Errorf("inspect SQLite schema identity: %w", err)
		}
	}
	if err := reader.db.QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").Scan(&state.ObjectCount); err != nil {
		return SchemaState{}, fmt.Errorf("inspect SQLite schema objects: %w", err)
	}
	checksum, err := schemaChecksum(ctx, reader.db)
	if err != nil {
		return SchemaState{}, err
	}
	state.LiveChecksum = checksum
	present, err := reader.presentTables(ctx)
	if err != nil {
		return SchemaState{}, err
	}
	if present["schema_manifest"] {
		if err := reader.readManifest(ctx, &state); err != nil {
			return SchemaState{}, err
		}
	}
	if present["schema_migrations"] {
		if err := reader.readMigrationLedger(ctx, &state); err != nil {
			return SchemaState{}, err
		}
	}
	state.Supported = state.ApplicationID == ApplicationID && state.SchemaVersion == SchemaVersion
	for _, table := range readerCoordinationTables {
		if !present[table] {
			state.Supported = false
		}
	}
	return state, nil
}

func (reader *Reader) readManifest(ctx context.Context, state *SchemaState) error {
	rows, err := reader.db.QueryContext(ctx,
		"SELECT schema_version, checksum FROM schema_manifest ORDER BY schema_version")
	if err != nil {
		return fmt.Errorf("read SQLite schema manifest: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var version int
		var checksum []byte
		if err := rows.Scan(&version, &checksum); err != nil {
			return fmt.Errorf("read SQLite schema manifest: %w", err)
		}
		state.ManifestVersions = append(state.ManifestVersions, version)
		if version == SchemaVersion && len(checksum) == sha256.Size &&
			[sha256.Size]byte(checksum) == state.ExpectedChecksum {
			state.ManifestMatches = true
		}
	}
	return rows.Err()
}

func (reader *Reader) readMigrationLedger(ctx context.Context, state *SchemaState) error {
	rows, err := reader.db.QueryContext(ctx,
		"SELECT migration_id, checksum, applied_at_us, state FROM schema_migrations ORDER BY migration_id")
	if err != nil {
		return fmt.Errorf("read SQLite migration ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()
	applied := make(map[string]bool, len(migrationIDs))
	for rows.Next() {
		var row MigrationRow
		var checksum []byte
		var appliedAt int64
		if err := rows.Scan(&row.ID, &checksum, &appliedAt, &row.State); err != nil {
			return fmt.Errorf("read SQLite migration ledger: %w", err)
		}
		row.AppliedAt = microsTime(appliedAt)
		if _, expected, migrationErr := migration(row.ID); migrationErr == nil {
			row.Matches = len(checksum) == sha256.Size && [sha256.Size]byte(checksum) == expected
		}
		applied[row.ID] = row.Matches && row.State == "applied"
		state.Migrations = append(state.Migrations, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	state.LedgerComplete = true
	for _, migrationID := range migrationIDs {
		if !applied[migrationID] {
			state.LedgerComplete = false
		}
	}
	return nil
}

func (reader *Reader) Runtime(ctx context.Context) (RuntimeState, error) {
	present, err := reader.presentTables(ctx)
	if err != nil {
		return RuntimeState{}, err
	}
	if !present["database_runtime"] {
		return RuntimeState{}, nil
	}
	var clean int
	var opened int64
	var closed sql.NullInt64
	if err := reader.db.QueryRowContext(ctx,
		"SELECT clean_shutdown, opened_at_us, closed_at_us FROM database_runtime WHERE singleton = 1",
	).Scan(&clean, &opened, &closed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RuntimeState{}, nil
		}
		return RuntimeState{}, fmt.Errorf("read SQLite runtime state: %w", err)
	}
	state := RuntimeState{Present: true, CleanShutdown: clean == 1, OpenedAt: microsTime(opened)}
	if closed.Valid {
		state.ClosedAt = microsTime(closed.Int64)
	}
	return state, nil
}

func (reader *Reader) Storage(ctx context.Context) (StorageState, error) {
	var state StorageState
	for _, probe := range []struct {
		pragma string
		target *int64
	}{
		{"PRAGMA page_size", &state.PageSize},
		{"PRAGMA page_count", &state.PageCount},
		{"PRAGMA wal_autocheckpoint", &state.AutoCheckpoint},
	} {
		if err := reader.db.QueryRowContext(ctx, probe.pragma).Scan(probe.target); err != nil {
			return StorageState{}, fmt.Errorf("inspect SQLite storage pragmas: %w", err)
		}
	}
	if err := reader.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&state.JournalMode); err != nil {
		return StorageState{}, fmt.Errorf("inspect SQLite journal mode: %w", err)
	}
	databaseBytes, databaseMode, databaseUID, err := readerFileFacts(reader.path)
	if err != nil {
		return StorageState{}, err
	}
	state.DatabaseBytes, state.DatabaseMode, state.DatabaseUID = databaseBytes, databaseMode, databaseUID
	_, directoryMode, directoryUID, err := readerFileFacts(filepath.Dir(reader.path))
	if err != nil {
		return StorageState{}, err
	}
	state.DirectoryMode, state.DirectoryUID = directoryMode, directoryUID
	state.WALBytes, _, _, err = readerFileFacts(reader.path + "-wal")
	if err != nil {
		return StorageState{}, err
	}
	state.SharedMemoryBytes, _, _, err = readerFileFacts(reader.path + "-shm")
	if err != nil {
		return StorageState{}, err
	}
	if state.WALBytes > walHeaderBytes && state.PageSize > 0 {
		state.WALFrames = (state.WALBytes - walHeaderBytes) / (state.PageSize + walFrameHeaderBytes)
	}
	free, _, _, err := filesystemStats(reader.path)
	if err != nil {
		return StorageState{}, fmt.Errorf("inspect SQLite filesystem: %w", err)
	}
	state.FreeBytes = free
	return state, nil
}

func readerFileFacts(path string) (int64, os.FileMode, uint32, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, 0, nil
	}
	if err != nil {
		return 0, 0, 0, fmt.Errorf("inspect SQLite path %s: %w", filepath.Base(path), err)
	}
	var owner uint32
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		owner = stat.Uid
	}
	return info.Size(), info.Mode().Perm(), owner, nil
}

// Integrity collects every foreign-key failure instead of stopping at the first
// the way verifyIntegrity does, because the operator's problem is precisely the
// set of rows behind "SQLite schema mismatch: foreign-key check failed".
func (reader *Reader) Integrity(ctx context.Context) (IntegrityState, error) {
	state := IntegrityState{}
	if err := reader.db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&state.QuickCheck); err != nil {
		return IntegrityState{}, fmt.Errorf("run SQLite integrity check: %w", err)
	}
	rows, err := reader.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return IntegrityState{}, fmt.Errorf("run SQLite foreign-key check: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var failure ForeignKeyFailure
		var constraint sql.NullInt64
		if err := rows.Scan(&failure.Table, &failure.RowID, &failure.Parent, &constraint); err != nil {
			return IntegrityState{}, fmt.Errorf("run SQLite foreign-key check: %w", err)
		}
		if len(state.ForeignKeyFailures) == readerForeignKeyFailureLimit {
			state.Truncated = true
			break
		}
		state.ForeignKeyFailures = append(state.ForeignKeyFailures, failure)
	}
	if err := rows.Err(); err != nil {
		return IntegrityState{}, fmt.Errorf("run SQLite foreign-key check: %w", err)
	}
	return state, nil
}

func (reader *Reader) Coordination(ctx context.Context) (CoordinationState, error) {
	present, err := reader.presentTables(ctx)
	if err != nil {
		return CoordinationState{}, err
	}
	now, err := sqliteNow(ctx, reader.db)
	if err != nil {
		return CoordinationState{}, fmt.Errorf("read SQLite reader clock: %w", err)
	}
	nowMicros := timeMicros(now)
	staleCutoff := timeMicros(now.Add(-readerStaleSessionWindow))
	var state CoordinationState
	counts := []struct {
		table     string
		statement string
		arguments []any
		target    *int
	}{
		{"coordination_projects", "SELECT count(*) FROM coordination_projects", nil, &state.Projects},
		{"coordination_agents", "SELECT count(*) FROM coordination_agents", nil, &state.Agents},
		{"conversations", "SELECT count(*) FROM conversations", nil, &state.Conversations},
		{"messages", "SELECT count(*) FROM messages", nil, &state.Messages},
		{"coordination_events", "SELECT count(*) FROM coordination_events", nil, &state.Events},
		{"leases", "SELECT count(*) FROM leases", nil, &state.Leases},
		{"leases", "SELECT count(*) FROM leases WHERE status = 'active' AND expires_at_us > ?",
			[]any{nowMicros}, &state.ActiveLeases},
		{"leases", "SELECT count(*) FROM leases WHERE status = 'active' AND expires_at_us <= ?",
			[]any{nowMicros}, &state.ExpiredActiveLeases},
		{"message_deliveries", "SELECT count(*) FROM message_deliveries", nil, &state.Deliveries},
		{"message_deliveries", "SELECT count(*) FROM message_deliveries WHERE read_at_us IS NULL", nil,
			&state.UnreadDeliveries},
		{"message_deliveries", `SELECT count(*) FROM message_deliveries
			WHERE acknowledgement_required = 1 AND acknowledged_at_us IS NULL`, nil,
			&state.UnacknowledgedDeliveries},
		{"coordination_agent_sessions", "SELECT count(*) FROM coordination_agent_sessions WHERE ended_at_us IS NULL",
			nil, &state.OpenSessions},
		{"coordination_agent_sessions", `SELECT count(*) FROM coordination_agent_sessions
			WHERE ended_at_us IS NULL AND last_seen_at_us < ?`, []any{staleCutoff}, &state.StaleOpenSessions},
	}
	for _, count := range counts {
		if !present[count.table] {
			continue
		}
		if err := reader.db.QueryRowContext(ctx, count.statement, count.arguments...).Scan(count.target); err != nil {
			return CoordinationState{}, fmt.Errorf("count SQLite %s: %w", count.table, err)
		}
	}
	if present["coordination_agents"] {
		var key sql.NullString
		var agents sql.NullInt64
		if err := reader.db.QueryRowContext(ctx, `SELECT project_key, count(*) FROM coordination_agents
			GROUP BY project_key ORDER BY count(*) DESC, project_key LIMIT 1`).Scan(&key, &agents); err != nil &&
			!errors.Is(err, sql.ErrNoRows) {
			return CoordinationState{}, fmt.Errorf("count SQLite coordination_agents: %w", err)
		}
		state.LargestProjectKey, state.AgentsInLargestProject = key.String, int(agents.Int64)
	}
	return state, nil
}

func (reader *Reader) presentTables(ctx context.Context) (map[string]bool, error) {
	rows, err := reader.db.QueryContext(ctx,
		"SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, fmt.Errorf("inspect SQLite tables: %w", err)
	}
	defer func() { _ = rows.Close() }()
	present := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("inspect SQLite tables: %w", err)
		}
		present[name] = true
	}
	return present, rows.Err()
}
