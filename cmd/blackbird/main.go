// Command blackbird is the coordination service and its command-line client.
// This package is one of the two blessed assembly points: it constructs the
// storage, transport, and installation adapters and binds them into the command
// grammar, which itself depends on none of them.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	sqlitedriver "modernc.org/sqlite"

	"github.com/phall1/blackbird/internal/cli"
	"github.com/phall1/blackbird/internal/cli/adminclient"
	"github.com/phall1/blackbird/internal/cli/logsource"
	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/cli/termwidth"
	"github.com/phall1/blackbird/internal/install"
	blackbirdruntime "github.com/phall1/blackbird/internal/runtime"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

var (
	version = "dev"
	commit  = "unknown"
	builtAt = "unknown"
)

type daemonRunner interface {
	Run(context.Context) error
}

type daemonFactory func(blackbirdruntime.BuildInfo, blackbirdruntime.Config) (daemonRunner, error)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}

func runMain(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return execute(ctx, args, stdout, stderr)
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return executeConfigured(ctx, args, stdout, stderr, nil, nil)
}

// executeConfigured is the test seam for daemon assembly: injected supplies the
// non-secret configuration a caller would otherwise have to pass as flags, and
// factory replaces the production daemon.
func executeConfigured(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	injected *blackbirdruntime.Config,
	factory daemonFactory,
) int {
	return executeWithManager(ctx, args, stdout, stderr, injected, factory, nil)
}

func executeWithManager(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	injected *blackbirdruntime.Config,
	factory daemonFactory,
	manager cli.ProductPort,
) int {
	return cli.Run(ctx, dependencies(injected, factory, manager, stdout), args, stdout, stderr)
}

func dependencies(
	injected *blackbirdruntime.Config,
	factory daemonFactory,
	manager cli.ProductPort,
	stdout io.Writer,
) cli.Dependencies {
	build := blackbirdruntime.BuildInfo{Version: version, Commit: commit, BuiltAt: builtAt}.Normalize()
	if manager == nil {
		if resolved, err := install.New(); err == nil {
			manager = resolved
		}
	}
	stateDir := stateDirectory(manager)
	defaults := daemonDefaults(injected, stateDir)

	return cli.Dependencies{
		Build:        cli.BuildInfo{Version: build.Version, Commit: build.Commit, BuiltAt: build.BuiltAt},
		Defaults:     defaults,
		DatabasePath: defaultDatabasePath(),
		Daemon:       daemonAdapter{build: build, injected: injected, factory: factory},
		Admin:        adminclient.New(handshakePath(stateDir), ""),
		Store:        readerAdapter{},
		Maintenance:  maintenanceAdapter{},
		Product:      manager,
		Logs:         logsource.New(stateDir),
		Input:        os.Stdin,
		Now:          time.Now,
		Env:          os.LookupEnv,
		Device:       deviceOf(stdout),
		WidthProbe:   termwidth.Probe,
	}
}

func daemonDefaults(injected *blackbirdruntime.Config, stateDir string) cli.DaemonOptions {
	defaults := cli.DaemonOptions{
		Storage:         string(blackbirdruntime.StorageSQLite),
		SQLitePath:      defaultDatabasePath(),
		StateDir:        stateDir,
		HTTPAddress:     "127.0.0.1:8080",
		MCPAddress:      install.MCPAddress,
		ShutdownTimeout: 30 * time.Second,
	}
	if injected == nil {
		return defaults
	}
	if injected.Storage != "" {
		defaults.Storage = string(injected.Storage)
	}
	if injected.SQLitePath != "" {
		defaults.SQLitePath = injected.SQLitePath
	}
	if injected.StateDir != "" {
		defaults.StateDir = injected.StateDir
	}
	if injected.HTTPAddress != "" {
		defaults.HTTPAddress = injected.HTTPAddress
	}
	if injected.MCPAddress != "" {
		defaults.MCPAddress = injected.MCPAddress
	}
	if injected.LogLevel != "" {
		defaults.LogLevel = injected.LogLevel
	}
	if injected.ShutdownTimeout > 0 {
		defaults.ShutdownTimeout = injected.ShutdownTimeout
	}
	return defaults
}

// defaultDatabasePath is the installed data path, never a relative filename: a
// relative default is resolved against the working directory, which is how a
// stray invocation used to migrate a full database into whatever directory the
// user happened to stand in.
func defaultDatabasePath() string {
	if data := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(data) {
		return filepath.Join(data, "blackbird", "blackbird.db")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "blackbird", "blackbird.db")
}

func stateDirectory(manager cli.ProductPort) string {
	if manager != nil {
		if dir := manager.StateDir(); dir != "" {
			return dir
		}
	}
	dir, err := install.DefaultStateDir()
	if err != nil {
		return ""
	}
	return dir
}

func handshakePath(stateDir string) string {
	if stateDir == "" {
		return ""
	}
	return install.HandshakePath(stateDir)
}

func deviceOf(stream io.Writer) render.Device {
	file, ok := stream.(*os.File)
	if !ok {
		return nil
	}
	return file
}

// daemonAdapter is the only place the command grammar's daemon options meet the
// runtime's configuration.
type daemonAdapter struct {
	build    blackbirdruntime.BuildInfo
	injected *blackbirdruntime.Config
	factory  daemonFactory
}

func (adapter daemonAdapter) Run(ctx context.Context, options cli.DaemonOptions) error {
	config := blackbirdruntime.Config{}
	if adapter.injected != nil {
		config = *adapter.injected
	}
	config.Storage = blackbirdruntime.StorageBackend(options.Storage)
	config.SQLitePath = options.SQLitePath
	config.StateDir = options.StateDir
	config.HTTPAddress = options.HTTPAddress
	config.MCPAddress = options.MCPAddress
	config.ShutdownTimeout = options.ShutdownTimeout
	if options.LogLevel != "" {
		config.LogLevel = options.LogLevel
	}

	factory := adapter.factory
	if factory == nil {
		factory = func(build blackbirdruntime.BuildInfo, config blackbirdruntime.Config) (daemonRunner, error) {
			return blackbirdruntime.NewProductionDaemon(build, config)
		}
	}
	daemon, err := factory(adapter.build, config)
	if err != nil {
		return fmt.Errorf("construct daemon: %w", err)
	}
	if err := daemon.Run(ctx); err != nil {
		return fmt.Errorf("run daemon: %w", err)
	}
	return nil
}

// readerAdapter inspects the database file read-only. It never calls
// sqlite.Open, which creates directories, applies migrations, and claims the
// runtime row: an inspection command must not be able to write.
type readerAdapter struct{}

func (readerAdapter) Inspect(ctx context.Context, path string, deep bool) (cli.Database, error) {
	facts := cli.Database{Path: path, ExpectedSchemaVersion: sqlite.SchemaVersion, ExpectedApplicationID: sqlite.ApplicationID}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return facts, nil
	}
	if err != nil {
		return facts, fmt.Errorf("inspect %s: %w", path, err)
	}
	facts.Present = true
	facts.SizeBytes = info.Size()
	facts.FileMode = info.Mode().Perm().String()

	reader, err := sqlite.OpenReader(ctx, sqlite.ReaderConfig{Path: path, AllowStale: true})
	if err != nil {
		return facts, fmt.Errorf("open %s read-only: %w", path, err)
	}
	defer func() { _ = reader.Close() }()
	facts.Mode = string(reader.Mode())

	schema, err := reader.Schema(ctx)
	if err != nil {
		return facts, fmt.Errorf("read schema: %w", err)
	}
	facts.SchemaVersion = schema.SchemaVersion
	facts.ApplicationID = schema.ApplicationID
	facts.Supported = schema.Supported
	facts.LedgerComplete = schema.LedgerComplete

	storage, err := reader.Storage(ctx)
	if err != nil {
		return facts, fmt.Errorf("read storage facts: %w", err)
	}
	facts.WALBytes = storage.WALBytes
	facts.FreeBytes = int64(storage.FreeBytes)
	facts.PageSize = storage.PageSize
	facts.PageCount = storage.PageCount
	facts.JournalMode = storage.JournalMode

	runtimeState, err := reader.Runtime(ctx)
	if err != nil {
		return facts, fmt.Errorf("read runtime state: %w", err)
	}
	facts.CleanShutdown = runtimeState.CleanShutdown

	coordination, err := reader.Coordination(ctx)
	if err != nil {
		return facts, fmt.Errorf("read coordination counts: %w", err)
	}
	facts.Projects = coordination.Projects
	facts.Agents = coordination.Agents
	facts.Conversations = coordination.Conversations
	facts.Messages = coordination.Messages
	facts.Events = coordination.Events
	facts.Deliveries = coordination.Deliveries
	facts.UnreadDeliveries = coordination.UnreadDeliveries
	facts.UnackedDeliveries = coordination.UnacknowledgedDeliveries
	facts.ActiveLeases = coordination.ActiveLeases
	facts.ExpiredActiveLeases = coordination.ExpiredActiveLeases
	facts.OpenSessions = coordination.OpenSessions
	facts.StaleOpenSessions = coordination.StaleOpenSessions

	if deep {
		integrity, err := reader.Integrity(ctx)
		if err != nil {
			return facts, fmt.Errorf("check integrity: %w", err)
		}
		facts.QuickCheck = integrity.QuickCheck
		facts.ForeignKeyFailures = len(integrity.ForeignKeyFailures)
	}
	return facts, nil
}

// maintenanceAdapter is the write half of gc. It opens the database read-write
// with mode=rw, so a missing file is an error rather than a fresh database, and
// with a short busy timeout, so a database another process still holds fails
// fast instead of blocking behind SQLite's writer claim. gc refuses to call it
// while the daemon answers; this timeout is the second line of that defence.
type maintenanceAdapter struct{}

// The backup and restore commands reach these two methods by asserting
// cli.SnapshotPort on the maintenance adapter, so a signature that drifts out
// of the interface does not fail to compile — it silently turns both commands
// into "this build cannot take a backup". This assertion is what makes that a
// build failure instead.
var _ cli.SnapshotPort = maintenanceAdapter{}

const maintenanceBusyTimeout = 2 * time.Second

func (maintenanceAdapter) Reclaim(ctx context.Context, path string, plan cli.ReclaimPlan) (cli.Reclaimed, error) {
	before, err := databaseBytes(path)
	if err != nil {
		return cli.Reclaimed{}, err
	}
	database, err := openForMaintenance(ctx, path)
	if err != nil {
		return cli.Reclaimed{}, err
	}
	defer func() { _ = database.Close() }()

	if plan.Checkpoint {
		if err := checkpointWAL(ctx, database, path); err != nil {
			return cli.Reclaimed{}, err
		}
	}
	if plan.Vacuum {
		if _, err := database.ExecContext(ctx, "VACUUM"); err != nil {
			return cli.Reclaimed{}, fmt.Errorf("vacuum %s: %w", path, err)
		}
		if plan.Checkpoint {
			if err := checkpointWAL(ctx, database, path); err != nil {
				return cli.Reclaimed{}, err
			}
		}
	}
	if err := database.Close(); err != nil {
		return cli.Reclaimed{}, fmt.Errorf("close %s: %w", path, err)
	}

	after, err := databaseBytes(path)
	if err != nil {
		return cli.Reclaimed{}, err
	}
	walAfter, err := fileBytes(path + "-wal")
	if err != nil {
		return cli.Reclaimed{}, err
	}
	return cli.Reclaimed{BeforeBytes: before, AfterBytes: after, WALBytes: walAfter}, nil
}

// Backup and Restore complete cli.SnapshotPort. They hang off the maintenance
// adapter rather than a Dependencies field of their own because that is the
// adapter that already owns writing to the database file; a binary without
// them is exactly the binary whose backup command should report it cannot take
// one, which is what the type assertion in the CLI arranges.
//
// Both publish the manifest sidecar beside the file they write. The port's
// contract is that neither operation leaves a snapshot that cannot be restored,
// and a snapshot without its manifest is precisely that.
func (maintenanceAdapter) Backup(ctx context.Context, source, target string) (cli.BackupRecord, error) {
	manifest, err := sqlite.BackupFile(ctx, source, target)
	if err != nil {
		return cli.BackupRecord{}, err
	}
	if err := sqlite.WriteBackupManifest(target, manifest); err != nil {
		return cli.BackupRecord{}, err
	}
	return snapshotRecord(target, manifest), nil
}

func (maintenanceAdapter) Restore(ctx context.Context, source, target string) (cli.BackupRecord, error) {
	manifest, err := sqlite.ReadBackupManifest(source)
	if err != nil {
		return cli.BackupRecord{}, err
	}
	restored, err := sqlite.Restore(ctx, source, manifest, target)
	if err != nil {
		return cli.BackupRecord{}, err
	}
	// The restored file is itself a database, so it gets its own manifest:
	// without one it could never be backed up or restored again, which would
	// make recovery a one-way door.
	if err := sqlite.WriteBackupManifest(target, restored); err != nil {
		return cli.BackupRecord{}, err
	}
	return snapshotRecord(target, restored), nil
}

func snapshotRecord(path string, manifest sqlite.BackupManifest) cli.BackupRecord {
	return cli.BackupRecord{
		Path:             path,
		ManifestPath:     sqlite.BackupManifestPath(path),
		FormatVersion:    manifest.FormatVersion,
		CreatedAt:        manifest.CreatedAt.Format(time.RFC3339Nano),
		DatabaseBytes:    manifest.DatabaseBytes,
		DatabaseSHA256:   hex.EncodeToString(manifest.DatabaseSHA256[:]),
		SchemaVersion:    manifest.SchemaVersion,
		SQLiteVersion:    manifest.SQLiteVersion,
		AuthorityStreams: len(manifest.AuthorityStreams),
	}
}

func openForMaintenance(ctx context.Context, path string) (*sql.DB, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("reclaim %s: the database path must be absolute", path)
	}
	query := url.Values{}
	query.Set("mode", "rw")
	query.Set("_busy_timeout", strconv.FormatInt(maintenanceBusyTimeout.Milliseconds(), 10))
	query.Set("_dqs", "false")
	query.Add("_pragma", "trusted_schema(OFF)")
	connector, err := sqlitedriver.NewConnector(
		(&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: query.Encode()}).String())
	if err != nil {
		return nil, fmt.Errorf("open %s read-write: %w", path, err)
	}
	database := sql.OpenDB(connector)
	database.SetMaxOpenConns(1)
	var applicationID int
	if err := database.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("open %s read-write: %w", path, err)
	}
	if applicationID != sqlite.ApplicationID {
		_ = database.Close()
		return nil, fmt.Errorf("reclaim %s: application id %d is not a Blackbird database", path, applicationID)
	}
	return database, nil
}

// checkpointWAL truncates the write-ahead log. A busy checkpoint means another
// connection is reading the database, which leaves the log in place: report it
// rather than claim space that was never reclaimed.
func checkpointWAL(ctx context.Context, database *sql.DB, path string) error {
	var busy, walFrames, checkpointed int
	if err := database.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").
		Scan(&busy, &walFrames, &checkpointed); err != nil {
		return fmt.Errorf("checkpoint %s: %w", path, err)
	}
	if busy != 0 {
		return fmt.Errorf("checkpoint %s: another connection is using the database", path)
	}
	return nil
}

// databaseBytes is the space the database actually occupies: the file plus its
// write-ahead log, because truncating the log is most of what gc reclaims.
func databaseBytes(path string) (int64, error) {
	main, err := fileBytes(path)
	if err != nil {
		return 0, err
	}
	if main == 0 {
		return 0, fmt.Errorf("reclaim %s: no such database", path)
	}
	wal, err := fileBytes(path + "-wal")
	if err != nil {
		return 0, err
	}
	return main + wal, nil
}

func fileBytes(path string) (int64, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("inspect %s: %w", path, err)
	}
	return info.Size(), nil
}
