package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
)

// BackupRecord is a published snapshot and the facts its manifest records.
// Digests are hex so a report, a manifest, and shasum agree character for
// character; the CLI never sees the raw manifest, which belongs to storage.
type BackupRecord struct {
	Path             string `json:"path"`
	ManifestPath     string `json:"manifest_path"`
	FormatVersion    int    `json:"format_version"`
	CreatedAt        string `json:"created_at"`
	DatabaseBytes    int64  `json:"database_bytes"`
	DatabaseSHA256   string `json:"database_sha256"`
	SchemaVersion    int    `json:"schema_version"`
	SQLiteVersion    string `json:"sqlite_version"`
	AuthorityStreams int    `json:"authority_streams"`
}

// SnapshotPort is the online backup and restore half of database maintenance.
// Both operations publish a manifest sidecar beside the file they write and
// return the facts it records: a snapshot standing alone on disk cannot be
// restored, so writing one without the other is not an option the port offers.
//
// It is reached by asserting it on MaintenancePort rather than through a
// Dependencies field of its own. The adapter that already holds the read-write
// connection is where these two operations belong, so a binary grows them by
// growing that adapter; a binary that has not is exactly the binary that should
// report it cannot take a backup.
type SnapshotPort interface {
	Backup(ctx context.Context, source, target string) (BackupRecord, error)
	Restore(ctx context.Context, source, target string) (BackupRecord, error)
}

// stalePartialAge is how long an unpublished partial must sit untouched before
// backup reaps it. A snapshot of a large database takes minutes and a partial
// is the only copy of an in-flight one, so the window is wide enough that only
// an abandoned file can fall inside it.
const stalePartialAge = time.Hour

// unpublishedPartial matches what storage names a snapshot it never published:
// the target path, ".partial.", and the hex of a sixteen-byte nonce. The
// pattern is spelled out here because the CLI cannot import the storage layer,
// and it has to move whenever that naming does.
var unpublishedPartial = regexp.MustCompile(`\.partial\.[0-9a-f]{32}$`)

// BackupCmd takes a verified online snapshot. The SQLite backup API copies
// pages out from under the live writer, so unlike gc this needs no stopped
// daemon and takes no mutating flag to guard.
type BackupCmd struct {
	Out string `placeholder:"PATH" help:"Write the snapshot here. Defaults to a timestamped file under the database's backups directory."`
}

// Help is Kong's HelpProvider hook.
func (cmd *BackupCmd) Help() string {
	return "The snapshot is verified before it is published and is written with a manifest " +
		"sidecar beside it. Restore requires that manifest, so keep the pair together."
}

type backupReport struct {
	Source     string       `json:"source"`
	Snapshot   BackupRecord `json:"snapshot"`
	Reaped     []string     `json:"reaped_partials,omitempty"`
	ReapFailed []string     `json:"unreaped_partials,omitempty"`
}

func (cmd *BackupCmd) Run(ctx context.Context, console *Console) error {
	source, err := console.databasePath()
	if err != nil {
		return err
	}
	if err := requireLiveDatabase(ctx, console, source); err != nil {
		return err
	}
	target, err := cmd.target(console, source)
	if err != nil {
		return err
	}
	snapshots, err := console.snapshots(source, target)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return withRemedy(fault(ExitError, err, "create the snapshot directory"),
			"pass --out=PATH under a directory you can write")
	}

	// Reaping runs first. A snapshot that fails leaves its own partial behind,
	// and the whole point of reclaiming the abandoned ones is to make room for
	// the copy about to be written.
	reaped, unreaped := reapUnpublishedPartials(filepath.Dir(target), console.now())

	record, err := snapshots.Backup(ctx, source, target)
	if err != nil {
		return backupFault(err, target)
	}
	return console.present(newView(backupReport{
		Source: source, Snapshot: record, Reaped: reaped, ReapFailed: unreaped,
	}, drawBackup))
}

// target resolves --out the way Globals resolves --db: a leading ~/ expands,
// anything else relative is refused rather than made absolute against whatever
// directory the user happened to stand in.
func (cmd *BackupCmd) target(console *Console, source string) (string, error) {
	if cmd.Out == "" {
		name := fmt.Sprintf("%s-%s.db", programName, console.now().UTC().Format("20060102T150405Z"))
		return filepath.Join(filepath.Dir(source), "backups", name), nil
	}
	expanded, err := expandHome(cmd.Out)
	if err != nil {
		return "", usageFault("resolve --out: %v", err)
	}
	if !filepath.IsAbs(expanded) {
		return "", usageFault("--out must be an absolute path; got %q", cmd.Out)
	}
	cleaned := filepath.Clean(expanded)
	// Storage refuses a target with no extension, because a snapshot has to own
	// its own "-wal" and "-shm" names. Say so here, where the flag is named.
	if filepath.Ext(cleaned) == "" {
		return "", usageFault("--out must name a file with an extension, such as %s.db; got %q",
			filepath.Join(cleaned, programName), cmd.Out)
	}
	return cleaned, nil
}

// RestoreCmd rebuilds a database from a verified snapshot. It refuses while a
// daemon holds the target for the same reason gc refuses to vacuum one, and it
// refuses to write over anything that is already there: a restore that silently
// replaced a database would destroy the state an operator still needed to
// diagnose why they were restoring.
type RestoreCmd struct {
	From string `required:"" placeholder:"PATH" help:"Snapshot to restore. Its manifest sidecar must sit beside it."`
	To   string `placeholder:"PATH" help:"Write the restored database here instead of at --db. The path must not exist."`
}

// Help is Kong's HelpProvider hook.
func (cmd *RestoreCmd) Help() string {
	return "Restore never replaces an existing database. Move the current one aside, or pass " +
		"--to=PATH to restore beside it and swap the files yourself."
}

type restoreReport struct {
	Source   string       `json:"source"`
	Target   string       `json:"target"`
	Snapshot BackupRecord `json:"snapshot"`
}

func (cmd *RestoreCmd) Run(ctx context.Context, console *Console) error {
	source, err := absolutePathFlag("--from", cmd.From)
	if err != nil {
		return err
	}
	target, err := cmd.target(console)
	if err != nil {
		return err
	}
	if source == target {
		return usageFault("--from and the restore target are both %s", target)
	}
	if _, err := os.Stat(source); err != nil {
		return withRemedy(notFoundFault("no snapshot at %s", source),
			"run \"blackbird backup\" to take one, or name an existing snapshot")
	}
	// The guard is the same one gc applies, and for the same reason: SQLite's
	// writer claim makes a second writer against a live database unsafe by
	// construction. A restore also publishes over the daemon's own file. It runs
	// before the port is resolved so that a live daemon is refused whether or not
	// this binary could have carried the restore out.
	if live, detail := daemonServes(ctx, console, target); live {
		return withRemedy(unavailableFault(nil, "the daemon is running (%s)", detail),
			"stop the daemon before restoring")
	}
	if err := refuseToClobber(target); err != nil {
		return err
	}
	snapshots, err := console.snapshots(source, target)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return withRemedy(fault(ExitError, err, "create the restore directory"),
			"pass --to=PATH under a directory you can write")
	}

	record, err := snapshots.Restore(ctx, source, target)
	if err != nil {
		return restoreFault(err, source, target)
	}
	return console.present(newView(restoreReport{
		Source: source, Target: target, Snapshot: record,
	}, drawRestore))
}

func (cmd *RestoreCmd) target(console *Console) (string, error) {
	if cmd.To == "" {
		return console.databasePath()
	}
	return absolutePathFlag("--to", cmd.To)
}

// snapshots resolves the port both commands need. The remedy names the SQLite
// invocation that copies source to target, which is the same thing in both
// directions, so an operator holding a binary without the port is not simply
// told no. It publishes no manifest, so what it writes cannot be restored by
// "blackbird restore" — which is exactly why the port exists.
func (console *Console) snapshots(source, target string) (SnapshotPort, error) {
	port, ok := console.Deps.Maintenance.(SnapshotPort)
	if !ok {
		return nil, withRemedy(
			unavailableFault(nil, "this binary cannot take or restore snapshots"),
			fmt.Sprintf("copy the database yourself with \"sqlite3 %s '.backup %s'\"", source, target))
	}
	return port, nil
}

// requireLiveDatabase turns "there is nothing to copy" into a not-found before
// the port opens a connection, so the operator reads the path rather than a
// driver error from two layers in.
func requireLiveDatabase(ctx context.Context, console *Console, path string) error {
	store, err := console.store()
	if err != nil {
		return err
	}
	database, err := store.Inspect(ctx, path, false)
	if err != nil {
		return withRemedy(unavailableFault(err, "read database %s", path),
			"run \"blackbird doctor\" to check the database")
	}
	if !database.Present {
		return withRemedy(notFoundFault("no database at %s", path),
			"run \"blackbird install\" and start the daemon to create it")
	}
	return nil
}

// refuseToClobber is the whole of "restore does not overwrite". Storage refuses
// the same way, but only after it has copied the snapshot into a partial, and
// an operator who is about to lose a database deserves the answer first.
func refuseToClobber(target string) error {
	for _, candidate := range []string{target, target + "-wal", target + "-shm"} {
		if _, err := os.Lstat(candidate); err == nil {
			return withRemedy(fault(ExitError, nil, "%s already exists", candidate),
				"move it aside, or pass --to=PATH to restore beside it")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fault(ExitError, err, "inspect %s", candidate)
		}
	}
	return nil
}

func absolutePathFlag(name, value string) (string, error) {
	expanded, err := expandHome(value)
	if err != nil {
		return "", usageFault("resolve %s: %v", name, err)
	}
	if !filepath.IsAbs(expanded) {
		return "", usageFault("%s must be an absolute path; got %q", name, value)
	}
	return filepath.Clean(expanded), nil
}

// reapUnpublishedPartials removes the abandoned copies a failed snapshot or
// restore deliberately retains. Nothing else reaps them, so a directory that
// has seen a handful of failures holds a handful of full-size databases; what
// is still recent is left alone, because it may be an in-flight copy.
func reapUnpublishedPartials(directory string, now time.Time) (reaped, unreaped []string) {
	// A directory that cannot be listed is left to the snapshot about to be
	// written there, which fails a moment later and says so far more precisely
	// than a reaper's complaint about housekeeping would.
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, nil
	}
	for _, entry := range entries {
		if entry.IsDir() || !unpublishedPartial.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil || now.Sub(info.ModTime()) < stalePartialAge {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if err := os.Remove(path); err != nil {
			unreaped = append(unreaped, path)
			continue
		}
		reaped = append(reaped, path)
	}
	return reaped, unreaped
}

// backupFault keeps the retained-partial path storage names in its error: that
// file is the only evidence of why the snapshot failed, and it is also the one
// thing the next backup will reap once it has aged.
func backupFault(err error, target string) error {
	return withRemedy(fault(ExitError, err, "back up to %s", target),
		"check free space and directory permissions, then run \"blackbird backup\" again")
}

func restoreFault(err error, source, target string) error {
	return withRemedy(fault(ExitError, err, "restore %s to %s", source, target),
		"restore needs the snapshot and the manifest sidecar \"blackbird backup\" wrote beside it; "+
			"verify both with \"blackbird doctor --deep\" after a successful restore")
}

func drawBackup(doc *render.Document, report backupReport) {
	doc.Heading("Snapshot")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "source", Value: report.Source},
		{Key: "snapshot", Value: report.Snapshot.Path},
		{Key: "manifest", Value: report.Snapshot.ManifestPath},
		{Key: "size", Value: render.Bytes(report.Snapshot.DatabaseBytes)},
		{Key: "sha256", Value: report.Snapshot.DatabaseSHA256},
		{Key: "schema", Value: itoa(report.Snapshot.SchemaVersion)},
		{Key: "sqlite", Value: orAbsent(report.Snapshot.SQLiteVersion)},
		{Key: "authority streams", Value: itoa(report.Snapshot.AuthorityStreams)},
	}})
	drawReaped(doc, report)
	doc.Blank()
	doc.Line(render.RoleMuted, "Restore needs both files. Keep the manifest beside the snapshot.")
}

func drawReaped(doc *render.Document, report backupReport) {
	if len(report.Reaped) == 0 && len(report.ReapFailed) == 0 {
		return
	}
	doc.Blank()
	// Every reaped path is named. Reaping deletes a file the operator never
	// asked this command to touch, so a count alone is not an account of it.
	for _, path := range report.Reaped {
		doc.Wrapped(render.RolePlain, "reaped abandoned partial "+path)
	}
	for _, path := range report.ReapFailed {
		doc.Wrapped(render.RoleWarn, "could not reap the abandoned partial "+path+"; remove it yourself")
	}
}

func drawRestore(doc *render.Document, report restoreReport) {
	doc.Heading("Restored database")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "snapshot", Value: report.Source},
		{Key: "target", Value: report.Target},
		{Key: "size", Value: render.Bytes(report.Snapshot.DatabaseBytes)},
		{Key: "sha256", Value: report.Snapshot.DatabaseSHA256},
		{Key: "schema", Value: itoa(report.Snapshot.SchemaVersion)},
		{Key: "sqlite", Value: orAbsent(report.Snapshot.SQLiteVersion)},
		{Key: "authority streams", Value: itoa(report.Snapshot.AuthorityStreams)},
	}})
	doc.Blank()
	// Storage seals every writer-control row it restores; writable activation
	// belongs to the recovery protocol, not to this command.
	doc.Line(render.RoleMuted, "Writer control is sealed. Verify with \"blackbird doctor --deep\" before starting the daemon.")
}
