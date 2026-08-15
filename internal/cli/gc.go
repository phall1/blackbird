package cli

import (
	"context"

	"github.com/phall1/blackbird/internal/cli/render"
)

// GCCmd reports reclaimable space. It never prunes the coordination event
// journal or the message tables: both carry no-update and no-delete triggers
// that abort the statement, so a retention pruner would fail on its first row.
type GCCmd struct {
	Checkpoint bool `help:"Truncate the write-ahead log. Requires a stopped daemon."`
	Vacuum     bool `help:"Rewrite the database to reclaim free pages. Requires a stopped daemon."`
}

// Help is Kong's HelpProvider hook.
func (cmd *GCCmd) Help() string {
	return "Without a mutating flag, gc only reports. The coordination event journal is " +
		"append-only and is never pruned."
}

type gcReport struct {
	Path             string     `json:"path"`
	DiskFreeBytes    int64      `json:"disk_free_bytes"`
	WALBytes         int64      `json:"wal_bytes"`
	SizeBytes        int64      `json:"size_bytes"`
	PageSize         int64      `json:"page_size"`
	PageCount        int64      `json:"page_count"`
	JournalImmutable bool       `json:"journal_immutable"`
	Reclaimed        *Reclaimed `json:"reclaimed,omitempty"`
}

func (cmd *GCCmd) Run(ctx context.Context, console *Console) error {
	store, err := console.store()
	if err != nil {
		return err
	}
	path, err := console.databasePath()
	if err != nil {
		return err
	}
	database, err := store.Inspect(ctx, path, false)
	if err != nil {
		return withRemedy(unavailableFault(err, "read database %s", path), "start the daemon")
	}

	report := gcReport{
		Path: path, DiskFreeBytes: database.FreeBytes, WALBytes: database.WALBytes,
		SizeBytes: database.SizeBytes, PageSize: database.PageSize, PageCount: database.PageCount,
		JournalImmutable: true,
	}

	if cmd.Checkpoint || cmd.Vacuum {
		reclaimed, err := cmd.reclaim(ctx, console, path)
		if err != nil {
			return err
		}
		report.Reclaimed = &reclaimed
	}
	return console.present(newView(report, drawGC))
}

// reclaim refuses while a daemon has this database open: SQLite's writer claim
// makes a second writer against a live database unsafe by construction, so this
// guard is a correctness requirement rather than politeness.
//
// The handshake record is not evidence either way. It is published best-effort
// and a pre-0.4 daemon never writes one, so gating on it left this guard inert
// in exactly the states where a live daemon is most likely.
func (cmd *GCCmd) reclaim(ctx context.Context, console *Console, path string) (Reclaimed, error) {
	if live, detail := daemonServes(ctx, console, path); live {
		return Reclaimed{}, withRemedy(
			unavailableFault(nil, "the daemon is running (%s)", detail),
			"stop the daemon before reclaiming space")
	}
	if console.Deps.Maintenance == nil {
		return Reclaimed{}, withRemedy(
			unavailableFault(nil, "this binary cannot rewrite the database"),
			"stop the daemon and run \"sqlite3 "+path+" 'PRAGMA wal_checkpoint(TRUNCATE); VACUUM;'\"")
	}
	reclaimed, err := console.Deps.Maintenance.Reclaim(ctx, path,
		ReclaimPlan{Checkpoint: cmd.Checkpoint, Vacuum: cmd.Vacuum})
	if err != nil {
		return Reclaimed{}, fault(ExitError, err, "reclaim space")
	}
	return reclaimed, nil
}

func drawGC(doc *render.Document, report gcReport) {
	doc.Heading("Reclaimable space")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "path", Value: report.Path},
		{Key: "database", Value: render.Bytes(report.SizeBytes)},
		{Key: "disk free", Value: render.Bytes(report.DiskFreeBytes)},
		{Key: "write-ahead log", Value: render.Bytes(report.WALBytes)},
	}})
	if report.Reclaimed != nil {
		doc.Blank()
		// A vacuum of an already compact database can add a page, so the delta is
		// not always positive and "reclaimed -4 KiB" is not a thing to print.
		if freed := report.Reclaimed.BeforeBytes - report.Reclaimed.AfterBytes; freed > 0 {
			doc.Linef(render.RolePlain, "reclaimed %s", render.Bytes(freed))
		} else {
			doc.Line(render.RolePlain, "reclaimed nothing: the database was already compact")
		}
	}
	doc.Blank()
	doc.Line(render.RoleMuted, "The coordination event journal is append-only and is never pruned.")
}
