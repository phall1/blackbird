package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSnapshots is a MaintenancePort that also satisfies SnapshotPort, which is
// how the real adapter is expected to carry these operations.
type fakeSnapshots struct {
	fakeMaintenance
	record     BackupRecord
	err        error
	backupCall [2]string
	restore    [2]string
}

func (snapshots *fakeSnapshots) Backup(_ context.Context, source, target string) (BackupRecord, error) {
	snapshots.backupCall = [2]string{source, target}
	if snapshots.err != nil {
		return BackupRecord{}, snapshots.err
	}
	record := snapshots.record
	record.Path = target
	record.ManifestPath = target + ".manifest.json"
	return record, nil
}

func (snapshots *fakeSnapshots) Restore(_ context.Context, source, target string) (BackupRecord, error) {
	snapshots.restore = [2]string{source, target}
	if snapshots.err != nil {
		return BackupRecord{}, snapshots.err
	}
	record := snapshots.record
	record.Path = target
	record.ManifestPath = source + ".manifest.json"
	return record, nil
}

func snapshotRecord() BackupRecord {
	return BackupRecord{
		FormatVersion: 1, CreatedAt: "2026-08-15T12:00:00Z", DatabaseBytes: 812 << 10,
		DatabaseSHA256: strings.Repeat("ab", 32), SchemaVersion: 4, SQLiteVersion: "3.45.1",
		AuthorityStreams: 2,
	}
}

func backupDeps(t *testing.T, snapshots *fakeSnapshots) Dependencies {
	t.Helper()
	deps := dependencies(t)
	deps.Store = &fakeStore{database: healthyDatabase()}
	deps.Admin = &fakeAdmin{err: errors.New("connection refused")}
	if snapshots != nil {
		deps.Maintenance = snapshots
	}
	return deps
}

// writePartial creates a file named the way storage names a snapshot it never
// published, aged so the reaper either sees it as abandoned or as in flight.
func writePartial(t *testing.T, path string, age time.Duration, now time.Time) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := now.Add(-age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBackupPublishesASnapshotBesideItsManifest(t *testing.T) {
	t.Parallel()

	snapshots := &fakeSnapshots{record: snapshotRecord()}
	deps := backupDeps(t, snapshots)
	target := filepath.Join(t.TempDir(), "snap.db")

	result := runCLI(t, deps, []string{"backup", "--out=" + target, "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	var report backupReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.Snapshot.Path != target || report.Snapshot.ManifestPath != target+".manifest.json" {
		t.Fatalf("snapshot = %#v", report.Snapshot)
	}
	if report.Source != deps.DatabasePath {
		t.Fatalf("source = %q, want %q", report.Source, deps.DatabasePath)
	}
	if snapshots.backupCall != [2]string{deps.DatabasePath, target} {
		t.Fatalf("port called with %v", snapshots.backupCall)
	}
}

// Backup is an online operation: the SQLite backup API copies pages out from
// under the live writer, so a running daemon is not a reason to refuse.
func TestBackupRunsWhileTheDaemonIsLive(t *testing.T) {
	t.Parallel()

	snapshots := &fakeSnapshots{record: snapshotRecord()}
	deps := backupDeps(t, snapshots)
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
	target := filepath.Join(t.TempDir(), "snap.db")

	result := runCLI(t, deps, []string{"backup", "--out=" + target})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if snapshots.backupCall[1] != target {
		t.Fatal("backup refused while the daemon was answering")
	}
}

func TestBackupDefaultsToATimestampedFileUnderTheDatabaseDirectory(t *testing.T) {
	t.Parallel()

	snapshots := &fakeSnapshots{record: snapshotRecord()}
	deps := backupDeps(t, snapshots)

	if code := runCLI(t, deps, []string{"backup"}).code; code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	want := filepath.Join(filepath.Dir(deps.DatabasePath), "backups", "blackbird-20260815T120000Z.db")
	if snapshots.backupCall[1] != want {
		t.Fatalf("target = %q, want %q", snapshots.backupCall[1], want)
	}
	if info, err := os.Stat(filepath.Dir(want)); err != nil || !info.IsDir() {
		t.Fatalf("backup did not create the snapshot directory: %v", err)
	}
}

func TestBackupRejectsATargetItCannotPublish(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		out  string
	}{
		{name: "relative path", out: "backups/snap.db"},
		{name: "directory with no extension", out: "/tmp/blackbird-backups"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			snapshots := &fakeSnapshots{record: snapshotRecord()}
			result := runCLI(t, backupDeps(t, snapshots), []string{"backup", "--out=" + test.out})
			if result.code != ExitUsage {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitUsage, result.stderr)
			}
			if snapshots.backupCall != [2]string{} {
				t.Fatalf("port was called with %v", snapshots.backupCall)
			}
		})
	}
}

// Nothing else reaps the partials a failed snapshot deliberately retains, so a
// backup directory would otherwise accumulate full-size database copies. A
// recent partial may still be an in-flight copy and is left alone.
func TestBackupReapsAbandonedPartialsAndSparesRecentOnes(t *testing.T) {
	t.Parallel()

	snapshots := &fakeSnapshots{record: snapshotRecord()}
	deps := backupDeps(t, snapshots)
	now := deps.Now()
	directory := t.TempDir()
	nonce := strings.Repeat("0", 32)

	abandoned := writePartial(t, filepath.Join(directory, "old.db.partial."+nonce), 48*time.Hour, now)
	inFlight := writePartial(t, filepath.Join(directory, "new.db.partial."+nonce), time.Minute, now)
	unrelated := writePartial(t, filepath.Join(directory, "notes.partial.txt"), 48*time.Hour, now)

	result := runCLI(t, deps, []string{"backup", "--out=" + filepath.Join(directory, "snap.db"), "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	var report backupReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Reaped) != 1 || report.Reaped[0] != abandoned {
		t.Fatalf("reaped = %v, want [%s]", report.Reaped, abandoned)
	}
	if _, err := os.Stat(abandoned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned partial survived: %v", err)
	}
	for _, kept := range []string{inFlight, unrelated} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("%s was reaped: %v", kept, err)
		}
	}
}

func TestBackupWithoutASnapshotPortExplainsItself(t *testing.T) {
	t.Parallel()

	deps := backupDeps(t, nil)
	deps.Maintenance = &fakeMaintenance{}

	result := runCLI(t, deps, []string{"backup"})
	if result.code != ExitUnavailable {
		t.Fatalf("code = %d, want %d", result.code, ExitUnavailable)
	}
	if !strings.Contains(result.stderr, "remedy: ") || !strings.Contains(result.stderr, "sqlite3") {
		t.Fatalf("stderr = %q, want a remedy naming an alternative", result.stderr)
	}
}

func TestBackupWithoutADatabaseExitsNotFound(t *testing.T) {
	t.Parallel()

	deps := backupDeps(t, &fakeSnapshots{record: snapshotRecord()})
	deps.Store = &fakeStore{database: Database{Present: false}}

	result := runCLI(t, deps, []string{"backup"})
	if result.code != ExitNotFound {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitNotFound, result.stderr)
	}
}

func TestRestoreRefusesWhileTheDaemonIsLive(t *testing.T) {
	t.Parallel()

	snapshots := &fakeSnapshots{record: snapshotRecord()}
	deps := backupDeps(t, snapshots)
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
	source := writePartial(t, filepath.Join(t.TempDir(), "snap.db"), 0, deps.Now())

	result := runCLI(t, deps, []string{"restore", "--from=" + source})
	if result.code != ExitUnavailable {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitUnavailable, result.stderr)
	}
	if snapshots.restore != [2]string{} {
		t.Fatal("restore wrote a database the daemon had open")
	}
	if !strings.Contains(result.stderr, "stop the daemon") {
		t.Fatalf("stderr = %q, want the remedy to name the daemon", result.stderr)
	}
}

// A restore that silently replaced a database would destroy the state the
// operator still needs to diagnose why they were restoring in the first place.
func TestRestoreRefusesToClobber(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sidecar string
	}{
		{name: "database", sidecar: ""},
		{name: "write-ahead log", sidecar: "-wal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			snapshots := &fakeSnapshots{record: snapshotRecord()}
			deps := backupDeps(t, snapshots)
			source := writePartial(t, filepath.Join(t.TempDir(), "snap.db"), 0, deps.Now())
			target := filepath.Join(t.TempDir(), "restored.db")
			writePartial(t, target+test.sidecar, 0, deps.Now())

			result := runCLI(t, deps, []string{"restore", "--from=" + source, "--to=" + target})
			if result.code != ExitError {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitError, result.stderr)
			}
			if snapshots.restore != [2]string{} {
				t.Fatalf("restore ran over %s", target+test.sidecar)
			}
			if !strings.Contains(result.stderr, "already exists") || !strings.Contains(result.stderr, "remedy: ") {
				t.Fatalf("stderr = %q, want a refusal with a remedy", result.stderr)
			}
		})
	}
}

func TestRestorePublishesIntoAFreshTarget(t *testing.T) {
	t.Parallel()

	snapshots := &fakeSnapshots{record: snapshotRecord()}
	deps := backupDeps(t, snapshots)
	source := writePartial(t, filepath.Join(t.TempDir(), "snap.db"), 0, deps.Now())
	target := filepath.Join(t.TempDir(), "restored", "blackbird.db")

	result := runCLI(t, deps, []string{"restore", "--from=" + source, "--to=" + target, "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	var report restoreReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.Source != source || report.Target != target {
		t.Fatalf("report = %#v", report)
	}
	if snapshots.restore != [2]string{source, target} {
		t.Fatalf("port called with %v", snapshots.restore)
	}
}

func TestRestoreRejectsBadInput(t *testing.T) {
	t.Parallel()

	existing := writePartial(t, filepath.Join(t.TempDir(), "snap.db"), 0,
		time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC))
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "no snapshot named", args: []string{"restore"}, want: ExitUsage},
		{name: "relative snapshot", args: []string{"restore", "--from=snap.db"}, want: ExitUsage},
		{name: "snapshot restored onto itself", args: []string{"restore", "--from=" + existing, "--to=" + existing},
			want: ExitUsage},
		{name: "snapshot that does not exist", args: []string{"restore", "--from=/nowhere/snap.db"},
			want: ExitNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			snapshots := &fakeSnapshots{record: snapshotRecord()}
			result := runCLI(t, backupDeps(t, snapshots), test.args)
			if result.code != test.want {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, test.want, result.stderr)
			}
			if snapshots.restore != [2]string{} {
				t.Fatalf("port was called with %v", snapshots.restore)
			}
		})
	}
}

func TestRestoreReportsThePortsFailureWithARemedy(t *testing.T) {
	t.Parallel()

	deps := backupDeps(t, &fakeSnapshots{err: errors.New("manifest does not match snapshot")})
	source := writePartial(t, filepath.Join(t.TempDir(), "snap.db"), 0, deps.Now())
	target := filepath.Join(t.TempDir(), "restored.db")

	result := runCLI(t, deps, []string{"restore", "--from=" + source, "--to=" + target})
	if result.code != ExitError {
		t.Fatalf("code = %d, want %d", result.code, ExitError)
	}
	if !strings.Contains(result.stderr, "manifest") || !strings.Contains(result.stderr, "remedy: ") {
		t.Fatalf("stderr = %q, want the cause and a remedy", result.stderr)
	}
}

func TestBackupReportsThePortsFailureWithARemedy(t *testing.T) {
	t.Parallel()

	deps := backupDeps(t, &fakeSnapshots{err: errors.New("no space left on device")})

	result := runCLI(t, deps, []string{"backup"})
	if result.code != ExitError {
		t.Fatalf("code = %d, want %d", result.code, ExitError)
	}
	if !strings.Contains(result.stderr, "no space left") || !strings.Contains(result.stderr, "remedy: ") {
		t.Fatalf("stderr = %q, want the cause and a remedy", result.stderr)
	}
}

// The rendered reports carry two facts the operator cannot get anywhere else:
// which files backup deleted on their behalf, and that a restored database is
// sealed rather than ready to serve.
func TestBackupAndRestoreRenderWhatTheOperatorMustKnow(t *testing.T) {
	t.Parallel()

	deps := backupDeps(t, &fakeSnapshots{record: snapshotRecord()})
	directory := t.TempDir()
	writePartial(t, filepath.Join(directory, "old.db.partial."+strings.Repeat("0", 32)), 48*time.Hour, deps.Now())

	backup := runCLI(t, deps, []string{"backup", "--width=200",
		"--out=" + filepath.Join(directory, "snap.db")})
	if backup.code != ExitOK {
		t.Fatalf("backup code = %d; stderr=%q", backup.code, backup.stderr)
	}
	for _, want := range []string{"Snapshot", "reaped abandoned partial", "old.db.partial",
		"Keep the manifest beside the snapshot"} {
		if !strings.Contains(backup.stdout, want) {
			t.Fatalf("backup stdout = %q, want %q", backup.stdout, want)
		}
	}

	source := writePartial(t, filepath.Join(directory, "snap2.db"), 0, deps.Now())
	restore := runCLI(t, deps, []string{"restore", "--width=200",
		"--from=" + source, "--to=" + filepath.Join(t.TempDir(), "restored.db")})
	if restore.code != ExitOK {
		t.Fatalf("restore code = %d; stderr=%q", restore.code, restore.stderr)
	}
	for _, want := range []string{"Restored database", "Writer control is sealed", "doctor --deep"} {
		if !strings.Contains(restore.stdout, want) {
			t.Fatalf("restore stdout = %q, want %q", restore.stdout, want)
		}
	}
}
