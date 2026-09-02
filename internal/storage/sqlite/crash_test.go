package sqlite

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	crashHelperDatabase = "BLACKBIRD_SQLITE_CRASH_DATABASE"
	crashHelperScenario = "BLACKBIRD_SQLITE_CRASH_SCENARIO"
	crashExitCode       = 86
)

func TestCrashRecoveryRollsBackEveryUncommittedPublicationBoundary(t *testing.T) {
	for _, scenario := range []string{"after-receipt", "after-event", "after-audit"} {
		t.Run(scenario, func(t *testing.T) {
			path := newCrashDatabase(t)
			output, err := runCrashHelper(t, path, scenario)
			assertCrashExit(t, err, output)

			store, err := Open(context.Background(), Config{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Error(err)
				}
			})
			if !store.Diagnostics().UncleanCheckRan {
				t.Fatal("process death did not trigger the unclean-startup integrity gate")
			}
			assertPublicationCounts(t, store.db, [3]int{})
			if err := store.IntegrityCheck(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCrashRecoveryPublishesNothingBeforeCommit(t *testing.T) {
	path := newCrashDatabase(t)
	command := crashHelperCommand(t, path, "before-commit")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "transaction-ready" {
		t.Fatalf("helper did not reach pre-commit boundary: stdout=%q stderr=%q error=%v", scanner.Text(), stderr.String(), scanner.Err())
	}
	reader, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_busy_timeout=1000")
	if err != nil {
		t.Fatal(err)
	}
	assertPublicationCounts(t, reader, [3]int{})
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	assertCrashExit(t, command.Wait(), stderr.String())

	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	assertPublicationCounts(t, store.db, [3]int{})
}

func TestCrashRecoveryRetainsAtomicCommitFromWAL(t *testing.T) {
	path := newCrashDatabase(t)
	output, err := runCrashHelper(t, path, "after-commit")
	assertCrashExit(t, err, output)
	if !strings.Contains(output, "wal-present") {
		t.Fatalf("helper did not leave WAL recovery evidence: %q", output)
	}

	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	if !store.Diagnostics().UncleanCheckRan {
		t.Fatal("post-commit process death did not trigger the unclean-startup integrity gate")
	}
	assertPublicationCounts(t, store.db, [3]int{1, 1, 1})
	if err := store.IntegrityCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCrashRecoveryDiscardsTransactionWithTruncatedWALCommitTail(t *testing.T) {
	source := newCrashDatabase(t)
	output, err := runCrashHelper(t, source, "after-commit")
	assertCrashExit(t, err, output)

	isolated := filepath.Join(t.TempDir(), "truncated-wal.db")
	copyCrashFixtureFile(t, source, isolated, 0)
	walInfo, err := os.Stat(source + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if walInfo.Size() < 512 {
		t.Fatalf("crash WAL unexpectedly small: %d bytes", walInfo.Size())
	}
	copyCrashFixtureFile(t, source+"-wal", isolated+"-wal", walInfo.Size()-256)

	store, err := Open(context.Background(), Config{Path: isolated})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	if !store.Diagnostics().UncleanCheckRan {
		t.Fatal("truncated WAL fixture did not trigger unclean-startup integrity gate")
	}
	assertPublicationCounts(t, store.db, [3]int{})
	if err := store.IntegrityCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCrashHarnessDistinguishesCleanAndUncleanStartup(t *testing.T) {
	path := newCrashDatabase(t)
	if output, err := runCrashHelper(t, path, "clean-close"); err != nil {
		t.Fatalf("clean helper failed: %v\n%s", err, output)
	}
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if store.Diagnostics().UncleanCheckRan {
		t.Fatal("clean subprocess shutdown reported an unclean startup")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	output, err := runCrashHelper(t, path, "after-commit")
	assertCrashExit(t, err, output)
	reopened, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	if !reopened.Diagnostics().UncleanCheckRan {
		t.Fatal("unclean subprocess shutdown did not report its integrity gate")
	}
}

func TestSQLiteCrashHelperProcess(t *testing.T) {
	path := os.Getenv(crashHelperDatabase)
	if path == "" {
		return
	}
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		crashHelperFail(err)
	}
	scenario := os.Getenv(crashHelperScenario)
	if scenario == "clean-close" {
		if err := store.Close(); err != nil {
			crashHelperFail(err)
		}
		return
	}

	err = store.withImmediate(context.Background(), func(tx *sql.Tx) error {
		if err := insertCrashReceipt(tx); err != nil {
			return err
		}
		if scenario == "after-receipt" {
			os.Exit(crashExitCode)
		}
		if err := insertCrashEvent(tx); err != nil {
			return err
		}
		if scenario == "after-event" {
			os.Exit(crashExitCode)
		}
		if err := insertCrashAudit(tx); err != nil {
			return err
		}
		switch scenario {
		case "after-audit":
			os.Exit(crashExitCode)
		case "before-commit":
			fmt.Println("transaction-ready")
			var release [1]byte
			_, _ = os.Stdin.Read(release[:])
			os.Exit(crashExitCode)
		case "after-commit":
			return nil
		default:
			return fmt.Errorf("unknown crash scenario %q", scenario)
		}
		return nil
	})
	if err != nil {
		crashHelperFail(err)
	}
	if info, err := os.Stat(path + "-wal"); err != nil || info.Size() == 0 {
		crashHelperFail(fmt.Errorf("inspect WAL: size=%d error=%v", func() int64 {
			if info == nil {
				return 0
			}
			return info.Size()
		}(), err))
	}
	fmt.Println("wal-present")
	os.Exit(crashExitCode)
}

func newCrashDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func crashHelperCommand(t *testing.T, path, scenario string) *exec.Cmd {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestSQLiteCrashHelperProcess$")
	command.Env = append(os.Environ(), crashHelperDatabase+"="+path, crashHelperScenario+"="+scenario)
	return command
}

func runCrashHelper(t *testing.T, path, scenario string) (string, error) {
	t.Helper()
	output, err := crashHelperCommand(t, path, scenario).CombinedOutput()
	return string(output), err
}

func assertCrashExit(t *testing.T, err error, output string) {
	t.Helper()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != crashExitCode {
		t.Fatalf("helper exit=%v, want code %d\n%s", err, crashExitCode, output)
	}
}

func copyCrashFixtureFile(t *testing.T, source, target string, limit int64) {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if limit > 0 {
		contents = contents[:limit]
	}
	if err := os.WriteFile(target, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func crashHelperFail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func assertPublicationCounts(t *testing.T, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, expected [3]int) {
	t.Helper()
	for index, table := range []string{"command_receipts", "domain_events", "audit_entries"} {
		var count int
		if err := query.QueryRowContext(context.Background(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != expected[index] {
			t.Fatalf("%s rows=%d, want %d (all counts=%v)", table, count, expected[index], expected)
		}
	}
}

func insertCrashReceipt(tx *sql.Tx) error {
	_, err := tx.Exec(`INSERT INTO command_receipts(
		receipt_id, command_id, scope_kind, scope_id, authority_id, authority_epoch, identity_kind, workspace_id,
		principal_id, client_instance_id, operation, operation_major, idempotency_key, request_fingerprint, result_digest,
		result_canonical, first_event_sequence, last_event_sequence, final_stream_digest, guard_digest,
		capsule_required, committed_at_us
	) VALUES (?, ?, 'workspace', ?, ?, ?, 'ordinary_workspace', ?, ?, ?, 'actor.create.v1', 1,
		'crash-key', zeroblob(32), zeroblob(32), X'00', 1, 1, zeroblob(32), zeroblob(32), 0, 1)`,
		"01b8e094-9888-7000-8000-000000000100", "01b8e094-9888-7000-8000-000000000101",
		"01b8e094-9888-7000-8000-000000000102", "01b8e094-9888-7000-8000-000000000106",
		"01b8e094-9888-7000-8000-000000000103", "01b8e094-9888-7000-8000-000000000102",
		"01b8e094-9888-7000-8000-000000000104", "01b8e094-9888-7000-8000-00000000010a")
	return err
}

func insertCrashEvent(tx *sql.Tx) error {
	_, err := tx.Exec(`INSERT INTO domain_events(
        event_id, command_id, receipt_id, authority_id, authority_epoch, scope_kind, scope_id,
        stream_sequence, previous_stream_digest, event_digest, stream_digest, aggregate_kind,
        aggregate_id, aggregate_version, event_index, event_type, event_schema, payload, principal_id,
        authorization_digest, correlation_id, recorded_at_us
    ) VALUES (?, ?, ?, ?, ?, 'workspace', ?, 1, zeroblob(32), zeroblob(32), zeroblob(32), 'actor',
        ?, 1, 0, 'ActorCreated', 1, X'7b7d', ?, zeroblob(32), ?, 1)`,
		"01b8e094-9888-7000-8000-000000000105", "01b8e094-9888-7000-8000-000000000101",
		"01b8e094-9888-7000-8000-000000000100", "01b8e094-9888-7000-8000-000000000106",
		"01b8e094-9888-7000-8000-000000000103", "01b8e094-9888-7000-8000-000000000102",
		"01b8e094-9888-7000-8000-000000000107", "01b8e094-9888-7000-8000-000000000104",
		"01b8e094-9888-7000-8000-000000000108")
	return err
}

func insertCrashAudit(tx *sql.Tx) error {
	_, err := tx.Exec(`INSERT INTO audit_entries(
		scope_kind, scope_id, audit_sequence, previous_entry_hash, entry_hash, canonical_entry, recorded_at_us
	) VALUES ('workspace', ?, 1, zeroblob(32), randomblob(32), X'7b7d', 1)`,
		"01b8e094-9888-7000-8000-000000000102")
	return err
}
