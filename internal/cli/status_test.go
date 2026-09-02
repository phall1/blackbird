package cli

import (
	"errors"
	"strings"
	"testing"
)

// TestStatusExplainsTheCleanShutdownFlag covers a row that alarmed every reader
// who found it: the flag is cleared only when the daemon closes the database,
// so "no" beside a running daemon is the expected state and says nothing about
// a crash. Left bare it taught readers that status output does not mean
// anything, which costs more than the row is worth.
func TestStatusExplainsTheCleanShutdownFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		serving  bool
		want     string
		problem  bool
		unwanted string
	}{
		{name: "the daemon holds the database open", serving: true,
			want: "expected while the daemon holds the database open"},
		{name: "nothing is serving", want: cleanShutdownDetail, problem: true,
			unwanted: "expected while the daemon"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			database := healthyDatabase()
			database.CleanShutdown = false

			deps := dependencies(t)
			deps.Product = &fakeProduct{}
			deps.Store = &fakeStore{database: database}
			if test.serving {
				deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
			} else {
				deps.Admin = &fakeAdmin{err: errors.New("connection refused")}
			}

			result := runCLI(t, deps, []string{"status", "--width=200"})
			if result.code != ExitOK {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
			}
			if !strings.Contains(result.stdout, test.want) {
				t.Fatalf("stdout = %q, want it to explain the flag with %q", result.stdout, test.want)
			}
			if test.unwanted != "" && strings.Contains(result.stdout, test.unwanted) {
				t.Fatalf("stdout = %q, still calls an unclean database expected", result.stdout)
			}
			if problem := strings.Contains(result.stdout, cleanShutdownProblem); problem != test.problem {
				t.Fatalf("problem reported = %t, want %t; stdout=%q", problem, test.problem, result.stdout)
			}
		})
	}
}

// TestStatusReportsAnUnreachableDaemonWithoutFailing pins a deliberate choice.
// Plain status is a report, and unattended callers already have the flag that
// turns liveness into an exit code: --require-running exits ExitUnavailable.
// Making the bare command exit non-zero would change the contract under every
// script that runs it for its output, so the diagnosis lives in doctor, whose
// exit code already means "a check failed".
func TestStatusReportsAnUnreachableDaemonWithoutFailing(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Store = &fakeStore{database: healthyDatabase()}
	deps.Admin = &fakeAdmin{err: errors.New("connection refused")}

	result := runCLI(t, deps, []string{"status", "--width=200"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if !strings.Contains(result.stdout, "reachable  no") {
		t.Fatalf("stdout = %q, want the daemon reported unreachable", result.stdout)
	}

	required := runCLI(t, deps, []string{"status", "--require-running"})
	if required.code != ExitUnavailable {
		t.Fatalf("--require-running code = %d, want %d", required.code, ExitUnavailable)
	}
}
