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

// peeringAdmin is a fakeAdmin that also implements the optional PeeringPort. It
// is a separate type so the tests above keep asserting what a client WITHOUT
// that capability reports, which is nothing.
type peeringAdmin struct {
	fakeAdmin
	peering Peering
	err     error
}

func (admin *peeringAdmin) Peering() (Peering, error) {
	if admin.err != nil {
		return Peering{}, admin.err
	}
	return admin.peering, nil
}

// TestStatusReportsPeering is the observability half: an operator cannot debug
// what the tool will not tell them, and "on" without the address would be a
// fact they cannot act on.
func TestStatusReportsPeering(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		admin AdminPort
		want  string
	}{
		"on names the address it is reachable at": {
			&peeringAdmin{fakeAdmin: fakeAdmin{health: Health{Reachable: true, Ready: true}},
				peering: Peering{Enabled: true, Address: "100.78.103.8:8080"}},
			"peering    on 100.78.103.8:8080",
		},
		"off is stated rather than left out": {
			&peeringAdmin{fakeAdmin: fakeAdmin{health: Health{Reachable: true, Ready: true}}},
			"peering    off",
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			deps := dependencies(t)
			deps.Product = &fakeProduct{}
			deps.Store = &fakeStore{database: healthyDatabase()}
			deps.Admin = testCase.admin

			result := runCLI(t, deps, []string{"status", "--width=200"})
			if result.code != ExitOK {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
			}
			if !strings.Contains(result.stdout, testCase.want) {
				t.Fatalf("stdout = %q, want %q", result.stdout, testCase.want)
			}
		})
	}
}

// TestStatusSaysNothingAboutPeeringWhenItCannotRead is the honest silence: a
// client that could not read the record must not report peering as off, which
// would be a claim.
func TestStatusSaysNothingAboutPeeringWhenItCannotRead(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Store = &fakeStore{database: healthyDatabase()}
	deps.Admin = &peeringAdmin{fakeAdmin: fakeAdmin{health: Health{Reachable: true, Ready: true}},
		err: errors.New("no handshake record")}

	result := runCLI(t, deps, []string{"status", "--width=200"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if strings.Contains(result.stdout, "peering") {
		t.Fatalf("stdout = %q, want no claim about peering", result.stdout)
	}
}

// TestStatusWithoutAPeeringCapableClientSaysNothing keeps the optional
// capability optional.
func TestStatusWithoutAPeeringCapableClientSaysNothing(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Store = &fakeStore{database: healthyDatabase()}
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}

	result := runCLI(t, deps, []string{"status", "--width=200"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if strings.Contains(result.stdout, "peering") {
		t.Fatalf("stdout = %q, want no claim about peering", result.stdout)
	}
}
