package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/phall1/blackbird/internal/install"
)

// legacyDaemonServer is a daemon released before the handshake protocol: it
// serves its API, has no liveness endpoint, and writes no handshake record. It
// answers "404 page not found" at /healthz exactly as the installed v0.3.0
// daemon does, which is the state Homebrew leaves every existing machine in.
func legacyDaemonServer(t *testing.T) (address string, requests *atomic.Int64) {
	t.Helper()

	requests = &atomic.Int64{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/local/admin/overview", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		mux.ServeHTTP(writer, request)
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://"), requests
}

// undiscoveredDaemonServer is a CURRENT daemon that could not publish its
// discovery record: it answers the liveness endpoint normally, but the CLI has
// no record to read a credential from. Publishing is best-effort by design — a
// state directory left root-owned by a past sudo run produces exactly this —
// so the daemon must not be reported as dead.
func undiscoveredDaemonServer(t *testing.T) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok","version":"0.4.0"}`))
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

func TestStatusNamesAServingDaemonThatPublishedNoRecord(t *testing.T) {
	t.Parallel()

	address := undiscoveredDaemonServer(t)
	result := runCLI(t, upgradedDependencies(t, address), []string{"status", "--width=200"})

	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	for _, want := range []string{"no discovery record", `"blackbird install"`} {
		if !strings.Contains(result.stdout, want) {
			t.Fatalf("stdout = %q, want it to contain %q", result.stdout, want)
		}
	}
	if strings.Contains(result.stdout, "reachable  no") {
		t.Fatalf("stdout = %q, calls a daemon that answered /healthz unreachable", result.stdout)
	}
}

// A daemon that is serving is not a failing check. Reporting it as one sent the
// user to a clean log with a remedy that changed nothing.
func TestDoctorWarnsRatherThanFailsForAServingDaemonWithNoRecord(t *testing.T) {
	t.Parallel()

	address := undiscoveredDaemonServer(t)
	result := runCLI(t, upgradedDependencies(t, address),
		[]string{"doctor", "--only=daemon.liveness", "--json"})

	var report doctorReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatalf("%v; stdout=%q", err, result.stdout)
	}
	if len(report.Checks) != 1 {
		t.Fatalf("checks = %#v, want exactly daemon.liveness", report.Checks)
	}
	if report.Checks[0].Status != checkWarn {
		t.Fatalf("daemon.liveness = %q, want %q", report.Checks[0].Status, checkWarn)
	}
	if !strings.Contains(report.Checks[0].Remedy, "blackbird install") {
		t.Fatalf("remedy = %q, want the one command that republishes the record", report.Checks[0].Remedy)
	}
}

// closedAddress is an address nothing listens on, which is what a daemon that
// is genuinely down looks like.
func closedAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

// upgradedDependencies is the first run after "brew upgrade": a new CLI, an old
// daemon still serving under launchd, and no handshake record for the client to
// read, so every authenticated call fails before it dials.
func upgradedDependencies(t *testing.T, address string) Dependencies {
	t.Helper()

	deps := dependencies(t)
	deps.Defaults = DaemonOptions{HTTPAddress: address}
	deps.Admin = &fakeAdmin{err: errors.New("no daemon handshake record: /state/blackbird/admin.json")}
	deps.Product = &fakeProduct{status: "daemon=unreachable installed=true path=/service definition=stale " +
		"updater=scheduled installed=true paths=/updater interval=6h0m0s"}
	deps.Store = &fakeStore{database: healthyDatabase()}
	return deps
}

// TestStatusNamesTheOlderProtocolInsteadOfCallingAHealthyDaemonUnreachable is
// the regression for the first status after an upgrade. launchd does not
// restart a job when Homebrew replaces the binary, so a new CLI meets an old,
// perfectly healthy daemon and used to report "daemon unreachable" with a
// remedy that changed nothing.
func TestStatusNamesTheOlderProtocolInsteadOfCallingAHealthyDaemonUnreachable(t *testing.T) {
	t.Parallel()

	address, _ := legacyDaemonServer(t)
	result := runCLI(t, upgradedDependencies(t, address), []string{"status", "--width=200"})

	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	for _, want := range []string{"older protocol", `run "blackbird install"`} {
		if !strings.Contains(result.stdout, want) {
			t.Fatalf("stdout = %q, want it to contain %q", result.stdout, want)
		}
	}
	if strings.Contains(result.stdout, install.DaemonUnreachable) {
		t.Fatalf("stdout = %q, still calls a serving daemon unreachable", result.stdout)
	}
	if strings.Contains(result.stdout, "reachable  no") {
		t.Fatalf("stdout = %q, still reports a daemon that answered as unreachable", result.stdout)
	}
}

// TestStatusJSONCarriesTheProbeThatProvedTheDaemonIsServing keeps the machine
// payload honest: a caller parsing --json must see the same distinction the
// rendered report makes.
func TestStatusJSONCarriesTheProbeThatProvedTheDaemonIsServing(t *testing.T) {
	t.Parallel()

	address, _ := legacyDaemonServer(t)
	result := runCLI(t, upgradedDependencies(t, address), []string{"status", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}

	var report statusReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Legacy {
		t.Fatalf("report.Legacy = false, want the older protocol reported; payload=%s", result.stdout)
	}
	if report.Probe == nil || !report.Probe.Accepted || report.Probe.Status != http.StatusNotFound {
		t.Fatalf("report.Probe = %#v, want an accepted connection answering 404", report.Probe)
	}
	if report.Probe.Address != address {
		t.Fatalf("report.Probe.Address = %q, want %q", report.Probe.Address, address)
	}
}

// TestDoctorTreatsAnOlderProtocolAsOneWarningWithOneRemedy is the regression for
// two red failures whose remedies were useless: the log is clean and "update"
// only re-runs Homebrew. The single action that converges this machine is
// "install", and it must be the only one offered.
func TestDoctorTreatsAnOlderProtocolAsOneWarningWithOneRemedy(t *testing.T) {
	t.Parallel()

	address, _ := legacyDaemonServer(t)
	result := runCLI(t, upgradedDependencies(t, address), []string{"doctor", "--width=200"})

	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stdout=%q", result.code, ExitOK, result.stdout)
	}
	if strings.Contains(result.stdout, "FAIL") {
		t.Fatalf("stdout = %q, still fails a check on a healthy daemon", result.stdout)
	}
	if !strings.Contains(result.stdout, `run "blackbird install"`) {
		t.Fatalf("stdout = %q, want the install remedy", result.stdout)
	}
	for _, unwanted := range []string{"logs --stream=err", `"blackbird update"`} {
		if strings.Contains(result.stdout, unwanted) {
			t.Fatalf("stdout = %q, still offers %q, which changes nothing here", result.stdout, unwanted)
		}
	}
}

// TestDoctorProbesTheDaemonOnce holds the shared probe: the service check and
// the liveness check read one answer, so a single run cannot report two
// different daemons and cannot pay for the network twice.
func TestDoctorProbesTheDaemonOnce(t *testing.T) {
	t.Parallel()

	address, requests := legacyDaemonServer(t)
	if code := runCLI(t, upgradedDependencies(t, address), []string{"doctor"}).code; code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("liveness requests = %d, want exactly 1", got)
	}
}

// TestHealthyDaemonIsNeverProbedOverTheNetwork keeps the added probe off the
// path every working installation takes: the admin client already answered.
func TestHealthyDaemonIsNeverProbedOverTheNetwork(t *testing.T) {
	t.Parallel()

	address, requests := legacyDaemonServer(t)
	deps := upgradedDependencies(t, address)
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true, Version: "0.4.0", SchemaVersion: 4}}
	deps.Product = &fakeProduct{}

	if code := runCLI(t, deps, []string{"status"}).code; code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("liveness requests = %d, want none when the client already answered", got)
	}
}

// TestStatusStillReportsADaemonThatIsGenuinelyDown guards the other side of the
// distinction: nothing listening is still unreachable, and its checks still
// fail.
func TestStatusStillReportsADaemonThatIsGenuinelyDown(t *testing.T) {
	t.Parallel()

	deps := upgradedDependencies(t, closedAddress(t))
	result := runCLI(t, deps, []string{"status", "--width=200"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if strings.Contains(result.stdout, "older protocol") {
		t.Fatalf("stdout = %q, claims an older protocol with nothing listening", result.stdout)
	}
	if code := runCLI(t, deps, []string{"doctor"}).code; code != ExitDegraded {
		t.Fatalf("doctor code = %d, want %d", code, ExitDegraded)
	}
}

// TestRequireRunningPointsAtInstallForAnOlderProtocol keeps the unattended path
// aligned with the rendered one: the exit code still says unavailable, but the
// remedy is the command that fixes it.
func TestRequireRunningPointsAtInstallForAnOlderProtocol(t *testing.T) {
	t.Parallel()

	address, _ := legacyDaemonServer(t)
	result := runCLI(t, upgradedDependencies(t, address), []string{"status", "--require-running"})
	if result.code != ExitUnavailable {
		t.Fatalf("code = %d, want %d", result.code, ExitUnavailable)
	}
	if !strings.Contains(result.stderr, `run "blackbird install"`) {
		t.Fatalf("stderr = %q, want the install remedy", result.stderr)
	}
	if !strings.Contains(result.stderr, "older protocol") {
		t.Fatalf("stderr = %q, want the state named", result.stderr)
	}
}

// TestProbeLivenessSeparatesNoDaemonFromAnOlderOne pins the one inference the
// whole slice rests on. A 200 belongs to a current daemon whose handshake
// record merely went missing, and calling that an older protocol would send a
// user to "install" for nothing.
func TestProbeLivenessSeparatesNoDaemonFromAnOlderOne(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		status       int
		closed       bool
		wantAccepted bool
		wantLegacy   bool
	}{
		{name: "no daemon at all", closed: true},
		{name: "older protocol", status: http.StatusNotFound, wantAccepted: true, wantLegacy: true},
		{name: "current daemon without a handshake record", status: http.StatusOK, wantAccepted: true},
		{name: "current daemon with storage down", status: http.StatusServiceUnavailable, wantAccepted: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var address string
			if test.closed {
				address = closedAddress(t)
			} else {
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.WriteHeader(test.status)
				}))
				t.Cleanup(server.Close)
				address = strings.TrimPrefix(server.URL, "http://")
			}

			probe := probeLiveness(context.Background(), address)
			if probe.Accepted != test.wantAccepted {
				t.Fatalf("probe.Accepted = %t, want %t (detail=%q)", probe.Accepted, test.wantAccepted, probe.Detail)
			}
			legacy := probe.Accepted && probe.Status == http.StatusNotFound
			if legacy != test.wantLegacy {
				t.Fatalf("legacy = %t, want %t; probe=%#v", legacy, test.wantLegacy, probe)
			}
		})
	}
}

// TestProbeLivenessWithoutAnAddressDialsNothing keeps the probe off the network
// when no address is configured, which is the state of an assembly with no
// injected defaults.
func TestProbeLivenessWithoutAnAddressDialsNothing(t *testing.T) {
	t.Parallel()

	if probe := probeLiveness(context.Background(), ""); probe.Accepted || probe.Status != 0 {
		t.Fatalf("probe = %#v, want an untouched probe", probe)
	}
}
