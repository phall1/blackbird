package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

func TestGrammarBuilds(t *testing.T) {
	t.Parallel()

	console := &Console{Deps: Dependencies{}, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	grammar := CLI{}
	if _, err := newParser(context.Background(), &grammar, console); err != nil {
		t.Fatalf("newParser() = %v, want no error", err)
	}
}

func TestNoGroupCommandDefinesRun(t *testing.T) {
	t.Parallel()

	groups := []any{&CLI{}, &ProjectsCmd{}, &AgentsCmd{}, &ThreadsCmd{}, &ReservationsCmd{}}
	for _, group := range groups {
		value := reflect.TypeOf(group)
		if _, found := value.MethodByName("Run"); found {
			t.Errorf("%s declares Run; Kong invokes Run on every node from the leaf to the root", value)
		}
	}
}

func TestBareInvocationPrintsHelpAndExitsOK(t *testing.T) {
	t.Parallel()

	result := runCLI(t, dependencies(t), nil)
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if !strings.Contains(result.stdout, "Usage: blackbird") {
		t.Fatalf("stdout = %q, want a usage block", result.stdout)
	}
	if strings.Contains(result.stderr, "flag") {
		t.Fatalf("stderr = %q, want no flag-package error", result.stderr)
	}
}

// TestBareInvocationCreatesNoFiles is the regression test for the stray
// database: a bare invocation used to start the daemon and migrate a fully
// populated blackbird.db into whatever directory the user happened to stand in.
func TestBareInvocationCreatesNoFiles(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)

	if code := runCLI(t, dependencies(t), nil).code; code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("working directory contains %v, want nothing", entries)
	}
}

func TestHelpFlagPrintsHelpAndExitsOK(t *testing.T) {
	t.Parallel()

	for _, argument := range []string{"--help", "-h"} {
		result := runCLI(t, dependencies(t), []string{argument})
		if result.code != ExitOK {
			t.Fatalf("%s: code = %d, want %d", argument, result.code, ExitOK)
		}
		if !strings.Contains(result.stdout, "Usage: blackbird") {
			t.Fatalf("%s: stdout = %q", argument, result.stdout)
		}
		if strings.Contains(result.stdout+result.stderr, "flag: help requested") {
			t.Fatalf("%s: leaked the flag package's help error", argument)
		}
	}
}

// TestHelpFlagDoesNotRunTheCommand covers Kong's help hook, which calls Exit and
// then returns nil: an exit function that returns lets parsing continue and the
// selected command run, so "daemon --help" would print help and start a daemon.
func TestHelpFlagDoesNotRunTheCommand(t *testing.T) {
	t.Parallel()

	daemon := &recordingDaemon{}
	deps := dependencies(t)
	deps.Daemon = daemon

	result := runCLI(t, deps, []string{"daemon", "--help"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d", result.code, ExitOK)
	}
	if daemon.calls != 0 {
		t.Fatalf("daemon ran %d times, want 0", daemon.calls)
	}
}

func TestHelpSubcommandMatchesHelpFlag(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	viaCommand := runCLI(t, deps, []string{"help", "status"})
	viaFlag := runCLI(t, deps, []string{"status", "--help"})
	if viaCommand.stdout != viaFlag.stdout {
		t.Fatalf("help status =\n%s\nstatus --help =\n%s", viaCommand.stdout, viaFlag.stdout)
	}
	if viaCommand.code != ExitOK || viaFlag.code != ExitOK {
		t.Fatalf("codes = %d and %d, want %d", viaCommand.code, viaFlag.code, ExitOK)
	}
}

func TestHelpSubcommandRejectsUnknownCommand(t *testing.T) {
	t.Parallel()

	result := runCLI(t, dependencies(t), []string{"help", "nonesuch"})
	if result.code != ExitUsage {
		t.Fatalf("code = %d, want %d", result.code, ExitUsage)
	}
}

func TestUnknownCommandSuggestsNearest(t *testing.T) {
	t.Parallel()

	result := runCLI(t, dependencies(t), []string{"staus"})
	if result.code != ExitUsage {
		t.Fatalf("code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, `did you mean "status"?`) {
		t.Fatalf("stderr = %q, want a suggestion", result.stderr)
	}
}

func TestUnknownFlagExitsUsage(t *testing.T) {
	t.Parallel()

	result := runCLI(t, dependencies(t), []string{"status", "--jsn"})
	if result.code != ExitUsage {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitUsage, result.stderr)
	}
	if !strings.Contains(result.stderr, "unknown flag") {
		t.Fatalf("stderr = %q, want an unknown-flag error", result.stderr)
	}
}

// TestVersionOutputIsFrozen guards the string the release workflow asserts
// against the build it just compiled. Changing it fails the release.
func TestVersionOutputIsFrozen(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Build = BuildInfo{Version: "0.4.0", Commit: "abc1234", BuiltAt: "2026-08-15T00:00:00Z"}
	const want = "blackbird version=0.4.0 commit=abc1234 built_at=2026-08-15T00:00:00Z\n"

	for _, args := range [][]string{{"--version"}, {"version"}} {
		result := runCLI(t, deps, args)
		if result.code != ExitOK {
			t.Fatalf("%v: code = %d, want %d; stderr=%q", args, result.code, ExitOK, result.stderr)
		}
		if result.stdout != want {
			t.Fatalf("%v: stdout = %q, want %q", args, result.stdout, want)
		}
	}
}

func TestVersionFlagHonoursJSON(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Build = BuildInfo{Version: "0.4.0", Commit: "abc1234", BuiltAt: "then"}
	result := runCLI(t, deps, []string{"--version", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	var decoded BuildInfo
	if err := json.Unmarshal([]byte(result.stdout), &decoded); err != nil {
		t.Fatalf("stdout = %q is not JSON: %v", result.stdout, err)
	}
	if decoded != deps.Build {
		t.Fatalf("payload = %#v, want %#v", decoded, deps.Build)
	}
}

func TestVersionFlagAfterCommandDoesNotRunIt(t *testing.T) {
	t.Parallel()

	daemon := &recordingDaemon{}
	deps := dependencies(t)
	deps.Daemon = daemon
	result := runCLI(t, deps, []string{"daemon", "--version"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if daemon.calls != 0 {
		t.Fatalf("daemon ran %d times, want 0", daemon.calls)
	}
	if !strings.HasPrefix(result.stdout, "blackbird version=") {
		t.Fatalf("stdout = %q", result.stdout)
	}
}

func TestNormalizeLegacyArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		want       []string
		wantNotice bool
	}{
		{name: "empty", args: nil, want: nil},
		{name: "installed plist argv", args: []string{"--sqlite-path=/tmp/blackbird.db"},
			want: []string{"daemon", "--sqlite-path=/tmp/blackbird.db"}, wantNotice: true},
		{name: "single hyphen", args: []string{"-sqlite-path", "/tmp/b.db"},
			want: []string{"daemon", "-sqlite-path", "/tmp/b.db"}, wantNotice: true},
		{name: "storage", args: []string{"--storage=sqlite"},
			want: []string{"daemon", "--storage=sqlite"}, wantNotice: true},
		{name: "http address", args: []string{"--http-address=127.0.0.1:9000"},
			want: []string{"daemon", "--http-address=127.0.0.1:9000"}, wantNotice: true},
		{name: "mcp address", args: []string{"--mcp-address=127.0.0.1:9001"},
			want: []string{"daemon", "--mcp-address=127.0.0.1:9001"}, wantNotice: true},
		{name: "explicit daemon", args: []string{"daemon", "--sqlite-path=/tmp/b.db"},
			want: []string{"daemon", "--sqlite-path=/tmp/b.db"}},
		{name: "other command", args: []string{"status", "--db=/tmp/b.db"},
			want: []string{"status", "--db=/tmp/b.db"}},
		{name: "global flag first", args: []string{"--json", "status"},
			want: []string{"--json", "status"}},
		{name: "version flag", args: []string{"--version"}, want: []string{"version"}},
		{name: "version flag with global", args: []string{"--json", "--version"},
			want: []string{"version", "--json"}},
		{name: "version after command", args: []string{"status", "--version"},
			want: []string{"status", "--version"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, notice := Normalize(test.args)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Normalize(%v) = %v, want %v", test.args, got, test.want)
			}
			if (notice != "") != test.wantNotice {
				t.Fatalf("notice = %q, wantNotice=%t", notice, test.wantNotice)
			}
		})
	}
}

// TestLegacyPlistArgvStillStartsTheDaemon feeds the exact argv the installed
// launchd plist runs. Homebrew replaces the binary before anything can rewrite
// that file, so rejecting this argv crash-loops every upgraded machine.
func TestLegacyPlistArgvStillStartsTheDaemon(t *testing.T) {
	t.Parallel()

	daemon := &recordingDaemon{}
	deps := dependencies(t)
	deps.Daemon = daemon

	const path = "/Users/phall/.local/share/blackbird/blackbird.db"
	result := runCLI(t, deps, []string{"--sqlite-path=" + path})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if daemon.calls != 1 {
		t.Fatalf("daemon ran %d times, want 1", daemon.calls)
	}
	if daemon.options.SQLitePath != path {
		t.Fatalf("SQLitePath = %q, want %q", daemon.options.SQLitePath, path)
	}
	if !strings.Contains(result.stderr, "deprecated") {
		t.Fatalf("stderr = %q, want a deprecation notice", result.stderr)
	}
	if result.stdout != "" {
		t.Fatalf("stdout = %q, want the notice on stderr only", result.stdout)
	}
}

func TestDaemonRejectsRelativeSQLitePath(t *testing.T) {
	t.Parallel()

	daemon := &recordingDaemon{}
	deps := dependencies(t)
	deps.Daemon = daemon

	result := runCLI(t, deps, []string{"daemon", "--sqlite-path=blackbird.db"})
	if result.code != ExitUsage {
		t.Fatalf("code = %d, want %d", result.code, ExitUsage)
	}
	if daemon.calls != 0 {
		t.Fatalf("daemon ran %d times, want 0", daemon.calls)
	}
}

func TestDatabaseFlagRejectsRelativePaths(t *testing.T) {
	t.Parallel()

	result := runCLI(t, dependencies(t), []string{"--db=blackbird.db", "status"})
	if result.code != ExitUsage {
		t.Fatalf("code = %d, want %d", result.code, ExitUsage)
	}
	if !strings.Contains(result.stderr, "--db") {
		t.Fatalf("stderr = %q, want the flag named", result.stderr)
	}
}

func TestDatabaseFlagExpandsHome(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	store := &fakeStore{}
	deps := dependencies(t)
	deps.Store = store
	deps.Admin = &fakeAdmin{}

	result := runCLI(t, deps, []string{"--db=~/blackbird.db", "status"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if want := filepath.Join(home, "blackbird.db"); store.path != want {
		t.Fatalf("path = %q, want %q", store.path, want)
	}
}

func TestGlobalFlagsParseBeforeAndAfterSubcommand(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{}
	for _, args := range [][]string{{"--json", "overview"}, {"overview", "--json"}} {
		result := runCLI(t, deps, args)
		if result.code != ExitOK {
			t.Fatalf("%v: code = %d; stderr=%q", args, result.code, result.stderr)
		}
		if !strings.HasPrefix(result.stdout, "{") {
			t.Fatalf("%v: stdout = %q, want JSON", args, result.stdout)
		}
	}
}

// addressableAdmin is an admin client whose target address can be set after the
// flags are parsed, which is what the production client does.
type addressableAdmin struct {
	fakeAdmin
	address string
}

func (admin *addressableAdmin) SetAddress(address string) { admin.address = address }

// TestAddressReachesTheAdminClient is the regression for a flag that rendered
// in --help and was wired to nothing: --address and $BLACKBIRD_ADDRESS are the
// only escape hatch when the handshake record names an address no daemon
// answers on, and neither of them changed where a request was sent.
func TestAddressReachesTheAdminClient(t *testing.T) {
	tests := []struct {
		name string
		env  string
		args []string
		want string
	}{
		{name: "flag before the command", args: []string{"--address=127.0.0.1:18300", "overview"}, want: "127.0.0.1:18300"},
		{name: "flag after the command", args: []string{"overview", "--address=127.0.0.1:18300"}, want: "127.0.0.1:18300"},
		{name: "environment", env: "127.0.0.1:18300", args: []string{"overview"}, want: "127.0.0.1:18300"},
		{name: "flag beats the environment", env: "127.0.0.1:1", args: []string{"--address=127.0.0.1:18300", "overview"},
			want: "127.0.0.1:18300"},
		{name: "unset leaves the handshake record authoritative", args: []string{"overview"}, want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("BLACKBIRD_ADDRESS", test.env)

			admin := &addressableAdmin{}
			deps := dependencies(t)
			deps.Admin = admin

			result := runCLI(t, deps, test.args)
			if result.code != ExitOK {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
			}
			if admin.address != test.want {
				t.Fatalf("client address = %q, want %q", admin.address, test.want)
			}
		})
	}
}

// Every admin request carries the daemon's bearer token, so a non-loopback
// address would exfiltrate the credential. The env binding makes that reachable
// without the user typing anything, so it must be refused before the client is
// ever handed the value.
func TestAddressRefusesToCarryTheTokenOffTheMachine(t *testing.T) {
	tests := []string{"192.168.1.157:19999", "example.com:8080", "0.0.0.0:8080", "[2001:db8::1]:8080"}
	for _, address := range tests {
		t.Run(address, func(t *testing.T) {
			t.Setenv("BLACKBIRD_ADDRESS", address)

			admin := &addressableAdmin{}
			deps := dependencies(t)
			deps.Admin = admin
			deps.Env = os.LookupEnv

			result := runCLI(t, deps, []string{"overview"})
			if result.code != ExitUsage {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitUsage, result.stderr)
			}
			if !strings.Contains(result.stderr, "loopback") {
				t.Fatalf("stderr = %q, want the loopback requirement stated", result.stderr)
			}
			if admin.address != "" {
				t.Fatalf("client address = %q, want a remote address never applied", admin.address)
			}
		})
	}
}

func TestAddressAcceptsLoopbackForms(t *testing.T) {
	tests := []string{"127.0.0.1:18300", "localhost:18300", "[::1]:18300"}
	for _, address := range tests {
		t.Run(address, func(t *testing.T) {
			t.Setenv("BLACKBIRD_ADDRESS", "")

			admin := &addressableAdmin{}
			deps := dependencies(t)
			deps.Admin = admin

			if result := runCLI(t, deps, []string{"--address=" + address, "overview"}); result.code == ExitUsage {
				t.Fatalf("loopback address rejected: stderr=%q", result.stderr)
			}
			if admin.address != address {
				t.Fatalf("client address = %q, want %q", admin.address, address)
			}
		})
	}
}

func TestAddressRejectsAValueThatIsNotHostPort(t *testing.T) {
	tests := []string{"nonsense", "http://127.0.0.1:8080", ":8080", "127.0.0.1:"}
	for _, address := range tests {
		t.Run(address, func(t *testing.T) {
			t.Setenv("BLACKBIRD_ADDRESS", "")

			admin := &addressableAdmin{}
			deps := dependencies(t)
			deps.Admin = admin

			result := runCLI(t, deps, []string{"--address=" + address, "overview"})
			if result.code != ExitUsage {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitUsage, result.stderr)
			}
			if !strings.Contains(result.stderr, "--address") {
				t.Fatalf("stderr = %q, want the flag named", result.stderr)
			}
			if admin.address != "" {
				t.Fatalf("client address = %q, want an unusable value never applied", admin.address)
			}
		})
	}
}

func TestEnvironmentBindings(t *testing.T) {
	deps := dependencies(t)
	deps.Admin = &fakeAdmin{}
	deps.Env = os.LookupEnv
	t.Setenv("BLACKBIRD_JSON", "true")

	result := runCLI(t, deps, []string{"overview"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if !strings.HasPrefix(result.stdout, "{") {
		t.Fatalf("stdout = %q, want JSON from BLACKBIRD_JSON", result.stdout)
	}
}

func TestJSONErrorsGoToStderrNotStdout(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{err: errors.New("connection refused")}

	result := runCLI(t, deps, []string{"overview", "--json"})
	if result.code != ExitUnavailable {
		t.Fatalf("code = %d, want %d", result.code, ExitUnavailable)
	}
	if result.stdout != "" {
		t.Fatalf("stdout = %q, want empty", result.stdout)
	}
	var envelope errorEnvelope
	if err := json.Unmarshal([]byte(result.stderr), &envelope); err != nil {
		t.Fatalf("stderr = %q is not JSON: %v", result.stderr, err)
	}
	if envelope.Error.Exit != ExitUnavailable || envelope.Error.Code != "unavailable" {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestExitCodesRoundTripThroughRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: ExitOK},
		{name: "plain", err: errors.New("boom"), want: ExitError},
		{name: "usage", err: usageFault("bad"), want: ExitUsage},
		{name: "not found", err: notFoundFault("gone"), want: ExitNotFound},
		{name: "unavailable", err: unavailableFault(nil, "down"), want: ExitUnavailable},
		{name: "degraded", err: fault(ExitDegraded, nil, "checks failed"), want: ExitDegraded},
		{name: "parse", err: &kong.ParseError{}, want: ExitUsage},
		{name: "wrapped fault", err: fmt.Errorf("outer: %w", notFoundFault("gone")), want: ExitNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := exitCodeFor(test.err); got != test.want {
				t.Fatalf("exitCodeFor(%v) = %d, want %d", test.err, got, test.want)
			}
		})
	}
}

func TestSignalCancellationExitsZero(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	daemon := &recordingDaemon{}
	deps := dependencies(t)
	deps.Daemon = daemon
	var stdout, stderr bytes.Buffer
	if code := Run(ctx, deps, []string{"daemon"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if daemon.calls != 0 {
		t.Fatalf("daemon ran %d times, want 0 on a cancelled context", daemon.calls)
	}
}

func TestRunRepanicsForeignPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("Run swallowed a panic that is not an exit status")
		}
	}()
	deps := dependencies(t)
	deps.Admin = panickingAdmin{}
	_ = Run(context.Background(), deps, []string{"overview"}, &bytes.Buffer{}, &bytes.Buffer{})
}

func TestFaultErrorCarriesCauseAndRemedy(t *testing.T) {
	t.Parallel()

	cause := errors.New("dial tcp: refused")
	err := withRemedy(unavailableFault(cause, "reach the daemon"), "start the daemon")
	if !errors.Is(err, cause) {
		t.Fatal("cause is not unwrappable")
	}
	if got, want := err.Error(), "reach the daemon: dial tcp: refused"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if err.Remedy != "start the daemon" {
		t.Fatalf("Remedy = %q", err.Remedy)
	}
	if got := (&FaultError{Message: "alone"}).Error(); got != "alone" {
		t.Fatalf("Error() = %q, want %q", got, "alone")
	}
}

func TestExitNameFallsBackToError(t *testing.T) {
	t.Parallel()

	if got := exitName(99); got != "error" {
		t.Fatalf("exitName(99) = %q, want %q", got, "error")
	}
	if got := exitName(ExitDegraded); got != "degraded" {
		t.Fatalf("exitName(5) = %q", got)
	}
}

func TestPreflightScanResolvesStyleBeforeParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		wantJSON  bool
		wantColor bool
	}{
		{name: "plain", args: []string{"status"}},
		{name: "json", args: []string{"--json", "status"}, wantJSON: true},
		{name: "color always", args: []string{"--color=always"}, wantColor: true},
		{name: "no color wins", args: []string{"--color=always", "--no-color"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			scanned := scanPreflight(test.args, func(string) (string, bool) { return "", false })
			if scanned.json != test.wantJSON {
				t.Fatalf("json = %t, want %t", scanned.json, test.wantJSON)
			}
			if got := scanned.style(Dependencies{}).Color(); got != test.wantColor {
				t.Fatalf("color = %t, want %t", got, test.wantColor)
			}
		})
	}
}

func TestGrammarVarsFillEveryInterpolatedDefault(t *testing.T) {
	t.Parallel()

	vars := grammarVars(Dependencies{DatabasePath: "/tmp/b.db"})
	for _, key := range []string{
		"db_default", "address_default", "daemon_storage", "daemon_sqlite_path",
		"daemon_state_dir", "daemon_http_address", "daemon_mcp_address",
		"daemon_log_level", "daemon_shutdown_timeout", "version",
	} {
		if _, ok := vars[key]; !ok {
			t.Errorf("grammarVars is missing %q", key)
		}
	}
	if vars["daemon_sqlite_path"] != "/tmp/b.db" {
		t.Fatalf("daemon_sqlite_path = %q", vars["daemon_sqlite_path"])
	}
	if vars["daemon_shutdown_timeout"] != (30 * time.Second).String() {
		t.Fatalf("daemon_shutdown_timeout = %q", vars["daemon_shutdown_timeout"])
	}
}
