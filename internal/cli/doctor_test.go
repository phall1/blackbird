package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/cli/render"
)

// doctorChecks runs doctor and returns the machine payload, which is the form a
// caller reacts to and the only one that cannot fold under the render width.
func doctorChecks(t *testing.T, deps Dependencies, args ...string) []checkResult {
	t.Helper()

	result := runCLI(t, deps, append([]string{"doctor", "--json"}, args...))
	var report doctorReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatalf("%v; stdout=%q stderr=%q", err, result.stdout, result.stderr)
	}
	return report.Checks
}

func onlyCheck(t *testing.T, deps Dependencies, name string) checkResult {
	t.Helper()

	checks := doctorChecks(t, deps, "--only="+name)
	if len(checks) != 1 {
		t.Fatalf("--only=%s produced %#v, want exactly one check", name, checks)
	}
	return checks[0]
}

func envOf(values map[string]string) render.Env {
	return func(name string) (string, bool) {
		value, found := values[name]
		return value, found
	}
}

// TestDoctorNamesADeadDaemonRatherThanBlamingStorage is the regression for the
// worst diagnosis this command produced: against a daemon that was not running
// at all it printed "daemon answered but storage is unavailable" above a
// connection-refused error, and sent the reader to inspect the database schema.
func TestDoctorNamesADeadDaemonRatherThanBlamingStorage(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{err: errors.New("contact daemon at 127.0.0.1:8080: connection refused")}

	check := onlyCheck(t, deps, "daemon.liveness")
	if check.Status != checkFail {
		t.Fatalf("status = %q, want %q", check.Status, checkFail)
	}
	if strings.Contains(check.Detail, "answered") {
		t.Fatalf("detail = %q, still says the daemon answered", check.Detail)
	}
	if !strings.Contains(check.Detail, "connection refused") {
		t.Fatalf("detail = %q, want the probe failure carried", check.Detail)
	}
	if !strings.Contains(check.Remedy, "blackbird install") {
		t.Fatalf("remedy = %q, want the command that starts the daemon", check.Remedy)
	}
	if strings.Contains(check.Remedy, "database.schema") {
		t.Fatalf("remedy = %q, still points at the database", check.Remedy)
	}
}

// A daemon that answers the liveness path and then reports its storage down is
// the other side of that distinction, and must keep its own diagnosis.
func TestDoctorStillNamesUnavailableStorageOnADaemonThatAnswers(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Detail: "storage is unavailable"}}

	check := onlyCheck(t, deps, "daemon.liveness")
	if check.Status != checkFail || !strings.Contains(check.Detail, "storage is unavailable") {
		t.Fatalf("check = %#v, want the storage diagnosis kept", check)
	}
}

func TestDoctorReadsTheDatabaseFactsItIsHanded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		check      string
		database   func(Database) Database
		want       string
		wantDetail string
		wantRemedy string
	}{
		{
			name:  "a group-readable database is a failure",
			check: "database.permissions",
			database: func(database Database) Database {
				database.FileMode = "-rw-r--r--"
				return database
			},
			want: checkFail, wantDetail: "-rw-r--r--", wantRemedy: "chmod 600",
		},
		{
			name:  "owner-only read and write passes",
			check: "database.permissions",
			database: func(database Database) Database {
				database.FileMode = ownerOnlyMode
				return database
			},
			want: checkPass, wantDetail: ownerOnlyMode,
		},
		{
			name:     "a mode nobody reported is not a finding",
			check:    "database.permissions",
			database: func(database Database) Database { return database },
			want:     checkPass,
		},
		{
			name:  "large disproportionate WAL warns",
			check: "database.wal",
			database: func(database Database) Database {
				database.SizeBytes = 2 << 20
				database.WALBytes = walWarningFloorBytes
				return database
			},
			want: checkWarn, wantDetail: "not keeping", wantRemedy: "gc --checkpoint",
		},
		{
			name:  "large proportional WAL passes",
			check: "database.wal",
			database: func(database Database) Database {
				database.SizeBytes = walWarningFloorBytes
				database.WALBytes = walWarningFloorBytes
				return database
			},
			want: checkPass, wantDetail: "wal=64 MiB",
		},
		{
			name:  "small disproportionate WAL passes",
			check: "database.wal",
			database: func(database Database) Database {
				database.SizeBytes = 4 << 10
				database.WALBytes = 1 << 20
				return database
			},
			want: checkPass, wantDetail: "wal=1 MiB",
		},
		{
			name:  "free space under the floor warns",
			check: "disk.free",
			database: func(database Database) Database {
				database.FreeBytes = 40 << 20
				return database
			},
			want: checkWarn, wantDetail: "floor", wantRemedy: "gc --vacuum",
		},
		{
			name:  "free space under ten times the database warns",
			check: "disk.free",
			database: func(database Database) Database {
				database.SizeBytes = 900 << 20
				database.FreeBytes = 2 << 30
				return database
			},
			want: checkWarn, wantDetail: "times the size",
		},
		{
			name:  "free space nobody measured is not a finding",
			check: "disk.free",
			database: func(database Database) Database {
				database.FreeBytes = 0
				return database
			},
			want: checkPass,
		},
		{
			name:  "a backlog of unreleased reservations warns",
			check: "reservations.expired",
			database: func(database Database) Database {
				database.ExpiredActiveLeases = expiredLeaseBacklog + 1
				return database
			},
			want: checkWarn, wantDetail: "releasing", wantRemedy: "--state=expired",
		},
		{
			name:  "ordinary churn does not warn",
			check: "reservations.expired",
			database: func(database Database) Database {
				database.ExpiredActiveLeases = expiredLeaseBacklog
				return database
			},
			want: checkPass,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			deps := dependencies(t)
			deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
			deps.Store = &fakeStore{database: test.database(healthyDatabase())}

			check := onlyCheck(t, deps, test.check)
			if check.Status != test.want {
				t.Fatalf("status = %q, want %q (detail=%q)", check.Status, test.want, check.Detail)
			}
			if !strings.Contains(check.Detail, test.wantDetail) {
				t.Fatalf("detail = %q, want it to name %q", check.Detail, test.wantDetail)
			}
			if !strings.Contains(check.Remedy, test.wantRemedy) {
				t.Fatalf("remedy = %q, want it to name %q", check.Remedy, test.wantRemedy)
			}
			if test.want == checkPass && check.Remedy != "" {
				t.Fatalf("remedy = %q on a passing check", check.Remedy)
			}
		})
	}
}

// TestDoctorHasAnOpinionAboutTheCleanShutdownFlag covers the row status renders
// that used to mean nothing: unclean beside a running daemon is the expected
// state of an open database, and only unclean with nothing serving reports a
// daemon that exited without closing up.
func TestDoctorHasAnOpinionAboutTheCleanShutdownFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		clean   bool
		serving bool
		want    string
		detail  string
	}{
		{name: "closed cleanly", clean: true, want: checkPass, detail: "clean_shutdown=yes"},
		{name: "open by a running daemon", serving: true, want: checkPass, detail: "expected while the daemon"},
		{name: "unclean with nothing serving", want: checkWarn, detail: cleanShutdownDetail},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			database := healthyDatabase()
			database.CleanShutdown = test.clean

			deps := dependencies(t)
			deps.Store = &fakeStore{database: database}
			if test.serving {
				deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
			} else {
				deps.Admin = &fakeAdmin{err: errors.New("connection refused")}
			}

			check := onlyCheck(t, deps, "database.shutdown")
			if check.Status != test.want || !strings.Contains(check.Detail, test.detail) {
				t.Fatalf("check = %#v, want %q naming %q", check, test.want, test.detail)
			}
			if test.want == checkWarn && !strings.Contains(check.Remedy, "logs --stream=err") {
				t.Fatalf("remedy = %q, want the log the crash is in", check.Remedy)
			}
		})
	}
}

// clientHomeWith writes the client configuration files install writes, and
// returns the environment that points doctor at them. A named client is given
// the URL passed for it; a client absent from the map has no file at all, which
// is how a machine without that client looks.
func clientHomeWith(t *testing.T, urls map[string]string) render.Env {
	t.Helper()

	home, config := t.TempDir(), t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if url, found := urls["claude"]; found {
		write(filepath.Join(home, ".claude.json"),
			`{"numStartups":7,"mcpServers":{"blackbird":{"type":"http","url":"`+url+`"}}}`)
	}
	if url, found := urls["codex"]; found {
		write(filepath.Join(home, ".codex", "config.toml"),
			"model = \"gpt\"\n\n# >>> blackbird\n"+codexBlackbirdTable+"\nurl = \""+url+"\"\n# <<< blackbird\n")
	}
	if url, found := urls["opencode"]; found {
		write(filepath.Join(config, "opencode", "opencode.json"),
			`{"theme":"dark","mcp":{"blackbird":{"type":"remote","url":"`+url+`"}}}`)
	}
	if _, found := urls["opencode-jsonc"]; found {
		write(filepath.Join(config, "opencode", "opencode.jsonc"), "// a comment JSON cannot hold\n{}\n")
	}
	if _, found := urls["claude-empty"]; found {
		write(filepath.Join(home, ".claude.json"), `{"numStartups":7,"mcpServers":{"other":{}}}`)
	}
	return envOf(map[string]string{"HOME": home, "XDG_CONFIG_HOME": config})
}

// TestDoctorVerifiesTheMCPClientEntries covers the failure nothing else can
// see: the clients rewrite their own configuration files, and an entry they
// drop takes Blackbird out of the agent's tool list while every other check
// stays green.
func TestDoctorVerifiesTheMCPClientEntries(t *testing.T) {
	t.Parallel()

	const url = "http://127.0.0.1:8081"
	tests := []struct {
		name    string
		files   map[string]string
		address string
		want    string
		detail  []string
	}{
		{
			name:  "every detected client carries the entry",
			files: map[string]string{"claude": url, "codex": url, "opencode": url},
			want:  checkPass, detail: []string{"claude=configured", "codex=configured", "opencode=configured"},
		},
		{
			name:  "a client that dropped the entry is named",
			files: map[string]string{"claude-empty": "", "codex": url},
			want:  checkWarn, detail: []string{"claude=" + clientMissing, "codex=configured"},
		},
		{
			name:  "an entry pointing somewhere else is drift, not absence",
			files: map[string]string{"codex": "http://127.0.0.1:9999"},
			want:  checkWarn, detail: []string{"codex=drifted(url=http://127.0.0.1:9999)"},
		},
		{
			name:  "a client this user does not have is not a finding",
			files: map[string]string{"claude": url},
			want:  checkPass, detail: []string{"claude=configured"},
		},
		{
			name:  "no client at all is not a finding",
			files: map[string]string{},
			want:  checkPass, detail: []string{"no MCP client configuration"},
		},
		{
			name:  "a JSONC configuration install will not touch is not drift",
			files: map[string]string{"opencode-jsonc": ""},
			want:  checkPass, detail: []string{"opencode=" + clientUnmanaged},
		},
		{
			// The entry is compared against the address this daemon serves MCP
			// on, not against a constant, so a daemon moved to another port
			// reports the entries as what they now are: wrong.
			name:    "the daemon's own address decides what is correct",
			files:   map[string]string{"claude": url},
			address: "127.0.0.1:9310", want: checkWarn,
			detail: []string{"url=http://127.0.0.1:9310", "claude=drifted"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			deps := dependencies(t)
			deps.Env = clientHomeWith(t, test.files)
			deps.Defaults.MCPAddress = test.address

			check := onlyCheck(t, deps, "clients")
			if check.Status != test.want {
				t.Fatalf("status = %q, want %q (detail=%q)", check.Status, test.want, check.Detail)
			}
			for _, want := range test.detail {
				if !strings.Contains(check.Detail, want) {
					t.Fatalf("detail = %q, want it to name %q", check.Detail, want)
				}
			}
			if test.want == checkWarn && !strings.Contains(check.Remedy, "blackbird install") {
				t.Fatalf("remedy = %q, want the command that rewrites the entries", check.Remedy)
			}
		})
	}
}

// The clients check reads files, so it must not read any when it was not asked
// for, and must not reach outside the environment it was given.
func TestDoctorReadsNoClientConfigurationWithoutAHome(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Env = envOf(map[string]string{})

	check := onlyCheck(t, deps, "clients")
	if check.Status != checkPass || !strings.Contains(check.Detail, "no MCP client configuration") {
		t.Fatalf("check = %#v, want a pass that reports nothing found", check)
	}
}
