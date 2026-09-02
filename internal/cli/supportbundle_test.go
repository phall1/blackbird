package cli

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/install"
)

// adminToken is the value the whole redaction contract is about: it is a live
// bearer credential for every message body on the machine, and a bundle is
// collected precisely so it can be sent to a stranger.
const adminToken = "0f9c2b7d4e1a63d58c07b2e94af16d3b"

// registrationToken is a credential this CLI has never seen and cannot hold a
// literal for. It is here so the assignment scrubber is tested by something
// other than the one secret the bundle already knows to remove.
const registrationToken = "Zm9vYmFyYmF6cXV4Y29ycmdl"

// stateDirProduct is fakeProduct pointed at a real directory, so the handshake
// record the bundle reads is a file on disk rather than a stub.
type stateDirProduct struct {
	fakeProduct
	stateDir string
}

func (product *stateDirProduct) StateDir() string { return product.stateDir }

type supportFixture struct {
	deps  Dependencies
	home  string
	state string
}

func supportBundleFixture(t *testing.T) supportFixture {
	t.Helper()

	home := t.TempDir()
	state := filepath.Join(home, ".local", "state", "blackbird")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	record := map[string]any{
		"schema": "blackbird.admin/v1", "http_address": "127.0.0.1:8080",
		"token": adminToken, "pid": 4242, "started_at": "2026-08-15T11:00:00Z", "version": "test",
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(install.HandshakePath(state), encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	// One client holding the entry install wrote and one that has lost it: the
	// bundle has to name which, because doctor collapses both into one line.
	writeFixtureFile(t, filepath.Join(home, ".claude.json"),
		`{"mcpServers":{"blackbird":{"url":"http://`+install.MCPAddress+`"}}}`)
	writeFixtureFile(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.other]\nurl = \"http://x\"\n")

	deps := dependencies(t)
	deps.DatabasePath = filepath.Join(home, ".local", "share", "blackbird", "blackbird.db")
	deps.Defaults = DaemonOptions{Storage: "sqlite", SQLitePath: deps.DatabasePath,
		StateDir: state, HTTPAddress: "127.0.0.1:8080", MCPAddress: install.MCPAddress}
	deps.Env = func(key string) (string, bool) {
		if key == "HOME" {
			return home, true
		}
		return "", false
	}
	deps.Admin = &fakeAdmin{
		health:   Health{Reachable: true, Ready: true, Version: "test", Address: "127.0.0.1:8080"},
		identity: Identity{PID: 4242, HTTPAddress: "127.0.0.1:8080", DatabasePath: deps.DatabasePath},
	}
	deps.Store = &fakeStore{database: healthyDatabase()}
	deps.Product = &stateDirProduct{stateDir: state}
	// The daemon is made to log its own credential twice over, in the two shapes
	// a leak actually takes: the literal value, and an assignment naming a
	// secret this CLI holds no copy of.
	deps.Logs = &fakeLogs{lines: []LogLine{
		{Stream: supportStreamOut, Text: "admin surface listening token=" + adminToken},
		{Stream: supportStreamErr, Text: `{"msg":"register","registration_token":"` + registrationToken + `"}`},
	}}
	return supportFixture{deps: deps, home: home, state: state}
}

// TestSupportBundleNeverEmitsTheAdminToken is the contract the command exists
// to keep. The token is planted in the handshake record and in a log line, and
// every surface the bundle has — the rendered report, the JSON payload, and the
// file --out writes — is searched for it.
func TestSupportBundleNeverEmitsTheAdminToken(t *testing.T) {
	t.Parallel()

	fixture := supportBundleFixture(t)
	out := filepath.Join(t.TempDir(), "nested", "bundle.json")

	surfaces := map[string]string{}
	for name, args := range map[string][]string{
		"rendered": {"support-bundle"},
		"json":     {"support-bundle", "--json"},
	} {
		result := runCLI(t, fixture.deps, args)
		if result.code != ExitOK {
			t.Fatalf("%s: code = %d, want %d; stderr=%q", name, result.code, ExitOK, result.stderr)
		}
		surfaces[name] = result.stdout + result.stderr
	}

	written := runCLI(t, fixture.deps, []string{"support-bundle", "--out=" + out})
	if written.code != ExitOK {
		t.Fatalf("--out: code = %d, want %d; stderr=%q", written.code, ExitOK, written.stderr)
	}
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	surfaces["file"] = string(content)
	surfaces["receipt"] = written.stdout + written.stderr

	for name, surface := range surfaces {
		if surface == "" {
			t.Fatalf("%s: produced no output", name)
		}
		if strings.Contains(surface, adminToken) {
			t.Errorf("%s: contains the admin token", name)
		}
		if strings.Contains(surface, registrationToken) {
			t.Errorf("%s: contains a credential-shaped log value", name)
		}
	}
	if !strings.Contains(surfaces["file"], redactedMarker) {
		t.Fatalf("bundle file records no redaction: %s", surfaces["file"])
	}
}

// The bundle is only worth redacting if it still carries the diagnosis, so the
// same run that proves the token is gone proves the sections are present.
func TestSupportBundleCarriesEverySection(t *testing.T) {
	t.Parallel()

	fixture := supportBundleFixture(t)
	result := runCLI(t, fixture.deps, []string{"support-bundle", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}

	var bundle supportBundle
	if err := json.Unmarshal([]byte(result.stdout), &bundle); err != nil {
		t.Fatalf("decode bundle: %v\n%s", err, result.stdout)
	}
	if bundle.Schema != supportBundleSchema {
		t.Errorf("schema = %q, want %q", bundle.Schema, supportBundleSchema)
	}
	if bundle.Build.Version != "test" || bundle.Host.OS == "" || bundle.Host.Arch == "" {
		t.Errorf("build/host = %+v %+v", bundle.Build, bundle.Host)
	}
	// --deep is not optional here: the integrity check is the one doctor only
	// runs when asked, and a reporter cannot be asked to re-run anything.
	if !checkNamed(bundle.Doctor.Checks, "database.integrity") {
		t.Errorf("doctor checks = %+v, want a deep integrity check", bundle.Doctor.Checks)
	}
	if bundle.Doctor.Passed == 0 {
		t.Errorf("doctor tally = %+v, want counted checks", bundle.Doctor)
	}
	if bundle.Status.Database.SizeBytes == 0 || bundle.GC == nil || bundle.GC.SizeBytes == 0 {
		t.Errorf("status/gc = %+v %+v", bundle.Status.Database, bundle.GC)
	}
	// Identity and the installer's own status line are reported at -v only, and
	// the bundle must not inherit the verbosity the user happened to type.
	if bundle.Status.Identity == nil || bundle.Status.ServiceLine == "" {
		t.Errorf("status = %+v, want the detailed projection", bundle.Status)
	}
	if len(bundle.Install.ServiceArgv) == 0 || bundle.Install.StateDir == "" ||
		bundle.Install.MCPURL == "" || bundle.Install.DefinitionState != install.DefinitionCurrent {
		t.Errorf("install = %+v", bundle.Install)
	}
	if !bundle.Handshake.Present || bundle.Handshake.PID != 4242 || !bundle.Handshake.TokenRedacted {
		t.Errorf("handshake = %+v", bundle.Handshake)
	}
	if len(bundle.Logs) != 2 || len(bundle.Logs[0].Lines) == 0 || len(bundle.Logs[1].Lines) == 0 {
		t.Errorf("logs = %+v, want a tail of each stream", bundle.Logs)
	}
	if len(bundle.Redaction.Removed) == 0 || len(bundle.Redaction.Kept) == 0 {
		t.Errorf("redaction = %+v, want the policy to travel with the bundle", bundle.Redaction)
	}
}

// The home prefix is rewritten rather than dropped: the shape of the path is
// the diagnosis, and the account name in it is not.
func TestSupportBundleRewritesHomePathsAndKeepsTheirShape(t *testing.T) {
	t.Parallel()

	fixture := supportBundleFixture(t)
	result := runCLI(t, fixture.deps, []string{"support-bundle", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if strings.Contains(result.stdout, fixture.home) {
		t.Errorf("bundle names the home directory %q", fixture.home)
	}
	for _, want := range []string{
		"~/.local/share/blackbird/blackbird.db",
		"~/.local/state/blackbird/" + install.HandshakeFileName,
	} {
		if !strings.Contains(result.stdout, want) {
			t.Errorf("bundle does not carry %q", want)
		}
	}
}

// A machine with nothing assembled is exactly the machine a bundle is collected
// from, so every port is missing here and the command still has to answer.
func TestSupportBundleSucceedsWithNoPortsAtAll(t *testing.T) {
	t.Parallel()

	result := runCLI(t, dependencies(t), []string{"support-bundle", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	var bundle supportBundle
	if err := json.Unmarshal([]byte(result.stdout), &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if len(bundle.Problems) == 0 {
		t.Errorf("problems = %v, want the missing ports named", bundle.Problems)
	}
	if len(bundle.Logs) != 2 || bundle.Logs[0].Detail == "" {
		t.Errorf("logs = %+v, want the missing source recorded per stream", bundle.Logs)
	}
	if bundle.Handshake.Present || bundle.Handshake.Detail == "" {
		t.Errorf("handshake = %+v, want an explained absence", bundle.Handshake)
	}
}

// A doctor run that fails exits ExitDegraded. The bundle that reports the same
// failure must not, or the command a user reaches for when Blackbird is broken
// is the one that refuses to produce anything.
func TestSupportBundleExitsOKWhileDoctorFails(t *testing.T) {
	t.Parallel()

	fixture := supportBundleFixture(t)
	fixture.deps.Store = &fakeStore{database: Database{Present: false}}

	if code := runCLI(t, fixture.deps, []string{"doctor", "--deep"}).code; code != ExitDegraded {
		t.Fatalf("doctor code = %d, want %d", code, ExitDegraded)
	}
	result := runCLI(t, fixture.deps, []string{"support-bundle"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if !strings.Contains(result.stdout, "FAIL") {
		t.Fatalf("stdout carries no failing check: %q", result.stdout)
	}
}

func TestSupportBundleOutWritesOwnerOnly(t *testing.T) {
	t.Parallel()

	fixture := supportBundleFixture(t)
	out := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(out, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runCLI(t, fixture.deps, []string{"support-bundle", "--out=" + out}).code; code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != fs.FileMode(0o600) {
		t.Fatalf("mode = %v, want -rw-------", mode)
	}
}

func TestSupportBundleRefusesARelativeOut(t *testing.T) {
	t.Parallel()

	fixture := supportBundleFixture(t)
	result := runCLI(t, fixture.deps, []string{"support-bundle", "--out=bundle.json"})
	if result.code != ExitUsage {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitUsage, result.stderr)
	}
}

// The scrubber runs over the encoded document, so these cases are the shapes it
// meets there: quoted values, assignments, and paths bounded by a separator or
// by JSON's own quoting.
func TestRedactorScrubsSecretsWithoutMauling(t *testing.T) {
	t.Parallel()

	scrub := redactor{home: "/home/al", secrets: []string{adminToken, "short"}}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "literal secret", in: `"` + adminToken + `"`, want: `"` + redactedMarker + `"`},
		{name: "bearer header", in: `"Authorization: Bearer abcdefgh12345"`,
			want: `"Authorization: Bearer ` + redactedMarker + `"`},
		{name: "json assignment", in: `"registration_token":"` + registrationToken + `"`,
			want: `"registration_token":"` + redactedMarker + `"`},
		// The shape a structured log line actually has once it is a string
		// inside this document: its own quoting escaped one level.
		{name: "escaped json assignment", in: `"{\"registration_token\":\"` + registrationToken + `\"}"`,
			want: `"{\"registration_token\":\"` + redactedMarker + `\"}"`},
		{name: "home prefix", in: `"/home/al/work/acme"`, want: `"~/work/acme"`},
		{name: "home exactly", in: `"/home/al"`, want: `"~"`},
		// A home of /home/al must not eat the front of another account's path.
		{name: "sibling account", in: `"/home/alice/work"`, want: `"/home/alice/work"`},
		// A short secret is not replaced: doing so would mangle ordinary text.
		{name: "short secret kept", in: `"a short sentence"`, want: `"a short sentence"`},
		// A word that merely reads like a credential keeps its sentence.
		{name: "prose survives", in: `"password is required"`, want: `"password is required"`},
		{name: "field name survives", in: `"token_redacted":true`, want: `"token_redacted":true`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := scrub.scrub(test.in); got != test.want {
				t.Fatalf("scrub(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

// A scrubbed document has to still be a document: the substitutions run on
// encoded JSON, so a replacement that crossed a delimiter would decode to
// something else or not at all.
func TestRedactorLeavesTheDocumentDecodable(t *testing.T) {
	t.Parallel()

	scrub := redactor{home: "/home/al", secrets: []string{adminToken}}
	bundle := supportBundle{
		Schema:    supportBundleSchema,
		Handshake: supportHandshake{Path: "/home/al/.local/state/blackbird/admin.json", Present: true},
		Logs: []supportLogStream{{Stream: supportStreamErr, Lines: []string{
			"token=" + adminToken + ", path=/home/al/x, note=<a & b>",
		}}},
		Redaction: supportRedactionPolicy,
	}
	redacted, err := scrub.apply(bundle)
	if err != nil {
		t.Fatalf("apply() = %v", err)
	}
	if redacted.Schema != supportBundleSchema || !redacted.Handshake.Present {
		t.Fatalf("round trip lost fields: %+v", redacted)
	}
	if redacted.Handshake.Path != "~/.local/state/blackbird/admin.json" {
		t.Errorf("handshake path = %q", redacted.Handshake.Path)
	}
	line := redacted.Logs[0].Lines[0]
	if strings.Contains(line, adminToken) || !strings.Contains(line, "note=<a & b>") {
		t.Errorf("log line = %q", line)
	}
}

func TestSupportBundleViewsRenderBothProjections(t *testing.T) {
	t.Parallel()

	views := []render.View{
		newView(supportBundle{Schema: supportBundleSchema,
			Logs: []supportLogStream{{Stream: supportStreamOut}}}, drawSupportBundle),
		newView(supportBundleReceipt{Path: "/tmp/bundle.json", Redaction: supportRedactionPolicy},
			drawSupportBundleReceipt),
	}
	for _, view := range views {
		if err := render.Conform(view); err != nil {
			t.Errorf("%T: %v", view, err)
		}
	}
}

// doctor reports every MCP client in one detail string, which is enough to say
// that something drifted and not enough to say what. The bundle is read by
// someone who cannot run a follow-up command, so it names each client.
func TestSupportBundleNamesEachMCPClient(t *testing.T) {
	t.Parallel()

	fixture := supportBundleFixture(t)
	result := runCLI(t, fixture.deps, []string{"support-bundle", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	var bundle supportBundle
	if err := json.Unmarshal([]byte(result.stdout), &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	states := map[string]string{}
	for _, client := range bundle.Clients {
		states[client.Name] = client.State
		if client.Path == "" {
			t.Errorf("client %+v has no path", client)
		}
	}
	if states["claude"] != clientConfigured || states["codex"] != clientMissing {
		t.Fatalf("clients = %+v, want claude configured and codex missing", bundle.Clients)
	}

	rendered := runCLI(t, fixture.deps, []string{"support-bundle"})
	if !strings.Contains(rendered.stdout, "codex") || !strings.Contains(rendered.stdout, clientMissing) {
		t.Fatalf("rendered bundle does not name the client that lost its entry:\n%s", rendered.stdout)
	}
}

func TestSupportBundleReportsAnUnwritableOut(t *testing.T) {
	t.Parallel()

	fixture := supportBundleFixture(t)
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	writeFixtureFile(t, blocker, "")

	result := runCLI(t, fixture.deps, []string{"support-bundle", "--out=" + filepath.Join(blocker, "bundle.json")})
	if result.code != ExitError {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitError, result.stderr)
	}
	if !strings.Contains(result.stderr, "remedy:") {
		t.Fatalf("stderr = %q, want a remedy", result.stderr)
	}
}

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func checkNamed(checks []checkResult, name string) bool {
	for _, check := range checks {
		if check.Name == name {
			return true
		}
	}
	return false
}
