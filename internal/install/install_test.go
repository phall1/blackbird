package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInstallConvergesServiceAndDetectedClientConfigs(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	configHome := filepath.Join(home, "config")
	mustMkdir(t, filepath.Join(configHome, "opencode"))
	mustMkdir(t, filepath.Join(home, ".claude"))
	mustMkdir(t, filepath.Join(home, ".codex"))
	mustWrite(t, filepath.Join(configHome, "opencode", "opencode.json"), `{"theme":"existing","mcp":{"other":{"type":"remote","url":"https://example.test"}}}`)
	mustWrite(t, filepath.Join(home, ".claude.json"), `{"projects":{"keep":true},"mcpServers":{"other":{"command":"other"}}}`)
	mustWrite(t, filepath.Join(home, ".codex", "config.toml"), "model = \"gpt-5\"\n\n[mcp_servers.blackbird]\nurl = \"http://old.test\"\n\n[features]\nsearch = true\n")
	runner := &recordingRunner{}
	manager := testManager(home, "linux", runner)

	first, err := manager.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		first.ServicePath,
		first.CompanionPath,
		first.UpdaterPaths[0],
		first.UpdaterPaths[1],
		filepath.Join(configHome, "opencode", "opencode.json"),
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".codex", "config.toml"),
	}
	firstContent := readAll(t, paths)
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if secondContent := readAll(t, paths); !reflect.DeepEqual(secondContent, firstContent) {
		t.Fatalf("second install changed converged files\nfirst=%q\nsecond=%q", firstContent, secondContent)
	}

	if got := firstContent[paths[2]]; !strings.Contains(got, "ExecStart=") || !strings.Contains(got, " update") ||
		!strings.Contains(got, "/home/linuxbrew/.linuxbrew/bin") || strings.Contains(got, "Restart=") {
		t.Fatalf("systemd updater service = %s", got)
	}
	if got := firstContent[paths[3]]; !strings.Contains(got, "OnStartupSec=21600") || !strings.Contains(got, "OnUnitActiveSec=21600") || !strings.Contains(got, "Persistent=true") {
		t.Fatalf("systemd updater timer = %s", got)
	}
	if got := firstContent[paths[4]]; !strings.Contains(got, `"theme": "existing"`) || strings.Count(got, `"blackbird"`) != 1 || !strings.Contains(got, `"other"`) {
		t.Fatalf("OpenCode config did not preserve and merge settings: %s", got)
	}
	if got := firstContent[paths[5]]; !strings.Contains(got, `"projects"`) || strings.Count(got, `"blackbird"`) != 1 || !strings.Contains(got, `"other"`) {
		t.Fatalf("Claude config did not preserve and merge settings: %s", got)
	}
	if got := firstContent[paths[6]]; !strings.Contains(got, `model = "gpt-5"`) || !strings.Contains(got, "[features]\nsearch = true") || strings.Contains(got, "old.test") || strings.Count(got, codexStart) != 1 || strings.Count(got, `[mcp_servers.blackbird]`) != 1 {
		t.Fatalf("Codex config did not converge: %s", got)
	}
	if got := firstContent[first.ServicePath]; strings.Count(got, "ExecStart=") != 1 || !strings.Contains(got, filepath.Join(home, "data", "blackbird", "blackbird.db")) {
		t.Fatalf("systemd definition = %s", got)
	}
	wantClients := []string{"opencode", "claude", "codex"}
	if !reflect.DeepEqual(first.Clients, wantClients) {
		t.Fatalf("clients = %v, want %v", first.Clients, wantClients)
	}
}

func TestInstallPreservesCompanionIdentityAcrossWorkingDirectories(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	manager := testManager(home, "linux", &recordingRunner{})
	manager.config.WorkingDir = filepath.Join(home, "first-project")
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager = testManager(home, "linux", &recordingRunner{})
	manager.config.WorkingDir = filepath.Join(home, "other-project")
	result, err := manager.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	definition, err := os.ReadFile(result.CompanionPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(definition), filepath.Join(home, "first-project")) || strings.Contains(string(definition), filepath.Join(home, "other-project")) {
		t.Fatalf("companion definition did not preserve identity: %s", definition)
	}
}

func TestInstallWritesAtomicLaunchAgentAndRestartsIt(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	runner := &recordingRunner{}
	manager := testManager(home, "darwin", runner)

	result, err := manager.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(result.ServicePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "<key>Label</key><string>"+serviceLabel+"</string>") || strings.Count(string(content), "<key>ProgramArguments</key>") != 1 {
		t.Fatalf("launch agent = %s", content)
	}
	updaterContent, err := os.ReadFile(result.UpdaterPaths[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := string(updaterContent); !strings.Contains(got, "<key>StartInterval</key><integer>21600</integer>") ||
		!strings.Contains(got, "update.err.log") || !strings.Contains(got, "/opt/homebrew/bin") ||
		strings.Contains(got, "KeepAlive") || strings.Contains(got, "RunAtLoad") {
		t.Fatalf("updater launch agent = %s", got)
	}
	want := []string{
		"launchctl bootout gui/501 " + result.ServicePath,
		"launchctl bootstrap gui/501 " + result.ServicePath,
		"launchctl kickstart -k gui/501/" + serviceLabel,
		"launchctl bootout gui/501 " + result.CompanionPath,
		"launchctl bootstrap gui/501 " + result.CompanionPath,
		"launchctl kickstart -k gui/501/" + companionLabel,
		"launchctl bootout gui/501 " + result.UpdaterPaths[0],
		"launchctl bootstrap gui/501 " + result.UpdaterPaths[0],
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("commands = %v, want %v", runner.commands, want)
	}
	if _, err := os.Stat(result.ServicePath + ".blackbird.tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary service file remains: %v", err)
	}
}

func TestStatusReportsDaemonAndUpdater(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	runner := &recordingRunner{outputs: []string{"active", "active", "active"}}
	manager := testManager(home, "linux", runner)
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	runner.outputs = []string{"active", "active", "active"}

	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "daemon=running (active) installed=true") ||
		!strings.Contains(status, "companion=running (active) installed=true") || !strings.Contains(status, "updater=scheduled (active) installed=true") || !strings.Contains(status, "interval=6h0m0s") {
		t.Fatalf("status = %q", status)
	}
	want := []string{
		"systemctl --user is-active blackbird.service",
		"systemctl --user is-active blackbird-claude.service",
		"systemctl --user is-active blackbird-update.timer",
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("commands = %v, want %v", runner.commands, want)
	}
}

func TestNativeStateReportsStoppedLaunchdJob(t *testing.T) {
	t.Parallel()
	output := "state = spawn scheduled\nactive count = 0\nlast exit code = 1"
	if got := nativeState("darwin", output, nil, "running", "stopped"); got != "stopped" {
		t.Fatalf("nativeState() = %q", got)
	}
	if got := nativeState("darwin", "state = running\nactive count = 1", nil, "running", "stopped"); got != "running" {
		t.Fatalf("nativeState() = %q", got)
	}
}

func TestStatusReportsDormantLaunchdUpdaterAsScheduled(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	runner := &recordingRunner{outputs: []string{"state = running", "state = running", "state = exited"}}
	manager := testManager(home, "darwin", runner)
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.outputs = []string{"state = running", "state = running", "state = exited"}
	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "daemon=running") || !strings.Contains(status, "companion=running") || !strings.Contains(status, "updater=scheduled") {
		t.Fatalf("status = %q", status)
	}
	if strings.Contains(status, "state = exited") {
		t.Fatalf("status leaked launchctl output: %q", status)
	}
}

func TestInstallRejectsUpdateIntervalOutsideBounds(t *testing.T) {
	t.Parallel()
	for _, interval := range []time.Duration{time.Minute, 25 * time.Hour} {
		manager := testManager(t.TempDir(), "linux", &recordingRunner{})
		manager.config.UpdateInterval = interval
		if _, err := manager.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "update interval") {
			t.Fatalf("Install() with interval %s error = %v", interval, err)
		}
	}
}

func TestInstallDoesNotOverwriteMalformedClientConfig(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	path := filepath.Join(home, "config", "opencode", "opencode.json")
	mustWrite(t, path, "{not-json\n")
	manager := testManager(home, "linux", &recordingRunner{})

	if _, err := manager.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("Install() error = %v, want parse failure", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), "{not-json\n"; got != want {
		t.Fatalf("malformed config was overwritten: got %q, want %q", got, want)
	}
	servicePath := filepath.Join(home, "config", "systemd", "user", "blackbird.service")
	if _, err := os.Stat(servicePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("service should not be installed after config failure: %v", err)
	}
}

func TestUpdateRestartsOnlyWhenBrewVersionChanges(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	runner := &recordingRunner{outputs: []string{"blackbird 1.0.0", "", "", "blackbird 1.0.0"}}
	manager := testManager(home, "linux", runner)

	result, err := manager.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || len(runner.commands) != 4 {
		t.Fatalf("unchanged update = %#v, commands=%v", result, runner.commands)
	}

	runner.commands = nil
	runner.outputs = []string{"blackbird 1.0.0", "", "", "blackbird 1.1.0", "", "", ""}
	result, err = manager.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed {
		t.Fatal("changed update was not reported")
	}
	if got := runner.commands; !reflect.DeepEqual(got[len(got)-6:], []string{
		"systemctl --user daemon-reload", "systemctl --user enable blackbird.service", "systemctl --user restart blackbird.service",
		"systemctl --user daemon-reload", "systemctl --user enable blackbird-claude.service", "systemctl --user restart blackbird-claude.service",
	}) {
		t.Fatalf("restart commands = %v", got)
	}
}

func TestUninstallRemovesOnlyServiceDefinition(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	runner := &recordingRunner{}
	manager := testManager(home, "linux", runner)
	result, err := manager.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dataFile := filepath.Join(home, "data", "blackbird", "blackbird.db")
	mustWrite(t, dataFile, "retained")
	runner.commands = nil

	if _, err := manager.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(result.ServicePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("service definition still exists: %v", err)
	}
	for _, path := range result.UpdaterPaths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("updater definition still exists: %v", err)
		}
	}
	if got, err := os.ReadFile(dataFile); err != nil || string(got) != "retained" {
		t.Fatalf("data was not retained: %q, %v", got, err)
	}
	want := []string{
		"systemctl --user disable --now blackbird.service",
		"systemctl --user disable --now blackbird-claude.service",
		"systemctl --user disable --now blackbird-update.timer",
		"systemctl --user daemon-reload",
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("commands = %v, want %v", runner.commands, want)
	}

	runner.commands = nil
	if _, err := manager.Uninstall(context.Background()); err != nil {
		t.Fatalf("repeated Uninstall() failed: %v", err)
	}
	if got := runner.commands; !reflect.DeepEqual(got, []string{"systemctl --user daemon-reload"}) {
		t.Fatalf("repeated uninstall commands = %v", got)
	}
}

func testManager(home, goos string, runner Runner) *Manager {
	return NewManager(Config{
		GOOS: goos, HomeDir: home, ConfigHome: filepath.Join(home, "config"),
		DataHome: filepath.Join(home, "data"), StateHome: filepath.Join(home, "state"),
		Executable: filepath.Join(home, "bin", "blackbird"), UID: 501, Runner: runner,
		LookPath: func(name string) (string, error) {
			if name == "claude" {
				return filepath.Join(home, ".local", "bin", "claude"), nil
			}
			return "", os.ErrNotExist
		},
	})
}

type recordingRunner struct {
	commands []string
	outputs  []string
}

func (runner *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	runner.commands = append(runner.commands, strings.Join(append([]string{name}, args...), " "))
	if len(runner.outputs) == 0 {
		return "", nil
	}
	output := runner.outputs[0]
	runner.outputs = runner.outputs[1:]
	return output, nil
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readAll(t *testing.T, paths []string) map[string]string {
	t.Helper()
	result := make(map[string]string, len(paths))
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[path] = string(content)
	}
	return result
}
