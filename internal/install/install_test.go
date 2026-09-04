package install

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
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

	if got := firstContent[paths[1]]; !strings.Contains(got, "ExecStart=") || !strings.Contains(got, " update") ||
		!strings.Contains(got, "/home/linuxbrew/.linuxbrew/bin") || strings.Contains(got, "Restart=") {
		t.Fatalf("systemd updater service = %s", got)
	}
	if got := firstContent[paths[2]]; !strings.Contains(got, "OnStartupSec=21600") || !strings.Contains(got, "OnUnitActiveSec=21600") || !strings.Contains(got, "Persistent=true") {
		t.Fatalf("systemd updater timer = %s", got)
	}
	if got := firstContent[paths[3]]; !strings.Contains(got, `"theme": "existing"`) || strings.Count(got, `"blackbird"`) != 1 || !strings.Contains(got, `"other"`) {
		t.Fatalf("OpenCode config did not preserve and merge settings: %s", got)
	}
	if got := firstContent[paths[4]]; !strings.Contains(got, `"projects"`) || strings.Count(got, `"blackbird"`) != 1 || !strings.Contains(got, `"other"`) {
		t.Fatalf("Claude config did not preserve and merge settings: %s", got)
	}
	if got := firstContent[paths[5]]; !strings.Contains(got, `model = "gpt-5"`) || !strings.Contains(got, "[features]\nsearch = true") || strings.Contains(got, "old.test") || strings.Count(got, codexStart) != 1 || strings.Count(got, `[mcp_servers.blackbird]`) != 1 {
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

func TestInstallLeavesUserManagedOpenCodeJSONCAlone(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	path := filepath.Join(home, "config", "opencode", "opencode.jsonc")
	mustWrite(t, path, "{\n  // user managed\n  \"plugins\": []\n}\n")
	manager := testManager(home, "linux", &recordingRunner{})
	result, err := manager.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "{\n  // user managed\n  \"plugins\": []\n}\n" {
		t.Fatalf("JSONC changed: %q, %v", content, err)
	}
	if _, err := os.Stat(filepath.Join(home, "config", "opencode", "opencode.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("competing JSON config created: %v", err)
	}
	if !reflect.DeepEqual(result.Clients, []string{"opencode", "claude"}) {
		t.Fatalf("clients = %v", result.Clients)
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
		"launchctl bootout gui/501 " + manager.companionPath(),
		"launchctl bootout gui/501 " + manager.piCompanionPath(),
		"launchctl bootout gui/501 " + result.ServicePath,
		"launchctl bootstrap gui/501 " + result.ServicePath,
		"launchctl kickstart -k gui/501/" + serviceLabel,
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
	runner := &recordingRunner{outputs: []string{"active", "active"}}
	manager := testManager(home, "linux", runner)
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	runner.outputs = []string{"active", "active"}

	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "daemon=running (active) installed=true") ||
		!strings.Contains(status, "updater=scheduled installed=true") || !strings.Contains(status, "interval=6h0m0s") {
		t.Fatalf("status = %q", status)
	}
	want := []string{
		"systemctl --user is-active blackbird.service",
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
	runner := &recordingRunner{outputs: []string{"state = running", "state = exited"}}
	manager := testManager(home, "darwin", runner)
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.outputs = []string{"state = running", "state = exited"}
	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "daemon=running") || !strings.Contains(status, "updater=scheduled") {
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
	if _, err := manager.convergeServiceDefinition(); err != nil {
		t.Fatal(err)
	}

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
	if got := runner.commands; !reflect.DeepEqual(got[len(got)-3:], []string{
		"systemctl --user daemon-reload", "systemctl --user enable blackbird.service", "systemctl --user restart blackbird.service",
	}) {
		t.Fatalf("restart commands = %v", got)
	}
}

func TestUpdateRepairsALegacyServiceDefinitionWithoutAVersionChange(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	runner := &recordingRunner{outputs: []string{"blackbird 1.0.0", "", "", "blackbird 1.0.0"}}
	manager := testManager(home, "linux", runner)
	mustWrite(t, manager.servicePath(), legacyUnit(manager.config.Executable, filepath.Join(home, "data", "blackbird", "blackbird.db")))

	result, err := manager.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatalf("update reported a version change = %#v", result)
	}
	if got := runner.commands; !reflect.DeepEqual(got[len(got)-3:], []string{
		"systemctl --user daemon-reload", "systemctl --user enable blackbird.service", "systemctl --user restart blackbird.service",
	}) {
		t.Fatalf("restart commands = %v", got)
	}
	content, err := os.ReadFile(manager.servicePath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), " \"daemon\" ") {
		t.Fatalf("unit file was not converged: %s", content)
	}
}

func TestUpdateNeverRepointsTheServiceAtANonInstalledBinary(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		foreign       bool
		installed     bool
		wantSkipped   bool
		wantRewritten bool
	}{
		"a build tree binary leaves the unit alone": {foreign: true, installed: true, wantSkipped: true},
		"an absent definition is not created":       {wantSkipped: true},
		"the installed binary repairs its unit":     {installed: true, wantRewritten: true},
	}
	for _, goos := range []string{"darwin", "linux"} {
		for name, test := range tests {
			t.Run(goos+"/"+name, func(t *testing.T) {
				t.Parallel()
				home := t.TempDir()
				runner := &recordingRunner{outputs: []string{"blackbird 1.0.0", "", "", "blackbird 1.0.0"}}
				manager := testManager(home, goos, runner)
				database := filepath.Join(home, "data", "blackbird", "blackbird.db")
				before := ""
				if test.installed {
					recorded := manager.config.Executable
					if test.foreign {
						recorded = filepath.Join(home, "build", "dist", "blackbird")
					}
					before = legacyDefinition(goos, recorded, database)
					mustWrite(t, manager.servicePath(), before)
				}

				result, err := manager.Update(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				content, err := os.ReadFile(manager.servicePath())
				switch {
				case !test.installed:
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("update created a service definition: %q, %v", content, err)
					}
				case err != nil:
					t.Fatal(err)
				case test.wantRewritten:
					if !strings.Contains(string(content), daemonCommand) {
						t.Fatalf("installed unit was not converged: %s", content)
					}
				case string(content) != before:
					t.Fatalf("unit was repointed at a non-installed binary:\n%s", content)
				}
				if result.DefinitionSkipped != test.wantSkipped {
					t.Fatalf("DefinitionSkipped = %t, want %t", result.DefinitionSkipped, test.wantSkipped)
				}
				restarted := false
				for _, command := range runner.commands {
					if strings.Contains(command, "kickstart") || strings.Contains(command, "restart blackbird.service") {
						restarted = true
					}
				}
				if restarted != test.wantRewritten {
					t.Fatalf("restarted = %t, want %t (commands=%v)", restarted, test.wantRewritten, runner.commands)
				}
			})
		}
	}
}

func TestInstallAdoptsTheServiceForTheRunningExecutable(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			manager := testManager(home, goos, &recordingRunner{})
			mustWrite(t, manager.servicePath(), legacyDefinition(goos, filepath.Join(home, "build", "dist", "blackbird"), "old.db"))

			if _, err := manager.Install(context.Background()); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(manager.servicePath())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(content), manager.config.Executable) || strings.Contains(string(content), "old.db") {
				t.Fatalf("install did not adopt the service: %s", content)
			}
		})
	}
}

func TestStatusSeparatesASlowStartFromACrashLoop(t *testing.T) {
	t.Parallel()
	startupLog := logRecord(2*time.Second, "INFO", "daemon starting") +
		logRecord(2*time.Second, "INFO", "storage opened") +
		logRecord(time.Second, "INFO", "handshake published")
	freshError := logRecord(time.Second, "ERROR", "storage open failed")
	staleError := logRecord(30*24*time.Hour, "ERROR", "open storage: SQLite schema mismatch: foreign-key check failed")
	deprecation := "blackbird: bare daemon flags are deprecated, use \"blackbird daemon\"\n"
	refused := stubProber{err: errors.New("connection refused")}
	tests := map[string]struct {
		supervisor string
		errorLog   string
		logAge     time.Duration
		prober     stubProber
		want       string
	}{
		"a still starting daemon is unreachable": {
			supervisor: "state = running\nlast exit code = 0", errorLog: startupLog,
			prober: refused, want: "daemon=unreachable",
		},
		"a fresh error record is a crash loop": {
			supervisor: "state = running\nlast exit code = 0", errorLog: startupLog + freshError,
			prober: refused, want: "daemon=crash-looping",
		},
		"a non-zero launchd exit status is a crash loop": {
			supervisor: "state = running\nlast exit code = 1", errorLog: startupLog,
			prober: refused, want: "daemon=crash-looping",
		},
		"pre-upgrade failures beneath a healthy start are stale": {
			supervisor: "state = running\nlast exit code = 0", errorLog: strings.Repeat(staleError, 23) + startupLog,
			prober: refused, want: "daemon=unreachable",
		},
		"the legacy argv deprecation notice is not a failure": {
			supervisor: "state = running", errorLog: deprecation + startupLog,
			prober: refused, want: "daemon=unreachable",
		},
		"an undatable fatal line is left to the supervisor": {
			supervisor: "state = running", errorLog: "SQLite schema mismatch: foreign-key check failed\n",
			prober: refused, want: "daemon=unreachable",
		},
		"errors outside the crash window are stale": {
			supervisor: "state = running", errorLog: staleError,
			prober: refused, want: "daemon=unreachable",
		},
		"an untouched error log is not inspected": {
			supervisor: "state = running", errorLog: freshError, logAge: 2 * time.Hour,
			prober: refused, want: "daemon=unreachable",
		},
		"errors beyond the inspected tail are ignored": {
			supervisor: "state = running", errorLog: freshError + strings.Repeat(startupLog, errorLogTailBytes/len(startupLog)+2),
			prober: refused, want: "daemon=unreachable",
		},
		"an answering daemon is running": {
			supervisor: "state = running", errorLog: startupLog + freshError,
			prober: stubProber{version: "1.0.0"}, want: "daemon=running",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			manager := testManager(home, "darwin", &recordingRunner{outputs: []string{test.supervisor, "state = running"}})
			manager.config.Prober = test.prober
			if _, err := manager.convergeServiceDefinition(); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, manager.daemonErrorLogPath(), test.errorLog)
			if test.logAge != 0 {
				stamp := time.Now().Add(-test.logAge)
				if err := os.Chtimes(manager.daemonErrorLogPath(), stamp, stamp); err != nil {
					t.Fatal(err)
				}
			}

			status, err := manager.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(status, test.want) {
				t.Fatalf("status = %q, want %q", status, test.want)
			}
		})
	}
}

func TestStatusReportsCrashLoopsTheSupervisorSamplesAsDown(t *testing.T) {
	t.Parallel()
	startupLog := "time=2026-08-15T09:00:00.000-04:00 level=INFO msg=\"daemon starting\" version=0.4.0\n"
	crashLog := "time=2026-08-15T09:00:00.030-04:00 level=ERROR msg=\"storage open failed\" err=\"foreign-key check failed\"\n"
	launchdRunning := "state = running\nactive count = 1\nruns = 1\nlast exit code = 0"
	launchdThrottled := "state = not running\nactive count = 0\nruns = 23\nlast exit code = 1"
	launchdWaiting := "state = waiting\npending execution reason = throttled\nruns = 24\nlast exit code = 0"
	launchdUnloaded := "Could not find service \"" + serviceLabel + "\" in domain for login"
	refused := stubProber{err: errors.New("connection refused")}
	answering := stubProber{version: "0.4.0"}
	unitDown := errors.New("exit status 3")
	tests := map[string]struct {
		goos          string
		supervisor    string
		supervisorErr error
		errorLog      string
		prober        stubProber
		want          string
	}{
		"darwin healthy steady state": {
			goos: "darwin", supervisor: launchdRunning, errorLog: startupLog,
			prober: answering, want: DaemonRunning,
		},
		"linux healthy steady state": {
			goos: "linux", supervisor: "active", errorLog: startupLog,
			prober: answering, want: DaemonRunning + " (active)",
		},
		"darwin healthy slow start": {
			goos: "darwin", supervisor: launchdRunning, errorLog: startupLog,
			prober: refused, want: DaemonUnreachable,
		},
		"linux healthy slow start": {
			goos: "linux", supervisor: "active", errorLog: startupLog,
			prober: refused, want: DaemonUnreachable + " (active)",
		},
		"darwin throttled crash loop": {
			goos: "darwin", supervisor: launchdThrottled, errorLog: startupLog,
			prober: refused, want: DaemonCrashLooping,
		},
		"darwin crash loop waiting out its minimum runtime": {
			goos: "darwin", supervisor: launchdWaiting, errorLog: startupLog,
			prober: refused, want: DaemonCrashLooping,
		},
		"linux auto-restart loop": {
			goos: "linux", supervisor: "activating (auto-restart)", supervisorErr: unitDown, errorLog: startupLog,
			prober: refused, want: DaemonCrashLooping + " (activating (auto-restart))",
		},
		"linux failed unit": {
			goos: "linux", supervisor: "failed", supervisorErr: unitDown, errorLog: startupLog,
			prober: refused, want: DaemonCrashLooping + " (failed)",
		},
		"darwin daemon deliberately stopped": {
			goos: "darwin", supervisor: launchdUnloaded, supervisorErr: unitDown, errorLog: startupLog + crashLog,
			prober: refused, want: DaemonStopped,
		},
		"linux daemon deliberately stopped": {
			goos: "linux", supervisor: "inactive", supervisorErr: unitDown, errorLog: startupLog + crashLog,
			prober: refused, want: DaemonStopped + " (inactive)",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := &recordingRunner{
				outputs: []string{test.supervisor, test.supervisor},
				errs:    []error{test.supervisorErr, test.supervisorErr},
			}
			manager := testManager(t.TempDir(), test.goos, runner)
			manager.config.Prober = test.prober
			if _, err := manager.convergeServiceDefinition(); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, manager.daemonErrorLogPath(), test.errorLog)

			status, err := manager.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if want := "daemon=" + test.want + " installed=true"; !strings.Contains(status, want) {
				t.Fatalf("status = %q, want %q", status, want)
			}
		})
	}
}

func TestStatusReportsAHealthyUpdaterAsScheduledOnEveryPlatform(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		goos       string
		output     string
		err        error
		want       string
		wantDaemon string
	}{
		"an active systemd timer carries no diagnostic detail": {
			goos: "linux", output: "active", want: "updater=scheduled installed=true", wantDaemon: "daemon=running (active)",
		},
		"an idle launchd agent is still scheduled": {
			goos: "darwin", output: "state = waiting", want: "updater=scheduled installed=true", wantDaemon: "daemon=running",
		},
		"a stopped systemd timer keeps its detail": {
			goos: "linux", output: "inactive", err: errors.New("exit status 3"),
			want: "updater=stopped (inactive)", wantDaemon: "daemon=running (active)",
		},
		"an unloaded launchd agent is stopped": {
			goos: "darwin", output: "Could not find service", err: errors.New("exit status 113"),
			want: "updater=stopped", wantDaemon: "daemon=running",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			healthy := "active"
			if test.goos == "darwin" {
				healthy = "state = running"
			}
			runner := &recordingRunner{outputs: []string{healthy, test.output}, errs: []error{nil, test.err}}
			manager := testManager(t.TempDir(), test.goos, runner)
			if _, err := manager.convergeServiceDefinition(); err != nil {
				t.Fatal(err)
			}
			for index, path := range manager.updaterPaths() {
				mustWrite(t, path, manager.updaterDefinitions()[index])
			}

			status, err := manager.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(status, test.want) || !strings.Contains(status, test.wantDaemon) {
				t.Fatalf("status = %q, want %q and %q", status, test.want, test.wantDaemon)
			}
		})
	}
}

func TestUpdaterDefinitionCarriesTheResolvedXDGEnvironment(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			manager := testManager(home, goos, &recordingRunner{})
			definition := manager.updaterDefinitions()[0]
			environment := map[string]string{
				"XDG_CONFIG_HOME": filepath.Join(home, "config"),
				"XDG_DATA_HOME":   filepath.Join(home, "data"),
				"XDG_STATE_HOME":  filepath.Join(home, "state"),
			}
			for key, value := range environment {
				want := "Environment=\"" + key + "=" + value + "\""
				if goos == "darwin" {
					want = "<key>" + key + "</key><string>" + value + "</string>"
				}
				if !strings.Contains(definition, want) {
					t.Fatalf("updater definition missing %q:\n%s", want, definition)
				}
			}

			updater := NewManager(Config{
				GOOS: goos, HomeDir: home, ConfigHome: environment["XDG_CONFIG_HOME"],
				DataHome: environment["XDG_DATA_HOME"], StateHome: environment["XDG_STATE_HOME"],
				Executable: manager.config.Executable, UID: 501, Runner: &recordingRunner{},
			})
			got, err := updater.serviceDefinition()
			if err != nil {
				t.Fatal(err)
			}
			want, err := manager.serviceDefinition()
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("updater converges a different definition:\n%s\nwant:\n%s", got, want)
			}
			bare := NewManager(Config{
				GOOS: goos, HomeDir: home, Executable: manager.config.Executable,
				UID: 501, Runner: &recordingRunner{},
			})
			bareDefinition, err := bare.serviceDefinition()
			if err != nil {
				t.Fatal(err)
			}
			if bareDefinition == want {
				t.Fatal("the XDG environment does not affect the converged definition, so this test proves nothing")
			}
		})
	}
}

func TestServiceDefinitionInvokesTheDaemonSubcommandWithAnExplicitStateDir(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			manager := testManager(home, goos, &recordingRunner{})
			definition, err := manager.serviceDefinition()
			if err != nil {
				t.Fatal(err)
			}
			stateDir := filepath.Join(home, "state", "blackbird")
			environment := "XDG_STATE_HOME=" + filepath.Join(home, "state")
			if goos == "darwin" {
				environment = "<key>XDG_STATE_HOME</key><string>" + filepath.Join(home, "state") + "</string>"
			}
			for _, want := range []string{"daemon", "--sqlite-path=" + filepath.Join(home, "data", "blackbird", "blackbird.db"),
				"--state-dir=" + stateDir, environment} {
				if !strings.Contains(definition, want) {
					t.Fatalf("definition missing %q:\n%s", want, definition)
				}
			}
			if got := manager.StateDir(); got != stateDir {
				t.Fatalf("StateDir() = %q, want %q", got, stateDir)
			}
			if got, want := manager.ServiceArgv()[1], "daemon"; got != want {
				t.Fatalf("ServiceArgv()[1] = %q, want %q", got, want)
			}
		})
	}
}

func TestServiceDefinitionRedirectsDaemonOutputWhereTheLogReaderLooks(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		goos         string
		outDirective string
		errDirective string
		redirection  func(directive, path string) string
	}{
		{
			goos: "darwin", outDirective: "StandardOutPath", errDirective: "StandardErrorPath",
			redirection: func(directive, path string) string {
				return "<key>" + directive + "</key><string>" + path + "</string>"
			},
		},
		{
			goos: "linux", outDirective: "StandardOutput", errDirective: "StandardError",
			redirection: func(directive, path string) string {
				return directive + "=append:" + path + "\n"
			},
		},
	} {
		t.Run(testCase.goos, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			manager := testManager(home, testCase.goos, &recordingRunner{})
			definition, err := manager.serviceDefinition()
			if err != nil {
				t.Fatal(err)
			}
			stateDir := filepath.Join(home, "state", "blackbird")
			// The file names are the log reader's, not this package's: a rename
			// on either side silently empties `blackbird logs`.
			for _, stream := range []struct{ directive, fileName string }{
				{directive: testCase.outDirective, fileName: "blackbird.log"},
				{directive: testCase.errDirective, fileName: "blackbird.err.log"},
			} {
				want := testCase.redirection(stream.directive, filepath.Join(stateDir, stream.fileName))
				if !strings.Contains(definition, want) {
					t.Fatalf("definition does not redirect into %s (want %q):\n%s", stream.fileName, want, definition)
				}
			}
		})
	}
}

// The supervisor opens the log files itself and creates neither them nor their
// directory, so systemd fails the whole unit when the state directory is
// missing. Converging a definition must therefore leave the directory behind
// even when the bytes on disk already matched and nothing was rewritten.
func TestConvergeServiceDefinitionCreatesTheStateDirectoryItLogsInto(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			manager := testManager(home, goos, &recordingRunner{})
			if _, err := manager.convergeServiceDefinition(); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(manager.StateDir()); err != nil {
				t.Fatal(err)
			}
			changed, err := manager.convergeServiceDefinition()
			if err != nil {
				t.Fatal(err)
			}
			if changed {
				t.Fatal("converging an unchanged definition reported a rewrite")
			}
			info, err := os.Stat(manager.StateDir())
			if err != nil {
				t.Fatalf("state directory missing after converge: %v", err)
			}
			if !info.IsDir() {
				t.Fatalf("%s is not a directory", manager.StateDir())
			}
		})
	}
}

func TestConvergeServiceDefinitionRewritesLegacyDefinitionOnceOnly(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	manager := testManager(home, "darwin", &recordingRunner{})
	mustWrite(t, manager.servicePath(), legacyPlist(manager.config.Executable, filepath.Join(home, "data", "blackbird", "blackbird.db")))

	changed, err := manager.convergeServiceDefinition()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy definition was not rewritten")
	}
	if state, err := manager.definitionState(); err != nil || state != DefinitionCurrent {
		t.Fatalf("definitionState() = %q, %v", state, err)
	}
	changed, err = manager.convergeServiceDefinition()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("converge rewrote an already current definition")
	}
}

func TestStatusReportsLivenessFromTheHandshakeRatherThanTheSupervisor(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		prober    stubProber
		errorLog  bool
		installed bool
		want      string
	}{
		"handshake answers":              {prober: stubProber{version: "1.0.0"}, installed: true, want: "daemon=running"},
		"handshake fails while crashing": {prober: stubProber{err: errors.New("connection refused")}, errorLog: true, installed: true, want: "daemon=crash-looping"},
		"handshake fails while quiet":    {prober: stubProber{err: errors.New("connection refused")}, installed: true, want: "daemon=unreachable"},
		"definition absent":              {prober: stubProber{version: "1.0.0"}, want: "daemon=not-installed"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			runner := &recordingRunner{outputs: []string{"state = running", "state = running"}}
			manager := testManager(home, "darwin", runner)
			manager.config.Prober = test.prober
			if test.installed {
				if _, err := manager.convergeServiceDefinition(); err != nil {
					t.Fatal(err)
				}
			}
			if test.errorLog {
				mustWrite(t, manager.daemonErrorLogPath(), logRecord(time.Second, "ERROR", "open storage: SQLite schema mismatch"))
			}
			status, err := manager.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(status, test.want) {
				t.Fatalf("status = %q, want %q", status, test.want)
			}
		})
	}
}

func TestStatusReportsStaleServiceDefinitions(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	manager := testManager(home, "darwin", &recordingRunner{outputs: []string{"state = running", "state = running"}})
	mustWrite(t, manager.servicePath(), legacyPlist(manager.config.Executable, "ignored.db"))

	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "definition=stale") {
		t.Fatalf("status = %q", status)
	}
}

func TestDefaultStateDirFollowsXDGStateHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "custom-state"))
	dir, err := DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "custom-state", "blackbird"); dir != want {
		t.Fatalf("DefaultStateDir() = %q, want %q", dir, want)
	}
	t.Setenv("XDG_STATE_HOME", "")
	dir, err = DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".local", "state", "blackbird"); dir != want {
		t.Fatalf("DefaultStateDir() = %q, want %q", dir, want)
	}
	if got, want := HandshakePath(dir), filepath.Join(dir, "admin.json"); got != want {
		t.Fatalf("HandshakePath() = %q, want %q", got, want)
	}
}

// logRecord renders one slog text record of a given age, matching the layout
// the daemon's TextHandler writes into the error log.
func logRecord(age time.Duration, level, message string) string {
	return "time=" + time.Now().Add(-age).Format("2006-01-02T15:04:05.000Z07:00") +
		" level=" + level + " msg=\"" + message + "\"\n"
}

func legacyPlist(executable, database string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key><string>` + serviceLabel + `</string>
  <key>ProgramArguments</key>
  <array><string>` + executable + `</string><string>--sqlite-path=` + database + `</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
`
}

func legacyUnit(executable, database string) string {
	return "[Service]\nType=simple\nExecStart=\"" + executable + "\" \"--sqlite-path=" + database + "\"\n"
}

func legacyDefinition(goos, executable, database string) string {
	if goos == "darwin" {
		return legacyPlist(executable, database)
	}
	return legacyUnit(executable, database)
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

// testManager builds a manager for the supported installation: Homebrew
// present. Detection is injected rather than inherited from the host, because
// the real lookup would otherwise make every install assertion in this file
// depend on whether the workstation running it happens to have Homebrew.
func testManager(home, goos string, runner Runner) *Manager {
	manager := NewManager(Config{
		GOOS: goos, HomeDir: home, ConfigHome: filepath.Join(home, "config"),
		DataHome: filepath.Join(home, "data"), StateHome: filepath.Join(home, "state"),
		Executable: filepath.Join(home, "bin", "blackbird"), UID: 501, Runner: runner,
		Prober: stubProber{version: "1.0.0"},
		LookPath: func(name string) (string, error) {
			if name == "claude" {
				return filepath.Join(home, ".local", "bin", "claude"), nil
			}
			if name == "pi" {
				return filepath.Join(home, ".npm-global", "bin", "pi"), nil
			}
			if name == "node" {
				return filepath.Join(home, ".local", "bin", "node"), nil
			}
			return "", os.ErrNotExist
		},
		LookPathIn: stubHomebrew(true),
	})
	return manager
}

// stubHomebrew resolves "brew" the way lookPathIn would on a machine that has
// it, or refuses the way it would on one that does not.
func stubHomebrew(present bool) func(string, string) (string, error) {
	return func(_, name string) (string, error) {
		if name == "brew" && present {
			return "/opt/homebrew/bin/brew", nil
		}
		return "", os.ErrNotExist
	}
}

// withoutHomebrew re-points a manager at a host with no Homebrew on the
// updater's PATH.
func withoutHomebrew(manager *Manager) *Manager {
	manager.config.LookPathIn = stubHomebrew(false)
	return manager
}

type stubProber struct {
	version string
	err     error
}

func (prober stubProber) Probe(context.Context, string) (string, error) {
	return prober.version, prober.err
}

type recordingRunner struct {
	commands []string
	outputs  []string
	errs     []error
}

func (runner *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	runner.commands = append(runner.commands, strings.Join(append([]string{name}, args...), " "))
	var err error
	if len(runner.errs) > 0 {
		err = runner.errs[0]
		runner.errs = runner.errs[1:]
	}
	if len(runner.outputs) == 0 {
		return "", err
	}
	output := runner.outputs[0]
	runner.outputs = runner.outputs[1:]
	return output, err
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

// TestInstallSchedulesNoUpdaterWithoutHomebrew pins the decision this package
// exists to make on a source build: the updater upgrades a Homebrew formula, so
// without Homebrew the honest outcome is no updater at all. Scheduling one
// anyway is what left Linux workstations running a timer that failed every tick.
func TestInstallSchedulesNoUpdaterWithoutHomebrew(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			runner := &recordingRunner{}
			manager := withoutHomebrew(testManager(home, goos, runner))

			result, err := manager.Install(context.Background())
			if err != nil {
				t.Fatalf("Install() failed: %v", err)
			}
			if len(result.UpdaterPaths) != 0 {
				t.Fatalf("UpdaterPaths = %v, want none", result.UpdaterPaths)
			}
			if result.UpdaterSkipped != UpdaterUnsupportedReason {
				t.Fatalf("UpdaterSkipped = %q, want %q", result.UpdaterSkipped, UpdaterUnsupportedReason)
			}
			if result.ServicePath == "" {
				t.Fatal("the daemon service must still be installed")
			}
			for _, path := range manager.updaterPaths() {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("updater definition %s exists, want none", path)
				}
			}
			for _, command := range runner.commands {
				if strings.Contains(command, "blackbird-update") || strings.Contains(command, updaterLabel) {
					t.Fatalf("commands scheduled an updater: %v", runner.commands)
				}
			}
		})
	}
}

// TestInstallTearsDownAnUpdaterHomebrewNoLongerBacks covers the machine that was
// installed when Homebrew was present and has since lost it. Declining to write
// a new updater is not enough: the old timer stays enabled and keeps firing.
func TestInstallTearsDownAnUpdaterHomebrewNoLongerBacks(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	manager := testManager(home, "linux", &recordingRunner{})
	first, err := manager.Install(context.Background())
	if err != nil {
		t.Fatalf("Install() with Homebrew failed: %v", err)
	}
	if len(first.UpdaterPaths) == 0 {
		t.Fatal("the Homebrew install scheduled no updater, so this test proves nothing")
	}

	runner := &recordingRunner{}
	manager.config.Runner = runner
	if _, err := withoutHomebrew(manager).Install(context.Background()); err != nil {
		t.Fatalf("Install() without Homebrew failed: %v", err)
	}
	for _, path := range first.UpdaterPaths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale updater definition %s survived", path)
		}
	}
	if !slices.Contains(runner.commands, "systemctl --user disable --now blackbird-update.timer") {
		t.Fatalf("the stale timer was never disabled: %v", runner.commands)
	}
}

// TestStatusReportsAnUnsupportedUpdater proves Homebrew's absence outranks the
// supervisor's opinion. A timer an earlier install left enabled answers
// is-active successfully and would otherwise report as scheduled forever.
func TestStatusReportsAnUnsupportedUpdater(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	manager := testManager(home, "linux", &recordingRunner{outputs: []string{"active", "active"}})
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatalf("Install() failed: %v", err)
	}

	withBrew, err := manager.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() failed: %v", err)
	}
	if !strings.Contains(withBrew, "updater="+UpdaterScheduled) {
		t.Fatalf("status with Homebrew = %q, want updater=%s", withBrew, UpdaterScheduled)
	}

	manager.config.Runner = &recordingRunner{outputs: []string{"active", "active"}}
	line, err := withoutHomebrew(manager).Status(context.Background())
	if err != nil {
		t.Fatalf("Status() without Homebrew failed: %v", err)
	}
	if !strings.Contains(line, "updater="+UpdaterUnsupported) {
		t.Fatalf("status = %q, want updater=%s", line, UpdaterUnsupported)
	}
}

// TestUpdateRefusesWithoutHomebrewBeforeRunningBrew keeps the failure legible.
// Reaching brew first reports a missing executable, which reads as a broken
// PATH rather than as a machine Homebrew never installed.
func TestUpdateRefusesWithoutHomebrewBeforeRunningBrew(t *testing.T) {
	t.Parallel()
	runner := &recordingRunner{}
	manager := withoutHomebrew(testManager(t.TempDir(), "linux", runner))

	if _, err := manager.Update(context.Background()); err == nil {
		t.Fatal("Update() succeeded without Homebrew")
	} else if !strings.Contains(err.Error(), "Homebrew is not installed") {
		t.Fatalf("Update() error = %v, want it to name Homebrew", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %v, want none before the refusal", runner.commands)
	}
}

// TestLookPathInSearchesTheGivenListOnly is the detector's own contract: it must
// read the PATH the updater unit runs with, never the process environment.
func TestLookPathInSearchesTheGivenListOnly(t *testing.T) {
	t.Parallel()
	absent := t.TempDir()
	present := t.TempDir()
	notExecutable := t.TempDir()
	mustWrite(t, filepath.Join(present, "brew"), "#!/bin/sh\n")
	if err := os.Chmod(filepath.Join(present, "brew"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(notExecutable, "brew"), "#!/bin/sh\n")
	mustMkdir(t, filepath.Join(absent, "brew"))

	found, err := lookPathIn(strings.Join([]string{absent, notExecutable, present}, string(os.PathListSeparator)), "brew")
	if err != nil {
		t.Fatalf("lookPathIn() failed: %v", err)
	}
	if want := filepath.Join(present, "brew"); found != want {
		t.Fatalf("lookPathIn() = %q, want %q", found, want)
	}
	if _, err := lookPathIn(strings.Join([]string{absent, notExecutable}, string(os.PathListSeparator)), "brew"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lookPathIn() error = %v, want os.ErrNotExist", err)
	}
}

// TestInstallConvergesAPartialUpdaterInstallation covers the half-written state
// a failed install or a hand-edited unit directory leaves behind. Treating the
// pair as all-or-nothing would strand whichever file survived, and asking
// systemd to disable a timer it never loaded fails the install outright.
func TestInstallConvergesAPartialUpdaterInstallation(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	manager := testManager(home, "linux", &recordingRunner{})
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatalf("Install() with Homebrew failed: %v", err)
	}
	paths := manager.updaterPaths()
	timer := paths[len(paths)-1]
	if !strings.HasSuffix(timer, ".timer") {
		t.Fatalf("updaterPaths() = %v, want the timer last", paths)
	}
	if err := os.Remove(timer); err != nil {
		t.Fatal(err)
	}

	runner := &recordingRunner{}
	manager.config.Runner = runner
	if _, err := withoutHomebrew(manager).Install(context.Background()); err != nil {
		t.Fatalf("Install() over a partial updater failed: %v", err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("updater definition %s survived: %v", path, err)
		}
	}
	if slices.Contains(runner.commands, "systemctl --user disable --now blackbird-update.timer") {
		t.Fatalf("disabled a timer that was not installed: %v", runner.commands)
	}
}

func TestRestartRotatesOversizedDaemonLogs(t *testing.T) {
	home := t.TempDir()
	manager := testManager(home, "linux", &recordingRunner{})
	if err := os.MkdirAll(manager.blackbirdStateDir(), 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	small := manager.daemonLogPath()
	large := manager.daemonErrorLogPath()
	if err := os.WriteFile(small, []byte("recent\n"), 0o600); err != nil {
		t.Fatalf("write stdout log: %v", err)
	}
	if err := os.WriteFile(large, bytes.Repeat([]byte("x"), maximumDaemonLogBytes+1), 0o600); err != nil {
		t.Fatalf("write stderr log: %v", err)
	}

	if err := manager.restart(context.Background()); err != nil {
		t.Fatalf("restart: %v", err)
	}

	// The oversized stream is moved aside so the supervisor reopens an empty
	// file at the original path; the small one is left alone.
	if _, err := os.Stat(large); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("oversized log should have been rotated away, stat returned %v", err)
	}
	rotated, err := os.Stat(large + ".1")
	if err != nil {
		t.Fatalf("rotated log is missing: %v", err)
	}
	if rotated.Size() != maximumDaemonLogBytes+1 {
		t.Fatalf("rotated log lost content: got %d bytes", rotated.Size())
	}
	if contents, err := os.ReadFile(small); err != nil || string(contents) != "recent\n" {
		t.Fatalf("small log should be untouched, got %q err %v", contents, err)
	}
}

func TestDarwinRestartRejectsGenuineBootoutFailure(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{outputs: []string{"Boot-out failed: 5: Input/output error"},
		errs: []error{errors.New("exit status 5")}}
	manager := testManager(t.TempDir(), "darwin", runner)
	err := manager.restart(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bootout") || !strings.Contains(err.Error(), "Input/output") {
		t.Fatalf("restart error = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %v, bootstrap must not run after failed bootout", runner.commands)
	}
}

func TestDarwinRestartAllowsAnUnloadedService(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{outputs: []string{"Could not find service"},
		errs: []error{errors.New("exit status 113"), nil, nil}}
	manager := testManager(t.TempDir(), "darwin", runner)
	if err := manager.restart(context.Background()); err != nil {
		t.Fatalf("restart = %v", err)
	}
	if len(runner.commands) != 3 || !strings.Contains(runner.commands[1], "bootstrap") {
		t.Fatalf("commands = %v", runner.commands)
	}
}

func TestRestartLeavesLogsAloneWhenAbsent(t *testing.T) {
	home := t.TempDir()
	manager := testManager(home, "linux", &recordingRunner{})
	// A first install restarts before either stream exists; rotation must not
	// turn that into an error.
	if err := manager.restart(context.Background()); err != nil {
		t.Fatalf("restart with no logs present: %v", err)
	}
}

// TestPeeringPreferenceSurvivesAnUnattendedUpdate is the reason the preference
// is a file rather than a flag on the daemon invocation.
//
// `blackbird update` runs convergeServiceDefinition, which REGENERATES the argv
// from the manager. A --peer that lived only in the unit file would therefore
// be erased by the next unattended Homebrew upgrade -- the operator's machine
// silently stopping peering hours after anything they did, which is the exact
// class of silent disagreement the peering flags refuse to make at startup.
func TestPeeringPreferenceSurvivesAnUnattendedUpdate(t *testing.T) {
	t.Parallel()

	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			manager := testManager(home, goos, &recordingRunner{})
			if err := manager.SetPeering(Peering{
				Enabled: true, Address: "100.78.103.8:8080",
				Allowed: []string{"phalls-mac-mini", "nFJpq2jD1311CNTRL"},
			}); err != nil {
				t.Fatal(err)
			}
			argv := manager.ServiceArgv()
			for _, want := range []string{"--peer", "--peer-address=100.78.103.8:8080",
				"--peer-allow=phalls-mac-mini", "--peer-allow=nFJpq2jD1311CNTRL"} {
				if !slices.Contains(argv, want) {
					t.Fatalf("argv = %v, missing %q", argv, want)
				}
			}
			// A second manager is the updater: a different process, holding no
			// memory of the install, regenerating the definition from disk.
			updater := testManager(home, goos, &recordingRunner{})
			definition, err := updater.serviceDefinition()
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"--peer", "--peer-allow=phalls-mac-mini"} {
				if !strings.Contains(definition, want) {
					t.Fatalf("the regenerated definition dropped %q:\n%s", want, definition)
				}
			}
		})
	}
}

// TestPeeringPreferenceDefaultsOffAndRefusesAnEmptyAllowList holds the two
// rules the daemon holds, at the command line where an operator can still act
// on them.
func TestPeeringPreferenceDefaultsOffAndRefusesAnEmptyAllowList(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	manager := testManager(home, runtime.GOOS, &recordingRunner{})
	preference, err := manager.Peering()
	if err != nil {
		t.Fatal(err)
	}
	if preference.Enabled {
		t.Fatal("a machine nobody configured reports peering on")
	}
	if slices.Contains(manager.ServiceArgv(), "--peer") {
		t.Fatalf("the default argv opens a network surface: %v", manager.ServiceArgv())
	}
	if err := manager.SetPeering(Peering{Enabled: true}); err == nil {
		t.Fatal("peering was enabled with no allowed peer")
	}
	// Options without the switch are refused rather than recorded, for the same
	// reason the daemon refuses them: the operator believes peering is on.
	if err := manager.SetPeering(Peering{Allowed: []string{"phalls-mac-mini"}}); err == nil {
		t.Fatal("an allow-list was recorded with peering off")
	}
}

// TestPeeringPreferenceCanBeTurnedOff proves the setting is reversible without
// hand-editing a unit file.
func TestPeeringPreferenceCanBeTurnedOff(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	manager := testManager(home, runtime.GOOS, &recordingRunner{})
	if err := manager.SetPeering(Peering{Enabled: true, Allowed: []string{"phalls-mac-mini"}}); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetPeering(Peering{}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(manager.ServiceArgv(), "--peer") {
		t.Fatalf("peering survived being turned off: %v", manager.ServiceArgv())
	}
}

// TestUnreadablePeeringPreferenceNeverWritesAUnitFile is the fail-closed half.
// A corrupt preference must not converge a definition that silently drops the
// flags; it must refuse where an operator sees it.
func TestUnreadablePeeringPreferenceNeverWritesAUnitFile(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	manager := testManager(home, runtime.GOOS, &recordingRunner{})
	if err := os.MkdirAll(manager.blackbirdConfigDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.peeringPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.convergeServiceDefinition(); err == nil {
		t.Fatal("a corrupt peering preference converged a definition anyway")
	}
	if _, err := os.Stat(manager.servicePath()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a unit file was written from an unreadable preference: %v", err)
	}
}
