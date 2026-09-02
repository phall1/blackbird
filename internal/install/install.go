// Package install manages Blackbird's per-user service and MCP client registration.
package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	serviceLabel          = "com.phall1.blackbird"
	companionLabel        = "com.phall1.blackbird.claude"
	piLabel               = "com.phall1.blackbird.pi"
	updaterLabel          = "com.phall1.blackbird.update"
	formula               = "phall1/tap/blackbird"
	mcpURL                = "http://127.0.0.1:8081"
	codexStart            = "# BEGIN BLACKBIRD MCP (managed by blackbird)"
	codexEnd              = "# END BLACKBIRD MCP (managed by blackbird)"
	defaultUpdateInterval = 6 * time.Hour
	minimumUpdateInterval = time.Hour
	maximumUpdateInterval = 24 * time.Hour
	updaterPath           = "/opt/homebrew/bin:/usr/local/bin:/home/linuxbrew/.linuxbrew/bin:/usr/bin:/bin"

	// HandshakeFileName is the daemon discovery record the runtime writes into
	// the state directory and the CLI reads back.
	HandshakeFileName = "admin.json"

	daemonCommand      = "daemon"
	defaultHTTPAddress = "127.0.0.1:8080"
	healthPath         = "/healthz"
	daemonLogFileName  = "blackbird.log"
	daemonErrFileName  = "blackbird.err.log"
	probeTimeout       = 2 * time.Second
	probeMaxBytes      = 8 << 10
	crashWindow        = time.Minute
	errorLogTailBytes  = 64 << 10
	errorLevelMarker   = "level=ERROR"
	logTimeField       = "time="
)

// Updater states reported by Status. UpdaterUnsupported is not a failure and no
// command resolves it: the unattended updater upgrades the Homebrew formula, so
// on a machine without Homebrew there is nothing worth scheduling. Reporting it
// as stopped instead would send every such machine into "run blackbird install"
// forever, and install would keep declining to schedule it.
const (
	UpdaterScheduled   = "scheduled"
	UpdaterStopped     = "stopped"
	UpdaterUnsupported = "unsupported"
)

// Daemon states reported by Status. They combine three independent facts: the
// unit file, the supervisor, and a real handshake against the daemon.
const (
	DaemonNotInstalled = "not-installed"
	DaemonStopped      = "stopped"
	DaemonRunning      = "running"
	DaemonUnreachable  = "unreachable"
	DaemonCrashLooping = "crash-looping"
)

// Service definition states reported by Status.
const (
	DefinitionAbsent  = "absent"
	DefinitionCurrent = "current"
	DefinitionStale   = "stale"
)

// Runner executes a host command and returns its combined output.
type Runner interface {
	Run(context.Context, string, ...string) (string, error)
}

type commandRunner struct{}

func (commandRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// Prober performs a liveness handshake against a running daemon and reports the
// version it answered with.
type Prober interface {
	Probe(context.Context, string) (string, error)
}

type httpProber struct{}

func (httpProber) Probe(ctx context.Context, address string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+healthPath, nil)
	if err != nil {
		return "", fmt.Errorf("build health request: %w", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("probe %s: %w", address, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("probe %s: unexpected status %d", address, response.StatusCode)
	}
	var health struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, probeMaxBytes)).Decode(&health); err != nil {
		return "", fmt.Errorf("decode health response: %w", err)
	}
	return health.Version, nil
}

// Config supplies host details. Tests can override every machine-dependent input.
type Config struct {
	GOOS           string
	HomeDir        string
	ConfigHome     string
	DataHome       string
	StateHome      string
	Executable     string
	WorkingDir     string
	UID            int
	UpdateInterval time.Duration
	Runner         Runner
	Prober         Prober
	LookPath       func(string) (string, error)
	// LookPathIn resolves an executable within an explicit PATH list instead of
	// the process environment. The unattended updater runs with updaterPath and
	// inherits no login shell, so that list — not the caller's PATH — decides
	// whether the updater can reach Homebrew.
	LookPathIn func(pathList, name string) (string, error)
}

// Manager manages the local Blackbird product installation.
type Manager struct {
	config Config
}

// UpdaterUnsupportedReason explains an installation that scheduled no updater.
// It is phrased for a user reading install or status output, not for a log.
const UpdaterUnsupportedReason = "Homebrew is not installed, and the unattended updater upgrades the Homebrew formula"

// Result describes files changed by an operation.
type Result struct {
	ServicePath  string
	UpdaterPaths []string
	Clients      []string
	// UpdaterSkipped explains why no unattended updater was scheduled, and is
	// empty when one was. It is not an error: the rest of the installation
	// converged, and only unattended upgrades are unavailable.
	UpdaterSkipped string
}

// UpdateResult reports whether Homebrew installed a different version.
// DefinitionSkipped records that the service definition was left untouched
// because the running binary is not the one the service invokes: repointing a
// service at a build-tree path breaks it on the next boot.
type UpdateResult struct {
	Changed           bool
	Before            string
	After             string
	DefinitionSkipped bool
}

// New returns a manager configured from the current process environment.
func New() (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}
	if candidate, lookupErr := exec.LookPath("blackbird"); lookupErr == nil {
		candidateInfo, candidateErr := os.Stat(candidate)
		executableInfo, executableErr := os.Stat(executable)
		if candidateErr == nil && executableErr == nil && os.SameFile(candidateInfo, executableInfo) {
			if absolute, absoluteErr := filepath.Abs(candidate); absoluteErr == nil {
				executable = absolute
			}
		}
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	return NewManager(Config{
		HomeDir: home, ConfigHome: os.Getenv("XDG_CONFIG_HOME"), DataHome: os.Getenv("XDG_DATA_HOME"),
		StateHome: os.Getenv("XDG_STATE_HOME"), Executable: executable, WorkingDir: workingDir,
	}), nil
}

// NewManager returns a manager with platform defaults applied.
func NewManager(config Config) *Manager {
	if config.GOOS == "" {
		config.GOOS = runtime.GOOS
	}
	if config.ConfigHome == "" {
		config.ConfigHome = filepath.Join(config.HomeDir, ".config")
	}
	if config.DataHome == "" {
		config.DataHome = filepath.Join(config.HomeDir, ".local", "share")
	}
	config.StateHome = stateHome(config.StateHome, config.HomeDir)
	if config.Runner == nil {
		config.Runner = commandRunner{}
	}
	if config.Prober == nil {
		config.Prober = httpProber{}
	}
	if config.LookPath == nil {
		config.LookPath = exec.LookPath
	}
	if config.LookPathIn == nil {
		config.LookPathIn = lookPathIn
	}
	if config.UID == 0 {
		config.UID = os.Getuid()
	}
	if config.UpdateInterval == 0 {
		config.UpdateInterval = defaultUpdateInterval
	}
	if config.WorkingDir == "" {
		config.WorkingDir = config.HomeDir
	}
	return &Manager{config: config}
}

func stateHome(configured, home string) string {
	if configured != "" {
		return configured
	}
	return filepath.Join(home, ".local", "state")
}

// DefaultStateDir resolves the Blackbird state directory from the process
// environment, applying exactly the resolution NewManager applies to
// Config.StateHome. Callers that already hold a Manager use Manager.StateDir.
func DefaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(stateHome(os.Getenv("XDG_STATE_HOME"), home), "blackbird"), nil
}

// HandshakePath returns the daemon handshake record inside a state directory.
func HandshakePath(stateDir string) string {
	return filepath.Join(stateDir, HandshakeFileName)
}

// StateDir returns the Blackbird state directory this manager installs against.
// The service definition passes it to the daemon explicitly because a launchd
// agent and a systemd user unit do not inherit the login shell's XDG variables.
func (manager *Manager) StateDir() string {
	return manager.blackbirdStateDir()
}

// ServiceArgv returns the argv the service definition must invoke. The explicit
// daemon subcommand replaces the pre-0.4 bare-flag form, which the CLI still
// accepts so an upgraded binary survives an unrewritten unit file.
func (manager *Manager) ServiceArgv() []string {
	return []string{
		manager.config.Executable,
		daemonCommand,
		"--sqlite-path=" + filepath.Join(manager.blackbirdDataDir(), "blackbird.db"),
		"--state-dir=" + manager.blackbirdStateDir(),
	}
}

// Install creates local directories, converges detected MCP clients, and restarts the service.
func (manager *Manager) Install(ctx context.Context) (Result, error) {
	if err := manager.validatePlatform(); err != nil {
		return Result{}, err
	}
	for _, directory := range []string{manager.blackbirdConfigDir(), manager.blackbirdDataDir(), manager.blackbirdStateDir()} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return Result{}, fmt.Errorf("create %s: %w", directory, err)
		}
	}
	if err := manager.cleanupLegacyAdapters(ctx); err != nil {
		return Result{}, err
	}

	clients, err := manager.configureClients()
	if err != nil {
		return Result{}, err
	}
	servicePath := manager.servicePath()
	if _, err := manager.convergeServiceDefinition(); err != nil {
		return Result{}, err
	}
	// Without Homebrew the updater has nothing to upgrade through, so scheduling
	// one buys a job that fails on every tick and a doctor warning no command
	// clears. Converge the other way instead: tear down an updater an earlier
	// install left behind, so a machine that loses Homebrew stops firing one.
	updaterPaths := manager.updaterPaths()
	skipped := ""
	if manager.homebrewAvailable() {
		for index, path := range updaterPaths {
			if err := atomicWrite(path, []byte(manager.updaterDefinitions()[index]), 0o600); err != nil {
				return Result{}, fmt.Errorf("write updater definition: %w", err)
			}
		}
	} else {
		if err := manager.disableUpdater(ctx); err != nil {
			return Result{}, err
		}
		updaterPaths, skipped = nil, UpdaterUnsupportedReason
	}
	if err := manager.restart(ctx); err != nil {
		return Result{}, err
	}
	if skipped == "" {
		if err := manager.restartUpdater(ctx); err != nil {
			return Result{}, err
		}
	}
	return Result{
		ServicePath: servicePath, UpdaterPaths: updaterPaths,
		Clients: clients, UpdaterSkipped: skipped,
	}, nil
}

// disableUpdater stops and removes an updater this machine can no longer run.
// It leaves the reload to the caller, which restarts the service immediately
// afterwards and reloads the supervisor as part of that.
func (manager *Manager) disableUpdater(ctx context.Context) error {
	// Each definition is inspected on its own rather than as a set: a partial
	// installation is exactly the state worth converging, and treating "all
	// present" as the trigger would strand whichever file survived.
	var present []string
	timerExists := false
	for _, path := range manager.updaterPaths() {
		switch _, err := os.Stat(path); {
		case err == nil:
			present = append(present, path)
			timerExists = timerExists || strings.HasSuffix(path, ".timer")
		case errors.Is(err, fs.ErrNotExist):
		default:
			return fmt.Errorf("inspect updater definition: %w", err)
		}
	}
	if len(present) == 0 {
		return nil
	}
	// Disabling a unit systemd has never heard of is an error, so ask only when
	// the timer is really there. Its absence still leaves files to remove.
	if manager.config.GOOS == "darwin" {
		_, _ = manager.config.Runner.Run(ctx, "launchctl", "bootout", manager.launchDomain(), present[0])
	} else if timerExists {
		if _, err := manager.runRequired(ctx, "systemctl", "--user", "disable", "--now", "blackbird-update.timer"); err != nil {
			return err
		}
	}
	for _, path := range present {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove updater definition: %w", err)
		}
	}
	return nil
}

// Status reports the daemon and periodic updater definitions and native states.
func (manager *Manager) Status(ctx context.Context) (string, error) {
	if err := manager.validatePlatform(); err != nil {
		return "", err
	}
	serviceInstalled, err := pathsExist(manager.servicePath())
	if err != nil {
		return "", fmt.Errorf("inspect service definition: %w", err)
	}
	updaterInstalled, err := pathsExist(manager.updaterPaths()...)
	if err != nil {
		return "", fmt.Errorf("inspect updater definition: %w", err)
	}

	var serviceOutput, updaterOutput string
	var serviceErr, updaterErr error
	if manager.config.GOOS == "darwin" {
		serviceOutput, serviceErr = manager.config.Runner.Run(ctx, "launchctl", "print", manager.launchDomain()+"/"+serviceLabel)
		updaterOutput, updaterErr = manager.config.Runner.Run(ctx, "launchctl", "print", manager.launchDomain()+"/"+updaterLabel)
	} else {
		serviceOutput, serviceErr = manager.config.Runner.Run(ctx, "systemctl", "--user", "is-active", "blackbird.service")
		updaterOutput, updaterErr = manager.config.Runner.Run(ctx, "systemctl", "--user", "is-active", "blackbird-update.timer")
	}
	supervisor := supervisorReport{
		goos:   manager.config.GOOS,
		state:  nativeState(manager.config.GOOS, serviceOutput, serviceErr, DaemonRunning, DaemonStopped),
		output: serviceOutput,
		err:    serviceErr,
	}
	// A periodic job is idle between ticks, so neither supervisor reports it as
	// running: a successful query is the whole signal. The state is reported
	// bare on both platforms because consumers match this field exactly, and a
	// healthy systemd timer would otherwise read as "scheduled (active)" and
	// never satisfy them.
	updaterState := nativeState(manager.config.GOOS, updaterOutput, updaterErr, UpdaterScheduled, UpdaterStopped)
	if updaterErr == nil {
		updaterState = UpdaterScheduled
	}
	// Homebrew's absence outranks whatever the supervisor says. A timer left
	// behind by an install that predates this check still reports as scheduled,
	// and it still cannot upgrade anything.
	if !manager.homebrewAvailable() {
		updaterState = UpdaterUnsupported
	}
	definitionState, err := manager.definitionState()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"daemon=%s installed=%t path=%s definition=%s updater=%s installed=%t paths=%s interval=%s",
		manager.daemonState(ctx, serviceInstalled, supervisor), serviceInstalled, manager.servicePath(),
		definitionState, updaterState, updaterInstalled,
		strings.Join(manager.updaterPaths(), ","), manager.config.UpdateInterval,
	), nil
}

// supervisorReport is one sample of the platform supervisor's opinion: the
// state nativeState derived, the raw output the failure signals are read out
// of, and the error the query itself returned.
type supervisorReport struct {
	goos   string
	state  string
	output string
	err    error
}

// daemonState resolves the supervisor's opinion against a real handshake. A
// loaded launchd job says nothing about liveness: the recorded crash loop kept
// the job loaded while every start aborted on a schema mismatch. The failure
// signals are read whether or not the supervisor currently reports the job as
// up, because a crash-looping daemon is dead at nearly every instant it can be
// sampled: systemd holds it in activating (auto-restart) between attempts, and
// launchd throttles it for the remainder of its ten-second minimum runtime.
func (manager *Manager) daemonState(ctx context.Context, installed bool, supervisor supervisorReport) string {
	if !installed {
		return DaemonNotInstalled
	}
	detail := ""
	if index := strings.Index(supervisor.state, " ("); index >= 0 {
		detail = supervisor.state[index:]
	}
	if _, err := manager.config.Prober.Probe(ctx, manager.daemonAddress()); err == nil {
		return DaemonRunning + detail
	}
	if manager.recentlyFailed(supervisor) {
		return DaemonCrashLooping + detail
	}
	if !strings.HasPrefix(supervisor.state, DaemonRunning) {
		return supervisor.state
	}
	return DaemonUnreachable + detail
}

func (manager *Manager) daemonAddress() string {
	content, err := os.ReadFile(HandshakePath(manager.blackbirdStateDir()))
	if err != nil {
		return defaultHTTPAddress
	}
	var handshake struct {
		HTTPAddress string `json:"http_address"`
	}
	if err := json.Unmarshal(content, &handshake); err != nil || handshake.HTTPAddress == "" {
		return defaultHTTPAddress
	}
	return handshake.HTTPAddress
}

// recentlyFailed reports an actual failure signal, never mere log freshness:
// the daemon routes all of its slog output to stderr at Info level, so its
// error log carries an ordinary start as well as a failing one. A daemon that
// is still binding its listener must read as unreachable, not as crash-looping,
// and a daemon the supervisor is deliberately holding down is stopped even if
// an earlier shutdown wrote to the error log.
func (manager *Manager) recentlyFailed(supervisor supervisorReport) bool {
	if supervisor.dormant() {
		return false
	}
	return supervisor.failed() || manager.loggedFailure()
}

// dormant reports that the supervisor is not trying to run the daemon at all.
// systemd only answers "inactive" for a unit it has stopped, never for one it
// is restarting, and launchctl print fails outright once the job is booted out.
func (supervisor supervisorReport) dormant() bool {
	if supervisor.goos == "darwin" {
		return supervisor.err != nil
	}
	state := strings.TrimSpace(supervisor.output)
	return state == "inactive" || state == "unknown"
}

// failed reads the supervisor's own record of a failing job. systemctl
// is-active exits non-zero for a restart loop and for an exhausted unit alike,
// so the state text is the only thing separating them from a clean stop, and
// launchd keeps both the last exit code and the throttling it applies to a job
// that dies inside its minimum runtime.
func (supervisor supervisorReport) failed() bool {
	if supervisor.goos != "darwin" {
		state := strings.TrimSpace(supervisor.output)
		return state == "failed" || strings.HasPrefix(state, "activating") || strings.Contains(state, "auto-restart")
	}
	if strings.Contains(strings.ToLower(supervisor.output), "throttled") {
		return true
	}
	for _, line := range strings.Split(supervisor.output, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "last exit code" && key != "last exit status" {
			continue
		}
		code, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil && code != 0 {
			return true
		}
	}
	return false
}

// loggedFailure reports whether the tail of the daemon's error log carries an
// Error record the daemon wrote inside the crash window. The supervisor opens
// this file in append mode and never truncates it, so the file's modification
// time belongs to its newest line only: an ordinary healthy start refreshes it
// above failures left there by earlier versions. Every line is therefore dated
// by its own timestamp, and the file time is kept only as a cheap way to skip
// reading an idle log at all.
func (manager *Manager) loggedFailure() bool {
	path := manager.daemonErrorLogPath()
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 || time.Since(info.ModTime()) >= crashWindow {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	offset := int64(0)
	if info.Size() > errorLogTailBytes {
		offset = info.Size() - errorLogTailBytes
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return false
	}
	tail, err := io.ReadAll(io.LimitReader(file, errorLogTailBytes))
	if err != nil {
		return false
	}
	lines := strings.Split(string(tail), "\n")
	if offset > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	for _, line := range lines {
		if freshFailureRecord(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

// freshFailureRecord dates one slog text record and reports an Error written
// inside the crash window. A line the slog handler never wrote - a panic, a
// runtime fatal, the legacy-argv deprecation notice - carries no timestamp, so
// it cannot be told apart from a pre-upgrade leftover and is left to the
// supervisor's own exit-code and throttling signals. The window is applied in
// both directions so a record stamped by a skewed clock ages out instead of
// pinning the daemon to crash-looping forever.
func freshFailureRecord(line string) bool {
	if !strings.Contains(line, errorLevelMarker) {
		return false
	}
	rest, found := strings.CutPrefix(line, logTimeField)
	if !found {
		return false
	}
	stamp, _, _ := strings.Cut(rest, " ")
	written, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return false
	}
	age := time.Since(written)
	return age < crashWindow && age > -crashWindow
}

// Update refreshes Homebrew metadata, upgrades Blackbird, and restarts only after a version change.
func (manager *Manager) Update(ctx context.Context) (UpdateResult, error) {
	// Fail on the cause rather than on its symptom. Reaching brew first reports
	// `exec: "brew": executable file not found in $PATH`, which reads as a
	// broken PATH on a machine that simply never had Homebrew.
	if _, err := manager.homebrew(); err != nil {
		return UpdateResult{}, fmt.Errorf(
			"cannot update: %s; update this installation the way it was installed", UpdaterUnsupportedReason)
	}
	before, err := manager.runRequired(ctx, "brew", "list", "--versions", formula)
	if err != nil {
		return UpdateResult{}, err
	}
	if _, err := manager.runRequired(ctx, "brew", "update"); err != nil {
		return UpdateResult{}, err
	}
	if _, err := manager.runRequired(ctx, "brew", "upgrade", formula); err != nil {
		return UpdateResult{}, err
	}
	after, err := manager.runRequired(ctx, "brew", "list", "--versions", formula)
	if err != nil {
		return UpdateResult{}, err
	}
	result := UpdateResult{Before: before, After: after, Changed: before != after}
	if err := manager.cleanupLegacyAdapters(ctx); err != nil {
		return UpdateResult{}, err
	}
	definitionChanged, skipped, err := manager.convergeInstalledServiceDefinition()
	if err != nil {
		return UpdateResult{}, err
	}
	result.DefinitionSkipped = skipped
	if result.Changed || definitionChanged {
		if err := manager.restart(ctx); err != nil {
			return UpdateResult{}, err
		}
	}
	return result, nil
}

// Uninstall stops per-user units and removes only their definitions. Product data is retained.
func (manager *Manager) Uninstall(ctx context.Context) (Result, error) {
	if err := manager.validatePlatform(); err != nil {
		return Result{}, err
	}
	path := manager.servicePath()
	serviceExists, statErr := pathsExist(path)
	if statErr != nil {
		return Result{}, fmt.Errorf("inspect service definition: %w", statErr)
	}
	updaterPaths := manager.updaterPaths()
	updaterExists, statErr := pathsExist(updaterPaths...)
	if statErr != nil {
		return Result{}, fmt.Errorf("inspect updater definition: %w", statErr)
	}
	if manager.config.GOOS == "darwin" {
		_, _ = manager.config.Runner.Run(ctx, "launchctl", "bootout", manager.launchDomain(), path)
		_, _ = manager.config.Runner.Run(ctx, "launchctl", "bootout", manager.launchDomain(), updaterPaths[0])
	} else if serviceExists {
		if _, err := manager.runRequired(ctx, "systemctl", "--user", "disable", "--now", "blackbird.service"); err != nil {
			return Result{}, err
		}
	}
	if err := manager.cleanupLegacyAdapters(ctx); err != nil {
		return Result{}, err
	}
	if manager.config.GOOS == "linux" && updaterExists {
		if _, err := manager.runRequired(ctx, "systemctl", "--user", "disable", "--now", "blackbird-update.timer"); err != nil {
			return Result{}, err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, fmt.Errorf("remove service definition: %w", err)
	}
	for _, updaterPath := range updaterPaths {
		if err := os.Remove(updaterPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return Result{}, fmt.Errorf("remove updater definition: %w", err)
		}
	}
	if manager.config.GOOS == "linux" {
		if _, err := manager.runRequired(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
			return Result{}, err
		}
	}
	return Result{ServicePath: path, UpdaterPaths: updaterPaths}, nil
}

func (manager *Manager) cleanupLegacyAdapters(ctx context.Context) error {
	paths := []string{manager.companionPath(), manager.piCompanionPath()}
	if manager.config.GOOS == "darwin" {
		for _, path := range paths {
			_, _ = manager.config.Runner.Run(ctx, "launchctl", "bootout", manager.launchDomain(), path)
		}
	} else {
		for index, unit := range []string{"blackbird-claude.service", "blackbird-pi.service"} {
			if exists, err := pathsExist(paths[index]); err != nil {
				return err
			} else if exists {
				if _, err := manager.runRequired(ctx, "systemctl", "--user", "disable", "--now", unit); err != nil {
					return err
				}
			}
		}
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove legacy adapter definition: %w", err)
		}
	}
	return nil
}

// lookPathIn resolves name against an explicit PATH list. exec.LookPath cannot
// do this: it reads the process environment, which is the one PATH the
// unattended updater will never run with.
func lookPathIn(pathList, name string) (string, error) {
	for _, directory := range filepath.SplitList(pathList) {
		if directory == "" {
			continue
		}
		candidate := filepath.Join(directory, name)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%q not found in %s: %w", name, pathList, fs.ErrNotExist)
}

// homebrew reports where the unattended updater would find Homebrew. Detection
// deliberately searches updaterPath rather than the caller's PATH: a Homebrew
// installed under a custom prefix is on the login shell's PATH and absent from
// the updater's, and scheduling a job on the strength of the wrong PATH is the
// failure this check exists to prevent.
func (manager *Manager) homebrew() (string, error) {
	return manager.config.LookPathIn(updaterPath, "brew")
}

func (manager *Manager) homebrewAvailable() bool {
	_, err := manager.homebrew()
	return err == nil
}

func pathsExist(paths ...string) (bool, error) {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

func nativeState(goos, output string, err error, active, inactive string) string {
	state := active
	if err != nil || goos == "darwin" && !strings.Contains(output, "state = running") {
		state = inactive
	}
	if output != "" && goos == "linux" {
		state += " (" + output + ")"
	}
	return state
}

func (manager *Manager) configureClients() ([]string, error) {
	configured := make([]string, 0, 3)
	openCodePath := filepath.Join(manager.config.ConfigHome, "opencode", "opencode.json")
	openCodeJSONCPath := filepath.Join(manager.config.ConfigHome, "opencode", "opencode.jsonc")
	if exists, err := pathsExist(openCodeJSONCPath); err != nil {
		return nil, fmt.Errorf("inspect OpenCode JSONC config: %w", err)
	} else if exists {
		configured = append(configured, "opencode")
	} else if manager.detected("opencode", filepath.Dir(openCodePath), openCodePath) {
		if err := mergeJSONClient(openCodePath, "mcp", map[string]any{"type": "remote", "url": mcpURL}); err != nil {
			return nil, fmt.Errorf("configure OpenCode: %w", err)
		}
		configured = append(configured, "opencode")
	}
	claudePath := filepath.Join(manager.config.HomeDir, ".claude.json")
	if manager.detected("claude", filepath.Join(manager.config.HomeDir, ".claude"), claudePath) {
		if err := mergeJSONClient(claudePath, "mcpServers", map[string]any{"type": "http", "url": mcpURL}); err != nil {
			return nil, fmt.Errorf("configure Claude: %w", err)
		}
		configured = append(configured, "claude")
	}
	codexPath := filepath.Join(manager.config.HomeDir, ".codex", "config.toml")
	if manager.detected("codex", filepath.Dir(codexPath), codexPath) {
		if err := mergeCodex(codexPath); err != nil {
			return nil, fmt.Errorf("configure Codex: %w", err)
		}
		configured = append(configured, "codex")
	}
	return configured, nil
}

func (manager *Manager) detected(executable, directory, configPath string) bool {
	if _, err := os.Stat(configPath); err == nil {
		return true
	}
	if info, err := os.Stat(directory); err == nil && info.IsDir() {
		return true
	}
	_, err := manager.config.LookPath(executable)
	return err == nil
}

func mergeJSONClient(path, collection string, client map[string]any) error {
	document := make(map[string]any)
	content, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(content, &document); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if document == nil {
			document = make(map[string]any)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	entries, ok := document[collection].(map[string]any)
	if !ok {
		if document[collection] != nil {
			return fmt.Errorf("%s field %q is not an object", path, collection)
		}
		entries = make(map[string]any)
		document[collection] = entries
	}
	entries["blackbird"] = client

	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicWrite(path, output.Bytes(), 0o600)
}

func mergeCodex(path string) error {
	content, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	managed := codexStart + "\n[mcp_servers.blackbird]\nurl = \"" + mcpURL + "\"\n" + codexEnd
	text := strings.TrimSpace(string(content))
	start := strings.Index(text, codexStart)
	end := strings.Index(text, codexEnd)
	switch {
	case start >= 0 && end >= start:
		end += len(codexEnd)
		text = strings.TrimSpace(text[:start] + managed + text[end:])
	case start >= 0 || end >= 0:
		return errors.New("incomplete managed Blackbird block")
	case text == "":
		text = managed
	default:
		text = replaceCodexSection(text, managed)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicWrite(path, []byte(text+"\n"), 0o600)
}

func replaceCodexSection(text, managed string) string {
	lines := strings.Split(text, "\n")
	sectionStart := -1
	sectionEnd := len(lines)
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[mcp_servers.blackbird]" {
			sectionStart = index
			continue
		}
		if sectionStart >= 0 && index > sectionStart && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			sectionEnd = index
			break
		}
	}
	if sectionStart < 0 {
		return text + "\n\n" + managed
	}
	prefix := strings.TrimSpace(strings.Join(lines[:sectionStart], "\n"))
	suffix := strings.TrimSpace(strings.Join(lines[sectionEnd:], "\n"))
	parts := make([]string, 0, 3)
	if prefix != "" {
		parts = append(parts, prefix)
	}
	parts = append(parts, managed)
	if suffix != "" {
		parts = append(parts, suffix)
	}
	return strings.Join(parts, "\n\n")
}

func atomicWrite(path string, content []byte, mode fs.FileMode) error {
	temporary := path + ".blackbird.tmp"
	if err := os.WriteFile(temporary, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func (manager *Manager) restart(ctx context.Context) error {
	if manager.config.GOOS == "darwin" {
		_, _ = manager.config.Runner.Run(ctx, "launchctl", "bootout", manager.launchDomain(), manager.servicePath())
		if _, err := manager.runRequired(ctx, "launchctl", "bootstrap", manager.launchDomain(), manager.servicePath()); err != nil {
			return err
		}
		_, err := manager.runRequired(ctx, "launchctl", "kickstart", "-k", manager.launchDomain()+"/"+serviceLabel)
		return err
	}
	if _, err := manager.runRequired(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if _, err := manager.runRequired(ctx, "systemctl", "--user", "enable", "blackbird.service"); err != nil {
		return err
	}
	_, err := manager.runRequired(ctx, "systemctl", "--user", "restart", "blackbird.service")
	return err
}

func (manager *Manager) restartUpdater(ctx context.Context) error {
	if manager.config.GOOS == "darwin" {
		path := manager.updaterPaths()[0]
		_, _ = manager.config.Runner.Run(ctx, "launchctl", "bootout", manager.launchDomain(), path)
		_, err := manager.runRequired(ctx, "launchctl", "bootstrap", manager.launchDomain(), path)
		return err
	}
	if _, err := manager.runRequired(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	_, err := manager.runRequired(ctx, "systemctl", "--user", "enable", "--now", "blackbird-update.timer")
	return err
}

func (manager *Manager) runRequired(ctx context.Context, name string, args ...string) (string, error) {
	output, err := manager.config.Runner.Run(ctx, name, args...)
	if err != nil {
		return "", fmt.Errorf("run %s %s: %w: %s", name, strings.Join(args, " "), err, output)
	}
	return output, nil
}

func (manager *Manager) validatePlatform() error {
	if manager.config.GOOS != "darwin" && manager.config.GOOS != "linux" {
		return fmt.Errorf("unsupported operating system %q", manager.config.GOOS)
	}
	if manager.config.Executable == "" {
		return errors.New("blackbird executable path is empty")
	}
	if manager.config.UpdateInterval < minimumUpdateInterval || manager.config.UpdateInterval > maximumUpdateInterval {
		return fmt.Errorf("update interval %s must be between %s and %s", manager.config.UpdateInterval, minimumUpdateInterval, maximumUpdateInterval)
	}
	return nil
}

func (manager *Manager) blackbirdConfigDir() string {
	return filepath.Join(manager.config.ConfigHome, "blackbird")
}

func (manager *Manager) blackbirdDataDir() string {
	return filepath.Join(manager.config.DataHome, "blackbird")
}

func (manager *Manager) blackbirdStateDir() string {
	return filepath.Join(manager.config.StateHome, "blackbird")
}

func (manager *Manager) launchDomain() string {
	return "gui/" + strconv.Itoa(manager.config.UID)
}

func (manager *Manager) servicePath() string {
	if manager.config.GOOS == "darwin" {
		return filepath.Join(manager.config.HomeDir, "Library", "LaunchAgents", serviceLabel+".plist")
	}
	return filepath.Join(manager.config.ConfigHome, "systemd", "user", "blackbird.service")
}

func (manager *Manager) companionPath() string {
	if manager.config.GOOS == "darwin" {
		return filepath.Join(manager.config.HomeDir, "Library", "LaunchAgents", companionLabel+".plist")
	}
	return filepath.Join(manager.config.ConfigHome, "systemd", "user", "blackbird-claude.service")
}

func (manager *Manager) piCompanionPath() string {
	if manager.config.GOOS == "darwin" {
		return filepath.Join(manager.config.HomeDir, "Library", "LaunchAgents", piLabel+".plist")
	}
	return filepath.Join(manager.config.ConfigHome, "systemd", "user", "blackbird-pi.service")
}

func (manager *Manager) updaterPaths() []string {
	if manager.config.GOOS == "darwin" {
		return []string{filepath.Join(manager.config.HomeDir, "Library", "LaunchAgents", updaterLabel+".plist")}
	}
	unitDirectory := filepath.Join(manager.config.ConfigHome, "systemd", "user")
	return []string{filepath.Join(unitDirectory, "blackbird-update.service"), filepath.Join(unitDirectory, "blackbird-update.timer")}
}

// updaterEnvironment is the environment the unattended updater must run with.
// Neither a launchd agent nor a systemd user unit inherits the login shell, so
// without these `blackbird update` resolves the XDG defaults instead of the
// directories this installation actually uses, and converges a service
// definition pointing at a different database and state directory than the one
// it is repairing.
func (manager *Manager) updaterEnvironment() []environmentEntry {
	return []environmentEntry{
		{name: "PATH", value: updaterPath},
		{name: "XDG_CONFIG_HOME", value: manager.config.ConfigHome},
		{name: "XDG_DATA_HOME", value: manager.config.DataHome},
		{name: "XDG_STATE_HOME", value: manager.config.StateHome},
	}
}

type environmentEntry struct {
	name  string
	value string
}

func (manager *Manager) updaterDefinitions() []string {
	environment := manager.updaterEnvironment()
	if manager.config.GOOS == "darwin" {
		variables := make([]string, 0, len(environment))
		for _, entry := range environment {
			variables = append(variables, "<key>"+xmlEscape(entry.name)+"</key><string>"+xmlEscape(entry.value)+"</string>")
		}
		return []string{fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array><string>%s</string><string>update</string></array>
  <key>EnvironmentVariables</key>
  <dict>%s</dict>
  <key>StartInterval</key><integer>%d</integer>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, updaterLabel, xmlEscape(manager.config.Executable), strings.Join(variables, ""), int(manager.config.UpdateInterval/time.Second), xmlEscape(filepath.Join(manager.blackbirdStateDir(), "update.log")), xmlEscape(filepath.Join(manager.blackbirdStateDir(), "update.err.log")))}
	}
	assignments := make([]string, 0, len(environment))
	for _, entry := range environment {
		assignments = append(assignments, "Environment="+systemdEscape(entry.name+"="+entry.value))
	}
	service := fmt.Sprintf(`[Unit]
Description=Update Blackbird through Homebrew
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
%s
ExecStart=%s update
`, strings.Join(assignments, "\n"), systemdEscape(manager.config.Executable))
	timer := fmt.Sprintf(`[Unit]
Description=Periodically update Blackbird through Homebrew

[Timer]
OnStartupSec=%d
OnUnitActiveSec=%d
Persistent=true
Unit=blackbird-update.service

[Install]
WantedBy=timers.target
`, int(manager.config.UpdateInterval/time.Second), int(manager.config.UpdateInterval/time.Second))
	return []string{service, timer}
}

func (manager *Manager) serviceDefinition() string {
	argv := manager.ServiceArgv()
	if manager.config.GOOS == "darwin" {
		arguments := make([]string, 0, len(argv))
		for _, argument := range argv {
			arguments = append(arguments, "<string>"+xmlEscape(argument)+"</string>")
		}
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>%s</array>
  <key>EnvironmentVariables</key>
  <dict><key>XDG_STATE_HOME</key><string>%s</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, serviceLabel, strings.Join(arguments, ""), xmlEscape(manager.config.StateHome),
			xmlEscape(manager.daemonLogPath()), xmlEscape(manager.daemonErrorLogPath()))
	}
	arguments := make([]string, 0, len(argv))
	for _, argument := range argv {
		arguments = append(arguments, systemdEscape(argument))
	}
	// Without these the daemon's output goes to the journal, where the log
	// reader cannot see it: it only ever reads these two files, so a Linux user
	// following `blackbird logs` — which three doctor remedies point at — gets
	// an empty stream. Appending to the same paths the launchd agent writes
	// makes both platforms behave identically. systemd creates the files but not
	// their parent, which is why convergeServiceDefinition ensures the state
	// directory before this definition reaches disk.
	return fmt.Sprintf(`[Unit]
Description=Blackbird local coordination service
After=network.target

[Service]
Type=simple
Environment=%s
ExecStart=%s
StandardOutput=append:%s
StandardError=append:%s
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`, systemdEscape("XDG_STATE_HOME="+manager.config.StateHome), strings.Join(arguments, " "),
		systemdPath(manager.daemonLogPath()), systemdPath(manager.daemonErrorLogPath()))
}

// convergeServiceDefinition rewrites the service definition only when the
// on-disk bytes differ, and reports whether it changed. Every upgraded machine
// repairs its own unit file on the next unattended updater tick.
func (manager *Manager) convergeServiceDefinition() (bool, error) {
	path := manager.servicePath()
	// Both supervisors open the daemon's log files themselves and neither
	// creates the directory holding them, so a missing state directory fails the
	// unit outright rather than degrading to no logs. Install creates it before
	// reaching here, but the unattended updater converges the definition without
	// having created anything, and the early return below skips straight to a
	// restart — so the guarantee belongs here, ahead of the comparison.
	if err := os.MkdirAll(manager.blackbirdStateDir(), 0o700); err != nil {
		return false, fmt.Errorf("create state directory: %w", err)
	}
	wanted := []byte(manager.serviceDefinition())
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("read service definition: %w", err)
	}
	if err == nil && bytes.Equal(current, wanted) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("create service directory: %w", err)
	}
	if err := atomicWrite(path, wanted, 0o600); err != nil {
		return false, fmt.Errorf("write service definition: %w", err)
	}
	return true, nil
}

// convergeInstalledServiceDefinition repairs the unit file only when this
// process is the binary the unit already invokes, and reports whether it was
// skipped. An unattended `blackbird update` can run from a build tree or a
// throwaway copy; writing ServiceArgv() then would repoint the supervisor at a
// path that disappears, and the service would fail to start on the next boot.
// Only `blackbird install` may name a new executable for the service.
func (manager *Manager) convergeInstalledServiceDefinition() (changed, skipped bool, err error) {
	recorded, err := manager.recordedServiceExecutable()
	if err != nil {
		return false, false, err
	}
	if !sameExecutable(recorded, manager.config.Executable) {
		return false, true, nil
	}
	changed, err = manager.convergeServiceDefinition()
	return changed, false, err
}

func (manager *Manager) recordedServiceExecutable() (string, error) {
	content, err := os.ReadFile(manager.servicePath())
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read service definition: %w", err)
	}
	return definitionExecutable(manager.config.GOOS, string(content)), nil
}

func definitionExecutable(goos, definition string) string {
	if goos == "darwin" {
		arguments := strings.Index(definition, "<key>ProgramArguments</key>")
		if arguments < 0 {
			return ""
		}
		rest := definition[arguments:]
		start := strings.Index(rest, "<string>")
		if start < 0 {
			return ""
		}
		rest = rest[start+len("<string>"):]
		end := strings.Index(rest, "</string>")
		if end < 0 {
			return ""
		}
		return xmlUnescape(rest[:end])
	}
	for _, line := range strings.Split(definition, "\n") {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), "ExecStart="); found {
			return firstSystemdArgument(value)
		}
	}
	return ""
}

func firstSystemdArgument(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, `"`) {
		if index := strings.IndexByte(value, ' '); index >= 0 {
			return value[:index]
		}
		return value
	}
	var argument strings.Builder
	for index := 1; index < len(value); index++ {
		switch {
		case value[index] == '\\' && index+1 < len(value):
			index++
			argument.WriteByte(value[index])
		case value[index] == '"':
			return strings.ReplaceAll(argument.String(), "%%", "%")
		default:
			argument.WriteByte(value[index])
		}
	}
	return strings.ReplaceAll(argument.String(), "%%", "%")
}

func sameExecutable(recorded, current string) bool {
	if recorded == "" || current == "" {
		return false
	}
	if recorded == current {
		return true
	}
	recordedInfo, err := os.Stat(recorded)
	if err != nil {
		return false
	}
	currentInfo, err := os.Stat(current)
	if err != nil {
		return false
	}
	return os.SameFile(recordedInfo, currentInfo)
}

func (manager *Manager) definitionState() (string, error) {
	current, err := os.ReadFile(manager.servicePath())
	if errors.Is(err, fs.ErrNotExist) {
		return DefinitionAbsent, nil
	}
	if err != nil {
		return "", fmt.Errorf("read service definition: %w", err)
	}
	if !bytes.Equal(current, []byte(manager.serviceDefinition())) {
		return DefinitionStale, nil
	}
	return DefinitionCurrent, nil
}

func (manager *Manager) daemonLogPath() string {
	return filepath.Join(manager.blackbirdStateDir(), daemonLogFileName)
}

func (manager *Manager) daemonErrorLogPath() string {
	return filepath.Join(manager.blackbirdStateDir(), daemonErrFileName)
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return replacer.Replace(value)
}

func xmlUnescape(value string) string {
	replacer := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&")
	return replacer.Replace(value)
}

func systemdEscape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`)
	return `"` + replacer.Replace(value) + `"`
}

// systemdPath renders a path for a directive that takes the rest of its line
// literally, such as StandardOutput=append:. Those are not unquoted the way
// ExecStart= and Environment= are, so systemdEscape's quotes would become part
// of the path; only the specifier introducer still has to be escaped.
func systemdPath(value string) string {
	return strings.ReplaceAll(value, "%", "%%")
}
