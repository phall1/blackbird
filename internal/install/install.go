// Package install manages Blackbird's per-user service and MCP client registration.
package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	updaterLabel          = "com.phall1.blackbird.update"
	formula               = "phall1/tap/blackbird"
	mcpURL                = "http://127.0.0.1:8081"
	codexStart            = "# BEGIN BLACKBIRD MCP (managed by blackbird)"
	codexEnd              = "# END BLACKBIRD MCP (managed by blackbird)"
	defaultUpdateInterval = 6 * time.Hour
	minimumUpdateInterval = time.Hour
	maximumUpdateInterval = 24 * time.Hour
	updaterPath           = "/opt/homebrew/bin:/usr/local/bin:/home/linuxbrew/.linuxbrew/bin:/usr/bin:/bin"
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

// Config supplies host details. Tests can override every machine-dependent input.
type Config struct {
	GOOS                string
	HomeDir             string
	ConfigHome          string
	DataHome            string
	StateHome           string
	Executable          string
	CompanionExecutable string
	ClaudeExecutable    string
	WorkingDir          string
	UID                 int
	UpdateInterval      time.Duration
	Runner              Runner
	LookPath            func(string) (string, error)
}

// Manager manages the local Blackbird product installation.
type Manager struct {
	config Config
}

// Result describes files changed by an operation.
type Result struct {
	ServicePath   string
	CompanionPath string
	UpdaterPaths  []string
	Clients       []string
}

type companionConfig struct {
	ProjectPath string `json:"project_path"`
	AgentName   string `json:"agent_name"`
}

// UpdateResult reports whether Homebrew installed a different version.
type UpdateResult struct {
	Changed bool
	Before  string
	After   string
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
		StateHome: os.Getenv("XDG_STATE_HOME"), Executable: executable,
		CompanionExecutable: filepath.Join(filepath.Dir(executable), "blackbird-claude"), WorkingDir: workingDir,
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
	if config.StateHome == "" {
		config.StateHome = filepath.Join(config.HomeDir, ".local", "state")
	}
	if config.Runner == nil {
		config.Runner = commandRunner{}
	}
	if config.LookPath == nil {
		config.LookPath = exec.LookPath
	}
	if config.UID == 0 {
		config.UID = os.Getuid()
	}
	if config.UpdateInterval == 0 {
		config.UpdateInterval = defaultUpdateInterval
	}
	if config.CompanionExecutable == "" {
		config.CompanionExecutable = filepath.Join(filepath.Dir(config.Executable), "blackbird-claude")
	}
	if config.ClaudeExecutable == "" {
		if executable, err := config.LookPath("claude"); err == nil {
			config.ClaudeExecutable = executable
		} else {
			config.ClaudeExecutable = "claude"
		}
	}
	if config.WorkingDir == "" {
		config.WorkingDir = config.HomeDir
	}
	return &Manager{config: config}
}

// Install creates local directories, converges detected MCP clients, and restarts the service.
func (manager *Manager) Install(ctx context.Context) (Result, error) {
	if err := manager.validatePlatform(); err != nil {
		return Result{}, err
	}
	for _, directory := range []string{manager.blackbirdConfigDir(), manager.blackbirdDataDir(), manager.blackbirdStateDir(), filepath.Join(manager.blackbirdStateDir(), "claude")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return Result{}, fmt.Errorf("create %s: %w", directory, err)
		}
	}
	if err := manager.convergeCompanionConfig(); err != nil {
		return Result{}, err
	}

	clients, err := manager.configureClients()
	if err != nil {
		return Result{}, err
	}
	servicePath := manager.servicePath()
	if err := os.MkdirAll(filepath.Dir(servicePath), 0o700); err != nil {
		return Result{}, fmt.Errorf("create service directory: %w", err)
	}
	if err := atomicWrite(servicePath, []byte(manager.serviceDefinition()), 0o600); err != nil {
		return Result{}, fmt.Errorf("write service definition: %w", err)
	}
	companionPath := manager.companionPath()
	if err := atomicWrite(companionPath, []byte(manager.companionDefinition()), 0o600); err != nil {
		return Result{}, fmt.Errorf("write companion definition: %w", err)
	}
	updaterPaths := manager.updaterPaths()
	for index, path := range updaterPaths {
		if err := atomicWrite(path, []byte(manager.updaterDefinitions()[index]), 0o600); err != nil {
			return Result{}, fmt.Errorf("write updater definition: %w", err)
		}
	}
	if err := manager.restart(ctx); err != nil {
		return Result{}, err
	}
	if err := manager.restartCompanion(ctx); err != nil {
		return Result{}, err
	}
	if err := manager.restartUpdater(ctx); err != nil {
		return Result{}, err
	}
	return Result{ServicePath: servicePath, CompanionPath: companionPath, UpdaterPaths: updaterPaths, Clients: clients}, nil
}

// Status reports the daemon and periodic updater definitions and native states.
func (manager *Manager) Status(ctx context.Context) (string, error) {
	if err := manager.validatePlatform(); err != nil {
		return "", err
	}
	if saved, found, err := manager.readCompanionConfig(); err != nil {
		return "", err
	} else if found {
		manager.config.WorkingDir = saved.ProjectPath
	}
	serviceInstalled, err := pathsExist(manager.servicePath())
	if err != nil {
		return "", fmt.Errorf("inspect service definition: %w", err)
	}
	updaterInstalled, err := pathsExist(manager.updaterPaths()...)
	if err != nil {
		return "", fmt.Errorf("inspect updater definition: %w", err)
	}

	companionInstalled, err := pathsExist(manager.companionPath())
	if err != nil {
		return "", fmt.Errorf("inspect companion definition: %w", err)
	}
	var serviceOutput, companionOutput, updaterOutput string
	var serviceErr, companionErr, updaterErr error
	if manager.config.GOOS == "darwin" {
		serviceOutput, serviceErr = manager.config.Runner.Run(ctx, "launchctl", "print", manager.launchDomain()+"/"+serviceLabel)
		companionOutput, companionErr = manager.config.Runner.Run(ctx, "launchctl", "print", manager.launchDomain()+"/"+companionLabel)
		updaterOutput, updaterErr = manager.config.Runner.Run(ctx, "launchctl", "print", manager.launchDomain()+"/"+updaterLabel)
	} else {
		serviceOutput, serviceErr = manager.config.Runner.Run(ctx, "systemctl", "--user", "is-active", "blackbird.service")
		companionOutput, companionErr = manager.config.Runner.Run(ctx, "systemctl", "--user", "is-active", "blackbird-claude.service")
		updaterOutput, updaterErr = manager.config.Runner.Run(ctx, "systemctl", "--user", "is-active", "blackbird-update.timer")
	}
	serviceState := nativeState(manager.config.GOOS, serviceOutput, serviceErr, "running", "stopped")
	companionState := nativeState(manager.config.GOOS, companionOutput, companionErr, "running", "stopped")
	updaterState := nativeState(manager.config.GOOS, updaterOutput, updaterErr, "scheduled", "stopped")
	return fmt.Sprintf(
		"daemon=%s installed=%t path=%s companion=%s installed=%t path=%s project=%s agent=ClaudeCode updater=%s installed=%t paths=%s interval=%s",
		serviceState, serviceInstalled, manager.servicePath(), companionState, companionInstalled, manager.companionPath(), manager.config.WorkingDir, updaterState, updaterInstalled,
		strings.Join(manager.updaterPaths(), ","), manager.config.UpdateInterval,
	), nil
}

// Update refreshes Homebrew metadata, upgrades Blackbird, and restarts only after a version change.
func (manager *Manager) Update(ctx context.Context) (UpdateResult, error) {
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
	if result.Changed {
		if err := manager.restart(ctx); err != nil {
			return UpdateResult{}, err
		}
		if err := manager.restartCompanion(ctx); err != nil {
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
	companionPath := manager.companionPath()
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
		_, _ = manager.config.Runner.Run(ctx, "launchctl", "bootout", manager.launchDomain(), companionPath)
		_, _ = manager.config.Runner.Run(ctx, "launchctl", "bootout", manager.launchDomain(), updaterPaths[0])
	} else if serviceExists {
		if _, err := manager.runRequired(ctx, "systemctl", "--user", "disable", "--now", "blackbird.service"); err != nil {
			return Result{}, err
		}
	}
	if manager.config.GOOS == "linux" {
		if companionExists, _ := pathsExist(companionPath); companionExists {
			if _, err := manager.runRequired(ctx, "systemctl", "--user", "disable", "--now", "blackbird-claude.service"); err != nil {
				return Result{}, err
			}
		}
	}
	if manager.config.GOOS == "linux" && updaterExists {
		if _, err := manager.runRequired(ctx, "systemctl", "--user", "disable", "--now", "blackbird-update.timer"); err != nil {
			return Result{}, err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, fmt.Errorf("remove service definition: %w", err)
	}
	if err := os.Remove(companionPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, fmt.Errorf("remove companion definition: %w", err)
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
	return Result{ServicePath: path, CompanionPath: companionPath, UpdaterPaths: updaterPaths}, nil
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
	if manager.detected("opencode", filepath.Dir(openCodePath), openCodePath) {
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

func (manager *Manager) convergeCompanionConfig() error {
	path := filepath.Join(manager.blackbirdConfigDir(), "claude.json")
	saved, found, err := manager.readCompanionConfig()
	if err != nil {
		return err
	}
	if found {
		manager.config.WorkingDir = saved.ProjectPath
		return nil
	}
	encoded, err := json.MarshalIndent(companionConfig{ProjectPath: manager.config.WorkingDir, AgentName: "ClaudeCode"}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(encoded, '\n'), 0o600)
}

func (manager *Manager) readCompanionConfig() (companionConfig, bool, error) {
	path := filepath.Join(manager.blackbirdConfigDir(), "claude.json")
	content, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return companionConfig{}, false, nil
	}
	if err != nil {
		return companionConfig{}, false, fmt.Errorf("read companion config: %w", err)
	}
	var saved companionConfig
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&saved); err != nil {
		return companionConfig{}, false, fmt.Errorf("parse companion config %s: %w", path, err)
	}
	if saved.ProjectPath == "" || saved.AgentName == "" {
		return companionConfig{}, false, fmt.Errorf("parse companion config %s: project_path and agent_name are required", path)
	}
	return saved, true, nil
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

func (manager *Manager) restartCompanion(ctx context.Context) error {
	if manager.config.GOOS == "darwin" {
		_, _ = manager.config.Runner.Run(ctx, "launchctl", "bootout", manager.launchDomain(), manager.companionPath())
		if _, err := manager.runRequired(ctx, "launchctl", "bootstrap", manager.launchDomain(), manager.companionPath()); err != nil {
			return err
		}
		_, err := manager.runRequired(ctx, "launchctl", "kickstart", "-k", manager.launchDomain()+"/"+companionLabel)
		return err
	}
	if _, err := manager.runRequired(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if _, err := manager.runRequired(ctx, "systemctl", "--user", "enable", "blackbird-claude.service"); err != nil {
		return err
	}
	_, err := manager.runRequired(ctx, "systemctl", "--user", "restart", "blackbird-claude.service")
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

func (manager *Manager) updaterPaths() []string {
	if manager.config.GOOS == "darwin" {
		return []string{filepath.Join(manager.config.HomeDir, "Library", "LaunchAgents", updaterLabel+".plist")}
	}
	unitDirectory := filepath.Join(manager.config.ConfigHome, "systemd", "user")
	return []string{filepath.Join(unitDirectory, "blackbird-update.service"), filepath.Join(unitDirectory, "blackbird-update.timer")}
}

func (manager *Manager) updaterDefinitions() []string {
	if manager.config.GOOS == "darwin" {
		return []string{fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array><string>%s</string><string>update</string></array>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>%s</string></dict>
  <key>StartInterval</key><integer>%d</integer>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, updaterLabel, xmlEscape(manager.config.Executable), updaterPath, int(manager.config.UpdateInterval/time.Second), xmlEscape(filepath.Join(manager.blackbirdStateDir(), "update.log")), xmlEscape(filepath.Join(manager.blackbirdStateDir(), "update.err.log")))}
	}
	service := fmt.Sprintf(`[Unit]
Description=Update Blackbird through Homebrew
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=%s
ExecStart=%s update
`, systemdEscape("PATH="+updaterPath), systemdEscape(manager.config.Executable))
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
	database := filepath.Join(manager.blackbirdDataDir(), "blackbird.db")
	if manager.config.GOOS == "darwin" {
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array><string>%s</string><string>--sqlite-path=%s</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, serviceLabel, xmlEscape(manager.config.Executable), xmlEscape(database), xmlEscape(filepath.Join(manager.blackbirdStateDir(), "blackbird.log")), xmlEscape(filepath.Join(manager.blackbirdStateDir(), "blackbird.err.log")))
	}
	return fmt.Sprintf(`[Unit]
Description=Blackbird local coordination service
After=network.target

[Service]
Type=simple
ExecStart=%s --sqlite-path=%s
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`, systemdEscape(manager.config.Executable), systemdEscape(database))
}

func (manager *Manager) companionDefinition() string {
	state := filepath.Join(manager.blackbirdStateDir(), "claude")
	if manager.config.GOOS == "darwin" {
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>--project</string><string>%s</string><string>--agent</string><string>ClaudeCode</string><string>--state-dir</string><string>%s</string><string>--claude</string><string>%s</string></array>
  <key>EnvironmentVariables</key><dict><key>HOME</key><string>%s</string><key>PATH</key><string>%s</string></dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string><key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, companionLabel, xmlEscape(manager.config.CompanionExecutable), xmlEscape(manager.config.WorkingDir), xmlEscape(state), xmlEscape(manager.config.ClaudeExecutable), xmlEscape(manager.config.HomeDir), xmlEscape(updaterPath), xmlEscape(filepath.Join(state, "companion.log")), xmlEscape(filepath.Join(state, "companion.err.log")))
	}
	return fmt.Sprintf(`[Unit]
Description=Blackbird Claude Code companion
After=blackbird.service
Requires=blackbird.service

[Service]
Type=simple
Environment=%s
ExecStart=%s --project %s --agent ClaudeCode --state-dir %s --claude %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, systemdEscape("PATH="+updaterPath), systemdEscape(manager.config.CompanionExecutable), systemdEscape(manager.config.WorkingDir), systemdEscape(state), systemdEscape(manager.config.ClaudeExecutable))
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return replacer.Replace(value)
}

func systemdEscape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`)
	return `"` + replacer.Replace(value) + `"`
}
