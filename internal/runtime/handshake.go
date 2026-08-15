package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/phall1/blackbird/internal/install"
)

const (
	handshakeSchema  = "blackbird.admin/v1"
	adminTokenPrefix = "bba_"
	adminTokenBytes  = 32
)

// adminHandshake is the daemon discovery and credential record. The token is
// minted per start and lives nowhere else, so a record left behind by a crashed
// daemon carries a credential that can no longer authenticate anything.
type adminHandshake struct {
	Schema      string `json:"schema"`
	HTTPAddress string `json:"http_address"`
	Token       string `json:"token"`
	PID         int    `json:"pid"`
	StartedAt   string `json:"started_at"`
	Version     string `json:"version"`
}

type adminHandshakeWorker struct {
	path      string
	logger    *slog.Logger
	handshake adminHandshake
}

func newAdminToken() (string, error) {
	material := make([]byte, adminTokenBytes)
	if _, err := rand.Read(material); err != nil {
		return "", fmt.Errorf("read random material: %w", err)
	}
	return adminTokenPrefix + hex.EncodeToString(material), nil
}

// newAdminHandshakeWorker resolves the handshake path from the explicitly
// configured state directory. A launchd agent and a systemd user unit inherit
// neither XDG_STATE_HOME nor the login shell's environment, so the installed
// service definition passes the directory as an argument; the environment
// fallback only serves developer invocations.
func newAdminHandshakeWorker(
	stateDir, token, httpAddress, version string,
	startedAt time.Time,
	logger *slog.Logger,
) (*adminHandshakeWorker, error) {
	// An unresolvable state directory costs discovery, never startup: this
	// constructor runs on the path that composes a daemon which is about to
	// serve, and returning an error here would wedge it under KeepAlive exactly
	// as a fatal Start would. An empty path makes Start log and continue.
	if stateDir == "" {
		if resolved, err := install.DefaultStateDir(); err == nil {
			stateDir = resolved
		}
	}
	path := ""
	if stateDir != "" {
		if absolute, err := filepath.Abs(stateDir); err == nil {
			path = install.HandshakePath(filepath.Clean(absolute))
		}
	}
	return &adminHandshakeWorker{
		path:   path,
		logger: logger,
		handshake: adminHandshake{
			Schema: handshakeSchema, HTTPAddress: httpAddress, Token: token,
			PID: os.Getpid(), StartedAt: startedAt.UTC().Format(time.RFC3339Nano), Version: version,
		},
	}, nil
}

// Start publishes this daemon's discovery record unconditionally. Binding the
// HTTP listener is the mutual exclusion, and it already happened: the kernel
// admits exactly one process to an address, and listeners bind before workers
// start. Reaching here therefore proves this process is the daemon, so its
// record is the truth and replaces whatever a crashed predecessor left behind.
//
// Earlier revisions tried to arbitrate ownership here with an exclusive create
// plus a liveness check on the recorded pid or address. Every variant turned a
// stale record into a permanent startup failure under launchd KeepAlive, which
// is a far worse outcome than a stale record: a recycled pid, a root-owned pid
// that only answers EPERM, or any unrelated service answering on the recorded
// port would each wedge the daemon forever.
//
// For the same reason it never fails: publishing is best-effort, so a state
// directory left root-owned by a past sudo invocation or a full disk costs
// discovery only. The daemon serves; the CLI degrades to --address.
func (worker *adminHandshakeWorker) Start(context.Context) error {
	if err := worker.write(); err != nil {
		worker.logger.Error("continuing without a discovery record; the CLI will need --address",
			slog.String("path", worker.path), slog.String("error", err.Error()))
	}
	return nil
}

func (worker *adminHandshakeWorker) write() error {
	if worker.path == "" {
		return errors.New("no state directory could be resolved")
	}
	directory := filepath.Dir(worker.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	// MkdirAll leaves an existing directory's mode alone, and a group-readable
	// state directory would hand the admin token to every uid on the machine.
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("restrict state directory: %w", err)
	}
	content, err := json.Marshal(worker.handshake)
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}
	if err := worker.publish(append(content, '\n')); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	worker.logger.Info("handshake published", slog.String("path", worker.path))
	return nil
}

// publish writes the record atomically so a reader never observes a partial
// document and never observes a window with no record at all.
func (worker *adminHandshakeWorker) publish(content []byte) error {
	file, err := os.CreateTemp(filepath.Dir(worker.path), ".admin-*.json")
	if err != nil {
		return fmt.Errorf("create handshake: %w", err)
	}
	name := file.Name()
	if _, err := file.Write(content); err != nil {
		return errors.Join(fmt.Errorf("write handshake: %w", err), file.Close(), os.Remove(name))
	}
	if err := file.Close(); err != nil {
		return errors.Join(fmt.Errorf("close handshake: %w", err), os.Remove(name))
	}
	if err := os.Rename(name, worker.path); err != nil {
		return errors.Join(fmt.Errorf("publish handshake: %w", err), os.Remove(name))
	}
	return nil
}

// Stop removes only a record this process wrote. A daemon that lost the address
// race, or a second daemon started for development, must never delete the live
// daemon's discovery record on its way out.
func (worker *adminHandshakeWorker) Stop(context.Context) error {
	if worker.path == "" {
		return nil
	}
	content, err := os.ReadFile(worker.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		// Symmetric with Start: discovery metadata must not fail a shutdown.
		worker.logger.Warn("leaving an unreadable handshake in place",
			slog.String("path", worker.path), slog.String("error", err.Error()))
		return nil
	}
	var current adminHandshake
	if err := json.Unmarshal(content, &current); err != nil {
		worker.logger.Warn("leaving an unreadable handshake in place", slog.String("path", worker.path))
		return nil
	}
	if current.PID != worker.handshake.PID || current.Token != worker.handshake.Token {
		worker.logger.Warn("leaving another daemon's handshake in place",
			slog.String("path", worker.path), slog.Int("owner_pid", current.PID))
		return nil
	}
	if err := os.Remove(worker.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove handshake: %w", err)
	}
	worker.logger.Info("handshake withdrawn", slog.String("path", worker.path))
	return nil
}
