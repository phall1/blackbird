package cli

import (
	"context"
	"errors"
	"path/filepath"
	"time"
)

// DaemonCmd runs the coordination service in the foreground. The installed
// launchd plist and systemd unit both invoke exactly this command, so every
// flag here is part of the service definition's contract.
type DaemonCmd struct {
	Storage         string        `enum:"sqlite,postgres" default:"${daemon_storage}" help:"Durable storage backend."`
	SQLitePath      string        `name:"sqlite-path" placeholder:"PATH" default:"${daemon_sqlite_path}" help:"Absolute path to the SQLite database."`
	StateDir        string        `name:"state-dir" placeholder:"PATH" default:"${daemon_state_dir}" help:"Directory holding the daemon handshake record."`
	HTTPAddress     string        `name:"http-address" placeholder:"HOST:PORT" default:"${daemon_http_address}" help:"HTTP listen address."`
	MCPAddress      string        `name:"mcp-address" placeholder:"HOST:PORT" default:"${daemon_mcp_address}" help:"MCP listen address."`
	LogLevel        string        `name:"log-level" enum:",debug,info,warn,error" default:"${daemon_log_level}" help:"Structured log severity."`
	ShutdownTimeout time.Duration `default:"${daemon_shutdown_timeout}" help:"Grace period for draining ingress on shutdown."`
}

// Help is Kong's HelpProvider hook: it supplies the command's long detail.
func (cmd *DaemonCmd) Help() string {
	return "Blocks until SIGINT or SIGTERM. Managed installs run this under launchd or systemd; " +
		"run it by hand only to debug."
}

func (cmd *DaemonCmd) Run(ctx context.Context, console *Console) error {
	if console.Deps.Daemon == nil {
		return unavailableFault(nil, "this binary cannot run a daemon")
	}
	if cmd.Storage == "sqlite" && !filepath.IsAbs(cmd.SQLitePath) {
		return withRemedy(usageFault("--sqlite-path must be an absolute path; got %q", cmd.SQLitePath),
			"run \"blackbird install\" to write a service definition with an absolute path")
	}
	if err := console.Deps.Daemon.Run(ctx, cmd.options()); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fault(ExitError, err, "daemon")
	}
	return nil
}

func (cmd *DaemonCmd) options() DaemonOptions {
	return DaemonOptions{
		Storage:         cmd.Storage,
		SQLitePath:      cmd.SQLitePath,
		StateDir:        cmd.StateDir,
		HTTPAddress:     cmd.HTTPAddress,
		MCPAddress:      cmd.MCPAddress,
		LogLevel:        cmd.LogLevel,
		ShutdownTimeout: cmd.ShutdownTimeout,
	}
}
