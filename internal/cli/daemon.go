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
	Storage         string        `enum:"sqlite" default:"${daemon_storage}" help:"Durable storage backend."`
	SQLitePath      string        `name:"sqlite-path" placeholder:"PATH" default:"${daemon_sqlite_path}" help:"Absolute path to the SQLite database."`
	StateDir        string        `name:"state-dir" placeholder:"PATH" default:"${daemon_state_dir}" help:"Directory holding the daemon handshake record."`
	HTTPAddress     string        `name:"http-address" placeholder:"HOST:PORT" default:"${daemon_http_address}" help:"HTTP listen address."`
	MCPAddress      string        `name:"mcp-address" placeholder:"HOST:PORT" default:"${daemon_mcp_address}" help:"MCP listen address."`
	LogLevel        string        `name:"log-level" enum:",debug,info,warn,error" default:"${daemon_log_level}" help:"Structured log severity."`
	ShutdownTimeout time.Duration `default:"${daemon_shutdown_timeout}" help:"Grace period for draining ingress on shutdown."`
	// Peering is off unless an operator asks for it, here, by name. A
	// local-first daemon that started listening on a network because someone
	// upgraded it would have broken its promise however private that network
	// is, so there is no environment variable and no implicit default: only
	// this flag turns it on.
	Peer bool `name:"peer" help:"Serve the peer-reachable routes on this machine's tailnet address. Off unless given."`
	// PeerAddress must name one of this machine's own tailnet addresses; the
	// daemon refuses any other, so it cannot be pointed at a wider interface.
	PeerAddress string `name:"peer-address" placeholder:"HOST:PORT" help:"Tailnet address for the peer listener. Defaults to this machine's tailnet address on the HTTP port."`
	// PeerAllow has no wildcard on purpose. "Every node in the tailnet" is a
	// decision worth one line per machine.
	//
	// The stable node id is the form to prefer, and the difference is not
	// cosmetic: a machine name is derived from a hostname the named node's own
	// owner chooses, while a stable id is assigned by the control plane and
	// survives a rename. Tailscale prevents duplicate names within a tailnet,
	// so a live collision cannot be manufactured today -- but "unforgeable" and
	// "the coordinator currently deduplicates" are different guarantees and
	// only one of them is this daemon's to rely on. Names stay supported
	// because they are what an operator reads off `tailscale status`.
	PeerAllow []string `name:"peer-allow" placeholder:"NAME" help:"Peer admitted by tailnet stable node id (preferred: control-plane assigned, survives a rename) or machine name. Repeatable, and required with --peer."`
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
	if !filepath.IsAbs(cmd.SQLitePath) {
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
		PeerEnabled:     cmd.Peer,
		PeerAddress:     cmd.PeerAddress,
		PeerAllowed:     cmd.PeerAllow,
	}
}
