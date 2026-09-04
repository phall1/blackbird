// Package cli owns Blackbird's command grammar, help copy, and exit contract.
// It declares the ports its commands need and never assembles storage or
// transport: cmd/blackbird builds the adapters and binds them into the parser.
package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/alecthomas/kong"

	"github.com/phall1/blackbird/internal/cli/konghelp"
	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/install"
)

const (
	programName        = "blackbird"
	daemonCommandName  = "daemon"
	versionCommandName = "version"

	// defaultHTTPAddress is where the installed service listens unless it was
	// started elsewhere. It is the address the CLI falls back to when no
	// injected default names one.
	defaultHTTPAddress = "127.0.0.1:8080"

	description = "Blackbird coordinates durable multi-agent work on this machine."
	footer      = `Run "blackbird help <command>" for detail on one command.`
)

// CLI is the whole command grammar. Group structs and the root itself define no
// Run method: Kong walks from the selected leaf to the root and invokes Run on
// every node that has one, so a method here would fire on every subcommand.
type CLI struct {
	Globals

	Daemon DaemonCmd `cmd:"" group:"operate" help:"Run the coordination service in the foreground."`
	Status StatusCmd `cmd:"" group:"operate" help:"Report service, daemon, and database state."`
	Doctor DoctorCmd `cmd:"" group:"operate" help:"Diagnose the installation and print remedies."`
	GC     GCCmd     `cmd:"" name:"gc" group:"operate" help:"Report reclaimable database space."`
	Logs   LogsCmd   `cmd:"" group:"operate" help:"Show daemon logs."`
	Hook   HookCmd   `cmd:"" group:"operate" help:"Deliver queued mail through a supported agent hook."`

	LeaseGuard LeaseGuardCmd `cmd:"" name:"lease-guard" group:"operate" help:"Check staged paths against other agents' exclusive reservations. Advisory: a local opt-in commit check, not file locking."`

	SupportBundle SupportBundleCmd `cmd:"" name:"support-bundle" group:"operate" aliases:"support" help:"Collect a redacted diagnostic bundle to attach to a bug report."`

	Overview     OverviewCmd     `cmd:"" group:"inspect" help:"Summarize projects, agents, mail, and reservations."`
	Projects     ProjectsCmd     `cmd:"" group:"inspect" aliases:"project" help:"Inspect registered projects."`
	Agents       AgentsCmd       `cmd:"" group:"inspect" aliases:"agent" help:"Inspect registered agents."`
	Inbox        InboxCmd        `cmd:"" group:"inspect" help:"Show an agent's unread and unacknowledged mail."`
	Threads      ThreadsCmd      `cmd:"" group:"inspect" aliases:"thread" help:"Inspect conversations."`
	Reservations ReservationsCmd `cmd:"" group:"inspect" aliases:"reservation,leases,lease" help:"Inspect file reservations."`
	Events       EventsCmd       `cmd:"" group:"inspect" aliases:"event,journal" help:"Read the coordination event journal."`
	Cost         CostCmd         `cmd:"" group:"inspect" help:"Report what contention and abandoned leases cost, beside the tokens spent alongside them."`
	Outbox       OutboxCmd       `cmd:"" group:"inspect" help:"Show cross-host mail this daemon is still holding, and why."`

	Install   InstallCmd   `cmd:"" group:"manage" help:"Install the per-user service, updater, and MCP client entries."`
	Update    UpdateCmd    `cmd:"" group:"manage" help:"Upgrade Blackbird through Homebrew and converge the service."`
	Uninstall UninstallCmd `cmd:"" group:"manage" help:"Stop and remove the service and updater. Data is retained."`
	Backup    BackupCmd    `cmd:"" group:"manage" help:"Take a verified online snapshot of the database."`
	Restore   RestoreCmd   `cmd:"" group:"manage" help:"Rebuild a database from a verified snapshot. Requires a stopped daemon."`

	Completion CompletionCmd `cmd:"" group:"shell" help:"Print a shell completion script."`
	Version    VersionCmd    `cmd:"" group:"shell" help:"Print build identity."`
	Help       HelpCmd       `cmd:"" group:"shell" help:"Show help for a command."`
}

type exitStatus int

var legacyDaemonFlags = map[string]bool{
	"storage": true, "sqlite-path": true, "http-address": true, "mcp-address": true,
}

const legacyDaemonNotice = "blackbird: starting the daemon without the \"daemon\" command is deprecated; " +
	"run \"blackbird install\" to update the service definition"

// Normalize adapts pre-0.4 invocations to the command grammar and returns the
// argv to parse plus the deprecation notice to print, if any. The installed
// launchd plist runs "blackbird --sqlite-path=..." with no subcommand and
// Homebrew replaces the binary before anything can rewrite that file, so an
// upgraded binary that rejected this argv would crash-loop every machine.
func Normalize(args []string) ([]string, string) {
	if len(args) == 0 {
		return nil, ""
	}
	if index := versionFlagIndex(args); index >= 0 {
		rewritten := make([]string, 0, len(args))
		rewritten = append(rewritten, versionCommandName)
		rewritten = append(rewritten, args[:index]...)
		return append(rewritten, args[index+1:]...), ""
	}
	name, ok := legacyFlagName(args[0])
	if !ok || !legacyDaemonFlags[name] {
		return args, ""
	}
	rewritten := make([]string, 0, len(args)+1)
	rewritten = append(rewritten, daemonCommandName)
	return append(rewritten, args...), legacyDaemonNotice
}

func legacyFlagName(argument string) (string, bool) {
	if !strings.HasPrefix(argument, "-") || argument == "-" || argument == "--" {
		return "", false
	}
	name := strings.TrimLeft(argument, "-")
	name, _, _ = strings.Cut(name, "=")
	if name == "" {
		return "", false
	}
	return name, true
}

// versionFlagIndex finds --version among the leading flags. Kong cannot serve a
// root flag with no command selected, so the flag is rewritten to the version
// command, which also guarantees --json is resolved before the payload renders.
func versionFlagIndex(args []string) int {
	for index, argument := range args {
		if argument == "--" || !strings.HasPrefix(argument, "-") {
			return -1
		}
		if argument == "--version" {
			return index
		}
	}
	return -1
}

// Run parses args and executes the selected command. It is the only exit-code
// authority in the binary: cmd/blackbird passes its return value to os.Exit.
func Run(ctx context.Context, deps Dependencies, args []string, stdout, stderr io.Writer) (code int) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		status, ok := recovered.(exitStatus)
		if !ok {
			panic(recovered)
		}
		code = int(status)
	}()

	preflight := scanPreflight(args, deps.Env)
	console := &Console{Deps: deps, Out: stdout, Err: stderr, Style: preflight.style(deps)}

	normalized, notice := Normalize(args)
	if len(normalized) == 0 {
		normalized = []string{"--help"}
	}
	if notice != "" {
		if _, err := io.WriteString(stderr, notice+"\n"); err != nil {
			return ExitError
		}
	}

	grammar := CLI{}
	parser, err := newParser(ctx, &grammar, console)
	if err != nil {
		return report(console, preflight, fault(ExitError, err, "build command grammar"))
	}

	parseCtx, err := parser.Parse(normalized)
	if err != nil {
		return report(console, preflight, err)
	}

	console.Globals = &grammar.Globals
	console.Style = consoleStyle(console.Globals, deps)
	applyAddress(deps.Admin, grammar.Address)
	if grammar.Globals.Version {
		if err := presentBuild(console); err != nil {
			return report(console, preflight, err)
		}
		return ExitOK
	}
	if ctx.Err() != nil {
		return ExitOK
	}

	if err := parseCtx.Run(); err != nil {
		if errors.Is(err, context.Canceled) {
			return ExitOK
		}
		return report(console, preflight, err)
	}
	return ExitOK
}

func newParser(ctx context.Context, grammar *CLI, console *Console) (*kong.Kong, error) {
	options := []kong.Option{
		kong.Name(programName),
		kong.Description(description),
		kong.Writers(console.Out, console.Err),
		kong.Exit(func(status int) { panic(exitStatus(status)) }),
		kong.Help(konghelp.Printer(console.Style, footer)),
		kong.ValueFormatter(func(value *kong.Value) string { return value.Help }),
		kong.Groups{
			"operate": "Operate",
			"inspect": "Inspect",
			"manage":  "Manage",
			"shell":   "Shell",
		},
		kong.Vars(grammarVars(console.Deps)),
		kong.Bind(console),
		kong.BindTo(ctx, (*context.Context)(nil)),
	}

	parser, err := kong.New(grammar, options...)
	if err != nil {
		return nil, err
	}
	return parser, nil
}

func grammarVars(deps Dependencies) map[string]string {
	defaults := deps.Defaults
	if defaults.Storage == "" {
		defaults.Storage = "sqlite"
	}
	if defaults.HTTPAddress == "" {
		defaults.HTTPAddress = defaultHTTPAddress
	}
	if defaults.MCPAddress == "" {
		defaults.MCPAddress = install.MCPAddress
	}
	if defaults.ShutdownTimeout <= 0 {
		defaults.ShutdownTimeout = 30 * time.Second
	}
	database := deps.DatabasePath
	if database == "" {
		database = defaultDatabasePath(deps.Env)
	}
	if defaults.SQLitePath == "" {
		defaults.SQLitePath = database
	}

	return map[string]string{
		"db_default":              database,
		"address_default":         defaults.HTTPAddress,
		"hook_api_default":        defaultHookAPIURL,
		"daemon_storage":          defaults.Storage,
		"daemon_sqlite_path":      defaults.SQLitePath,
		"daemon_state_dir":        defaults.StateDir,
		"daemon_http_address":     defaults.HTTPAddress,
		"daemon_mcp_address":      defaults.MCPAddress,
		"daemon_log_level":        defaults.LogLevel,
		"daemon_shutdown_timeout": defaults.ShutdownTimeout.String(),
		"version":                 deps.Build.Version,
	}
}

// preflight is what can be known about the output style before parsing, which
// is when Kong may already have to print help or a usage error.
type preflight struct {
	json    bool
	ascii   bool
	noColor bool
	never   bool
	always  bool
}

func scanPreflight(args []string, lookup render.Env) preflight {
	scanned := preflight{}
	for _, argument := range args {
		switch argument {
		case "--json":
			scanned.json = true
		case "--ascii":
			scanned.ascii = true
		case "--no-color":
			scanned.noColor = true
		case "--color=never":
			scanned.never = true
		case "--color=always":
			scanned.always = true
		}
	}
	if lookup != nil {
		if value, ok := lookup("BLACKBIRD_JSON"); ok && value != "" && value != "0" && value != "false" {
			scanned.json = true
		}
	}
	return scanned
}

func (scanned preflight) style(deps Dependencies) render.Style {
	choice := render.ColorAuto
	switch {
	case scanned.noColor || scanned.never:
		choice = render.ColorNever
	case scanned.always:
		choice = render.ColorAlways
	}
	return render.NewStyle(render.Detect(render.Options{
		Device:     deps.Device,
		Env:        deps.Env,
		Color:      choice,
		ASCII:      scanned.ascii,
		WidthProbe: deps.WidthProbe,
	}))
}

func consoleStyle(globals *Globals, deps Dependencies) render.Style {
	return render.NewStyle(render.Detect(render.Options{
		Device:     deps.Device,
		Env:        deps.Env,
		Color:      globals.colorChoice(),
		ASCII:      globals.ASCII,
		Width:      globals.Width,
		WidthProbe: deps.WidthProbe,
	}))
}

// report writes a failure in the requested form and returns its exit code.
// Failures always go to stderr so that a --json success payload piped into a
// parser is never mixed with an error document.
func report(console *Console, scanned preflight, err error) int {
	code := exitCodeFor(err)
	asJSON := scanned.json
	if console.Globals != nil {
		asJSON = console.Globals.JSON
	}
	if asJSON {
		target := render.Target{Out: console.Err, Style: console.Style, JSON: true}
		if writeErr := render.Present(target, newView(newErrorEnvelope(err, code), drawErrorEnvelope)); writeErr != nil {
			return ExitError
		}
		return code
	}

	message := programName + ": " + err.Error() + "\n"
	var carried *FaultError
	if errors.As(err, &carried) && carried.Remedy != "" {
		message += "  remedy: " + carried.Remedy + "\n"
	}
	if code == ExitUsage {
		message += `Run "` + programName + ` --help" for usage.` + "\n"
	}
	if _, writeErr := io.WriteString(console.Err, message); writeErr != nil {
		return ExitError
	}
	return code
}
