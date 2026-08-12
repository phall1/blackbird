package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/phall1/blackbird/internal/install"
	blackbirdruntime "github.com/phall1/blackbird/internal/runtime"
)

const (
	exitOK    = 0
	exitUsage = 2
	exitError = 1
)

var (
	version = "dev"
	commit  = "unknown"
	builtAt = "unknown"
)

type daemonRunner interface {
	Run(context.Context) error
}

type daemonFactory func(blackbirdruntime.BuildInfo, blackbirdruntime.Config) (daemonRunner, error)

type productManager interface {
	Install(context.Context) (install.Result, error)
	Status(context.Context) (string, error)
	Update(context.Context) (install.UpdateResult, error)
	Uninstall(context.Context) (install.Result, error)
}

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}

func runMain(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return execute(ctx, args, stdout, stderr)
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return executeConfigured(ctx, args, stdout, stderr, nil, nil)
}

func executeConfigured(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	injected *blackbirdruntime.Config,
	factory daemonFactory,
) int {
	return executeWithManager(ctx, args, stdout, stderr, injected, factory, nil)
}

func executeWithManager(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	injected *blackbirdruntime.Config,
	factory daemonFactory,
	manager productManager,
) int {
	if len(args) > 0 && isProductCommand(args[0]) {
		if len(args) != 1 {
			if err := writef(stderr, "blackbird: %s does not accept arguments\n", args[0]); err != nil {
				return exitError
			}
			return exitUsage
		}
		if manager == nil {
			var err error
			manager, err = install.New()
			if err != nil {
				if writeErr := writef(stderr, "blackbird: %v\n", err); writeErr != nil {
					return exitError
				}
				return exitError
			}
		}
		return executeProductCommand(ctx, args[0], manager, stdout, stderr)
	}

	flags := flag.NewFlagSet("blackbird", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	showVersion := flags.Bool("version", false, "print build identity and exit")
	config := blackbirdruntime.Config{
		Storage: blackbirdruntime.StorageSQLite, SQLitePath: "blackbird.db",
		HTTPAddress: "127.0.0.1:8080", MCPAddress: "127.0.0.1:8081",
	}
	if injected != nil {
		config = *injected
	}
	storage := flags.String("storage", string(config.Storage), "storage backend (sqlite or postgres)")
	flags.StringVar(&config.SQLitePath, "sqlite-path", config.SQLitePath, "SQLite database path")
	flags.StringVar(&config.HTTPAddress, "http-address", config.HTTPAddress, "HTTP listen address")
	flags.StringVar(&config.MCPAddress, "mcp-address", config.MCPAddress, "MCP listen address")
	if err := flags.Parse(args); err != nil {
		if writeErr := writef(stderr, "blackbird: %v\n", err); writeErr != nil {
			return exitError
		}
		return exitUsage
	}
	if flags.NArg() != 0 {
		if err := writef(stderr, "blackbird: unexpected argument %q\n", flags.Arg(0)); err != nil {
			return exitError
		}
		return exitUsage
	}

	build := blackbirdruntime.BuildInfo{
		Version: version,
		Commit:  commit,
		BuiltAt: builtAt,
	}.Normalize()
	if *showVersion {
		if err := writef(stdout, "blackbird version=%s commit=%s built_at=%s\n", build.Version, build.Commit, build.BuiltAt); err != nil {
			return exitError
		}
		return exitOK
	}
	if ctx.Err() != nil {
		return exitOK
	}
	config.Storage = blackbirdruntime.StorageBackend(*storage)
	if factory == nil {
		factory = func(build blackbirdruntime.BuildInfo, config blackbirdruntime.Config) (daemonRunner, error) {
			return blackbirdruntime.NewProductionDaemon(build, config)
		}
	}
	daemon, err := factory(build, config)
	if err != nil {
		if writeErr := writef(stderr, "blackbird: %v\n", err); writeErr != nil {
			return exitError
		}
		return exitError
	}

	if err := daemon.Run(ctx); err != nil {
		if writeErr := writef(stderr, "blackbird: %v\n", err); writeErr != nil {
			return exitError
		}
		return exitError
	}

	return exitOK
}

func isProductCommand(argument string) bool {
	switch argument {
	case "install", "status", "update", "uninstall":
		return true
	default:
		return false
	}
}

func executeProductCommand(ctx context.Context, command string, manager productManager, stdout, stderr io.Writer) int {
	var err error
	switch command {
	case "install":
		var result install.Result
		result, err = manager.Install(ctx)
		if err == nil {
			err = writef(stdout, "installed service=%s companion=%s updater=%s clients=%s\n", result.ServicePath, result.CompanionPath, stringsOrNone(result.UpdaterPaths), stringsOrNone(result.Clients))
		}
	case "status":
		var status string
		status, err = manager.Status(ctx)
		if err == nil {
			err = writef(stdout, "%s\n", status)
		}
	case "update":
		var result install.UpdateResult
		result, err = manager.Update(ctx)
		if err == nil {
			err = writef(stdout, "updated changed=%t before=%q after=%q\n", result.Changed, result.Before, result.After)
		}
	case "uninstall":
		var result install.Result
		result, err = manager.Uninstall(ctx)
		if err == nil {
			err = writef(stdout, "uninstalled service=%s companion=%s updater=%s data=retained\n", result.ServicePath, result.CompanionPath, stringsOrNone(result.UpdaterPaths))
		}
	}
	if err != nil {
		if writeErr := writef(stderr, "blackbird: %v\n", err); writeErr != nil {
			return exitError
		}
		return exitError
	}
	return exitOK
}

func stringsOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	result := values[0]
	for _, value := range values[1:] {
		result += "," + value
	}
	return result
}

func writef(output io.Writer, format string, args ...any) error {
	_, err := fmt.Fprintf(output, format, args...)
	return err
}
