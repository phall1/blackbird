package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

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
			return blackbirdruntime.NewDaemon(build, config, blackbirdruntime.Dependencies{})
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

func writef(output io.Writer, format string, args ...any) error {
	_, err := fmt.Fprintf(output, format, args...)
	return err
}
