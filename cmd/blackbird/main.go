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

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}

func runMain(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return execute(ctx, args, stdout, stderr)
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("blackbird", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	showVersion := flags.Bool("version", false, "print build identity and exit")
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

	daemon := blackbirdruntime.New(blackbirdruntime.BuildInfo{
		Version: version,
		Commit:  commit,
		BuiltAt: builtAt,
	})
	if *showVersion {
		info := daemon.BuildInfo()
		if err := writef(stdout, "blackbird version=%s commit=%s built_at=%s\n", info.Version, info.Commit, info.BuiltAt); err != nil {
			return exitError
		}
		return exitOK
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
