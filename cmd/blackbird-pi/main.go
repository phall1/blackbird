package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/phall1/blackbird/internal/companion"
)

var version = "dev"

func main() {
	syscall.Umask(0o077)
	flags := flag.NewFlagSet("blackbird-pi", flag.ExitOnError)
	project := flags.String("project", "", "absolute project directory")
	agent := flags.String("agent", "Pi", "stable Blackbird agent name")
	state := flags.String("state-dir", defaultStateDir(), "private delivery state directory")
	api := flags.String("api", "http://127.0.0.1:8080", "Blackbird local API base URL")
	pi := flags.String("pi", "pi", "Pi executable")
	node := flags.String("node", "", "Node executable for a Pi JavaScript entrypoint")
	showVersion := flags.Bool("version", false, "print version")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "blackbird-pi: %v\n", err)
		os.Exit(2)
	}
	if *showVersion {
		fmt.Printf("blackbird-pi version=%s\n", version)
		return
	}
	executable := *pi
	var prefixArgs []string
	if *node != "" {
		executable = *node
		prefixArgs = []string{*pi}
	}
	worker, err := companion.New(companion.Config{ProjectPath: *project, AgentName: *agent, StateDir: *state, APIBaseURL: *api, Harness: companion.HarnessPi, Executable: executable, PrefixArgs: prefixArgs})
	if err != nil {
		fmt.Fprintf(os.Stderr, "blackbird-pi: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = worker.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("blackbird-pi: serving agent=%q project=%q state=%q\n", *agent, *project, *state)
	if err := worker.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "blackbird-pi: %v\n", err)
		os.Exit(1)
	}
}

func defaultStateDir() string {
	if value := os.Getenv("XDG_STATE_HOME"); value != "" {
		return filepath.Join(value, "blackbird", "pi")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "blackbird", "pi")
}
