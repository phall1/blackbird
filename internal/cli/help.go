package cli

import (
	"github.com/alecthomas/kong"
)

// HelpCmd shows help for a command path. It traces the requested path and
// prints the same document --help prints, without going through the help flag's
// exit hook.
type HelpCmd struct {
	Command []string `arg:"" optional:"" placeholder:"COMMAND" help:"Command path to describe."`
}

func (cmd *HelpCmd) Run(parseCtx *kong.Context) error {
	traced, err := kong.Trace(parseCtx.Kong, cmd.Command)
	if err != nil {
		return usageFault("%v", err)
	}
	if traced.Error != nil {
		return usageFault("%v", traced.Error)
	}
	if err := traced.PrintUsage(false); err != nil {
		return fault(ExitError, err, "print help")
	}
	return nil
}
