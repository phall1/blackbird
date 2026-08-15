package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/phall1/blackbird/internal/cli/render"
)

// LogsCmd shows what the daemon wrote. It is the first command a user reaches
// for when the service is crash-looping, so it must work with no daemon, no
// database, and no credential.
type LogsCmd struct {
	Follow bool   `short:"f" help:"Stream new lines until interrupted."`
	Lines  int    `short:"n" default:"50" help:"Number of trailing lines to show, counted across every selected stream."`
	Stream string `enum:"out,err,both" default:"both" help:"Which daemon stream to read."`
}

type logsReport struct {
	Stream string    `json:"stream"`
	Lines  []LogLine `json:"lines"`
}

func (cmd *LogsCmd) Run(ctx context.Context, console *Console) error {
	source, err := console.logs()
	if err != nil {
		return err
	}
	if cmd.Follow && console.Globals.JSON {
		return usageFault("--follow cannot be combined with --json")
	}
	lines, err := limitOf("--lines", cmd.Lines)
	if err != nil {
		return err
	}

	report := logsReport{Stream: cmd.Stream}
	emit := func(line LogLine) error {
		report.Lines = append(report.Lines, line)
		return nil
	}
	if cmd.Follow {
		emit = func(line LogLine) error {
			if _, err := io.WriteString(console.Out, line.Text+"\n"); err != nil {
				return fmt.Errorf("write log line: %w", err)
			}
			return nil
		}
	}

	err = source.Tail(ctx, LogRequest{Stream: cmd.Stream, Lines: lines, Follow: cmd.Follow}, emit)
	switch {
	case errors.Is(err, context.Canceled):
		return nil
	case err != nil:
		return withRemedy(unavailableFault(err, "read daemon logs"),
			"run \"blackbird install\" to create the state directory")
	}
	if cmd.Follow {
		return nil
	}
	return console.present(newView(report, drawLogs))
}

func drawLogs(doc *render.Document, report logsReport) {
	if len(report.Lines) == 0 {
		doc.Line(render.RoleMuted, "No log lines yet.")
		return
	}
	for _, line := range report.Lines {
		doc.Line(logRole(line.Stream), line.Text)
	}
}

func logRole(stream string) render.Role {
	if stream == "err" {
		return render.RoleError
	}
	return render.RolePlain
}
