package render

import (
	"bytes"
	"strings"
	"testing"
)

func sampleHelpDoc() HelpDoc {
	return HelpDoc{
		Usage:   "blackbird runs [<run-id>] [flags]",
		Summary: "List and inspect coordinated runs.",
		Detail:  "Runs group the work a set of agents performed against one project.",
		Sections: []HelpSection{
			{Title: "Arguments", Items: []HelpItem{{Term: "<run-id>", Help: "Run to inspect."}}},
			{
				Title:       "Flags",
				Description: "Global flags apply to every subcommand.",
				Items: []HelpItem{
					{Term: "--color=STRING", Help: "Colorize output.", Default: "auto"},
					{Term: "--sqlite-path=PATH", Help: "Database path.", Envs: []string{"BLACKBIRD_SQLITE_PATH"}},
					{Term: "--json", Help: ""},
				},
			},
			{Title: "Hidden", Items: nil},
		},
		Footer: "Run \"blackbird <command> --help\" for more information on a command.",
	}
}

const helpPlainGolden = `Usage: blackbird runs [<run-id>] [flags]

List and inspect coordinated runs.

Runs group the work a set of agents performed against one project.

Arguments
  <run-id>  Run to inspect.

Flags
  Global flags apply to every subcommand.
  --color=STRING      Colorize output. (default: auto)
  --sqlite-path=PATH  Database path. ($BLACKBIRD_SQLITE_PATH)
  --json

Run "blackbird <command> --help" for more information on a command.
`

func TestHelpPlainGolden(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	if err := Help(&buffer, PlainStyle(80), sampleHelpDoc()); err != nil {
		t.Fatalf("Help: %v", err)
	}
	if got := buffer.String(); got != helpPlainGolden {
		t.Fatalf("help =\n%s\nwant\n%s", got, helpPlainGolden)
	}
}

func TestHelpStyledCarriesRoles(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	style := NewStyle(Capabilities{Color: true, Width: 80})
	if err := Help(&buffer, style, sampleHelpDoc()); err != nil {
		t.Fatalf("Help: %v", err)
	}
	got := buffer.String()
	for _, want := range []string{
		esc(RoleHeading) + "Usage: " + ansiReset,
		esc(RoleHeading) + "Flags" + ansiReset,
		esc(RoleAccent) + "--color=STRING" + ansiReset,
		esc(RoleMuted) + " (default: auto)" + ansiReset,
		esc(RoleMuted) + " ($BLACKBIRD_SQLITE_PATH)" + ansiReset,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("help is missing %q:\n%s", visible(want), visible(got))
		}
	}
}

func TestHelpWrapsAtNarrowWidth(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	if err := Help(&buffer, PlainStyle(48), sampleHelpDoc()); err != nil {
		t.Fatalf("Help: %v", err)
	}
	for _, line := range strings.Split(buffer.String(), "\n") {
		if DisplayWidth(line) > 48 {
			t.Fatalf("line %q is %d columns, want at most 48", line, DisplayWidth(line))
		}
	}
}

func TestHelpLongTermSpillsToOwnLine(t *testing.T) {
	t.Parallel()

	doc := HelpDoc{Sections: []HelpSection{{Title: "Flags", Items: []HelpItem{
		{Term: "--an-extremely-long-flag-name-that-overflows=VALUE", Help: "Spills."},
		{Term: "--short", Help: "Fits."},
	}}}}
	var buffer bytes.Buffer
	if err := Help(&buffer, PlainStyle(80), doc); err != nil {
		t.Fatalf("Help: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(buffer.String(), "\n"), "\n")
	if lines[1] != "  --an-extremely-long-flag-name-that-overflows=VALUE" {
		t.Fatalf("long term did not get its own line: %q", lines[1])
	}
	if lines[2] != strings.Repeat(" ", 2+maxTermColumn+2)+"Spills." {
		t.Fatalf("help text is not at the help column: %q", lines[2])
	}
}

func TestHelpOmitsEmptyParts(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	if err := Help(&buffer, PlainStyle(80), HelpDoc{
		Usage:    "blackbird",
		Sections: []HelpSection{{Title: "Empty"}},
	}); err != nil {
		t.Fatalf("Help: %v", err)
	}
	if got, want := buffer.String(), "Usage: blackbird\n"; got != want {
		t.Fatalf("help = %q, want %q", got, want)
	}

	buffer.Reset()
	if err := Help(&buffer, PlainStyle(80), HelpDoc{}); err != nil {
		t.Fatalf("Help: %v", err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("empty HelpDoc rendered %q", buffer.String())
	}
}

func TestHelpRejectsMissingWriterAndWrapsWriteErrors(t *testing.T) {
	t.Parallel()

	if err := Help(nil, PlainStyle(80), sampleHelpDoc()); err != ErrNoOutput {
		t.Fatalf("Help(nil) = %v, want ErrNoOutput", err)
	}
	err := Help(failingWriter{}, PlainStyle(80), sampleHelpDoc())
	if err == nil || !strings.HasPrefix(err.Error(), "render help:") {
		t.Fatalf("Help write error = %v", err)
	}
}

func TestHelpItemsWithMultipleEnvs(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	doc := HelpDoc{Sections: []HelpSection{{Title: "Flags", Items: []HelpItem{
		{Term: "--path", Help: "Path.", Default: "/tmp", Envs: []string{"A", "B"}},
	}}}}
	if err := Help(&buffer, PlainStyle(80), doc); err != nil {
		t.Fatalf("Help: %v", err)
	}
	if got, want := buffer.String(), "Flags\n  --path  Path. (default: /tmp) ($A, $B)\n"; got != want {
		t.Fatalf("help = %q, want %q", got, want)
	}
	if strings.Count(buffer.String(), "/tmp") != 1 {
		t.Fatal("the default was rendered more than once")
	}
}
