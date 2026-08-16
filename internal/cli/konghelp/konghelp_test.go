package konghelp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alecthomas/kong"

	"github.com/phall1/blackbird/internal/cli/render"
)

type miniature struct {
	JSON    bool   `help:"Emit JSON."`
	Color   string `enum:"auto,never" default:"auto" env:"MINI_COLOR" help:"Colorize output."`
	Secret  string `hidden:"" help:"Not for humans."`
	Verbose int    `short:"v" type:"counter" help:"Increase detail."`

	Show   showCmd   `cmd:"" group:"inspect" help:"Show one thing."`
	Hidden hiddenCmd `cmd:"" hidden:"" help:"Not for humans."`
	Plain  plainCmd  `cmd:"" help:"Ungrouped command."`
}

type showCmd struct {
	Thing string `arg:"" help:"Thing to show."`
	Limit int    `default:"25" help:"Maximum rows."`
}

type hiddenCmd struct{}

type plainCmd struct{}

func parse(t *testing.T, args ...string) (*kong.Context, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	parser, err := kong.New(&miniature{},
		kong.Name("mini"),
		kong.Description("A miniature grammar."),
		kong.Writers(&out, &out),
		kong.Exit(func(int) {}),
		kong.Groups{"inspect": "Inspect"},
	)
	if err != nil {
		t.Fatalf("kong.New() = %v", err)
	}
	ctx, err := parser.Parse(args)
	if err != nil {
		t.Fatalf("Parse(%v) = %v", args, err)
	}
	return ctx, &out
}

func TestDocumentDescribesTheApplication(t *testing.T) {
	t.Parallel()

	ctx, _ := parse(t, "plain")
	doc := Document(kong.HelpOptions{}, ctx, "footer text")
	root := Document(kong.HelpOptions{}, contextForRoot(t), "footer text")
	if root.Summary != "A miniature grammar." {
		t.Fatalf("summary = %q", root.Summary)
	}
	if root.Footer != "footer text" {
		t.Fatalf("footer = %q", root.Footer)
	}
	if !strings.HasPrefix(root.Usage, "mini") || !strings.Contains(root.Usage, "<command>") {
		t.Fatalf("usage = %q", root.Usage)
	}
	if doc.Footer != "" {
		t.Fatalf("a subcommand carries the root footer: %q", doc.Footer)
	}
}

func contextForRoot(t *testing.T) *kong.Context {
	t.Helper()
	var out bytes.Buffer
	parser, err := kong.New(&miniature{},
		kong.Name("mini"),
		kong.Description("A miniature grammar."),
		kong.Writers(&out, &out),
		kong.Exit(func(int) {}),
		kong.Groups{"inspect": "Inspect"},
	)
	if err != nil {
		t.Fatalf("kong.New() = %v", err)
	}
	ctx, err := kong.Trace(parser, nil)
	if err != nil {
		t.Fatalf("Trace() = %v", err)
	}
	return ctx
}

func TestDocumentGroupsCommandsAndHidesInternalNodes(t *testing.T) {
	t.Parallel()

	doc := Document(kong.HelpOptions{}, contextForRoot(t), "")
	titles := map[string][]string{}
	for _, section := range doc.Sections {
		for _, item := range section.Items {
			titles[section.Title] = append(titles[section.Title], item.Term)
		}
	}
	if len(titles["Inspect"]) != 1 || titles["Inspect"][0] != "show" {
		t.Fatalf("inspect section = %v", titles["Inspect"])
	}
	if len(titles["Commands"]) != 1 || titles["Commands"][0] != "plain" {
		t.Fatalf("commands section = %v", titles["Commands"])
	}
	for _, terms := range titles {
		for _, term := range terms {
			if strings.Contains(term, "hidden") || strings.Contains(term, "secret") {
				t.Fatalf("hidden node %q reached the help document", term)
			}
		}
	}
}

func TestFlagTermsCarryDefaultsAndEnvironmentSeparately(t *testing.T) {
	t.Parallel()

	doc := Document(kong.HelpOptions{}, contextForRoot(t), "")
	flags := map[string]render.HelpItem{}
	for _, section := range doc.Sections {
		if section.Title != "Flags" {
			continue
		}
		for _, item := range section.Items {
			flags[item.Term] = item
		}
	}

	color, ok := flags["--color=auto|never"]
	if !ok {
		t.Fatalf("flags = %v, want an enum placeholder", flags)
	}
	if color.Default != "auto" {
		t.Fatalf("default = %q, want auto", color.Default)
	}
	if strings.Contains(color.Help, "default") || strings.Contains(color.Help, "MINI_COLOR") {
		t.Fatalf("help = %q, want no folded suffixes", color.Help)
	}
	if len(color.Envs) != 1 || color.Envs[0] != "MINI_COLOR" {
		t.Fatalf("envs = %v", color.Envs)
	}
	if _, ok := flags["-v, --verbose"]; !ok {
		t.Fatalf("flags = %v, want a counter without a placeholder", flags)
	}
	if _, ok := flags["--json"]; !ok {
		t.Fatalf("flags = %v, want a boolean without a placeholder", flags)
	}
}

func TestSubcommandDocumentCarriesArguments(t *testing.T) {
	t.Parallel()

	ctx, _ := parse(t, "show", "widget")
	doc := Document(kong.HelpOptions{}, ctx, "")
	var arguments []string
	for _, section := range doc.Sections {
		if section.Title == "Arguments" {
			for _, item := range section.Items {
				arguments = append(arguments, item.Term)
			}
		}
	}
	if len(arguments) != 1 || arguments[0] != "<thing>" {
		t.Fatalf("arguments = %v", arguments)
	}
	if !strings.Contains(doc.Usage, "mini show <thing>") {
		t.Fatalf("usage = %q", doc.Usage)
	}
}

func TestValueFormatterOverridesHelpText(t *testing.T) {
	t.Parallel()

	options := kong.HelpOptions{ValueFormatter: func(*kong.Value) string { return "formatted" }}
	doc := Document(options, contextForRoot(t), "")
	for _, section := range doc.Sections {
		if section.Title != "Flags" {
			continue
		}
		for _, item := range section.Items {
			if item.Help != "formatted" {
				t.Fatalf("help = %q, want the formatter's output", item.Help)
			}
		}
	}
}

func TestPrinterWritesThroughTheParserWriters(t *testing.T) {
	t.Parallel()

	ctx, out := parse(t, "plain")
	if err := Printer(render.PlainStyle(80), "footer")(kong.HelpOptions{}, ctx); err != nil {
		t.Fatalf("Printer() = %v", err)
	}
	if !strings.Contains(out.String(), "Usage: mini plain") {
		t.Fatalf("out = %q", out.String())
	}
}

func TestDefaultOfIgnoresFalseAndEmpty(t *testing.T) {
	t.Parallel()

	if got := defaultOf(nil); got != "" {
		t.Fatalf("defaultOf(nil) = %q", got)
	}
	if got := defaultOf(&kong.Value{HasDefault: true, Default: "false"}); got != "" {
		t.Fatalf("defaultOf(false) = %q", got)
	}
	if got := defaultOf(&kong.Value{HasDefault: true, Default: "25"}); got != "25" {
		t.Fatalf("defaultOf(25) = %q", got)
	}
}
