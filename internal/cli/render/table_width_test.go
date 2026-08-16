package render

import (
	"fmt"
	"strings"
	"testing"
)

// commandTables mirrors every table shape the command layer builds, with rows
// the size the live database actually holds: absolute project keys, RFC 3339
// stamps, and space-joined selector paths. A shape that fits only because its
// fixture is short proves nothing.
func commandTables() []struct {
	name  string
	table Table
} {
	return []struct {
		name  string
		table Table
	}{
		{
			name: "projects",
			table: Table{
				Columns: []Column{
					{Title: "PROJECT"},
					{Title: "AGENTS", Align: AlignRight},
					{Title: "ACTIVE", Align: AlignRight},
					{Title: "THREADS", Align: AlignRight},
					{Title: "WORKSPACE", Role: RoleMuted},
				},
				Empty: "No projects are registered yet.",
				Rows: []Row{
					TextRow("/Users/phall/workspace/blackbird", "30", "4", "12", "ws_01JQ8H3V6KQ2N7Z0RB4TMC9YXD"),
					TextRow("/Users/phall/dotfiles", "9", "0", "4", "ws_01JQ8H3V6KQ2N7Z0RB4TMC9YXE"),
					TextRow("/Users/phall/workspace/second-brain", "8", "1", "3", ""),
				},
			},
		},
		{
			name: "agents",
			table: Table{
				Columns: []Column{
					{Title: "AGENT"},
					{Title: "PROJECT", Role: RoleMuted},
					{Title: "LIVE"},
					{Title: "UNREAD", Align: AlignRight},
					{Title: "UNACKED", Align: AlignRight},
					{Title: "LEASES", Align: AlignRight},
				},
				Empty: "No agents are registered yet.",
				Rows: []Row{
					TextRow("orchestrator", "/Users/phall/workspace/blackbird", "yes", "12", "3", "2"),
					TextRow("render-surgeon", "/Users/phall/workspace/blackbird", "yes", "0", "0", "1"),
					TextRow("ClaudeCode", "/Users/phall/dotfiles", "no", "17", "3", "0"),
				},
			},
		},
		{
			name: "inbox summaries",
			table: Table{
				Columns: []Column{
					{Title: "AGENT"},
					{Title: "PROJECT", Role: RoleMuted},
					{Title: "UNREAD", Align: AlignRight},
					{Title: "UNACKED", Align: AlignRight},
					{Title: "OLDEST UNREAD", Role: RoleMuted},
				},
				Empty: "No mail is waiting.",
				Rows: []Row{
					TextRow("orchestrator", "/Users/phall/workspace/blackbird", "12", "3", "2026-08-15T14:03:22.481Z"),
					TextRow("ClaudeCode", "/Users/phall/dotfiles", "17", "3", "2026-08-11T09:41:07.002Z"),
				},
			},
		},
		{
			name: "inbox pending",
			table: Table{
				Columns: []Column{
					{Title: "TO"},
					{Title: "FROM"},
					{Title: "SUBJECT"},
					{Title: "STATE"},
					{Title: "SENT", Role: RoleMuted},
				},
				Rows: []Row{
					TextRow("orchestrator", "render-surgeon",
						"tables ignore terminal width and mangle headers", "unread", "3h ago"),
					TextRow("ClaudeCode", "-", "dotfiles pins blackbird release artifacts", "unacknowledged", "4d ago"),
				},
			},
		},
		{
			name: "threads",
			table: Table{
				Columns: []Column{
					{Title: "TOPIC"},
					{Title: "PROJECT", Role: RoleMuted},
					{Title: "STATE"},
					{Title: "MESSAGES", Align: AlignRight},
					{Title: "UNREAD", Align: AlignRight},
					{Title: "LAST", Role: RoleMuted},
				},
				Empty: "No conversations yet.",
				Rows: []Row{
					TextRow("cli overhaul: width, exit codes, and the daemon subcommand",
						"/Users/phall/workspace/blackbird", "open", "14", "9", "2m ago"),
					TextRow("release v0.4.0", "/Users/phall/workspace/blackbird", "open", "6", "0", "3h ago"),
					TextRow("harness delivery in native plugins", "/Users/phall/dotfiles", "closed", "7", "0", "9d ago"),
				},
			},
		},
		{
			name: "reservations",
			table: Table{
				Columns: []Column{
					{Title: "HOLDER"},
					{Title: "MODE"},
					{Title: "STATE"},
					{Title: "EXPIRES"},
					{Title: "PATHS"},
				},
				Empty: "No reservations are held.",
				Rows: []Row{
					TextRow("render-surgeon", "exclusive", "active", "-42m",
						"internal/cli/render/table.go internal/cli/render/width.go internal/cli/render/humanize.go"),
					TextRow("orchestrator", "shared", "expired", "-3h12m", "internal/cli/globals.go"),
				},
			},
		},
		{
			name: "events",
			table: Table{
				Columns: []Column{
					{Title: "POS", Align: AlignRight},
					{Title: "WHEN", Role: RoleMuted},
					{Title: "TYPE"},
					{Title: "AGENT"},
					{Title: "SUBJECT", Role: RoleMuted},
				},
				Empty: "The journal is empty.",
				Rows: []Row{
					TextRow("106", "2m ago", "message.sent", "render-surgeon",
						"tables ignore terminal width and mangle headers"),
					TextRow("105", "3h ago", "reservation.acquired", "orchestrator", "internal/cli/render"),
				},
			},
		},
		{
			name: "single wide column",
			table: Table{
				Columns: []Column{{Title: "SUBJECT"}},
				Rows:    []Row{TextRow("a subject line far longer than any terminal is ever going to be, twice over")},
			},
		},
		{
			name: "all numeric",
			table: Table{
				Columns: []Column{
					{Title: "MESSAGES", Align: AlignRight},
					{Title: "UNREAD", Align: AlignRight},
					{Title: "UNACKED", Align: AlignRight},
					{Title: "LEASES", Align: AlignRight},
					{Title: "EVENTS", Align: AlignRight},
				},
				Rows: []Row{TextRow("27", "29", "6", "41", "106")},
			},
		},
		{
			name: "indented",
			table: Table{
				Columns: []Column{{Title: "PATH"}, {Title: "MODE"}, {Title: "EXPIRES", Align: AlignRight}},
				Rows:    []Row{TextRow("internal/cli/render/table.go", "exclusive", "-42m")},
				Indent:  4,
			},
		},
		{
			name: "wide runes",
			table: Table{
				Columns: []Column{{Title: "AGENT"}, {Title: "SUBJECT"}, {Title: "UNREAD", Align: AlignRight}},
				Rows: []Row{
					TextRow("\u65e5\u672c\u8a9e\u30a8\u30fc\u30b8\u30a7\u30f3\u30c8",
						"\u30e1\u30c3\u30bb\u30fc\u30b8\u306e\u4ef6\u540d\u304c\u3068\u3066\u3082\u9577\u3044", "12"),
					TextRow("planner", "a plain ascii subject", "3"),
				},
			},
		},
	}
}

// TestTableNeverExceedsRequestedWidth is the invariant the release broke: a
// table that no caller configured still has to fit the terminal it is printed
// into. Every shape, every width, every style.
func TestTableNeverExceedsRequestedWidth(t *testing.T) {
	t.Parallel()

	widths := [...]int{1, 5, 10, 20, 40, 60, 80, 120, 160}
	styles := []struct {
		name  string
		build func(int) Style
	}{
		{name: "plain", build: PlainStyle},
		{name: "unicode", build: func(width int) Style {
			return NewStyle(Capabilities{Unicode: true, Width: width})
		}},
		{name: "color", build: func(width int) Style {
			return NewStyle(Capabilities{Color: true, Unicode: true, TTY: true, Width: width})
		}},
	}

	for _, fixture := range commandTables() {
		for _, style := range styles {
			for _, width := range widths {
				t.Run(fmt.Sprintf("%s/%s/%d", fixture.name, style.name, width), func(t *testing.T) {
					t.Parallel()
					for _, line := range strings.Split(renderTable(style.build(width), fixture.table), "\n") {
						if got := DisplayWidth(line); got > width {
							t.Fatalf("at width %d line is %d columns: %q", width, got, visible(line))
						}
					}
				})
			}
		}
	}
}

// TestTableHonoursDistinctWidths pins the reported symptom directly: rendering
// the same table at two widths produced identical output because the shrink
// loop only moved columns a caller had marked, and no caller marked any.
func TestTableHonoursDistinctWidths(t *testing.T) {
	t.Parallel()

	for _, fixture := range commandTables() {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			narrow := widestLine(renderTable(PlainStyle(40), fixture.table))
			wide := widestLine(renderTable(PlainStyle(120), fixture.table))
			if narrow > 40 {
				t.Fatalf("width 40 rendered %d columns", narrow)
			}
			if wide < narrow {
				t.Fatalf("width 120 rendered %d columns, narrower than width 40 at %d", wide, narrow)
			}
		})
	}
}

func widestLine(rendered string) int {
	widest := 0
	for _, line := range strings.Split(rendered, "\n") {
		widest = max(widest, DisplayWidth(line))
	}
	return widest
}

// TestTableHeadingsNeverLoseTheirHead is the mangling half of the defect: the
// last column was hard-chopped, and when that column was right-aligned the
// heading was truncated from the front, so LEASES was printed as ...SES.
func TestTableHeadingsNeverLoseTheirHead(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{
			{Title: "AGENT"},
			{Title: "LEASES", Align: AlignRight},
		},
		Rows: []Row{TextRow("an agent name that consumes the entire line on its own", "41")},
	}
	for _, width := range [...]int{8, 12, 20, 40} {
		heading := strings.Split(renderTable(PlainStyle(width), table), "\n")[0]
		cells := strings.Fields(heading)
		if len(cells) != 2 {
			t.Fatalf("width %d rendered %d headings: %q", width, len(cells), heading)
		}
		for index, title := range [...]string{"AGENT", "LEASES"} {
			shown := strings.TrimSuffix(strings.TrimSuffix(cells[index], "..."), "…")
			if shown == "" || !strings.HasPrefix(title, shown) {
				t.Fatalf("width %d rendered %q for the %s heading, which is not its head", width, cells[index], title)
			}
		}
	}
}

// TestTableHeadingTruncatesRightWhileBodyKeepsTail separates the two rules a
// right-aligned numeric column obeys: the digits that matter are the last ones,
// but the heading that names the column is the first ones.
func TestTableHeadingTruncatesRightWhileBodyKeepsTail(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{{Title: "LEASES", Align: AlignRight, MinWidth: 4, Priority: 1}},
		Rows:    []Row{TextRow("1234567")},
	}
	lines := strings.Split(renderTable(PlainStyle(4), table), "\n")
	if want := "L..."; lines[0] != want {
		t.Fatalf("heading = %q, want %q", lines[0], want)
	}
	if want := "...7"; lines[1] != want {
		t.Fatalf("body = %q, want %q", lines[1], want)
	}
}

// TestTableTextAbsorbsShrinkAndNumericsHold is the allocation rule: prose gives
// up columns, counts do not.
func TestTableTextAbsorbsShrinkAndNumericsHold(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{
			{Title: "TOPIC"},
			{Title: "PROJECT"},
			{Title: "MESSAGES", Align: AlignRight},
			{Title: "UNREAD", Align: AlignRight},
		},
		Rows: []Row{
			TextRow("cli overhaul: width, exit codes, and the daemon subcommand",
				"/Users/phall/workspace/blackbird", "1408", "997"),
		},
	}
	body := strings.Split(renderTable(PlainStyle(60), table), "\n")[1]
	if DisplayWidth(body) > 60 {
		t.Fatalf("row is %d columns: %q", DisplayWidth(body), body)
	}
	if !strings.HasSuffix(body, "997") || !strings.Contains(body, "1408") {
		t.Fatalf("numeric columns lost digits: %q", body)
	}
	if !strings.Contains(body, "...") {
		t.Fatalf("no text column absorbed the shrink: %q", body)
	}
}

// TestTablePinnedColumnsShrinkOnlyAsALastResort proves the ladder: numerics are
// squeezed once no prose is left to give, before any column is dropped.
func TestTablePinnedColumnsShrinkOnlyAsALastResort(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{
			{Title: "MESSAGES", Align: AlignRight},
			{Title: "UNREAD", Align: AlignRight},
			{Title: "UNACKED", Align: AlignRight},
		},
		Rows: []Row{TextRow("1408", "997", "612")},
	}
	lines := strings.Split(renderTable(PlainStyle(20), table), "\n")
	for _, line := range lines {
		if DisplayWidth(line) > 20 {
			t.Fatalf("line %q is %d columns", line, DisplayWidth(line))
		}
	}
	if strings.Count(lines[1], "  ") < 2 {
		t.Fatalf("a column was dropped before the others were squeezed: %q", lines[1])
	}
}

// TestTableDropsTrailingColumnsWhenNothingFits covers the floor of the ladder:
// six columns cannot each hold one character in five, so the tail goes rather
// than the line overflowing.
func TestTableDropsTrailingColumnsWhenNothingFits(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{
			{Title: "AGENT"}, {Title: "PROJECT"}, {Title: "LIVE"},
			{Title: "UNREAD", Align: AlignRight}, {Title: "UNACKED", Align: AlignRight},
			{Title: "LEASES", Align: AlignRight},
		},
		Rows: []Row{TextRow("orchestrator", "/Users/phall/workspace/blackbird", "yes", "12", "3", "2")},
	}
	rendered := renderTable(PlainStyle(5), table)
	for _, line := range strings.Split(rendered, "\n") {
		if DisplayWidth(line) > 5 {
			t.Fatalf("line %q is %d columns", line, DisplayWidth(line))
		}
	}
	if !strings.HasPrefix(rendered, "A") {
		t.Fatalf("the leading column was dropped instead of the trailing ones:\n%s", rendered)
	}
}

// TestTableIndentCountsAgainstTheWidth: an indented table is inset by the
// margin, and the margin is part of the line.
func TestTableIndentCountsAgainstTheWidth(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{{Title: "PATH"}, {Title: "MODE"}},
		Rows:    []Row{TextRow("internal/cli/render/table.go", "exclusive")},
		Indent:  8,
	}
	for _, line := range strings.Split(renderTable(PlainStyle(24), table), "\n") {
		if DisplayWidth(line) > 24 {
			t.Fatalf("line %q is %d columns", line, DisplayWidth(line))
		}
	}
}

// commandTable finds a shape by name so a golden and the invariant sweep read
// the same fixture.
func commandTable(t *testing.T, name string) Table {
	t.Helper()
	for _, fixture := range commandTables() {
		if fixture.name == name {
			return fixture.table
		}
	}
	t.Fatalf("no command table named %q", name)
	return Table{}
}

// TestTableAgentsGolden freezes the shape the release rendered at 89 columns
// into an 80-column terminal, at 80 and at the narrowest width the CLI clamps
// to. Note the LEASES heading at 40: it is L..., never ...SES.
func TestTableAgentsGolden(t *testing.T) {
	t.Parallel()

	agents := commandTable(t, "agents")
	wide := "" +
		"AGENT           PROJECT                           LIVE  UNREAD  UNACKED  LEASES\n" +
		"orchestrator    /Users/phall/workspace/blackbird  yes       12        3       2\n" +
		"render-surgeon  /Users/phall/workspace/blackbird  yes        0        0       1\n" +
		"ClaudeCode      /Users/phall/dotfiles             no        17        3       0"
	if got := renderTable(PlainStyle(80), agents); got != wide {
		t.Fatalf("agents at 80 =\n%s\nwant\n%s", got, wide)
	}

	narrow := "" +
		"AGENT     PROJECT   LIVE  UNR  UNA  L...\n" +
		"orche...  /User...  yes    12    3     2\n" +
		"rende...  /User...  yes     0    0     1\n" +
		"Claud...  /User...  no     17    3     0"
	if got := renderTable(PlainStyle(40), agents); got != narrow {
		t.Fatalf("agents at 40 =\n%s\nwant\n%s", got, narrow)
	}
}

// TestTableThreadsGolden freezes the worst shape in the release: 145 columns,
// wrapping twice in a default terminal, with the counts that carry the meaning
// pushed off the end of the line.
func TestTableThreadsGolden(t *testing.T) {
	t.Parallel()

	threads := commandTable(t, "threads")
	wide := "" +
		"TOPIC                   PROJECT                 STATE   MESSAGES  UNREAD  LAST\n" +
		"cli overhaul: width...  /Users/phall/worksp...  open          14       9  2m ago\n" +
		"release v0.4.0          /Users/phall/worksp...  open           6       0  3h ago\n" +
		"harness delivery in...  /Users/phall/dotfiles   closed         7       0  9d ago"
	if got := renderTable(PlainStyle(80), threads); got != wide {
		t.Fatalf("threads at 80 =\n%s\nwant\n%s", got, wide)
	}

	narrow := "" +
		"TOPIC    PROJECT   STATE   ME  U  LAST\n" +
		"cli ...  /User...  open    14  9  2m ago\n" +
		"rele...  /User...  open     6  0  3h ago\n" +
		"harn...  /User...  closed   7  0  9d ago"
	if got := renderTable(PlainStyle(40), threads); got != narrow {
		t.Fatalf("threads at 40 =\n%s\nwant\n%s", got, narrow)
	}
}
