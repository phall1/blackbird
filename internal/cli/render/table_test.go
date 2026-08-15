package render

import (
	"strings"
	"testing"
)

func renderTable(style Style, table Table) string {
	writer := &lineWriter{}
	tableBlock{table: table}.write(writer, style)
	return strings.Join(writer.lines, "\n")
}

func TestTableNaturalLayoutGolden(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{
			{Title: "agent"},
			{Title: "project"},
			{Title: "unread", Align: AlignRight},
		},
		Rows: []Row{
			TextRow("planner", "blackbird", "12"),
			TextRow("reviewer", "blackbird", "3"),
			TextRow("scribe", "dotfiles", "0"),
		},
	}
	want := "" +
		"AGENT     PROJECT    UNREAD\n" +
		"planner   blackbird      12\n" +
		"reviewer  blackbird       3\n" +
		"scribe    dotfiles        0"
	if got := renderTable(PlainStyle(80), table); got != want {
		t.Fatalf("table =\n%s\nwant\n%s", got, want)
	}
}

func TestTableShrinksHighestPriorityColumnFirst(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{
			{Title: "id"},
			{Title: "summary", Priority: 2},
			{Title: "owner", Priority: 1},
		},
		Rows: []Row{TextRow("run-1", "a long summary of the run in progress", "planner")},
	}
	got := renderTable(PlainStyle(30), table)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("table has %d lines:\n%s", len(lines), got)
	}
	for _, line := range lines {
		if DisplayWidth(line) > 30 {
			t.Fatalf("line %q is %d columns", line, DisplayWidth(line))
		}
	}
	if !strings.Contains(lines[1], "run-1") {
		t.Fatalf("priority-0 column lost characters:\n%s", got)
	}
	if !strings.Contains(lines[1], "...") {
		t.Fatalf("no column was truncated:\n%s", got)
	}
	if !strings.Contains(lines[1], "planner") && !strings.Contains(lines[1], "plan") {
		t.Fatalf("owner column vanished:\n%s", got)
	}
}

func TestTableNeverShrinksBelowMinWidth(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{
			{Title: "alpha", MinWidth: 5, Priority: 1},
			{Title: "beta", MinWidth: 4, Priority: 1},
			{Title: "gamma", MinWidth: 5, Priority: 1},
		},
		Rows: []Row{TextRow("aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc")},
	}
	got := renderTable(PlainStyle(20), table)
	body := strings.Split(got, "\n")[1]
	if DisplayWidth(body) > 20 {
		t.Fatalf("row %q is %d columns, want at most 20", body, DisplayWidth(body))
	}
	parts := strings.Split(body, "  ")
	if len(parts) != 3 {
		t.Fatalf("row collapsed to %d columns: %q", len(parts), body)
	}
	for index, floor := range [...]int{5, 4, 5} {
		if DisplayWidth(parts[index]) < floor {
			t.Fatalf("column %d fell below its floor of %d: %q", index, floor, body)
		}
	}
}

func TestTableRightAlignedNumericsSurviveShrink(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{
			{Title: "description", Priority: 3},
			{Title: "bytes", Align: AlignRight},
		},
		Rows: []Row{TextRow("a description that is far too long to fit", "1048576")},
	}
	got := renderTable(PlainStyle(40), table)
	if !strings.HasSuffix(got, "1048576") {
		t.Fatalf("numeric column shrank:\n%s", got)
	}
}

func TestTableRightAlignedTruncationKeepsTail(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{{Title: "n", Align: AlignRight, MinWidth: 5, Priority: 1}},
		Rows:    []Row{TextRow("1234567890")},
	}
	got := renderTable(PlainStyle(5), table)
	if want := "    N\n...90"; got != want {
		t.Fatalf("table =\n%s\nwant\n%s", got, want)
	}
}

func TestTableOverflowTruncatesLastColumn(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{{Title: "alpha"}, {Title: "beta"}},
		Rows:    []Row{TextRow("aaaaaaaa", "bbbbbbbb")},
	}
	got := renderTable(PlainStyle(8), table)
	for _, line := range strings.Split(got, "\n") {
		if DisplayWidth(line) > 8 {
			t.Fatalf("line %q is %d columns, want at most 8", line, DisplayWidth(line))
		}
	}
}

func TestTableEmptyMessage(t *testing.T) {
	t.Parallel()

	withMessage := Table{
		Columns: []Column{{Title: "run"}, {Title: "state"}},
		Empty:   "no runs",
	}
	if got, want := renderTable(PlainStyle(40), withMessage), "RUN  STATE\nno runs"; got != want {
		t.Fatalf("table =\n%s\nwant\n%s", got, want)
	}

	withMessage.Empty = ""
	if got, want := renderTable(PlainStyle(40), withMessage), "RUN  STATE"; got != want {
		t.Fatalf("table =\n%s\nwant\n%s", got, want)
	}

	columnless := Table{Empty: "nothing here"}
	if got, want := renderTable(PlainStyle(40), columnless), "nothing here"; got != want {
		t.Fatalf("table = %q, want %q", got, want)
	}
	if got := renderTable(PlainStyle(40), Table{}); got != "" {
		t.Fatalf("empty table = %q, want empty", got)
	}
}

func TestTableIndentAndShortRows(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{{Title: "a"}, {Title: "b"}},
		Rows:    []Row{{Cells: []Cell{{Text: "only"}}}},
		Indent:  2,
	}
	want := "  A     B\n  only"
	if got := renderTable(PlainStyle(40), table); got != want {
		t.Fatalf("table =\n%s\nwant\n%s", got, want)
	}
}

func TestTableStyledAndPlainHaveIdenticalGeometry(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{
			{Title: "agent", Role: RoleAccent},
			{Title: "state"},
			{Title: "count", Align: AlignRight, Role: RoleMuted},
		},
		Rows: []Row{
			{Cells: []Cell{{Text: "planner"}, {Text: "active", Role: RoleOK}, {Text: "12"}}},
			TextRow("scribe", "idle", "0"),
		},
	}
	styled := renderTable(NewStyle(Capabilities{Color: true, Width: 40}), table)
	plain := renderTable(PlainStyle(40), table)
	if !strings.Contains(styled, esc(RoleOK)) || !strings.Contains(styled, esc(RoleAccent)) {
		t.Fatalf("styled table carries no roles:\n%s", visible(styled))
	}

	var stripped []string
	for _, line := range strings.Split(styled, "\n") {
		stripped = append(stripped, strings.TrimRight(stripANSI(line), " "))
	}
	if got := strings.Join(stripped, "\n"); got != plain {
		t.Fatalf("styled geometry =\n%s\nwant\n%s", got, plain)
	}
}

func TestTableEmitsNoTrailingWhitespace(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{{Title: "wide-column-title"}, {Title: "b"}},
		Rows:    []Row{TextRow("x", "y"), TextRow("", "")},
	}
	for _, style := range [...]Style{PlainStyle(80), NewStyle(Capabilities{Color: true, Width: 80})} {
		for _, line := range strings.Split(renderTable(style, table), "\n") {
			if line != strings.TrimRight(line, " ") {
				t.Fatalf("line %q has trailing whitespace", visible(line))
			}
		}
	}
}

func TestTableWideRunesAlign(t *testing.T) {
	t.Parallel()

	table := Table{
		Columns: []Column{{Title: "name"}, {Title: "state"}},
		Rows: []Row{
			TextRow("\u65e5\u672c", "active"),
			TextRow("abcd", "idle"),
		},
	}
	lines := strings.Split(renderTable(NewStyle(Capabilities{Unicode: true, Width: 40}), table), "\n")
	if len(lines) != 3 {
		t.Fatalf("table has %d lines", len(lines))
	}
	first := strings.Index(lines[1], "active")
	second := strings.Index(lines[2], "idle")
	if DisplayWidth(lines[1][:first]) != DisplayWidth(lines[2][:second]) {
		t.Fatalf("wide and narrow rows disagree on the state column:\n%s", strings.Join(lines, "\n"))
	}
}
