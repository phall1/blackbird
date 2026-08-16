package render

import (
	"strings"
	"testing"
)

func renderBlock(style Style, item block) string {
	writer := &lineWriter{}
	item.write(writer, style)
	return strings.Join(writer.lines, "\n")
}

func samplePanel(title string) Panel {
	body := newDocument()
	body.Line(RolePlain, "wal 4.1 MiB")
	body.Status(StatusOK, "healthy")
	return Panel{Title: title, Body: body}
}

func TestPanelUnicodeBorderGolden(t *testing.T) {
	t.Parallel()

	style := NewStyle(Capabilities{Unicode: true, Width: 30})
	want := "" +
		"\u250c\u2500 Storage \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510\n" +
		"\u2502 wal 4.1 MiB                \u2502\n" +
		"\u2502 \u2714 healthy                  \u2502\n" +
		"\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518"
	got := renderBlock(style, panelBlock{panel: samplePanel("Storage")})
	if got != want {
		t.Fatalf("panel =\n%s\nwant\n%s", got, want)
	}
	for _, line := range strings.Split(got, "\n") {
		if DisplayWidth(line) != 30 {
			t.Fatalf("line %q is %d columns, want 30", line, DisplayWidth(line))
		}
	}
}

func TestPanelASCIIBorderGolden(t *testing.T) {
	t.Parallel()

	want := "" +
		"+- Storage ------------------+\n" +
		"| wal 4.1 MiB                |\n" +
		"| + healthy                  |\n" +
		"+----------------------------+"
	got := renderBlock(PlainStyle(30), panelBlock{panel: samplePanel("Storage")})
	if got != want {
		t.Fatalf("panel =\n%s\nwant\n%s", got, want)
	}
	for _, symbol := range got {
		if symbol > 0x7f {
			t.Fatalf("ASCII panel contains %U", symbol)
		}
	}
}

func TestPanelWithoutTitleOrBody(t *testing.T) {
	t.Parallel()

	want := "" +
		"+--------+\n" +
		"+--------+"
	if got := renderBlock(PlainStyle(10), panelBlock{panel: Panel{}}); got != want {
		t.Fatalf("panel =\n%s\nwant\n%s", got, want)
	}
}

func TestPanelTitleTruncatedToFit(t *testing.T) {
	t.Parallel()

	panel := Panel{Title: "a very long panel title indeed"}
	got := renderBlock(PlainStyle(20), panelBlock{panel: panel})
	lines := strings.Split(got, "\n")
	for _, line := range lines {
		if DisplayWidth(line) != 20 {
			t.Fatalf("line %q is %d columns, want 20", line, DisplayWidth(line))
		}
	}
	if !strings.Contains(lines[0], "...") {
		t.Fatalf("title was not truncated: %q", lines[0])
	}
	if !strings.HasSuffix(lines[0], "-+") {
		t.Fatalf("top border does not close: %q", lines[0])
	}
}

func TestPanelDropsTitleWhenTooNarrow(t *testing.T) {
	t.Parallel()

	got := renderBlock(PlainStyle(6), panelBlock{panel: Panel{Title: "Storage"}})
	if want := "+----+\n+----+"; got != want {
		t.Fatalf("panel =\n%s\nwant\n%s", got, want)
	}
	if got := renderBlock(PlainStyle(1), panelBlock{panel: Panel{Title: "x"}}); DisplayWidth(strings.Split(got, "\n")[0]) != 5 {
		t.Fatalf("panel below the chrome minimum =\n%s", got)
	}
}

func TestPanelBodyLinesTruncatedAndPadded(t *testing.T) {
	t.Parallel()

	body := newDocument()
	body.Line(RolePlain, "short")
	body.Line(RolePlain, strings.Repeat("x", 200))
	got := renderBlock(PlainStyle(20), panelBlock{panel: Panel{Title: "T", Body: body}})
	lines := strings.Split(got, "\n")
	if len(lines) != 4 {
		t.Fatalf("panel has %d lines:\n%s", len(lines), got)
	}
	for _, line := range lines {
		if DisplayWidth(line) != 20 {
			t.Fatalf("line %q is %d columns, want 20", line, DisplayWidth(line))
		}
	}
	if !strings.Contains(lines[2], "...") {
		t.Fatalf("long body line was not truncated: %q", lines[2])
	}
}

func TestPanelRowSplitsWidthEvenly(t *testing.T) {
	t.Parallel()

	got := renderBlock(PlainStyle(120), panelRowBlock{panels: []Panel{
		samplePanel("A"), samplePanel("B"), samplePanel("C"),
	}})
	lines := strings.Split(got, "\n")
	if len(lines) != 4 {
		t.Fatalf("panel row has %d lines:\n%s", len(lines), got)
	}
	for _, line := range lines {
		if DisplayWidth(line) != 120 {
			t.Fatalf("line %q is %d columns, want 120", line, DisplayWidth(line))
		}
	}
	if strings.Count(lines[0], "+-") != 3 {
		t.Fatalf("expected three panels on one line: %q", lines[0])
	}
}

func TestPanelRowGivesRemainderToTheLeftmost(t *testing.T) {
	t.Parallel()

	got := renderBlock(PlainStyle(69), panelRowBlock{panels: []Panel{samplePanel("A"), samplePanel("B")}})
	lines := strings.Split(got, "\n")
	first := strings.Index(lines[0], "  +")
	if first != 34 {
		t.Fatalf("leftmost panel is %d columns, want 34: %q", first, lines[0])
	}
	if DisplayWidth(lines[0]) != 69 {
		t.Fatalf("row is %d columns, want 69", DisplayWidth(lines[0]))
	}
}

func TestPanelRowPadsShortPanels(t *testing.T) {
	t.Parallel()

	short := newDocument()
	short.Line(RolePlain, "one")
	tall := newDocument()
	tall.Line(RolePlain, "one")
	tall.Line(RolePlain, "two")
	tall.Line(RolePlain, "three")

	got := renderBlock(PlainStyle(100), panelRowBlock{panels: []Panel{
		{Title: "S", Body: short},
		{Title: "T", Body: tall},
	}})
	lines := strings.Split(got, "\n")
	if len(lines) != 5 {
		t.Fatalf("panel row has %d lines:\n%s", len(lines), got)
	}
	for _, line := range lines {
		if DisplayWidth(line) != 100 {
			t.Fatalf("line %q is %d columns, want 100", line, DisplayWidth(line))
		}
	}
}

func TestPanelRowStacksWhenNarrow(t *testing.T) {
	t.Parallel()

	got := renderBlock(PlainStyle(50), panelRowBlock{panels: []Panel{samplePanel("A"), samplePanel("B")}})
	lines := strings.Split(got, "\n")
	if len(lines) != 8 {
		t.Fatalf("stacked row has %d lines:\n%s", len(lines), got)
	}
	if !strings.HasPrefix(lines[0], "+- A ") || !strings.HasPrefix(lines[4], "+- B ") {
		t.Fatalf("panels were not stacked:\n%s", got)
	}
}

func TestPanelRowHonoursExplicitMinWidth(t *testing.T) {
	t.Parallel()

	wide := samplePanel("A")
	wide.MinWidth = 60
	other := samplePanel("B")
	other.MinWidth = 60

	stacked := renderBlock(PlainStyle(100), panelRowBlock{panels: []Panel{wide, other}})
	if len(strings.Split(stacked, "\n")) != 8 {
		t.Fatalf("panels wider than the row were not stacked:\n%s", stacked)
	}
	sideBySide := renderBlock(PlainStyle(130), panelRowBlock{panels: []Panel{wide, other}})
	if len(strings.Split(sideBySide, "\n")) != 4 {
		t.Fatalf("panels that fit were stacked:\n%s", sideBySide)
	}
}

func TestPanelRowDegenerateCases(t *testing.T) {
	t.Parallel()

	if got := renderBlock(PlainStyle(80), panelRowBlock{}); got != "" {
		t.Fatalf("empty panel row = %q", got)
	}
	single := renderBlock(PlainStyle(40), panelRowBlock{panels: []Panel{samplePanel("Solo")}})
	if DisplayWidth(strings.Split(single, "\n")[0]) != 40 {
		t.Fatalf("single panel did not take the full width:\n%s", single)
	}
}

func TestPanelRoleStylesBorderOnly(t *testing.T) {
	t.Parallel()

	style := NewStyle(Capabilities{Color: true, Width: 30})
	got := renderBlock(style, panelBlock{panel: Panel{Title: "T", Role: RoleWarn, Body: newDocument().Line(RolePlain, "body")}})
	if !strings.Contains(got, esc(RoleWarn)) {
		t.Fatalf("border is not styled:\n%s", visible(got))
	}
	if strings.Contains(got, esc(RoleWarn)+"body") {
		t.Fatalf("body inherited the border role:\n%s", visible(got))
	}
	muted := renderBlock(style, panelBlock{panel: Panel{Title: "T"}})
	if !strings.Contains(muted, esc(RoleMuted)) {
		t.Fatalf("default border role is not muted:\n%s", visible(muted))
	}
}
