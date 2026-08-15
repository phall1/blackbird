package render

import "strings"

const (
	defaultPanelMinWidth = 32
	panelRowGutter       = 2
	panelChrome          = 4
)

type boxSet struct {
	topLeft     string
	topRight    string
	bottomLeft  string
	bottomRight string
	horizontal  string
	vertical    string
}

var unicodeBox = boxSet{
	topLeft:     "┌",
	topRight:    "┐",
	bottomLeft:  "└",
	bottomRight: "┘",
	horizontal:  "─",
	vertical:    "│",
}

var asciiBox = boxSet{
	topLeft:     "+",
	topRight:    "+",
	bottomLeft:  "+",
	bottomRight: "+",
	horizontal:  "-",
	vertical:    "|",
}

// Panel is a bordered group. Body is built with Document.Sub.
type Panel struct {
	Title    string
	Role     Role
	Body     *Document
	MinWidth int
}

type panelBlock struct {
	panel Panel
}

func (item panelBlock) write(writer *lineWriter, style Style) {
	writer.addAll(panelLines(item.panel, style, style.Width()))
}

type panelRowBlock struct {
	panels []Panel
}

func (item panelRowBlock) write(writer *lineWriter, style Style) {
	panels := item.panels
	switch len(panels) {
	case 0:
		return
	case 1:
		writer.addAll(panelLines(panels[0], style, style.Width()))
		return
	}

	minimum := 0
	for _, panel := range panels {
		minimum += panelMinWidth(panel)
	}
	total := style.Width()
	if total < minimum+panelRowGutter*(len(panels)-1) {
		for _, panel := range panels {
			writer.addAll(panelLines(panel, style, total))
		}
		return
	}

	span := (total - panelRowGutter*(len(panels)-1)) / len(panels)
	remainder := (total - panelRowGutter*(len(panels)-1)) % len(panels)
	columns := make([][]string, len(panels))
	widths := make([]int, len(panels))
	height := 0
	for index, panel := range panels {
		width := span
		if index == 0 {
			width += remainder
		}
		widths[index] = width
		columns[index] = panelLines(panel, style, width)
		height = max(height, len(columns[index]))
	}

	gutter := strings.Repeat(" ", panelRowGutter)
	for line := range height {
		parts := make([]string, len(columns))
		for index, column := range columns {
			if line < len(column) {
				parts[index] = Pad(column[line], widths[index], AlignLeft)
				continue
			}
			parts[index] = strings.Repeat(" ", widths[index])
		}
		writer.add(strings.Join(parts, gutter))
	}
}

func panelMinWidth(panel Panel) int {
	if panel.MinWidth > 0 {
		return panel.MinWidth
	}
	return defaultPanelMinWidth
}

func panelLines(panel Panel, style Style, width int) []string {
	box := asciiBox
	if style.Unicode() {
		box = unicodeBox
	}
	role := panel.Role
	if role == RoleInherit {
		role = RoleMuted
	}
	if width < panelChrome+1 {
		width = panelChrome + 1
	}
	inner := width - panelChrome
	frame := width - 2

	lines := []string{style.Apply(role, topBorder(panel.Title, frame, box, style))}

	var body []string
	if panel.Body != nil {
		body = panel.Body.lines(style.WithWidth(inner))
	}
	vertical := style.Apply(role, box.vertical)
	for _, line := range body {
		cell := Pad(Truncate(line, inner, style.Unicode()), inner, AlignLeft)
		lines = append(lines, vertical+" "+cell+" "+vertical)
	}

	lines = append(lines, style.Apply(role, box.bottomLeft+strings.Repeat(box.horizontal, frame)+box.bottomRight))
	return lines
}

func topBorder(title string, frame int, box boxSet, style Style) string {
	if title == "" {
		return box.topLeft + strings.Repeat(box.horizontal, frame) + box.topRight
	}

	span := frame - 4
	if span < 1 {
		return box.topLeft + strings.Repeat(box.horizontal, frame) + box.topRight
	}
	title = Truncate(title, span, style.Unicode())
	fill := frame - 3 - DisplayWidth(title)
	return box.topLeft + box.horizontal + " " + title + " " + strings.Repeat(box.horizontal, fill) + box.topRight
}
