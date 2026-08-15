package render

import (
	"slices"
	"strings"
)

const (
	tableGutter      = 2
	flexibleMinWidth = 8
	hardMinWidth     = 1
	flexiblePriority = 1
	pinnedPriority   = 0
)

type Align uint8

const (
	AlignLeft Align = iota
	AlignRight
)

// Trim is the end of a cell that is sacrificed when its column narrows.
type Trim uint8

const (
	// TrimAuto keeps the tail of a right-aligned cell and the head of every
	// other one. Headings never follow it: a heading read from its tail names
	// the wrong column, so LEASES narrowed to four columns is LEA… and never
	// …SES.
	TrimAuto Trim = iota
	TrimRight
	TrimLeft
)

// Column describes one table column. Priority orders shrinking: higher shrinks
// first and negative never shrinks, while zero — the value a caller that
// declares nothing gets — derives the answer from Align, so left-aligned prose
// absorbs the loss and right-aligned numerics keep every digit. A width-fitting
// rule that only works when every caller opts in does not work.
type Column struct {
	Title    string
	Align    Align
	Role     Role
	Trim     Trim
	MinWidth int
	Priority int
}

// Cell is one table value. RoleInherit defers to the column's role.
type Cell struct {
	Text string
	Role Role
}

type Row struct {
	Cells []Cell
}

// Table is a dense, rule-free grid: an uppercased heading row, a two-space
// gutter, and nothing else.
type Table struct {
	Columns []Column
	Rows    []Row
	Empty   string
	Indent  int
}

func TextRow(cells ...string) Row {
	row := Row{Cells: make([]Cell, 0, len(cells))}
	for _, text := range cells {
		row.Cells = append(row.Cells, Cell{Text: text})
	}
	return row
}

type tableBlock struct {
	table Table
}

func (item tableBlock) write(writer *lineWriter, style Style) {
	table := item.table
	indent := max(table.Indent, 0)
	margin := strings.Repeat(" ", indent)

	if len(table.Columns) == 0 {
		if table.Empty != "" {
			writer.add(margin + style.Apply(RoleMuted, table.Empty))
		}
		return
	}

	widths := fitColumns(table, style.Width(), indent)
	writer.add(margin + joinCells(headerCells(table), widths, table.Columns, style))
	for _, row := range table.Rows {
		writer.add(margin + joinCells(bodyCells(table, row), widths, table.Columns, style))
	}
	if len(table.Rows) == 0 && table.Empty != "" {
		writer.add(margin + style.Apply(RoleMuted, table.Empty))
	}
}

type styledCell struct {
	text string
	role Role
	trim Trim
}

func headerCells(table Table) []styledCell {
	cells := make([]styledCell, len(table.Columns))
	for index, column := range table.Columns {
		cells[index] = styledCell{text: strings.ToUpper(column.Title), role: RoleHeading, trim: TrimRight}
	}
	return cells
}

func bodyCells(table Table, row Row) []styledCell {
	cells := make([]styledCell, len(table.Columns))
	for index, column := range table.Columns {
		cell := Cell{}
		if index < len(row.Cells) {
			cell = row.Cells[index]
		}
		role := cell.Role
		if role == RoleInherit {
			role = column.Role
		}
		cells[index] = styledCell{text: cell.Text, role: role, trim: columnTrim(column)}
	}
	return cells
}

func columnTrim(column Column) Trim {
	switch {
	case column.Trim != TrimAuto:
		return column.Trim
	case column.Align == AlignRight:
		return TrimLeft
	default:
		return TrimRight
	}
}

func joinCells(cells []styledCell, widths []int, columns []Column, style Style) string {
	parts := make([]string, 0, len(cells))
	for index, cell := range cells {
		width := widths[index]
		if width <= 0 {
			continue
		}
		text := cell.text
		if cell.trim == TrimLeft {
			text = TruncateLeft(text, width, style.Unicode())
		} else {
			text = Truncate(text, width, style.Unicode())
		}
		parts = append(parts, Pad(style.Apply(cell.role, text), width, columns[index].Align))
	}
	return strings.Join(parts, strings.Repeat(" ", tableGutter))
}

func shrinkPriority(column Column) int {
	switch {
	case column.Priority != 0:
		return column.Priority
	case column.Align == AlignRight:
		return pinnedPriority
	default:
		return flexiblePriority
	}
}

func flexible(column Column) bool { return shrinkPriority(column) > 0 }

type columnFilter func(Column) bool

func anyColumn(Column) bool           { return true }
func flexibleOnly(column Column) bool { return flexible(column) }
func pinnedOnly(column Column) bool   { return !flexible(column) }

// fitColumns resolves every column width. Its contract is absolute: the widths
// it returns cannot render a line wider than available, whatever the caller
// declared. The ladder spends the cheapest thing first — prose down to a
// readable floor, then a pinned column's heading down to the width of its own
// data, then prose down to a single column, then everything, and only when even
// one column apiece will not fit are trailing columns dropped.
func fitColumns(table Table, available int, indent int) []int {
	natural := naturalWidths(table)
	widths := slices.Clone(natural)
	budget := max(available-indent, 0)

	hard := hardFloors(natural)

	shrink(table, widths, proseFloors(table, natural), budget, flexibleOnly)
	shrink(table, widths, dataFloors(table, natural), budget, pinnedOnly)
	shrink(table, widths, hard, budget, flexibleOnly)
	shrink(table, widths, hard, budget, anyColumn)
	dropTrailing(widths, budget)
	return widths
}

func naturalWidths(table Table) []int {
	widths := make([]int, len(table.Columns))
	for index, column := range table.Columns {
		widths[index] = DisplayWidth(strings.ToUpper(column.Title))
	}
	for _, row := range table.Rows {
		for index := range table.Columns {
			if index < len(row.Cells) {
				widths[index] = max(widths[index], DisplayWidth(row.Cells[index].Text))
			}
		}
	}
	return widths
}

// proseFloors is where a flexible column stops giving ground on the first pass:
// wide enough that a value is still recognisable by its head.
func proseFloors(table Table, natural []int) []int {
	floors := make([]int, len(natural))
	for index, column := range table.Columns {
		floor := flexibleMinWidth
		if column.MinWidth > 0 {
			floor = column.MinWidth
		}
		floors[index] = min(floor, natural[index])
	}
	return floors
}

// dataFloors is what a pinned column needs to keep every character of its
// values: its heading may be shortened, its digits may not.
func dataFloors(table Table, natural []int) []int {
	floors := make([]int, len(natural))
	for index, column := range table.Columns {
		widest := hardMinWidth
		for _, row := range table.Rows {
			if index < len(row.Cells) {
				widest = max(widest, DisplayWidth(row.Cells[index].Text))
			}
		}
		floors[index] = min(max(widest, column.MinWidth), natural[index])
	}
	return floors
}

func hardFloors(natural []int) []int {
	floors := make([]int, len(natural))
	for index, width := range natural {
		floors[index] = min(hardMinWidth, width)
	}
	return floors
}

func lineWidth(widths []int) int {
	total := 0
	shown := 0
	for _, width := range widths {
		if width <= 0 {
			continue
		}
		total += width
		shown++
	}
	if shown > 1 {
		total += tableGutter * (shown - 1)
	}
	return total
}

func shrink(table Table, widths []int, floors []int, budget int, eligible columnFilter) {
	for lineWidth(widths) > budget {
		target := -1
		for index, column := range table.Columns {
			if widths[index] <= floors[index] || !eligible(column) {
				continue
			}
			switch {
			case target < 0:
				target = index
			case shrinkPriority(column) > shrinkPriority(table.Columns[target]):
				target = index
			case shrinkPriority(column) == shrinkPriority(table.Columns[target]) && widths[index] > widths[target]:
				target = index
			}
		}
		if target < 0 {
			return
		}
		widths[target]--
	}
}

func dropTrailing(widths []int, budget int) {
	for index := len(widths) - 1; index >= 0 && lineWidth(widths) > budget; index-- {
		widths[index] = 0
	}
}
