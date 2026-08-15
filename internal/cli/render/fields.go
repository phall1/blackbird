package render

import "strings"

const (
	fieldGutter       = 2
	minFieldValueSpan = 8
)

// Field is one key-value pair. An empty Key continues the previous value in the
// value column.
type Field struct {
	Key   string
	Value string
	Role  Role
}

// Fields is a key-value detail block.
type Fields struct {
	Items   []Field
	KeyRole Role
	Indent  int
}

type fieldsBlock struct {
	fields Fields
}

func (item fieldsBlock) write(writer *lineWriter, style Style) {
	fields := item.fields
	if len(fields.Items) == 0 {
		return
	}

	keyRole := fields.KeyRole
	if keyRole == RoleInherit {
		keyRole = RoleMuted
	}
	indent := max(fields.Indent, 0)
	keyColumn := 0
	for _, field := range fields.Items {
		keyColumn = max(keyColumn, DisplayWidth(field.Key))
	}

	margin := strings.Repeat(" ", indent)
	valueColumn := indent + keyColumn + fieldGutter
	valueSpan := max(style.Width()-valueColumn, minFieldValueSpan)
	continuation := strings.Repeat(" ", valueColumn)

	for _, field := range fields.Items {
		valueRole := field.Role
		if valueRole == RoleInherit {
			valueRole = RolePlain
		}
		lines := Wrap(field.Value, valueSpan, 0)

		head := continuation
		if field.Key != "" {
			head = margin + Pad(style.Apply(keyRole, field.Key), keyColumn, AlignLeft) + strings.Repeat(" ", fieldGutter)
		}
		writer.add(head + style.Apply(valueRole, lines[0]))
		for _, line := range lines[1:] {
			writer.add(continuation + style.Apply(valueRole, line))
		}
	}
}
