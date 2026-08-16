package render

import (
	"strings"
	"testing"
)

func TestFieldsAlignKeys(t *testing.T) {
	t.Parallel()

	fields := Fields{Items: []Field{
		{Key: "database", Value: "/Users/phall/.local/share/blackbird/blackbird.db"},
		{Key: "schema", Value: "46"},
		{Key: "wal", Value: "4.1 MiB"},
	}}
	want := "" +
		"database  /Users/phall/.local/share/blackbird/blackbird.db\n" +
		"schema    46\n" +
		"wal       4.1 MiB"
	if got := renderBlock(PlainStyle(80), fieldsBlock{fields: fields}); got != want {
		t.Fatalf("fields =\n%s\nwant\n%s", got, want)
	}
}

func TestFieldsIndentAndEmpty(t *testing.T) {
	t.Parallel()

	if got := renderBlock(PlainStyle(80), fieldsBlock{fields: Fields{}}); got != "" {
		t.Fatalf("empty fields = %q", got)
	}
	fields := Fields{Items: []Field{{Key: "a", Value: "1"}}, Indent: 4}
	if got, want := renderBlock(PlainStyle(80), fieldsBlock{fields: fields}), "    a  1"; got != want {
		t.Fatalf("fields = %q, want %q", got, want)
	}
}

func TestFieldsWrapLongValuesWithHangingIndent(t *testing.T) {
	t.Parallel()

	fields := Fields{Items: []Field{
		{Key: "reason", Value: "the lease expired because the holder stopped renewing it well before the deadline"},
	}}
	lines := strings.Split(renderBlock(PlainStyle(40), fieldsBlock{fields: fields}), "\n")
	if len(lines) < 3 {
		t.Fatalf("value did not wrap:\n%s", strings.Join(lines, "\n"))
	}
	if !strings.HasPrefix(lines[0], "reason  the lease") {
		t.Fatalf("first line = %q", lines[0])
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, strings.Repeat(" ", 8)) {
			t.Fatalf("continuation %q is not at the value column", line)
		}
		if DisplayWidth(line) > 40 {
			t.Fatalf("line %q is %d columns", line, DisplayWidth(line))
		}
	}
}

func TestFieldsEmptyKeyContinuesValueColumn(t *testing.T) {
	t.Parallel()

	fields := Fields{Items: []Field{
		{Key: "selectors", Value: "internal/cli/**"},
		{Key: "", Value: "internal/runtime/**"},
	}}
	want := "" +
		"selectors  internal/cli/**\n" +
		"           internal/runtime/**"
	if got := renderBlock(PlainStyle(80), fieldsBlock{fields: fields}); got != want {
		t.Fatalf("fields =\n%s\nwant\n%s", got, want)
	}
}

func TestFieldsRolesDefaultToMutedKeysAndPlainValues(t *testing.T) {
	t.Parallel()

	style := NewStyle(Capabilities{Color: true, Width: 80})
	fields := Fields{Items: []Field{
		{Key: "state", Value: "expired", Role: RoleError},
		{Key: "mode", Value: "exclusive"},
	}}
	got := renderBlock(style, fieldsBlock{fields: fields})
	if !strings.Contains(got, esc(RoleMuted)+"state"+ansiReset) {
		t.Fatalf("key is not muted:\n%s", visible(got))
	}
	if !strings.Contains(got, esc(RoleError)+"expired"+ansiReset) {
		t.Fatalf("value role was dropped:\n%s", visible(got))
	}
	if strings.Contains(got, esc(RoleMuted)+"exclusive") {
		t.Fatalf("plain value picked up the key role:\n%s", visible(got))
	}

	custom := Fields{Items: []Field{{Key: "k", Value: "v"}}, KeyRole: RoleAccent}
	if !strings.Contains(renderBlock(style, fieldsBlock{fields: custom}), esc(RoleAccent)+"k"+ansiReset) {
		t.Fatal("explicit KeyRole was ignored")
	}
}

func TestFieldsNarrowWidthKeepsMinimumValueSpan(t *testing.T) {
	t.Parallel()

	fields := Fields{Items: []Field{{Key: strings.Repeat("k", 40), Value: "alpha beta gamma"}}}
	lines := strings.Split(renderBlock(PlainStyle(40), fieldsBlock{fields: fields}), "\n")
	if len(lines) < 2 {
		t.Fatalf("value did not wrap at the minimum span:\n%s", strings.Join(lines, "\n"))
	}
}
