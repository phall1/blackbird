package render

import "testing"

func TestStyleAppliesSGRWhenColorEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		role   Role
		prefix string
	}{
		{name: "heading", role: RoleHeading, prefix: "\x1b[1m"},
		{name: "muted", role: RoleMuted, prefix: "\x1b[2m"},
		{name: "accent", role: RoleAccent, prefix: "\x1b[36m"},
		{name: "ok", role: RoleOK, prefix: "\x1b[32m"},
		{name: "warn", role: RoleWarn, prefix: "\x1b[33m"},
		{name: "error", role: RoleError, prefix: "\x1b[31m"},
		{name: "info", role: RoleInfo, prefix: "\x1b[34m"},
	}

	styled := NewStyle(Capabilities{Color: true, Width: 80})
	plain := PlainStyle(80)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := styled.Apply(test.role, "value")
			want := test.prefix + "value" + "\x1b[0m"
			if got != want {
				t.Fatalf("Apply(%s) = %q, want %q", test.role, visible(got), visible(want))
			}
			if got := plain.Apply(test.role, "value"); got != "value" {
				t.Fatalf("plain Apply(%s) = %q, want %q", test.role, visible(got), "value")
			}
			if DisplayWidth(styled.Apply(test.role, "value")) != 5 {
				t.Fatalf("styling changed display width of %s", test.role)
			}
		})
	}
}

func TestStyleRoleInheritPlainAndEmptyEmitNoEscape(t *testing.T) {
	t.Parallel()

	styled := NewStyle(Capabilities{Color: true, Width: 80})
	for _, role := range []Role{RoleInherit, RolePlain, roleCount, Role(200)} {
		if got := styled.Apply(role, "value"); got != "value" {
			t.Fatalf("Apply(%d) = %q, want %q", role, visible(got), "value")
		}
	}
	if got := styled.Apply(RoleOK, ""); got != "" {
		t.Fatalf("Apply on empty text = %q, want empty", visible(got))
	}
}

func TestRoleString(t *testing.T) {
	t.Parallel()

	tests := map[Role]string{
		RoleInherit: "inherit",
		RolePlain:   "plain",
		RoleHeading: "heading",
		RoleMuted:   "muted",
		RoleAccent:  "accent",
		RoleOK:      "ok",
		RoleWarn:    "warn",
		RoleError:   "error",
		RoleInfo:    "info",
		Role(200):   "unknown",
	}
	for role, want := range tests {
		if got := role.String(); got != want {
			t.Fatalf("Role(%d).String() = %q, want %q", role, got, want)
		}
	}
}

func TestClearScreenOnlyOnTerminal(t *testing.T) {
	t.Parallel()

	if got := NewStyle(Capabilities{TTY: true, Width: 80}).ClearScreen(); got != "\x1b[H\x1b[2J" {
		t.Fatalf("ClearScreen() = %q on a terminal", visible(got))
	}
	if got := PlainStyle(80).ClearScreen(); got != "" {
		t.Fatalf("ClearScreen() = %q off a terminal, want empty", visible(got))
	}
}

func TestNewStyleCarriesCapabilitiesAndWithWidthCopies(t *testing.T) {
	t.Parallel()

	style := NewStyle(Capabilities{TTY: true, Color: true, Unicode: true, Width: 120})
	if !style.TTY() || !style.Color() || !style.Unicode() || style.Width() != 120 {
		t.Fatalf("NewStyle lost capabilities: %+v", style)
	}

	narrow := style.WithWidth(40)
	if narrow.Width() != 40 {
		t.Fatalf("WithWidth(40).Width() = %d", narrow.Width())
	}
	if style.Width() != 120 {
		t.Fatalf("WithWidth mutated the receiver: %d", style.Width())
	}
	if !narrow.Color() || !narrow.Unicode() || !narrow.TTY() {
		t.Fatalf("WithWidth dropped capabilities: %+v", narrow)
	}
	if got := style.WithWidth(0).Width(); got != 1 {
		t.Fatalf("WithWidth(0).Width() = %d, want 1", got)
	}
	if got := NewStyle(Capabilities{}).Width(); got != FallbackWidth {
		t.Fatalf("NewStyle zero width = %d, want %d", got, FallbackWidth)
	}
	if got := PlainStyle(0).Width(); got != FallbackWidth {
		t.Fatalf("PlainStyle(0).Width() = %d, want %d", got, FallbackWidth)
	}
	if PlainStyle(80).Color() || PlainStyle(80).Unicode() || PlainStyle(80).TTY() {
		t.Fatal("PlainStyle is not plain")
	}
}
