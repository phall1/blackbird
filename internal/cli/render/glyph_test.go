package render

import "testing"

func allStatuses() []Status {
	statuses := make([]Status, 0, statusCount)
	for status := StatusNone; status < statusCount; status++ {
		statuses = append(statuses, status)
	}
	return statuses
}

func TestGlyphsAreSingleWidthInBothModes(t *testing.T) {
	t.Parallel()

	unicodeStyle := NewStyle(Capabilities{Unicode: true, Width: 80})
	asciiStyle := PlainStyle(80)
	for _, status := range allStatuses() {
		if got := DisplayWidth(unicodeStyle.Glyph(status)); got != 1 {
			t.Fatalf("unicode glyph for status %d is %d columns", status, got)
		}
		if got := DisplayWidth(asciiStyle.Glyph(status)); got != 1 {
			t.Fatalf("ascii glyph for status %d is %d columns", status, got)
		}
	}
}

func TestASCIIGlyphSetIsPureASCII(t *testing.T) {
	t.Parallel()

	style := PlainStyle(80)
	for _, status := range allStatuses() {
		glyph := style.Glyph(status)
		if len(glyph) != 1 || glyph[0] > 0x7f {
			t.Fatalf("ascii glyph for status %d is %q", status, glyph)
		}
	}
}

func TestGlyphRolesMapToSemanticColors(t *testing.T) {
	t.Parallel()

	style := PlainStyle(80)
	tests := map[Status]Role{
		StatusNone:    RolePlain,
		StatusOK:      RoleOK,
		StatusWarn:    RoleWarn,
		StatusError:   RoleError,
		StatusPending: RoleMuted,
		StatusActive:  RoleAccent,
		StatusUnknown: RoleMuted,
		StatusBullet:  RoleMuted,
		StatusArrow:   RoleMuted,
	}
	for status, want := range tests {
		if got := style.GlyphRole(status); got != want {
			t.Fatalf("GlyphRole(%d) = %s, want %s", status, got, want)
		}
	}
}

func TestGlyphUnknownStatusFallsBack(t *testing.T) {
	t.Parallel()

	for _, style := range [...]Style{PlainStyle(80), NewStyle(Capabilities{Unicode: true, Width: 80})} {
		if got, want := style.Glyph(Status(200)), style.Glyph(StatusUnknown); got != want {
			t.Fatalf("Glyph(200) = %q, want %q", got, want)
		}
		if got, want := style.GlyphRole(Status(200)), RoleMuted; got != want {
			t.Fatalf("GlyphRole(200) = %s, want %s", got, want)
		}
	}
}

func TestStatusLineComposesGlyphAndText(t *testing.T) {
	t.Parallel()

	if got, want := PlainStyle(80).StatusLine(StatusOK, "started"), "+ started"; got != want {
		t.Fatalf("StatusLine = %q, want %q", got, want)
	}
	if got, want := NewStyle(Capabilities{Unicode: true, Width: 80}).StatusLine(StatusActive, "leased"), "\u25c6 leased"; got != want {
		t.Fatalf("StatusLine = %q, want %q", got, want)
	}

	styled := NewStyle(Capabilities{Color: true, Width: 80}).StatusLine(StatusOK, "started")
	if want := esc(RoleOK) + "+" + ansiReset + " started"; styled != want {
		t.Fatalf("StatusLine = %q, want %q", visible(styled), visible(want))
	}
}
