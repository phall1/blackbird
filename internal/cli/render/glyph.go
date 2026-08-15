package render

// Status is a semantic marker rendered as a single-column glyph.
type Status uint8

const (
	StatusNone Status = iota
	StatusOK
	StatusWarn
	StatusError
	StatusPending
	StatusActive
	StatusUnknown
	StatusBullet
	StatusArrow
	statusCount
)

// Every glyph in both sets occupies exactly one display column, which is what
// lets a status column stay aligned whether or not Unicode is available.
var unicodeGlyphs = [statusCount]string{
	StatusNone:    " ",
	StatusOK:      "✔",
	StatusWarn:    "▲",
	StatusError:   "✖",
	StatusPending: "◌",
	StatusActive:  "◆",
	StatusUnknown: "?",
	StatusBullet:  "•",
	StatusArrow:   "→",
}

var asciiGlyphs = [statusCount]string{
	StatusNone:    " ",
	StatusOK:      "+",
	StatusWarn:    "!",
	StatusError:   "x",
	StatusPending: ".",
	StatusActive:  ">",
	StatusUnknown: "?",
	StatusBullet:  "-",
	StatusArrow:   ">",
}

var glyphRoles = [statusCount]Role{
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

func normalizeStatus(status Status) Status {
	if status >= statusCount {
		return StatusUnknown
	}
	return status
}

func (style Style) Glyph(status Status) string {
	status = normalizeStatus(status)
	if style.unicode {
		return unicodeGlyphs[status]
	}
	return asciiGlyphs[status]
}

func (style Style) GlyphRole(status Status) Role {
	return glyphRoles[normalizeStatus(status)]
}

// StatusLine composes the glyph and its text, colouring only the glyph.
func (style Style) StatusLine(status Status, text string) string {
	return style.Apply(style.GlyphRole(status), style.Glyph(status)) + " " + text
}
