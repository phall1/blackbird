package render

// Role is a semantic output class. Commands name roles, never colours, so a
// palette change is one edit and every command moves together.
type Role uint8

const (
	// RoleInherit is the zero value: the enclosing element's role applies.
	RoleInherit Role = iota
	RolePlain
	RoleHeading
	RoleMuted
	RoleAccent
	RoleOK
	RoleWarn
	RoleError
	RoleInfo
	roleCount
)

const ansiReset = "\x1b[0m"

var palette = [roleCount]string{
	RoleInherit: "",
	RolePlain:   "",
	RoleHeading: "\x1b[1m",
	RoleMuted:   "\x1b[2m",
	RoleAccent:  "\x1b[36m",
	RoleOK:      "\x1b[32m",
	RoleWarn:    "\x1b[33m",
	RoleError:   "\x1b[31m",
	RoleInfo:    "\x1b[34m",
}

var roleNames = [roleCount]string{
	RoleInherit: "inherit",
	RolePlain:   "plain",
	RoleHeading: "heading",
	RoleMuted:   "muted",
	RoleAccent:  "accent",
	RoleOK:      "ok",
	RoleWarn:    "warn",
	RoleError:   "error",
	RoleInfo:    "info",
}

func (role Role) String() string {
	if role >= roleCount {
		return "unknown"
	}
	return roleNames[role]
}

// Style is an immutable rendering decision set. It is a value type; copying it
// is free and there is no shared mutable state to race on.
type Style struct {
	color   bool
	unicode bool
	tty     bool
	width   int
}

func NewStyle(capabilities Capabilities) Style {
	width := capabilities.Width
	if width <= 0 {
		width = FallbackWidth
	}
	return Style{
		color:   capabilities.Color,
		unicode: capabilities.Unicode,
		tty:     capabilities.TTY,
		width:   width,
	}
}

// PlainStyle is the colourless, ASCII-only style used by tests and by every
// non-terminal stream.
func PlainStyle(width int) Style {
	if width <= 0 {
		width = FallbackWidth
	}
	return Style{width: width}
}

func (style Style) Color() bool   { return style.color }
func (style Style) Unicode() bool { return style.unicode }
func (style Style) TTY() bool     { return style.tty }
func (style Style) Width() int    { return style.width }

func (style Style) WithWidth(width int) Style {
	if width <= 0 {
		width = 1
	}
	style.width = width
	return style
}

// Apply wraps text in the SGR sequence for role, or returns it unchanged when
// colour is off or the role carries no colour of its own.
func (style Style) Apply(role Role, text string) string {
	if !style.color || text == "" || role >= roleCount {
		return text
	}
	prefix := palette[role]
	if prefix == "" {
		return text
	}
	return prefix + text + ansiReset
}

// ClearScreen returns the home-and-erase sequence for a --watch redraw, or ""
// when the stream is not a terminal.
func (style Style) ClearScreen() string {
	if !style.tty {
		return ""
	}
	return "\x1b[H\x1b[2J"
}
