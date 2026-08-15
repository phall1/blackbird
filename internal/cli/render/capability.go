package render

import (
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

const (
	// FallbackWidth is used when no width can be determined, including every
	// non-terminal stream. Machine consumers should use --json instead.
	FallbackWidth = 80
	MinWidth      = 40
	MaxWidth      = 160
)

// ColorChoice is the value of --color.
type ColorChoice string

const (
	ColorAuto   ColorChoice = "auto"
	ColorAlways ColorChoice = "always"
	ColorNever  ColorChoice = "never"
)

func ParseColorChoice(text string) (ColorChoice, error) {
	switch ColorChoice(text) {
	case "", ColorAuto:
		return ColorAuto, nil
	case ColorAlways:
		return ColorAlways, nil
	case ColorNever:
		return ColorNever, nil
	default:
		return "", fmt.Errorf("color must be auto, always, or never: %q", text)
	}
}

func (choice *ColorChoice) UnmarshalText(text []byte) error {
	parsed, err := ParseColorChoice(string(text))
	if err != nil {
		return err
	}
	*choice = parsed
	return nil
}

func (choice ColorChoice) String() string {
	if choice == "" {
		return string(ColorAuto)
	}
	return string(choice)
}

// Env looks up an environment variable. os.LookupEnv satisfies it directly.
type Env func(key string) (string, bool)

// Device is the minimum an output stream must expose to be classified.
// *os.File satisfies it; a bytes.Buffer does not, which is the point.
type Device interface {
	Stat() (fs.FileInfo, error)
}

// Options are the raw inputs to Detect. Every field is optional; the zero value
// describes a non-terminal, colourless, 80-column stream.
type Options struct {
	Device     Device
	Env        Env
	Color      ColorChoice
	ASCII      bool
	Width      int
	WidthProbe func() (int, bool)
}

// Capabilities is the resolved answer. It is a value; commands pass it around
// freely and tests construct it literally.
type Capabilities struct {
	TTY     bool
	Color   bool
	Unicode bool
	Width   int
}

func IsTerminal(device Device) bool {
	if device == nil {
		return false
	}
	info, err := device.Stat()
	if err != nil || info == nil {
		return false
	}
	mode := info.Mode()
	return mode&os.ModeCharDevice != 0 && mode&os.ModeDevice != 0
}

func Detect(options Options) Capabilities {
	lookup := options.Env
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}
	terminal, _ := lookup("TERM")
	dumb := terminal == "dumb"
	tty := IsTerminal(options.Device)

	return Capabilities{
		TTY:     tty,
		Color:   resolveColor(options.Color, lookup, tty, dumb),
		Unicode: resolveUnicode(options.ASCII, lookup, tty, dumb),
		Width:   resolveWidth(options, lookup),
	}
}

func resolveColor(choice ColorChoice, lookup Env, tty, dumb bool) bool {
	switch choice {
	case ColorNever:
		return false
	case ColorAlways:
		return true
	case ColorAuto:
	}

	if value, ok := lookup("NO_COLOR"); ok && value != "" {
		return false
	}
	if value, ok := lookup("CLICOLOR_FORCE"); ok && value != "0" {
		return true
	}
	if dumb {
		return false
	}
	return tty
}

func resolveUnicode(ascii bool, lookup Env, tty, dumb bool) bool {
	if ascii || dumb || !tty {
		return false
	}
	for _, key := range [...]string{"LC_ALL", "LC_CTYPE", "LANG"} {
		value, ok := lookup(key)
		if !ok || value == "" {
			continue
		}
		lowered := strings.ToLower(value)
		return strings.Contains(lowered, "utf-8") || strings.Contains(lowered, "utf8")
	}
	return true
}

func resolveWidth(options Options, lookup Env) int {
	if options.Width > 0 {
		return clampWidth(options.Width)
	}
	if value, ok := lookup("COLUMNS"); ok {
		if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && parsed > 0 {
			return clampWidth(parsed)
		}
	}
	if options.WidthProbe != nil {
		if probed, ok := options.WidthProbe(); ok && probed > 0 {
			return clampWidth(probed)
		}
	}
	return FallbackWidth
}

func clampWidth(width int) int {
	return min(max(width, MinWidth), MaxWidth)
}
