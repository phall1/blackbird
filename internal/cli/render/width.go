package render

import (
	"strings"
	"unicode"
)

const (
	escapeByte      = 0x1b
	zeroWidthSpace  = 0x200b
	unicodeEllipsis = "\u2026"
	asciiEllipsis   = "..."
)

// wideRunes approximates UAX #11 East Asian Wide and Fullwidth plus the emoji
// blocks terminals render two columns wide. It is deliberately narrow: the
// Miscellaneous Symbols and Dingbats block is included only where
// Emoji_Presentation is the default, so text-presentation symbols such as
// U+2714 and U+2716 — this package's own status glyphs — stay one column.
var wideRunes = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x1100, Hi: 0x115f, Stride: 1},
		{Lo: 0x231a, Hi: 0x231b, Stride: 1},
		{Lo: 0x2329, Hi: 0x232a, Stride: 1},
		{Lo: 0x23e9, Hi: 0x23ec, Stride: 1},
		{Lo: 0x23f0, Hi: 0x23f0, Stride: 1},
		{Lo: 0x23f3, Hi: 0x23f3, Stride: 1},
		{Lo: 0x25fd, Hi: 0x25fe, Stride: 1},
		{Lo: 0x2614, Hi: 0x2615, Stride: 1},
		{Lo: 0x2648, Hi: 0x2653, Stride: 1},
		{Lo: 0x267f, Hi: 0x267f, Stride: 1},
		{Lo: 0x2693, Hi: 0x2693, Stride: 1},
		{Lo: 0x26a1, Hi: 0x26a1, Stride: 1},
		{Lo: 0x26aa, Hi: 0x26ab, Stride: 1},
		{Lo: 0x26bd, Hi: 0x26be, Stride: 1},
		{Lo: 0x26c4, Hi: 0x26c5, Stride: 1},
		{Lo: 0x26ce, Hi: 0x26ce, Stride: 1},
		{Lo: 0x26d4, Hi: 0x26d4, Stride: 1},
		{Lo: 0x26ea, Hi: 0x26ea, Stride: 1},
		{Lo: 0x26f2, Hi: 0x26f3, Stride: 1},
		{Lo: 0x26f5, Hi: 0x26f5, Stride: 1},
		{Lo: 0x26fa, Hi: 0x26fa, Stride: 1},
		{Lo: 0x26fd, Hi: 0x26fd, Stride: 1},
		{Lo: 0x2705, Hi: 0x2705, Stride: 1},
		{Lo: 0x270a, Hi: 0x270b, Stride: 1},
		{Lo: 0x2728, Hi: 0x2728, Stride: 1},
		{Lo: 0x274c, Hi: 0x274c, Stride: 1},
		{Lo: 0x274e, Hi: 0x274e, Stride: 1},
		{Lo: 0x2753, Hi: 0x2755, Stride: 1},
		{Lo: 0x2757, Hi: 0x2757, Stride: 1},
		{Lo: 0x2795, Hi: 0x2797, Stride: 1},
		{Lo: 0x27b0, Hi: 0x27b0, Stride: 1},
		{Lo: 0x27bf, Hi: 0x27bf, Stride: 1},
		{Lo: 0x2b1b, Hi: 0x2b1c, Stride: 1},
		{Lo: 0x2b50, Hi: 0x2b50, Stride: 1},
		{Lo: 0x2b55, Hi: 0x2b55, Stride: 1},
		{Lo: 0x2e80, Hi: 0x303e, Stride: 1},
		{Lo: 0x3041, Hi: 0x33ff, Stride: 1},
		{Lo: 0x3400, Hi: 0x4dbf, Stride: 1},
		{Lo: 0x4e00, Hi: 0x9fff, Stride: 1},
		{Lo: 0xa000, Hi: 0xa4cf, Stride: 1},
		{Lo: 0xa960, Hi: 0xa97f, Stride: 1},
		{Lo: 0xac00, Hi: 0xd7a3, Stride: 1},
		{Lo: 0xf900, Hi: 0xfaff, Stride: 1},
		{Lo: 0xfe10, Hi: 0xfe19, Stride: 1},
		{Lo: 0xfe30, Hi: 0xfe6f, Stride: 1},
		{Lo: 0xff00, Hi: 0xff60, Stride: 1},
		{Lo: 0xffe0, Hi: 0xffe6, Stride: 1},
	},
	R32: []unicode.Range32{
		{Lo: 0x1f300, Hi: 0x1f64f, Stride: 1},
		{Lo: 0x1f680, Hi: 0x1f6ff, Stride: 1},
		{Lo: 0x1f7e0, Hi: 0x1f7eb, Stride: 1},
		{Lo: 0x1f900, Hi: 0x1f9ff, Stride: 1},
		{Lo: 0x1fa70, Hi: 0x1faff, Stride: 1},
		{Lo: 0x20000, Hi: 0x2fffd, Stride: 1},
		{Lo: 0x30000, Hi: 0x3fffd, Stride: 1},
	},
}

func stripANSI(text string) string {
	if !strings.ContainsRune(text, escapeByte) {
		return text
	}

	var builder strings.Builder
	builder.Grow(len(text))
	index := 0
	for index < len(text) {
		if text[index] != escapeByte {
			builder.WriteByte(text[index])
			index++
			continue
		}
		index++
		if index >= len(text) {
			break
		}
		if text[index] != '[' {
			index++
			continue
		}
		index++
		for index < len(text) && (text[index] < 0x40 || text[index] > 0x7e) {
			index++
		}
		if index < len(text) {
			index++
		}
	}
	return builder.String()
}

func runeWidth(symbol rune) int {
	switch {
	case symbol == zeroWidthSpace:
		return 0
	case symbol < 0x20 || symbol == 0x7f:
		return 0
	case unicode.Is(unicode.Mn, symbol), unicode.Is(unicode.Me, symbol), unicode.Is(unicode.Cf, symbol):
		return 0
	case unicode.Is(wideRunes, symbol):
		return 2
	default:
		return 1
	}
}

// DisplayWidth is the number of terminal columns text occupies once ANSI
// sequences are removed.
func DisplayWidth(text string) int {
	width := 0
	for _, symbol := range stripANSI(text) {
		width += runeWidth(symbol)
	}
	return width
}

func ellipsisFor(unicodeOK bool) string {
	if unicodeOK {
		return unicodeEllipsis
	}
	return asciiEllipsis
}

func cutRight(text string, width int) string {
	if width <= 0 {
		return ""
	}
	used := 0
	var builder strings.Builder
	for _, symbol := range text {
		size := runeWidth(symbol)
		if used+size > width {
			break
		}
		builder.WriteRune(symbol)
		used += size
	}
	return builder.String()
}

func cutLeft(text string, width int) string {
	if width <= 0 {
		return ""
	}
	symbols := []rune(text)
	used := 0
	index := len(symbols)
	for index > 0 {
		size := runeWidth(symbols[index-1])
		if used+size > width {
			break
		}
		used += size
		index--
	}
	return string(symbols[index:])
}

// Truncate shortens text to width display columns, appending an ellipsis when
// anything was removed.
func Truncate(text string, width int, unicodeOK bool) string {
	if width <= 0 {
		return ""
	}
	plain := stripANSI(text)
	if DisplayWidth(plain) <= width {
		return text
	}

	ellipsis := ellipsisFor(unicodeOK)
	marker := DisplayWidth(ellipsis)
	// An ellipsis that leaves no room for text says only "something was here".
	// In a narrow column that is every heading at once, so the marker is spent
	// only when at least one character of the text survives beside it.
	if width <= marker {
		return cutRight(plain, width)
	}
	return cutRight(plain, width-marker) + ellipsis
}

// TruncateLeft is Truncate's mirror image: the ellipsis leads and the tail
// survives, which is what right-aligned numeric cells need.
func TruncateLeft(text string, width int, unicodeOK bool) string {
	if width <= 0 {
		return ""
	}
	plain := stripANSI(text)
	if DisplayWidth(plain) <= width {
		return text
	}

	ellipsis := ellipsisFor(unicodeOK)
	marker := DisplayWidth(ellipsis)
	if width <= marker {
		return cutLeft(plain, width)
	}
	return ellipsis + cutLeft(plain, width-marker)
}

// Pad widens text to width display columns. It never truncates.
func Pad(text string, width int, align Align) string {
	gap := width - DisplayWidth(text)
	if gap <= 0 {
		return text
	}
	padding := strings.Repeat(" ", gap)
	if align == AlignRight {
		return padding + text
	}
	return text + padding
}

// Wrap breaks text on spaces at width display columns, hard-cutting only words
// that cannot fit alone, and indents every line after the first by hanging.
func Wrap(text string, width int, hanging int) []string {
	if width <= 0 {
		width = 1
	}
	if hanging < 0 {
		hanging = 0
	}
	if hanging >= width {
		hanging = width - 1
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}

	continuation := width - hanging
	var chunks []string
	current := ""
	for _, word := range words {
		for {
			limit := width
			if len(chunks) > 0 {
				limit = continuation
			}
			gap := 0
			if current != "" {
				gap = 1
			}
			if DisplayWidth(current)+gap+DisplayWidth(word) <= limit {
				if current != "" {
					current += " "
				}
				current += word
				break
			}
			if current != "" {
				chunks = append(chunks, current)
				current = ""
				continue
			}
			head := cutRight(word, limit)
			if head == "" {
				head = string([]rune(word)[0])
			}
			chunks = append(chunks, head)
			word = strings.TrimPrefix(word, head)
			if word == "" {
				break
			}
		}
	}
	if current != "" {
		chunks = append(chunks, current)
	}
	if len(chunks) == 0 {
		return []string{""}
	}

	indent := strings.Repeat(" ", hanging)
	for index := 1; index < len(chunks); index++ {
		chunks[index] = indent + chunks[index]
	}
	return chunks
}
