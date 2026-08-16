package render

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestStripANSIRemovesCSISequences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "no escapes", input: "plain text", want: "plain text"},
		{name: "single sequence", input: "\x1b[32mok\x1b[0m", want: "ok"},
		{name: "adjacent sequences", input: "\x1b[1m\x1b[36mid\x1b[0m", want: "id"},
		{name: "parameterised", input: "\x1b[38;5;120mx\x1b[0m", want: "x"},
		{name: "trailing bare escape", input: "tail\x1b", want: "tail"},
		{name: "non csi escape", input: "a\x1bZb", want: "ab"},
		{name: "unterminated csi", input: "a\x1b[38;5", want: "a"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := stripANSI(test.input); got != test.want {
				t.Fatalf("stripANSI(%q) = %q, want %q", visible(test.input), visible(got), test.want)
			}
		})
	}
}

func TestDisplayWidth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  int
	}{
		{name: "empty", input: "", want: 0},
		{name: "ascii", input: "abc", want: 3},
		{name: "styled ascii", input: "\x1b[32mok\x1b[0m", want: 2},
		{name: "combining acute", input: "e\u0301", want: 1},
		{name: "zero width space", input: "a\u200bb", want: 2},
		{name: "control character", input: "a\tb", want: 2},
		{name: "hangul jamo", input: "\u1100", want: 2},
		{name: "cjk ideographs", input: "\u65e5\u672c\u8a9e", want: 6},
		{name: "fullwidth latin", input: "\uff21\uff22", want: 4},
		{name: "hiragana", input: "\u3042", want: 2},
		{name: "mixed", input: "ab\u65e5", want: 4},
		{name: "rocket emoji", input: "\U0001f680", want: 2},
		{name: "text presentation check", input: "\u2714", want: 1},
		{name: "text presentation cross", input: "\u2716", want: 1},
		{name: "arrow", input: "\u2192", want: 1},
		{name: "supplementary ideograph", input: "\U00020000", want: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := DisplayWidth(test.input); got != test.want {
				t.Fatalf("DisplayWidth(%q) = %d, want %d", test.input, got, test.want)
			}
		})
	}
}

func TestWideRunesTableIsWellFormed(t *testing.T) {
	t.Parallel()

	previous := rune(-1)
	for _, entry := range wideRunes.R16 {
		if entry.Stride != 1 {
			t.Fatalf("R16 range %04x-%04x has stride %d, want 1", entry.Lo, entry.Hi, entry.Stride)
		}
		if rune(entry.Lo) <= previous || entry.Hi < entry.Lo {
			t.Fatalf("R16 range %04x-%04x is out of order", entry.Lo, entry.Hi)
		}
		previous = rune(entry.Hi)
		for _, sample := range [...]rune{rune(entry.Lo), rune(entry.Hi)} {
			if runeWidth(sample) != 2 && runeWidth(sample) != 0 {
				t.Fatalf("rune %04x in a wide range has width %d", sample, runeWidth(sample))
			}
		}
	}

	previous = rune(-1)
	for _, entry := range wideRunes.R32 {
		if entry.Stride != 1 {
			t.Fatalf("R32 range %05x-%05x has stride %d, want 1", entry.Lo, entry.Hi, entry.Stride)
		}
		if entry.Lo <= 0xffff {
			t.Fatalf("R32 range %05x-%05x belongs in R16", entry.Lo, entry.Hi)
		}
		if rune(entry.Lo) <= previous || entry.Hi < entry.Lo {
			t.Fatalf("R32 range %05x-%05x is out of order", entry.Lo, entry.Hi)
		}
		previous = rune(entry.Hi)
		if got := DisplayWidth(string(rune(entry.Lo))); got != 2 {
			t.Fatalf("DisplayWidth(%05x) = %d, want 2", entry.Lo, got)
		}
	}
}

func TestTruncateAddsEllipsisAtBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		width     int
		unicodeOK bool
		want      string
	}{
		{name: "exact fit", input: "abcde", width: 5, want: "abcde"},
		{name: "shorter", input: "abc", width: 5, want: "abc"},
		{name: "ascii ellipsis", input: "abcdef", width: 5, want: "ab..."},
		{name: "unicode ellipsis", input: "abcdef", width: 5, unicodeOK: true, want: "abcd\u2026"},
		{name: "width equals ellipsis keeps text", input: "abcdef", width: 3, want: "abc"},
		{name: "width below ellipsis", input: "abcdef", width: 2, want: "ab"},
		{name: "zero width", input: "abcdef", width: 0, want: ""},
		{name: "negative width", input: "abcdef", width: -1, want: ""},
		{name: "wide runes never split", input: "\u65e5\u672c\u8a9e", width: 5, unicodeOK: true, want: "\u65e5\u672c\u2026"},
		{name: "wide runes ascii ellipsis", input: "\u65e5\u672c\u8a9e", width: 5, want: "\u65e5..."},
		{name: "styled input is flattened", input: "\x1b[32mabcdef\x1b[0m", width: 5, want: "ab..."},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := Truncate(test.input, test.width, test.unicodeOK)
			if got != test.want {
				t.Fatalf("Truncate(%q, %d, %t) = %q, want %q", test.input, test.width, test.unicodeOK, got, test.want)
			}
			if test.width > 0 && DisplayWidth(got) > test.width {
				t.Fatalf("Truncate overflowed: %q is %d columns, want at most %d", got, DisplayWidth(got), test.width)
			}
		})
	}
}

func TestTruncateLeftKeepsTail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		width     int
		unicodeOK bool
		want      string
	}{
		{name: "exact fit", input: "12345", width: 5, want: "12345"},
		{name: "ascii ellipsis", input: "1234567", width: 5, want: "...67"},
		{name: "unicode ellipsis", input: "1234567", width: 5, unicodeOK: true, want: "\u20264567"},
		{name: "width equals ellipsis keeps text", input: "1234567", width: 3, want: "567"},
		{name: "width below ellipsis", input: "1234567", width: 2, want: "67"},
		{name: "zero width", input: "1234567", width: 0, want: ""},
		{name: "wide runes never split", input: "\u65e5\u672c\u8a9e", width: 4, unicodeOK: true, want: "\u2026\u8a9e"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := TruncateLeft(test.input, test.width, test.unicodeOK)
			if got != test.want {
				t.Fatalf("TruncateLeft(%q, %d, %t) = %q, want %q", test.input, test.width, test.unicodeOK, got, test.want)
			}
			if test.width > 0 && DisplayWidth(got) > test.width {
				t.Fatalf("TruncateLeft overflowed: %q is %d columns", got, DisplayWidth(got))
			}
		})
	}
}

func TestPadAlignsBothDirections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		width int
		align Align
		want  string
	}{
		{name: "left", input: "ab", width: 5, align: AlignLeft, want: "ab   "},
		{name: "right", input: "ab", width: 5, align: AlignRight, want: "   ab"},
		{name: "exact", input: "abcde", width: 5, want: "abcde"},
		{name: "already wider", input: "abcdef", width: 5, want: "abcdef"},
		{name: "styled counts display width", input: "\x1b[32mab\x1b[0m", width: 4, want: "\x1b[32mab\x1b[0m  "},
		{name: "wide runes", input: "\u65e5", width: 4, want: "\u65e5  "},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := Pad(test.input, test.width, test.align); got != test.want {
				t.Fatalf("Pad(%q, %d) = %q, want %q", visible(test.input), test.width, visible(got), visible(test.want))
			}
		})
	}
}

func TestWrapHangingIndent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		width   int
		hanging int
		want    []string
	}{
		{name: "empty", input: "", width: 10, want: []string{""}},
		{name: "whitespace only", input: "   ", width: 10, want: []string{""}},
		{name: "fits", input: "one two", width: 10, want: []string{"one two"}},
		{name: "wraps on spaces", input: "one two three four", width: 10, want: []string{"one two", "three four"}},
		{name: "hanging indent", input: "alpha beta gamma", width: 12, hanging: 3, want: []string{"alpha beta", "   gamma"}},
		{name: "long word hard cut", input: "supercalifragilistic", width: 8, want: []string{"supercal", "ifragili", "stic"}},
		{name: "long word after text", input: "hi supercalifragilistic", width: 8, want: []string{"hi", "supercal", "ifragili", "stic"}},
		{name: "zero width is one column", input: "ab", width: 0, want: []string{"a", "b"}},
		{name: "hanging clamped to width", input: "ab cd", width: 2, hanging: 9, want: []string{"ab", " c", " d"}},
		{name: "negative hanging", input: "one two", width: 4, hanging: -3, want: []string{"one", "two"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := Wrap(test.input, test.width, test.hanging)
			if !slices.Equal(got, test.want) {
				t.Fatalf("Wrap(%q, %d, %d) = %q, want %q", test.input, test.width, test.hanging, got, test.want)
			}
		})
	}
}

func TestWrapPreservesStyledSuffixes(t *testing.T) {
	t.Parallel()

	got := Wrap("Colorize output. \x1b[2m(default: auto)\x1b[0m", 40, 0)
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "\x1b[2m") || !strings.Contains(joined, "\x1b[0m") {
		t.Fatalf("Wrap stripped styling: %q", visible(joined))
	}
}

func FuzzWidthArithmetic(f *testing.F) {
	seeds := []string{
		"",
		"plain",
		"\x1b[32mok\x1b[0m",
		"e\u0301",
		"\u65e5\u672c\u8a9e",
		"\uff21\uff22",
		"\U0001f680\U0001f9ff",
		"a\u200bb\tc",
		"\x1b[",
		strings.Repeat("\u3042", 40),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		width := DisplayWidth(text)
		if width < 0 || width > 2*utf8.RuneCountInString(text) {
			t.Fatalf("DisplayWidth(%q) = %d is out of bounds", text, width)
		}
		for _, limit := range [...]int{0, 1, 5, 40} {
			for _, unicodeOK := range [...]bool{false, true} {
				if got := DisplayWidth(Truncate(text, limit, unicodeOK)); got > limit {
					t.Fatalf("Truncate(%q, %d, %t) is %d columns", text, limit, unicodeOK, got)
				}
				if got := DisplayWidth(TruncateLeft(text, limit, unicodeOK)); got > limit {
					t.Fatalf("TruncateLeft(%q, %d, %t) is %d columns", text, limit, unicodeOK, got)
				}
			}
			if limit > 0 {
				for _, line := range Wrap(text, limit, 0) {
					if got := DisplayWidth(line); got > limit && utf8.RuneCountInString(line) > 1 {
						t.Fatalf("Wrap(%q, %d) produced a %d-column line %q", text, limit, got, line)
					}
				}
			}
		}
	})
}
