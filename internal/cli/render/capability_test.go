package render

import (
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"
)

type stubFileInfo struct {
	mode fs.FileMode
}

func (info stubFileInfo) Name() string       { return "stub" }
func (info stubFileInfo) Size() int64        { return 0 }
func (info stubFileInfo) Mode() fs.FileMode  { return info.mode }
func (info stubFileInfo) ModTime() time.Time { return time.Time{} }
func (info stubFileInfo) IsDir() bool        { return false }
func (info stubFileInfo) Sys() any           { return nil }

type stubDevice struct {
	mode fs.FileMode
	err  error
}

func (device stubDevice) Stat() (fs.FileInfo, error) {
	if device.err != nil {
		return nil, device.err
	}
	return stubFileInfo{mode: device.mode}, nil
}

func environment(pairs map[string]string) Env {
	return func(key string) (string, bool) {
		value, ok := pairs[key]
		return value, ok
	}
}

func terminalDevice() Device { return stubDevice{mode: os.ModeCharDevice | os.ModeDevice} }

func TestParseColorChoiceAndUnmarshalText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		want      ColorChoice
		wantError bool
	}{
		{name: "empty is auto", input: "", want: ColorAuto},
		{name: "auto", input: "auto", want: ColorAuto},
		{name: "always", input: "always", want: ColorAlways},
		{name: "never", input: "never", want: ColorNever},
		{name: "yes rejected", input: "yes", wantError: true},
		{name: "one rejected", input: "1", wantError: true},
		{name: "capitalized rejected", input: "Always", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseColorChoice(test.input)
			if (err != nil) != test.wantError {
				t.Fatalf("ParseColorChoice(%q) error = %v, wantError=%t", test.input, err, test.wantError)
			}
			if test.wantError {
				return
			}
			if got != test.want {
				t.Fatalf("ParseColorChoice(%q) = %q, want %q", test.input, got, test.want)
			}

			choice := ColorNever
			if err := choice.UnmarshalText([]byte(test.input)); err != nil {
				t.Fatalf("UnmarshalText(%q): %v", test.input, err)
			}
			if choice != test.want {
				t.Fatalf("UnmarshalText(%q) left %q, want %q", test.input, choice, test.want)
			}
			if choice.String() != string(test.want) {
				t.Fatalf("String() = %q, want %q", choice.String(), test.want)
			}
		})
	}
}

func TestUnmarshalTextLeavesReceiverOnFailure(t *testing.T) {
	t.Parallel()

	choice := ColorAlways
	if err := choice.UnmarshalText([]byte("magenta")); err == nil {
		t.Fatal("UnmarshalText accepted an unknown colour choice")
	}
	if choice != ColorAlways {
		t.Fatalf("receiver mutated to %q", choice)
	}
	var zero ColorChoice
	if zero.String() != "auto" {
		t.Fatalf("zero ColorChoice String() = %q, want auto", zero.String())
	}
}

func TestIsTerminalClassifiesStreams(t *testing.T) {
	t.Parallel()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("open pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	tests := []struct {
		name   string
		device Device
		want   bool
	}{
		{name: "nil device", device: nil},
		{name: "pipe", device: writer},
		{name: "stat error", device: stubDevice{err: errors.New("closed")}},
		{name: "regular file", device: stubDevice{mode: 0}},
		{name: "char device only", device: stubDevice{mode: os.ModeCharDevice}},
		{name: "named pipe", device: stubDevice{mode: os.ModeNamedPipe}},
		{name: "character device", device: terminalDevice(), want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := IsTerminal(test.device); got != test.want {
				t.Fatalf("IsTerminal() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestDetectColorPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		choice ColorChoice
		env    map[string]string
		tty    bool
		want   bool
	}{
		{name: "never beats force", choice: ColorNever, env: map[string]string{"CLICOLOR_FORCE": "1"}, tty: true},
		{name: "always beats no color", choice: ColorAlways, env: map[string]string{"NO_COLOR": "1"}, want: true},
		{name: "no color beats force", env: map[string]string{"NO_COLOR": "1", "CLICOLOR_FORCE": "1"}, tty: true},
		{name: "empty no color is absent", env: map[string]string{"NO_COLOR": ""}, tty: true, want: true},
		{name: "force zero falls through", env: map[string]string{"CLICOLOR_FORCE": "0"}},
		{name: "force enables without tty", env: map[string]string{"CLICOLOR_FORCE": "1"}, want: true},
		{name: "dumb terminal", env: map[string]string{"TERM": "dumb"}, tty: true},
		{name: "auto on tty", choice: ColorAuto, tty: true, want: true},
		{name: "auto off tty", choice: ColorAuto},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			options := Options{Color: test.choice, Env: environment(test.env)}
			if test.tty {
				options.Device = terminalDevice()
			}
			if got := Detect(options).Color; got != test.want {
				t.Fatalf("Detect().Color = %t, want %t", got, test.want)
			}
		})
	}
}

func TestDetectUnicodeAndASCIIFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		ascii bool
		env   map[string]string
		tty   bool
		want  bool
	}{
		{name: "ascii forced", ascii: true, env: map[string]string{"LANG": "en_US.UTF-8"}, tty: true},
		{name: "dumb terminal", env: map[string]string{"TERM": "dumb"}, tty: true},
		{name: "not a terminal", env: map[string]string{"LANG": "en_US.UTF-8"}},
		{name: "posix locale", env: map[string]string{"LC_ALL": "C"}, tty: true},
		{name: "utf8 lang", env: map[string]string{"LANG": "en_US.UTF-8"}, tty: true, want: true},
		{name: "utf8 without dash", env: map[string]string{"LANG": "en_US.utf8"}, tty: true, want: true},
		{name: "absent locale", tty: true, want: true},
		{name: "empty locale skipped", env: map[string]string{"LC_ALL": "", "LANG": "en_US.UTF-8"}, tty: true, want: true},
		{name: "lc all overrides lang", env: map[string]string{"LC_ALL": "en_US.UTF-8", "LANG": "C"}, tty: true, want: true},
		{name: "lc ctype wins", env: map[string]string{"LC_CTYPE": "C", "LANG": "en_US.UTF-8"}, tty: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			options := Options{ASCII: test.ascii, Env: environment(test.env)}
			if test.tty {
				options.Device = terminalDevice()
			}
			if got := Detect(options).Unicode; got != test.want {
				t.Fatalf("Detect().Unicode = %t, want %t", got, test.want)
			}
		})
	}
}

func TestDetectWidthPrecedenceAndClamping(t *testing.T) {
	t.Parallel()

	probe := func(width int, ok bool) func() (int, bool) {
		return func() (int, bool) { return width, ok }
	}

	tests := []struct {
		name    string
		width   int
		env     map[string]string
		probe   func() (int, bool)
		want    int
		noProbe bool
	}{
		{name: "explicit wins", width: 120, env: map[string]string{"COLUMNS": "200"}, probe: probe(150, true), want: 120},
		{name: "columns beats probe", env: map[string]string{"COLUMNS": "100"}, probe: probe(150, true), want: 100},
		{name: "probe beats fallback", probe: probe(150, true), want: 150},
		{name: "no source", noProbe: true, want: FallbackWidth},
		{name: "columns not a number", env: map[string]string{"COLUMNS": "abc"}, probe: probe(90, true), want: 90},
		{name: "columns zero", env: map[string]string{"COLUMNS": "0"}, probe: probe(90, true), want: 90},
		{name: "probe reports zero", probe: probe(0, true), want: FallbackWidth},
		{name: "probe reports failure", probe: probe(90, false), want: FallbackWidth},
		{name: "explicit clamped low", width: 10, want: MinWidth},
		{name: "explicit clamped high", width: 4000, want: MaxWidth},
		{name: "columns clamped low", env: map[string]string{"COLUMNS": "10"}, want: MinWidth},
		{name: "columns clamped high", env: map[string]string{"COLUMNS": "4000"}, want: MaxWidth},
		{name: "probe clamped low", probe: probe(10, true), want: MinWidth},
		{name: "probe clamped high", probe: probe(4000, true), want: MaxWidth},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			options := Options{Width: test.width, Env: environment(test.env)}
			if !test.noProbe {
				options.WidthProbe = test.probe
			}
			if got := Detect(options).Width; got != test.want {
				t.Fatalf("Detect().Width = %d, want %d", got, test.want)
			}
		})
	}
}

func TestDetectZeroOptionsIsSafe(t *testing.T) {
	t.Parallel()

	got := Detect(Options{})
	want := Capabilities{Width: FallbackWidth}
	if got != want {
		t.Fatalf("Detect(Options{}) = %+v, want %+v", got, want)
	}
}
