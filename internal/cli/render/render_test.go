package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func visible(text string) string {
	return strings.ReplaceAll(text, "\x1b", "^[")
}

func esc(role Role) string {
	return palette[role]
}

type fixturePayload struct {
	Name     string   `json:"name"`
	Note     string   `json:"note"`
	Counters []int    `json:"counters"`
	Tags     []string `json:"tags"`
}

type fixtureView struct {
	Of[fixturePayload]
}

func (view fixtureView) Describe(doc *Document) {
	doc.Heading("Overview")
	doc.Fields(Fields{Items: []Field{
		{Key: "name", Value: view.Value.Name},
		{Key: "note", Value: view.Value.Note},
	}})
	doc.Blank()
	doc.Table(Table{
		Columns: []Column{{Title: "tag"}, {Title: "count", Align: AlignRight}},
		Rows:    []Row{TextRow("alpha", "1"), TextRow("beta", "2")},
		Empty:   "no tags",
	})
	doc.Status(StatusOK, "ready")
}

func newFixtureView() fixtureView {
	return fixtureView{Of: Of[fixturePayload]{Value: fixturePayload{
		Name:     "blackbird",
		Note:     "tags & <ids> are not escaped",
		Counters: []int{1, 2},
		Tags:     []string{"alpha", "beta"},
	}}}
}

var _ View = fixtureView{}

type describeOnly struct{}

func (describeOnly) Describe(doc *Document) { doc.Line(RolePlain, "human only") }

// describeOnly satisfies only half of View; asserting it against View here must
// fail to compile, which is the type-level half of the dual-output guarantee.
var _ interface{ Describe(*Document) } = describeOnly{}

type silentView struct {
	Of[fixturePayload]
}

func (silentView) Describe(*Document) {}

type nilPayloadView struct {
	Of[any]
}

func (nilPayloadView) Describe(doc *Document) { doc.Line(RolePlain, "text") }

type typedNilView struct {
	Of[*fixturePayload]
}

func (typedNilView) Describe(doc *Document) { doc.Line(RolePlain, "text") }

type badPayloadView struct {
	Of[chan int]
}

func (badPayloadView) Describe(doc *Document) { doc.Line(RolePlain, "text") }

var errWriterFailed = errors.New("writer failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriterFailed }

const fixtureHumanGolden = `Overview
name  blackbird
note  tags & <ids> are not escaped

TAG    COUNT
alpha      1
beta       2
+ ready
`

const fixtureJSONGolden = `{
  "name": "blackbird",
  "note": "tags & <ids> are not escaped",
  "counters": [
    1,
    2
  ],
  "tags": [
    "alpha",
    "beta"
  ]
}
`

func TestPresentHumanGolden(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	if err := Present(Target{Out: &buffer, Style: PlainStyle(80)}, newFixtureView()); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := buffer.String(); got != fixtureHumanGolden {
		t.Fatalf("Present human output =\n%s\nwant\n%s", visible(got), visible(fixtureHumanGolden))
	}
}

func TestPresentJSONIsIndentedAndHTMLSafe(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	if err := Present(Target{Out: &buffer, Style: PlainStyle(80), JSON: true}, newFixtureView()); err != nil {
		t.Fatalf("Present: %v", err)
	}
	got := buffer.String()
	if got != fixtureJSONGolden {
		t.Fatalf("Present JSON output =\n%s\nwant\n%s", got, fixtureJSONGolden)
	}
	if strings.Contains(got, "\\u0026") || strings.Contains(got, "\\u003c") {
		t.Fatal("HTML escaping is enabled")
	}
	if strings.Count(got, "\n\n") != 0 || !strings.HasSuffix(got, "}\n") {
		t.Fatalf("JSON output has unexpected trailing bytes: %q", got)
	}
}

func TestPresentJSONAndHumanShareOnePayload(t *testing.T) {
	t.Parallel()

	view := newFixtureView()
	view.Value.Name = "changed"

	var human, machine bytes.Buffer
	if err := Present(Target{Out: &human, Style: PlainStyle(80)}, view); err != nil {
		t.Fatalf("Present human: %v", err)
	}
	if err := Present(Target{Out: &machine, Style: PlainStyle(80), JSON: true}, view); err != nil {
		t.Fatalf("Present json: %v", err)
	}
	if !strings.Contains(human.String(), "changed") {
		t.Fatalf("human projection missed the change:\n%s", human.String())
	}
	if !strings.Contains(machine.String(), `"name": "changed"`) {
		t.Fatalf("machine projection missed the change:\n%s", machine.String())
	}
}

func TestPresentRejectsMissingWriterAndView(t *testing.T) {
	t.Parallel()

	if err := Present(Target{}, newFixtureView()); !errors.Is(err, ErrNoOutput) {
		t.Fatalf("Present with no writer = %v, want ErrNoOutput", err)
	}
	var buffer bytes.Buffer
	if err := Present(Target{Out: &buffer}, nil); err == nil {
		t.Fatal("Present accepted a nil view")
	}
}

func TestPresentWrapsWriterErrors(t *testing.T) {
	t.Parallel()

	for _, machine := range [...]bool{false, true} {
		err := Present(Target{Out: failingWriter{}, Style: PlainStyle(80), JSON: machine}, newFixtureView())
		if err == nil {
			t.Fatalf("Present(JSON=%t) returned no error", machine)
		}
		if !errors.Is(err, errWriterFailed) {
			t.Fatalf("Present(JSON=%t) error %v does not unwrap to the writer failure", machine, err)
		}
	}
}

func TestPresentJSONEncodeErrorIsWrapped(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	err := Present(Target{Out: &buffer, Style: PlainStyle(80), JSON: true}, badPayloadView{})
	if err == nil {
		t.Fatal("Present encoded an unencodable payload")
	}
	if !strings.HasPrefix(err.Error(), "encode json payload:") {
		t.Fatalf("error %q is missing its context", err)
	}
	var unsupported *json.UnsupportedTypeError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error %v does not unwrap to *json.UnsupportedTypeError", err)
	}
}

func TestWatchFrameClearsOnlyOnTerminal(t *testing.T) {
	t.Parallel()

	var terminal bytes.Buffer
	style := NewStyle(Capabilities{TTY: true, Width: 80})
	if err := WatchFrame(Target{Out: &terminal, Style: style}, newFixtureView()); err != nil {
		t.Fatalf("WatchFrame: %v", err)
	}
	if got := terminal.String(); got != "\x1b[H\x1b[2J"+fixtureHumanGolden {
		t.Fatalf("WatchFrame on a terminal =\n%s", visible(got))
	}

	var piped bytes.Buffer
	if err := WatchFrame(Target{Out: &piped, Style: PlainStyle(80)}, newFixtureView()); err != nil {
		t.Fatalf("WatchFrame: %v", err)
	}
	if got := piped.String(); got != fixtureHumanGolden {
		t.Fatalf("WatchFrame off a terminal =\n%s", visible(got))
	}

	var machine bytes.Buffer
	if err := WatchFrame(Target{Out: &machine, Style: style, JSON: true}, newFixtureView()); err != nil {
		t.Fatalf("WatchFrame: %v", err)
	}
	if strings.Contains(machine.String(), "\x1b") {
		t.Fatal("WatchFrame emitted an escape into JSON output")
	}

	if err := WatchFrame(Target{Style: style}, newFixtureView()); !errors.Is(err, ErrNoOutput) {
		t.Fatalf("WatchFrame with no writer = %v, want ErrNoOutput", err)
	}
	if err := WatchFrame(Target{Out: failingWriter{}, Style: style}, newFixtureView()); !errors.Is(err, errWriterFailed) {
		t.Fatalf("WatchFrame writer error = %v", err)
	}
}

func TestConform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		view    View
		wantErr string
	}{
		{name: "complete view", view: newFixtureView()},
		{name: "nil view", wantErr: "view is nil"},
		{name: "silent describe", view: silentView{}, wantErr: "describes no human output"},
		{name: "nil payload", view: nilPayloadView{}, wantErr: "no machine payload"},
		{name: "typed nil payload", view: typedNilView{}, wantErr: "marshals to null"},
		{name: "unmarshalable payload", view: badPayloadView{}, wantErr: "marshal payload"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := Conform(test.view)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Conform: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Conform error = %v, want one containing %q", err, test.wantErr)
			}
		})
	}
}

func TestDocumentChainingAndBlockCount(t *testing.T) {
	t.Parallel()

	doc := newDocument()
	if doc.Blocks() != 0 {
		t.Fatalf("fresh document has %d blocks", doc.Blocks())
	}
	chained := doc.
		Heading("h").
		Line(RolePlain, "l").
		Linef(RolePlain, "n=%d", 2).
		Blank().
		Status(StatusOK, "s").
		Fields(Fields{Items: []Field{{Key: "k", Value: "v"}}}).
		Table(Table{Columns: []Column{{Title: "c"}}}).
		Panel(Panel{Title: "p"}).
		PanelRow(Panel{Title: "a"}, Panel{Title: "b"})
	if chained != doc {
		t.Fatal("builders did not return the receiver")
	}
	if doc.Blocks() != 9 {
		t.Fatalf("Blocks() = %d, want 9", doc.Blocks())
	}
	if sub := doc.Sub(); sub == doc || sub.Blocks() != 0 {
		t.Fatal("Sub did not return a fresh document")
	}

	var buffer bytes.Buffer
	if err := doc.render(&buffer, PlainStyle(80)); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buffer.String(), "n=2") {
		t.Fatalf("Linef output missing:\n%s", buffer.String())
	}
}

func TestDocumentRenderEndsWithExactlyOneNewline(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	if err := newDocument().render(&buffer, PlainStyle(80)); err != nil {
		t.Fatalf("render: %v", err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("empty document rendered %q", buffer.String())
	}

	buffer.Reset()
	doc := newDocument().Line(RolePlain, "one").Blank()
	if err := doc.render(&buffer, PlainStyle(80)); err != nil {
		t.Fatalf("render: %v", err)
	}
	if got := buffer.String(); got != "one\n\n" {
		t.Fatalf("render = %q, want %q", got, "one\n\n")
	}
	if got := fixtureHumanGolden; !strings.HasSuffix(got, "\n") || strings.HasSuffix(got, "\n\n") {
		t.Fatalf("golden does not end with exactly one newline: %q", got)
	}
}

func TestDocumentTrimsTrailingSpaces(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	doc := newDocument().Line(RolePlain, "padded   ")
	if err := doc.render(&buffer, PlainStyle(80)); err != nil {
		t.Fatalf("render: %v", err)
	}
	if got := buffer.String(); got != "padded\n" {
		t.Fatalf("render = %q, want %q", got, "padded\n")
	}
}

func TestDocumentSubRendersNestedInsidePanel(t *testing.T) {
	t.Parallel()

	doc := newDocument()
	body := doc.Sub()
	body.Table(Table{
		Columns: []Column{{Title: "agent"}, {Title: "state"}},
		Rows:    []Row{TextRow("planner", "active")},
	})
	doc.Panel(Panel{Title: "Agents", Body: body})

	var buffer bytes.Buffer
	if err := doc.render(&buffer, PlainStyle(30)); err != nil {
		t.Fatalf("render: %v", err)
	}
	want := "" +
		"+- Agents -------------------+\n" +
		"| AGENT    STATE             |\n" +
		"| planner  active            |\n" +
		"+----------------------------+\n"
	if got := buffer.String(); got != want {
		t.Fatalf("nested panel =\n%s\nwant\n%s", got, want)
	}
}

func TestStyledOutputCarriesRolesWithoutChangingGeometry(t *testing.T) {
	t.Parallel()

	style := NewStyle(Capabilities{Color: true, Width: 80})
	var styled bytes.Buffer
	if err := Present(Target{Out: &styled, Style: style}, newFixtureView()); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !strings.Contains(styled.String(), esc(RoleHeading)+"Overview"+ansiReset) {
		t.Fatalf("heading is not styled:\n%s", visible(styled.String()))
	}
	if !strings.Contains(styled.String(), esc(RoleOK)+"+"+ansiReset+" ready") {
		t.Fatalf("status glyph is not styled:\n%s", visible(styled.String()))
	}

	var lines []string
	for _, line := range strings.Split(strings.TrimSuffix(styled.String(), "\n"), "\n") {
		lines = append(lines, stripANSI(line))
	}
	if got := strings.Join(lines, "\n") + "\n"; got != fixtureHumanGolden {
		t.Fatalf("styled geometry differs once stripped:\n%s", visible(got))
	}
}
