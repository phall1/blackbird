// Package render draws Blackbird's terminal output. It depends on nothing
// outside the standard library: capabilities, width, and the clock are all
// supplied by the caller, so every rendering decision is a pure function of
// its inputs and can be asserted byte for byte.
package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var ErrNoOutput = errors.New("render target has no output writer")

// Target is where a command result goes and how it is dressed.
type Target struct {
	Out   io.Writer
	Err   io.Writer
	Style Style
	JSON  bool
}

// View is the single contract every command result satisfies. Describe builds
// the human projection; Payload returns the machine projection. Present accepts
// nothing else, so a command that renders at all renders both.
type View interface {
	Describe(doc *Document)
	Payload() any
}

// Of supplies Payload for a typed result. Embedding it keeps the JSON type
// named at the declaration site and leaves the author only Describe to write.
type Of[T any] struct {
	Value T
}

func (of Of[T]) Payload() any { return of.Value }

// Present writes view to target in exactly one form. It is the only exported
// sink for a command result: Document cannot be constructed, rendered, or
// flattened from outside this package.
func Present(target Target, view View) error {
	if target.Out == nil {
		return ErrNoOutput
	}
	if view == nil {
		return errors.New("present requires a view")
	}

	if target.JSON {
		encoder := json.NewEncoder(target.Out)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(view.Payload()); err != nil {
			return fmt.Errorf("encode json payload: %w", err)
		}
		return nil
	}

	doc := newDocument()
	view.Describe(doc)
	if err := doc.render(target.Out, target.Style); err != nil {
		return fmt.Errorf("render document: %w", err)
	}
	return nil
}

// WatchFrame renders one frame of a --watch loop: the home-and-erase sequence
// when the stream is a terminal, then the view. Keeping the escape here is what
// lets the command layer redraw without reaching for an io.Writer of its own.
func WatchFrame(target Target, view View) error {
	if target.Out == nil {
		return ErrNoOutput
	}
	if clear := target.Style.ClearScreen(); clear != "" && !target.JSON {
		if _, err := io.WriteString(target.Out, clear); err != nil {
			return fmt.Errorf("write frame prefix: %w", err)
		}
	}
	return Present(target, view)
}

// Conform reports whether view produces both projections. Command tests call it
// so a half-built view fails at test time as well as compile time.
func Conform(view View) error {
	if view == nil {
		return errors.New("view is nil")
	}

	doc := newDocument()
	view.Describe(doc)
	if doc.Blocks() == 0 {
		return errors.New("view describes no human output")
	}

	payload := view.Payload()
	if payload == nil {
		return errors.New("view has no machine payload")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	if string(encoded) == "null" {
		return errors.New("view payload marshals to null")
	}
	return nil
}

type block interface {
	write(writer *lineWriter, style Style)
}

type lineWriter struct {
	lines []string
}

func (writer *lineWriter) add(text string) {
	writer.lines = append(writer.lines, strings.TrimRight(text, " "))
}

func (writer *lineWriter) addAll(lines []string) {
	for _, line := range lines {
		writer.add(line)
	}
}

// Document is the human projection under construction. Command code receives
// one through View.Describe and never builds or renders one directly.
type Document struct {
	blocks []block
}

func newDocument() *Document { return &Document{} }

// Sub returns an empty document for nesting inside a Panel body.
func (doc *Document) Sub() *Document { return &Document{} }

func (doc *Document) Blocks() int { return len(doc.blocks) }

func (doc *Document) Heading(text string) *Document {
	doc.blocks = append(doc.blocks, headingBlock{text: text})
	return doc
}

func (doc *Document) Line(role Role, text string) *Document {
	doc.blocks = append(doc.blocks, lineBlock{role: role, text: text})
	return doc
}

func (doc *Document) Wrapped(role Role, text string) *Document {
	doc.blocks = append(doc.blocks, foldBlock{role: role, text: text})
	return doc
}

func (doc *Document) Linef(role Role, format string, args ...any) *Document {
	return doc.Line(role, fmt.Sprintf(format, args...))
}

// Raw emits text exactly as given, exempt from the width clipping every other
// block obeys. It exists for payloads whose bytes are the product rather than a
// report of one — a generated completion script clipped to the terminal width
// is a syntax error, not a tidier script.
func (doc *Document) Raw(text string) *Document {
	doc.blocks = append(doc.blocks, rawBlock{text: text})
	return doc
}

func (doc *Document) Blank() *Document {
	doc.blocks = append(doc.blocks, blankBlock{})
	return doc
}

func (doc *Document) Status(status Status, text string) *Document {
	doc.blocks = append(doc.blocks, statusBlock{status: status, text: text})
	return doc
}

func (doc *Document) Fields(fields Fields) *Document {
	doc.blocks = append(doc.blocks, fieldsBlock{fields: fields})
	return doc
}

func (doc *Document) Table(table Table) *Document {
	doc.blocks = append(doc.blocks, tableBlock{table: table})
	return doc
}

func (doc *Document) Panel(panel Panel) *Document {
	doc.blocks = append(doc.blocks, panelBlock{panel: panel})
	return doc
}

func (doc *Document) PanelRow(panels ...Panel) *Document {
	doc.blocks = append(doc.blocks, panelRowBlock{panels: panels})
	return doc
}

func (doc *Document) write(writer *lineWriter, style Style) {
	for _, item := range doc.blocks {
		item.write(writer, style)
	}
}

func (doc *Document) lines(style Style) []string {
	writer := &lineWriter{}
	doc.write(writer, style)
	return writer.lines
}

func (doc *Document) render(out io.Writer, style Style) error {
	lines := doc.lines(style)
	if len(lines) == 0 {
		return nil
	}
	if _, err := io.WriteString(out, strings.Join(lines, "\n")+"\n"); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

type headingBlock struct {
	text string
}

func (item headingBlock) write(writer *lineWriter, style Style) {
	writer.add(style.Apply(RoleHeading, Truncate(item.text, style.Width(), style.Unicode())))
}

type lineBlock struct {
	role Role
	text string
}

// Line is verbatim: panels compose it at their own inner width, and help emits
// space-aligned columns through it, so folding here would collapse padding that
// carries meaning. Prose that can overrun belongs in Wrapped.
func (item lineBlock) write(writer *lineWriter, style Style) {
	writer.add(style.Apply(item.role, item.text))
}

type foldBlock struct {
	role Role
	text string
}

// Wrapped folds prose to the style's width instead of clipping it: a doctor
// remedy is long enough to overrun a default terminal, and truncating one
// throws away the command the user is being told to run. Leading indentation is
// preserved and carried onto continuation lines.
func (item foldBlock) write(writer *lineWriter, style Style) {
	if DisplayWidth(item.text) <= style.Width() {
		writer.add(style.Apply(item.role, item.text))
		return
	}
	body := strings.TrimLeft(item.text, " ")
	indent := strings.Repeat(" ", len(item.text)-len(body))
	for _, line := range Wrap(body, style.Width()-len(indent), 0) {
		writer.add(style.Apply(item.role, indent+line))
	}
}

type rawBlock struct {
	text string
}

func (item rawBlock) write(writer *lineWriter, _ Style) {
	writer.add(item.text)
}

type blankBlock struct{}

func (blankBlock) write(writer *lineWriter, _ Style) {
	writer.add("")
}

type statusBlock struct {
	status Status
	text   string
}

func (item statusBlock) write(writer *lineWriter, style Style) {
	// The glyph and its separating space are part of the rendered line, so the
	// text budget is what remains after them, and continuation lines align under
	// the text rather than under the glyph.
	hanging := DisplayWidth(style.Glyph(item.status)) + 1
	if hanging+DisplayWidth(item.text) <= style.Width() {
		writer.add(style.StatusLine(item.status, item.text))
		return
	}
	lines := Wrap(item.text, style.Width()-hanging, 0)
	writer.add(style.StatusLine(item.status, lines[0]))
	for _, line := range lines[1:] {
		writer.add(strings.Repeat(" ", hanging) + line)
	}
}
