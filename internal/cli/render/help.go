package render

import (
	"fmt"
	"io"
	"strings"
)

const (
	helpIndent    = 2
	helpGutter    = 2
	maxTermColumn = 28
)

// HelpItem is one flag, argument, or subcommand. Default and Envs are rendered
// here and nowhere else, so a help adapter must not also fold them into Help.
type HelpItem struct {
	Term    string
	Help    string
	Default string
	Envs    []string
}

type HelpSection struct {
	Title       string
	Description string
	Items       []HelpItem
}

// HelpDoc is a dependency-free model of a command's help. An adapter over a
// flag parser translates into this; render never sees the parser.
type HelpDoc struct {
	Usage    string
	Summary  string
	Detail   string
	Sections []HelpSection
	Footer   string
}

// Help renders doc. It is the one exported writer besides Present, because a
// flag parser owns the moment help is printed and cannot route through a View.
func Help(out io.Writer, style Style, doc HelpDoc) error {
	if out == nil {
		return ErrNoOutput
	}

	built := newDocument()
	if doc.Usage != "" {
		built.Line(RolePlain, style.Apply(RoleHeading, "Usage: ")+doc.Usage)
	}
	appendParagraph(built, style, doc.Summary, 0)
	appendParagraph(built, style, doc.Detail, 0)
	for _, section := range doc.Sections {
		appendSection(built, style, section)
	}
	if doc.Footer != "" {
		appendParagraph(built, style, doc.Footer, 0)
	}

	if err := built.render(out, style); err != nil {
		return fmt.Errorf("render help: %w", err)
	}
	return nil
}

func appendParagraph(doc *Document, style Style, text string, indent int) {
	if strings.TrimSpace(text) == "" {
		return
	}
	if doc.Blocks() > 0 {
		doc.Blank()
	}
	margin := strings.Repeat(" ", indent)
	for _, line := range Wrap(text, max(style.Width()-indent, minFieldValueSpan), 0) {
		doc.Line(RolePlain, margin+line)
	}
}

func appendSection(doc *Document, style Style, section HelpSection) {
	if len(section.Items) == 0 {
		return
	}
	if doc.Blocks() > 0 {
		doc.Blank()
	}
	if section.Title != "" {
		doc.Line(RoleHeading, section.Title)
	}
	if strings.TrimSpace(section.Description) != "" {
		for _, line := range Wrap(section.Description, max(style.Width()-helpIndent, minFieldValueSpan), 0) {
			doc.Line(RolePlain, strings.Repeat(" ", helpIndent)+line)
		}
	}

	termColumn := 0
	for _, item := range section.Items {
		termColumn = max(termColumn, DisplayWidth(item.Term))
	}
	termColumn = min(termColumn, maxTermColumn)

	margin := strings.Repeat(" ", helpIndent)
	helpColumn := helpIndent + termColumn + helpGutter
	helpSpan := max(style.Width()-helpColumn, minFieldValueSpan)
	continuation := strings.Repeat(" ", helpColumn)

	for _, item := range section.Items {
		term := style.Apply(RoleAccent, item.Term)
		lines := Wrap(itemHelp(item, style), helpSpan, 0)
		if lines[0] == "" && len(lines) == 1 {
			doc.Line(RolePlain, margin+term)
			continue
		}
		if DisplayWidth(item.Term) > termColumn {
			doc.Line(RolePlain, margin+term)
		} else {
			doc.Line(RolePlain, margin+Pad(term, termColumn, AlignLeft)+strings.Repeat(" ", helpGutter)+lines[0])
			lines = lines[1:]
		}
		for _, line := range lines {
			doc.Line(RolePlain, continuation+line)
		}
	}
}

func itemHelp(item HelpItem, style Style) string {
	text := item.Help
	if item.Default != "" {
		text += style.Apply(RoleMuted, fmt.Sprintf(" (default: %s)", item.Default))
	}
	if len(item.Envs) > 0 {
		names := make([]string, 0, len(item.Envs))
		for _, name := range item.Envs {
			names = append(names, "$"+name)
		}
		text += style.Apply(RoleMuted, " ("+strings.Join(names, ", ")+")")
	}
	return strings.TrimSpace(text)
}
