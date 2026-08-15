// Package konghelp maps Kong's parse model onto render's help document. It is
// the only place the two vocabularies meet: render never sees a parser type and
// the command grammar never formats a line.
package konghelp

import (
	"fmt"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/phall1/blackbird/internal/cli/render"
)

const (
	commandsTitle  = "Commands"
	maxPlaceholder = 24
)

// Printer returns the HelpPrinter Kong calls for --help and for the help
// command. It writes through ctx.Stdout so kong.Writers redirects it in tests.
func Printer(style render.Style, footer string) kong.HelpPrinter {
	return func(options kong.HelpOptions, ctx *kong.Context) error {
		if err := render.Help(ctx.Stdout, style, Document(options, ctx, footer)); err != nil {
			return fmt.Errorf("print help: %w", err)
		}
		return nil
	}
}

// Document projects the selected node onto a help document. Defaults and
// environment names are carried as fields, never folded into the help text,
// because render owns how they are rendered.
func Document(options kong.HelpOptions, ctx *kong.Context, footer string) render.HelpDoc {
	node := ctx.Selected()
	if node == nil {
		node = ctx.Model.Node
	}

	doc := render.HelpDoc{
		Usage:   usage(ctx.Model.Name, node),
		Summary: node.Help,
		Detail:  node.Detail,
	}
	if node.Type == kong.ApplicationNode {
		doc.Summary = ctx.Model.Help
		doc.Footer = footer
	}
	doc.Sections = append(doc.Sections, argumentSection(node)...)
	doc.Sections = append(doc.Sections, commandSections(node)...)
	doc.Sections = append(doc.Sections, flagSection(options, node))
	return trimEmpty(doc)
}

func usage(program string, node *kong.Node) string {
	parts := append([]string{program}, path(node)...)
	for _, positional := range node.Positional {
		parts = append(parts, placeholder(positional))
	}
	if len(node.Children) > 0 {
		parts = append(parts, "<command>")
	}
	return strings.Join(append(parts, "[flags]"), " ")
}

func path(node *kong.Node) []string {
	if node == nil || node.Type == kong.ApplicationNode {
		return nil
	}
	return append(path(node.Parent), node.Name)
}

func placeholder(value *kong.Value) string {
	name := "<" + value.Name + ">"
	if !value.Required {
		return "[" + name + "]"
	}
	return name
}

func argumentSection(node *kong.Node) []render.HelpSection {
	items := make([]render.HelpItem, 0, len(node.Positional))
	for _, positional := range node.Positional {
		items = append(items, render.HelpItem{
			Term:    placeholder(positional),
			Help:    positional.Help,
			Default: defaultOf(positional),
		})
	}
	if len(items) == 0 {
		return nil
	}
	return []render.HelpSection{{Title: "Arguments", Items: items}}
}

func commandSections(node *kong.Node) []render.HelpSection {
	titles := make([]string, 0, len(node.Children))
	grouped := make(map[string][]render.HelpItem, len(node.Children))
	for _, child := range node.Children {
		if child.Hidden {
			continue
		}
		title := commandsTitle
		if child.Group != nil && child.Group.Title != "" {
			title = child.Group.Title
		}
		if _, seen := grouped[title]; !seen {
			titles = append(titles, title)
		}
		grouped[title] = append(grouped[title], render.HelpItem{Term: child.Name, Help: child.Help})
	}

	sections := make([]render.HelpSection, 0, len(titles))
	for _, title := range titles {
		sections = append(sections, render.HelpSection{Title: title, Items: grouped[title]})
	}
	return sections
}

func flagSection(options kong.HelpOptions, node *kong.Node) render.HelpSection {
	seen := make(map[string]bool)
	items := make([]render.HelpItem, 0, len(node.Flags))
	for current := node; current != nil; current = current.Parent {
		for _, flag := range current.Flags {
			if flag.Hidden || seen[flag.Name] {
				continue
			}
			seen[flag.Name] = true
			items = append(items, render.HelpItem{
				Term:    flagTerm(flag),
				Help:    helpText(options, flag.Value),
				Default: defaultOf(flag.Value),
				Envs:    flag.Envs,
			})
		}
	}
	return render.HelpSection{Title: "Flags", Items: items}
}

// flagTerm spells a flag without Kong's own default suffix, which render adds
// from HelpItem.Default. Printing it twice is the failure this replaces.
func flagTerm(flag *kong.Flag) string {
	term := "--" + flag.Name
	if flag.Short != 0 {
		term = "-" + string(flag.Short) + ", " + term
	}
	if flag.IsBool() || flag.IsCounter() {
		return term
	}
	return term + "=" + flagPlaceholder(flag)
}

func flagPlaceholder(flag *kong.Flag) string {
	if flag.PlaceHolder != "" {
		return flag.PlaceHolder
	}
	if choices := enumChoices(flag); choices != "" {
		return choices
	}
	return strings.ToUpper(strings.ReplaceAll(flag.Name, "-", "_"))
}

func enumChoices(flag *kong.Flag) string {
	if flag.Enum == "" {
		return ""
	}
	members := flag.EnumSlice()
	for _, member := range members {
		if member == "" {
			return ""
		}
	}
	joined := strings.Join(members, "|")
	if len(joined) > maxPlaceholder {
		return ""
	}
	return joined
}

func helpText(options kong.HelpOptions, value *kong.Value) string {
	if options.ValueFormatter != nil {
		return options.ValueFormatter(value)
	}
	return value.Help
}

// defaultOf reports a default worth showing. A false boolean and an empty
// string are the absence of a value, not a default a reader benefits from.
func defaultOf(value *kong.Value) string {
	if value == nil || !value.HasDefault || value.Default == "" || value.Default == "false" {
		return ""
	}
	return value.Default
}

func trimEmpty(doc render.HelpDoc) render.HelpDoc {
	sections := make([]render.HelpSection, 0, len(doc.Sections))
	for _, section := range doc.Sections {
		if len(section.Items) > 0 {
			sections = append(sections, section)
		}
	}
	doc.Sections = sections
	return doc
}
