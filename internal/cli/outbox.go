package cli

import (
	"context"

	"github.com/phall1/blackbird/internal/cli/render"
)

// The operator's view of cross-host mail this daemon is still holding.
//
// A peer being unreachable is the ORDINARY failure of cross-host mail -- a
// laptop closed, a host not peered yet, a machine name misspelled -- and until
// this existed a queued delivery was visible only to the agent that sent it and
// in the daemon log. An operator who cannot see the queue cannot tell "the mail
// is waiting" from "the mail was never sent", and those call for opposite
// actions: one is waiting, the other is a name to go and fix.
//
// The three delivery states are kept apart in the rendering for the same
// reason, because they are three different jobs:
//
//   - queued is owed to the wire and will be retried; the row says when.
//   - delivered has crossed and is kept only as a receipt.
//   - undeliverable is TERMINAL and names an operator action. The peer
//     answered and said no -- the agent does not exist over there, this machine
//     is not on its allow-list -- and retrying against that answer is a loop
//     that hides what somebody has to go and change.
//
// Subject and body are deliberately absent. This is a delivery view; an
// operator diagnosing why mail is stuck has no business reading the contents of
// a message out of a queue.
type OutboxCmd struct {
	Project string `arg:"" optional:"" placeholder:"PATH" help:"Project key. Defaults to the current directory."`
	Limit   int    `default:"20" help:"Maximum rows."`
}

func (cmd *OutboxCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	project, err := projectKeyOrWorkingDirectory(cmd.Project)
	if err != nil {
		return err
	}
	limit, err := limitOf("--limit", cmd.Limit)
	if err != nil {
		return err
	}
	page, err := admin.Outbox(ctx, OutboxQuery{ProjectKey: project, Limit: limit})
	if err != nil {
		return daemonFault(err, "read the cross-host mail queue")
	}
	return console.present(newView(page, drawOutbox))
}

func drawOutbox(doc *render.Document, page OutboxPage) {
	doc.Heading("Outbox")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "project", Value: page.ProjectKey},
	}})
	doc.Blank()
	doc.Table(outboxTable(page))
	// A terminal entry is the one row that will never resolve itself, so it is
	// named after the table rather than left to be spotted in a column.
	stuck := 0
	for _, entry := range page.Entries {
		if entry.State == "undeliverable" {
			stuck++
		}
	}
	if stuck > 0 {
		doc.Blank()
		noun := "deliveries"
		if stuck == 1 {
			noun = "delivery"
		}
		doc.Status(render.StatusWarn, itoa(stuck)+" "+noun+
			" will not be retried: the peer answered and refused. Check the recipient's name on that host, "+
			"and that this machine is on its allowed-peer list.")
	}
}

func outboxTable(page OutboxPage) render.Table {
	table := render.Table{
		Columns: []render.Column{
			{Title: "TO"},
			{Title: "HOST", Trim: render.TrimLeft},
			{Title: "FROM"},
			{Title: "STATE"},
			{Title: "TRIES", Align: render.AlignRight},
			{Title: "NEXT TRY", Role: render.RoleMuted},
			{Title: "LAST ERROR", Role: render.RoleMuted, Trim: render.TrimRight},
		},
		Empty: "No cross-host mail is waiting.",
	}
	for _, entry := range page.Entries {
		table.Rows = append(table.Rows, render.Row{Cells: []render.Cell{
			{Text: entry.ToAgent},
			{Text: entry.Host},
			{Text: entry.FromAgent},
			{Text: entry.State, Role: outboxStateRole(entry.State)},
			{Text: itoa(entry.Attempts)},
			// An entry with no next attempt has reached a terminal state; a
			// dash says so rather than the epoch.
			{Text: orDash(entry.NextAttemptAt)},
			{Text: orDash(entry.LastError)},
		}})
	}
	return table
}

func outboxStateRole(state string) render.Role {
	switch state {
	case "delivered":
		return render.RoleOK
	case "undeliverable":
		return render.RoleError
	default:
		return render.RoleWarn
	}
}

func orDash(text string) string {
	if text == "" {
		return "-"
	}
	return text
}
