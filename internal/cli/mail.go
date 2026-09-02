package cli

import (
	"context"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
)

// InboxCmd shows what an agent has not yet read or acknowledged. Message bodies
// are never projected by the admin surface, so neither are they rendered here.
type InboxCmd struct {
	Agent    string        `arg:"" optional:"" placeholder:"NAME" help:"Agent whose inbox to read. Omit for every agent."`
	Project  string        `placeholder:"PATH" help:"Project key. Defaults to the current directory."`
	Unread   bool          `help:"Show only unread deliveries."`
	Unacked  bool          `help:"Show only deliveries awaiting acknowledgement."`
	Limit    int           `default:"25" help:"Maximum deliveries to show."`
	Watch    bool          `help:"Re-render until interrupted."`
	Interval time.Duration `default:"2s" help:"Re-render interval for --watch."`
}

type inboxReport struct {
	Inbox Inbox `json:"inbox"`
	now   time.Time
}

func (cmd *InboxCmd) Run(ctx context.Context, console *Console) error {
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
	return console.loop(ctx, cmd.Watch, cmd.Interval, func(ctx context.Context) (render.View, error) {
		inbox, err := admin.Inbox(ctx, InboxQuery{
			ProjectKey: project, AgentName: cmd.Agent,
			UnreadOnly: cmd.Unread, UnackedOnly: cmd.Unacked, Limit: limit,
		})
		if err != nil {
			return nil, daemonFault(err, "read inbox")
		}
		if cmd.Agent != "" && len(inbox.Summaries) == 0 {
			return nil, notFoundFault("no agent matches %q", cmd.Agent)
		}
		return newView(inboxReport{Inbox: inbox, now: console.now()}, drawInbox), nil
	})
}

func drawInbox(doc *render.Document, report inboxReport) {
	summaries := render.Table{
		Columns: []render.Column{
			{Title: "AGENT"},
			{Title: "PROJECT", Role: render.RoleMuted, Trim: render.TrimLeft},
			{Title: "UNREAD", Align: render.AlignRight},
			{Title: "UNACKED", Align: render.AlignRight},
			{Title: "OLDEST UNREAD", Role: render.RoleMuted},
		},
		Empty: "No mail is waiting.",
	}
	for _, summary := range report.Inbox.Summaries {
		summaries.Rows = append(summaries.Rows, render.Row{Cells: []render.Cell{
			{Text: summary.AgentName},
			{Text: summary.ProjectKey, Role: render.RoleMuted},
			{Text: itoa(summary.UnreadDeliveries), Role: countRole(summary.UnreadDeliveries)},
			{Text: itoa(summary.UnackedDeliveries), Role: countRole(summary.UnackedDeliveries)},
			{Text: instant(summary.OldestUnreadAt, report.now), Role: render.RoleMuted},
		}})
	}
	doc.Table(summaries)

	if len(report.Inbox.Pending) == 0 {
		return
	}
	doc.Blank()
	pending := render.Table{
		Columns: []render.Column{
			{Title: "TO"},
			{Title: "FROM"},
			{Title: "SUBJECT"},
			{Title: "STATE"},
			{Title: "SENT", Role: render.RoleMuted},
		},
	}
	for _, item := range report.Inbox.Pending {
		pending.Rows = append(pending.Rows, render.TextRow(item.RecipientAgentName,
			orAbsent(item.AuthorAgentName), item.Subject, deliveryState(item), instant(item.SentAt, report.now)))
	}
	doc.Table(pending)
	drawTruncation(doc, report.Inbox.Truncated, len(report.Inbox.Pending))
}

func deliveryState(item InboxItem) string {
	switch {
	case !item.Read:
		return "unread"
	case item.AckRequired && !item.Acknowledged:
		return "unacknowledged"
	default:
		return "read"
	}
}

// ThreadsCmd inspects conversations.
type ThreadsCmd struct {
	List ThreadsListCmd `cmd:"" default:"withargs" help:"List conversations."`
	Show ThreadsShowCmd `cmd:"" help:"Show one conversation."`
}

type ThreadsListCmd struct {
	Project string `placeholder:"PATH" help:"Limit to one project key."`
	Open    bool   `help:"Show only open conversations."`
	Limit   int    `default:"25" help:"Maximum conversations to show."`
}

type threadsReport struct {
	Conversations []Conversation `json:"conversations"`
	Truncated     bool           `json:"truncated"`
	now           time.Time
}

func (cmd *ThreadsListCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	limit, err := limitOf("--limit", cmd.Limit)
	if err != nil {
		return err
	}
	page, err := admin.Conversations(ctx, ConversationQuery{
		ProjectKey: cmd.Project, OpenOnly: cmd.Open, Limit: limit,
	})
	if err != nil {
		return daemonFault(err, "read conversations")
	}
	return console.present(newView(threadsReport{Conversations: page.Conversations, Truncated: page.Truncated, now: console.now()}, drawThreads))
}

func drawThreads(doc *render.Document, report threadsReport) {
	table := render.Table{
		Columns: []render.Column{
			{Title: "TOPIC"},
			{Title: "PROJECT", Role: render.RoleMuted, Trim: render.TrimLeft},
			{Title: "STATE"},
			{Title: "MESSAGES", Align: render.AlignRight},
			{Title: "UNREAD", Align: render.AlignRight},
			{Title: "LAST", Role: render.RoleMuted},
		},
		Empty: "No conversations yet.",
	}
	for _, conversation := range report.Conversations {
		table.Rows = append(table.Rows, render.TextRow(conversation.Topic, conversation.ProjectKey,
			conversation.Status, itoa(conversation.Messages), itoa(conversation.UnreadDeliveries),
			instant(conversation.LastMessageAt, report.now)))
	}
	doc.Table(table)
	drawTruncation(doc, report.Truncated, len(report.Conversations))
}

type ThreadsShowCmd struct {
	Conversation string `arg:"" placeholder:"ID" help:"Conversation id."`
}

type threadReport struct {
	Conversation Conversation `json:"conversation"`
	now          time.Time
}

func (cmd *ThreadsShowCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	page, err := admin.Conversations(ctx, ConversationQuery{ConversationID: cmd.Conversation})
	if err != nil {
		return daemonFault(err, "read conversation")
	}
	if len(page.Conversations) == 0 {
		return notFoundFault("no conversation matches %q", cmd.Conversation)
	}
	return console.present(newView(threadReport{Conversation: page.Conversations[0], now: console.now()}, drawThread))
}

func drawThread(doc *render.Document, report threadReport) {
	conversation := report.Conversation
	doc.Heading(conversation.Topic)
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "id", Value: conversation.ConversationID},
		{Key: "project", Value: conversation.ProjectKey},
		{Key: "state", Value: conversation.Status},
		{Key: "opened by", Value: orAbsent(conversation.OpenedByAgentName)},
		{Key: "messages", Value: itoa(conversation.Messages)},
		{Key: "participants", Value: itoa(conversation.Participants)},
		{Key: "unread", Value: itoa(conversation.UnreadDeliveries), Role: countRole(conversation.UnreadDeliveries)},
		{Key: "last message", Value: instant(conversation.LastMessageAt, report.now)},
		{Key: "last subject", Value: orAbsent(conversation.LastMessageSubject)},
	}})
	doc.Blank()
	doc.Line(render.RoleMuted, "Message bodies are private to their recipients and are not projected here.")
}

// ReservationsCmd inspects and administratively releases file reservations.
type ReservationsCmd struct {
	List    ReservationsListCmd    `cmd:"" default:"withargs" help:"List file reservations."`
	Release ReservationsReleaseCmd `cmd:"" help:"Force-release a reservation held by a dead agent."`
}

type ReservationsReleaseCmd struct {
	LeaseID string `arg:"" name:"lease-id" help:"Lease identifier shown by reservations list."`
	Force   bool   `help:"Confirm release without the holder's credentials."`
}

type ReservationsListCmd struct {
	Project  string        `placeholder:"PATH" help:"Limit to one project key."`
	Agent    string        `placeholder:"NAME" help:"Limit to one holder."`
	Path     string        `placeholder:"PATH" help:"Limit to reservations covering this path."`
	Mode     string        `enum:"any,shared,exclusive" default:"any" help:"Limit to one reservation mode."`
	State    string        `enum:"all,active,expired,released" default:"active" help:"Limit to one lifecycle state."`
	Limit    int           `default:"50" help:"Maximum reservations to show."`
	Watch    bool          `help:"Re-render until interrupted."`
	Interval time.Duration `default:"2s" help:"Re-render interval for --watch."`
}

type reservationsReport struct {
	Reservations []Reservation `json:"reservations"`
	Truncated    bool          `json:"truncated"`
}

func (cmd *ReservationsListCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	limit, err := limitOf("--limit", cmd.Limit)
	if err != nil {
		return err
	}
	// The daemon rejects a padded path rather than matching nothing, and a
	// selector path is stored relative and cleaned, so the flag is trimmed here
	// and matched textually there.
	selectorPath := strings.TrimSpace(cmd.Path)
	return console.loop(ctx, cmd.Watch, cmd.Interval, func(ctx context.Context) (render.View, error) {
		page, err := admin.Reservations(ctx, ReservationQuery{
			ProjectKey: cmd.Project, AgentName: cmd.Agent, State: cmd.State,
			Mode: cmd.Mode, Path: selectorPath, Limit: limit,
		})
		if err != nil {
			return nil, daemonFault(err, "read reservations")
		}
		return newView(reservationsReport(page), drawReservations), nil
	})
}

func (cmd *ReservationsReleaseCmd) Run(ctx context.Context, console *Console) error {
	if !cmd.Force {
		return usageFault("reservation release requires --force")
	}
	admin, err := console.admin()
	if err != nil {
		return err
	}
	released, err := admin.ForceReleaseReservation(ctx, cmd.LeaseID)
	if err != nil {
		return daemonFault(err, "force-release reservation")
	}
	return console.present(newView(released, drawReservationRelease))
}

func drawReservationRelease(doc *render.Document, released ReservationRelease) {
	doc.Status(render.StatusOK, "reservation force-released")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "lease", Value: released.LeaseID},
		{Key: "released at", Value: released.ReleasedAt},
	}})
}

func drawReservations(doc *render.Document, report reservationsReport) {
	table := render.Table{
		Columns: []render.Column{
			{Title: "HOLDER"},
			{Title: "MODE"},
			{Title: "STATE"},
			{Title: "EXPIRES"},
			{Title: "PATHS"},
		},
		Empty: "No reservations are held.",
	}
	for _, reservation := range report.Reservations {
		state := render.Cell{Text: reservation.State}
		if reservation.Expired {
			state.Role = render.RoleWarn
		}
		table.Rows = append(table.Rows, render.Row{Cells: []render.Cell{
			{Text: orAbsent(reservation.HolderAgentName)},
			{Text: reservation.Mode},
			state,
			{Text: countdown(reservation.ExpiresInMS)},
			{Text: selectorPaths(reservation.Selectors), Role: render.RoleMuted},
		}})
	}
	doc.Table(table)
	drawTruncation(doc, report.Truncated, len(report.Reservations))
}

// EventsCmd reads the coordination event journal. The journal is append-only
// and records one row per recipient, so a message to three agents appears three
// times; collapsing them would misreport what happened.
type EventsCmd struct {
	Project string `placeholder:"PATH" help:"Limit to one project key."`
	Agent   string `placeholder:"NAME" help:"Limit to one agent."`
	Type    string `placeholder:"TYPE" help:"Limit to one event type."`
	Limit   int    `default:"50" help:"Maximum events to show."`
}

type eventsReport struct {
	Events    []Event `json:"events"`
	Truncated bool    `json:"truncated"`
	now       time.Time
}

func (cmd *EventsCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	limit, err := limitOf("--limit", cmd.Limit)
	if err != nil {
		return err
	}
	page, err := admin.Events(ctx, EventQuery{
		ProjectKey: cmd.Project, AgentName: cmd.Agent, Type: cmd.Type, Limit: limit,
	})
	if err != nil {
		return daemonFault(err, "read the event journal")
	}
	return console.present(newView(eventsReport{
		Events: page.Events, Truncated: page.Truncated, now: console.now(),
	}, drawEvents))
}

func drawEvents(doc *render.Document, report eventsReport) {
	table := render.Table{
		Columns: []render.Column{
			{Title: "POS", Align: render.AlignRight},
			{Title: "WHEN", Role: render.RoleMuted},
			{Title: "TYPE"},
			{Title: "AGENT"},
			{Title: "SUBJECT", Role: render.RoleMuted},
		},
		Empty: "The journal is empty.",
	}
	for _, event := range report.Events {
		table.Rows = append(table.Rows, render.TextRow(utoa(event.Position),
			instant(event.OccurredAt, report.now), event.Type, orAbsent(event.AgentName), event.Subject))
	}
	doc.Table(table)
	drawTruncation(doc, report.Truncated, len(report.Events))
}
