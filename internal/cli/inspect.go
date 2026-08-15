package cli

import (
	"context"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
)

// OverviewCmd is the one-screen roll-up: what exists, what is live, and what is
// waiting for someone.
type OverviewCmd struct {
	Watch    bool          `help:"Re-render until interrupted."`
	Interval time.Duration `default:"2s" help:"Re-render interval for --watch."`
}

type overviewReport struct {
	Overview Overview  `json:"overview"`
	Projects []Project `json:"projects"`
}

func (cmd *OverviewCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	return console.loop(ctx, cmd.Watch, cmd.Interval, func(ctx context.Context) (render.View, error) {
		overview, err := admin.Overview(ctx)
		if err != nil {
			return nil, daemonFault(err, "read overview")
		}
		projects, err := admin.Projects(ctx)
		if err != nil {
			return nil, daemonFault(err, "read projects")
		}
		return newView(overviewReport{Overview: overview, Projects: projects}, drawOverview), nil
	})
}

func drawOverview(doc *render.Document, report overviewReport) {
	overview := report.Overview
	doc.Heading("Overview")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "projects", Value: itoa(overview.Projects)},
		{Key: "agents", Value: itoa(overview.Agents) + " (" + itoa(overview.ActiveAgents) + " active)"},
		{Key: "conversations", Value: itoa(overview.Conversations)},
		{Key: "messages", Value: itoa(overview.Messages)},
		{Key: "unread mail", Value: itoa(overview.UnreadDeliveries), Role: countRole(overview.UnreadDeliveries)},
		{Key: "unacknowledged", Value: itoa(overview.UnackedDeliveries), Role: countRole(overview.UnackedDeliveries)},
		{Key: "reservations", Value: itoa(overview.ActiveReservations) + " active, " +
			itoa(overview.ExpiredReservations) + " expired", Role: countRole(overview.ExpiredReservations)},
		{Key: "journal", Value: itoa(overview.CoordinationEvents) + " events"},
	}})

	doc.Blank()
	doc.Table(projectTable(report.Projects))
}

func countRole(count int) render.Role {
	if count > 0 {
		return render.RoleWarn
	}
	return render.RoleInherit
}

// ProjectsCmd inspects registered projects. It declares no Run method: Kong
// invokes Run on every node from the selected leaf up to the root, so a method
// here would fire for every subcommand.
type ProjectsCmd struct {
	List ProjectsListCmd `cmd:"" default:"withargs" help:"List registered projects."`
	Show ProjectsShowCmd `cmd:"" help:"Show one project and its agents."`
}

type ProjectsListCmd struct{}

type projectsReport struct {
	Projects []Project `json:"projects"`
}

func (cmd *ProjectsListCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	projects, err := admin.Projects(ctx)
	if err != nil {
		return daemonFault(err, "read projects")
	}
	return console.present(newView(projectsReport{Projects: projects}, drawProjects))
}

func drawProjects(doc *render.Document, report projectsReport) {
	doc.Table(projectTable(report.Projects))
}

func projectTable(projects []Project) render.Table {
	table := render.Table{
		Columns: []render.Column{
			{Title: "PROJECT", Trim: render.TrimLeft},
			{Title: "AGENTS", Align: render.AlignRight},
			{Title: "ACTIVE", Align: render.AlignRight},
			{Title: "THREADS", Align: render.AlignRight},
			{Title: "WORKSPACE", Role: render.RoleMuted},
		},
		Empty: "No projects are registered yet.",
	}
	for _, project := range projects {
		table.Rows = append(table.Rows, render.TextRow(project.ProjectKey, itoa(project.Agents),
			itoa(project.ActiveAgents), itoa(project.Conversations), project.WorkspaceID))
	}
	return table
}

type ProjectsShowCmd struct {
	Project string `arg:"" placeholder:"PATH" help:"Project key."`
}

type projectReport struct {
	Project   Project `json:"project"`
	Agents    []Agent `json:"agents"`
	Truncated bool    `json:"truncated"`
}

func (cmd *ProjectsShowCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	projects, err := admin.Projects(ctx)
	if err != nil {
		return daemonFault(err, "read projects")
	}
	found, ok := findProject(projects, cmd.Project)
	if !ok {
		return notFoundFault("no project matches %q", cmd.Project)
	}
	page, err := admin.Agents(ctx, AgentQuery{ProjectKey: found.ProjectKey})
	if err != nil {
		return daemonFault(err, "read agents")
	}
	return console.present(newView(projectReport{
		Project: found, Agents: page.Agents, Truncated: page.Truncated,
	}, drawProject))
}

func findProject(projects []Project, key string) (Project, bool) {
	for _, project := range projects {
		if project.ProjectKey == key {
			return project, true
		}
	}
	return Project{}, false
}

func drawProject(doc *render.Document, report projectReport) {
	doc.Heading(report.Project.ProjectKey)
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "workspace", Value: orAbsent(report.Project.WorkspaceID)},
		{Key: "run", Value: orAbsent(report.Project.RunID)},
		{Key: "agents", Value: itoa(report.Project.Agents) + " (" + itoa(report.Project.ActiveAgents) + " active)"},
		{Key: "conversations", Value: itoa(report.Project.Conversations)},
	}})
	doc.Blank()
	doc.Table(agentTable(report.Agents))
	drawTruncation(doc, report.Truncated, len(report.Agents))
}

// AgentsCmd inspects registered agents.
type AgentsCmd struct {
	List AgentsListCmd `cmd:"" default:"withargs" help:"List registered agents."`
	Show AgentsShowCmd `cmd:"" help:"Show one agent, its session, and its mail counts."`
}

type AgentsListCmd struct {
	Project string `placeholder:"PATH" help:"Limit to one project key."`
	Active  bool   `help:"Show only agents with a live session."`
	Limit   int    `default:"50" help:"Maximum agents to show."`
}

type agentsReport struct {
	Agents    []Agent `json:"agents"`
	Truncated bool    `json:"truncated"`
}

func (cmd *AgentsListCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	limit, err := limitOf("--limit", cmd.Limit)
	if err != nil {
		return err
	}
	page, err := admin.Agents(ctx, AgentQuery{ProjectKey: cmd.Project, ActiveOnly: cmd.Active, Limit: limit})
	if err != nil {
		return daemonFault(err, "read agents")
	}
	return console.present(newView(agentsReport(page), drawAgents))
}

func drawAgents(doc *render.Document, report agentsReport) {
	doc.Table(agentTable(report.Agents))
	drawTruncation(doc, report.Truncated, len(report.Agents))
}

func agentTable(agents []Agent) render.Table {
	table := render.Table{
		Columns: []render.Column{
			{Title: "AGENT"},
			{Title: "PROJECT", Role: render.RoleMuted, Trim: render.TrimLeft},
			{Title: "LIVE"},
			{Title: "UNREAD", Align: render.AlignRight},
			{Title: "UNACKED", Align: render.AlignRight},
			{Title: "LEASES", Align: render.AlignRight},
		},
		Empty: "No agents are registered yet.",
	}
	for _, agent := range agents {
		table.Rows = append(table.Rows, render.Row{Cells: []render.Cell{
			{Text: agent.AgentName},
			{Text: agent.ProjectKey, Role: render.RoleMuted},
			{Text: yesNo(agent.Active), Role: boolRole(agent.Active)},
			{Text: itoa(agent.UnreadDeliveries), Role: countRole(agent.UnreadDeliveries)},
			{Text: itoa(agent.UnackedDeliveries), Role: countRole(agent.UnackedDeliveries)},
			{Text: itoa(agent.ActiveLeases)},
		}})
	}
	return table
}

type AgentsShowCmd struct {
	Agent   string `arg:"" placeholder:"NAME" help:"Agent name."`
	Project string `placeholder:"PATH" help:"Project key. Required when a name is ambiguous."`
}

type agentReport struct {
	Agent Agent `json:"agent"`
	now   time.Time
}

func (cmd *AgentsShowCmd) Run(ctx context.Context, console *Console) error {
	admin, err := console.admin()
	if err != nil {
		return err
	}
	page, err := admin.Agents(ctx, AgentQuery{ProjectKey: cmd.Project, AgentName: cmd.Agent})
	if err != nil {
		return daemonFault(err, "read agents")
	}
	switch len(page.Agents) {
	case 0:
		return notFoundFault("no agent matches %q", cmd.Agent)
	case 1:
		return console.present(newView(agentReport{Agent: page.Agents[0], now: console.now()}, drawAgent))
	default:
		return withRemedy(usageFault("%q matches %d agents", cmd.Agent, len(page.Agents)),
			"pass --project=PATH to disambiguate")
	}
}

func drawAgent(doc *render.Document, report agentReport) {
	agent := report.Agent
	doc.Heading(agent.AgentName)
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "project", Value: agent.ProjectKey},
		{Key: "actor", Value: agent.ActorID},
		{Key: "session", Value: orAbsent(agent.SessionID)},
		{Key: "live", Value: yesNo(agent.Active), Role: boolRole(agent.Active)},
		{Key: "unread", Value: itoa(agent.UnreadDeliveries), Role: countRole(agent.UnreadDeliveries)},
		{Key: "unacknowledged", Value: itoa(agent.UnackedDeliveries), Role: countRole(agent.UnackedDeliveries)},
		{Key: "reservations", Value: itoa(agent.ActiveLeases)},
		{Key: "last seen", Value: instant(agent.LastSeenAt, report.now)},
	}})
}
