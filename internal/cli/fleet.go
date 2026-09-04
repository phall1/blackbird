package cli

import (
	"context"
	"sort"
	"strconv"
	"sync"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/cli/render"
)

// The fleet cost view: this host's cost report beside its peers', unioned and
// never merged.
//
// Every rule below exists because a fleet number is easier to believe and
// harder to check than a local one.
//
//   - A HOST NEVER DISAPPEARS. Each named peer occupies a row whether it
//     answered or not, and a peer that did not answer is reported with the
//     reason it gave. The command exits ExitDegraded when any host is silent,
//     so an unattended caller learns that the answer is short without parsing
//     the report. A fleet total that quietly drops a host is worse than an
//     error: it looks like an answer.
//
//   - ONLY SPEND IS SUMMED. Token classes and call counts are additive facts
//     about work that happened, so their union across hosts is meaningful.
//     Contention is NOT summed, for exactly the reason the admin cost query
//     refuses to sum across projects: contention exists only between agents
//     that could have collided, and agents on two machines hold leases over two
//     different checkouts on two different disks. Adding those refusals would
//     manufacture a collision that could not have happened. Contention stays on
//     the host that measured it, in that host's own section.
//
//   - THERE IS NO FLEET WINDOW. Each daemon normalizes the lookback against its
//     own clock and states the window it actually used; nothing here reconciles
//     those clocks or claims a single interval covering all of them. The view
//     states the lookback that was REQUESTED, and every host's own window is
//     printed beside its row.
//
//   - The per-host sections are the ordinary cost report, drawn by the ordinary
//     renderer. There is no second projection of cost anywhere in this file, so
//     an operator reading a fleet view and an agent reading its own report
//     cannot be shown numbers computed two different ways.

// FleetHost is one host's contribution to the fleet view. Answered is the
// field the whole type exists for: Report is nil exactly when the host did not
// answer, and Detail then carries what went wrong instead of a zero.
type FleetHost struct {
	Host     string               `json:"host"`
	Local    bool                 `json:"local"`
	Answered bool                 `json:"answered"`
	Detail   string               `json:"detail,omitempty"`
	Report   *adminapi.CostReport `json:"report,omitempty"`
}

// FleetModel is one model's spend summed across the hosts that answered. Hosts
// says how many contributed, so a model reported by one machine out of three is
// not read as a fleet-wide figure.
type FleetModel struct {
	Model          string   `json:"model"`
	Hosts          int      `json:"hosts"`
	Calls          uint64   `json:"calls"`
	UncachedInput  uint64   `json:"uncached_input_tokens"`
	CacheRead      uint64   `json:"cache_read_tokens"`
	CacheWrite     uint64   `json:"cache_write_tokens"`
	Output         uint64   `json:"output_tokens"`
	CacheReadShare *float64 `json:"cache_read_share,omitempty"`
	CacheReuse     *float64 `json:"cache_reuse,omitempty"`
}

// FleetCostReport is the whole answer. Complete is false whenever any named
// host is missing from Models, and Silent names those hosts: the pair is what
// keeps the totals from being read as a fleet total when they are not.
type FleetCostReport struct {
	ProjectKey    string       `json:"project_key"`
	LookbackHours int          `json:"lookback_hours,omitempty"`
	Hosts         []FleetHost  `json:"hosts"`
	Silent        []string     `json:"silent_hosts,omitempty"`
	Models        []FleetModel `json:"models,omitempty"`
	Complete      bool         `json:"complete"`
}

// LocalHostLabel names this machine in a fleet view. It is deliberately not a
// hostname: this daemon is not told its own tailnet name by anything in the
// tree, and inventing one would put a fabricated identity in the one column a
// reader uses to decide which machine to go and look at.
const LocalHostLabel = "this host"

// fleetCost gathers every host's report. The local report is read through the
// ordinary admin client, so the operator's own numbers come from exactly the
// route "blackbird cost" already uses; peers are read through the peer route,
// which carries no credential of this machine at all.
func fleetCost(ctx context.Context, console *Console, query CostQuery, endpoints []string) (FleetCostReport, error) {
	admin, err := console.admin()
	if err != nil {
		return FleetCostReport{}, err
	}
	report := FleetCostReport{ProjectKey: query.ProjectKey, LookbackHours: query.SinceHours,
		Hosts: make([]FleetHost, 0, len(endpoints)+1)}

	local := FleetHost{Host: LocalHostLabel, Local: true}
	localReport, localErr := admin.Cost(ctx, query)
	if localErr != nil {
		// The local daemon failing is not a fleet outage, it is this command
		// having no ground to stand on: report it as the fault it is rather
		// than as one silent host among several.
		return FleetCostReport{}, daemonFault(localErr, "read cost report")
	}
	local.Answered, local.Report = true, &localReport
	report.Hosts = append(report.Hosts, local)

	report.Hosts = append(report.Hosts, gatherPeerCosts(ctx, console, query, endpoints)...)
	for _, host := range report.Hosts {
		if !host.Answered {
			report.Silent = append(report.Silent, host.Host)
		}
	}
	report.Models = unionModels(report.Hosts)
	report.Complete = len(report.Silent) == 0
	return report, nil
}

// gatherPeerCosts fans out with a fixed, small bound. The bound is not a
// throughput decision: every peer call is one outbound connection and one
// pending response buffer here, and one report running on the far side holding
// one of ITS read connections. A fleet of twenty machines must not open twenty
// of each at once, and a caller that names twenty peers is exactly the caller
// who would.
func gatherPeerCosts(ctx context.Context, console *Console, query CostQuery, endpoints []string) []FleetHost {
	hosts := make([]FleetHost, len(endpoints))
	port := console.peerCost()
	gate := make(chan struct{}, maxFleetFanOut)
	var group sync.WaitGroup
	for index, endpoint := range endpoints {
		hosts[index] = FleetHost{Host: endpoint}
		group.Add(1)
		go func() {
			defer group.Done()
			gate <- struct{}{}
			defer func() { <-gate }()
			peerReport, err := port.PeerCost(ctx, endpoint, query)
			if err != nil {
				hosts[index].Detail = err.Error()
				return
			}
			hosts[index].Answered, hosts[index].Report = true, &peerReport
		}()
	}
	group.Wait()
	return hosts
}

// maxFleetFanOut bounds concurrent peer queries from one command.
const maxFleetFanOut = 4

// unionModels sums the token classes of every host that answered, keeping the
// three input classes apart for the reason the schema does: they are billed at
// materially different rates and the split cannot be recovered from a sum.
//
// The two ratios are recomputed from the summed columns rather than averaged
// from the per-host ratios, because an average of ratios over different
// denominators is not a ratio of anything. They stay absent when their
// denominator is zero, so "caching was never used" never renders as "caching is
// failing".
func unionModels(hosts []FleetHost) []FleetModel {
	totals := map[string]*FleetModel{}
	for _, host := range hosts {
		if !host.Answered || host.Report == nil || host.Report.Cache == nil {
			continue
		}
		for _, model := range host.Report.Cache.Models {
			entry, present := totals[model.Model]
			if !present {
				entry = &FleetModel{Model: model.Model}
				totals[model.Model] = entry
			}
			entry.Hosts++
			entry.Calls += model.Calls
			entry.UncachedInput += model.UncachedInput
			entry.CacheRead += model.CacheRead
			entry.CacheWrite += model.CacheWrite
			entry.Output += model.Output
		}
	}
	union := make([]FleetModel, 0, len(totals))
	for _, entry := range totals {
		billed := entry.UncachedInput + entry.CacheRead + entry.CacheWrite
		if billed > 0 {
			share := float64(entry.CacheRead) / float64(billed)
			entry.CacheReadShare = &share
		}
		if entry.CacheWrite > 0 {
			reuse := float64(entry.CacheRead) / float64(entry.CacheWrite)
			entry.CacheReuse = &reuse
		}
		union = append(union, *entry)
	}
	sort.Slice(union, func(left, right int) bool {
		leftBilled := union[left].UncachedInput + union[left].CacheRead + union[left].CacheWrite
		rightBilled := union[right].UncachedInput + union[right].CacheRead + union[right].CacheWrite
		if leftBilled != rightBilled {
			return leftBilled > rightBilled
		}
		return union[left].Model < union[right].Model
	})
	return union
}

func drawFleetCost(doc *render.Document, report FleetCostReport) {
	doc.Heading("Fleet cost")
	answered := 0
	for _, host := range report.Hosts {
		if host.Answered {
			answered++
		}
	}
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "project", Value: report.ProjectKey},
		{Key: "lookback", Value: fleetLookback(report.LookbackHours)},
		{Key: "hosts", Value: strconv.Itoa(answered) + " of " + strconv.Itoa(len(report.Hosts)) + " answered",
			Role: fleetHostsRole(report.Complete)},
	}})
	doc.Blank()
	// Stated before the totals, because a reader who meets the caveat after the
	// numbers has already formed a view of them.
	for _, host := range report.Hosts {
		if host.Answered {
			continue
		}
		doc.Status(render.StatusError, host.Host+" did not answer: "+host.Detail+
			". Its spend is NOT in the union below, so every total there is short by whatever that host spent.")
	}
	if !report.Complete {
		doc.Blank()
	}
	doc.Table(fleetHostTable(report))
	doc.Blank()
	doc.Table(fleetModelTable(report))
	doc.Blank()
	// Contention is per host on purpose, and the reason is worth one line where
	// somebody might otherwise add up the columns themselves.
	doc.Wrapped(render.RoleMuted, "Spend is unioned across hosts because tokens are additive. Contention and "+
		"abandonment are NOT: a lease protects a path on one machine's disk, so agents on two hosts cannot "+
		"collide and summing their refusals would invent a collision. Each host's contention stays in its own "+
		"section below, measured against that host's own clock.")
	for _, host := range report.Hosts {
		if !host.Answered || host.Report == nil {
			continue
		}
		doc.Blank()
		doc.Heading("Host " + host.Host)
		drawCost(doc, *host.Report)
	}
}

func fleetLookback(hours int) string {
	if hours <= 0 {
		return "each daemon's default window"
	}
	return strconv.Itoa(hours) + "h, as each daemon resolved it against its own clock"
}

func fleetHostsRole(complete bool) render.Role {
	if complete {
		return render.RoleOK
	}
	return render.RoleWarn
}

func fleetHostTable(report FleetCostReport) render.Table {
	table := render.Table{
		Columns: []render.Column{
			{Title: "HOST", Trim: render.TrimLeft},
			{Title: "ANSWERED"},
			{Title: "WINDOW", Role: render.RoleMuted},
			{Title: "CALLS", Align: render.AlignRight},
			{Title: "BILLED IN", Align: render.AlignRight},
			{Title: "OUT", Align: render.AlignRight},
			{Title: "REFUSALS", Align: render.AlignRight},
			{Title: "ABANDONED", Align: render.AlignRight},
		},
		Empty: "No host was named.",
	}
	for _, host := range report.Hosts {
		table.Rows = append(table.Rows, render.TextRow(fleetHostRow(host)...))
	}
	return table
}

// fleetHostRow renders an unobserved section as a dash rather than as zero,
// which is the same rule the single-host report keeps: nothing recorded and
// nothing spent are different claims and only the first means something is
// broken.
func fleetHostRow(host FleetHost) []string {
	if !host.Answered || host.Report == nil {
		return []string{host.Host, "no", "-", "-", "-", "-", "-", "-"}
	}
	calls, billed, output := "-", "-", "-"
	if cache := host.Report.Cache; cache != nil {
		var totalCalls, totalBilled, totalOutput uint64
		for _, model := range cache.Models {
			totalCalls += model.Calls
			totalBilled += model.UncachedInput + model.CacheRead + model.CacheWrite
			totalOutput += model.Output
		}
		calls, billed, output = itoa64(totalCalls), itoa64(totalBilled), itoa64(totalOutput)
	}
	refusals := "-"
	if contention := host.Report.Contention; contention != nil {
		refusals = itoa64(contention.Refusals)
	}
	abandoned := "-"
	if abandonment := host.Report.Abandonment; abandonment != nil {
		abandoned = itoa64(abandonment.Abandoned)
	}
	return []string{host.Host, "yes", host.Report.Since + " to " + host.Report.Until,
		calls, billed, output, refusals, abandoned}
}

func fleetModelTable(report FleetCostReport) render.Table {
	empty := "No model call was recorded on any host that answered."
	if !report.Complete {
		empty = "No model call was recorded on any host that answered, and at least one host did not answer."
	}
	table := render.Table{
		Columns: []render.Column{
			{Title: "MODEL", Trim: render.TrimLeft},
			{Title: "HOSTS", Align: render.AlignRight},
			{Title: "CALLS", Align: render.AlignRight},
			{Title: "UNCACHED IN", Align: render.AlignRight},
			{Title: "CACHE READ", Align: render.AlignRight},
			{Title: "CACHE WRITE", Align: render.AlignRight},
			{Title: "OUT", Align: render.AlignRight},
			{Title: "READ SHARE", Align: render.AlignRight},
			{Title: "REUSE", Align: render.AlignRight},
		},
		Empty: empty,
	}
	for _, model := range report.Models {
		table.Rows = append(table.Rows, render.TextRow(model.Model, strconv.Itoa(model.Hosts),
			itoa64(model.Calls), itoa64(model.UncachedInput), itoa64(model.CacheRead),
			itoa64(model.CacheWrite), itoa64(model.Output),
			costRatio(model.CacheReadShare), costRatio(model.CacheReuse)))
	}
	return table
}
