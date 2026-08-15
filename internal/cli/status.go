package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/install"
)

// StatusCmd reports the three independent facts that decide whether Blackbird
// is working: the unit file, the supervisor, and a real handshake with the
// running process. A loaded launchd job says nothing about liveness, which is
// how a schema-mismatch crash loop reported "running" 23 times in a row.
type StatusCmd struct {
	RequireRunning bool          `help:"Exit 4 unless the daemon answers a liveness probe."`
	Timeout        time.Duration `default:"2s" help:"Liveness probe timeout."`
	Watch          bool          `help:"Re-render until interrupted."`
	Interval       time.Duration `default:"2s" help:"Re-render interval for --watch."`
}

type statusReport struct {
	Build        BuildInfo         `json:"build"`
	Service      map[string]string `json:"service"`
	ServiceLine  string            `json:"service_line,omitempty"`
	Daemon       string            `json:"daemon"`
	Health       Health            `json:"health"`
	Legacy       bool              `json:"legacy_protocol,omitempty"`
	Undiscovered bool              `json:"serving_without_record,omitempty"`
	Probe        *daemonProbe      `json:"probe,omitempty"`
	Identity     *Identity         `json:"identity,omitempty"`
	Database     Database          `json:"database"`
	Problems     []string          `json:"problems,omitempty"`
}

func (cmd *StatusCmd) Run(ctx context.Context, console *Console) error {
	return console.loop(ctx, cmd.Watch, cmd.Interval, func(ctx context.Context) (render.View, error) {
		report, err := cmd.collect(ctx, console)
		if err != nil {
			return nil, err
		}
		if cmd.RequireRunning && !report.Health.Ready {
			remedy := "run \"blackbird doctor\" for the failing check"
			if report.Legacy {
				remedy = legacyProtocolRemedy
			}
			return nil, withRemedy(unavailableFault(nil, "daemon is %s", orAbsent(report.Daemon)), remedy)
		}
		return newView(report, drawStatus), nil
	})
}

func (cmd *StatusCmd) collect(ctx context.Context, console *Console) (statusReport, error) {
	report := statusReport{Build: console.Deps.Build, Service: map[string]string{}, Daemon: install.DaemonNotInstalled}

	if manager, err := console.product(); err == nil {
		line, statusErr := manager.Status(ctx)
		if statusErr != nil {
			report.Problems = append(report.Problems, "read installation status: "+statusErr.Error())
		} else {
			report.Service = serviceFacts(line)
			report.Daemon = report.Service["daemon"]
			if console.Globals.Verbose > 0 {
				report.ServiceLine = line
			}
		}
	} else {
		report.Problems = append(report.Problems, err.Error())
	}

	probeCtx := ctx
	if cmd.Timeout > 0 {
		timed, cancel := context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()
		probeCtx = timed
	}
	if admin, err := console.admin(); err == nil {
		state := inspectDaemon(probeCtx, console, admin)
		report.Health = state.Health
		report.Legacy = state.Legacy
		if state.Probe.Address != "" {
			probe := state.Probe
			report.Probe = &probe
		}
		report.Undiscovered = state.Undiscovered
		switch {
		case state.Legacy:
			report.Daemon = legacyProtocolState
			report.Problems = append(report.Problems, legacyProtocolProblem)
		case state.Undiscovered:
			report.Daemon = undiscoveredState
			report.Problems = append(report.Problems, undiscoveredProblem)
		}
		if state.Health.Ready && console.Globals.Verbose > 0 {
			if identity, identityErr := admin.Identity(probeCtx); identityErr == nil {
				report.Identity = &identity
			} else {
				report.Problems = append(report.Problems, "read daemon identity: "+identityErr.Error())
			}
		}
	} else {
		report.Problems = append(report.Problems, err.Error())
	}

	if store, err := console.store(); err == nil {
		path, pathErr := console.databasePath()
		if pathErr != nil {
			report.Problems = append(report.Problems, pathErr.Error())
		} else {
			database, inspectErr := store.Inspect(ctx, path, false)
			database.Path = path
			if inspectErr != nil {
				report.Problems = append(report.Problems, "read database: "+inspectErr.Error())
			}
			if staleRead(database) {
				report.Problems = append(report.Problems, staleReadProblem)
			}
			report.Database = database
		}
	} else {
		report.Problems = append(report.Problems, err.Error())
	}

	return report, nil
}

func drawStatus(doc *render.Document, report statusReport) {
	doc.Heading("Blackbird")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "version", Value: report.Build.Version},
		{Key: "commit", Value: report.Build.Commit},
	}})

	doc.Blank()
	doc.Heading("Service")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "daemon", Value: orAbsent(report.Daemon), Role: daemonRole(report.Daemon)},
		{Key: "definition", Value: orAbsent(serviceDefinitionState(report.Service)),
			Role: definitionRole(serviceDefinitionState(report.Service))},
		{Key: "path", Value: orAbsent(report.Service["path"])},
		{Key: "updater", Value: orAbsent(report.Service["updater"])},
	}})
	if report.ServiceLine != "" {
		doc.Line(render.RoleMuted, "  "+report.ServiceLine)
	}

	doc.Blank()
	doc.Heading("Daemon")
	doc.Fields(render.Fields{Indent: 2, Items: daemonFields(report)})
	if report.Identity != nil {
		doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
			{Key: "pid", Value: itoa(report.Identity.PID)},
			{Key: "uptime", Value: render.Duration(time.Duration(report.Identity.UptimeMS) * time.Millisecond)},
			{Key: "http", Value: orAbsent(report.Identity.HTTPAddress)},
			{Key: "mcp", Value: orAbsent(report.Identity.MCPAddress)},
			{Key: "database", Value: orAbsent(report.Identity.DatabasePath)},
		}})
	}

	doc.Blank()
	doc.Heading("Database")
	doc.Fields(render.Fields{Indent: 2, Items: databaseFields(report.Database)})

	if len(report.Problems) > 0 {
		doc.Blank()
		doc.Heading("Problems")
		for _, problem := range report.Problems {
			doc.Status(render.StatusWarn, problem)
		}
	}
}

// daemonFields refuses to answer "reachable no" about a process that is
// answering on its port. A daemon predating the handshake protocol has no
// liveness endpoint to report readiness from at all, so readiness is named
// unknown rather than false.
func daemonFields(report statusReport) []render.Field {
	if report.Legacy && report.Probe != nil {
		return []render.Field{
			{Key: "reachable", Value: "yes (older protocol)", Role: render.RoleWarn},
			{Key: "ready", Value: "unknown", Role: render.RoleMuted},
			{Key: "address", Value: orAbsent(report.Probe.Address)},
			{Key: "detail", Value: "accepts connections but serves no " + livenessPath +
				" and writes no handshake record"},
		}
	}
	if report.Undiscovered && report.Probe != nil {
		return []render.Field{
			{Key: "reachable", Value: "yes", Role: render.RoleOK},
			{Key: "ready", Value: "yes", Role: render.RoleOK},
			{Key: "address", Value: orAbsent(report.Probe.Address)},
			{Key: "detail", Value: "answers " + livenessPath + " but left no discovery record, " +
				"so authenticated reads are unavailable"},
		}
	}
	return []render.Field{
		{Key: "reachable", Value: yesNo(report.Health.Reachable), Role: boolRole(report.Health.Reachable)},
		{Key: "ready", Value: yesNo(report.Health.Ready), Role: boolRole(report.Health.Ready)},
		{Key: "version", Value: orAbsent(report.Health.Version)},
		{Key: "detail", Value: orAbsent(report.Health.Detail)},
	}
}

func databaseFields(database Database) []render.Field {
	if !database.Present {
		return []render.Field{
			{Key: "path", Value: orAbsent(database.Path)},
			{Key: "present", Value: "no", Role: render.RoleWarn},
		}
	}
	schema := render.RoleOK
	if !database.Supported {
		schema = render.RoleError
	}
	return []render.Field{
		{Key: "path", Value: orAbsent(database.Path)},
		{Key: "read", Value: readModeSummary(database), Role: readModeRole(database)},
		{Key: "size", Value: render.Bytes(database.SizeBytes)},
		{Key: "wal", Value: render.Bytes(database.WALBytes)},
		{Key: "schema", Value: schemaSummary(database), Role: schema},
		{Key: "journal", Value: orAbsent(database.JournalMode)},
		{Key: "clean-shutdown", Value: yesNo(database.CleanShutdown)},
	}
}

// A stale read opens the file immutable, which bypasses the write-ahead log:
// every count below is behind the daemon by the whole uncheckpointed WAL. That
// is a wrong answer, not a caveat, so it is named wherever the numbers appear.
const (
	readModeLive  = "live"
	readModeStale = "stale"

	staleReadProblem = "the database was read in stale mode: these numbers exclude the " +
		"uncheckpointed write-ahead log and are behind the daemon"
	staleReadRemedy = "re-run as the user that owns the database, or stop the daemon and " +
		"run \"blackbird gc --checkpoint\" to fold the write-ahead log into the file"
)

func staleRead(database Database) bool { return database.Present && database.Mode == readModeStale }

func readModeSummary(database Database) string {
	if staleRead(database) {
		return readModeStale + " (behind the daemon by the uncheckpointed WAL)"
	}
	return orAbsent(database.Mode)
}

func readModeRole(database Database) render.Role {
	switch {
	case staleRead(database):
		return render.RoleWarn
	case database.Mode == readModeLive:
		return render.RoleOK
	default:
		return render.RoleMuted
	}
}

func schemaSummary(database Database) string {
	if database.SchemaVersion == database.ExpectedSchemaVersion {
		return "v" + itoa(database.SchemaVersion)
	}
	return "v" + itoa(database.SchemaVersion) + " want v" + itoa(database.ExpectedSchemaVersion)
}

// The daemon Homebrew leaves running through an upgrade predates the handshake
// protocol: it accepts connections on its address, answers 404 at the liveness
// path, and writes no handshake record. launchd does not restart a job when the
// binary underneath it is replaced, so this is the state every existing
// installation is in the first time the new CLI runs. Reported as "unreachable"
// it sends the user to a clean log and to "update", which only re-runs
// Homebrew; the one command that ends it is "install", which rewrites the
// service definition to the explicit daemon form and kickstarts the job.
const (
	livenessPath = "/healthz"

	legacyProtocolState  = install.DaemonRunning + " (older protocol)"
	legacyProtocolRemedy = "run \"blackbird install\" to rewrite the service definition and restart the daemon"

	// The Daemon section above already names the address and what answered
	// there, so this line carries only the one action that ends the state.
	legacyProtocolProblem = "the daemon predates the handshake protocol; run \"blackbird install\""

	// A daemon that answers the liveness path but left no readable record is
	// current and healthy; only discovery is missing, which is what publishing
	// the record best-effort at startup allows. Restarting republishes it.
	undiscoveredState   = install.DaemonRunning + " (no discovery record)"
	undiscoveredRemedy  = "restart the daemon with \"blackbird install\" to republish its discovery record"
	undiscoveredProblem = "the daemon is serving but left no discovery record; restart it with \"blackbird install\""

	probeTimeout       = 2 * time.Second
	probeResponseLimit = 4 << 10
)

// daemonProbe is what an unauthenticated request to the liveness path found.
// Accepted and Status are separate facts: a refused connection means no daemon,
// while an accepted connection answered 404 means a daemon that predates the
// endpoint.
type daemonProbe struct {
	Address  string `json:"address"`
	Accepted bool   `json:"accepted"`
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// daemonState is the single liveness answer status and doctor both read. Missing
// reports that no client was bound at all; Failure reports that the bound client
// could not complete the probe.
type daemonState struct {
	Health       Health
	Probe        daemonProbe
	Legacy       bool
	Undiscovered bool
	Missing      error
	Failure      error
}

func inspectDaemon(ctx context.Context, console *Console, admin AdminPort) daemonState {
	state := daemonState{}
	health, err := admin.Health(ctx)
	state.Health = health
	if err != nil {
		state.Failure = err
		state.Health.Detail = err.Error()
	}
	if state.Health.Reachable {
		return state
	}
	state.Probe = probeLiveness(ctx, daemonAddress(console, state.Health))
	state.Legacy = state.Probe.Accepted && state.Probe.Status == http.StatusNotFound
	state.Undiscovered = state.Probe.Accepted && state.Probe.Status == http.StatusOK
	return state
}

// daemonServes answers "would writing to path race a running daemon" for
// callers that must not mutate a live database. The question is about this
// database, not about the port: something listening on the daemon's address
// says nothing about a database the user named explicitly with --db.
//
// When the daemon can be authenticated its own identity settles it. When it
// cannot — no record published, or a daemon predating the record entirely —
// a bare connection is treated as serving the daemon's default database, since
// a false negative there means two writers against one SQLite file.
func daemonServes(ctx context.Context, console *Console, path string) (bool, string) {
	health := Health{}
	if admin, err := console.admin(); err == nil {
		if reported, probeErr := admin.Health(ctx); probeErr == nil {
			health = reported
			if reported.Reachable {
				identity, identityErr := admin.Identity(ctx)
				// Only a database the daemon positively names, and that is not
				// this one, clears the guard. Not knowing means assuming the worst.
				if identityErr != nil || identity.DatabasePath == "" {
					return true, "it answers " + livenessPath
				}
				if samePath(identity.DatabasePath, path) {
					return true, "it has " + path + " open"
				}
				return false, ""
			}
		}
	}
	if !samePath(console.Deps.Defaults.SQLitePath, path) {
		return false, ""
	}
	if probe := probeLiveness(ctx, daemonAddress(console, health)); probe.Accepted {
		return true, "something accepts connections at " + probe.Address
	}
	return false, ""
}

func samePath(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

// daemonAddress is where a daemon would be if one were running. The handshake
// record is authoritative when it exists, but the whole point of this probe is
// the case where it does not, which is why the configured default is the last
// resort rather than an error.
func daemonAddress(console *Console, health Health) string {
	if console.Globals != nil && console.Globals.Address != "" {
		return console.Globals.Address
	}
	if health.Address != "" {
		return health.Address
	}
	return console.Deps.Defaults.HTTPAddress
}

// probeLiveness answers the question the admin client cannot: whether anything
// is listening at the daemon's address, and what it says at the liveness path.
// The client will not dial without a handshake record, so without this probe a
// daemon written before that record is indistinguishable from no daemon at all.
func probeLiveness(ctx context.Context, address string) daemonProbe {
	probe := daemonProbe{Address: address}
	if address == "" {
		return probe
	}
	dialer := net.Dialer{Timeout: probeTimeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		probe.Detail = err.Error()
		return probe
	}
	_ = connection.Close()
	probe.Accepted = true

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+livenessPath, nil)
	if err != nil {
		probe.Detail = err.Error()
		return probe
	}
	response, err := (&http.Client{Timeout: probeTimeout}).Do(request)
	if err != nil {
		probe.Detail = err.Error()
		return probe
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, probeResponseLimit))
	probe.Status = response.StatusCode
	return probe
}

func daemonRole(state string) render.Role {
	switch {
	case state == "":
		return render.RoleMuted
	case state == legacyProtocolState, state == undiscoveredState:
		return render.RoleWarn
	case hasPrefix(state, install.DaemonRunning):
		return render.RoleOK
	case hasPrefix(state, install.DaemonCrashLooping), hasPrefix(state, install.DaemonUnreachable):
		return render.RoleError
	default:
		return render.RoleWarn
	}
}

func definitionRole(state string) render.Role {
	switch state {
	case install.DefinitionCurrent:
		return render.RoleOK
	case install.DefinitionStale:
		return render.RoleWarn
	default:
		return render.RoleMuted
	}
}
