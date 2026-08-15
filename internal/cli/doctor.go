package cli

import (
	"context"
	"slices"
	"strings"

	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/install"
)

const (
	checkPass = "pass"
	checkWarn = "warn"
	checkFail = "fail"
)

// DoctorCmd runs every check the CLI can perform without a credential and
// prints a remedy for each failure. It exits ExitDegraded when a check fails so
// an unattended caller can react without parsing the report.
type DoctorCmd struct {
	Strict bool     `help:"Treat warnings as failures."`
	Deep   bool     `help:"Include slow checks: database integrity."`
	Only   []string `placeholder:"CHECK" help:"Run only the named checks."`
}

type checkResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Remedy string `json:"remedy,omitempty"`
}

type doctorReport struct {
	Checks []checkResult `json:"checks"`
	Passed int           `json:"passed"`
	Warned int           `json:"warned"`
	Failed int           `json:"failed"`
	Strict bool          `json:"strict"`
}

func (cmd *DoctorCmd) Run(ctx context.Context, console *Console) error {
	checks := cmd.collect(ctx, console)
	if len(cmd.Only) > 0 {
		checks = filterChecks(checks, cmd.Only)
		if len(checks) == 0 {
			return usageFault("no check matches %s", strings.Join(cmd.Only, ", "))
		}
	}

	report := doctorReport{Checks: checks, Strict: cmd.Strict}
	for _, check := range checks {
		switch check.Status {
		case checkPass:
			report.Passed++
		case checkWarn:
			report.Warned++
		default:
			report.Failed++
		}
	}
	if err := console.present(newView(report, drawDoctor)); err != nil {
		return err
	}
	if report.Failed > 0 || (cmd.Strict && report.Warned > 0) {
		return fault(ExitDegraded, nil, "%d check(s) failed", report.Failed+strictWarnings(cmd.Strict, report.Warned))
	}
	return nil
}

func strictWarnings(strict bool, warned int) int {
	if strict {
		return warned
	}
	return 0
}

// checkGroup is one probe and every check name it can produce. --only selects
// groups before they run: the network probe and the --deep whole-database
// foreign-key check must not be paid for by a caller who asked for neither.
type checkGroup struct {
	names []string
	run   func(ctx context.Context, console *Console, daemon *daemonCache) []checkResult
}

// daemonCache holds the one liveness answer the service and daemon checks
// share. Probing twice would let a single run report two different daemons, and
// the service check needs the answer to tell a daemon that is merely older than
// this CLI from one that is failing to start.
type daemonCache struct {
	state *daemonState
}

func (cache *daemonCache) get(ctx context.Context, console *Console) daemonState {
	if cache.state != nil {
		return *cache.state
	}
	state := daemonState{}
	admin, err := console.admin()
	if err != nil {
		state.Missing = err
	} else {
		timed, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		state = inspectDaemon(timed, console, admin)
	}
	cache.state = &state
	return state
}

func (cmd *DoctorCmd) groups() []checkGroup {
	return []checkGroup{
		{names: []string{"binary"}, run: cmd.binaryCheck},
		{names: []string{"service.state", "service.definition", "updater"}, run: cmd.serviceChecks},
		{names: []string{"daemon.liveness"}, run: cmd.daemonChecks},
		{names: []string{"database.file", "database.read", "database.schema", "database.integrity"},
			run: cmd.databaseChecks},
	}
}

func (cmd *DoctorCmd) collect(ctx context.Context, console *Console) []checkResult {
	daemon := &daemonCache{}
	checks := []checkResult{}
	for _, group := range cmd.groups() {
		if !cmd.selects(group) {
			continue
		}
		checks = append(checks, group.run(ctx, console, daemon)...)
	}
	return checks
}

func (cmd *DoctorCmd) selects(group checkGroup) bool {
	if len(cmd.Only) == 0 {
		return true
	}
	for _, name := range group.names {
		if slices.Contains(cmd.Only, name) {
			return true
		}
	}
	return false
}

func (cmd *DoctorCmd) binaryCheck(_ context.Context, console *Console, _ *daemonCache) []checkResult {
	return []checkResult{{
		Name:   "binary",
		Status: checkPass,
		Detail: "version=" + orAbsent(console.Deps.Build.Version) + " commit=" + orAbsent(console.Deps.Build.Commit),
	}}
}

func (cmd *DoctorCmd) serviceChecks(ctx context.Context, console *Console, daemon *daemonCache) []checkResult {
	manager, err := console.product()
	if err != nil {
		return []checkResult{{Name: "service.state", Status: checkWarn, Detail: err.Error()}}
	}
	line, err := manager.Status(ctx)
	if err != nil {
		return []checkResult{{Name: "service.state", Status: checkFail, Detail: err.Error(),
			Remedy: "run \"blackbird install\""}}
	}
	facts := serviceFacts(line)

	state := checkResult{Name: "service.state", Status: checkPass, Detail: "daemon=" + orAbsent(facts["daemon"])}
	switch {
	case hasPrefix(facts["daemon"], install.DaemonRunning):
	case facts["daemon"] == install.DaemonNotInstalled:
		state.Status = checkFail
		state.Remedy = "run \"blackbird install\""
	case daemon.get(ctx, console).Legacy:
		// The supervisor's own probe speaks the current protocol, so it calls
		// this daemon unreachable too. The process is up and serving.
		state.Detail = "daemon=" + legacyProtocolState
	case daemon.get(ctx, console).Undiscovered:
		state.Detail = "daemon=" + undiscoveredState
	default:
		state.Status = checkFail
		state.Remedy = "run \"blackbird logs --stream=err\" and then \"blackbird update\""
	}

	definition := checkResult{Name: "service.definition", Status: checkPass,
		Detail: "definition=" + serviceDefinitionState(facts) + " argv=" + strings.Join(manager.ServiceArgv(), " ")}
	switch serviceDefinitionState(facts) {
	case install.DefinitionCurrent:
	case install.DefinitionStale:
		definition.Status = checkWarn
		definition.Remedy = "run \"blackbird install\" to rewrite the service definition"
	default:
		definition.Status = checkFail
		definition.Remedy = "run \"blackbird install\""
	}

	updater := checkResult{Name: "updater", Status: checkPass, Detail: "updater=" + orAbsent(facts["updater"])}
	if facts["updater"] != "scheduled" {
		updater.Status = checkWarn
		updater.Remedy = "run \"blackbird install\" to schedule unattended updates"
	}

	return []checkResult{state, definition, updater}
}

func (cmd *DoctorCmd) daemonChecks(ctx context.Context, console *Console, daemon *daemonCache) []checkResult {
	return []checkResult{cmd.daemonCheck(ctx, console, daemon)}
}

// A daemon running an older protocol is a warning, not a failure: nothing is
// broken, one command converges it, and a red line beside a remedy that reads
// "inspect the log" is what sent users to a clean log after every upgrade.
func (cmd *DoctorCmd) daemonCheck(ctx context.Context, console *Console, daemon *daemonCache) checkResult {
	check := checkResult{Name: "daemon.liveness"}
	state := daemon.get(ctx, console)
	switch {
	case state.Missing != nil:
		check.Status = checkWarn
		check.Detail = state.Missing.Error()
	case state.Legacy:
		check.Status = checkWarn
		check.Detail = "daemon=" + legacyProtocolState + " address=" + orAbsent(state.Probe.Address) +
			": it accepts connections but serves no " + livenessPath + " and writes no handshake record"
		check.Remedy = legacyProtocolRemedy
	case state.Undiscovered:
		check.Status = checkWarn
		check.Detail = "daemon=" + undiscoveredState + " address=" + orAbsent(state.Probe.Address) +
			": it answers " + livenessPath + " but left no discovery record"
		check.Remedy = undiscoveredRemedy
	case state.Failure != nil:
		check.Status = checkFail
		check.Detail = state.Failure.Error()
		check.Remedy = "run \"blackbird logs --stream=err\""
	case !state.Health.Ready:
		check.Status = checkFail
		check.Detail = "daemon answered but storage is unavailable: " + orAbsent(state.Health.Detail)
		check.Remedy = "run \"blackbird doctor --deep\" and inspect database.schema"
	default:
		check.Status = checkPass
		check.Detail = "version=" + orAbsent(state.Health.Version) + " schema=v" + itoa(state.Health.SchemaVersion)
	}
	return check
}

func (cmd *DoctorCmd) databaseChecks(ctx context.Context, console *Console, _ *daemonCache) []checkResult {
	store, err := console.store()
	if err != nil {
		return []checkResult{{Name: "database.file", Status: checkWarn, Detail: err.Error()}}
	}
	path, err := console.databasePath()
	if err != nil {
		return []checkResult{{Name: "database.file", Status: checkFail, Detail: err.Error(),
			Remedy: "pass --db=PATH"}}
	}
	database, err := store.Inspect(ctx, path, cmd.Deep)
	if err != nil {
		return []checkResult{{Name: "database.file", Status: checkFail, Detail: path + ": " + err.Error(),
			Remedy: "run \"blackbird install\" to create the data directory, then start the daemon"}}
	}

	file := checkResult{Name: "database.file", Status: checkPass,
		Detail: path + " size=" + render.Bytes(database.SizeBytes) + " wal=" + render.Bytes(database.WALBytes)}
	if !database.Present {
		file.Status = checkFail
		file.Remedy = "start the daemon to create the database"
	}

	read := checkResult{Name: "database.read", Status: checkPass, Detail: "mode=" + orAbsent(database.Mode)}
	if staleRead(database) {
		read.Status = checkWarn
		read.Detail = "mode=" + readModeStale + ": " + staleReadProblem
		read.Remedy = staleReadRemedy
	}

	schema := checkResult{Name: "database.schema", Status: checkPass, Detail: schemaDetail(database)}
	switch {
	case !database.Present:
		schema.Status = checkWarn
		schema.Detail = "database is absent"
	case !database.Supported || database.SchemaVersion != database.ExpectedSchemaVersion:
		schema.Status = checkFail
		schema.Remedy = "the daemon cannot open this database; run \"blackbird logs --stream=err\" " +
			"and then \"blackbird update\" to install a binary matching the schema"
	case !database.LedgerComplete:
		schema.Status = checkWarn
		schema.Remedy = "run \"blackbird doctor --deep\""
	}

	checks := []checkResult{file, read, schema}
	if cmd.Deep && database.Present {
		integrity := checkResult{Name: "database.integrity", Status: checkPass,
			Detail: "quick_check=" + orAbsent(database.QuickCheck) + " foreign_key_failures=" + itoa(database.ForeignKeyFailures)}
		if database.QuickCheck != "ok" || database.ForeignKeyFailures > 0 {
			integrity.Status = checkFail
			integrity.Remedy = "stop the daemon and restore the most recent backup"
		}
		checks = append(checks, integrity)
	}
	return checks
}

func schemaDetail(database Database) string {
	return "schema_version=" + itoa(database.SchemaVersion) +
		" want=" + itoa(database.ExpectedSchemaVersion) +
		" application_id=" + itoa(database.ApplicationID)
}

func filterChecks(checks []checkResult, only []string) []checkResult {
	kept := make([]checkResult, 0, len(checks))
	for _, check := range checks {
		if slices.Contains(only, check.Name) {
			kept = append(kept, check)
		}
	}
	return kept
}

func drawDoctor(doc *render.Document, report doctorReport) {
	doc.Heading("Doctor")
	for _, check := range report.Checks {
		doc.Status(checkStatus(check.Status), strings.ToUpper(check.Status)+"  "+check.Name+"  "+check.Detail)
		if check.Remedy != "" {
			doc.Wrapped(render.RoleMuted, "      remedy: "+check.Remedy)
		}
	}
	doc.Blank()
	doc.Linef(render.RolePlain, "%d passed, %d warned, %d failed", report.Passed, report.Warned, report.Failed)
}

func checkStatus(status string) render.Status {
	switch status {
	case checkPass:
		return render.StatusOK
	case checkWarn:
		return render.StatusWarn
	default:
		return render.StatusError
	}
}
