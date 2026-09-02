package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
		{names: []string{"database.file", "database.permissions", "database.read", "database.schema",
			"database.shutdown", "disk.free", "reservations.expired", "database.integrity"},
			run: cmd.databaseChecks},
		{names: []string{"clients"}, run: cmd.clientChecks},
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
	switch facts["updater"] {
	case install.UpdaterScheduled:
	case install.UpdaterUnsupported:
		// A pass, not a warning: nothing is broken, and the remedy below would
		// send this machine to an install that declines to schedule an updater.
		// Under --strict a warning here would fail the gate on every tick.
		updater.Detail += ": " + install.UpdaterUnsupportedReason
	default:
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
//
// The order of the cases below is the diagnosis. "Nothing answered" has to be
// decided before readiness, because a daemon that never answered is not ready
// either: reading the states in the other order reported a dead daemon as one
// whose storage had failed, and sent the user to inspect a database schema
// while holding a connection-refused error.
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
	case !state.Health.Reachable:
		check.Status = checkFail
		check.Detail = "daemon=" + install.DaemonUnreachable + " address=" + orAbsent(probedAddress(state)) +
			": " + orAbsent(probeFailure(state))
		check.Remedy = unreachableDaemonRemedy
	case state.Failure != nil:
		check.Status = checkFail
		check.Detail = "daemon answered " + livenessPath + " but the readiness probe did not complete: " +
			state.Failure.Error()
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

// The remedy names starting the daemon first because that is what an
// unreachable daemon needs in every case doctor can distinguish here: install
// converges the service definition and kickstarts the job, and the log is only
// worth reading once something has tried and failed to come up.
const unreachableDaemonRemedy = "run \"blackbird install\" to start the service, " +
	"then \"blackbird logs --stream=err\" if it still does not answer"

// probedAddress is where the daemon was looked for. The client reports the
// address from the handshake record even when the request failed, and the
// fallback probe reports the one it dialled, so between them an unreachable
// daemon still names a port the user can check.
func probedAddress(state daemonState) string {
	if state.Health.Address != "" {
		return state.Health.Address
	}
	return state.Probe.Address
}

func probeFailure(state daemonState) string {
	switch {
	case state.Failure != nil:
		return state.Failure.Error()
	case state.Health.Detail != "":
		return state.Health.Detail
	default:
		return state.Probe.Detail
	}
}

func (cmd *DoctorCmd) databaseChecks(ctx context.Context, console *Console, daemon *daemonCache) []checkResult {
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

	schema := schemaCheck(database)

	checks := []checkResult{file, permissionsCheck(database, path), read, schema,
		cmd.shutdownCheck(ctx, console, daemon, database), diskCheck(database), expiredLeaseCheck(database)}
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

// schemaCheck reports what the schema version actually means, which is not one
// thing. The daemon climbs a migration ladder on open, so a database older than
// this binary is not broken — it converges the next time the daemon opens it,
// and doctor reads the file read-only, so doctor is exactly the observer that
// sees the un-migrated state. Reporting that as a failure sends the user to an
// update that has nothing to install and fails --strict over a condition that
// heals itself.
//
// The three unhealthy directions need three different answers:
//
//   - A foreign application id is not a Blackbird database at all. No version of
//     Blackbird can open it, so no update helps.
//   - A version above this binary's was written by a newer Blackbird. That is
//     the one case an update actually fixes.
//   - A version below 1, or one this binary cannot climb from, is off the ladder
//     and only a restore or a fresh database resolves it.
func schemaCheck(database Database) checkResult {
	schema := checkResult{Name: "database.schema", Status: checkPass, Detail: schemaDetail(database)}
	switch {
	case !database.Present:
		schema.Status = checkWarn
		schema.Detail = "database is absent"
	case database.ApplicationID != database.ExpectedApplicationID:
		schema.Status = checkFail
		schema.Remedy = "this file is not a Blackbird database; move it aside, or restore one with " +
			"\"blackbird restore --from PATH\""
	case database.SchemaVersion > database.ExpectedSchemaVersion:
		schema.Status = checkFail
		schema.Remedy = "this database was written by a newer Blackbird; run \"blackbird update\" " +
			"to install a binary that understands its schema"
	case database.SchemaVersion < 1:
		schema.Status = checkFail
		schema.Remedy = "this schema version is not one the daemon can migrate from; restore a backup " +
			"with \"blackbird restore --from PATH\""
	case database.SchemaVersion < database.ExpectedSchemaVersion:
		// On the ladder and behind: the next daemon start migrates it. Say so,
		// because the number alone reads like the failure it used to be.
		schema.Status = checkWarn
		schema.Detail += " (the daemon migrates this on its next start)"
		schema.Remedy = "run \"blackbird install\" to start the service, which applies the migration"
	case !database.Supported:
		schema.Status = checkFail
		schema.Remedy = "the daemon cannot open this database; run \"blackbird logs --stream=err\" " +
			"and then \"blackbird update\" to install a binary matching the schema"
	case !database.LedgerComplete:
		schema.Status = checkWarn
		schema.Remedy = "run \"blackbird doctor --deep\""
	}
	return schema
}

func schemaDetail(database Database) string {
	return "schema_version=" + itoa(database.SchemaVersion) +
		" want=" + itoa(database.ExpectedSchemaVersion) +
		" application_id=" + itoa(database.ApplicationID)
}

// The three thresholds below are deliberately generous. Doctor is read by
// someone who already suspects a problem, so a check that fires on a healthy
// machine costs more attention than one that stays quiet slightly too long.
const (
	// Running out of disk corrupts nothing — SQLite fails the write — but every
	// coordination call starts failing, so the floor sits where there is still
	// room to stop the daemon, vacuum, and read the logs.
	diskFreeFloorBytes = 1 << 30

	// The floor rises with the database because a vacuum writes a second copy
	// of the file before replacing the original.
	diskFreeSizeMultiple = 10

	// The rendering fs.FileMode gives owner-only read and write. Only its last
	// six characters are read, so any group or other bit fails the check
	// whatever the owner bits say.
	ownerOnlyMode = "-rw-------"

	// Expired-but-unreleased leases block nobody: the daemon's conflict test
	// compares expiry against now, so an expired lease is already invisible to
	// an acquire. They measure whether agents release what they reserve, and a
	// handful is ordinary churn between an agent's last renewal and its exit.
	// A backlog this size means the protocol is being ignored, which is worth
	// one line of warning and no more.
	expiredLeaseBacklog = 25
)

// permissionsCheck fails rather than warns: the database holds every message
// body on the machine, and a mode that lets another account read them is not a
// state the user should have to decide about.
func permissionsCheck(database Database, path string) checkResult {
	check := checkResult{Name: "database.permissions", Status: checkPass,
		Detail: "mode=" + orAbsent(database.FileMode)}
	if !groupOrOtherReadable(database.FileMode) {
		return check
	}
	check.Status = checkFail
	check.Detail = "mode=" + database.FileMode +
		": every message body and coordination record is readable by another account on this machine"
	check.Remedy = "run \"chmod 600 " + path + "\""
	return check
}

// groupOrOtherReadable reads fs.FileMode's own rendering, where the first
// character is the file type and the remaining nine are owner, group, and other
// in that order. An empty or unrecognized mode reports nothing rather than
// guessing: a store that does not report the mode has not found a problem.
func groupOrOtherReadable(mode string) bool {
	if len(mode) != len(ownerOnlyMode) {
		return false
	}
	return strings.Trim(mode[4:], "-") != ""
}

func diskCheck(database Database) checkResult {
	check := checkResult{Name: "disk.free", Status: checkPass,
		Detail: "free=" + freeSpace(database) + " database=" + render.Bytes(database.SizeBytes)}
	// A store that reports no free space has not measured it. Warning on a
	// number nobody supplied would fire on every assembly that reads the
	// database with a reader that does not stat the filesystem.
	if database.FreeBytes <= 0 {
		return check
	}
	switch {
	case database.FreeBytes < diskFreeFloorBytes:
		check.Detail += ": below the " + render.Bytes(diskFreeFloorBytes) + " floor"
	case database.FreeBytes < diskFreeSizeMultiple*database.SizeBytes:
		check.Detail += ": under " + itoa(diskFreeSizeMultiple) + " times the size of the database"
	default:
		return check
	}
	check.Status = checkWarn
	check.Remedy = "free space on this filesystem; \"blackbird gc --vacuum\" with the daemon stopped " +
		"returns the database's own free pages to it"
	return check
}

func freeSpace(database Database) string {
	if database.FreeBytes <= 0 {
		return render.Absent
	}
	return render.Bytes(database.FreeBytes)
}

// expiredLeaseCheck reports reservations whose holder never released them. It
// is a warning about how agents are behaving, not about the daemon, so the
// remedy is the command that names the holders rather than anything to run
// against the database.
func expiredLeaseCheck(database Database) checkResult {
	check := checkResult{Name: "reservations.expired", Status: checkPass,
		Detail: "expired=" + itoa(database.ExpiredActiveLeases) + " active=" + itoa(database.ActiveLeases)}
	if database.ExpiredActiveLeases <= expiredLeaseBacklog {
		return check
	}
	check.Status = checkWarn
	check.Detail += ": agents are ending without releasing their reservations"
	check.Remedy = "run \"blackbird reservations --state=expired\" to find which agents leave them behind"
	return check
}

// shutdownCheck gives doctor an opinion about the one status row that alarms
// readers for no reason. The flag stays unclean for as long as the daemon holds
// the database open, so it only diagnoses anything once nothing is serving —
// and that is the case doctor was silent about, where it means the last daemon
// exited without closing up.
//
// It consults the shared liveness answer rather than probing again: the verdict
// is a joint fact about the database and the daemon, and a full run has already
// paid for that probe.
func (cmd *DoctorCmd) shutdownCheck(
	ctx context.Context,
	console *Console,
	daemon *daemonCache,
	database Database,
) checkResult {
	check := checkResult{Name: "database.shutdown", Status: checkPass,
		Detail: "clean_shutdown=" + yesNo(database.CleanShutdown)}
	switch {
	case !database.Present:
		check.Detail = "database is absent"
	case database.CleanShutdown:
	case daemonServingState(daemon.get(ctx, console)):
		check.Detail += ": expected while the daemon holds the database open"
	default:
		check.Status = checkWarn
		check.Detail += ": " + cleanShutdownDetail
		check.Remedy = cleanShutdownRemedy
	}
	return check
}

func daemonServingState(state daemonState) bool {
	return daemonServing(state.Health, state.Legacy, state.Undiscovered)
}

// The MCP client entry is the whole delivery model: install merges a blackbird
// server into each client's own configuration file, and the clients rewrite
// those files themselves. When one drops the entry the daemon stays healthy,
// every other check stays green, and Blackbird has simply vanished from that
// agent's tool list with no diagnostic anywhere. So doctor re-reads what
// install wrote instead of trusting that it stayed written.
//
// Only a client whose configuration file exists is reported on. A client this
// user does not have is not a finding, exactly as an unsupported updater is
// not, and a warning about it would be permanent and unfixable.
const (
	clientConfigured = "configured"
	clientMissing    = "missing"
	clientUnmanaged  = "unmanaged"

	clientRemedy = "run \"blackbird install\" to restore the MCP server entry"

	codexBlackbirdTable = "[mcp_servers.blackbird]"
)

func (cmd *DoctorCmd) clientChecks(_ context.Context, console *Console, _ *daemonCache) []checkResult {
	check := checkResult{Name: "clients", Status: checkPass}
	want := mcpURL(console)
	clients := detectedClients(console)
	states := make([]string, 0, len(clients))
	for _, client := range clients {
		state, configured := client.state(want)
		states = append(states, client.name+"="+state)
		if !configured {
			check.Status = checkWarn
			check.Remedy = clientRemedy
		}
	}
	if len(states) == 0 {
		check.Detail = "no MCP client configuration was found for this user"
		return []checkResult{check}
	}
	check.Detail = "url=" + want + " " + strings.Join(states, " ")
	return []checkResult{check}
}

// mcpURL is the address the client entries must name. It comes from the
// daemon's own configured listener rather than from a constant the installer
// also holds, so a daemon moved to another port reports the entries as drifted,
// which is what they are.
func mcpURL(console *Console) string {
	address := console.Deps.Defaults.MCPAddress
	if address == "" {
		address = install.MCPAddress
	}
	return "http://" + address
}

// mcpClient is one MCP client's configuration file and how to read the
// blackbird server entry out of it. collection is the JSON object that holds
// the servers; an empty collection means Codex's TOML file.
type mcpClient struct {
	name       string
	path       string
	collection string
	unmanaged  bool
}

func (client mcpClient) state(want string) (string, bool) {
	if client.unmanaged {
		return clientUnmanaged + "(" + filepath.Base(client.path) + ")", true
	}
	url, found, err := client.read()
	switch {
	case err != nil:
		return "unreadable(" + err.Error() + ")", false
	case !found:
		return clientMissing, false
	case url != want:
		return "drifted(url=" + url + ")", false
	default:
		return clientConfigured, true
	}
}

func (client mcpClient) read() (string, bool, error) {
	if client.collection == "" {
		return readCodexClient(client.path)
	}
	return readJSONClient(client.path, client.collection)
}

// detectedClients resolves the paths install writes to, from the injected
// environment only. The environment is the whole input: a run pointed at
// another home must report on that home's files rather than on the ones the
// process happens to have.
func detectedClients(console *Console) []mcpClient {
	home := clientHome(console.Deps.Env)
	if home == "" {
		return nil
	}
	config := clientConfigHome(console.Deps.Env, home)
	openCode := mcpClient{name: "opencode", path: filepath.Join(config, "opencode", "opencode.json"), collection: "mcp"}
	// Install writes no entry when OpenCode keeps its configuration as JSONC,
	// because it will not parse one. Reporting that as a missing entry would
	// send the user to an install that deliberately leaves the file alone.
	if jsonc := filepath.Join(config, "opencode", "opencode.jsonc"); fileExists(jsonc) {
		openCode = mcpClient{name: "opencode", path: jsonc, unmanaged: true}
	}
	candidates := []mcpClient{
		{name: "claude", path: filepath.Join(home, ".claude.json"), collection: "mcpServers"},
		{name: "codex", path: filepath.Join(home, ".codex", "config.toml")},
		openCode,
	}
	detected := make([]mcpClient, 0, len(candidates))
	for _, candidate := range candidates {
		if fileExists(candidate.path) {
			detected = append(detected, candidate)
		}
	}
	return detected
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func clientHome(lookup render.Env) string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	if home, ok := lookup("HOME"); ok && filepath.IsAbs(home) {
		return home
	}
	return ""
}

func clientConfigHome(lookup render.Env, home string) string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	if config, ok := lookup("XDG_CONFIG_HOME"); ok && filepath.IsAbs(config) {
		return config
	}
	return filepath.Join(home, ".config")
}

// clientDocument names the two fields it needs rather than decoding into a map,
// so the decoder discards the rest of the file as it streams: a client's
// configuration also carries that client's own history, and a map would hold
// every megabyte of it in memory to answer one question about one entry.
type clientDocument struct {
	MCPServers map[string]clientServer `json:"mcpServers"`
	MCP        map[string]clientServer `json:"mcp"`
}

type clientServer struct {
	URL string `json:"url"`
}

func readJSONClient(path, collection string) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = file.Close() }()

	var document clientDocument
	if err := json.NewDecoder(file).Decode(&document); err != nil {
		return "", false, err
	}
	servers := document.MCPServers
	if collection == "mcp" {
		servers = document.MCP
	}
	server, found := servers["blackbird"]
	return server.URL, found, nil
}

// readCodexClient finds the managed table in Codex's TOML file without a TOML
// parser: the command grammar depends on nothing but the standard library and
// Kong, and the installer writes a fixed two-line table between markers it owns.
func readCodexClient(path string) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = file.Close() }()

	inside := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == codexBlackbirdTable:
			inside = true
		case strings.HasPrefix(line, "["):
			inside = false
		case inside && strings.HasPrefix(line, "url"):
			_, value, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			return strings.Trim(strings.TrimSpace(value), "\""), true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", false, err
	}
	return "", false, nil
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
