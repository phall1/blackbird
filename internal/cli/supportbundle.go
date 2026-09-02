package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/install"
)

// SupportBundleCmd collects, in one pass, every fact a Blackbird bug report
// needs. Filing one otherwise means running six commands and knowing which of
// their output matters, which is knowledge the reporter does not have — that is
// why they are filing the bug.
//
// It never fails on what it finds. A doctor run that reports a failing check
// exits ExitDegraded so an unattended caller can react; a bundle collected
// *because* something is broken must still be produced and still exit zero, or
// the one command a user runs when Blackbird is sick is the one that refuses to
// answer.
type SupportBundleCmd struct {
	Out string `placeholder:"PATH" help:"Write the bundle here as JSON instead of rendering it."`
}

// Help is Kong's HelpProvider hook.
func (cmd *SupportBundleCmd) Help() string {
	return "The bundle is redacted before it is rendered or written: the daemon's admin token is " +
		"removed wherever it appears, and every path below your home directory is rewritten to ~. " +
		"It still names the projects you coordinate in, so read it before you attach it."
}

const (
	supportBundleSchema = "blackbird.support/v1"

	// Each stream gets its own budget rather than sharing one. "logs --lines"
	// counts across both streams, so a chatty stdout crowds out precisely the
	// stderr tail that explains why the daemon exited.
	supportBundleLogLines = 200

	supportStreamOut = "out"
	supportStreamErr = "err"
)

// supportBundle is the whole document, in the order a reader works through it:
// what this binary is, what machine it is on, what is wrong, and then the raw
// material behind that verdict.
type supportBundle struct {
	Schema      string             `json:"schema"`
	CollectedAt string             `json:"collected_at"`
	Build       BuildInfo          `json:"build"`
	Host        supportHost        `json:"host"`
	Doctor      doctorReport       `json:"doctor"`
	Status      statusReport       `json:"status"`
	GC          *gcReport          `json:"gc,omitempty"`
	Install     supportInstall     `json:"install"`
	Handshake   supportHandshake   `json:"handshake"`
	Clients     []supportClient    `json:"mcp_clients"`
	Logs        []supportLogStream `json:"logs"`
	Redaction   supportRedaction   `json:"redaction"`
	Problems    []string           `json:"collection_problems,omitempty"`
}

type supportHost struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Go   string `json:"go"`
	CPUs int    `json:"cpus"`
}

// supportInstall is where the product put itself. Every value here is one the
// installer owns, so a mismatch between the argv the service definition should
// carry and the state the supervisor reports is visible without a second
// command.
//
// The service definition is reported as its path, its drift state, and the argv
// install writes — not as the file's bytes. A launchd plist or a systemd unit
// also carries whatever environment the user put in it, and copying an
// arbitrary file into a document meant to be attached to a public issue is how
// a credential nobody remembered leaves the machine.
type supportInstall struct {
	StateDir        string   `json:"state_dir,omitempty"`
	DatabasePath    string   `json:"database_path,omitempty"`
	HandshakePath   string   `json:"handshake_path,omitempty"`
	ServicePath     string   `json:"service_path,omitempty"`
	DefinitionState string   `json:"service_definition,omitempty"`
	ServiceArgv     []string `json:"service_argv,omitempty"`
	Updater         string   `json:"updater,omitempty"`
	UpdaterPaths    string   `json:"updater_paths,omitempty"`
	MCPURL          string   `json:"mcp_url,omitempty"`
}

// supportHandshake is the daemon's discovery record with its credential taken
// out. TokenRedacted is stated rather than implied: a reader who cannot see a
// token field cannot tell a redacted record from one the daemon never wrote.
type supportHandshake struct {
	Path          string `json:"path,omitempty"`
	Present       bool   `json:"present"`
	Schema        string `json:"schema,omitempty"`
	HTTPAddress   string `json:"http_address,omitempty"`
	PID           int    `json:"pid,omitempty"`
	StartedAt     string `json:"started_at,omitempty"`
	Version       string `json:"version,omitempty"`
	TokenRedacted bool   `json:"token_redacted"`
	Detail        string `json:"detail,omitempty"`
}

type supportClient struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

type supportLogStream struct {
	Stream string   `json:"stream"`
	Lines  []string `json:"lines"`
	Detail string   `json:"detail,omitempty"`
}

// supportRedaction travels inside the bundle so the person deciding whether to
// send it reads the policy rather than inferring it, and so a reviewer of the
// bundle knows which absences are redactions and which are findings.
type supportRedaction struct {
	Removed []string `json:"removed"`
	Kept    []string `json:"kept"`
}

// supportBundleReceipt is what --out reports. Its path is deliberately not
// redacted: it names a file on the reader's own machine that they have to be
// able to open, and it is printed to the terminal rather than written into the
// document that gets attached to an issue.
type supportBundleReceipt struct {
	Path      string           `json:"path"`
	Bytes     int              `json:"bytes"`
	Redaction supportRedaction `json:"redaction"`
}

var supportRedactionPolicy = supportRedaction{
	Removed: []string{
		"the daemon's admin credential, everywhere it occurs, including inside daemon log lines",
		"any credential-shaped assignment in log lines, argv, and error text",
		"the home directory prefix of every path, rewritten to ~",
	},
	Kept: []string{
		"paths below the home directory, project keys among them: a coordination failure is " +
			"about a specific reservation, conversation, or workspace, and a bundle with those " +
			"stripped cannot diagnose the fault it was collected for",
		"daemon log message text, which is where the failure is actually described",
		"the operating system, architecture, and Go version, which decide which supervisor, " +
			"updater, and SQLite build are in play — but never the hostname or the user name, " +
			"which decide nothing and cannot be taken back once the bundle is attached",
	},
}

func (cmd *SupportBundleCmd) Run(ctx context.Context, console *Console) error {
	target, err := cmd.target()
	if err != nil {
		return err
	}
	bundle, err := cmd.collect(ctx, console)
	if err != nil {
		return err
	}
	if target == "" {
		return console.present(newView(bundle, drawSupportBundle))
	}
	written, err := writeSupportBundle(target, bundle)
	if err != nil {
		return err
	}
	return console.present(newView(supportBundleReceipt{
		Path: target, Bytes: written, Redaction: bundle.Redaction,
	}, drawSupportBundleReceipt))
}

// target resolves --out the way backup resolves its own: a leading ~/ expands,
// and anything else relative is refused rather than made absolute against
// whatever directory the user happened to stand in.
func (cmd *SupportBundleCmd) target() (string, error) {
	if cmd.Out == "" {
		return "", nil
	}
	expanded, err := expandHome(cmd.Out)
	if err != nil {
		return "", usageFault("resolve --out: %v", err)
	}
	if !filepath.IsAbs(expanded) {
		return "", usageFault("--out must be an absolute path; got %q", cmd.Out)
	}
	return filepath.Clean(expanded), nil
}

// collect assembles the document and then redacts it as a whole. The order
// matters: the handshake record is read first because it carries the one secret
// on this machine the redactor has to be able to recognize, and the log tail is
// collected afterwards so a daemon that logged its own credential is scrubbed
// by the same value the handshake section names.
func (cmd *SupportBundleCmd) collect(ctx context.Context, console *Console) (supportBundle, error) {
	// Doctor and status only report the daemon's identity and the installer's
	// own status line at -v. A bundle is collected once, by someone who cannot
	// be asked to run it again with another flag, so it is assembled through a
	// console that always asks for the detailed form.
	detailed := detailedConsole(console)

	handshake, credential := readHandshakeRecord(detailed)
	scrub := redactor{home: clientHome(console.Deps.Env), secrets: []string{credential}}

	bundle := supportBundle{
		Schema:      supportBundleSchema,
		CollectedAt: console.now().UTC().Format(time.RFC3339),
		Build:       console.Deps.Build,
		Host:        hostFacts(),
		Handshake:   handshake,
		Clients:     supportClients(detailed),
		Logs:        supportLogs(ctx, detailed),
		Redaction:   supportRedactionPolicy,
	}

	deep := DoctorCmd{Deep: true}
	bundle.Doctor = tallyChecks(deep.collect(ctx, detailed))

	status := StatusCmd{Timeout: probeTimeout}
	report, err := status.collect(ctx, detailed)
	if err != nil {
		bundle.Problems = append(bundle.Problems, "collect status: "+err.Error())
	}
	bundle.Status = report
	bundle.GC = gcSection(report.Database)
	bundle.Install, bundle.Problems = supportInstallFacts(detailed, report, handshake, bundle.Problems)

	return scrub.apply(bundle)
}

// detailedConsole is the same console asking for the verbose projection. It
// copies Globals rather than mutating them, because the console it was given is
// the one the result renders through and a bundle must not silently change what
// the user's own --json or --width asked for.
func detailedConsole(console *Console) *Console {
	if console.Globals == nil {
		return console
	}
	copied := *console
	globals := *console.Globals
	globals.Verbose = max(globals.Verbose, 1)
	copied.Globals = &globals
	return &copied
}

// hostFacts names the machine's shape and nothing that identifies it.
func hostFacts() supportHost {
	return supportHost{
		OS: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), CPUs: runtime.NumCPU(),
	}
}

// tallyChecks counts a doctor run the way DoctorCmd.Run counts its own, so the
// bundle's summary line and a doctor invocation cannot disagree about the same
// checks. Only the tally is repeated; the checks themselves come from doctor.
func tallyChecks(checks []checkResult) doctorReport {
	report := doctorReport{Checks: checks}
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
	return report
}

// gcSection projects the read-only inspection status already paid for. Opening
// the database a third time would report different numbers than the section
// above it, and gc's mutating flags are deliberately unreachable here: a bundle
// explains a state, it does not change one.
func gcSection(database Database) *gcReport {
	if database.Path == "" {
		return nil
	}
	report := gcReport{
		Path: database.Path, DiskFreeBytes: database.FreeBytes, WALBytes: database.WALBytes,
		SizeBytes: database.SizeBytes, PageSize: database.PageSize, PageCount: database.PageCount,
		JournalImmutable: true,
	}
	return &report
}

func supportInstallFacts(
	console *Console,
	status statusReport,
	handshake supportHandshake,
	problems []string,
) (supportInstall, []string) {
	facts := supportInstall{
		DatabasePath:    status.Database.Path,
		HandshakePath:   handshake.Path,
		ServicePath:     status.Service["path"],
		DefinitionState: serviceDefinitionState(status.Service),
		Updater:         status.Service["updater"],
		UpdaterPaths:    status.Service["updater_paths"],
		MCPURL:          mcpURL(console),
	}
	manager, err := console.product()
	if err != nil {
		return facts, append(problems, err.Error())
	}
	facts.StateDir = manager.StateDir()
	facts.ServiceArgv = manager.ServiceArgv()
	return facts, problems
}

// readHandshakeRecord reads the record the daemon publishes on start and
// returns it beside the credential it carries. The credential is read for one
// reason only: it is the value every other section has to be scrubbed against.
// A daemon that logged its own token would otherwise ship it in the log tail
// below while this section looked perfectly clean.
func readHandshakeRecord(console *Console) (supportHandshake, string) {
	record := supportHandshake{Path: handshakeRecordPath(console), TokenRedacted: true}
	if record.Path == "" {
		record.Detail = "no state directory is known, so the daemon's discovery record cannot be located"
		return record, ""
	}
	content, err := os.ReadFile(record.Path)
	if err != nil {
		record.Detail = err.Error()
		return record, ""
	}
	var decoded struct {
		Schema      string `json:"schema"`
		HTTPAddress string `json:"http_address"`
		Token       string `json:"token"`
		PID         int    `json:"pid"`
		StartedAt   string `json:"started_at"`
		Version     string `json:"version"`
	}
	if err := json.Unmarshal(content, &decoded); err != nil {
		record.Detail = "unreadable: " + err.Error()
		return record, ""
	}
	record.Present = true
	record.Schema = decoded.Schema
	record.HTTPAddress = decoded.HTTPAddress
	record.PID = decoded.PID
	record.StartedAt = decoded.StartedAt
	record.Version = decoded.Version
	return record, decoded.Token
}

// handshakeRecordPath prefers the installer's own state directory over the
// injected default, for the same reason status does: the service definition
// passes the directory to the daemon explicitly, so the manager knows where the
// running daemon was told to write rather than where this shell would guess.
func handshakeRecordPath(console *Console) string {
	stateDir := console.Deps.Defaults.StateDir
	if manager, err := console.product(); err == nil && manager.StateDir() != "" {
		stateDir = manager.StateDir()
	}
	if stateDir == "" {
		return ""
	}
	return install.HandshakePath(stateDir)
}

// supportClients re-reads what install wrote into each detected client, which
// is the same read doctor's clients check performs. It is repeated in full here
// because doctor collapses every client into one detail string, and a bundle
// has to say which client lost its entry.
func supportClients(console *Console) []supportClient {
	want := mcpURL(console)
	detected := detectedClients(console)
	clients := make([]supportClient, 0, len(detected))
	for _, client := range detected {
		state, _ := client.state(want)
		clients = append(clients, supportClient{Name: client.name, Path: client.path, State: state})
	}
	return clients
}

// supportLogs tails both daemon streams separately. A failure to read one is
// recorded against that stream rather than aborting: the log is usually the
// most valuable section and it is also the one most likely to be missing, on a
// machine where the daemon has never started.
func supportLogs(ctx context.Context, console *Console) []supportLogStream {
	streams := []supportLogStream{{Stream: supportStreamOut}, {Stream: supportStreamErr}}
	source, err := console.logs()
	if err != nil {
		for index := range streams {
			streams[index].Detail = err.Error()
		}
		return streams
	}
	for index := range streams {
		lines := []string{}
		request := LogRequest{Stream: streams[index].Stream, Lines: supportBundleLogLines}
		tailErr := source.Tail(ctx, request, func(line LogLine) error {
			lines = append(lines, line.Text)
			return nil
		})
		if tailErr != nil {
			streams[index].Detail = tailErr.Error()
		}
		streams[index].Lines = lines
	}
	return streams
}

func writeSupportBundle(path string, bundle supportBundle) (int, error) {
	encoded, err := encodeSupportBundle(bundle)
	if err != nil {
		return 0, fault(ExitError, err, "encode the support bundle")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, withRemedy(fault(ExitError, err, "create the bundle directory"),
			"pass --out=PATH under a directory you can write")
	}
	// Owner-only, exactly as the database is: the bundle carries every log line
	// the daemon wrote, and controlling who reads that is the point of
	// collecting it into one file rather than pasting it somewhere.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, withRemedy(fault(ExitError, err, "write %s", path),
			"pass --out=PATH under a directory you can write")
	}
	defer func() { _ = file.Close() }()
	if err := file.Chmod(0o600); err != nil {
		return 0, withRemedy(fault(ExitError, err, "secure %s", path),
			"pass --out=PATH under a directory you can write")
	}
	if _, err := file.Write(encoded); err != nil {
		return 0, withRemedy(fault(ExitError, err, "write %s", path),
			"pass --out=PATH under a directory you can write")
	}
	return len(encoded), nil
}

// encodeSupportBundle writes the document indented and without HTML escaping,
// so the file a user is asked to read before sending is one they can actually
// read, and so a path containing an ampersand is not rendered as an escape.
func encodeSupportBundle(bundle supportBundle) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(bundle); err != nil {
		return nil, fmt.Errorf("encode support bundle: %w", err)
	}
	return buffer.Bytes(), nil
}

const (
	redactedMarker = "[redacted]"
	homeMarker     = "~"

	// A shorter value than this is not a credential worth the risk of matching
	// it: replacing every occurrence of a four-character string would mangle
	// the log text the bundle exists to carry.
	minimumSecretLength = 8
)

// credentialAssignment matches a credential named by whatever wrote it, so a
// value this CLI has never seen is still removed — a daemon's structured log
// carries "registration_token" for every agent that registers.
//
// The keyword is deliberately not anchored to a word boundary, because the
// interesting keys are compounds and "_" is a word character: an anchored
// pattern reads registration_token as one word and matches nothing. The
// narrowing is done by the two parts that follow instead. The separator must be
// an assignment or a single space, and the value must be long enough to be a
// secret rather than the next word in a sentence, so "password is required"
// matches nothing while "token_redacted": true keeps its field name.
//
// The separator also accepts an escaped quote. The daemon logs structured JSON,
// so by the time a log line is a string inside this document its own quoting
// has been escaped once, and a pattern that only knew the bare quote read
// straight past every credential a log line carries.
var credentialAssignment = regexp.MustCompile(
	`(?i)(bearer|token|secret|password|api[_-]?key)((?:\\?")?\s*[:= ]\s*(?:\\?")?)([A-Za-z0-9._+/=-]{8,})`)

// redactor rewrites the assembled document rather than each field as it is
// built. A field-by-field scrub protects only the fields its author remembered,
// and the two values that must never leave this machine — the daemon's admin
// credential and the user's home directory — reach the bundle through daemon
// log lines, error strings, and service argv just as readily as through the
// fields that name them.
type redactor struct {
	home    string
	secrets []string
}

// apply encodes, scrubs, and decodes. Working on the encoded document is what
// makes the guarantee total: every string in the bundle passes through the same
// pass, whatever section it came from and whoever added that section later.
//
// It also keeps the substitutions safe. Neither the redaction marker nor "~"
// needs escaping, JSON's own quoting bounds every replacement, and the matched
// value class excludes the quote, backslash, and comma that delimit the
// document — so a scrubbed document is still the document.
func (scrub redactor) apply(bundle supportBundle) (supportBundle, error) {
	encoded, err := encodeSupportBundle(bundle)
	if err != nil {
		return supportBundle{}, fault(ExitError, err, "redact the support bundle")
	}
	var redacted supportBundle
	if err := json.Unmarshal([]byte(scrub.scrub(string(encoded))), &redacted); err != nil {
		return supportBundle{}, fault(ExitError, err, "decode the redacted support bundle")
	}
	return redacted, nil
}

func (scrub redactor) scrub(document string) string {
	for _, secret := range scrub.secrets {
		if len(secret) < minimumSecretLength {
			continue
		}
		document = strings.ReplaceAll(document, secret, redactedMarker)
	}
	// The home prefix is rewritten rather than removed: "~/.local/share/
	// blackbird/blackbird.db" diagnoses everything the absolute path does,
	// while the account name it contains diagnoses nothing. The separator and
	// the closing quote are what bound the match, so a home of /home/al cannot
	// eat the front of /home/alice.
	if len(scrub.home) > 1 {
		document = strings.ReplaceAll(document, scrub.home+"/", homeMarker+"/")
		document = strings.ReplaceAll(document, `"`+scrub.home+`"`, `"`+homeMarker+`"`)
	}
	return credentialAssignment.ReplaceAllString(document, "${1}${2}"+redactedMarker)
}

func drawSupportBundle(doc *render.Document, bundle supportBundle) {
	doc.Heading("Support bundle")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "schema", Value: bundle.Schema},
		{Key: "collected", Value: bundle.CollectedAt},
		{Key: "version", Value: orAbsent(bundle.Build.Version)},
		{Key: "commit", Value: orAbsent(bundle.Build.Commit)},
		{Key: "built at", Value: orAbsent(bundle.Build.BuiltAt)},
		{Key: "host", Value: bundle.Host.OS + "/" + bundle.Host.Arch +
			" " + bundle.Host.Go + " cpus=" + itoa(bundle.Host.CPUs)},
	}})

	doc.Blank()
	drawDoctor(doc, bundle.Doctor)
	doc.Blank()
	drawStatus(doc, bundle.Status)
	if bundle.GC != nil {
		doc.Blank()
		drawGC(doc, *bundle.GC)
	}

	doc.Blank()
	doc.Heading("Installation")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "state dir", Value: orAbsent(bundle.Install.StateDir)},
		{Key: "database", Value: orAbsent(bundle.Install.DatabasePath)},
		{Key: "handshake", Value: orAbsent(bundle.Install.HandshakePath)},
		{Key: "service", Value: orAbsent(bundle.Install.ServicePath)},
		{Key: "definition", Value: orAbsent(bundle.Install.DefinitionState)},
		{Key: "argv", Value: orAbsent(strings.Join(bundle.Install.ServiceArgv, " "))},
		{Key: "updater", Value: orAbsent(bundle.Install.Updater)},
		{Key: "updater paths", Value: orAbsent(bundle.Install.UpdaterPaths)},
		{Key: "mcp url", Value: orAbsent(bundle.Install.MCPURL)},
	}})

	doc.Blank()
	doc.Heading("Handshake record")
	doc.Fields(render.Fields{Indent: 2, Items: []render.Field{
		{Key: "path", Value: orAbsent(bundle.Handshake.Path)},
		{Key: "present", Value: yesNo(bundle.Handshake.Present), Role: boolRole(bundle.Handshake.Present)},
		{Key: "schema", Value: orAbsent(bundle.Handshake.Schema)},
		{Key: "address", Value: orAbsent(bundle.Handshake.HTTPAddress)},
		{Key: "pid", Value: itoa(bundle.Handshake.PID)},
		{Key: "started", Value: orAbsent(bundle.Handshake.StartedAt)},
		{Key: "version", Value: orAbsent(bundle.Handshake.Version)},
		{Key: "token", Value: redactedMarker, Role: render.RoleMuted},
		{Key: "detail", Value: orAbsent(bundle.Handshake.Detail)},
	}})

	drawSupportClients(doc, bundle.Clients)
	drawSupportLogs(doc, bundle.Logs)

	if len(bundle.Problems) > 0 {
		doc.Blank()
		doc.Heading("Collection problems")
		for _, problem := range bundle.Problems {
			doc.Status(render.StatusWarn, problem)
		}
	}

	drawSupportRedaction(doc, bundle.Redaction)
}

func drawSupportClients(doc *render.Document, clients []supportClient) {
	doc.Blank()
	doc.Heading("MCP clients")
	if len(clients) == 0 {
		doc.Line(render.RoleMuted, "  no MCP client configuration was found for this user")
		return
	}
	items := make([]render.Field, 0, len(clients))
	for _, client := range clients {
		items = append(items, render.Field{Key: client.Name, Value: client.State + "  " + client.Path})
	}
	doc.Fields(render.Fields{Indent: 2, Items: items})
}

// drawSupportLogs prints log lines verbatim rather than wrapped. A wrapped
// structured log line is no longer the line the daemon wrote, and matching one
// against the daemon's own output is most of what reading this section is for.
func drawSupportLogs(doc *render.Document, streams []supportLogStream) {
	for _, stream := range streams {
		doc.Blank()
		doc.Heading("Daemon log (" + stream.Stream + ")")
		if stream.Detail != "" {
			doc.Status(render.StatusWarn, stream.Detail)
		}
		if len(stream.Lines) == 0 {
			doc.Line(render.RoleMuted, "  no lines")
			continue
		}
		for _, line := range stream.Lines {
			doc.Line(logRole(stream.Stream), line)
		}
	}
}

func drawSupportRedaction(doc *render.Document, redaction supportRedaction) {
	doc.Blank()
	doc.Heading("Redaction")
	for _, removed := range redaction.Removed {
		doc.Wrapped(render.RoleMuted, "  removed: "+removed)
	}
	for _, kept := range redaction.Kept {
		doc.Wrapped(render.RoleMuted, "  kept: "+kept)
	}
}

func drawSupportBundleReceipt(doc *render.Document, receipt supportBundleReceipt) {
	doc.Linef(render.RolePlain, "wrote support bundle %s (%s)",
		receipt.Path, render.Bytes(int64(receipt.Bytes)))
	drawSupportRedaction(doc, receipt.Redaction)
	doc.Blank()
	doc.Wrapped(render.RoleMuted, "Read it before you attach it: it names the projects you coordinate in.")
}
