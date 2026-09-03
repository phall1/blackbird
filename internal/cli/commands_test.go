package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/install"
)

type runResult struct {
	code   int
	stdout string
	stderr string
}

func runCLI(t *testing.T, deps Dependencies, args []string) runResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), deps, args, &stdout, &stderr)
	return runResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func dependencies(t *testing.T) Dependencies {
	t.Helper()
	return Dependencies{
		Build:        BuildInfo{Version: "test", Commit: "cafe", BuiltAt: "then"},
		DatabasePath: filepath.Join(t.TempDir(), "blackbird.db"),
		Now:          func() time.Time { return time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC) },
		Env:          func(string) (string, bool) { return "", false },
	}
}

type recordingDaemon struct {
	calls   int
	options DaemonOptions
	err     error
}

func (daemon *recordingDaemon) Run(_ context.Context, options DaemonOptions) error {
	daemon.calls++
	daemon.options = options
	return daemon.err
}

type fakeAdmin struct {
	health        Health
	identity      Identity
	overview      Overview
	projects      []Project
	agents        []Agent
	inbox         Inbox
	conversations []Conversation
	reservations  []Reservation
	release       ReservationRelease
	events        []Event
	truncated     bool
	err           error

	releasedLeaseID string

	agentQuery        AgentQuery
	inboxQuery        InboxQuery
	conversationQuery ConversationQuery
	reservationQuery  ReservationQuery
	eventQuery        EventQuery

	cost      CostReport
	costQuery CostQuery
}

func (admin *fakeAdmin) Health(context.Context) (Health, error) {
	if admin.err != nil {
		return Health{}, admin.err
	}
	return admin.health, nil
}

func (admin *fakeAdmin) Identity(context.Context) (Identity, error) {
	return admin.identity, admin.err
}

func (admin *fakeAdmin) Overview(context.Context) (Overview, error) {
	return admin.overview, admin.err
}

func (admin *fakeAdmin) Projects(context.Context) ([]Project, error) {
	return admin.projects, admin.err
}

// The daemon owns every predicate, so the double answers a query with exactly
// the rows it was given: a CLI that still filtered a page client-side would be
// invisible to a double that filtered too.
func (admin *fakeAdmin) Agents(_ context.Context, query AgentQuery) (AgentsPage, error) {
	admin.agentQuery = query
	if admin.err != nil {
		return AgentsPage{}, admin.err
	}
	if query.AgentName == "" {
		return AgentsPage{Agents: admin.agents, Truncated: admin.truncated}, nil
	}
	matched := make([]Agent, 0, len(admin.agents))
	for _, agent := range admin.agents {
		if agent.AgentName == query.AgentName {
			matched = append(matched, agent)
		}
	}
	return AgentsPage{Agents: matched, Truncated: admin.truncated}, nil
}

func (admin *fakeAdmin) Inbox(_ context.Context, query InboxQuery) (Inbox, error) {
	admin.inboxQuery = query
	return admin.inbox, admin.err
}

func (admin *fakeAdmin) Conversations(_ context.Context, query ConversationQuery) (ConversationsPage, error) {
	admin.conversationQuery = query
	if admin.err != nil {
		return ConversationsPage{}, admin.err
	}
	if query.ConversationID == "" {
		return ConversationsPage{Conversations: admin.conversations, Truncated: admin.truncated}, nil
	}
	matched := make([]Conversation, 0, len(admin.conversations))
	for _, conversation := range admin.conversations {
		if conversation.ConversationID == query.ConversationID {
			matched = append(matched, conversation)
		}
	}
	return ConversationsPage{Conversations: matched, Truncated: admin.truncated}, nil
}

func (admin *fakeAdmin) Reservations(_ context.Context, query ReservationQuery) (ReservationsPage, error) {
	admin.reservationQuery = query
	if admin.err != nil {
		return ReservationsPage{}, admin.err
	}
	return ReservationsPage{Reservations: admin.reservations, Truncated: admin.truncated}, nil
}

func (admin *fakeAdmin) ForceReleaseReservation(_ context.Context,
	leaseID string) (ReservationRelease, error) {
	admin.releasedLeaseID = leaseID
	return admin.release, admin.err
}

func (admin *fakeAdmin) Events(_ context.Context, query EventQuery) (EventsPage, error) {
	admin.eventQuery = query
	if admin.err != nil {
		return EventsPage{}, admin.err
	}
	return EventsPage{Events: admin.events, Truncated: admin.truncated}, nil
}

func (admin *fakeAdmin) Cost(_ context.Context, query CostQuery) (CostReport, error) {
	admin.costQuery = query
	if admin.err != nil {
		return CostReport{}, admin.err
	}
	return admin.cost, nil
}

type panickingAdmin struct{}

func (panickingAdmin) Health(context.Context) (Health, error)     { panic("boom") }
func (panickingAdmin) Identity(context.Context) (Identity, error) { panic("boom") }
func (panickingAdmin) Overview(context.Context) (Overview, error) { panic("boom") }
func (panickingAdmin) Projects(context.Context) ([]Project, error) {
	panic("boom")
}

func (panickingAdmin) Agents(context.Context, AgentQuery) (AgentsPage, error) { panic("boom") }
func (panickingAdmin) Inbox(context.Context, InboxQuery) (Inbox, error)       { panic("boom") }
func (panickingAdmin) Conversations(context.Context, ConversationQuery) (ConversationsPage, error) {
	panic("boom")
}

func (panickingAdmin) Reservations(context.Context, ReservationQuery) (ReservationsPage, error) {
	panic("boom")
}
func (panickingAdmin) Cost(context.Context, CostQuery) (CostReport, error) { panic("boom") }

func (panickingAdmin) ForceReleaseReservation(context.Context, string) (ReservationRelease, error) {
	panic("boom")
}

func (panickingAdmin) Events(context.Context, EventQuery) (EventsPage, error) { panic("boom") }

type fakeStore struct {
	database Database
	err      error
	path     string
	deep     bool
}

func (store *fakeStore) Inspect(_ context.Context, path string, deep bool) (Database, error) {
	store.path = path
	store.deep = deep
	database := store.database
	database.Path = path
	return database, store.err
}

type fakeProduct struct {
	called         string
	status         string
	statusErr      error
	err            error
	updaterSkipped string
}

func (product *fakeProduct) Install(context.Context) (install.Result, error) {
	product.called = "install"
	if product.err != nil {
		return install.Result{}, product.err
	}
	if product.updaterSkipped != "" {
		return install.Result{ServicePath: "/service", Clients: []string{"opencode", "codex"},
			UpdaterSkipped: product.updaterSkipped}, nil
	}
	return install.Result{ServicePath: "/service", UpdaterPaths: []string{"/updater"},
		Clients: []string{"opencode", "codex"}}, nil
}

func (product *fakeProduct) Status(context.Context) (string, error) {
	product.called = "status"
	if product.statusErr != nil {
		return "", product.statusErr
	}
	if product.status != "" {
		return product.status, nil
	}
	return "daemon=running installed=true path=/service definition=current " +
		"updater=scheduled installed=true paths=/updater interval=6h0m0s", nil
}

func (product *fakeProduct) Update(context.Context) (install.UpdateResult, error) {
	product.called = "update"
	if product.err != nil {
		return install.UpdateResult{}, product.err
	}
	return install.UpdateResult{Changed: true, Before: "blackbird 1.0.0", After: "blackbird 1.1.0"}, nil
}

func (product *fakeProduct) Uninstall(context.Context) (install.Result, error) {
	product.called = "uninstall"
	if product.err != nil {
		return install.Result{}, product.err
	}
	return install.Result{ServicePath: "/service", UpdaterPaths: []string{"/updater"}}, nil
}

func (product *fakeProduct) ServiceArgv() []string {
	return []string{"/opt/homebrew/bin/blackbird", "daemon", "--sqlite-path=/data/blackbird.db"}
}

func (product *fakeProduct) StateDir() string { return "/state/blackbird" }

type fakeLogs struct {
	lines   []LogLine
	err     error
	request LogRequest
}

func (logs *fakeLogs) Tail(_ context.Context, request LogRequest, emit func(LogLine) error) error {
	logs.request = request
	if logs.err != nil {
		return logs.err
	}
	for _, line := range logs.lines {
		if err := emit(line); err != nil {
			return err
		}
	}
	return nil
}

type fakeMaintenance struct {
	plan      ReclaimPlan
	reclaimed Reclaimed
	err       error
}

func (maintenance *fakeMaintenance) Reclaim(_ context.Context, _ string, plan ReclaimPlan) (Reclaimed, error) {
	maintenance.plan = plan
	return maintenance.reclaimed, maintenance.err
}

func healthyDatabase() Database {
	return Database{
		Present: true, Mode: readModeLive, SizeBytes: 812 << 10, WALBytes: 4 << 20, FreeBytes: 1 << 30,
		PageSize: 4096, PageCount: 200, JournalMode: "wal",
		SchemaVersion: 4, ExpectedSchemaVersion: 4,
		ApplicationID: 1111641420, ExpectedApplicationID: 1111641420,
		Supported: true, LedgerComplete: true, CleanShutdown: true, QuickCheck: "ok",
	}
}

func TestDaemonCommandPassesOptionsThrough(t *testing.T) {
	t.Parallel()

	daemon := &recordingDaemon{}
	deps := dependencies(t)
	deps.Daemon = daemon
	deps.Defaults = DaemonOptions{Storage: "sqlite", SQLitePath: "/data/blackbird.db",
		StateDir: "/state", HTTPAddress: "127.0.0.1:1", MCPAddress: "127.0.0.1:2",
		ShutdownTimeout: 5 * time.Second}

	result := runCLI(t, deps, []string{"daemon", "--http-address=127.0.0.1:9100", "--log-level=debug"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	want := DaemonOptions{Storage: "sqlite", SQLitePath: "/data/blackbird.db", StateDir: "/state",
		HTTPAddress: "127.0.0.1:9100", MCPAddress: "127.0.0.1:2", LogLevel: "debug",
		ShutdownTimeout: 5 * time.Second}
	if daemon.options != want {
		t.Fatalf("options = %#v, want %#v", daemon.options, want)
	}
}

func TestDaemonCommandWrapsRunError(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Daemon = &recordingDaemon{err: errors.New("listen: address in use")}
	deps.Defaults = DaemonOptions{Storage: "sqlite", SQLitePath: "/data/blackbird.db"}

	result := runCLI(t, deps, []string{"daemon"})
	if result.code != ExitError {
		t.Fatalf("code = %d, want %d", result.code, ExitError)
	}
	if !strings.Contains(result.stderr, "address in use") {
		t.Fatalf("stderr = %q", result.stderr)
	}
}

func TestDaemonCommandWithoutPortIsUnavailable(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Defaults = DaemonOptions{Storage: "sqlite", SQLitePath: "/data/blackbird.db"}
	if code := runCLI(t, deps, []string{"daemon"}).code; code != ExitUnavailable {
		t.Fatalf("code = %d, want %d", code, ExitUnavailable)
	}
}

func TestDaemonTreatsCancellationAsSuccess(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Daemon = &recordingDaemon{err: context.Canceled}
	deps.Defaults = DaemonOptions{Storage: "sqlite", SQLitePath: "/data/blackbird.db"}
	if code := runCLI(t, deps, []string{"daemon"}).code; code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
}

func TestStatusReportsEveryDaemonState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		daemon string
		health Health
	}{
		{name: "running", daemon: install.DaemonRunning, health: Health{Reachable: true, Ready: true}},
		{name: "stopped", daemon: install.DaemonStopped},
		{name: "not installed", daemon: install.DaemonNotInstalled},
		{name: "unreachable", daemon: install.DaemonUnreachable},
		{name: "crash looping", daemon: install.DaemonCrashLooping},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			deps := dependencies(t)
			deps.Product = &fakeProduct{status: "daemon=" + test.daemon + " installed=true path=/service " +
				"definition=current updater=scheduled installed=true paths=/updater interval=6h0m0s"}
			deps.Admin = &fakeAdmin{health: test.health}
			deps.Store = &fakeStore{database: healthyDatabase()}

			result := runCLI(t, deps, []string{"status"})
			if result.code != ExitOK {
				t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
			}
			if !strings.Contains(result.stdout, test.daemon) {
				t.Fatalf("stdout = %q, want %q", result.stdout, test.daemon)
			}
		})
	}
}

func TestStatusRequireRunningExitsUnavailable(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{status: "daemon=unreachable installed=true path=/service definition=current"}
	deps.Admin = &fakeAdmin{health: Health{Reachable: true}}
	deps.Store = &fakeStore{database: healthyDatabase()}

	result := runCLI(t, deps, []string{"status", "--require-running"})
	if result.code != ExitUnavailable {
		t.Fatalf("code = %d, want %d", result.code, ExitUnavailable)
	}
}

func TestStatusReportsProblemsWithoutDatabaseOrDaemon(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	result := runCLI(t, deps, []string{"status"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if !strings.Contains(result.stdout, "Problems") {
		t.Fatalf("stdout = %q, want a problems section", result.stdout)
	}
}

func TestStatusJSONCarriesEveryFact(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true, Version: "0.4.0", SchemaVersion: 4}}
	deps.Store = &fakeStore{database: healthyDatabase()}

	result := runCLI(t, deps, []string{"status", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	var report statusReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatalf("stdout = %q: %v", result.stdout, err)
	}
	if report.Daemon != install.DaemonRunning || !report.Health.Ready || report.Database.SchemaVersion != 4 {
		t.Fatalf("report = %#v", report)
	}
	if report.Service["definition"] != install.DefinitionCurrent {
		t.Fatalf("service = %#v", report.Service)
	}
}

func TestStatusWatchRefusesJSONAndNonTerminal(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Admin = &fakeAdmin{}
	deps.Store = &fakeStore{database: healthyDatabase()}

	for _, args := range [][]string{{"status", "--watch", "--json"}, {"status", "--watch"}} {
		if code := runCLI(t, deps, args).code; code != ExitUsage {
			t.Fatalf("%v: code = %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestWatchLoopStopsOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	console := &Console{
		Globals: &Globals{},
		Out:     &bytes.Buffer{},
		Err:     &bytes.Buffer{},
		Style:   render.NewStyle(render.Capabilities{TTY: true, Width: 80}),
	}
	renders := 0
	err := console.loop(ctx, true, minimumWatchInterval, func(context.Context) (render.View, error) {
		renders++
		return newView(struct {
			Value string `json:"value"`
		}{Value: "x"}, func(doc *render.Document, _ struct {
			Value string `json:"value"`
		}) {
			doc.Line(render.RolePlain, "frame")
		}), nil
	})
	if err != nil {
		t.Fatalf("loop() = %v", err)
	}
	if renders != 1 {
		t.Fatalf("renders = %d, want 1", renders)
	}
}

func TestWatchLoopRejectsTinyInterval(t *testing.T) {
	t.Parallel()

	console := &Console{
		Globals: &Globals{},
		Out:     &bytes.Buffer{},
		Err:     &bytes.Buffer{},
		Style:   render.NewStyle(render.Capabilities{TTY: true, Width: 80}),
	}
	err := console.loop(context.Background(), true, time.Millisecond, func(context.Context) (render.View, error) {
		return newView(struct{}{}, func(doc *render.Document, _ struct{}) { doc.Line(render.RolePlain, "x") }), nil
	})
	if exitCodeFor(err) != ExitUsage {
		t.Fatalf("loop() = %v, want a usage fault", err)
	}
}

func TestDoctorAggregatesCheckStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status string
		strict bool
		want   int
	}{
		{name: "all pass", status: "daemon=running installed=true path=/s definition=current updater=scheduled",
			want: ExitOK},
		{name: "warn", status: "daemon=running installed=true path=/s definition=stale updater=scheduled",
			want: ExitOK},
		{name: "warn strict", status: "daemon=running installed=true path=/s definition=stale updater=scheduled",
			strict: true, want: ExitDegraded},
		{name: "fail", status: "daemon=not-installed installed=false path=/s definition=absent updater=stopped",
			want: ExitDegraded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			deps := dependencies(t)
			deps.Product = &fakeProduct{status: test.status}
			deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true, Version: "0.4.0", SchemaVersion: 4}}
			deps.Store = &fakeStore{database: healthyDatabase()}

			args := []string{"doctor"}
			if test.strict {
				args = append(args, "--strict")
			}
			if code := runCLI(t, deps, args).code; code != test.want {
				t.Fatalf("code = %d, want %d", code, test.want)
			}
		})
	}
}

// TestDoctorSeparatesTheSchemaMismatchDirections pins that a schema version is
// not one condition with one remedy. The daemon climbs a migration ladder when
// it opens the database, so a version behind this binary heals on the next
// start; doctor reads the file read-only and is therefore the one observer that
// sees the un-migrated state. Failing there would send the user to an update
// with nothing to install and hold --strict red over a condition nothing is
// wrong with. The other three directions are real failures, and each needs a
// different answer.
func TestDoctorSeparatesTheSchemaMismatchDirections(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		schemaVersion int
		applicationID int
		wantCode      int
		wantStrict    int
		wantRemedy    string
	}{
		"behind the binary migrates itself": {
			schemaVersion: 3, wantCode: ExitOK, wantStrict: ExitDegraded,
			wantRemedy: "blackbird install",
		},
		"ahead of the binary needs an update": {
			schemaVersion: 5, wantCode: ExitDegraded, wantStrict: ExitDegraded,
			wantRemedy: "blackbird update",
		},
		"off the ladder needs a restore": {
			schemaVersion: 0, wantCode: ExitDegraded, wantStrict: ExitDegraded,
			wantRemedy: "blackbird restore",
		},
		"a foreign application id is not ours": {
			schemaVersion: 4, applicationID: 12345, wantCode: ExitDegraded, wantStrict: ExitDegraded,
			wantRemedy: "not a Blackbird database",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			database := healthyDatabase()
			database.SchemaVersion = test.schemaVersion
			database.Supported = false
			if test.applicationID != 0 {
				database.ApplicationID = test.applicationID
			}

			deps := dependencies(t)
			deps.Product = &fakeProduct{}
			deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
			deps.Store = &fakeStore{database: database}

			result := runCLI(t, deps, []string{"doctor"})
			if result.code != test.wantCode {
				t.Fatalf("code = %d, want %d; stdout=%q", result.code, test.wantCode, result.stdout)
			}
			if !strings.Contains(result.stdout, "schema_version="+itoa(test.schemaVersion)) ||
				!strings.Contains(result.stdout, "want=4") {
				t.Fatalf("stdout = %q, want both versions named", result.stdout)
			}
			// The renderer wraps a remedy across lines, so match against the
			// collapsed text rather than let a line break hide the phrase.
			if !strings.Contains(strings.Join(strings.Fields(result.stdout), " "), test.wantRemedy) {
				t.Fatalf("stdout = %q, want the remedy to name %q", result.stdout, test.wantRemedy)
			}

			strict := runCLI(t, deps, []string{"doctor", "--strict"})
			if strict.code != test.wantStrict {
				t.Fatalf("strict code = %d, want %d", strict.code, test.wantStrict)
			}
		})
	}
}

func TestDoctorOnlyFiltersChecks(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
	deps.Store = &fakeStore{database: healthyDatabase()}

	result := runCLI(t, deps, []string{"doctor", "--only=binary", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	var report doctorReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) != 1 || report.Checks[0].Name != "binary" {
		t.Fatalf("checks = %#v", report.Checks)
	}
}

func TestDoctorRejectsUnknownCheckName(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	if code := runCLI(t, deps, []string{"doctor", "--only=nonesuch"}).code; code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestDoctorDeepAddsIntegrityCheck(t *testing.T) {
	t.Parallel()

	store := &fakeStore{database: healthyDatabase()}
	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
	deps.Store = store

	result := runCLI(t, deps, []string{"doctor", "--deep"})
	if !store.deep {
		t.Fatal("deep inspection was not requested")
	}
	if !strings.Contains(result.stdout, "database.integrity") {
		t.Fatalf("stdout = %q", result.stdout)
	}
}

func TestGCReportsWithoutMutating(t *testing.T) {
	t.Parallel()

	maintenance := &fakeMaintenance{}
	deps := dependencies(t)
	deps.Store = &fakeStore{database: healthyDatabase()}
	deps.Maintenance = maintenance

	result := runCLI(t, deps, []string{"gc", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	var report gcReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.Reclaimed != nil {
		t.Fatalf("gc reclaimed %#v without being asked", report.Reclaimed)
	}
	if maintenance.plan != (ReclaimPlan{}) {
		t.Fatalf("maintenance was called with %#v", maintenance.plan)
	}
}

func TestGCRefusesWhileDaemonIsLive(t *testing.T) {
	t.Parallel()

	maintenance := &fakeMaintenance{}
	deps := dependencies(t)
	deps.Store = &fakeStore{database: healthyDatabase()}
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
	deps.Maintenance = maintenance

	result := runCLI(t, deps, []string{"gc", "--vacuum"})
	if result.code != ExitUnavailable {
		t.Fatalf("code = %d, want %d", result.code, ExitUnavailable)
	}
	if maintenance.plan != (ReclaimPlan{}) {
		t.Fatal("gc mutated a database while the daemon was answering")
	}
}

// The guard asks whether a daemon holds THIS database, not whether anything is
// listening: refusing on a bare port meant gc on an explicitly named database
// failed whenever an unrelated daemon happened to be up.
func TestGCScopesTheLiveDaemonGuardToTheTargetDatabase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		daemonPath  string
		wantRefused bool
	}{
		{name: "the daemon holds the target database", daemonPath: "", wantRefused: true},
		{name: "the daemon names a different database", daemonPath: "/somewhere/else.db", wantRefused: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			maintenance := &fakeMaintenance{reclaimed: Reclaimed{BeforeBytes: 1 << 20, AfterBytes: 1 << 19}}
			deps := dependencies(t)
			deps.Store = &fakeStore{database: healthyDatabase()}
			deps.Maintenance = maintenance
			admin := &fakeAdmin{health: Health{Reachable: true, Ready: true}}
			if test.daemonPath != "" {
				admin.identity = Identity{DatabasePath: test.daemonPath}
			} else {
				admin.identity = Identity{DatabasePath: deps.Defaults.SQLitePath}
			}
			deps.Admin = admin

			result := runCLI(t, deps, []string{"gc", "--vacuum"})
			refused := result.code == ExitUnavailable
			if refused != test.wantRefused {
				t.Fatalf("code = %d (refused=%t), want refused=%t; stderr=%q",
					result.code, refused, test.wantRefused, result.stderr)
			}
			if test.wantRefused && maintenance.plan != (ReclaimPlan{}) {
				t.Fatal("gc mutated a database the daemon had open")
			}
		})
	}
}

func TestGCReclaimsWhenDaemonIsDown(t *testing.T) {
	t.Parallel()

	maintenance := &fakeMaintenance{reclaimed: Reclaimed{BeforeBytes: 1 << 20, AfterBytes: 1 << 19}}
	deps := dependencies(t)
	deps.Store = &fakeStore{database: healthyDatabase()}
	deps.Admin = &fakeAdmin{err: errors.New("connection refused")}
	deps.Maintenance = maintenance

	result := runCLI(t, deps, []string{"gc", "--checkpoint", "--vacuum"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if maintenance.plan != (ReclaimPlan{Checkpoint: true, Vacuum: true}) {
		t.Fatalf("plan = %#v", maintenance.plan)
	}
}

func TestGCPrunePassesExplicitRetentionBounds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	maintenance := &fakeMaintenance{}
	deps := dependencies(t)
	deps.Now = func() time.Time { return now }
	deps.Store = &fakeStore{database: healthyDatabase()}
	deps.Admin = &fakeAdmin{err: errors.New("connection refused")}
	deps.Maintenance = maintenance

	result := runCLI(t, deps, []string{"gc", "--prune", "--older-than=24h", "--max-events=42"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	want := ReclaimPlan{Prune: true, PruneBefore: now.Add(-24 * time.Hour), MaxEvents: 42}
	if maintenance.plan != want {
		t.Fatalf("plan = %#v, want %#v", maintenance.plan, want)
	}
}

func TestGCWithoutMaintenancePortExplainsItself(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Store = &fakeStore{database: healthyDatabase()}

	result := runCLI(t, deps, []string{"gc", "--vacuum"})
	if result.code != ExitUnavailable {
		t.Fatalf("code = %d, want %d", result.code, ExitUnavailable)
	}
	if !strings.Contains(result.stderr, "remedy:") {
		t.Fatalf("stderr = %q, want a remedy", result.stderr)
	}
}

func TestOverviewRendersEmptyState(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{}

	result := runCLI(t, deps, []string{"overview"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if !strings.Contains(result.stdout, "No projects are registered yet.") {
		t.Fatalf("stdout = %q", result.stdout)
	}
}

func TestOverviewAggregatesCounts(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{
		overview: Overview{Projects: 2, Agents: 47, ActiveAgents: 3, UnreadDeliveries: 29,
			UnackedDeliveries: 6, ActiveReservations: 9, ExpiredReservations: 9, CoordinationEvents: 106},
		projects: []Project{{ProjectKey: "/workspace/blackbird", Agents: 30, ActiveAgents: 2}},
	}

	result := runCLI(t, deps, []string{"overview"})
	for _, want := range []string{"47", "29", "106", "/workspace/blackbird"} {
		if !strings.Contains(result.stdout, want) {
			t.Fatalf("stdout = %q, want %q", result.stdout, want)
		}
	}
}

func TestProjectsShowUnknownExitsNotFound(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{projects: []Project{{ProjectKey: "/a"}}}

	if code := runCLI(t, deps, []string{"projects", "show", "/b"}).code; code != ExitNotFound {
		t.Fatalf("code = %d, want %d", code, ExitNotFound)
	}
}

func TestProjectsShowRendersAgents(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{
		projects: []Project{{ProjectKey: "/a", WorkspaceID: "ws_1", Agents: 1}},
		agents:   []Agent{{ProjectKey: "/a", AgentName: "scout", Active: true}},
	}

	result := runCLI(t, deps, []string{"projects", "show", "/a"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if !strings.Contains(result.stdout, "scout") || !strings.Contains(result.stdout, "ws_1") {
		t.Fatalf("stdout = %q", result.stdout)
	}
}

func TestProjectsListIsTheDefaultSubcommand(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{projects: []Project{{ProjectKey: "/a"}}}

	bare := runCLI(t, deps, []string{"projects"})
	explicit := runCLI(t, deps, []string{"projects", "list"})
	if bare.stdout != explicit.stdout {
		t.Fatalf("projects = %q, projects list = %q", bare.stdout, explicit.stdout)
	}
}

// The daemon applies --active before its LIMIT. The double answers with a row
// the predicate excludes, so a CLI that filtered the page itself would drop it
// and this test would catch the post-LIMIT filter coming back.
func TestAgentsListSendsTheLivenessPredicateInsteadOfFilteringThePage(t *testing.T) {
	t.Parallel()

	admin := &fakeAdmin{agents: []Agent{
		{AgentName: "scout", ProjectKey: "/a", Active: true},
		{AgentName: "sleeper", ProjectKey: "/a"},
	}}
	deps := dependencies(t)
	deps.Admin = admin

	result := runCLI(t, deps, []string{"agents", "--project=/a", "--active"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if admin.agentQuery.ProjectKey != "/a" || !admin.agentQuery.ActiveOnly || admin.agentQuery.Limit != 50 {
		t.Fatalf("query = %#v", admin.agentQuery)
	}
	if !strings.Contains(result.stdout, "scout") || !strings.Contains(result.stdout, "sleeper") {
		t.Fatalf("stdout = %q, want every row the daemon returned", result.stdout)
	}

	off := runCLI(t, deps, []string{"agents", "--project=/a"})
	if off.code != ExitOK || admin.agentQuery.ActiveOnly {
		t.Fatalf("code = %d, query = %#v", off.code, admin.agentQuery)
	}
}

func TestAgentsShowResolvesAndDisambiguates(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{agents: []Agent{
		{AgentName: "scout", ProjectKey: "/a", ActorID: "actor_1"},
		{AgentName: "scout", ProjectKey: "/b", ActorID: "actor_2"},
	}}
	if code := runCLI(t, deps, []string{"agents", "show", "scout"}).code; code != ExitUsage {
		t.Fatalf("ambiguous name: code = %d, want %d", code, ExitUsage)
	}
	if code := runCLI(t, deps, []string{"agents", "show", "ghost"}).code; code != ExitNotFound {
		t.Fatalf("unknown name: code = %d, want %d", code, ExitNotFound)
	}

	deps.Admin = &fakeAdmin{agents: []Agent{{AgentName: "scout", ProjectKey: "/a", ActorID: "actor_1"}}}
	result := runCLI(t, deps, []string{"agents", "show", "scout"})
	if result.code != ExitOK || !strings.Contains(result.stdout, "actor_1") {
		t.Fatalf("code = %d, stdout = %q", result.code, result.stdout)
	}
}

// --unread and --unacked are WHERE clauses the daemon applies before its LIMIT.
// Filtering the page here rendered nothing whenever the newest deliveries were
// already read, which is the state a busy mailbox is usually in.
func TestInboxSendsTheMailPredicatesInsteadOfFilteringThePage(t *testing.T) {
	t.Parallel()

	admin := &fakeAdmin{inbox: Inbox{
		ProjectKey: "/a",
		Summaries:  []InboxSummary{{AgentName: "scout", UnreadDeliveries: 1, UnackedDeliveries: 1}},
		Pending: []InboxItem{
			{RecipientAgentName: "scout", Subject: "alpha"},
			{RecipientAgentName: "scout", Subject: "beta", Read: true},
			{RecipientAgentName: "scout", Subject: "gamma", Read: true, AckRequired: true},
		},
	}}
	deps := dependencies(t)
	deps.Admin = admin

	unread := runCLI(t, deps, []string{"inbox", "scout", "--project=/a", "--unread"})
	if !admin.inboxQuery.UnreadOnly || admin.inboxQuery.UnackedOnly {
		t.Fatalf("unread query = %#v", admin.inboxQuery)
	}
	for _, subject := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(unread.stdout, subject) {
			t.Fatalf("unread stdout = %q, want every row the daemon returned", unread.stdout)
		}
	}

	unacked := runCLI(t, deps, []string{"inbox", "scout", "--project=/a", "--unacked"})
	if admin.inboxQuery.UnreadOnly || !admin.inboxQuery.UnackedOnly {
		t.Fatalf("unacked query = %#v", admin.inboxQuery)
	}
	if !strings.Contains(unacked.stdout, "alpha") {
		t.Fatalf("unacked stdout = %q, want every row the daemon returned", unacked.stdout)
	}

	both := runCLI(t, deps, []string{"inbox", "scout", "--project=/a", "--unread", "--unacked"})
	if both.code != ExitOK || !admin.inboxQuery.UnreadOnly || !admin.inboxQuery.UnackedOnly ||
		admin.inboxQuery.AgentName != "scout" || admin.inboxQuery.ProjectKey != "/a" ||
		admin.inboxQuery.Limit != 25 {
		t.Fatalf("code = %d, query = %#v", both.code, admin.inboxQuery)
	}
}

func TestInboxDefaultsProjectToWorkingDirectory(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)

	admin := &fakeAdmin{}
	deps := dependencies(t)
	deps.Admin = admin

	if code := runCLI(t, deps, []string{"inbox"}).code; code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	if admin.inboxQuery.ProjectKey == "" {
		t.Fatal("inbox did not default the project key to the working directory")
	}
}

func TestInboxUnknownAgentExitsNotFound(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{inbox: Inbox{ProjectKey: "/a"}}

	if code := runCLI(t, deps, []string{"inbox", "ghost", "--project=/a"}).code; code != ExitNotFound {
		t.Fatalf("code = %d, want %d", code, ExitNotFound)
	}
}

func TestThreadsListSendsTheOpenPredicateInsteadOfFilteringThePage(t *testing.T) {
	t.Parallel()

	admin := &fakeAdmin{conversations: []Conversation{
		{ConversationID: "c1", Topic: "open thread", Status: "open"},
		{ConversationID: "c2", Topic: "closed thread", Status: "closed"},
	}}
	deps := dependencies(t)
	deps.Admin = admin

	result := runCLI(t, deps, []string{"threads", "--open"})
	if !admin.conversationQuery.OpenOnly || admin.conversationQuery.Limit != 25 {
		t.Fatalf("query = %#v", admin.conversationQuery)
	}
	if !strings.Contains(result.stdout, "open thread") || !strings.Contains(result.stdout, "closed thread") {
		t.Fatalf("stdout = %q, want every row the daemon returned", result.stdout)
	}

	off := runCLI(t, deps, []string{"threads"})
	if off.code != ExitOK || admin.conversationQuery.OpenOnly {
		t.Fatalf("code = %d, query = %#v", off.code, admin.conversationQuery)
	}
}

func TestThreadsShowRendersMetadataAndRefusesUnknown(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{conversations: []Conversation{
		{ConversationID: "c1", Topic: "release", Status: "open", Messages: 27, Participants: 4},
	}}

	result := runCLI(t, deps, []string{"threads", "show", "c1"})
	if result.code != ExitOK || !strings.Contains(result.stdout, "release") {
		t.Fatalf("code = %d, stdout = %q", result.code, result.stdout)
	}
	if !strings.Contains(result.stdout, "not projected here") {
		t.Fatalf("stdout = %q, want the privacy note", result.stdout)
	}
	if code := runCLI(t, deps, []string{"threads", "show", "c9"}).code; code != ExitNotFound {
		t.Fatalf("code = %d, want %d", code, ExitNotFound)
	}
}

// Mode and path are matched in SQL, where the path comparison respects
// separator boundaries. Re-deriving either here would filter a page the daemon
// had already limited, and would reinstate the prefix match that reported a
// lease on the sibling a/foo as covering a/f.
func TestReservationsSendTheModeAndPathPredicatesInsteadOfFilteringThePage(t *testing.T) {
	t.Parallel()

	admin := &fakeAdmin{reservations: []Reservation{
		{LeaseID: "l1", Mode: "exclusive", State: "active", HolderAgentName: "scout",
			Selectors: []Selector{{Kind: "path", Path: "a/one.go"}}, ExpiresInMS: 60000},
		{LeaseID: "l2", Mode: "shared", State: "active", HolderAgentName: "sleeper",
			Selectors: []Selector{{Kind: "path", Path: "b/two.go"}}, ExpiresInMS: -1000, Expired: true},
	}}
	deps := dependencies(t)
	deps.Admin = admin

	byMode := runCLI(t, deps, []string{"reservations", "--mode=exclusive"})
	if admin.reservationQuery.Mode != "exclusive" || admin.reservationQuery.State != "active" ||
		admin.reservationQuery.Limit != 50 {
		t.Fatalf("query = %#v", admin.reservationQuery)
	}
	if !strings.Contains(byMode.stdout, "scout") || !strings.Contains(byMode.stdout, "sleeper") {
		t.Fatalf("stdout = %q, want every row the daemon returned", byMode.stdout)
	}

	byPath := runCLI(t, deps, []string{"reservations", "--path=  b/two.go  "})
	if admin.reservationQuery.Path != "b/two.go" {
		t.Fatalf("query = %#v, want the path trimmed for the daemon", admin.reservationQuery)
	}
	if !strings.Contains(byPath.stdout, "scout") {
		t.Fatalf("stdout = %q, want every row the daemon returned", byPath.stdout)
	}

	bare := runCLI(t, deps, []string{"reservations"})
	if bare.code != ExitOK || admin.reservationQuery.Path != "" ||
		admin.reservationQuery.Mode != ReservationModeAny {
		t.Fatalf("code = %d, query = %#v", bare.code, admin.reservationQuery)
	}
}

func TestReservationsShowExpiryCountdown(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{reservations: []Reservation{
		{LeaseID: "l1", Mode: "exclusive", State: "active", ExpiresInMS: -125000, Expired: true},
	}}

	result := runCLI(t, deps, []string{"reservations", "--state=all"})
	if !strings.Contains(result.stdout, "-2m5s") {
		t.Fatalf("stdout = %q, want a negative countdown", result.stdout)
	}
}

func TestReservationReleaseRequiresForceAndCallsAdmin(t *testing.T) {
	t.Parallel()
	const leaseID = "01b8e094-9888-7000-8000-000000000123"
	admin := &fakeAdmin{release: ReservationRelease{LeaseID: leaseID,
		ReleasedAt: "2026-09-02T03:40:00Z", Forced: true}}
	deps := dependencies(t)
	deps.Admin = admin

	withoutForce := runCLI(t, deps, []string{"reservation", "release", leaseID})
	if withoutForce.code != ExitUsage || admin.releasedLeaseID != "" ||
		!strings.Contains(withoutForce.stderr, "requires --force") {
		t.Fatalf("without force: code=%d released=%q stderr=%q",
			withoutForce.code, admin.releasedLeaseID, withoutForce.stderr)
	}
	forced := runCLI(t, deps, []string{"reservation", "release", leaseID, "--force"})
	if forced.code != ExitOK || admin.releasedLeaseID != leaseID ||
		!strings.Contains(forced.stdout, "reservation force-released") {
		t.Fatalf("forced: code=%d released=%q stdout=%q stderr=%q",
			forced.code, admin.releasedLeaseID, forced.stdout, forced.stderr)
	}
}

func TestEventsRendersJournal(t *testing.T) {
	t.Parallel()

	admin := &fakeAdmin{events: []Event{
		{Position: 106, Type: "message.sent", AgentName: "scout", Subject: "msg_1",
			OccurredAt: "2026-08-15T11:59:00Z"},
	}}
	deps := dependencies(t)
	deps.Admin = admin

	result := runCLI(t, deps, []string{"events", "--type=message.sent", "--limit=10"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if admin.eventQuery.Type != "message.sent" || admin.eventQuery.Limit != 10 {
		t.Fatalf("query = %#v", admin.eventQuery)
	}
	if !strings.Contains(result.stdout, "106") || !strings.Contains(result.stdout, "1m ago") {
		t.Fatalf("stdout = %q", result.stdout)
	}
}

func TestInspectCommandsWithoutDaemonExitUnavailable(t *testing.T) {
	t.Parallel()

	commands := [][]string{
		{"overview"}, {"projects"}, {"agents"}, {"inbox", "scout", "--project=/a"},
		{"threads"}, {"reservations"}, {"events"},
	}
	for _, args := range commands {
		t.Run(args[0], func(t *testing.T) {
			t.Parallel()
			deps := dependencies(t)
			deps.Admin = &fakeAdmin{err: errors.New("connection refused")}
			if code := runCLI(t, deps, args).code; code != ExitUnavailable {
				t.Fatalf("%v: code = %d, want %d", args, code, ExitUnavailable)
			}
		})
	}
}

func TestInspectCommandsWithoutAClientExitUnavailable(t *testing.T) {
	t.Parallel()

	if code := runCLI(t, dependencies(t), []string{"overview"}).code; code != ExitUnavailable {
		t.Fatalf("code = %d, want %d", code, ExitUnavailable)
	}
}

func TestLogsTailsRequestedStream(t *testing.T) {
	t.Parallel()

	logs := &fakeLogs{lines: []LogLine{
		{Stream: "err", Text: "SQLite schema mismatch"},
		{Stream: "out", Text: "started"},
	}}
	deps := dependencies(t)
	deps.Logs = logs

	result := runCLI(t, deps, []string{"logs", "--stream=err", "-n", "10"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if logs.request != (LogRequest{Stream: "err", Lines: 10}) {
		t.Fatalf("request = %#v", logs.request)
	}
	if !strings.Contains(result.stdout, "SQLite schema mismatch") {
		t.Fatalf("stdout = %q", result.stdout)
	}
}

func TestLogsReportsAnEmptyStream(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Logs = &fakeLogs{}
	result := runCLI(t, deps, []string{"logs"})
	if !strings.Contains(result.stdout, "No log lines yet.") {
		t.Fatalf("stdout = %q", result.stdout)
	}
}

func TestLogsFollowRefusesJSON(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Logs = &fakeLogs{}
	if code := runCLI(t, deps, []string{"logs", "--follow", "--json"}).code; code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestLogsFollowStreamsDirectly(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Logs = &fakeLogs{lines: []LogLine{{Stream: "out", Text: "line one"}}}
	result := runCLI(t, deps, []string{"logs", "--follow"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if result.stdout != "line one\n" {
		t.Fatalf("stdout = %q", result.stdout)
	}
}

func TestLogsSurfacesSourceFailure(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Logs = &fakeLogs{err: errors.New("no state directory")}
	if code := runCLI(t, deps, []string{"logs"}).code; code != ExitUnavailable {
		t.Fatalf("code = %d, want %d", code, ExitUnavailable)
	}
}

func TestProductCommandsPreserveTheirOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		command string
		want    string
	}{
		{command: "install", want: "installed service=/service updater=/updater clients=opencode,codex\n"},
		{command: "update", want: "updated changed=true before=\"blackbird 1.0.0\" after=\"blackbird 1.1.0\"\n"},
		{command: "uninstall", want: "uninstalled service=/service updater=/updater data=retained\n"},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			t.Parallel()
			product := &fakeProduct{}
			deps := dependencies(t)
			deps.Product = product

			result := runCLI(t, deps, []string{test.command})
			if result.code != ExitOK || result.stdout != test.want || result.stderr != "" {
				t.Fatalf("code=%d stdout=%q stderr=%q, want stdout=%q", result.code, result.stdout, result.stderr, test.want)
			}
			if product.called != test.command {
				t.Fatalf("called = %q, want %q", product.called, test.command)
			}
		})
	}
}

func TestProductCommandsEmitJSON(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	result := runCLI(t, deps, []string{"install", "--json"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	var report installReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.ServicePath != "/service" || len(report.Clients) != 2 {
		t.Fatalf("report = %#v", report)
	}
}

func TestProductCommandsSurfaceFailures(t *testing.T) {
	t.Parallel()

	for _, command := range []string{"install", "update", "uninstall"} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			deps := dependencies(t)
			deps.Product = &fakeProduct{err: errors.New("brew is not installed")}
			if code := runCLI(t, deps, []string{command}).code; code != ExitError {
				t.Fatalf("code = %d, want %d", code, ExitError)
			}
		})
	}
}

func TestProductCommandsWithoutAManagerExitUnavailable(t *testing.T) {
	t.Parallel()

	for _, command := range []string{"install", "update", "uninstall"} {
		if code := runCLI(t, dependencies(t), []string{command}).code; code != ExitUnavailable {
			t.Fatalf("%s: code = %d, want %d", command, code, ExitUnavailable)
		}
	}
}

func TestServiceFactsParseTheInstallerStatusLine(t *testing.T) {
	t.Parallel()

	line := "daemon=running (0.4.0) installed=true path=/service definition=stale " +
		"updater=scheduled installed=true paths=/updater interval=6h0m0s"
	facts := serviceFacts(line)
	if facts["daemon"] != "running (0.4.0)" || facts["definition"] != "stale" || facts["updater"] != "scheduled" {
		t.Fatalf("facts = %#v", facts)
	}
	if facts["updater_installed"] != "true" {
		t.Fatalf("second installed key = %q", facts["updater_installed"])
	}
	if got := serviceDefinitionState(map[string]string{}); got != install.DefinitionAbsent {
		t.Fatalf("serviceDefinitionState({}) = %q", got)
	}
}

func TestCompletionScriptsCoverEveryVisibleCommand(t *testing.T) {
	t.Parallel()

	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			t.Parallel()
			result := runCLI(t, dependencies(t), []string{"completion", shell})
			if result.code != ExitOK {
				t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
			}
			for _, command := range []string{"daemon", "status", "doctor", "gc", "logs", "overview",
				"projects", "agents", "inbox", "threads", "reservations", "events", "install",
				"update", "uninstall", "completion", "version", "help"} {
				if !strings.Contains(result.stdout, command) {
					t.Fatalf("%s script does not mention %q", shell, command)
				}
			}
			if !strings.Contains(result.stdout, "blackbird") {
				t.Fatalf("%s script does not mention the program", shell)
			}
		})
	}
}

func TestCompletionDefaultsToBash(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	bare := runCLI(t, deps, []string{"completion"})
	explicit := runCLI(t, deps, []string{"completion", "bash"})
	if bare.stdout != explicit.stdout {
		t.Fatalf("completion = %q, completion bash = %q", bare.stdout, explicit.stdout)
	}
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	t.Parallel()

	if code := runCLI(t, dependencies(t), []string{"completion", "elvish"}).code; code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestCompletionModelEmitsJSON(t *testing.T) {
	t.Parallel()

	result := runCLI(t, dependencies(t), []string{"completion", "zsh", "--json"})
	var script completionScript
	if err := json.Unmarshal([]byte(result.stdout), &script); err != nil {
		t.Fatalf("stdout = %q: %v", result.stdout, err)
	}
	if script.Shell != "zsh" || len(script.Model.Commands) == 0 {
		t.Fatalf("script = %#v", script)
	}
	for _, command := range script.Model.Commands {
		if len(command.Path) == 0 {
			t.Fatalf("command %#v has no path", command)
		}
	}
}

func TestEveryCommandRendersBothProjections(t *testing.T) {
	t.Parallel()

	views := []render.View{
		newView(statusReport{Service: map[string]string{}}, drawStatus),
		newView(doctorReport{Checks: []checkResult{{Name: "binary", Status: checkPass}}}, drawDoctor),
		newView(gcReport{Path: "/a"}, drawGC),
		newView(overviewReport{}, drawOverview),
		newView(projectsReport{}, drawProjects),
		newView(projectReport{}, drawProject),
		newView(agentsReport{}, drawAgents),
		newView(agentReport{}, drawAgent),
		newView(inboxReport{}, drawInbox),
		newView(threadsReport{}, drawThreads),
		newView(threadReport{}, drawThread),
		newView(reservationsReport{}, drawReservations),
		newView(eventsReport{}, drawEvents),
		newView(logsReport{}, drawLogs),
		newView(installReport{}, drawInstall),
		newView(updateReport{}, drawUpdate),
		newView(uninstallReport{}, drawUninstall),
		newView(BuildInfo{Version: "test"}, drawBuild),
		newView(completionScript{Shell: "bash", lines: []string{"x"}}, drawCompletion),
		newView(errorEnvelope{Error: errorDetail{Message: "x"}}, drawErrorEnvelope),
	}
	for _, view := range views {
		if err := render.Conform(view); err != nil {
			t.Errorf("%T: %v", view, err)
		}
	}
}

func TestFormatHelpers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC)
	if got := instant("", now); got != render.Absent {
		t.Fatalf("instant(\"\") = %q", got)
	}
	if got := instant("not a time", now); got != "not a time" {
		t.Fatalf("instant(bad) = %q", got)
	}
	if got := instant("2026-08-15T11:00:00Z", now); got != "1h ago" {
		t.Fatalf("instant(hour ago) = %q", got)
	}
	if got := countdown(0); got != render.Absent {
		t.Fatalf("countdown(0) = %q", got)
	}
	if got := countdown(125000); got != "2m5s" {
		t.Fatalf("countdown(2m5s) = %q", got)
	}
	if got := countdown(-125000); got != "-2m5s" {
		t.Fatalf("countdown(-2m5s) = %q", got)
	}
	if got := selectorPaths(nil); got != render.Absent {
		t.Fatalf("selectorPaths(nil) = %q", got)
	}
	if got := selectorPaths([]Selector{{Path: "/a"}, {Path: "/b"}}); got != "/a /b" {
		t.Fatalf("selectorPaths = %q", got)
	}
	if got, err := limitOf("--limit", 25); got != 25 || err != nil {
		t.Fatalf("limitOf(25) = %d, %v", got, err)
	}
	if got := joinOrNone(nil); got != "none" {
		t.Fatalf("joinOrNone(nil) = %q", got)
	}
}

func TestConsoleReportsMissingPorts(t *testing.T) {
	t.Parallel()

	console := &Console{Globals: &Globals{}, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	for name, err := range map[string]error{
		"admin":    secondOf(console.admin()),
		"store":    secondOf(console.store()),
		"product":  secondOf(console.product()),
		"logs":     secondOf(console.logs()),
		"database": secondOfString(console.databasePath()),
	} {
		if exitCodeFor(err) != ExitUnavailable {
			t.Errorf("%s: err = %v, want an unavailable fault", name, err)
		}
	}
	if console.now().IsZero() {
		t.Fatal("now() returned the zero time without an injected clock")
	}
}

func secondOf[T any](_ T, err error) error { return err }

func secondOfString(_ string, err error) error { return err }

func TestStatusVerboseAddsTheRawLineAndIdentity(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Admin = &fakeAdmin{
		health: Health{Reachable: true, Ready: true},
		identity: Identity{PID: 4242, UptimeMS: 90000, HTTPAddress: "127.0.0.1:8080", DatabasePath: "/data/b.db",
			Metrics: RuntimeMetrics{Requests: map[string]map[string]int64{
				"mcp blackbird_agents_list": {"ok": 3, "UNAUTHENTICATED": 1},
			}, LeaseConflicts: 2, SSEConnections: 1, DatabaseBytes: 4096, WALBytes: 1024}},
	}
	deps.Store = &fakeStore{database: healthyDatabase()}

	quiet := runCLI(t, deps, []string{"status"})
	if strings.Contains(quiet.stdout, "4242") {
		t.Fatalf("stdout = %q, want no identity without --verbose", quiet.stdout)
	}
	verbose := runCLI(t, deps, []string{"status", "-v"})
	for _, want := range []string{"4242", "interval=6h0m0s", "Metrics", "requests", "4", "lease-conflicts", "2",
		"sse-active", "1", "mcp blackbird_agents_list", "UNAUTHENTICATED=1 ok=3"} {
		if !strings.Contains(verbose.stdout, want) {
			t.Fatalf("stdout missing %q: %q", want, verbose.stdout)
		}
	}
}

func TestListCommandsRenderTheTruncationTheDaemonReported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		rows int
	}{
		{name: "agents", args: []string{"agents"}, rows: 1},
		{name: "threads", args: []string{"threads"}, rows: 1},
		{name: "reservations", args: []string{"reservations"}, rows: 1},
		{name: "events", args: []string{"events"}, rows: 1},
		{name: "inbox", args: []string{"inbox", "--project=/a"}, rows: 1},
		{name: "projects show", args: []string{"projects", "show", "/a"}, rows: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			deps := dependencies(t)
			deps.Admin = truncatedAdmin()

			result := runCLI(t, deps, test.args)
			if result.code != ExitOK {
				t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
			}
			if !strings.Contains(result.stdout, "raise --limit") {
				t.Fatalf("stdout = %q, want the page marked as partial", result.stdout)
			}

			deps.Admin = truncatedAdmin()
			asJSON := runCLI(t, deps, append(append([]string{}, test.args...), "--json"))
			if !strings.Contains(asJSON.stdout, `"truncated": true`) {
				t.Fatalf("json = %q, want the truncated flag", asJSON.stdout)
			}
		})
	}
}

func truncatedAdmin() *fakeAdmin {
	return &fakeAdmin{
		truncated: true,
		projects:  []Project{{ProjectKey: "/a"}},
		agents:    []Agent{{AgentName: "scout", ProjectKey: "/a"}},
		conversations: []Conversation{
			{ConversationID: "c1", Topic: "release", ProjectKey: "/a", Status: "open"},
		},
		reservations: []Reservation{{LeaseID: "l1", Mode: "shared", State: "active"}},
		events:       []Event{{Position: 1, Type: "message.sent", ProjectKey: "/a"}},
		inbox: Inbox{
			ProjectKey: "/a",
			Truncated:  true,
			Summaries:  []InboxSummary{{AgentName: "scout", UnreadDeliveries: 1}},
			Pending:    []InboxItem{{RecipientAgentName: "scout", Subject: "alpha"}},
		},
	}
}

func TestDaemonRejectionsMapToTheDocumentedExitCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "bad request is usage",
			err:  &AdminStatusError{Status: 400, Path: "/api/v1/local/admin/agents", Detail: "limit must be from 1 through 256"},
			want: ExitUsage},
		{name: "not found is not-found",
			err:  &AdminStatusError{Status: 404, Path: "/api/v1/local/admin/agents"},
			want: ExitNotFound},
		{name: "server error is unavailable",
			err:  &AdminStatusError{Status: 500, Path: "/api/v1/local/admin/agents"},
			want: ExitUnavailable},
		{name: "transport failure is unavailable",
			err:  errors.New("connection refused"),
			want: ExitUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			deps := dependencies(t)
			deps.Admin = &fakeAdmin{err: test.err}

			result := runCLI(t, deps, []string{"agents"})
			if result.code != test.want {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, test.want, result.stderr)
			}
			if !strings.Contains(result.stderr, test.err.Error()) {
				t.Fatalf("stderr = %q, want the daemon's own message", result.stderr)
			}
		})
	}
}

func TestDaemonRejectionKeepsItsMessageInJSON(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{err: &AdminStatusError{Status: 400, Path: "/api/v1/local/admin/reservations",
		Detail: "mode must be one of any, shared or exclusive"}}

	result := runCLI(t, deps, []string{"reservations", "--json"})
	if result.code != ExitUsage {
		t.Fatalf("code = %d, want %d", result.code, ExitUsage)
	}
	var envelope errorEnvelope
	if err := json.Unmarshal([]byte(result.stderr), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Exit != ExitUsage || envelope.Error.Code != "usage" ||
		!strings.Contains(envelope.Error.Message, "mode must be one of") {
		t.Fatalf("envelope = %#v", envelope.Error)
	}
}

func TestLimitBelowOneIsAUsageError(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"agents", "--limit=0"},
		{"threads", "--limit=-3"},
		{"reservations", "--limit=0"},
		{"events", "--limit=0"},
		{"inbox", "--project=/a", "--limit=0"},
		{"logs", "--lines=0"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			deps := dependencies(t)
			deps.Admin = &fakeAdmin{}
			deps.Logs = &fakeLogs{}

			result := runCLI(t, deps, args)
			if result.code != ExitUsage {
				t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitUsage, result.stderr)
			}
			if !strings.Contains(result.stderr, "must be at least 1") {
				t.Fatalf("stderr = %q", result.stderr)
			}
		})
	}
}

func TestStaleReadIsReportedByStatusAndDoctor(t *testing.T) {
	t.Parallel()

	stale := healthyDatabase()
	stale.Mode = readModeStale

	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
	deps.Store = &fakeStore{database: stale}

	status := runCLI(t, deps, []string{"status"})
	// The problem sentence folds at the render width, so assert on a fragment
	// that cannot straddle the fold rather than on the whole phrase.
	if !strings.Contains(status.stdout, readModeStale) ||
		!strings.Contains(status.stdout, "uncheckpointed") {
		t.Fatalf("status stdout = %q, want the stale read named", status.stdout)
	}

	doctor := runCLI(t, deps, []string{"doctor", "--only=database.read", "--json"})
	var report doctorReport
	if err := json.Unmarshal([]byte(doctor.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) != 1 || report.Checks[0].Status != checkWarn || report.Checks[0].Remedy == "" {
		t.Fatalf("checks = %#v", report.Checks)
	}

	deps.Store = &fakeStore{database: healthyDatabase()}
	live := runCLI(t, deps, []string{"doctor", "--only=database.read", "--json"})
	report = doctorReport{}
	if err := json.Unmarshal([]byte(live.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) != 1 || report.Checks[0].Status != checkPass {
		t.Fatalf("checks = %#v", report.Checks)
	}
}

// A skipped check must not be paid for: the daemon probe is a network round
// trip and --deep runs a whole-database foreign-key check.
func TestDoctorOnlySkipsTheProbesItDoesNotReport(t *testing.T) {
	t.Parallel()

	store := &fakeStore{database: healthyDatabase()}
	deps := dependencies(t)
	deps.Product = &fakeProduct{}
	deps.Admin = panickingAdmin{}
	deps.Store = store

	result := runCLI(t, deps, []string{"doctor", "--only=binary", "--deep"})
	if result.code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
	}
	if store.path != "" {
		t.Fatalf("the database was inspected for --only=binary: %q", store.path)
	}
	if product := deps.Product.(*fakeProduct); product.called != "" {
		t.Fatalf("the installation was queried for --only=binary: %q", product.called)
	}
}

// A group names the checks it produces so --only can skip it without running
// it. If the two ever drift, --only silently stops reporting a check.
func TestEveryDoctorCheckIsSelectableByName(t *testing.T) {
	t.Parallel()

	command := &DoctorCmd{}
	declared := []string{}
	for _, group := range command.groups() {
		declared = append(declared, group.names...)
	}

	healthy := func(t *testing.T) Dependencies {
		t.Helper()
		deps := dependencies(t)
		deps.Product = &fakeProduct{}
		deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true, Version: "0.4.0", SchemaVersion: 4}}
		deps.Store = &fakeStore{database: healthyDatabase()}
		return deps
	}

	full := runCLI(t, healthy(t), []string{"doctor", "--deep", "--json"})
	var report doctorReport
	if err := json.Unmarshal([]byte(full.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) != len(declared) {
		t.Fatalf("a full run produced %d checks, groups declare %d", len(report.Checks), len(declared))
	}
	for _, check := range report.Checks {
		if !slices.Contains(declared, check.Name) {
			t.Fatalf("check %q belongs to no group", check.Name)
		}
	}

	for _, name := range declared {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := runCLI(t, healthy(t), []string{"doctor", "--deep", "--json", "--only=" + name})
			var only doctorReport
			if err := json.Unmarshal([]byte(result.stdout), &only); err != nil {
				t.Fatal(err)
			}
			if len(only.Checks) != 1 || only.Checks[0].Name != name {
				t.Fatalf("--only=%s produced %#v", name, only.Checks)
			}
		})
	}
}

// TestDoctorPassesAnUnsupportedUpdater is the half of this fix that keeps the
// diagnosis honest. Warning here would be advisory noise on every non-Homebrew
// machine and, under --strict, a permanent failure whose printed remedy is an
// install that deliberately declines to schedule an updater.
func TestDoctorPassesAnUnsupportedUpdater(t *testing.T) {
	t.Parallel()

	const line = "daemon=running installed=true path=/s definition=current updater=" + install.UpdaterUnsupported
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "strict"}[strict], func(t *testing.T) {
			t.Parallel()
			deps := dependencies(t)
			deps.Product = &fakeProduct{status: line}
			deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true, Version: "0.4.0", SchemaVersion: 4}}
			deps.Store = &fakeStore{database: healthyDatabase()}

			args := []string{"doctor", "--only=updater", "--json"}
			if strict {
				args = append(args, "--strict")
			}
			result := runCLI(t, deps, args)
			if result.code != ExitOK {
				t.Fatalf("code = %d, want %d; stdout=%q", result.code, ExitOK, result.stdout)
			}
			var report doctorReport
			if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Checks) != 1 || report.Checks[0].Status != checkPass {
				t.Fatalf("checks = %#v, want one passing check", report.Checks)
			}
			if report.Checks[0].Remedy != "" {
				t.Fatalf("remedy = %q, want none: no command schedules an updater here", report.Checks[0].Remedy)
			}
			if !strings.Contains(report.Checks[0].Detail, "Homebrew") {
				t.Fatalf("detail = %q, want it to name Homebrew", report.Checks[0].Detail)
			}
		})
	}
}

// TestStatusExplainsAnUnsupportedUpdater proves the state is not left as a bare
// word the reader has to interpret: "unsupported" beside no explanation reads as
// a broken installation.
func TestStatusExplainsAnUnsupportedUpdater(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{status: "daemon=running installed=true path=/s definition=current " +
		"updater=" + install.UpdaterUnsupported + " installed=false paths= interval=6h0m0s"}
	deps.Admin = &fakeAdmin{health: Health{Reachable: true, Ready: true}}
	deps.Store = &fakeStore{database: healthyDatabase()}

	result := runCLI(t, deps, []string{"status"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d", result.code, ExitOK)
	}
	// The sentence folds at the render width, so assert on fragments that
	// cannot straddle the fold.
	if !strings.Contains(result.stdout, install.UpdaterUnsupported) ||
		!strings.Contains(result.stdout, "Homebrew") ||
		!strings.Contains(result.stdout, "Problems") {
		t.Fatalf("stdout = %q, want the unsupported updater explained", result.stdout)
	}
}

// TestInstallReportsSchedulingNoUpdater keeps a silent success from implying
// unattended updates that will never run.
func TestInstallReportsSchedulingNoUpdater(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Product = &fakeProduct{updaterSkipped: install.UpdaterUnsupportedReason}

	result := runCLI(t, deps, []string{"install"})
	if result.code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", result.code, ExitOK, result.stderr)
	}
	if !strings.Contains(result.stdout, "updater=none") ||
		!strings.Contains(result.stdout, "Homebrew") {
		t.Fatalf("stdout = %q, want the skipped updater named", result.stdout)
	}
}
