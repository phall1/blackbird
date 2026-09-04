package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/phall1/blackbird/internal/adminapi"
)

// fakePeers answers for a fleet without a tailnet. Answers are keyed by the
// endpoint the client normalized, so a test can assert what was dialed as well
// as what came back.
type fakePeers struct {
	mu       sync.Mutex
	answers  map[string]adminapi.CostReport
	failures map[string]error
	queries  []CostQuery
	dialed   []string
	inflight atomic.Int32
	peak     atomic.Int32
	hold     chan struct{}
}

func (peers *fakePeers) PeerCost(_ context.Context, endpoint string,
	query CostQuery) (adminapi.CostReport, error) {
	current := peers.inflight.Add(1)
	for {
		peak := peers.peak.Load()
		if current <= peak || peers.peak.CompareAndSwap(peak, current) {
			break
		}
	}
	if peers.hold != nil {
		<-peers.hold
	}
	defer peers.inflight.Add(-1)

	peers.mu.Lock()
	peers.queries = append(peers.queries, query)
	peers.dialed = append(peers.dialed, endpoint)
	peers.mu.Unlock()
	if err, failed := peers.failures[endpoint]; failed {
		return adminapi.CostReport{}, err
	}
	return peers.answers[endpoint], nil
}

func hostCost(models ...adminapi.CostModel) adminapi.CostReport {
	return adminapi.CostReport{ProjectKey: "/repo", Since: "2026-09-03T00:00:00Z",
		Until: "2026-09-03T01:00:00Z", Cache: &adminapi.CostCache{Models: models}}
}

func runFleetCost(t *testing.T, peers *fakePeers, local adminapi.CostReport, args ...string) runResult {
	t.Helper()
	deps := dependencies(t)
	deps.Admin = &fakeAdmin{cost: local}
	deps.Peers = peers
	return runCLI(t, deps, append([]string{"cost", "/repo"}, args...))
}

// TestFleetCostUnionsSpendAcrossHosts is the feature working. The union is a
// sum of additive facts, and every input class stays apart on the way through:
// a cache read and an uncached input token are billed an order of magnitude
// differently, so a summed "input" column would answer nothing.
func TestFleetCostUnionsSpendAcrossHosts(t *testing.T) {
	t.Parallel()

	peers := &fakePeers{answers: map[string]adminapi.CostReport{
		"mini:8080": hostCost(adminapi.CostModel{Model: "opus", Calls: 2,
			UncachedInput: 100, CacheRead: 900, CacheWrite: 50, Output: 30}),
	}}
	local := hostCost(adminapi.CostModel{Model: "opus", Calls: 3,
		UncachedInput: 200, CacheRead: 100, CacheWrite: 50, Output: 70})
	result := runFleetCost(t, peers, local, "--peer", "mini")
	if result.code != ExitOK {
		t.Fatalf("exit=%d, stderr=%q", result.code, result.stderr)
	}
	// 5 calls, 300+1000+100 billed input split three ways, 100 output.
	if !strings.Contains(result.stdout, "opus") {
		t.Fatalf("the union names no model:\n%s", result.stdout)
	}
	for _, want := range []string{"300", "1000", "100"} {
		if !strings.Contains(result.stdout, want) {
			t.Fatalf("the union is missing the summed column %q:\n%s", want, result.stdout)
		}
	}
	if peers.dialed[0] != "mini:8080" {
		t.Fatalf("dialed %q; a peer named without a port must take the service default", peers.dialed[0])
	}
}

// TestFleetCostNamesASilentHostAndExitsDegraded is the whole reason this view
// exists. A fleet total that quietly drops a host is worse than an error,
// because it looks like an answer.
func TestFleetCostNamesASilentHostAndExitsDegraded(t *testing.T) {
	t.Parallel()

	peers := &fakePeers{
		answers:  map[string]adminapi.CostReport{"mini:8080": hostCost()},
		failures: map[string]error{"mini:8080": errors.New("connection refused")},
	}
	result := runFleetCost(t, peers, hostCost(adminapi.CostModel{Model: "opus", Calls: 1, Output: 5}),
		"--peer", "mini")
	if result.code != ExitDegraded {
		t.Fatalf("exit=%d for a fleet missing a host, want ExitDegraded=%d; stderr=%q",
			result.code, ExitDegraded, result.stderr)
	}
	if !strings.Contains(result.stdout, "mini:8080 did not answer") {
		t.Fatalf("the report does not name the silent host:\n%s", result.stdout)
	}
	if !strings.Contains(result.stdout, "connection refused") {
		t.Fatalf("the report does not say why the host was silent:\n%s", result.stdout)
	}
	if !strings.Contains(result.stdout, "NOT in the union") {
		t.Fatalf("the report does not say the totals are short:\n%s", result.stdout)
	}
	// The hosts that DID answer are still reported. A missing peer degrades the
	// answer; it does not withdraw it.
	if !strings.Contains(result.stdout, "opus") {
		t.Fatalf("a silent peer suppressed the hosts that answered:\n%s", result.stdout)
	}
}

// TestFleetCostNeverSumsContention is the modelling rule, asserted where it can
// actually be broken. Agents on two machines hold leases over two different
// checkouts on two different disks and cannot collide, so adding their refusals
// would manufacture a collision that never happened.
func TestFleetCostNeverSumsContention(t *testing.T) {
	t.Parallel()

	remote := hostCost()
	remote.Contention = &adminapi.CostContention{Refusals: 7}
	local := hostCost()
	local.Contention = &adminapi.CostContention{Refusals: 5}
	peers := &fakePeers{answers: map[string]adminapi.CostReport{"mini:8080": remote}}

	report, err := fleetCost(context.Background(),
		fleetConsole(t, local, peers), CostQuery{ProjectKey: "/repo"}, []string{"mini:8080"})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range report.Hosts {
		if host.Report == nil || host.Report.Contention == nil {
			t.Fatal("a host lost its contention section")
		}
	}
	// The union carries spend only; there is no fleet contention field to sum
	// into, and that absence is the design.
	result := runFleetCost(t, &fakePeers{answers: map[string]adminapi.CostReport{"mini:8080": remote}},
		local, "--peer", "mini")
	if strings.Contains(result.stdout, "12") {
		t.Fatalf("the fleet view printed a summed refusal count:\n%s", result.stdout)
	}
	if !strings.Contains(result.stdout, "cannot collide") {
		t.Fatalf("the fleet view does not say why contention is not summed:\n%s", result.stdout)
	}
}

func fleetConsole(t *testing.T, local adminapi.CostReport, peers PeerCostPort) *Console {
	t.Helper()
	deps := dependencies(t)
	deps.Admin = &fakeAdmin{cost: local}
	deps.Peers = peers
	return &Console{Deps: deps, Globals: &Globals{}}
}

// TestFleetCostBoundsTheFanOut keeps a fleet of many machines from opening one
// connection per machine at once -- here, and one report per machine over there.
func TestFleetCostBoundsTheFanOut(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	peers := &fakePeers{answers: map[string]adminapi.CostReport{}, hold: release}
	named := []string{}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		named = append(named, name+":8080")
		peers.answers[name+":8080"] = hostCost()
	}
	done := make(chan FleetCostReport, 1)
	go func() {
		report, err := fleetCost(context.Background(), fleetConsole(t, hostCost(), peers),
			CostQuery{ProjectKey: "/repo"}, named)
		if err != nil {
			t.Error(err)
		}
		done <- report
	}()
	deadline := time.After(5 * time.Second)
	for peers.inflight.Load() < maxFleetFanOut {
		select {
		case <-deadline:
			t.Fatalf("only %d peer queries started", peers.inflight.Load())
		default:
		}
	}
	close(release)
	<-done
	if peak := peers.peak.Load(); peak > maxFleetFanOut {
		t.Fatalf("peak concurrent peer queries = %d, want at most %d", peak, maxFleetFanOut)
	}
}

// TestFleetCostFailsWhenTheLocalDaemonCannotAnswer separates a fleet outage
// from this command having no ground to stand on. The local report is the one
// host that is never "silent": if it fails, the whole view is a fault.
func TestFleetCostFailsWhenTheLocalDaemonCannotAnswer(t *testing.T) {
	t.Parallel()

	deps := dependencies(t)
	deps.Admin = &fakeAdmin{err: errors.New("storage is down")}
	deps.Peers = &fakePeers{answers: map[string]adminapi.CostReport{"mini:8080": hostCost()}}
	result := runCLI(t, deps, []string{"cost", "/repo", "--peer", "mini"})
	if result.code == ExitOK || result.code == ExitDegraded {
		t.Fatalf("exit=%d when the local daemon could not answer; want a fault", result.code)
	}
}

// TestFleetCostJSONKeepsHostsAndSilence is the machine contract: a consumer
// must be able to see which hosts contributed without reading prose.
func TestFleetCostJSONKeepsHostsAndSilence(t *testing.T) {
	t.Parallel()

	peers := &fakePeers{
		answers:  map[string]adminapi.CostReport{"mini:8080": hostCost(), "old:8080": hostCost()},
		failures: map[string]error{"old:8080": errors.New("no route to host")},
	}
	result := runFleetCost(t, peers, hostCost(), "--peer", "mini", "--peer", "old", "--json")
	if result.code != ExitDegraded {
		t.Fatalf("exit=%d, want ExitDegraded; stderr=%q", result.code, result.stderr)
	}
	var payload FleetCostReport
	if err := json.Unmarshal([]byte(result.stdout), &payload); err != nil {
		t.Fatalf("decode %q: %v", result.stdout, err)
	}
	if payload.Complete {
		t.Fatal("complete=true with a silent host")
	}
	if len(payload.Hosts) != 3 || len(payload.Silent) != 1 || payload.Silent[0] != "old:8080" {
		t.Fatalf("hosts=%+v silent=%v", payload.Hosts, payload.Silent)
	}
	if !payload.Hosts[0].Local || payload.Hosts[0].Host != LocalHostLabel {
		t.Fatalf("the local host is not first or not labelled: %+v", payload.Hosts[0])
	}
}

// TestFleetPeerEndpointsAreNormalizedAndLoopbackIsRefused states what an
// operator may type. A loopback peer is this machine, which the peer route
// refuses by design and which the fleet view already counts.
func TestFleetPeerEndpointsAreNormalizedAndLoopbackIsRefused(t *testing.T) {
	t.Parallel()

	accepted := map[string]string{
		"mini":                      "mini:" + defaultPeerPort(),
		"mini:9000":                 "mini:9000",
		"http://mini:9000":          "mini:9000",
		"http://mini.tail1.ts.net/": "mini.tail1.ts.net:" + defaultPeerPort(),
		"100.79.155.27:8080":        "100.79.155.27:8080",
	}
	for input, want := range accepted {
		got, err := peerEndpoint(input)
		if err != nil {
			t.Errorf("peerEndpoint(%q) failed: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("peerEndpoint(%q) = %q, want %q", input, got, want)
		}
	}
	for _, refused := range []string{"", "  ", "127.0.0.1:8080", "localhost", "localhost:8080",
		"https://mini:8080", "mini:8080/cost"} {
		if got, err := peerEndpoint(refused); err == nil {
			t.Errorf("peerEndpoint(%q) = %q, want a refusal", refused, got)
		}
	}
}

// TestPeerCostClientSendsNoCredential is the property that makes dialling
// another machine safe. The admin token authenticates an operator to the daemon
// on THIS machine; nothing may carry it off the host.
func TestPeerCostClientSendsNoCredential(t *testing.T) {
	t.Parallel()

	var headers http.Header
	var path, query string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		headers, path, query = request.Header.Clone(), request.URL.Path, request.URL.RawQuery
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"project_key":"/repo","since":"a","until":"b"}`))
	}))
	defer server.Close()

	client := newPeerCostClient()
	report, err := client.PeerCost(context.Background(), strings.TrimPrefix(server.URL, "http://"),
		CostQuery{ProjectKey: "/repo", SinceHours: 3, Limit: 7})
	if err != nil {
		t.Fatal(err)
	}
	if report.ProjectKey != "/repo" {
		t.Fatalf("report=%+v", report)
	}
	if headers.Get("Authorization") != "" || headers.Get("Cookie") != "" {
		t.Fatalf("the peer client sent a credential: %v", headers)
	}
	if path != peerCostPath {
		t.Fatalf("path=%q, want %q", path, peerCostPath)
	}
	for _, want := range []string{"project_key=", "since_hours=3", "limit=7"} {
		if !strings.Contains(query, want) {
			t.Fatalf("query=%q is missing %q", query, want)
		}
	}
}

// TestPeerCostClientRefusesARedirect keeps a peer from bouncing this query at a
// host the operator never named.
func TestPeerCostClientRefusesARedirect(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "http://example.invalid/cost", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	_, err := newPeerCostClient().PeerCost(context.Background(),
		strings.TrimPrefix(server.URL, "http://"), CostQuery{ProjectKey: "/repo"})
	if err == nil {
		t.Fatal("a redirect was followed")
	}
}

// TestPeerCostClientTranslatesRefusalsIntoWork names what the operator has to
// go and change, because the refusals mean entirely different jobs.
func TestPeerCostClientTranslatesRefusalsIntoWork(t *testing.T) {
	t.Parallel()

	cases := []struct {
		status int
		want   string
	}{
		{http.StatusForbidden, "allowed-peer list"},
		{http.StatusNotFound, "before fleet cost"},
		{http.StatusServiceUnavailable, "could not answer right now"},
		{http.StatusBadRequest, "rejected the query"},
	}
	for _, test := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(test.status)
			_, _ = writer.Write([]byte(`{"code":"FORBIDDEN","message":"nope"}`))
		}))
		_, err := newPeerCostClient().PeerCost(context.Background(),
			strings.TrimPrefix(server.URL, "http://"), CostQuery{ProjectKey: "/repo"})
		server.Close()
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("status %d gave %v, want a message containing %q", test.status, err, test.want)
		}
	}
}

// TestPeerCostClientCapsTheResponse keeps a hostile or broken peer from
// spending this process's memory.
func TestPeerCostClientCapsTheResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"project_key":"`))
		chunk := strings.Repeat("x", 1<<16)
		for range 128 {
			if _, err := writer.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	_, err := newPeerCostClient().PeerCost(context.Background(),
		strings.TrimPrefix(server.URL, "http://"), CostQuery{ProjectKey: "/repo"})
	if err == nil {
		t.Fatal("an endless body decoded without complaint")
	}
}

// TestPeerCostClientStripsTerminalEscapes is the boundary where a peer's JSON
// stops being somebody else's text and starts being rendered into a terminal
// -- which is an interpreter.
//
// Before the fleet view, every string this command printed came from the daemon
// on this machine. A hostile or compromised peer can now choose a model name, a
// path, an agent name and a problem message, and an ANSI/OSC payload in any of
// them rewrites the operator's screen: the "did not answer" warnings the fleet
// view exists to show are exactly what a clear-screen hides, and OSC 52 writes
// the clipboard.
func TestPeerCostClientStripsTerminalEscapes(t *testing.T) {
	t.Parallel()

	// A real payload: clear the screen, then an OSC 52 clipboard write.
	const hostile = "claude\x1b[2J\x1b]52;c;aGVsbG8=\x07-sonnet"
	const clean = "claude[2J]52;c;aGVsbG8=-sonnet"
	encoded, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	quoted := string(encoded)
	body := fmt.Sprintf(`{"project_key":%[1]s,"since":%[1]s,"until":%[1]s,
		"unobserved":[%[1]s],
		"contention":{"agents":[{"agent_name":%[1]s,"actor_id":%[1]s}],
			"contended_paths":[{"path":%[1]s,"kind":%[1]s}]},
		"abandonment":{"leases":[{"lease_id":%[1]s,"holder_agent_name":%[1]s,
			"mode":%[1]s,"contended_path":%[1]s}]},
		"cache":{"models":[{"model":%[1]s}]}}`, quoted)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(body))
	}))
	defer server.Close()

	report, err := newPeerCostClient().PeerCost(context.Background(),
		strings.TrimPrefix(server.URL, "http://"), CostQuery{ProjectKey: "/repo"})
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"project_key":    report.ProjectKey,
		"since":          report.Since,
		"until":          report.Until,
		"unobserved":     report.Unobserved[0],
		"agent_name":     report.Contention.Agents[0].AgentName,
		"actor_id":       report.Contention.Agents[0].ActorID,
		"path":           report.Contention.Paths[0].Path,
		"kind":           report.Contention.Paths[0].Kind,
		"lease_id":       report.Abandonment.Leases[0].LeaseID,
		"holder":         report.Abandonment.Leases[0].HolderAgent,
		"mode":           report.Abandonment.Leases[0].Mode,
		"contended_path": report.Abandonment.Leases[0].ContendedPath,
		"model":          report.Cache.Models[0].Model,
	} {
		if got != clean {
			t.Errorf("%s = %q, want %q", name, got, clean)
		}
	}
}

// TestPeerRefusalDetailStripsTerminalEscapes covers the other string a peer
// chooses: the problem message rendered beside the host in the failure column.
func TestPeerRefusalDetailStripsTerminalEscapes(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte("{\"code\":\"FOR\\u001b[2JBIDDEN\",\"message\":\"go\\u001b]52;c;x\\u0007 away\"}"))
	}))
	defer server.Close()

	_, err := newPeerCostClient().PeerCost(context.Background(),
		strings.TrimPrefix(server.URL, "http://"), CostQuery{ProjectKey: "/repo"})
	if err == nil {
		t.Fatal("a 403 was not reported")
	}
	if strings.ContainsAny(err.Error(), "\x1b\x07") {
		t.Fatalf("the refusal carries control characters into the terminal: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "FOR[2JBIDDEN: go]52;c;x away") {
		t.Fatalf("the detail lost more than its control characters: %q", err.Error())
	}
}

// TestSanitizePeerTextKeepsEveryPrintableRune is the other half of the filter:
// it must delete escapes without mangling a legitimate name, including one in
// a non-Latin script, and must leave valid UTF-8 behind.
func TestSanitizePeerTextKeepsEveryPrintableRune(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]string{
		"claude-opus-4-5":       "claude-opus-4-5",
		"/repo/パス":              "/repo/パス",
		"a\tb\nc":               "abc",
		"\u009bmshifted":        "mshifted",
		"trailing\x7f":          "trailing",
		"emoji \U0001F600 kept": "emoji \U0001F600 kept",
	} {
		if got := sanitizePeerText(input); got != want {
			t.Errorf("sanitizePeerText(%q) = %q, want %q", input, got, want)
		}
		if !utf8.ValidString(sanitizePeerText(input)) {
			t.Errorf("sanitizePeerText(%q) produced invalid UTF-8", input)
		}
	}
}
