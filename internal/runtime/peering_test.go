package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	httptransport "github.com/phall1/blackbird/internal/transport/http"
)

// The fixtures below are the real shapes, captured from `tailscale status
// --json` and `tailscale whois --json` on this tailnet. Parsing is asserted
// against what the client actually emits rather than against a hand-written
// idea of it, because a field rename upstream would otherwise turn every
// verification into a silent refusal that no test could see.
const (
	whoisFixture = `{
  "Node": {
    "ID": 256610575571796,
    "StableID": "nFJpq2jD1311CNTRL",
    "Name": "phalls-mac-mini.tail1354da.ts.net.",
    "Addresses": ["100.79.155.27/32"],
    "Online": true,
    "ComputedName": "phalls-mac-mini",
    "ComputedNameWithHost": "phalls-mac-mini"
  },
  "UserProfile": {
    "ID": 434126217919283,
    "LoginName": "owner@example.com",
    "DisplayName": "The Owner"
  },
  "CapMap": null
}`
	statusFixture = `{
  "Version": "1.98.8",
  "BackendState": "Running",
  "TailscaleIPs": ["100.78.103.8", "fd7a:115c:a1e0::7233:6709"],
  "Self": {
    "ID": "nnjQLUo2L911CNTRL",
    "HostName": "a-laptop",
    "DNSName": "a-laptop.tail1354da.ts.net.",
    "TailscaleIPs": ["100.78.103.8", "fd7a:115c:a1e0::7233:6709"]
  }
}`
	stoppedStatusFixture = `{"BackendState":"Stopped","Self":{"TailscaleIPs":[]}}`
)

type recordedRun struct {
	arguments []string
}

// runRecorder is written from every goroutine that resolves, because coalescing
// and the subprocess cap are properties that only exist under concurrency.
type runRecorder struct {
	mu   sync.Mutex
	runs []recordedRun
}

func (recorder *runRecorder) record(arguments []string) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.runs = append(recorder.runs, recordedRun{arguments: append([]string(nil), arguments...)})
}

func (recorder *runRecorder) count() int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return len(recorder.runs)
}

func (recorder *runRecorder) first() recordedRun {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.runs[0]
}

// stubTailnet builds a tailnet probe whose only contact with the outside world
// is the injected exec seam, so these assertions hold identically on a machine
// inside this tailnet and on a CI runner that has never joined one.
func stubTailnet(
	t *testing.T,
	answer func(arguments []string) (string, string, error),
) (*tailnet, *runRecorder) {
	t.Helper()
	recorder := &runRecorder{}
	probe := newTailnet()
	probe.lookPath = func(string) (string, error) { return "/usr/local/bin/tailscale", nil }
	probe.run = func(_ context.Context, _ string, arguments ...string) ([]byte, string, error) {
		recorder.record(arguments)
		stdout, stderr, err := answer(arguments)
		return []byte(stdout), stderr, err
	}
	return probe, recorder
}

func answerFixtures(arguments []string) (string, string, error) {
	switch arguments[0] {
	case "whois":
		return whoisFixture, "", nil
	case "status":
		return statusFixture, "", nil
	default:
		return "", "unknown subcommand", errors.New("exit status 1")
	}
}

func TestResolvePeerReadsTheClientsRealWhoisRecord(t *testing.T) {
	t.Parallel()

	probe, runs := stubTailnet(t, answerFixtures)
	identity, err := probe.ResolvePeer(t.Context(), "100.79.155.27:41234")
	if err != nil {
		t.Fatalf("ResolvePeer() error = %v", err)
	}
	want := httptransport.PeerIdentity{
		MachineName: "phalls-mac-mini", StableID: "nFJpq2jD1311CNTRL", LoginName: "owner@example.com",
	}
	if identity != want {
		t.Fatalf("identity = %+v, want %+v", identity, want)
	}
	// The client is asked about the caller's address and port, which is the
	// form `tailscale whois` accepts.
	if got := strings.Join(runs.first().arguments, " "); got != "whois --json 100.79.155.27:41234" {
		t.Fatalf("invocation = %q", got)
	}
}

// TestResolvePeerNeverReusesAnAdmission is the fix for a cache that outlived
// its evidence. A verified identity used to be remembered for a TTL, which
// meant that for the length of that window the daemon kept admitting a peer
// after tailscaled died, after the node was deleted, after the key expired and
// after an ACL changed -- while the comments beside it said the opposite. The
// property asserted here is the one an operator revoking access relies on:
// every admission consults Tailscale.
func TestResolvePeerNeverReusesAnAdmission(t *testing.T) {
	t.Parallel()

	alive := true
	probe, runs := stubTailnet(t, func(arguments []string) (string, string, error) {
		if !alive {
			return "", "failed to connect to local tailscaled", errors.New("exit status 1")
		}
		return answerFixtures(arguments)
	})
	for range 3 {
		if _, err := probe.ResolvePeer(t.Context(), "100.79.155.27:41234"); err != nil {
			t.Fatalf("ResolvePeer() error = %v", err)
		}
	}
	if runs.count() != 3 {
		t.Fatalf("invocations = %d, want one per request", runs.count())
	}
	alive = false
	if _, err := probe.ResolvePeer(t.Context(), "100.79.155.27:41234"); !errors.Is(err, httptransport.ErrPeerUnavailable) {
		t.Fatalf("ResolvePeer() after the backend died = %v, want %v", err, httptransport.ErrPeerUnavailable)
	}
}

// TestResolvePeerRemembersARefusalBriefly is the half of the bound that IS
// safe to cache. A remembered refusal can only refuse a caller who would have
// been refused anyway, and without it an address whois will not resolve forks
// a process per request on a route that needs no credential.
func TestResolvePeerRemembersARefusalBriefly(t *testing.T) {
	t.Parallel()

	probe, runs := stubTailnet(t, func([]string) (string, string, error) {
		return "", "peer not found", errors.New("exit status 1")
	})
	base := time.Now()
	probe.now = func() time.Time { return base }
	for range 5 {
		if _, err := probe.ResolvePeer(t.Context(), "100.79.155.27:41234"); !errors.Is(err, httptransport.ErrPeerUnknown) {
			t.Fatalf("ResolvePeer() error = %v, want %v", err, httptransport.ErrPeerUnknown)
		}
	}
	if runs.count() != 1 {
		t.Fatalf("invocations = %d, want 1", runs.count())
	}
	base = base.Add(probe.refusalTTL + time.Second)
	if _, err := probe.ResolvePeer(t.Context(), "100.79.155.27:41234"); !errors.Is(err, httptransport.ErrPeerUnknown) {
		t.Fatalf("ResolvePeer() after the refusal expired = %v", err)
	}
	if runs.count() != 2 {
		t.Fatalf("invocations = %d, want 2 once the refusal expired", runs.count())
	}
}

// TestResolvePeerRecoversImmediatelyFromARefusal keeps the negative cache from
// becoming a lockout: an address that starts verifying is admitted at once
// rather than after the refusal window an unrelated failure opened.
func TestResolvePeerRecoversImmediatelyFromARefusal(t *testing.T) {
	t.Parallel()

	known := false
	probe, _ := stubTailnet(t, func(arguments []string) (string, string, error) {
		if !known {
			return "", "peer not found", errors.New("exit status 1")
		}
		return answerFixtures(arguments)
	})
	if _, err := probe.ResolvePeer(t.Context(), "100.79.155.27:41234"); err == nil {
		t.Fatal("ResolvePeer() admitted an unknown caller")
	}
	known = true
	// The refusal is still inside its window, so a second address proves the
	// window exists while this one proves recovery does not wait for it.
	if _, err := probe.ResolvePeer(t.Context(), "100.79.155.28:41234"); err != nil {
		t.Fatalf("ResolvePeer() error = %v", err)
	}
}

// TestResolvePeerCoalescesConcurrentLookups bounds the cost of an
// unauthenticated route. /healthz is peer-classified and needs no credential,
// so without coalescing a burst of N requests from one source is a burst of N
// `tailscale whois` processes.
func TestResolvePeerCoalescesConcurrentLookups(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	var invocations atomic.Int64
	probe, _ := stubTailnet(t, func(arguments []string) (string, string, error) {
		invocations.Add(1)
		<-release
		return answerFixtures(arguments)
	})
	const callers = 16
	var arrived atomic.Int64
	errs := make(chan error, callers)
	for range callers {
		go func() {
			arrived.Add(1)
			_, err := probe.ResolvePeer(context.Background(), "100.79.155.27:41234")
			errs <- err
		}()
	}
	// The assertion is made while the leader is still in flight, because that
	// is when a follower would fork: every caller has entered ResolvePeer, one
	// lookup is running, and the count of lookups must still be one.
	deadline := time.Now().Add(10 * time.Second)
	for arrived.Load() < callers || invocations.Load() < 1 {
		if time.Now().After(deadline) {
			close(release)
			t.Fatalf("callers never arrived: arrived = %d, invocations = %d",
				arrived.Load(), invocations.Load())
		}
		time.Sleep(time.Millisecond)
	}
	probe.mu.Lock()
	waiting := len(probe.inflight)
	probe.mu.Unlock()
	if waiting != 1 {
		close(release)
		t.Fatalf("in-flight lookups = %d, want 1", waiting)
	}
	if got := invocations.Load(); got != 1 {
		close(release)
		t.Fatalf("invocations while one lookup is in flight = %d, want 1", got)
	}
	close(release)
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("ResolvePeer() error = %v", err)
		}
	}
}

// TestResolvePeerCapsLiveSubprocesses is the second half of the same bound: a
// flood from MANY sources coalesces into nothing, so the ceiling has to be on
// live processes rather than on distinct addresses.
func TestResolvePeerCapsLiveSubprocesses(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	var live, peak atomic.Int64
	probe, _ := stubTailnet(t, func(arguments []string) (string, string, error) {
		running := live.Add(1)
		for {
			highest := peak.Load()
			if running <= highest || peak.CompareAndSwap(highest, running) {
				break
			}
		}
		<-release
		live.Add(-1)
		return answerFixtures(arguments)
	})
	// The deadline has to outlast the test's own release, or a caller that
	// waits for a slot reports the cap as a failure.
	probe.timeout = 30 * time.Second
	const callers = 24
	errs := make(chan error, callers)
	for index := range callers {
		go func() {
			_, err := probe.ResolvePeer(context.Background(),
				fmt.Sprintf("100.79.155.%d:41234", index+1))
			errs <- err
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for live.Load() < tailnetProbeConcurrency && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	for range callers {
		<-errs
	}
	if got := peak.Load(); got > tailnetProbeConcurrency {
		t.Fatalf("peak live subprocesses = %d, want at most %d", got, tailnetProbeConcurrency)
	}
}

// TestResolvePeerFailsClosed walks every way the identity service can let this
// daemon down. None of them returns an identity, and each carries the sentinel
// the guard turns into a log reason an operator can act on.
func TestResolvePeerFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		probe   func(t *testing.T) *tailnet
		address string
		want    error
	}{
		{
			name: "tailscale is not installed",
			probe: func(t *testing.T) *tailnet {
				t.Helper()
				probe, _ := stubTailnet(t, answerFixtures)
				probe.lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
				return probe
			},
			address: "100.79.155.27:41234",
			want:    httptransport.ErrPeerUnavailable,
		},
		{
			name: "tailscaled went away while the daemon was running",
			probe: func(t *testing.T) *tailnet {
				t.Helper()
				probe, _ := stubTailnet(t, func([]string) (string, string, error) {
					return "", "failed to connect to local tailscaled", errors.New("exit status 1")
				})
				return probe
			},
			address: "100.79.155.27:41234",
			want:    httptransport.ErrPeerUnavailable,
		},
		{
			name: "the tailnet does not know this caller",
			probe: func(t *testing.T) *tailnet {
				t.Helper()
				probe, _ := stubTailnet(t, func([]string) (string, string, error) {
					return "", "2026/09/03 16:47:40 peer not found", errors.New("exit status 1")
				})
				return probe
			},
			address: "100.101.102.103:1",
			want:    httptransport.ErrPeerUnknown,
		},
		{
			name: "whois answered with something that is not JSON",
			probe: func(t *testing.T) *tailnet {
				t.Helper()
				probe, _ := stubTailnet(t, func([]string) (string, string, error) { return "not json", "", nil })
				return probe
			},
			address: "100.79.155.27:41234",
			want:    httptransport.ErrPeerMalformed,
		},
		{
			name: "whois answered with no node",
			probe: func(t *testing.T) *tailnet {
				t.Helper()
				probe, _ := stubTailnet(t, func([]string) (string, string, error) { return `{"Node":null}`, "", nil })
				return probe
			},
			address: "100.79.155.27:41234",
			want:    httptransport.ErrPeerUnknown,
		},
		{
			name: "whois answered with a node that has no name",
			probe: func(t *testing.T) *tailnet {
				t.Helper()
				probe, _ := stubTailnet(t, func([]string) (string, string, error) {
					return `{"Node":{"StableID":"nABC","Name":"","ComputedName":""}}`, "", nil
				})
				return probe
			},
			address: "100.79.155.27:41234",
			want:    httptransport.ErrPeerMalformed,
		},
		{
			name:    "the remote address carries no port",
			probe:   func(t *testing.T) *tailnet { t.Helper(); probe, _ := stubTailnet(t, answerFixtures); return probe },
			address: "100.79.155.27",
			want:    httptransport.ErrPeerMalformed,
		},
		{
			name:    "the remote host is not an address at all",
			probe:   func(t *testing.T) *tailnet { t.Helper(); probe, _ := stubTailnet(t, answerFixtures); return probe },
			address: "phalls-mac-mini:41234",
			want:    httptransport.ErrPeerMalformed,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			identity, err := testCase.probe(t).ResolvePeer(t.Context(), testCase.address)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("ResolvePeer() error = %v, want %v", err, testCase.want)
			}
			if identity != (httptransport.PeerIdentity{}) {
				t.Fatalf("a failed resolution returned an identity: %+v", identity)
			}
		})
	}
}

// TestResolvePeerNeverInfersFromTheAddressRange is the rule the whole design
// rests on. A caller inside 100.64.0.0/10 that whois does not recognise is
// refused exactly like any other stranger; the range is not a credential.
func TestResolvePeerNeverInfersFromTheAddressRange(t *testing.T) {
	t.Parallel()

	probe, _ := stubTailnet(t, func([]string) (string, string, error) {
		return "", "peer not found", errors.New("exit status 1")
	})
	for _, address := range []string{"100.64.0.1:1", "100.79.155.27:41234", "100.127.255.254:9"} {
		if _, err := probe.ResolvePeer(t.Context(), address); !errors.Is(err, httptransport.ErrPeerUnknown) {
			t.Fatalf("ResolvePeer(%q) error = %v, want %v", address, err, httptransport.ErrPeerUnknown)
		}
	}
}

func TestSelfReadsTheClientsRealStatusRecord(t *testing.T) {
	t.Parallel()

	probe, _ := stubTailnet(t, answerFixtures)
	self, err := probe.Self(t.Context())
	if err != nil {
		t.Fatalf("Self() error = %v", err)
	}
	if len(self.Addresses) != 2 || self.Addresses[0].String() != "100.78.103.8" {
		t.Fatalf("addresses = %v", self.Addresses)
	}
	// The identity half is what stops this machine from being its own peer, so
	// it is read from the same record the addresses come from.
	if self.StableID != "nnjQLUo2L911CNTRL" || self.MachineName != "a-laptop" {
		t.Fatalf("self = %+v", self)
	}
}

func TestSelfRefusesAStoppedBackend(t *testing.T) {
	t.Parallel()

	probe, _ := stubTailnet(t, func([]string) (string, string, error) { return stoppedStatusFixture, "", nil })
	if _, err := probe.Self(t.Context()); !errors.Is(err, httptransport.ErrPeerUnavailable) {
		t.Fatalf("Self() error = %v, want %v", err, httptransport.ErrPeerUnavailable)
	}
}

func TestPeeringConfigValidation(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		peering PeeringConfig
		valid   bool
	}{
		"off is the default and needs nothing":     {PeeringConfig{}, true},
		"on with a named peer":                     {PeeringConfig{Enabled: true, Allowed: []string{"phalls-mac-mini"}}, true},
		"on with an address and a named peer":      {PeeringConfig{Enabled: true, Address: "100.78.103.8:8080", Allowed: []string{"m"}}, true},
		"on with no named peer admits nobody":      {PeeringConfig{Enabled: true}, false},
		"on with only blank names admits nobody":   {PeeringConfig{Enabled: true, Allowed: []string{"", "  "}}, false},
		"on with an unparsable address":            {PeeringConfig{Enabled: true, Address: "not-an-address", Allowed: []string{"m"}}, false},
		"off but an operator named peers":          {PeeringConfig{Allowed: []string{"phalls-mac-mini"}}, false},
		"off but an operator supplied an address":  {PeeringConfig{Address: "100.78.103.8:8080"}, false},
		"config validation carries peering errors": {PeeringConfig{Enabled: true}, false},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config := Config{Storage: StorageSQLite, SQLitePath: "blackbird.db",
				HTTPAddress: "127.0.0.1:8080", MCPAddress: "127.0.0.1:8081", Peering: testCase.peering}
			err := config.Validate()
			if testCase.valid != (err == nil) {
				t.Fatalf("Validate() error = %v, want valid=%v", err, testCase.valid)
			}
			if err != nil && !strings.Contains(err.Error(), "peering") {
				t.Fatalf("Validate() error = %v, want it to name peering", err)
			}
		})
	}
}

func addresses(t *testing.T, texts ...string) []netip.Addr {
	t.Helper()
	parsed := make([]netip.Addr, 0, len(texts))
	for _, text := range texts {
		address, err := netip.ParseAddr(text)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, address)
	}
	return parsed
}

func TestPeerListenAddressDefaultsToThisMachinesTailnetAddress(t *testing.T) {
	t.Parallel()

	got, err := peerListenAddress(PeeringConfig{Enabled: true, Allowed: []string{"m"}},
		"127.0.0.1:8080", addresses(t, "fd7a:115c:a1e0::7233:6709", "100.78.103.8"))
	if err != nil {
		t.Fatalf("peerListenAddress() error = %v", err)
	}
	if got != "100.78.103.8:8080" {
		t.Fatalf("address = %q, want %q", got, "100.78.103.8:8080")
	}
}

// TestPeerListenAddressRefusesAnyAddressThisMachineDoesNotOwn is the second
// mechanism: even with the guard installed, the peer routes never appear on an
// interface Tailscale is not in front of.
func TestPeerListenAddressRefusesAnyAddressThisMachineDoesNotOwn(t *testing.T) {
	t.Parallel()

	self := addresses(t, "100.78.103.8")
	for _, requested := range []string{"0.0.0.0:8080", "192.168.1.5:8080", "127.0.0.1:8080", "100.79.155.27:8080"} {
		_, err := peerListenAddress(PeeringConfig{Enabled: true, Address: requested, Allowed: []string{"m"}},
			"127.0.0.1:8080", self)
		if err == nil {
			t.Fatalf("peerListenAddress(%q) was accepted", requested)
		}
	}
	got, err := peerListenAddress(PeeringConfig{Enabled: true, Address: "100.78.103.8:9999", Allowed: []string{"m"}},
		"127.0.0.1:8080", self)
	if err != nil || got != "100.78.103.8:9999" {
		t.Fatalf("peerListenAddress() = %q, %v", got, err)
	}
}

func TestComposePeeringOffProducesADisabledAdmissionAndNoAddress(t *testing.T) {
	t.Parallel()

	probe, runs := stubTailnet(t, answerFixtures)
	admission, address, err := composePeering(t.Context(), Config{HTTPAddress: "127.0.0.1:8080"},
		probe, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("composePeering() error = %v", err)
	}
	if address != "" || admission.Enabled() {
		t.Fatalf("peering off composed address=%q enabled=%v", address, admission.Enabled())
	}
	// A daemon nobody configured must not shell out to anything at startup.
	if runs.count() != 0 {
		t.Fatalf("peering off invoked the tailscale client %d times", runs.count())
	}
}

func TestComposePeeringOnResolvesTheAddressAndAdmission(t *testing.T) {
	t.Parallel()

	probe, _ := stubTailnet(t, answerFixtures)
	config := Config{HTTPAddress: "127.0.0.1:8080",
		Peering: PeeringConfig{Enabled: true, Allowed: []string{"phalls-mac-mini"}}}
	admission, address, err := composePeering(t.Context(), config, probe, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("composePeering() error = %v", err)
	}
	if address != "100.78.103.8:8080" || !admission.Enabled() {
		t.Fatalf("composePeering() = %q, enabled=%v", address, admission.Enabled())
	}
}

// TestComposePeeringRefusesToStartWithoutTailscale is the fail-closed startup
// rule. An operator who asked for peering on a machine that cannot provide it
// gets a refusal they can read, not a daemon that looks peered and admits
// nobody.
func TestComposePeeringRefusesToStartWithoutTailscale(t *testing.T) {
	t.Parallel()

	probe, _ := stubTailnet(t, answerFixtures)
	probe.lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	config := Config{HTTPAddress: "127.0.0.1:8080",
		Peering: PeeringConfig{Enabled: true, Allowed: []string{"phalls-mac-mini"}}}
	_, _, err := composePeering(t.Context(), config, probe, nil, slog.New(slog.DiscardHandler))
	if !errors.Is(err, httptransport.ErrPeerUnavailable) {
		t.Fatalf("composePeering() error = %v, want %v", err, httptransport.ErrPeerUnavailable)
	}
}

// TestDaemonRefusesAPeerListenerWithoutAnEnabledAdmission is the structural
// guarantee that a composition cannot open a peer port with nothing deciding
// who reaches it.
func TestDaemonRefusesAPeerListenerWithoutAnEnabledAdmission(t *testing.T) {
	t.Parallel()

	daemon := newTestDaemon(t, Dependencies{
		OpenSQLite: func(context.Context, sqliteConfig) (Storage, error) { return &testStore{}, nil },
		Compose: func(context.Context, Storage) (HandlerBundle, error) {
			return HandlerBundle{
				HTTP: http.HandlerFunc(noopHandler), MCP: http.HandlerFunc(noopHandler),
				PeerAddress:   "100.78.103.8:8080",
				PeerAdmission: httptransport.NewPeerAdmission(httptransport.PeerAdmissionDependencies{}),
			}, nil
		},
	})
	err := daemon.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "peer listener requires an enabled peer admission") {
		t.Fatalf("Run() error = %v", err)
	}
}

// TestDaemonBindsAndServesThePeerListener is the lifecycle half: a composition
// that supplies a peer address gets a third bound listener serving the same
// guarded HTTP handler, and a composition that supplies none gets two.
//
// The admission decision itself is asserted in internal/transport/http, where a
// request's source address can be set. Over a real socket every test client is
// loopback, so a test here could only ever exercise the pass-through arm.
func TestDaemonBindsAndServesThePeerListener(t *testing.T) {
	t.Parallel()

	peerAddress := reservedAddress(t)
	admission := httptransport.NewPeerAdmission(httptransport.PeerAdmissionDependencies{
		Resolver: fixedResolver{identity: httptransport.PeerIdentity{
			MachineName: "phalls-mac-mini", StableID: "nFJpq2jD1311CNTRL",
		}},
		Allowed: []string{"phalls-mac-mini"},
	})
	handler, err := httptransport.NewPeerHandler(httptransport.PeerDependencies{
		Version: "test", Address: peerAddress, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET "+httptransport.PathLocalPeer, handler)

	bound := make(chan string, 8)
	ready := make(chan struct{})
	daemon, err := NewDaemon(BuildInfo{}, Config{
		Storage: StorageSQLite, SQLitePath: "unused.db",
		HTTPAddress: reservedAddress(t), MCPAddress: reservedAddress(t), ShutdownTimeout: 2 * time.Second,
	}, Dependencies{
		Logger:     slog.New(slog.DiscardHandler),
		OpenSQLite: func(context.Context, sqliteConfig) (Storage, error) { return &testStore{}, nil },
		Listen: func(network, address string) (net.Listener, error) {
			listener, listenErr := net.Listen(network, address)
			if listenErr == nil {
				bound <- listener.Addr().String()
			}
			return listener, listenErr
		},
		Ready: func() { close(ready) },
		Compose: func(context.Context, Storage) (HandlerBundle, error) {
			return HandlerBundle{HTTP: mux, MCP: http.HandlerFunc(noopHandler),
				PeerAddress: peerAddress, PeerAdmission: admission}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	select {
	case <-ready:
	case runErr := <-done:
		t.Fatalf("Run() returned before ready: %v", runErr)
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not become ready")
	}
	if len(bound) != 3 {
		t.Fatalf("bound listeners = %d, want 3", len(bound))
	}

	report := getJSON(t, "http://"+peerAddress+httptransport.PathLocalPeer)
	if report["peering"] != "on" || report["address"] != peerAddress {
		t.Fatalf("peer probe over the peer listener reported %v", report)
	}
	// The probe answered a loopback client, which verified nothing, so it must
	// report no caller rather than invent one.
	if report["caller"] != nil {
		t.Fatalf("peer probe claimed a caller for an unverified client: %v", report["caller"])
	}

	cancel()
	if runErr := <-done; runErr != nil {
		t.Fatalf("Run() error = %v", runErr)
	}
}

func TestDaemonWithoutPeeringBindsOnlyTheTwoLocalListeners(t *testing.T) {
	t.Parallel()

	bound := make(chan string, 8)
	ready := make(chan struct{})
	daemon, err := NewDaemon(BuildInfo{}, Config{
		Storage: StorageSQLite, SQLitePath: "unused.db",
		HTTPAddress: reservedAddress(t), MCPAddress: reservedAddress(t), ShutdownTimeout: 2 * time.Second,
	}, Dependencies{
		Logger:     slog.New(slog.DiscardHandler),
		OpenSQLite: func(context.Context, sqliteConfig) (Storage, error) { return &testStore{}, nil },
		Listen: func(network, address string) (net.Listener, error) {
			listener, listenErr := net.Listen(network, address)
			if listenErr == nil {
				bound <- listener.Addr().String()
			}
			return listener, listenErr
		},
		Ready: func() { close(ready) },
		Compose: func(context.Context, Storage) (HandlerBundle, error) {
			return HandlerBundle{HTTP: http.HandlerFunc(noopHandler), MCP: http.HandlerFunc(noopHandler)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	select {
	case <-ready:
	case runErr := <-done:
		t.Fatalf("Run() returned before ready: %v", runErr)
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not become ready")
	}
	if len(bound) != 2 {
		t.Fatalf("bound listeners = %d, want 2", len(bound))
	}
	cancel()
	if runErr := <-done; runErr != nil {
		t.Fatalf("Run() error = %v", runErr)
	}
}

// reservedAddress returns a loopback address nothing is listening on. The peer
// listener needs a concrete address rather than port zero, because the point of
// the assertion is that the composition's address is the one that gets bound.
func reservedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

type fixedResolver struct {
	identity httptransport.PeerIdentity
}

func (resolver fixedResolver) ResolvePeer(context.Context, string) (httptransport.PeerIdentity, error) {
	return resolver.identity, nil
}

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, response.StatusCode, body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return decoded
}

// TestRunTailscaleSeparatesStreamsAndReportsTheExitStatus exercises the one
// piece of this file that actually forks. It runs a shell rather than the
// tailscale client so it asserts the same thing on every machine, and it is
// here because the stderr/exit split is what whoisFailure classifies on.
func TestRunTailscaleSeparatesStreamsAndReportsTheExitStatus(t *testing.T) {
	t.Parallel()

	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell on this machine")
	}
	stdout, stderr, err := runTailscale(t.Context(), shell, "-c", "printf out; printf err >&2")
	if err != nil {
		t.Fatalf("runTailscale() error = %v", err)
	}
	if string(stdout) != "out" || stderr != "err" {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}

	stdout, stderr, err = runTailscale(t.Context(), shell, "-c", "printf 'peer not found' >&2; exit 1")
	if err == nil {
		t.Fatal("runTailscale() error = nil for a non-zero exit")
	}
	if len(stdout) != 0 || stderr != "peer not found" {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}
	// The classification the guard's log reason is built from.
	if !errors.Is(whoisFailure(stderr, err), httptransport.ErrPeerUnknown) {
		t.Fatalf("whoisFailure() did not classify a peer-not-found exit")
	}
}

// TestEveryPeerReachableRouteIsServedByTheProductionMux is the assertion that
// would have caught a route in the security partition that nobody registered.
//
// The peer cost route was classified peer-reachable, requested by the fleet
// client, and never mounted: the guard admitted the caller, the request fell
// through to the /api/v1/local/ catch-all, and the inner mux answered 404 --
// which the client then reported as "that host is running an older build",
// naming the wrong machine as the problem. Every bound the route existed to
// impose was, in consequence, not in effect anywhere.
//
// The reason the transport package's own route table did not catch it is that
// it is a hand-written list checked against the classifier -- two statements of
// the same intention, agreeing with each other. This one checks the partition
// against the MUX THE DAEMON SERVES, which is the only thing that can disagree.
func TestEveryPeerReachableRouteIsServedByTheProductionMux(t *testing.T) {
	t.Parallel()

	named := func(name string) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(name))
		})
	}
	mux := http.NewServeMux()
	for _, route := range productionHTTPRoutes(named("health"), named("peer"), named("peer-cost"),
		named("peer-mail"), named("admin"), named("local")) {
		mux.Handle(route.pattern, route.handler)
	}
	for _, route := range httptransport.PeerReachableRoutes() {
		method, path, found := strings.Cut(route, " ")
		if !found {
			t.Fatalf("peer route %q names no method", route)
		}
		request := httptest.NewRequest(method, path, nil)
		_, pattern := mux.Handler(request)
		// The pattern has to be the route's own. Matching a prefix pattern
		// instead is exactly the failure this test exists for: it looks served
		// and answers 404.
		if pattern != route {
			t.Errorf("peer-reachable route %q is served by pattern %q, "+
				"so a verified peer reaches a route nobody mounted", route, pattern)
		}
	}
}

// TestProductionMuxServesNoUnclassifiedPeerRoute is the same cross-check in the
// other direction: a pattern registered under the peer path prefix that nobody
// added to the partition would be served to loopback and refused to peers,
// which is safe but silently useless.
func TestProductionMuxServesNoUnclassifiedPeerRoute(t *testing.T) {
	t.Parallel()

	nothing := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	peerRoutes := httptransport.PeerReachableRoutes()
	for _, route := range productionHTTPRoutes(nothing, nothing, nothing, nothing, nothing, nothing) {
		if !strings.Contains(route.pattern, "/peer") {
			continue
		}
		if !slices.Contains(peerRoutes, route.pattern) {
			t.Errorf("the production mux serves %q under the peer prefix, but the partition does not name it",
				route.pattern)
		}
	}
}

// TestAnAbortingCallerCannotPoisonTheRefusalCache closes a denial of service
// built out of the two bounds that prevent one.
//
// One caller's lookup answers for every caller parked behind it, and a refusal
// is remembered briefly. If the lookup inherited the caller's cancellation, a
// client that connected and immediately aborted would cancel the leader's
// lookup, hand its own error to everyone waiting, and leave that address
// refused for the whole negative-cache window -- locking a legitimate peer out
// with one aborted request every few seconds.
func TestAnAbortingCallerCannotPoisonTheRefusalCache(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	probe, _ := stubTailnet(t, func(arguments []string) (string, string, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		return answerFixtures(arguments)
	})
	aborting, abort := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := probe.ResolvePeer(aborting, "100.79.155.27:41234")
		done <- err
	}()
	<-started
	abort()
	<-done

	// The next caller is a different request with a live context, and it must
	// be admitted rather than served the aborted caller's refusal.
	identity, err := probe.ResolvePeer(context.Background(), "100.79.155.27:41234")
	if err != nil {
		t.Fatalf("ResolvePeer() after an aborted caller = %v, want the verified peer", err)
	}
	if identity.MachineName != "phalls-mac-mini" {
		t.Fatalf("identity = %+v", identity)
	}
}

// TestTheRefusalCacheIsBounded keeps a bound from becoming a leak. Entries
// expire logically and nothing walks them, so a caller cycling source addresses
// would grow the map for as long as it kept going.
func TestTheRefusalCacheIsBounded(t *testing.T) {
	t.Parallel()

	probe, _ := stubTailnet(t, func([]string) (string, string, error) {
		return "", "peer not found", errors.New("exit status 1")
	})
	base := time.Now()
	probe.now = func() time.Time { return base }
	for index := range maxRememberedRefusals + 200 {
		address := netip.AddrFrom4([4]byte{100, 64, byte(index / 256), byte(index % 256)})
		if _, err := probe.ResolvePeer(t.Context(), net.JoinHostPort(address.String(), "41234")); err == nil {
			t.Fatal("an unknown caller was admitted")
		}
	}
	probe.mu.Lock()
	remembered := len(probe.refused)
	probe.mu.Unlock()
	if remembered > maxRememberedRefusals {
		t.Fatalf("remembered refusals = %d, want at most %d", remembered, maxRememberedRefusals)
	}
	// Once the entries expire the map makes room again, so the cap is a
	// ceiling rather than a permanent refusal to remember anything.
	base = base.Add(probe.refusalTTL + time.Second)
	if _, err := probe.ResolvePeer(t.Context(), "100.79.155.27:41234"); err == nil {
		t.Fatal("an unknown caller was admitted")
	}
	probe.mu.Lock()
	_, present := probe.refused["100.79.155.27"]
	probe.mu.Unlock()
	if !present {
		t.Fatal("the cap outlived the entries that filled it")
	}
}
