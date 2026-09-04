package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	httptransport "github.com/phall1/blackbird/internal/transport/http"
)

// The daemon consumes Tailscale through its command-line client, and that is a
// decision rather than an expedient.
//
//   - Dependency weight. The tailscale.com module carries the whole node
//     implementation -- the control-plane client, wireguard-go, the netstack,
//     DERP -- into a binary whose job is a local SQLite coordinator. It would
//     be the largest dependency in the tree by an order of magnitude, and every
//     one of its advisories would become this daemon's release problem, for a
//     single string lookup.
//   - The local API is not a stable contract. Reaching tailscaled directly
//     means reimplementing its per-platform discovery: a unix socket on Linux,
//     a port-and-token file on macOS depending on which of the three macOS
//     builds is installed, a named pipe on Windows. Getting that wrong is a
//     security bug, not a cosmetic one, and the CLI already contains the
//     correct version of it for the machine it is running on.
//   - Failure behaviour is what we want. Tailscale absent, tailscaled stopped,
//     or the caller unknown are all non-zero exits with an explanation on
//     stderr. There is no partial-success mode to misread, and nothing to fall
//     back to.
//   - Testability. The whole surface is one exec seam and a JSON parser, both
//     injected, so every assertion below holds identically on a workstation
//     inside this tailnet and on a CI runner that has never heard of it.
//
// The cost is a subprocess per unverified caller. It is bounded three ways, and
// none of them is a cache of a successful answer:
//
//   - the route is classified BEFORE anything is resolved, so an unclassified
//     route cannot be used to spend a process;
//   - concurrent lookups of the same address are coalesced into one process,
//     and the total number of live processes is capped;
//   - a REFUSAL is remembered briefly, so an address the identity service will
//     not vouch for cannot be made to fork per request.
//
// A verified identity is deliberately NOT remembered. It was tried, and it was
// wrong: an admission cached for a TTL keeps admitting after tailscaled dies,
// after the peer's node is deleted, after its key expires and after an ACL
// changes, which is precisely the window an operator revoking access believes
// they have closed. Remembering a refusal has the opposite sign -- it can only
// ever refuse a caller who would otherwise have been refused -- so it is safe
// where remembering an admission is not.
const (
	tailscaleExecutable = "tailscale"
	tailnetProbeTimeout = 3 * time.Second
	// tailnetRefusalTTL bounds how long a refusal is reused. It is short
	// because it also delays recovery once the identity service comes back,
	// and long enough that a flood from one unresolvable source forks once
	// rather than once per request.
	tailnetRefusalTTL = 5 * time.Second
	// tailnetProbeConcurrency caps live `tailscale` processes. An admission
	// decision that cannot be made because the machine is saturated is a
	// refusal, which is the correct direction to fail in.
	tailnetProbeConcurrency = 4
	// maxRememberedRefusals bounds the refusal map. Entries expire logically
	// but nothing walks them, so a caller that cycles source addresses would
	// otherwise grow the map for as long as it kept going. Declining to
	// remember a refusal costs a subprocess and refuses nobody, which is why
	// the cap can simply stop recording rather than needing an eviction policy
	// anyone has to reason about.
	maxRememberedRefusals = 1024
	tailnetRunning        = "Running"
)

// tailnet is the daemon's window onto Tailscale.
type tailnet struct {
	lookPath   func(string) (string, error)
	run        func(ctx context.Context, executable string, arguments ...string) ([]byte, string, error)
	timeout    time.Duration
	refusalTTL time.Duration
	now        func() time.Time
	// slots caps live subprocesses across every caller.
	slots chan struct{}

	mu sync.Mutex
	// inflight coalesces concurrent lookups of the same address. Followers wait
	// on the leader's answer rather than forking their own copy of it.
	inflight map[string]*peerLookup
	// refused remembers a refusal, never an admission.
	refused map[string]refusedPeer
}

// peerLookup is one in-flight resolution. Followers read identity and err only
// after done is closed, which is the happens-before the race detector needs.
type peerLookup struct {
	done     chan struct{}
	identity httptransport.PeerIdentity
	err      error
}

type refusedPeer struct {
	err     error
	expires time.Time
}

func newTailnet() *tailnet {
	return &tailnet{
		lookPath:   exec.LookPath,
		run:        runTailscale,
		timeout:    tailnetProbeTimeout,
		refusalTTL: tailnetRefusalTTL,
		now:        time.Now,
		slots:      make(chan struct{}, tailnetProbeConcurrency),
		inflight:   make(map[string]*peerLookup),
		refused:    make(map[string]refusedPeer),
	}
}

// runTailscale executes the client and returns stdout, stderr, and the exit
// status. Stderr is returned separately because it carries the only usable
// distinction between "this caller is unknown" and "Tailscale is not running",
// and both of those refuse either way.
func runTailscale(ctx context.Context, executable string, arguments ...string) ([]byte, string, error) {
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), strings.TrimSpace(stderr.String()), err
}

func (probe *tailnet) execute(ctx context.Context, arguments ...string) ([]byte, string, error) {
	executable, err := probe.lookPath(tailscaleExecutable)
	if err != nil {
		return nil, "", fmt.Errorf("%w: the tailscale client is not on this daemon's PATH: %w",
			httptransport.ErrPeerUnavailable, err)
	}
	bounded, cancel := context.WithTimeout(ctx, probe.timeout)
	defer cancel()
	stdout, stderr, err := probe.run(bounded, executable, arguments...)
	return stdout, stderr, err
}

// whoisNode is the subset of the client's whois record this daemon reads. It is
// deliberately narrow: every additional field would be one more way for an
// upstream rename to turn verification into a silent refusal.
type whoisNode struct {
	StableID     string `json:"StableID"`
	Name         string `json:"Name"`
	ComputedName string `json:"ComputedName"`
}

type whoisRecord struct {
	Node        *whoisNode `json:"Node"`
	UserProfile *struct {
		LoginName string `json:"LoginName"`
	} `json:"UserProfile"`
}

// ResolvePeer verifies a caller against Tailscale's own identity service.
//
// Every failure is a refusal. There is no branch here that admits a caller
// because its address falls inside 100.64.0.0/10: that range describes where a
// packet claims to come from, and the guard needs to know who sent it.
func (probe *tailnet) ResolvePeer(
	ctx context.Context,
	remoteAddress string,
) (httptransport.PeerIdentity, error) {
	host, port, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return httptransport.PeerIdentity{},
			fmt.Errorf("%w: remote address %q has no host and port", httptransport.ErrPeerMalformed, remoteAddress)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return httptransport.PeerIdentity{},
			fmt.Errorf("%w: remote host %q is not an IP address", httptransport.ErrPeerMalformed, host)
	}
	key := address.Unmap().String()
	return probe.resolveOnce(ctx, key, port)
}

// resolveOnce runs at most one lookup per address at a time. A caller that
// arrives while one is running waits for that answer instead of forking its
// own, which is what keeps an unauthenticated route from turning a burst of
// requests into a burst of processes.
func (probe *tailnet) resolveOnce(
	ctx context.Context,
	key string,
	port string,
) (httptransport.PeerIdentity, error) {
	probe.mu.Lock()
	if entry, present := probe.refused[key]; present && probe.now().Before(entry.expires) {
		probe.mu.Unlock()
		return httptransport.PeerIdentity{}, entry.err
	}
	if leader, running := probe.inflight[key]; running {
		probe.mu.Unlock()
		select {
		case <-leader.done:
			return leader.identity, leader.err
		case <-ctx.Done():
			return httptransport.PeerIdentity{},
				fmt.Errorf("%w: the caller left before its identity was verified: %w",
					httptransport.ErrPeerUnavailable, ctx.Err())
		}
	}
	lookup := &peerLookup{done: make(chan struct{})}
	probe.inflight[key] = lookup
	probe.mu.Unlock()

	lookup.identity, lookup.err = probe.whois(ctx, key, port)

	probe.mu.Lock()
	delete(probe.inflight, key)
	if lookup.err != nil {
		probe.rememberRefusal(key, lookup.err)
	} else {
		// A previously refused address that now verifies must stop being
		// refused immediately; the negative entry is a flood bound, not a
		// decision anybody should have to wait out.
		delete(probe.refused, key)
	}
	probe.mu.Unlock()
	close(lookup.done)
	return lookup.identity, lookup.err
}

// rememberRefusal records a refusal under the map's cap, sweeping what has
// already expired before deciding there is no room. The caller holds the mutex.
func (probe *tailnet) rememberRefusal(key string, err error) {
	now := probe.now()
	if len(probe.refused) >= maxRememberedRefusals {
		for remembered, entry := range probe.refused {
			if !now.Before(entry.expires) {
				delete(probe.refused, remembered)
			}
		}
	}
	if len(probe.refused) >= maxRememberedRefusals {
		// Full of live entries. Not remembering this one costs a subprocess on
		// the next request from the same address and admits nobody.
		return
	}
	probe.refused[key] = refusedPeer{err: err, expires: now.Add(probe.refusalTTL)}
}

// whois is the one place a subprocess is forked for a caller. The slot is taken
// before the fork and bounded by the same deadline the probe itself carries, so
// a saturated machine refuses rather than queues without limit.
//
// The lookup deliberately does NOT inherit the caller's cancellation. One
// caller is answering for every caller parked behind it, and a refusal is
// remembered briefly -- so a client that connects and immediately aborts would
// otherwise cancel the leader's lookup, hand its own error to everyone waiting,
// and leave that address refused for the whole negative-cache window. That is a
// denial of service built out of the two bounds that exist to prevent one. The
// timeout below is what stops the lookup instead, and it is the only thing that
// needs to.
func (probe *tailnet) whois(
	ctx context.Context,
	key string,
	port string,
) (httptransport.PeerIdentity, error) {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), probe.timeout)
	defer cancel()
	select {
	case probe.slots <- struct{}{}:
		defer func() { <-probe.slots }()
	case <-bounded.Done():
		return httptransport.PeerIdentity{},
			fmt.Errorf("%w: this daemon is already resolving as many callers as it will at once",
				httptransport.ErrPeerUnavailable)
	}
	stdout, stderr, err := probe.execute(bounded, "whois", "--json", net.JoinHostPort(key, port))
	if err != nil {
		return httptransport.PeerIdentity{}, whoisFailure(stderr, err)
	}
	var record whoisRecord
	if err := json.Unmarshal(stdout, &record); err != nil {
		return httptransport.PeerIdentity{},
			fmt.Errorf("%w: the whois record could not be decoded: %w", httptransport.ErrPeerMalformed, err)
	}
	if record.Node == nil || strings.TrimSpace(record.Node.StableID) == "" {
		return httptransport.PeerIdentity{},
			fmt.Errorf("%w: the whois record named no node", httptransport.ErrPeerUnknown)
	}
	identity := httptransport.PeerIdentity{
		MachineName: machineName(record.Node),
		StableID:    strings.TrimSpace(record.Node.StableID),
	}
	if record.UserProfile != nil {
		identity.LoginName = strings.TrimSpace(record.UserProfile.LoginName)
	}
	if identity.MachineName == "" {
		return httptransport.PeerIdentity{},
			fmt.Errorf("%w: the whois record named no machine", httptransport.ErrPeerMalformed)
	}
	return identity, nil
}

// whoisFailure classifies a non-zero exit for the log only. "peer not found" is
// the client's own wording for an address it does not recognise; anything else
// -- a stopped tailscaled, a permission error, a timeout -- is reported as the
// service being unavailable, because that is the honest reading of "the client
// ran and would not answer".
func whoisFailure(stderr string, err error) error {
	if strings.Contains(strings.ToLower(stderr), "peer not found") {
		return fmt.Errorf("%w: %s", httptransport.ErrPeerUnknown, stderr)
	}
	if stderr != "" {
		return fmt.Errorf("%w: %s", httptransport.ErrPeerUnavailable, stderr)
	}
	return fmt.Errorf("%w: %w", httptransport.ErrPeerUnavailable, err)
}

// machineName prefers the tailnet's computed name and falls back to the first
// label of the DNS name, which is the same string with the tailnet domain and
// its trailing dot still attached.
func machineName(node *whoisNode) string {
	if computed := strings.TrimSpace(node.ComputedName); computed != "" {
		return computed
	}
	name := strings.TrimSuffix(strings.TrimSpace(node.Name), ".")
	if label, _, found := strings.Cut(name, "."); found {
		return label
	}
	return name
}

// tailnetSelf is what this machine is, on its own tailnet.
//
// The identity half is not decoration. `tailscale whois` answers for THIS
// node's own address exactly as readily as it answers for another node's, and
// a peer address is a local address: a process on this machine that dials the
// peer listener instead of loopback presents a non-loopback source, verifies
// cleanly, and -- under the natural symmetric fleet configuration, where every
// host's allow-list names every host including itself -- is admitted. So the
// guard has to know which identity is its own in order to refuse it.
type tailnetSelf struct {
	StableID    string
	MachineName string
	Addresses   []netip.Addr
}

// Self reports this machine's own tailnet identity and addresses. The addresses
// turn "--peer" into a concrete bind address and refuse an operator-supplied
// address that is not one of them: binding the peer listener anywhere else
// would put these routes on a network Tailscale is not guarding.
func (probe *tailnet) Self(ctx context.Context) (tailnetSelf, error) {
	stdout, stderr, err := probe.execute(ctx, "status", "--json")
	if err != nil {
		if stderr != "" {
			return tailnetSelf{}, fmt.Errorf("%w: %s", httptransport.ErrPeerUnavailable, stderr)
		}
		return tailnetSelf{}, fmt.Errorf("%w: %w", httptransport.ErrPeerUnavailable, err)
	}
	var status struct {
		BackendState string `json:"BackendState"`
		Self         *struct {
			ID           string   `json:"ID"`
			HostName     string   `json:"HostName"`
			DNSName      string   `json:"DNSName"`
			TailscaleIPs []string `json:"TailscaleIPs"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(stdout, &status); err != nil {
		return tailnetSelf{}, fmt.Errorf("%w: the status record could not be decoded: %w",
			httptransport.ErrPeerUnavailable, err)
	}
	if status.BackendState != tailnetRunning {
		return tailnetSelf{}, fmt.Errorf("%w: the tailscale backend is %q rather than %q",
			httptransport.ErrPeerUnavailable, status.BackendState, tailnetRunning)
	}
	if status.Self == nil || len(status.Self.TailscaleIPs) == 0 {
		return tailnetSelf{}, fmt.Errorf("%w: this machine has no tailnet address", httptransport.ErrPeerUnavailable)
	}
	addresses := make([]netip.Addr, 0, len(status.Self.TailscaleIPs))
	for _, text := range status.Self.TailscaleIPs {
		address, parseErr := netip.ParseAddr(text)
		if parseErr != nil {
			return tailnetSelf{}, fmt.Errorf("%w: this machine's address %q could not be parsed",
				httptransport.ErrPeerUnavailable, text)
		}
		addresses = append(addresses, address.Unmap())
	}
	// The machine name is derived the same way a peer's is, from the DNS name's
	// first label, so "is this me?" compares two strings produced by the same
	// rule rather than two spellings of the same node.
	return tailnetSelf{
		StableID:    strings.TrimSpace(status.Self.ID),
		MachineName: machineName(&whoisNode{Name: status.Self.DNSName, ComputedName: ""}),
		Addresses:   addresses,
	}, nil
}

// PeeringConfig is the operator's opt-in to tailnet reachability. The zero
// value is off, which is the only default this daemon will ever ship: a
// local-first tool that starts listening on a network because someone upgraded
// it has broken its promise, however private that network is.
type PeeringConfig struct {
	Enabled bool
	// Address is the tailnet address the peer listener binds. Empty means this
	// machine's own tailnet address on the HTTP port.
	Address string
	// Allowed names the peers admitted, by tailnet machine name or stable node
	// id. It is required when Enabled, and there is no wildcard.
	Allowed []string
}

func (peering PeeringConfig) validate() error {
	if !peering.Enabled {
		// Options without the switch are refused rather than ignored: an
		// operator who wrote them believes peering is on, and a daemon that
		// silently disagrees is the failure this whole feature is guarding.
		if peering.Address != "" || len(peering.Allowed) != 0 {
			return errors.New("peering options were supplied without enabling peering")
		}
		return nil
	}
	if len(peering.named()) == 0 {
		return errors.New("enabling peering requires naming at least one allowed peer")
	}
	if peering.Address != "" {
		if err := validateTCPAddress(peering.Address); err != nil {
			return fmt.Errorf("address: %w", err)
		}
	}
	return nil
}

func (peering PeeringConfig) named() []string {
	names := make([]string, 0, len(peering.Allowed))
	for _, name := range peering.Allowed {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			names = append(names, trimmed)
		}
	}
	return names
}

// peerListenAddress resolves where the peer listener binds, and refuses every
// address that is not one of this machine's own tailnet addresses. Binding
// 0.0.0.0 would put the peer routes on every interface and leave the guard as
// the only thing between them and the internet; one mechanism is not a
// partition.
func peerListenAddress(peering PeeringConfig, httpAddress string, self []netip.Addr) (string, error) {
	if peering.Address == "" {
		_, port, err := net.SplitHostPort(httpAddress)
		if err != nil {
			return "", fmt.Errorf("derive the peer address from the HTTP address %q: %w", httpAddress, err)
		}
		for _, address := range self {
			if address.Is4() {
				return net.JoinHostPort(address.String(), port), nil
			}
		}
		return "", fmt.Errorf("%w: this machine has no IPv4 tailnet address to bind",
			httptransport.ErrPeerUnavailable)
	}
	host, port, err := net.SplitHostPort(peering.Address)
	if err != nil {
		return "", fmt.Errorf("peer address %q: %w", peering.Address, err)
	}
	requested, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("peer address host %q is not an IP address", host)
	}
	requested = requested.Unmap()
	for _, address := range self {
		if address == requested {
			return net.JoinHostPort(requested.String(), port), nil
		}
	}
	return "", fmt.Errorf("peer address %q is not one of this machine's tailnet addresses %s",
		peering.Address, formatAddresses(self))
}

func formatAddresses(addresses []netip.Addr) string {
	texts := make([]string, 0, len(addresses))
	for _, address := range addresses {
		texts = append(texts, address.String())
	}
	return "[" + strings.Join(texts, " ") + "]"
}

// selfReader is the seam the composition root resolves peering through.
type selfReader interface {
	Self(context.Context) (tailnetSelf, error)
}

// composePeering builds the admission policy and the address it is served at.
//
// Peering off composes a disabled admission rather than none, so a non-loopback
// caller is refused by a guard that says why in the log instead of falling
// through to a handler-level check that says nothing about peering.
//
// Peering on and Tailscale missing REFUSES TO START. The operator asked for a
// capability this machine cannot provide, and a daemon that started anyway
// would look peered while admitting nobody -- the failure mode that costs the
// most time to diagnose. Tailscale disappearing later is different and is
// handled differently: the listener stays bound, whois fails, and every peer
// request is refused with tailnet_unavailable until it comes back. That is now
// literally true rather than nearly true -- a verified identity is never
// remembered, so there is no window in which a dead backend keeps admitting
// (see the comment on ResolvePeer's bounds); the only thing remembered across
// requests is a REFUSAL, and briefly.
func composePeering(
	ctx context.Context,
	config Config,
	probe selfReader,
	observer httptransport.PeerObserver,
	logger *slog.Logger,
) (*httptransport.PeerAdmission, string, error) {
	if !config.Peering.Enabled {
		return httptransport.NewPeerAdmission(httptransport.PeerAdmissionDependencies{
			Logger: logger, Metrics: observer}), "", nil
	}
	self, err := probe.Self(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("peering is enabled but this machine's tailnet identity is unreadable: %w", err)
	}
	address, err := peerListenAddress(config.Peering, config.HTTPAddress, self.Addresses)
	if err != nil {
		return nil, "", fmt.Errorf("resolve the peer listen address: %w", err)
	}
	resolver, ok := probe.(httptransport.PeerResolver)
	if !ok {
		return nil, "", errors.New("peering requires a tailnet identity resolver")
	}
	allowed := config.Peering.named()
	admission := httptransport.NewPeerAdmission(httptransport.PeerAdmissionDependencies{
		Resolver: resolver, Allowed: allowed, Logger: logger, Metrics: observer,
		Self: httptransport.PeerIdentity{StableID: self.StableID, MachineName: self.MachineName},
	})
	logger.Info("tailnet peering enabled",
		slog.String("address", address), slog.Any("allowed_peers", allowed),
		slog.String("self_stable_id", self.StableID), slog.String("self_machine_name", self.MachineName))
	return admission, address, nil
}
