package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/adminapi"
)

// The outbound half of the fleet view.
//
// It talks to a peer daemon's peer cost route and to nothing else, and it
// carries NO CREDENTIAL OF THIS MACHINE. That is the property worth protecting
// here: the admin token authenticates an operator to the daemon on this
// machine, it is minted per start, and it must never leave the host. A peer
// authenticates this caller the only way the model allows -- by asking its own
// tailnet who is calling -- so there is nothing for this client to present and
// nothing for a hostile endpoint to capture by pretending to be a peer.
//
// Everything about a remote call is bounded, because the remote side is a
// machine this process does not control:
//
//   - a per-peer deadline, so one unresponsive host cannot hang the report;
//   - a response size cap, so a host answering with an endless body cannot
//     exhaust this process's memory;
//   - a redirect refusal, so a peer cannot bounce this client at an address the
//     operator never named;
//   - and, in the caller, a bounded fan-out over the peers.

const (
	peerCostPath = "/api/v1/local/peer/cost"
	// peerCostTimeout bounds one peer's whole answer, connection included. A
	// fleet report is an interactive command, so a host that cannot answer in
	// this long is more useful reported as silent than waited for.
	peerCostTimeout = 10 * time.Second
	// peerCostMaxResponse caps a peer's body. A cost report is a few kilobytes
	// at the largest page size this daemon serves; the cap is far above that
	// and still finite.
	peerCostMaxResponse = 4 << 20
)

// PeerCostPort reads one peer daemon's cost report. It is a port so a test can
// answer for a fleet of hosts without a tailnet, and so the command grammar
// keeps depending on nothing but the standard library and adminapi.
type PeerCostPort interface {
	PeerCost(ctx context.Context, endpoint string, query CostQuery) (adminapi.CostReport, error)
}

// peerCostClient is the default PeerCostPort.
type peerCostClient struct {
	HTTP    *http.Client
	Timeout time.Duration
}

func newPeerCostClient() *peerCostClient {
	return &peerCostClient{Timeout: peerCostTimeout, HTTP: &http.Client{
		// A peer that answers with a redirect is answering a question nobody
		// asked. Following it would send this query to a host the operator did
		// not name, which is the one thing an explicit peer list exists to stop.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("a peer must answer directly rather than redirect")
		},
	}}
}

// PeerCost reads one peer's report. Every failure is returned rather than
// swallowed: the caller renders it beside the host that produced it, because a
// host that did not answer has to be visible in the report.
func (client *peerCostClient) PeerCost(ctx context.Context, endpoint string,
	query CostQuery) (adminapi.CostReport, error) {
	address, err := peerDialAddress(endpoint)
	if err != nil {
		return adminapi.CostReport{}, err
	}
	timeout := client.Timeout
	if timeout <= 0 {
		timeout = peerCostTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	values := url.Values{}
	values.Set("project_key", query.ProjectKey)
	if query.SinceHours > 0 {
		values.Set("since_hours", strconv.Itoa(query.SinceHours))
	}
	if query.Limit > 0 {
		values.Set("limit", strconv.Itoa(query.Limit))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+address+peerCostPath+"?"+values.Encode(), nil)
	if err != nil {
		return adminapi.CostReport{}, fmt.Errorf("build peer request: %w", err)
	}
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return adminapi.CostReport{}, fmt.Errorf("contact peer at %s: %w", address, err)
	}
	defer func() { _ = response.Body.Close() }()

	body := io.LimitReader(response.Body, peerCostMaxResponse)
	if response.StatusCode != http.StatusOK {
		return adminapi.CostReport{}, peerStatusError(address, response.StatusCode, body)
	}
	var report adminapi.CostReport
	if err := json.NewDecoder(body).Decode(&report); err != nil {
		return adminapi.CostReport{}, fmt.Errorf("decode the report from %s: %w", address, err)
	}
	return sanitizePeerReport(report), nil
}

// Everything a peer says is rendered into an interactive terminal, and a
// terminal is an INTERPRETER. Before the fleet view every string this command
// printed came from the daemon on this machine; a peer report is the first
// text a different host chooses. A model name of "\x1b[2J\x1b]52;c;...\x07" is a
// screen wipe and a clipboard write, and the screen it wipes is the one
// carrying the "did not answer" warnings the fleet view exists to show.
//
// So peer-sourced text is sanitized HERE, at the boundary where it stops being
// somebody else's JSON, rather than in the renderer. The renderer's job is
// layout, it is shared with locally sourced text that has never needed this,
// and a filter placed there would be one refactor away from being bypassed by
// a new call site. --json output is unaffected either way, because Go escapes
// control characters when it encodes; it is the human path that interprets.
func sanitizePeerReport(report adminapi.CostReport) adminapi.CostReport {
	report.ProjectKey = sanitizePeerText(report.ProjectKey)
	report.Since = sanitizePeerText(report.Since)
	report.Until = sanitizePeerText(report.Until)
	for index, note := range report.Unobserved {
		report.Unobserved[index] = sanitizePeerText(note)
	}
	if report.Contention != nil {
		for index := range report.Contention.Agents {
			agent := &report.Contention.Agents[index]
			agent.AgentName = sanitizePeerText(agent.AgentName)
			agent.ActorID = sanitizePeerText(agent.ActorID)
		}
		for index := range report.Contention.Paths {
			path := &report.Contention.Paths[index]
			path.Path = sanitizePeerText(path.Path)
			path.Kind = sanitizePeerText(path.Kind)
		}
	}
	if report.Abandonment != nil {
		for index := range report.Abandonment.Leases {
			lease := &report.Abandonment.Leases[index]
			lease.LeaseID = sanitizePeerText(lease.LeaseID)
			lease.HolderAgent = sanitizePeerText(lease.HolderAgent)
			lease.Mode = sanitizePeerText(lease.Mode)
			lease.ContendedPath = sanitizePeerText(lease.ContendedPath)
		}
	}
	if report.Cache != nil {
		for index := range report.Cache.Models {
			report.Cache.Models[index].Model = sanitizePeerText(report.Cache.Models[index].Model)
		}
	}
	return report
}

// sanitizePeerText drops every C0 and C1 control character, which is the whole
// of the escape vocabulary: an ANSI sequence needs ESC (or the C1 CSI/OSC
// bytes) to start, and without one the remainder is inert punctuation. It
// deletes rather than replaces so a name that was always printable is
// untouched, and it keeps the string valid UTF-8 by working over runes.
func sanitizePeerText(text string) string {
	if strings.IndexFunc(text, unprintablePeerRune) < 0 {
		return text
	}
	return strings.Map(func(character rune) rune {
		if unprintablePeerRune(character) {
			return -1
		}
		return character
	}, text)
}

func unprintablePeerRune(character rune) bool {
	// U+0080..U+009F are the C1 controls, which a terminal in 8-bit mode reads
	// as CSI, OSC and friends without any ESC in front of them.
	return character < 0x20 || (character >= 0x7f && character <= 0x9f)
}

// peerStatusError translates the refusals a peer can give into words that name
// what the operator has to change, because every one of them is a different
// job: a machine to add to an allow-list, a daemon to start peering on, a
// project key that does not exist over there, or simply a busy host.
func peerStatusError(address string, status int, body io.Reader) error {
	detail := problemMessage(body)
	switch status {
	case http.StatusForbidden:
		return fmt.Errorf("%s refused this machine: it is not on that host's allowed-peer list, "+
			"or that host is not serving peers (%s)", address, detail)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("%s could not answer right now: %s", address, detail)
	case http.StatusNotFound:
		return fmt.Errorf("%s serves no peer cost route: it is running a build from before fleet cost (%s)",
			address, detail)
	case http.StatusBadRequest:
		return fmt.Errorf("%s rejected the query: %s", address, detail)
	default:
		return fmt.Errorf("%s answered %d: %s", address, status, detail)
	}
}

func problemMessage(body io.Reader) string {
	var problem struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(body).Decode(&problem); err != nil || problem.Message == "" {
		return "no detail"
	}
	if problem.Code == "" {
		return sanitizePeerText(problem.Message)
	}
	return sanitizePeerText(problem.Code + ": " + problem.Message)
}

// peerEndpoints normalizes every value the operator typed, BEFORE anything is
// dialled. A fleet report that half ran and then failed on a typo would leave
// an operator unsure whether the hosts it did reach were the ones they meant.
func peerEndpoints(peers []string) ([]string, error) {
	endpoints := make([]string, 0, len(peers))
	for _, peer := range peers {
		endpoint, err := peerEndpoint(peer)
		if err != nil {
			return nil, err
		}
		if slices.Contains(endpoints, endpoint) {
			// Two spellings of one host would put that host in the fleet twice
			// and double its spend in the union, which is the same defect as
			// dropping one silently, pointing the other way.
			return nil, usageFault("--peer names %s twice", endpoint)
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

// peerEndpoint is peerDialAddress plus the one refusal that belongs to the
// FLAG rather than to the transport: a loopback "peer" is this machine, the
// peer route on this machine refuses loopback callers by design, and an
// operator who typed one is asking for a fleet of one host counted twice.
//
// The split matters because the client must stay dialable at any address a
// test or a future caller hands it, while the flag has an opinion about which
// addresses are a mistake.
func peerEndpoint(endpoint string) (string, error) {
	address, err := peerDialAddress(endpoint)
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", usageFault("--peer must be HOST or HOST:PORT; got %q", endpoint)
	}
	if peerLoopback(host) {
		return "", usageFault("--peer names this machine (%q); a fleet report already includes this host", endpoint)
	}
	return address, nil
}

// peerDialAddress turns HOST, HOST:PORT or http://HOST:PORT into HOST:PORT.
func peerDialAddress(endpoint string) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", usageFault("--peer must name a host")
	}
	if scheme, rest, found := strings.Cut(trimmed, "://"); found {
		if !strings.EqualFold(scheme, "http") {
			return "", usageFault("--peer speaks plain HTTP over the tailnet, so %q is not supported; "+
				"the tailnet is the encrypted channel", scheme)
		}
		trimmed = strings.TrimSuffix(rest, "/")
	}
	if strings.ContainsAny(trimmed, "/?#") {
		return "", usageFault("--peer must be HOST or HOST:PORT with no path; got %q", endpoint)
	}
	host, port := trimmed, ""
	if parsed, parsedPort, err := net.SplitHostPort(trimmed); err == nil {
		host, port = parsed, parsedPort
	} else if strings.Count(trimmed, ":") > 1 && !strings.HasPrefix(trimmed, "[") {
		// A bare IPv6 literal. Bracket it so the default port can be attached.
		if address, addrErr := netip.ParseAddr(trimmed); addrErr == nil {
			host = address.String()
		}
	}
	if host == "" {
		return "", usageFault("--peer must name a host; got %q", endpoint)
	}
	if port == "" {
		port = defaultPeerPort()
	}
	return net.JoinHostPort(host, port), nil
}

func peerLoopback(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	address, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	return err == nil && address.IsLoopback()
}

// defaultPeerPort is derived from the address the installed service listens on
// rather than written out, so the two cannot drift apart.
func defaultPeerPort() string {
	if _, port, err := net.SplitHostPort(defaultHTTPAddress); err == nil {
		return port
	}
	return "8080"
}
