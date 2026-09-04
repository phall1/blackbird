package http

import (
	"context"
	"errors"
	"log/slog"
	"net"
	stdhttp "net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/phall1/blackbird/internal/domain"
)

// PathLocalPeer is the peer reachability probe. It answers what this daemon
// believes about peering and echoes back the identity it verified for the
// caller, so an operator can prove the whole path -- listener, tailnet, whois,
// allow-list -- rather than inferring it from a route that also needs an agent
// token.
const PathLocalPeer = "/api/v1/local/peer"

// Reach is how far a route may be reached from.
//
// The zero value is ReachLoopback, and that is the entire point of naming the
// type: a route nobody classified is loopback-only. Forgetting to classify a
// new route cannot widen the surface, it can only fail closed.
type Reach uint8

const (
	// ReachLoopback admits only a connection arriving on this machine's
	// loopback interface. It is the default for every route.
	ReachLoopback Reach = iota
	// ReachPeer additionally admits a caller whose tailnet identity this daemon
	// verified and whose machine an operator named. It never replaces the
	// route's own authentication; it is admission on top of it.
	ReachPeer
)

func (reach Reach) String() string {
	if reach == ReachPeer {
		return "peer"
	}
	return "loopback"
}

// peerReachableRoutes is the ENTIRE non-loopback surface of this daemon. It is
// a list rather than a property spread across handlers so that a reviewer reads
// the partition in one place, and so that widening it is a diff nobody can miss.
//
// What is absent from this list carries more weight than what is present:
//
//   - Every reservation mutation -- acquire, renew, release, force-release.
//     Claims never cross a host boundary, because the resource a lease protects
//     is a path on one machine's disk: a lease on a file in this checkout says
//     nothing about the same relative path in a different checkout on a
//     different disk, so a remote holder could only ever be wrong. Agent-facing
//     lease mutation lives on the MCP listener, which peering never binds, and
//     the operator's force-release lives under the admin prefix below; neither
//     is reachable from a peer by two independent mechanisms.
//   - Agent registration and telemetry ingest. Both are writes into this
//     daemon's own authority, and both are performed by processes on this
//     machine. Telemetry crosses hosts read-only, in the direction of a union;
//     nothing about that requires accepting a write from another host.
//   - The coordination event feed and its consumer acknowledgement. The feed
//     carries reservation events, and the acknowledgement moves a durable
//     cursor. Neither is mail.
//   - Every admin route. Peer identity authenticates a machine; it is not admin
//     authorization, and a peer must not acquire the operator surface by being
//     on the tailnet. The admin token stays exactly as it was, and the route
//     stays loopback-only besides.
//   - The agent-facing cost and spend rollups. What crosses is the OPERATOR's
//     projection at PathLocalPeerCost, which names its project explicitly and
//     carries no agent credential; the agent's own report is confined to the
//     workspace its registration token authenticated into, and a peer holds no
//     such token. One projection, two credentials, and the peer never acquires
//     the agent's.
//   - The agent-facing message read. It was on this list once and it was wrong
//     twice over. It authenticates with a LOCAL agent's registration token,
//     which no peer holds and no route issues, so the crossing it promised was
//     unreachable; and the only way to make it work would be copying an agent
//     token between hosts, where it is a bearer credential for this daemon's
//     ENTIRE local API rather than for mail. Meanwhile listing it moved token
//     guessing against that credential from a loopback-only surface to every
//     allowed peer. Mail crosses at PathLocalPeerMail, whose credential is a
//     verified machine rather than a copied agent token.
//
// What IS present here beyond the probes is the two crossings the model allows:
// telemetry read-only, in the direction of a union, and mail, which is
// append-only and leaves each host authoritative for its own mailbox.
//
// PathLocalPeerMail is the only WRITE on this list, and it is the only write
// that could be: it appends a message to a mailbox this host resolves,
// addresses and mints every identifier for. See peermail.go for the four
// properties that keep it from being a replication protocol.
var peerReachableRoutes = []string{
	"GET " + PathHealth,
	"GET " + PathReady,
	"GET " + PathLocalPeer,
	"GET " + PathLocalPeerCost,
	"POST " + PathLocalPeerMail,
}

// LoopbackOnly refuses every non-loopback caller, unconditionally.
//
// It exists for the MCP listener, and the reason is the load-bearing half of
// the whole partition. Every agent-facing lease mutation -- acquire, renew,
// release -- is an MCP tool, and the argument that a peer cannot reach one
// rested entirely on MCP being bound to loopback by convention. A convention is
// one mechanism, and it is one an operator revokes with a flag: `--mcp-address
// 0.0.0.0:8081` published every tool on every interface, authenticated only by
// an agent bearer token in the body, with no loopback check anywhere in the
// path. The address validator checked host:port syntax and nothing else.
//
// So the second mechanism lives here, at the request rather than at the bind:
// whatever address the MCP listener ends up on, a caller that did not arrive
// over loopback is refused before the SDK handler sees a byte. This is
// deliberately NOT the peer guard -- there is no peer identity that makes lease
// mutation acceptable across hosts, because the resource a lease protects is a
// path on one machine's disk.
func LoopbackOnly(next stdhttp.Handler) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		if !loopbackRequest(request) {
			writeLocalProblem(writer, stdhttp.StatusForbidden, domain.ErrorCodeForbidden,
				"this listener serves only loopback connections")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// peerRouteMarker marks a pattern in the classifier. It is a named type rather
// than a function so the classification is a type assertion: a redirect handler
// that net/http substitutes for an unclean path is not this type, and so
// classifies as loopback.
type peerRouteMarker struct{}

func (peerRouteMarker) ServeHTTP(stdhttp.ResponseWriter, *stdhttp.Request) {}

// peerRouteClassifier routes with net/http's own pattern semantics rather than
// a hand-written prefix match, because a partition that disagrees with the mux
// it guards is a partition that is wrong somewhere nobody looks. Method is part
// of a pattern, so a POST to a path whose GET is peer-reachable classifies as
// loopback without anyone having to remember to say so.
var peerRouteClassifier = sync.OnceValue(func() *stdhttp.ServeMux {
	mux := stdhttp.NewServeMux()
	for _, route := range peerReachableRoutes {
		mux.Handle(route, peerRouteMarker{})
	}
	return mux
})

// RouteReach reports how far the route that would serve this request may be
// reached from.
func RouteReach(request *stdhttp.Request) Reach {
	handler, pattern := peerRouteClassifier().Handler(request)
	if pattern == "" {
		return ReachLoopback
	}
	if _, marked := handler.(peerRouteMarker); !marked {
		return ReachLoopback
	}
	return ReachPeer
}

// PeerReachableRoutes returns the classified routes. It exists so a test can
// assert the partition against the routes the daemon actually serves.
func PeerReachableRoutes() []string {
	return append([]string(nil), peerReachableRoutes...)
}

// PeerIdentity is a caller's VERIFIED tailnet identity. Every field is a fact
// the identity service returned; nothing here is derived from the source
// address, because an address is not a credential.
type PeerIdentity struct {
	// MachineName is the tailnet's name for the node, e.g. "phalls-mac-mini".
	MachineName string
	// StableID is the node's stable identifier. It survives a rename, which
	// makes it the durable half of an allow-list entry.
	StableID string
	// LoginName is the tailnet user that owns the node, when the identity
	// service reported one. It is logged, never used to decide admission.
	LoginName string
}

// The refusal reasons a PeerResolver may report. Every one of them refuses;
// they differ only in what an operator reading the log is told to go fix.
var (
	// ErrPeerUnavailable reports that the identity service could not be
	// consulted at all -- Tailscale is not installed, or its daemon is not
	// running. This is the state a running daemon enters if Tailscale goes away
	// underneath it: the peer listener stays bound and admits nobody.
	ErrPeerUnavailable = errors.New("tailnet identity service is unavailable")
	// ErrPeerUnknown reports that the identity service answered and did not
	// recognise the caller.
	ErrPeerUnknown = errors.New("caller is not a recognised tailnet peer")
	// ErrPeerMalformed reports an answer this daemon could not read, or a
	// remote address it could not parse.
	ErrPeerMalformed = errors.New("tailnet identity is malformed")
)

// PeerResolver turns a caller's remote address into a verified tailnet
// identity. It is an interface so that no test needs a tailnet to exist, and so
// that the daemon's only dependency on Tailscale is one injected seam in the
// composition root rather than an import in the transport layer.
//
// An implementation MUST fail rather than guess. Returning a synthesised
// identity for an address that merely looks like a tailnet address would make
// the guard decorative.
type PeerResolver interface {
	ResolvePeer(ctx context.Context, remoteAddress string) (PeerIdentity, error)
}

// peerAdmissionKey carries the verified identity from the guard to the routes,
// so a handler can report who it is serving without resolving anything itself.
type peerAdmissionKey struct{}

// Peer returns the verified tailnet identity that admitted this request. A
// loopback request carries none, and the absence is the honest answer: nothing
// was verified, so nothing may be reported.
func Peer(request *stdhttp.Request) (PeerIdentity, bool) {
	identity, ok := request.Context().Value(peerAdmissionKey{}).(PeerIdentity)
	return identity, ok
}

// PeerAdmissionDependencies configures the non-loopback admission policy.
type PeerAdmissionDependencies struct {
	// Resolver verifies a caller. A nil Resolver is peering switched off: every
	// non-loopback request is refused, and the refusal is logged as such rather
	// than left to look like a routing accident.
	Resolver PeerResolver
	// Allowed names the peers this daemon admits, by tailnet machine name or
	// stable node id, compared case-insensitively. An empty set admits nobody.
	// There is deliberately no wildcard: "every node in the tailnet" is a
	// decision that should cost an operator one line per machine.
	//
	// The STABLE NODE ID is the form to prefer, and the difference is not
	// cosmetic. A machine name is derived from a hostname the node's own owner
	// chooses, so it is an identifier the named party controls; a stable id is
	// assigned by the control plane and survives a rename. Tailscale dedups
	// names within a tailnet, so a live collision cannot be manufactured, but
	// "the identifier is unforgeable" and "the coordinator currently prevents
	// duplicates" are different guarantees and only one of them is this
	// daemon's to rely on. Machine names stay supported because they are what
	// an operator can read off `tailscale status`.
	Allowed []string
	// Self is this machine's own verified identity, and naming it is what stops
	// a local process from becoming a peer. A connection to the peer listener
	// from this host presents a tailnet source address rather than a loopback
	// one, and `tailscale whois` answers for it as readily as for any other
	// node -- so under the natural symmetric fleet configuration, where every
	// host's allow-list names every host, every local process would otherwise
	// hold a credential the operator believes belongs to other machines.
	//
	// A zero Self disables the check rather than failing closed, because the
	// only composer that can supply it is the one that read it from Tailscale,
	// and a test constructing an admission directly is not a machine that can
	// call itself.
	Self PeerIdentity
	// Logger receives one record per refusal, with the reason and whatever
	// identity was actually verified. A nil Logger is silent rather than a
	// composition error.
	Logger *slog.Logger
	// Metrics counts admissions and refusals. Without it a refusal is visible
	// only in the log: the guard runs OUTSIDE the metrics wrapper by
	// construction -- it has to, since a refused request never reaches the mux
	// the wrapper is measuring -- so an attack against the peer listener would
	// leave every counter flat. A nil Metrics counts nothing.
	Metrics PeerObserver
}

// PeerObserver counts admission decisions. It is the narrow half of the metrics
// registry, declared here so the guard depends on a verb rather than on a type.
type PeerObserver interface {
	ObserveRequest(operation, outcome string)
}

// PeerAdmission is the process's single admission point for non-loopback
// callers.
type PeerAdmission struct {
	resolver PeerResolver
	allowed  map[string]struct{}
	self     PeerIdentity
	logger   *slog.Logger
	metrics  PeerObserver
}

// peerAdmissionMetric is the bounded operation label for admission decisions.
// The outcome is always a refusal reason from the fixed set below or
// "admitted", so nothing a caller controls becomes a label.
const peerAdmissionMetric = "peer admission"

// NewPeerAdmission builds the admission policy. It never fails: a policy with
// no resolver and no allowed peers is the correct, fully closed default, and a
// daemon that nobody configured composes exactly that.
func NewPeerAdmission(dependencies PeerAdmissionDependencies) *PeerAdmission {
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	admission := &PeerAdmission{logger: logger, self: dependencies.Self,
		allowed: make(map[string]struct{}, len(dependencies.Allowed))}
	if !isNil(dependencies.Resolver) {
		admission.resolver = dependencies.Resolver
	}
	if !isNil(dependencies.Metrics) {
		admission.metrics = dependencies.Metrics
	}
	for _, name := range dependencies.Allowed {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			admission.allowed[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	return admission
}

// Enabled reports whether any non-loopback caller could be admitted. Both
// halves are required: a resolver with an empty allow-list verifies callers it
// then refuses, and an allow-list with no resolver names peers it cannot
// verify. Neither is peering.
func (admission *PeerAdmission) Enabled() bool {
	return admission != nil && admission.resolver != nil && len(admission.allowed) > 0
}

// Guard is the middleware that admits or refuses every request. It wraps the
// whole HTTP ingress rather than individual handlers, which is what makes the
// route table above the only place the partition is decided.
//
// A loopback request passes through untouched and carries no identity. Every
// other request must clear three gates in this order: peering is on, the route
// is classified peer-reachable, and the caller's identity verifies to a named
// peer. Classification runs before resolution on purpose -- resolving costs a
// subprocess, and an unclassified route must not become a way to spend one.
func (admission *PeerAdmission) Guard(next stdhttp.Handler) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		if loopbackRequest(request) {
			next.ServeHTTP(writer, request)
			return
		}
		identity, ok := admission.admit(writer, request)
		if !ok {
			return
		}
		admission.observe("admitted")
		admission.logger.Debug("peer admitted",
			slog.String("machine_name", identity.MachineName), slog.String("stable_id", identity.StableID),
			slog.String("method", request.Method), slog.String("path", request.URL.Path))
		next.ServeHTTP(writer, request.WithContext(
			context.WithValue(request.Context(), peerAdmissionKey{}, identity)))
	})
}

func (admission *PeerAdmission) admit(
	writer stdhttp.ResponseWriter,
	request *stdhttp.Request,
) (PeerIdentity, bool) {
	if admission.resolver == nil {
		admission.refuse(writer, request, "peering_disabled", PeerIdentity{}, nil)
		return PeerIdentity{}, false
	}
	if RouteReach(request) != ReachPeer {
		admission.refuse(writer, request, "route_is_loopback_only", PeerIdentity{}, nil)
		return PeerIdentity{}, false
	}
	if !tailnetHost(request.Host) {
		admission.refuse(writer, request, "host_is_not_a_tailnet_name", PeerIdentity{}, nil)
		return PeerIdentity{}, false
	}
	if browserOriginated(request) {
		admission.refuse(writer, request, "caller_is_a_browser", PeerIdentity{}, nil)
		return PeerIdentity{}, false
	}
	identity, err := admission.resolver.ResolvePeer(request.Context(), request.RemoteAddr)
	if err != nil {
		admission.refuse(writer, request, peerRefusalReason(err), PeerIdentity{}, err)
		return PeerIdentity{}, false
	}
	if identity.MachineName == "" || identity.StableID == "" {
		admission.refuse(writer, request, "identity_incomplete", identity, nil)
		return PeerIdentity{}, false
	}
	if admission.isSelf(identity) {
		admission.refuse(writer, request, "peer_is_this_machine", identity, nil)
		return PeerIdentity{}, false
	}
	if !admission.allows(identity) {
		admission.refuse(writer, request, "peer_not_allowed", identity, nil)
		return PeerIdentity{}, false
	}
	return identity, true
}

// isSelf refuses this machine calling its own peer listener.
//
// It is checked BEFORE the allow-list, and separately from it, for two
// reasons. Dropping self from the allow-list at composition time would leave
// the hole open for an operator who names this host under its other spelling,
// and it would report the refusal as "peer_not_allowed" -- which sends whoever
// reads the log to edit a list that is already correct. This is not a peer that
// was not named; it is a caller that is not a peer at all.
func (admission *PeerAdmission) isSelf(identity PeerIdentity) bool {
	if admission.self.StableID != "" &&
		strings.EqualFold(admission.self.StableID, identity.StableID) {
		return true
	}
	return admission.self.MachineName != "" &&
		strings.EqualFold(admission.self.MachineName, identity.MachineName)
}

func (admission *PeerAdmission) allows(identity PeerIdentity) bool {
	if _, named := admission.allowed[strings.ToLower(identity.StableID)]; named {
		return true
	}
	_, named := admission.allowed[strings.ToLower(identity.MachineName)]
	return named
}

func (admission *PeerAdmission) observe(outcome string) {
	if admission.metrics != nil {
		admission.metrics.ObserveRequest(peerAdmissionMetric, outcome)
	}
}

// browserOriginated refuses a request a web browser made.
//
// Nothing on the peer surface is for a browser: the only client is this
// product's own Go client, which sends neither header. A browser running on an
// allowed peer, pointed by a hostile page at this daemon's MagicDNS name, would
// otherwise clear every gate the guard has -- the Host header is a real tailnet
// name and the source address is a real allowed machine -- because the guard
// authenticates the MACHINE and a browser is a confused deputy on it. The Host
// filter alone cannot see that, since the attacker's page does not have to
// choose the Host header for a cross-origin request to carry one this daemon
// accepts.
//
// This is a refusal filter and not a credential: a caller that omits both
// headers still has to verify. It costs nothing to non-browser clients, and it
// stops being a theoretical concern the first time a route on this list is
// reachable without a header a browser will not attach.
func browserOriginated(request *stdhttp.Request) bool {
	return request.Header.Get("Origin") != "" ||
		request.Header.Get("Sec-Fetch-Site") != "" ||
		request.Header.Get("Sec-Fetch-Mode") != ""
}

// refuse records the rejection before the caller receives it. The identity
// fields are whatever was actually verified -- empty when nothing was, because
// a source address is a claim about routing and not a claim about who is
// calling, and writing one into a machine_name field would be inventing a fact.
func (admission *PeerAdmission) refuse(
	writer stdhttp.ResponseWriter,
	request *stdhttp.Request,
	reason string,
	identity PeerIdentity,
	cause error,
) {
	attributes := []any{
		slog.String("reason", reason),
		slog.String("request_id", inboundRequestID(request)),
		slog.String("remote_address", request.RemoteAddr),
		slog.String("method", request.Method),
		slog.String("path", request.URL.Path),
		slog.String("machine_name", identity.MachineName),
		slog.String("stable_id", identity.StableID),
		slog.String("login_name", identity.LoginName),
	}
	if cause != nil {
		attributes = append(attributes, slog.Any("error", cause))
	}
	admission.observe(reason)
	admission.logger.Warn("peer request refused", attributes...)
	writeLocalProblem(writer, stdhttp.StatusForbidden, domain.ErrorCodeForbidden,
		"this route is reachable only from a loopback connection")
}

// tailnetHost is a REFUSAL filter on the Host header, and it is emphatically
// not a credential: nothing here admits anybody, and a caller that clears it
// still has to verify. It exists because the loopback path validates Host as
// DNS-rebinding protection and the peer path would otherwise validate none at
// all, which would let a browser on an allowed peer be pointed at this daemon
// through an attacker's domain. A tailnet caller addresses this daemon by its
// tailnet address or its MagicDNS name; anything else is somebody else's idea
// of where this daemon lives.
func tailnetHost(host string) bool {
	name := host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		name = parsed
	} else if strings.Count(host, ":") == 1 {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if strings.HasSuffix(name, ".ts.net") {
		return true
	}
	address, err := netip.ParseAddr(strings.Trim(name, "[]"))
	if err != nil {
		return false
	}
	address = address.Unmap()
	// 100.64.0.0/10 is Tailscale's IPv4 range and fd7a:115c:a1e0::/48 its IPv6
	// range. Both are the addresses this daemon can be ADDRESSED at, never a
	// statement about where a packet came from.
	return tailnetIPv4.Contains(address) || tailnetIPv6.Contains(address)
}

var (
	tailnetIPv4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetIPv6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// peerRefusalReason names the cause for the log. It never changes the decision:
// every branch here has already refused.
func peerRefusalReason(err error) string {
	switch {
	case errors.Is(err, ErrPeerUnknown):
		return "peer_unknown"
	case errors.Is(err, ErrPeerMalformed):
		return "identity_malformed"
	case errors.Is(err, ErrPeerUnavailable):
		return "tailnet_unavailable"
	default:
		return "identity_unverified"
	}
}

// PeerDependencies configures the peer reachability probe.
type PeerDependencies struct {
	Version string
	// Address is where this daemon accepts peer connections, empty when it
	// accepts none.
	Address string
	Enabled bool
}

type peerHandler struct {
	version string
	address string
	enabled bool
}

type localPeerCaller struct {
	MachineName string `json:"machine_name"`
	StableID    string `json:"stable_id"`
	LoginName   string `json:"login_name,omitempty"`
}

type localPeerReport struct {
	Peering string `json:"peering"`
	Address string `json:"address,omitempty"`
	Version string `json:"version"`
	// Caller is absent for a loopback request. There is no verified identity to
	// report there, and reporting the source address in its place would be a
	// fabricated fact in the one response an operator reads to decide whether
	// verification works at all.
	Caller *localPeerCaller `json:"caller,omitempty"`
}

// NewPeerHandler serves GET /api/v1/local/peer. It is behind the same loopback
// guard as every other route and is classified peer-reachable, so it answers
// both the operator on this machine and a verified peer -- which is what makes
// it useful for telling those two cases apart.
func NewPeerHandler(dependencies PeerDependencies) (stdhttp.Handler, error) {
	if dependencies.Enabled && dependencies.Address == "" {
		return nil, errors.New("peer HTTP transport requires the address peering is served at")
	}
	handler := &peerHandler{version: dependencies.Version,
		address: dependencies.Address, enabled: dependencies.Enabled}
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("GET "+PathLocalPeer, handler.describe)
	return localSafety(mux), nil
}

func (handler *peerHandler) describe(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if len(request.URL.Query()) != 0 {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "query parameters are invalid")
		return
	}
	report := localPeerReport{Peering: "off", Version: handler.version}
	if handler.enabled {
		report.Peering = "on"
		report.Address = handler.address
	}
	if identity, verified := Peer(request); verified {
		report.Caller = &localPeerCaller{MachineName: identity.MachineName,
			StableID: identity.StableID, LoginName: identity.LoginName}
	}
	writeLocalJSON(writer, stdhttp.StatusOK, report)
}
