package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	peerRemoteAddress = "100.79.155.27:41234"
	peerHostHeader    = "100.78.103.8:8080"
)

// stubResolver is the injected identity seam. Every assertion in this file runs
// identically on a workstation inside a tailnet and on a CI runner that has
// never seen one, which is the entire reason PeerResolver is an interface.
type stubResolver struct {
	identity PeerIdentity
	err      error
	calls    int
}

func (resolver *stubResolver) ResolvePeer(context.Context, string) (PeerIdentity, error) {
	resolver.calls++
	if resolver.err != nil {
		return PeerIdentity{}, resolver.err
	}
	return resolver.identity, nil
}

func theMini() PeerIdentity {
	return PeerIdentity{MachineName: "phalls-mac-mini", StableID: "nFJpq2jD1311CNTRL", LoginName: "owner@example.com"}
}

// servedRoute is one route the production HTTP mux registers, paired with the
// reach it is meant to have. The table is the review surface: it states, route
// by route, what this daemon exposes to a tailnet peer.
type servedRoute struct {
	method string
	path   string
	reach  Reach
}

// servedRoutes states, route by route, what this daemon exposes to a peer.
//
// It is a hand-written table checked against the classifier, so it can only
// ever catch a partition that disagrees with what a REVIEWER expected -- it
// cannot catch a partition that disagrees with the mux. It did not catch the
// peer cost route being classified peer-reachable and mounted by nobody,
// because it agreed with the classifier about it. That cross-check lives where
// the mux is built, in internal/runtime: see
// TestEveryPeerReachableRouteIsServedByTheProductionMux. Both are needed and
// neither replaces the other.
func servedRoutes() []servedRoute {
	return []servedRoute{
		{stdhttp.MethodGet, PathHealth, ReachPeer},
		{stdhttp.MethodGet, PathReady, ReachPeer},
		{stdhttp.MethodGet, PathLocalPeer, ReachPeer},
		{stdhttp.MethodGet, PathLocalPeerCost, ReachPeer},
		// Mail is the one write that crosses, and it crosses in exactly one
		// direction on exactly one method.
		{stdhttp.MethodPost, PathLocalPeerMail, ReachPeer},
		// The agent-facing message read is LOOPBACK. It was peer-reachable
		// once, and it was wrong twice: it authenticates with a local agent's
		// registration token that no peer holds and no route issues, so the
		// crossing was unreachable, and listing it moved guessing against that
		// credential -- a bearer token for this daemon's whole local API --
		// from loopback to every allowed peer. Mail crosses at
		// PathLocalPeerMail instead.
		{stdhttp.MethodGet, PathLocalMessages + "01J000000000000000000000AA", ReachLoopback},
		// The peer cost route is a READ. A peer must not be able to write
		// telemetry into this host by aiming a POST at the same path.
		{stdhttp.MethodPost, PathLocalPeerCost, ReachLoopback},
		// And the mail route is a WRITE: a peer must not be able to read a
		// mailbox by aiming a GET at the same path.
		{stdhttp.MethodGet, PathLocalPeerMail, ReachLoopback},
		{stdhttp.MethodPost, PathLocalAgentRegister, ReachLoopback},
		{stdhttp.MethodPost, PathLocalTelemetry, ReachLoopback},
		{stdhttp.MethodGet, PathLocalCoordinationEvents, ReachLoopback},
		{stdhttp.MethodPost, PathLocalCoordinationEventsAck, ReachLoopback},
		{stdhttp.MethodGet, PathLocalCoordinationEventsStream, ReachLoopback},
		{stdhttp.MethodGet, PathLocalAdminIdentity, ReachLoopback},
		{stdhttp.MethodGet, PathLocalAdminOverview, ReachLoopback},
		{stdhttp.MethodGet, PathLocalAdminProjects, ReachLoopback},
		{stdhttp.MethodGet, PathLocalAdminAgents, ReachLoopback},
		{stdhttp.MethodGet, PathLocalAdminInbox, ReachLoopback},
		{stdhttp.MethodGet, PathLocalAdminConversations, ReachLoopback},
		{stdhttp.MethodGet, PathLocalAdminReservations, ReachLoopback},
		{stdhttp.MethodPost, PathLocalAdminReservations + "/lease-1/release", ReachLoopback},
		{stdhttp.MethodGet, PathLocalAdminEvents, ReachLoopback},
		{stdhttp.MethodGet, PathLocalAdminCost, ReachLoopback},
	}
}

func peerRequest(method, path string) *stdhttp.Request {
	request := httptest.NewRequest(method, path, nil)
	request.RemoteAddr = peerRemoteAddress
	request.Host = peerHostHeader
	return request
}

func admitting(t *testing.T, resolver PeerResolver, allowed ...string) *PeerAdmission {
	t.Helper()
	_, logger := newLoggingSink()
	return NewPeerAdmission(PeerAdmissionDependencies{Resolver: resolver, Allowed: allowed, Logger: logger})
}

// echoHandler is the handler under the guard. It reports whether the request
// arrived carrying a verified identity, which is what "admitted" means.
func echoHandler() stdhttp.Handler {
	return localSafety(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		identity, verified := Peer(request)
		writeLocalJSON(writer, stdhttp.StatusOK, map[string]any{
			"verified": verified, "machine_name": identity.MachineName,
		})
	}))
}

// TestPartitionClassifiesEveryServedRouteAndDefaultsToLoopback is the review
// surface: it states, route by route, what the daemon exposes to a tailnet
// peer. A new route that nobody classified lands in the loopback column, which
// is the failure mode this design chooses.
func TestPartitionClassifiesEveryServedRouteAndDefaultsToLoopback(t *testing.T) {
	t.Parallel()

	peerCount := 0
	for _, route := range servedRoutes() {
		got := RouteReach(peerRequest(route.method, route.path))
		if got != route.reach {
			t.Errorf("RouteReach(%s %s) = %s, want %s", route.method, route.path, got, route.reach)
		}
		if route.reach == ReachPeer {
			peerCount++
		}
	}
	// A peer-reachable route added to the partition without a line in the table
	// above would go unasserted, so the two are held to the same count.
	if peerCount != len(PeerReachableRoutes()) {
		t.Fatalf("table classifies %d peer routes; the partition names %d: %v",
			peerCount, len(PeerReachableRoutes()), PeerReachableRoutes())
	}
	// A route nobody ever registered is loopback without anyone saying so.
	if got := RouteReach(peerRequest(stdhttp.MethodGet, "/api/v1/local/something-invented-next-quarter")); got != ReachLoopback {
		t.Fatalf("unclassified route reach = %s, want %s", got, ReachLoopback)
	}
	// Method is part of the classification: a POST to a peer-reachable GET
	// path is loopback without anyone having to remember to say so.
	if got := RouteReach(peerRequest(stdhttp.MethodPost, PathLocalPeer)); got != ReachLoopback {
		t.Fatalf("POST to a peer-reachable GET path reach = %s, want %s", got, ReachLoopback)
	}
}

// TestVerifiedPeerIsAdmittedToAPeerRoute is the feature working.
func TestVerifiedPeerIsAdmittedToAPeerRoute(t *testing.T) {
	t.Parallel()

	resolver := &stubResolver{identity: theMini()}
	recorder := httptest.NewRecorder()
	admitting(t, resolver, "phalls-mac-mini").Guard(echoHandler()).ServeHTTP(recorder,
		peerRequest(stdhttp.MethodGet, PathLocalPeer))

	if recorder.Code != stdhttp.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, stdhttp.StatusOK, recorder.Body)
	}
	var body struct {
		Verified    bool   `json:"verified"`
		MachineName string `json:"machine_name"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Verified || body.MachineName != "phalls-mac-mini" {
		t.Fatalf("admitted identity = %+v, want the verified mini", body)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}
}

// TestVerifiedPeerIsRefusedOnALeaseRoute is the invariant the whole design
// exists for: a peer this daemon fully verified, and that an operator named,
// still cannot touch a lease. The force-release route is the lease mutation the
// HTTP surface has; every agent-facing one lives on the MCP listener, which
// peering never binds.
func TestVerifiedPeerIsRefusedOnALeaseRoute(t *testing.T) {
	t.Parallel()

	resolver := &stubResolver{identity: theMini()}
	sink, logger := newLoggingSink()
	admission := NewPeerAdmission(PeerAdmissionDependencies{
		Resolver: resolver, Allowed: []string{"phalls-mac-mini"}, Logger: logger,
	})
	recorder := httptest.NewRecorder()
	admission.Guard(echoHandler()).ServeHTTP(recorder,
		peerRequest(stdhttp.MethodPost, PathLocalAdminReservations+"/lease-1/release"))

	if recorder.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, stdhttp.StatusForbidden, recorder.Body)
	}
	if !strings.Contains(sink.String(), "route_is_loopback_only") {
		t.Fatalf("log did not name the refusal reason: %s", sink.String())
	}
	// Classification runs before resolution, so an unclassified route cannot be
	// used to make this daemon fork a subprocess per request.
	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d, want 0 for a loopback-only route", resolver.calls)
	}
}

// TestVerifiedPeerIsRefusedOnEveryLoopbackOnlyRoute walks the whole partition
// from the outside, because a single-route assertion would not notice a guard
// that admitted by prefix.
func TestVerifiedPeerIsRefusedOnEveryLoopbackOnlyRoute(t *testing.T) {
	t.Parallel()

	guard := admitting(t, &stubResolver{identity: theMini()}, "phalls-mac-mini").Guard(echoHandler())
	for _, route := range servedRoutes() {
		request := peerRequest(route.method, route.path)
		if RouteReach(request) == ReachPeer {
			continue
		}
		recorder := httptest.NewRecorder()
		guard.ServeHTTP(recorder, request)
		if recorder.Code != stdhttp.StatusForbidden {
			t.Errorf("%s %s status = %d, want %d", route.method, route.path, recorder.Code, stdhttp.StatusForbidden)
		}
	}
}

// TestUnverifiedCallerIsRefusedEverywhere covers every way verification can
// fail. None of them falls back to open, and each names its own reason so an
// operator reads what to go fix.
func TestUnverifiedCallerIsRefusedEverywhere(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		resolver *stubResolver
		reason   string
	}{
		{"tailscale is not installed or not running", &stubResolver{err: ErrPeerUnavailable}, "tailnet_unavailable"},
		{"whois does not recognise the caller", &stubResolver{err: ErrPeerUnknown}, "peer_unknown"},
		{"the identity does not parse", &stubResolver{err: ErrPeerMalformed}, "identity_malformed"},
		{"whois fails for a reason we cannot classify", &stubResolver{err: errors.New("broken pipe")}, "identity_unverified"},
		{"the identity is missing its stable id", &stubResolver{identity: PeerIdentity{MachineName: "phalls-mac-mini"}}, "identity_incomplete"},
		{"the peer verified but was never named", &stubResolver{identity: theMini()}, "peer_not_allowed"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			sink, logger := newLoggingSink()
			admission := NewPeerAdmission(PeerAdmissionDependencies{
				Resolver: testCase.resolver, Allowed: []string{"some-other-machine"}, Logger: logger,
			})
			for _, route := range servedRoutes() {
				recorder := httptest.NewRecorder()
				admission.Guard(echoHandler()).ServeHTTP(recorder, peerRequest(route.method, route.path))
				if recorder.Code != stdhttp.StatusForbidden {
					t.Fatalf("%s %s status = %d, want %d", route.method, route.path, recorder.Code, stdhttp.StatusForbidden)
				}
			}
			if !strings.Contains(sink.String(), testCase.reason) {
				t.Fatalf("log did not name %q: %s", testCase.reason, sink.String())
			}
		})
	}
}

// TestRefusalLogsOnlyTheIdentityItActuallyVerified holds the log to the same
// standard as a stored measurement. A refused caller whose identity never
// resolved has no machine name, and inventing one from its source address would
// put a fabricated fact into the record an operator trusts most.
func TestRefusalLogsOnlyTheIdentityItActuallyVerified(t *testing.T) {
	t.Parallel()

	sink, logger := newLoggingSink()
	admission := NewPeerAdmission(PeerAdmissionDependencies{
		Resolver: &stubResolver{err: ErrPeerUnknown}, Allowed: []string{"phalls-mac-mini"}, Logger: logger,
	})
	recorder := httptest.NewRecorder()
	admission.Guard(echoHandler()).ServeHTTP(recorder, peerRequest(stdhttp.MethodGet, PathHealth))

	logged := sink.String()
	if !strings.Contains(logged, `machine_name=""`) || !strings.Contains(logged, `stable_id=""`) {
		t.Fatalf("unverified refusal claimed an identity: %s", logged)
	}
	if !strings.Contains(logged, peerRemoteAddress) {
		t.Fatalf("refusal did not record the source address: %s", logged)
	}

	// A caller that DID verify is named, because there the fact exists.
	namedSink, namedLogger := newLoggingSink()
	named := NewPeerAdmission(PeerAdmissionDependencies{
		Resolver: &stubResolver{identity: theMini()}, Allowed: []string{"a-different-machine"}, Logger: namedLogger,
	})
	named.Guard(echoHandler()).ServeHTTP(httptest.NewRecorder(), peerRequest(stdhttp.MethodGet, PathHealth))
	if !strings.Contains(namedSink.String(), "phalls-mac-mini") ||
		!strings.Contains(namedSink.String(), "nFJpq2jD1311CNTRL") {
		t.Fatalf("verified-but-unnamed refusal did not record the identity: %s", namedSink.String())
	}
}

// TestPeeringDisabledRefusesEveryNonLoopbackCaller is the default. It must hold
// for the peer-reachable routes too: classification widens nothing on its own.
func TestPeeringDisabledRefusesEveryNonLoopbackCaller(t *testing.T) {
	t.Parallel()

	sink, logger := newLoggingSink()
	admission := NewPeerAdmission(PeerAdmissionDependencies{Logger: logger})
	if admission.Enabled() {
		t.Fatal("an admission with no resolver reported peering enabled")
	}
	guard := admission.Guard(echoHandler())
	for _, route := range servedRoutes() {
		recorder := httptest.NewRecorder()
		guard.ServeHTTP(recorder, peerRequest(route.method, route.path))
		if recorder.Code != stdhttp.StatusForbidden {
			t.Fatalf("%s %s status = %d, want %d", route.method, route.path, recorder.Code, stdhttp.StatusForbidden)
		}
	}
	if !strings.Contains(sink.String(), "peering_disabled") {
		t.Fatalf("log did not name the refusal reason: %s", sink.String())
	}
}

// TestAllowListWithoutAResolverIsNotPeering guards the other half of Enabled:
// naming peers this daemon cannot verify is a configuration mistake, not a
// weaker form of peering.
func TestAllowListWithoutAResolverIsNotPeering(t *testing.T) {
	t.Parallel()

	admission := NewPeerAdmission(PeerAdmissionDependencies{Allowed: []string{"phalls-mac-mini"}})
	if admission.Enabled() {
		t.Fatal("an admission with no resolver reported peering enabled")
	}
	recorder := httptest.NewRecorder()
	admission.Guard(echoHandler()).ServeHTTP(recorder, peerRequest(stdhttp.MethodGet, PathHealth))
	if recorder.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, stdhttp.StatusForbidden)
	}
}

// TestResolverWithAnEmptyAllowListAdmitsNobody is the fail-closed reading of an
// operator who enabled the listener and named no peers.
func TestResolverWithAnEmptyAllowListAdmitsNobody(t *testing.T) {
	t.Parallel()

	admission := NewPeerAdmission(PeerAdmissionDependencies{Resolver: &stubResolver{identity: theMini()}})
	if admission.Enabled() {
		t.Fatal("an admission with an empty allow-list reported peering enabled")
	}
	recorder := httptest.NewRecorder()
	admission.Guard(echoHandler()).ServeHTTP(recorder, peerRequest(stdhttp.MethodGet, PathHealth))
	if recorder.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, stdhttp.StatusForbidden)
	}
}

// TestAllowListMatchesMachineNameOrStableIDCaseInsensitively covers the two
// spellings an operator can reasonably write, and the rename the stable id
// survives.
func TestAllowListMatchesMachineNameOrStableIDCaseInsensitively(t *testing.T) {
	t.Parallel()

	for _, allowed := range []string{"phalls-mac-mini", "PHALLS-MAC-MINI", "nFJpq2jD1311CNTRL", "nfjpq2jd1311cntrl"} {
		recorder := httptest.NewRecorder()
		admitting(t, &stubResolver{identity: theMini()}, allowed).Guard(echoHandler()).ServeHTTP(recorder,
			peerRequest(stdhttp.MethodGet, PathHealth))
		if recorder.Code != stdhttp.StatusOK {
			t.Errorf("allow=%q status = %d, want %d", allowed, recorder.Code, stdhttp.StatusOK)
		}
	}
}

// TestLoopbackNeedsNoTailnetAndCarriesNoIdentity keeps the default path free of
// the guard: the CLI on this machine must work with Tailscale uninstalled, and
// it must not be handed an identity nobody verified.
func TestLoopbackNeedsNoTailnetAndCarriesNoIdentity(t *testing.T) {
	t.Parallel()

	resolver := &stubResolver{err: ErrPeerUnavailable}
	request := httptest.NewRequest(stdhttp.MethodGet, PathHealth, nil)
	request.RemoteAddr = "127.0.0.1:52000"
	request.Host = "127.0.0.1:8080"
	recorder := httptest.NewRecorder()
	admitting(t, resolver, "phalls-mac-mini").Guard(echoHandler()).ServeHTTP(recorder, request)

	if recorder.Code != stdhttp.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, stdhttp.StatusOK, recorder.Body)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d, want 0 for a loopback request", resolver.calls)
	}
	if !strings.Contains(recorder.Body.String(), `"verified":false`) {
		t.Fatalf("loopback request carried an identity: %s", recorder.Body)
	}
}

// TestHandlersRefuseNonLoopbackWithoutTheGuard is the defence in depth. A
// handler composed on its own -- as every existing test composes one -- still
// refuses a non-loopback caller, so the guard widens the surface and nothing
// narrows it.
func TestHandlersRefuseNonLoopbackWithoutTheGuard(t *testing.T) {
	t.Parallel()

	handler := echoHandler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, peerRequest(stdhttp.MethodGet, PathHealth))
	if recorder.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, stdhttp.StatusForbidden)
	}
}

func TestPeerHandlerReportsPeeringAndTheVerifiedCaller(t *testing.T) {
	t.Parallel()

	handler, err := NewPeerHandler(PeerDependencies{Version: "1.2.3", Address: "100.78.103.8:8080", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	admitting(t, &stubResolver{identity: theMini()}, "phalls-mac-mini").
		Guard(handler).ServeHTTP(recorder, peerRequest(stdhttp.MethodGet, PathLocalPeer))

	if recorder.Code != stdhttp.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, stdhttp.StatusOK, recorder.Body)
	}
	var report localPeerReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Peering != "on" || report.Address != "100.78.103.8:8080" || report.Version != "1.2.3" {
		t.Fatalf("report = %+v", report)
	}
	if report.Caller == nil || report.Caller.MachineName != "phalls-mac-mini" ||
		report.Caller.StableID != "nFJpq2jD1311CNTRL" {
		t.Fatalf("caller = %+v, want the verified mini", report.Caller)
	}
}

// TestPeerHandlerReportsNoCallerForLoopback is the no-fabrication rule applied
// to the one response an operator reads to decide whether verification works.
func TestPeerHandlerReportsNoCallerForLoopback(t *testing.T) {
	t.Parallel()

	handler, err := NewPeerHandler(PeerDependencies{Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(stdhttp.MethodGet, PathLocalPeer, nil)
	request.RemoteAddr = "127.0.0.1:52000"
	request.Host = "127.0.0.1:8080"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	var report localPeerReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Peering != "off" || report.Address != "" {
		t.Fatalf("report = %+v, want peering off with no address", report)
	}
	if report.Caller != nil {
		t.Fatalf("caller = %+v, want none: nothing about a loopback caller was verified", report.Caller)
	}
}

func TestPeerHandlerRefusesToClaimPeeringWithoutAnAddress(t *testing.T) {
	t.Parallel()

	if _, err := NewPeerHandler(PeerDependencies{Version: "1.2.3", Enabled: true}); err == nil {
		t.Fatal("NewPeerHandler() accepted peering with no address")
	}
}

func TestReachStringNamesBothSides(t *testing.T) {
	t.Parallel()

	if fmt.Sprint(ReachLoopback, " ", ReachPeer) != "loopback peer" {
		t.Fatalf("Reach strings = %q", fmt.Sprint(ReachLoopback, " ", ReachPeer))
	}
}

// TestPeerRequestWithAForeignHostHeaderIsRefused covers the DNS-rebinding
// vector the loopback path already closes. It is a refusal filter, so the
// interesting assertion is that clearing it is not sufficient either: the
// identity still decides.
func TestPeerRequestWithAForeignHostHeaderIsRefused(t *testing.T) {
	t.Parallel()

	refused := []string{"attacker.example.com", "attacker.example.com:8080", "127.0.0.1:8080",
		"localhost:8080", "192.168.1.5:8080", ""}
	for _, host := range refused {
		resolver := &stubResolver{identity: theMini()}
		request := peerRequest(stdhttp.MethodGet, PathHealth)
		request.Host = host
		recorder := httptest.NewRecorder()
		admitting(t, resolver, "phalls-mac-mini").Guard(echoHandler()).ServeHTTP(recorder, request)
		if recorder.Code != stdhttp.StatusForbidden {
			t.Errorf("Host %q status = %d, want %d", host, recorder.Code, stdhttp.StatusForbidden)
		}
		if resolver.calls != 0 {
			t.Errorf("Host %q resolved an identity it should have refused first", host)
		}
	}
	for _, host := range []string{"100.78.103.8:8080", "a-laptop.tail1354da.ts.net:8080",
		"A-Laptop.Tail1354da.TS.NET.:8080", "[fd7a:115c:a1e0::7233:6709]:8080"} {
		request := peerRequest(stdhttp.MethodGet, PathHealth)
		request.Host = host
		recorder := httptest.NewRecorder()
		admitting(t, &stubResolver{identity: theMini()}, "phalls-mac-mini").
			Guard(echoHandler()).ServeHTTP(recorder, request)
		if recorder.Code != stdhttp.StatusOK {
			t.Errorf("Host %q status = %d, want %d; body=%s", host, recorder.Code, stdhttp.StatusOK, recorder.Body)
		}
	}
	// A tailnet-shaped Host is not itself a credential: an unverified caller
	// addressing this daemon correctly is still refused.
	request := peerRequest(stdhttp.MethodGet, PathHealth)
	recorder := httptest.NewRecorder()
	admitting(t, &stubResolver{err: ErrPeerUnknown}, "phalls-mac-mini").
		Guard(echoHandler()).ServeHTTP(recorder, request)
	if recorder.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, stdhttp.StatusForbidden)
	}
}

// countingObserver is the metrics half of the guard.
type countingObserver struct {
	mu       sync.Mutex
	outcomes map[string]int
}

func (observer *countingObserver) ObserveRequest(operation, outcome string) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.outcomes == nil {
		observer.outcomes = make(map[string]int)
	}
	observer.outcomes[operation+"/"+outcome]++
}

func (observer *countingObserver) count(key string) int {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return observer.outcomes[key]
}

// TestThisMachineIsNotItsOwnPeer closes the hole that the natural fleet
// configuration opens.
//
// Deploying the same allow-list to every host is what an operator does, and it
// names this host among the others. A peer address is a LOCAL address: a
// process here that dials the peer listener instead of loopback presents the
// tailnet address as its source, `tailscale whois` answers for it with this
// node's own record, and without this check the allow-list matches. Every local
// process would then hold a credential the operator believes belongs to other
// machines -- including, once the cost route is mounted, the report the admin
// token exists to gate.
func TestThisMachineIsNotItsOwnPeer(t *testing.T) {
	t.Parallel()

	self := PeerIdentity{MachineName: "a-laptop", StableID: "nnjQLUo2L911CNTRL"}
	for name, identity := range map[string]PeerIdentity{
		"by stable id":    {MachineName: "renamed-since", StableID: self.StableID},
		"by machine name": {MachineName: self.MachineName, StableID: "nDIFFERENT11CNTRL"},
		"by both":         self,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sink, logger := newLoggingSink()
			admission := NewPeerAdmission(PeerAdmissionDependencies{
				Resolver: &stubResolver{identity: identity},
				// The allow-list names this machine, which is what a symmetric
				// fleet configuration does.
				Allowed: []string{self.MachineName, self.StableID, "phalls-mac-mini"},
				Self:    self, Logger: logger,
			})
			recorder := httptest.NewRecorder()
			admission.Guard(echoHandler()).ServeHTTP(recorder, peerRequest(stdhttp.MethodGet, PathLocalPeer))
			if recorder.Code != stdhttp.StatusForbidden {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, stdhttp.StatusForbidden, recorder.Body)
			}
			// The reason matters as much as the refusal: "not allowed" would
			// send an operator to edit a list that is already correct.
			if !strings.Contains(sink.String(), "peer_is_this_machine") {
				t.Fatalf("refusal reason missing from the log: %s", sink.String())
			}
		})
	}
}

// TestSelfIsRefusedBeforeTheAllowListIsConsulted keeps the check from being
// reducible to "drop self from the allow-list at compose time", which would
// leave the hole open for an operator who names this host under a spelling the
// composer did not anticipate.
func TestSelfIsRefusedBeforeTheAllowListIsConsulted(t *testing.T) {
	t.Parallel()

	self := PeerIdentity{MachineName: "a-laptop", StableID: "nnjQLUo2L911CNTRL"}
	admission := NewPeerAdmission(PeerAdmissionDependencies{
		Resolver: &stubResolver{identity: self},
		// Nobody named this machine, and it is still refused as self rather
		// than as a stranger.
		Allowed: []string{"phalls-mac-mini"}, Self: self,
	})
	recorder := httptest.NewRecorder()
	admission.Guard(echoHandler()).ServeHTTP(recorder, peerRequest(stdhttp.MethodGet, PathLocalPeer))
	if recorder.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, stdhttp.StatusForbidden)
	}
}

// TestABrowserIsRefusedOnEveryPeerRoute is the DNS-rebinding and CSRF half.
//
// The guard authenticates a MACHINE, so a browser running on an allowed peer is
// a confused deputy holding that machine's credential: a hostile page can make
// it issue requests to this daemon's MagicDNS name, and both the Host filter
// and the source address are then genuine. Nothing on the peer surface is for a
// browser, and this product's own client sends none of these headers, so the
// filter costs real callers nothing.
func TestABrowserIsRefusedOnEveryPeerRoute(t *testing.T) {
	t.Parallel()

	for _, header := range []struct{ name, value string }{
		{"Origin", "https://an-attacker.example"},
		{"Sec-Fetch-Site", "cross-site"},
		// Same-origin is refused too: a page served BY this daemon is still a
		// browser, and no peer route serves one.
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "no-cors"},
	} {
		t.Run(header.name+"="+header.value, func(t *testing.T) {
			t.Parallel()

			resolver := &stubResolver{identity: theMini()}
			request := peerRequest(stdhttp.MethodGet, PathLocalPeer)
			request.Header.Set(header.name, header.value)
			recorder := httptest.NewRecorder()
			admitting(t, resolver, "phalls-mac-mini").Guard(echoHandler()).ServeHTTP(recorder, request)

			if recorder.Code != stdhttp.StatusForbidden {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, stdhttp.StatusForbidden, recorder.Body)
			}
			// The refusal costs no subprocess: a browser is turned away before
			// anything is resolved.
			if resolver.calls != 0 {
				t.Fatalf("resolver calls = %d, want 0", resolver.calls)
			}
		})
	}
}

// TestAdmissionDecisionsAreCounted keeps an attack on the peer listener from
// being visible in the log alone. The guard runs outside the metrics wrapper by
// construction -- a refused request never reaches the mux being measured -- so
// without this the counters stay flat under a flood.
func TestAdmissionDecisionsAreCounted(t *testing.T) {
	t.Parallel()

	observer := &countingObserver{}
	admission := NewPeerAdmission(PeerAdmissionDependencies{
		Resolver: &stubResolver{identity: theMini()},
		Allowed:  []string{"phalls-mac-mini"}, Metrics: observer,
	})
	handler := admission.Guard(echoHandler())
	handler.ServeHTTP(httptest.NewRecorder(), peerRequest(stdhttp.MethodGet, PathLocalPeer))
	handler.ServeHTTP(httptest.NewRecorder(), peerRequest(stdhttp.MethodGet, PathLocalAdminIdentity))

	if got := observer.count("peer admission/admitted"); got != 1 {
		t.Fatalf("admitted count = %d, want 1", got)
	}
	if got := observer.count("peer admission/route_is_loopback_only"); got != 1 {
		t.Fatalf("refused count = %d, want 1; outcomes=%v", got, observer.outcomes)
	}
}

// TestLoopbackOnlyRefusesEveryNonLoopbackCaller is the second mechanism under
// the MCP listener. Before it, "MCP is loopback-only" was a convention that a
// single flag revoked: --mcp-address on a tailnet address published every
// lease-mutating tool with no loopback check anywhere in the path.
func TestLoopbackOnlyRefusesEveryNonLoopbackCaller(t *testing.T) {
	t.Parallel()

	served := false
	guarded := LoopbackOnly(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		served = true
		writer.WriteHeader(stdhttp.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	guarded.ServeHTTP(recorder, peerRequest(stdhttp.MethodPost, "/"))
	if recorder.Code != stdhttp.StatusForbidden || served {
		t.Fatalf("non-loopback status = %d, served = %v", recorder.Code, served)
	}

	// A verified peer identity on the request changes nothing. There is no
	// tailnet identity that makes lease mutation acceptable across hosts.
	admitted := peerRequest(stdhttp.MethodPost, "/")
	admitted = admitted.WithContext(context.WithValue(admitted.Context(), peerAdmissionKey{}, theMini()))
	recorder = httptest.NewRecorder()
	guarded.ServeHTTP(recorder, admitted)
	if recorder.Code != stdhttp.StatusForbidden || served {
		t.Fatalf("verified-peer status = %d, served = %v", recorder.Code, served)
	}

	loopback := httptest.NewRequest(stdhttp.MethodPost, "/", nil)
	loopback.RemoteAddr = "127.0.0.1:53124"
	loopback.Host = "127.0.0.1:8081"
	recorder = httptest.NewRecorder()
	guarded.ServeHTTP(recorder, loopback)
	if recorder.Code != stdhttp.StatusOK || !served {
		t.Fatalf("loopback status = %d, served = %v", recorder.Code, served)
	}
}
