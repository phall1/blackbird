package http

import (
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/transport/metrics"
)

const adminTestToken = "bba_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type stubAdminStore struct {
	identity      coordination.AdminStorageIdentity
	overview      coordination.AdminOverview
	projects      coordination.AdminProjectsPage
	agents        coordination.AdminAgentsPage
	inbox         coordination.AdminInboxPage
	conversations coordination.AdminConversationsPage
	reservations  coordination.AdminReservationsPage
	forcedLease   coordination.Lease
	events        coordination.AdminEventsPage
	schemaVersion int
	err           error

	forcedLeaseID domain.LeaseID

	agentsQuery        coordination.AdminAgentsQuery
	inboxQuery         coordination.AdminInboxQuery
	conversationsQuery coordination.AdminConversationsQuery
	reservationsQuery  coordination.AdminReservationsQuery
	eventsQuery        coordination.AdminEventsQuery
}

func (store *stubAdminStore) CheckReadiness(context.Context) (int, error) {
	return store.schemaVersion, store.err
}

func (store *stubAdminStore) AdminStorageIdentity(context.Context) (coordination.AdminStorageIdentity, error) {
	return store.identity, store.err
}

func (store *stubAdminStore) AdminOverview(context.Context) (coordination.AdminOverview, error) {
	return store.overview, store.err
}

func (store *stubAdminStore) ListAdminProjects(context.Context) (coordination.AdminProjectsPage, error) {
	return store.projects, store.err
}

func (store *stubAdminStore) ListAdminAgents(_ context.Context,
	query coordination.AdminAgentsQuery) (coordination.AdminAgentsPage, error) {
	store.agentsQuery = query
	return store.agents, store.err
}

func (store *stubAdminStore) AdminInbox(_ context.Context,
	query coordination.AdminInboxQuery) (coordination.AdminInboxPage, error) {
	store.inboxQuery = query
	return store.inbox, store.err
}

func (store *stubAdminStore) ListAdminConversations(_ context.Context,
	query coordination.AdminConversationsQuery) (coordination.AdminConversationsPage, error) {
	store.conversationsQuery = query
	return store.conversations, store.err
}

func (store *stubAdminStore) ListAdminReservations(_ context.Context,
	query coordination.AdminReservationsQuery) (coordination.AdminReservationsPage, error) {
	store.reservationsQuery = query
	return store.reservations, store.err
}

func (store *stubAdminStore) ForceReleaseAdminReservation(_ context.Context,
	leaseID domain.LeaseID) (coordination.Lease, error) {
	store.forcedLeaseID = leaseID
	return store.forcedLease, store.err
}

func (store *stubAdminStore) ListAdminEvents(_ context.Context,
	query coordination.AdminEventsQuery) (coordination.AdminEventsPage, error) {
	store.eventsQuery = query
	return store.events, store.err
}

func TestNewAdminHandlerFailsClosedWithoutStoreOrToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		dependencies AdminDependencies
	}{
		{name: "no store", dependencies: AdminDependencies{Token: NewAdminTokenDigest(adminTestToken)}},
		{name: "nil store", dependencies: AdminDependencies{Admin: (*stubAdminStore)(nil),
			Token: NewAdminTokenDigest(adminTestToken)}},
		{name: "no token", dependencies: AdminDependencies{Admin: &stubAdminStore{}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler, err := NewAdminHandler(test.dependencies)
			if err == nil || handler != nil {
				t.Fatalf("handler=%v error=%v", handler, err)
			}
		})
	}
}

func TestLocalAdminRejectsEveryCredentialButTheAdminToken(t *testing.T) {
	t.Parallel()
	handler := newAdminTestHandler(t, &stubAdminStore{})
	tests := []struct {
		name       string
		authorized string
	}{
		{name: "absent"},
		{name: "not bearer", authorized: "Basic " + adminTestToken},
		{name: "trailing space", authorized: "Bearer " + adminTestToken + " "},
		{name: "agent token", authorized: "Bearer bbm_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "near miss", authorized: "Bearer " + strings.TrimSuffix(adminTestToken, "f") + "e"},
	}
	var bodies []string
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalAdminOverview, nil)
			if test.authorized != "" {
				request.Header.Set("Authorization", test.authorized)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != stdhttp.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("status=%d headers=%v", response.Code, response.Header())
			}
			var problem localProblem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil ||
				problem.Code != domain.ErrorCodeUnauthenticated {
				t.Fatalf("problem=%+v error=%v", problem, err)
			}
			bodies = append(bodies, response.Body.String())
		})
	}
	for index := 1; index < len(bodies); index++ {
		if bodies[index] != bodies[0] {
			t.Fatalf("rejection bodies differ: %q vs %q", bodies[0], bodies[index])
		}
	}

	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalAdminOverview, nil)
	request.Header.Set("Authorization", "Bearer "+adminTestToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusOK {
		t.Fatalf("accepted status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestLocalAdminTokenIsRejectedByAgentEndpoints(t *testing.T) {
	t.Parallel()
	store := openLocalHTTPStore(t, filepath.Join(t.TempDir(), "coordination.db"))
	defer func() { _ = store.Close() }()
	handler, err := NewLocalHandler(LocalDependencies{Coordination: store})
	if err != nil {
		t.Fatal(err)
	}
	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalCoordinationEvents, nil)
	request.Header.Set("Authorization", "Bearer "+adminTestToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusUnauthorized {
		t.Fatalf("admin token on agent endpoint status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestLocalAdminRejectsNonLoopbackAndQueryCredentials(t *testing.T) {
	t.Parallel()
	handler := newAdminTestHandler(t, &stubAdminStore{})

	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalAdminOverview, nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("Authorization", "Bearer "+adminTestToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var problem localProblem
	if response.Code != stdhttp.StatusForbidden ||
		json.Unmarshal(response.Body.Bytes(), &problem) != nil || problem.Code != domain.ErrorCodeForbidden {
		t.Fatalf("non-loopback status=%d problem=%+v", response.Code, problem)
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("safety headers=%v", response.Header())
	}

	request = newLocalHTTPRequest(stdhttp.MethodGet, PathLocalAdminAgents+"?access_token="+adminTestToken, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("query credential status=%d", response.Code)
	}
}

func TestLocalAdminRejectsInvalidQueryParameters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
		status int
	}{
		{name: "overview takes no parameters", target: PathLocalAdminOverview + "?project_key=/repo", status: stdhttp.StatusBadRequest},
		{name: "projects takes no parameters", target: PathLocalAdminProjects + "?limit=1", status: stdhttp.StatusBadRequest},
		{name: "unknown parameter", target: PathLocalAdminAgents + "?bogus=1", status: stdhttp.StatusBadRequest},
		{name: "duplicate parameter", target: PathLocalAdminAgents + "?limit=1&limit=2", status: stdhttp.StatusBadRequest},
		{name: "zero limit", target: PathLocalAdminAgents + "?limit=0", status: stdhttp.StatusBadRequest},
		{name: "limit above page size", target: PathLocalAdminAgents + "?limit=257", status: stdhttp.StatusBadRequest},
		{name: "limit at page size", target: PathLocalAdminAgents + "?limit=256", status: stdhttp.StatusOK},
		{name: "inbox without project key", target: PathLocalAdminInbox, status: stdhttp.StatusBadRequest},
		{name: "inbox with project key", target: PathLocalAdminInbox + "?project_key=/repo", status: stdhttp.StatusOK},
		{name: "unknown reservation state", target: PathLocalAdminReservations + "?state=bogus", status: stdhttp.StatusBadRequest},
		{name: "released reservation state", target: PathLocalAdminReservations + "?state=released", status: stdhttp.StatusOK},
		{name: "unknown event type", target: PathLocalAdminEvents + "?type=lease.exploded", status: stdhttp.StatusBadRequest},
		{name: "known event type", target: PathLocalAdminEvents + "?type=lease.acquired", status: stdhttp.StatusOK},
		{name: "malformed conversation id", target: PathLocalAdminConversations + "?conversation_id=nope", status: stdhttp.StatusBadRequest},
		{name: "unknown active flag", target: PathLocalAdminAgents + "?active=yes", status: stdhttp.StatusBadRequest},
		{name: "active flag", target: PathLocalAdminAgents + "?active=true", status: stdhttp.StatusOK},
		{name: "unknown unread flag", target: PathLocalAdminInbox + "?project_key=/repo&unread=maybe",
			status: stdhttp.StatusBadRequest},
		{name: "unread and unacked flags", target: PathLocalAdminInbox + "?project_key=/repo&unread=true&unacked=true",
			status: stdhttp.StatusOK},
		{name: "unknown open flag", target: PathLocalAdminConversations + "?open=sure", status: stdhttp.StatusBadRequest},
		{name: "open flag", target: PathLocalAdminConversations + "?open=true", status: stdhttp.StatusOK},
		{name: "unknown reservation mode", target: PathLocalAdminReservations + "?mode=bogus", status: stdhttp.StatusBadRequest},
		{name: "any reservation mode", target: PathLocalAdminReservations + "?mode=any", status: stdhttp.StatusOK},
		{name: "shared reservation mode", target: PathLocalAdminReservations + "?mode=shared", status: stdhttp.StatusOK},
		{name: "padded reservation path", target: PathLocalAdminReservations + "?path=%20internal%2Fapp.go",
			status: stdhttp.StatusBadRequest},
		{name: "oversized reservation path", target: PathLocalAdminReservations + "?path=" +
			strings.Repeat("x", coordination.MaxLeaseSelectorBytes+1), status: stdhttp.StatusBadRequest},
		{name: "reservation path", target: PathLocalAdminReservations + "?path=internal%2Fapp.go", status: stdhttp.StatusOK},
		{name: "oversized project key", target: PathLocalAdminAgents + "?project_key=" +
			strings.Repeat("x", coordination.MaxKeyBytes+1), status: stdhttp.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := newAdminTestHandler(t, &stubAdminStore{})
			response := serveAdmin(handler, test.target)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
			if test.status == stdhttp.StatusBadRequest {
				var problem localProblem
				if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil ||
					problem.Code != domain.ErrorCodeInvalidArgument {
					t.Fatalf("problem=%+v error=%v", problem, err)
				}
			}
		})
	}
}

func TestLocalAdminPassesQueriesThroughUnchanged(t *testing.T) {
	t.Parallel()
	store := &stubAdminStore{}
	handler := newAdminTestHandler(t, store)

	if response := serveAdmin(handler, PathLocalAdminAgents); response.Code != stdhttp.StatusOK {
		t.Fatalf("agents status=%d", response.Code)
	}
	if store.agentsQuery != (coordination.AdminAgentsQuery{}) {
		t.Fatalf("absent parameters must reach storage as zero values: %+v", store.agentsQuery)
	}
	if response := serveAdmin(handler, PathLocalAdminAgents+"?project_key=/repo&agent=alice&limit=7"); response.Code != stdhttp.StatusOK {
		t.Fatalf("agents status=%d", response.Code)
	}
	if store.agentsQuery != (coordination.AdminAgentsQuery{ProjectKey: "/repo", AgentName: "alice", Limit: 7}) {
		t.Fatalf("agents query=%+v", store.agentsQuery)
	}
	if response := serveAdmin(handler, PathLocalAdminReservations); response.Code != stdhttp.StatusOK {
		t.Fatalf("reservations status=%d", response.Code)
	}
	if store.reservationsQuery.State != coordination.AdminReservationAll {
		t.Fatalf("absent state must normalize to all: %+v", store.reservationsQuery)
	}
	if response := serveAdmin(handler, PathLocalAdminEvents+"?type=message.available&agent=bob"); response.Code != stdhttp.StatusOK {
		t.Fatalf("events status=%d", response.Code)
	}
	if store.eventsQuery != (coordination.AdminEventsQuery{AgentName: "bob",
		EventType: coordination.EventMessageAvailable}) {
		t.Fatalf("events query=%+v", store.eventsQuery)
	}
}

// Every filter predicate must reach the store, which applies it in SQL before
// LIMIT. A predicate dropped at this edge is a page the caller renders as the
// whole truth while matching rows sit behind the limit.
func TestLocalAdminPassesFilterPredicatesToTheStore(t *testing.T) {
	t.Parallel()
	store := &stubAdminStore{}
	handler := newAdminTestHandler(t, store)

	if response := serveAdmin(handler, PathLocalAdminAgents+"?active=true&limit=25"); response.Code != stdhttp.StatusOK {
		t.Fatalf("agents status=%d body=%s", response.Code, response.Body.String())
	}
	if store.agentsQuery != (coordination.AdminAgentsQuery{ActiveOnly: true, Limit: 25}) {
		t.Fatalf("agents query=%+v", store.agentsQuery)
	}
	if response := serveAdmin(handler,
		PathLocalAdminInbox+"?project_key=/repo&unacked=true&limit=25"); response.Code != stdhttp.StatusOK {
		t.Fatalf("inbox status=%d body=%s", response.Code, response.Body.String())
	}
	if store.inboxQuery != (coordination.AdminInboxQuery{ProjectKey: "/repo", UnackedOnly: true, Limit: 25}) {
		t.Fatalf("inbox query=%+v", store.inboxQuery)
	}
	if response := serveAdmin(handler, PathLocalAdminInbox+"?project_key=/repo&unread=true"); response.Code != stdhttp.StatusOK {
		t.Fatalf("inbox status=%d body=%s", response.Code, response.Body.String())
	}
	if store.inboxQuery != (coordination.AdminInboxQuery{ProjectKey: "/repo", UnreadOnly: true}) {
		t.Fatalf("inbox query=%+v", store.inboxQuery)
	}
	if response := serveAdmin(handler, PathLocalAdminConversations+"?open=true"); response.Code != stdhttp.StatusOK {
		t.Fatalf("conversations status=%d body=%s", response.Code, response.Body.String())
	}
	if store.conversationsQuery != (coordination.AdminConversationsQuery{OpenOnly: true}) {
		t.Fatalf("conversations query=%+v", store.conversationsQuery)
	}
	if response := serveAdmin(handler,
		PathLocalAdminReservations+"?mode=shared&path=internal%2Fapp.go"); response.Code != stdhttp.StatusOK {
		t.Fatalf("reservations status=%d body=%s", response.Code, response.Body.String())
	}
	if store.reservationsQuery != (coordination.AdminReservationsQuery{State: coordination.AdminReservationAll,
		Mode: coordination.LeaseShared, Path: "internal/app.go"}) {
		t.Fatalf("reservations query=%+v", store.reservationsQuery)
	}
	if response := serveAdmin(handler, PathLocalAdminReservations+"?mode=any"); response.Code != stdhttp.StatusOK {
		t.Fatalf("reservations status=%d body=%s", response.Code, response.Body.String())
	}
	if store.reservationsQuery.Mode != "" {
		t.Fatalf("mode=any must reach storage as no mode predicate: %+v", store.reservationsQuery)
	}
}

func TestLocalAdminForceReleaseRequiresTokenAndValidLease(t *testing.T) {
	t.Parallel()
	fixture := newAdminFixture(t)
	handler := newAdminTestHandler(t, fixture.store)
	target := PathLocalAdminReservations + "/" + fixture.leaseID.String() + "/release"

	request := newLocalHTTPRequest(stdhttp.MethodPost, target, nil)
	request.Header.Set("Authorization", "Bearer "+adminTestToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fixture.store.forcedLeaseID != fixture.leaseID {
		t.Fatalf("forced lease=%v, want %v", fixture.store.forcedLeaseID, fixture.leaseID)
	}
	var result localAdminReservationRelease
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.LeaseID != fixture.leaseID.String() || !result.Forced || result.ReleasedAt != fixture.observedAt {
		t.Fatalf("release=%+v", result)
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, newLocalHTTPRequest(stdhttp.MethodPost, target, nil))
	if unauthorized.Code != stdhttp.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	invalid := newLocalHTTPRequest(stdhttp.MethodPost, PathLocalAdminReservations+"/not-a-lease/release", nil)
	invalid.Header.Set("Authorization", "Bearer "+adminTestToken)
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != stdhttp.StatusBadRequest {
		t.Fatalf("invalid status=%d body=%s", invalidResponse.Code, invalidResponse.Body.String())
	}
}

func TestLocalAdminEncodesPopulatedProjections(t *testing.T) {
	t.Parallel()
	fixture := newAdminFixture(t)
	metrics := metrics.New()
	metrics.ObserveRequest("mcp blackbird_agents_list", "ok")
	metrics.ObserveLeaseConflict()
	handler := newAdminTestHandler(t, fixture.store, metrics)

	t.Run("identity", func(t *testing.T) {
		var identity localAdminIdentity
		decodeAdmin(t, handler, PathLocalAdminIdentity, &identity)
		if identity.Version != "0.4.0" || identity.Commit != "abcdef" || identity.PID != 4242 ||
			identity.HTTPAddress != "127.0.0.1:8080" || identity.MCPAddress != "127.0.0.1:8081" ||
			identity.StorageBackend != "sqlite" || identity.DatabasePath != "/state/blackbird.db" ||
			identity.SchemaVersion != 4 || identity.ObservedAt != fixture.observedAt || identity.UptimeMS <= 0 ||
			identity.Metrics.Requests["mcp blackbird_agents_list"]["ok"] != 1 ||
			identity.Metrics.LeaseConflicts != 1 {
			t.Fatalf("identity=%+v", identity)
		}
	})

	t.Run("overview", func(t *testing.T) {
		var overview localAdminOverview
		decodeAdmin(t, handler, PathLocalAdminOverview, &overview)
		if overview != (localAdminOverview{Projects: 2, Agents: 47, ActiveAgents: 3, Conversations: 19, Messages: 27,
			Deliveries: 39, UnreadDeliveries: 29, UnackedDeliveries: 6, ActiveReservations: 0, ExpiredReservations: 9,
			CoordinationEvents: 106, ObservedAt: fixture.observedAt}) {
			t.Fatalf("overview=%+v", overview)
		}
	})

	t.Run("projects", func(t *testing.T) {
		var page localAdminProjectsPage
		decodeAdmin(t, handler, PathLocalAdminProjects, &page)
		if len(page.Projects) != 2 || page.ObservedAt != fixture.observedAt {
			t.Fatalf("projects=%+v", page)
		}
		if page.Projects[0].ProjectKey != "/Users/phall/workspace/blackbird" ||
			page.Projects[0].WorkspaceID != fixture.workspaceID.String() ||
			page.Projects[0].RunID != fixture.runID.String() || page.Projects[0].Agents != 30 ||
			page.Projects[0].CreatedAt != fixture.createdAt || page.Projects[0].LastEventAt != fixture.observedAt {
			t.Fatalf("project=%+v", page.Projects[0])
		}
		if page.Projects[1].RunID != "" || page.Projects[1].LastEventAt != "" {
			t.Fatalf("absent optional fields must be omitted: %+v", page.Projects[1])
		}
	})

	t.Run("agents", func(t *testing.T) {
		var page localAdminAgentsPage
		decodeAdmin(t, handler, PathLocalAdminAgents, &page)
		if len(page.Agents) != 2 || !page.Truncated || page.ObservedAt != fixture.observedAt {
			t.Fatalf("agents=%+v", page)
		}
		if !page.Agents[0].Active || page.Agents[0].SessionID != fixture.sessionID.String() ||
			page.Agents[0].LastSeenAt != fixture.observedAt || page.Agents[0].UnreadDeliveries != 4 {
			t.Fatalf("online agent=%+v", page.Agents[0])
		}
		if page.Agents[1].Active || page.Agents[1].SessionID != "" || page.Agents[1].StartedAt != "" ||
			page.Agents[1].LastSeenAt != "" || page.Agents[1].CreatedAt != fixture.createdAt {
			t.Fatalf("offline agent must round-trip with empty session fields: %+v", page.Agents[1])
		}
	})

	t.Run("inbox", func(t *testing.T) {
		var page localAdminInboxPage
		decodeAdmin(t, handler, PathLocalAdminInbox+"?project_key=/repo", &page)
		if page.ProjectKey != "/repo" || len(page.Summaries) != 2 || len(page.Pending) != 1 || !page.Truncated {
			t.Fatalf("inbox=%+v", page)
		}
		if page.Summaries[1].UnreadDeliveries != 0 || page.Summaries[1].OldestUnreadAt != "" {
			t.Fatalf("agent without mail must report zero: %+v", page.Summaries[1])
		}
		if page.Pending[0].Subject != "handoff" || page.Pending[0].Kind != string(coordination.RecipientBcc) ||
			page.Pending[0].Read || !page.Pending[0].AckRequired ||
			page.Pending[0].RecipientActorID != fixture.actorID.String() ||
			page.Pending[0].SentAt != fixture.createdAt {
			t.Fatalf("pending=%+v", page.Pending[0])
		}
	})

	t.Run("conversations", func(t *testing.T) {
		var page localAdminConversationsPage
		decodeAdmin(t, handler, PathLocalAdminConversations, &page)
		if len(page.Conversations) != 1 || page.Conversations[0].Status != string(coordination.AdminConversationOpen) ||
			page.Conversations[0].Topic != "CLI overhaul" || page.Conversations[0].Messages != 12 ||
			page.Conversations[0].LastMessageSubject != "handoff" {
			t.Fatalf("conversations=%+v", page)
		}
	})

	t.Run("reservations", func(t *testing.T) {
		var page localAdminReservationsPage
		decodeAdmin(t, handler, PathLocalAdminReservations, &page)
		if len(page.Reservations) != 1 || page.ObservedAt != fixture.observedAt {
			t.Fatalf("reservations=%+v", page)
		}
		reservation := page.Reservations[0]
		if reservation.State != string(coordination.AdminReservationExpired) || !reservation.Expired ||
			reservation.ExpiresInMS != -120000 || reservation.Mode != string(coordination.LeaseExclusive) ||
			reservation.ReleasedAt != "" || len(reservation.Selectors) != 2 ||
			reservation.Selectors[0] != (localAdminSelector{Kind: string(coordination.LeaseSelectorExact), Path: "internal/app.go"}) ||
			reservation.Selectors[1].Kind != string(coordination.LeaseSelectorSubtree) {
			t.Fatalf("reservation=%+v", reservation)
		}
	})

	t.Run("events", func(t *testing.T) {
		var page localAdminEventsPage
		decodeAdmin(t, handler, PathLocalAdminEvents, &page)
		if len(page.Events) != 2 || page.Events[0].Position != 106 ||
			page.Events[0].Type != string(coordination.EventMessageAvailable) ||
			string(page.Events[0].Payload) != `{"message_id":"m"}` ||
			page.Events[0].AgentName != "alice" || page.Events[0].OccurredAt != fixture.observedAt {
			t.Fatalf("events=%+v", page)
		}
		if string(page.Events[1].Payload) != "null" || page.Events[1].AgentName != "" {
			t.Fatalf("absent payload and agent must encode as null and be omitted: %+v", page.Events[1])
		}
	})
}

func TestLocalAdminEncodesEmptyCollectionsAsArrays(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
		field  string
	}{
		{name: "projects", target: PathLocalAdminProjects, field: `"projects":[]`},
		{name: "agents", target: PathLocalAdminAgents, field: `"agents":[]`},
		{name: "inbox summaries", target: PathLocalAdminInbox + "?project_key=/repo", field: `"summaries":[]`},
		{name: "inbox pending", target: PathLocalAdminInbox + "?project_key=/repo", field: `"pending":[]`},
		{name: "conversations", target: PathLocalAdminConversations, field: `"conversations":[]`},
		{name: "reservations", target: PathLocalAdminReservations, field: `"reservations":[]`},
		{name: "events", target: PathLocalAdminEvents, field: `"events":[]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := serveAdmin(newAdminTestHandler(t, &stubAdminStore{}), test.target)
			if response.Code != stdhttp.StatusOK || !strings.Contains(response.Body.String(), test.field) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestLocalAdminStoreErrorsBecomeProblemDocuments(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
		err    error
		status int
		code   domain.ErrorCode
	}{
		{name: "invalid coordination", target: PathLocalAdminOverview, err: coordination.ErrInvalid,
			status: stdhttp.StatusBadRequest, code: domain.ErrorCodeInvalidArgument},
		{name: "opaque failure", target: PathLocalAdminEvents, err: errAdminTestOpaque,
			status: stdhttp.StatusInternalServerError, code: domain.ErrorCodeInternal},
		{name: "identity without storage", target: PathLocalAdminIdentity, err: errAdminTestOpaque,
			status: stdhttp.StatusServiceUnavailable, code: domain.ErrorCodeDependencyUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := newAdminTestHandler(t, &stubAdminStore{err: test.err})
			response := serveAdmin(handler, test.target)
			var problem localProblem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.status || problem.Code != test.code {
				t.Fatalf("status=%d problem=%+v", response.Code, problem)
			}
			if strings.Contains(problem.Message, errAdminTestOpaque.Error()) ||
				strings.Contains(problem.Message, "/state/blackbird.db") {
				t.Fatalf("problem message leaked internals: %q", problem.Message)
			}
			if response.Header().Get("Content-Type") != mediaTypeProblem {
				t.Fatalf("content type=%q", response.Header().Get("Content-Type"))
			}
		})
	}
}

var errAdminTestOpaque = adminTestError("sqlite: unable to open /state/blackbird.db")

type adminTestError string

func (err adminTestError) Error() string { return string(err) }

type adminFixture struct {
	store       *stubAdminStore
	workspaceID domain.WorkspaceID
	runID       domain.RunID
	actorID     domain.ActorID
	sessionID   domain.ActorSessionID
	leaseID     domain.LeaseID
	observedAt  string
	createdAt   string
}

func newAdminFixture(t *testing.T) adminFixture {
	t.Helper()
	observed := time.Date(2026, time.August, 15, 9, 41, 2, 113000000, time.UTC)
	created := observed.Add(-time.Hour)
	observedUS := coordination.MicrosFromTime(observed)
	createdUS := coordination.MicrosFromTime(created)
	workspaceID, err := domain.NewWorkspaceID()
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	actorID, err := domain.NewActorID()
	if err != nil {
		t.Fatal(err)
	}
	otherActorID, err := domain.NewActorID()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := domain.NewActorSessionID()
	if err != nil {
		t.Fatal(err)
	}
	leaseID, err := domain.NewLeaseID()
	if err != nil {
		t.Fatal(err)
	}
	conversationID, err := domain.NewConversationID()
	if err != nil {
		t.Fatal(err)
	}
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	exact, err := coordination.NewLeaseSelector(coordination.LeaseSelectorExact, "internal/app.go")
	if err != nil {
		t.Fatal(err)
	}
	subtree, err := coordination.NewLeaseSelector(coordination.LeaseSelectorSubtree, "internal/transport")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := domain.NewAuthorityID()
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := domain.ParseAuthorityEpoch(authority.String())
	if err != nil {
		t.Fatal(err)
	}
	forcedLease, err := coordination.NewLeaseView(coordination.LeaseViewParams{LeaseID: leaseID,
		WorkspaceID: workspaceID, Holder: actorID, HolderSession: sessionID, AuthorityEpoch: epoch,
		Mode: coordination.LeaseExclusive, Selectors: []coordination.LeaseSelector{exact},
		AcquiredAt: created, ExpiresAt: observed.Add(time.Hour), ReleasedAt: &observed})
	if err != nil {
		t.Fatal(err)
	}
	store := &stubAdminStore{
		schemaVersion: 4,
		identity: coordination.AdminStorageIdentity{StorageBackend: "sqlite", DatabasePath: "/state/blackbird.db",
			SchemaVersion: 4, ObservedAtUS: observedUS},
		overview: coordination.AdminOverview{Projects: 2, Agents: 47, ActiveAgents: 3, Conversations: 19, Messages: 27,
			Deliveries: 39, UnreadDeliveries: 29, UnackedDeliveries: 6, ExpiredReservations: 9,
			CoordinationEvents: 106, ObservedAtUS: observedUS},
		projects: coordination.AdminProjectsPage{ObservedAtUS: observedUS, Projects: []coordination.AdminProject{
			{ProjectKey: "/Users/phall/workspace/blackbird", WorkspaceID: workspaceID, RunID: runID, Agents: 30,
				ActiveAgents: 2, Conversations: 11, CreatedAtUS: createdUS, LastEventAtUS: observedUS},
			{ProjectKey: "/Users/phall/dotfiles", WorkspaceID: workspaceID, Agents: 1, CreatedAtUS: createdUS},
		}},
		agents: coordination.AdminAgentsPage{ObservedAtUS: observedUS, Truncated: true, Agents: []coordination.AdminAgent{
			{ProjectKey: "/repo", AgentName: "alice", ActorID: actorID, SessionID: sessionID, Active: true,
				CreatedAtUS: createdUS, StartedAtUS: createdUS, LastSeenAtUS: observedUS, UnreadDeliveries: 4,
				UnackedDeliveries: 1, ActiveLeases: 2},
			{ProjectKey: "/repo", AgentName: "bob", ActorID: otherActorID, CreatedAtUS: createdUS},
		}},
		inbox: coordination.AdminInboxPage{ProjectKey: "/repo", ObservedAtUS: observedUS, Truncated: true,
			Summaries: []coordination.AdminInboxSummary{
				{ProjectKey: "/repo", AgentName: "alice", ActorID: actorID, UnreadDeliveries: 4,
					UnackedDeliveries: 1, OldestUnreadAtUS: createdUS},
				{ProjectKey: "/repo", AgentName: "bob", ActorID: otherActorID},
			},
			Pending: []coordination.AdminInboxItem{{MessageID: messageID, ConversationID: conversationID,
				ProjectKey: "/repo", RecipientAgentName: "alice", RecipientActorID: actorID,
				AuthorAgentName: "bob", AuthorActorID: otherActorID, Subject: "handoff",
				Kind: coordination.RecipientBcc, AcknowledgementRequired: true, SentAtUS: createdUS}}},
		conversations: coordination.AdminConversationsPage{ObservedAtUS: observedUS,
			Conversations: []coordination.AdminConversation{{ConversationID: conversationID, WorkspaceID: workspaceID,
				ProjectKey: "/repo", Topic: "CLI overhaul", Status: coordination.AdminConversationOpen,
				OpenedByAgentName: "alice", OpenedByActorID: actorID, Messages: 12, Participants: 3,
				UnreadDeliveries: 2, OpenedAtUS: createdUS, LastMessageAtUS: observedUS,
				LastMessageAuthor: "bob", LastMessageSubject: "handoff"}}},
		forcedLease: forcedLease,
		reservations: coordination.AdminReservationsPage{ObservedAtUS: observedUS,
			Reservations: []coordination.AdminReservation{{LeaseID: leaseID, ProjectKey: "/repo",
				WorkspaceID: workspaceID, HolderAgentName: "alice", HolderActorID: actorID,
				HolderSessionID: sessionID, Mode: coordination.LeaseExclusive,
				State: coordination.AdminReservationExpired, Expired: true,
				Selectors:    []coordination.LeaseSelector{exact, subtree},
				AcquiredAtUS: createdUS, ExpiresAtUS: coordination.MicrosFromTime(observed.Add(-2 * time.Minute)),
				ExpiresInMS: -120000}}},
		events: coordination.AdminEventsPage{ObservedAtUS: observedUS, Events: []coordination.AdminEvent{
			{Position: 106, ProjectKey: "/repo", WorkspaceID: workspaceID, AgentName: "alice", ActorID: actorID,
				EventType: coordination.EventMessageAvailable, SubjectID: messageID.String(),
				Payload: []byte(`{"message_id":"m"}`), OccurredAtUS: observedUS},
			{Position: 105, ProjectKey: "/repo", WorkspaceID: workspaceID, ActorID: otherActorID,
				EventType: coordination.EventLeaseReleased, SubjectID: leaseID.String(),
				OccurredAtUS: createdUS},
		}},
	}
	return adminFixture{store: store, workspaceID: workspaceID, runID: runID, actorID: actorID, sessionID: sessionID,
		leaseID: leaseID, observedAt: observed.Format(time.RFC3339Nano), createdAt: created.Format(time.RFC3339Nano)}
}

func newAdminTestHandler(t *testing.T, store coordination.LocalAdminStore,
	registries ...*metrics.Registry) stdhttp.Handler {
	t.Helper()
	var metrics *metrics.Registry
	if len(registries) != 0 {
		metrics = registries[0]
	}
	handler, err := NewAdminHandler(AdminDependencies{Admin: store, Token: NewAdminTokenDigest(adminTestToken),
		Metrics: metrics,
		Identity: LocalIdentity{Version: "0.4.0", Commit: "abcdef", BuiltAt: "2026-08-15T00:00:00Z", PID: 4242,
			StartedAt: time.Now().Add(-time.Minute), HTTPAddress: "127.0.0.1:8080", MCPAddress: "127.0.0.1:8081"}})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serveAdmin(handler stdhttp.Handler, target string) *httptest.ResponseRecorder {
	request := newLocalHTTPRequest(stdhttp.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer "+adminTestToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeAdmin(t *testing.T, handler stdhttp.Handler, target string, destination any) {
	t.Helper()
	response := serveAdmin(handler, target)
	if response.Code != stdhttp.StatusOK || response.Header().Get("Content-Type") != mediaTypeJSON {
		t.Fatalf("status=%d content-type=%q body=%s", response.Code, response.Header().Get("Content-Type"),
			response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), destination); err != nil {
		t.Fatalf("decode %s: %v (%s)", target, err, response.Body.String())
	}
}
