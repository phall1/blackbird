package http

import (
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

type stubOutboxReader struct {
	entries    []coordination.PeerMailEntry
	err        error
	projectKey string
	limit      int
}

func (reader *stubOutboxReader) PeerMailQueue(
	_ context.Context,
	projectKey string,
	limit int,
) ([]coordination.PeerMailEntry, error) {
	reader.projectKey, reader.limit = projectKey, limit
	return reader.entries, reader.err
}

func adminOutboxHandler(t *testing.T, outbox coordination.PeerMailQueueReader) stdhttp.Handler {
	t.Helper()
	handler, err := NewAdminHandler(AdminDependencies{Admin: &stubAdminStore{},
		Token: NewAdminTokenDigest(adminTestToken), Outbox: outbox})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

// TestAdminOutboxReportsAMissingCapabilityRatherThanAnEmptyQueue is the same
// distinction the cost route makes, and it matters more here: an operator reads
// this route to find out whether mail is stuck, and an empty queue means
// "nothing is stuck" -- the opposite of "this daemon cannot tell you".
func TestAdminOutboxReportsAMissingCapabilityRatherThanAnEmptyQueue(t *testing.T) {
	t.Parallel()

	response := getAdminCost(t, adminOutboxHandler(t, nil), PathLocalAdminOutbox+"?project_key=/repo")
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatalf("status=%d without a queue reader, want 503 rather than an empty queue: %s",
			response.Code, response.Body.String())
	}
}

func TestAdminOutboxRequiresAProject(t *testing.T) {
	t.Parallel()

	response := getAdminCost(t, adminOutboxHandler(t, &stubOutboxReader{}), PathLocalAdminOutbox)
	if response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status=%d for an outbox request naming no project, want 400", response.Code)
	}
}

// TestAdminOutboxProjectsTheDeliveryFactsAndNothingElse covers both halves of
// the payload contract: the delivery facts an operator acts on are all present,
// and the message CONTENTS are not. A queue view is for diagnosing why mail is
// stuck, not for reading it.
func TestAdminOutboxProjectsTheDeliveryFactsAndNothingElse(t *testing.T) {
	t.Parallel()

	queued := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	reader := &stubOutboxReader{entries: []coordination.PeerMailEntry{
		{
			MessageID: messageID,
			Address:   coordination.PeerAddress{Agent: "reviewer", Host: "phalls-mac-mini"},
			FromAgent: "author", State: coordination.PeerDeliveryQueued, Attempts: 2,
			LastError: "contact peer: connection refused",
			Subject:   "SECRET SUBJECT", Body: "SECRET BODY",
			QueuedAt: queued,
			// A terminal entry has no next attempt; this one does.
			NextAttemptAt: queued.Add(time.Minute),
		},
		{
			MessageID: secondID,
			Address:   coordination.PeerAddress{Agent: "ghost", Host: "phalls-mac-mini"},
			FromAgent: "author", State: coordination.PeerDeliveryUndeliverable, Attempts: 1,
			LastError: "no such agent", QueuedAt: queued,
		},
	}}
	response := getAdminCost(t, adminOutboxHandler(t, reader),
		PathLocalAdminOutbox+"?project_key=/repo&limit=5")
	if response.Code != stdhttp.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if reader.projectKey != "/repo" || reader.limit != 5 {
		t.Fatalf("query = %q limit=%d, want the project and limit from the request",
			reader.projectKey, reader.limit)
	}
	var page adminapi.OutboxPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.ProjectKey != "/repo" || len(page.Entries) != 2 {
		t.Fatalf("page = %+v", page)
	}
	first := page.Entries[0]
	if first.MessageID != messageID.String() || first.Host != "phalls-mac-mini" ||
		first.ToAgent != "reviewer" || first.FromAgent != "author" ||
		first.State != string(coordination.PeerDeliveryQueued) || first.Attempts != 2 ||
		first.LastError != "contact peer: connection refused" || first.NextAttemptAt == "" {
		t.Fatalf("entry = %+v", first)
	}
	// The zero time is reported as absent, never as the epoch: a terminal entry
	// has no next attempt, and 1970 would read as "overdue by decades".
	if page.Entries[1].NextAttemptAt != "" {
		t.Fatalf("a terminal entry named a next attempt: %q", page.Entries[1].NextAttemptAt)
	}
	if body := response.Body.String(); strings.Contains(body, "SECRET") {
		t.Fatalf("the queue view leaked message contents: %s", body)
	}
}

// TestAdminOutboxIsLoopbackOnly holds the route on the operator's side of the
// partition. It is an admin route, and peer identity is not admin authorization.
func TestAdminOutboxIsLoopbackOnly(t *testing.T) {
	t.Parallel()

	if reach := RouteReach(peerRequest(stdhttp.MethodGet, PathLocalAdminOutbox)); reach != ReachLoopback {
		t.Fatalf("RouteReach(%s) = %s, want %s", PathLocalAdminOutbox, reach, ReachLoopback)
	}
	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalAdminOutbox+"?project_key=/repo", nil)
	response := httptest.NewRecorder()
	adminOutboxHandler(t, &stubOutboxReader{}).ServeHTTP(response, request)
	if response.Code != stdhttp.StatusUnauthorized {
		t.Fatalf("status=%d without the admin token, want 401", response.Code)
	}
}
