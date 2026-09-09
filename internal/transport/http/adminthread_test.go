package http

import (
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

func TestAdminThreadWireContract(t *testing.T) {
	t.Parallel()
	conversation, _ := domain.NewConversationID()
	message, _ := domain.NewMessageID()
	store := &stubAdminStore{thread: coordination.AdminThreadPage{ProjectKey: "/repo", ConversationID: conversation,
		Messages: []coordination.AdminThreadMessage{{MessageID: message, Position: 9, AuthorAgentName: "alice",
			Subject: "subject", Body: "full body\nwith a second line", SentAtUS: 1000000}}, HasMore: true, Next: 9, ObservedAtUS: 2000000}}
	handler := newAdminTestHandler(t, store)
	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalAdminThread+"?project_key=/repo&conversation_id="+conversation.String()+"&after=7&limit=1", nil)
	request.Header.Set("Authorization", "Bearer "+adminTestToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var page adminapi.ThreadPage
	if response.Code != stdhttp.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
	if store.threadQuery != (coordination.AdminThreadQuery{ProjectKey: "/repo", ConversationID: conversation, After: 7, Limit: 1}) {
		t.Fatalf("query=%+v", store.threadQuery)
	}
	if page.ProjectKey != "/repo" || page.ConversationID != conversation.String() || !page.HasMore || page.Next != 9 || page.ObservedAt != "1970-01-01T00:00:02Z" {
		t.Fatalf("page=%+v", page)
	}
	want := adminapi.ThreadMessage{MessageID: message.String(), Position: 9, AuthorAgentName: "alice", Subject: "subject", Body: "full body\nwith a second line", SentAt: "1970-01-01T00:00:01Z"}
	if len(page.Messages) != 1 || page.Messages[0] != want {
		t.Fatalf("messages=%+v", page.Messages)
	}
	store.thread.Messages = nil
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), `"messages":[]`) {
		t.Fatalf("empty messages must be an array: %s", response.Body)
	}
}

func TestAdminThreadGuardsAndValidation(t *testing.T) {
	t.Parallel()
	conversation, _ := domain.NewConversationID()
	valid := "project_key=/repo&conversation_id=" + conversation.String()
	tests := []struct {
		name, query, token, remote, host string
		status                           int
	}{
		{name: "missing token", query: valid, status: stdhttp.StatusUnauthorized},
		{name: "agent token", query: valid, token: "bbm_wrong", status: stdhttp.StatusUnauthorized},
		{name: "wrong token", query: valid, token: "wrong", status: stdhttp.StatusUnauthorized},
		{name: "non loopback", query: valid, token: adminTestToken, remote: "192.0.2.1:1234", status: stdhttp.StatusForbidden},
		{name: "non loopback host", query: valid, token: adminTestToken, host: "evil.example", status: stdhttp.StatusForbidden},
		{name: "query credential", query: valid + "&access_token=" + adminTestToken, token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "missing project", query: "conversation_id=" + conversation.String(), token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "missing conversation", query: "project_key=/repo", token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "bad conversation", query: "project_key=/repo&conversation_id=bogus", token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "negative cursor", query: valid + "&after=-1", token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "empty cursor", query: valid + "&after=", token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "unsafe cursor", query: valid + "&after=9007199254740992", token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "bad cursor", query: valid + "&after=1.5", token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "zero limit", query: valid + "&limit=0", token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "oversized limit", query: valid + "&limit=257", token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "duplicate scope", query: valid + "&project_key=/other", token: adminTestToken, status: stdhttp.StatusBadRequest},
		{name: "unknown parameter", query: valid + "&agent=alice", token: adminTestToken, status: stdhttp.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &stubAdminStore{}
			request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalAdminThread+"?"+test.query, nil)
			request.Header.Set("Authorization", "Bearer "+test.token)
			if test.remote != "" {
				request.RemoteAddr = test.remote
			}
			if test.host != "" {
				request.Host = test.host
			}
			response := httptest.NewRecorder()
			newAdminTestHandler(t, store).ServeHTTP(response, request)
			if response.Code != test.status || !store.threadQuery.ConversationID.IsZero() {
				t.Fatalf("status=%d query=%+v body=%s", response.Code, store.threadQuery, response.Body)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("headers=%v", response.Header())
			}
		})
	}
}

func TestAdminThreadNotFound(t *testing.T) {
	t.Parallel()
	conversation, _ := domain.NewConversationID()
	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalAdminThread+"?project_key=/repo&conversation_id="+conversation.String(), nil)
	request.Header.Set("Authorization", "Bearer "+adminTestToken)
	response := httptest.NewRecorder()
	notFound, err := domain.NewCommandError(domain.ErrorCodeNotFound, "conversation was not found", nil)
	if err != nil {
		t.Fatal(err)
	}
	newAdminTestHandler(t, &stubAdminStore{err: notFound}).ServeHTTP(response, request)
	if response.Code != stdhttp.StatusNotFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
}
