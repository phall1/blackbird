package http

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

type logSink struct {
	mu sync.Mutex
	bytes.Buffer
}

func (sink *logSink) Write(data []byte) (int, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.Buffer.Write(data)
}

func (sink *logSink) String() string {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.Buffer.String()
}

func newLoggingSink() (*logSink, *slog.Logger) {
	sink := &logSink{}
	return sink, slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestLocalHTTPRegistrationSSEWakeAndCatchUp(t *testing.T) {
	store := openLocalHTTPStore(t, filepath.Join(t.TempDir(), "coordination.db"))
	defer func() { _ = store.Close() }()
	handler, err := NewLocalHandler(LocalDependencies{Coordination: store, PollInterval: 10 * time.Millisecond,
		Heartbeat: time.Second, WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	alice := registerLocalHTTPAgent(t, server.URL, "/workspace/project", "alice", "")
	bob := registerLocalHTTPAgent(t, server.URL, "/workspace/project", "bob", "")
	streamContext, cancelStream := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelStream()
	streamRequest, _ := stdhttp.NewRequestWithContext(streamContext, stdhttp.MethodGet,
		server.URL+PathLocalCoordinationEventsStream, nil)
	streamRequest.Header.Set("Authorization", "Bearer "+bob.RegistrationToken)
	streamRequest.Header.Set("Accept", "text/event-stream")
	streamResponse, err := server.Client().Do(streamRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = streamResponse.Body.Close() }()
	if streamResponse.StatusCode != stdhttp.StatusOK || streamResponse.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream response=%d %q", streamResponse.StatusCode, streamResponse.Header.Get("Content-Type"))
	}

	aliceSession, err := store.AuthenticateLocalAgent(context.Background(), alice.RegistrationToken)
	if err != nil {
		t.Fatal(err)
	}
	bobSession, err := store.AuthenticateLocalAgent(context.Background(), bob.RegistrationToken)
	if err != nil {
		t.Fatal(err)
	}
	conversationID, _ := domain.NewConversationID()
	if _, err = store.OpenConversation(context.Background(), application.OpenConversationParams{ConversationID: conversationID,
		WorkspaceID: aliceSession.WorkspaceID, RunID: aliceSession.RunID, OpenedBy: aliceSession.ActorID,
		OpenedBySession: aliceSession.ActorSessionID, Topic: "HTTP E2E"}); err != nil {
		t.Fatal(err)
	}
	recipient, _ := application.NewRecipient(bobSession.ActorID, application.RecipientTo)
	messageID, _ := domain.NewMessageID()
	if _, err = store.SendMessage(context.Background(), application.SendMessageParams{MessageID: messageID,
		ConversationID: conversationID, WorkspaceID: aliceSession.WorkspaceID, Author: aliceSession.ActorID,
		AuthorSession: aliceSession.ActorSessionID, Subject: "wake", Body: "durable", Recipients: []application.Recipient{recipient}}); err != nil {
		t.Fatal(err)
	}

	wakeup := readLocalWakeup(t, streamResponse.Body)
	request, _ := stdhttp.NewRequest(stdhttp.MethodGet, server.URL+PathLocalCoordinationEvents+"?after=&limit=1", nil)
	request.Header.Set("Authorization", "Bearer "+bob.RegistrationToken)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var page localCoordinationEventsPage
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != stdhttp.StatusOK || len(page.Events) != 1 || page.Events[0].Type != application.CoordinationEventMessageAvailable ||
		page.Events[0].Subject != messageID.String() || page.NextCursor != wakeup.Cursor {
		t.Fatalf("catch-up response=%d page=%+v wakeup=%+v", response.StatusCode, page, wakeup)
	}
}

func TestLocalHTTPAuthorizationHostAndQuerySafety(t *testing.T) {
	store := openLocalHTTPStore(t, filepath.Join(t.TempDir(), "coordination.db"))
	defer func() { _ = store.Close() }()
	handler, err := NewLocalHandler(LocalDependencies{Coordination: store})
	if err != nil {
		t.Fatal(err)
	}
	token := registerLocalHTTPDirect(t, handler).RegistrationToken

	for name, target := range map[string]string{
		"events missing bearer":  PathLocalCoordinationEvents,
		"message missing bearer": PathLocalMessages + "01900000-0000-7000-8000-000000000001",
	} {
		t.Run(name, func(t *testing.T) {
			request := newLocalHTTPRequest(stdhttp.MethodGet, target, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != stdhttp.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("safety headers=%v", response.Header())
			}
		})
	}
	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalCoordinationEvents+"?token="+url.QueryEscape(token), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("query token status=%d", response.Code)
	}
	request = newLocalHTTPRequest(stdhttp.MethodGet, PathLocalMessages+"01900000-0000-7000-8000-000000000001?access_token="+
		url.QueryEscape(token), nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("message query token status=%d", response.Code)
	}
	request = newLocalHTTPRequest(stdhttp.MethodGet, PathLocalCoordinationEvents, nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusForbidden {
		t.Fatalf("non-loopback status=%d", response.Code)
	}
	var forbidden localProblem
	if err := json.NewDecoder(response.Body).Decode(&forbidden); err != nil || forbidden.Code != domain.ErrorCodeForbidden {
		t.Fatalf("non-loopback problem=%+v error=%v", forbidden, err)
	}

	request = newLocalHTTPRequest(stdhttp.MethodGet, PathLocalCoordinationEvents+"?after=&limit=1&limit=2", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusBadRequest {
		t.Fatalf("duplicate query status=%d", response.Code)
	}
}

func TestLocalHTTPMessageFetchExactAndPrivate(t *testing.T) {
	store := openLocalHTTPStore(t, filepath.Join(t.TempDir(), "coordination.db"))
	defer func() { _ = store.Close() }()
	handler, err := NewLocalHandler(LocalDependencies{Coordination: store})
	if err != nil {
		t.Fatal(err)
	}
	alice := registerLocalHTTPAgentSession(t, store, handler, "/workspace/project", "alice")
	bob := registerLocalHTTPAgentSession(t, store, handler, "/workspace/project", "bob")
	charlie := registerLocalHTTPAgentSession(t, store, handler, "/workspace/project", "charlie")
	outsider := registerLocalHTTPAgentSession(t, store, handler, "/workspace/project", "outsider")

	conversationID, _ := domain.NewConversationID()
	if _, err := store.OpenConversation(context.Background(), application.OpenConversationParams{ConversationID: conversationID,
		WorkspaceID: alice.session.WorkspaceID, RunID: alice.session.RunID, OpenedBy: alice.session.ActorID,
		OpenedBySession: alice.session.ActorSessionID, Topic: "direct fetch"}); err != nil {
		t.Fatal(err)
	}
	bobRecipient, _ := application.NewRecipient(bob.session.ActorID, application.RecipientTo)
	charlieRecipient, _ := application.NewRecipient(charlie.session.ActorID, application.RecipientBcc)
	parentID, _ := domain.NewMessageID()
	if _, err := store.SendMessage(context.Background(), application.SendMessageParams{MessageID: parentID,
		ConversationID: conversationID, WorkspaceID: alice.session.WorkspaceID, Author: alice.session.ActorID,
		AuthorSession: alice.session.ActorSessionID, Subject: "parent", Body: "first", Recipients: []application.Recipient{bobRecipient}}); err != nil {
		t.Fatal(err)
	}
	messageID, _ := domain.NewMessageID()
	sent, err := store.SendMessage(context.Background(), application.SendMessageParams{MessageID: messageID,
		ConversationID: conversationID, WorkspaceID: alice.session.WorkspaceID, Author: alice.session.ActorID,
		AuthorSession: alice.session.ActorSessionID, Subject: "handoff", Body: "exact durable body",
		ReplyTo: &parentID, Recipients: []application.Recipient{bobRecipient, charlieRecipient}, AcknowledgementRequired: true})
	if err != nil {
		t.Fatal(err)
	}

	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalMessages+messageID.String(), nil)
	request.Header.Set("Authorization", "Bearer "+bob.response.RegistrationToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var output localMessage
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	digest := sent.Digest()
	if response.Code != stdhttp.StatusOK || output.MessageID != messageID.String() ||
		output.ConversationID != conversationID.String() || output.AuthorActorID != alice.session.ActorID.String() ||
		output.Subject != "handoff" || output.Body != "exact durable body" || output.BodyDigest != hex.EncodeToString(digest[:]) ||
		output.ReplyTo != parentID.String() || output.SentAt != sent.SentAt().Format(time.RFC3339Nano) ||
		output.Position != sent.Position() || len(output.Deliveries) != 1 ||
		output.Deliveries[0] != (localDelivery{RecipientActorID: bob.session.ActorID.String(), Kind: "to"}) {
		t.Fatalf("fetch status=%d output=%+v", response.Code, output)
	}

	missingID, _ := domain.NewMessageID()
	var hiddenBody string
	for index, id := range []string{messageID.String(), missingID.String(), "not-a-message-id"} {
		request = newLocalHTTPRequest(stdhttp.MethodGet, PathLocalMessages+id, nil)
		request.Header.Set("Authorization", "Bearer "+outsider.response.RegistrationToken)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != stdhttp.StatusNotFound {
			t.Fatalf("private fetch %d status=%d body=%s", index, response.Code, response.Body.String())
		}
		body := response.Body.String()
		var problem localProblem
		if err := json.Unmarshal([]byte(body), &problem); err != nil || problem.Code != domain.ErrorCodeNotFound {
			t.Fatalf("private fetch %d problem=%+v error=%v", index, problem, err)
		}
		if index == 0 {
			hiddenBody = body
		} else if body != hiddenBody {
			t.Fatalf("hidden and absent responses differ: hidden=%q absent=%q", hiddenBody, body)
		}
	}
}

type localHTTPAgent struct {
	response localRegisterResponse
	session  application.LocalAgentSession
}

func registerLocalHTTPAgentSession(t *testing.T, store application.LocalCoordinationStore, handler stdhttp.Handler,
	project, agent string) localHTTPAgent {
	t.Helper()
	body, _ := json.Marshal(localRegisterRequest{ProjectKey: project, AgentName: agent})
	request := newLocalHTTPRequest(stdhttp.MethodPost, PathLocalAgentRegister, bytes.NewReader(body))
	request.Header.Set("Content-Type", mediaTypeJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var registered localRegisterResponse
	if err := json.NewDecoder(response.Body).Decode(&registered); err != nil || response.Code != stdhttp.StatusOK {
		t.Fatalf("registration status=%d response=%+v error=%v", response.Code, registered, err)
	}
	authenticated, err := store.AuthenticateLocalAgent(context.Background(), registered.RegistrationToken)
	if err != nil {
		t.Fatal(err)
	}
	return localHTTPAgent{response: registered, session: authenticated}
}

func TestLocalHTTPRegistrationResumeSurvivesStoreRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordination.db")
	store := openLocalHTTPStore(t, path)
	handler, _ := NewLocalHandler(LocalDependencies{Coordination: store})
	first := registerLocalHTTPDirect(t, handler)
	cursorRequest := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalCoordinationEvents+"?limit=1", nil)
	cursorRequest.Header.Set("Authorization", "Bearer "+first.RegistrationToken)
	cursorResponse := httptest.NewRecorder()
	handler.ServeHTTP(cursorResponse, cursorRequest)
	var initialPage localCoordinationEventsPage
	if err := json.NewDecoder(cursorResponse.Body).Decode(&initialPage); err != nil || initialPage.NextCursor == "" {
		t.Fatalf("initial cursor page=%+v error=%v", initialPage, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openLocalHTTPStore(t, path)
	defer func() { _ = store.Close() }()
	handler, _ = NewLocalHandler(LocalDependencies{Coordination: store})
	body, _ := json.Marshal(localRegisterRequest{ProjectKey: first.ProjectKey, AgentName: first.AgentName,
		RegistrationToken: &first.RegistrationToken})
	request := newLocalHTTPRequest(stdhttp.MethodPost, PathLocalAgentRegister, bytes.NewReader(body))
	request.Header.Set("Content-Type", mediaTypeJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var resumed localRegisterResponse
	if err := json.NewDecoder(response.Body).Decode(&resumed); err != nil {
		t.Fatal(err)
	}
	if response.Code != stdhttp.StatusOK || resumed.ActorID != first.ActorID || resumed.SessionID == first.SessionID || resumed.RegistrationToken != "" {
		t.Fatalf("resumed status=%d response=%+v first=%+v", response.Code, resumed, first)
	}

	request = newLocalHTTPRequest(stdhttp.MethodGet, PathLocalCoordinationEvents+"?after="+
		url.QueryEscape(initialPage.NextCursor)+"&limit=1", nil)
	request.Header.Set("Authorization", "Bearer "+first.RegistrationToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusOK {
		t.Fatalf("restarted bearer status=%d body=%s", response.Code, response.Body.String())
	}
}

func openLocalHTTPStore(t *testing.T, path string) *sqlite.Store {
	t.Helper()
	store, err := sqlite.Open(context.Background(), sqlite.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func registerLocalHTTPAgent(t *testing.T, baseURL, project, agent, registrationToken string) localRegisterResponse {
	t.Helper()
	input := localRegisterRequest{ProjectKey: project, AgentName: agent}
	if registrationToken != "" {
		input.RegistrationToken = &registrationToken
	}
	body, _ := json.Marshal(input)
	response, err := stdhttp.Post(baseURL+PathLocalAgentRegister, mediaTypeJSON, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var result localRegisterResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != stdhttp.StatusOK || result.RegistrationToken == "" {
		t.Fatalf("registration status=%d result=%+v", response.StatusCode, result)
	}
	return result
}

func registerLocalHTTPDirect(t *testing.T, handler stdhttp.Handler) localRegisterResponse {
	t.Helper()
	body := strings.NewReader(`{"project_key":"/workspace/project","agent_name":"agent"}`)
	request := newLocalHTTPRequest(stdhttp.MethodPost, PathLocalAgentRegister, body)
	request.Header.Set("Content-Type", mediaTypeJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var result localRegisterResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.Code != stdhttp.StatusOK || result.RegistrationToken == "" {
		t.Fatalf("registration status=%d result=%+v", response.Code, result)
	}
	return result
}

func newLocalHTTPRequest(method, target string, body io.Reader) *stdhttp.Request {
	request := httptest.NewRequest(method, target, body)
	request.Host = "localhost"
	request.RemoteAddr = "127.0.0.1:1234"
	return request
}

func readLocalWakeup(t *testing.T, body io.Reader) localWakeup {
	t.Helper()
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "data: ") {
			continue
		}
		var result localWakeup
		if err := json.Unmarshal([]byte(strings.TrimPrefix(scanner.Text(), "data: ")), &result); err != nil {
			t.Fatal(err)
		}
		if result.Cursor == "" {
			t.Fatal("SSE wakeup omitted cursor")
		}
		return result
	}
	t.Fatalf("stream ended before wakeup: %v", scanner.Err())
	return localWakeup{}
}

func TestLocalTransportRecordsAccessAndPreservesDiscardedCauses(t *testing.T) {
	store := openLocalHTTPStore(t, filepath.Join(t.TempDir(), "coordination.db"))
	sink, logger := newLoggingSink()
	handler, err := NewLocalHandler(LocalDependencies{Coordination: store, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	agent := registerLocalHTTPDirect(t, handler)
	if logged := sink.String(); !strings.Contains(logged, `msg="local request"`) ||
		!strings.Contains(logged, "path="+PathLocalAgentRegister) ||
		!strings.Contains(logged, "status=200") || !strings.Contains(logged, "duration_ms=") {
		t.Fatalf("registration access record missing:\n%s", logged)
	}
	if strings.Contains(sink.String(), agent.RegistrationToken) {
		t.Fatalf("access record leaked the registration token:\n%s", sink.String())
	}

	// A closed store makes every coordination call fail with a wrapped cause the
	// sanitized local problem is required to drop.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalCoordinationEvents, nil)
	request.Header.Set("Authorization", "Bearer "+agent.RegistrationToken)
	request.Header.Set(headerRequestID, "req-local-supplied")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code == stdhttp.StatusOK {
		t.Fatalf("closed store answered %d", response.Code)
	}
	logged := sink.String()
	if !strings.Contains(logged, `msg="local operation failed"`) ||
		!strings.Contains(logged, "operation=agent.authenticate") {
		t.Fatalf("failure record missing:\n%s", logged)
	}
	if !strings.Contains(logged, "request_id=req-local-supplied") {
		t.Fatalf("supplied correlation id was not honored:\n%s", logged)
	}
	if strings.Contains(response.Body.String(), "sql") || strings.Contains(response.Body.String(), "closed") {
		t.Fatalf("client body disclosed the cause: %s", response.Body.String())
	}
}

func TestLocalAccessRecordRejectsAnInvalidInboundRequestID(t *testing.T) {
	store := openLocalHTTPStore(t, filepath.Join(t.TempDir(), "coordination.db"))
	defer func() { _ = store.Close() }()
	sink, logger := newLoggingSink()
	handler, err := NewLocalHandler(LocalDependencies{Coordination: store, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	request := newLocalHTTPRequest(stdhttp.MethodGet, PathLocalCoordinationEvents, nil)
	request.Header.Set(headerRequestID, "req local supplied")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	logged := sink.String()
	if strings.Contains(logged, "req local supplied") {
		t.Fatalf("access record accepted a request id the error contract rejects:\n%s", logged)
	}
	if !strings.Contains(logged, "request_id=req_") || !strings.Contains(logged, "status=401") {
		t.Fatalf("access record missing a minted id or the rejection status:\n%s", logged)
	}
}
