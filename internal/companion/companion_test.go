package companion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		config Config
	}{
		{name: "empty", config: Config{}},
		{name: "missing project", config: Config{ProjectPath: filepath.Join(t.TempDir(), "missing"), AgentName: "agent", StateDir: t.TempDir()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if worker, err := New(test.config); err == nil {
				_ = worker.Close()
				t.Fatal("New() accepted invalid configuration")
			}
		})
	}
}

func TestDeliveryUsesSessionIDThenResumeAndPersistsEvidence(t *testing.T) {
	project := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	claude := filepath.Join(t.TempDir(), "claude")
	logPath := filepath.Join(t.TempDir(), "claude.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CLAUDE_TEST_LOG\"\nprintf '{\"result\":\"ok\"}'\n"
	if err := os.WriteFile(claude, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_TEST_LOG", logPath)
	messages := map[string]message{
		"m1": {MessageID: "m1", ConversationID: "conversation", Subject: "first", Body: "body one"},
		"m2": {MessageID: "m2", ConversationID: "conversation", Subject: "second", Body: "body two"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, messagesPath) {
			_ = json.NewEncoder(writer).Encode(messages[strings.TrimPrefix(request.URL.Path, messagesPath)])
			return
		}
		http.NotFound(writer, request)
	}))
	defer server.Close()
	worker, err := New(Config{ProjectPath: project, AgentName: "ClaudeCode", StateDir: state,
		APIBaseURL: server.URL, Harness: HarnessClaude, Executable: claude, Now: func() time.Time { return time.Unix(100, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	worker.token = "token"
	for _, id := range []string{"m1", "m2"} {
		if _, err := worker.db.Exec(`INSERT INTO deliveries(message_id,conversation_id,status) VALUES(?, '', 'pending')`, id); err != nil {
			t.Fatal(err)
		}
		if err := worker.deliver(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(log)
	if strings.Count(logged, "-p ") != 2 || !strings.Contains(logged, "--session-id") || !strings.Contains(logged, "Blackbird durable message ID: m1") ||
		!strings.Contains(logged, "--resume") || !strings.Contains(logged, "Blackbird durable message ID: m2") {
		t.Fatalf("Claude invocations = %q", logged)
	}
	for _, id := range []string{"m1", "m2"} {
		var status, transcript string
		if err := worker.db.QueryRow(`SELECT status,transcript_path FROM deliveries WHERE message_id=?`, id).Scan(&status, &transcript); err != nil {
			t.Fatal(err)
		}
		if status != "delivered" {
			t.Fatalf("%s status = %s", id, status)
		}
		if info, err := os.Stat(transcript); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("transcript permissions: info=%v err=%v", info, err)
		}
	}
}

func TestNewQuarantinesCrashAmbiguityAndSecuresState(t *testing.T) {
	project := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	worker, err := New(Config{ProjectPath: project, AgentName: "ClaudeCode", StateDir: state, Harness: HarnessClaude})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.db.Exec(`INSERT INTO deliveries(message_id,conversation_id,status) VALUES('message','conversation','running')`); err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	worker, err = New(Config{ProjectPath: project, AgentName: "ClaudeCode", StateDir: state, Harness: HarnessClaude})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	var status string
	if err := worker.db.QueryRow(`SELECT status FROM deliveries WHERE message_id='message'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "ambiguous" {
		t.Fatalf("status = %s", status)
	}
	if info, err := os.Stat(state); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("state permissions: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(filepath.Join(state, "deliveries.db")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("database permissions: info=%v err=%v", info, err)
	}
}

func TestSessionBindingIsDurable(t *testing.T) {
	worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state"), Harness: HarnessClaude})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	first, initialized, err := worker.session("conversation")
	if err != nil || initialized {
		t.Fatalf("first session = %q, %t, %v", first, initialized, err)
	}
	second, initialized, err := worker.session("conversation")
	if err != nil || initialized || second != first {
		t.Fatalf("second session = %q, %t, %v", second, initialized, err)
	}
	if err := worker.db.QueryRow(`SELECT session_id FROM sessions WHERE conversation_id='conversation'`).Scan(new(string)); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
}

func TestStartFailureRetriesWithSessionID(t *testing.T) {
	worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state"), Harness: HarnessClaude, Executable: filepath.Join(t.TempDir(), "missing")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(message{MessageID: "message", ConversationID: "conversation", Body: "body"})
	}))
	defer server.Close()
	worker.config.APIBaseURL = server.URL
	worker.token = "token"
	if _, err := worker.db.Exec(`INSERT INTO deliveries(message_id,conversation_id,status) VALUES('message','','pending')`); err != nil {
		t.Fatal(err)
	}
	if err := worker.deliver(context.Background(), "message"); err == nil {
		t.Fatal("missing Claude executable did not fail")
	}
	_, initialized, err := worker.session("conversation")
	if err != nil || initialized {
		t.Fatalf("session initialized after start failure: initialized=%t err=%v", initialized, err)
	}
}

func TestProcessReadyStopsAfterFailureToPreserveOrder(t *testing.T) {
	worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state"), Harness: HarnessClaude, Executable: filepath.Join(t.TempDir(), "missing")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		id := strings.TrimPrefix(request.URL.Path, messagesPath)
		_ = json.NewEncoder(writer).Encode(message{MessageID: id, ConversationID: "conversation", Body: id})
	}))
	defer server.Close()
	worker.config.APIBaseURL = server.URL
	worker.token = "token"
	for _, id := range []string{"first", "second"} {
		if _, err := worker.db.Exec(`INSERT INTO deliveries(message_id,conversation_id,status) VALUES(?,'','pending')`, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := worker.processReady(context.Background()); err == nil {
		t.Fatal("processReady did not report first delivery failure")
	}
	var first, second string
	if err := worker.db.QueryRow(`SELECT status FROM deliveries WHERE message_id='first'`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := worker.db.QueryRow(`SELECT status FROM deliveries WHERE message_id='second'`).Scan(&second); err != nil {
		t.Fatal(err)
	}
	if first != "retry" || second != "pending" {
		t.Fatalf("delivery statuses = first:%s second:%s", first, second)
	}
}

func TestRegistrationTokenPersistsAndIsReusedAfterRestart(t *testing.T) {
	project := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	var payloads []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != registerPath {
			http.NotFound(writer, request)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		payloads = append(payloads, payload)
		_ = json.NewEncoder(writer).Encode(registration{RegistrationToken: "durable-token"})
	}))
	defer server.Close()

	for range 2 {
		worker, err := New(Config{ProjectPath: project, AgentName: "agent", StateDir: state, APIBaseURL: server.URL, Harness: HarnessClaude})
		if err != nil {
			t.Fatal(err)
		}
		if err := worker.register(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := worker.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(payloads) != 2 {
		t.Fatalf("registration requests = %d, want 2", len(payloads))
	}
	if _, sent := payloads[0]["registration_token"]; sent {
		t.Fatalf("first registration unexpectedly resumed: %#v", payloads[0])
	}
	if payloads[1]["registration_token"] != "durable-token" {
		t.Fatalf("second registration did not resume: %#v", payloads[1])
	}
}

func TestCatchUpPaginatesFiltersAndPersistsCursorAtomically(t *testing.T) {
	worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state"), Harness: HarnessClaude})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	worker.token = "secret"

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer secret" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		page := eventPage{NextCursor: "cursor-2"}
		switch request.URL.Query().Get("after") {
		case "":
			page.NextCursor, page.HasMore = "cursor-1", true
			page.Events = append(page.Events,
				struct {
					Type    string `json:"type"`
					Subject string `json:"subject"`
				}{Type: "message.available", Subject: "message-1"},
				struct {
					Type    string `json:"type"`
					Subject string `json:"subject"`
				}{Type: "message.read", Subject: "ignored"},
			)
		case "cursor-1":
			page.Events = append(page.Events,
				struct {
					Type    string `json:"type"`
					Subject string `json:"subject"`
				}{Type: "message.available", Subject: "message-1"},
				struct {
					Type    string `json:"type"`
					Subject string `json:"subject"`
				}{Type: "message.available", Subject: "message-2"},
			)
		default:
			t.Errorf("unexpected cursor %q", request.URL.Query().Get("after"))
		}
		_ = json.NewEncoder(writer).Encode(page)
	}))
	defer server.Close()
	worker.config.APIBaseURL = server.URL

	if err := worker.catchUp(context.Background()); err != nil {
		t.Fatal(err)
	}
	var deliveries int
	if err := worker.db.QueryRow(`SELECT count(*) FROM deliveries`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	var cursor string
	if err := worker.db.QueryRow(`SELECT value FROM metadata WHERE key='cursor'`).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || deliveries != 2 || cursor != "cursor-2" {
		t.Fatalf("requests=%d deliveries=%d cursor=%q", requests, deliveries, cursor)
	}
}

func TestRetryBackoffTerminatesAfterMaximumAttempts(t *testing.T) {
	now := time.Unix(1_000, 0).UTC()
	worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state"), Harness: HarnessClaude, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	if _, err := worker.db.Exec(`INSERT INTO deliveries(message_id,conversation_id,status) VALUES('message','','pending')`); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		cause := errors.New("delivery failed")
		if err := worker.retry("message", cause); !errors.Is(err, cause) {
			t.Fatalf("retry %d error = %v", attempt, err)
		}
	}
	var status, next string
	var attempts int
	if err := worker.db.QueryRow(`SELECT status,attempts,next_attempt_at FROM deliveries WHERE message_id='message'`).Scan(&status, &attempts, &next); err != nil {
		t.Fatal(err)
	}
	wantNext := now.Add(32 * time.Second).Format(time.RFC3339Nano)
	if status != "failed" || attempts != maxAttempts || next != wantNext {
		t.Fatalf("status=%s attempts=%d next=%s, want failed/%d/%s", status, attempts, next, maxAttempts, wantNext)
	}
}

func TestWaitForWakeAuthenticatesAndHandlesStreamOutcomes(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		body       string
		wantError  bool
		wantBearer bool
	}{
		{name: "wake", status: http.StatusOK, body: "event: wake\ndata: available\n\n", wantBearer: true},
		{name: "closed without wake", status: http.StatusOK, body: "event: keepalive\n\n"},
		{name: "server failure", status: http.StatusServiceUnavailable, body: "offline", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var bearer string
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				bearer = request.Header.Get("Authorization")
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state"), APIBaseURL: server.URL, Harness: HarnessClaude})
			if err != nil {
				t.Fatal(err)
			}
			defer worker.Close()
			worker.token = "secret"
			err = worker.waitForWake(context.Background())
			if (err != nil) != test.wantError {
				t.Fatalf("waitForWake() error = %v", err)
			}
			if test.wantBearer && bearer != "Bearer secret" {
				t.Fatalf("Authorization = %q", bearer)
			}
		})
	}
}

func TestCanceledClaudeExecutionIsQuarantinedAsAmbiguous(t *testing.T) {
	claude := filepath.Join(t.TempDir(), "claude")
	if err := os.WriteFile(claude, []byte("#!/bin/sh\nsleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(message{MessageID: "message", ConversationID: "conversation", Body: "body"})
	}))
	defer server.Close()
	worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state"), Harness: HarnessClaude, Executable: claude, APIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	worker.token = "secret"
	if _, err := worker.db.Exec(`INSERT INTO deliveries(message_id,conversation_id,status) VALUES('message','','pending')`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := worker.deliver(ctx, "message"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deliver() error = %v, want deadline exceeded", err)
	}
	var status, lastError string
	if err := worker.db.QueryRow(`SELECT status,last_error FROM deliveries WHERE message_id='message'`).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "ambiguous" || !strings.Contains(lastError, "outcome is unknown") {
		t.Fatalf("status=%q last_error=%q", status, lastError)
	}
}

func TestPiDeliveryUsesExactSessionIDForEveryTurn(t *testing.T) {
	project := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	pi := filepath.Join(t.TempDir(), "pi")
	logPath := filepath.Join(t.TempDir(), "pi.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$PI_TEST_LOG\"\nprintf '{\"type\":\"agent_end\"}\\n'\n"
	if err := os.WriteFile(pi, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PI_TEST_LOG", logPath)
	messages := map[string]message{
		"m1": {MessageID: "m1", ConversationID: "conversation", Body: "body one"},
		"m2": {MessageID: "m2", ConversationID: "conversation", Body: "body two"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(messages[strings.TrimPrefix(request.URL.Path, messagesPath)])
	}))
	defer server.Close()
	worker, err := New(Config{ProjectPath: project, AgentName: "Pi", StateDir: state, APIBaseURL: server.URL,
		Harness: HarnessPi, Executable: pi, Now: func() time.Time { return time.Unix(100, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	worker.token = "token"
	for _, id := range []string{"m1", "m2"} {
		if _, err := worker.db.Exec(`INSERT INTO deliveries(message_id,conversation_id,status) VALUES(?, '', 'pending')`, id); err != nil {
			t.Fatal(err)
		}
		if err := worker.deliver(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(logged), "-p --approve") != 2 || strings.Contains(string(logged), "--resume") || strings.Count(string(logged), "--session-id") != 2 ||
		strings.Count(string(logged), "--session-dir "+filepath.Join(state, "sessions")) != 2 || strings.Count(string(logged), "--approve") != 2 {
		t.Fatalf("Pi invocations = %q", logged)
	}
}
