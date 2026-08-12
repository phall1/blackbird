package companion

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
		APIBaseURL: server.URL, ClaudePath: claude, Now: func() time.Time { return time.Unix(100, 0) }})
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
	worker, err := New(Config{ProjectPath: project, AgentName: "ClaudeCode", StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.db.Exec(`INSERT INTO deliveries(message_id,conversation_id,status) VALUES('message','conversation','running')`); err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	worker, err = New(Config{ProjectPath: project, AgentName: "ClaudeCode", StateDir: state})
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
	worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state")})
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
	worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state"), ClaudePath: filepath.Join(t.TempDir(), "missing")})
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
	worker, err := New(Config{ProjectPath: t.TempDir(), AgentName: "agent", StateDir: filepath.Join(t.TempDir(), "state"), ClaudePath: filepath.Join(t.TempDir(), "missing")})
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
