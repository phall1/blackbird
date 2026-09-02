package cli

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestHookDeliversAndPersistsCursor(t *testing.T) {
	t.Parallel()

	var lock sync.Mutex
	registrations := 0
	eventCursors := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		switch request.URL.Path {
		case "/api/v1/local/agents/register":
			registrations++
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if registrations == 1 {
				if _, exists := body["registration_token"]; exists {
					t.Errorf("first registration sent a token: %v", body)
				}
				writeHookFixture(writer, map[string]any{"registration_token": "bbm_test"})
				return
			}
			if body["registration_token"] != "bbm_test" {
				t.Errorf("resumed registration = %v", body)
			}
			writeHookFixture(writer, map[string]any{})
		case "/api/v1/local/coordination/events":
			if request.Header.Get("Authorization") != "Bearer bbm_test" {
				t.Errorf("authorization = %q", request.Header.Get("Authorization"))
			}
			eventCursors = append(eventCursors, request.URL.Query().Get("after"))
			if len(eventCursors) == 1 {
				writeHookFixture(writer, map[string]any{"events": []map[string]any{{
					"type": "message.available", "subject": "message-1",
				}}, "next_cursor": "cursor-1", "has_more": false})
				return
			}
			writeHookFixture(writer, map[string]any{"events": []any{}, "next_cursor": "cursor-2", "has_more": false})
		case "/api/v1/local/messages/message-1":
			writeHookFixture(writer, map[string]any{
				"message_id": "message-1", "conversation_id": "conversation-1", "author_actor_id": "actor-1",
				"subject": "handoff", "body": "tests are green",
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	stateDir := t.TempDir()
	input := `{"hook_event_name":"UserPromptSubmit","cwd":"/workspace/project"}`
	firstOut, firstErr := &strings.Builder{}, &strings.Builder{}
	code := Run(context.Background(), Dependencies{Input: strings.NewReader(input)}, []string{
		"hook", "claude", "--api-url=" + server.URL, "--state-dir=" + stateDir,
	}, firstOut, firstErr)
	if code != ExitOK || firstErr.Len() != 0 {
		t.Fatalf("first code=%d stderr=%q", code, firstErr.String())
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(firstOut.String()), &first); err != nil {
		t.Fatal(err)
	}
	specific := first["hookSpecificOutput"].(map[string]any)
	if specific["hookEventName"] != "UserPromptSubmit" ||
		!strings.Contains(specific["additionalContext"].(string), "tests are green") {
		t.Fatalf("output = %#v", first)
	}

	stateFiles, err := filepath.Glob(filepath.Join(stateDir, "claude", "*.json"))
	if err != nil || len(stateFiles) != 1 {
		t.Fatalf("state files=%v error=%v", stateFiles, err)
	}
	info, err := os.Stat(stateFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != fs.FileMode(0o600) {
		t.Fatalf("state mode=%v", mode)
	}
	directory, err := os.Stat(filepath.Dir(stateFiles[0]))
	if err != nil {
		t.Fatal(err)
	}
	if mode := directory.Mode().Perm(); mode != fs.FileMode(0o700) {
		t.Fatalf("state directory mode=%v", mode)
	}

	secondOut, secondErr := &strings.Builder{}, &strings.Builder{}
	code = Run(context.Background(), Dependencies{Input: strings.NewReader(input)}, []string{
		"hook", "claude", "--api-url=" + server.URL, "--state-dir=" + stateDir,
	}, secondOut, secondErr)
	if code != ExitOK || secondErr.Len() != 0 || secondOut.String() != "{}\n" {
		t.Fatalf("second code=%d stdout=%q stderr=%q", code, secondOut.String(), secondErr.String())
	}
	lock.Lock()
	defer lock.Unlock()
	if registrations != 2 || len(eventCursors) != 2 || eventCursors[0] != "" || eventCursors[1] != "cursor-1" {
		t.Fatalf("registrations=%d cursors=%v", registrations, eventCursors)
	}
}

func TestHookOutputContracts(t *testing.T) {
	t.Parallel()
	message := []hookMessage{{MessageID: "m1", ConversationID: "c1", AuthorActorID: "a1", Subject: "subject", Body: "body"}}
	tests := []struct {
		host string
		want string
	}{
		{host: "claude", want: `"hookSpecificOutput"`},
		{host: "cursor", want: `"additional_context"`},
		{host: "copilot", want: `"additionalContext"`},
	}
	for _, testCase := range tests {
		t.Run(testCase.host, func(t *testing.T) {
			var output strings.Builder
			if err := writeHookOutput(&output, testCase.host, "SessionStart", message); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), testCase.want) || !strings.Contains(output.String(), "body") {
				t.Fatalf("output=%s", output.String())
			}
		})
	}
}

func TestHookRejectsCredentialExfiltrationOrigins(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"https://127.0.0.1:8080", "http://example.com:8080", "http://user@127.0.0.1:8080"} {
		if _, err := hookOrigin(raw); err == nil {
			t.Errorf("hookOrigin(%q) succeeded", raw)
		}
	}
}

func TestHookFailsOpenWhenDaemonIsUnavailable(t *testing.T) {
	t.Parallel()
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	code := Run(context.Background(), Dependencies{Input: strings.NewReader(`{"cwd":"/repo"}`)}, []string{
		"hook", "cursor", "--api-url=http://127.0.0.1:1", "--state-dir=" + t.TempDir(),
	}, stdout, stderr)
	if code != ExitOK || stdout.String() != "{}\n" || !strings.Contains(stderr.String(), "register agent") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func writeHookFixture(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}
