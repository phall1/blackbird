package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/cli"
)

func writeHandshake(t *testing.T, address, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.json")
	record := handshake{Schema: handshakeSchema, HTTPAddress: address, Token: token, PID: 4242, Version: "0.4.0"}
	content, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type recordedRequest struct {
	path  string
	query url.Values
	token string
}

func serve(t *testing.T, handler func(recordedRequest) (int, string)) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	var seen []recordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		record := recordedRequest{
			path:  request.URL.Path,
			query: request.URL.Query(),
			token: strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "),
		}
		seen = append(seen, record)
		status, body := handler(record)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, &seen
}

func addressOf(t *testing.T, server *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(server.URL, "http://")
}

func TestHealthCombinesLivenessAndReadiness(t *testing.T) {
	t.Parallel()

	server, _ := serve(t, func(request recordedRequest) (int, string) {
		switch request.path {
		case pathHealth:
			return http.StatusOK, `{"status":"ok","version":"0.4.0"}`
		case pathReady:
			return http.StatusOK, `{"status":"ready","storage":"ok","schema_version":4}`
		default:
			return http.StatusNotFound, `{}`
		}
	})

	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	health, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() = %v", err)
	}
	if !health.Reachable || !health.Ready || health.Version != "0.4.0" || health.SchemaVersion != 4 {
		t.Fatalf("health = %#v", health)
	}
}

func TestHealthReportsAReachableDaemonWithFailingStorage(t *testing.T) {
	t.Parallel()

	server, _ := serve(t, func(request recordedRequest) (int, string) {
		if request.path == pathHealth {
			return http.StatusOK, `{"status":"ok","version":"0.4.0"}`
		}
		return http.StatusServiceUnavailable, `{"code":"DEPENDENCY_UNAVAILABLE"}`
	})

	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	health, err := client.Health(context.Background())
	// The readiness probe was refused, so the caller is told the probe did not
	// complete — and still reads that the daemon itself answered.
	if err == nil {
		t.Fatal("Health() = nil, want the refusal reported")
	}
	if !health.Reachable || health.Ready {
		t.Fatalf("health = %#v, want reachable but not ready", health)
	}
	if !strings.Contains(health.Detail, "storage") {
		t.Fatalf("detail = %q", health.Detail)
	}
}

// A refused connection must reach the caller as an error. Returning nil made a
// dead daemon indistinguishable from a live one whose storage had failed, and
// doctor diagnosed it as the second: it printed the connection error under
// "daemon answered but storage is unavailable" and sent the user to inspect the
// database schema.
func TestHealthOnConnectionRefused(t *testing.T) {
	t.Parallel()

	client := New(writeHandshake(t, "127.0.0.1:1", "bba_token"), "")
	health, err := client.Health(context.Background())
	if err == nil {
		t.Fatal("Health() = nil, want the failed probe reported as an error")
	}
	if health.Reachable || health.Detail == "" {
		t.Fatalf("health = %#v", health)
	}
	if health.Address != "127.0.0.1:1" {
		t.Fatalf("health.Address = %q, want the address the probe used", health.Address)
	}
}

func TestQueriesCarryTheWireParameterNames(t *testing.T) {
	t.Parallel()

	server, seen := serve(t, func(request recordedRequest) (int, string) {
		if request.path == pathOverview || request.path == pathIdentity {
			return http.StatusOK, `{}`
		}
		return http.StatusOK, `{"agents":[],"conversations":[],"reservations":[],"events":[],"projects":[],"summaries":[]}`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	ctx := context.Background()

	if _, err := client.Agents(ctx, cli.AgentQuery{ProjectKey: "/a", AgentName: "scout", Limit: 10}); err != nil {
		t.Fatalf("Agents() = %v", err)
	}
	if _, err := client.Inbox(ctx, cli.InboxQuery{ProjectKey: "/a", AgentName: "scout"}); err != nil {
		t.Fatalf("Inbox() = %v", err)
	}
	if _, err := client.Conversations(ctx, cli.ConversationQuery{ConversationID: "c1"}); err != nil {
		t.Fatalf("Conversations() = %v", err)
	}
	if _, err := client.Reservations(ctx, cli.ReservationQuery{State: "active"}); err != nil {
		t.Fatalf("Reservations() = %v", err)
	}
	if _, err := client.Events(ctx, cli.EventQuery{Type: "message.sent"}); err != nil {
		t.Fatalf("Events() = %v", err)
	}
	if _, err := client.Projects(ctx); err != nil {
		t.Fatalf("Projects() = %v", err)
	}
	if _, err := client.Overview(ctx); err != nil {
		t.Fatalf("Overview() = %v", err)
	}
	if _, err := client.Identity(ctx); err != nil {
		t.Fatalf("Identity() = %v", err)
	}

	requests := *seen
	if len(requests) != 8 {
		t.Fatalf("recorded %d requests, want 8", len(requests))
	}
	if requests[0].query.Get("project_key") != "/a" || requests[0].query.Get("agent") != "scout" ||
		requests[0].query.Get("limit") != "10" {
		t.Fatalf("agents query = %v", requests[0].query)
	}
	if requests[2].query.Get("conversation_id") != "c1" {
		t.Fatalf("conversations query = %v", requests[2].query)
	}
	if requests[3].query.Get("state") != "active" {
		t.Fatalf("reservations query = %v", requests[3].query)
	}
	if requests[4].query.Get("type") != "message.sent" {
		t.Fatalf("events query = %v", requests[4].query)
	}
	for _, request := range requests {
		if request.token != "bba_token" {
			t.Fatalf("%s carried token %q", request.path, request.token)
		}
	}
}

func TestEventsReportPayloadSize(t *testing.T) {
	t.Parallel()

	server, _ := serve(t, func(recordedRequest) (int, string) {
		return http.StatusOK, `{"events":[{"position":7,"type":"message.sent","payload":{"a":1}}]}`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	page, err := client.Events(context.Background(), cli.EventQuery{})
	if err != nil {
		t.Fatalf("Events() = %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].Position != 7 || page.Events[0].PayloadSize == 0 {
		t.Fatalf("events = %#v", page.Events)
	}
}

func TestUnauthorizedMeansAStaleHandshake(t *testing.T) {
	t.Parallel()

	server, _ := serve(t, func(recordedRequest) (int, string) {
		return http.StatusUnauthorized, `{"code":"UNAUTHENTICATED"}`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_stale"), "")
	if _, err := client.Overview(context.Background()); !errors.Is(err, ErrStaleHandshake) {
		t.Fatalf("Overview() = %v, want ErrStaleHandshake", err)
	}
}

func TestUnavailableStorageIsReported(t *testing.T) {
	t.Parallel()

	server, _ := serve(t, func(recordedRequest) (int, string) {
		return http.StatusServiceUnavailable, `{"code":"DEPENDENCY_UNAVAILABLE"}`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	_, err := client.Overview(context.Background())
	if err == nil || !strings.Contains(err.Error(), "storage is unavailable") {
		t.Fatalf("Overview() = %v", err)
	}
}

func TestUnexpectedStatusIsReported(t *testing.T) {
	t.Parallel()

	server, _ := serve(t, func(recordedRequest) (int, string) {
		return http.StatusTeapot, `{}`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	_, err := client.Overview(context.Background())
	if err == nil || !strings.Contains(err.Error(), "418") {
		t.Fatalf("Overview() = %v", err)
	}
}

func TestMalformedPayloadIsReported(t *testing.T) {
	t.Parallel()

	server, _ := serve(t, func(recordedRequest) (int, string) {
		return http.StatusOK, `not json`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	_, err := client.Overview(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("Overview() = %v", err)
	}
}

func TestDiscoveryFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		path    string
		want    error
	}{
		{name: "no path", want: ErrNoHandshake},
		{name: "missing file", path: "absent.json", want: ErrNoHandshake},
		{name: "not json", path: "admin.json", content: "{", want: ErrStaleHandshake},
		{name: "wrong schema", path: "admin.json", content: `{"schema":"other/v1"}`, want: ErrStaleHandshake},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := ""
			if test.path != "" {
				path = filepath.Join(t.TempDir(), test.path)
				if test.content != "" {
					if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			client := New(path, "")
			if _, err := client.Overview(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("Overview() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestExplicitAddressOverridesTheRecord(t *testing.T) {
	t.Parallel()

	server, seen := serve(t, func(recordedRequest) (int, string) {
		return http.StatusOK, `{"projects":[]}`
	})
	client := New(writeHandshake(t, "127.0.0.1:1", "bba_token"), addressOf(t, server))
	if _, err := client.Projects(context.Background()); err != nil {
		t.Fatalf("Projects() = %v", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("the explicit address was not used")
	}
}

// TestSetAddressOverridesTheRecordAfterConstruction covers the hand-off the
// --address flag needs: the client is built before Kong parses anything, so a
// client that could only be addressed at construction meant the flag reached
// nothing.
func TestSetAddressOverridesTheRecordAfterConstruction(t *testing.T) {
	t.Parallel()

	server, seen := serve(t, func(recordedRequest) (int, string) {
		return http.StatusOK, `{"projects":[]}`
	})
	client := New(writeHandshake(t, "127.0.0.1:1", "bba_token"), "")
	client.SetAddress(addressOf(t, server))
	if _, err := client.Projects(context.Background()); err != nil {
		t.Fatalf("Projects() = %v", err)
	}
	if len(*seen) != 1 || (*seen)[0].token != "bba_token" {
		t.Fatalf("requests = %#v, want one carrying the record's token", *seen)
	}
}

// TestAMissingRecordNamesTheCredentialWhenAnAddressWasGiven keeps a user who
// reached for --address from reading an error that looks like the flag was
// ignored: the address is honoured, and the record is still missing.
func TestAMissingRecordNamesTheCredentialWhenAnAddressWasGiven(t *testing.T) {
	t.Parallel()

	client := New(filepath.Join(t.TempDir(), "absent.json"), "127.0.0.1:18300")
	_, err := client.Overview(context.Background())
	if !errors.Is(err, ErrNoHandshake) {
		t.Fatalf("Overview() = %v, want %v", err, ErrNoHandshake)
	}
	if !strings.Contains(err.Error(), "--address") {
		t.Fatalf("Overview() = %q, want the flag's limit explained", err)
	}
}

func TestClientReportsItsConfiguredTimeout(t *testing.T) {
	t.Parallel()

	client := New("/state/admin.json", "127.0.0.1:8080")
	if client.Timeout != defaultTimeout || client.HandshakePath != "/state/admin.json" {
		t.Fatalf("client = %#v", client)
	}
}

func TestFilterPredicatesTravelAsWireParameters(t *testing.T) {
	t.Parallel()

	server, seen := serve(t, func(recordedRequest) (int, string) {
		return http.StatusOK, `{"agents":[],"conversations":[],"reservations":[],"events":[],"summaries":[]}`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	ctx := context.Background()

	if _, err := client.Agents(ctx, cli.AgentQuery{ActiveOnly: true}); err != nil {
		t.Fatalf("Agents() = %v", err)
	}
	if _, err := client.Inbox(ctx, cli.InboxQuery{UnreadOnly: true, UnackedOnly: true}); err != nil {
		t.Fatalf("Inbox() = %v", err)
	}
	if _, err := client.Conversations(ctx, cli.ConversationQuery{OpenOnly: true}); err != nil {
		t.Fatalf("Conversations() = %v", err)
	}
	if _, err := client.Reservations(ctx, cli.ReservationQuery{Mode: "shared", Path: "a/f"}); err != nil {
		t.Fatalf("Reservations() = %v", err)
	}

	requests := *seen
	if len(requests) != 4 {
		t.Fatalf("recorded %d requests, want 4", len(requests))
	}
	if requests[0].query.Get("active") != "true" {
		t.Fatalf("agents query = %v", requests[0].query)
	}
	if requests[1].query.Get("unread") != "true" || requests[1].query.Get("unacked") != "true" {
		t.Fatalf("inbox query = %v", requests[1].query)
	}
	if requests[2].query.Get("open") != "true" {
		t.Fatalf("conversations query = %v", requests[2].query)
	}
	if requests[3].query.Get("mode") != "shared" || requests[3].query.Get("path") != "a/f" {
		t.Fatalf("reservations query = %v", requests[3].query)
	}
}

// A daemon older than these predicates rejects an unknown parameter name, so a
// filter that is off must not be spelled out on the wire at all.
func TestUnusedFilterPredicatesAreOmitted(t *testing.T) {
	t.Parallel()

	server, seen := serve(t, func(recordedRequest) (int, string) {
		return http.StatusOK, `{"agents":[],"conversations":[],"reservations":[],"summaries":[]}`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	ctx := context.Background()

	if _, err := client.Agents(ctx, cli.AgentQuery{}); err != nil {
		t.Fatalf("Agents() = %v", err)
	}
	if _, err := client.Inbox(ctx, cli.InboxQuery{}); err != nil {
		t.Fatalf("Inbox() = %v", err)
	}
	if _, err := client.Conversations(ctx, cli.ConversationQuery{}); err != nil {
		t.Fatalf("Conversations() = %v", err)
	}
	if _, err := client.Reservations(ctx, cli.ReservationQuery{Mode: cli.ReservationModeAny}); err != nil {
		t.Fatalf("Reservations() = %v", err)
	}

	for index, name := range []string{"active", "unread", "open", "mode"} {
		if _, present := (*seen)[index].query[name]; present {
			t.Fatalf("%s carried %s=%q", (*seen)[index].path, name, (*seen)[index].query.Get(name))
		}
	}
	if _, present := (*seen)[1].query["unacked"]; present {
		t.Fatalf("inbox carried unacked = %v", (*seen)[1].query)
	}
}

func TestEveryPageDecodesTheTruncatedFlag(t *testing.T) {
	t.Parallel()

	server, _ := serve(t, func(recordedRequest) (int, string) {
		return http.StatusOK, `{"agents":[],"conversations":[],"reservations":[],"events":[],
			"summaries":[],"pending":[],"truncated":true}`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")
	ctx := context.Background()

	agents, err := client.Agents(ctx, cli.AgentQuery{})
	if err != nil || !agents.Truncated {
		t.Fatalf("agents = %#v, %v", agents, err)
	}
	inbox, err := client.Inbox(ctx, cli.InboxQuery{})
	if err != nil || !inbox.Truncated {
		t.Fatalf("inbox = %#v, %v", inbox, err)
	}
	conversations, err := client.Conversations(ctx, cli.ConversationQuery{})
	if err != nil || !conversations.Truncated {
		t.Fatalf("conversations = %#v, %v", conversations, err)
	}
	reservations, err := client.Reservations(ctx, cli.ReservationQuery{})
	if err != nil || !reservations.Truncated {
		t.Fatalf("reservations = %#v, %v", reservations, err)
	}
	events, err := client.Events(ctx, cli.EventQuery{})
	if err != nil || !events.Truncated {
		t.Fatalf("events = %#v, %v", events, err)
	}
}

func TestRejectionsCarryTheStatusAndTheDaemonsMessage(t *testing.T) {
	t.Parallel()

	server, _ := serve(t, func(recordedRequest) (int, string) {
		return http.StatusBadRequest, `{"code":"INVALID_ARGUMENT","message":"limit must be from 1 through 256"}`
	})
	client := New(writeHandshake(t, addressOf(t, server), "bba_token"), "")

	_, err := client.Agents(context.Background(), cli.AgentQuery{Limit: 300})
	var rejected *cli.AdminStatusError
	if !errors.As(err, &rejected) {
		t.Fatalf("Agents() = %v, want an AdminStatusError", err)
	}
	if rejected.Status != http.StatusBadRequest || rejected.Detail != "limit must be from 1 through 256" {
		t.Fatalf("rejection = %#v", rejected)
	}
	if !strings.Contains(rejected.Error(), "limit must be from 1 through 256") {
		t.Fatalf("error = %q", rejected.Error())
	}
}
