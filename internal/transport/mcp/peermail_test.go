package mcp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/storage/sqlite"
)

// recordingDispatch answers a send without a network, so these assertions are
// about what blackbird_say reports rather than about the wire.
type recordingDispatch struct {
	state    coordination.PeerDeliveryState
	detail   string
	receipt  string
	attempts int
	seen     []coordination.PeerMailEntry
}

func (dispatch *recordingDispatch) Deliver(_ context.Context,
	entries []coordination.PeerMailEntry) []coordination.PeerMailResult {
	dispatch.seen = append(dispatch.seen, entries...)
	results := make([]coordination.PeerMailResult, 0, len(entries))
	for _, entry := range entries {
		results = append(results, coordination.PeerMailResult{Address: entry.Address,
			State: dispatch.state, Detail: dispatch.detail, RemoteMessageID: dispatch.receipt,
			Attempts: dispatch.attempts})
	}
	return results
}

func peerMailServer(t *testing.T, dispatch coordination.PeerMailDispatch) (*sqlite.Store, *Server) {
	t.Helper()
	store, err := sqlite.Open(context.Background(), sqlite.Config{
		Path: filepath.Join(t.TempDir(), "peer-mail.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server, err := NewServer(Dependencies{Coordination: store, WorkReferences: testWorkReferenceObserver{},
		PeerMailStore: store, PeerMailDispatch: dispatch})
	if err != nil {
		t.Fatal(err)
	}
	return store, server
}

// TestSayReportsEachRemoteRecipientsOwnState is the agent-facing contract: the
// three states are distinguishable, and a local recipient in the same call is
// unaffected by what the remote one did.
func TestSayReportsEachRemoteRecipientsOwnState(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		dispatch *recordingDispatch
		want     coordination.PeerDeliveryState
	}{
		{"delivered", &recordingDispatch{state: coordination.PeerDeliveryDelivered,
			receipt: "peer-minted", attempts: 1}, coordination.PeerDeliveryDelivered},
		{"queued", &recordingDispatch{state: coordination.PeerDeliveryQueued,
			detail: "peer could not be reached", attempts: 1}, coordination.PeerDeliveryQueued},
		{"undeliverable", &recordingDispatch{state: coordination.PeerDeliveryUndeliverable,
			detail: "no such agent", attempts: 1}, coordination.PeerDeliveryUndeliverable},
	}
	for _, testCase := range cases {
		_, server := peerMailServer(t, testCase.dispatch)
		client, closeMCP := connect(t, server)

		sender := callCoord[agentSessionOutput](t, client, ToolJoin,
			registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "implementer"})
		callCoord[agentSessionOutput](t, client, ToolJoin,
			registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "reviewer"})

		said := callCoord[sayOutput](t, client, ToolSay, sayInput{
			AgentToken: sender.RegistrationToken, Topic: "peering", Slug: "peering",
			To:      []string{"reviewer", "reviewer@phalls-mac-mini"},
			Subject: "handover", Body: "the peer route is in",
		})
		if len(said.RemoteDeliveries) != 1 {
			t.Fatalf("%s: remote deliveries=%+v, want one", testCase.name, said.RemoteDeliveries)
		}
		remote := said.RemoteDeliveries[0]
		if remote.State != string(testCase.want) {
			t.Fatalf("%s: state=%q, want %q", testCase.name, remote.State, testCase.want)
		}
		if remote.Recipient != "reviewer@phalls-mac-mini" {
			t.Fatalf("%s: recipient=%q", testCase.name, remote.Recipient)
		}
		if testCase.want == coordination.PeerDeliveryDelivered {
			if remote.RemoteMessageID != "peer-minted" || remote.Detail != "" {
				t.Fatalf("%s: a delivered recipient must carry the peer's receipt and no detail: %+v",
					testCase.name, remote)
			}
		} else if remote.Detail == "" {
			t.Fatalf("%s: a %s recipient must say why", testCase.name, remote.State)
		}
		// The local recipient is delivered locally in the same message, and its
		// delivery record is the ordinary one.
		if len(said.Deliveries) != 2 {
			t.Fatalf("%s: deliveries=%+v, want the local agent and the peer actor",
				testCase.name, said.Deliveries)
		}
		// The remote message body travelled to the dispatcher as the STORED
		// body, so what the peer receives cannot diverge from what is recorded.
		if len(testCase.dispatch.seen) != 1 || testCase.dispatch.seen[0].Body != "the peer route is in" {
			t.Fatalf("%s: dispatched=%+v", testCase.name, testCase.dispatch.seen)
		}
		closeMCP()
	}
}

// TestSayRefusesACrossHostRecipientWhenPeeringIsNotComposed is the failure this
// design chooses: an explicit refusal rather than silently dropping half of a
// recipient list, which would leave an agent believing it had handed work over.
func TestSayRefusesACrossHostRecipientWhenPeeringIsNotComposed(t *testing.T) {
	t.Parallel()
	store, err := sqlite.Open(context.Background(), sqlite.Config{
		Path: filepath.Join(t.TempDir(), "no-peering.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	client, closeMCP := connect(t, newTestServer(t, store))
	defer closeMCP()

	sender := callCoord[agentSessionOutput](t, client, ToolJoin,
		registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "implementer"})
	failure := callCoordFailure(t, client, ToolSay, sayInput{
		AgentToken: sender.RegistrationToken, Topic: "peering", Slug: "peering",
		To: []string{"reviewer@phalls-mac-mini"}, Subject: "s", Body: "b",
	})
	if !strings.Contains(strings.ToLower(failure.Message), "cross-host mail") {
		t.Fatalf("failure=%+v, want a refusal naming the missing capability", failure)
	}
}

// TestSayLeavesLocalOnlySendsUntouched is the compatibility assertion: a daemon
// with peering composed still answers an ordinary send with no remote section
// at all, so nothing an existing agent reads has changed shape.
func TestSayLeavesLocalOnlySendsUntouched(t *testing.T) {
	t.Parallel()
	dispatch := &recordingDispatch{state: coordination.PeerDeliveryDelivered}
	_, server := peerMailServer(t, dispatch)
	client, closeMCP := connect(t, server)
	defer closeMCP()

	sender := callCoord[agentSessionOutput](t, client, ToolJoin,
		registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "implementer"})
	callCoord[agentSessionOutput](t, client, ToolJoin,
		registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "reviewer"})

	said := callCoord[sayOutput](t, client, ToolSay, sayInput{
		AgentToken: sender.RegistrationToken, Topic: "local", Slug: "local",
		To: []string{"reviewer"}, Subject: "s", Body: "b",
	})
	if said.RemoteDeliveries != nil {
		t.Fatalf("a local-only send reported remote deliveries: %+v", said.RemoteDeliveries)
	}
	if len(dispatch.seen) != 0 {
		t.Fatalf("a local-only send reached the dispatcher: %+v", dispatch.seen)
	}
}

// TestSayRefusesAMalformedCrossHostAddress keeps a repaired address from
// becoming a message delivered to a machine nobody named.
func TestSayRefusesAMalformedCrossHostAddress(t *testing.T) {
	t.Parallel()
	_, server := peerMailServer(t, &recordingDispatch{state: coordination.PeerDeliveryDelivered})
	client, closeMCP := connect(t, server)
	defer closeMCP()

	sender := callCoord[agentSessionOutput](t, client, ToolJoin,
		registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "implementer"})
	failure := callCoordFailure(t, client, ToolSay, sayInput{
		AgentToken: sender.RegistrationToken, Topic: "bad", Slug: "bad",
		To: []string{"reviewer@"}, Subject: "s", Body: "b",
	})
	if !strings.Contains(failure.Message, "name@host") {
		t.Fatalf("failure=%+v, want the grammar named", failure)
	}
}
