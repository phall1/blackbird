package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	stdhttp "net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/storage/sqlite"
	"github.com/phall1/blackbird/internal/transport/contracts"
	httptransport "github.com/phall1/blackbird/internal/transport/http"
)

const testActorSessionID = "01b8e094-9888-7000-8000-00000000001f"

// identityPlaneToolNames is the W0/W1 surface whose MCP registration is
// conditional. The same operations stay reachable over HTTP either way.
var identityPlaneToolNames = []string{
	ToolInstallationBootstrap, ToolPrincipalRegister, ToolDevicePairingBegin, ToolDevicePair,
	ToolWorkspaceCreate, ToolWorkspaceMemberInvite, ToolWorkspaceMembershipAccept, ToolActorCreate,
	ToolActorDelegationPropose, ToolActorDelegationActivate, ToolSessionStart, ToolWorkRefObserve,
	ToolObjectiveAndWorkCreate, ToolObjectiveActivate, ToolRunPlanWithBindings, ToolRunJoin,
	ToolRunStart, ToolContextGet, ToolEventsSync,
}

// coordinationToolNames is the surface an agent actually gets over MCP, listed
// once so the exposure count and the schema assertions cannot describe
// different sets.
var coordinationToolNames = []string{
	ToolAgentRegister, ToolAgentsList, ToolConversationOpen, ToolMessageSend, ToolMessageReply,
	ToolInboxFetch, ToolThreadFetch, ToolMessageMarkRead, ToolMessageAcknowledge,
	ToolReservationAcquire, ToolReservationRenew, ToolReservationRelease, ToolReservationsStatus, ToolWait,
}

type testMCPAuthenticator struct{}

func (testMCPAuthenticator) Authenticate(context.Context, string, string) (contracts.AuthenticationEvidence, *contracts.ErrorDTO, error) {
	return validAuthenticationEvidence(), nil, nil
}

type testHTTPAuthenticator struct{}

func (testHTTPAuthenticator) Authenticate(context.Context, *stdhttp.Request, string, string) (contracts.AuthenticationEvidence, *contracts.ErrorDTO, error) {
	return validAuthenticationEvidence(), nil, nil
}

func validAuthenticationEvidence() contracts.AuthenticationEvidence {
	principal, err := domain.ParsePrincipalID("01b8e094-9888-7000-8000-000000000004")
	if err != nil {
		panic(err)
	}
	authority, err := domain.ParseAuthorityID("01b8e094-9888-7000-8000-000000000003")
	if err != nil {
		panic(err)
	}
	binding, err := contracts.NewChannelBindingDigest(strings.Repeat("b", 64))
	if err != nil {
		panic(err)
	}
	audience, err := contracts.NewAuthenticationAudience("blackbird-mcp")
	if err != nil {
		panic(err)
	}
	provenance, err := contracts.NewAuthenticationAuditProvenance(authority, nil)
	if err != nil {
		panic(err)
	}
	evidence, err := contracts.NewAuthenticationEvidence(contracts.AuthenticationEvidenceParams{
		PrincipalID: principal, PrincipalRevision: domain.InitialVersion(), ChannelBinding: binding,
		Audience: audience, AuditProvenance: provenance, VerifiedAt: time.Now().Add(-time.Second),
	})
	if err != nil {
		panic(err)
	}
	return evidence
}

type testSessionBinder struct {
	session domain.ActorSessionID
	called  atomic.Bool
}

func (binder *testSessionBinder) CurrentActorSession(context.Context, contracts.AuthenticationEvidence, string) (domain.ActorSessionID, *contracts.ErrorDTO, error) {
	binder.called.Store(true)
	return binder.session, nil, nil
}

type testHandlers struct {
	contracts.InstallationBootstrapHandler
	contracts.PrincipalRegisterHandler
	contracts.DevicePairingBeginHandler
	contracts.DevicePairHandler
	contracts.WorkspaceCreateHandler
	contracts.WorkspaceMemberInviteHandler
	contracts.WorkspaceMembershipAcceptHandler
	contracts.ActorCreateHandler
	contracts.ActorDelegationProposeHandler
	contracts.ActorDelegationActivateHandler
	contracts.SessionStartHandler
	contracts.WorkRefObserveHandler
	contracts.ObjectiveAndWorkCreateHandler
	contracts.ObjectiveActivateHandler
	contracts.RunPlanWithBindingsHandler
	contracts.RunJoinHandler
	contracts.RunStartHandler
	events  func(context.Context, contracts.AuthenticationEvidence, contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error)
	context func(context.Context, contracts.AuthenticationEvidence, contracts.ContextGetRequestDTO) (contracts.ContextPageDTO, *contracts.ErrorDTO, error)
}

func (handlers *testHandlers) HandleEventsSync(ctx context.Context, evidence contracts.AuthenticationEvidence, request contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
	return handlers.events(ctx, evidence, request)
}

func (handlers *testHandlers) HandleContextGet(ctx context.Context, evidence contracts.AuthenticationEvidence, request contracts.ContextGetRequestDTO) (contracts.ContextPageDTO, *contracts.ErrorDTO, error) {
	return handlers.context(ctx, evidence, request)
}

func TestHTTPAndMCPSemanticEnvelopeParity(t *testing.T) {
	t.Parallel()
	session := parseSession(t)
	request := contracts.EventsSyncRequestDTO{Schema: contracts.SchemaEventsSyncRequest, RequestID: "req-parity",
		Operation: contracts.OperationEventsSync, ActorSessionID: session, AfterCursor: "bbec1_fixture", Limit: 64}

	t.Run("success", func(t *testing.T) {
		handlers := &testHandlers{events: successfulEvents, context: contextFailure}
		httpBody, status := callHTTP(t, handlers, request)
		if status != stdhttp.StatusOK {
			t.Fatalf("HTTP status = %d, want 200: %s", status, httpBody)
		}
		mcpResult := callMCP(t, handlers, request)
		if mcpResult.IsError {
			t.Fatalf("MCP result is error: %+v", mcpResult)
		}
		mcpBody, err := json.Marshal(mcpResult.StructuredContent)
		if err != nil {
			t.Fatalf("marshal MCP structured content: %v", err)
		}
		httpPage, err := contracts.DecodeEventPage(httpBody)
		if err != nil {
			t.Fatalf("decode HTTP page: %v", err)
		}
		mcpPage, err := contracts.DecodeEventPage(mcpBody)
		if err != nil {
			t.Fatalf("decode MCP page: %v", err)
		}
		if !reflect.DeepEqual(httpPage, mcpPage) {
			t.Fatalf("semantic envelopes differ\nHTTP: %+v\nMCP:  %+v", httpPage, mcpPage)
		}
	})

	t.Run("typed error", func(t *testing.T) {
		handlers := &testHandlers{events: eventsFailure, context: contextFailure}
		httpBody, status := callHTTP(t, handlers, request)
		if status != stdhttp.StatusGone {
			t.Fatalf("HTTP status = %d, want 410: %s", status, httpBody)
		}
		var problem struct {
			contracts.ErrorDTO
		}
		if err := json.Unmarshal(httpBody, &problem); err != nil {
			t.Fatalf("decode HTTP problem: %v", err)
		}
		mcpResult := callMCP(t, handlers, request)
		if !mcpResult.IsError {
			t.Fatal("MCP typed failure did not set isError")
		}
		mcpBody, err := json.Marshal(mcpResult.StructuredContent)
		if err != nil {
			t.Fatalf("marshal MCP error: %v", err)
		}
		mcpError, err := contracts.DecodeError(mcpBody)
		if err != nil {
			t.Fatalf("decode MCP error: %v", err)
		}
		if !reflect.DeepEqual(problem.ErrorDTO, mcpError) {
			t.Fatalf("error envelopes differ\nHTTP: %+v\nMCP:  %+v", problem.ErrorDTO, mcpError)
		}
	})
}

func TestMCPDiscoveryStrictnessResourcesAndCancellation(t *testing.T) {
	t.Parallel()
	session := parseSession(t)
	started := make(chan struct{})
	canceled := make(chan struct{})
	var calls atomic.Int32
	handlers := &testHandlers{context: contextFailure, events: func(ctx context.Context, _ contracts.AuthenticationEvidence, request contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		close(canceled)
		return contracts.EventPageDTO{}, nil, ctx.Err()
	}}
	binder := &testSessionBinder{session: session}
	server := newTestServer(t, handlers, binder)
	clientSession, closeSessions := connect(t, server)
	defer closeSessions()

	tools, err := clientSession.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) != 19 {
		t.Fatalf("tool count = %d, want 19", len(tools.Tools))
	}
	w1Tools := map[string]bool{
		ToolWorkRefObserve:         false,
		ToolObjectiveAndWorkCreate: false,
		ToolObjectiveActivate:      false,
		ToolRunPlanWithBindings:    false,
		ToolRunJoin:                false,
		ToolRunStart:               false,
	}
	for _, tool := range tools.Tools {
		if _, ok := w1Tools[tool.Name]; ok {
			w1Tools[tool.Name] = true
		}
		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal schema for %s: %v", tool.Name, err)
		}
		if !bytes.Contains(encoded, []byte(`"additionalProperties":false`)) {
			t.Fatalf("tool %s has permissive input schema: %s", tool.Name, encoded)
		}
		output, err := json.Marshal(tool.OutputSchema)
		if err != nil {
			t.Fatalf("marshal output schema for %s: %v", tool.Name, err)
		}
		if !bytes.Contains(output, []byte(`"type":"object"`)) {
			t.Fatalf("tool %s output schema lacks Claude-compatible root object type: %s", tool.Name, output)
		}
	}
	for name, found := range w1Tools {
		if !found {
			t.Errorf("W1 tool %q was not discovered", name)
		}
	}

	resource, err := clientSession.ReadResource(context.Background(), &sdkmcp.ReadResourceParams{URI: ResourceCurrentContext})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if !binder.called.Load() || len(resource.Contents) != 1 || !strings.Contains(resource.Contents[0].Text, string(domain.ErrorCodeCursorExpired)) {
		t.Fatalf("resource did not use bound actor session and typed result: %+v", resource)
	}

	malformed := struct {
		contracts.EventsSyncRequestDTO
		Unexpected string `json:"unexpected"`
	}{EventsSyncRequestDTO: validEventsRequest(session), Unexpected: "forbidden"}
	result, err := clientSession.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: ToolEventsSync, Arguments: malformed})
	if err != nil {
		t.Fatalf("malformed CallTool: %v", err)
	}
	if !result.IsError || calls.Load() != 0 {
		t.Fatalf("malformed request result/calls = %+v/%d", result, calls.Load())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, callErr := clientSession.CallTool(ctx, &sdkmcp.CallToolParams{Name: ToolEventsSync, Arguments: validEventsRequest(session)})
		done <- callErr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not receive request cancellation")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("client call did not finish after cancellation")
	}
}

func TestStreamableHTTPHandler(t *testing.T) {
	t.Parallel()

	session := parseSession(t)
	handlers := &testHandlers{events: successfulEvents, context: contextFailure}
	server := newTestServer(t, handlers, &testSessionBinder{session: session})
	httpServer := httptest.NewServer(server.HTTPHandler(&sdkmcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, MaxRequestBodyBytes: contracts.MaxCommandJSONBytes,
		PropagateRequestCancellation: true,
	}))
	defer httpServer.Close()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "blackbird-http-test", Version: "v1"}, nil)
	clientSession, err := client.Connect(context.Background(), &sdkmcp.StreamableClientTransport{
		Endpoint: httpServer.URL, HTTPClient: httpServer.Client(), DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect Streamable HTTP: %v", err)
	}
	defer func() { _ = clientSession.Close() }()
	tools, err := clientSession.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools over Streamable HTTP: %v", err)
	}
	if len(tools.Tools) != 19 {
		t.Fatalf("Streamable HTTP tool count = %d, want 19", len(tools.Tools))
	}
}

func TestNewServerRequiresCompleteComposition(t *testing.T) {
	t.Parallel()
	if _, err := NewServer(Dependencies{}); err == nil {
		t.Fatal("NewServer() error = nil, want incomplete-composition error")
	}
}

func TestLocalCoordinationEndToEndSurvivesDaemonRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordination.db")
	store, err := sqlite.Open(context.Background(), sqlite.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, &testHandlers{events: successfulEvents, context: contextFailure},
		&testSessionBinder{session: parseSession(t)}, store)
	client, closeMCP := connect(t, server)
	assertCoordinationToolSchemas(t, client)

	alice := callCoord[agentSessionOutput](t, client, ToolAgentRegister, registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "alice"})
	bob := callCoord[agentSessionOutput](t, client, ToolAgentRegister, registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "bob"})
	if alice.RegistrationToken == "" || bob.RegistrationToken == "" {
		t.Fatal("new registrations did not issue bearer tokens")
	}
	agents := callCoord[activeAgentsOutput](t, client, ToolAgentsList, tokenInput{AgentToken: alice.RegistrationToken})
	if len(agents.Agents) != 2 || agents.Agents[0].Name != "alice" || agents.Agents[1].Name != "bob" {
		t.Fatalf("active agents = %+v", agents.Agents)
	}
	conversation := callCoord[conversationOutput](t, client, ToolConversationOpen,
		openConversationInput{AgentToken: alice.RegistrationToken, Topic: "restart handoff"})
	message := callCoord[messageOutput](t, client, ToolMessageSend, sendMessageInput{AgentToken: alice.RegistrationToken,
		ConversationID: conversation.ConversationID, To: []string{"bob"}, Subject: "handoff", Body: "durable payload",
		AcknowledgementRequired: true})
	inbox := callCoord[messagePageOutput](t, client, ToolInboxFetch,
		fetchInboxInput{AgentToken: bob.RegistrationToken, UnreadOnly: true, Limit: 32})
	if len(inbox.Messages) != 1 || inbox.Messages[0].MessageID != message.MessageID {
		t.Fatalf("bob inbox = %+v", inbox)
	}
	read := callCoord[deliveryFactOutput](t, client, ToolMessageMarkRead,
		messageFactInput{AgentToken: bob.RegistrationToken, MessageID: message.MessageID})
	ack := callCoord[deliveryFactOutput](t, client, ToolMessageAcknowledge,
		messageFactInput{AgentToken: bob.RegistrationToken, MessageID: message.MessageID})
	if !read.Read || !ack.Read || !ack.Acknowledged {
		t.Fatalf("read/ack = %+v / %+v", read, ack)
	}
	// Acknowledgement resolves the digest from the single stored message, so a
	// message the caller cannot see fails outright instead of being searched for.
	assertCoordinationInputRejected(t, client, ToolMessageAcknowledge, messageFactInput{
		AgentToken: bob.RegistrationToken, MessageID: "01b8e094-9888-7000-8000-0000000000ff"})
	if unread := callCoord[messagePageOutput](t, client, ToolInboxFetch,
		fetchInboxInput{AgentToken: bob.RegistrationToken, UnreadOnly: true, Limit: 32}); len(unread.Messages) != 0 {
		t.Fatalf("read message remained unread: %+v", unread)
	}
	if all := callCoord[messagePageOutput](t, client, ToolInboxFetch,
		map[string]any{"agent_token": bob.RegistrationToken}); len(all.Messages) != 1 {
		t.Fatalf("all inbox omitted read message: %+v", all)
	}
	reply := callCoord[messageOutput](t, client, ToolMessageReply, map[string]any{
		"agent_token": bob.RegistrationToken, "conversation_id": conversation.ConversationID, "to": []string{"alice"},
		"subject": "re: handoff", "body": "received", "reply_to_message_id": message.MessageID,
	})
	if reply.ReplyTo != message.MessageID {
		t.Fatalf("reply = %+v", reply)
	}
	lease := callCoord[reservationOutput](t, client, ToolReservationAcquire, map[string]any{
		"agent_token": alice.RegistrationToken,
		"selectors":   []reservationSelectorInput{{Kind: "subtree", Path: "src"}},
	})
	if lease.LeaseID == "" || len(lease.Fences) == 0 {
		t.Fatalf("lease = %+v", lease)
	}

	closeMCP()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = sqlite.Open(context.Background(), sqlite.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server = newTestServer(t, &testHandlers{events: successfulEvents, context: contextFailure},
		&testSessionBinder{session: parseSession(t)}, store)
	client, closeMCP = connect(t, server)
	defer closeMCP()
	aliceToken, bobToken := alice.RegistrationToken, bob.RegistrationToken
	// Registration is where a restarted agent learns what it still holds. The
	// daemon rebinds these leases to the new session either way; saying nothing
	// about them is how an exclusive reservation gets abandoned for its TTL.
	resumed := callCoord[agentSessionOutput](t, client, ToolAgentRegister,
		registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "alice", RegistrationToken: &aliceToken})
	if resumed.RegistrationToken != "" {
		t.Fatal("resuming a registered name issued a second token")
	}
	if len(resumed.HeldReservations) != 1 || resumed.HeldReservations[0].LeaseID != lease.LeaseID {
		t.Fatalf("resumed reservations = %+v, want the lease held across the restart", resumed.HeldReservations)
	}
	if resumed.HeldReservations[0].ExpiresInMS <= 0 || len(resumed.HeldReservations[0].Fences) == 0 ||
		len(resumed.HeldReservations[0].Selectors) != 1 || resumed.HeldReservations[0].Selectors[0].Path != "src" {
		t.Fatalf("resumed reservation = %+v, want the time left, the fences and the selectors",
			resumed.HeldReservations[0])
	}
	if resumed.Inbox.Unread != 1 || len(resumed.Inbox.Recent) != 1 || resumed.Inbox.Recent[0].From != "bob" {
		t.Fatalf("resumed inbox = %+v, want bob's unread reply", resumed.Inbox)
	}
	if len(resumed.OpenConversations) != 1 || resumed.OpenConversations[0].ConversationID != conversation.ConversationID ||
		resumed.OpenConversations[0].Messages != 2 {
		t.Fatalf("resumed conversations = %+v", resumed.OpenConversations)
	}
	if len(resumed.OtherAgents) != 1 || resumed.OtherAgents[0].Name != "bob" {
		t.Fatalf("resumed roster = %+v, want the other agent present", resumed.OtherAgents)
	}
	resumedBob := callCoord[agentSessionOutput](t, client, ToolAgentRegister,
		registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "bob", RegistrationToken: &bobToken})
	if len(resumedBob.HeldReservations) != 0 {
		t.Fatalf("bob holds no reservation but was handed %+v", resumedBob.HeldReservations)
	}
	renewed := callCoord[reservationOutput](t, client, ToolReservationRenew, map[string]any{
		"agent_token": aliceToken, "lease_id": lease.LeaseID, "fences": lease.Fences,
	})
	if renewed.LeaseID != lease.LeaseID {
		t.Fatalf("renewed lease = %+v", renewed)
	}
	thread := callCoord[messagePageOutput](t, client, ToolThreadFetch, map[string]any{
		"agent_token": aliceToken, "conversation_id": conversation.ConversationID,
	})
	if len(thread.Messages) != 2 || thread.Messages[0].Body != "durable payload" || !thread.Messages[0].Deliveries[0].Acknowledged ||
		thread.Messages[1].ReplyTo != message.MessageID {
		t.Fatalf("durable thread = %+v", thread)
	}
	conflict, err := client.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: ToolReservationAcquire,
		Arguments: reservationAcquireInput{AgentToken: bobToken, Mode: "exclusive", TTLSeconds: 3600,
			Selectors: []reservationSelectorInput{{Kind: "exact", Path: "src/main.go"}}}})
	if err != nil {
		t.Fatalf("reservation conflict call: %v", err)
	}
	if !conflict.IsError || !strings.Contains(strings.ToLower(conflict.Content[0].(*sdkmcp.TextContent).Text), "lease") {
		t.Fatalf("overlapping reservation did not conflict: %+v", conflict)
	}
	assertCoordinationInputRejected(t, client, ToolInboxFetch, map[string]any{"agent_token": aliceToken, "limit": 0})
	assertCoordinationInputRejected(t, client, ToolReservationAcquire, map[string]any{"agent_token": bobToken,
		"mode": "invalid", "selectors": []reservationSelectorInput{{Kind: "exact", Path: "other.go"}}})
	assertCoordinationInputRejected(t, client, ToolReservationRenew, map[string]any{"agent_token": aliceToken,
		"lease_id": renewed.LeaseID, "fences": renewed.Fences, "ttl_seconds": 0})
	assertCoordinationInputRejected(t, client, ToolReservationRelease, map[string]any{"agent_token": aliceToken,
		"lease_id": renewed.LeaseID, "fences": renewed.Fences, "ttl_seconds": 1})
	callCoord[reservationOutput](t, client, ToolReservationRelease, map[string]any{"agent_token": aliceToken,
		"lease_id": renewed.LeaseID, "fences": renewed.Fences})
	callCoord[reservationOutput](t, client, ToolReservationAcquire, reservationAcquireInput{AgentToken: bobToken,
		Mode: "exclusive", TTLSeconds: 300, Selectors: []reservationSelectorInput{{Kind: "exact", Path: "src/main.go"}}})
	callCoord[reservationOutput](t, client, ToolReservationAcquire, reservationAcquireInput{AgentToken: aliceToken,
		Mode: "shared", TTLSeconds: 300, Selectors: []reservationSelectorInput{{Kind: "subtree", Path: "docs"}}})
	callCoord[reservationOutput](t, client, ToolReservationAcquire, reservationAcquireInput{AgentToken: bobToken,
		Mode: "shared", TTLSeconds: 300, Selectors: []reservationSelectorInput{{Kind: "exact", Path: "docs/guide.md"}}})
}

func TestIdentityPlaneStaysOffMCPUnlessExposed(t *testing.T) {
	t.Parallel()
	store, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "exposure.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	handlers := &testHandlers{events: successfulEvents, context: contextFailure}
	binder := &testSessionBinder{session: parseSession(t)}
	server := newServerExposing(t, false, handlers, binder, store)
	client, closeMCP := connect(t, server)
	defer closeMCP()

	tools, err := client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	listed := make(map[string]bool, len(tools.Tools))
	for _, tool := range tools.Tools {
		listed[tool.Name] = true
	}
	for _, name := range identityPlaneToolNames {
		if listed[name] {
			t.Errorf("identity-plane tool %q was published on a transport that carries no credential", name)
		}
	}
	for _, name := range coordinationToolNames {
		if !listed[name] {
			t.Errorf("coordination tool %q was not published", name)
		}
	}
	if len(listed) != len(coordinationToolNames) {
		t.Fatalf("coordination surface = %d tools, want %d: %v", len(listed), len(coordinationToolNames), listed)
	}
	discovery, err := json.Marshal(tools)
	if err != nil {
		t.Fatalf("marshal coordination tools/list: %v", err)
	}
	if bytes.Contains(discovery, []byte(`"outputSchema"`)) {
		t.Fatalf("coordination tools/list publishes redundant output schemas: %d bytes", len(discovery))
	}
	const maxCoordinationDiscoveryBytes = 32 << 10
	if len(discovery) > maxCoordinationDiscoveryBytes {
		t.Fatalf("coordination tools/list = %d bytes, want at most %d", len(discovery), maxCoordinationDiscoveryBytes)
	}
	// Resources are a fixed pair of URIs rather than a per-request token cost, so
	// withholding the tools must not withhold them.
	if _, err := client.ReadResource(context.Background(), &sdkmcp.ReadResourceParams{URI: ResourceCurrentContext}); err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if !binder.called.Load() {
		t.Fatal("resource did not resolve the bound actor session")
	}
}

// TestMCPToolFailuresReachTheLoggerWithoutArguments covers the transport's only
// diagnostic. MCP had no logger at all, so a coordination tool that failed left
// nothing behind; and the arguments it fails on carry the agent's bearer token,
// which is why the record is built from the tool name and the failure text the
// caller already has rather than from the request.
func TestMCPToolFailuresReachTheLoggerWithoutArguments(t *testing.T) {
	t.Parallel()
	store, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "logging.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	sink := &lockedBuffer{}
	server, err := NewServer(Dependencies{
		Logger:        slog.New(slog.NewJSONHandler(sink, nil)),
		Authenticator: testMCPAuthenticator{}, CurrentSession: &testSessionBinder{session: parseSession(t)},
		Coordination:          store,
		InstallationBootstrap: &testHandlers{}, PrincipalRegister: &testHandlers{},
		DevicePairingBegin: &testHandlers{}, DevicePair: &testHandlers{}, WorkspaceCreate: &testHandlers{},
		WorkspaceMemberInvite: &testHandlers{}, WorkspaceMembershipAccept: &testHandlers{},
		ActorCreate: &testHandlers{}, ActorDelegationPropose: &testHandlers{}, ActorDelegationActivate: &testHandlers{},
		SessionStart: &testHandlers{}, WorkRefObserve: &testHandlers{}, ObjectiveAndWorkCreate: &testHandlers{},
		ObjectiveActivate: &testHandlers{}, RunPlanWithBindings: &testHandlers{}, RunJoin: &testHandlers{},
		RunStart: &testHandlers{}, ContextGet: &testHandlers{}, EventsSync: &testHandlers{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	client, closeMCP := connect(t, server)
	defer closeMCP()

	const secret = "bbm_00000000000000000000000000000000"
	result, err := client.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: ToolReservationAcquire,
		Arguments: reservationAcquireInput{AgentToken: secret, Mode: "exclusive", TTLSeconds: 60,
			Selectors: []reservationSelectorInput{{Kind: "exact", Path: "src/main.go"}}}})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("an unknown agent token was accepted")
	}
	logged := sink.String()
	if !strings.Contains(logged, ToolReservationAcquire) || !strings.Contains(logged, "tool failed") ||
		!strings.Contains(logged, string(domain.ErrorCodeUnauthenticated)) {
		t.Fatalf("failure log = %q, want the tool name, the failure and its code", logged)
	}
	// One failure earns one record. The coordination tools log their own with
	// the request id and the cause chain, so the generic middleware record would
	// only repeat the half of it that reached the caller anyway.
	if records := strings.Count(logged, "\"level\":\"ERROR\""); records != 1 {
		t.Fatalf("one failure produced %d records: %s", records, logged)
	}
	if !strings.Contains(logged, `"request_id":"req_`) {
		t.Fatalf("failure log carries no request id: %q", logged)
	}
	if strings.Contains(logged, secret) {
		t.Fatalf("failure log carried the caller's token: %q", logged)
	}
	// The caller is given the same identifier, so a bug report can name the
	// record an operator has to find.
	failure := coordinationFailureOf(t, result)
	if failure.Code != string(domain.ErrorCodeUnauthenticated) || !strings.Contains(logged, failure.RequestID) {
		t.Fatalf("caller failure = %+v, log = %q", failure, logged)
	}

	// A successful call is not noise: only failures earn a record.
	sink.Reset()
	callCoord[agentSessionOutput](t, client, ToolAgentRegister,
		registerAgentInput{ProjectKey: "/workspace/logged", AgentName: "alice"})
	if logged := sink.String(); logged != "" {
		t.Fatalf("successful call logged %q", logged)
	}
}

// TestCoordinationFailuresCarryTheirCodeAndTheirBlockers covers what an agent
// can do with a refusal. The SDK flattens a returned Go error into a bare
// string, so a lease conflict and a dead token used to arrive looking identical
// and the only remaining strategy was to give up or to retry something that
// could never work. A conflict has to name the holder, the time left, and a
// retry posture, because those are the inputs to every decision that follows.
func TestCoordinationFailuresCarryTheirCodeAndTheirBlockers(t *testing.T) {
	t.Parallel()
	client, alice, bob := newCoordinationSession(t, "failures.db")
	held := callCoord[reservationOutput](t, client, ToolReservationAcquire, reservationAcquireInput{
		AgentToken: alice, Mode: "exclusive", TTLSeconds: 300,
		Selectors: []reservationSelectorInput{{Kind: "exact", Path: "src/main.go"}}})

	conflict := callCoordFailure(t, client, ToolReservationAcquire, reservationAcquireInput{
		AgentToken: bob, Mode: "exclusive", TTLSeconds: 300,
		Selectors: []reservationSelectorInput{{Kind: "subtree", Path: "src"}}})
	if conflict.Code != string(domain.ErrorCodeLeaseConflict) || conflict.Category != string(domain.ErrorCategoryConflict) ||
		conflict.Conflict != string(domain.ConflictLease) || !conflict.Retryable {
		t.Fatalf("lease conflict = %+v, want a retryable machine-readable LEASE_CONFLICT", conflict)
	}
	if len(conflict.Blockers) != 1 || conflict.Blockers[0].HolderAgentName != "alice" ||
		conflict.Blockers[0].LeaseID != held.LeaseID || conflict.Blockers[0].Mode != "exclusive" {
		t.Fatalf("conflict blockers = %+v, want the lease alice holds", conflict.Blockers)
	}
	if conflict.Blockers[0].ExpiresInMS <= 0 || conflict.RetryAfterMS != conflict.Blockers[0].ExpiresInMS {
		t.Fatalf("conflict retry advice = %d, blocker = %+v", conflict.RetryAfterMS, conflict.Blockers[0])
	}
	if len(conflict.Blockers[0].Selectors) != 1 || conflict.Blockers[0].Selectors[0].Path != "src/main.go" {
		t.Fatalf("blocker selectors = %+v, want the path that overlapped", conflict.Blockers[0].Selectors)
	}

	// An agent's own lease never blocks it, so widening a reservation it already
	// holds must not report the agent to itself as a blocker.
	callCoord[reservationOutput](t, client, ToolReservationAcquire, reservationAcquireInput{
		AgentToken: alice, Mode: "exclusive", TTLSeconds: 300,
		Selectors: []reservationSelectorInput{{Kind: "exact", Path: "src/main.go"}}})

	unauthenticated := callCoordFailure(t, client, ToolAgentsList, tokenInput{AgentToken: "bbm_" + strings.Repeat("0", 32)})
	if unauthenticated.Code != string(domain.ErrorCodeUnauthenticated) || unauthenticated.Retryable ||
		len(unauthenticated.Blockers) != 0 {
		t.Fatalf("unauthenticated failure = %+v, want a terminal UNAUTHENTICATED with no blockers", unauthenticated)
	}
	invalid := callCoordFailure(t, client, ToolThreadFetch, map[string]any{
		"agent_token": bob, "conversation_id": "not-a-conversation"})
	if invalid.Code != string(domain.ErrorCodeInvalidArgument) || invalid.Category != string(domain.ErrorCategoryValidation) ||
		invalid.Retryable {
		t.Fatalf("invalid request failure = %+v, want a terminal INVALID_ARGUMENT", invalid)
	}
	stale := callCoordFailure(t, client, ToolReservationRelease, map[string]any{"agent_token": alice,
		"lease_id": held.LeaseID, "fences": []fenceOutput{{ConflictKey: held.Fences[0].ConflictKey, Counter: 1 << 20}}})
	if stale.Conflict != string(domain.ConflictFence) || stale.Retryable {
		t.Fatalf("stale fence failure = %+v, want a terminal FenceConflict", stale)
	}
	if stale.RequestID == "" || stale.Message == "" {
		t.Fatalf("failure omitted its identifier or its message: %+v", stale)
	}
}

// TestReservationsStatusAnswersWhoIsBlockingMe covers the question an agent
// could not ask at all: the reservation projection existed only on the
// operator's loopback CLI, which is not a surface the blocked agent has.
func TestReservationsStatusAnswersWhoIsBlockingMe(t *testing.T) {
	t.Parallel()
	client, alice, bob := newCoordinationSession(t, "status.db")
	callCoord[reservationOutput](t, client, ToolReservationAcquire, reservationAcquireInput{
		AgentToken: alice, Mode: "exclusive", TTLSeconds: 300,
		Selectors: []reservationSelectorInput{{Kind: "exact", Path: "src/main.go"}}})
	callCoord[reservationOutput](t, client, ToolReservationAcquire, reservationAcquireInput{
		AgentToken: bob, Mode: "shared", TTLSeconds: 300,
		Selectors: []reservationSelectorInput{{Kind: "subtree", Path: "docs"}}})

	// A subtree path is covered on directory boundaries, so asking about a file
	// inside it has to find the lease over the directory.
	covered := callCoord[reservationsStatusOutput](t, client, ToolReservationsStatus,
		reservationsStatusInput{AgentToken: alice, Path: "docs/guide.md"})
	if len(covered.Reservations) != 1 || covered.Reservations[0].HolderAgentName != "bob" ||
		covered.Reservations[0].Mode != "shared" || covered.Reservations[0].ExpiresInMS <= 0 {
		t.Fatalf("status for a covered path = %+v", covered.Reservations)
	}
	if covered.Reservations[0].HolderActorID == "" || covered.Truncated {
		t.Fatalf("status entry = %+v", covered.Reservations[0])
	}
	all := callCoord[reservationsStatusOutput](t, client, ToolReservationsStatus,
		reservationsStatusInput{AgentToken: bob})
	if len(all.Reservations) != 2 {
		t.Fatalf("unfiltered status = %+v, want both leases including the caller's own", all.Reservations)
	}
	free := callCoord[reservationsStatusOutput](t, client, ToolReservationsStatus,
		reservationsStatusInput{AgentToken: bob, Path: "internal/other.go"})
	if len(free.Reservations) != 0 {
		t.Fatalf("status for an unheld path = %+v", free.Reservations)
	}
	assertCoordinationInputRejected(t, client, ToolReservationsStatus, map[string]any{"agent_token": alice, "limit": 0})
}

// TestWaitReportsWhichConditionEndedIt covers the tool that turns a refusal into
// a queue. Which of the three things happened is returned rather than inferred,
// because a caller comparing timestamps gets it wrong exactly when the deadline
// and the release coincide.
func TestWaitReportsWhichConditionEndedIt(t *testing.T) {
	t.Parallel()
	client, alice, bob := newCoordinationSession(t, "wait.db")
	held := callCoord[reservationOutput](t, client, ToolReservationAcquire, reservationAcquireInput{
		AgentToken: alice, Mode: "exclusive", TTLSeconds: 300,
		Selectors: []reservationSelectorInput{{Kind: "exact", Path: "src/main.go"}}})

	blocked := callCoord[coordinationWaitOutput](t, client, ToolWait, coordinationWaitInput{
		AgentToken: bob, Path: "src/main.go", TimeoutSeconds: 1})
	if blocked.Reason != string(application.CoordinationWaitDeadline) || len(blocked.Blockers) != 1 ||
		blocked.Blockers[0].HolderAgentName != "alice" {
		t.Fatalf("wait on a held path = %+v", blocked)
	}
	// A holder that gave up its lease is not a blocker any more, and the waiter
	// has to be told so rather than sitting out the rest of its budget.
	callCoord[reservationOutput](t, client, ToolReservationRelease, map[string]any{
		"agent_token": alice, "lease_id": held.LeaseID, "fences": held.Fences})
	freed := callCoord[coordinationWaitOutput](t, client, ToolWait, coordinationWaitInput{
		AgentToken: bob, Path: "src/main.go", TimeoutSeconds: 30})
	if freed.Reason != string(application.CoordinationWaitPathFree) || len(freed.Blockers) != 0 {
		t.Fatalf("wait on a freed path = %+v", freed)
	}
	// A shared reader waits only for exclusive writers, and never for itself.
	callCoord[reservationOutput](t, client, ToolReservationAcquire, reservationAcquireInput{
		AgentToken: bob, Mode: "shared", TTLSeconds: 300,
		Selectors: []reservationSelectorInput{{Kind: "exact", Path: "src/main.go"}}})
	shared := callCoord[coordinationWaitOutput](t, client, ToolWait, coordinationWaitInput{
		AgentToken: alice, Path: "src/main.go", Mode: "shared", TimeoutSeconds: 30})
	if shared.Reason != string(application.CoordinationWaitPathFree) {
		t.Fatalf("shared wait behind a shared reader = %+v", shared)
	}
	// await_mail alone is a valid wait: reaching the deadline rather than an
	// argument failure is what proves the flag arrived at the store.
	mail := callCoord[coordinationWaitOutput](t, client, ToolWait, coordinationWaitInput{
		AgentToken: bob, AwaitMail: true, TimeoutSeconds: 1})
	if mail.Reason != string(application.CoordinationWaitDeadline) || mail.WaitedMS <= 0 {
		t.Fatalf("mail wait = %+v", mail)
	}
	neither := callCoordFailure(t, client, ToolWait, coordinationWaitInput{AgentToken: bob, TimeoutSeconds: 1})
	if neither.Code != string(domain.ErrorCodeInvalidArgument) {
		t.Fatalf("wait for nothing = %+v, want INVALID_ARGUMENT", neither)
	}
	assertCoordinationInputRejected(t, client, ToolWait, map[string]any{"agent_token": bob,
		"path": "src/main.go", "timeout_seconds": 600})
}

// TestBoundedWaitTimeoutClampsWhateverTheCallerAsksFor covers the guard behind
// the schema. A maximum in the schema binds only a client that validates
// against it, and a hold that outlives the caller's own request timeout is
// indistinguishable from a hung daemon.
func TestBoundedWaitTimeoutClampsWhateverTheCallerAsksFor(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		seconds  uint32
		expected time.Duration
	}{
		{name: "unset asks for the ceiling", seconds: 0, expected: application.MaxCoordinationWait},
		{name: "within the ceiling is honoured", seconds: 5, expected: 5 * time.Second},
		{name: "at the ceiling is honoured", seconds: uint32(application.MaxCoordinationWait / time.Second),
			expected: application.MaxCoordinationWait},
		{name: "beyond the ceiling is clamped", seconds: 86400, expected: application.MaxCoordinationWait},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := boundedWaitTimeout(testCase.seconds); got != testCase.expected {
				t.Fatalf("boundedWaitTimeout(%d) = %s, want %s", testCase.seconds, got, testCase.expected)
			}
		})
	}
}

// TestConversationSlugReopensTheSameThread covers what a compacted agent cannot
// infer. Without a stable name, reopening "the auth refactor" mints a second
// conversation and every reply its teammates already wrote stays in a thread it
// can no longer name.
func TestConversationSlugReopensTheSameThread(t *testing.T) {
	t.Parallel()
	client, alice, bob := newCoordinationSession(t, "slug.db")
	opened := callCoord[conversationOutput](t, client, ToolConversationOpen, openConversationInput{
		AgentToken: alice, Topic: "auth refactor", Slug: "auth-refactor"})
	if opened.Reused || opened.Slug != "auth-refactor" || opened.ConversationID == "" {
		t.Fatalf("first open = %+v, want a fresh conversation under the slug", opened)
	}
	reopened := callCoord[conversationOutput](t, client, ToolConversationOpen, openConversationInput{
		AgentToken: alice, Topic: "something else entirely", Slug: "auth-refactor"})
	if !reopened.Reused || reopened.ConversationID != opened.ConversationID || reopened.Topic != opened.Topic {
		t.Fatalf("reopen = %+v, want the stored conversation %+v", reopened, opened)
	}
	// The slug is per repository rather than per agent: finding a teammate's
	// thread is the whole reason to name one.
	joined := callCoord[conversationOutput](t, client, ToolConversationOpen, openConversationInput{
		AgentToken: bob, Topic: "auth refactor", Slug: "auth-refactor"})
	if !joined.Reused || joined.ConversationID != opened.ConversationID {
		t.Fatalf("teammate open = %+v, want the same conversation", joined)
	}
	callCoord[messageOutput](t, client, ToolMessageSend, sendMessageInput{AgentToken: bob,
		ConversationID: joined.ConversationID, To: []string{"alice"}, Subject: "found it", Body: "in the same thread"})
	thread := callCoord[messagePageOutput](t, client, ToolThreadFetch, map[string]any{
		"agent_token": alice, "conversation_id": opened.ConversationID})
	if len(thread.Messages) != 1 {
		t.Fatalf("thread after a reopen = %+v", thread.Messages)
	}
	// A conversation nobody has to find again still opens without a slug.
	anonymous := callCoord[conversationOutput](t, client, ToolConversationOpen, openConversationInput{
		AgentToken: alice, Topic: "one-off"})
	if anonymous.Reused || anonymous.Slug != "" || anonymous.ConversationID == opened.ConversationID {
		t.Fatalf("unslugged open = %+v", anonymous)
	}
}

// TestCoordinationFailureMapsEveryShapeOfError covers the two ends of the
// mapping that a tool call cannot reach: an error the daemon never meant to
// describe, and a domain sentinel that carries a code but no message.
func TestCoordinationFailureMapsEveryShapeOfError(t *testing.T) {
	t.Parallel()
	opaque := coordinationFailure("req_opaque", errors.New("a storage detail nobody outside the daemon may read"))
	if opaque.Code != string(domain.ErrorCodeInternal) || opaque.Category != string(domain.ErrorCategoryInternal) ||
		!opaque.Retryable {
		t.Fatalf("opaque failure = %+v, want a retryable INTERNAL", opaque)
	}
	if strings.Contains(opaque.Message, "storage detail") {
		t.Fatalf("opaque failure leaked its cause: %+v", opaque)
	}
	sentinel := coordinationFailure("req_sentinel", fmt.Errorf("wrapped: %w", domain.ErrNotFound))
	if sentinel.Code != string(domain.ErrorCodeNotFound) || sentinel.Message == "" || sentinel.Retryable {
		t.Fatalf("sentinel failure = %+v, want NOT_FOUND with a message", sentinel)
	}
}

// TestSoonestExpiryAdvisesTheShortestWaitThatCanClear covers the retry advice.
// A shorter wait retries into the same refusal; a longer one idles past the
// moment the path came free.
func TestSoonestExpiryAdvisesTheShortestWaitThatCanClear(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		blockers []reservationHolderOutput
		expected int64
	}{
		{name: "no blockers advise no wait"},
		{name: "one blocker advises its own remainder",
			blockers: []reservationHolderOutput{{ExpiresInMS: 5000}}, expected: 5000},
		{name: "many blockers advise the first to lapse",
			blockers: []reservationHolderOutput{{ExpiresInMS: 5000}, {ExpiresInMS: 900}, {ExpiresInMS: 2000}},
			expected: 900},
		{name: "an overdue blocker advises no wait at all",
			blockers: []reservationHolderOutput{{ExpiresInMS: 5000}, {ExpiresInMS: -1}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := soonestExpiry(testCase.blockers); got != testCase.expected {
				t.Fatalf("soonestExpiry(%+v) = %d, want %d", testCase.blockers, got, testCase.expected)
			}
		})
	}
}

func TestDescribeLeaseConflictUsesRequestedMode(t *testing.T) {
	t.Parallel()

	actor, err := domain.NewActorID()
	if err != nil {
		t.Fatal(err)
	}
	selector, err := application.NewLeaseSelector(application.LeaseSelectorExact, "src/main.go")
	if err != nil {
		t.Fatal(err)
	}
	session := application.LocalAgentSession{ActorID: actor}
	for _, testCase := range []struct {
		name string
		mode application.LeaseMode
		want application.LeaseMode
	}{
		{name: "shared waits only on writers", mode: application.LeaseShared, want: application.LeaseExclusive},
		{name: "exclusive waits on everyone", mode: application.LeaseExclusive},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store := &leaseConflictQueryStore{}
			err := describeLeaseConflict(context.Background(), store, session, testCase.mode,
				[]application.LeaseSelector{selector}, domain.ErrLeaseConflict)
			if err == nil || !errors.Is(err, domain.ErrLeaseConflict) {
				t.Fatalf("error = %v, want lease conflict", err)
			}
			if store.query.Mode != testCase.want {
				t.Fatalf("query mode = %q, want %q", store.query.Mode, testCase.want)
			}
		})
	}
}

type leaseConflictQueryStore struct {
	application.LocalCoordinationStore
	query application.AdminReservationsQuery
}

func (store *leaseConflictQueryStore) LocalAgentReservations(_ context.Context, _ application.LocalAgentSession,
	query application.AdminReservationsQuery) (application.AdminReservationsPage, error) {
	store.query = query
	return application.AdminReservationsPage{}, nil
}

func newCoordinationSession(t *testing.T, name string) (*sdkmcp.ClientSession, string, string) {
	t.Helper()
	store, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), name)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server := newTestServer(t, &testHandlers{events: successfulEvents, context: contextFailure},
		&testSessionBinder{session: parseSession(t)}, store)
	client, closeMCP := connect(t, server)
	t.Cleanup(closeMCP)
	alice := callCoord[agentSessionOutput](t, client, ToolAgentRegister,
		registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "alice"})
	bob := callCoord[agentSessionOutput](t, client, ToolAgentRegister,
		registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "bob"})
	return client, alice.RegistrationToken, bob.RegistrationToken
}

func callCoordFailure(t *testing.T, session *sdkmcp.ClientSession, tool string, input any) coordinationFailureOutput {
	t.Helper()
	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: tool, Arguments: input})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return coordinationFailureOf(t, result)
}

func coordinationFailureOf(t *testing.T, result *sdkmcp.CallToolResult) coordinationFailureOutput {
	t.Helper()
	if !result.IsError {
		t.Fatalf("call succeeded where a failure was expected: %+v", result.StructuredContent)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal failure: %v", err)
	}
	var failure coordinationFailureOutput
	if err := json.Unmarshal(encoded, &failure); err != nil {
		t.Fatalf("decode failure %s: %v", encoded, err)
	}
	if failure.Code == "" {
		t.Fatalf("failure reached the agent without a code: %s", encoded)
	}
	return failure
}

// lockedBuffer is written from the server's goroutine and read from the test's.
type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (sink *lockedBuffer) Write(payload []byte) (int, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.buffer.Write(payload)
}

func (sink *lockedBuffer) String() string {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.buffer.String()
}

func (sink *lockedBuffer) Reset() {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.buffer.Reset()
}

func assertCoordinationToolSchemas(t *testing.T, session *sdkmcp.ClientSession) {
	t.Helper()
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list coordination tools: %v", err)
	}
	tools := make(map[string]sdkmcp.Tool, len(result.Tools))
	for _, tool := range result.Tools {
		tools[tool.Name] = *tool
	}
	expectedDefaults := map[string]map[string]any{
		ToolMessageSend:        {"acknowledgement_required": false},
		ToolMessageReply:       {"acknowledgement_required": false},
		ToolInboxFetch:         {"unread_only": false, "after": float64(0), "limit": float64(50)},
		ToolThreadFetch:        {"after": float64(0), "limit": float64(50)},
		ToolReservationAcquire: {"mode": "exclusive", "ttl_seconds": float64(3600)},
		ToolReservationRenew:   {"ttl_seconds": float64(3600)},
		ToolReservationsStatus: {"limit": float64(50)},
		ToolWait:               {"await_mail": false, "mode": "exclusive", "timeout_seconds": float64(60)},
	}
	for toolName, defaults := range expectedDefaults {
		tool, ok := tools[toolName]
		if !ok {
			t.Fatalf("coordination tool %q was not discovered", toolName)
		}
		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s schema: %v", toolName, err)
		}
		var schema struct {
			Properties map[string]struct {
				Default any `json:"default"`
			} `json:"properties"`
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Fatalf("decode %s schema: %v", toolName, err)
		}
		for field, want := range defaults {
			if slicesContains(schema.Required, field) {
				t.Errorf("%s schema requires optional field %q", toolName, field)
			}
			if got := schema.Properties[field].Default; !reflect.DeepEqual(got, want) {
				t.Errorf("%s.%s default = %#v, want %#v", toolName, field, got, want)
			}
		}
	}

	for name, tool := range tools {
		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s schema: %v", name, err)
		}
		var schema struct {
			Properties map[string]struct {
				Description string `json:"description"`
				Enum        []any  `json:"enum"`
				Items       struct {
					Properties map[string]struct {
						Enum []any `json:"enum"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Fatalf("decode %s schema: %v", name, err)
		}
		token, ok := schema.Properties["agent_token"]
		if !ok {
			continue
		}
		if !strings.Contains(token.Description, "registration_token") {
			t.Errorf("%s.agent_token description does not name registration_token: %q", name, token.Description)
		}
	}

	// A tool description and its parameter descriptions are the only
	// documentation an agent ever reads: there is no manual to consult and no
	// second call that explains the first. An undescribed parameter is guessed
	// at, and a guessed parameter is a failed call.
	for _, name := range coordinationToolNames {
		tool := tools[name]
		if len(tool.Description) < 40 {
			t.Errorf("coordination tool %q has no usable description: %q", name, tool.Description)
		}
		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s schema: %v", name, err)
		}
		var described struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(encoded, &described); err != nil {
			t.Fatalf("decode %s schema: %v", name, err)
		}
		for property, value := range described.Properties {
			if value.Description == "" {
				t.Errorf("%s.%s has no description", name, property)
			}
		}
	}

	// The slug is the property a compacted agent cannot infer, so it has to be
	// stated where the agent looks rather than in a commit message.
	open := tools[ToolConversationOpen]
	openSchema, err := json.Marshal(open.InputSchema)
	if err != nil {
		t.Fatalf("marshal conversation_open schema: %v", err)
	}
	var openDecoded struct {
		Properties struct {
			Slug struct {
				Description string `json:"description"`
			} `json:"slug"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(openSchema, &openDecoded); err != nil {
		t.Fatalf("decode conversation_open schema: %v", err)
	}
	if slicesContains(openDecoded.Required, "slug") {
		t.Error("conversation_open requires a slug")
	}
	if !strings.Contains(openDecoded.Properties.Slug.Description, "same") {
		t.Errorf("slug description does not say that reopening returns the same conversation: %q",
			openDecoded.Properties.Slug.Description)
	}

	acquire := tools[ToolReservationAcquire]
	acquireSchema, err := json.Marshal(acquire.InputSchema)
	if err != nil {
		t.Fatalf("marshal acquire schema: %v", err)
	}
	var acquireDecoded struct {
		Properties struct {
			Selectors struct {
				Items struct {
					Properties struct {
						Kind struct {
							Enum []any `json:"enum"`
						} `json:"kind"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"selectors"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(acquireSchema, &acquireDecoded); err != nil {
		t.Fatalf("decode acquire schema: %v", err)
	}
	if kinds := acquireDecoded.Properties.Selectors.Items.Properties.Kind.Enum; !reflect.DeepEqual(kinds, []any{"exact", "subtree"}) {
		t.Errorf("selector kind enum = %#v, want exact and subtree", kinds)
	}

	// agent_register is the one tool whose result an agent must act on, so its
	// description still names the state it returns even though repeated output
	// schemas are deliberately omitted from discovery.
	register := tools[ToolAgentRegister]
	if !strings.Contains(register.Description, "reservations") {
		t.Errorf("agent_register description does not mention the reservations it returns: %q", register.Description)
	}

	// The wait ceiling is published as well as enforced, so a client discovers
	// the bound instead of learning it from a budget that came back shorter than
	// it asked for.
	wait := tools[ToolWait]
	waitSchema, err := json.Marshal(wait.InputSchema)
	if err != nil {
		t.Fatalf("marshal wait schema: %v", err)
	}
	var waitDecoded struct {
		Properties struct {
			TimeoutSeconds struct {
				Maximum *float64 `json:"maximum"`
			} `json:"timeout_seconds"`
			Mode struct {
				Enum []any `json:"enum"`
			} `json:"mode"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(waitSchema, &waitDecoded); err != nil {
		t.Fatalf("decode wait schema: %v", err)
	}
	ceiling := application.MaxCoordinationWait.Seconds()
	if maximum := waitDecoded.Properties.TimeoutSeconds.Maximum; maximum == nil || *maximum != ceiling {
		t.Errorf("wait timeout maximum = %v, want the daemon ceiling %v", maximum, ceiling)
	}
	if modes := waitDecoded.Properties.Mode.Enum; !reflect.DeepEqual(modes, []any{"shared", "exclusive"}) {
		t.Errorf("wait mode enum = %#v, want shared and exclusive", modes)
	}
	// Output shapes are repeated in every discovery response but add no runtime
	// capability: the SDK still emits structuredContent and its JSON text
	// fallback. Keeping them nil is the wire-size contract this test protects.
	for _, name := range coordinationToolNames {
		if tools[name].OutputSchema != nil {
			t.Errorf("%s publishes a redundant output schema", name)
		}
	}

	release := tools[ToolReservationRelease]
	encoded, err := json.Marshal(release.InputSchema)
	if err != nil {
		t.Fatalf("marshal release schema: %v", err)
	}
	if bytes.Contains(encoded, []byte(`"ttl_seconds"`)) {
		t.Fatalf("release schema includes ttl_seconds: %s", encoded)
	}
}

func slicesContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertCoordinationInputRejected(t *testing.T, session *sdkmcp.ClientSession, tool string, input any) {
	t.Helper()
	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: tool, Arguments: input})
	if err != nil {
		t.Fatalf("%s invalid call: %v", tool, err)
	}
	if !result.IsError {
		t.Fatalf("%s accepted invalid input: %#v", tool, input)
	}
}

func callCoord[Output any](t *testing.T, session *sdkmcp.ClientSession, tool string, input any) Output {
	t.Helper()
	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: tool, Arguments: input})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if result.IsError {
		t.Fatalf("%s tool error: %+v", tool, result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal %s output: %v", tool, err)
	}
	var output Output
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("decode %s output: %v", tool, err)
	}
	return output
}

func callHTTP(t *testing.T, handlers *testHandlers, request contracts.EventsSyncRequestDTO) ([]byte, int) {
	t.Helper()
	handler, err := httptransport.NewHandler(httptransport.Dependencies{
		Authenticator: testHTTPAuthenticator{}, InstallationBootstrap: handlers, PrincipalRegister: handlers,
		DevicePairingBegin: handlers, DevicePair: handlers, WorkspaceCreate: handlers, WorkspaceMemberInvite: handlers,
		WorkspaceMembershipAccept: handlers, ActorCreate: handlers, ActorDelegationPropose: handlers,
		ActorDelegationActivate: handlers, SessionStart: handlers, ContextGet: handlers, EventsSync: handlers,
		WorkRefObserve: handlers, ObjectiveAndWorkCreate: handlers, ObjectiveActivate: handlers,
		RunPlanWithBindings: handlers, RunJoin: handlers, RunStart: handlers,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	httpRequest := httptest.NewRequest(stdhttp.MethodPost, httptransport.PathEventsSync, bytes.NewReader(body))
	httpRequest.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	return response.Body.Bytes(), response.Code
}

func callMCP(t *testing.T, handlers *testHandlers, request contracts.EventsSyncRequestDTO) *sdkmcp.CallToolResult {
	t.Helper()
	server := newTestServer(t, handlers, &testSessionBinder{session: request.ActorSessionID})
	clientSession, closeSessions := connect(t, server)
	defer closeSessions()
	result, err := clientSession.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: ToolEventsSync, Arguments: request})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

func newTestServer(t *testing.T, handlers *testHandlers, binder CurrentSessionBinder, coordination ...application.LocalCoordinationStore) *Server {
	t.Helper()
	return newServerExposing(t, true, handlers, binder, coordination...)
}

func newServerExposing(t *testing.T, identityPlane bool, handlers *testHandlers, binder CurrentSessionBinder,
	coordination ...application.LocalCoordinationStore) *Server {
	t.Helper()
	var coordinationStore application.LocalCoordinationStore
	if len(coordination) != 0 {
		coordinationStore = coordination[0]
	}
	server, err := NewServer(Dependencies{
		Authenticator: testMCPAuthenticator{}, CurrentSession: binder, InstallationBootstrap: handlers,
		Coordination:        coordinationStore,
		ExposeIdentityPlane: identityPlane,
		PrincipalRegister:   handlers, DevicePairingBegin: handlers, DevicePair: handlers, WorkspaceCreate: handlers,
		WorkspaceMemberInvite: handlers, WorkspaceMembershipAccept: handlers, ActorCreate: handlers,
		ActorDelegationPropose: handlers, ActorDelegationActivate: handlers, SessionStart: handlers,
		WorkRefObserve: handlers, ObjectiveAndWorkCreate: handlers, ObjectiveActivate: handlers,
		RunPlanWithBindings: handlers, RunJoin: handlers, RunStart: handlers,
		ContextGet: handlers, EventsSync: handlers,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

func connect(t *testing.T, server *Server) (*sdkmcp.ClientSession, func()) {
	t.Helper()
	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server Connect: %v", err)
	}
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "blackbird-test", Version: "v1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		t.Fatalf("client Connect: %v", err)
	}
	return clientSession, func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	}
}

func parseSession(t *testing.T) domain.ActorSessionID {
	t.Helper()
	session, err := domain.ParseActorSessionID(testActorSessionID)
	if err != nil {
		t.Fatalf("parse session: %v", err)
	}
	return session
}

func validEventsRequest(session domain.ActorSessionID) contracts.EventsSyncRequestDTO {
	return contracts.EventsSyncRequestDTO{Schema: contracts.SchemaEventsSyncRequest, RequestID: "req-parity",
		Operation: contracts.OperationEventsSync, ActorSessionID: session, AfterCursor: "bbec1_fixture", Limit: 64}
}

func successfulEvents(_ context.Context, _ contracts.AuthenticationEvidence, request contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
	return contracts.EventPageDTO{Schema: contracts.SchemaEventPage, RequestID: request.RequestID,
		Operation: contracts.OperationEventsSync, Events: []contracts.RawEventEnvelopeDTO{},
		NextCursor: request.AfterCursor, HeadCursor: "bbec1_head", HasMore: false}, nil, nil
}

func eventsFailure(_ context.Context, _ contracts.AuthenticationEvidence, request contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
	failure := cursorFailure(request.RequestID)
	return contracts.EventPageDTO{}, &failure, nil
}

func contextFailure(_ context.Context, _ contracts.AuthenticationEvidence, request contracts.ContextGetRequestDTO) (contracts.ContextPageDTO, *contracts.ErrorDTO, error) {
	failure := cursorFailure(request.RequestID)
	return contracts.ContextPageDTO{}, &failure, nil
}

func cursorFailure(requestID string) contracts.ErrorDTO {
	return contracts.ErrorDTO{Schema: contracts.SchemaError, RequestID: requestID, Code: domain.ErrorCodeCursorExpired,
		Category: domain.ErrorCategoryCursor, Message: "The cursor expired.",
		Details: contracts.ErrorDetailsDTO{Recovery: contracts.RecoveryObtainCheckpoint}}
}
