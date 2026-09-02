package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
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
	callCoord[agentSessionOutput](t, client, ToolAgentRegister, registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "alice", RegistrationToken: &aliceToken})
	callCoord[agentSessionOutput](t, client, ToolAgentRegister, registerAgentInput{ProjectKey: "/workspace/repo", AgentName: "bob", RegistrationToken: &bobToken})
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
	if !listed[ToolAgentRegister] || !listed[ToolReservationAcquire] || len(listed) != 12 {
		t.Fatalf("coordination surface = %d tools, want the 12 coordination tools: %v", len(listed), listed)
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
