package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/transport/contracts"
	httptransport "github.com/phall1/blackbird/internal/transport/http"
)

const testActorSessionID = "01b8e094-9888-7000-8000-00000000001f"

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
	if len(tools.Tools) != 13 {
		t.Fatalf("tool count = %d, want 13", len(tools.Tools))
	}
	for _, tool := range tools.Tools {
		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal schema for %s: %v", tool.Name, err)
		}
		if !bytes.Contains(encoded, []byte(`"additionalProperties":false`)) {
			t.Fatalf("tool %s has permissive input schema: %s", tool.Name, encoded)
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

func TestNewServerRequiresCompleteComposition(t *testing.T) {
	t.Parallel()
	if _, err := NewServer(Dependencies{}); err == nil {
		t.Fatal("NewServer() error = nil, want incomplete-composition error")
	}
}

func callHTTP(t *testing.T, handlers *testHandlers, request contracts.EventsSyncRequestDTO) ([]byte, int) {
	t.Helper()
	handler, err := httptransport.NewHandler(httptransport.Dependencies{
		Authenticator: testHTTPAuthenticator{}, InstallationBootstrap: handlers, PrincipalRegister: handlers,
		DevicePairingBegin: handlers, DevicePair: handlers, WorkspaceCreate: handlers, WorkspaceMemberInvite: handlers,
		WorkspaceMembershipAccept: handlers, ActorCreate: handlers, ActorDelegationPropose: handlers,
		ActorDelegationActivate: handlers, SessionStart: handlers, ContextGet: handlers, EventsSync: handlers,
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

func newTestServer(t *testing.T, handlers *testHandlers, binder CurrentSessionBinder) *Server {
	t.Helper()
	server, err := NewServer(Dependencies{
		Authenticator: testMCPAuthenticator{}, CurrentSession: binder, InstallationBootstrap: handlers,
		PrincipalRegister: handlers, DevicePairingBegin: handlers, DevicePair: handlers, WorkspaceCreate: handlers,
		WorkspaceMemberInvite: handlers, WorkspaceMembershipAccept: handlers, ActorCreate: handlers,
		ActorDelegationPropose: handlers, ActorDelegationActivate: handlers, SessionStart: handlers,
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
