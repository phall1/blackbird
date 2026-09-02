package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/transport/contracts"
)

const actorSessionID = "01b8e094-9888-7000-8000-00000000001f"

type testAuthenticator struct {
	operation string
	seenDone  bool
	evidence  *AuthenticationEvidence
	failure   *contracts.ErrorDTO
	err       error
}

func (authenticator *testAuthenticator) Authenticate(
	ctx context.Context,
	_ *http.Request,
	operation string,
	requestID string,
) (AuthenticationEvidence, *contracts.ErrorDTO, error) {
	authenticator.operation = operation
	authenticator.seenDone = ctx.Err() != nil
	if authenticator.failure != nil {
		failure := *authenticator.failure
		failure.RequestID = requestID
		return AuthenticationEvidence{}, &failure, authenticator.err
	}
	if authenticator.err != nil {
		return AuthenticationEvidence{}, nil, authenticator.err
	}
	if authenticator.evidence != nil {
		return *authenticator.evidence, nil, nil
	}
	return validAuthenticationEvidence(), nil, nil
}

// sessionBoundEvidence is the evidence an authenticated agent presents: the
// same trusted tuple plus the actor session the access record reports.
func sessionBoundEvidence(t *testing.T) AuthenticationEvidence {
	t.Helper()
	session, err := domain.ParseActorSessionID(actorSessionID)
	if err != nil {
		t.Fatalf("parse actor session: %v", err)
	}
	base := validAuthenticationEvidence()
	provenance, err := contracts.NewAuthenticationAuditProvenance(base.AuditProvenance().SourceAuthorityID(), nil)
	if err != nil {
		t.Fatalf("audit provenance: %v", err)
	}
	evidence, err := contracts.NewAuthenticationEvidence(contracts.AuthenticationEvidenceParams{
		PrincipalID: base.PrincipalID(), PrincipalRevision: base.PrincipalRevision(),
		ActorSessionID: &session, ActorSessionRevision: domain.InitialVersion(),
		ChannelBinding: base.ChannelBindingDigest(), Audience: base.Audience(),
		AuditProvenance: provenance, VerifiedAt: base.VerifiedAt(),
	})
	if err != nil {
		t.Fatalf("session-bound evidence: %v", err)
	}
	return evidence
}

func validAuthenticationEvidence() AuthenticationEvidence {
	principal, err := domain.ParsePrincipalID("01b8e094-9888-7000-8000-000000000004")
	if err != nil {
		panic(err)
	}
	authority, err := domain.ParseAuthorityID("01b8e094-9888-7000-8000-000000000003")
	if err != nil {
		panic(err)
	}
	binding, err := contracts.NewChannelBindingDigest(strings.Repeat("a", 64))
	if err != nil {
		panic(err)
	}
	audience, err := contracts.NewAuthenticationAudience("blackbird-product-api")
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

type testHandlers struct {
	InstallationBootstrapHandler
	PrincipalRegisterHandler
	DevicePairingBeginHandler
	DevicePairHandler
	WorkspaceCreateHandler
	WorkspaceMemberInviteHandler
	WorkspaceMembershipAcceptHandler
	ActorCreateHandler
	ActorDelegationProposeHandler
	ActorDelegationActivateHandler
	SessionStartHandler
	WorkRefObserveHandler
	ObjectiveAndWorkCreateHandler
	ObjectiveActivateHandler
	RunPlanWithBindingsHandler
	RunJoinHandler
	RunStartHandler
	ContextGetHandler
	events func(context.Context, AuthenticationEvidence, contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error)
}

func (handlers *testHandlers) HandleEventsSync(
	ctx context.Context,
	evidence AuthenticationEvidence,
	request contracts.EventsSyncRequestDTO,
) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
	return handlers.events(ctx, evidence, request)
}

func testDependencies(authenticator Authenticator, handlers *testHandlers) Dependencies {
	return Dependencies{
		Authenticator:             authenticator,
		InstallationBootstrap:     handlers,
		PrincipalRegister:         handlers,
		DevicePairingBegin:        handlers,
		DevicePair:                handlers,
		WorkspaceCreate:           handlers,
		WorkspaceMemberInvite:     handlers,
		WorkspaceMembershipAccept: handlers,
		ActorCreate:               handlers,
		ActorDelegationPropose:    handlers,
		ActorDelegationActivate:   handlers,
		SessionStart:              handlers,
		WorkRefObserve:            handlers,
		ObjectiveAndWorkCreate:    handlers,
		ObjectiveActivate:         handlers,
		RunPlanWithBindings:       handlers,
		RunJoin:                   handlers,
		RunStart:                  handlers,
		ContextGet:                handlers,
		EventsSync:                handlers,
	}
}

func newTestHandler(t *testing.T, authenticator *testAuthenticator, handlers *testHandlers) http.Handler {
	t.Helper()
	handler, err := NewHandler(testDependencies(authenticator, handlers))
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func TestNewHandlerRequiresCompleteComposition(t *testing.T) {
	t.Parallel()
	if _, err := NewHandler(Dependencies{}); err == nil {
		t.Fatal("NewHandler() error = nil, want incomplete-composition error")
	}
}

func TestAllRoutesAreLiteralPOSTRoutes(t *testing.T) {
	t.Parallel()
	authenticator := &testAuthenticator{}
	handlers := &testHandlers{events: successfulEvents}
	handler := newTestHandler(t, authenticator, handlers)
	routes := []struct {
		path      string
		operation string
	}{
		{PathInstallationBootstrap, contracts.OperationInstallationBootstrap},
		{PathPrincipalRegister, contracts.OperationPrincipalRegister},
		{PathDevicePairingBegin, contracts.OperationDevicePairingBegin},
		{PathDevicePair, contracts.OperationDevicePair},
		{PathWorkspaceCreate, contracts.OperationWorkspaceCreate},
		{PathWorkspaceMemberInvite, contracts.OperationWorkspaceMemberInvite},
		{PathWorkspaceMembershipAccept, contracts.OperationWorkspaceMembershipAccept},
		{PathActorCreate, contracts.OperationActorCreate},
		{PathActorDelegationPropose, contracts.OperationActorDelegationPropose},
		{PathActorDelegationActivate, contracts.OperationActorDelegationActivate},
		{PathSessionStart, contracts.OperationSessionStart},
		{PathWorkRefObserve, contracts.OperationWorkRefObserve},
		{PathObjectiveAndWorkCreate, contracts.OperationObjectiveAndWorkCreate},
		{PathObjectiveActivate, contracts.OperationObjectiveActivate},
		{PathRunPlanWithBindings, contracts.OperationRunPlanWithBindings},
		{PathRunJoin, contracts.OperationRunJoin},
		{PathRunStart, contracts.OperationRunStart},
		{PathContextGet, contracts.OperationContextGet},
		{PathEventsSync, contracts.OperationEventsSync},
	}
	for _, route := range routes {
		request := httptest.NewRequest(http.MethodPost, route.path, strings.NewReader(`{}`))
		request.Header.Set("Content-Type", mediaTypeJSON)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnprocessableEntity {
			t.Errorf("POST %s status = %d, want %d", route.path, response.Code, http.StatusUnprocessableEntity)
		}
		if authenticator.operation != route.operation {
			t.Errorf("POST %s authenticated operation = %q, want %q", route.path, authenticator.operation, route.operation)
		}
	}

	request := httptest.NewRequest(http.MethodGet, PathEventsSync, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET route status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestEventsSyncStrictBoundaryAndStableEncoding(t *testing.T) {
	t.Parallel()
	authenticator := &testAuthenticator{}
	handlers := &testHandlers{events: successfulEvents}
	handler := newTestHandler(t, authenticator, handlers)
	body := validEventsRequest(t)

	var prior []byte
	for attempt := 0; attempt < 2; attempt++ {
		request := httptest.NewRequest(http.MethodPost, PathEventsSync, bytes.NewReader(body))
		request.Header.Set("Content-Type", mediaTypeJSON)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != mediaTypeJSON {
			t.Fatalf("response = (%d, %q), want (200, application/json)", response.Code, response.Header().Get("Content-Type"))
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
		}
		if attempt > 0 && !bytes.Equal(prior, response.Body.Bytes()) {
			t.Fatalf("successful response changed across replay\nfirst: %s\nnext:  %s", prior, response.Body.Bytes())
		}
		prior = append([]byte(nil), response.Body.Bytes()...)
	}
	if authenticator.operation != contracts.OperationEventsSync {
		t.Fatalf("authenticated operation = %q, want %q", authenticator.operation, contracts.OperationEventsSync)
	}
}

func TestHTTPBoundaryRejectsMediaTypesAndOversizeBodies(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, &testAuthenticator{}, &testHandlers{events: successfulEvents})
	tests := []struct {
		name        string
		contentType string
		encoding    string
		body        []byte
	}{
		{name: "missing content type", body: validEventsRequest(t)},
		{name: "content type parameters", contentType: "application/json; charset=utf-8", body: validEventsRequest(t)},
		{name: "compressed", contentType: mediaTypeJSON, encoding: "gzip", body: validEventsRequest(t)},
		{name: "oversize", contentType: mediaTypeJSON, body: bytes.Repeat([]byte("x"), contracts.MaxCommandJSONBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, PathEventsSync, bytes.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			if test.encoding != "" {
				request.Header.Set("Content-Encoding", test.encoding)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnprocessableEntity || response.Header().Get("Content-Type") != mediaTypeProblem {
				t.Fatalf("response = (%d, %q), want (422, application/problem+json)", response.Code, response.Header().Get("Content-Type"))
			}
		})
	}
}

func TestTypedFailureAndCancellation(t *testing.T) {
	t.Parallel()
	authenticator := &testAuthenticator{}
	handlers := &testHandlers{events: func(_ context.Context, _ AuthenticationEvidence, request contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
		failure := contracts.ErrorDTO{
			Schema: contracts.SchemaError, RequestID: request.RequestID, Code: domain.ErrorCodeCursorExpired,
			Category: domain.ErrorCategoryCursor, Message: "The event cursor expired.",
			Details: contracts.ErrorDetailsDTO{Recovery: contracts.RecoveryObtainCheckpoint},
		}
		return contracts.EventPageDTO{}, &failure, nil
	}}
	handler := newTestHandler(t, authenticator, handlers)
	request := httptest.NewRequest(http.MethodPost, PathEventsSync, bytes.NewReader(validEventsRequest(t)))
	request.Header.Set("Content-Type", mediaTypeJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusGone {
		t.Fatalf("typed failure status = %d, want 410", response.Code)
	}
	var problem struct {
		Status int              `json:"status"`
		Code   domain.ErrorCode `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Status != http.StatusGone || problem.Code != domain.ErrorCodeCursorExpired {
		t.Fatalf("problem = %+v, want CURSOR_EXPIRED/410", problem)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	request = httptest.NewRequest(http.MethodPost, PathEventsSync, bytes.NewReader(validEventsRequest(t))).WithContext(canceled)
	request.Header.Set("Content-Type", mediaTypeJSON)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !authenticator.seenDone {
		t.Fatal("authenticator did not receive canceled request context")
	}
}

func TestAuthenticatorInternalErrorIsNotDisclosed(t *testing.T) {
	t.Parallel()
	authenticator := &testAuthenticator{err: errors.New("credential backend secret")}
	handler := newTestHandler(t, authenticator, &testHandlers{events: successfulEvents})
	request := httptest.NewRequest(http.MethodPost, PathEventsSync, bytes.NewReader(validEventsRequest(t)))
	request.Header.Set("Content-Type", mediaTypeJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "credential backend secret") {
		t.Fatalf("response status/body = %d/%s", response.Code, response.Body.String())
	}
}

func TestAuthenticatorTypedFailureUsesTransportRequestID(t *testing.T) {
	t.Parallel()
	authenticator := &testAuthenticator{failure: &contracts.ErrorDTO{
		Schema: contracts.SchemaError, Code: domain.ErrorCodeUnauthenticated,
		Category: domain.ErrorCategoryAuthentication, Message: "Authentication is required.",
		Details: contracts.ErrorDetailsDTO{Recovery: contracts.RecoveryReauthenticate},
	}}
	handler := newTestHandler(t, authenticator, &testHandlers{events: successfulEvents})
	request := httptest.NewRequest(http.MethodPost, PathEventsSync, bytes.NewReader(validEventsRequest(t)))
	request.Header.Set("Content-Type", mediaTypeJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "req-events-http") {
		t.Fatalf("response status/body = %d/%s", response.Code, response.Body.String())
	}
}

func validEventsRequest(t *testing.T) []byte {
	t.Helper()
	session, err := domain.ParseActorSessionID(actorSessionID)
	if err != nil {
		t.Fatalf("parse actor session: %v", err)
	}
	encoded, err := json.Marshal(contracts.EventsSyncRequestDTO{
		Schema: contracts.SchemaEventsSyncRequest, RequestID: "req-events-http", Operation: contracts.OperationEventsSync,
		ActorSessionID: session, AfterCursor: "bbec1_fixture", Limit: 64,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return encoded
}

func successfulEvents(
	_ context.Context,
	_ AuthenticationEvidence,
	request contracts.EventsSyncRequestDTO,
) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
	return contracts.EventPageDTO{
		Schema: contracts.SchemaEventPage, RequestID: request.RequestID, Operation: contracts.OperationEventsSync,
		Events: []contracts.RawEventEnvelopeDTO{}, NextCursor: request.AfterCursor, HeadCursor: "bbec1_head", HasMore: false,
	}, nil, nil
}

// logSink collects handler log output. It is synchronized because the SSE route
// logs from a poll loop while the test reads what has been written so far.
type logSink struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (sink *logSink) Write(data []byte) (int, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.buffer.Write(data)
}

func (sink *logSink) String() string {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.buffer.String()
}

func newLoggingSink() (*logSink, *slog.Logger) {
	sink := &logSink{}
	return sink, slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func newLoggingTestHandler(t *testing.T, authenticator *testAuthenticator, handlers *testHandlers) (http.Handler, *logSink) {
	t.Helper()
	sink, logger := newLoggingSink()
	dependencies := testDependencies(authenticator, handlers)
	dependencies.Logger = logger
	handler, err := NewHandler(dependencies)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler, sink
}

func TestInboundRequestIDIsHonoredOnlyWhenTheErrorContractAcceptsIt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		supplied []string
		want     string
	}{
		{name: "absent", supplied: nil},
		{name: "accepted", supplied: []string{"req-client-supplied"}, want: "req-client-supplied"},
		{name: "oversize", supplied: []string{"req-" + strings.Repeat("x", 200)}},
		{name: "whitespace", supplied: []string{"req client supplied"}},
		{name: "repeated", supplied: []string{"req-first", "req-second"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(t, &testAuthenticator{}, &testHandlers{events: successfulEvents})
			// A rejected content type fails before the body is read, so the
			// answer carries the transport's own correlation id rather than the
			// one the request payload would have supplied.
			request := httptest.NewRequest(http.MethodPost, PathEventsSync, strings.NewReader(`{}`))
			for _, value := range test.supplied {
				request.Header.Add(headerRequestID, value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			var problem struct {
				RequestID string `json:"request_id"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if test.want != "" {
				if problem.RequestID != test.want {
					t.Fatalf("request_id = %q, want %q", problem.RequestID, test.want)
				}
				return
			}
			if !strings.HasPrefix(problem.RequestID, "req_") || len(problem.RequestID) != len("req_")+32 {
				t.Fatalf("request_id = %q, want a minted req_<128 bits>", problem.RequestID)
			}
		})
	}
}

func TestDiscardedCausesReachTheLogAndNeverTheClient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		authenticator *testAuthenticator
		handlers      *testHandlers
		stage         string
	}{
		{
			name:          "authenticate",
			authenticator: &testAuthenticator{err: errors.New("credential backend secret")},
			handlers:      &testHandlers{events: successfulEvents},
			stage:         "authenticate",
		},
		{
			name:          "handle",
			authenticator: &testAuthenticator{},
			handlers: &testHandlers{events: func(context.Context, AuthenticationEvidence, contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
				return contracts.EventPageDTO{}, nil, fmt.Errorf("read events: %w", errors.New("credential backend secret"))
			}},
			stage: "handle",
		},
		{
			name:          "correlate_result",
			authenticator: &testAuthenticator{},
			handlers: &testHandlers{events: func(ctx context.Context, evidence AuthenticationEvidence, request contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
				page, _, _ := successfulEvents(ctx, evidence, request)
				page.RequestID = "req-some-other-request"
				return page, nil, nil
			}},
			stage: "correlate_result",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler, sink := newLoggingTestHandler(t, test.authenticator, test.handlers)
			request := httptest.NewRequest(http.MethodPost, PathEventsSync, bytes.NewReader(validEventsRequest(t)))
			request.Header.Set("Content-Type", mediaTypeJSON)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", response.Code)
			}
			if strings.Contains(response.Body.String(), "credential backend secret") ||
				strings.Contains(response.Body.String(), "req-some-other-request") {
				t.Fatalf("client body disclosed the cause: %s", response.Body.String())
			}
			logged := sink.String()
			if !strings.Contains(logged, `msg="http operation failed"`) ||
				!strings.Contains(logged, "stage="+test.stage) ||
				!strings.Contains(logged, "operation="+contracts.OperationEventsSync) {
				t.Fatalf("failure record missing stage or operation:\n%s", logged)
			}
			if !strings.Contains(logged, "request_id=") {
				t.Fatalf("failure record omitted the correlation id:\n%s", logged)
			}
		})
	}
}

func TestAccessRecordCorrelatesOutcomeAndActorWithoutSecrets(t *testing.T) {
	t.Parallel()
	failing := &testHandlers{events: func(_ context.Context, _ AuthenticationEvidence, request contracts.EventsSyncRequestDTO) (contracts.EventPageDTO, *contracts.ErrorDTO, error) {
		failure := contracts.ErrorDTO{
			Schema: contracts.SchemaError, RequestID: request.RequestID, Code: domain.ErrorCodeCursorExpired,
			Category: domain.ErrorCategoryCursor, Message: "The event cursor expired.",
			Details: contracts.ErrorDetailsDTO{Recovery: contracts.RecoveryObtainCheckpoint},
		}
		return contracts.EventPageDTO{}, &failure, nil
	}}
	tests := []struct {
		name     string
		handlers *testHandlers
		want     []string
	}{
		{
			name:     "success",
			handlers: &testHandlers{events: successfulEvents},
			want:     []string{"outcome=ok", "request_id=req-events-http"},
		},
		{
			name:     "typed failure",
			handlers: failing,
			want:     []string{"outcome=error", "error_code=" + string(domain.ErrorCodeCursorExpired)},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			evidence := sessionBoundEvidence(t)
			handler, sink := newLoggingTestHandler(t, &testAuthenticator{evidence: &evidence}, test.handlers)
			request := httptest.NewRequest(http.MethodPost, PathEventsSync, bytes.NewReader(validEventsRequest(t)))
			request.Header.Set("Content-Type", mediaTypeJSON)
			request.Header.Set("Authorization", "Bearer super-secret-credential")
			handler.ServeHTTP(httptest.NewRecorder(), request)

			logged := sink.String()
			if !strings.Contains(logged, `msg="http request"`) {
				t.Fatalf("no access record:\n%s", logged)
			}
			for _, want := range append(test.want,
				"operation="+contracts.OperationEventsSync,
				"duration_ms=",
				"principal_id=01b8e094-9888-7000-8000-000000000004",
				"actor_session_id="+actorSessionID,
			) {
				if !strings.Contains(logged, want) {
					t.Fatalf("access record missing %q:\n%s", want, logged)
				}
			}
			if strings.Contains(logged, "super-secret-credential") || strings.Contains(logged, strings.Repeat("a", 64)) {
				t.Fatalf("access record leaked a credential or channel binding:\n%s", logged)
			}
		})
	}
}
