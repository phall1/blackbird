package http

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	PathLocalAgentRegister            = "/api/v1/local/agents/register"
	PathLocalCoordinationEvents       = "/api/v1/local/coordination/events"
	PathLocalCoordinationEventsStream = "/api/v1/local/coordination/events/stream"
	PathLocalMessages                 = "/api/v1/local/messages/"

	localMaxJSONBytes = 8 << 10
	localDefaultLimit = 100
	localPollInterval = 500 * time.Millisecond
	localHeartbeat    = 15 * time.Second
	localWriteTimeout = 5 * time.Second
)

type LocalDependencies struct {
	Coordination application.LocalCoordinationStore
	// Logger receives the causes the sanitized local problems drop, plus one
	// access record per request. A nil Logger is silent rather than a
	// composition error, so a test can exercise a route without a log sink.
	Logger       *slog.Logger
	PollInterval time.Duration
	Heartbeat    time.Duration
	WriteTimeout time.Duration
}

type localHandler struct {
	coordination application.LocalCoordinationStore
	logger       *slog.Logger
	pollInterval time.Duration
	heartbeat    time.Duration
	writeTimeout time.Duration
}

// localRequestIDKey carries the request's correlation id from the access
// middleware to the handlers, so a logged failure and its access record share
// one key even though the local wire contract has no request_id field.
type localRequestIDKey struct{}

func localRequestID(request *stdhttp.Request) string {
	value, _ := request.Context().Value(localRequestIDKey{}).(string)
	return value
}

type localRegisterRequest struct {
	ProjectKey        string  `json:"project_key"`
	AgentName         string  `json:"agent_name"`
	RegistrationToken *string `json:"registration_token,omitempty"`
}

type localRegisterResponse struct {
	ProjectKey        string `json:"project_key"`
	AgentName         string `json:"agent_name"`
	WorkspaceID       string `json:"workspace_id"`
	ActorID           string `json:"actor_id"`
	SessionID         string `json:"session_id"`
	RegistrationToken string `json:"registration_token,omitempty"`
}

type localCoordinationEvent struct {
	Type       application.CoordinationEventType `json:"type"`
	Subject    string                            `json:"subject"`
	Payload    json.RawMessage                   `json:"payload"`
	OccurredAt string                            `json:"occurred_at"`
}

type localCoordinationEventsPage struct {
	Events     []localCoordinationEvent `json:"events"`
	NextCursor string                   `json:"next_cursor"`
	HasMore    bool                     `json:"has_more"`
}

type localWakeup struct {
	Cursor string `json:"cursor"`
}

type localDelivery struct {
	RecipientActorID string `json:"recipient_actor_id"`
	Kind             string `json:"kind"`
	Read             bool   `json:"read"`
	Acknowledged     bool   `json:"acknowledged"`
}

type localMessage struct {
	MessageID      string          `json:"message_id"`
	ConversationID string          `json:"conversation_id"`
	AuthorActorID  string          `json:"author_actor_id"`
	Subject        string          `json:"subject"`
	Body           string          `json:"body"`
	BodyDigest     string          `json:"body_digest"`
	ReplyTo        string          `json:"reply_to,omitempty"`
	SentAt         string          `json:"sent_at"`
	Position       uint64          `json:"position"`
	Deliveries     []localDelivery `json:"deliveries"`
}

type localProblem struct {
	Code    domain.ErrorCode `json:"code"`
	Message string           `json:"message"`
}

func NewLocalHandler(dependencies LocalDependencies) (stdhttp.Handler, error) {
	if isNil(dependencies.Coordination) {
		return nil, errors.New("local HTTP transport requires coordination storage")
	}
	if dependencies.PollInterval < 0 || dependencies.Heartbeat < 0 || dependencies.WriteTimeout < 0 {
		return nil, errors.New("local HTTP transport durations cannot be negative")
	}
	if dependencies.PollInterval == 0 {
		dependencies.PollInterval = localPollInterval
	}
	if dependencies.Heartbeat == 0 {
		dependencies.Heartbeat = localHeartbeat
	}
	if dependencies.WriteTimeout == 0 {
		dependencies.WriteTimeout = localWriteTimeout
	}
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	handler := &localHandler{coordination: dependencies.Coordination, logger: logger,
		pollInterval: dependencies.PollInterval,
		heartbeat:    dependencies.Heartbeat, writeTimeout: dependencies.WriteTimeout}
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("POST "+PathLocalAgentRegister, handler.register)
	mux.HandleFunc("GET "+PathLocalCoordinationEvents, handler.events)
	mux.HandleFunc("GET "+PathLocalCoordinationEventsStream, handler.stream)
	mux.HandleFunc("GET "+PathLocalMessages+"{message_id}", handler.message)
	// Access logging wraps the loopback guard so a rejected non-loopback caller
	// is recorded too — that rejection is exactly the one an operator hunts for.
	return handler.access(localSafety(mux)), nil
}

// access resolves the request's correlation id and emits one record per
// request. It logs the path but never the query string or any header: the local
// surface carries bearer tokens in both places.
func (handler *localHandler) access(next stdhttp.Handler) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		started := time.Now()
		requestID := inboundRequestID(request)
		recorder := &localRecorder{ResponseWriter: writer}
		next.ServeHTTP(recorder, request.WithContext(
			context.WithValue(request.Context(), localRequestIDKey{}, requestID)))
		handler.logger.Info("local request",
			slog.String("request_id", requestID),
			slog.String("method", request.Method),
			slog.String("path", request.URL.Path),
			slog.Int("status", recorder.committedStatus()),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()))
	})
}

// localRecorder observes the committed status for the access record. It has to
// forward the streaming capabilities the SSE route depends on: Flush directly,
// and the write deadlines ResponseController reaches through Unwrap.
type localRecorder struct {
	stdhttp.ResponseWriter
	status int
}

func (recorder *localRecorder) WriteHeader(status int) {
	if recorder.status == 0 {
		recorder.status = status
	}
	recorder.ResponseWriter.WriteHeader(status)
}

func (recorder *localRecorder) Write(data []byte) (int, error) {
	if recorder.status == 0 {
		recorder.status = stdhttp.StatusOK
	}
	return recorder.ResponseWriter.Write(data)
}

func (recorder *localRecorder) Flush() {
	if flusher, ok := recorder.ResponseWriter.(stdhttp.Flusher); ok {
		flusher.Flush()
	}
}

func (recorder *localRecorder) Unwrap() stdhttp.ResponseWriter { return recorder.ResponseWriter }

// committedStatus reports what net/http will have sent: a handler that returned
// without writing anything still produces 200.
func (recorder *localRecorder) committedStatus() int {
	if recorder.status == 0 {
		return stdhttp.StatusOK
	}
	return recorder.status
}

// fail records the cause before the client receives the sanitized problem.
// Without it every %w chain the application built dies at this boundary.
func (handler *localHandler) fail(writer stdhttp.ResponseWriter, request *stdhttp.Request, operation string, err error) {
	handler.logFailure(request, operation, err)
	writeLocalError(writer, err)
}

func (handler *localHandler) logFailure(request *stdhttp.Request, operation string, err error) {
	handler.logger.Error("local operation failed",
		slog.String("request_id", localRequestID(request)),
		slog.String("operation", operation),
		slog.Any("error", err))
}

func (handler *localHandler) message(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if !rejectQueryCredentials(writer, request.URL.Query()) {
		return
	}
	session, ok := handler.authenticate(writer, request)
	if !ok {
		return
	}
	if len(request.URL.Query()) != 0 {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "query parameters are invalid")
		return
	}
	messageID, err := domain.ParseMessageID(request.PathValue("message_id"))
	if err != nil {
		writeLocalProblem(writer, stdhttp.StatusNotFound, domain.ErrorCodeNotFound, "message was not found")
		return
	}
	message, err := handler.coordination.GetVisibleMessage(request.Context(), session.WorkspaceID, session.ActorID, messageID)
	if err != nil {
		var commandError *domain.CommandError
		if errors.As(err, &commandError) && commandError.Code() == domain.ErrorCodeNotFound {
			writeLocalProblem(writer, stdhttp.StatusNotFound, domain.ErrorCodeNotFound, "message was not found")
			return
		}
		handler.fail(writer, request, "message.get", err)
		return
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localMessageOutput(message))
}

func localMessageOutput(message application.Message) localMessage {
	digest := message.Digest()
	result := localMessage{MessageID: message.ID().String(), ConversationID: message.ConversationID().String(),
		AuthorActorID: message.Author().String(), Subject: message.Subject(), Body: message.Body(),
		BodyDigest: hex.EncodeToString(digest[:]), SentAt: message.SentAt().Format(time.RFC3339Nano),
		Position: message.Position(), Deliveries: []localDelivery{}}
	if reply := message.ReplyTo(); reply != nil {
		result.ReplyTo = reply.String()
	}
	for _, delivery := range message.Deliveries() {
		_, read := delivery.ReadAt()
		_, acknowledged := delivery.AcknowledgedAt()
		result.Deliveries = append(result.Deliveries, localDelivery{RecipientActorID: delivery.Recipient().ActorID().String(),
			Kind: string(delivery.Recipient().Kind()), Read: read, Acknowledged: acknowledged})
	}
	return result
}

func localSafety(next stdhttp.Handler) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if !loopbackRequest(request) {
			writeLocalProblem(writer, stdhttp.StatusForbidden, domain.ErrorCodeForbidden, "local API access requires a loopback connection")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func loopbackRequest(request *stdhttp.Request) bool {
	remoteHost, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || !isLoopbackHost(remoteHost) {
		return false
	}
	host := request.Host
	if parsedHost, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = parsedHost
	} else if strings.Contains(host, ":") {
		return false
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func (handler *localHandler) register(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if !strictJSONRequest(writer, request) {
		return
	}
	var input localRegisterRequest
	if err := decodeLocalJSON(writer, request, &input); err != nil {
		writeLocalProblem(writer, stdhttp.StatusUnprocessableEntity, domain.ErrorCodeInvalidSchema, "request body does not match the registration schema")
		return
	}
	token := ""
	if input.RegistrationToken != nil {
		token = *input.RegistrationToken
	}
	session, issued, err := handler.coordination.RegisterLocalAgent(request.Context(), input.ProjectKey, input.AgentName, token)
	if err != nil {
		handler.fail(writer, request, "agent.register", err)
		return
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localRegisterResponse{ProjectKey: session.ProjectKey, AgentName: session.AgentName,
		WorkspaceID: session.WorkspaceID.String(), ActorID: session.ActorID.String(), SessionID: session.ActorSessionID.String(),
		RegistrationToken: issued})
}

func (handler *localHandler) events(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if !rejectQueryCredentials(writer, request.URL.Query()) {
		return
	}
	session, ok := handler.authenticate(writer, request)
	if !ok {
		return
	}
	after, limit, ok := localEventQuery(writer, request.URL.Query(), true)
	if !ok {
		return
	}
	page, err := handler.sync(request, session, after, limit)
	if err != nil {
		handler.fail(writer, request, "coordination.events", err)
		return
	}
	events := make([]localCoordinationEvent, 0, len(page.Events()))
	for _, event := range page.Events() {
		events = append(events, localCoordinationEvent{Type: event.EventType(), Subject: event.SubjectID(),
			Payload: json.RawMessage(event.Payload()), OccurredAt: event.OccurredAt().Format(time.RFC3339Nano)})
	}
	writeLocalJSON(writer, stdhttp.StatusOK, localCoordinationEventsPage{Events: events,
		NextCursor: page.NextCursor().String(), HasMore: page.HasMore()})
}

func (handler *localHandler) stream(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if !rejectQueryCredentials(writer, request.URL.Query()) {
		return
	}
	session, ok := handler.authenticate(writer, request)
	if !ok {
		return
	}
	after, _, ok := localEventQuery(writer, request.URL.Query(), false)
	if !ok {
		return
	}
	if after == "" {
		after = request.Header.Get("Last-Event-ID")
	}
	if strings.ContainsAny(after, "\r\n") {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeCursorInvalid, "event cursor is invalid")
		return
	}
	flusher, ok := writer.(stdhttp.Flusher)
	if !ok {
		writeLocalProblem(writer, stdhttp.StatusInternalServerError, domain.ErrorCodeInternal, "streaming is unavailable")
		return
	}
	// Validate the supplied cursor before committing an SSE response.
	page, err := handler.sync(request, session, after, application.MaxQueryPageSize)
	if err != nil {
		handler.fail(writer, request, "coordination.events.stream", err)
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")
	controller := stdhttp.NewResponseController(writer)
	if err := controller.SetWriteDeadline(time.Now().Add(handler.writeTimeout)); err != nil && !errors.Is(err, stdhttp.ErrNotSupported) {
		writeLocalProblem(writer, stdhttp.StatusInternalServerError, domain.ErrorCodeInternal, "streaming is unavailable")
		return
	}
	writer.WriteHeader(stdhttp.StatusOK)
	flusher.Flush()
	if err := controller.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, stdhttp.ErrNotSupported) {
		return
	}

	poll := time.NewTicker(handler.pollInterval)
	heartbeat := time.NewTicker(handler.heartbeat)
	defer poll.Stop()
	defer heartbeat.Stop()
	cursor := after
	for {
		if len(page.Events()) > 0 {
			next := page.NextCursor().String()
			encoded, marshalErr := json.Marshal(localWakeup{Cursor: next})
			if marshalErr != nil || !handler.writeSSE(writer, flusher, "cursor", next, encoded) {
				return
			}
			cursor = next
			if page.HasMore() {
				page, err = handler.sync(request, session, cursor, application.MaxQueryPageSize)
				if err != nil {
					handler.logFailure(request, "coordination.events.stream", err)
					return
				}
				continue
			}
		}
		select {
		case <-request.Context().Done():
			return
		case <-heartbeat.C:
			if !handler.writeChunk(writer, flusher, []byte(": heartbeat\n\n")) {
				return
			}
		case <-poll.C:
			page, err = handler.sync(request, session, cursor, application.MaxQueryPageSize)
			if err != nil {
				handler.logFailure(request, "coordination.events.stream", err)
				return
			}
		}
	}
}

func rejectQueryCredentials(writer stdhttp.ResponseWriter, values url.Values) bool {
	for key := range values {
		lower := strings.ToLower(key)
		if lower == "token" || lower == "access_token" || lower == "authorization" || strings.HasSuffix(lower, "_token") {
			writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
				"credentials must be supplied only in the Authorization header")
			return false
		}
	}
	return true
}

func (handler *localHandler) authenticate(writer stdhttp.ResponseWriter, request *stdhttp.Request) (application.LocalAgentSession, bool) {
	value := request.Header.Get("Authorization")
	if len(request.Header.Values("Authorization")) != 1 || len(value) < 8 || !strings.EqualFold(value[:7], "Bearer ") ||
		strings.TrimSpace(value[7:]) != value[7:] || strings.ContainsAny(value[7:], " \t\r\n") {
		writer.Header().Set("WWW-Authenticate", "Bearer")
		writeLocalProblem(writer, stdhttp.StatusUnauthorized, domain.ErrorCodeUnauthenticated, "a valid bearer token is required")
		return application.LocalAgentSession{}, false
	}
	session, err := handler.coordination.AuthenticateLocalAgent(request.Context(), value[7:])
	if err != nil {
		writer.Header().Set("WWW-Authenticate", "Bearer")
		handler.fail(writer, request, "agent.authenticate", err)
		return application.LocalAgentSession{}, false
	}
	return session, true
}

func (handler *localHandler) sync(request *stdhttp.Request, session application.LocalAgentSession, after string,
	limit uint16) (application.CoordinationEventsPage, error) {
	var cursor application.CoordinationEventCursor
	var err error
	if after != "" {
		cursor, err = application.NewCoordinationEventCursor(after)
		if err != nil {
			return application.CoordinationEventsPage{}, err
		}
	}
	query, err := application.NewCoordinationEventsQuery(session.WorkspaceID, session.ActorID, cursor, limit)
	if err != nil {
		return application.CoordinationEventsPage{}, err
	}
	return handler.coordination.SyncCoordinationEvents(request.Context(), query)
}

func localEventQuery(writer stdhttp.ResponseWriter, values url.Values, allowLimit bool) (string, uint16, bool) {
	for key, entries := range values {
		if key != "after" && (key != "limit" || !allowLimit) || len(entries) != 1 {
			writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "query parameters are invalid")
			return "", 0, false
		}
	}
	after := values.Get("after")
	limit := uint16(localDefaultLimit)
	if text := values.Get("limit"); text != "" {
		parsed, err := strconv.ParseUint(text, 10, 16)
		if err != nil || parsed == 0 || parsed > application.MaxQueryPageSize {
			writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument,
				fmt.Sprintf("limit must be from 1 through %d", application.MaxQueryPageSize))
			return "", 0, false
		}
		limit = uint16(parsed)
	}
	return after, limit, true
}

func strictJSONRequest(writer stdhttp.ResponseWriter, request *stdhttp.Request) bool {
	if request.Header.Get("Content-Encoding") != "" || !isJSONContentType(request.Header.Get("Content-Type")) {
		writeLocalProblem(writer, stdhttp.StatusUnsupportedMediaType, domain.ErrorCodeInvalidSchema,
			"request must use unencoded application/json")
		return false
	}
	return true
}

func decodeLocalJSON(writer stdhttp.ResponseWriter, request *stdhttp.Request, destination any) error {
	if request.ContentLength > localMaxJSONBytes {
		return errors.New("request body is too large")
	}
	body, err := io.ReadAll(stdhttp.MaxBytesReader(writer, request.Body, localMaxJSONBytes))
	if err != nil {
		return err
	}
	if err := rejectDuplicateTopLevelMembers(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func rejectDuplicateTopLevelMembers(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("request body must be a JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("request object member is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("request object contains a duplicate member")
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func (handler *localHandler) writeSSE(writer stdhttp.ResponseWriter, flusher stdhttp.Flusher, event, id string, data []byte) bool {
	chunk := []byte("event: " + event + "\nid: " + id + "\ndata: " + string(data) + "\n\n")
	return handler.writeChunk(writer, flusher, chunk)
}

func (handler *localHandler) writeChunk(writer stdhttp.ResponseWriter, flusher stdhttp.Flusher, chunk []byte) bool {
	controller := stdhttp.NewResponseController(writer)
	if err := controller.SetWriteDeadline(time.Now().Add(handler.writeTimeout)); err != nil && !errors.Is(err, stdhttp.ErrNotSupported) {
		return false
	}
	if _, err := writer.Write(chunk); err != nil {
		return false
	}
	flusher.Flush()
	err := controller.SetWriteDeadline(time.Time{})
	return err == nil || errors.Is(err, stdhttp.ErrNotSupported)
}

func writeLocalJSON(writer stdhttp.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		writeLocalProblem(writer, stdhttp.StatusInternalServerError, domain.ErrorCodeInternal, "request could not be completed")
		return
	}
	writer.Header().Set("Content-Type", mediaTypeJSON)
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func writeLocalError(writer stdhttp.ResponseWriter, err error) {
	var commandError *domain.CommandError
	if errors.As(err, &commandError) {
		writeLocalProblem(writer, statusFor(commandError.Code()), commandError.Code(), commandError.Error())
		return
	}
	if errors.Is(err, application.ErrInvalidCoordination) {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "coordination request is invalid")
		return
	}
	writeLocalProblem(writer, stdhttp.StatusInternalServerError, domain.ErrorCodeInternal, "request could not be completed")
}

func writeLocalProblem(writer stdhttp.ResponseWriter, status int, code domain.ErrorCode, message string) {
	encoded, _ := json.Marshal(localProblem{Code: code, Message: message})
	writer.Header().Set("Content-Type", mediaTypeProblem)
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}
