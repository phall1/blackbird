package http

import (
	"bytes"
	"encoding/json"
	"errors"
	stdhttp "net/http"
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

// The observation plane's ingest route (ADR-0001).
//
// This is deliberately HTTP and deliberately not an MCP tool. An MCP tool would
// put a telemetry schema in every session's tool list, where the model pays
// context tokens for it on every turn -- to report the very tokens it is
// spending. The adapter is a process, not a model; it should call an endpoint.
//
// The route never fails in a way that matters. Bad items are rejected
// individually and reported back so the adapter can log them; good items in the
// same request are still accepted. A full queue drops rather than blocks. The
// response is 202 whenever the caller is authenticated and sent parseable JSON,
// because there is no failure here an adapter should retry into.

var (
	errTelemetryTrailingContent = errors.New("trailing content after the observation object")
	errTelemetryMissingStart    = errors.New("started_at is required")
)

const (
	// localTelemetryMaxJSONBytes bounds one submission. Together with the
	// sink's queue depth it is the plane's whole memory story: a bounded body
	// times a bounded number of queued envelopes.
	localTelemetryMaxJSONBytes = 256 << 10
	// localTelemetryMaxRejectionsReported caps the diagnostic list. An adapter
	// with a systematic bug produces one distinct mistake repeated, so the
	// first few say everything the rest would.
	localTelemetryMaxRejectionsReported = 8
)

type localTelemetryRequest struct {
	ModelCalls []json.RawMessage `json:"model_calls"`
	Spans      []json.RawMessage `json:"spans"`
}

type localTelemetryUsage struct {
	UncachedInputTokens uint64  `json:"uncached_input_tokens"`
	CacheReadTokens     uint64  `json:"cache_read_tokens"`
	CacheWriteTokens    uint64  `json:"cache_write_tokens"`
	OutputTokens        uint64  `json:"output_tokens"`
	ReasoningTokens     *uint64 `json:"reasoning_tokens"`
}

type localTelemetryModelCall struct {
	DedupeKey      string              `json:"dedupe_key"`
	Harness        string              `json:"harness"`
	HarnessSession string              `json:"harness_session"`
	Provider       string              `json:"provider"`
	Model          string              `json:"model"`
	Operation      string              `json:"operation"`
	Usage          localTelemetryUsage `json:"usage"`
	Outcome        string              `json:"outcome"`
	ErrorKind      string              `json:"error_kind"`
	StartedAt      string              `json:"started_at"`
	DurationMS     *int64              `json:"duration_ms"`
	PhuxTerminal   string              `json:"phux_terminal"`
	RawUsage       string              `json:"raw_usage"`
}

type localTelemetrySpan struct {
	DedupeKey      string `json:"dedupe_key"`
	Harness        string `json:"harness"`
	HarnessSession string `json:"harness_session"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Outcome        string `json:"outcome"`
	ErrorKind      string `json:"error_kind"`
	StartedAt      string `json:"started_at"`
	DurationMS     *int64 `json:"duration_ms"`
	PhuxTerminal   string `json:"phux_terminal"`
	Attributes     string `json:"attributes"`
}

type localTelemetryRejection struct {
	Kind   string `json:"kind"`
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

type localTelemetryResponse struct {
	Accepted   int                       `json:"accepted"`
	Dropped    int                       `json:"dropped"`
	Rejected   int                       `json:"rejected"`
	Rejections []localTelemetryRejection `json:"rejections,omitempty"`
}

func (handler *localHandler) telemetry(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	if !strictJSONRequest(writer, request) {
		return
	}
	session, ok := handler.authenticate(writer, request)
	if !ok {
		return
	}
	if handler.telemetrySink == nil {
		writeLocalProblem(writer, stdhttp.StatusServiceUnavailable, domain.ErrorCodeDependencyUnavailable,
			"this daemon is not collecting telemetry")
		return
	}
	var input localTelemetryRequest
	if err := decodeLocalJSONWithin(writer, request, &input, localTelemetryMaxJSONBytes); err != nil {
		writeLocalProblem(writer, stdhttp.StatusUnprocessableEntity, domain.ErrorCodeInvalidSchema,
			"request body does not match the telemetry schema")
		return
	}
	if len(input.ModelCalls)+len(input.Spans) > telemetry.MaxEventsPerEnvelope {
		writeLocalProblem(writer, stdhttp.StatusUnprocessableEntity, domain.ErrorCodeInvalidArgument,
			"submit at most "+itoa(telemetry.MaxEventsPerEnvelope)+" observations per request")
		return
	}

	envelope := telemetry.Envelope{
		Attribution: telemetry.Attribution{
			ProjectKey: session.ProjectKey,
			ActorID:    session.ActorID,
			SessionID:  session.ActorSessionID,
		},
		ReceivedAt: time.Now().UTC(),
	}
	response := localTelemetryResponse{}
	for index, raw := range input.ModelCalls {
		call, err := decodeTelemetryModelCall(raw)
		if err != nil {
			response.reject("model_call", index, err.Error())
			continue
		}
		envelope.ModelCalls = append(envelope.ModelCalls, call)
	}
	for index, raw := range input.Spans {
		span, err := decodeTelemetrySpan(raw)
		if err != nil {
			response.reject("span", index, err.Error())
			continue
		}
		envelope.Spans = append(envelope.Spans, span)
	}

	admitted := envelope.Len()
	if handler.telemetrySink.Offer(envelope) {
		response.Accepted = admitted
	} else {
		response.Dropped = admitted
	}
	writeLocalJSON(writer, stdhttp.StatusAccepted, response)
}

func (response *localTelemetryResponse) reject(kind string, index int, reason string) {
	response.Rejected++
	if len(response.Rejections) < localTelemetryMaxRejectionsReported {
		response.Rejections = append(response.Rejections,
			localTelemetryRejection{Kind: kind, Index: index, Reason: reason})
	}
}

func decodeTelemetryModelCall(raw json.RawMessage) (domain.ModelCall, error) {
	var input localTelemetryModelCall
	if err := strictDecodeTelemetryItem(raw, &input); err != nil {
		return domain.ModelCall{}, err
	}
	startedAt, err := parseTelemetryInstant(input.StartedAt)
	if err != nil {
		return domain.ModelCall{}, err
	}
	usage := domain.TokenUsage{
		UncachedInput: input.Usage.UncachedInputTokens,
		CacheRead:     input.Usage.CacheReadTokens,
		CacheWrite:    input.Usage.CacheWriteTokens,
		Output:        input.Usage.OutputTokens,
	}
	if input.Usage.ReasoningTokens != nil {
		usage.Reasoning = *input.Usage.ReasoningTokens
		usage.ReasoningReported = true
	}
	call := domain.ModelCall{
		DedupeKey:      input.DedupeKey,
		Harness:        domain.Harness(input.Harness),
		HarnessSession: input.HarnessSession,
		Provider:       input.Provider,
		Model:          input.Model,
		Operation:      domain.ModelOperation(input.Operation),
		Usage:          usage,
		Outcome:        domain.ObservedOutcome(input.Outcome),
		ErrorKind:      input.ErrorKind,
		StartedAt:      startedAt,
		PhuxTerminal:   input.PhuxTerminal,
		RawUsage:       input.RawUsage,
	}
	if input.DurationMS != nil {
		call.Duration = time.Duration(*input.DurationMS) * time.Millisecond
		call.DurationKnown = true
	}
	if err := call.Validate(); err != nil {
		return domain.ModelCall{}, err
	}
	return call, nil
}

func decodeTelemetrySpan(raw json.RawMessage) (domain.Span, error) {
	var input localTelemetrySpan
	if err := strictDecodeTelemetryItem(raw, &input); err != nil {
		return domain.Span{}, err
	}
	startedAt, err := parseTelemetryInstant(input.StartedAt)
	if err != nil {
		return domain.Span{}, err
	}
	span := domain.Span{
		DedupeKey:      input.DedupeKey,
		Harness:        domain.Harness(input.Harness),
		HarnessSession: input.HarnessSession,
		Kind:           domain.SpanKind(input.Kind),
		Name:           input.Name,
		Outcome:        domain.ObservedOutcome(input.Outcome),
		ErrorKind:      input.ErrorKind,
		StartedAt:      startedAt,
		PhuxTerminal:   input.PhuxTerminal,
		Attributes:     input.Attributes,
	}
	if input.DurationMS != nil {
		span.Duration = time.Duration(*input.DurationMS) * time.Millisecond
		span.DurationKnown = true
	}
	if err := span.Validate(); err != nil {
		return domain.Span{}, err
	}
	return span, nil
}

// strictDecodeTelemetryItem rejects unknown fields per item rather than per
// request. A misspelled token field would otherwise decode to zero and be
// stored as a real measurement -- silent undercounting is the exact failure
// this plane exists to detect, so it must not be the plane's own bug.
func strictDecodeTelemetryItem(raw json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return errTelemetryTrailingContent
	}
	return nil
}

func parseTelemetryInstant(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errTelemetryMissingStart
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 20)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
