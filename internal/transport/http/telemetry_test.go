package http

import (
	"encoding/json"
	stdhttp "net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/phall1/blackbird/internal/application"
)

type capturingTelemetrySink struct {
	mu        sync.Mutex
	envelopes []application.TelemetryEnvelope
	refuse    bool
}

func (sink *capturingTelemetrySink) Offer(envelope application.TelemetryEnvelope) bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.refuse {
		return false
	}
	sink.envelopes = append(sink.envelopes, envelope)
	return true
}

func (sink *capturingTelemetrySink) last() (application.TelemetryEnvelope, bool) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.envelopes) == 0 {
		return application.TelemetryEnvelope{}, false
	}
	return sink.envelopes[len(sink.envelopes)-1], true
}

func newTelemetryHandler(t *testing.T, sink TelemetryOffer) (stdhttp.Handler, string) {
	t.Helper()
	store := openLocalHTTPStore(t, filepath.Join(t.TempDir(), "coordination.db"))
	t.Cleanup(func() { _ = store.Close() })
	handler, err := NewLocalHandler(LocalDependencies{Coordination: store, Telemetry: sink})
	if err != nil {
		t.Fatal(err)
	}
	return handler, registerLocalHTTPDirect(t, handler).RegistrationToken
}

func postTelemetry(t *testing.T, handler stdhttp.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := newLocalHTTPRequest(stdhttp.MethodPost, PathLocalTelemetry, strings.NewReader(body))
	request.Header.Set("Content-Type", mediaTypeJSON)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

const claudeShapedCall = `{"model_calls":[{
	"dedupe_key":"msg_01ABC","harness":"claude-code","harness_session":"3231c9b2",
	"provider":"anthropic","model":"claude-opus-5","operation":"chat",
	"usage":{"uncached_input_tokens":2,"cache_read_tokens":26354,
	"cache_write_tokens":23947,"output_tokens":1469,"reasoning_tokens":298},
	"outcome":"ok","started_at":"2026-09-02T05:06:52.813Z","duration_ms":4210}]}`

func TestTelemetryIngestAcceptsAndAttributesFromTheToken(t *testing.T) {
	t.Parallel()
	sink := &capturingTelemetrySink{}
	handler, token := newTelemetryHandler(t, sink)

	response := postTelemetry(t, handler, token, claudeShapedCall)
	if response.Code != stdhttp.StatusAccepted {
		t.Fatalf("status=%d body=%s, want 202", response.Code, response.Body.String())
	}
	var result localTelemetryResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 || result.Rejected != 0 || result.Dropped != 0 {
		t.Fatalf("result=%+v, want one accepted observation", result)
	}

	envelope, ok := sink.last()
	if !ok {
		t.Fatal("nothing reached the sink")
	}
	// Attribution comes from the authenticated session, never the body: an
	// adapter must not be able to bill its spend to another agent.
	if envelope.Attribution.ProjectKey != "/workspace/project" {
		t.Fatalf("project=%q, want the session's", envelope.Attribution.ProjectKey)
	}
	if envelope.Attribution.ActorID.String() == "" || envelope.Attribution.SessionID.String() == "" {
		t.Fatalf("attribution=%+v, want the session's actor and session", envelope.Attribution)
	}
	usage := envelope.ModelCalls[0].Usage
	if usage.UncachedInput != 2 || usage.CacheRead != 26354 || usage.CacheWrite != 23947 {
		t.Fatalf("usage=%+v, want the disjoint classes preserved", usage)
	}
	if usage.BilledInput() != 50303 {
		t.Fatalf("billed input=%d, want the sum of the three input classes", usage.BilledInput())
	}
}

// One bad observation must not cost the good ones in the same request. An
// adapter that loses a whole batch to a single typo learns nothing and reports
// nothing.
func TestTelemetryIngestRejectsPerItemAndKeepsTheRest(t *testing.T) {
	t.Parallel()
	sink := &capturingTelemetrySink{}
	handler, token := newTelemetryHandler(t, sink)

	body := `{"model_calls":[
		{"dedupe_key":"good","harness":"pi","provider":"anthropic","model":"m","operation":"chat",
		 "usage":{"uncached_input_tokens":1,"output_tokens":1},"outcome":"ok",
		 "started_at":"2026-09-02T05:06:52Z","duration_ms":10},
		{"dedupe_key":"bad-reasoning","harness":"pi","provider":"anthropic","model":"m","operation":"chat",
		 "usage":{"uncached_input_tokens":1,"output_tokens":5,"reasoning_tokens":9},"outcome":"ok",
		 "started_at":"2026-09-02T05:06:52Z","duration_ms":10},
		{"dedupe_key":"bad-harness","harness":"emacs","provider":"anthropic","model":"m","operation":"chat",
		 "usage":{"output_tokens":1},"outcome":"ok",
		 "started_at":"2026-09-02T05:06:52Z","duration_ms":10}]}`
	response := postTelemetry(t, handler, token, body)
	if response.Code != stdhttp.StatusAccepted {
		t.Fatalf("status=%d, want 202 even with rejected items", response.Code)
	}
	var result localTelemetryResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 || result.Rejected != 2 {
		t.Fatalf("result=%+v, want one accepted and two rejected", result)
	}
	if len(result.Rejections) != 2 {
		t.Fatalf("rejections=%+v, want both reported so the adapter can log them", result.Rejections)
	}
	// Reasoning is a subset of output, so claiming more reasoning than output is
	// a contradiction rather than a large number.
	if !strings.Contains(result.Rejections[0].Reason, "reasoning") {
		t.Fatalf("first rejection=%q, want the reasoning-subset violation named", result.Rejections[0].Reason)
	}
}

// A misspelled token field would otherwise decode to zero and be stored as a
// real measurement, which is the exact silent undercounting this plane exists
// to detect.
func TestTelemetryIngestRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	handler, token := newTelemetryHandler(t, &capturingTelemetrySink{})
	body := `{"model_calls":[{"dedupe_key":"typo","harness":"pi","provider":"a","model":"m",
		"operation":"chat","usage":{"input_tokens":900,"output_tokens":1},"outcome":"ok",
		"started_at":"2026-09-02T05:06:52Z","duration_ms":10}]}`
	var result localTelemetryResponse
	response := postTelemetry(t, handler, token, body)
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Rejected != 1 || result.Accepted != 0 {
		t.Fatalf("result=%+v, want the misspelled usage field rejected rather than read as zero", result)
	}
}

// A full queue is reported, not hidden, and is still not an error.
func TestTelemetryIngestReportsDropsWithoutFailing(t *testing.T) {
	t.Parallel()
	handler, token := newTelemetryHandler(t, &capturingTelemetrySink{refuse: true})
	response := postTelemetry(t, handler, token, claudeShapedCall)
	if response.Code != stdhttp.StatusAccepted {
		t.Fatalf("status=%d, want 202; a drop is not a caller error", response.Code)
	}
	var result localTelemetryResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Dropped != 1 || result.Accepted != 0 {
		t.Fatalf("result=%+v, want the drop reported", result)
	}
}

func TestTelemetryIngestRequiresABearerToken(t *testing.T) {
	t.Parallel()
	handler, _ := newTelemetryHandler(t, &capturingTelemetrySink{})
	if response := postTelemetry(t, handler, "", claudeShapedCall); response.Code != stdhttp.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", response.Code)
	}
}

// A daemon that does not collect says so, rather than 404ing as though the
// route were a typo.
func TestTelemetryIngestAnnouncesWhenCollectionIsOff(t *testing.T) {
	t.Parallel()
	handler, token := newTelemetryHandler(t, nil)
	response := postTelemetry(t, handler, token, claudeShapedCall)
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503 when no sink is composed", response.Code)
	}
}

func TestTelemetryIngestBoundsOneSubmission(t *testing.T) {
	t.Parallel()
	handler, token := newTelemetryHandler(t, &capturingTelemetrySink{})
	item := `{"dedupe_key":"k","harness":"pi","provider":"a","model":"m","operation":"chat",
		"usage":{"output_tokens":1},"outcome":"ok","started_at":"2026-09-02T05:06:52Z","duration_ms":1}`
	items := make([]string, application.MaxTelemetryEventsPerEnvelope+1)
	for index := range items {
		items[index] = item
	}
	body := `{"model_calls":[` + strings.Join(items, ",") + `]}`
	response := postTelemetry(t, handler, token, body)
	if response.Code != stdhttp.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422 for an oversized submission", response.Code)
	}
}
