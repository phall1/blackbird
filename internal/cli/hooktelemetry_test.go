package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of a real Claude Code transcript line, trimmed to what the scanner
// reads. input_tokens sits beside a much larger cache_read: Anthropic reports
// input EXCLUDING cache, which is the whole reason this mapping needs no
// subtraction.
const assistantLine = `{"type":"assistant","timestamp":"2026-09-02T05:06:52.813Z",` +
	`"sessionId":"3231c9b2-e112-47ee-b9bd-40a47a403b27","message":{"id":"msg_01ABC",` +
	`"model":"claude-opus-5","usage":{"input_tokens":2,"cache_creation_input_tokens":23947,` +
	`"cache_read_input_tokens":26354,"output_tokens":1469,` +
	`"output_tokens_details":{"thinking_tokens":298}}}}`

func writeTranscript(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transcript.jsonl")
	body := ""
	for _, line := range lines {
		body += line + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanHookTranscriptMapsDisjointTokenClasses(t *testing.T) {
	t.Parallel()
	path := writeTranscript(t, assistantLine)
	calls, offset, err := scanHookTranscript(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls=%d, want 1", len(calls))
	}
	call := calls[0]
	if call.DedupeKey != "msg_01ABC" || call.Model != "claude-opus-5" || call.Provider != "anthropic" {
		t.Fatalf("attribution=%+v", call)
	}
	if call.Usage.UncachedInputTokens != 2 || call.Usage.CacheReadTokens != 26354 ||
		call.Usage.CacheWriteTokens != 23947 || call.Usage.OutputTokens != 1469 {
		t.Fatalf("usage=%+v, want the four classes carried across unchanged", call.Usage)
	}
	if call.Usage.ReasoningTokens == nil || *call.Usage.ReasoningTokens != 298 {
		t.Fatalf("reasoning=%v, want 298", call.Usage.ReasoningTokens)
	}
	// A transcript records cost, never latency. Reporting a zero would be a
	// fabricated instant response.
	if call.DurationMS != nil {
		t.Fatalf("duration=%v, want nil because the transcript does not measure it", *call.DurationMS)
	}
	if call.RawUsage == "" {
		t.Fatal("raw usage must travel with the observation so the mapping stays auditable")
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if offset != stat.Size() {
		t.Fatalf("offset=%d, want the whole file consumed (%d)", offset, stat.Size())
	}
}

func TestScanHookTranscriptSkipsEntriesWithoutUsage(t *testing.T) {
	t.Parallel()
	path := writeTranscript(t,
		`{"type":"user","timestamp":"2026-09-02T05:06:00Z","message":{"role":"user"}}`,
		`{"type":"assistant","timestamp":"2026-09-02T05:06:10Z","message":{"id":"m","model":"x"}}`,
		`not json at all`,
		assistantLine,
	)
	calls, _, err := scanHookTranscript(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls=%d, want only the entry that carries usage", len(calls))
	}
}

// The watermark is what makes a re-run cheap and a re-read harmless.
func TestScanHookTranscriptResumesFromTheWatermark(t *testing.T) {
	t.Parallel()
	path := writeTranscript(t, assistantLine)
	_, offset, err := scanHookTranscript(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls, second, err := scanHookTranscript(path, offset)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("calls=%d, want nothing new on a second pass", len(calls))
	}
	if second != offset {
		t.Fatalf("offset moved from %d to %d with nothing read", offset, second)
	}
}

// A record still being written has no newline yet. Consuming it would store a
// truncated entry and advance past the real one.
func TestScanHookTranscriptLeavesAPartialFinalLine(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "transcript.jsonl")
	partial := assistantLine + "\n" + `{"type":"assistant","timestamp":"2026`
	if err := os.WriteFile(path, []byte(partial), 0o600); err != nil {
		t.Fatal(err)
	}
	calls, offset, err := scanHookTranscript(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls=%d, want only the complete record", len(calls))
	}
	if offset != int64(len(assistantLine)+1) {
		t.Fatalf("offset=%d, want the watermark to stop before the partial line", offset)
	}
}

// A host that replaced the transcript leaves an offset past the end. Trusting
// it would skip the whole new file.
func TestScanHookTranscriptRestartsWhenTheFileShrank(t *testing.T) {
	t.Parallel()
	path := writeTranscript(t, assistantLine)
	calls, _, err := scanHookTranscript(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls=%d, want a restart from the beginning", len(calls))
	}
}

func TestScanHookTranscriptBoundsOneRun(t *testing.T) {
	t.Parallel()
	lines := make([]string, hookTelemetryMaxPerRun+10)
	for index := range lines {
		lines[index] = strings.Replace(assistantLine, "msg_01ABC", "msg_"+itoaHook(index), 1)
	}
	path := writeTranscript(t, lines...)
	calls, offset, err := scanHookTranscript(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != hookTelemetryMaxPerRun {
		t.Fatalf("calls=%d, want the per-run cap %d", len(calls), hookTelemetryMaxPerRun)
	}
	stat, _ := os.Stat(path)
	if offset >= stat.Size() {
		t.Fatal("a capped run must leave the remainder for the next invocation")
	}
}

func itoaHook(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}

// A transcript this hook has not seen before restarts, because an offset into a
// different file means nothing.
func TestReportHookTelemetryResetsOnANewTranscript(t *testing.T) {
	t.Parallel()
	var received hookTelemetryRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewDecoder(request.Body).Decode(&received)
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write([]byte(`{"accepted":1}`))
	}))
	defer server.Close()
	origin, _ := url.Parse(server.URL + "/")

	path := writeTranscript(t, assistantLine)
	state := hookState{RegistrationToken: "token", TranscriptPath: "/some/other.jsonl", TranscriptOffset: 999}
	updated, err := reportHookTelemetry(context.Background(), server.Client(), origin, state, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(received.ModelCalls) != 1 {
		t.Fatalf("posted=%d, want the new transcript read from its start", len(received.ModelCalls))
	}
	if updated.TranscriptPath != path || updated.TranscriptOffset == 999 {
		t.Fatalf("state=%+v, want the watermark rebound to the new transcript", updated)
	}
}

// A failed post must not advance the watermark, or the observations it was
// carrying are lost with no way to notice.
func TestReportHookTelemetryKeepsTheWatermarkWhenThePostFails(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	origin, _ := url.Parse(server.URL + "/")

	path := writeTranscript(t, assistantLine)
	state := hookState{RegistrationToken: "token"}
	updated, err := reportHookTelemetry(context.Background(), server.Client(), origin, state, path)
	if err == nil {
		t.Fatal("a rejected submission must be reported to the caller for logging")
	}
	if updated.TranscriptOffset != 0 || updated.TranscriptPath != "" {
		t.Fatalf("state=%+v, want the watermark untouched so the next run retries", updated)
	}
}

func TestReportHookTelemetryIgnoresAHostWithNoTranscript(t *testing.T) {
	t.Parallel()
	state := hookState{RegistrationToken: "token"}
	updated, err := reportHookTelemetry(context.Background(), http.DefaultClient, nil, state, "")
	if err != nil {
		t.Fatal(err)
	}
	if updated != state {
		t.Fatal("a host that exposes no transcript must be a no-op")
	}
}
