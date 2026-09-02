package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Claude Code's half of the observation plane (ADR-0001).
//
// Claude Code is the asymmetric adapter. Pi and OpenCode hand a plugin the
// token counts directly; Claude Code's MCP surface shows a server only its own
// tool frames, and the usage lives in the session transcript. So this reads the
// transcript the hook payload names, from a byte watermark, and reports what it
// finds after the hook has already answered the host.
//
// Ordering is the point: telemetry runs after writeHookOutput, so a slow or
// absent daemon cannot delay the mail this hook exists to deliver. Every error
// path here is a log line and a return.
const (
	// hookTelemetryPath is the daemon's ingest route.
	hookTelemetryPath = "api/v1/local/telemetry"
	// hookTelemetryMaxPerRun bounds one invocation's catch-up. A months-old
	// transcript scanned in one pass would post thousands of observations
	// inside a hook the host is waiting on; the watermark makes the remainder
	// the next invocation's problem, which is exactly what a watermark is for.
	hookTelemetryMaxPerRun = 256
	// hookTelemetryMaxLineBytes skips a transcript line too large to be a
	// usage record. Transcript lines carry full message content and can be
	// megabytes; the usage object never is.
	hookTelemetryMaxLineBytes = 1 << 20
	// hookTelemetryMaxRawUsage matches the daemon's raw_usage bound.
	hookTelemetryMaxRawUsage = 4096
)

type hookTranscriptUsage struct {
	InputTokens              uint64 `json:"input_tokens"`
	CacheCreationInputTokens uint64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     uint64 `json:"cache_read_input_tokens"`
	OutputTokens             uint64 `json:"output_tokens"`
	OutputTokensDetails      *struct {
		ThinkingTokens uint64 `json:"thinking_tokens"`
	} `json:"output_tokens_details"`
}

type hookTranscriptEntry struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	SessionID string `json:"sessionId"`
	Message   *struct {
		ID    string               `json:"id"`
		Model string               `json:"model"`
		Usage *hookTranscriptUsage `json:"usage"`
	} `json:"message"`
}

type hookTelemetryUsage struct {
	UncachedInputTokens uint64  `json:"uncached_input_tokens"`
	CacheReadTokens     uint64  `json:"cache_read_tokens"`
	CacheWriteTokens    uint64  `json:"cache_write_tokens"`
	OutputTokens        uint64  `json:"output_tokens"`
	ReasoningTokens     *uint64 `json:"reasoning_tokens,omitempty"`
}

type hookTelemetryModelCall struct {
	DedupeKey      string             `json:"dedupe_key"`
	Harness        string             `json:"harness"`
	HarnessSession string             `json:"harness_session,omitempty"`
	Provider       string             `json:"provider"`
	Model          string             `json:"model"`
	Operation      string             `json:"operation"`
	Usage          hookTelemetryUsage `json:"usage"`
	Outcome        string             `json:"outcome"`
	StartedAt      string             `json:"started_at"`
	// DurationMS is always nil here. A transcript records what a call cost and
	// never how long it took, and a fabricated zero would drag every latency
	// statistic toward instant.
	DurationMS *int64 `json:"duration_ms"`
	RawUsage   string `json:"raw_usage,omitempty"`
}

type hookTelemetryRequest struct {
	ModelCalls []hookTelemetryModelCall `json:"model_calls"`
}

// scanHookTranscript reads observations from offset and reports where it
// stopped. A transcript this hook has not seen before, or one that shrank
// because the host replaced it, restarts from the beginning.
func scanHookTranscript(path string, offset int64) ([]hookTelemetryModelCall, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	if offset > info.Size() {
		offset = 0
	}
	file, err := os.Open(path) //nolint:gosec // the host names its own transcript.
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, 0, err
	}
	reader := bufio.NewReader(file)
	calls := make([]hookTelemetryModelCall, 0, 16)
	position := offset
	for len(calls) < hookTelemetryMaxPerRun {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && errors.Is(err, io.EOF) {
			// A final line without its newline is a record still being written.
			// Leave the watermark before it so the next run reads it whole.
			break
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return calls, position, err
		}
		position += int64(len(line))
		if len(line) > hookTelemetryMaxLineBytes {
			continue
		}
		if call, ok := transcriptModelCall(line); ok {
			calls = append(calls, call)
		}
	}
	return calls, position, nil
}

func transcriptModelCall(line []byte) (hookTelemetryModelCall, bool) {
	var entry hookTranscriptEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return hookTelemetryModelCall{}, false
	}
	if entry.Type != "assistant" || entry.Message == nil || entry.Message.Usage == nil {
		return hookTelemetryModelCall{}, false
	}
	if entry.Message.ID == "" || entry.Message.Model == "" || entry.Timestamp == "" {
		return hookTelemetryModelCall{}, false
	}
	usage := entry.Message.Usage
	// Anthropic reports input_tokens EXCLUDING cache, so these four classes are
	// already disjoint and none of them needs a subtraction. A live transcript
	// shows input_tokens=2 beside cache_read_input_tokens=26354, which is the
	// shape this mapping relies on.
	call := hookTelemetryModelCall{
		DedupeKey:      entry.Message.ID,
		Harness:        "claude-code",
		HarnessSession: entry.SessionID,
		Provider:       "anthropic",
		Model:          entry.Message.Model,
		Operation:      "chat",
		Usage: hookTelemetryUsage{
			UncachedInputTokens: usage.InputTokens,
			CacheReadTokens:     usage.CacheReadInputTokens,
			CacheWriteTokens:    usage.CacheCreationInputTokens,
			OutputTokens:        usage.OutputTokens,
		},
		Outcome:   "ok",
		StartedAt: entry.Timestamp,
	}
	if usage.OutputTokensDetails != nil {
		thinking := min(usage.OutputTokensDetails.ThinkingTokens, usage.OutputTokens)
		call.Usage.ReasoningTokens = &thinking
	}
	if raw, err := json.Marshal(usage); err == nil && len(raw) <= hookTelemetryMaxRawUsage {
		call.RawUsage = string(raw)
	}
	return call, true
}

// postHookTelemetry submits one batch. A failure is returned for logging and
// never retried: the watermark has not advanced, so the next invocation sees
// the same records again.
func postHookTelemetry(ctx context.Context, client *http.Client, origin *url.URL, token string,
	calls []hookTelemetryModelCall) error {
	if len(calls) == 0 {
		return nil
	}
	body, err := json.Marshal(hookTelemetryRequest{ModelCalls: calls})
	if err != nil {
		return err
	}
	target := origin.ResolveReference(&url.URL{Path: hookTelemetryPath})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, hookHTTPBodyLimit))
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("telemetry rejected with HTTP %d", response.StatusCode)
	}
	return nil
}

// reportHookTelemetry is the whole Claude Code path, in the order that keeps it
// harmless: read, post, and only then advance the watermark. It reports the new
// watermark and whether anything is worth logging.
func reportHookTelemetry(ctx context.Context, client *http.Client, origin *url.URL,
	state hookState, transcript string) (hookState, error) {
	if transcript == "" {
		return state, nil
	}
	offset := state.TranscriptOffset
	if state.TranscriptPath != transcript {
		offset = 0
	}
	calls, next, err := scanHookTranscript(transcript, offset)
	if err != nil {
		return state, err
	}
	// The watermark advances only past records that were accepted. A failed
	// post leaves it where it was, so the next invocation retries -- and the
	// daemon deduplicates anything that did land.
	if err := postHookTelemetry(ctx, client, origin, state.RegistrationToken, calls); err != nil {
		return state, err
	}
	state.TranscriptPath = transcript
	state.TranscriptOffset = next
	return state, nil
}

// hookTelemetryTimeout keeps the observation plane's request well inside the
// budget a host allows a hook, since this runs after the useful work.
const hookTelemetryTimeout = 3 * time.Second
