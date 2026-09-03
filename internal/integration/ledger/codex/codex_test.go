package codex_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/integration/ledger"
	"github.com/phall1/blackbird/internal/integration/ledger/codex"
)

// Every fixture below is a real line shape taken from the rollout tree this
// adapter was measured against, trimmed to the fields the mapping reads.
const (
	sessionHeader = `{"timestamp":"2026-07-04T05:06:33.285Z","type":"session_meta",` +
		`"payload":{"session_id":"019f2b85-702c-7713-9187-11513be0e1a2",` +
		`"id":"019f2b85-702c-7713-9187-11513be0e1a2","cwd":"/Users/phall/workspace/intel-lanes/agent",` +
		`"originator":"codex_exec","model_provider":"openai","base_instructions":{"text":"ignored"}}}`
	turnContext = `{"timestamp":"2026-07-04T05:06:34.420Z","type":"turn_context",` +
		`"payload":{"turn_id":"019f2b85-70ae","cwd":"/Users/phall/workspace/intel-lanes/agent/sub",` +
		`"model":"gpt-5.5","effort":"high"}}`
	// The first call of a real session: input 18985 INCLUDES cached 13696.
	firstCall = `{"timestamp":"2026-07-04T05:06:41.946Z","type":"event_msg","payload":{"type":"token_count",` +
		`"info":{"total_token_usage":{"input_tokens":18985,"cached_input_tokens":13696,` +
		`"output_tokens":323,"reasoning_output_tokens":82,"total_tokens":19308},` +
		`"last_token_usage":{"input_tokens":18985,"cached_input_tokens":13696,` +
		`"output_tokens":323,"reasoning_output_tokens":82,"total_tokens":19308},` +
		`"model_context_window":258400}}}`
	secondCall = `{"timestamp":"2026-07-04T05:06:48.924Z","type":"event_msg","payload":{"type":"token_count",` +
		`"info":{"total_token_usage":{"input_tokens":42420,"cached_input_tokens":32512,` +
		`"output_tokens":658,"reasoning_output_tokens":139,"total_tokens":43078},` +
		`"last_token_usage":{"input_tokens":23435,"cached_input_tokens":18816,` +
		`"output_tokens":335,"reasoning_output_tokens":57,"total_tokens":23770},` +
		`"model_context_window":258400}}}`
	// The repeat: a later ordinal, a later timestamp, and a running total that
	// did not move. Observed verbatim (ordinals 48 and 49 of one session).
	secondCallRepeated = `{"timestamp":"2026-07-04T05:06:52.001Z","ordinal":49,"type":"event_msg",` +
		`"payload":{"type":"token_count",` +
		`"info":{"total_token_usage":{"input_tokens":42420,"cached_input_tokens":32512,` +
		`"output_tokens":658,"reasoning_output_tokens":139,"total_tokens":43078},` +
		`"last_token_usage":{"input_tokens":23435,"cached_input_tokens":18816,` +
		`"output_tokens":335,"reasoning_output_tokens":57,"total_tokens":23770},` +
		`"model_context_window":258400}}}`
	// A rate-limit refresh: the running total is restated and nothing was spent.
	rateLimitRefresh = `{"timestamp":"2026-07-04T05:07:00.000Z","type":"event_msg","payload":{"type":"token_count",` +
		`"info":{"total_token_usage":{"input_tokens":42420,"cached_input_tokens":32512,` +
		`"output_tokens":658,"reasoning_output_tokens":139,"total_tokens":43078},` +
		`"last_token_usage":{"input_tokens":0,"cached_input_tokens":0,"output_tokens":0,` +
		`"reasoning_output_tokens":0,"total_tokens":0}}}}`
)

// decodeOne runs the adapter over a sequence of lines the way the framework
// does -- threading each returned context into the next call -- and returns the
// observations and the errors. It is the whole point of the contextual shape,
// so the tests exercise it rather than a single line in isolation.
func decodeAll(t *testing.T, lines ...string) ([]domain.ModelCall, []string, []error) {
	t.Helper()
	adapter := codex.New()
	fileContext := ""
	projectKey := ""
	calls := make([]domain.ModelCall, 0, len(lines))
	errs := make([]error, 0)
	for _, line := range lines {
		record, ok, err := adapter.DecodeInContext([]byte(line), fileContext)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if record.ProjectKey != "" && projectKey == "" {
			projectKey = record.ProjectKey
		}
		if record.Context != "" {
			fileContext = record.Context
		}
		if ok {
			calls = append(calls, record.Call)
		}
	}
	return calls, []string{projectKey, fileContext}, errs
}

// TestCodexInputConventionIsInvertedFromAnthropic is the regression guard the
// whole adapter exists around, and it is written to fail loudly if someone
// later "simplifies" the subtraction away.
//
// Codex reports input_tokens INCLUDING cache. Anthropic reports it EXCLUDING
// cache. Handed the identical five numbers, the two conventions must produce
// different uncached input, and only one of them is right for this ledger. If
// input_tokens were mapped straight onto UncachedInput -- the change that looks
// like a simplification -- every Codex row would count its cached prompt twice,
// no bound would be violated, no error would be raised, and every cross-harness
// total would overstate Codex while OpenCode stayed correct.
func TestCodexInputConventionIsInvertedFromAnthropic(t *testing.T) {
	t.Parallel()
	calls, _, errs := decodeAll(t, sessionHeader, turnContext, firstCall)
	if len(errs) != 0 {
		t.Fatalf("unexpected decode errors: %v", errs)
	}
	if len(calls) != 1 {
		t.Fatalf("calls=%d, want 1", len(calls))
	}
	usage := calls[0].Usage

	const rawInput, rawCached = 18985, 13696
	// The Anthropic reading of the same numbers, spelled out rather than
	// imported, so this test states the contrast it is guarding.
	anthropicReading := domain.TokenUsage{UncachedInput: rawInput, CacheRead: rawCached}

	if usage.UncachedInput != rawInput-rawCached {
		t.Fatalf("uncached input=%d, want %d (input %d MINUS cached %d; Codex's input "+
			"includes cache and this subtraction is the adapter's whole job)",
			usage.UncachedInput, rawInput-rawCached, rawInput, rawCached)
	}
	if usage.UncachedInput == anthropicReading.UncachedInput {
		t.Fatal("uncached input matches the Anthropic convention, so the subtraction was lost")
	}
	if usage.CacheRead != rawCached {
		t.Fatalf("cache read=%d, want %d", usage.CacheRead, rawCached)
	}
	// The identity that makes the mistake visible: what a provider bills as
	// input is exactly the number Codex reported, never that number plus its
	// own cached subset.
	if usage.BilledInput() != rawInput {
		t.Fatalf("billed input=%d, want %d; the disjoint classes must sum back to "+
			"Codex's reported input_tokens", usage.BilledInput(), rawInput)
	}
	if usage.Output != 323 || usage.Reasoning != 82 || !usage.ReasoningReported {
		t.Fatalf("output usage=%+v", usage)
	}
}

// TestNormalizeCountsCacheWriteAsAThirdInputComponent pins the reading of the
// field that appeared after the corpus was measured. The three classes must
// still sum to the reported input.
func TestNormalizeCountsCacheWriteAsAThirdInputComponent(t *testing.T) {
	t.Parallel()
	line := `{"timestamp":"2026-09-02T08:37:31.759Z","type":"event_msg","payload":{"type":"token_count",` +
		`"info":{"total_token_usage":{"input_tokens":20527,"cached_input_tokens":4480,` +
		`"cache_write_input_tokens":1024,"output_tokens":191,"reasoning_output_tokens":64},` +
		`"last_token_usage":{"input_tokens":20527,"cached_input_tokens":4480,` +
		`"cache_write_input_tokens":1024,"output_tokens":191,"reasoning_output_tokens":64}}}}`
	calls, _, errs := decodeAll(t, sessionHeader, turnContext, line)
	if len(errs) != 0 || len(calls) != 1 {
		t.Fatalf("calls=%d errs=%v", len(calls), errs)
	}
	usage := calls[0].Usage
	if usage.UncachedInput != 20527-4480-1024 {
		t.Fatalf("uncached input=%d, want %d", usage.UncachedInput, 20527-4480-1024)
	}
	if usage.CacheWrite != 1024 || usage.CacheRead != 4480 {
		t.Fatalf("usage=%+v", usage)
	}
	if usage.BilledInput() != 20527 {
		t.Fatalf("billed input=%d, want 20527", usage.BilledInput())
	}
}

// TestNormalizeSaturatesWhenPartsExceedTheWhole covers the unsigned arithmetic
// that would otherwise wrap into an astronomically large token count.
func TestNormalizeSaturatesWhenPartsExceedTheWhole(t *testing.T) {
	t.Parallel()
	line := `{"timestamp":"2026-09-02T08:37:31.759Z","type":"event_msg","payload":{"type":"token_count",` +
		`"info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":900,` +
		`"cache_write_input_tokens":900,"output_tokens":10,"reasoning_output_tokens":99},` +
		`"last_token_usage":{"input_tokens":100,"cached_input_tokens":900,` +
		`"cache_write_input_tokens":900,"output_tokens":10,"reasoning_output_tokens":99}}}}`
	calls, _, errs := decodeAll(t, sessionHeader, turnContext, line)
	if len(errs) != 0 || len(calls) != 1 {
		t.Fatalf("calls=%d errs=%v", len(calls), errs)
	}
	usage := calls[0].Usage
	if usage.UncachedInput != 0 || usage.CacheRead != 100 || usage.CacheWrite != 0 {
		t.Fatalf("usage=%+v, want the components clamped to the reported input", usage)
	}
	if usage.Reasoning != 10 {
		t.Fatalf("reasoning=%d, want it clamped to output", usage.Reasoning)
	}
	if err := calls[0].Validate(); err != nil {
		t.Fatalf("saturated usage must still validate: %v", err)
	}
}

// TestDedupeKeyCollapsesARepeatedEmission is the other half of getting Codex's
// numbers right. The harness restates a finished call with a new timestamp and
// a new ordinal while its own running total stands still; counted twice, one
// observed session's 79,683 tokens would have been billed as 117,098.
func TestDedupeKeyCollapsesARepeatedEmission(t *testing.T) {
	t.Parallel()
	calls, _, errs := decodeAll(t, sessionHeader, turnContext, firstCall, secondCall, secondCallRepeated)
	if len(errs) != 0 {
		t.Fatalf("unexpected decode errors: %v", errs)
	}
	if len(calls) != 3 {
		t.Fatalf("calls=%d, want 3 decoded records", len(calls))
	}
	if calls[1].DedupeKey != calls[2].DedupeKey {
		t.Fatalf("the repeat got its own dedupe key (%q vs %q); it would be counted twice",
			calls[1].DedupeKey, calls[2].DedupeKey)
	}
	if calls[0].DedupeKey == calls[1].DedupeKey {
		t.Fatal("two distinct calls share a dedupe key; real spend would be discarded")
	}
	if !strings.Contains(calls[0].DedupeKey, "019f2b85-702c-7713-9187-11513be0e1a2") {
		t.Fatalf("dedupe key %q does not name its session, so two sessions could collide",
			calls[0].DedupeKey)
	}
}

// TestDecodeSkipsRateLimitRefreshEvents keeps an event that spent nothing out of
// the plane, where it would be an observation of no call at all.
func TestDecodeSkipsRateLimitRefreshEvents(t *testing.T) {
	t.Parallel()
	calls, _, errs := decodeAll(t, sessionHeader, turnContext, rateLimitRefresh)
	if len(errs) != 0 {
		t.Fatalf("a refresh is not malformed: %v", errs)
	}
	if len(calls) != 0 {
		t.Fatalf("calls=%d, want none", len(calls))
	}
}

// TestSessionHeaderCarriesAttributionAndTurnContextCarriesTheModel pins which
// line speaks for what. turn_context names a working directory too -- often a
// subdirectory or a second workspace root -- and letting it speak would scatter
// one session's spend across project keys.
func TestSessionHeaderCarriesAttributionAndTurnContextCarriesTheModel(t *testing.T) {
	t.Parallel()
	calls, state, errs := decodeAll(t, sessionHeader, turnContext, firstCall)
	if len(errs) != 0 || len(calls) != 1 {
		t.Fatalf("calls=%d errs=%v", len(calls), errs)
	}
	if state[0] != "/Users/phall/workspace/intel-lanes/agent" {
		t.Fatalf("project key=%q, want the session header's cwd rather than the turn's", state[0])
	}
	call := calls[0]
	if call.Model != "gpt-5.5" || call.Provider != "openai" {
		t.Fatalf("model=%q provider=%q", call.Model, call.Provider)
	}
	if call.Harness != domain.HarnessCodex {
		t.Fatalf("harness=%q", call.Harness)
	}
	if call.HarnessSession != "019f2b85-702c-7713-9187-11513be0e1a2" {
		t.Fatalf("harness session=%q", call.HarnessSession)
	}
	if call.DurationKnown {
		t.Fatal("a rollout records no latency; a fabricated zero would drag every average toward instant")
	}
	if call.RawUsage == "" {
		t.Fatal("raw usage is the audit trail for the subtraction and must be kept")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(call.RawUsage), &raw); err != nil {
		t.Fatalf("raw usage is not readable JSON: %v", err)
	}
	if _, present := raw["last_token_usage"]; !present {
		t.Fatalf("raw usage does not keep the delta it normalized: %s", call.RawUsage)
	}
	if err := call.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestModelChangesWithTheTurnAndAttributionDoesNot covers a compaction turn,
// where Codex swaps to a smaller model mid-session.
func TestModelChangesWithTheTurnAndAttributionDoesNot(t *testing.T) {
	t.Parallel()
	compactTurn := `{"timestamp":"2026-07-04T05:06:44.000Z","type":"turn_context",` +
		`"payload":{"cwd":"/elsewhere","model":"gpt-5.4-mini"}}`
	calls, state, errs := decodeAll(t, sessionHeader, turnContext, firstCall, compactTurn, secondCall)
	if len(errs) != 0 || len(calls) != 2 {
		t.Fatalf("calls=%d errs=%v", len(calls), errs)
	}
	if calls[0].Model != "gpt-5.5" || calls[1].Model != "gpt-5.4-mini" {
		t.Fatalf("models=%q,%q", calls[0].Model, calls[1].Model)
	}
	if state[0] != "/Users/phall/workspace/intel-lanes/agent" {
		t.Fatalf("project key moved to %q", state[0])
	}
}

// TestResumedSessionAdoptsTheNewSessionIDAndKeepsTheModel covers the second
// session_meta a forked or resumed thread appends, which arrives before the
// turn_context that would restate the model.
func TestResumedSessionAdoptsTheNewSessionIDAndKeepsTheModel(t *testing.T) {
	t.Parallel()
	resumed := `{"timestamp":"2026-07-04T05:06:45.000Z","type":"session_meta",` +
		`"payload":{"id":"019f2b99-0000-7000-8000-000000000000","cwd":"/elsewhere",` +
		`"model_provider":"openai","parent_thread_id":"019f2b85-702c-7713-9187-11513be0e1a2"}}`
	calls, state, errs := decodeAll(t, sessionHeader, turnContext, firstCall, resumed, secondCall)
	if len(errs) != 0 || len(calls) != 2 {
		t.Fatalf("calls=%d errs=%v", len(calls), errs)
	}
	if calls[1].HarnessSession != "019f2b99-0000-7000-8000-000000000000" {
		t.Fatalf("harness session=%q, want the resumed thread's", calls[1].HarnessSession)
	}
	if calls[1].Model != "gpt-5.5" {
		t.Fatalf("model=%q, want the model carried across the resume", calls[1].Model)
	}
	if state[0] != "/Users/phall/workspace/intel-lanes/agent" {
		t.Fatalf("project key moved to %q", state[0])
	}
}

// TestUsageBeforeItsSessionHeaderIsReportedRatherThanGuessed keeps an
// unattributable observation out of the plane and visible in a counter.
func TestUsageBeforeItsSessionHeaderIsReportedRatherThanGuessed(t *testing.T) {
	t.Parallel()
	for name, lines := range map[string][]string{
		"no header at all": {firstCall},
		"no model yet":     {sessionHeader, firstCall},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			calls, _, errs := decodeAll(t, lines...)
			if len(calls) != 0 {
				t.Fatalf("calls=%d, want none", len(calls))
			}
			if len(errs) != 1 {
				t.Fatalf("errors=%v, want exactly one malformed report", errs)
			}
		})
	}
}

func TestDecodeClassifiesUnreadableLines(t *testing.T) {
	t.Parallel()
	for name, testCase := range map[string]struct {
		line     string
		observed bool
		failed   bool
	}{
		"blank":          {line: "   "},
		"not json":       {line: "recovered log fragment"},
		"truncated json": {line: `{"type":"event_msg","payload":`, failed: true},
		"unknown type":   {line: `{"type":"response_item","payload":{"type":"message"}}`},
		"other event":    {line: `{"type":"event_msg","payload":{"type":"task_started"}}`},
		"token count no info": {line: `{"timestamp":"2026-07-04T05:06:41.946Z","type":"event_msg",` +
			`"payload":{"type":"token_count"}}`, failed: true},
		"unreadable timestamp": {line: `{"timestamp":"yesterday","type":"event_msg","payload":` +
			`{"type":"token_count","info":{"total_token_usage":{"input_tokens":5},` +
			`"last_token_usage":{"input_tokens":5}}}}`, failed: true},
		"turn context without a model": {line: `{"type":"turn_context","payload":{"cwd":"/x"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			calls, _, errs := decodeAll(t, sessionHeader, turnContext, testCase.line)
			if got := len(calls) > 0; got != testCase.observed {
				t.Fatalf("observed=%v, want %v", got, testCase.observed)
			}
			if got := len(errs) > 0; got != testCase.failed {
				t.Fatalf("failed=%v (%v), want %v", got, errs, testCase.failed)
			}
		})
	}
}

// TestDedupeKeyStaysInsideThePlanesBound covers the hash fallback. The bound is
// the idempotency guarantee, so a pathological session id must shorten the key
// rather than have the record rejected at validation.
func TestDedupeKeyStaysInsideThePlanesBound(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("s", domain.MaxHarnessSessionBytes)
	header := `{"type":"session_meta","payload":{"id":"` + long +
		`","cwd":"/w","model_provider":"openai"}}`
	calls, _, errs := decodeAll(t, header, turnContext, firstCall, secondCall)
	if len(errs) != 0 || len(calls) != 2 {
		t.Fatalf("calls=%d errs=%v", len(calls), errs)
	}
	for _, call := range calls {
		if len(call.DedupeKey) > domain.MaxDedupeKeyBytes {
			t.Fatalf("dedupe key is %d bytes, over the plane's bound", len(call.DedupeKey))
		}
		if err := call.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
	}
	if calls[0].DedupeKey == calls[1].DedupeKey {
		t.Fatal("the hash fallback collapsed two distinct calls")
	}
}

type namedEntry struct {
	fs.DirEntry
	name string
}

func (entry namedEntry) Name() string { return entry.name }

func TestLedgerMatchesRolloutsOnly(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"rollout-2026-07-03T23-06-33-019f2b85.jsonl": true,
		"rollout-2026-06-10T00-06-56-019eafb6.jsonl": true,
		// Compressed rollouts are skipped rather than failed: the framework
		// resumes by seeking to a byte offset, which a zstd stream cannot honour.
		"rollout-2026-05-01T00-00-00-019e0000.jsonl.zst": false,
		"history.jsonl":     false,
		"state_5.sqlite":    false,
		"config.toml":       false,
		"rollout-notes.txt": false,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := codex.New().Ledger(filepath.Join("/root", name), namedEntry{name: name}); got != want {
				t.Fatalf("Ledger(%q)=%v, want %v", name, got, want)
			}
		})
	}
}

// TestDecodeWithoutContextIsTheEmptyContextCase pins the ledger.Adapter method
// the framework never calls for this adapter. It must behave as a first line
// would: header lines still establish their facts, and an observation without
// one is reported rather than guessed.
func TestDecodeWithoutContextIsTheEmptyContextCase(t *testing.T) {
	t.Parallel()
	adapter := codex.New()
	record, ok, err := adapter.Decode([]byte(sessionHeader))
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v; a header is context, not an observation", ok, err)
	}
	if record.ProjectKey != "/Users/phall/workspace/intel-lanes/agent" || record.Context == "" {
		t.Fatalf("record=%+v", record)
	}
	if _, ok, err := adapter.Decode([]byte(firstCall)); ok || err == nil {
		t.Fatalf("ok=%v err=%v; usage with no carried header must be reported", ok, err)
	}
}

func TestDefaultRootHonoursCodexHome(t *testing.T) {
	t.Setenv("CODEX_HOME", "/custom/codex")
	root, err := codex.DefaultRoot()
	if err != nil {
		t.Fatal(err)
	}
	if root != "/custom/codex" {
		t.Fatalf("root=%q", root)
	}
	t.Setenv("CODEX_HOME", "  ")
	root, err = codex.DefaultRoot()
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory on this machine")
	}
	if root != filepath.Join(home, ".codex") {
		t.Fatalf("root=%q, want the default Codex home", root)
	}
}

// recordingIngest captures what the collector offered.
type recordingIngest struct {
	mutex     sync.Mutex
	envelopes []telemetry.Envelope
}

func (ingest *recordingIngest) Offer(envelope telemetry.Envelope) bool {
	ingest.mutex.Lock()
	defer ingest.mutex.Unlock()
	ingest.envelopes = append(ingest.envelopes, envelope)
	return true
}

func (ingest *recordingIngest) calls() []domain.ModelCall {
	ingest.mutex.Lock()
	defer ingest.mutex.Unlock()
	collected := make([]domain.ModelCall, 0, 8)
	for _, envelope := range ingest.envelopes {
		collected = append(collected, envelope.ModelCalls...)
	}
	return collected
}

// TestCollectorResumesMidFileWithTheSessionHeaderItAlreadyRead is the end-to-end
// case the contextual shape exists for, and the one that would be silently
// wrong if the carry lived in the adapter instead of the cursor. The first pass
// reads the header and one call; a second collector -- a fresh process, sharing
// only the cursor file -- resumes at the byte watermark, past the header, and
// must still know the model.
func TestCollectorResumesMidFileWithTheSessionHeaderItAlreadyRead(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	statePath := filepath.Join(t.TempDir(), "codex.json")
	path := filepath.Join(root, "sessions", "2026", "07", "03",
		"rollout-2026-07-03T23-06-33-019f2b85.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(lines ...string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(sessionHeader, turnContext, firstCall)
	first := &recordingIngest{}
	collector, err := ledger.New(ledger.Config{
		Adapter: codex.New(), Root: root, StatePath: statePath, Ingest: first,
	})
	if err != nil {
		t.Fatal(err)
	}
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pass.Offered != 1 || pass.Malformed != 0 {
		t.Fatalf("first pass=%+v", pass)
	}

	// A second process appends two more calls, one of them the repeat.
	write(sessionHeader, turnContext, firstCall, secondCall, secondCallRepeated)
	resumed := &recordingIngest{}
	collector, err = ledger.New(ledger.Config{
		Adapter: codex.New(), Root: root, StatePath: statePath, Ingest: resumed,
	})
	if err != nil {
		t.Fatal(err)
	}
	pass, err = collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pass.Malformed != 0 {
		t.Fatalf("resuming past the session header lost it: %+v", pass)
	}
	if pass.Duplicates != 1 {
		t.Fatalf("duplicates=%d, want the repeated emission collapsed in-pass", pass.Duplicates)
	}
	if pass.Offered != 1 {
		t.Fatalf("offered=%d, want only the one new call", pass.Offered)
	}
	calls := resumed.calls()
	if len(calls) != 1 {
		t.Fatalf("calls=%d", len(calls))
	}
	if calls[0].Model != "gpt-5.5" || calls[0].Usage.UncachedInput != 23435-18816 {
		t.Fatalf("resumed call=%+v", calls[0])
	}
	for _, envelope := range resumed.envelopes {
		if envelope.Attribution.ProjectKey != "/Users/phall/workspace/intel-lanes/agent" {
			t.Fatalf("attribution=%+v, want the pinned project key from the first pass",
				envelope.Attribution)
		}
		if envelope.Source != telemetry.SourceCollected {
			t.Fatalf("source=%v", envelope.Source)
		}
	}
}

// TestForkedThreadReplayCollapsesIntoTheParentsRecords covers the cross-file
// half of the duplicate problem. A forked thread's rollout re-emits its
// parent's token_count events under the parent's session id and running totals,
// stamped with one synthetic timestamp at the fork. A key built from the
// timestamp, the event's ordinal, or the file it was read from would count all
// of them a second time -- 148 records and 12.3M billed input tokens on the
// tree this was measured against.
func TestForkedThreadReplayCollapsesIntoTheParentsRecords(t *testing.T) {
	t.Parallel()
	forkHeader := `{"timestamp":"2026-07-04T06:00:00.000Z","type":"session_meta",` +
		`"payload":{"id":"019f2b85-702c-7713-9187-11513be0e1a2",` +
		`"cwd":"/Users/phall/workspace/intel-lanes/agent","model_provider":"openai",` +
		`"forked_from_id":"019f2b85-702c-7713-9187-11513be0e1a2"}}`
	replayed := strings.ReplaceAll(firstCall, "2026-07-04T05:06:41.946Z", "2026-07-04T06:00:00.000Z")
	if replayed == firstCall {
		t.Fatal("fixture did not restamp the replayed record")
	}
	original, _, errs := decodeAll(t, sessionHeader, turnContext, firstCall)
	if len(errs) != 0 || len(original) != 1 {
		t.Fatalf("calls=%d errs=%v", len(original), errs)
	}
	replay, _, errs := decodeAll(t, forkHeader, turnContext, replayed)
	if len(errs) != 0 || len(replay) != 1 {
		t.Fatalf("calls=%d errs=%v", len(replay), errs)
	}
	if original[0].StartedAt.Equal(replay[0].StartedAt) {
		t.Fatal("fixture is not exercising the restamp")
	}
	if original[0].DedupeKey != replay[0].DedupeKey {
		t.Fatalf("the replay got its own dedupe key (%q vs %q); a forked thread would "+
			"double the parent's whole history", original[0].DedupeKey, replay[0].DedupeKey)
	}
}
