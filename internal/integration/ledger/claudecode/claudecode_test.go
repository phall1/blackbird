package claudecode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/phall1/blackbird/internal/domain"
)

// assistantLine is a real transcript record, trimmed to the fields this
// adapter reads and keeping the token values a live session produced. The
// input_tokens of 2 beside a cache read of 26354 is the whole reason the plane
// refuses a column called "input": it is not the billed input, and a harness
// that meant the other thing would put 50303 in the same field.
const assistantLine = `{"type":"assistant","uuid":"9efce75c-bd20-40c8-a8c0-f221935df7cf",` +
	`"timestamp":"2026-09-02T05:06:52.813Z","sessionId":"3231c9b2-e112-47ee-b9bd-40a47a403b27",` +
	`"cwd":"/Users/phall/workspace/blackbird","gitBranch":"main","version":"2.1.258",` +
	`"message":{"id":"msg_011Cee2pRqwyzzuzXP2TnpKA","model":"claude-opus-5","role":"assistant",` +
	`"usage":{"input_tokens":2,"cache_creation_input_tokens":23947,` +
	`"cache_read_input_tokens":26354,"output_tokens":1469,` +
	`"output_tokens_details":{"thinking_tokens":298},"service_tier":"standard"}}}`

func decodeOne(t *testing.T, line string) domain.ModelCall {
	t.Helper()
	record, ok, err := New().Decode([]byte(line))
	if err != nil || !ok {
		t.Fatalf("Decode() = ok %v, err %v; want a usage record", ok, err)
	}
	return record.Call
}

func TestDecodeKeepsTheTokenClassesDisjoint(t *testing.T) {
	t.Parallel()
	call := decodeOne(t, assistantLine)

	if call.Usage.UncachedInput != 2 {
		t.Errorf("uncached input = %d, want 2 -- Anthropic's input_tokens excludes cache", call.Usage.UncachedInput)
	}
	if call.Usage.CacheRead != 26354 {
		t.Errorf("cache read = %d, want 26354", call.Usage.CacheRead)
	}
	if call.Usage.CacheWrite != 23947 {
		t.Errorf("cache write = %d, want 23947", call.Usage.CacheWrite)
	}
	if call.Usage.Output != 1469 {
		t.Errorf("output = %d, want 1469", call.Usage.Output)
	}
	if !call.Usage.ReasoningReported || call.Usage.Reasoning != 298 {
		t.Errorf("reasoning = %d reported %v, want 298 reported", call.Usage.Reasoning, call.Usage.ReasoningReported)
	}
	if got := call.Usage.BilledInput(); got != 2+26354+23947 {
		t.Errorf("billed input = %d, want the three input classes summed", got)
	}
}

func TestDecodeAttributesTheCallWithoutInventingLatency(t *testing.T) {
	t.Parallel()
	record, ok, err := New().Decode([]byte(assistantLine))
	if err != nil || !ok {
		t.Fatalf("Decode() = ok %v, err %v", ok, err)
	}
	call := record.Call
	if call.DedupeKey != "msg_011Cee2pRqwyzzuzXP2TnpKA" {
		t.Errorf("dedupe key = %q, want the provider's message id", call.DedupeKey)
	}
	if call.Harness != domain.HarnessClaudeCode || call.Provider != "anthropic" {
		t.Errorf("attribution = %s/%s", call.Harness, call.Provider)
	}
	if call.Model != "claude-opus-5" || call.Operation != domain.ModelOperationChat {
		t.Errorf("model = %q operation = %q", call.Model, call.Operation)
	}
	if call.HarnessSession != "3231c9b2-e112-47ee-b9bd-40a47a403b27" {
		t.Errorf("harness session = %q", call.HarnessSession)
	}
	if record.ProjectKey != "/Users/phall/workspace/blackbird" {
		t.Errorf("project key = %q, want the record's own cwd", record.ProjectKey)
	}
	if call.DurationKnown || call.Duration != 0 {
		t.Errorf("duration = %s known %v; a transcript cannot measure latency and must not fake it",
			call.Duration, call.DurationKnown)
	}
	if call.RawUsage == "" {
		t.Error("raw usage is empty; the audit trail for the normalization is not optional")
	}
	if err := call.Validate(); err != nil {
		t.Errorf("the decoded call fails the plane's own validation: %v", err)
	}
	if call.StartedAt.Format("2006-01-02T15:04:05.000Z") != "2026-09-02T05:06:52.813Z" {
		t.Errorf("started at = %s", call.StartedAt)
	}
}

func TestDecodeClampsReasoningIntoOutput(t *testing.T) {
	t.Parallel()
	// Reasoning is a subset of output, never additional. A provider that
	// reported more must not produce a row the plane will reject outright.
	line := `{"type":"assistant","timestamp":"2026-09-02T05:06:52.813Z","sessionId":"s",` +
		`"cwd":"/w","message":{"id":"msg_1","model":"m","usage":{"input_tokens":1,` +
		`"output_tokens":10,"output_tokens_details":{"thinking_tokens":99}}}}`
	call := decodeOne(t, line)
	if call.Usage.Reasoning != 10 {
		t.Errorf("reasoning = %d, want it clamped to output", call.Usage.Reasoning)
	}
	if err := call.Validate(); err != nil {
		t.Errorf("clamped call still invalid: %v", err)
	}
}

func TestDecodeOmitsReasoningWhenTheHarnessDoesNotReportIt(t *testing.T) {
	t.Parallel()
	line := `{"type":"assistant","timestamp":"2026-09-02T05:06:52.813Z","sessionId":"s",` +
		`"cwd":"/w","message":{"id":"msg_2","model":"m","usage":{"input_tokens":1,"output_tokens":10}}}`
	call := decodeOne(t, line)
	if call.Usage.ReasoningReported {
		t.Error("reasoning reported for a record that carried no breakdown; " +
			"omitted and zero are different facts")
	}
}

func TestDecodeSkipsLinesItDoesNotObserve(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line string
	}{
		{name: "blank", line: "   "},
		{name: "not an object", line: "[1,2,3]"},
		{name: "user turn", line: `{"type":"user","message":{"role":"user"}}`},
		{name: "assistant without usage", line: `{"type":"assistant","message":{"id":"x","model":"m"}}`},
		{name: "session metadata", line: `{"type":"mode","sessionId":"s"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record, ok, err := New().Decode([]byte(test.line))
			if ok || err != nil {
				t.Fatalf("Decode(%s) = %+v ok %v err %v; want a silent skip", test.name, record, ok, err)
			}
		})
	}
}

func TestDecodeReportsMalformedRecordsRatherThanSwallowingThem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line string
	}{
		{name: "truncated json", line: `{"type":"assistant","message":{"id":"msg_3","usage":{"input_`},
		{
			name: "no message id",
			line: `{"type":"assistant","timestamp":"2026-09-02T05:06:52.813Z",` +
				`"message":{"model":"m","usage":{"input_tokens":1}}}`,
		},
		{
			name: "unreadable timestamp",
			line: `{"type":"assistant","timestamp":"yesterday",` +
				`"message":{"id":"msg_4","model":"m","usage":{"input_tokens":1}}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, ok, err := New().Decode([]byte(test.line))
			if ok {
				t.Fatal("a malformed record decoded as an observation")
			}
			if !errors.Is(err, ErrMalformedRecord) {
				t.Fatalf("error = %v, want it to classify as malformed so a counter can see it", err)
			}
		})
	}
}

func TestRawUsageStaysInsideThePlanesBound(t *testing.T) {
	t.Parallel()
	// The projection is a fixed set of integers, so the audit trail is bounded
	// by construction rather than by truncation. This asserts the construction
	// argument rather than trusting it: a field added to transcriptUsage that
	// carried unbounded text would fail here before it reached the store.
	raw := decodeOne(t, assistantLine).RawUsage
	if len(raw) > maxRawUsageBytes {
		t.Fatalf("raw usage is %d bytes, over the plane's %d-byte bound", len(raw), maxRawUsageBytes)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("raw usage is not readable JSON: %v", err)
	}
	if decoded["cache_read_input_tokens"] != float64(26354) {
		t.Errorf("raw usage lost the numbers the mapping read: %v", decoded)
	}
}

type fakeEntry struct {
	name string
	dir  bool
}

func (entry fakeEntry) Name() string { return entry.name }
func (entry fakeEntry) IsDir() bool  { return entry.dir }
func (entry fakeEntry) Type() os.FileMode {
	if entry.dir {
		return os.ModeDir
	}
	return 0
}
func (entry fakeEntry) Info() (os.FileInfo, error) { return nil, errors.New("not needed") }

func TestLedgerMatchesOnlyTranscripts(t *testing.T) {
	t.Parallel()
	adapter := New()
	tests := []struct {
		name string
		want bool
	}{
		{name: "3231c9b2.jsonl", want: true},
		{name: "notes.md", want: false},
		{name: ".hidden.jsonl", want: false},
		{name: "transcript.json", want: false},
	}
	for _, test := range tests {
		if got := adapter.Ledger(filepath.Join("/root", test.name), fakeEntry{name: test.name}); got != test.want {
			t.Errorf("Ledger(%q) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestDefaultRootHonoursTheHarnessOwnConfigDirectory(t *testing.T) {
	// Not parallel: it sets an environment variable, which is process-wide.
	t.Setenv("CLAUDE_CONFIG_DIR", "/tmp/elsewhere")
	root, err := DefaultRoot()
	if err != nil {
		t.Fatalf("DefaultRoot() error = %v", err)
	}
	if root != filepath.Join("/tmp/elsewhere", "projects") {
		t.Errorf("root = %q, want the configured directory's projects tree", root)
	}

	t.Setenv("CLAUDE_CONFIG_DIR", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory on this machine")
	}
	root, err = DefaultRoot()
	if err != nil {
		t.Fatalf("DefaultRoot() error = %v", err)
	}
	if root != filepath.Join(home, ".claude", "projects") {
		t.Errorf("root = %q, want the default tree under the home directory", root)
	}
}

func TestHarnessMatchesThePushAdapter(t *testing.T) {
	t.Parallel()
	// The ownership partition is keyed on this value. If the collector and the
	// push adapter ever disagree about the harness name, the sink stops
	// superseding and both are counted.
	if New().Harness() != domain.HarnessClaudeCode {
		t.Fatalf("harness = %q, want %q", New().Harness(), domain.HarnessClaudeCode)
	}
}

func TestSyntheticTurnsAreNotModelCalls(t *testing.T) {
	t.Parallel()
	// Taken from a live tree: the harness writes its own assistant turns --
	// interrupts and error placeholders -- with an all-zero usage object and a
	// plain UUID for an id. They are not calls, and counting them puts a model
	// named "<synthetic>" at the top of a rollup ranked by observations.
	line := `{"type":"assistant","timestamp":"2026-09-02T05:06:52.813Z","sessionId":"s","cwd":"/w",` +
		`"message":{"id":"8737e7c0-5d70-4b01-8111-0660a407b82b","model":"<synthetic>",` +
		`"usage":{"input_tokens":0,"output_tokens":0,"cache_creation_input_tokens":0,` +
		`"cache_read_input_tokens":0,"output_tokens_details":null}}}`
	record, ok, err := New().Decode([]byte(line))
	if ok || err != nil {
		t.Fatalf("Decode(synthetic) = %+v ok %v err %v; want a silent skip", record, ok, err)
	}

	// A record with no model at all is the same story: there is nothing to
	// attribute the spend to, and "" would become its own rollup group.
	line = `{"type":"assistant","timestamp":"2026-09-02T05:06:52.813Z","sessionId":"s","cwd":"/w",` +
		`"message":{"id":"msg_9","usage":{"input_tokens":1,"output_tokens":1}}}`
	if _, ok, err := New().Decode([]byte(line)); ok || err != nil {
		t.Fatalf("Decode(no model) = ok %v err %v; want a silent skip", ok, err)
	}
}
