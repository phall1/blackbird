package ledger

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

// recordingIngest stands in for the sink. It captures whole envelopes so a
// test can assert attribution and source as well as counts, and it can refuse,
// which is the branch that decides whether a full queue loses observations.
type recordingIngest struct {
	mutex     sync.Mutex
	envelopes []telemetry.Envelope
	refuseAt  int
}

func (ingest *recordingIngest) Offer(envelope telemetry.Envelope) bool {
	ingest.mutex.Lock()
	defer ingest.mutex.Unlock()
	if ingest.refuseAt > 0 && len(ingest.envelopes) >= ingest.refuseAt {
		return false
	}
	ingest.envelopes = append(ingest.envelopes, envelope)
	return true
}

func (ingest *recordingIngest) calls() []domain.ModelCall {
	ingest.mutex.Lock()
	defer ingest.mutex.Unlock()
	collected := make([]domain.ModelCall, 0, 16)
	for _, envelope := range ingest.envelopes {
		collected = append(collected, envelope.ModelCalls...)
	}
	return collected
}

func (ingest *recordingIngest) keys() []string {
	keys := make([]string, 0, 16)
	for _, call := range ingest.calls() {
		keys = append(keys, call.DedupeKey)
	}
	return keys
}

// testAdapter reads a deliberately trivial line format -- "key project
// tokens" -- so these tests assert the framework rather than a harness's
// transcript schema. The Claude Code mapping has its own tests.
type testAdapter struct {
	harness domain.Harness
	suffix  string
}

func (adapter testAdapter) Harness() domain.Harness {
	if adapter.harness == "" {
		return domain.HarnessClaudeCode
	}
	return adapter.harness
}

func (adapter testAdapter) Ledger(_ string, entry fs.DirEntry) bool {
	suffix := adapter.suffix
	if suffix == "" {
		suffix = ".log"
	}
	return strings.HasSuffix(entry.Name(), suffix)
}

func (testAdapter) Decode(line []byte) (Record, bool, error) {
	text := strings.TrimSpace(string(line))
	if text == "" || strings.HasPrefix(text, "#") {
		return Record{}, false, nil
	}
	fields := strings.Fields(text)
	if len(fields) != 3 {
		return Record{}, false, fmt.Errorf("want three fields, got %d", len(fields))
	}
	var tokens uint64
	if _, err := fmt.Sscanf(fields[2], "%d", &tokens); err != nil {
		return Record{}, false, err
	}
	project := fields[1]
	if project == "-" {
		// The sentinel for a line that named no workspace.
		project = ""
	}
	return Record{
		ProjectKey: project,
		Call: domain.ModelCall{
			DedupeKey: fields[0],
			Harness:   domain.HarnessClaudeCode,
			Provider:  "anthropic",
			Model:     "test-model",
			Operation: domain.ModelOperationChat,
			// The token count lands in BOTH classes so one field can drive both
			// kinds of assertion. Output is the class the framework's
			// high-water mark reads, because output is the only class that
			// differs between a ledger's successive records of one call.
			Usage:     domain.TokenUsage{UncachedInput: tokens, Output: tokens},
			Outcome:   domain.ObservedOutcomeOK,
			StartedAt: time.Date(2026, time.September, 2, 5, 0, 0, 0, time.UTC),
		},
	}, true, nil
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
}

func newTestCollector(t *testing.T, root string, ingest telemetry.Ingest, adjust func(*Config)) *Collector {
	t.Helper()
	config := Config{
		Adapter:   testAdapter{},
		Root:      root,
		StatePath: filepath.Join(t.TempDir(), "cursors.json"),
		Ingest:    ingest,
	}
	if adjust != nil {
		adjust(&config)
	}
	collector, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return collector
}

func TestNewRejectsAnIncompleteComposition(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{Ingest: &recordingIngest{}}); err == nil {
		t.Error("a collector without an adapter composed")
	}
	if _, err := New(Config{Adapter: testAdapter{}}); err == nil {
		t.Error("a collector without an ingest port composed")
	}
	if _, err := New(Config{Adapter: testAdapter{harness: "gpt-cli"}, Ingest: &recordingIngest{}}); err == nil {
		t.Error("a collector claiming a harness the plane does not know composed")
	}
}

func TestAMachineWithoutTheHarnessIsNormal(t *testing.T) {
	t.Parallel()
	// The Homebrew updater's rule, applied here: absence is a passing state, so
	// a daemon on a workstation that has never run the harness reports a probe
	// and does no work rather than raising something an operator cannot fix.
	ingest := &recordingIngest{}
	for _, root := range []string{"", filepath.Join(t.TempDir(), "never-installed")} {
		collector := newTestCollector(t, root, ingest, nil)
		probe := collector.Probe()
		if probe.Present {
			t.Fatalf("probe reports a tree present at %q", root)
		}
		if probe.Reason == "" {
			t.Error("probe gives no reason an operator could read")
		}
		pass, err := collector.Collect(context.Background())
		if err != nil {
			t.Fatalf("Collect() on an absent tree = %v; absence is not a failure", err)
		}
		if pass.FilesSeen != 0 || pass.Offered != 0 {
			t.Errorf("pass over an absent tree did work: %+v", pass)
		}
	}
	if len(ingest.envelopes) != 0 {
		t.Error("an absent tree produced observations")
	}
}

func TestProbeRejectsAFileWhereADirectoryBelongs(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "not-a-directory")
	writeFile(t, path, "")
	collector := newTestCollector(t, path, &recordingIngest{}, nil)
	if probe := collector.Probe(); probe.Present || probe.Reason == "" {
		t.Fatalf("probe = %+v, want an explained absence", probe)
	}
}

func TestCollectWalksRecursivelyAndAttributesByProjectKey(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "alpha", "one.log"), "a /proj/alpha 10\nb /proj/alpha 20\n")
	writeFile(t, filepath.Join(root, "beta", "nested", "two.log"), "c /proj/beta 30\n")
	writeFile(t, filepath.Join(root, "beta", "notes.txt"), "d /proj/beta 40\n")
	writeFile(t, filepath.Join(root, ".hidden", "three.log"), "e /proj/hidden 50\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if pass.FilesSeen != 2 || pass.FilesRead != 2 {
		t.Errorf("files seen %d read %d, want 2 and 2 -- a hidden directory and a non-ledger file are skipped",
			pass.FilesSeen, pass.FilesRead)
	}
	if got := ingest.keys(); len(got) != 3 {
		t.Fatalf("keys = %v, want three observations", got)
	}
	projects := map[string]int{}
	for _, envelope := range ingest.envelopes {
		if envelope.Source != telemetry.SourceCollected {
			t.Errorf("envelope source = %v, want collected -- the sink's partition depends on it", envelope.Source)
		}
		projects[envelope.Attribution.ProjectKey] += len(envelope.ModelCalls)
		if envelope.Attribution.ActorID.IsZero() {
			t.Error("collected envelope carries no actor")
		}
	}
	if projects["/proj/alpha"] != 2 || projects["/proj/beta"] != 1 {
		t.Errorf("attribution = %v, want the ledger's own project keys", projects)
	}
}

func TestSteadyStateReadsOnlyNewBytes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "session.log")
	writeFile(t, path, "a /proj 10\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	first, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect() = %v", err)
	}
	if first.BytesRead == 0 || first.Offered != 1 {
		t.Fatalf("first pass = %+v", first)
	}

	// An unchanged file is not even opened. This is the property that makes a
	// one-minute poll cost nothing on a machine with years of transcripts.
	second, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() = %v", err)
	}
	if second.FilesRead != 0 || second.BytesRead != 0 || second.Offered != 0 {
		t.Fatalf("an unchanged file was re-read: %+v", second)
	}

	appendFile(t, path, "b /proj 20\n")
	third, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("third Collect() = %v", err)
	}
	if third.FilesRead != 1 || third.Offered != 1 {
		t.Fatalf("growth pass = %+v, want exactly the appended record", third)
	}
	if got := ingest.keys(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("keys = %v, want each record delivered exactly once", got)
	}
}

func TestAPartialFinalLineIsCarriedToTheNextPass(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "session.log")
	// The harness is mid-write: the last record has no newline yet.
	writeFile(t, path, "a /proj 10\nb /proj 2")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if got := ingest.keys(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("keys = %v, want only the complete line; half a record is not an observation", got)
	}

	appendFile(t, path, "0\n")
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("second Collect() = %v", err)
	}
	calls := ingest.calls()
	if len(calls) != 2 || calls[1].DedupeKey != "b" {
		t.Fatalf("calls = %v, want the carried line read whole", ingest.keys())
	}
	if calls[1].Usage.UncachedInput != 20 {
		t.Errorf("carried record decoded as %d tokens, want 20 -- the carry read half a number",
			calls[1].Usage.UncachedInput)
	}
}

func TestATruncatedFileIsReadFromTheStartAgain(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "session.log")
	writeFile(t, path, "a /proj 10\nb /proj 20\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	// The harness replaced the file. Reading from the old offset would decode
	// the middle of a line; restarting costs writes the dedupe key collapses.
	writeFile(t, path, "c /proj 30\n")
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() = %v", err)
	}
	if pass.Restarted != 1 {
		t.Errorf("restarted = %d, want the shrink recognized", pass.Restarted)
	}
	if got := ingest.keys(); len(got) != 3 || got[2] != "c" {
		t.Fatalf("keys = %v, want the replacement read from the start", got)
	}
}

func TestDuplicateRecordsCollapseWithinAPass(t *testing.T) {
	t.Parallel()
	// Claude Code writes one transcript record per content block of a single
	// API message, so a real transcript holds roughly twice as many usage
	// records as calls. Summing records rather than calls overstates spend by
	// nearly 100%, which is why this is a correctness test and not an
	// efficiency one.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"),
		"a /proj 10\na /proj 10\na /proj 10\nb /proj 20\nb /proj 20\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.Duplicates != 3 || pass.Observed != 2 || pass.Restatements != 0 {
		t.Fatalf("pass = %+v, want three duplicates collapsed into two observations", pass)
	}
	if got := ingest.keys(); len(got) != 2 {
		t.Fatalf("keys = %v, want one row per call", got)
	}
}

func TestARepeatedKeyReportingMoreOutputIsOfferedAgain(t *testing.T) {
	t.Parallel()
	// The regression this exists for, and the reason the test above is not
	// enough on its own: it writes repeats whose counts are IDENTICAL, so it
	// encodes the assumption that a repeated key is a copy. On the live Claude
	// Code tree that assumption is false. The harness writes one transcript
	// record per content block of a single API message, and those records are
	// successive snapshots of a response still being written -- one measured
	// message ran 3, 3, 3, 3, 3, 836, with the thinking count on the terminal
	// record alone. Collapsing to the first stored 2,317,338 output tokens
	// where the truth was 2,771,686: 16.4% of all output on the machine, gone,
	// permanently, with the observation COUNT still correct so nothing looked
	// missing.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"),
		"a /proj 3\na /proj 3\na /proj 836\na /proj 12\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	// Two repeats add nothing and are collapsed; the one that grows is a
	// restatement and must reach the store, whose monotone upsert keeps it.
	// A record that then reports LESS is a snapshot already superseded.
	if pass.Duplicates != 2 || pass.Restatements != 1 || pass.Offered != 2 {
		t.Fatalf("pass = %+v, want the growing record re-offered and the rest collapsed", pass)
	}
	calls := ingest.calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %+v, want the first snapshot and the finished record", calls)
	}
	if calls[0].Usage.Output != 3 || calls[1].Usage.Output != 836 {
		t.Fatalf("outputs = %d, %d; want the finished count delivered",
			calls[0].Usage.Output, calls[1].Usage.Output)
	}
}

func TestAMalformedLineIsCountedAndSkipped(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"),
		"a /proj 10\nthis is not a record at all\nb /proj notanumber\n# comment\nc /proj 30\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v; a malformed line must never fail a pass", err)
	}
	if pass.Malformed != 2 {
		t.Errorf("malformed = %d, want the two unreadable lines counted", pass.Malformed)
	}
	if got := ingest.keys(); len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("keys = %v, want the readable records on either side of the damage", got)
	}
}

func TestAnOversizeLineIsConsumedWithoutBufferingIt(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	huge := strings.Repeat("x", 4096)
	writeFile(t, filepath.Join(root, "session.log"), "a /proj 10\n"+huge+"\nb /proj 20\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, func(config *Config) {
		config.MaxLineBytes = 64
	})
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.Oversize != 1 {
		t.Errorf("oversize = %d, want the long line counted", pass.Oversize)
	}
	if got := ingest.keys(); len(got) != 2 || got[1] != "b" {
		t.Fatalf("keys = %v, want the reader to resume after the long line rather than lose its place", got)
	}
}

func TestARecordTheStoreWouldRejectIsCountedRatherThanOffered(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// An empty dedupe key fails the plane's own validation. Catching it here
	// keeps a mapping bug from becoming a write failure the sink can only
	// count in aggregate.
	writeFile(t, filepath.Join(root, "session.log"), " /proj 10\na /proj 20\n")
	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.Malformed != 1 || pass.Offered != 1 {
		t.Fatalf("pass = %+v, want the invalid record rejected and the valid one delivered", pass)
	}
}

func TestRecordsWithNoProjectKeyAreDroppedRatherThanMisattributed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"), "a - 10\n")
	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	// Counted as unattributed, NOT as dropped. The two are opposite conditions:
	// this record's watermark advances and no later pass will retry it, whereas
	// a sink refusal rewinds and is retried within the interval. Sharing one
	// counter would report a mapping bug as load and load as a mapping bug.
	if pass.Unattributed != 1 || pass.Dropped != 0 || pass.Offered != 0 {
		t.Fatalf("pass = %+v, want the unattributable record counted apart from backpressure", pass)
	}
}

func TestTheProjectKeyIsPinnedOncePerFile(t *testing.T) {
	t.Parallel()
	// A session's later records may name a subdirectory as the working
	// directory. Letting that repoint the attribution would scatter one
	// session's spend across several project keys in every rollup.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"), "a /proj 10\nb /proj/packages/thing 20\n")
	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	for _, envelope := range ingest.envelopes {
		if envelope.Attribution.ProjectKey != "/proj" {
			t.Fatalf("project key = %q, want the first one this file named", envelope.Attribution.ProjectKey)
		}
	}
}

func TestARefusedBatchRewindsTheWatermark(t *testing.T) {
	t.Parallel()
	// A full sink is normal under load. What must not happen is the watermark
	// advancing past records nothing accepted, because the next pass would then
	// never see them again.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"), "a /proj 10\n")
	ingest := &recordingIngest{refuseAt: 1}
	// refuseAt 1 lets nothing through: the very first Offer is refused.
	ingest.refuseAt = 1
	ingest.envelopes = make([]telemetry.Envelope, 1)
	collector := newTestCollector(t, root, ingest, nil)
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.LimitReached != "sink" || pass.Dropped != 1 {
		t.Fatalf("pass = %+v, want the refusal recorded", pass)
	}

	ingest.envelopes = nil
	ingest.refuseAt = 0
	retry, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("retry Collect() = %v", err)
	}
	if retry.Offered != 1 {
		t.Fatalf("retry = %+v, want the rewound record delivered", retry)
	}
}

func TestARecordLimitLeavesTheRestForTheNextPass(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	var builder strings.Builder
	for index := range 10 {
		fmt.Fprintf(&builder, "key%d /proj 1\n", index)
	}
	writeFile(t, filepath.Join(root, "session.log"), builder.String())

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, func(config *Config) {
		config.MaxRecordsPerPass = 4
	})
	first, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if first.Observed != 4 || first.LimitReached != "records" {
		t.Fatalf("first pass = %+v, want the bound reported", first)
	}
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("second Collect() = %v", err)
	}
	if got := len(ingest.keys()); got != 8 {
		t.Fatalf("delivered %d over two bounded passes, want the watermark to resume", got)
	}
}

func TestAByteLimitStopsAPassOverUnreadableBulk(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"), strings.Repeat("# comment\n", 200)+"a /proj 1\n")
	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, func(config *Config) {
		config.MaxBytesPerPass = 100
	})
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.LimitReached != "bytes" {
		t.Fatalf("pass = %+v, want the byte bound to stop a file of lines nobody observes", pass)
	}
}

func TestAFileBoundDefersFilesRatherThanStarvingThem(t *testing.T) {
	t.Parallel()
	// The per-pass file bound once stopped the WALK, which made it permanent
	// starvation rather than deferral: walk order is deterministic, so the same
	// lexically-first files were read on every pass and everything past them
	// was never read at all, forever, with no self-healing. Discovery now sees
	// the whole tree and the READ WINDOW rotates.
	root := t.TempDir()
	for index := range 5 {
		writeFile(t, filepath.Join(root, fmt.Sprintf("s%d.log", index)),
			fmt.Sprintf("k%d /proj 1\n", index))
	}
	statePath := filepath.Join(t.TempDir(), "cursors.json")
	ingest := &recordingIngest{}
	newBounded := func() *Collector {
		return newTestCollector(t, root, ingest, func(config *Config) {
			config.MaxFilesPerPass = 2
			config.StatePath = statePath
		})
	}
	pass, err := newBounded().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	// Discovery sees everything; only the read is bounded. That is what makes
	// pruning safe, and pruning against a partial view is what once deleted the
	// watermark of every file past the bound.
	if pass.FilesSeen != 5 || pass.FilesWindow != 2 || pass.LimitReached != "files" {
		t.Fatalf("pass = %+v, want the whole tree seen and the read window bounded", pass)
	}
	// Regression: the bound must not be reported before the read loop runs. It
	// once was, and the loop's own limit check then abandoned the pass, so a
	// tree over the bound walked every interval and collected nothing at all.
	if pass.Offered != 2 {
		t.Fatalf("offered = %d, want the files in the window to be read", pass.Offered)
	}
	if pass.CursorsPruned != 0 {
		t.Fatalf("pruned = %d cursors while every discovered file was still live", pass.CursorsPruned)
	}

	// The window rotates, and each collector is constructed afresh so the
	// rotation is proven to survive a restart through the cursor file rather
	// than through memory this process happens to still hold.
	for range 3 {
		if _, err := newBounded().Collect(context.Background()); err != nil {
			t.Fatalf("rotating Collect() = %v", err)
		}
	}
	if got := ingest.keys(); len(got) != 5 {
		t.Fatalf("delivered %v over four bounded passes, want every file reached", got)
	}
}

func TestTheDepthBoundIsCountedRatherThanSilent(t *testing.T) {
	t.Parallel()
	// The bound exists to make a symlink loop finite, but it also fires on a
	// legitimately deep layout -- Claude Code's live tree already reaches
	// <project>/<session>/subagents/workflows/<workflow>/<agent>.jsonl. A bound
	// that drops files with nothing in any counter to say so is an unexplained
	// gap in the numbers, which is the one thing a spend report must not have.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "shallow.log"), "a /proj 1\n")
	writeFile(t, filepath.Join(root, "one", "two", "deep.log"), "b /proj 2\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, func(config *Config) {
		config.MaxWalkDepth = 2
	})
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.DepthSkipped != 1 {
		t.Errorf("depth_skipped = %d, want the refused directory counted", pass.DepthSkipped)
	}
	if got := ingest.keys(); len(got) != 1 || got[0] != "a" {
		t.Errorf("keys = %v, want only the file within the depth bound", got)
	}
}

func TestDiscoveryOverflowSuppressesPruning(t *testing.T) {
	t.Parallel()
	// The memory guard on discovery is the ONE condition under which the set in
	// hand is a partial view of the tree. Pruning against it would throw away
	// the watermark of every file the walk never reached, turning a bound into
	// a full re-read.
	root := t.TempDir()
	for index := range 5 {
		writeFile(t, filepath.Join(root, fmt.Sprintf("s%d.log", index)),
			fmt.Sprintf("k%d /proj 1\n", index))
	}
	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, func(config *Config) {
		// The guard is clamped to at least the read window, so both move
		// together: a tracking ceiling below the window would make part of the
		// window unreachable and reintroduce the starvation rotation prevents.
		config.MaxFilesTracked = 2
		config.MaxFilesPerPass = 2
	})
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.FilesSeen != 2 {
		t.Fatalf("pass = %+v, want discovery truncated at the memory guard", pass)
	}
	if pass.CursorsPruned != 0 {
		t.Fatalf("pruned = %d cursors from a partial view of the tree", pass.CursorsPruned)
	}
}

func TestWalkDepthIsBounded(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a", "b", "c", "deep.log"), "k /proj 1\n")
	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, func(config *Config) {
		config.MaxWalkDepth = 2
	})
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.FilesSeen != 0 {
		t.Fatalf("files seen = %d, want the depth bound to stop the descent", pass.FilesSeen)
	}
}

func TestACancelledContextStopsAPassWithoutFailingIt(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"), "a /proj 10\n")
	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pass, err := collector.Collect(ctx)
	if err == nil && pass.Offered != 0 {
		t.Fatalf("a cancelled pass produced observations: %+v", pass)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want the cancellation", err)
	}
}

func TestCursorsSurviveARestart(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	statePath := filepath.Join(t.TempDir(), "nested", "cursors.json")
	writeFile(t, filepath.Join(root, "session.log"), "a /proj 10\n")

	ingest := &recordingIngest{}
	first := newTestCollector(t, root, ingest, func(config *Config) { config.StatePath = statePath })
	pass, err := first.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.CursorSaveFail {
		t.Fatal("the cursor file could not be written")
	}

	// A new process, the same state file: the record already delivered is not
	// read again, and the project key it pinned is remembered.
	second := newTestCollector(t, root, ingest, func(config *Config) { config.StatePath = statePath })
	resumed, err := second.Collect(context.Background())
	if err != nil {
		t.Fatalf("resumed Collect() = %v", err)
	}
	if resumed.FilesRead != 0 || resumed.Offered != 0 {
		t.Fatalf("a restart re-read delivered bytes: %+v", resumed)
	}
}

func TestACorruptCursorFileIsIgnoredRatherThanFatal(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	statePath := filepath.Join(t.TempDir(), "cursors.json")
	writeFile(t, statePath, "{not json")
	writeFile(t, filepath.Join(root, "session.log"), "a /proj 10\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, func(config *Config) { config.StatePath = statePath })
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.Offered != 1 {
		t.Fatalf("pass = %+v; an unreadable watermark must cost a re-read, not the collection", pass)
	}
}

func TestCursorsForVanishedFilesArePruned(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	statePath := filepath.Join(t.TempDir(), "cursors.json")
	path := filepath.Join(root, "session.log")
	writeFile(t, path, "a /proj 10\n")

	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, func(config *Config) { config.StatePath = statePath })
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() = %v", err)
	}
	if pass.CursorsPruned != 1 {
		t.Fatalf("pruned = %d, want the cursor for a vanished file dropped", pass.CursorsPruned)
	}
	if len(collector.cursors) != 0 {
		t.Fatalf("cursors = %v, want the state file bounded by the tree", collector.cursors)
	}
}

func TestInMemoryCursorsAreAllowed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"), "a /proj 10\n")
	ingest := &recordingIngest{}
	collector := newTestCollector(t, root, ingest, func(config *Config) { config.StatePath = "" })
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	second, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() = %v", err)
	}
	if second.FilesRead != 0 {
		t.Fatalf("in-memory cursors did not hold within a process: %+v", second)
	}
}

func TestHarnessIsReportedForTheOwnershipPartition(t *testing.T) {
	t.Parallel()
	collector := newTestCollector(t, t.TempDir(), &recordingIngest{}, nil)
	if collector.Harness() != domain.HarnessClaudeCode {
		t.Fatalf("harness = %q", collector.Harness())
	}
}

func TestAPassReportsItsOwnDuration(t *testing.T) {
	t.Parallel()
	// Regression: with unnamed results the deferred duration wrote to a local
	// the return had already copied, so every pass reported zero. A live run
	// over 100 MB of transcripts logged "dur=0s", which reads as a collector
	// that did nothing.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "session.log"), "a /proj 10\n")
	tick := time.Date(2026, time.September, 2, 5, 0, 0, 0, time.UTC)
	collector := newTestCollector(t, root, &recordingIngest{}, func(config *Config) {
		config.Now = func() time.Time {
			tick = tick.Add(time.Millisecond)
			return tick
		}
	})
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() = %v", err)
	}
	if pass.Duration <= 0 {
		t.Fatalf("duration = %s, want the elapsed time of the pass", pass.Duration)
	}
	if pass.StartedAt.IsZero() {
		t.Error("pass reports no start time")
	}
}

// contextualAdapter reads a format whose observation lines are deliberately not
// self-describing, so these tests assert the framework's carry rather than any
// harness's schema. Three line shapes:
//
//	"project <key>"  attribution only, no observation
//	"model <name>"   context only, no observation
//	"<key> <tokens>" an observation, which needs the carried model
type contextualAdapter struct {
	oversize bool
}

func (contextualAdapter) Harness() domain.Harness { return domain.HarnessCodex }

func (contextualAdapter) Ledger(_ string, entry fs.DirEntry) bool {
	return strings.HasSuffix(entry.Name(), ".log")
}

func (adapter contextualAdapter) Decode(line []byte) (Record, bool, error) {
	return adapter.DecodeInContext(line, "")
}

func (adapter contextualAdapter) DecodeInContext(line []byte, fileContext string) (Record, bool, error) {
	fields := strings.Fields(strings.TrimSpace(string(line)))
	if len(fields) != 2 {
		return Record{}, false, nil
	}
	switch fields[0] {
	case "project":
		return Record{ProjectKey: fields[1]}, false, nil
	case "model":
		name := fields[1]
		if adapter.oversize {
			name = strings.Repeat(name, MaxFileContextBytes)
		}
		return Record{Context: name}, false, nil
	}
	if fileContext == "" {
		return Record{}, false, errors.New("observation before its header")
	}
	var tokens uint64
	if _, err := fmt.Sscanf(fields[1], "%d", &tokens); err != nil {
		return Record{}, false, err
	}
	return Record{Call: domain.ModelCall{
		DedupeKey: fields[0],
		Harness:   domain.HarnessCodex,
		Provider:  "openai",
		Model:     fileContext,
		Operation: domain.ModelOperationChat,
		Usage:     domain.TokenUsage{UncachedInput: tokens},
		Outcome:   domain.ObservedOutcomeOK,
		StartedAt: time.Date(2026, time.September, 2, 5, 0, 0, 0, time.UTC),
	}}, true, nil
}

// TestContextualAdapterCarriesHeaderFactsForward covers the framework change the
// second adapter needed: a line may establish attribution and per-file context
// without being an observation itself, and the last model named wins.
func TestContextualAdapterCarriesHeaderFactsForward(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "one.log"), strings.Join([]string{
		"project /w", "model gpt-5.5", "a 10", "model gpt-5.4-mini", "b 20",
	}, "\n")+"\n")
	ingest := &recordingIngest{}
	collector, err := New(Config{Adapter: contextualAdapter{}, Root: root, Ingest: ingest})
	if err != nil {
		t.Fatal(err)
	}
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pass.Offered != 2 || pass.Malformed != 0 {
		t.Fatalf("pass=%+v", pass)
	}
	calls := ingest.calls()
	if calls[0].Model != "gpt-5.5" || calls[1].Model != "gpt-5.4-mini" {
		t.Fatalf("models=%q,%q; the carry is last-writer-wins", calls[0].Model, calls[1].Model)
	}
	if ingest.envelopes[0].Attribution.ProjectKey != "/w" {
		t.Fatalf("attribution=%+v; a non-observation line must be able to name the workspace",
			ingest.envelopes[0].Attribution)
	}
}

// TestContextSurvivesARestartBesideItsWatermark is the property that makes the
// carry safe to resume on. The context lives in the cursor entry with the byte
// offset, so a fresh collector that resumes past the header still holds it --
// and a cursor file that is lost takes the offset with it, sending the file
// back to the header it needs.
func TestContextSurvivesARestartBesideItsWatermark(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	statePath := filepath.Join(t.TempDir(), "cursors.json")
	path := filepath.Join(root, "one.log")
	writeFile(t, path, "project /w\nmodel gpt-5.5\na 10\n")
	collect := func(ingest *recordingIngest) Pass {
		t.Helper()
		collector, err := New(Config{
			Adapter: contextualAdapter{}, Root: root, StatePath: statePath, Ingest: ingest,
		})
		if err != nil {
			t.Fatal(err)
		}
		pass, err := collector.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return pass
	}
	if pass := collect(&recordingIngest{}); pass.Offered != 1 {
		t.Fatalf("first pass=%+v", pass)
	}
	writeFile(t, path, "project /w\nmodel gpt-5.5\na 10\nb 20\n")
	resumed := &recordingIngest{}
	pass := collect(resumed)
	if pass.Malformed != 0 || pass.Offered != 1 {
		t.Fatalf("resumed pass=%+v; the header was already consumed and must come from the cursor", pass)
	}
	calls := resumed.calls()
	if len(calls) != 1 || calls[0].Model != "gpt-5.5" {
		t.Fatalf("resumed calls=%+v", calls)
	}
	stored, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stored), `"context":"gpt-5.5"`) {
		t.Fatalf("cursor file does not carry the context: %s", stored)
	}
}

// TestReplacedFileKeepsItsContext covers the rotation branch. Re-reading from
// zero re-establishes the header anyway, so keeping the carry costs nothing and
// dropping it would strand every record before the new header line.
func TestReplacedFileKeepsItsContext(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "one.log")
	writeFile(t, path, "project /w\nmodel gpt-5.5\na 10\nb 20\nc 30\n")
	ingest := &recordingIngest{}
	collector, err := New(Config{Adapter: contextualAdapter{}, Root: root, Ingest: ingest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "d 40\n")
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pass.Restarted != 1 || pass.Malformed != 0 || pass.Offered != 1 {
		t.Fatalf("pass=%+v", pass)
	}
}

// TestOversizeContextIsIgnoredRatherThanTruncated keeps a ledger from deciding
// how large the cursor file grows, and keeps a half-written context from being
// read back as though it were whole.
func TestOversizeContextIsIgnoredRatherThanTruncated(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "one.log"), "project /w\nmodel gpt-5.5\na 10\n")
	ingest := &recordingIngest{}
	collector, err := New(Config{
		Adapter: contextualAdapter{oversize: true}, Root: root, Ingest: ingest,
	})
	if err != nil {
		t.Fatal(err)
	}
	pass, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pass.Offered != 0 || pass.Malformed != 1 {
		t.Fatalf("pass=%+v, want the oversize context refused and the record reported", pass)
	}
}
