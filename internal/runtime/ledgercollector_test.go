package runtime

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/integration/ledger/claudecode"
	"github.com/phall1/blackbird/internal/integration/ledger/codex"
)

type countingIngest struct {
	mutex sync.Mutex
	calls []domain.ModelCall
}

func (ingest *countingIngest) Offer(envelope telemetry.Envelope) bool {
	ingest.mutex.Lock()
	defer ingest.mutex.Unlock()
	ingest.calls = append(ingest.calls, envelope.ModelCalls...)
	return true
}

func (ingest *countingIngest) count() int {
	ingest.mutex.Lock()
	defer ingest.mutex.Unlock()
	return len(ingest.calls)
}

const runtimeTranscriptLine = `{"type":"assistant","timestamp":"2026-09-02T05:06:52.813Z",` +
	`"sessionId":"3231c9b2-e112-47ee-b9bd-40a47a403b27","cwd":"/Users/phall/workspace/blackbird",` +
	`"message":{"id":"msg_runtime_1","model":"claude-opus-5","usage":{"input_tokens":2,` +
	`"cache_creation_input_tokens":23947,"cache_read_input_tokens":26354,"output_tokens":1469}}}`

// transcriptTree builds the tree shape the harness actually writes: one
// directory per project, one .jsonl per session, and sibling directories the
// adapter must leave alone.
func transcriptTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	project := filepath.Join(root, "-Users-phall-workspace-blackbird")
	if err := os.MkdirAll(filepath.Join(project, "memory"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	transcript := filepath.Join(project, "3231c9b2-e112-47ee-b9bd-40a47a403b27.jsonl")
	body := `{"type":"mode","sessionId":"s"}` + "\n" +
		runtimeTranscriptLine + "\n" +
		// The same API message written again: Claude Code emits one record per
		// content block, so this is the common case rather than an edge one.
		runtimeTranscriptLine + "\n" +
		"{ this line is broken\n"
	if err := os.WriteFile(transcript, []byte(body), 0o600); err != nil {
		t.Fatalf("write transcript: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "memory", "notes.md"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write notes: %v", err)
	}
	return root
}

func newTestCollectorWorker(t *testing.T, root string, ingest telemetry.Ingest) *ledgerCollectorWorker {
	t.Helper()
	worker, err := newLedgerCollectorWorker(
		[]ledgerCollectorSpec{{adapter: claudecode.New(), root: root}},
		ingest, t.TempDir(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newLedgerCollectorWorker() error = %v", err)
	}
	if worker == nil {
		t.Fatal("newLedgerCollectorWorker() returned no worker")
	}
	return worker
}

func TestTheCollectorReadsARealTranscriptTreeOnce(t *testing.T) {
	t.Parallel()
	ingest := &countingIngest{}
	worker := newTestCollectorWorker(t, transcriptTree(t), ingest)
	worker.collectOnce(context.Background())

	if got := ingest.count(); got != 1 {
		t.Fatalf("collected %d calls, want one: the transcript holds one API message written twice", got)
	}
	call := ingest.calls[0]
	if call.Usage.CacheRead != 26354 || call.Usage.UncachedInput != 2 {
		t.Errorf("usage = %+v, want the disjoint classes preserved through composition", call.Usage)
	}
	if call.DurationKnown {
		t.Error("composition invented a latency a transcript cannot measure")
	}

	// A second pass over an unchanged tree finds nothing and opens nothing.
	worker.collectOnce(context.Background())
	if got := ingest.count(); got != 1 {
		t.Fatalf("a second pass re-delivered records: %d", got)
	}
}

func TestTheCollectorWorkerStartsAndStopsWithoutTheDaemonWaitingOnIt(t *testing.T) {
	t.Parallel()
	ingest := &countingIngest{}
	worker := newTestCollectorWorker(t, transcriptTree(t), ingest)
	worker.delay = time.Millisecond
	worker.interval = time.Millisecond

	if err := worker.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := worker.Start(context.Background()); err == nil {
		t.Error("Start() twice was accepted")
	}
	deadline := time.Now().Add(2 * time.Second)
	for ingest.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ingest.count() == 0 {
		t.Fatal("the poller never ran a pass")
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := worker.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	// Stopping an unstarted worker is a no-op, because runtime stops what it
	// composed whether or not startup got that far.
	if err := (&ledgerCollectorWorker{}).Stop(context.Background()); err != nil {
		t.Errorf("Stop() on an unstarted worker = %v", err)
	}
}

func TestAMachineWithNoTranscriptTreeIsNotAFailure(t *testing.T) {
	t.Parallel()
	ingest := &countingIngest{}
	worker := newTestCollectorWorker(t, filepath.Join(t.TempDir(), "absent"), ingest)
	if err := worker.Start(context.Background()); err != nil {
		t.Fatalf("Start() on a machine without the harness = %v", err)
	}
	worker.collectOnce(context.Background())
	if ingest.count() != 0 {
		t.Error("an absent tree produced observations")
	}
	if err := worker.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() = %v", err)
	}
}

func TestAHarnessIsClaimedOnlyWhenItsLedgerIsActuallyThere(t *testing.T) {
	t.Parallel()
	// Superseding a push is a claim -- "do not store this, I have it from the
	// ledger" -- and a daemon that cannot see the ledger cannot back it.
	//
	// This inverts a rule that read the other way, and the inversion is the
	// fix. The daemon is a per-user service and does not inherit the login
	// shell, so a CLAUDE_CONFIG_DIR or CODEX_HOME exported in a profile is
	// absent here and the resolved root points at nothing. Claiming the harness
	// then dropped every pushed observation while collecting none -- and both
	// halves are silent, because an absent probe is a PASSING state by design
	// and the plane counts write failures rather than returning them. Spend
	// read zero forever with no error anywhere.
	absent := filepath.Join(t.TempDir(), "never-ran")
	present := t.TempDir()
	specs := []ledgerCollectorSpec{
		{adapter: claudecode.New(), rootErr: os.ErrNotExist},
		{adapter: claudecode.New(), root: absent},
		{adapter: codex.New(), root: present},
	}
	set := collectedSpecHarnesses(specs)
	if set.Collects(domain.HarnessClaudeCode) {
		t.Error("a harness with no readable ledger claimed the pushes it cannot replace")
	}
	if !set.Collects(domain.HarnessCodex) {
		t.Error("a harness whose ledger is right there did not claim it")
	}
	// Composition still succeeds either way: an absent tree is a fact about the
	// machine, not a failure, and the collector exists so the harness starts
	// being collected as soon as the tree does appear.
	worker, err := newLedgerCollectorWorker(specs, &countingIngest{}, "", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newLedgerCollectorWorker() = %v", err)
	}
	if worker == nil {
		t.Fatal("no worker composed for an unlocatable ledger")
	}
	worker.collectOnce(context.Background())
}

func TestNoIngestMeansNoCollectorGoroutine(t *testing.T) {
	t.Parallel()
	worker, err := newLedgerCollectorWorker(productionLedgerCollectors(), nil, "",
		slog.New(slog.DiscardHandler))
	if err != nil || worker != nil {
		t.Fatalf("worker = %v, err = %v; a daemon without an observation plane grows no poller", worker, err)
	}
	worker, err = newLedgerCollectorWorker(nil, &countingIngest{}, "", slog.New(slog.DiscardHandler))
	if err != nil || worker != nil {
		t.Fatalf("worker = %v, err = %v; no specs means no poller", worker, err)
	}
}

func TestProductionComposesTheCollectedHarnesses(t *testing.T) {
	t.Parallel()
	specs := productionLedgerCollectors()
	composed := make(map[domain.Harness]int, len(specs))
	for _, spec := range specs {
		composed[spec.adapter.Harness()]++
	}
	for _, harness := range []domain.Harness{domain.HarnessClaudeCode, domain.HarnessCodex} {
		if composed[harness] != 1 {
			t.Fatalf("specs = %+v, want exactly one %s collector", specs, harness)
		}
	}
	if len(specs) != len(composed) {
		// Two collectors for one harness would share a cursor file, and each
		// pass would overwrite the other's watermarks.
		t.Fatalf("specs = %+v, want one collector per harness", specs)
	}
	set := collectedSpecHarnesses(specs)
	for harness := range composed {
		if !set.Collects(harness) {
			t.Errorf("%s is composed but not claimed, so its pushes would not be superseded", harness)
		}
	}
	if set.Collects(domain.HarnessOpenCode) || set.Collects(domain.HarnessPi) {
		t.Error("a harness with no collector was claimed; its plugin's pushes would be dropped for nothing")
	}
}

func TestAPassIsBoundedInTime(t *testing.T) {
	t.Parallel()
	ingest := &countingIngest{}
	worker := newTestCollectorWorker(t, transcriptTree(t), ingest)
	worker.timeout = time.Nanosecond
	// The pass gives up rather than running to completion, and says nothing
	// about it: a bounded pass resumes from its watermark next interval.
	worker.collectOnce(context.Background())
}
