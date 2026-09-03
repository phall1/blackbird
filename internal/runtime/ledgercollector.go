package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/integration/ledger"
	"github.com/phall1/blackbird/internal/integration/ledger/claudecode"
	"github.com/phall1/blackbird/internal/integration/ledger/codex"
)

const (
	// ledgerCollectInterval is how often a ledger tree is re-walked. It is
	// slow on purpose. A pass over an unchanged tree is a stat per file and no
	// open at all, but spend is a rollup nobody watches by the second, and the
	// only thing a faster poll buys is a shorter gap between a turn finishing
	// and its tokens being queryable.
	ledgerCollectInterval = time.Minute
	// ledgerCollectDelay lets the daemon finish coming up before the first
	// pass. The first pass is the expensive one -- it reads whatever history is
	// on disk -- and startup is the one moment coordination latency is visible.
	ledgerCollectDelay = 15 * time.Second
	// ledgerCollectTimeout bounds one pass. A pass that cannot finish inside it
	// stops where it is and resumes from its watermark next interval, which is
	// what keeps a machine with years of transcripts from holding a goroutine
	// and a file handle open indefinitely.
	ledgerCollectTimeout = 30 * time.Second
	// ledgerStateDirName is where cursors live under the daemon's state
	// directory. They are adapter bookkeeping and deliberately not database
	// rows: a poll must not take the SQLite write arbiter to record that
	// nothing changed.
	ledgerStateDirName = "telemetry-collectors"
)

// ledgerCollectorSpecs describes the collectors this daemon composes, before
// they have an ingest port to write to. The two-step exists because the sink
// must be constructed knowing which harnesses are collected, and the collectors
// must be constructed knowing the sink -- so the harness set is settled first
// and the wiring second.
type ledgerCollectorSpec struct {
	adapter ledger.Adapter
	root    string
	rootErr error
}

// productionLedgerCollectors resolves the ledger trees this machine may have.
// A locator that fails is not an error: it means this daemon cannot find that
// harness's ledger here, the collector is composed anyway with an empty root,
// and its probe reports absence as a passing state -- the vocabulary the
// Homebrew updater established, for the same reason. A daemon on a workstation
// that has never run the harness is a healthy daemon.
func productionLedgerCollectors() []ledgerCollectorSpec {
	claudeRoot, claudeErr := claudecode.DefaultRoot()
	codexRoot, codexErr := codex.DefaultRoot()
	return []ledgerCollectorSpec{
		{adapter: claudecode.New(), root: claudeRoot, rootErr: claudeErr},
		// Codex has no plugin surface, so this collector is the only way its
		// spend is ever observed. Composing it here is also what puts `codex`
		// into the sink's collected partition, via collectedSpecHarnesses --
		// which is why a future Codex extension that pushed could not double
		// count even if its author never read this file.
		{adapter: codex.New(), root: codexRoot, rootErr: codexErr},
	}
}

// newLedgerCollectorWorker wires the specs to a sink. It returns nil when
// nothing could be composed, so a daemon without an observation plane grows no
// goroutine it has no use for.
func newLedgerCollectorWorker(specs []ledgerCollectorSpec, ingest telemetry.Ingest,
	stateDir string, logger *slog.Logger) (*ledgerCollectorWorker, error) {
	if ingest == nil || len(specs) == 0 {
		return nil, nil
	}
	collectors := make([]*ledger.Collector, 0, len(specs))
	for _, spec := range specs {
		statePath := ""
		if stateDir != "" {
			statePath = filepath.Join(stateDir, ledgerStateDirName,
				string(spec.adapter.Harness())+".json")
		}
		if spec.rootErr != nil {
			// The tree could not be located on this machine. That is a fact
			// about the machine, not a failure: the collector is composed with
			// an empty root and its probe reports absence. The harness is then
			// NOT claimed by the sink's collected partition, so a push adapter
			// for it keeps working rather than being superseded by a collector
			// that can see nothing. See collectedSpecHarnesses.
			logger.Info("ledger tree not locatable on this machine",
				slog.String("harness", string(spec.adapter.Harness())),
				slog.Any("error", spec.rootErr))
		}
		collector, err := ledger.New(ledger.Config{
			Adapter: spec.adapter, Root: spec.root, StatePath: statePath,
			Ingest: ingest, Logger: logger,
		})
		if err != nil {
			return nil, fmt.Errorf("compose %s ledger collector: %w", spec.adapter.Harness(), err)
		}
		collectors = append(collectors, collector)
	}
	return &ledgerCollectorWorker{
		collectors: collectors, logger: logger,
		interval: ledgerCollectInterval, delay: ledgerCollectDelay, timeout: ledgerCollectTimeout,
	}, nil
}

// ledgerCollectorWorker polls the composed ledger collectors.
//
// It is an observation-plane worker and therefore forbidden from mattering. It
// writes only through the sink, which never blocks; it returns no error a
// caller could act on; it recovers a panic, because a defect in a token reader
// must stop observation rather than the daemon; and every pass is bounded in
// time. Nothing it does can make a lease, a message, or a reservation fail,
// and that is a property of its structure rather than of its care.
type ledgerCollectorWorker struct {
	collectors []*ledger.Collector
	logger     *slog.Logger
	interval   time.Duration
	delay      time.Duration
	timeout    time.Duration

	cancel context.CancelFunc
	done   chan struct{}
}

func (worker *ledgerCollectorWorker) Start(ctx context.Context) error {
	if worker.cancel != nil {
		return errors.New("ledger collector worker is already started")
	}
	// Detached for the reason the telemetry drain is: Start's context describes
	// starting up, not running.
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	worker.cancel = cancel
	worker.done = make(chan struct{})
	for _, collector := range worker.collectors {
		probe := collector.Probe()
		worker.logger.Info("ledger collector composed",
			slog.String("harness", string(probe.Harness)),
			slog.String("root", probe.Root),
			slog.Bool("present", probe.Present),
			slog.String("reason", probe.Reason))
	}
	go func() {
		defer close(worker.done)
		worker.pollUntil(runCtx)
	}()
	return nil
}

func (worker *ledgerCollectorWorker) Stop(ctx context.Context) error {
	if worker.cancel == nil {
		return nil
	}
	worker.cancel()
	select {
	case <-worker.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (worker *ledgerCollectorWorker) pollUntil(ctx context.Context) {
	defer worker.recoverPoll()
	timer := time.NewTimer(worker.delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			worker.collectOnce(ctx)
			timer.Reset(worker.interval)
		}
	}
}

// collectOnce runs one bounded pass per collector and logs what it found. A
// failure is logged and dropped: an unreadable ledger tree is a normal state of
// the world, not a fault this daemon can or should do anything about.
func (worker *ledgerCollectorWorker) collectOnce(ctx context.Context) {
	for _, collector := range worker.collectors {
		passCtx, cancel := context.WithTimeout(ctx, worker.timeout)
		pass, err := collector.Collect(passCtx)
		cancel()
		if err != nil {
			worker.logger.Warn("ledger collection pass failed",
				slog.String("harness", string(pass.Harness)), slog.Any("error", err))
		}
		worker.logPass(pass)
		if ctx.Err() != nil {
			return
		}
	}
}

// logPass reports a pass that did work. A steady-state pass that opened no file
// says nothing at all, because a log line every minute per harness forever is
// how a useful signal gets ignored.
//
// The trigger is LinesScanned rather than Offered, and that distinction is the
// point. An adapter whose harness has changed its format returns "not an
// observation" for every line -- which is not malformed, and is the correct
// answer for most lines in any ledger -- so a pass that read thirty thousand
// new lines and observed nothing looked EXACTLY like a pass that found nothing
// new. Those are the two things an operator most needs to tell apart, and one
// of them was invisible. A pass that scanned lines now always logs what it made
// of them.
func (worker *ledgerCollectorWorker) logPass(pass ledger.Pass) {
	if pass.CursorSaveFail {
		// A cursor that cannot be written means the next pass re-reads from the
		// last watermark that landed. The dedupe key makes that harmless and
		// merely wasteful -- but a state directory this daemon cannot write is
		// worth saying out loud, since nothing else here would ever fail.
		worker.logger.Warn("ledger collector could not persist its cursors",
			slog.String("harness", string(pass.Harness)))
	}
	if pass.LinesScanned == 0 && pass.Offered == 0 && pass.Malformed == 0 &&
		pass.Dropped == 0 && pass.Unattributed == 0 && pass.Oversize == 0 {
		return
	}
	worker.logger.Info("ledger collection pass",
		slog.String("harness", string(pass.Harness)),
		slog.Int("files_seen", pass.FilesSeen), slog.Int("files_window", pass.FilesWindow),
		slog.Int("files_read", pass.FilesRead), slog.Int("lines_scanned", pass.LinesScanned),
		slog.Int("observed", pass.Observed), slog.Int("offered", pass.Offered),
		slog.Int("duplicates", pass.Duplicates), slog.Int("restatements", pass.Restatements),
		slog.Int("malformed", pass.Malformed),
		slog.Int("oversize", pass.Oversize), slog.Int("dropped", pass.Dropped),
		slog.Int("unattributed", pass.Unattributed), slog.Int("restarted", pass.Restarted),
		slog.Int("depth_skipped", pass.DepthSkipped),
		slog.String("limit", pass.LimitReached),
		slog.Duration("duration", pass.Duration))
}

// recoverPoll keeps a defect in a ledger reader from taking the daemon with it.
func (worker *ledgerCollectorWorker) recoverPoll() {
	if recovered := recover(); recovered != nil {
		worker.logger.Error("ledger collection panicked and stopped", slog.Any("panic", recovered))
	}
}
