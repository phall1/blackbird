package runtime

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/phall1/blackbird/internal/application"
)

const (
	// defaultTelemetryRetention is how long an observation is kept. The
	// observation plane is the one place in this daemon where deleting data is
	// ordinary: coordination bodies are permanent because another agent may
	// still need to read them, and nothing reads a six-week-old token count
	// that a rollup has not already absorbed.
	defaultTelemetryRetention = 30 * 24 * time.Hour
	// defaultTelemetrySweepInterval is deliberately far longer than the
	// retention resolution anyone cares about. Sweeping hourly would take the
	// write arbiter 720 times to delete what one nightly pass deletes once.
	defaultTelemetrySweepInterval = time.Hour
	// telemetrySweepTimeout bounds one sweep so a large backlog cannot hold the
	// write lane open indefinitely on a machine that has been off for months.
	telemetrySweepTimeout = 30 * time.Second
)

// telemetryWorker owns the observation plane's two goroutines: the sink drain
// and the retention sweep.
//
// It is a Worker so that runtime stops it in the one window where stopping is
// safe -- after ingress has drained, so nothing can still be offering, and
// before storage closes, so the final flush has somewhere to write.
type telemetryWorker struct {
	sink      *application.TelemetrySink
	store     application.TelemetryStore
	logger    *slog.Logger
	retention time.Duration
	interval  time.Duration

	cancel context.CancelFunc
	drain  chan struct{}
	sweep  chan struct{}
}

func newTelemetryWorker(store application.TelemetryStore, logger *slog.Logger) *telemetryWorker {
	return &telemetryWorker{
		sink:      application.NewTelemetrySink(store, application.TelemetrySinkConfig{Logger: logger}),
		store:     store,
		logger:    logger,
		retention: defaultTelemetryRetention,
		interval:  defaultTelemetrySweepInterval,
	}
}

func (worker *telemetryWorker) Start(ctx context.Context) error {
	if worker.cancel != nil {
		return errors.New("telemetry worker is already started")
	}
	// The lifetime context is deliberately detached from Start's: Start's
	// context describes starting up, not running, and a worker that stopped
	// when startup finished would observe nothing.
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	worker.cancel = cancel
	worker.drain = make(chan struct{})
	worker.sweep = make(chan struct{})
	go func() {
		defer close(worker.drain)
		worker.sink.Run(runCtx)
	}()
	go func() {
		defer close(worker.sweep)
		worker.sweepUntil(runCtx)
	}()
	return nil
}

// Stop closes the sink first so its bounded flush still has an open database,
// then cancels the sweep. The order matters: cancelling first would abandon
// whatever the drain had already accepted.
func (worker *telemetryWorker) Stop(ctx context.Context) error {
	if worker.cancel == nil {
		return nil
	}
	_ = worker.sink.Close()
	worker.cancel()
	for _, done := range []chan struct{}{worker.drain, worker.sweep} {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	stats := worker.sink.Stats()
	worker.logger.Info("telemetry stopped",
		slog.Uint64("accepted", stats.Accepted), slog.Uint64("written", stats.Written),
		slog.Uint64("dropped_queue_full", stats.DroppedFull),
		slog.Uint64("dropped_closed", stats.DroppedClosed),
		slog.Uint64("write_failures", stats.WriteFailures))
	return nil
}

func (worker *telemetryWorker) sweepUntil(ctx context.Context) {
	ticker := time.NewTicker(worker.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			worker.sweepOnce(ctx)
		}
	}
}

// sweepOnce deletes expired observations. Every failure here is logged and
// dropped: a sweep that cannot run costs disk, and disk is not worth failing a
// daemon over.
func (worker *telemetryWorker) sweepOnce(ctx context.Context) {
	sweepCtx, cancel := context.WithTimeout(ctx, telemetrySweepTimeout)
	defer cancel()
	deleted, err := worker.store.SweepTelemetry(sweepCtx, time.Now().UTC().Add(-worker.retention))
	if err != nil {
		worker.logger.Warn("telemetry retention sweep failed", slog.Any("error", err))
		return
	}
	if deleted > 0 {
		worker.logger.Info("telemetry retention sweep",
			slog.Int64("deleted", deleted), slog.Duration("retention", worker.retention))
	}
}
