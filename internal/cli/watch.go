package cli

import (
	"context"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
)

const minimumWatchInterval = 200 * time.Millisecond

// loop renders once, or repeatedly when watching. It refuses to watch a stream
// that is not a terminal and refuses to interleave frames with JSON, because
// both produce output no consumer can read.
func (console *Console) loop(
	ctx context.Context,
	watching bool,
	interval time.Duration,
	build func(ctx context.Context) (render.View, error),
) error {
	view, err := build(ctx)
	if err != nil {
		return err
	}
	if !watching {
		return console.present(view)
	}
	if console.Globals.JSON {
		return usageFault("--watch cannot be combined with --json")
	}
	if !console.Style.TTY() {
		return usageFault("--watch requires a terminal on stdout")
	}
	if interval < minimumWatchInterval {
		return usageFault("--interval must be at least %s", minimumWatchInterval)
	}

	if err := console.watch(view); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			refreshed, buildErr := build(ctx)
			if buildErr != nil {
				return buildErr
			}
			if err := console.watch(refreshed); err != nil {
				return err
			}
		}
	}
}
