package sqlite

import (
	"context"
	"testing"
	"time"
)

func TestPassiveCheckpointLoopRunsUntilCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		passiveCheckpointLoop(ctx, time.Millisecond, func(context.Context) {
			select {
			case called <- struct{}{}:
			default:
			}
		})
	}()

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("periodic passive checkpoint did not run")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("periodic passive checkpoint did not stop")
	}
}
