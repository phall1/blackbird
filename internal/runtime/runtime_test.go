package runtime

import (
	"context"
	"testing"
)

func TestNewNormalizesBuildInfo(t *testing.T) {
	t.Parallel()

	daemon := New(BuildInfo{})
	got := daemon.BuildInfo()
	want := (BuildInfo{Version: "dev", Commit: "unknown", BuiltAt: "unknown"})
	if got != want {
		t.Fatalf("BuildInfo() = %#v, want %#v", got, want)
	}
}

func TestRunStopsCleanlyWhenContextIsCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := New(BuildInfo{}).Run(ctx); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
}
