package runtime

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/application/coordination"
)

type reportingStore struct {
	stats coordination.ContentionStats
}

func (store *reportingStore) Close() error { return nil }

func (store *reportingStore) ContentionStats() coordination.ContentionStats { return store.stats }

type silentStore struct{}

func (silentStore) Close() error { return nil }

// TestContentionLossIsLoggedHoweverItWasLost is a defect found by driving a
// real daemon rather than by reading the code, and it is the one that matters
// most about this line: it is the ONLY place a lost contention fact is ever
// stated. The journal has no error return by construction, so a loss it does
// not print is a loss nobody can ever learn about.
//
// The guard used to name three counters -- offered, queue-full and invalid --
// and miss the rest. A fact offered after the journal closed counts as
// DroppedClosed and nothing else, so a daemon that lost facts AT SHUTDOWN, the
// likeliest moment to lose one, printed nothing at all. Lost() covers every
// kind of loss by construction, so a counter added later cannot fall back
// outside the guard.
func TestContentionLossIsLoggedHoweverItWasLost(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		stats coordination.ContentionStats
		want  bool
	}{
		{name: "nothing handled and nothing lost", stats: coordination.ContentionStats{}},
		{name: "facts written", stats: coordination.ContentionStats{Offered: 2, Written: 2}, want: true},
		{name: "queue full", stats: coordination.ContentionStats{DroppedFull: 1}, want: true},
		{name: "journal already closed", stats: coordination.ContentionStats{DroppedClosed: 1}, want: true},
		{name: "unencodable fact", stats: coordination.ContentionStats{DroppedInvalid: 1}, want: true},
		{name: "commit failed", stats: coordination.ContentionStats{DroppedWrite: 9, WriteFailures: 1}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			daemon := &Daemon{logger: slog.New(slog.NewTextHandler(&output, nil))}
			daemon.logContention(&reportingStore{stats: test.stats}, true)
			if logged := strings.Contains(output.String(), "contention journal stopped"); logged != test.want {
				t.Fatalf("logged=%t want=%t for %+v; output=%q", logged, test.want, test.stats, output.String())
			}
		})
	}
}

// TestContentionLossSaysWhetherTheJournalWasFlushed keeps the counts readable.
// A drain that timed out leaves the snapshot taken before the final batch, so
// offered minus written is an upper bound on the loss rather than the loss --
// and saying which is the difference between an honest report and a misleading
// one. The old code did not report at all in that case.
func TestContentionLossSaysWhetherTheJournalWasFlushed(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	daemon := &Daemon{logger: slog.New(slog.NewTextHandler(&output, nil))}
	daemon.logContention(&reportingStore{stats: coordination.ContentionStats{Offered: 5, Written: 1}}, false)
	if !strings.Contains(output.String(), "flushed=false") {
		t.Fatalf("an unflushed journal did not say so: %q", output.String())
	}
}

// TestAStoreThatRecordsNoContentionReportsNothing keeps the capability
// optional: a backend without a journal is a valid backend, and it must not be
// able to fail or clutter a shutdown by being asked to report on itself.
func TestAStoreThatRecordsNoContentionReportsNothing(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	daemon := &Daemon{logger: slog.New(slog.NewTextHandler(&output, nil))}
	daemon.logContention(silentStore{}, true)
	if output.Len() != 0 {
		t.Fatalf("a store with no contention journal logged %q", output.String())
	}
}
