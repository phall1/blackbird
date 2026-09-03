package coordination

import "testing"

// TestContentionStatsSumsEveryKindOfLoss is what the cost report reads to
// decide whether its counts are measurements or floors. The kinds are kept
// apart for diagnosis and summed for that one question, and a kind added later
// must fall inside Lost() rather than outside it -- a loss outside it is a loss
// no reader is ever told about.
func TestContentionStatsSumsEveryKindOfLoss(t *testing.T) {
	t.Parallel()
	if got := (ContentionStats{Offered: 9, Written: 9}).Lost(); got != 0 {
		t.Fatalf("a clean journal reports %d lost", got)
	}
	stats := ContentionStats{DroppedFull: 1, DroppedClosed: 2, DroppedInvalid: 4, DroppedWrite: 8}
	if got := stats.Lost(); got != 15 {
		t.Fatalf("Lost()=%d, want every kind summed", got)
	}
	// WriteFailures counts BATCHES and must not be summed into a fact count:
	// one failed batch carries many facts, so adding it would double-count the
	// failure and still understate the loss.
	stats.WriteFailures = 1
	if got := stats.Lost(); got != 15 {
		t.Fatalf("Lost()=%d after a batch failure; batch counts are not fact counts", got)
	}
}
