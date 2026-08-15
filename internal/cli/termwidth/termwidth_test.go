package termwidth

import (
	"os"
	"testing"
)

func TestProbeReportsNoWidthForAPipe(t *testing.T) {
	t.Parallel()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	if width, ok := ProbeFile(writer); ok || width != 0 {
		t.Fatalf("ProbeFile(pipe) = (%d, %t), want (0, false)", width, ok)
	}
}

func TestProbeFileRejectsNil(t *testing.T) {
	t.Parallel()

	if width, ok := ProbeFile(nil); ok || width != 0 {
		t.Fatalf("ProbeFile(nil) = (%d, %t), want (0, false)", width, ok)
	}
}

// TestProbeAnswersConsistently pins the contract rather than the value: a test
// binary's stdout is a pipe under go test and a terminal under a bare run.
func TestProbeAnswersConsistently(t *testing.T) {
	t.Parallel()

	width, ok := Probe()
	if ok && width <= 0 {
		t.Fatalf("Probe() = (%d, true), want a positive width", width)
	}
	if !ok && width != 0 {
		t.Fatalf("Probe() = (%d, false), want no width", width)
	}
}
