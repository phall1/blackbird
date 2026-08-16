package logsource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/cli"
)

func stateDirWith(t *testing.T, out, errText string) string {
	t.Helper()
	directory := t.TempDir()
	if out != "" {
		if err := os.WriteFile(filepath.Join(directory, outFileName), []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if errText != "" {
		if err := os.WriteFile(filepath.Join(directory, errFileName), []byte(errText), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func collect(t *testing.T, source *Source, request cli.LogRequest) []cli.LogLine {
	t.Helper()
	var lines []cli.LogLine
	if err := source.Tail(context.Background(), request, func(line cli.LogLine) error {
		lines = append(lines, line)
		return nil
	}); err != nil {
		t.Fatalf("Tail() = %v", err)
	}
	return lines
}

func TestTailReturnsTheLastLinesOfEachStream(t *testing.T) {
	t.Parallel()

	source := New(stateDirWith(t, "one\ntwo\nthree\n", "boom\n"))
	lines := collect(t, source, cli.LogRequest{Stream: "both", Lines: 2})
	if len(lines) != 2 {
		t.Fatalf("lines = %#v", lines)
	}
	if lines[0].Stream != "out" || lines[0].Text != "three" {
		t.Fatalf("out line = %#v", lines[0])
	}
	if lines[1].Stream != "err" || lines[1].Text != "boom" {
		t.Fatalf("err line = %#v", lines[1])
	}
}

// TestTailSpendsOneLineBudgetAcrossStreams is the regression for --lines being
// applied per stream: "logs -n 50" under the default --stream=both returned up
// to a hundred rows, which is not what the flag says and not what a pager or a
// pipe downstream of it was sized for.
func TestTailSpendsOneLineBudgetAcrossStreams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		out   string
		err   string
		lines int
		want  []cli.LogLine
	}{
		{
			name: "budget splits evenly", out: "o1\no2\no3\no4\n", err: "e1\ne2\ne3\ne4\n", lines: 4,
			want: []cli.LogLine{
				{Stream: "out", Text: "o3"}, {Stream: "out", Text: "o4"},
				{Stream: "err", Text: "e3"}, {Stream: "err", Text: "e4"},
			},
		},
		{
			name: "a silent stream costs nothing", out: "", err: "e1\ne2\ne3\n", lines: 3,
			want: []cli.LogLine{
				{Stream: "err", Text: "e1"}, {Stream: "err", Text: "e2"}, {Stream: "err", Text: "e3"},
			},
		},
		{
			name: "a short stream hands back its share", out: "o1\n", err: "e1\ne2\ne3\ne4\n", lines: 4,
			want: []cli.LogLine{
				{Stream: "out", Text: "o1"},
				{Stream: "err", Text: "e2"}, {Stream: "err", Text: "e3"}, {Stream: "err", Text: "e4"},
			},
		},
		{
			name: "an odd budget is never exceeded", out: "o1\no2\no3\n", err: "e1\ne2\ne3\n", lines: 3,
			want: []cli.LogLine{
				{Stream: "out", Text: "o2"}, {Stream: "out", Text: "o3"},
				{Stream: "err", Text: "e3"},
			},
		},
		{
			name: "everything fits", out: "o1\n", err: "e1\n", lines: 50,
			want: []cli.LogLine{{Stream: "out", Text: "o1"}, {Stream: "err", Text: "e1"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			source := New(stateDirWith(t, test.out, test.err))
			lines := collect(t, source, cli.LogRequest{Stream: "both", Lines: test.lines})
			if len(lines) > test.lines {
				t.Fatalf("lines = %#v, want at most %d", lines, test.lines)
			}
			if !reflect.DeepEqual(lines, test.want) {
				t.Fatalf("lines = %#v, want %#v", lines, test.want)
			}
		})
	}
}

func TestTailSelectsASingleStream(t *testing.T) {
	t.Parallel()

	source := New(stateDirWith(t, "out line\n", "err line\n"))
	lines := collect(t, source, cli.LogRequest{Stream: "err", Lines: 10})
	if len(lines) != 1 || lines[0].Text != "err line" {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestTailDefaultsToBothStreams(t *testing.T) {
	t.Parallel()

	source := New(stateDirWith(t, "out line\n", "err line\n"))
	lines := collect(t, source, cli.LogRequest{Lines: 10})
	if len(lines) != 2 {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestTailToleratesMissingFiles(t *testing.T) {
	t.Parallel()

	source := New(t.TempDir())
	if lines := collect(t, source, cli.LogRequest{Stream: "both", Lines: 10}); len(lines) != 0 {
		t.Fatalf("lines = %#v, want none", lines)
	}
}

func TestTailReadsOnlyTheTailOfALargeFile(t *testing.T) {
	t.Parallel()

	var builder strings.Builder
	for index := range 40000 {
		builder.WriteString("line " + strconv.Itoa(index) + "\n")
	}
	source := New(stateDirWith(t, builder.String(), ""))
	lines := collect(t, source, cli.LogRequest{Stream: "out", Lines: 3})
	if len(lines) != 3 || lines[2].Text != "line 39999" {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestTailRejectsAnUnknownStream(t *testing.T) {
	t.Parallel()

	source := New(t.TempDir())
	err := source.Tail(context.Background(), cli.LogRequest{Stream: "stdout"}, func(cli.LogLine) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "unknown stream") {
		t.Fatalf("Tail() = %v", err)
	}
}

func TestTailRequiresAStateDirectory(t *testing.T) {
	t.Parallel()

	err := New("").Tail(context.Background(), cli.LogRequest{}, func(cli.LogLine) error { return nil })
	if err == nil {
		t.Fatal("Tail() accepted an empty state directory")
	}
}

func TestTailStopsWhenTheConsumerFails(t *testing.T) {
	t.Parallel()

	source := New(stateDirWith(t, "one\ntwo\n", ""))
	sentinel := errors.New("stop")
	err := source.Tail(context.Background(), cli.LogRequest{Stream: "out", Lines: 10}, func(cli.LogLine) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Tail() = %v, want the consumer's error", err)
	}
}

func TestFollowEmitsNewLinesAndStopsOnCancellation(t *testing.T) {
	t.Parallel()

	directory := stateDirWith(t, "first\n", "")
	source := New(directory)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	seen := make(chan string, 8)
	done := make(chan error, 1)
	go func() {
		done <- source.Tail(ctx, cli.LogRequest{Stream: "out", Lines: 10, Follow: true}, func(line cli.LogLine) error {
			seen <- line.Text
			return nil
		})
	}()

	if got := <-seen; got != "first" {
		t.Fatalf("first line = %q", got)
	}
	file, err := os.OpenFile(filepath.Join(directory, outFileName), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("second\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-seen:
		if got != "second" {
			t.Fatalf("appended line = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow did not emit the appended line")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Tail() = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow did not stop on cancellation")
	}
}

func TestFollowRestartsAfterTruncation(t *testing.T) {
	t.Parallel()

	directory := stateDirWith(t, "one\ntwo\n", "")
	path := filepath.Join(directory, outFileName)
	if err := os.WriteFile(path, []byte("fresh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, offset, err := readFrom(path, 1<<20)
	if err != nil {
		t.Fatalf("readFrom() = %v", err)
	}
	if len(lines) != 1 || lines[0] != "fresh" {
		t.Fatalf("lines = %#v", lines)
	}
	if offset != int64(len("fresh\n")) {
		t.Fatalf("offset = %d", offset)
	}
}

// TestReadFromConsumesOnlyTheLinesItEmitted is the regression for a follower
// that reported the file size as its new offset: an append between the stat and
// the read was emitted immediately and then emitted again on the next poll.
func TestReadFromConsumesOnlyTheLinesItEmitted(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), outFileName)
	if err := os.WriteFile(path, []byte("one\ntwo"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, offset, err := readFrom(path, 0)
	if err != nil {
		t.Fatalf("readFrom() = %v", err)
	}
	if len(lines) != 1 || lines[0] != "one" {
		t.Fatalf("lines = %#v, want only the terminated line", lines)
	}
	if offset != int64(len("one\n")) {
		t.Fatalf("offset = %d, want %d", offset, len("one\n"))
	}

	if err := os.WriteFile(path, []byte("one\ntwo-tail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, offset, err = readFrom(path, offset)
	if err != nil {
		t.Fatalf("readFrom() = %v", err)
	}
	if len(lines) != 1 || lines[0] != "two-tail" {
		t.Fatalf("lines = %#v, want the completed line exactly once", lines)
	}
	if offset != int64(len("one\ntwo-tail\n")) {
		t.Fatalf("offset = %d, want %d", offset, len("one\ntwo-tail\n"))
	}
}

func TestTailReportsTheOffsetItConsumed(t *testing.T) {
	t.Parallel()

	directory := stateDirWith(t, "one\npart", "")
	lines, offset, err := tailFile(filepath.Join(directory, outFileName), 10, true)
	if err != nil {
		t.Fatalf("tailFile() = %v", err)
	}
	if len(lines) != 1 || lines[0] != "one" {
		t.Fatalf("lines = %#v", lines)
	}
	if offset != int64(len("one\n")) {
		t.Fatalf("offset = %d, want %d", offset, len("one\n"))
	}

	lines, offset, err = tailFile(filepath.Join(directory, outFileName), 10, false)
	if err != nil {
		t.Fatalf("tailFile() = %v", err)
	}
	if len(lines) != 2 || lines[1] != "part" {
		t.Fatalf("lines = %#v, want the trailing fragment when not following", lines)
	}
	if offset != int64(len("one\npart")) {
		t.Fatalf("offset = %d, want %d", offset, len("one\npart"))
	}
}

// TestFollowEmitsATornWriteOnceWhenItCompletes exercises the daemon writing a
// line in two syscalls: the follower must wait for the newline instead of
// emitting the fragment and then the whole line.
func TestFollowEmitsATornWriteOnceWhenItCompletes(t *testing.T) {
	t.Parallel()

	directory := stateDirWith(t, "first\n", "")
	source := New(directory)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	seen := make(chan string, 8)
	go func() {
		_ = source.Tail(ctx, cli.LogRequest{Stream: "out", Lines: 10, Follow: true}, func(line cli.LogLine) error {
			seen <- line.Text
			return nil
		})
	}()
	if got := <-seen; got != "first" {
		t.Fatalf("first line = %q", got)
	}

	file, err := os.OpenFile(filepath.Join(directory, outFileName), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("tor"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * pollInterval)
	if _, err := file.WriteString("n write\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-seen:
		if got != "torn write" {
			t.Fatalf("emitted %q, want the completed line", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow did not emit the completed line")
	}
	select {
	case got := <-seen:
		t.Fatalf("follow emitted %q twice over", got)
	case <-time.After(2 * pollInterval):
	}
}

func TestTailSkipsThePartialLineAtTheWindowEdge(t *testing.T) {
	t.Parallel()

	var builder strings.Builder
	for index := range 120000 {
		builder.WriteString("line " + strconv.Itoa(index) + "\n")
	}
	directory := stateDirWith(t, builder.String(), "")
	lines, offset, err := tailFile(filepath.Join(directory, outFileName), 0, true)
	if err != nil {
		t.Fatalf("tailFile() = %v", err)
	}
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "line ") {
		t.Fatalf("first line = %#v, want a whole line", lines[:1])
	}
	if offset != int64(builder.Len()) {
		t.Fatalf("offset = %d, want the end of the file %d", offset, builder.Len())
	}
}

func TestSourceResolvesStreamPaths(t *testing.T) {
	t.Parallel()

	source := New("/state")
	if got, want := source.path("err"), filepath.Join("/state", errFileName); got != want {
		t.Fatalf("path(err) = %q, want %q", got, want)
	}
	if got, want := source.path("out"), filepath.Join("/state", outFileName); got != want {
		t.Fatalf("path(out) = %q, want %q", got, want)
	}
}
