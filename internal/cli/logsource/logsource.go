// Package logsource tails the daemon's log files. It reads the same two files
// the installed service definition redirects stdout and stderr into, so it
// works with no daemon, no database, and no credential.
package logsource

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/cli"
)

const (
	outFileName      = "blackbird.log"
	errFileName      = "blackbird.err.log"
	pollInterval     = 200 * time.Millisecond
	maximumTailKB    = 512
	maximumLineBytes = 1 << 20
)

// Source reads the daemon's streams out of a state directory.
type Source struct {
	StateDir string
}

var _ cli.LogPort = (*Source)(nil)

func New(stateDir string) *Source { return &Source{StateDir: stateDir} }

func (source *Source) Tail(ctx context.Context, request cli.LogRequest, emit func(cli.LogLine) error) error {
	if source.StateDir == "" {
		return errors.New("no state directory is configured")
	}
	streams, err := source.streams(request.Stream)
	if err != nil {
		return err
	}

	offsets := make(map[string]int64, len(streams))
	tails := make([][]string, len(streams))
	available := make([]int, len(streams))
	for index, stream := range streams {
		lines, size, err := tailFile(source.path(stream), request.Lines, request.Follow)
		if err != nil {
			return err
		}
		offsets[stream] = size
		tails[index] = lines
		available[index] = len(lines)
	}
	allowances := budget(available, request.Lines)
	for index, stream := range streams {
		lines := tails[index]
		if allowance := allowances[index]; allowance < len(lines) {
			lines = lines[len(lines)-allowance:]
		}
		for _, line := range lines {
			if err := emit(cli.LogLine{Stream: stream, Text: line}); err != nil {
				return err
			}
		}
	}
	if !request.Follow {
		return nil
	}
	return source.follow(ctx, streams, offsets, emit)
}

func (source *Source) follow(
	ctx context.Context,
	streams []string,
	offsets map[string]int64,
	emit func(cli.LogLine) error,
) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			for _, stream := range streams {
				lines, offset, err := readFrom(source.path(stream), offsets[stream])
				if err != nil {
					return err
				}
				offsets[stream] = offset
				for _, line := range lines {
					if err := emit(cli.LogLine{Stream: stream, Text: line}); err != nil {
						return err
					}
				}
			}
		}
	}
}

// budget spends one --lines allowance across every requested stream instead of
// granting it to each of them, which is what made "logs -n 50 --stream=both"
// print a hundred rows. Streams draw equal shares and whatever a short stream
// leaves is handed to the others, so one silent stream still costs nothing.
func budget(available []int, total int) []int {
	allowance := make([]int, len(available))
	if total <= 0 {
		copy(allowance, available)
		return allowance
	}
	remaining := total
	for remaining > 0 {
		hungry := 0
		for index, count := range available {
			if allowance[index] < count {
				hungry++
			}
		}
		if hungry == 0 {
			break
		}
		share := remaining / hungry
		if share == 0 {
			share = 1
		}
		for index, count := range available {
			if remaining == 0 {
				break
			}
			grant := min(share, count-allowance[index], remaining)
			if grant <= 0 {
				continue
			}
			allowance[index] += grant
			remaining -= grant
		}
	}
	return allowance
}

func (source *Source) streams(requested string) ([]string, error) {
	switch requested {
	case "", "both":
		return []string{"out", "err"}, nil
	case "out", "err":
		return []string{requested}, nil
	default:
		return nil, fmt.Errorf("unknown stream %q", requested)
	}
}

func (source *Source) path(stream string) string {
	if stream == "err" {
		return filepath.Join(source.StateDir, errFileName)
	}
	return filepath.Join(source.StateDir, outFileName)
}

// tailFile returns at most the last count lines and the offset it stopped at.
// A missing file is not an error: the daemon may never have written to it. When
// the caller goes on to follow the file, a trailing fragment is left unread and
// unreported: the daemon is mid-write, and consuming it emits half a line now
// and the whole line again on the next poll.
func tailFile(path string, count int, follow bool) ([]string, int64, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("inspect %s: %w", path, err)
	}
	start := int64(0)
	if window := int64(maximumTailKB << 10); info.Size() > window {
		start = info.Size() - window
		skipped, err := skipPartialLine(file, start, info.Size())
		if err != nil {
			return nil, 0, fmt.Errorf("read %s: %w", path, err)
		}
		start += skipped
	}

	lines, fragment, consumed, err := readLines(file, start, info.Size())
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}
	if !follow && fragment != "" {
		lines = append(lines, fragment)
		consumed += int64(len(fragment))
	}
	if count > 0 && len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return lines, start + consumed, nil
}

// readFrom returns the complete lines written since offset and the offset those
// lines end at. The returned offset is what was consumed, never the file size:
// the daemon appends between the stat and the read, and reporting the size as
// consumed emits those bytes now and again on the next poll.
func readFrom(path string, offset int64) ([]string, int64, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, offset, nil
	}
	if err != nil {
		return nil, offset, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, offset, fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Size() < offset {
		offset = 0
	}
	if info.Size() == offset {
		return nil, offset, nil
	}
	lines, _, consumed, err := readLines(file, offset, info.Size())
	if err != nil {
		return nil, offset, fmt.Errorf("read %s: %w", path, err)
	}
	return lines, offset + consumed, nil
}

// readLines splits [start, end) into newline-terminated lines. It reports the
// bytes those lines occupy and, separately, any trailing fragment: an offset
// derived from consumed bytes is always a line boundary, so the next read never
// starts mid-line.
func readLines(file *os.File, start, end int64) ([]string, string, int64, error) {
	if end <= start {
		return nil, "", 0, nil
	}
	scanner := bufio.NewScanner(io.NewSectionReader(file, start, end-start))
	scanner.Buffer(make([]byte, 0, 64<<10), maximumLineBytes)
	scanner.Split(scanTerminatedLines)
	var lines []string
	var fragment string
	var consumed int64
	for scanner.Scan() {
		chunk := scanner.Text()
		if !strings.HasSuffix(chunk, "\n") {
			fragment = chunk
			break
		}
		consumed += int64(len(chunk))
		lines = append(lines, strings.TrimSuffix(strings.TrimSuffix(chunk, "\n"), "\r"))
	}
	if err := scanner.Err(); err != nil {
		return nil, "", 0, fmt.Errorf("scan lines: %w", err)
	}
	return lines, fragment, consumed, nil
}

// scanTerminatedLines keeps the newline in the token, which is what lets the
// caller tell a complete line from a fragment and count bytes exactly.
func scanTerminatedLines(data []byte, atEOF bool) (int, []byte, error) {
	if index := bytes.IndexByte(data, '\n'); index >= 0 {
		return index + 1, data[:index+1], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// skipPartialLine reports how many bytes separate start from the first line
// boundary after it. The tail window lands in the middle of a line whenever the
// file is larger than it.
func skipPartialLine(file *os.File, start, end int64) (int64, error) {
	reader := bufio.NewReaderSize(io.NewSectionReader(file, start, end-start), 64<<10)
	skipped := int64(0)
	for {
		chunk, err := reader.ReadSlice('\n')
		skipped += int64(len(chunk))
		switch {
		case err == nil, errors.Is(err, io.EOF):
			return skipped, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return 0, fmt.Errorf("skip partial line: %w", err)
		}
	}
}
