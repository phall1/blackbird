//go:build unix

package termwidth

import (
	"os"

	"golang.org/x/sys/unix"
)

// Probe reports the width of the controlling terminal on stdout. It answers
// false whenever the stream is not a terminal, which is every pipe, file, and
// CI runner, so the caller falls back to COLUMNS and then to a fixed width.
func Probe() (int, bool) {
	return ProbeFile(os.Stdout)
}

func ProbeFile(file *os.File) (int, bool) {
	if file == nil {
		return 0, false
	}
	size, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
	if err != nil || size == nil || size.Col == 0 {
		return 0, false
	}
	return int(size.Col), true
}
