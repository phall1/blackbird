//go:build !unix

package termwidth

import "os"

// Probe reports no width on platforms without a winsize ioctl, so the caller
// falls back to COLUMNS and then to a fixed width.
func Probe() (int, bool) { return 0, false }

func ProbeFile(*os.File) (int, bool) { return 0, false }
