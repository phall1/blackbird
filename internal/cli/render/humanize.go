package render

import (
	"fmt"
	"math"
	"strings"
	"time"
)

const timestampLayout = "2006-01-02 15:04:05"

// Absent is what every humaniser prints for a zero instant.
const Absent = "-"

var byteUnits = [...]string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

// Instant converts a microsecond Unix timestamp to a UTC time. Blackbird's
// admin read models carry timestamps this way (application.TimeFromMicros has
// the same contract), so this is the adapter into the time.Time surface below.
// Non-positive values yield the zero time.
func Instant(micros int64) time.Time {
	if micros <= 0 {
		return time.Time{}
	}
	return time.UnixMicro(micros).UTC()
}

// Timestamp renders an absolute UTC stamp: "2026-08-15 14:03:22Z".
func Timestamp(instant time.Time) string {
	if instant.IsZero() {
		return Absent
	}
	return instant.UTC().Format(timestampLayout) + "Z"
}

func TimestampMicros(micros int64) string {
	return Timestamp(Instant(micros))
}

// RelativeTime renders instant relative to now.
func RelativeTime(instant time.Time, now time.Time) string {
	if instant.IsZero() {
		return "never"
	}
	delta := now.Sub(instant)
	switch {
	case delta < time.Second && delta > -time.Second:
		return "now"
	case delta < 0:
		return "in " + magnitude(-delta)
	default:
		return magnitude(delta) + " ago"
	}
}

func RelativeMicros(micros int64, now time.Time) string {
	return RelativeTime(Instant(micros), now)
}

// RelativeStamp renders an RFC 3339 instant from the admin surface relative to
// now, falling back to the raw text when the daemon reports a form we do not
// know. The admin projections carry instants as strings; a command that prints
// one raw spends 25 columns saying "3h ago" and disagrees with every command
// that does not, so this is the single conversion tables use.
func RelativeStamp(value string, now time.Time) string {
	if value == "" {
		return Absent
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return RelativeTime(parsed, now)
}

func magnitude(delta time.Duration) string {
	days := int64(delta / (24 * time.Hour))
	switch {
	case delta < time.Minute:
		return fmt.Sprintf("%ds", int64(delta/time.Second))
	case delta < time.Hour:
		return fmt.Sprintf("%dm", int64(delta/time.Minute))
	case delta < 24*time.Hour:
		return fmt.Sprintf("%dh", int64(delta/time.Hour))
	case days < 30:
		return fmt.Sprintf("%dd", days)
	case days < 365:
		return fmt.Sprintf("%dmo", days/30)
	default:
		return fmt.Sprintf("%dy", days/365)
	}
}

// Duration renders a duration in ASCII only, so it needs no second code path
// when Unicode is unavailable.
func Duration(value time.Duration) string {
	switch {
	case value == math.MinInt64:
		return "-" + Duration(math.MaxInt64)
	case value < 0:
		return "-" + Duration(-value)
	case value == 0:
		return "0s"
	case value < time.Millisecond:
		return "<1ms"
	case value < time.Second:
		return fmt.Sprintf("%dms", int64(value/time.Millisecond))
	case value < time.Minute:
		return trimZeroDecimal(fmt.Sprintf("%.1f", value.Seconds())) + "s"
	case value < time.Hour:
		return trimZeroUnit(fmt.Sprintf("%dm%ds", int64(value/time.Minute), int64(value/time.Second)%60), "0s")
	case value < 24*time.Hour:
		return trimZeroUnit(fmt.Sprintf("%dh%dm", int64(value/time.Hour), int64(value/time.Minute)%60), "0m")
	default:
		return trimZeroUnit(fmt.Sprintf("%dd%dh", int64(value/(24*time.Hour)), int64(value/time.Hour)%24), "0h")
	}
}

func DurationMicros(micros int64) string {
	return Duration(time.Duration(micros) * time.Microsecond)
}

// Bytes renders a byte count with binary units and ASCII suffixes.
func Bytes(count int64) string {
	switch {
	case count == math.MinInt64:
		return "-" + Bytes(math.MaxInt64)
	case count < 0:
		return "-" + Bytes(-count)
	case count < 1024:
		return fmt.Sprintf("%d B", count)
	}

	value := float64(count)
	unit := 0
	for value >= 1024 && unit < len(byteUnits) {
		value /= 1024
		unit++
	}
	return trimZeroDecimal(fmt.Sprintf("%.1f", value)) + " " + byteUnits[unit-1]
}

func trimZeroDecimal(text string) string {
	return strings.TrimSuffix(text, ".0")
}

func trimZeroUnit(text string, suffix string) string {
	if trimmed := strings.TrimSuffix(text, suffix); trimmed != text && trimmed != "" {
		return trimmed
	}
	return text
}
