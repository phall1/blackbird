package render

import (
	"math"
	"testing"
	"time"
)

var reference = time.Date(2026, 8, 15, 14, 3, 22, 0, time.UTC)

func TestInstantAndTimestamp(t *testing.T) {
	t.Parallel()

	if !Instant(0).IsZero() || !Instant(-1).IsZero() {
		t.Fatal("non-positive micros must yield the zero time")
	}
	if got := Timestamp(time.Time{}); got != Absent {
		t.Fatalf("Timestamp(zero) = %q, want %q", got, Absent)
	}
	if got := TimestampMicros(0); got != Absent {
		t.Fatalf("TimestampMicros(0) = %q, want %q", got, Absent)
	}

	micros := reference.UnixMicro()
	if got := Instant(micros); !got.Equal(reference) {
		t.Fatalf("Instant round trip = %s, want %s", got, reference)
	}
	if got, want := TimestampMicros(micros), "2026-08-15 14:03:22Z"; got != want {
		t.Fatalf("TimestampMicros = %q, want %q", got, want)
	}
	local := reference.In(time.FixedZone("plus2", 2*60*60))
	if got, want := Timestamp(local), "2026-08-15 14:03:22Z"; got != want {
		t.Fatalf("Timestamp normalised to %q, want %q", got, want)
	}
}

func TestRelativeTimeBuckets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		delta time.Duration
		want  string
	}{
		{name: "sub second", delta: 999 * time.Millisecond, want: "now"},
		{name: "one second", delta: time.Second, want: "1s ago"},
		{name: "fifty nine seconds", delta: 59 * time.Second, want: "59s ago"},
		{name: "one minute", delta: time.Minute, want: "1m ago"},
		{name: "just under an hour", delta: 3599 * time.Second, want: "59m ago"},
		{name: "one hour", delta: time.Hour, want: "1h ago"},
		{name: "just under a day", delta: 23*time.Hour + 59*time.Minute, want: "23h ago"},
		{name: "one day", delta: 24 * time.Hour, want: "1d ago"},
		{name: "twenty nine days", delta: 29 * 24 * time.Hour, want: "29d ago"},
		{name: "thirty days", delta: 30 * 24 * time.Hour, want: "1mo ago"},
		{name: "three hundred sixty four days", delta: 364 * 24 * time.Hour, want: "12mo ago"},
		{name: "one year", delta: 365 * 24 * time.Hour, want: "1y ago"},
		{name: "two years", delta: 730 * 24 * time.Hour, want: "2y ago"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			instant := reference.Add(-test.delta)
			if got := RelativeTime(instant, reference); got != test.want {
				t.Fatalf("RelativeTime(-%s) = %q, want %q", test.delta, got, test.want)
			}
			if got := RelativeMicros(instant.UnixMicro(), reference); got != test.want {
				t.Fatalf("RelativeMicros(-%s) = %q, want %q", test.delta, got, test.want)
			}
		})
	}
}

func TestRelativeTimeFutureAndSentinel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		instant time.Time
		want    string
	}{
		{name: "zero instant", want: "never"},
		{name: "future minutes", instant: reference.Add(3 * time.Minute), want: "in 3m"},
		{name: "future days", instant: reference.Add(50 * 24 * time.Hour), want: "in 1mo"},
		{name: "sub second future", instant: reference.Add(200 * time.Millisecond), want: "now"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := RelativeTime(test.instant, reference); got != test.want {
				t.Fatalf("RelativeTime = %q, want %q", got, test.want)
			}
		})
	}
	if got := RelativeMicros(0, reference); got != "never" {
		t.Fatalf("RelativeMicros(0) = %q, want never", got)
	}
	if got := RelativeMicros(-5, reference); got != "never" {
		t.Fatalf("RelativeMicros(-5) = %q, want never", got)
	}
}

func TestRelativeStamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "", want: Absent},
		{name: "utc", value: "2026-08-15T11:03:22Z", want: "3h ago"},
		{name: "fractional seconds", value: "2026-08-15T14:03:20.481Z", want: "1s ago"},
		{name: "offset", value: "2026-08-15T10:03:22-04:00", want: "now"},
		{name: "future", value: "2026-08-16T14:03:22Z", want: "in 1d"},
		{name: "unparsable is passed through", value: "yesterday", want: "yesterday"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := RelativeStamp(test.value, reference); got != test.want {
				t.Fatalf("RelativeStamp(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestDurationBuckets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value time.Duration
		want  string
	}{
		{name: "zero", value: 0, want: "0s"},
		{name: "negative", value: -3 * time.Second, want: "-3s"},
		{name: "sub millisecond", value: 500 * time.Microsecond, want: "<1ms"},
		{name: "milliseconds", value: 450 * time.Millisecond, want: "450ms"},
		{name: "one millisecond", value: time.Millisecond, want: "1ms"},
		{name: "fractional seconds", value: 1500 * time.Millisecond, want: "1.5s"},
		{name: "whole seconds trim", value: 9 * time.Second, want: "9s"},
		{name: "minutes and seconds", value: 4*time.Minute + 12*time.Second, want: "4m12s"},
		{name: "whole minutes trim", value: 4 * time.Minute, want: "4m"},
		{name: "hours and minutes", value: 2*time.Hour + 5*time.Minute, want: "2h5m"},
		{name: "whole hours trim", value: 2 * time.Hour, want: "2h"},
		{name: "days and hours", value: 3*24*time.Hour + 4*time.Hour, want: "3d4h"},
		{name: "whole days trim", value: 3 * 24 * time.Hour, want: "3d"},
		{name: "minimum duration", value: math.MinInt64, want: "-106751d23h"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := Duration(test.value); got != test.want {
				t.Fatalf("Duration(%s) = %q, want %q", test.value, got, test.want)
			}
			if test.value > math.MinInt64/1000 && test.value < math.MaxInt64/1000 {
				micros := int64(test.value / time.Microsecond)
				if got := DurationMicros(micros); got != Duration(time.Duration(micros)*time.Microsecond) {
					t.Fatalf("DurationMicros(%d) = %q", micros, got)
				}
			}
		})
	}
}

func TestBytesBuckets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		count int64
		want  string
	}{
		{name: "zero", count: 0, want: "0 B"},
		{name: "bytes", count: 512, want: "512 B"},
		{name: "last byte", count: 1023, want: "1023 B"},
		{name: "one kibibyte", count: 1024, want: "1 KiB"},
		{name: "fractional kibibyte", count: 1536, want: "1.5 KiB"},
		{name: "one mebibyte", count: 1 << 20, want: "1 MiB"},
		{name: "wal size", count: 4299161, want: "4.1 MiB"},
		{name: "one gibibyte", count: 1 << 30, want: "1 GiB"},
		{name: "one tebibyte", count: 1 << 40, want: "1 TiB"},
		{name: "one pebibyte", count: 1 << 50, want: "1 PiB"},
		{name: "one exbibyte", count: 1 << 60, want: "1 EiB"},
		{name: "negative", count: -1024, want: "-1 KiB"},
		{name: "minimum", count: math.MinInt64, want: "-8 EiB"},
		{name: "maximum", count: math.MaxInt64, want: "8 EiB"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := Bytes(test.count); got != test.want {
				t.Fatalf("Bytes(%d) = %q, want %q", test.count, got, test.want)
			}
		})
	}
}

func TestHumanizeOutputIsASCII(t *testing.T) {
	t.Parallel()

	samples := []string{
		Timestamp(reference),
		Timestamp(time.Time{}),
		RelativeTime(reference.Add(-90*time.Minute), reference),
		RelativeTime(reference.Add(90*time.Minute), reference),
		RelativeTime(time.Time{}, reference),
		Duration(500 * time.Microsecond),
		Duration(-3 * time.Second),
		Duration(90 * time.Minute),
		DurationMicros(1234567),
		Bytes(1536),
		Bytes(-4299161),
	}
	for _, sample := range samples {
		for _, symbol := range sample {
			if symbol > 0x7f {
				t.Fatalf("%q contains the non-ASCII rune %U", sample, symbol)
			}
		}
	}
}
