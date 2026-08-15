package cli

import (
	"errors"
	"strings"
	"testing"
)

// TestGCReportsAVacuumThatDidNotShrinkTheDatabase covers the real maintenance
// port: vacuuming an already compact database can add a page, and the report
// used to render that as "reclaimed -4 KiB".
func TestGCReportsAVacuumThatDidNotShrinkTheDatabase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		reclaimed Reclaimed
		want      string
	}{
		{
			name:      "database grew by a page",
			reclaimed: Reclaimed{BeforeBytes: 1 << 20, AfterBytes: 1<<20 + 4096},
			want:      "reclaimed nothing",
		},
		{
			name:      "write-ahead log truncated",
			reclaimed: Reclaimed{BeforeBytes: 1 << 20, AfterBytes: 1 << 19},
			want:      "reclaimed 512 KiB",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			deps := dependencies(t)
			deps.Store = &fakeStore{database: healthyDatabase()}
			deps.Admin = &fakeAdmin{err: errors.New("connection refused")}
			deps.Maintenance = &fakeMaintenance{reclaimed: test.reclaimed}

			result := runCLI(t, deps, []string{"gc", "--vacuum"})
			if result.code != ExitOK {
				t.Fatalf("code = %d; stderr=%q", result.code, result.stderr)
			}
			if !strings.Contains(result.stdout, test.want) {
				t.Fatalf("stdout = %q, want %q", result.stdout, test.want)
			}
			if strings.Contains(result.stdout, "reclaimed -") {
				t.Fatalf("stdout = %q, want no negative byte count", result.stdout)
			}
		})
	}
}
