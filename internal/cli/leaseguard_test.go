package cli

import (
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/adminapi"
	// The guard restates the daemon's overlap rule because internal/cli may not
	// import internal/application. Test files are exempt from the layer rules,
	// which is what lets the duplication be pinned rather than merely reviewed.
	"github.com/phall1/blackbird/internal/application"
)

func guardReservation(holder, mode string, expired bool, selectors ...adminapi.Selector) Reservation {
	return Reservation{
		LeaseID: "lease-" + holder, HolderAgentName: holder, Mode: mode,
		State: "active", Expired: expired, Selectors: selectors, ExpiresInMS: 600_000,
	}
}

func exact(path string) adminapi.Selector   { return adminapi.Selector{Kind: "exact", Path: path} }
func subtree(path string) adminapi.Selector { return adminapi.Selector{Kind: "subtree", Path: path} }

func guardDeps(t *testing.T, reservations []Reservation) Dependencies {
	t.Helper()
	deps := dependencies(t)
	deps.Admin = &fakeAdmin{reservations: reservations}
	return deps
}

// The headline case, and the one that actually happened: an agent holds a file
// exclusively and someone else stages it.
func TestLeaseGuardBlocksAPathHeldByAnotherAgent(t *testing.T) {
	deps := guardDeps(t, []Reservation{
		guardReservation("rollups-5d", "exclusive", false, exact("internal/transport/mcp/mcp.go")),
	})
	result := runCLI(t, deps, []string{"lease-guard", "--project", "/repo", "--agent", "other-agent",
		"internal/transport/mcp/mcp.go"})
	if result.code != ExitError {
		t.Fatalf("exit=%d, want %d; a foreign exclusive claim must refuse the commit", result.code, ExitError)
	}
	combined := result.stdout + result.stderr
	if !strings.Contains(combined, "rollups-5d") {
		t.Fatalf("output must name the holder so the caller can coordinate:\n%s", combined)
	}
	// The refusal has to keep saying what it is, or a reader takes it for
	// locking and trusts a clean run as proof of exclusivity.
	if !strings.Contains(combined, "advisory") && !strings.Contains(combined, "Reservations are advisory") {
		t.Fatalf("output must restate that reservations are advisory:\n%s", combined)
	}
}

// A subtree lease one directory up is the least obvious way to be blocked, so
// the report names the claim rather than only the path.
func TestLeaseGuardBlocksUnderASubtreeClaimAndNamesIt(t *testing.T) {
	deps := guardDeps(t, []Reservation{
		guardReservation("owner", "exclusive", false, subtree("internal/storage")),
	})
	result := runCLI(t, deps, []string{"lease-guard", "--project", "/repo", "--agent", "me",
		"internal/storage/sqlite/telemetry.go"})
	if result.code != ExitError {
		t.Fatalf("exit=%d, want a refusal under a subtree claim", result.code)
	}
	if !strings.Contains(result.stdout+result.stderr, "subtree:internal/storage") {
		t.Fatalf("output must name the covering claim:\n%s", result.stdout+result.stderr)
	}
}

func TestLeaseGuardIgnoresYourOwnLease(t *testing.T) {
	deps := guardDeps(t, []Reservation{
		guardReservation("me", "exclusive", false, exact("internal/cli/leaseguard.go")),
	})
	result := runCLI(t, deps, []string{"lease-guard", "--project", "/repo", "--agent", "me",
		"internal/cli/leaseguard.go"})
	if result.code != ExitOK {
		t.Fatalf("exit=%d, want your own claim to pass", result.code)
	}
}

// Shared leases coexist by definition; only exclusive ones conflict.
func TestLeaseGuardIgnoresSharedAndExpiredClaims(t *testing.T) {
	deps := guardDeps(t, []Reservation{
		guardReservation("reader", "shared", false, exact("a.go")),
		guardReservation("ghost", "exclusive", true, exact("b.go")),
	})
	result := runCLI(t, deps, []string{"lease-guard", "--project", "/repo", "--agent", "me", "a.go", "b.go"})
	if result.code != ExitOK {
		t.Fatalf("exit=%d, want shared and expired claims to pass", result.code)
	}
}

// Blocking needs an identity. Without one, every lease looks foreign -- your
// own included -- so the guard warns instead of refusing your own commit.
func TestLeaseGuardWarnsRatherThanBlocksWithoutAnAgentName(t *testing.T) {
	deps := guardDeps(t, []Reservation{
		guardReservation("someone", "exclusive", false, exact("a.go")),
	})
	result := runCLI(t, deps, []string{"lease-guard", "--project", "/repo", "a.go"})
	if result.code != ExitOK {
		t.Fatalf("exit=%d, want a warning when the guard cannot tell whose lease it is", result.code)
	}
	if !strings.Contains(result.stdout+result.stderr, "warning only") {
		t.Fatalf("output must say it is only warning:\n%s", result.stdout+result.stderr)
	}
}

func TestLeaseGuardModeOverridesTheDefault(t *testing.T) {
	reservations := []Reservation{guardReservation("someone", "exclusive", false, exact("a.go"))}
	warn := runCLI(t, guardDeps(t, reservations),
		[]string{"lease-guard", "--project", "/repo", "--agent", "me", "--mode", "warn", "a.go"})
	if warn.code != ExitOK {
		t.Fatalf("warn exit=%d, want 0", warn.code)
	}
	off := runCLI(t, guardDeps(t, reservations),
		[]string{"lease-guard", "--project", "/repo", "--mode", "off", "a.go"})
	if off.code != ExitOK || !strings.Contains(off.stdout+off.stderr, "skipped") {
		t.Fatalf("off exit=%d output=%q, want a skipped check", off.code, off.stdout+off.stderr)
	}
}

// The advisory posture in its most load-bearing form: a hook that blocks
// commits when the daemon is down is a hook people delete, and a deleted hook
// enforces nothing.
func TestLeaseGuardFailsOpenWhenTheDaemonIsUnavailable(t *testing.T) {
	deps := dependencies(t)
	deps.Admin = &fakeAdmin{err: &AdminStatusError{Status: 503, Path: "/reservations"}}
	result := runCLI(t, deps, []string{"lease-guard", "--project", "/repo", "--agent", "me", "a.go"})
	if result.code != ExitOK {
		t.Fatalf("exit=%d, want the guard to fail open when the daemon cannot answer", result.code)
	}
	if !strings.Contains(result.stdout+result.stderr, "skipped") {
		t.Fatalf("a skipped check must say so rather than look clean:\n%s", result.stdout+result.stderr)
	}
}

func TestLeaseGuardFailsOpenWithNoAdminClient(t *testing.T) {
	result := runCLI(t, dependencies(t), []string{"lease-guard", "--project", "/repo", "a.go"})
	if result.code != ExitOK {
		t.Fatalf("exit=%d, want an unconfigured guard to pass", result.code)
	}
}

func TestLeaseGuardQueriesOnlyActiveExclusiveLeasesForTheProject(t *testing.T) {
	admin := &fakeAdmin{}
	deps := dependencies(t)
	deps.Admin = admin
	runCLI(t, deps, []string{"lease-guard", "--project", "/repo", "--agent", "me", "a.go"})
	query := admin.reservationQuery
	if query.ProjectKey != "/repo" || query.State != "active" || query.Mode != "exclusive" {
		t.Fatalf("query=%+v, want the project's active exclusive leases only", query)
	}
}

func TestNormalizeGuardPathsCleansAndDeduplicates(t *testing.T) {
	got := normalizeGuardPaths([]string{"  b.go ", "./a.go", "a.go", "", "dir/../a.go", "../outside.go", "."})
	want := []string{"a.go", "b.go"}
	if len(got) != len(want) {
		t.Fatalf("paths=%v, want %v", got, want)
	}
	for index, value := range want {
		if got[index] != value {
			t.Fatalf("paths=%v, want %v", got, want)
		}
	}
}

// The guard restates the daemon's overlap rule because the layer boundary
// forbids importing it. This is what keeps the restatement honest: the two
// implementations are compared over the shapes a commit can present, so they
// cannot drift apart without failing the build.
func TestGuardOverlapMatchesTheDaemon(t *testing.T) {
	selectors := []adminapi.Selector{
		exact("a.go"),
		exact("internal/cli/leaseguard.go"),
		subtree("internal"),
		subtree("internal/cli"),
		subtree("internal/clifoo"),
	}
	paths := []string{
		"a.go", "ab.go", "internal/cli/leaseguard.go", "internal/cli", "internal",
		"internal/clifoo/x.go", "internalx/y.go", "other/a.go",
	}
	overlaps, disjoint := 0, 0
	for _, selector := range selectors {
		for _, path := range paths {
			staged, err := application.NewLeaseSelector(
				application.LeaseSelectorExact, path)
			if err != nil {
				t.Fatalf("build staged selector %q: %v", path, err)
			}
			held, err := application.NewLeaseSelector(
				application.LeaseSelectorKind(selector.Kind), selector.Path)
			if err != nil {
				t.Fatalf("build held selector %+v: %v", selector, err)
			}
			want := application.LeaseSelectorsOverlap(held, staged)
			_, got := guardCoveringSelector(
				Reservation{Selectors: []adminapi.Selector{selector}}, path)
			if got != want {
				t.Fatalf("selector %s:%s vs path %q: guard=%v daemon=%v",
					selector.Kind, selector.Path, path, got, want)
			}
			if want {
				overlaps++
			} else {
				disjoint++
			}
		}
	}
	// Two implementations that both always answer false agree perfectly and
	// prove nothing, so the table has to exercise both answers.
	if overlaps == 0 || disjoint == 0 {
		t.Fatalf("table produced %d overlaps and %d non-overlaps; it must exercise both", overlaps, disjoint)
	}
}
