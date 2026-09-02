package cli

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
)

// Blackbird reservations are advisory, and this command does not change that.
//
// A lease is a claim agents agree to respect. Nothing in the daemon can stop a
// process from opening a file, and nothing here does either: this is a local,
// opt-in enforcement layer that a developer or an agent chooses to install into
// their own commit path. It is not filesystem fencing, it grants no isolation,
// and `git commit --no-verify` walks straight past it. What it buys is that a
// claim another agent already made becomes visible at the moment you would
// otherwise overwrite it, in the one place a shared checkout actually collides.
//
// That framing decides every default below. The guard fails OPEN -- an
// unreachable daemon, an unreadable admin credential, a repository the daemon
// has never seen, a path it cannot parse -- because a hook that blocks commits
// when the coordination service is down is a hook people delete, and a deleted
// hook enforces nothing at all. It refuses a commit only when it can name a
// live exclusive holder that is not you.
const (
	leaseGuardOff   = "off"
	leaseGuardWarn  = "warn"
	leaseGuardBlock = "block"

	// leaseGuardMaxReservations bounds the single admin read. A local checkout
	// with more live exclusive leases than this is not a coordination problem
	// this hook can help with.
	leaseGuardMaxReservations = 200
	leaseGuardTimeout         = 3 * time.Second
)

// LeaseGuardCmd refuses a commit that would write a path another agent holds an
// exclusive Blackbird reservation on.
type LeaseGuardCmd struct {
	Paths []string `arg:"" optional:"" name:"path" help:"Repository-relative paths to check. Pre-commit frameworks pass the staged files; with none given, the staged files are read from git."`
	Agent string   `placeholder:"NAME" env:"BLACKBIRD_AGENT_NAME" help:"Your own Blackbird agent name. Leases held under it are yours and never block you."`
	Mode  string   `enum:"auto,off,warn,block" default:"auto" env:"BLACKBIRD_LEASE_GUARD" help:"auto blocks when --agent identifies you and warns when it cannot, because a guard that cannot tell your lease from a teammate's must not refuse your own commit."`
	// Project overrides the repository root. The daemon keys reservations by the
	// project path an agent registered with, which is the repository root.
	Project string `placeholder:"PATH" help:"Project key to check. Defaults to the git repository root."`
}

type leaseGuardConflict struct {
	Path    string `json:"path"`
	Holder  string `json:"holder_agent_name"`
	LeaseID string `json:"lease_id"`
	// Selector is the claim that covers Path, which is not always Path itself:
	// a subtree lease one directory up is the common case and the least
	// obvious, so the report always names what was actually claimed.
	Selector    string `json:"selector"`
	ExpiresInMS int64  `json:"expires_in_ms"`
}

type leaseGuardReport struct {
	Mode      string               `json:"mode"`
	Checked   int                  `json:"checked"`
	Conflicts []leaseGuardConflict `json:"conflicts"`
	// Advisory is always true. It is in the payload so a machine consumer
	// cannot read a clean result as proof that nothing else touched the files.
	Advisory bool `json:"advisory"`
	// Skipped explains a check that did not run, so a permanently silent guard
	// is distinguishable from a permanently clean one.
	Skipped string `json:"skipped,omitempty"`
}

func (cmd *LeaseGuardCmd) Run(ctx context.Context, console *Console) error {
	mode := cmd.resolveMode()
	if mode == leaseGuardOff {
		return console.present(newView(leaseGuardReport{Mode: mode, Advisory: true,
			Skipped: "disabled by --mode/BLACKBIRD_LEASE_GUARD"}, drawLeaseGuard))
	}
	paths, err := cmd.stagedPaths(ctx)
	if err != nil {
		return cmd.skip(console, mode, fmt.Sprintf("could not read staged paths: %v", err))
	}
	if len(paths) == 0 {
		return console.present(newView(leaseGuardReport{Mode: mode, Advisory: true}, drawLeaseGuard))
	}
	project, err := cmd.projectKey(ctx)
	if err != nil {
		return cmd.skip(console, mode, fmt.Sprintf("could not resolve the repository root: %v", err))
	}
	admin, err := console.admin()
	if err != nil {
		// No admin client composed at all. Coordination is simply not
		// configured here; that is not a reason to refuse a commit.
		return cmd.skip(console, mode, "no daemon client is configured")
	}
	lookup, cancel := context.WithTimeout(ctx, leaseGuardTimeout)
	defer cancel()
	page, err := admin.Reservations(lookup, ReservationQuery{
		ProjectKey: project, State: "active", Mode: "exclusive", Limit: leaseGuardMaxReservations,
	})
	if err != nil {
		return cmd.skip(console, mode, fmt.Sprintf("daemon unavailable: %v", err))
	}

	report := leaseGuardReport{Mode: mode, Checked: len(paths), Advisory: true,
		Conflicts: leaseGuardConflicts(paths, page.Reservations, cmd.Agent)}
	if err := console.present(newView(report, drawLeaseGuard)); err != nil {
		return err
	}
	if mode == leaseGuardBlock && len(report.Conflicts) > 0 {
		return withRemedy(fault(ExitError, nil,
			"%d staged path(s) are exclusively reserved by another agent", len(report.Conflicts)),
			"coordinate with the holder, narrow your change, or commit with --no-verify")
	}
	return nil
}

// resolveMode turns auto into a decision. Blocking needs an identity: without
// one every lease looks like someone else's, including your own, and a guard
// that refuses your own commits is one you uninstall within the hour.
func (cmd *LeaseGuardCmd) resolveMode() string {
	switch cmd.Mode {
	case leaseGuardOff, leaseGuardWarn, leaseGuardBlock:
		return cmd.Mode
	default:
		if strings.TrimSpace(cmd.Agent) == "" {
			return leaseGuardWarn
		}
		return leaseGuardBlock
	}
}

// skip reports a check that could not run and always succeeds. Every reason a
// lookup fails is a reason the daemon could not speak, never evidence that the
// commit is unsafe.
func (cmd *LeaseGuardCmd) skip(console *Console, mode, reason string) error {
	return console.present(newView(leaseGuardReport{Mode: mode, Advisory: true, Skipped: reason},
		drawLeaseGuard))
}

func (cmd *LeaseGuardCmd) stagedPaths(ctx context.Context) ([]string, error) {
	if len(cmd.Paths) > 0 {
		return normalizeGuardPaths(cmd.Paths), nil
	}
	output, err := exec.CommandContext(ctx, "git", "diff", "--cached", "--name-only", "--diff-filter=ACMR").Output()
	if err != nil {
		return nil, err
	}
	return normalizeGuardPaths(strings.Split(string(output), "\n")), nil
}

// projectKey resolves the repository identity every agent working on this
// repository shares.
//
// It is the MAIN worktree, never the caller's own. Worktree-per-writer is the
// default here, and `git rev-parse --show-toplevel` answers with the worktree
// you are standing in -- so keying on it would give every agent a private
// project nobody else registers under, and the guard would report "clear"
// forever while agents overwrote each other. `git worktree list` names the main
// worktree first, which is the one identity all of them agree on.
func (cmd *LeaseGuardCmd) projectKey(ctx context.Context) (string, error) {
	if trimmed := strings.TrimSpace(cmd.Project); trimmed != "" {
		return trimmed, nil
	}
	output, err := exec.CommandContext(ctx, "git", "worktree", "list", "--porcelain").Output()
	if err != nil {
		return "", err
	}
	root := mainWorktreePath(string(output))
	if root == "" {
		return "", fmt.Errorf("git reported no repository root")
	}
	// Agents register with the resolved absolute path, so a checkout reached
	// through a symlink must key the same way or every lookup silently misses.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	return root, nil
}

// mainWorktreePath reads the first "worktree" record of `git worktree list
// --porcelain`, which git documents as the main worktree regardless of where
// the command was run.
func mainWorktreePath(listing string) string {
	for _, line := range strings.Split(listing, "\n") {
		if path, found := strings.CutPrefix(strings.TrimSpace(line), "worktree "); found {
			return strings.TrimSpace(path)
		}
	}
	return ""
}

// normalizeGuardPaths cleans and de-duplicates the incoming paths into the
// repository-relative, slash-separated form a lease selector is stored in.
func normalizeGuardPaths(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	paths := make([]string, 0, len(values))
	for _, value := range values {
		cleaned := strings.TrimSpace(value)
		if cleaned == "" {
			continue
		}
		cleaned = filepath.ToSlash(filepath.Clean(cleaned))
		if cleaned == "." || strings.HasPrefix(cleaned, "../") {
			continue
		}
		cleaned = strings.TrimPrefix(cleaned, "./")
		if _, duplicate := seen[cleaned]; duplicate {
			continue
		}
		seen[cleaned] = struct{}{}
		paths = append(paths, cleaned)
	}
	sort.Strings(paths)
	return paths
}

// leaseGuardConflicts pairs each staged path with the first foreign exclusive
// claim covering it. One conflict per path: a path covered by two leases is
// blocked by either, and listing both would pad the message without changing
// what the caller must do.
func leaseGuardConflicts(paths []string, reservations []Reservation, agent string) []leaseGuardConflict {
	own := strings.TrimSpace(agent)
	conflicts := make([]leaseGuardConflict, 0)
	for _, path := range paths {
		for _, reservation := range reservations {
			// Expired leases are reported by the daemon as active until the
			// reaper runs; treating one as a blocker would refuse a commit on a
			// claim its own holder no longer has.
			if reservation.Expired || !strings.EqualFold(reservation.Mode, "exclusive") {
				continue
			}
			if own != "" && reservation.HolderAgentName == own {
				continue
			}
			selector, matched := guardCoveringSelector(reservation, path)
			if !matched {
				continue
			}
			conflicts = append(conflicts, leaseGuardConflict{
				Path: path, Holder: reservation.HolderAgentName, LeaseID: reservation.LeaseID,
				Selector: selector, ExpiresInMS: reservation.ExpiresInMS,
			})
			break
		}
	}
	return conflicts
}

// guardCoveringSelector restates the daemon's overlap rule for the one case a
// commit can present: a staged path is always an exact file, so a claim covers
// it when the claim names that file or names a subtree above it.
//
// The rule lives in internal/application/coordination, which this layer may
// not import. The duplication is pinned instead: TestGuardOverlapMatchesTheDaemon
// compares this against coordination.LeaseSelectorsOverlap over a table, so the
// two cannot drift without failing the build.
func guardCoveringSelector(reservation Reservation, path string) (string, bool) {
	for _, selector := range reservation.Selectors {
		if selector.Path == path {
			return selector.Kind + ":" + selector.Path, true
		}
		if selector.Kind == "subtree" && strings.HasPrefix(path, selector.Path+"/") {
			return selector.Kind + ":" + selector.Path, true
		}
	}
	return "", false
}

func drawLeaseGuard(doc *render.Document, report leaseGuardReport) {
	if report.Skipped != "" {
		doc.Linef(render.RoleMuted, "lease guard skipped: %s", report.Skipped)
		return
	}
	if len(report.Conflicts) == 0 {
		doc.Linef(render.RoleMuted, "lease guard: %d path(s) clear of other agents' exclusive claims", report.Checked)
		return
	}
	role, verb := render.RoleError, "blocking"
	if report.Mode == leaseGuardWarn {
		role, verb = render.RoleWarn, "warning only"
	}
	doc.Linef(role, "lease guard (%s): %d staged path(s) are exclusively reserved by another agent",
		verb, len(report.Conflicts))
	table := render.Table{
		Columns: []render.Column{
			{Title: "PATH"},
			{Title: "HELD BY"},
			{Title: "CLAIM"},
			{Title: "EXPIRES"},
		},
	}
	for _, conflict := range report.Conflicts {
		table.Rows = append(table.Rows, render.Row{Cells: []render.Cell{
			{Text: conflict.Path},
			{Text: guardHolderName(conflict.Holder)},
			{Text: conflict.Selector, Role: render.RoleMuted},
			{Text: guardRemaining(conflict.ExpiresInMS)},
		}})
	}
	doc.Table(table)
	// The advisory line is not decoration. A reader who takes a refusal here as
	// a guarantee will assume a clean run means nobody else touched the files,
	// and that is exactly what an advisory claim cannot promise.
	doc.Line(render.RoleMuted,
		"Reservations are advisory. This hook is a local opt-in check, not file locking.")
}

func guardHolderName(holder string) string {
	if strings.TrimSpace(holder) == "" {
		return "an unnamed agent"
	}
	return holder
}

func guardRemaining(milliseconds int64) string {
	if milliseconds <= 0 {
		return "no time"
	}
	return (time.Duration(milliseconds) * time.Millisecond).Round(time.Second).String()
}
