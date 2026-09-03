// Package ledger tails the usage ledgers agent harnesses already write to
// disk, and turns what it finds into observations on Blackbird's observation
// plane (ADR-0001).
//
// Why a daemon-side tail rather than another harness plugin.
//
// The two producers that came first -- the OpenCode plugin and the Pi
// extension -- push from inside the harness. That only ever captures a session
// where the plugin was loaded and the daemon was up, and it needs a plugin API
// per harness, which most harnesses do not have. The ledgers, meanwhile, are
// already complete on disk: a transcript records every call whether or not
// Blackbird was running when it happened. So a tail sees history, survives the
// daemon being down, and costs one small adapter per harness instead of one
// extension project per harness.
//
// The cost of adding a second mechanism is that two of them can observe the
// same turn. That is settled structurally rather than by convention, in
// application/telemetry's Sink.Offer: ownership is partitioned per harness and
// the sink drops pushed model calls for a harness this daemon collects. Read
// internal/application/telemetry/collection.go for the argument; nothing in
// this package is entitled to assume it instead.
//
// The shape here is deliberately thin at the adapter and thick in the shared
// machinery, because the next eight harnesses should cost one Decode function
// each. The framework owns recursive discovery, per-file byte offsets, the
// partial-last-line carry, truncation and replacement, in-pass dedupe, every
// bound, and the durable cursor file. An Adapter owns exactly two facts: which
// files are its ledgers, and how to read one line.
//
// The second adapter added one thing to that list, and it is worth naming
// rather than absorbing. Claude Code repeats the workspace and the model on
// every record that carries usage, so its lines are self-describing and the
// framework never had to remember anything about a file except how far into it
// it had read. Codex writes those facts once, in a session header, and then
// emits bare token counts -- so an adapter for it needs a fact established by
// an earlier line. ContextualAdapter is that, and the carried value is kept in
// the cursor beside the byte offset rather than in the adapter, so the two are
// lost and recovered together and there is no resume that holds one without the
// other. It stayed an optional interface so the self-describing case did not
// grow a parameter it would always ignore.
package ledger

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	// DefaultMaxLineBytes bounds one line held in memory. A transcript line
	// carries whole message content and is routinely megabytes; the usage
	// object inside it never is. A line over the bound is consumed and skipped
	// rather than buffered, so a single enormous record cannot decide this
	// daemon's resident size.
	DefaultMaxLineBytes = 1 << 20
	// DefaultMaxRecordsPerPass bounds one pass's output. A first pass over
	// months of history finds tens of thousands of calls; posting them all at
	// once would fill the sink's queue and drop most of them. The watermark
	// makes the remainder the next pass's work, which is what a watermark is
	// for.
	DefaultMaxRecordsPerPass = 2048
	// DefaultMaxFilesPerPass bounds how many files one pass READS. A ledger
	// tree grows one directory per project and one file per session and is
	// never pruned, so a machine years into a harness can hold far more than
	// this. The bound is a deferral rather than a cap: discovery sees the whole
	// tree, the read window starts after the file the previous pass finished
	// on, and it wraps -- so every file is reached within ceil(N/bound) passes.
	// An earlier version stopped the walk at this count, which made the bound
	// permanent starvation instead: walk order is deterministic, so the same
	// lexically-first files were read every pass and everything past them was
	// never read at all.
	DefaultMaxFilesPerPass = 1024
	// DefaultMaxFilesTracked is the memory guard on discovery, and it is
	// deliberately far above any operating limit: it exists so a pathological
	// tree cannot decide this daemon's resident size, not to ration work. Only
	// past this does discovery truncate, and only then is cursor pruning
	// skipped -- because pruning against a partial view of the tree would throw
	// away the watermark of every file it did not reach.
	DefaultMaxFilesTracked = 65536
	// DefaultMaxBytesPerPass bounds the reading itself, independently of how
	// many records that reading yields. A file of lines this adapter does not
	// understand would otherwise be unbounded work at zero output.
	DefaultMaxBytesPerPass = 64 << 20
	// DefaultMaxWalkDepth bounds recursion: finite for a tree with a symlink
	// loop in it, and generous enough that a harness deepening its layout does
	// not silently stop being observed.
	//
	// The number is not arbitrary and the margin is the point. Claude Code's
	// live tree already reaches
	// <project>/<session>/subagents/workflows/<workflow>/<agent>.jsonl -- six
	// levels -- so the previous value of 6 sat exactly on the deepest thing it
	// writes, and one more nesting level would have dropped every file below it
	// with nothing in any counter to say so. Pair this with Pass.DepthSkipped,
	// which is what makes the bound observable rather than silent.
	DefaultMaxWalkDepth = 12
	// DefaultMaxSeenKeys bounds the in-pass duplicate set. A harness may write
	// the same call several times -- Claude Code writes one transcript record
	// per content block of a single API message, so a real transcript holds
	// roughly twice as many usage records as calls -- and collapsing them here
	// halves the write volume. Past the bound the set stops growing and dedupe
	// falls back to the store's unique index on (actor, dedupe key), which is
	// the durable guarantee either way.
	DefaultMaxSeenKeys = 16384
	// MaxFileContextBytes bounds the per-file context a ContextualAdapter
	// carries. It is generous for a session header -- a model name, a provider,
	// a session id -- and finite, so a ledger cannot decide how large this
	// daemon's cursor file grows. A longer value is ignored rather than
	// truncated: half a context is worse than none, because the adapter would
	// read it back as though it were whole.
	MaxFileContextBytes = 1024
	// envelopeSize keeps one offered envelope inside the plane's own per
	// envelope bound, so a collected batch costs the drain no more than a
	// pushed one.
	envelopeSize = telemetry.MaxEventsPerEnvelope
)

// Record is one observation an Adapter read out of one line.
type Record struct {
	// Call is the normalized observation. Its DedupeKey must be the harness's
	// own stable identifier for the call whenever one exists: that key is what
	// makes re-reading a line harmless, and it is the reason an imprecise
	// watermark is an acceptable design rather than a bug.
	Call domain.ModelCall
	// ProjectKey is the workspace the call happened in, as the ledger reports
	// it. An empty value means this line did not say, and the collector falls
	// back to the project key it has already pinned for this file.
	ProjectKey string
	// Context is per-file state this adapter wants carried forward to the lines
	// after this one, and persisted in the cursor so it survives a restart. It
	// is opaque to the framework, bounded by MaxFileContextBytes, and only ever
	// read back by the adapter that wrote it.
	//
	// It exists because a ledger's observation lines are not always
	// self-describing. Claude Code repeats cwd and model on every usage record,
	// so its adapter needs none of this. Codex writes each of those exactly
	// once, in a session_meta header, and then emits bare token_count events for
	// the rest of the file -- so without a carry the model is unknowable and
	// every record fails validation.
	//
	// Empty means "no change": the previous context stands. That is deliberately
	// last-writer-wins, unlike ProjectKey's first-writer-wins pin, because the
	// two answer different questions. Attribution must not drift across a
	// session; the model genuinely can change mid-session and the later value is
	// the right one.
	Context string
}

// Adapter is the whole per-harness surface. Two methods, both pure: the
// framework does every side effect, so an adapter is testable against a byte
// slice and a path and nothing else.
type Adapter interface {
	// Harness names the producer. It decides the ownership partition, so it
	// must be the same value the harness's push adapter reports.
	Harness() domain.Harness
	// Ledger reports whether a discovered file is one this adapter reads. It
	// is given the path and the walk entry so an adapter can match on name,
	// extension, or position in the tree without a stat of its own.
	Ledger(path string, entry fs.DirEntry) bool
	// Decode maps one complete line to one observation:
	//
	//	(record, true, nil)  a usage record
	//	(_, false, nil)      a line this adapter does not observe -- the common
	//	                     case, and not a fault
	//	(_, false, err)      a line that should have been readable and was not;
	//	                     counted as malformed, logged once per pass, skipped
	//
	// It must never panic and must never retain the slice it is given.
	Decode(line []byte) (Record, bool, error)
}

// ContextualAdapter is an optional Adapter capability, for the ledger whose
// observation lines do not carry everything an observation needs.
//
// It is optional rather than folded into Adapter so that an adapter whose lines
// ARE self-describing stays exactly as simple as it was: Claude Code's reads a
// line and nothing else, and adding a parameter it would always ignore would
// have made every future adapter pay for one harness's shape. The framework
// checks for this interface once, at composition.
//
// The carried value is the adapter's own, persisted beside that file's byte
// watermark, so the two are lost and recovered together: a cursor that survives
// carries the context that describes the offset it points at, and a cursor that
// does not sends the file back to offset zero, where the header line that
// establishes the context is read again. There is no state in which the
// framework resumes mid-file holding a watermark but no context.
type ContextualAdapter interface {
	Adapter
	// DecodeInContext is Decode given the context this adapter last returned
	// for this file, empty before it has returned one. It has Decode's contract
	// otherwise, and may return a Record with ok false purely to carry context
	// or attribution forward from a line that is not itself an observation.
	DecodeInContext(line []byte, fileContext string) (Record, bool, error)
}

// Probe reports what this collector found on this machine, in the vocabulary
// the Homebrew updater established: a machine without the harness installed is
// SUPPORTED-but-absent rather than degraded. A daemon on a workstation that has
// never run Claude Code is a healthy daemon, and a warning there would be
// permanent and unactionable.
type Probe struct {
	Harness domain.Harness
	// Root is the directory this collector walks, empty when there is none.
	Root string
	// Present says a root was located and exists. When it is false, Reason
	// says why in one clause fit for an operator to read.
	Present bool
	Reason  string
}

// Pass is one collection cycle's body-free audit record. It carries counts and
// paths and never a byte of ledger content, for the reason the beads adapter
// keeps a body-free transcript: an audit record that quotes the thing it is
// auditing becomes a second copy of it, with none of the bounds.
type Pass struct {
	Harness domain.Harness
	// FilesSeen is every ledger file discovered; FilesRead is the subset that
	// had new bytes. In steady state FilesRead is near zero and no file is
	// opened at all, which is the property that makes polling cheap.
	FilesSeen int
	// FilesWindow is the subset of FilesSeen this pass was allowed to read.
	// It is smaller than FilesSeen only when discovery exceeded the per-pass
	// file bound, and the window rotates, so a file outside it is deferred to
	// a later pass rather than starved.
	FilesWindow  int
	FilesRead    int
	BytesRead    int64
	LinesScanned int
	Observed     int
	Duplicates   int
	// Restatements counts records the harness rewrote with MORE output than an
	// earlier record carrying the same dedupe key. They are re-offered rather
	// than collapsed, because the earlier record was a partial snapshot of a
	// call still being written and the later one is the whole of it. See the
	// note on scan's duplicate handling; this counter is the only external
	// evidence that the mechanism is working.
	Restatements int
	Malformed    int
	Oversize     int
	Offered      int
	// Dropped counts observations refused by the sink because its queue was
	// full. It is TRANSIENT: the watermark rewinds and the next pass offers
	// them again.
	Dropped int
	// Unattributed counts observations discarded because no ledger line named
	// a workspace, or because the collector identity could not be derived. It
	// is PERMANENT: the watermark advances past them and no later pass will
	// retry, so it must not share a counter with Dropped. A rising
	// Unattributed and a rising Dropped call for opposite responses --
	// the first is a mapping bug, the second is backpressure.
	Unattributed int
	Restarted    int
	// DepthSkipped counts directories the walk refused to descend into
	// because they sat at the depth bound. It exists because the bound was
	// silent: a harness that nests one level deeper than it used to would drop
	// every file below with no counter anywhere to say so.
	DepthSkipped   int
	LimitReached   string
	StartedAt      time.Time
	Duration       time.Duration
	CursorsPruned  int
	CursorSaveFail bool
}

// Config composes a collector. Every bound has a default, and every default is
// finite: a collector with a zero Config is bounded, not unbounded.
type Config struct {
	Adapter Adapter
	// Root is the directory to walk. Composition supplies it rather than the
	// adapter discovering it, so a test names a temporary directory and asserts
	// the same thing on a workstation that runs the harness and one that does
	// not. This is the injected-detection precedent the Homebrew updater set.
	Root string
	// StatePath is where cursors are kept between runs. Empty is allowed and
	// means in-memory cursors: a restart then re-reads, which the store's
	// dedupe index makes correct and merely wasteful.
	StatePath string
	Ingest    telemetry.Ingest
	Logger    *slog.Logger
	Now       func() time.Time

	MaxLineBytes      int
	MaxRecordsPerPass int
	MaxFilesPerPass   int
	MaxFilesTracked   int
	MaxBytesPerPass   int64
	MaxWalkDepth      int
	MaxSeenKeys       int
}

func (config Config) withDefaults() Config {
	if config.MaxLineBytes <= 0 {
		config.MaxLineBytes = DefaultMaxLineBytes
	}
	if config.MaxRecordsPerPass <= 0 {
		config.MaxRecordsPerPass = DefaultMaxRecordsPerPass
	}
	if config.MaxFilesPerPass <= 0 {
		config.MaxFilesPerPass = DefaultMaxFilesPerPass
	}
	if config.MaxFilesTracked <= 0 {
		config.MaxFilesTracked = DefaultMaxFilesTracked
	}
	if config.MaxFilesTracked < config.MaxFilesPerPass {
		// A tracking ceiling below the read window would make the window
		// unreachable and reintroduce the starvation it exists to prevent.
		config.MaxFilesTracked = config.MaxFilesPerPass
	}
	if config.MaxBytesPerPass <= 0 {
		config.MaxBytesPerPass = DefaultMaxBytesPerPass
	}
	if config.MaxWalkDepth <= 0 {
		config.MaxWalkDepth = DefaultMaxWalkDepth
	}
	if config.MaxSeenKeys <= 0 {
		config.MaxSeenKeys = DefaultMaxSeenKeys
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.DiscardHandler)
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return config
}

// cursor is one file's watermark. Size is kept beside Offset so a pass can
// decide, from a stat alone, that a file has nothing new -- and so a file that
// shrank is recognized as replaced rather than read from a nonsense position.
type cursor struct {
	Offset     int64  `json:"offset"`
	Size       int64  `json:"size"`
	ProjectKey string `json:"project_key,omitempty"`
	// Context is the adapter's carry for this file. It rides with the offset on
	// purpose: an offset without the context that describes it would be a
	// watermark pointing into a file the adapter can no longer read.
	Context  string `json:"context,omitempty"`
	SeenAtUS int64  `json:"seen_at_us"`
}

type cursorFile struct {
	Version int               `json:"version"`
	Harness string            `json:"harness"`
	Cursors map[string]cursor `json:"cursors"`
	// ResumeAfter is the last path the previous pass's read window covered. It
	// is what makes the per-pass file bound a deferral rather than starvation,
	// and it is persisted for the same reason the offsets are: a daemon that
	// restarts every hour on a tree larger than one window would otherwise read
	// the same prefix forever. Absent in a cursor file written before rotation
	// existed, which simply starts the next window at the beginning.
	ResumeAfter string `json:"resume_after,omitempty"`
}

const cursorFileVersion = 1

// Collector tails one harness's ledger tree. It is not safe for concurrent
// use: one goroutine polls it, which is all the observation plane needs.
type Collector struct {
	config  Config
	cursors map[string]cursor
	loaded  bool
	// resumeAfter rotates the read window. See cursorFile.ResumeAfter.
	resumeAfter string
	// contextual is the adapter again when it carries per-file state, and nil
	// when it does not. Resolved once at composition so the hot path does not
	// pay a type assertion per line.
	contextual ContextualAdapter
}

func New(config Config) (*Collector, error) {
	config = config.withDefaults()
	if config.Adapter == nil {
		return nil, errors.New("ledger collector needs an adapter")
	}
	if !config.Adapter.Harness().Valid() {
		return nil, fmt.Errorf("ledger collector adapter reports unknown harness %q", config.Adapter.Harness())
	}
	if config.Ingest == nil {
		return nil, errors.New("ledger collector needs an ingest port")
	}
	contextual, _ := config.Adapter.(ContextualAdapter)
	return &Collector{config: config, cursors: make(map[string]cursor), contextual: contextual}, nil
}

// decode routes one line to whichever of the two adapter shapes was composed.
func (collector *Collector) decode(line []byte, fileContext string) (Record, bool, error) {
	if collector.contextual != nil {
		return collector.contextual.DecodeInContext(line, fileContext)
	}
	return collector.config.Adapter.Decode(line)
}

func (collector *Collector) Harness() domain.Harness { return collector.config.Adapter.Harness() }

// Probe reports whether this machine has the tree this collector reads. It
// never fails: absence is the answer, not an error.
func (collector *Collector) Probe() Probe {
	probe := Probe{Harness: collector.Harness(), Root: collector.config.Root}
	probe.Present, probe.Reason = RootPresent(collector.config.Root)
	return probe
}

// RootPresent answers whether a ledger tree is actually readable at root, and
// says why in one operator-readable clause when it is not.
//
// It is exported because composition has to ask the question BEFORE a collector
// exists. The observation plane partitions ownership per harness -- a harness
// this daemon collects has its pushed model calls dropped -- and that partition
// has to be settled when the sink is built, which is upstream of every
// collector. Asking it through one function is what keeps the claim "we collect
// this harness" and the evidence for it from drifting apart.
func RootPresent(root string) (present bool, reason string) {
	if root == "" {
		return false, "no ledger directory is configured for this harness on this machine"
	}
	info, err := os.Stat(root)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, "the harness has not run on this machine, so it has written no ledger directory"
	case err != nil:
		return false, "the ledger directory could not be read on this machine"
	case !info.IsDir():
		return false, "the configured ledger path is not a directory"
	default:
		return true, ""
	}
}

// Collect runs one pass and reports what it did. The error return is for a
// caller that wants to log; a caller that ignores it is behaving correctly,
// because there is no failure here that anything should act on.
// The returns are named so the deferred duration lands in the value the caller
// receives. With an unnamed result the defer writes to a local the return
// statement has already copied, and every pass reports a duration of zero --
// which is exactly what a live run of this collector reported before the names
// were added.
func (collector *Collector) Collect(ctx context.Context) (pass Pass, err error) {
	pass = Pass{Harness: collector.Harness(), StartedAt: collector.config.Now()}
	defer func() { pass.Duration = collector.config.Now().Sub(pass.StartedAt) }()

	probe := collector.Probe()
	if !probe.Present {
		return pass, nil
	}
	collector.loadCursors()

	found, overflowed, err := collector.discover(ctx, &pass)
	if err != nil {
		return pass, err
	}
	window, deferred := collector.window(found)
	pass.FilesWindow = len(window)
	seen := make(map[string]uint64, 64)
	for _, path := range window {
		if ctx.Err() != nil {
			pass.LimitReached = "context"
			break
		}
		if pass.LimitReached != "" {
			break
		}
		collector.readFile(ctx, path, seen, &pass)
	}
	// A deferred remainder is reported only after the files this pass DID
	// cover have been read. Reporting it earlier would make the read loop's own
	// limit-reached check abandon the pass before it read anything, so a tree
	// over the file bound would walk every interval and collect nothing.
	if deferred && pass.LimitReached == "" {
		pass.LimitReached = "files"
	}
	// Pruning is skipped only when discovery itself overflowed its memory
	// guard. Then, and only then, the set in hand is a partial view of the
	// tree, and treating it as the whole would throw away the watermark of
	// every file it did not reach -- turning a bound into a full re-read.
	// A merely deferred window is NOT a partial view: discovery saw everything.
	if !overflowed {
		live := make(map[string]struct{}, len(found))
		for _, path := range found {
			live[path] = struct{}{}
		}
		pass.CursorsPruned = collector.prune(live)
	}
	collector.saveCursors(&pass)
	return pass, nil
}

// window selects the files this pass reads, starting after the one the previous
// pass finished on and wrapping at the end. Rotation is what turns the per-pass
// file bound into a deferral: with a fixed start the same lexical prefix would
// be read on every pass forever and everything past it would never be read at
// all, which is the behaviour this replaced.
func (collector *Collector) window(found []string) (window []string, deferred bool) {
	if len(found) == 0 {
		collector.resumeAfter = ""
		return nil, false
	}
	if len(found) <= collector.config.MaxFilesPerPass {
		collector.resumeAfter = ""
		return found, false
	}
	// SearchStrings gives the first path >= resumeAfter; a hit means that exact
	// file was covered last pass, so the window opens after it.
	start := sort.SearchStrings(found, collector.resumeAfter)
	if start < len(found) && found[start] == collector.resumeAfter {
		start++
	}
	if start >= len(found) {
		start = 0
	}
	window = make([]string, 0, collector.config.MaxFilesPerPass)
	for offset := range collector.config.MaxFilesPerPass {
		window = append(window, found[(start+offset)%len(found)])
	}
	collector.resumeAfter = window[len(window)-1]
	return window, true
}

// discover walks the tree once, bounded in depth and in retained paths, and
// returns every ledger file in it in sorted order. The sort is a total order
// independent of the walk's own, so the rotating read window has a stable
// sequence to advance through.
//
// The second return says the memory guard truncated the walk, which is the only
// condition under which the result is a PARTIAL view of the tree and therefore
// unsafe to prune against. Exceeding the per-pass read bound is a different
// thing entirely and is decided by window, not here.
func (collector *Collector) discover(ctx context.Context, pass *Pass) ([]string, bool, error) {
	root := filepath.Clean(collector.config.Root)
	depthOf := func(path string) int {
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." {
			return 0
		}
		return strings.Count(relative, string(filepath.Separator)) + 1
	}
	files := make([]string, 0, 64)
	overflowed := false
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree is ordinary: another user's directory, a
			// file removed between the readdir and the stat. Skip it and keep
			// walking rather than abandoning every other project's ledger.
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if path == root {
				return nil
			}
			if strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			if depthOf(path) >= collector.config.MaxWalkDepth {
				// Counted, not silent. The bound is a guard against a symlink
				// loop, and a guard that fires on a legitimate layout must be
				// visible or it becomes an unexplained gap in the numbers.
				pass.DepthSkipped++
				return fs.SkipDir
			}
			return nil
		}
		// Only regular files. A symlink is not followed: following one turns a
		// bounded walk into an unbounded one and lets anything outside the tree
		// decide what this daemon reads.
		if !entry.Type().IsRegular() {
			return nil
		}
		if !collector.config.Adapter.Ledger(path, entry) {
			return nil
		}
		files = append(files, path)
		if len(files) >= collector.config.MaxFilesTracked {
			overflowed = true
			return fs.SkipAll
		}
		return nil
	})
	sort.Strings(files)
	pass.FilesSeen = len(files)
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return files, overflowed, fmt.Errorf("walk %s ledger tree: %w", collector.Harness(), walkErr)
	}
	return files, overflowed, nil
}

// readFile reads one file's new bytes. Every early return leaves the cursor
// where it was, so the next pass retries the same bytes -- which is safe
// because the dedupe key is the harness's own, not this file's position.
func (collector *Collector) readFile(ctx context.Context, path string, seen map[string]uint64, pass *Pass) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	mark := collector.cursors[path]
	switch {
	case mark.Offset > info.Size():
		// The file shrank: the harness replaced or rotated it. Anything already
		// stored keeps its dedupe key, so re-reading from the start costs
		// writes that collapse rather than rows that duplicate.
		mark = cursor{ProjectKey: mark.ProjectKey, Context: mark.Context}
		pass.Restarted++
	case mark.Offset == info.Size():
		// The steady state, and the reason polling is nearly free: a file that
		// has not grown is never opened.
		mark.Size = info.Size()
		mark.SeenAtUS = collector.config.Now().UnixMicro()
		collector.cursors[path] = mark
		return
	}
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Seek(mark.Offset, io.SeekStart); err != nil {
		return
	}
	pass.FilesRead++
	collector.scan(ctx, file, path, &mark, seen, pass)
	mark.Size = info.Size()
	mark.SeenAtUS = collector.config.Now().UnixMicro()
	collector.cursors[path] = mark
}

// scan reads complete lines from the current offset, advancing the watermark
// only past lines it finished with.
func (collector *Collector) scan(ctx context.Context, file *os.File, path string,
	mark *cursor, seen map[string]uint64, pass *Pass) {
	reader := bufio.NewReaderSize(file, 64<<10)
	batch := make([]domain.ModelCall, 0, envelopeSize)
	projectKey := mark.ProjectKey
	fileContext := mark.Context
	// settled is the offset every record before it has been handed to the
	// plane from. A refused batch rewinds to it, so the watermark never runs
	// ahead of what was actually delivered and a full sink costs a re-read
	// rather than an observation.
	settled := mark.Offset
	flush := func() bool {
		if len(batch) == 0 {
			settled = mark.Offset
			return true
		}
		delivered := collector.offer(projectKey, batch, pass)
		batch = batch[:0]
		if !delivered {
			mark.Offset = settled
			return false
		}
		settled = mark.Offset
		return true
	}
	for {
		if pass.LinesScanned%256 == 0 && ctx.Err() != nil {
			pass.LimitReached = "context"
			break
		}
		if pass.Observed >= collector.config.MaxRecordsPerPass {
			pass.LimitReached = "records"
			break
		}
		if pass.BytesRead >= collector.config.MaxBytesPerPass {
			pass.LimitReached = "bytes"
			break
		}
		line, consumed, complete, oversize, err := readLine(reader, collector.config.MaxLineBytes)
		if consumed == 0 || !complete {
			// A trailing fragment is a record still being written. Leaving the
			// watermark before it is what makes the carry work: the next pass
			// reads the line whole instead of decoding half of it.
			break
		}
		pass.BytesRead += consumed
		pass.LinesScanned++
		mark.Offset += consumed
		if err != nil && !errors.Is(err, io.EOF) {
			break
		}
		if oversize {
			pass.Oversize++
			continue
		}
		record, ok, decodeErr := collector.decode(line, fileContext)
		if decodeErr != nil {
			pass.Malformed++
			continue
		}
		// Attribution and context are taken BEFORE the observation check, so a
		// header line can establish where a session ran and what answered it
		// without pretending to be a usage record. The original ordering assumed
		// every ledger repeats those facts on the lines that carry usage, which
		// is true of Claude Code and false of Codex.
		if record.ProjectKey != "" && projectKey == "" {
			// Pin the project key on the first record that names one and never
			// move it. A session's later records may report a subdirectory as
			// the working directory, and letting that repoint the attribution
			// would scatter one session's spend across several project keys.
			projectKey = record.ProjectKey
			mark.ProjectKey = projectKey
		}
		if record.Context != "" && len(record.Context) <= MaxFileContextBytes {
			fileContext = record.Context
			mark.Context = fileContext
		}
		if !ok {
			continue
		}
		// Duplicate handling, and why it is a HIGH-WATER MARK rather than a set.
		//
		// A ledger repeats a dedupe key for two different reasons, and treating
		// them alike loses data. Codex restates a finished call verbatim, and
		// Claude Code writes one transcript record per content block of a
		// single API message -- but those per-block records are NOT copies of
		// each other. They are successive snapshots of a response still being
		// written, and only the terminal one carries the whole output count and
		// the thinking-token breakdown. Measured over 138 live transcripts:
		// 15,602 usage records, 7,094 distinct message ids, and keeping the
		// FIRST record of each lost 454,348 output tokens -- 16.4% of all output
		// on the machine, concentrated almost entirely in subagent transcripts,
		// with 440 calls also losing a reasoning count they had reported. The
		// input and cache classes never differed between the records of one
		// message; only output did, and it only ever grew.
		//
		// So a repeat is skipped only when it reports no more output than the
		// best already offered for that key. One that reports more is offered
		// again as a restatement, and the store's monotone upsert -- which is
		// the other half of this fix, and necessary because the per-pass record
		// bound can split one message's records across two passes -- keeps the
		// larger value. Neither half is sufficient alone.
		key := record.Call.DedupeKey
		best, known := seen[key]
		if known && record.Call.Usage.Output <= best {
			pass.Duplicates++
			continue
		}
		if known {
			pass.Restatements++
		}
		if known || len(seen) < collector.config.MaxSeenKeys {
			// Updating a known key does not grow the set, so the bound only
			// ever refuses NEW keys. Past it, dedupe falls back to the store's
			// unique index and its monotone upsert, which is the durable
			// guarantee either way.
			seen[key] = record.Call.Usage.Output
		}
		if err := record.Call.Validate(); err != nil {
			pass.Malformed++
			collector.config.Logger.Warn("ledger record rejected by the observation plane",
				slog.String("harness", string(collector.Harness())),
				slog.String("path", path), slog.Any("error", err))
			continue
		}
		pass.Observed++
		batch = append(batch, record.Call)
		if len(batch) >= envelopeSize && !flush() {
			return
		}
	}
	flush()
}

// offer hands one batch to the plane. A refusal ends the pass and the caller
// rewinds this file's watermark, so the next pass reads the same records again
// and the sink's queue gets the interval to drain. Re-delivery is free: the
// dedupe key is the harness's own identifier, so the store collapses the
// repeat.
//
// The two ways a batch can fail to land are counted APART, because they are
// opposite conditions with opposite remedies. Backpressure is transient and the
// watermark rewinds; a batch with no honest attribution is permanent and the
// watermark advances past it forever. One counter for both would report a
// mapping bug as load, and load as a mapping bug.
func (collector *Collector) offer(projectKey string, calls []domain.ModelCall, pass *Pass) bool {
	if projectKey == "" {
		// No ledger line named a workspace. The observations are real, but
		// there is nowhere honest to attribute them, and a fabricated project
		// key would pollute every other project's rollup.
		pass.Unattributed += len(calls)
		return true
	}
	attribution, err := telemetry.CollectorAttribution(collector.Harness(), projectKey)
	if err != nil {
		pass.Unattributed += len(calls)
		collector.config.Logger.Warn("ledger batch could not be attributed",
			slog.String("harness", string(collector.Harness())),
			slog.String("project_key", projectKey), slog.Any("error", err))
		return true
	}
	envelope := telemetry.Envelope{
		Attribution: attribution,
		ModelCalls:  append([]domain.ModelCall(nil), calls...),
		Source:      telemetry.SourceCollected,
		ReceivedAt:  collector.config.Now(),
	}
	if !collector.config.Ingest.Offer(envelope) {
		pass.Dropped += len(calls)
		pass.LimitReached = "sink"
		return false
	}
	pass.Offered += len(calls)
	return true
}

// readLine consumes exactly one line and reports how many bytes it took, so a
// caller can advance a byte watermark without trusting the length of what it
// got back. A line longer than limit is consumed and discarded rather than
// buffered: that is the difference between a bounded reader and one whose
// memory a ledger file decides.
func readLine(reader *bufio.Reader, limit int) (line []byte, consumed int64, complete, oversize bool, err error) {
	buffer := make([]byte, 0, 512)
	for {
		chunk, readErr := reader.ReadSlice('\n')
		consumed += int64(len(chunk))
		if !oversize {
			if len(buffer)+len(chunk) > limit {
				oversize = true
				buffer = nil
			} else {
				buffer = append(buffer, chunk...)
			}
		}
		if readErr == nil {
			return buffer, consumed, true, oversize, nil
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		// io.EOF with bytes in hand is a partial final line; with none it is
		// the end of the file. Neither is a complete line.
		return nil, consumed, false, oversize, readErr
	}
}

// Cursor persistence. The cursors are adapter bookkeeping, not a coordination
// fact, and they are deliberately NOT in the coordination database: a poll
// would otherwise take the SQLite write arbiter every interval to record that
// nothing had changed, which is exactly the kind of coupling the observation
// plane's one rule exists to prevent. A lost cursor file costs a re-read that
// the dedupe index absorbs.

func (collector *Collector) loadCursors() {
	if collector.loaded {
		return
	}
	collector.loaded = true
	if collector.config.StatePath == "" {
		return
	}
	data, err := os.ReadFile(collector.config.StatePath)
	if err != nil {
		return
	}
	var stored cursorFile
	if err := json.Unmarshal(data, &stored); err != nil {
		// A corrupt cursor file is repaired by ignoring it. Refusing to collect
		// because a watermark could not be read would be strictly worse than
		// re-reading from zero, which is what the dedupe key is for.
		collector.config.Logger.Warn("ledger cursor file unreadable; re-reading from the start",
			slog.String("harness", string(collector.Harness())),
			slog.String("path", collector.config.StatePath))
		return
	}
	if stored.Version != cursorFileVersion || stored.Harness != string(collector.Harness()) {
		return
	}
	collector.resumeAfter = stored.ResumeAfter
	for path, mark := range stored.Cursors {
		if mark.Offset >= 0 {
			collector.cursors[path] = mark
		}
	}
}

// prune drops cursors for files that are gone, so a state file cannot grow
// without bound on a machine whose harness rotates its ledgers.
func (collector *Collector) prune(live map[string]struct{}) int {
	pruned := 0
	for path := range collector.cursors {
		if _, present := live[path]; !present {
			delete(collector.cursors, path)
			pruned++
		}
	}
	return pruned
}

func (collector *Collector) saveCursors(pass *Pass) {
	if collector.config.StatePath == "" {
		return
	}
	data, err := json.Marshal(cursorFile{
		Version:     cursorFileVersion,
		Harness:     string(collector.Harness()),
		Cursors:     collector.cursors,
		ResumeAfter: collector.resumeAfter,
	})
	if err != nil {
		pass.CursorSaveFail = true
		return
	}
	if err := os.MkdirAll(filepath.Dir(collector.config.StatePath), 0o700); err != nil {
		pass.CursorSaveFail = true
		return
	}
	temporary := collector.config.StatePath + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		pass.CursorSaveFail = true
		return
	}
	if err := os.Rename(temporary, collector.config.StatePath); err != nil {
		_ = os.Remove(temporary)
		pass.CursorSaveFail = true
	}
}
