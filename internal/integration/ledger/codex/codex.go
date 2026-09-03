// Package codex reads Codex's rollout transcripts as a usage ledger for
// Blackbird's observation plane.
//
// Codex is the harness with no plugin surface at all. Nothing can run inside it
// that would push an observation, so a daemon-side reader of the ledger it
// already writes is not one mechanism among two here -- it is the only way
// Codex spend is ever observable. That also means there is no push to collide
// with: registering this collector puts `codex` in the sink's collected
// partition, so a future Codex extension cannot double count even if someone
// writes one and forgets this exists.
//
// Everything below was measured against the 208 rollout files on the machine
// this adapter was written on -- 11,909 token_count events -- rather than
// assumed. Six findings decide the whole mapping.
//
//   - CODEX'S input_tokens INCLUDES CACHE. This is the exact inverse of
//     Anthropic's, where input_tokens excludes it. Across all 11,909 records
//     cached_input_tokens never exceeded input_tokens, and the running total
//     reconciled only when the two were read as a whole and a part. So uncached
//     input is input minus cached (minus cache-write, below), and mapping
//     input_tokens straight onto this plane's uncached-input field would count
//     the cached prompt twice on every Codex row while OpenCode, whose
//     tokens.input excludes cache, stayed correct. Nothing about the result
//     would look wrong. TestCodexInputConventionIsInvertedFromAnthropic exists
//     to fail if someone later "simplifies" the subtraction away.
//
//   - THE PER-CALL NUMBER IS last_token_usage, NOT total_token_usage. Each
//     token_count event carries both: a cumulative running total for the
//     session and the delta for the call that just finished. Summing the
//     cumulative field would grow quadratically with session length. Verified
//     the other way round too: on 134 of the 135 unarchived sessions, the
//     deduplicated deltas summed exactly to the session's final cumulative.
//
//   - CODEX EMITS THE SAME CALL MORE THAN ONCE WITHIN A FILE. 101 events across
//     35 of the 208 files repeated an earlier event's cumulative totals exactly
//     -- the harness's own running total had not advanced, so no tokens had been
//     spent, though the repeat carries a later timestamp and a later ordinal.
//     One observed session reported 79,683 cumulative
//     tokens and would have been billed 117,098 by naive summation, a 47%
//     overstatement from a single repeat. That is why the dedupe key is built
//     from the cumulative watermark rather than from the delta or from a
//     position in the file: two events reporting the same watermark describe
//     the same spend, and an event that advances it describes new spend. It is
//     the same class of hazard as Claude Code's per-content-block repetition,
//     and it is load-bearing rather than hygienic.
//
//   - A FORKED THREAD REPLAYS ITS PARENT'S HISTORY. 146 of the 208 files carry
//     fork or parent metadata, and a fork's rollout re-emits the parent's
//     token_count events verbatim -- under the PARENT's session id and running
//     totals, but stamped with a single synthetic timestamp at the moment of the
//     fork. 53 dedupe keys were found in more than one file this way, 148
//     records and 12.3M billed input tokens across the corpus. A key built from
//     a timestamp, an ordinal, or the file it was read from would count every
//     one of them twice; the session-plus-watermark key collapses them, and the
//     framework's in-pass duplicate set spans the whole pass rather than one
//     file precisely so it can.
//
//   - A token_count EVENT IS NOT ALWAYS A CALL. 71 events carried an all-zero
//     last_token_usage; they are emitted to refresh rate-limit state. Left in,
//     they would be observations of nothing, which is what the `<synthetic>`
//     model is on the Claude Code side.
//
//   - THE OBSERVATION LINES ARE NOT SELF-DESCRIBING. A token_count event names
//     no model, no provider, no session and no working directory. Those live in
//     the session_meta header (present as line one of all 208 files) and in the
//     turn_context records (present in all 208, always naming a model). That is
//     what ledger.ContextualAdapter is for, and it is the one thing this
//     harness needed that the framework did not already have.
//
// Two more choices worth stating because their alternatives look reasonable.
//
// The `threads` table in ~/.codex/state_5.sqlite was considered and rejected as
// a token source. It offers cheap attribution -- cwd, git origin, branch -- but
// its only spend column is a single conflated `tokens_used` scalar that cannot
// be decomposed into the disjoint classes this plane requires, and it appears
// to accumulate per-turn totals, so it recounts the cached prompt every turn
// (one 208-row sample reported 24,962,988 for a single thread). Reading it
// would also mean opening another process's live WAL database from a collector
// whose one hard rule is that it must never be able to make a coordination
// write fail. Everything it offers for attribution is already in the rollout
// file -- 208 of 208 carry cwd and model_provider in session_meta, and a model
// in turn_context -- so the join buys nothing and costs a second storage
// dependency. No join means no way to count a thread twice.
//
// Compressed rollouts (`.jsonl.zst`, written by some builds for older sessions)
// are not matched, and that is a skip rather than an error. The framework's
// whole resume model is a byte offset seeked into the file, which a compressed
// stream cannot honour; supporting them is a framework change, not an adapter
// one. None were present on the machine this was measured against.
//
// A rollout records what a call cost and never how long it took, so duration is
// omitted rather than zeroed, for the reason the Claude Code adapter omits it.
//
// Measured end to end over that tree, one pass reads 208 files and 91,313 lines
// in about 1.5s and yields 11,589 observations, which reconciles exactly:
// 11,909 token_count events, less 71 that spent nothing, less 101 in-file
// repeats, less 148 fork replays. Zero malformed, zero dropped, and 22 project
// keys attributed. If a change here moves those numbers, that subtraction is
// where to start.
package codex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/integration/ledger"
)

const (
	// LedgerPrefix and LedgerExtension together identify a rollout. The Codex
	// home holds skills, plugins, caches, vendored packages and several large
	// SQLite databases; matching on both keeps this adapter from opening a file
	// whose format it has no claim on.
	LedgerPrefix    = "rollout-"
	LedgerExtension = ".jsonl"

	// Record types in a rollout. session_meta and turn_context carry no usage
	// and are read only for the context they establish.
	typeSessionMeta = "session_meta"
	typeTurnContext = "turn_context"
	typeEventMsg    = "event_msg"
	eventTokenCount = "token_count"

	maxRawUsageBytes = domain.MaxRawUsageBytes
)

// Locator finds the Codex home on this machine, injected for the reason the
// Homebrew updater's detection is: a test that let the real lookup run would
// assert one thing on a workstation that runs Codex and another on one that
// does not, and neither result would be a fact about the code.
type Locator func() (string, error)

// DefaultRoot resolves the Codex home, honouring CODEX_HOME because that is
// what Codex itself honours. It reports the path whether or not it exists.
//
// The root is the whole Codex home rather than just `sessions/`, because Codex
// moves a rollout to `archived_sessions/` when a thread is archived and the
// history there is real spend -- 73 of the 208 files measured. One root covers
// both trees with one cursor file, and the move is harmless: the dedupe key is
// derived from the session and its own running total, so re-reading the file at
// its new path collapses into the rows already stored. The walk is bounded by
// the framework's depth limit, which keeps it to roughly 1,500 directory
// entries and about 15ms on the tree measured.
func DefaultRoot() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("CODEX_HOME")); configured != "" {
		return configured, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate the Codex rollout tree: %w", err)
	}
	return filepath.Join(home, ".codex"), nil
}

// Adapter reads Codex rollouts. It holds no state of its own: the per-file
// carry lives in the framework's cursor, so it survives a daemon restart
// alongside the byte watermark it describes.
type Adapter struct{}

var (
	_ ledger.Adapter           = Adapter{}
	_ ledger.ContextualAdapter = Adapter{}
)

func New() Adapter { return Adapter{} }

func (Adapter) Harness() domain.Harness { return domain.HarnessCodex }

// Ledger accepts rollout transcripts and nothing else.
func (Adapter) Ledger(_ string, entry fs.DirEntry) bool {
	name := entry.Name()
	return strings.HasPrefix(name, LedgerPrefix) && filepath.Ext(name) == LedgerExtension
}

// ErrMalformedRecord marks a line that announced itself as a Codex record and
// then could not be read as one. It is separate from "this is not a usage
// record" because the two mean opposite things: the second is most of the file,
// and the first is a mapping that has gone wrong and should be visible in a
// counter.
var ErrMalformedRecord = errors.New("malformed Codex rollout record")

// Decode reads a line with no carried context. It exists to satisfy
// ledger.Adapter; the framework calls DecodeInContext.
func (adapter Adapter) Decode(line []byte) (ledger.Record, bool, error) {
	return adapter.DecodeInContext(line, "")
}

// DecodeInContext maps one rollout line, given what earlier lines in the same
// file established. It is pure, allocates only what it returns, and never
// retains the slice it was given.
func (Adapter) DecodeInContext(line []byte, fileContext string) (ledger.Record, bool, error) {
	trimmed := trimSpace(line)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ledger.Record{}, false, nil
	}
	var entry rolloutEntry
	if err := json.Unmarshal(trimmed, &entry); err != nil {
		// A line that is not JSON at all is a truncated or interleaved write.
		// Reported rather than skipped, because a steady trickle of them is how
		// a format change announces itself.
		return ledger.Record{}, false, fmt.Errorf("%w: %w", ErrMalformedRecord, err)
	}
	carried := parseContext(fileContext)
	switch {
	case entry.Type == typeSessionMeta:
		return sessionRecord(entry, carried)
	case entry.Type == typeTurnContext:
		return turnRecord(entry, carried)
	case entry.Type == typeEventMsg && entry.Payload.Type == eventTokenCount:
		return usageRecord(entry, carried)
	default:
		return ledger.Record{}, false, nil
	}
}

// sessionRecord carries the session header forward. It is the only line that
// contributes attribution: turn_context also names a working directory, and it
// is often a subdirectory or a second workspace root, so letting it speak would
// scatter one session's spend across project keys.
//
// The model is carried through rather than cleared, because a resumed or forked
// session appends a second session_meta and the turn_context that would restate
// the model has not been read yet.
func sessionRecord(entry rolloutEntry, carried sessionContext) (ledger.Record, bool, error) {
	session := entry.Payload.ID
	if session == "" {
		// Older builds wrote session_id; every file measured carried id, and
		// 146 of 264 headers carried both.
		session = entry.Payload.SessionID
	}
	next := sessionContext{
		Session:  session,
		Provider: entry.Payload.ModelProvider,
		Model:    carried.Model,
	}
	return ledger.Record{ProjectKey: entry.Payload.CWD, Context: next.encode()}, false, nil
}

// turnRecord carries the model forward. Codex can change model mid-session --
// a smaller one summarizes for compaction -- so this is last-writer-wins, and
// the record that follows is attributed to whatever most recently answered.
func turnRecord(entry rolloutEntry, carried sessionContext) (ledger.Record, bool, error) {
	if entry.Payload.Model == "" {
		return ledger.Record{}, false, nil
	}
	carried.Model = entry.Payload.Model
	return ledger.Record{Context: carried.encode()}, false, nil
}

func usageRecord(entry rolloutEntry, carried sessionContext) (ledger.Record, bool, error) {
	info := entry.Payload.Info
	if info == nil || info.LastTokenUsage == nil || info.TotalTokenUsage == nil {
		return ledger.Record{}, false,
			fmt.Errorf("%w: token_count carries no usage totals", ErrMalformedRecord)
	}
	last := info.LastTokenUsage
	if last.empty() {
		// A rate-limit refresh, not a call. Skipped rather than reported
		// malformed: the harness wrote exactly what it meant to.
		return ledger.Record{}, false, nil
	}
	if carried.Model == "" || carried.Provider == "" || carried.Session == "" {
		// Unreachable in normal operation, and deliberately loud if it ever
		// stops being so. The context rides in the same cursor entry as the
		// byte offset, so a file resumed mid-way always carries the header it
		// already read, and a file whose cursor was lost restarts at offset
		// zero where session_meta is line one. Reaching here means the header
		// changed shape or was skipped as oversize.
		return ledger.Record{}, false,
			fmt.Errorf("%w: token_count before its session header was read", ErrMalformedRecord)
	}
	startedAt, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
	if err != nil {
		return ledger.Record{}, false, fmt.Errorf("%w: unreadable timestamp: %w", ErrMalformedRecord, err)
	}
	call := domain.ModelCall{
		DedupeKey:      dedupeKey(carried.Session, info.TotalTokenUsage),
		Harness:        domain.HarnessCodex,
		HarnessSession: carried.Session,
		Provider:       carried.Provider,
		Model:          carried.Model,
		Operation:      domain.ModelOperationChat,
		Usage:          last.normalize(),
		Outcome:        domain.ObservedOutcomeOK,
		StartedAt:      startedAt.UTC(),
		// Duration stays unknown. See the package comment.
		RawUsage: rawUsage(info),
	}
	return ledger.Record{Call: call}, true, nil
}

// rolloutEntry is the projection this adapter reads. It is one flat struct
// across three record types rather than a discriminated decode, because a
// rollout line carries whole message bodies, reasoning traces and tool output,
// and a second pass over it to pick a shape would double the parsing cost of
// every line in the file. Fields absent from a given type simply stay zero;
// encoding/json skips the rest without materializing it.
type rolloutEntry struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Payload   struct {
		// session_meta.
		ID            string `json:"id"`
		SessionID     string `json:"session_id"`
		CWD           string `json:"cwd"`
		ModelProvider string `json:"model_provider"`
		// turn_context.
		Model string `json:"model"`
		// event_msg.
		Type string          `json:"type"`
		Info *tokenCountInfo `json:"info"`
	} `json:"payload"`
}

type tokenCountInfo struct {
	// TotalTokenUsage is the session's running total, used only as the dedupe
	// watermark. TotalTokenUsage is never summed: see the package comment.
	TotalTokenUsage *rolloutUsage `json:"total_token_usage"`
	// LastTokenUsage is the delta for the call that just finished, and the only
	// field this adapter turns into an observation.
	LastTokenUsage *rolloutUsage `json:"last_token_usage"`
}

type rolloutUsage struct {
	// InputTokens INCLUDES cache on this harness. That is the whole reason
	// normalize subtracts rather than mapping names across.
	InputTokens uint64 `json:"input_tokens"`
	// CachedInputTokens is the portion of InputTokens served from cache.
	CachedInputTokens uint64 `json:"cached_input_tokens"`
	// CacheWriteInputTokens appeared in builds after the bulk of the corpus was
	// written -- 4 of 11,909 records carried it, all zero -- so its relationship
	// to InputTokens could not be measured directly. It is read as a second
	// component of the input, alongside CachedInputTokens, because that is what
	// the field family says and because it is the reading that cannot overstate:
	// if it turns out to be additive instead, this under-reports a quantity that
	// has been zero in every record seen, whereas the other reading would inflate
	// the input on every row. RawUsage keeps the numbers either way, so the
	// choice stays recoverable rather than silent.
	CacheWriteInputTokens uint64 `json:"cache_write_input_tokens"`
	OutputTokens          uint64 `json:"output_tokens"`
	ReasoningOutputTokens uint64 `json:"reasoning_output_tokens"`
	TotalTokens           uint64 `json:"total_tokens"`
}

func (usage *rolloutUsage) empty() bool {
	return usage.InputTokens == 0 && usage.CachedInputTokens == 0 &&
		usage.CacheWriteInputTokens == 0 && usage.OutputTokens == 0
}

// normalize converts Codex's inclusive input into this plane's disjoint
// classes. The subtraction IS the adapter's job -- see the package comment and
// TestCodexInputConventionIsInvertedFromAnthropic.
//
// It saturates rather than wrapping. uint64 arithmetic that went negative would
// produce an astronomically large token count that passes every bound check
// below MaxCanonicalInteger only by accident, so a provider reporting parts that
// exceed the whole yields zero uncached input instead.
func (usage *rolloutUsage) normalize() domain.TokenUsage {
	cached := min(usage.CachedInputTokens, usage.InputTokens)
	cacheWrite := min(usage.CacheWriteInputTokens, usage.InputTokens-cached)
	return domain.TokenUsage{
		UncachedInput: usage.InputTokens - cached - cacheWrite,
		CacheRead:     cached,
		CacheWrite:    cacheWrite,
		Output:        usage.OutputTokens,
		// Reasoning is a subset of output, never additional to it. Clamping
		// rather than rejecting keeps a provider rounding difference from
		// discarding a real observation.
		Reasoning:         min(usage.ReasoningOutputTokens, usage.OutputTokens),
		ReasoningReported: true,
	}
}

// sessionContext is the per-file carry. It is JSON rather than a delimited
// string because it lands verbatim in the cursor file, where being readable is
// worth more than being short, and because a model name is harness-supplied and
// must not be able to forge a delimiter.
type sessionContext struct {
	Session  string `json:"session,omitempty"`
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
}

func (carried sessionContext) encode() string {
	encoded, err := json.Marshal(carried)
	if err != nil || len(encoded) > ledger.MaxFileContextBytes {
		// Returning nothing leaves the previous context standing, which is the
		// conservative half of the trade: a stale model attributes a call to
		// the wrong one, a missing context drops it entirely, and neither is
		// worth reaching by writing a context the framework would refuse.
		return ""
	}
	return string(encoded)
}

func parseContext(fileContext string) sessionContext {
	var carried sessionContext
	if fileContext == "" {
		return carried
	}
	if err := json.Unmarshal([]byte(fileContext), &carried); err != nil {
		return sessionContext{}
	}
	return carried
}

// dedupeKey is built from the session and the session's own running total,
// because that pair is what distinguishes a call from a repeat report of it.
// Two events carrying the same running total describe the same spend even when
// they arrive seconds apart with different ordinals; an event that advances it
// is new. The delta is not part of the key: a repeat restates it identically,
// so it adds nothing, and one observed repeat class restated a stale delta
// against an unchanged total, which the key must collapse rather than admit.
func dedupeKey(session string, total *rolloutUsage) string {
	var builder strings.Builder
	builder.WriteString("codex/")
	builder.WriteString(session)
	for _, value := range [...]uint64{
		total.InputTokens, total.CachedInputTokens, total.CacheWriteInputTokens,
		total.OutputTokens, total.ReasoningOutputTokens,
	} {
		builder.WriteByte('/')
		builder.WriteString(strconv.FormatUint(value, 10))
	}
	key := builder.String()
	if len(key) <= domain.MaxDedupeKeyBytes {
		return key
	}
	// A session id long enough to reach here is not something this harness
	// writes, but the key is the idempotency guarantee and must stay within the
	// plane's bound rather than be rejected at validation. Hashing preserves
	// both stability and distinctness.
	digest := sha256.Sum256([]byte(key))
	return "codex/sha256/" + hex.EncodeToString(digest[:])
}

// rawUsage keeps the numbers this mapping actually read -- both the delta it
// normalized and the running total it keyed on -- bounded. It is the audit
// trail for the normalization itself: without it a subtraction bug is
// undetectable after the fact, having discarded the only evidence it was wrong.
func rawUsage(info *tokenCountInfo) string {
	encoded, err := json.Marshal(info)
	if err != nil || len(encoded) > maxRawUsageBytes {
		return ""
	}
	return string(encoded)
}

func trimSpace(line []byte) []byte {
	start := 0
	for start < len(line) && isSpace(line[start]) {
		start++
	}
	end := len(line)
	for end > start && isSpace(line[end-1]) {
		end--
	}
	return line[start:end]
}

func isSpace(character byte) bool {
	switch character {
	case ' ', '\t', '\r', '\n', '\v', '\f':
		return true
	default:
		return false
	}
}
