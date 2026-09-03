// Package claudecode reads Claude Code's session transcripts as a usage
// ledger for Blackbird's observation plane.
//
// Claude Code is the asymmetric harness. Its MCP surface shows a server only
// that server's own tool frames, so a Blackbird MCP session can see nothing at
// all about what a turn cost. The counts live in the session transcript, which
// the harness writes for its own reasons and keeps whether or not this daemon
// is running -- which is precisely what makes tailing the right mechanism here
// rather than a second-best one.
//
// Four facts about that file decide everything below, and all four were
// measured against the live transcript tree rather than assumed:
//
//   - Anthropic's usage reports input_tokens EXCLUDING cache. A real record
//     shows input_tokens 2 beside cache_read_input_tokens 26354 and
//     cache_creation_input_tokens 23947. The four classes are already disjoint,
//     so this adapter maps names and subtracts nothing. (Codex is the opposite
//     and will need the subtraction; that is the adapter's job, not the
//     framework's, which is why Decode is where normalization lives.)
//
//   - The same API message is written to the transcript once per content
//     block. Across the whole live tree, 15,602 assistant records carried usage
//     and only 7,094 distinct message ids: summing records rather than calls
//     would have overstated spend by 120%. message.id is the dedupe key, and it
//     is load-bearing rather than hygienic.
//
//   - THOSE PER-BLOCK RECORDS ARE NOT COPIES OF EACH OTHER, and reading them as
//     copies is how the previous version of this adapter lost 16.4% of every
//     output token on the machine. They are successive snapshots of a response
//     still being written. The input, cache-read and cache-write counts are
//     identical across all of them -- verified to the token over the whole tree
//     -- but output GROWS, and only the terminal record carries the finished
//     count and the output_tokens_details thinking breakdown. One measured
//     message ran 3, 3, 3, 3, 3, 836, with the thinking count on the last
//     record alone. Keeping the first of each key stored 2,317,338 output
//     tokens where the true figure was 2,771,686, and left 440 calls reporting
//     NULL reasoning -- which the schema defines as "this harness does not
//     report them", so the loss read as a fact rather than as a gap. The damage
//     concentrated almost entirely in subagent transcripts, so a "what did my
//     subagent fleet cost" report was the query that returned near zero.
//     Nothing about it looked wrong: the observation COUNT was right the whole
//     time.
//
//     The fix is not in this file, because it is not a mapping question. This
//     adapter's job is to report each record faithfully; deciding which of two
//     records bearing one key is the truer one belongs to the framework's
//     in-pass high-water mark and to the store's monotone upsert. Both are
//     required -- the per-pass record bound can split one message across two
//     passes, and passes share no memory.
//
//   - Every assistant record carries its own cwd, so the project key is read
//     rather than decoded out of the directory name. The directory name is a
//     lossy encoding of a path -- separators, dots and underscores all become
//     dashes -- and decoding it would silently attribute a project with a dash
//     in its name to a project that does not exist.
//
// A transcript records what a call cost and never how long it took, so
// duration is omitted rather than zeroed. This is the one adapter that reports
// no latency, and a fabricated zero would drag every latency statistic in the
// plane toward instant.
package claudecode

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/integration/ledger"
)

const (
	// LedgerExtension is the transcript format: one JSON object per line.
	LedgerExtension = ".jsonl"
	// syntheticModel is the sentinel the harness writes for an assistant turn
	// it produced itself -- an interrupt, an API error placeholder -- rather
	// than one a provider answered. Those records carry a usage object of all
	// zeroes and a plain UUID where a message id belongs, so nothing filters
	// them out by accident. Left in, they become a model named "<synthetic>"
	// at the top of a by-model rollup ranked by observation count, standing for
	// no spend at all. Found in a live tree: three of them in the first 2048
	// records read.
	syntheticModel = "<synthetic>"
	// maxRawUsageBytes matches the plane's bound. The usage object in a live
	// transcript carries per-iteration breakdowns and service tiers and runs to
	// several hundred bytes; the normalized subset this adapter records is what
	// gets kept, so the audit trail is the numbers the mapping actually read
	// rather than everything that happened to sit beside them.
	maxRawUsageBytes = domain.MaxRawUsageBytes
)

// Locator finds the transcript tree on this machine. It is injected for the
// reason the Homebrew updater's detection is: a test that let the real lookup
// run would assert one thing on a workstation that has run Claude Code and
// another on one that has not, and neither result would be a fact about the
// code. Absence is a supported answer, never an error.
type Locator func() (string, error)

// DefaultRoot resolves the transcript tree from the environment, honouring
// CLAUDE_CONFIG_DIR because that is what the harness itself honours. It
// reports the path whether or not it exists: whether the directory is there is
// the collector's probe to make, not this function's.
func DefaultRoot() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); configured != "" {
		return filepath.Join(configured, "projects"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate the Claude Code transcript tree: %w", err)
	}
	return filepath.Join(home, ".claude", "projects"), nil
}

// Adapter reads Claude Code transcripts. It holds no state: the framework owns
// every offset, and this type owns only the mapping.
type Adapter struct{}

var _ ledger.Adapter = Adapter{}

func New() Adapter { return Adapter{} }

func (Adapter) Harness() domain.Harness { return domain.HarnessClaudeCode }

// Ledger accepts the transcript files and nothing else. The tree also holds
// memory directories and per-session subdirectories the harness writes for its
// own purposes; matching on the extension keeps this adapter from reading a
// file whose format it has no claim on.
func (Adapter) Ledger(_ string, entry fs.DirEntry) bool {
	name := entry.Name()
	return !strings.HasPrefix(name, ".") && filepath.Ext(name) == LedgerExtension
}

// transcriptEntry is the projection this adapter reads. It is deliberately a
// narrow struct rather than a map: a transcript line carries whole message
// bodies, tool results, and file snapshots, and decoding into a map would pull
// all of it into memory to reach five integers.
type transcriptEntry struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	SessionID string `json:"sessionId"`
	CWD       string `json:"cwd"`
	Message   *struct {
		ID    string           `json:"id"`
		Model string           `json:"model"`
		Usage *transcriptUsage `json:"usage"`
	} `json:"message"`
}

type transcriptUsage struct {
	// InputTokens EXCLUDES cache on this provider. That is the whole reason
	// this maps to uncached_input rather than to a billed total.
	InputTokens              uint64 `json:"input_tokens"`
	CacheCreationInputTokens uint64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     uint64 `json:"cache_read_input_tokens"`
	OutputTokens             uint64 `json:"output_tokens"`
	OutputTokensDetails      *struct {
		ThinkingTokens uint64 `json:"thinking_tokens"`
	} `json:"output_tokens_details"`
}

// ErrMalformedRecord marks a line that announced itself as an assistant usage
// record and then could not be read as one. It is separate from "this is not a
// usage record" because the two mean opposite things: the second is every
// other line in the file, and the first is a mapping that has gone wrong and
// should be visible in a counter.
var ErrMalformedRecord = errors.New("malformed Claude Code transcript record")

// Decode maps one transcript line. It is pure, allocates only what it returns,
// and never retains the slice it was given.
func (Adapter) Decode(line []byte) (ledger.Record, bool, error) {
	trimmed := trimSpace(line)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ledger.Record{}, false, nil
	}
	var entry transcriptEntry
	if err := json.Unmarshal(trimmed, &entry); err != nil {
		// A line that is not JSON at all is a truncated or interleaved write.
		// It is reported as malformed rather than skipped silently, because a
		// steady trickle of them is how a format change announces itself.
		return ledger.Record{}, false, fmt.Errorf("%w: %w", ErrMalformedRecord, err)
	}
	if entry.Type != "assistant" || entry.Message == nil || entry.Message.Usage == nil {
		return ledger.Record{}, false, nil
	}
	if entry.Message.Model == syntheticModel || entry.Message.Model == "" {
		// Not a model call. Skipped rather than reported malformed: the harness
		// wrote exactly what it meant to, and this adapter simply does not
		// observe turns no provider answered.
		return ledger.Record{}, false, nil
	}
	if entry.Message.ID == "" {
		// Without the message id there is no dedupe key, and without a dedupe
		// key this record would be counted again on every re-read. Dropping it
		// is the conservative half of the trade.
		return ledger.Record{}, false, fmt.Errorf("%w: assistant record carries no message id", ErrMalformedRecord)
	}
	startedAt, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
	if err != nil {
		return ledger.Record{}, false, fmt.Errorf("%w: unreadable timestamp: %w", ErrMalformedRecord, err)
	}
	usage := entry.Message.Usage
	call := domain.ModelCall{
		DedupeKey:      entry.Message.ID,
		Harness:        domain.HarnessClaudeCode,
		HarnessSession: entry.SessionID,
		Provider:       "anthropic",
		Model:          entry.Message.Model,
		Operation:      domain.ModelOperationChat,
		Usage: domain.TokenUsage{
			UncachedInput: usage.InputTokens,
			CacheRead:     usage.CacheReadInputTokens,
			CacheWrite:    usage.CacheCreationInputTokens,
			Output:        usage.OutputTokens,
		},
		Outcome:   domain.ObservedOutcomeOK,
		StartedAt: startedAt.UTC(),
		// Duration stays unknown. See the package comment.
		RawUsage: rawUsage(usage),
	}
	if details := usage.OutputTokensDetails; details != nil {
		// Reasoning is a subset of output, never additional to it. Clamping
		// rather than rejecting keeps a provider rounding difference from
		// discarding a real observation.
		call.Usage.Reasoning = min(details.ThinkingTokens, usage.OutputTokens)
		call.Usage.ReasoningReported = true
	}
	return ledger.Record{Call: call, ProjectKey: entry.CWD}, true, nil
}

// rawUsage keeps the numbers this mapping actually read, bounded. It is the
// audit trail for the normalization itself: without it a mapping bug is
// undetectable after the fact, having discarded the only evidence it was wrong.
func rawUsage(usage *transcriptUsage) string {
	encoded, err := json.Marshal(usage)
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
