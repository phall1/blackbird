# The observation plane

Token spend, latency, and span timing for the agent fleet. Decided in
[ADR-0001](adr/0001-the-phux-boundary.md), which is also why it lives here
rather than in phux.

This document is the adapter contract. If you are writing a new harness
adapter, everything you must get right is below.

## The one rule

**Telemetry may never make a coordination write fail.** Coordination is the
product; this is a projection against it. The rule is enforced structurally,
not by care:

- Ingest enqueues to a bounded ring and returns. A full queue drops and counts;
  it never blocks a caller, so no ingest burst can apply backpressure.
- One drain goroutine batches and writes a single transaction per batch, so a
  lease acquire waits behind at most one bounded telemetry commit no matter how
  hard an adapter is reporting.
- No foreign key points from a telemetry table into a coordination table. One
  would let an observation refuse a coordination delete.
- A write failure is counted and dropped. It is never returned, because no
  caller has anything useful to do with it.
- A panic in the drain is recovered. A defect here stops observation, not the
  daemon.

Read the counters with `blackbird status`; they are in
`telemetry.SinkStats`.

## The token classes are disjoint

This is the part that is wrong everywhere else, so it is worth being blunt.

| Class | Meaning |
|---|---|
| `uncached_input_tokens` | processed fresh — neither served from nor written to cache |
| `cache_read_tokens` | served from a prompt cache |
| `cache_write_tokens` | written into a prompt cache by this call |
| `output_tokens` | generated |
| `reasoning_tokens` | the reasoning subset **of** `output_tokens`, never additional |

What a provider bills as "input" is the sum of the first three. Harnesses
disagree about what the word means, and the disagreement is invisible in the
numbers:

- Anthropic reports `input_tokens` **excluding** cache. A live Claude Code
  transcript shows `input_tokens: 2` beside `cache_read_input_tokens: 26354`.
- OpenAI reports a cumulative `input_tokens` **including** cached and
  cache-write tokens.

Add those together as though they meant the same thing and you undercount one
harness and double-count the other, with nothing about the result looking
wrong. So the schema refuses the ambiguous name: there is no `input_tokens`
column, and `gen_ai.usage.input_tokens` from OpenTelemetry maps to the sum
rather than to any single column.

`reasoning_tokens` is **omitted**, not zeroed, when a harness does not report
it. "This provider gives no reasoning breakdown" and "this call did no
reasoning" are different facts that average identically if you collapse them.
`duration_ms` is likewise omitted rather than zeroed when a source cannot
measure latency.

Every observation should carry `raw_usage`: the bounded payload the adapter
derived its counts from. That is the audit trail for the normalization itself.
Without it a mapping bug is undetectable and unrecoverable after the fact —
which is exactly how an OpenCode schema change once hid 51% of messages.

## Wire contract

```
POST /api/v1/local/telemetry
Authorization: Bearer <registration_token>
Content-Type: application/json
```

The token is the one registration returns. **Attribution is taken from it, not
from the body** — an adapter cannot bill its spend to another agent, which is
the only security property this plane needs.

```json
{
  "model_calls": [{
    "dedupe_key": "msg_01ABC",
    "harness": "claude-code",
    "harness_session": "3231c9b2-...",
    "provider": "anthropic",
    "model": "claude-opus-5",
    "operation": "chat",
    "usage": {
      "uncached_input_tokens": 2,
      "cache_read_tokens": 26354,
      "cache_write_tokens": 23947,
      "output_tokens": 1469,
      "reasoning_tokens": 298
    },
    "outcome": "ok",
    "started_at": "2026-09-02T05:06:52.813Z",
    "duration_ms": 4210,
    "raw_usage": "{...}"
  }],
  "spans": [{
    "dedupe_key": "build-1",
    "harness": "pi",
    "kind": "build",
    "name": "make check",
    "outcome": "error",
    "error_kind": "exit_status",
    "started_at": "2026-09-02T05:06:52Z",
    "duration_ms": 92000
  }]
}
```

Response is always `202` when the caller is authenticated and the body parses:

```json
{"accepted": 12, "dropped": 0, "rejected": 1, "rejections": [{"kind": "model_call", "index": 3, "reason": "..."}]}
```

- `accepted` — validated and queued.
- `dropped` — validated, but the sink was full or closed. Normal under load.
- `rejected` — failed validation. **Log these.** They mean your mapping is
  wrong, and they are reported per item so one bad field never costs the good
  observations in the same request.

Unknown JSON fields are rejected per item, deliberately: a misspelled token
field would otherwise decode to zero and be stored as a real measurement.

`503 DEPENDENCY_UNAVAILABLE` means this daemon is not collecting. Stop
emitting; do not retry.

Bounds: 256 KiB per request, 128 observations per request, 4096 bytes of
`raw_usage`, 24 hours of `duration_ms`.

## Idempotency

Ingest is idempotent on `(actor, dedupe_key)`. Use the provider's own
identifier when you have one — Anthropic's `message.id`, OpenCode's message
`id`, Pi's `responseId`. Every adapter has a duplicate-delivery path, so this
is not optional hygiene:

- OpenCode reference-counts one supervisor across activations, so the same
  event can reach two hook instances.
- The Claude Code transcript reader re-scans from an imprecise watermark, and a
  live transcript carries the same assistant usage many times over.
- Codex restates a finished call verbatim, and a forked thread replays its
  parent's whole history.
- Any adapter may retry a request whose response was lost.

With nothing stable to key on, synthesize a unique value. It simply never
dedupes, which is correct rather than special.

**A duplicate is not always a copy, and this is where the plane has already been
burned once.** Claude Code writes one transcript record per content block of a
single API message. All of them carry the message id, so all of them collide on
the dedupe key — but they are successive snapshots of a response still being
written. Input, cache-read and cache-write are identical across them; output
grows, and only the terminal record carries the finished count and the
`output_tokens_details` thinking breakdown. A measured message ran
`3, 3, 3, 3, 3, 836`.

So a conflict is absorbed **monotonically**: a conflicting row replaces the
stored one when, and only when, it reports strictly more output. Under the
first-writer-wins rule this replaced, 16.4% of every output token on a live
workstation was discarded permanently — no re-scan could repair it — while the
observation *count* stayed correct, so nothing looked missing. The loss
concentrated in subagent transcripts, so "what did my subagent fleet cost" was
the query that returned near zero.

Two consequences for an adapter author:

- **Report each record faithfully; do not pick a winner.** Deciding which of two
  records bearing one key is the truer one belongs to the collector's in-pass
  high-water mark and to the store's upsert, not to a mapping.
- **An emitter that genuinely retries an identical call is unaffected**, since
  it reports no more output than is stored. Monotone absorption keeps
  first-writer-wins semantics for every case that actually is a copy.

Spans have no monotone measure of completeness, so a span conflict is still
ignored outright.

## Why this is not an MCP tool

An MCP tool would put a telemetry schema in every session's tool list, where
the model pays context tokens for it on every turn — to report the tokens it is
spending. The adapter is a process, not a model. It calls an endpoint.

## Per-harness notes

**Pi** (`packages/pi-extension`) needs no normalization argument. Its own
`Usage` type already carries the disjoint classes, its provider adapters do the
subtraction (*"OpenAI includes cached and cache-write tokens in input_tokens,
so subtract both"*), and it documents `reasoning` as a subset of `output`. The
adapter maps names. Latency comes from pairing `message_start` with
`message_end`.

**OpenCode** (`packages/opencode-plugin`) reports `tokens.input` already
excluding cache, with `tokens.cache.read`/`.write` as siblings. The `event`
hook records only messages with `time.completed` — `message.updated` fires
repeatedly while a response streams, and recording an in-flight message would
store a zero-duration call and then store it again.

**Codex** (`internal/integration/ledger/codex`) has no plugin surface at all, so
the daemon-side reader of its rollout tree under `CODEX_HOME` is not one
mechanism among two — it is the only way Codex spend is ever observed. It is
also the harness whose convention is inverted: `input_tokens` **includes**
cache, so uncached input is `input_tokens` minus `cached_input_tokens` minus
`cache_write_input_tokens`. Mapping the name straight across would count the
cached prompt twice on every row while OpenCode stayed correct, and nothing
about the result would look wrong. Two duplicate paths matter as much as the
subtraction: the harness restates a finished call with a new timestamp while
its own running total stands still, and a forked thread replays its parent's
whole history under the parent's session id. Both are collapsed by keying on
the session plus that running total, which is why the dedupe key is not a
timestamp, an ordinal, or a file position. Read the package comment for the
measurements behind each of those.

**Claude Code** is the asymmetric one. Its MCP surface shows a server only its
own tool frames, so there is no usage there at all; the counts live in the
session transcript. `internal/integration/ledger/claudecode` reads that
transcript tree from the daemon, under `CLAUDE_CONFIG_DIR` where it is set and
`~/.claude/projects` otherwise. A transcript records what a call cost and never
how long it took, so `duration_ms` is omitted rather than faked — this is the
one adapter that reports no latency. Every assistant record carries its own
`cwd`, so the project key is read rather than decoded out of the directory name,
which is a lossy encoding that would misattribute any path containing a dash.

`blackbird hook claude` pushes the same counts from inside a session hook, from
a byte watermark, **after** it has answered the host so a slow or absent daemon
cannot delay a turn. **It is superseded by the collector and kept only for
compatibility**: a daemon that collects `claude-code` drops what this pushes, at
`Sink.Offer`, so the two can never both be counted. Do not extend it; extend the
adapter.

## Ownership: collect or push, never both

Two mechanisms can observe one turn, and dedupe does **not** settle it — a
pushed call is attributed to the registered agent that posted it and a collected
one to the collector's synthetic identity, so two actors carrying the same
message id are two rows. Ownership is therefore partitioned per harness at
`Sink.Offer`, which is the single entry to the plane's only writer:

| | admitted | dropped |
|---|---|---|
| a harness this daemon **collects** | collected model calls, and pushed **spans** | pushed model calls |
| every other harness | pushed observations | — |

Spans are untouched by the partition, because a collector reads a token ledger
and supersedes token counts rather than timing.

**A harness is claimed only when its ledger tree is actually present on this
machine.** Superseding a push is a claim the daemon has to be able to back. The
daemon is a per-user service and does not inherit the login shell, so a
`CLAUDE_CONFIG_DIR` or `CODEX_HOME` exported in a profile is absent from its
environment and the root it resolves points at nothing. Claiming the harness
anyway dropped every push while collecting nothing — and both halves are silent,
since an absent ledger is a *passing* probe state by design and the plane counts
write failures rather than returning them. The cost of the rule is a bounded,
visible overlap if a tree first appears after the daemon started; the cost of
its absence was permanent, total, and invisible.

## Reading it back

One optional rollup on `blackbird_status` (`spend: true`), and no separate telemetry tool. There is no
CLI, no dashboard, and no row feed — the plane is written by processes and read
by agents, and an agent asking what it spent wants a handful of totals it can
act on, not a page of observations it has to add up in its own context.

It is one tool rather than several because every tool costs every session a
slice of context on every turn. A `dimension` parameter answers "which model",
"which agent", "which harness", and "what is slow" without four entries in
`tools/list`. And it is registered **only when a telemetry reader is composed**,
so a daemon that collects nothing advertises nothing.

| `dimension` | Table | Ranked by | Answers |
|---|---|---|---|
| `model` (default) | model calls | tokens | where the budget goes |
| `agent` | model calls | tokens | who is spending it |
| `harness` | model calls | tokens | Claude Code vs Codex vs OpenCode vs Pi |
| `span_kind` | spans | total duration | which kind of work takes the clock |
| `span_name` | spans | total duration | which specific activity is slow |

Span dimensions report zero tokens. A span has none — that is the truth, not a
missing value.

Scope is not a parameter. The report always covers the caller's own project,
taken from the authenticated session, so it can never read across into another
workspace; `mine_only` narrows further to the calling agent, which is how an
agent asks what it personally has cost. `since_hours` defaults to 24 and is
capped at 720, and `limit` defaults to 10 and is capped at 50 — both are
clamped rather than rejected, because a clamped answer is still useful.

Two fields deserve care when reading a group:

- **`billed_input_tokens`** is the headline — `uncached + cache_read +
  cache_write`, what a provider actually invoices. Compare it against
  `uncached_input_tokens` to see what caching is really saving.
- **`measured_durations`**, not `observations`, is the denominator for any mean
  latency. Claude Code reports no latency at all, so dividing
  `total_duration_ms` by `observations` reports its calls as instant. For
  finding a bottleneck, prefer `total_duration_ms` outright: the group holding
  the most wall clock is the one to fix, however fast any single call looks.

`totals` covers the whole window rather than the returned groups, so it stays
honest when `truncated` is true.

## Retention

Telemetry rows are neither immutable nor journaled, and are swept on a
schedule; deleting them is ordinary rather than a policy decision. Retention is
measured from `recorded_at_us`, the daemon's clock at the moment it accepted
the row — never from the adapter's `started_at`, because an adapter with a
wrong clock must not be able to make its rows immortal.

Cost is not stored anywhere. Price is a function of provider, model, token
class, and date; a computed cost in a durable row freezes one day's price into
a fact. Cost is a projection over these numbers.
