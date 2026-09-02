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
`application.TelemetrySinkStats`.

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
  live transcript carries the same assistant usage twice a millisecond apart.
- Any adapter may retry a request whose response was lost.

With nothing stable to key on, synthesize a unique value. It simply never
dedupes, which is correct rather than special.

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

**Claude Code** is the asymmetric one. Its MCP surface shows a server only its
own tool frames, so there is no usage there at all; the counts live in the
session transcript. `blackbird hook claude` reads the transcript named by the
hook payload from a byte watermark, **after** it has answered the host, so a
slow or absent daemon cannot delay a turn. A transcript records what a call
cost and never how long it took, so `duration_ms` is omitted rather than
faked — this is the one adapter that reports no latency.

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
| `harness` | model calls | tokens | Claude Code vs OpenCode vs Pi |
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
