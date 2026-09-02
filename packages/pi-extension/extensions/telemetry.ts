// Blackbird's observation plane (blackbird ADR-0001), Pi side.
//
// Pi is the one harness that needs no normalization argument: its own Usage
// type already carries the disjoint classes Blackbird stores, and its provider
// adapters do the subtraction that makes them disjoint -- "OpenAI includes
// cached and cache-write tokens in input_tokens, so subtract both". Reasoning
// is documented there as a subset of output, which is exactly Blackbird's rule.
// So this file maps names; it does not reinterpret numbers.
//
// Emission is best effort in the strongest sense. Nothing here is awaited on a
// turn's critical path, no failure propagates to Pi, and a daemon that is down,
// slow, or not collecting costs one rejected promise that is swallowed here.

const TELEMETRY_PATH = "api/v1/local/telemetry"

/** Flush when this many observations are buffered. */
const FLUSH_AT = 32
/** Or when this long has passed, whichever comes first. */
const FLUSH_AFTER_MS = 5_000
/** Hard ceiling on the buffer. Beyond it the oldest observations are dropped:
 *  a daemon that is unreachable must cost this extension bounded memory, and
 *  recent spend is more useful than a complete history nobody can read. */
const MAX_BUFFERED = 256
/** The daemon rejects a submission larger than this many observations. */
const MAX_PER_REQUEST = 128

export interface TokenClasses {
  uncached_input_tokens: number
  cache_read_tokens: number
  cache_write_tokens: number
  output_tokens: number
  reasoning_tokens?: number
}

export interface ModelCallObservation {
  dedupe_key: string
  harness: "pi"
  harness_session?: string
  provider: string
  model: string
  operation: "chat"
  usage: TokenClasses
  outcome: "ok" | "error" | "aborted"
  error_kind?: string
  started_at: string
  duration_ms: number
  raw_usage?: string
}

/** Pi's Usage, as much of it as this mapping reads. */
export interface PiUsage {
  input?: unknown
  output?: unknown
  cacheRead?: unknown
  cacheWrite?: unknown
  reasoning?: unknown
}

function count(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0
}

/**
 * Maps Pi's Usage onto Blackbird's disjoint classes.
 *
 * `reasoning` is deliberately forwarded only when Pi reports a number. Pi
 * leaves it undefined for providers with no reasoning breakdown, and collapsing
 * that into zero would make "this model does no thinking" indistinguishable
 * from "this provider does not say", which are different facts that average
 * very differently.
 */
export function normalizePiUsage(usage: PiUsage | undefined): TokenClasses {
  const classes: TokenClasses = {
    uncached_input_tokens: count(usage?.input),
    cache_read_tokens: count(usage?.cacheRead),
    cache_write_tokens: count(usage?.cacheWrite),
    output_tokens: count(usage?.output),
  }
  if (typeof usage?.reasoning === "number" && Number.isFinite(usage.reasoning)) {
    // Blackbird requires reasoning <= output. Pi says reasoning is a subset of
    // output, so a value above it is a provider bug rather than a big number,
    // and clamping keeps one bad response from rejecting the whole observation.
    classes.reasoning_tokens = Math.min(Math.max(0, Math.floor(usage.reasoning)), classes.output_tokens)
  }
  return classes
}

const STOP_REASON_OUTCOMES: Record<string, "ok" | "error" | "aborted"> = {
  error: "error",
  aborted: "aborted",
}

export function outcomeForStopReason(stopReason: unknown): "ok" | "error" | "aborted" {
  return (typeof stopReason === "string" ? STOP_REASON_OUTCOMES[stopReason] : undefined) ?? "ok"
}

export interface EmitterOptions {
  baseURL: URL
  token: string
  fetch: typeof globalThis.fetch
  /** Called with the reason an emission was abandoned. Diagnostics only; the
   *  emitter never throws and never retries. */
  onFailure?: (error: unknown) => void
}

/**
 * Buffers observations and posts them in bounded batches.
 *
 * The emitter is deliberately fire-and-forget: `record` returns synchronously,
 * `flush` never rejects, and a failed POST discards its batch rather than
 * retrying. Retrying would trade a known-bounded memory cost for an unbounded
 * one, to recover data whose whole value is being cheap.
 */
export class TelemetryEmitter {
  readonly #options: EmitterOptions
  #buffer: ModelCallObservation[] = []
  #timer: ReturnType<typeof setTimeout> | undefined
  #inFlight: Promise<void> = Promise.resolve()
  #closed = false

  constructor(options: EmitterOptions) {
    this.#options = options
  }

  record(observation: ModelCallObservation): void {
    if (this.#closed) return
    this.#buffer.push(observation)
    if (this.#buffer.length > MAX_BUFFERED) {
      this.#buffer.splice(0, this.#buffer.length - MAX_BUFFERED)
    }
    if (this.#buffer.length >= FLUSH_AT) {
      void this.flush()
      return
    }
    if (this.#timer === undefined) {
      this.#timer = setTimeout(() => {
        this.#timer = undefined
        void this.flush()
      }, FLUSH_AFTER_MS)
      this.#timer.unref?.()
    }
  }

  async flush(): Promise<void> {
    if (this.#timer !== undefined) {
      clearTimeout(this.#timer)
      this.#timer = undefined
    }
    const pending = this.#buffer
    this.#buffer = []
    if (pending.length === 0) return this.#inFlight
    this.#inFlight = this.#inFlight.then(async () => {
      for (let index = 0; index < pending.length; index += MAX_PER_REQUEST) {
        await this.#post(pending.slice(index, index + MAX_PER_REQUEST))
      }
    })
    return this.#inFlight
  }

  async close(): Promise<void> {
    await this.flush()
    this.#closed = true
    await this.#inFlight
  }

  async #post(batch: ModelCallObservation[]): Promise<void> {
    try {
      const response = await this.#options.fetch(new URL(TELEMETRY_PATH, this.#options.baseURL), {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.#options.token}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ model_calls: batch }),
      })
      if (!response.ok) {
        this.#options.onFailure?.(new Error(`blackbird: telemetry rejected with HTTP ${response.status}`))
        return
      }
      // A 202 can still carry rejections. They mean this mapping is wrong, which
      // is worth surfacing precisely because the request itself succeeded.
      const result = await response.json() as { rejected?: number; rejections?: unknown }
      if (typeof result.rejected === "number" && result.rejected > 0) {
        this.#options.onFailure?.(new Error(
          `blackbird: ${result.rejected} observation(s) rejected: ${JSON.stringify(result.rejections)}`,
        ))
      }
    } catch (error) {
      // The daemon being absent is the normal case, not an incident.
      this.#options.onFailure?.(error)
    }
  }
}
