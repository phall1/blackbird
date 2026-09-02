import { describe, expect, it, vi } from "vitest"

import { TelemetryEmitter, normalizePiUsage, outcomeForStopReason } from "../extensions/telemetry.js"

describe("normalizePiUsage", () => {
  // Pi already hands an extension disjoint classes -- its provider adapters do
  // the subtraction ("OpenAI includes cached and cache-write tokens in
  // input_tokens, so subtract both"). This mapping renames; it must not adjust.
  it("carries Pi's disjoint classes across unchanged", () => {
    expect(normalizePiUsage({ input: 2, cacheRead: 26354, cacheWrite: 23947, output: 1469, reasoning: 298 }))
      .toEqual({
        uncached_input_tokens: 2,
        cache_read_tokens: 26354,
        cache_write_tokens: 23947,
        output_tokens: 1469,
        reasoning_tokens: 298,
      })
  })

  // "this provider reports no reasoning breakdown" and "this call did no
  // reasoning" are different facts that would average identically if collapsed.
  it("omits reasoning entirely when Pi does not report it", () => {
    const classes = normalizePiUsage({ input: 10, output: 5 })
    expect(classes.reasoning_tokens).toBeUndefined()
    expect("reasoning_tokens" in classes).toBe(false)
  })

  it("keeps a reported zero distinguishable from an absent value", () => {
    expect(normalizePiUsage({ input: 10, output: 5, reasoning: 0 }).reasoning_tokens).toBe(0)
  })

  // Blackbird requires reasoning <= output. A provider that disagrees is a bug
  // upstream, and rejecting the whole observation over it loses real spend.
  it("clamps reasoning to output rather than losing the observation", () => {
    expect(normalizePiUsage({ output: 5, reasoning: 9 }).reasoning_tokens).toBe(5)
  })

  it("treats missing, negative, and non-numeric counts as zero", () => {
    expect(normalizePiUsage(undefined)).toEqual({
      uncached_input_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0, output_tokens: 0,
    })
    expect(normalizePiUsage({ input: -5, output: "many" }).uncached_input_tokens).toBe(0)
  })
})

describe("outcomeForStopReason", () => {
  it("separates failure from cancellation", () => {
    expect(outcomeForStopReason("error")).toBe("error")
    expect(outcomeForStopReason("aborted")).toBe("aborted")
    expect(outcomeForStopReason("stop")).toBe("ok")
    expect(outcomeForStopReason(undefined)).toBe("ok")
  })
})

function observation(dedupe: string) {
  return {
    dedupe_key: dedupe,
    harness: "pi" as const,
    provider: "anthropic",
    model: "claude-opus-5",
    operation: "chat" as const,
    usage: { uncached_input_tokens: 1, cache_read_tokens: 0, cache_write_tokens: 0, output_tokens: 1 },
    outcome: "ok" as const,
    started_at: "2026-09-02T05:06:52.813Z",
    duration_ms: 10,
  }
}

describe("TelemetryEmitter", () => {
  it("posts a batch with the bearer token to the ingest route", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ accepted: 1 }), { status: 202 }))
    const emitter = new TelemetryEmitter({
      baseURL: new URL("http://127.0.0.1:8080/"), token: "secret", fetch: fetch as never,
    })
    emitter.record(observation("a"))
    await emitter.flush()

    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, init] = fetch.mock.calls[0] as [URL, RequestInit]
    expect(url.pathname).toBe("/api/v1/local/telemetry")
    expect((init.headers as Record<string, string>)["authorization"]).toBe("Bearer secret")
    expect(JSON.parse(init.body as string)).toEqual({ model_calls: [observation("a")] })
  })

  // The daemon being absent is the normal case on a machine that does not run
  // it, not an incident, and it must never reach Pi.
  it("swallows a transport failure", async () => {
    const onFailure = vi.fn()
    const emitter = new TelemetryEmitter({
      baseURL: new URL("http://127.0.0.1:8080/"),
      token: "secret",
      fetch: vi.fn().mockRejectedValue(new Error("connection refused")) as never,
      onFailure,
    })
    emitter.record(observation("a"))
    await expect(emitter.flush()).resolves.toBeUndefined()
    expect(onFailure).toHaveBeenCalledTimes(1)
  })

  // A 202 that reports rejections means this mapping is wrong, which is worth
  // surfacing precisely because the request itself succeeded.
  it("surfaces rejections carried by a successful response", async () => {
    const onFailure = vi.fn()
    const emitter = new TelemetryEmitter({
      baseURL: new URL("http://127.0.0.1:8080/"),
      token: "secret",
      fetch: vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ accepted: 0, rejected: 1, rejections: [{ reason: "bad" }] }), { status: 202 }),
      ) as never,
      onFailure,
    })
    emitter.record(observation("a"))
    await emitter.flush()
    expect(onFailure).toHaveBeenCalledTimes(1)
    expect(String(onFailure.mock.calls[0]?.[0])).toContain("rejected")
  })

  it("splits a buffer larger than the daemon's per-request bound", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ accepted: 1 }), { status: 202 }))
    const emitter = new TelemetryEmitter({
      baseURL: new URL("http://127.0.0.1:8080/"), token: "secret", fetch: fetch as never,
    })
    // Flushing is triggered by the buffer threshold, so drive it directly.
    for (let index = 0; index < 200; index += 1) emitter.record(observation(`k${String(index)}`))
    await emitter.flush()
    const submitted = fetch.mock.calls.reduce(
      (total, call) => total + (JSON.parse((call[1] as RequestInit).body as string) as { model_calls: unknown[] }).model_calls.length,
      0,
    )
    expect(submitted).toBe(200)
    for (const call of fetch.mock.calls) {
      const body = JSON.parse((call[1] as RequestInit).body as string) as { model_calls: unknown[] }
      expect(body.model_calls.length).toBeLessThanOrEqual(128)
    }
  })

  it("stops recording once closed", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ accepted: 1 }), { status: 202 }))
    const emitter = new TelemetryEmitter({
      baseURL: new URL("http://127.0.0.1:8080/"), token: "secret", fetch: fetch as never,
    })
    await emitter.close()
    emitter.record(observation("after-close"))
    await emitter.flush()
    expect(fetch).not.toHaveBeenCalled()
  })
})
