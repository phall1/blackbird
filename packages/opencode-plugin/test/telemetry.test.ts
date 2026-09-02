import { describe, expect, it, vi } from "vitest"

import {
  TelemetryEmitter,
  boundedRawUsage,
  errorKindForMessage,
  normalizeOpenCodeTokens,
  outcomeForMessage,
  publishEmitter,
} from "../src/telemetry.js"
import { recordAssistantMessage, supervisorKey } from "../src/index.js"

describe("normalizeOpenCodeTokens", () => {
  // OpenCode's `input` already excludes cache: `cache.read` and `cache.write`
  // are siblings of it, not subsets. Summing them as though they overlapped is
  // the failure this whole plane exists to prevent.
  it("maps OpenCode's sibling cache counts onto the disjoint classes", () => {
    expect(normalizeOpenCodeTokens({ input: 120, output: 40, reasoning: 12, cache: { read: 9000, write: 500 } }))
      .toEqual({
        uncached_input_tokens: 120,
        cache_read_tokens: 9000,
        cache_write_tokens: 500,
        output_tokens: 40,
        reasoning_tokens: 12,
      })
  })

  it("omits reasoning when OpenCode does not report a number", () => {
    expect("reasoning_tokens" in normalizeOpenCodeTokens({ input: 1, output: 1 })).toBe(false)
  })

  it("clamps reasoning to output", () => {
    expect(normalizeOpenCodeTokens({ output: 5, reasoning: 50 }).reasoning_tokens).toBe(5)
  })

  it("treats absent, negative, and non-numeric counts as zero", () => {
    expect(normalizeOpenCodeTokens(undefined)).toEqual({
      uncached_input_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0, output_tokens: 0,
    })
  })
})

describe("outcome mapping", () => {
  it("separates an abort from a failure", () => {
    expect(outcomeForMessage(undefined)).toBe("ok")
    expect(outcomeForMessage({ name: "MessageAbortedError" })).toBe("aborted")
    expect(outcomeForMessage({ name: "ProviderAuthError" })).toBe("error")
    expect(errorKindForMessage({ name: "ProviderAuthError" })).toBe("ProviderAuthError")
    expect(errorKindForMessage(undefined)).toBeUndefined()
  })
})

describe("boundedRawUsage", () => {
  it("keeps a small payload and drops one too large for the daemon's bound", () => {
    expect(boundedRawUsage({ input: 1 })).toBe(`{"input":1}`)
    expect(boundedRawUsage({ blob: "x".repeat(5000) })).toBeUndefined()
    expect(boundedRawUsage(undefined)).toBeUndefined()
  })
})

function messageEvent(overrides: Record<string, unknown> = {}) {
  return {
    type: "message.updated",
    properties: {
      info: {
        id: "msg_opencode_1",
        sessionID: "ses_1",
        role: "assistant",
        modelID: "claude-opus-5",
        providerID: "anthropic",
        time: { created: 1_756_790_000_000, completed: 1_756_790_004_210 },
        tokens: { input: 120, output: 40, reasoning: 12, cache: { read: 9000, write: 500 } },
        ...overrides,
      },
    },
  }
}

describe("recordAssistantMessage", () => {
  const key = supervisorKey({
    baseUrl: new URL("http://127.0.0.1:8080/"),
    projectKey: "/workspace/project",
    agentName: "OpenCode",
    stateDir: "/tmp/state",
  } as never)

  function emitterFixture() {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ accepted: 1 }), { status: 202 }))
    const emitter = new TelemetryEmitter({
      baseUrl: new URL("http://127.0.0.1:8080/"), token: "secret", fetch: fetch as never,
    })
    const release = publishEmitter(key, emitter)
    return { fetch, emitter, release }
  }

  it("records a completed assistant message with a real duration", async () => {
    const { fetch, emitter, release } = emitterFixture()
    recordAssistantMessage(key, messageEvent())
    await emitter.flush()
    const body = JSON.parse((fetch.mock.calls[0]?.[1] as RequestInit).body as string) as {
      model_calls: Record<string, unknown>[]
    }
    const call = body.model_calls[0]
    expect(call?.["dedupe_key"]).toBe("msg_opencode_1")
    expect(call?.["harness_session"]).toBe("ses_1")
    expect(call?.["duration_ms"]).toBe(4210)
    expect(call?.["usage"]).toEqual({
      uncached_input_tokens: 120, cache_read_tokens: 9000, cache_write_tokens: 500,
      output_tokens: 40, reasoning_tokens: 12,
    })
    expect(call?.["raw_usage"]).toContain("9000")
    release()
  })

  // message.updated fires repeatedly while a response streams. Recording an
  // in-flight message would store a zero-duration call and then store it again.
  it("ignores a message that has not finished", async () => {
    const { fetch, emitter, release } = emitterFixture()
    recordAssistantMessage(key, messageEvent({ time: { created: 1_756_790_000_000 } }))
    await emitter.flush()
    expect(fetch).not.toHaveBeenCalled()
    release()
  })

  it("ignores non-assistant messages and unknown keys", async () => {
    const { fetch, emitter, release } = emitterFixture()
    recordAssistantMessage(key, messageEvent({ role: "user" }))
    recordAssistantMessage("no-such-key", messageEvent())
    await emitter.flush()
    expect(fetch).not.toHaveBeenCalled()
    release()
  })

  // OpenCode reference-counts one supervisor across activations, so the same
  // event can arrive twice. It is not corrected locally: the dedupe key is the
  // provider's message id and the daemon is idempotent on it.
  it("emits a stable dedupe key when the same event arrives twice", async () => {
    const { fetch, emitter, release } = emitterFixture()
    recordAssistantMessage(key, messageEvent())
    recordAssistantMessage(key, messageEvent())
    await emitter.flush()
    const body = JSON.parse((fetch.mock.calls[0]?.[1] as RequestInit).body as string) as {
      model_calls: { dedupe_key: string }[]
    }
    expect(body.model_calls.map((call) => call.dedupe_key)).toEqual(["msg_opencode_1", "msg_opencode_1"])
    release()
  })

  it("never throws on a malformed event", () => {
    const { release } = emitterFixture()
    expect(() => { recordAssistantMessage(key, {}) }).not.toThrow()
    expect(() => { recordAssistantMessage(key, { properties: null }) }).not.toThrow()
    expect(() => { recordAssistantMessage(key, messageEvent({ id: 42 })) }).not.toThrow()
    release()
  })
})
