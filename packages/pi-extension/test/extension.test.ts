import { mkdtemp, readFile, stat } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent"
import { afterEach, describe, expect, it, vi } from "vitest"
import { blackbirdFailure, resolveOptions, runSupervisor, type SupervisorDependencies } from "../extensions/index.js"

const controllers: AbortController[] = []
afterEach(() => { for (const controller of controllers) controller.abort() })

function context(entries: unknown[] = []): ExtensionContext {
  return { sessionManager: { getEntries: () => entries } } as unknown as ExtensionContext
}

function host(onSend?: (message: Record<string, unknown>) => void): ExtensionAPI {
  const handlers = new Map<string, ((event: unknown) => void)[]>()
  return {
    on: vi.fn((name: string, handler: (event: unknown) => void) => {
      const values = handlers.get(name) ?? []
      values.push(handler)
      handlers.set(name, values)
    }),
    sendMessage: vi.fn((message: Record<string, unknown>) => {
      onSend?.(message)
      for (const handler of handlers.get("message_end") ?? []) handler({ message: { role: "custom", ...message } })
    }),
  } as unknown as ExtensionAPI
}

function dependencies(fetcher: typeof fetch, legacy?: SupervisorDependencies["importLegacy"], connected = vi.fn()): SupervisorDependencies {
  return { fetch: fetcher, importLegacy: legacy ?? (async () => ({ delivered: [], quarantined: [] })), sleep: async (_milliseconds, signal) => {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError")
  }, connected }
}

describe("configuration", () => {
  it("derives private project state and rejects non-loopback transport", () => {
    expect(resolveOptions("/repo", { XDG_STATE_HOME: "/state" }).stateDir).toMatch(/^\/state\/blackbird\/pi-extension\/[a-f0-9]{16}$/)
    expect(() => resolveOptions("/repo", { BLACKBIRD_API_URL: "https://example.com" })).toThrow(/loopback/)
  })
})

describe("supervisor", () => {
  it("registers, admits the exact message into Pi, commits the cursor, and persists private state", async () => {
    const stateDir = await mkdtemp(join(tmpdir(), "blackbird-pi-"))
    const controller = new AbortController()
    controllers.push(controller)
    const sent: Record<string, unknown>[] = []
    const connected = vi.fn()
    let catchUps = 0
    const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : input)
      if (url.pathname.endsWith("/agents/register")) {
        expect(JSON.parse(String(init?.body))).toEqual({ project_key: "/repo", agent_name: "Pi" })
        return Response.json({ registration_token: "token" })
      }
      if (url.pathname.endsWith("/coordination/events")) {
        catchUps += 1
        return Response.json({
          events: catchUps === 1 ? [{ type: "message.available", subject: "m1", payload: {}, occurred_at: "now" }] : [],
          next_cursor: "cursor-1", has_more: false,
        })
      }
      if (url.pathname.endsWith("/messages/m1")) return Response.json({
        message_id: "m1", conversation_id: "c1", author_actor_id: "a1", subject: "Work", body: "Do it",
        body_digest: "digest", sent_at: "now",
      })
      controller.abort()
      throw new DOMException("Aborted", "AbortError")
    })
    await runSupervisor(host((message) => sent.push(message)), context(), {
      ...resolveOptions("/repo", { XDG_STATE_HOME: "/unused" }), stateDir, legacyStateDir: join(stateDir, "legacy"),
    }, controller.signal, dependencies(fetcher as typeof fetch, undefined, connected))
    expect(connected).toHaveBeenCalledOnce()
    expect(sent).toEqual([expect.objectContaining({ customType: "blackbird-inbox", details: {
      blackbirdMessageId: "m1", blackbirdConversationId: "c1", blackbirdBodyDigest: "digest",
    } })])
    expect(JSON.parse(await readFile(join(stateDir, "state.json"), "utf8"))).toMatchObject({ cursor: "cursor-1", delivered: ["m1"] })
    expect((await stat(join(stateDir, "token"))).mode & 0o777).toBe(0o600)
    expect((await stat(stateDir)).mode & 0o777).toBe(0o700)
  })

  it("does not fetch delivered or quarantined legacy messages and resumes the legacy token", async () => {
    const stateDir = await mkdtemp(join(tmpdir(), "blackbird-pi-"))
    const controller = new AbortController()
    controllers.push(controller)
    let registration: unknown
    const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : input)
      if (url.pathname.endsWith("/agents/register")) {
        registration = JSON.parse(String(init?.body))
        return Response.json({})
      }
      if (url.pathname.endsWith("/coordination/events")) return Response.json({
        events: ["delivered", "ambiguous"].map((subject) => ({ type: "message.available", subject, payload: {}, occurred_at: "now" })),
        next_cursor: "legacy-cursor", has_more: false,
      })
      controller.abort()
      throw new DOMException("Aborted", "AbortError")
    })
    const sendMessage = vi.fn()
    await runSupervisor(host(sendMessage), context(), {
      ...resolveOptions("/repo", { XDG_STATE_HOME: "/unused" }), stateDir, legacyStateDir: join(stateDir, "legacy"),
    }, controller.signal, dependencies(fetcher as typeof fetch, async () => ({
      token: "legacy-token", cursor: "legacy-cursor", delivered: ["delivered"], quarantined: ["ambiguous"],
    })))
    expect(registration).toMatchObject({ registration_token: "legacy-token" })
    expect(sendMessage).not.toHaveBeenCalled()
    expect(fetcher.mock.calls.some(([input]) => new URL(input instanceof Request ? input.url : input).pathname.includes("/messages/"))).toBe(false)
  })

  it("deduplicates a message already present in the active Pi session", async () => {
    const stateDir = await mkdtemp(join(tmpdir(), "blackbird-pi-"))
    const controller = new AbortController()
    controllers.push(controller)
    const fetcher = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(input instanceof Request ? input.url : input)
      if (url.pathname.endsWith("/agents/register")) return Response.json({ registration_token: "token" })
      if (url.pathname.endsWith("/coordination/events")) return Response.json({
        events: [{ type: "message.available", subject: "m1", payload: {}, occurred_at: "now" }], next_cursor: "cursor", has_more: false,
      })
      controller.abort()
      throw new DOMException("Aborted", "AbortError")
    })
    const sendMessage = vi.fn()
    await runSupervisor(host(sendMessage), context([{ type: "custom_message", customType: "blackbird-inbox", details: {
      blackbirdMessageId: "m1", blackbirdConversationId: "c1", blackbirdBodyDigest: "digest",
    } }]), { ...resolveOptions("/repo", { XDG_STATE_HOME: "/unused" }), stateDir, legacyStateDir: join(stateDir, "legacy") },
    controller.signal, dependencies(fetcher as typeof fetch))
    expect(sendMessage).not.toHaveBeenCalled()
  })

  it("stops promptly when Pi shuts down before a queued message is admitted", async () => {
    const stateDir = await mkdtemp(join(tmpdir(), "blackbird-pi-"))
    const controller = new AbortController()
    controllers.push(controller)
    const fetcher = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(input instanceof Request ? input.url : input)
      if (url.pathname.endsWith("/agents/register")) return Response.json({ registration_token: "token" })
      if (url.pathname.endsWith("/coordination/events")) return Response.json({
        events: [{ type: "message.available", subject: "m1", payload: {}, occurred_at: "now" }], next_cursor: "cursor", has_more: false,
      })
      if (url.pathname.endsWith("/messages/m1")) return Response.json({
        message_id: "m1", conversation_id: "c1", author_actor_id: "a1", subject: "Work", body: "Do it", body_digest: "digest", sent_at: "now",
      })
      throw new Error(`unexpected URL ${url}`)
    })
    const task = runSupervisor({ on: vi.fn(), sendMessage: vi.fn() } as unknown as ExtensionAPI, context(), {
      ...resolveOptions("/repo", { XDG_STATE_HOME: "/unused" }), stateDir, legacyStateDir: join(stateDir, "legacy"),
    }, controller.signal, dependencies(fetcher as typeof fetch))
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(3))
    controller.abort()
    await expect(task).resolves.toBeUndefined()
  })
})

describe("blackbirdFailure", () => {
  it("carries the daemon's error code and message", async () => {
    const response = new Response(JSON.stringify({ code: "LEASE_CONFLICT", message: "an active overlapping lease exists" }),
      { status: 409, headers: { "content-type": "application/problem+json" } })
    const error = await blackbirdFailure(response, "reservation")
    expect(error.message).toBe("blackbird: reservation failed with HTTP 409: LEASE_CONFLICT: an active overlapping lease exists")
  })

  it("reports the code alone when the problem carries no message", async () => {
    const response = new Response(JSON.stringify({ code: "UNAUTHENTICATED" }), { status: 401 })
    expect((await blackbirdFailure(response, "registration")).message)
      .toBe("blackbird: registration failed with HTTP 401: UNAUTHENTICATED")
  })

  it("falls back to the status when the body is not a problem document", async () => {
    const response = new Response("<html>bad gateway</html>", { status: 502 })
    expect((await blackbirdFailure(response, "stream")).message).toBe("blackbird: stream failed with HTTP 502")
  })
})
