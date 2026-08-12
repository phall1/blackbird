import { chmod, mkdtemp, readFile, stat, writeFile } from "node:fs/promises"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, describe, expect, it, vi } from "vitest"
import { acquireSupervisor, deterministicMessageID, resolveOptions, runSupervisor, type SessionClient } from "../src/index.js"

const controllers: AbortController[] = []
afterEach(() => { for (const controller of controllers) controller.abort() })

describe("configuration and IDs", () => {
  it("uses the XDG state directory and stable OpenCode IDs", () => {
    const options = resolveOptions({ baseUrl: "https://blackbird.test", projectKey: "/repo", agentName: "Agent One" }, { XDG_STATE_HOME: "/state" })
    expect(options.stateDir).toMatch(/^\/state\/blackbird\/opencode\/[a-f0-9]{16}\/Agent_One$/)
    expect(deterministicMessageID("message_123")).toMatch(/^msg_[A-Za-z0-9_-]{26}$/)
    expect(deterministicMessageID("message_123")).toBe(deterministicMessageID("message_123"))
    expect(options.catchUpPath).toBe("/api/v1/local/coordination/events")
    expect(options.streamPath).toBe("/api/v1/local/coordination/events/stream")
    expect(options.messagePath).toBe("/api/v1/local/messages")
  })

  it("expands a portable home-relative project key", () => {
    const options = resolveOptions({ baseUrl: "http://127.0.0.1:8081", projectKey: "~/workspace/project", agentName: "agent" })
    expect(options.projectKey).toBe(join(homedir(), "workspace/project"))
  })

  it("rejects insecure or ambiguous configuration", () => {
    expect(() => resolveOptions({ baseUrl: "file:///tmp", projectKey: "/repo", agentName: "agent" })).toThrow(/http or https/)
    expect(() => resolveOptions({ baseUrl: "http://blackbird.example", projectKey: "/repo", agentName: "agent" })).toThrow(/loopback/)
    expect(() => resolveOptions({ baseUrl: "http://127.0.0.1", projectKey: "/repo", agentName: "agent", catchUpLimit: 257 })).toThrow(/catchUpLimit/)
    expect(() => resolveOptions({ baseUrl: "https://x", projectKey: "/repo", agentName: "agent", routing: { mode: "fixed", sessionID: "" } })).toThrow(/sessionID/)
  })
})

describe("supervisor", () => {
  it("shares one supervisor across repeated OpenCode project activations", async () => {
    let starts = 0
    let stopped = false
    const start = async (signal: AbortSignal) => {
      starts += 1
      await new Promise<void>((resolve) => signal.addEventListener("abort", () => resolve(), { once: true }))
      stopped = true
    }
    const releaseFirst = acquireSupervisor("identity", start)
    const releaseSecond = acquireSupervisor("identity", start)
    expect(starts).toBe(1)
    await releaseFirst()
    expect(stopped).toBe(false)
    await releaseSecond()
    expect(stopped).toBe(true)
  })

  it("starts a replacement after a supervisor exits", async () => {
    let starts = 0
    const release = acquireSupervisor("restart", async () => { starts += 1 })
    await vi.waitFor(() => expect(starts).toBe(1))
    const releaseReplacement = acquireSupervisor("restart", async () => { starts += 1 })
    await vi.waitFor(() => expect(starts).toBe(2))
    await release()
    await releaseReplacement()
  })

  it("registers, catches up opaque events, fetches exact messages, and treats SSE as wake-only", async () => {
    const stateDir = await mkdtemp(join(tmpdir(), "blackbird-plugin-"))
    const controller = new AbortController()
    controllers.push(controller)
    const prompt = vi.fn<SessionClient["prompt"]>(async () => undefined)
    const session: SessionClient = { create: vi.fn<SessionClient["create"]>(async () => ({ id: "ses_created" })), prompt }
    const requests: { url: URL; init?: RequestInit }[] = []
    let catchUps = 0
    const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : input)
      requests.push({ url, ...(init === undefined ? {} : { init }) })
      if (url.pathname === "/register") return Response.json({ registration_token: "secret" })
      if (url.pathname === "/events") {
        catchUps += 1
        return Response.json({
          events: catchUps === 1
            ? [
                { type: "lease.renewed", subject: "lease_1", payload: {}, occurred_at: "2026-08-12T00:00:00Z" },
                { type: "message.available", subject: "message_1", payload: { tempting_body: "never deliver me" }, occurred_at: "2026-08-12T00:00:01Z" },
              ]
            : [],
          next_cursor: catchUps === 1 ? "opaque/page+1==" : "opaque/page+1==",
          has_more: false,
        })
      }
      if (url.pathname === "/messages/message_1") {
        return Response.json({ message_id: "message_1", conversation_id: "conversation_1", subject: "Work", body: "Do it", position: 1 })
      }
      const stream = new ReadableStream({ start(target) { target.enqueue(new TextEncoder().encode(`event: cursor\nid: ignored\ndata: {"cursor":"wake-only","message":{"body":"never deliver me"}}\n\n`)) } })
      return new Response(stream, { headers: { "content-type": "text/event-stream" } })
    })
    const task = runSupervisor(session, {
      baseUrl: "https://blackbird.test",
      projectKey: "/repo",
      agentName: "agent",
      stateDir,
      routing: { mode: "fixed", sessionID: "ses_fixed" },
      paths: { register: "/register", catchUp: "/events", stream: "/stream", message: "/messages" },
    }, controller.signal, { fetch: fetcher as typeof fetch, random: () => 0.5, sleep: async () => undefined })
    await vi.waitFor(() => expect(prompt).toHaveBeenCalledOnce())
    expect(prompt).toHaveBeenCalledWith(expect.objectContaining({
      sessionID: "ses_fixed",
      id: deterministicMessageID("message_1"),
      delivery: "queue",
      resume: true,
      text: "[Blackbird message message_1 from unknown actor]\nSubject: Work\n\nDo it",
    }))
    await vi.waitFor(() => expect(catchUps).toBeGreaterThan(1))
    controller.abort()
    await task
    expect(JSON.parse(await readFile(join(stateDir, "cursor.json"), "utf8"))).toMatchObject({ cursor: "opaque/page+1==", delivered: ["message_1"] })
    expect(requests[1]?.url.searchParams.has("after")).toBe(false)
    expect(requests.some(({ url }) => url.pathname === "/messages/message_1")).toBe(true)
    expect(requests.filter(({ url }) => url.pathname === "/messages/message_1")).toHaveLength(1)
    expect(requests.some(({ url }) => url.pathname === "/events" && url.searchParams.get("after") === "opaque/page+1==")).toBe(true)
    expect((await stat(join(stateDir, "token"))).mode & 0o777).toBe(0o600)
    expect((await stat(join(stateDir, "cursor.json"))).mode & 0o777).toBe(0o600)
  })

  it("resumes registration with a saved token when the server omits a newly issued token", async () => {
    const stateDir = await mkdtemp(join(tmpdir(), "blackbird-plugin-"))
    await writeFile(join(stateDir, "token"), "saved-secret\n", { mode: 0o644 })
    const controller = new AbortController()
    controllers.push(controller)
    let registrationBody: unknown
    const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : input)
      if (url.pathname === "/register") {
        if (typeof init?.body !== "string") throw new Error("registration body was not JSON text")
        registrationBody = JSON.parse(init.body) as unknown
        return Response.json({ actor_id: "actor", session_id: "new-session" })
      }
      if (url.pathname === "/events") return Response.json({ events: [], next_cursor: "baseline", has_more: false })
      controller.abort()
      throw new DOMException("Aborted", "AbortError")
    })
    const session: SessionClient = { create: vi.fn(), prompt: vi.fn() }
    await runSupervisor(session, {
      baseUrl: "https://blackbird.test", projectKey: "/repo", agentName: "agent", stateDir,
      paths: { register: "/register", catchUp: "/events", stream: "/stream" }, routing: { mode: "conversation" },
      backoff: { minimumMs: 10, maximumMs: 10, jitter: 0 },
    }, controller.signal, { fetch: fetcher as typeof fetch, random: () => 0.5, sleep: async () => undefined })
    expect(registrationBody).toEqual({ project_key: "/repo", agent_name: "agent", registration_token: "saved-secret" })
    expect(await readFile(join(stateDir, "token"), "utf8")).toBe("saved-secret\n")
    expect((await stat(join(stateDir, "token"))).mode & 0o777).toBe(0o600)
  })

  it("does not commit a page cursor until every available message is admitted", async () => {
    const stateDir = await mkdtemp(join(tmpdir(), "blackbird-plugin-"))
    await chmod(stateDir, 0o700)
    const controller = new AbortController()
    controllers.push(controller)
    const prompt = vi.fn<SessionClient["prompt"]>(async ({ metadata }) => {
      if (metadata["blackbird_message_id"] === "m2") throw new Error("queue unavailable")
    })
    const fetcher = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(input instanceof Request ? input.url : input)
      if (url.pathname === "/register") return Response.json({ registration_token: "secret" })
      if (url.pathname === "/events") {
        return Response.json({
          events: ["m1", "m2"].map((subject) => ({ type: "message.available", subject, payload: {}, occurred_at: "2026-08-12T00:00:00Z" })),
          next_cursor: "must-not-commit",
          has_more: false,
        })
      }
      const id = url.pathname.split("/").at(-1)
      if (id === undefined) throw new Error("message URL omitted its ID")
      return Response.json({ message_id: id, conversation_id: "conversation", subject: id, body: `body ${id}`, position: id === "m1" ? 1 : 2 })
    })
    const create = vi.fn<SessionClient["create"]>(async () => ({ id: "session" }))
    await runSupervisor({ create, prompt }, {
      baseUrl: "https://blackbird.test", projectKey: "/repo", agentName: "agent", stateDir,
      paths: { register: "/register", catchUp: "/events", stream: "/stream", message: "/messages" },
      backoff: { minimumMs: 10, maximumMs: 10, jitter: 0 },
    }, controller.signal, { fetch: fetcher as typeof fetch, random: () => 0.5, sleep: async () => { controller.abort() } })
    const state = JSON.parse(await readFile(join(stateDir, "cursor.json"), "utf8")) as unknown
    expect(state).toMatchObject({ cursor: "" })
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ location: { directory: "/repo" } }))
    expect(prompt.mock.calls.map(([call]) => call.metadata["blackbird_message_id"])).toEqual(["m1", "m2"])
  })
})
