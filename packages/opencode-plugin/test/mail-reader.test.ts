import { mkdtemp, writeFile, rm } from "node:fs/promises"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { Effect } from "effect"
import { afterEach, expect, it } from "vitest"
import { createMailReader } from "../src/mail-reader.js"

const directories: string[] = []
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))) })
async function handshake(address = "127.0.0.1:8080", token = "private-token") {
  const directory = await mkdtemp(join(tmpdir(), "blackbird-reader-"))
  directories.push(directory)
  const path = join(directory, "admin.json")
  await writeFile(path, JSON.stringify({ schema: "blackbird.admin/v1", http_address: address, token }))
  return path
}

it("reads only authenticated admin GETs scoped to the host project and reloads rotated credentials", async () => {
  const path = await handshake()
  const calls: { url: URL; init: RequestInit | undefined }[] = []
  const fetcher: typeof fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input)
    calls.push({ url, init })
    if (url.pathname.endsWith("agents")) return Response.json({ agents: [], truncated: false })
    if (url.pathname.endsWith("thread")) return Response.json({ messages: [], has_more: false, next: 5 })
    return Response.json({ pending: [], truncated: true })
  }
  const reader = createMailReader("/repo with spaces", path, fetcher)
  await Effect.runPromise(reader.agents())
  await writeFile(path, JSON.stringify({ schema: "blackbird.admin/v1", http_address: "127.0.0.1:8080", token: "rotated" }))
  const inbox = await Effect.runPromise(reader.inbox({ agent: "Alice & Bob", unread: true }))
  await Effect.runPromise(reader.thread({ conversation_id: "conversation-1", after: 5 }))
  expect(inbox.truncated).toBe(true)
  expect(calls.map((call) => call.url.searchParams.get("project_key"))).toEqual(Array<string>(3).fill("/repo with spaces"))
  expect(calls[1]?.url.searchParams.get("agent")).toBe("Alice & Bob")
  expect(calls[1]?.url.searchParams.get("unread")).toBe("true")
  expect(calls[2]?.url.searchParams.get("after")).toBe("5")
  expect(new Headers(calls[1]?.init?.headers).get("authorization")).toBe("Bearer rotated")
  expect(calls.every((call) => call.init?.method === undefined && call.init?.redirect === "error")).toBe(true)
})

it("rejects non-loopback discovery without sending the admin token", async () => {
  let fetched = false
  const fetcher: typeof fetch = async () => { fetched = true; return Response.json({}) }
  const reader = createMailReader("/repo", await handshake("example.com:8080"), fetcher)
  await expect(Effect.runPromise(reader.agents())).rejects.toThrow("loopback")
  expect(fetched).toBe(false)
})

it("redacts malformed and unauthenticated responses and reports missing daemon", async () => {
  const path = await handshake()
  const malformed: typeof fetch = async () => Response.json({ token: "private-token" })
  await expect(Effect.runPromise(createMailReader("/repo", path, malformed).agents())).rejects.toThrow("mailbox unavailable")
  const rejected: typeof fetch = async () => new Response("private-token", { status: 401 })
  await expect(Effect.runPromise(createMailReader("/repo", path, rejected).agents())).rejects.toThrow("HTTP 401")
  await expect(Effect.runPromise(createMailReader("/repo", `${path}-missing`).agents())).rejects.toThrow("blackbird status")
})

it("propagates host interruption to the HTTP request", async () => {
  let signal: AbortSignal | undefined
  const fetcher: typeof fetch = (_input, init) => {
    signal = init?.signal ?? undefined
    return new Promise((_resolve, reject) => signal?.addEventListener("abort", () => reject(new Error("cancelled"))))
  }
  const reader = createMailReader("/repo", await handshake(), fetcher)
  const controller = new AbortController()
  const task = Effect.runPromise(reader.agents(), { signal: controller.signal })
  await new Promise<void>((resolve) => {
    const timer = setInterval(() => { if (signal) { clearInterval(timer); resolve() } }, 1)
  })
  controller.abort()
  await expect(task).rejects.toThrow()
  expect(signal?.aborted).toBe(true)
})
