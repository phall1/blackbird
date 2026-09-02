import { createHash } from "node:crypto"
import { chmod, mkdir, open, readFile, rename, rm, stat } from "node:fs/promises"
import { homedir } from "node:os"
import { dirname, join } from "node:path"
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent"

const CUSTOM_TYPE = "blackbird-inbox"
const CONSUMER_ID = "pi-extension"
const MAX_QUARANTINED = 4096

interface DeliveryDetails {
  blackbirdMessageId: string
  blackbirdConversationId: string
  blackbirdBodyDigest: string
}

interface State {
  quarantined: string[]
}

interface LoadedState extends State {
  legacyCursor: string
  legacyDelivered: string[]
}

interface Message {
  message_id: string
  conversation_id: string
  author_actor_id: string
  subject: string
  body: string
  body_digest: string
  sent_at: string
}

interface RuntimeOptions {
  baseURL: URL
  projectKey: string
  agentName: string
  stateDir: string
  legacyStateDir: string
}

import { TelemetryEmitter, normalizePiUsage, outcomeForStopReason } from "./telemetry.js"

export interface SupervisorDependencies {
  fetch: typeof globalThis.fetch
  sleep(milliseconds: number, signal: AbortSignal): Promise<void>
  importLegacy(path: string): Promise<{ token?: string; cursor?: string; delivered: string[]; quarantined: string[] }>
  connected(): void
}

const defaults: SupervisorDependencies = {
  fetch: globalThis.fetch,
  sleep: async (milliseconds, signal) => {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, milliseconds)
      timer.unref?.()
      const abort = (): void => { clearTimeout(timer); reject(new DOMException("Aborted", "AbortError")) }
      if (signal.aborted) abort()
      else signal.addEventListener("abort", abort, { once: true })
    })
  },
  importLegacy: importLegacyState,
  connected: () => {},
}

function object(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined
}

function string(source: Record<string, unknown>, key: string): string {
  const value = source[key]
  if (typeof value !== "string" || value === "") throw new Error(`blackbird: invalid ${key}`)
  return value
}

export function resolveOptions(cwd: string, environment: NodeJS.ProcessEnv = process.env): RuntimeOptions {
  const baseURL = new URL(environment["BLACKBIRD_API_URL"] ?? "http://127.0.0.1:8080")
  if (baseURL.protocol !== "http:" || !["127.0.0.1", "localhost", "::1"].includes(baseURL.hostname)) {
    throw new Error("blackbird: Pi delivery requires the loopback HTTP API")
  }
  baseURL.pathname = baseURL.pathname.replace(/\/$/, "") + "/"
  const root = environment["XDG_STATE_HOME"] ?? join(environment["HOME"] ?? homedir(), ".local", "state")
  const projectHash = createHash("sha256").update(cwd).digest("hex").slice(0, 16)
  return {
    baseURL,
    projectKey: cwd,
    agentName: environment["BLACKBIRD_PI_AGENT_NAME"] ?? "Pi",
    stateDir: join(root, "blackbird", "pi-extension", projectHash),
    legacyStateDir: join(root, "blackbird", "pi"),
  }
}

async function privateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 })
  await chmod(path, 0o700)
}

async function atomicWrite(path: string, content: string): Promise<void> {
  await privateDirectory(dirname(path))
  const temporary = `${path}.${process.pid}.${crypto.randomUUID()}.tmp`
  const handle = await open(temporary, "wx", 0o600)
  try { await handle.writeFile(content); await handle.sync() } finally { await handle.close() }
  await rename(temporary, path)
}

async function loadState(path: string): Promise<LoadedState> {
  try {
    const value = object(JSON.parse(await readFile(path, "utf8")))
    if (!value) throw new Error("invalid state")
    return {
      legacyCursor: typeof value["cursor"] === "string" ? value["cursor"] : "",
      legacyDelivered: Array.isArray(value["delivered"])
        ? value["delivered"].filter((item): item is string => typeof item === "string")
        : [],
      quarantined: Array.isArray(value["quarantined"])
        ? value["quarantined"].filter((item): item is string => typeof item === "string")
        : [],
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { legacyCursor: "", legacyDelivered: [], quarantined: [] }
    throw error
  }
}

async function importLegacyState(path: string): Promise<{ token?: string; cursor?: string; delivered: string[]; quarantined: string[] }> {
  try { await stat(path) } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { delivered: [], quarantined: [] }
    throw error
  }
  const { DatabaseSync } = await import("node:sqlite")
  const database = new DatabaseSync(path, { readOnly: true })
  try {
    const token = database.prepare("SELECT value FROM metadata WHERE key='registration_token'").get() as { value?: unknown } | undefined
    const cursor = database.prepare("SELECT value FROM metadata WHERE key='cursor'").get() as { value?: unknown } | undefined
    const rows = database.prepare("SELECT message_id,status FROM deliveries").all() as { message_id: unknown; status: unknown }[]
    const delivered = rows.filter((row) => row.status === "delivered").flatMap((row) => typeof row.message_id === "string" ? [row.message_id] : [])
    const quarantined = rows.filter((row) => row.status === "ambiguous" || row.status === "failed" || row.status === "running").flatMap((row) => typeof row.message_id === "string" ? [row.message_id] : [])
    const replayPending = rows.some((row) => row.status === "pending" || row.status === "retry")
    return {
      ...(typeof token?.value === "string" ? { token: token.value } : {}),
      ...(typeof cursor?.value === "string" && !replayPending ? { cursor: cursor.value } : {}),
      delivered,
      quarantined,
    }
  } finally { database.close() }
}

function messageDetails(value: unknown): DeliveryDetails | undefined {
  const source = object(value)
  if (!source || typeof source["blackbirdMessageId"] !== "string" || typeof source["blackbirdConversationId"] !== "string" || typeof source["blackbirdBodyDigest"] !== "string") return undefined
  return { blackbirdMessageId: source["blackbirdMessageId"], blackbirdConversationId: source["blackbirdConversationId"], blackbirdBodyDigest: source["blackbirdBodyDigest"] }
}

function parseMessage(value: unknown): Message {
  const source = object(value)
  if (!source) throw new Error("blackbird: invalid message")
  return {
    message_id: string(source, "message_id"), conversation_id: string(source, "conversation_id"),
    author_actor_id: string(source, "author_actor_id"), subject: string(source, "subject"), body: string(source, "body"),
    body_digest: string(source, "body_digest"), sent_at: string(source, "sent_at"),
  }
}

function prompt(message: Message): string {
  return `Blackbird durable message ID: ${message.message_id}\nConversation ID: ${message.conversation_id}\nAuthor actor ID: ${message.author_actor_id}\nSent at: ${message.sent_at}\nSubject: ${message.subject}\nBody digest: ${message.body_digest}\n\n${message.body}`
}

async function acquireLock(path: string): Promise<() => Promise<void>> {
  await privateDirectory(dirname(path))
  try {
    const handle = await open(path, "wx", 0o600)
    await handle.writeFile(`${process.pid}\n`)
    await handle.close()
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error
    const pid = Number.parseInt((await readFile(path, "utf8")).trim(), 10)
    try { process.kill(pid, 0); throw new Error(`blackbird: project inbox is already owned by process ${pid}`) }
    catch (cause) { if ((cause as NodeJS.ErrnoException).code !== "ESRCH") throw cause }
    await rm(path, { force: true })
    return acquireLock(path)
  }
  return async () => { await rm(path, { force: true }) }
}

async function register(options: RuntimeOptions, tokenPath: string, legacyToken: string | undefined, fetcher: typeof fetch, signal: AbortSignal): Promise<string> {
  let token: string | undefined
  try { token = (await readFile(tokenPath, "utf8")).trim() || undefined } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error }
  token ??= legacyToken
  const response = await fetcher(new URL("api/v1/local/agents/register", options.baseURL), {
    method: "POST", headers: { "content-type": "application/json" }, signal,
    body: JSON.stringify({ project_key: options.projectKey, agent_name: options.agentName, ...(token ? { registration_token: token } : {}) }),
  })
  if (!response.ok) throw await blackbirdFailure(response, "registration")
  const result = object(await response.json())
  const issued = result?.["registration_token"]
  if (typeof issued === "string" && issued !== "") token = issued
  if (!token) throw new Error("blackbird: registration returned no reusable token")
  await atomicWrite(tokenPath, `${token}\n`)
  return token
}

// The daemon reports a failure as application/problem+json carrying a stable
// error code and a message written for whoever made the call. Reporting only
// the status discards both, so a user debugging this extension sees a bare
// number where the server had already explained itself.
export async function blackbirdFailure(response: Response, action: string): Promise<Error> {
  let detail = ""
  try {
    const problem = object(await response.json())
    const code = problem?.["code"]
    if (typeof code === "string" && code !== "") {
      const message = problem?.["message"]
      detail = typeof message === "string" && message !== "" ? `: ${code}: ${message}` : `: ${code}`
    }
  } catch {
    // A body that is absent or not JSON leaves the status as the only signal.
  }
  return new Error(`blackbird: ${action} failed with HTTP ${response.status}${detail}`)
}

export async function runSupervisor(pi: ExtensionAPI, ctx: ExtensionContext, options: RuntimeOptions, signal: AbortSignal, dependencies: SupervisorDependencies = defaults): Promise<void> {
  await privateDirectory(options.stateDir)
  const releaseLock = await acquireLock(join(options.stateDir, "active.lock"))
  const statePath = join(options.stateDir, "state.json")
  try {
    const loaded = await loadState(statePath)
    const state: State = { quarantined: loaded.quarantined }
    const legacy = await dependencies.importLegacy(join(options.legacyStateDir, "deliveries.db"))
    const legacyCursor = loaded.legacyCursor || legacy.cursor || ""
    // Transcript-derived IDs remain an in-memory host idempotency check. The
    // durable delivery position itself now belongs to the server consumer.
    const delivered = new Set([...legacy.delivered, ...loaded.legacyDelivered])
    const quarantined = new Set([...legacy.quarantined, ...state.quarantined])
    for (const entry of ctx.sessionManager.getEntries()) {
      if (entry.type === "custom_message" && entry.customType === CUSTOM_TYPE) {
        const details = messageDetails(entry.details)
        if (details) delivered.add(details.blackbirdMessageId)
      }
    }
    let persistChain = Promise.resolve()
    const persist = async (): Promise<void> => {
      persistChain = persistChain.then(async () => {
        state.quarantined = [...quarantined].slice(-MAX_QUARANTINED)
        await atomicWrite(statePath, `${JSON.stringify(state)}\n`)
      })
      await persistChain
    }
    const token = await register(options, join(options.stateDir, "token"), legacy.token, dependencies.fetch, signal)
    dependencies.connected()
    const headers = { authorization: `Bearer ${token}`, accept: "application/json" }
    const acknowledge = async (cursor: string): Promise<void> => {
      const response = await dependencies.fetch(new URL("api/v1/local/coordination/events/ack", options.baseURL), {
        method: "POST", headers: { ...headers, "content-type": "application/json" }, signal,
        body: JSON.stringify({ consumer_id: CONSUMER_ID, cursor }),
      })
      if (!response.ok) throw await blackbirdFailure(response, "cursor acknowledgement")
    }
    if (legacyCursor !== "") await acknowledge(legacyCursor)
    // This state rewrite retires the old cursor/delivered arrays only after the
    // server has accepted their position.
    await persist()
    const admitted = new Map<string, { resolve(): void; reject(error: Error): void }>()
    const onMessageEnd = (event: { message: unknown }): void => {
      const message = object(event.message)
      if (message?.["role"] !== "custom" || message["customType"] !== CUSTOM_TYPE) return
      const details = messageDetails(message["details"])
      if (!details) return
      delivered.add(details.blackbirdMessageId)
      admitted.get(details.blackbirdMessageId)?.resolve()
      admitted.delete(details.blackbirdMessageId)
    }
    pi.on("message_end", onMessageEnd)

    // The observation plane (blackbird ADR-0001). Pi is the only harness that
    // hands an extension a fully normalized Usage, so this records what it is
    // given rather than reinterpreting it.
    //
    // It rides the same bearer token and shares this supervisor's lifetime, and
    // it is deliberately downstream of everything above: an emitter failure
    // cannot reach mail delivery, because the emitter never throws.
    const telemetry = process.env["BLACKBIRD_PI_TELEMETRY"] === "0"
      ? undefined
      : new TelemetryEmitter({ baseURL: options.baseURL, token, fetch: dependencies.fetch })
    // message_end reports when a response finished. Latency needs when it
    // started, which only message_start knows, so the pair is what produces a
    // duration rather than a timestamp.
    const startedAt = new Map<string, number>()
    const turnKey = (message: Record<string, unknown>): string =>
      typeof message["responseId"] === "string" && message["responseId"] !== "" ? message["responseId"] : "current"
    const onMessageStart = (): void => { startedAt.set("current", Date.now()) }
    const onModelUsage = (event: { message: unknown }): void => {
      if (!telemetry) return
      const message = object(event.message)
      if (!message || message["role"] !== "assistant") return
      const usage = object(message["usage"])
      if (!usage) return
      const key = turnKey(message)
      const began = startedAt.get(key) ?? startedAt.get("current") ?? Date.now()
      startedAt.delete(key)
      startedAt.delete("current")
      const responseId = typeof message["responseId"] === "string" ? message["responseId"] : ""
      const model = typeof message["responseModel"] === "string" && message["responseModel"] !== ""
        ? message["responseModel"]
        : typeof message["model"] === "string" ? message["model"] : ""
      const provider = typeof message["provider"] === "string" ? message["provider"] : ""
      if (model === "" || provider === "") return
      telemetry.record({
        // responseId is the provider's own identifier when present, which makes
        // a retry or a replayed event idempotent at the daemon. Without one a
        // synthesized key simply never dedupes, which is correct.
        dedupe_key: responseId !== "" ? responseId : `pi:${String(began)}:${String(Math.random()).slice(2, 10)}`,
        harness: "pi",
        provider,
        model,
        operation: "chat",
        usage: normalizePiUsage(usage),
        outcome: outcomeForStopReason(message["stopReason"]),
        started_at: new Date(began).toISOString(),
        duration_ms: Math.max(0, Date.now() - began),
      })
    }
    pi.on("message_start", onMessageStart)
    pi.on("message_end", onModelUsage)
    signal.addEventListener("abort", () => { void telemetry?.close() }, { once: true })
    const deliver = async (message: Message): Promise<void> => {
      if (delivered.has(message.message_id) || quarantined.has(message.message_id)) return
      await new Promise<void>((resolve, reject) => {
        const abort = (): void => {
          admitted.delete(message.message_id)
          reject(new DOMException("Aborted", "AbortError"))
        }
        const finish = (): void => {
          signal.removeEventListener("abort", abort)
          resolve()
        }
        admitted.set(message.message_id, { resolve: finish, reject })
        if (signal.aborted) { abort(); return }
        signal.addEventListener("abort", abort, { once: true })
        pi.sendMessage({ customType: CUSTOM_TYPE, content: prompt(message), display: true, details: {
          blackbirdMessageId: message.message_id,
          blackbirdConversationId: message.conversation_id,
          blackbirdBodyDigest: message.body_digest,
        } }, { triggerTurn: true, deliverAs: "followUp" })
      })
    }
    const catchUp = async (): Promise<void> => {
      while (!signal.aborted) {
        const url = new URL("api/v1/local/coordination/events", options.baseURL)
        url.searchParams.set("limit", "100")
        url.searchParams.set("consumer", CONSUMER_ID)
        const response = await dependencies.fetch(url, { headers, signal })
        if (!response.ok) throw await blackbirdFailure(response, "catch-up")
        const page = object(await response.json())
        if (!page || !Array.isArray(page["events"])) throw new Error("blackbird: invalid catch-up page")
        for (const value of page["events"]) {
          const event = object(value)
          const cursor = event?.["cursor"]
          if (!event || typeof cursor !== "string" || cursor === "") throw new Error("blackbird: invalid event cursor")
          if (event["type"] === "message.available") {
            const subject = event["subject"]
            if (typeof subject !== "string" || subject === "") throw new Error("blackbird: invalid message event")
            // An ambiguous host delivery is intentionally not acknowledged. It
            // remains quarantined at the head until an operator reconciles it.
            if (quarantined.has(subject)) return
            if (!delivered.has(subject)) {
              const messageResponse = await dependencies.fetch(new URL(`api/v1/local/messages/${encodeURIComponent(subject)}`, options.baseURL), { headers, signal })
              if (!messageResponse.ok) throw await blackbirdFailure(messageResponse, "message fetch")
              const message = parseMessage(await messageResponse.json())
              if (message.message_id !== subject) throw new Error("blackbird: message ID mismatch")
              await deliver(message)
            }
          }
          await acknowledge(cursor)
        }
        if (page["has_more"] === true && page["events"].length === 0) throw new Error("blackbird: catch-up page did not advance")
        if (page["has_more"] !== true) return
      }
    }
    let delay = 250
    while (!signal.aborted) {
      try {
        await catchUp()
        const url = new URL("api/v1/local/coordination/events/stream", options.baseURL)
        url.searchParams.set("consumer", CONSUMER_ID)
        const response = await dependencies.fetch(url, { headers: { ...headers, accept: "text/event-stream" }, signal })
        if (!response.ok) throw await blackbirdFailure(response, "stream")
        const reader = response.body?.getReader()
        if (!reader) throw new Error("blackbird: stream has no body")
        await reader.read()
        await reader.cancel()
        delay = 250
      } catch (error) {
        if (signal.aborted || (error as Error).name === "AbortError") break
        await dependencies.sleep(delay, signal)
        delay = Math.min(delay * 2, 30_000)
      }
    }
    for (const pending of admitted.values()) pending.reject(new Error("blackbird: Pi session stopped before message admission"))
  } finally { await releaseLock() }
}

export default function blackbirdPi(pi: ExtensionAPI): void {
  let controller: AbortController | undefined
  let task: Promise<void> | undefined
  let status = "inactive"
  pi.registerCommand("blackbird", {
    description: "Show Blackbird inbox connection status",
    handler: async (_args, ctx) => { ctx.ui.notify(`Blackbird Pi inbox: ${status}`, status === "connected" ? "info" : "warning") },
  })
  pi.on("session_start", (_event, ctx) => {
    if (process.env["BLACKBIRD_PI_DISABLED"] === "1") { status = "disabled"; return }
    controller = new AbortController()
    status = "connecting"
    task = runSupervisor(pi, ctx, resolveOptions(ctx.cwd), controller.signal, { ...defaults, connected: () => { status = "connected" } }).then(() => { status = "stopped" }).catch((error: unknown) => {
      status = String(error)
      if (ctx.hasUI) ctx.ui.notify(status, "warning")
    })
  })
  pi.on("session_shutdown", async () => {
    controller?.abort()
    await task
    controller = undefined
    task = undefined
    status = "inactive"
  })
}
