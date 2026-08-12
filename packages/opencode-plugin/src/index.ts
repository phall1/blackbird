import { createHash } from "node:crypto"
import { chmod, mkdir, open, readFile, rename } from "node:fs/promises"
import { homedir } from "node:os"
import { dirname, join } from "node:path"
import { Plugin, type PluginOptions } from "@opencode-ai/plugin"

type Cursor = string
type MessagePosition = string | number

export interface BlackbirdMessage {
  readonly message_id: string
  readonly conversation_id: string
  readonly subject: string
  readonly body: string
  readonly position: MessagePosition
  readonly author_actor_id?: string
  readonly sent_at?: string
}

interface State {
  cursor: Cursor
  delivered: string[]
  sessions: Record<string, string>
}

interface RoutingFixed {
  readonly mode: "fixed"
  readonly sessionID: string
}

interface RoutingConversation {
  readonly mode: "conversation"
  readonly agent?: string
}

export interface BlackbirdOptions {
  readonly baseUrl: string
  readonly projectKey: string
  readonly agentName: string
  readonly token?: string
  readonly stateDir?: string
  readonly routing?: RoutingFixed | RoutingConversation
  readonly paths?: {
    readonly register?: string
    readonly catchUp?: string
    readonly stream?: string
    readonly message?: string
  }
  readonly catchUpLimit?: number
  readonly backoff?: {
    readonly minimumMs?: number
    readonly maximumMs?: number
    readonly jitter?: number
  }
}

export interface SessionClient {
  create(input: { title: string; agent?: string }): Promise<{ id: string }>
  prompt(input: {
    sessionID: string
    id: string
    text: string
    metadata: Record<string, string | number>
    delivery: "queue"
    resume: true
  }): Promise<unknown>
}

export interface SupervisorDependencies {
  readonly fetch: typeof globalThis.fetch
  readonly random: () => number
  readonly sleep: (milliseconds: number, signal: AbortSignal) => Promise<void>
}

interface ResolvedOptions {
  readonly baseUrl: URL
  readonly projectKey: string
  readonly agentName: string
  readonly token?: string
  readonly stateDir: string
  readonly routing: RoutingFixed | RoutingConversation
  readonly registerPath: string
  readonly catchUpPath: string
  readonly streamPath: string
  readonly messagePath: string
  readonly catchUpLimit: number
  readonly minimumMs: number
  readonly maximumMs: number
  readonly jitter: number
}

const defaultDependencies: SupervisorDependencies = {
  fetch: globalThis.fetch,
  random: Math.random,
  sleep: async (milliseconds, signal) => {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        signal.removeEventListener("abort", abort)
        resolve()
      }, milliseconds)
      const abort = (): void => {
        clearTimeout(timer)
        reject(signal.reason instanceof Error ? signal.reason : new DOMException("Aborted", "AbortError"))
      }
      if (signal.aborted) abort()
      else signal.addEventListener("abort", abort, { once: true })
    })
  },
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined
}

function requiredString(source: Record<string, unknown>, key: string): string {
  const value = source[key]
  if (typeof value !== "string" || value.trim() === "") throw new Error(`blackbird: ${key} must be a non-empty string`)
  return value
}

function optionalNumber(value: unknown, fallback: number, minimum: number, maximum: number, name: string): number {
  if (value === undefined) return fallback
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`blackbird: ${name} must be between ${String(minimum)} and ${String(maximum)}`)
  }
  return value
}

function safeSegment(value: string): string {
  const segment = value.replaceAll(/[^A-Za-z0-9_.-]/g, "_").slice(0, 80)
  return segment || "agent"
}

export function resolveOptions(raw: PluginOptions | BlackbirdOptions, environment: NodeJS.ProcessEnv = process.env): ResolvedOptions {
  const source = record(raw)
  if (!source) throw new Error("blackbird: options must be an object")
  const baseUrl = new URL(requiredString(source, "baseUrl"))
  if (baseUrl.protocol !== "http:" && baseUrl.protocol !== "https:") throw new Error("blackbird: baseUrl must use http or https")
  if (baseUrl.protocol === "http:" && !isLoopbackHostname(baseUrl.hostname)) {
    throw new Error("blackbird: plaintext http is allowed only for a loopback Blackbird server")
  }
  baseUrl.pathname = baseUrl.pathname.replace(/\/$/, "") + "/"
  const projectKey = requiredString(source, "projectKey")
  const agentName = requiredString(source, "agentName")
  const routingValue = record(source["routing"])
  let routing: RoutingFixed | RoutingConversation
  if (routingValue?.["mode"] === "fixed") routing = { mode: "fixed", sessionID: requiredString(routingValue, "sessionID") }
  else if (routingValue === undefined || routingValue["mode"] === "conversation") {
    const agent = routingValue?.["agent"]
    if (agent !== undefined && typeof agent !== "string") throw new Error("blackbird: routing.agent must be a string")
    routing = agent === undefined ? { mode: "conversation" } : { mode: "conversation", agent }
  } else throw new Error("blackbird: routing.mode must be fixed or conversation")
  const paths = record(source["paths"])
  const backoff = record(source["backoff"])
  const projectHash = createHash("sha256").update(projectKey).digest("hex").slice(0, 16)
  const stateRoot = environment["XDG_STATE_HOME"] ?? join(environment["HOME"] ?? homedir(), ".local", "state")
  return {
    baseUrl,
    projectKey,
    agentName,
    ...(typeof source["token"] === "string" ? { token: source["token"] } : {}),
    stateDir: typeof source["stateDir"] === "string" ? source["stateDir"] : join(stateRoot, "blackbird", "opencode", projectHash, safeSegment(agentName)),
    routing,
    registerPath: typeof paths?.["register"] === "string" ? paths["register"] : "/api/v1/local/agents/register",
    catchUpPath: typeof paths?.["catchUp"] === "string" ? paths["catchUp"] : "/api/v1/local/coordination/events",
    streamPath: typeof paths?.["stream"] === "string" ? paths["stream"] : "/api/v1/local/coordination/events/stream",
    messagePath: typeof paths?.["message"] === "string" ? paths["message"] : "/api/v1/local/messages",
    catchUpLimit: optionalNumber(source["catchUpLimit"], 100, 1, 256, "catchUpLimit"),
    minimumMs: optionalNumber(backoff?.["minimumMs"], 250, 10, 60_000, "backoff.minimumMs"),
    maximumMs: optionalNumber(backoff?.["maximumMs"], 30_000, 10, 300_000, "backoff.maximumMs"),
    jitter: optionalNumber(backoff?.["jitter"], 0.2, 0, 1, "backoff.jitter"),
  }
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "")
  if (normalized === "localhost" || normalized === "::1") return true
  const octets = normalized.split(".")
  return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255) && Number(octets[0]) === 127
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 })
  await chmod(path, 0o700)
}

async function writeAtomic(path: string, contents: string, mode: number): Promise<void> {
  await ensurePrivateDirectory(dirname(path))
  const temporary = `${path}.${String(process.pid)}.${crypto.randomUUID()}.tmp`
  const handle = await open(temporary, "wx", mode)
  try {
    await handle.writeFile(contents, "utf8")
    await handle.sync()
  } finally {
    await handle.close()
  }
  await chmod(temporary, mode)
  await rename(temporary, path)
  const directory = await open(dirname(path), "r")
  try { await directory.sync() } finally { await directory.close() }
}

async function readState(path: string): Promise<State> {
  try {
    const value: unknown = JSON.parse(await readFile(path, "utf8"))
    const source = record(value)
    if (!source || typeof source["cursor"] !== "string") throw new Error("invalid state")
    const delivered = Array.isArray(source["delivered"]) ? source["delivered"].filter((item): item is string => typeof item === "string") : []
    const sessionsSource = record(source["sessions"]) ?? {}
    const sessions = Object.fromEntries(Object.entries(sessionsSource).filter((entry): entry is [string, string] => typeof entry[1] === "string"))
    return { cursor: source["cursor"], delivered, sessions }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { cursor: "", delivered: [], sessions: {} }
    throw new Error(`blackbird: cannot read cursor state ${path}`, { cause: error })
  }
}

async function register(options: ResolvedOptions, fetcher: typeof fetch, signal: AbortSignal): Promise<string> {
  const tokenPath = join(options.stateDir, "token")
  let savedToken = options.token
  if (savedToken === undefined) {
    try {
      savedToken = (await readFile(tokenPath, "utf8")).trim()
      if (!savedToken) throw new Error("empty token file")
      await chmod(tokenPath, 0o600)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
    }
  }
  const response = await fetcher(new URL(options.registerPath, options.baseUrl), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      project_key: options.projectKey,
      agent_name: options.agentName,
      ...(savedToken === undefined ? {} : { registration_token: savedToken }),
    }),
    signal,
  })
  if (!response.ok) throw new Error(`blackbird: registration failed with HTTP ${String(response.status)}`)
  const result = record(await response.json())
  const issuedToken = result?.["registration_token"]
  if (issuedToken !== undefined && (typeof issuedToken !== "string" || issuedToken === "")) {
    throw new Error("blackbird: registration response included an invalid registration_token")
  }
  const token = typeof issuedToken === "string" ? issuedToken : savedToken
  if (token === undefined) throw new Error("blackbird: initial registration response omitted registration_token")
  await writeAtomic(tokenPath, `${token}\n`, 0o600)
  return token
}

export function deterministicMessageID(blackbirdID: string): string {
  return `msg_${createHash("sha256").update(`blackbird:${blackbirdID}`).digest("base64url").slice(0, 26)}`
}

function parseMessage(value: unknown): BlackbirdMessage {
  const source = record(value)
  if (!source) throw new Error("blackbird: message is not an object")
  const position = source["position"]
  if (typeof position !== "string" && typeof position !== "number") throw new Error("blackbird: message.position is invalid")
  return {
    message_id: requiredString(source, "message_id"),
    conversation_id: requiredString(source, "conversation_id"),
    subject: requiredString(source, "subject"),
    body: requiredString(source, "body"),
    position,
    ...(typeof source["author_actor_id"] === "string" ? { author_actor_id: source["author_actor_id"] } : {}),
    ...(typeof source["sent_at"] === "string" ? { sent_at: source["sent_at"] } : {}),
  }
}

function promptText(message: BlackbirdMessage): string {
  const author = message.author_actor_id ?? "unknown actor"
  return `[Blackbird message ${message.message_id} from ${author}]\nSubject: ${message.subject}\n\n${message.body}`
}

function urlWithCursor(base: URL, path: string, cursor: Cursor, limit?: number): URL {
  const url = new URL(path, base)
  if (cursor !== "") url.searchParams.set("after", cursor)
  if (limit !== undefined) url.searchParams.set("limit", String(limit))
  return url
}

function messageURL(base: URL, path: string, messageID: string): URL {
  return new URL(`${path.replace(/\/$/, "")}/${encodeURIComponent(messageID)}`, base)
}

interface CoordinationEvent {
  readonly type: string
  readonly subject: string
}

function parseEvent(value: unknown): CoordinationEvent {
  const source = record(value)
  if (!source || !Object.hasOwn(source, "payload")) throw new Error("blackbird: coordination event is invalid")
  requiredString(source, "occurred_at")
  return { type: requiredString(source, "type"), subject: requiredString(source, "subject") }
}

async function* parseSSE(response: Response, signal: AbortSignal): AsyncGenerator<{ data: unknown; id?: string }> {
  if (!response.body) throw new Error("blackbird: SSE response has no body")
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
  const abort = (): void => { void reader.cancel(signal.reason).catch(() => undefined) }
  signal.addEventListener("abort", abort, { once: true })
  let buffer = ""
  try {
    while (!signal.aborted) {
      const result = await reader.read()
      buffer += result.value ?? ""
      let boundary = buffer.search(/\r?\n\r?\n/)
      while (boundary >= 0) {
        const block = buffer.slice(0, boundary)
        const separator = buffer.slice(boundary).startsWith("\r\n") ? 4 : 2
        buffer = buffer.slice(boundary + separator)
        let id: string | undefined
        const data: string[] = []
        for (const line of block.split(/\r?\n/)) {
          if (line.startsWith("id:")) id = line.slice(3).trimStart()
          if (line.startsWith("data:")) data.push(line.slice(5).trimStart())
        }
        if (data.length > 0) yield { data: JSON.parse(data.join("\n")), ...(id === undefined ? {} : { id }) }
        boundary = buffer.search(/\r?\n\r?\n/)
      }
      if (result.done) return
    }
  } finally {
    signal.removeEventListener("abort", abort)
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}

export async function runSupervisor(
  session: SessionClient,
  rawOptions: PluginOptions | BlackbirdOptions,
  signal: AbortSignal,
  dependencies: SupervisorDependencies = defaultDependencies,
): Promise<void> {
  const options = resolveOptions(rawOptions)
  if (options.maximumMs < options.minimumMs) throw new Error("blackbird: backoff.maximumMs must not be less than minimumMs")
  await ensurePrivateDirectory(options.stateDir)
  const statePath = join(options.stateDir, "cursor.json")
  const state = await readState(statePath)
  let token: string | undefined
  let tokenAttempt = 0
  while (!signal.aborted && token === undefined) {
    try {
      token = await register(options, dependencies.fetch, signal)
    } catch (error) {
      if (isAborted(signal) || (error as Error).name === "AbortError") return
      const exponential = Math.min(options.maximumMs, options.minimumMs * 2 ** Math.min(tokenAttempt, 20))
      const factor = 1 + (dependencies.random() * 2 - 1) * options.jitter
      tokenAttempt += 1
      await dependencies.sleep(Math.max(0, Math.round(exponential * factor)), signal)
    }
  }
  if (token === undefined) return
  const delivered = new Set(state.delivered)
  const sessionQueues = new Map<string, Promise<void>>()

  const persist = async (): Promise<void> => {
    state.delivered = [...delivered].slice(-2048)
    await writeAtomic(statePath, `${JSON.stringify(state)}\n`, 0o600)
  }
  const targetSession = async (message: BlackbirdMessage): Promise<string> => {
    if (options.routing.mode === "fixed") return options.routing.sessionID
    const existing = state.sessions[message.conversation_id]
    if (existing !== undefined) return existing
    const created = await session.create({
      title: `Blackbird: ${message.subject}`.slice(0, 120),
      ...(options.routing.agent === undefined ? {} : { agent: options.routing.agent }),
    })
    state.sessions[message.conversation_id] = created.id
    await persist()
    return created.id
  }
  const deliver = async (message: BlackbirdMessage): Promise<void> => {
    if (delivered.has(message.message_id)) return
    const sessionID = await targetSession(message)
    const previous = sessionQueues.get(sessionID) ?? Promise.resolve()
    const queued = previous.then(async () => {
      await session.prompt({
        sessionID,
        id: deterministicMessageID(message.message_id),
        text: promptText(message),
        metadata: {
          blackbird_message_id: message.message_id,
          blackbird_conversation_id: message.conversation_id,
          blackbird_position: message.position,
        },
        delivery: "queue",
        resume: true,
      })
      delivered.add(message.message_id)
    })
    sessionQueues.set(sessionID, queued)
    try { await queued } finally { if (sessionQueues.get(sessionID) === queued) sessionQueues.delete(sessionID) }
  }
  const headers = { authorization: `Bearer ${token}`, accept: "application/json" }
  const fetchMessage = async (messageID: string): Promise<BlackbirdMessage> => {
    const response = await dependencies.fetch(messageURL(options.baseUrl, options.messagePath, messageID), { headers, signal })
    if (!response.ok) throw new Error(`blackbird: message fetch failed with HTTP ${String(response.status)}`)
    const message = parseMessage(await response.json())
    if (message.message_id !== messageID) throw new Error("blackbird: message response ID did not match the requested message")
    return message
  }
  const catchUp = async (): Promise<void> => {
    while (!signal.aborted) {
      const response = await dependencies.fetch(urlWithCursor(options.baseUrl, options.catchUpPath, state.cursor, options.catchUpLimit), { headers, signal })
      if (!response.ok) throw new Error(`blackbird: catch-up failed with HTTP ${String(response.status)}`)
      const page = record(await response.json())
      if (!page || !Array.isArray(page["events"]) || typeof page["next_cursor"] !== "string") throw new Error("blackbird: invalid catch-up response")
      const events = page["events"].map(parseEvent)
      for (const event of events) {
        if (event.type === "message.available" && !delivered.has(event.subject)) await deliver(await fetchMessage(event.subject))
      }
      const next = page["next_cursor"]
      if (page["has_more"] === true && next === state.cursor) throw new Error("blackbird: catch-up cursor did not advance")
      state.cursor = next
      await persist()
      if (page["has_more"] !== true) return
    }
  }

  let attempt = 0
  while (!signal.aborted) {
    try {
      await catchUp()
      const response = await dependencies.fetch(urlWithCursor(options.baseUrl, options.streamPath, state.cursor), {
        headers: { ...headers, accept: "text/event-stream" },
        signal,
      })
      if (!response.ok) throw new Error(`blackbird: stream failed with HTTP ${String(response.status)}`)
      if (!(response.headers.get("content-type") ?? "").toLowerCase().includes("text/event-stream")) {
        throw new Error("blackbird: stream did not return text/event-stream")
      }
      attempt = 0
      for await (const event of parseSSE(response, signal)) {
        const envelope = record(event.data)
        const cursor = envelope?.["cursor"]
        if (typeof cursor !== "string" || cursor === "") throw new Error("blackbird: invalid stream wakeup")
        break
      }
    } catch (error) {
      if (isAborted(signal) || (error as Error).name === "AbortError") break
      const exponential = Math.min(options.maximumMs, options.minimumMs * 2 ** Math.min(attempt, 20))
      const factor = 1 + (dependencies.random() * 2 - 1) * options.jitter
      attempt += 1
      await dependencies.sleep(Math.max(0, Math.round(exponential * factor)), signal)
    }
  }
  await Promise.allSettled(sessionQueues.values())
}

function isAborted(signal: AbortSignal): boolean {
  return signal.aborted
}

export default Plugin.define({
  id: "phall1.blackbird",
  setup: (ctx) => {
    resolveOptions(ctx.options)
    const controller = new AbortController()
    const session: SessionClient = {
      create: async (input) => ctx.session.create(input),
      prompt: async (input) => ctx.session.prompt(input),
    }
    const task = runSupervisor(session, ctx.options, controller.signal).catch((error: unknown) => {
      if (!controller.signal.aborted) process.stderr.write(`[blackbird] inbox supervisor stopped: ${String(error)}\n`)
    })
    return async () => {
      controller.abort()
      await task
    }
  },
})
