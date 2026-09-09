import { readFile } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"
import { Effect } from "effect"
import { z } from "zod"
import { AgentsPage, InboxPage, ThreadPage, type InboxQuery, type ThreadQuery } from "./rpc.js"

const Handshake = z.object({ schema: z.literal("blackbird.admin/v1"), http_address: z.string(), token: z.string().min(1) })

export function handshakePath() {
  return join(process.env["XDG_STATE_HOME"] ?? join(homedir(), ".local", "state"), "blackbird", "admin.json")
}

function loopbackAddress(address: string) {
  const url = new URL(`http://${address}`)
  if (!["127.0.0.1", "[::1]", "localhost"].includes(url.hostname) || url.username || url.password) {
    throw new Error("Blackbird admin handshake must point to loopback")
  }
  return url
}

export function createMailReader(projectKey: string, path = handshakePath(), fetcher = globalThis.fetch) {
  const get = <T>(endpoint: string, query: Record<string, string>, schema: z.ZodType<T>) =>
    Effect.tryPromise({
      try: async (signal) => {
        const handshake = Handshake.parse(JSON.parse(await readFile(path, { encoding: "utf8", signal })))
        const url = new URL(`/api/v1/local/admin/${endpoint}`, loopbackAddress(handshake.http_address))
        url.search = new URLSearchParams({ project_key: projectKey, limit: "256", ...query }).toString()
        const response = await fetcher(url, {
          headers: { authorization: `Bearer ${handshake.token}`, accept: "application/json" },
          signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]), redirect: "error",
        })
        if (!response.ok) throw new Error(`Blackbird ${endpoint} returned HTTP ${String(response.status)}; check the daemon version and status`)
        return schema.parse(await response.json())
      },
      // Never return raw HTTP bodies or the handshake (which contains a secret).
      catch: (error) => new Error(error instanceof Error && error.message.startsWith("Blackbird ")
        ? error.message : "Blackbird mailbox unavailable. Run blackbird status on the OpenCode server machine."),
    })
  return {
    agents: () => get("agents", {}, AgentsPage),
    inbox: (query: z.infer<typeof InboxQuery>) => get("inbox", {
      ...(query.agent === undefined ? {} : { agent: query.agent }), unread: String(query.unread),
    }, InboxPage),
    thread: (query: z.infer<typeof ThreadQuery>) => get("thread", {
      conversation_id: query.conversation_id, after: String(query.after),
    }, ThreadPage),
  }
}
