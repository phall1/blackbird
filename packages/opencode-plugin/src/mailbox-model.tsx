// Keep reactive state in the host's TSX pipeline so it shares the UI's Solid runtime.
import { createStore } from "solid-js/store"
import type { z } from "zod"
import type { AgentsPage, InboxPage, ThreadPage, InboxQuery, ThreadQuery } from "./rpc.js"

export interface MailReader {
  agents(signal: AbortSignal): Promise<z.infer<typeof AgentsPage>>
  inbox(query: z.infer<typeof InboxQuery>, signal: AbortSignal): Promise<z.infer<typeof InboxPage>>
  thread(query: z.infer<typeof ThreadQuery>, signal: AbortSignal): Promise<z.infer<typeof ThreadPage>>
}

export function createMailbox(reader: MailReader) {
  const [state, set] = createStore({
    mode: "agents" as "agents" | "inbox" | "thread", agent: "", unread: false,
    conversation: "", after: 0, loading: false, error: "",
    agents: { agents: [], truncated: false } as z.infer<typeof AgentsPage>,
    inbox: { pending: [], truncated: false } as z.infer<typeof InboxPage>,
    thread: { messages: [], has_more: false, next: 0 } as z.infer<typeof ThreadPage>,
  })
  let active: AbortController | undefined

  async function refresh() {
    active?.abort()
    const controller = new AbortController()
    active = controller
    set({ loading: true, error: "" })
    try {
      const result = await load(controller.signal)
      if (!controller.signal.aborted) set(result)
    } catch {
      if (!controller.signal.aborted) set("error", "Mailbox unavailable. Check blackbird status on the server, then press r to retry.")
    } finally {
      if (!controller.signal.aborted) set("loading", false)
    }
  }

  async function load(signal: AbortSignal) {
    if (state.mode === "agents") return { agents: await reader.agents(signal) }
    if (state.mode === "thread") return { thread: await reader.thread({ conversation_id: state.conversation, after: state.after }, signal) }
    return { inbox: await reader.inbox({ ...(state.agent ? { agent: state.agent } : {}), unread: state.unread }, signal) }
  }

  return {
    state, refresh,
    dispose: () => active?.abort(),
    inbox: (agent: string) => { set({ mode: "inbox", agent }); return refresh() },
    thread: (conversation: string) => { set({ mode: "thread", conversation, after: 0 }); return refresh() },
    next: () => { if (!state.thread.has_more) return; set("after", state.thread.next); return refresh() },
    first: () => { set("after", 0); return refresh() },
    toggleUnread: () => { set("unread", !state.unread); return refresh() },
    back: () => { set("mode", state.mode === "thread" ? "inbox" : "agents"); return refresh() },
  }
}

// Mail is untrusted terminal text; retain body newlines while stripping terminal
// control characters and bidi controls. No terminal escapes are interpreted.
export function mailText(value: string) {
  // eslint-disable-next-line no-control-regex -- deliberately remove terminal controls
  return value.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "")
}
