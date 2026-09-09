import { expect, it } from "vitest"
import { createMailbox, mailText, type MailReader } from "../src/mailbox-model.js"

function reader(overrides: Partial<MailReader> = {}): MailReader {
  return {
    agents: async () => ({ agents: [], truncated: false }),
    inbox: async () => ({ pending: [], truncated: false }),
    thread: async () => ({ messages: [], has_more: false, next: 0 }),
    ...overrides,
  }
}

it("discards late responses when switching mailboxes and cancels on disposal", async () => {
  const pending: { signal: AbortSignal; resolve: (value: { pending: []; truncated: boolean }) => void }[] = []
  const model = createMailbox(reader({ inbox: (_query, signal) => new Promise((resolve) => { pending.push({ signal, resolve }) }) }))
  const first = model.inbox("alice")
  const second = model.inbox("bob")
  expect(pending[0]?.signal.aborted).toBe(true)
  pending[1]?.resolve({ pending: [], truncated: true })
  await second
  pending[0]?.resolve({ pending: [], truncated: false })
  await first
  expect(model.state.agent).toBe("bob")
  expect(model.state.inbox.truncated).toBe(true)
  model.dispose()
  expect(pending[1]?.signal.aborted).toBe(true)
})

it("applies unread on the server, retains mailbox on back, and pages threads", async () => {
  const queries: unknown[] = []
  const model = createMailbox(reader({
    inbox: async (query) => { queries.push(query); return { pending: [], truncated: false } },
    thread: async (query) => { queries.push(query); return { messages: [], has_more: query.after === 0, next: 256 } },
  }))
  await model.inbox("alice")
  await model.toggleUnread()
  await model.thread("thread-1")
  await model.next()
  await model.back()
  expect(queries).toEqual([
    { agent: "alice", unread: false }, { agent: "alice", unread: true },
    { conversation_id: "thread-1", after: 0 }, { conversation_id: "thread-1", after: 256 },
    { agent: "alice", unread: true },
  ])
  model.dispose()
})

it("shows failures and supports a successful retry", async () => {
  let fail = true
  const model = createMailbox(reader({ agents: async () => {
    if (fail) throw new Error("secret response")
    return { agents: [], truncated: false }
  } }))
  await model.refresh()
  expect(model.state.error).toContain("retry")
  expect(model.state.error).not.toContain("secret")
  fail = false
  await model.refresh()
  expect(model.state.error).toBe("")
  expect(model.state.loading).toBe(false)
  model.dispose()
})

it("preserves multiline mail while removing terminal and bidi controls", () => {
  expect(mailText("Hello\n\u001b[2J\u202eevil\u0007")).toBe("Hello\n[2Jevil")
})
