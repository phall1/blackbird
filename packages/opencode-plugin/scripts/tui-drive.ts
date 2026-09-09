import { createServer } from "node:http"
import { mkdtemp, writeFile, rm } from "node:fs/promises"
import { join, resolve } from "node:path"
import { Effect } from "effect"
import { Llm, OpenCodeDriver } from "opencode-drive"

const plugin = process.env.BLACKBIRD_PLUGIN_DIRECTORY ?? resolve(".")

const fixture = Effect.acquireRelease(Effect.tryPromise(async () => {
  const directory = await mkdtemp("/private/tmp/opencode/blackbird-drive-")
  const server = createServer((request, response) => {
    const url = new URL(request.url!, "http://127.0.0.1")
    response.setHeader("content-type", "application/json")
    if (request.headers.authorization !== "Bearer fixture") { response.writeHead(401).end(); return }
    if (url.pathname.endsWith("agents")) {
      response.end(JSON.stringify({ agents: [{ agent_name: "Builder", active: true, unread_deliveries: 1, unacked_deliveries: 1 }], truncated: false }))
      return
    }
    if (url.pathname.endsWith("inbox")) {
      response.end(JSON.stringify({ pending: [{ message_id: "message-1", conversation_id: "conversation-1", recipient_agent_name: "Builder", author_agent_name: "Reviewer", subject: "Mailbox browser review", read: false, acknowledged: false, acknowledgement_required: true, sent_at: "2026-09-09T12:00:00Z" }], truncated: false }))
      return
    }
    response.end(JSON.stringify({ messages: [{ message_id: "message-1", position: 1, author_agent_name: "Reviewer", subject: "Mailbox browser review", body: "Looks good. Keep browsing read-only.\n\nKeyboard and mouse should both work.", sent_at: "2026-09-09T12:00:00Z" }], has_more: false, next: 1 }))
  })
  await new Promise<void>((yes) => server.listen(0, "127.0.0.1", yes))
  const address = server.address() as { port: number }
  const path = join(directory, "admin.json")
  await writeFile(path, JSON.stringify({ schema: "blackbird.admin/v1", http_address: `127.0.0.1:${address.port}`, token: "fixture" }))
  return { server, directory, path }
}), ({ server, directory }) => Effect.promise(async () => {
  server.closeAllConnections()
  await new Promise<void>((yes) => server.close(() => yes()))
  await rm(directory, { recursive: true, force: true })
}))

export default Effect.scoped(Effect.gen(function* () {
  const { path } = yield* fixture
  yield* OpenCodeDriver.use({
    keepArtifacts: process.env.BLACKBIRD_DRIVE_KEEP === "1",
    project: { git: true, files: { "README.md": "# Isolated Blackbird UI fixture\n" } },
    config: { autoupdate: false, plugins: [{ package: plugin, options: { handshakePath: path } }] },
    tui: { viewport: { cols: 130, rows: 42 } },
  }, ({ ui, llm, artifacts }) => Effect.gen(function* () {
    yield* Effect.log(`Blackbird UI fixture: ${artifacts}`)
    const click = (id: string) => ui.getElement({ id }).pipe(Effect.flatMap((element) => ui.click(element)))
    const open = () => Effect.gen(function* () {
      yield* ui.press("p", { ctrl: true })
      yield* ui.type("Toggle Blackbird mailboxes")
      yield* ui.waitFor("Toggle Blackbird mailboxes")
      yield* ui.arrow("down")
      yield* ui.enter()
    })
    yield* open()
    yield* ui.waitFor("Builder").pipe(Effect.tapError(() => ui.screenshot("blackbird-failure").pipe(Effect.flatMap(Effect.log))))
    yield* Effect.log(yield* ui.screenshot("blackbird-mailboxes"))
    yield* ui.enter()
    yield* ui.waitFor("Mailbox browser review")
    yield* ui.press("u")
    yield* ui.waitFor("Unread only")
    yield* ui.enter()
    yield* ui.waitFor("Looks good. Keep browsing read-only.")
    yield* Effect.log(yield* ui.screenshot("blackbird-thread"))
    yield* ui.press("escape")
    yield* ui.waitFor("Unread only")
    yield* ui.press("escape")
    yield* ui.waitFor("Builder")
    yield* ui.press("escape")
    yield* llm.queue(Llm.text("Ready to inspect mail."))
    yield* ui.submit("Prepare to inspect mail.")
    yield* ui.waitFor("Ready to inspect mail.")
    yield* ui.submit("/blackbird")
    yield* ui.waitFor("Builder")
    yield* Effect.log(yield* ui.screenshot("blackbird-session-panel"))
    yield* ui.press("f")
    yield* Effect.log(yield* ui.screenshot("blackbird-fullscreen"))
    yield* ui.resize({ cols: 60, rows: 28 })
    yield* ui.waitFor("Builder")
    yield* ui.waitFor((state) => state.elements.some((element) => element.id === "blackbird-list" && element.focused))
    yield* ui.enter()
    yield* ui.waitFor("Mailbox browser review")
    yield* click("blackbird-unread")
    yield* ui.waitFor("Unread only")
    yield* Effect.log(yield* ui.screenshot("blackbird-narrow"))
    yield* click("blackbird-back")
    yield* ui.waitFor("Builder")
    yield* click("blackbird-refresh")
    yield* ui.waitFor("Builder")
    yield* ui.press("escape")
  }))
}))
