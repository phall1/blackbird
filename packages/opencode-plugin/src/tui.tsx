/** @jsxImportSource @opentui/solid */
import { Plugin } from "@opencode/plugin/tui"
import type { Context, PanelInput } from "@opencode/plugin/tui/context"
import { Show, createResource } from "solid-js"
import { Mail } from "./rpc.js"
import { MailboxView } from "./mailbox-view.tsx"

function connection(context: Context, location = context.location ?? context.data.location.default()) {
  const rpc = context.client.rpc(Mail)
  return {
    directory: location.directory,
    reader: {
      agents: (signal: AbortSignal) => rpc.agents({}, { location, signal }),
      inbox: (input: Parameters<typeof rpc.inbox>[0], signal: AbortSignal) => rpc.inbox(input, { location, signal }),
      thread: (input: Parameters<typeof rpc.thread>[0], signal: AbortSignal) => rpc.thread(input, { location, signal }),
    },
  }
}

function SessionMailbox(props: { context: Context; panel: PanelInput }) {
  const [synced, { refetch }] = createResource(() => props.panel.sessionID, (id) => props.context.data.session.sync(id))
  const location = () => props.context.data.session.get(props.panel.sessionID)?.location
  props.context.keymap.layer(() => ({
    enabled: () => props.panel.focused && !location(),
    commands: [{ bind: "r", run: () => { void refetch() } }, { bind: "escape", run: props.panel.close }],
  }))
  return <Show when={location()} keyed fallback={<text>{synced.error ? "Session unavailable. Press r to retry." : "Loading workspace…"}</text>}>
    {(value) => <MailboxView context={props.context} {...connection(props.context, value)} focused={props.panel.focused} close={props.panel.close} fullscreen={props.panel.toggleFullscreen} />}
  </Show>
}

function toggle(context: Context) {
  if (context.ui.panel.current()?.name === "blackbird.mail") { context.ui.panel.close(); return }
  if (context.ui.panel.open("blackbird.mail")) return
  const route = context.ui.router.current()
  if (route.type === "plugin" && route.name === "blackbird.mail") { context.ui.router.navigate({ type: "home" }); return }
  context.ui.router.navigate({ type: "plugin", name: "blackbird.mail" })
}

export default Plugin.define({
  id: "phall1.blackbird.tui",
  setup(context) {
    const page = context.ui.router.register({ name: "blackbird.mail", render: () =>
      <MailboxView context={context} {...connection(context)} focused={true} close={() => context.ui.router.navigate({ type: "home" })} />,
    })
    const panel = context.ui.slot({ append: "session.panel", render: (panel) =>
      <Show when={panel.name === "blackbird.mail"}><SessionMailbox context={context} panel={panel} /></Show>,
    })
    const commands = context.ui.slot({ append: "app", render: () => {
      context.keymap.layer(() => ({ mode: "global", commands: [{
        id: "blackbird.mail", title: "Toggle Blackbird mailboxes", group: "Blackbird", palette: true,
        slash: { name: "blackbird", aliases: ["mail"] }, run: () => toggle(context),
      }] }))
      return null
    } })
    return () => { commands(); panel(); page() }
  },
})
