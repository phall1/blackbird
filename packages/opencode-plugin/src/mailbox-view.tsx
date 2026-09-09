/** @jsxImportSource @opentui/solid */
import type { Context } from "@opencode/plugin/tui/context"
import type { BoxRenderable } from "@opentui/core"
import { For, Show, createMemo, onCleanup, onMount } from "solid-js"
import { createMailbox, mailText, type MailReader } from "./mailbox-model.tsx"
import { restoreMailboxFocus } from "./mailbox-focus.tsx"

export function MailboxView(props: { context: Context; reader: MailReader; directory: string; focused: boolean; close(): void; fullscreen?: () => void }) {
  const model = createMailbox(props.reader)
  const state = model.state
  const theme = props.context.theme
  const accent = theme.text.action.primary.default
  let root: BoxRenderable | undefined
  restoreMailboxFocus(props.context.renderer, () => root, () => state.mode === "thread" ? "blackbird-thread" : "blackbird-list", () => props.focused)
  onMount(() => { void model.refresh() })
  onCleanup(model.dispose)
  const back = () => state.mode === "agents" ? props.close() : model.back()
  const options = createMemo(() => {
    if (state.mode === "agents") return [
      { name: "All mailboxes", description: "Browse every delivery in this workspace", value: "" },
      ...state.agents.agents.map((agent) => ({ name: mailText(agent.agent_name), value: agent.agent_name,
        description: `${String(agent.unread_deliveries)} unread · ${String(agent.unacked_deliveries)} awaiting ack · ${agent.active ? "active" : "offline"}` })),
    ]
    return state.inbox.pending.map((mail) => ({
      name: `${mail.read ? "  " : "● "}${mailText(mail.subject)}`, value: mail.conversation_id,
      description: `${mailText(mail.author_agent_name)} → ${mailText(mail.recipient_agent_name)} · ${mailText(mail.sent_at)}${mail.acknowledgement_required && !mail.acknowledged ? " · ACK NEEDED" : ""}`,
    }))
  })
  const truncated = () => state.mode === "agents" ? state.agents.truncated : state.inbox.truncated
  props.context.keymap.layer(() => ({
    enabled: () => props.focused,
    commands: [
      { bind: "escape", run: back }, { bind: "r", run: model.refresh },
      { bind: "u", enabled: () => state.mode === "inbox", run: model.toggleUnread },
      { bind: "n", enabled: () => state.mode === "thread" && !state.loading, run: model.next },
      { bind: "f", run: () => props.fullscreen?.() },
    ],
  }))
  return <box ref={(value) => { root = value }} id="blackbird-mailbox" flexDirection="column" flexGrow={1} minHeight={0} paddingX={1} border borderColor={theme.border.default} backgroundColor={theme.background.default}>
    <box flexDirection="row" justifyContent="space-between" paddingY={1}>
      <text fg={accent} flexShrink={1} wrapMode="word">BLACKBIRD / {state.mode === "agents" ? "Mailboxes" : mailText(state.agent || "All mailboxes")}</text>
      <text id="blackbird-back" onMouseUp={() => { void back() }} fg={theme.text.subdued}>[esc] Back</text>
    </box>
    <text fg={theme.text.subdued} wrapMode="word">{mailText(props.directory)}</text>
    <box flexDirection="row" gap={2} paddingY={1}>
      <text id="blackbird-refresh" onMouseUp={() => { void model.refresh() }} fg={accent}>[r] Refresh</text>
      <Show when={state.mode === "inbox"}><text id="blackbird-unread" onMouseUp={() => { void model.toggleUnread() }} fg={accent}>[u] {state.unread ? "Unread only" : "All mail"}</text></Show>
      <Show when={props.fullscreen}><text onMouseUp={() => props.fullscreen?.()} fg={accent}>[f] Expand</text></Show>
    </box>
    <Show when={!state.loading && !state.error} fallback={<text fg={theme.text.subdued}>{state.error || "Loading mail…"}</text>}>
      <Show when={state.mode === "thread"} fallback={<>
        <Show when={options().length > 0} fallback={<text fg={theme.text.subdued}>No messages in this view.</text>}>
          <select id="blackbird-list" flexGrow={1} minHeight={0} focused={props.focused} options={options()} showDescription
            backgroundColor={theme.background.default} textColor={theme.text.default}
            selectedBackgroundColor={theme.background.surface.offset} selectedTextColor={accent}
            onSelect={(_index, option) => {
              if (!option) return
              const value = String(option.value)
              void (state.mode === "agents" ? model.inbox(value) : model.thread(value))
            }} />
        </Show>
        <Show when={truncated()}><text fg={theme.text.subdued}>Showing the newest 256 entries. Narrow to a mailbox or unread mail.</text></Show>
      </>}>
        <scrollbox id="blackbird-thread" flexGrow={1} minHeight={0} focused={props.focused}>
          <Show when={state.thread.messages.length} fallback={<text>No messages in this thread.</text>}>
            <For each={state.thread.messages}>{(mail) => <box flexDirection="column" paddingBottom={2}>
              <text fg={accent} wrapMode="word">{mailText(mail.subject)}</text>
              <text fg={theme.text.subdued} wrapMode="word">{mailText(mail.author_agent_name)} · {mailText(mail.sent_at)}</text>
              <text fg={theme.text.default} wrapMode="word">{mailText(mail.body)}</text>
            </box>}</For>
          </Show>
        </scrollbox>
        <box flexDirection="row" gap={2}>
          <Show when={state.after > 0}><text id="blackbird-first" onMouseUp={() => { void model.first() }} fg={accent}>First page</text></Show>
          <Show when={state.thread.has_more}><text id="blackbird-next" onMouseUp={() => { void model.next() }} fg={accent}>[n] Next page</text></Show>
        </box>
      </Show>
    </Show>
    <text fg={theme.text.subdued} paddingY={1} wrapMode="word">↑↓ Navigate · Enter Open · Browsing leaves receipts unchanged</text>
  </box>
}
