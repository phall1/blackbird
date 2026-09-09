# blackbird-opencode

Native OpenCode V2 mailbox browser plus a **notify-mode** adapter that catches up through Blackbird's coordination
event journal and follows its wake-only stream, then appends each available
durable message to an OpenCode session transcript without marking it read,
acknowledging it, or spending an agent turn.

## Configuration

### Mailbox browser

Load the local checkout in `opencode.jsonc` after `npm ci && npm run build`
inside `packages/opencode-plugin`:

```jsonc
{
  "plugins": ["/absolute/path/blackbird/packages/opencode-plugin"]
}
```

Open **Toggle Blackbird mailboxes** in the command palette, or type
`/blackbird` (`/mail` also works). In a session it opens a host-managed side
panel; from home it opens a full-page browser. Narrow terminals use the host's
full-screen panel presentation.

- Select a mailbox, or **All mailboxes**, then open a delivery to read its thread.
- `↑`/`↓` and Enter navigate; `u` switches all/unread mail; `r` refreshes.
- Escape returns one level, then closes; `f` expands a session panel.
- Threads paginate in message order with **Next page** (`n`) and **First page**.
- Agent/inbox lists are capped at 256 and report truncation. Unread and mailbox
  filters run on the daemon before the limit.

Browsing is read-only: it never registers an agent, marks mail read, sends an
acknowledgement, advances a consumer cursor, or starts an agent turn. Receipt
badges describe the recipient agent's state, even while a human reads the mail.
Thread detail requires a daemon containing `/api/v1/local/admin/thread`.

The Effect server reads the daemon's private
`$XDG_STATE_HOME/blackbird/admin.json` handshake (default
`~/.local/state/blackbird/admin.json`) on each request, so daemon restarts and
token rotation need no plugin restart. Set `options.handshakePath` for a custom
daemon state directory. Admin credentials stay on the OpenCode server and are
sent only to the discovered loopback address. The TUI uses typed RPC and also
works against a remote OpenCode server; `blackbird status` must work there.
Mailbox scope follows the current OpenCode location, including moved sessions.

### Optional transcript delivery

Add an `agentName` and the existing delivery settings to enable notify mode:

```jsonc
{
  "plugins": [
    {
      "package": "/absolute/path/blackbird/packages/opencode-plugin",
      "options": {
        "baseUrl": "http://127.0.0.1:8080",
        "projectKey": "~/workspace/project",
        "agentName": "OpenCode",
        "routing": { "mode": "conversation" }
      }
    }
  ]
}
```

For delivery, `baseUrl` and `agentName` are required; V2 defaults `projectKey`
to its location directory (V1 requires it explicitly). A `projectKey` beginning
with `~/` is expanded to the current user's home directory. Routing is either:

- `{ "mode": "fixed", "sessionID": "ses_..." }` for one existing session.
- `{ "mode": "conversation", "agent": "build" }` (the default) for one
  persisted OpenCode session per Blackbird conversation.

Optional `paths` keys are `register` (`/api/v1/local/agents/register`),
`catchUp` (`/api/v1/local/coordination/events`), `stream`
(`/api/v1/local/coordination/events/stream`), `ack`
(`/api/v1/local/coordination/events/ack`), and `message`
(`/api/v1/local/messages`). Optional `stateDir` overrides the default
`$XDG_STATE_HOME/blackbird/opencode/<project-hash>/<agent-name>`. `token` can
bootstrap a deployment-managed bearer token. Every startup registers or resumes
the agent; a saved token is sent as `registration_token`, and remains valid when
a resumed registration omits a newly issued token. The token is stored with mode
`0600`. Avoid putting one directly in shared configuration.

The adapter uses the server-side `opencode-plugin` consumer and a `limit` query
parameter. Each event carries its own opaque `cursor`; the adapter acknowledges
that cursor only after OpenCode has durably accepted the corresponding message.
Events contain `{ type, subject, payload, occurred_at, cursor }`. Only
`message.available` is admitted: its subject is fetched authoritatively with
`GET /api/v1/local/messages/{message_id}` before delivery. Other event types are
ignored. Message fields are `message_id`, `conversation_id`, `subject`, `body`,
`position`, and optional author/time metadata.

The authenticated SSE endpoint uses the same named consumer and emits wakeups
such as `{ "cursor": "..." }`. SSE data is never interpreted as a message body. A
wakeup or disconnected stream starts another authoritative catch-up pass.

V2 uses the host's `session.synthetic` Effect. V1 posts one text part to `POST /session/{id}/message` with `noReply:
true`, so OpenCode persists the message into the transcript and does *not* run
an agent turn for it. A delivered message therefore costs the user nothing; the
agent reads it as context the next time a turn runs (or on the running turn's
next step, since the loop re-reads the transcript at every step). Nothing in
this plugin ever starts a turn on the user's behalf.

The message carries a deterministic `msg_` ID derived from the Blackbird message
ID: OpenCode upserts on that ID, so a redelivery rewrites the same transcript
entry instead of appending a duplicate. Blackbird's identifiers travel as the
text part's `metadata` (`blackbird_message_id`, `blackbird_conversation_id`,
`blackbird_position`).

Delivery remains deliberately at-least-once: a crash between OpenCode accepting
a deterministic ID and Blackbird accepting its cursor acknowledgement safely
retries the same ID. Cursor progress and generic deduplication are durable on the
server; the private local state contains only conversation-to-session routing.
Delivery remains ordered by the event page, so a later event cannot commit past
an earlier failed delivery.

## Development

Requires Bun 1.3.14 or newer. The UI build uses OpenTUI's Solid-universal
compiler, keeps host runtime imports external, and ships compiled ESM. Raw TSX
inside `node_modules` is not compiled by the host, so source-only validation is
insufficient.

```sh
npm ci
npm run gates
npm run test:tui
# Also render the installed tarball (requires opencode2 on PATH):
BLACKBIRD_PACK_TUI=1 npm run test:pack
```

`npm run test:pack` packs the package, installs that tarball into a clean
temporary project, and imports the installed entrypoint.

The V2 server pins `@opencode/plugin` and `@opencode/schema` beta-19365 with
Effect rc.112; the TUI pins OpenTUI 0.5.11 and Solid 1.9.12. The default export
uses `Plugin.define({ effect })`, with a separate V1 `server` compatibility hook.
The existing Promise delivery transport feeds host operations through a scoped
Effect queue: no nested runtime, and delivery settles only after host acceptance.
The shared identity scope survives individual activation reloads and interrupts
both HTTP and queued host work when its last owner unloads. Unexpected supervisor
exits retry after one second; failed or interrupted host jobs reject their
delivery Promise while leaving the worker able to process the next job.
Browser-only loads start no delivery background work.

`npm run test:tui` uses Drive with isolated mail fixtures and captures mailbox,
thread, session-panel, and full-screen screenshots. The packed-artifact smoke
loads the server, shared RPC, and TUI with the V2 host resolver. Local directory
entrypoints are deliberately at package root because the host probes `server`,
`tui`, and `rpc` there.
