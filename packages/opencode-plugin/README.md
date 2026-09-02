# blackbird-opencode

OpenCode **notify-mode** plugin that catches up through Blackbird's coordination
event journal and follows its wake-only stream, then appends each available
durable message to an OpenCode session transcript without marking it read,
acknowledging it, or spending an agent turn.

## Configuration

```jsonc
{
  "plugins": [
    {
        "package": "blackbird-opencode@0.1.3",
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

`baseUrl`, `projectKey`, and `agentName` are required. A `projectKey` beginning
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

Delivery posts one text part to `POST /session/{id}/message` with `noReply:
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

```sh
npm ci
npm run gates
```

`npm run test:pack` packs the package, installs that tarball into a clean
temporary project, and imports the installed entrypoint.
