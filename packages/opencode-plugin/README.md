# blackbird-opencode

OpenCode V2 Promise plugin that catches up through Blackbird's coordination
event journal and follows its wake-only stream, then queues each available
durable message into an OpenCode session without marking it read or acknowledging
it.

## Configuration

```jsonc
{
  "plugins": [
    {
      "package": "blackbird-opencode@0.1.2",
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
(`/api/v1/local/coordination/events/stream`), and `message`
(`/api/v1/local/messages`). Optional `stateDir` overrides the default
`$XDG_STATE_HOME/blackbird/opencode/<project-hash>/<agent-name>`. `token` can
bootstrap a deployment-managed bearer token. Every startup registers or resumes
the agent; a saved token is sent as `registration_token`, and remains valid when
a resumed registration omits a newly issued token. The token is stored with mode
`0600`. Avoid putting one directly in shared configuration.

The catch-up endpoint receives optional `after` and `limit` query parameters and
returns `{ events, next_cursor, has_more }`. The initial zero cursor is omitted;
subsequent opaque cursors are persisted and returned without interpretation.
Events contain `{ type, subject, payload, occurred_at }`. Only
`message.available` is admitted: its subject is fetched authoritatively with
`GET /api/v1/local/messages/{message_id}` before delivery. Other event types are
ignored. Message fields are `message_id`, `conversation_id`, `subject`, `body`,
`position`, and optional author/time metadata.

The authenticated SSE endpoint receives optional `after` and emits wakeups such
as `{ "cursor": "..." }`. SSE data is never interpreted as a message body. A
wakeup or disconnected stream starts another authoritative catch-up pass.

Delivery uses a deterministic prompt and `msg_` ID with `ctx.session.prompt`,
`delivery: "queue"`, and `resume: true`. Cursor and recent-message dedupe state
are atomically replaced with mode `0600` only after every event in a catch-up
page has been admitted or deduplicated. This is deliberately at-least-once: a
crash between OpenCode accepting a deterministic ID and the page state commit
safely retries the same ID. Conversation routing persists a distinct target
session for every conversation. Delivery remains ordered by the event page, so
a later event cannot commit the cursor past an earlier failed delivery.

## Development

```sh
npm ci
npm run gates
```

`npm run test:pack` packs the package, installs that tarball into a clean
temporary project, and imports the installed entrypoint.
