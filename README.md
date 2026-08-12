# Blackbird

Blackbird is a durable, local-first coordination service for human and AI agent
work. It is a standalone Go replacement for the legacy Python Agent Mail
service.

The released product includes:

- a production daemon with HTTP and MCP transports and durable SQLite storage;
- repository-scoped agent registration, secure resume tokens, and peer
  discovery;
- conversations, immutable messages, replies, inboxes, threads, independent
  read and acknowledgement facts, and To/Cc/Bcc privacy;
- a private, tamper-evident coordination event journal with authenticated
  catch-up cursors and a wake-only SSE stream;
- shared and exclusive exact/subtree file reservations with expiry, renewal,
  overlap detection, and fencing tokens;
- strict W0 identity and W1 work/run contracts with idempotent orchestration;
- per-user launchd and systemd services, unattended Homebrew updates, and
  idempotent MCP client configuration; and
- reproducible native releases for Apple Silicon macOS and amd64/arm64 Linux.

SQLite is the supported daily-use backend. PostgreSQL remains explicit and
fail-closed for coordination operations that have not landed there yet.

## Install

```sh
brew install phall1/tap/blackbird
blackbird install
blackbird status
```

`blackbird install` starts the service and adds the remote MCP endpoint at
`http://127.0.0.1:8081` to detected OpenCode, Claude Code, and Codex clients.

## Daily Use

Start with `blackbird_agent_register`, passing an absolute repository path as
`project_key` and a stable `agent_name`. Retain the returned
`registration_token` to resume the same identity after process or machine
restarts.

The daily-use MCP tools are:

- `blackbird_agent_register` and `blackbird_agents_list`;
- `blackbird_conversation_open`, `blackbird_message_send`, and
  `blackbird_message_reply`;
- `blackbird_inbox_fetch`, `blackbird_thread_fetch`,
  `blackbird_message_mark_read`, and `blackbird_message_acknowledge`; and
- `blackbird_reservation_acquire`, `blackbird_reservation_renew`, and
  `blackbird_reservation_release`.

All tools except initial registration authenticate with the returned
`agent_token`. Reserve the narrowest relevant paths before editing, use one
conversation per work item, acknowledge required handoffs, and release
reservations when work completes.

## OpenCode Push Delivery

The `blackbird-opencode` package is an OpenCode V2 plugin that turns durable
`message.available` events into queued, resumable OpenCode session prompts. It
uses SSE only as a low-latency wake signal, catches up from the SQLite event
journal after every reconnect, resolves each message through a privacy-checked
endpoint, and does not mark or acknowledge mail on the agent's behalf.

Add it to OpenCode's `plugins` configuration with an absolute repository path:

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

OpenCode installs the package and its production dependencies in its isolated
plugin cache. Registration tokens, opaque cursors, deduplication facts, and
conversation-to-session bindings are stored under `$XDG_STATE_HOME/blackbird`
with private directory and file permissions.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
go build ./...
```

Build metadata can be supplied with linker flags targeting `main.version`,
`main.commit`, and `main.builtAt`. Unset fields use explicit development
values.

## Local Product Management

The released `blackbird` binary manages its per-user service without requiring
root access:

```sh
blackbird install
blackbird status
blackbird update
blackbird uninstall
```

`install` creates XDG config, data, and state directories, writes atomic
launchd agents on macOS or systemd user units on Linux for both the daemon and
the `blackbird-claude` companion, and safely restarts them. The companion binds
the project directory in which `blackbird install` first runs to the stable
agent name `ClaudeCode`; repeated installs preserve that configured working
directory. It consumes only the loopback API at `127.0.0.1:8080`, stores its
registration token, delivery state, conversation-to-Claude UUID bindings, and
transcript evidence under `$XDG_STATE_HOME/blackbird/claude` with private
permissions, and invokes the same-user `claude` executable in the project
directory. It never marks messages read or acknowledges them automatically.
Messages are processed serially in journal order. Transient failures retry with
bounded exponential backoff; if the companion stops after Claude starts but
before success is durably recorded, that delivery is quarantined as ambiguous
instead of being replayed automatically.

Installation also installs an unattended Homebrew updater that runs every six
hours: a non-`KeepAlive` launchd job on macOS, or a systemd user timer and
oneshot service on Linux. Updater failures are retained in Blackbird's state
logs on macOS and the user journal on Linux. The updater never restarts itself;
the daemon restarts only after the installed formula version changes.

Installation also adds one `blackbird` HTTP MCP entry to detected OpenCode,
Claude Code, and Codex configurations while preserving unrelated settings.
Repeated installs converge the daemon, updater, and client definitions.

`update` runs `brew update` followed by
`brew upgrade phall1/tap/blackbird`; the service is restarted only when the
installed formula version changes. `status` reports both the daemon and updater.
`uninstall` stops the daemon, companion, and updater and removes only their
service definitions. Both databases, transcripts, logs, XDG directories, and
MCP client settings are retained.
