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
- one per-user launchd or systemd daemon, unattended Homebrew updates, and
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

Upgrading from 0.3.x needs no action: the installed service definition keeps
working. Run `blackbird install` once to move it to the explicit `daemon`
command, which is required before 0.5.0.

## Command Line

`blackbird --help` lists every command. Each one renders a report for a
terminal or, with `--json`, the same data for a script.

```sh
blackbird overview                 # projects, agents, mail, reservations at a glance
blackbird status                   # service, daemon handshake, and database state
blackbird doctor                   # diagnose the installation and print remedies
blackbird agents --project=$PWD    # who is registered, and what they hold
blackbird inbox --unread           # mail waiting on an agent
blackbird reservations --state=expired
blackbird events --limit=20        # tail the coordination journal
blackbird logs --follow
```

`status` handshakes with the running daemon rather than trusting the
supervisor, so a loaded-but-crashing job reports as crash-looping instead of
running. `doctor` exits 5 when any check fails and 0 otherwise, so warnings stay
advisory; `--strict` makes a warning fail too. Every finding names the exact
command that resolves it.

Shell completions come from the binary itself:

```sh
blackbird completion bash > $(brew --prefix)/etc/bash_completion.d/blackbird
blackbird completion zsh  > "${fpath[1]}/_blackbird"
blackbird completion fish > ~/.config/fish/completions/blackbird.fish
```

The CLI reads a loopback-only admin API and authenticates with a per-start
token the daemon writes to `$XDG_STATE_HOME/blackbird/admin.json` with owner
only permissions. `--address` targets a daemon on a non-default port and
refuses any host that is not loopback, since every request carries that token.

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

## Pi Delivery

`blackbird-pi` is a Pi-native extension. It runs only inside an active Pi
session and injects durable messages as ordered follow-ups:

```sh
pi install npm:blackbird-pi@0.1.0
```

## Claude Code Delivery

The `blackbird` Claude Code plugin uses MCP Channels. Claude owns its stdio
channel server for the active session; there is no Blackbird adapter service.

```sh
claude plugin marketplace add phall1/blackbird
claude plugin install blackbird@blackbird
claude --channels plugin:blackbird@blackbird
```

Adapter delivery never marks a Blackbird message read or acknowledged.

## Development

```sh
make lint       # all enabled static analyzers and formatting checks
make test-race  # shuffled tests under the race detector
make check      # the complete pre-push/CI quality gate
make hooks      # install fast pre-commit and exhaustive pre-push hooks with prek
```

The live `bd` compatibility probe is intentionally excluded from hermetic test
runs. Set `BLACKBIRD_RUN_EXTERNAL_TESTS=1` to exercise it against the installed
binary and local issue store.

Build metadata can be supplied with linker flags targeting `main.version`,
`main.commit`, and `main.builtAt`. Unset fields use explicit development
values.

## Releases

Releases are cut by release-please from Conventional Commit subjects. `feat:`
takes the minor, `fix:` and `perf:` take the patch, and every other type is
recorded without appearing in the changelog.

Landing a commit on `main` updates a single `chore: release main` pull request,
rebased onto `main` each run. That pull request is the release: merging it
writes the changelog and manifest, tags `vX.Y.Z`, and triggers the release
workflow, which builds each target on its own native runner, rebuilds and
compares the binary to prove the build is reproducible, asserts `--version`
against the tag, publishes the archives with checksums, and dispatches the
formula update to `phall1/homebrew-tap`.

The release branch is generated. Never commit to it or merge into it: the next
run rebases it away. Anything that belongs to a human — upgrade notes, guidance,
rationale — belongs in this README or in the commit subject that earns the
changelog line.

Pull requests squash, and the repository allows nothing else. One pull request
becomes one commit whose subject is the pull request title, so a change earns
exactly one changelog line. A merge commit that repeats the branch's own
`feat:` subject earns two, which is how 0.4.0 came to list its feature twice.

Two settings are load-bearing and easy to break. The root package declares no
`component`: release-please parses the component back out of the merged release
pull request's title, an aggregate title carries none, and a configured
component it cannot find makes it refuse to tag with `PR component: undefined
does not match configured component`. The release then sits merged and
untagged, which blocks every later release too. Branch auto-deletion is also
off, so a merged release branch survives long enough for its release to be
built. If a release ever lands merged but untagged, read the Release Please run
log before touching anything: the abort line names the cause.

The pinned Go toolchain is deliberate and appears in `go.mod` and both
workflows. Keep them in step, and note that the release build omits
`-buildid=`: with it, Go emits a macOS binary without an `LC_UUID` load command
that the dynamic loader refuses to run. Builds stay reproducible without it,
which the workflow verifies on every release.

## Local Product Management

The released `blackbird` binary manages its per-user service without requiring
root access:

```sh
blackbird install
blackbird status
blackbird update
blackbird uninstall
```

`install` creates XDG config, data, and state directories and one launchd agent
or systemd user unit for the daemon. During upgrades it stops and removes
definitions left by the retired `blackbird-claude` and `blackbird-pi` services
while retaining their private databases and transcripts for migration.
OpenCode, Pi, and Claude Code delivery is owned by their native plugin systems.

Installation also installs an unattended Homebrew updater that runs every six
hours: a non-`KeepAlive` launchd job on macOS, or a systemd user timer and
oneshot service on Linux. Updater failures are retained in Blackbird's state
logs on macOS and the user journal on Linux. The updater never restarts itself;
the daemon restarts only after the installed formula version changes.

Installation also adds one `blackbird` HTTP MCP entry to detected OpenCode,
Claude Code, and Codex configurations while preserving unrelated settings.
When user-managed OpenCode JSONC exists, Blackbird leaves it untouched rather
than creating a competing JSON file. Repeated installs converge the remaining
daemon, updater, and client definitions.

`update` runs `brew update` followed by
`brew upgrade phall1/tap/blackbird`; the service is restarted only when the
installed formula version changes. `status` reports both the daemon and updater.
`uninstall` stops the daemon and updater, cleans legacy adapter definitions, and
retains databases, transcripts, logs, XDG directories, and MCP client settings.
