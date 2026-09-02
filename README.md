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
- shared and exclusive exact/subtree advisory path claims with expiry, renewal,
  overlap detection, and internal claim generations, plus an opt-in
  `blackbird lease-guard` pre-commit check that surfaces another agent's claim
  before you overwrite it;
- one per-user launchd or systemd daemon, unattended Homebrew updates, and
  idempotent MCP client configuration; and
- reproducible native releases for Apple Silicon macOS and amd64/arm64 Linux.

SQLite is the only storage backend. The daemon's `--storage` flag survives with
that single legal value so an already-installed service definition keeps
working; `ls internal/storage/` is the current adapter set.

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
blackbird reservation release <lease-id> --force  # clear a dead agent's lease
blackbird events --limit=20        # tail the coordination journal
blackbird logs --follow
blackbird support-bundle           # one redacted document describing the whole install
```

`status` handshakes with the running daemon rather than trusting the
supervisor, so a loaded-but-crashing job reports as crash-looping instead of
running. `status -v` adds process-local request outcomes, lease contention,
live SSE connections, and database/WAL bytes from the authenticated loopback
admin surface. `doctor` exits 5 when any check fails and 0 otherwise, so
warnings stay advisory; `--strict` makes a warning fail too. Every finding names
the exact command that resolves it.

`support-bundle` collects what a bug report needs in one pass -- build
identity, a deep `doctor` run, `status`, the gc report, the tail of each log
stream, install paths, and each detected MCP client -- and redacts the daemon's
admin token, credential-shaped assignments in free text, and the home directory
prefix before emitting anything. It exits 0 whenever it produced a bundle, even
when the `doctor` run inside it reports failures: the command you reach for when
Blackbird is sick must not be the one that refuses to answer. `--out PATH`
writes the JSON owner-only and prints a receipt; without it the bundle is the
output. The document carries its own redaction policy, so whoever receives it
can read what was kept rather than infer it.

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

Start with `blackbird_join`, passing an absolute repository path as
`project_key` and a stable `agent_name`. Retain the returned
`registration_token` to resume the same identity after process or machine
restarts.

The MCP surface is exactly eight tools: `blackbird_join`, `blackbird_claim`,
`blackbird_release`, `blackbird_status`, `blackbird_say`, `blackbird_read`,
`blackbird_ack`, and `blackbird_wait`. Status also accepts optional work-item
and spend queries instead of advertising specialist tools.

All tools except initial join authenticate with the returned `agent_token`.
Claim the narrowest relevant paths before editing, use one conversation per
work item, acknowledge required handoffs, and release exact selector sets when
work completes.

A refused claim is a normal `ok:false` result, not a retry-loop error. Its
`blocked_by` and `options` identify the holder and the useful next actions;
`blackbird_status` answers the same question at any time, and `blackbird_wait`
parks until the path frees or mail arrives. It returns `path_free`,
`mail_arrived`, or `deadline`, so a caller that ran out of budget still learns
what happened.

## Delivery modes

"Push" says only that an adapter moved a message; it does not say what the host
does to the model. Blackbird names that behavior with three verbs:

- **notify** adds durable context without starting a model turn. OpenCode uses
  this mode with `noReply: true`; a future Codex adapter can use
  `thread/inject_items` for the same contract.
- **steer** admits a message into the active model loop. Claude Code MCP
  Channels provide this mid-turn path.
- **queue** schedules an ordered follow-up that runs when the host can accept
  another turn. Pi uses this mode while a session is busy.

These are host behaviors, not Blackbird mailbox facts. Adapter delivery in any
mode never marks a message read or acknowledged.

## Command-hook delivery (queue)

`blackbird hook` is one fail-open Go adapter for the command-hook contracts that
can add stdout to model context. It supports Claude Code, Cursor, and GitHub
Copilot CLI with host-specific JSON emitted by the same binary. Hooks only run at
host lifecycle boundaries, so this is queue delivery rather than externally
triggerable push. Codex's outbound-only `notify` callback and Devin's hosted
automations cannot consume this contract and are explicitly unsupported. See
[command-hook delivery](docs/HOOK_ADAPTERS.md) for exact config and limits.

## OpenCode Delivery (notify)

The `blackbird-opencode` package appends each durable `message.available` event
to an OpenCode session transcript without spending an agent turn — the message
is persisted and visible, and no agent loop is scheduled to answer it. It uses
SSE only as a low-latency wake signal, catches up from the SQLite event journal
after every reconnect, resolves each message through a privacy-checked endpoint,
and does not mark or acknowledge mail on the agent's behalf.

Add it to OpenCode's `plugins` configuration with an absolute repository path:

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

Every version pinned in a delivery example on this page is the one this
repository shipped when the example was written; release-please bumps each
package on its own tag, so read the current set rather than those lines:

```sh
jq -r '"\(.name)@\(.version)"' packages/*/package.json
```

OpenCode installs the package and its production dependencies in its isolated
plugin cache. Blackbird stores each adapter's delivery cursor server-side;
registration tokens, conversation-to-session bindings, and host-specific
quarantine state remain under `$XDG_STATE_HOME/blackbird` with private directory
and file permissions.

## Pi Delivery (queue)

`blackbird-pi` is a Pi-native extension. It runs only inside an active Pi
session and queues durable messages as ordered follow-ups that trigger a turn
when Pi can accept one:

```sh
pi install npm:blackbird-pi@0.1.1
```

## Claude Code Delivery (steer)

The `blackbird` Claude Code plugin uses MCP Channels to steer messages into the
active model loop. Claude owns its stdio channel server for the active session;
there is no Blackbird adapter service.

```sh
claude plugin marketplace add phall1/blackbird
claude plugin install blackbird@blackbird
claude --channels plugin:blackbird@blackbird
```

Adapter delivery never marks a Blackbird message read or acknowledged.

## Gemini CLI Delivery

Gemini CLI push delivery is not on the roadmap. Its [hook events][gemini-hooks]
run only from the CLI's own lifecycle, so an external Blackbird message cannot
wake an active session. Its A2A server also advertises
[`pushNotifications: false`][gemini-a2a], while the HTTP API still has an open
[authentication defect][gemini-a2a-auth]. Reconsider this only if Gemini ships
an externally triggerable, authenticated push primitive; MCP remains the pull
half and cannot substitute for one.

[gemini-hooks]: https://geminicli.com/docs/hooks/reference/
[gemini-a2a]: https://github.com/google-gemini/gemini-cli/blob/4963a4456a886bb6af7dcfb807ad6e3e46ce46fc/packages/a2a-server/src/http/app.ts
[gemini-a2a-auth]: https://github.com/google-gemini/gemini-cli/issues/29001

## Agent Host Protocol

Microsoft's [Agent Host Protocol][ahp] represents a host's sessions, chats, and
subagents to clients; it explicitly does not define peer identity,
agent-to-agent messaging, task assignment, or coordination. Blackbird therefore
does not adopt AHP as its core protocol: its repository-scoped agents, durable
mail, and advisory path claims are complementary. If a supported host exposes a
stable AHP endpoint, integrate it through a thin adapter rather than changing
Blackbird's storage or delivery semantics.

[ahp]: https://github.com/microsoft/agent-host-protocol

## JetBrains and Zed through ACP

Blackbird does not ship an Agent Client Protocol agent. ACP clients spawn a
[coding agent that owns its model, tools, and prompt turns][acp-architecture];
Blackbird is a coordinator, not a second coding-agent runtime. A Blackbird ACP
process would therefore open a separate coordination-only chat, while wrapping
an existing ACP agent would duplicate that agent's session, authentication, and
tool lifecycle just to proxy JSON-RPC.

The useful integration already exists one layer lower. [JetBrains][jetbrains-acp]
and [Zed][zed-acp] both forward configured MCP servers to the selected external
agent, so install Blackbird's MCP server for the real coding agent rather than
replacing it with a Blackbird-branded ACP shell. Reconsider an ACP adapter only
if the protocol gains a client-side facility for injecting context into an
already-running external-agent thread; stable ACP v1 exposes no such method.

[acp-architecture]: https://agentclientprotocol.com/get-started/architecture
[jetbrains-acp]: https://www.jetbrains.com/help/ai-assistant/acp.html
[zed-acp]: https://zed.dev/docs/ai/external-agents

## Development

```sh
make lint       # all enabled static analyzers and formatting checks
make test-race  # shuffled tests under the race detector
make check      # the complete pre-push/CI quality gate
make hooks      # install fast pre-commit and exhaustive pre-push hooks with prek
```

`make hooks` also installs `blackbird lease-guard`, which checks a commit's
staged paths against exclusive path claims held by other agents. It is a
courtesy check, not a lock: claims are advisory, the guard is opt-in twice over
(you install the hooks, and it only refuses when `BLACKBIRD_AGENT_NAME` names
your registered agent), an unreachable daemon always passes, and `--no-verify`
skips it. Set `BLACKBIRD_LEASE_GUARD=off|warn|block` to override the default.

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

The updater is scheduled only when Homebrew is present, because it upgrades the
Homebrew formula and has nothing to do without it. Detection searches the PATH
the updater itself runs with rather than your shell's, since a Homebrew under a
custom prefix is on one and not the other. On a machine without it — a source
build, typically — `install` schedules no updater and removes one an earlier
install left behind, `status` and `doctor` report `updater=unsupported` rather
than a fault, and `update` refuses with that reason instead of a missing-`brew`
error. Nothing else about the installation changes, and such a machine is
updated by whatever installed it.

Installation also adds one `blackbird` HTTP MCP entry to detected OpenCode,
Claude Code, and Codex configurations while preserving unrelated settings.
When user-managed OpenCode JSONC exists, Blackbird leaves it untouched rather
than creating a competing JSON file. Repeated installs converge the remaining
daemon, updater, and client definitions.

`update` runs `brew update` followed by
`brew upgrade phall1/tap/blackbird`; the service is restarted only when the
installed formula version changes, and it fails before running either command
when Homebrew is absent. `status` reports both the daemon and updater.
`uninstall` stops the daemon and updater, cleans legacy adapter definitions, and
retains databases, transcripts, logs, XDG directories, and MCP client settings.
