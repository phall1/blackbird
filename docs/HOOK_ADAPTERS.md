# Command-hook delivery

`blackbird hook` is one one-shot Go adapter for agent hosts whose command-hook
contract can add stdout to model context. It reads the host event JSON from
stdin, registers or resumes a repository-scoped Blackbird agent, catches up at
most four durable events, and emits that host's response JSON. It never marks a
message read or acknowledged.

This is **queue-at-a-hook-boundary**, not push. The process exists only while the
host invokes it; an external Blackbird message cannot wake the host. Network,
state, and malformed-input failures are fail-open (`{}` on stdout and a
diagnostic on stderr), so a down daemon never blocks a user prompt.

Private registration tokens and cursors live under
`$XDG_STATE_HOME/blackbird/hooks` with mode `0600`. Override the loopback origin
with `BLACKBIRD_API_URL`, the stable recipient name with
`BLACKBIRD_HOOK_AGENT_NAME`, or the state root with
`BLACKBIRD_HOOK_STATE_DIR`. Do not run a hook and another Blackbird adapter under
the same agent name unless they share the same state directory.

## Claude Code

Claude Code processes `hookSpecificOutput.additionalContext` for both
`SessionStart` and `UserPromptSubmit`, so the hook can drain mail on session
resume and before each user turn:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "blackbird hook claude", "timeout": 10 }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "blackbird hook claude", "timeout": 10 }
        ]
      }
    ]
  }
}
```

Prefer the shipped Claude MCP Channel when steer-mode mid-turn delivery is
available. This hook is the queue-mode fallback; enabling both under the default
`ClaudeCode` name would give two consumers one registration identity.

Source: [Claude Code hooks reference][claude-hooks].

## Cursor

Cursor's `sessionStart` hook accepts `additional_context`. Its
`beforeSubmitPrompt` hook can only allow or block a prompt, so it cannot carry
Blackbird mail and is intentionally not configured.

```json
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      { "command": "blackbird hook cursor", "timeout": 10 }
    ]
  }
}
```

Place this in `~/.cursor/hooks.json` or merge it into a project's
`.cursor/hooks.json`. Delivery occurs only when a new composer conversation
starts; later mail remains durable in Blackbird for the next session or an MCP
inbox read.

Source: [Cursor hooks reference][cursor-hooks].

## GitHub Copilot CLI

Copilot CLI's `sessionStart` command hooks accept `additionalContext` and can
invoke the binary without a shell:

```json
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {
        "type": "command",
        "exec": "blackbird",
        "args": ["hook", "copilot"],
        "timeoutSec": 10
      }
    ]
  }
}
```

Copilot's `notification` event also accepts `additionalContext`, but injecting
there can wake an idle model and becomes **steer**, not queue. It is therefore
not enabled by the default snippet. Cloud-agent jobs additionally have a
different hook lifecycle and restricted network; this local loopback adapter is
for Copilot CLI.

Source: [GitHub Copilot hooks reference][copilot-hooks].

## Contracts that cannot deliver

- **Codex CLI:** `notify` invokes a command *after Codex emits its own
  notification* and only supplies a JSON payload to that command. Codex does not
  consume command output as model context, so wiring `blackbird hook` there
  would pretend stderr/stdout is delivery when it is not. Use Blackbird MCP pull
  until Codex exposes an inbound context hook or `thread/inject_items` adapter.
- **Devin:** Devin's documented automations start sessions from external events;
  it does not publish a local command-hook stdin/stdout contract that can add
  context to an existing session. A Blackbird webhook automation would be a
  separate hosted integration, not another config entry for this binary.

These are explicit non-integrations. The binary accepts only `claude`, `cursor`,
and `copilot`, so an unsupported host fails configuration instead of silently
dropping mail.

Sources: [Codex configuration reference][codex-config] and
[Devin automations][devin-automations].

[claude-hooks]: https://code.claude.com/docs/en/hooks
[cursor-hooks]: https://cursor.com/docs/hooks
[copilot-hooks]: https://docs.github.com/en/copilot/reference/hooks-configuration
[codex-config]: https://developers.openai.com/codex/config-reference
[devin-automations]: https://docs.devin.ai/product-guides/automations
