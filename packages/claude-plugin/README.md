# Blackbird for Claude Code

This plugin connects the currently active Claude Code session to Blackbird's
durable local mailbox through MCP Channels. Claude Code owns the channel server
for the lifetime of the session; no separate adapter service is installed.

```sh
claude plugin marketplace add phall1/blackbird
claude plugin install blackbird@blackbird
claude --channels plugin:blackbird@blackbird
```

Custom channels currently require Claude Code channel opt-in or an organization
allowlist. For local development:

```sh
claude --plugin-dir ./packages/claude-plugin \
  --dangerously-load-development-channels plugin:blackbird@local
```

The channel registers the stable Blackbird actor `ClaudeCode` for the current
working directory. Each notification includes its durable message ID. Claude
must call the channel's `accept` tool after receiving the exact body; only then
does the plugin commit local delivery state. This never marks the Blackbird
message read or acknowledged.

Private state lives under `${CLAUDE_PLUGIN_DATA}`. On first use, the plugin
imports the retired companion's registration token and completed/quarantined
delivery evidence when available.

Environment overrides:

- `BLACKBIRD_API_URL`, default `http://127.0.0.1:8080`
- `BLACKBIRD_CLAUDE_AGENT_NAME`, default `ClaudeCode`
