#!/usr/bin/env bash
# SessionStart: report whether the flywheel's moving parts are actually up.
#
# The Blackbird daemon is what parallel agents coordinate through. If it is
# down, sessions should know immediately rather than discovering it when a
# reservation call fails.
set -uo pipefail

export PATH="$HOME/.local/go/bin:$HOME/.local/bin:$PATH"

probe() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && exec 3<&- 3>&-; }

if probe 8080 && probe 8081; then
  status="Blackbird daemon is UP (HTTP 127.0.0.1:8080, MCP 127.0.0.1:8081). Register with blackbird_agent_register before editing, and reserve paths before writing."
else
  status="Blackbird daemon is DOWN. Start it with \`make daemon\` (or \`go run ./cmd/blackbird\`) before relying on coordination tools; blackbird_* MCP calls will fail until then."
fi

if command -v go >/dev/null 2>&1; then
  toolchain="Go $(go version | awk '{print $3}' | sed 's/^go//') available."
else
  toolchain="WARNING: go is not on PATH; no local gate can run. Add \$HOME/.local/go/bin to PATH."
fi

jq -nc --arg ctx "$status
$toolchain" '{hookSpecificOutput: {hookEventName: "SessionStart", additionalContext: $ctx}}'
