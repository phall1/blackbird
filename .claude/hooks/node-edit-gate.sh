#!/usr/bin/env bash
# PostToolUse gate for the TypeScript/JavaScript plugin packages.
#
# The Go daemon is only one of four released components. packages/claude-plugin,
# packages/opencode-plugin, and packages/pi-extension ship independently and
# have their own gates; without this they get no edit-time feedback at all.
#
# Never blocks. Findings come back as context.
set -uo pipefail

payload="$(cat)"
file="$(printf '%s' "$payload" | jq -r '.tool_input.file_path // .tool_response.filePath // empty' 2>/dev/null)"

[ -n "$file" ] || exit 0
[ -f "$file" ] || exit 0
case "$file" in
  *.ts|*.mts|*.js|*.mjs) ;;
  *) exit 0 ;;
esac
case "$file" in
  */node_modules/*|*/dist/*) exit 0 ;;
esac
command -v node >/dev/null 2>&1 || exit 0

# Locate the owning package: the nearest ancestor holding a package.json.
pkg="$(dirname "$file")"
while [ "$pkg" != "/" ] && [ ! -f "$pkg/package.json" ]; do pkg="$(dirname "$pkg")"; done
[ -f "$pkg/package.json" ] || exit 0

root="$(git -C "$(dirname "$file")" rev-parse --show-toplevel 2>/dev/null)" || exit 0
rel="${file#"$root"/}"
name="$(basename "$pkg")"
findings=""

if [ ! -d "$pkg/node_modules" ]; then
  findings="${findings}- deps: ${name} has no node_modules; its gates cannot run. Install with \`cd packages/${name} && npm ci\`.
"
else
  case "$file" in
    *.js|*.mjs)
      if ! syntax="$(node --check "$file" 2>&1)"; then
        findings="${findings}- syntax: ${rel} is not valid JavaScript:
$(printf '%s' "$syntax" | head -10)
"
      fi ;;
    *.ts|*.mts)
      if [ -f "$pkg/tsconfig.json" ] && [ -x "$pkg/node_modules/.bin/tsc" ]; then
        if ! types="$(cd "$pkg" && ./node_modules/.bin/tsc --noEmit -p tsconfig.json 2>&1)"; then
          findings="${findings}- types: ${name} does not type-check:
$(printf '%s' "$types" | head -20)
"
        fi
      fi ;;
  esac
fi

[ -n "$findings" ] || exit 0

jq -nc --arg ctx "Blackbird edit gate on ${rel} (package ${name}):
${findings}
Full package gate: \`cd packages/${name} && npm run gates\`." \
  '{hookSpecificOutput: {hookEventName: "PostToolUse", additionalContext: $ctx}}'
