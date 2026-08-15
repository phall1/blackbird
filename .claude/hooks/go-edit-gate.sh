#!/usr/bin/env bash
# PostToolUse gate for Go edits.
#
# Three cheap checks that mirror what CI enforces, run the moment a .go file is
# written: gofmt (auto-fixed), the hexagonal import boundaries from
# internal/architecturetest, and whether the package still compiles.
#
# Never blocks. Findings are injected back as context so the agent can fix them
# without a half-finished refactor being treated as an error.
set -uo pipefail

export PATH="$HOME/.local/go/bin:$HOME/.local/bin:$PATH"

MODULE="github.com/phall1/blackbird"

payload="$(cat)"
file="$(printf '%s' "$payload" | jq -r '.tool_input.file_path // .tool_response.filePath // empty' 2>/dev/null)"

[ -n "$file" ] || exit 0
[ "${file%.go}" != "$file" ] || exit 0
[ -f "$file" ] || exit 0
command -v go >/dev/null 2>&1 || exit 0

root="$(git -C "$(dirname "$file")" rev-parse --show-toplevel 2>/dev/null)" || exit 0
rel="${file#"$root"/}"
findings=""

# 1. gofmt — CI runs `test -z "$(gofmt -l .)"`, so fix it here rather than fail there.
if [ -n "$(gofmt -l "$file" 2>/dev/null)" ]; then
  if gofmt -w "$file" 2>/dev/null; then
    findings="${findings}- gofmt: reformatted ${rel} (it was not gofmt-clean; CI fails on that).
"
  fi
fi

# 2. Import boundaries — mirrors validateImport in internal/architecturetest.
#    Test files are exempt from layering but not from the forbidden-tree rule.
layer_of_dir() {
  case "$1" in
    cmd|cmd/*) echo cmd ;;
    internal/*) echo "$1" | cut -d/ -f2 ;;
    *) echo other ;;
  esac
}
layer_of_import() {
  case "$1" in
    "$MODULE"/internal/*) echo "${1#"$MODULE"/internal/}" | cut -d/ -f1 ;;
    "$MODULE"/cmd/*) echo cmd ;;
    *) echo "" ;;
  esac
}

importer="$(layer_of_dir "$(dirname "$rel")")"
is_test=0
case "$rel" in *_test.go) is_test=1 ;; esac

allowed_layers=" domain application storage integration transport runtime install companion architecturetest "
outward_layers=" storage integration transport "

imports="$(awk '
  /^import \(/ { inblock = 1; next }
  inblock && /^\)/ { inblock = 0; next }
  (inblock || /^import "/) && match($0, /"[^"]+"/) {
    print substr($0, RSTART + 1, RLENGTH - 2)
  }
' "$file" 2>/dev/null)"

while IFS= read -r imp; do
  [ -n "$imp" ] || continue

  case "$imp" in
    */spikes/go-stack*|*/src/mcp_agent_mail*)
      findings="${findings}- boundary: ${rel} imports forbidden legacy/proof tree \"${imp}\".
"
      continue ;;
  esac

  [ "$is_test" -eq 0 ] || continue

  imported="$(layer_of_import "$imp")"

  case "$imp" in
    "$MODULE"/internal/*)
      case "$allowed_layers" in
        *" $imported "*) ;;
        *) findings="${findings}- boundary: ${rel} imports undeclared internal layer \"${imported}\"; add it to allowedInternalLayers or move the code.
" ; continue ;;
      esac ;;
  esac

  if [ "$importer" = domain ]; then
    # domain is standard-library only: a first path segment containing a dot is external.
    first="${imp%%/*}"
    case "$first" in
      *.*) findings="${findings}- boundary: domain must use the standard library only; ${rel} imports \"${imp}\".
" ; continue ;;
    esac
  fi

  [ -n "$imported" ] || continue

  case "$importer" in
    domain)
      [ "$imported" = domain ] || findings="${findings}- boundary: domain cannot import ${imported} (${rel}).
" ;;
    application)
      case "$imported" in
        domain|application) ;;
        *) findings="${findings}- boundary: application may import only domain and itself among Blackbird packages; ${rel} imports ${imported}.
" ;;
      esac ;;
    storage|integration|transport)
      case "$imported" in
        domain|application|"$importer") ;;
        *) findings="${findings}- boundary: ${importer} may import inward layers or itself; ${rel} imports ${imported}.
" ;;
      esac ;;
    *)
      case "$outward_layers" in
        *" $imported "*)
          case "$importer" in
            runtime|cmd) ;;
            *) findings="${findings}- boundary: only runtime or cmd may assemble outward layer ${imported} (${rel}).
" ;;
          esac ;;
      esac ;;
  esac
done <<< "$imports"

# 3. Does the package still build?
if ! build_output="$(cd "$root" && go build "./$(dirname "$rel")" 2>&1)"; then
  findings="${findings}- build: ./$(dirname "$rel") does not compile:
$(printf '%s' "$build_output" | head -20)
"
fi

[ -n "$findings" ] || exit 0

jq -nc --arg ctx "Blackbird edit gate on ${rel}:
${findings}
Fix these before running the full gate (\`make check\`)." \
  '{hookSpecificOutput: {hookEventName: "PostToolUse", additionalContext: $ctx}}'
