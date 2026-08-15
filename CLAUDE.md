# Blackbird

Durable, local-first coordination service for human and AI agent work: a Go
daemon exposing HTTP and MCP transports over SQLite, providing agent identity,
durable mail, and file reservations. It is the standalone replacement for the
legacy Python Agent Mail service.

This repository dogfoods itself. Agents working here coordinate through the
Blackbird daemon they are building. See "Agent coordination protocol" below.

## Toolchain

Match CI exactly. Mismatched versions produce failures that reproduce nowhere.

| Tool | Version | Notes |
| --- | --- | --- |
| Go | 1.26.6 | `go.mod` requires 1.26.4, `toolchain` pins 1.26.6 |
| golangci-lint | 2.12.0 | config is `version: "2"` schema; v1 will not parse it |
| Node | >= 22.19.0 | plugin packages only |
| prek | >= 0.2.0 | `make hooks` installs pre-commit and pre-push |

`GOTOOLCHAIN=go1.26.6` is set in `.claude/settings.json` so sessions build with
exactly CI's compiler. Do not rely on the version in a downloaded tarball's
filename — `go.dev/dl/` serves the current patch release under an older
release's name, and `GOTOOLCHAIN=auto` will happily use a newer local toolchain
because it satisfies the `toolchain` directive. Check with `go version` inside
the repo, not the name of the file you downloaded.

The patch version is a security floor, not a preference: `make vuln` reports
every stdlib advisory fixed in a later patch release, so a toolchain left behind
turns the gate red with no code change. 1.26.5 carried six such advisories.

## Quality gates

`make check` is the contract: `lint vet test-race coverage build vuln`. Run it
before declaring Go work done. Individual gates:

```sh
make lint        # golangci-lint config verify + run
make vet         # go vet ./...
make test        # go test -shuffle=on ./...
make test-race   # go test -race -shuffle=on ./...
make test-stress # -count=3, exposes order and concurrency flakes
make coverage    # enforces a floor, see the trap below
make build       # go mod verify, go mod tidy -diff, CGO_ENABLED=0 build
make vuln        # govulncheck v1.6.0
```

**Coverage floor.** `make coverage` and CI both enforce **61.0%**; total
coverage is currently **61.8%**. The two floors live in `Makefile`
(`COVERAGE_FLOOR`) and `.github/workflows/ci.yml` — they are deliberately
identical, so a green `make coverage` now means a green CI gate. If you change
one, change both, and read the number rather than trusting the exit code:

```sh
go tool cover -func=/tmp/blackbird-coverage.out | tail -1
```

They previously differed (58.8% local, 59.2% CI, sitting exactly on the CI
floor), which meant any uncovered statement failed CI while `make coverage`
still exited zero. Do not reintroduce that gap: when you raise coverage, ratchet
both floors up together and leave a little slack.

**The plugin packages are their own Go module.** `packages/go.mod` exists only
so `npm ci` cannot change the root module's package set: `flatted`, a transitive
dependency of `opencode-plugin`, vendors a Go package under `node_modules`, and
without the nested module it joined `./...` — dragging the coverage total down
~0.5pp on any workstation that had installed the Node dependencies while CI,
which never runs `npm ci` in the Go job, saw a different number. Do not delete
it.

CI additionally requires `test -z "$(gofmt -l .)"`, `go mod tidy -diff`, and
runs the test matrix on ubuntu-24.04 and macos-15.

The three plugin packages have their own gates and their own CI workflows. They
need dependencies installed first (`npm ci`), which is not done by any Go
target:

```sh
cd packages/<pkg> && npm ci && npm run gates
```

`gates` means check + test + `npm audit` for `claude-plugin`, and check + test +
`test:pack` for `opencode-plugin` and `pi-extension`.

Git hooks are installed with `make hooks` (prek): gofmt, `go vet`, and a fast
golangci pass on pre-commit, and the full `make check` on pre-push. They are not
installed by cloning — run `make hooks` once per checkout.

## Repository map

Four independently released components. `release-please-config.json` maps each
to its own tag and changelog; the Go root explicitly excludes `packages/*`.

- **Go daemon** (root) — the product. Tag `vX.Y.Z`.
- `packages/claude-plugin` — Claude Code plugin. Delivers durable messages into
  a live session as an MCP Channel. Tag `claude-plugin-vX.Y.Z`.
- `packages/opencode-plugin` — OpenCode V2 plugin, TypeScript.
- `packages/pi-extension` — Pi companion extension, TypeScript.

Go layout:

```
cmd/blackbird           daemon entrypoint and product commands
cmd/blackbird-openapi    OpenAPI document generator
internal/domain          pure model: identity state, transitions, events, errors
internal/application     use cases, orchestration, codecs, authentication, ports
internal/storage         sqlite (supported) and postgres (fail-closed) adapters
internal/integration     beads, localsecurity
internal/transport       contracts, http, mcp
internal/runtime         composition root and daemon lifecycle
internal/install         launchd/systemd install, status, update, uninstall
internal/architecturetest  executable architecture policy
```

## Architecture invariants

Hexagonal, enforced by `internal/architecturetest/import_boundaries_test.go`.
These are tests, not style guidance — violating them breaks the build.

- **`domain` uses the standard library only.** No third-party imports, no other
  Blackbird layers. This is checked import by import.
- **`application` may import only `domain` and itself.** It must not reach into
  `storage`, `integration`, `transport`, or `runtime`. Dependencies invert
  through ports defined in `application`.
- **`storage`, `integration`, `transport` may import inward or themselves** —
  `domain`, `application`, or their own layer. They must not import each other,
  and must not import `runtime`.
- **Only `runtime` and `cmd` may assemble outward layers.** Composition happens
  in the composition root, nowhere else.
- **New top-level directories under `internal/` must be declared** in
  `allowedInternalLayers`, or every file in them fails the boundary test.
- **`/spikes/go-stack` and `/src/mcp_agent_mail` are forbidden** anywhere in the
  module graph, package sources, or `go.mod` replacements. They are the
  abandoned proof and legacy trees.

Test files are exempt from layering rules but not from the forbidden-tree rule.

## Conventions

- **Conventional commits are load-bearing.** release-please derives versions and
  changelogs from them. `feat:` and `fix:` cut releases; scope changes to a
  plugin package so the right component is versioned.
- **Lint policy is `default: all` with an explicit disable list.** The disabled
  linters in `.golangci.yml` are a deliberate decision to drop subjective
  style/architecture linters while keeping the full bug and security analyzer
  set. Do not disable a linter to make an error go away, and do not add
  `//nolint` without a reason that would survive review — fix the finding.
- Imports are grouped with `goimports` local-prefix
  `github.com/phall1/blackbird`.
- SQLite is the supported daily-use backend. PostgreSQL is explicit and
  fail-closed for coordination operations that have not landed there yet; do not
  paper over a Postgres gap to make a test pass.

## Running the daemon

```sh
make daemon                            # HTTP 127.0.0.1:8080, MCP 127.0.0.1:8081
go run ./cmd/blackbird -sqlite-path /path/to/blackbird.db
go run ./cmd/blackbird -version
```

`make daemon` stores its database at `~/.local/share/blackbird/blackbird.db`
(override with `BLACKBIRD_DB`) so the repository working tree stays clean.

For a daemon that outlives the shell, use the product's own installer rather
than a hand-written unit — exercising it is part of dogfooding:

```sh
blackbird install    # per-user systemd/launchd service + MCP client registration
blackbird status     # service state, updater state, paths
blackbird uninstall  # reverses both
```

On Linux this writes `~/.config/systemd/user/blackbird.service`
(`Restart=on-failure`) plus a `blackbird-update` timer that fires every 6h, and
merges `mcpServers.blackbird` into `~/.claude.json`. Only clients it actually
detects are touched. Note the daemon is then user-scoped *and* repo-scoped via
`.mcp.json`; both name the server `blackbird` and point at the same URL, so the
duplication is harmless — the repo-scoped entry is what teammates get on clone.

**Known rough edge.** `install` also schedules `blackbird-update.timer` every 6h,
and `Update` shells out to `brew` unconditionally
(`internal/install/install.go`). The supported install path is Homebrew, so on a
Linux source build the timer fails every 6h with
`exec: "brew": executable file not found`. Disable it there:
`systemctl --user disable --now blackbird-update.timer`. Install should detect
that it was not installed via Homebrew and skip the updater instead.

Flags: `-storage` (sqlite|postgres), `-sqlite-path`, `-http-address`,
`-mcp-address`. Bare `blackbird` runs the daemon; `install`, `status`, `update`,
and `uninstall` are product commands that manage the per-user service.

MCP is served over Streamable HTTP at the root of the MCP listener, so the
endpoint is `http://127.0.0.1:8081` with no path suffix.

## Agent coordination protocol

Blackbird is wired into this repo over MCP. Follow this protocol so parallel
agents do not clobber each other.

1. **Register once per session.** `blackbird_agent_register` with `project_key`
   set to this repository's absolute path and a stable `agent_name`.
2. **Keep the token.** The returned `registration_token` is the value every
   other tool takes as `agent_token` — they are the same string despite the
   different field names. Pass it back as `registration_token` to resume the
   same identity after a restart.
3. **Reserve before editing.** `blackbird_reservation_acquire` with `mode`
   (`shared` for reads, `exclusive` for writes) and `selectors`, each
   `{kind: "exact"|"subtree", path}`. Reserve the narrowest path that covers
   your edit. Hold the returned `lease_id` and `fences`.
4. **Renew long work.** `blackbird_reservation_renew` takes the `lease_id` and
   the current `fences`. Stale fences are rejected — that is the fencing token
   doing its job, not a bug.
5. **Release when done.** `blackbird_reservation_release`. Do not leave leases
   to expire if you can release them.
6. **One conversation per work item.** `blackbird_conversation_open`, then
   `blackbird_message_send` / `blackbird_message_reply`. Acknowledge required
   handoffs with `blackbird_message_acknowledge`; mark read with
   `blackbird_message_mark_read`. Never mark or acknowledge on another agent's
   behalf.

Because this repo builds the tool it runs on, coordination failures are product
bugs. When the protocol misbehaves, capture it as a bug against Blackbird rather
than working around it silently.

## The flywheel

Repository-local Claude Code configuration. Each layer exists to remove work
from the next session rather than only from this one.

**Automatic checks** — optional, and deliberately *not* committed.
`.claude/hooks/` and `.claude/settings.local.json` are gitignored: edit gates
shell out to whatever Go and Node happen to be on a given developer's PATH, so
they are personal tooling rather than part of the project's contract. Nothing
in this repository depends on them, and `make check` remains the only gate that
speaks for the project. If you want the same feedback loop, the three scripts
worth having are:

- a `PostToolUse` gate on `Edit`/`Write` that reformats non-gofmt-clean Go
  files, checks the edited file's imports against the layer rules above, and
  compiles the package — reporting findings as context and never blocking, so a
  half-finished refactor is not treated as an error;
- the same for the plugin packages: syntax-check `.js`/`.mjs`, type-check `.ts`
  against the package's own `tsconfig.json`, and say so when a package has no
  `node_modules` to gate with;
- a `SessionStart` probe reporting whether the daemon is up and which Go is on
  PATH.

**Specialists** — `.claude/agents/`. Delegate rather than re-deriving:

- `boundary-auditor` — hexagonal import boundaries, with the inversion that
  fixes each violation.
- `coverage-guard` — which uncovered statements threaten the 61.0% floor.
- `contract-reviewer` — MCP/HTTP surface changes and their effect on the three
  plugin packages.

**Commands** — `.claude/commands/`:

- `/gate` — run `make check` and interpret the result against CI's real floors.
- `/claim` — register with Blackbird and reserve paths before editing.
- `/handoff` — release leases and leave a durable handoff message.
- `/flywheel` — convert this session's hard-won knowledge into a durable rule.

`/flywheel` is the part that compounds. When something costs you more than one
attempt to figure out, that is the signal to run it: the fix belongs in this
file, an agent, or a command — somewhere the next session will read it, not only
in the current transcript. Prefer this file and `.claude/agents/` over a hook,
since those are what teammates actually get on clone.
