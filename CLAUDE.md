# Blackbird

Durable, local-first coordination service for human and AI agent work: a Go
daemon exposing HTTP and MCP transports over SQLite, providing agent identity,
durable mail, and file reservations. It is the standalone replacement for the
legacy Python Agent Mail service.

This repository dogfoods itself. Agents working here coordinate through the
Blackbird daemon they are building. See "Agent coordination protocol" below.

## How to read this file

This codebase moves fast, and a document that mirrors values living in the code
goes stale silently — which is worse than saying nothing, because it is
confidently wrong. So this file states **invariants and where to look**, and
gives you the command to derive anything that changes.

It is also deliberately agent-facing and narrow. `README.md` is the human-facing
document and owns install, the command line, daily use, delivery to each client,
and the release flow. When the two overlap, README wins and this file should
point at it rather than restate it.

Two consequences for you:

- **A number or path you need is derived, not quoted.** Where a threshold, a
  version, or a file location matters, you will find the command that reports
  it, not the value itself. Run it.
- **If you find a stale claim here, fixing it is part of your task**, not a
  distraction from it. Prefer replacing the stale fact with the command that
  derives it, so it cannot go stale again.

Anything below stated as a rule ("`domain` uses the standard library only") is
meant to be durable. Anything that names a specific file does so because that
file is a stable anchor — `go.mod`, `Makefile`, the CI workflow — not because
the source tree is expected to hold still.

## Toolchain

Match CI exactly. Mismatched versions produce failures that reproduce nowhere.
Every version is pinned in a file rather than here:

| Tool | Pinned in |
| --- | --- |
| Go | `toolchain` directive in `go.mod`, and `go-version` in the CI workflows |
| golangci-lint | the lint action's `version` in CI; `.golangci.yml` declares which config schema it must parse |
| Node | `engines` in each `packages/*/package.json` |
| govulncheck | the version in the `vuln` target of `Makefile` |

```sh
grep -E '^(go|toolchain) ' go.mod
grep -rhoE '(go-version|version): [v0-9.]+' .github/workflows/ci.yml | sort -u
```

`.claude/settings.json` sets `GOTOOLCHAIN` to the same pin so sessions build
with exactly CI's compiler. Keep it in step with `go.mod`; if they drift, local
builds silently stop testing what CI tests.

Two traps worth knowing:

- **A downloaded tarball's filename is not evidence of its version.** `go.dev/dl`
  serves the current patch release under an older release's name, and
  `GOTOOLCHAIN=auto` will happily accept a newer local toolchain because it
  still satisfies the `toolchain` directive. Check with `go version` inside the
  repo.
- **The patch version is a security floor, not a preference.** `make vuln`
  reports every stdlib advisory fixed in a later patch release, so a toolchain
  left behind turns the gate red with no code change at all. When `make vuln`
  fails on stdlib findings, read the "Fixed in" line before suspecting your own
  work.

## Quality gates

`make check` is the contract. Run it before declaring Go work done, and read
the target list from the Makefile rather than from memory:

```sh
grep -E '^(check|\.PHONY)' Makefile
make help 2>/dev/null || sed -n '/^[a-z-]*:/p' Makefile
```

Each target is a single gate: lint, vet, the race-and-shuffle test run, the
coverage floor, the build and module checks, and the vulnerability scan.
`make test-stress` repeats the suite to expose order and concurrency flakes.

**The coverage floor is enforced in two places and they must stay identical** —
`COVERAGE_FLOOR` in `Makefile`, and the threshold in the CI workflow. Read both,
then read what the tree actually measures:

```sh
grep COVERAGE_FLOOR Makefile
grep -A3 'coverage floor' .github/workflows/ci.yml
go tool cover -func=/tmp/blackbird-coverage.out | tail -1   # after make coverage
```

Never conclude coverage is fine from the Makefile's exit code — read the number.
The two floors once differed, with the total sitting exactly on the higher one,
so a green local gate meant a red CI gate and the margin reached zero without
anyone noticing. When you raise coverage, ratchet both floors together and leave
slack; when you lower one, you have almost certainly made a mistake.

**The plugin packages are their own Go module.** `packages/go.mod` exists only so
`npm ci` cannot change the root module's package set: a transitive Node
dependency vendors Go source under `node_modules`, and without the nested module
it joined `./...` — pulling the coverage total down on any workstation that had
installed the Node dependencies, while CI, which does not run `npm ci` in the Go
job, measured something different. Do not delete it. Confirm the boundary holds
with:

```sh
go list ./... | grep node_modules   # must print nothing
```

CI also enforces formatting and module tidiness, and runs the test matrix on
more than one OS. Read the workflow for the current set rather than assuming.

The plugin packages have their own gates and their own CI workflows, and need
their dependencies installed first — no Go target does this for you:

```sh
cd packages/<pkg> && npm ci && npm run gates
```

What `gates` runs differs per package; read the `scripts` block of that
package's `package.json`.

Git hooks are installed with `make hooks` (prek): a fast subset on pre-commit
and the full `make check` on pre-push. They are not installed by cloning — run
`make hooks` once per checkout.

## Repository map

Independently released components, each mapped to its own tag and changelog by
`release-please-config.json`; the Go root explicitly excludes the plugin
packages. Read the current set from that config rather than from a list here:

```sh
grep -E '"[^"]+": \{|"component"|"package-name"' release-please-config.json
ls packages/
```

The Go daemon at the root is the product. Each directory under `packages/` is a
separate client — Claude Code, OpenCode, and Pi companion extensions — versioned
and released on its own tag.

For the Go layout, ask the tree rather than trusting a diagram:

```sh
go list ./... | sed 's|github.com/phall1/blackbird/||'
```

The shape is hexagonal: a pure `domain`, an `application` layer of use cases and
ports, outward adapters for storage, integration, and transport, and a
composition root that assembles them. The next section is the enforceable
version of that sentence.

## Architecture invariants

Hexagonal, and enforced as executable policy by the architecture test package —
not style guidance. Violating one breaks the build:

```sh
go test ./internal/architecturetest/
```

Layer is the first path segment under `internal/`; anything under `cmd/` is
`cmd`.

- **`domain` uses the standard library only.** No third-party imports, no other
  Blackbird layers. This is checked import by import.
- **`application` may import only `domain` and itself** among Blackbird
  packages. External dependencies are allowed. It must never reach into
  storage, integration, transport, or runtime — those invert through ports
  declared in `application`.
- **Outward layers may import inward or themselves.** Storage, integration, and
  transport may import `domain`, `application`, or their own layer. They must
  not import each other, and must not import the runtime.
- **Only the runtime and `cmd` may assemble outward layers.** Composition
  happens in the composition root, nowhere else.
- **A new top-level directory under `internal/` must be declared** in the
  architecture test's allow-list, or every file in it fails. Add one only for a
  genuinely new architectural layer, never to silence a misplaced package.
- **The abandoned proof and legacy trees are forbidden** anywhere in the module
  graph, package sources, or `go.mod` replacements. The architecture test names
  them; read it if a path is rejected and you do not know why.

Test files are exempt from the layering rules but not from the forbidden-tree
rule.

When the architecture test fails, delegate to the `boundary-auditor` agent — a
violation almost always means a dependency points the wrong way, and the fix is
an inversion rather than an exemption.

## Conventions

- **Conventional commits are load-bearing.** release-please derives versions and
  changelogs from them. `feat:` and `fix:` cut releases; scope a change to a
  plugin package so the right component is versioned. A `chore:` or `test:` that
  should have been a `fix:` silently withholds a release from users.
- **Pull requests squash, and the repository allows nothing else** — so the
  subject that reaches `main`, and therefore the changelog, is the **pull
  request title**, not any commit subject on your branch. A branch whose commits
  are impeccably conventional still releases nothing if its PR title is prose.
  Title the PR as the commit you want, and let the strongest change on the
  branch decide the type. `README.md` under "Releases" is the human-facing
  authority on this; do not duplicate its detail here.
- **Lint policy is `default: all` with an explicit disable list.** The disabled
  linters in `.golangci.yml` are a deliberate decision to drop subjective
  style and architecture linters while keeping the full bug and security
  analyzer set. Do not disable a linter to make an error go away, and do not add
  `//nolint` without a reason that would survive review — fix the finding.
- Imports are grouped with `goimports` using this module as the local prefix.
- SQLite is the supported daily-use backend. PostgreSQL is explicit and
  fail-closed for coordination operations that have not landed there yet; do not
  paper over a Postgres gap to make a test pass, and do not write tests that
  make an unimplemented Postgres path look supported.

## Running the daemon

```sh
make daemon                      # addresses are printed by the target
go run ./cmd/blackbird -version
```

`-help` prints nothing and exits non-zero — the flag set discards its output —
so derive the flags from where they are registered instead:

```sh
grep -rnE 'flags\.(Bool|String|Int|Duration|Var)' ./cmd/blackbird
```

Bare `blackbird` runs the daemon; the product commands that manage the per-user
service are dispatched before flag parsing, so they take no leading dash.

`make daemon` keeps its database outside the working tree so the repository
stays clean; the target names the path and the environment variable that
overrides it.

For a daemon that outlives the shell, use the product's own installer rather
than a hand-written unit — exercising it is part of dogfooding:

```sh
blackbird install    # per-user service + MCP client registration
blackbird status     # service state, updater state, paths
blackbird uninstall  # reverses both
```

`install` writes a per-user service, schedules an updater, and merges its MCP
server entry into the clients it actually detects. `blackbird status` reports
what is installed and where — trust it over any description here. Note the
daemon ends up both user-scoped and repo-scoped via `.mcp.json`; both name the
same server at the same URL, so the duplication is harmless, and the repo-scoped
entry is what teammates get on clone.

MCP is served over Streamable HTTP at the **root** of the MCP listener — the
endpoint has no path suffix. Getting this wrong looks like a dead server.

**Verify before trusting the installer's updater.** The supported install path
is Homebrew, and the update path has assumed it, so a source build on a machine
without Homebrew can end up with a scheduled updater that fails on every fire.
Check after installing:

```sh
blackbird status
systemctl --user list-timers 'blackbird*'   # Linux
```

If the updater cannot work on your machine, disable that timer rather than
letting it fail on a schedule. If you find this is still true, it is a product
bug worth fixing rather than documenting again.

## Agent coordination protocol

Blackbird is wired into this repo over MCP. Follow this protocol so parallel
agents do not clobber each other. The tool list your client exposes is
authoritative for exact names and arguments; the sequence below is the part that
matters.

1. **Register once per session**, with `project_key` set to this repository's
   absolute path and a stable agent name.
2. **Keep the token.** Registration returns a `registration_token`, and every
   other tool takes that same string as `agent_token` — one value, two field
   names. Pass it back as `registration_token` to resume the same identity after
   a restart.
3. **Reserve before editing.** Acquire `exclusive` for writes and `shared` for
   reads, with selectors naming the narrowest path that covers your edit —
   `exact` for a single file, `subtree` only when the change genuinely spans a
   package. Hold the returned lease ID and fences.
4. **Renew long work** with the lease ID and the *current* fences. Stale fences
   are rejected; that is the fencing token doing its job, not a bug.
5. **Release when done** rather than letting a lease expire — an expiring lease
   blocks other agents for its whole TTL.
6. **One conversation per work item.** Open a conversation, then send and reply
   within it. Acknowledge required handoffs explicitly, and never mark or
   acknowledge on another agent's behalf: read and acknowledgement facts belong
   to the recipient.

On a lease conflict, do not retry blindly and do not widen your selector.
Another agent holds an overlapping lease — coordinate through a conversation, or
narrow your scope to a disjoint path.

Because this repo builds the tool it runs on, coordination failures are product
bugs. When the protocol misbehaves, capture it as a bug against Blackbird rather
than working around it silently.

## The flywheel

Repository-local Claude Code configuration. Each layer exists to remove work
from the next session rather than only from this one.

**Specialists** — `.claude/agents/`. Delegate rather than re-deriving:

- `boundary-auditor` — hexagonal import boundaries, with the inversion that
  fixes each violation.
- `coverage-guard` — which uncovered statements threaten the coverage floor.
- `contract-reviewer` — MCP and HTTP surface changes and their effect on the
  plugin packages.

**Commands** — `.claude/commands/`:

- `/gate` — run `make check` and interpret the result against CI's real floors.
- `/claim` — register with Blackbird and reserve paths before editing.
- `/handoff` — release leases and leave a durable handoff message.
- `/flywheel` — convert this session's hard-won knowledge into a durable rule.

**Automatic checks** are optional and deliberately *not* committed.
`.claude/hooks/` and `.claude/settings.local.json` are gitignored: edit gates
shell out to whatever Go and Node happen to be on a given developer's PATH, so
they are personal tooling rather than part of the project's contract. Nothing
here depends on them, and `make check` remains the only gate that speaks for the
project. If you want the same feedback loop, the shape worth having is a
non-blocking `PostToolUse` gate that formats, checks the edited file's imports
against the layer rules above, and compiles the package — reporting findings as
context so a half-finished refactor is not treated as an error.

`/flywheel` is the part that compounds. When something costs you more than one
attempt to figure out, that is the signal to run it: the fix belongs in this
file, an agent, or a command — somewhere the next session will read it, not only
in the current transcript. Prefer this file and `.claude/agents/` over a hook,
since those are what teammates actually get on clone. And write it the way this
file is written: state the invariant, give the command that derives the value,
and resist quoting a number that will be false next month.
