---
description: Register this session with Blackbird and reserve the paths you are about to edit
argument-hint: "<paths or package you intend to change>"
allowed-tools: Bash, Read, Grep, Glob, mcp__blackbird__blackbird_agent_register, mcp__blackbird__blackbird_agents_list, mcp__blackbird__blackbird_reservation_acquire, mcp__blackbird__blackbird_reservations_status, mcp__blackbird__blackbird_wait, mcp__blackbird__blackbird_conversation_open
---

Claim work so parallel agents in this repository do not collide.

Target: $ARGUMENTS

## Steps

1. **Take your own worktree before you write anything.** Run
   `git worktree list`. If another agent is working in the checkout you are
   standing in, you share an index with them: staging is repository-wide, so
   their `git add` sweeps up whatever you are holding. No reservation prevents
   that — the daemon never sees a commit. Run
   `make worktree NAME=<what-you-are-doing>` and move there. Skip this only for
   read-only work.

2. **Register** with `blackbird_agent_register`:
   - `project_key`: the repository's **main worktree**, which is the first entry
     of `git worktree list` — never the worktree you are standing in. Every
     agent on this repository must key the same way or you each get a private
     project, see none of each other's leases, and every check below silently
     passes.
   - `agent_name`: a stable name for this session
   Keep the returned `registration_token` — it is the `agent_token` every other
   Blackbird tool expects. Export it as `BLACKBIRD_AGENT_NAME` too, so the
   pre-commit lease guard can tell your own claims from a teammate's.

3. **See who else is here** with `blackbird_agents_list`. If another agent is
   active, assume overlapping work is possible.

4. **Reserve the narrowest paths that cover the intended edit** with
   `blackbird_reservation_acquire`:
   - `mode`: `exclusive` when you will write, `shared` when you only read
   - `selectors`: `{kind: "exact"|"subtree", path}` — prefer `exact` for single
     files, `subtree` only when the change genuinely spans a package
   - `ttl_seconds`: long enough for the work, not the whole session
   Record the `lease_id` and `fences`; renewal and release both require them.

5. **On `LEASE_CONFLICT`**, do not retry blindly and do not widen your selector.
   The failure is structured and already tells you what to do next: read
   `blockers` for the agents holding the path, their `holder_agent_name` (the
   name `blackbird_message_send` takes), and `retry_after_ms` for the soonest
   expiry. `blackbird_reservations_status` asks the same question at any time.
   Then pick one:
   - **The hold is short** — `blackbird_wait` on the path. It returns `path_free`
     as soon as the lease is released, or `deadline` with the blockers still
     standing. It is bounded by a server-enforced ceiling the tool schema
     publishes, so it cannot park you indefinitely; a `deadline` means decide
     again, not retry automatically.
   - **The hold is long or unclear** — `blackbird_conversation_open` with the
     named holder and coordinate.
   - **Your scope was too wide** — narrow to a disjoint path and reserve that.

6. **Open a conversation for the work item** if this is more than a trivial
   edit, so the handoff has somewhere to land.

Report the worktree you are in, what you registered as, what you reserved, and
any conflict you hit. Then proceed with the actual work.
