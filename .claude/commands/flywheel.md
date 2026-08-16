---
description: Turn what this session learned into durable repo rules so the next session starts smarter
allowed-tools: Bash, Read, Grep, Glob, Edit, Write
---

This is the step that makes the loop compound. Everything else in this repo's
setup makes one session efficient; this makes the *next* one start ahead.

Review the session so far and find knowledge that would otherwise be lost.

## What qualifies

Capture something only if it is durable, non-obvious, and would have saved time
if known at the start:

- an invariant the code enforces but does not explain
- a gate or CI behaviour that surprised you (especially a local-vs-CI mismatch)
- a protocol detail whose naming or semantics mislead
- a failure mode that cost more than one attempt to diagnose

Do **not** capture: what the code plainly says, what git history already
records, one-off task state, or anything already written in `CLAUDE.md`.

## Where it goes

| Kind of knowledge | Destination |
| --- | --- |
| A rule every session must follow | `CLAUDE.md` |
| A repeatable review with its own method | a new agent in `.claude/agents/` |
| A repeatable multi-step action | a new command in `.claude/commands/` |

Prefer editing an existing file over adding a new one. Two overlapping rules are
worse than one precise rule.

Edit gates are **not** a destination: `.claude/hooks/` is gitignored personal
tooling, so anything written there is invisible to everyone else and vanishes on
a fresh clone. If a check must run for the whole project, it belongs in
`make check`.

## Rules for writing it

This codebase moves fast, so the failure mode is not "we never wrote it down" —
it is documentation that was true once and is now confidently wrong. Write
against that:

- **State the invariant, not the reading.** "The floor is enforced in two places
  and they must stay identical" survives; "the floor is N%" is false the day
  someone raises it, and worse than silence because it will be believed.
- **Where a value matters, write the command that derives it.** A one-line
  `grep` or `go tool cover` invocation next to the rule is what makes it
  self-maintaining. Run the command before you commit it — a derivation command
  that returns the wrong thing is its own kind of stale.
- **Prefer directories and package paths over file names**, and prefer "the
  architecture test" over its current filename. Source files move; the layer
  they live in rarely does.
- **State the fact and its consequence.** "Coverage sits at the floor, so any
  uncovered addition fails CI" beats "watch coverage".
- **If you must pin a number, pin it once** and make every other mention point
  at that place. When you change a gate threshold, change it in every file that
  enforces it and grep for stale copies of the old value before you finish:
  `grep -rn '<old value>' CLAUDE.md .claude/ Makefile .github/`

Before finishing, re-read what you wrote and ask of every sentence: will this be
true in three months, and if not, have I written the command that will be?

Report exactly what you added or changed and why it will pay off. If the session
produced nothing durable, say that rather than inventing a rule.
