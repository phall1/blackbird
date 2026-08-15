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
| A check that should run automatically on edit | `.claude/hooks/` + `.claude/settings.json` |

Prefer editing an existing file over adding a new one. Two overlapping rules are
worse than one precise rule.

## Rules for writing it

- State the fact and its consequence. "Coverage is at the CI floor, so any
  uncovered addition fails CI" beats "watch coverage".
- Put numbers, paths, and command names in. Vague guidance does not survive.
- If you add a hook, pipe-test it before writing it into settings, and prove it
  fires.
- If you change a gate number, change it in every place it appears
  (`Makefile`, `.github/workflows/ci.yml`, `CLAUDE.md`).

Report exactly what you added or changed and why it will pay off. If the session
produced nothing durable, say that rather than inventing a rule.
