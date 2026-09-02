---
audience: contributors, agents
stability: stable
last-reviewed: 2026-09-02
---

# Architecture Decision Records

**TL;DR.** Index of every decision that has closed off a design space in
Blackbird. Read these when you need to know *why* something is the way it is;
`CLAUDE.md` and `README.md` describe *what* the code is and how to run it.

Format follows [Michael Nygard's template][nygard]: context, decision,
consequences, and the alternatives that were rejected. An ADR records a choice
between viable approaches, and it is most useful when it says what was decided
*against* — the rejected alternative is the part a future reader cannot
reconstruct from the code.

[nygard]: https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions

## Index

<!--
Every ADR has exactly one row here, inserted at its numeric position when the
ADR is written. The row is deliberately a collision point: two branches
claiming the same number produce a textual conflict on this table, where the
two files alone would merge silently.
-->

| # | Decision | Status |
|---|----------|--------|
| [0001](./0001-the-phux-boundary.md) | The phux boundary: consensus and lineage are different authorities | Accepted (the two daemons do not connect; the seam is one additive field in phux's `phux.agent/v1` record, and the observation plane lands here because phux ADR-0009 and ADR-0092 put it outside phux) |

## When to write one

- Picking between viable approaches with long-term consequences.
- Closing off a design space — especially deciding *against* something.
- A boundary with another system, where the decision has to be legible from
  the other side.

## When not to

- Bug fixes, refactors, and anything a reader recovers from `git log`.
- Invariants that are already enforced executably. The architecture test in
  `internal/architecturetest/` is the record of the layering rules, and a
  prose copy of it would only go stale beside a check that cannot.

## Numbering

Sequential from 0001, never reused, never renumbered. A superseded ADR keeps
its number and its file, and its `Status:` line names the ADR that replaced it;
the history of a reversed decision is the point of keeping it.

An ADR number cited from outside this repository is a promise. If an external
consumer references a Blackbird ADR that does not appear in this table, the
reference is stale — resolve it here rather than writing a document to make the
number exist.
