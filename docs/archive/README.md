# Archive

**Nothing in this directory describes the running system.** Every tree here is a
design document for something that was not built, retained only because it
explains why the shipping code looks the way it does. If you are trying to learn
how Blackbird works, close this directory: `README.md` is the human-facing
document, `CLAUDE.md` is the agent-facing one, and the code is authority over
both.

Read anything here as provenance, never as a specification of behavior. A file
here may describe a table, a worker, a wire name, or an operation that has no
counterpart in the tree. Do not implement from these documents, do not cite them
in a review, and do not treat their `MUST` language as binding — it never was.

## `effect-sidecar/`

A 29-file specification for an independent coordination plane written in
TypeScript and Effect v4, using Blackbird's architecture as reference material.
It was authored as a single commit and never left the proposed stage; no code was
ever written against it. Its own charter authorized only disposable
investigation pending an acceptance manifest that was never produced.

Concretely, its outbox, projector, event journal, subscription workers, and
projection-rebuild machinery **do not exist in this repository** and never have.
`09-events-outbox-projections.md` and the "outbox/projector job fibers" in
`14-operations-observability.md` are the clearest examples: they read as
operational runbooks for a daemon that was never built.

Derive when it was written rather than trusting a date here:

```sh
git log --diff-filter=A --format='%h %ad %s' --date=short -- docs/archive/effect-sidecar/
```

### Why it is kept

It is the only written account of the accepted architecture corpus that shaped
the Go domain — the multi-principal, multi-device, multi-tenant model in
`internal/domain` that the shipping single-user daemon does not exercise. When
you find a domain type whose generality the product does not appear to need, the
charter and domain-model pages explain the shape it was cut to fit.

That provenance is the whole of its value. `00-charter.md`, `02-context-authority.md`,
and `03-domain-model.md` are the pages worth reading for it; the rest is
implementation detail for a system that does not exist.

Its `references.md` cites paths in the live tree. Those citations were accurate
when written and are not maintained — verify each against the current tree
before relying on one.
