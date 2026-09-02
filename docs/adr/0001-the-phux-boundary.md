---
audience: contributors, agents
stability: stable
last-reviewed: 2026-09-02
---

# 0001 — The phux boundary: consensus and lineage are different authorities

**TL;DR.** Blackbird is authority over what agents *agree*; phux is authority
over what phux *executes*. Neither daemon connects to the other. The seam is
one additive field in phux's existing `phux.agent/v1` metadata record, written
by the harness adapters both projects already ship, and it exists only so the
two ledgers can be joined after the fact. Blackbird is not a phux workload
client, and the observation plane — token spend, latency, throughput — lands
in Blackbird because phux has twice decided it does not want it.

Status: Accepted
Date: 2026-09-02

## Context

The two systems grew toward each other from opposite ends and briefly claimed
the same middle.

phux owns the live execution substrate: one per-user server owning processes
and PTYs while clients attach separately (phux ADR-0003), a wire-primary
`TerminalId` (phux ADR-0016), and a terminal owner that arbitrates input and
signals (phux ADR-0033). phux ADR-0092 (*Proposed*) extends that downward into
durability, giving a phux **work coordinator** sole-writer authority over
Objectives, Runs, WorkSessions, Artifacts, Signals, bindings, and evidence.

Blackbird moved the other way. It carries a sealed W0/W1 plane with its own
actors, objectives, work units, and runs. That plane was never reachable — two
composition gates in the runtime meant no request could mint the identity its
own handlers required — and production MCP no longer publishes it while its
deletion proceeds. The part that was always live and used is agent identity per
project, durable mail and conversations, and advisory path claims with leases.

So the collision resolved itself before it was adjudicated, and the boundary
that is left is sharper than the one that was proposed here first. The earlier
framing — *phux is the runtime, Blackbird is the record* — does not survive
contact with phux ADR-0092, which puts durable records squarely inside phux.
It is the wrong axis. Runtime and record are both present on both sides.

The axis that actually separates them is **where a fact comes from**:

- A phux coordinator fact is *derived from execution phux owns*. It carries
  source authority, incarnation, sequence, and explicit gaps, and phux can
  attest to it because phux ran the process that produced it.
- A Blackbird fact is *asserted by a peer that nothing executes*. A lease, a
  message, an acknowledgement, an agent's registration under a project key —
  none of these require a PTY, a phux server, or even a terminal. They are
  agreements between agents that may be running in an IDE, in CI, headless on
  another host, or under a harness phux has never seen.

Those are different authorities over different kinds of truth, and neither can
substitute for the other. phux cannot arbitrate a lease between an agent it is
running and one it is not. Blackbird cannot attest that a process exited.

There is also a concrete defect to clear. Four open phux issues — `phux-pjc5`
(P0) with its six stages, and `phux-ktzk` — are justified by a document that
does not exist:

> "Implement the `phux-workload/v1` service pairing required by **Blackbird
> ADR-0005**." — `phux-pjc5`
>
> "Expose the additive machine contract required by **Blackbird ADR-0005**:
> `phux agent probe --json` returns …" — `phux-ktzk`

`blackbird:docs/architecture/adr/0005-phux-runtime-binding.md` was never
written. It appears exactly once in this repository, in the reference list of
the **archived** effect-sidecar design (`docs/archive/effect-sidecar/`), where
Blackbird was to be a sidecar dialing a runtime provider and provisioning that
provider's key registry at `RuntimeEndpointRegistration`. That architecture is
gone. Its requirements outlived it in another repository's backlog, and phux
has been holding a P0 open against them.

## Decision

**Blackbird and phux do not connect.** Blackbird is not a phux workload client,
holds no phux workload key, provisions no phux key registry, and does not read
`phux agent probe`. phux is not a Blackbird MCP client and writes nothing to
Blackbird. Neither daemon's availability affects the other's; neither's
handshake admits the other.

This retires the phantom requirement. `phux-pjc5` and `phux-ktzk` may still be
worth building — handing an agent a rented box without handing it your machine
is a real product need, and it is the justification that should carry them —
but Blackbird is not the requester and must not be cited as one.

**Neither side mints the other's identities.** Blackbird does not reintroduce
Objective, Run, or WorkSession identity; that plane was deleted here and, if it
returns anywhere, it returns in phux under ADR-0092. phux does not mint agent
coordination identity, path reservations, leases, or fencing tokens. A concept
that appears in both ledgers is a defect in one of them.

**The seam is metadata, not a connection.** phux ADR-0040 makes
`phux.agent/v1` a normative, `TerminalId`-scoped L3 record that *anything able
to reach the socket* may write, and phux ADR-0067 already has the Pi and
OpenCode integrations refreshing agent projections each turn. Where an agent is
both registered with Blackbird and running in a phux terminal, the harness
adapter writes the Blackbird correlation into that record — the agent id and
the project key it registered under, nothing more. It is additive to an
accepted phux record, needs no new phux wire, no capability bit, no version
bump, and no authority change on either side. Absent either system the field is
simply missing, and every consumer already treats the record's fields as
optional.

That single field is what makes the interesting join possible after the fact —
this Blackbird lease conflict happened in that phux terminal, which cost these
tokens — without either system depending on the other to function.

**The observation plane lands in Blackbird.** phux has ruled it out twice on
paper: ADR-0009's positioning table puts "compaction / cost dashboards" outside
phux, and ADR-0092 restates it while widening phux's scope in every other
direction. phux ADR-0082 supplies the design constraint rather than an
objection — it retired a working CI metrics store because "the store's own cost
model beat it," a per-run collector paid continuously for a question asked
occasionally, and it named the exit: a dashboard belongs to a consumer "fed by
a source phux does not have to run." Blackbird is that source. It already has
the durable store, the migration ladder, backup and restore, per-project
identity, the systemd deployment, and adapters in the same three harnesses that
see the token counts.

It lands as a **separate module, separate tables, and separate retention**
inside this repository and this process, under one hard rule: *the observation
plane may never make a coordination write fail.* Coordination is the product;
telemetry is a projection against it. A full disk, a schema drift, or a
malformed harness record degrades observation and must not touch a lease.

## Authority

| Fact | Authority |
|---|---|
| Agent identity and registration under a project key | Blackbird |
| Durable mail, conversations, delivery, read and acknowledgement | Blackbird |
| Advisory path claims, lease holders, TTLs, and internal claim generations | Blackbird |
| Agent-reported observations: token spend, latency, model attribution | Blackbird |
| Process, process group, PTY, exit, and authoritative geometry | phux terminal owner |
| Terminal output order and engine/bootstrap generation | phux terminal owner |
| Input lease, signal delivery, acknowledged input result | phux terminal owner |
| Objective, Run, WorkSession, Artifact, and Signal lineage | phux coordinator (ADR-0092) |
| Agent name, kind, lifecycle state, attention for a live terminal | `phux.agent/v1` record |
| Correlation between the two ledgers | The harness adapter that wrote it |

Blackbird records a phux fact only as an untrusted observation with its source
named, exactly as `internal/integration` already models a work reference: an
observation, never Blackbird authority. It cannot rewrite one, and it never
blocks on one.

## Consequences

- The cross-repo dependency is deleted rather than satisfied, which is the
  cheapest possible resolution and the only one that does not add an
  authentication surface to a boundary that carries no traffic.
- Both systems stay independently useful. Blackbird coordinates agents in
  harnesses with no terminal at all; phux multiplexes terminals for people who
  have never heard of Blackbird.
- The join is best-effort and lossy by construction. An agent that never ran in
  a phux terminal has no correlation, and a stale record can outlive its writer
  — phux ADR-0040 accepts that tradeoff already. Analysis must tolerate an
  absent join key rather than assume one.
- Two durable stores exist once ADR-0092 ships. That is accepted because they
  hold disjoint facts; the non-duplication rule above is what keeps it from
  becoming two answers to one question, and it is enforced by review, not by a
  test.
- Writing decisions down here is new. This is Blackbird ADR-0001; the numbering
  starts at one and the external citation of "Blackbird ADR-0005" resolves to
  nothing on purpose.

## Alternatives considered

**Keep the runtime-vs-record framing.** Rejected: phux ADR-0092 makes phux a
record keeper too, so the axis does not separate the systems. Adopting it would
have required either arguing phux out of a decision already merged in its own
repository, or quietly meaning something narrower than the words say.

**Write Blackbird ADR-0005 to satisfy the citation.** Rejected: it would
require backfilling four decision records that were never made in order to
reach a number, and then ratifying a sidecar architecture this repository has
archived. A citation to a document that should not exist is fixed by deleting
the requirement, not by writing the document.

**Make Blackbird a phux workload client.** Rejected: it buys nothing either
system needs. Blackbird would gain the ability to read terminal state it does
not act on, at the cost of a key registry, a challenge protocol, a revocation
path, and a startup dependency on a daemon that most Blackbird deployments do
not run.

**Put the observation plane in phux.** Rejected on phux's own authority
(ADR-0009, ADR-0092) and on data grounds: phux sees terminal I/O, not harness
ledgers. Token counts come from the provider accounting each harness keeps, and
the join worth having — spend against coordination causality — needs the
coordination side, which phux does not have.

**Put the observation plane in a third service.** Rejected: it would need its
own identity, storage, migration, backup, deployment, and adapters, all of
which exist here, to hold facts whose only interesting queries join against
data that also lives here.
