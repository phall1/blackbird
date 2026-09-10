---
audience: contributors, agents
stability: draft
last-reviewed: 2026-09-09
---

# 0002 — An optional provider route preserves separate authorities

Status: **Proposed**

Date: 2026-09-09

Related: [provider product/technical proposal](../../specs/blackbird-41d/PRODUCT.md)

## Context

Cockpit and phux-mobile need the same durable correspondence independently of any terminal. phux is the connection and resource substrate for those clients. ADR-0001 deliberately prohibited daemon connections while preventing a collision between execution and coordination authority. The new experience needs an explicit exception to that connection rule, without reviving either daemon's abandoned claim to own the other's facts.

## Proposed decision

Allow phux to expose an **optional, independently negotiated Blackbird provider route** through a fixed authenticated local adapter. phux owns device admission, connection/routing mechanics, bounds, and correlation. Blackbird owns project grants, participant identity, immutable mail, receipts, and client-send idempotency. Either daemon starts and remains independently useful when the other is absent.

The route is not a terminal frame, an arbitrary HTTP proxy, a workload admission path, or a task coordinator. Blackbird never obtains phux terminal-control authority from this integration. phux does not persist/retry correspondence or infer that a message completes work. Host adapters retain model-admission semantics. Namespaced resource references join facts explicitly without a universal Agent schema.

If accepted with a matching phux decision, this supersedes only ADR-0001's categorical “neither daemon connects” and metadata-only seam clauses. Its authority separation, independent availability, Go daemon, optional harness correlation, and observation-plane ownership remain. The proposed phux ADR-0092 work coordinator must be reconciled separately; this decision does not assign its Objects/Runs/acceptance domain to Blackbird.

## Alternatives considered

- **Direct Blackbird remote API in each client:** simpler locally, but independently repeats phux endpoint reachability and connection setup and does not exercise the intended highway. Keep it a future deployment option through the same mailbox contract if required.
- **Generic port/HTTP forwarding:** a much larger authorization surface with no mailbox operation boundary. The first provider needs fixed operations and explicit project grants, not client-selected destinations.
- **Mailbox as terminal metadata or AgentSession child:** ties durable correspondence to a live resource and collides with the terminal protocol's responsibilities.
- **Move Blackbird into phux/Rust:** language unification does not settle authority, authorization, or unknown outcomes; it creates migration work before demonstrating the product.

## Consequences

New service/authentication and operator-write contracts are required. Existing loopback admin APIs cannot be exposed as-is. Both native clients must consume the same semantics, and phux's matching ADR plus Cockpit authority guidance must be reviewed before implementation. QUIC, provider federation, background push, Executor, and a generalized extension SDK follow evidence from the initial direct-host slice.

This record is proposed. ADR-0001 remains accepted until the user ratifies the amendment.
