# Effect Sidecar engineering specification

> **ARCHIVED — this is not a description of the running system.** This tree specifies
> a TypeScript/Effect sidecar that was never implemented; its outbox, projector, and
> event-journal machinery do not exist in this repository. It is retained only to explain
> the shape of the Go domain model. See [the archive README](../README.md).

> **Authority:** Proposed specification index and navigation guide  
> **Status:** Proposed experimental sidecar design; not a Blackbird replacement  
> **Implementation authorization:** Disposable E0 investigations only; no product implementation until the acceptance manifest is approved  
> **Normative language:** `MUST`, `MUST NOT`, `SHOULD`, and `MAY` express proposed requirements throughout this tree except explicitly descriptive citation/status text. They become implementation-authorizing only when the exact specification revision is promoted to **Accepted**.

## Non-replacement declaration

**Effect Sidecar** is a placeholder name for an independent coordination system implemented with TypeScript and Effect v4. It uses Blackbird's accepted architecture and selected implementation behavior as engineering reference material. It is not a port, successor, compatibility mode, or second Blackbird authority.

The sidecar MUST have its own:

- product and wire namespace (`sidecar.*`, never `blackbird.*`);
- database, migrations, credentials, ports, state directories, release artifacts, and evidence;
- workspace and authority identities;
- contracts and version lifecycle.

It MUST NOT open a Blackbird database, import Go internals, live-dual-write Blackbird state, claim Blackbird verification, or become writable authority for an existing Blackbird workspace. A future importer, if approved, is offline, deterministic, non-destructive, export-based, and excludes credentials, sessions, active leases, and runtime authority.

## Status legend

| Label | Meaning |
|---|---|
| **Implemented reference** | Behavior found in current `blackbird/` code. It is useful evidence, not automatically Verified or complete. |
| **Accepted target** | Language-neutral behavior accepted in Blackbird ADRs/catalog but not necessarily implemented. |
| **Experimental sidecar decision** | A proposed requirement for this independent system. It has no Blackbird authority or inherited verification. |
| **Open owner decision** | Product or release choice that implementation agents may not silently make. |

Every subsystem table uses these labels. When sources disagree, follow [reference and maturity](01-reference-and-maturity.md), not README marketing claims.

## Reading paths

### Implementer

1. [Charter](00-charter.md)
2. [Reference and maturity](01-reference-and-maturity.md)
3. [Context and authority](02-context-authority.md)
4. [Domain model](03-domain-model.md) and [state machines](04-state-machines.md)
5. [Contracts](06-contracts.md), [operation registry](06-operation-registry.md), [data model](07-data-model.md), and [unit of work](08-consistency-uow.md)
6. [Effect v4 overlay](effect-v4/README.md)
7. [Verification](15-verification.md)

### Architecture reviewer

Read [context and authority](02-context-authority.md), [domain model](03-domain-model.md), [consistency](08-consistency-uow.md), [failure/recovery](13-failure-recovery.md), then [Effect package architecture](effect-v4/02-package-architecture.md).

### Operator / SRE

Read [failure/recovery](13-failure-recovery.md), [operations and observability](14-operations-observability.md), [Effect runtime and packaging](effect-v4/01-runtime-packaging.md), and [storage](effect-v4/05-storage.md).

### Security reviewer

Read [authority](02-context-authority.md), [contracts](06-contracts.md), [security/privacy](10-security-privacy.md), [failure/recovery](13-failure-recovery.md), then the Effect runtime/storage overlay.

### Migration or conformance agent

Read [reference and maturity](01-reference-and-maturity.md), [use cases](05-use-cases.md), [contracts](06-contracts.md), [verification](15-verification.md), and [roadmap/conformance](effect-v4/08-roadmap-conformance.md). Never infer parity from shared names.

## Document map

### Language-neutral system specification

| Page | Purpose |
|---|---|
| [00 — Charter](00-charter.md) | Purpose, scope, principles, non-goals, success definition |
| [01 — Reference and maturity](01-reference-and-maturity.md) | Source precedence and implemented/target/sidecar separation |
| [02 — Context and authority](02-context-authority.md) | System boundaries, trust zones, owners of facts |
| [03 — Domain model](03-domain-model.md) | Identities, aggregates, values, invariants, logical ER map |
| [04 — State machines](04-state-machines.md) | Legal lifecycle transitions and forbidden implications |
| [05 — Use cases](05-use-cases.md) | Complete actor/use-case inventory and acceptance outcomes |
| [06 — Contracts](06-contracts.md) | Commands, queries, envelopes, errors, schemas, compatibility |
| [06A — Operation registry](06-operation-registry.md) | Versioned operation entries, commit sets, facts, effects and exposure |
| [07 — Data model](07-data-model.md) | Logical records, constraints, engine mapping and coverage |
| [08 — Consistency and UoW](08-consistency-uow.md) | Transaction algorithm, receipts, versions, authority time |
| [09 — Events/outbox/projections](09-events-outbox-projections.md) | Journal, workers, subscriptions, search, rebuild |
| [10 — Security/privacy](10-security-privacy.md) | Pairing, grants, secrets, privacy and threats |
| [11 — Integrations](11-integrations.md) | Phux, trackers, notifications, object stores, clients |
| [12 — Sequence diagrams](12-sequence-diagrams.md) | End-to-end normal and adverse flows |
| [13 — Failure/recovery](13-failure-recovery.md) | Failure taxonomy, backup, restore, failover, reconciliation |
| [14 — Operations/observability](14-operations-observability.md) | Deployment, health, telemetry, runbooks and budgets |
| [15 — Verification](15-verification.md) | Test matrix, evidence, conformance and promotion gates |
| [References](references.md) | Authoritative source map and implementation seams |

### Effect v4 implementation overlay

| Page | Purpose |
|---|---|
| [Overlay index](effect-v4/README.md) | Mapping from neutral rules to Effect implementation |
| [Runtime and packaging](effect-v4/01-runtime-packaging.md) | Node baseline, Bun challenger, artifacts and supply chain |
| [Package architecture](effect-v4/02-package-architecture.md) | Workspace layout and dependency enforcement |
| [Services, Layers and runtime](effect-v4/03-services-layers-runtime.md) | Effect service graph, scopes, fibers, shutdown |
| [Schema and codecs](effect-v4/04-schema-codecs.md) | Effect Schema, JCS, branded IDs and generated contracts |
| [Storage](effect-v4/05-storage.md) | SQLite worker, PostgreSQL, migrations, UoW mapping |
| [Transports and integrations](effect-v4/06-transports-integrations.md) | HTTP, MCP, CLI, streams and provider adapters |
| [Testing and performance](effect-v4/07-testing-performance.md) | Effect test strategy, fault injection and budgets |
| [Roadmap and conformance](effect-v4/08-roadmap-conformance.md) | Proof slices, backlog stages, optional import |
| [Decisions and risks](effect-v4/09-decisions-risks.md) | Decision ledger, open owner choices, triggers |

## Implementer start checklist

Before writing product code, an implementation agent MUST first point to an approved acceptance manifest naming this exact revision, approver, resolved owner decisions, dependency pins and authorized stage. Until then, only disposable E0 probes that cannot become product authority are permitted. After acceptance, it MUST demonstrate:

- [ ] the sidecar name, namespace, workspace identity, ports, paths, and credentials are independent;
- [ ] current Effect/TypeScript/Node versions are explicitly pinned after re-evaluating the time-stamped baseline;
- [ ] the package import-boundary test fails on a deliberate forbidden import;
- [ ] UUIDv7, bounded integer, canonical timestamp, JCS, and hash vectors pass cross-language fixtures;
- [ ] one command atomically writes state, receipt, event, audit, and outbox or none;
- [ ] exact replay, changed-input key reuse, stale version, cancellation, and indeterminate commit are tested;
- [ ] the same semantic corpus passes SQLite and PostgreSQL;
- [ ] SQLite does not block the main Node event loop;
- [ ] no wake stream is treated as durable history;
- [ ] no external effect occurs inside a command transaction;
- [ ] clean-machine packaging, crash recovery, backup, and restore have retained evidence.

## Related sources

The standalone repository implementation is linked from [references](references.md). The accepted architecture corpus used during authorship lives in the original design repository and is cited there as external, revision-sensitive reference material; it is deliberately not copied into this independent repository.
