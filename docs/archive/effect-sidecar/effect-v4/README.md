# Effect v4 implementation overlay

> **ARCHIVED — this is not a description of the running system.** Nothing in this
> overlay was implemented. See [the archive README](../../README.md).

> **Authority:** Experimental implementation decision overlay  
> **Status:** Time-stamped reference baseline; re-evaluate before coding  
> **Parent:** [Language-neutral specification](../README.md)

This layer explains how to implement the neutral system with TypeScript and Effect v4 without allowing Effect, Node, SQL libraries or generated types to redefine domain semantics.

## Baseline

- Runtime: Node.js 24 LTS, exact patch pinned in release manifest.
- Effect ecosystem: one exactly aligned v4 release line. At authoring time the observed candidate was `4.0.0-rc.108`; npm `latest` still pointed to v3.
- TypeScript: exact version pinned; current exploratory reference is 6.0.3.
- Package manager/lock: npm workspaces with committed complete lockfile unless a sidecar ADR selects another deterministic manager.
- SQLite: `@effect/sql-sqlite-node`/`node:sqlite` isolated behind a supervised worker because synchronous operations and busy waits can block an event loop.
- PostgreSQL: asynchronous `@effect/sql-pg` adapter with engine-native SQL.
- MCP: official TypeScript SDK behind a narrow adapter; SDK/Zod types remain transport-local.
- Challenger: Bun compiled executable must pass a dedicated packaging/durability spike before consideration.

No prerelease package is approved for production merely because it is listed here.

## Mapping

| Neutral concern | Effect implementation |
|---|---|
| typed values/states | Effect Schema branded wire/row decoders plus plain immutable domain data |
| expected failures | tagged typed error channel |
| defects/invariant violations | defects; fail request/worker and alert, never coerce to domain rejection |
| dependency ports | Context services and Layers |
| resource lifetime | Scope/acquire-release |
| concurrency | scoped fibers, queues, semaphores and streams |
| retry policy | Effect Schedule computes policy; durable next time remains DB state |
| timeout/cancellation | Effect interruption around cancellable boundaries; commit finalization protected |
| telemetry | Effect OpenTelemetry and structured log adapters |
| testing time | TestClock for scheduling only; DB authority time supplied by storage fixture |
| command decision | plain synchronous function, explicitly not Effect |

## Overlay pages

1. [Runtime and packaging](01-runtime-packaging.md)
2. [Package architecture](02-package-architecture.md)
3. [Services, Layers and runtime](03-services-layers-runtime.md)
4. [Schema and codecs](04-schema-codecs.md)
5. [Storage](05-storage.md)
6. [Transports and integrations](06-transports-integrations.md)
7. [Testing and performance](07-testing-performance.md)
8. [Roadmap and conformance](08-roadmap-conformance.md)
9. [Decisions and risks](09-decisions-risks.md)

## Non-negotiable implementation rules

1. `domain` imports no Effect, SQL, HTTP, MCP, filesystem, Node or configuration package unless a future ADR explicitly chooses Effect data structures there; initial decision is plain TypeScript data/functions.
2. Layers are constructed once at the composition root, not dynamically per request.
3. No authority/session is hidden in mutable `FiberRef`; authenticated immutable context is an explicit argument.
4. No detached fibers. Every fork belongs to a Scope/supervisor.
5. Effect `Clock`, Queue, Stream, Schedule and Cluster/Workflow state are never durable authority.
6. Database rows and Effect encodings never cross into domain transitions.
7. The SQLite worker owns the connection and transaction; main-thread code cannot open the DB.
8. External I/O never occurs inside a command UoW.
9. `unknown` is decoded at every transport, DB, config, provider and worker boundary.
10. Public/persisted contracts remain ordinary versioned JSON and SQL, independent of Effect upgrades.
