# Effect testing, fault injection and performance

> **Authority:** Experimental implementation verification overlay  
> **Related:** [Neutral verification](../15-verification.md) · [Storage](05-storage.md)

## Effect-specific test layers

- deterministic `IdSource`;
- database-backed `AuthorityClock` fixture independent of `TestClock`;
- TestClock for retry/heartbeat/client scheduling;
- recording authentication/policy/signer/provider ports;
- real SQLite worker Layer with fault protocol enabled only in tests;
- real PostgreSQL 18 testcontainer Layer;
- in-memory telemetry exporter with secret canary scanner;
- scoped runtime harness asserting no leaked fibers/handles/workers.

## Domain and Schema tests

Use exhaustive transition tables plus fast-check/property tests for command histories and invariants. Schema corpora cover valid/invalid/excess/unknown/version/bounds. Differential JCS/hash vectors run against an independent implementation.

Do not test domain transitions by running Effect when a plain function test suffices.

## UoW/model tests

A recording UoW verifies declaration completeness and canonical guard order. A reference state model generates command histories; both engines must return equivalent semantic outcomes. Race authorization changes against final CAS.

## SQLite worker faults

Test controls can pause/kill at:

- before queue admission;
- after transaction begin/receipt insert/state write/event/audit/outbox;
- before/inside/after commit;
- before worker response;
- during busy wait, checkpoint and online backup.

Production exports/bundle MUST omit fault controls. Tests use actual subprocess/process termination where crash semantics matter, not a thrown exception.

## Node runtime tests

- event-loop lag under SQLite busy/large read/backup;
- worker queue byte/count bounds and fairness;
- worker death/restart/unknown in-flight outcomes;
- AbortSignal↔Effect interruption and commit masking;
- signal handling and ordered shutdown;
- unhandled rejection/defect behavior;
- heap/handle/fiber snapshots after repeated connect/disconnect;
- native addon/runtime mismatch and package relocation;
- 24-hour soak with steady writes/subscriptions/provider failures.

## Provider/adversarial tests

Duplicate/late/reordered/wrong-scope/wrong-incarnation observations; provider timeout before/after acceptance; kill the actual outbox executor after provider return but before outcome persistence; claim expiry while an old provider call still runs; non-idempotent unknown result; circuit breaker isolation; poison job park; notification recurrence/generation; tracker stale version; object hash/size/quota/cancellation.

## Provisional performance gates

| Surface | Local target |
|---|---:|
| ordinary durable write | p95 ≤ 60 ms; p99 ≤ 200 ms |
| ordinary query | p95 ≤ 40 ms; p99 ≤ 150 ms |
| context checkpoint | p95 ≤ 200 ms |
| cursor resume | p95 ≤ 750 ms |
| event-loop lag under representative workload | p99 ≤ 20 ms; max ≤ 100 ms |
| warm/cold readiness | p95 ≤ 500 ms / 1 s |
| outbox no-op recovery | ≥ 500 completions/s |
| idle RSS | p95 ≤ 125 MiB |
| representative RSS | p95 ≤ 300 MiB; max ≤ 450 MiB |
| local artifact hashing/ingestion | median ≥ 100 MiB/s; p5 ≥ 50 MiB/s |

Correctness gates have zero tolerance: acknowledged loss while committed authority survives, duplicate domain outcome, cross-workspace/recipient disclosure, overlapping exclusive grant, accepted stale fence, event-chain mismatch.

## Benchmark manifest

Every performance report references a versioned manifest defining operation registry entry, exact request/payload stratum, deterministic seeded-state digest, engine/runtime/platform/filesystem, durability/DB settings, concurrency/arrival pattern, warm/cold state, timing start/end boundaries, included success/replay/error dispositions, sample/run counts and raw-sample retention location. “Ordinary write/query,” readiness, cursor resume and outbox completion have no metric meaning outside this manifest.

Initial manifest bindings: ordinary durable write is `sidecar.message.send.v1` at 1 KiB body/one recipient against the representative seed; ordinary query is `sidecar.run.get.v1`; cursor resume is one `events.sync` page of 256 events; outbox completion spans committed claim through durable success for the no-network fixture. If these operations are unavailable at a stage, the gate is not yet applicable rather than silently substituted.

## Representative workload

Adopt the shape—not inherited evidence—of Blackbird W1:

- long-lived event/message/delivery/decision/lease/run histories;
- 32 actors, 64 subscribers;
- 20 writes/s steady with 100/s bursts;
- varied message fan-out/payload sizes;
- ready outbox backlog and active runtime bindings;
- broad/selective authorized search;
- 256 KiB median/1 MiB max context;
- external artifact corpus.

Create a versioned deterministic sidecar seed and digest. Tiny fixtures are profiling only.

## Measurement

Use native release artifact, pinned platform/runtime/DB settings and raw retained samples. Record event-loop lag, worker-RPC latency/queue, GC/heap/RSS, CPU, descriptors, handles/fibers, DB/WAL/index growth, throughput/errors and quantiles. Do not pool operation/payload strata.

## Review gates

Before milestone promotion run:

- TypeScript compile and lint/import architecture;
- unit/model/schema/property/fuzz corpus;
- SQLite/PostgreSQL conformance;
- transport/provider fixtures;
- abrupt subprocess tests;
- clean-package smoke;
- security secret scan;
- independent fresh-context architecture/correctness review;
- final diff/spec/contract artifact inspection.

A green Effect test with fake time/database is not storage/recovery evidence.
