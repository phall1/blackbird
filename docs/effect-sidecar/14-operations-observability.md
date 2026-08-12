# Operations and observability

> **Authority:** Experimental sidecar operational contract  
> **Related:** [Recovery](13-failure-recovery.md) · [Verification](15-verification.md) · [Runtime packaging](effect-v4/01-runtime-packaging.md)

## Deployment shapes

### Local

One supervised daemon artifact contains product/admin/MCP adapters, workers and a dedicated SQLite worker thread. It owns a private database and artifact directory. A per-user launchd/systemd unit starts it. No cloud, PostgreSQL, broker or system Node installation is required.

### Hosted

The same codebase runs explicit API and worker/projection roles against PostgreSQL 18 and object storage. Roles are deployment modes of a modular monolith, not independently authoritative microservices. Managed ingress owns public TLS/edge controls.

### Coexistence

Sidecar and Blackbird use distinct ports, service names, paths, credentials and client configuration entries. Install/update/uninstall touches only sidecar-owned files and retains user data unless an explicitly approved destructive command exists.

## Process lifecycle

Startup order:

1. parse typed config and secret references;
2. verify artifact/build/runtime/native-addon versions;
3. open secret store;
4. for SQLite, acquire/bootstrap the database worker process/thread and let it exclusively open the DB, verify engine/source/options/filesystem, migrate and recover; for PostgreSQL, acquire the scoped pool and perform the equivalent guarded steps;
5. read authority metadata and inspect recovery/integrity markers through the owning storage adapter;
6. register role/capability health;
7. start outbox/projector **job fibers** (not the already-running SQLite database worker), then listeners;
8. declare readiness only for supported role/capabilities.

Shutdown order:

1. gate ingress and stop accepting new commands/queries;
2. drain accepted request work and process-owned commit-outcome fibers boundedly;
3. stop new outbox claims and finish or durably classify active claims;
4. close subscriptions with resumable cursor and close listeners/provider producers;
5. stop projector/outbox job fibers;
6. flush bounded audit/log/telemetry exporters after all normal producers stop;
7. close pools, SQLite database worker and secret handles.

No detached fiber or handle may keep the process alive accidentally.

## Health model

| Endpoint/state | Meaning |
|---|---|
| liveness | event loop/process responsive; does not assert DB authority |
| startup | initialization still progressing or failed with safe stage |
| readiness-read | schema/integrity/query path usable |
| readiness-write | current authority/epoch, clock and command UoW usable |
| readiness-worker | claim/provider prerequisites usable for declared worker role |
| degraded | explicit dependency/projection/runtime impairment without false full readiness |

Health responses expose build/schema/capability and bounded safe reasons, never secrets/content.

## Four evidence streams

1. **Domain journal:** authoritative successful facts; not a log sink.
2. **Security audit:** hash-chained admissions, denials and administrative security actions.
3. **Structured logs:** operational facts/failures with build, component, operation, outcome, request/trace/correlation IDs.
4. **Metrics/traces:** bounded RED/USE metrics and OpenTelemetry spans across ingress, auth, command, transaction, outbox and providers.

## Required metrics

- command/query counts and latency by bounded operation/outcome;
- DB transaction, lock, busy, pool and serialization metrics;
- event-loop lag, worker RPC queue depth/latency and worker restarts;
- subscription connections, lag, resume and slow-consumer closes;
- outbox ready count, oldest age, attempts, claims, parked and possibly-applied;
- lease acquire/conflict/expiry and stale-fence rejection;
- runtime reconciliation state/age;
- attention generation and provider attempt age;
- artifact bytes/failures/quota;
- process CPU/RSS/heap/GC, active fibers/handles, descriptors;
- backup/restore/projection rebuild age and outcome.

Never label metrics by workspace, principal, actor, path, URL, idempotency key, message, artifact, lease or terminal.

## Tracing

Propagate trace/correlation/causation/idempotency identities as appropriate. Domain events retain correlation/causation, not sampling state. Spans must distinguish:

- validation/auth/policy preparation;
- receipt resolution;
- lock/authority-time/domain/CAS/journal/commit;
- commit outcome unknown;
- outbox claim/provider/reconciliation;
- cursor sync/projection rebuild;
- worker-thread queue and SQLite execution.

Content and credentials are forbidden span attributes.

## Diagnostic bundle

An authorized command produces a redacted immutable bundle with:

- build/runtime/platform/native module and migration manifests;
- configuration keys with values redacted/classified;
- health/readiness history;
- bounded recent structured logs;
- metric snapshots and profiles;
- DB integrity/schema/high-water summaries;
- outbox/projection counts without content;
- checksums and collection audit.

Canary-secret tests must pass against the bundle.

## Runbooks

Minimum operator runbooks:

- daemon will not become ready;
- SQLite busy/WAL growth/disk full/corruption;
- PostgreSQL unavailable/deadlock/serialization storm;
- event-loop blocked or SQLite worker unresponsive;
- outbox backlog/provider outage/possibly-applied operation;
- cursor expiry/subscriber backpressure;
- projection rebuild mismatch;
- backup failure and restore drill;
- authority epoch rotation/stale writer suspicion;
- runtime reconciliation backlog;
- credential compromise/revocation;
- upgrade/migration interruption and rollback-to-old-binary constraints.

## Initial sidecar resource targets

These are independent provisional gates:

| Resource | Target |
|---|---:|
| compressed local artifact | ≤ 100 MiB |
| idle RSS p95 | ≤ 125 MiB |
| representative workspace RSS | p95 ≤ 300 MiB; max ≤ 450 MiB |
| idle CPU | ≤ 1% one core over 10 min |
| event-loop lag | p99 ≤ 20 ms; max ≤ 100 ms under representative load |
| warm/cold readiness | p95 ≤ 500 ms / 1 s |
| per-subscription buffer | ≤ 1 MiB and ≤ 1,024 events |
| retained fiber/handle/heap trend | none over 24-hour soak |

See [testing/performance](effect-v4/07-testing-performance.md) for workload and measurement rules.
