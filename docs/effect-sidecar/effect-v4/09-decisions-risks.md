# Decision ledger, risks and reconsideration triggers

> **Authority:** Experimental decision record and owner-decision boundary  
> **Related:** [Charter](../00-charter.md) · [Runtime](01-runtime-packaging.md) · [Roadmap](08-roadmap-conformance.md)

## Proposed experimental decisions

The entries below are adopted into this Proposed design for review; they do not authorize product implementation. Acceptance requires the manifest described after the table.

| Decision | Rationale | Reconsider when |
|---|---|---|
| Independent sidecar, not replacement | preserves Blackbird authority/ADR and clean experimentation | owner explicitly proposes superseding product/ADR |
| Independent `sidecar.*` namespace/storage/credentials | prevents accidental dual authority and false compatibility | never for ordinary implementation convenience |
| Node 24 LTS exact patch baseline | diagnostics, MCP/native ecosystem, support window | Bun/other challenger passes complete proof and simplifies operations |
| aligned exact Effect v4 package set | prerelease packages evolve together | stable v4 exists and passes explicit upgrade migration |
| SQLite in supervised worker | synchronous `node:sqlite`/busy waits must not block main event loop | measured async/native alternative passes durability/backup/package gates |
| PostgreSQL explicit async adapter | hosted concurrency and operations | product drops hosted target |
| pure synchronous domain decision | bounded transaction and deterministic retry | no trigger; core invariant |
| normalized state + journal/outbox | query/recovery clarity without maximal event sourcing | an evidence-backed ADR proves alternate model simpler/correct |
| no broker/cache/workflow authority | complete local product and fewer failure modes | measured scale/availability need behind outbox |
| offline export importer only | no shared DB/live dual-write/authority confusion | explicit future federation/import ADR |

## Acceptance manifest

The approving owner promotes an exact commit by recording: approver identity/date, specification and sidecar ADR digests, permanent name/namespace, authorized E stages, exact Node/TypeScript/package-manager/Effect/MCP/JCS/UUID pins, credential-vault and security posture, supported distribution/platform/engine matrix, repository/license/support posture, hosted/federation/import decisions, operation-registry digest, unresolved risks explicitly accepted, and release-budget authority. A partial or verbal selection does not promote maturity.

## Open owner decisions

Implementation agents MUST NOT silently choose:

1. permanent product/package/binary/service name;
2. whether any prerelease Effect v4 build may serve production users;
3. exact Node patch, package manager and aligned Effect/TypeScript versions at kickoff;
4. exact RFC 8785 and UUIDv7 libraries after security/compatibility review;
5. OS credential-vault adapters and recovery UX;
6. initial scope: E1 overlap only or commitment to complete E2–E5 catalog;
7. hosted/public-service and federation intent;
8. local distribution format (private runtime archive vs qualified SEA/Bun);
9. content-at-rest encryption/E2EE posture;
10. license, publication repository and support matrix;
11. whether optional Blackbird offline import should ever exist;
12. release approval and budget changes.

## Primary risks

| Risk | Impact | Mitigation/evidence |
|---|---|---|
| Effect v4 prerelease churn | cross-cutting source/runtime changes | exact aligned pins, isolation, upgrade ADR and full corpus |
| synchronous SQLite blocks worker/main | latency/timeouts/availability | dedicated worker, event-loop and queue gates, bounded busy |
| worker RPC complicates commit outcomes | false cancellation/retry | explicit versioned protocol and indeterminate receipt recovery |
| native packaging/signing | install failures/supply-chain surface | clean-machine matrix, SBOM, signatures, runtime bundle spike |
| TypeScript boundary erosion | framework/SQL leaks into domain | project refs/exports/lint/architecture tests |
| Effect expertise concentration | maintenance errors/Promise escapes | concise idiom guide, reviews, explicit ports, defect tests |
| current reference incomplete/overclaimed | parity blesses wrong behavior | maturity labels and operation mapping |
| SQLite/Postgres semantic drift | local/hosted different product | shared history/error/fault corpus and engine-specific review |
| JCS/numeric/timestamp mismatch | broken receipts/events/federation | independent vectors and canonical scalar module |
| unbounded fibers/queues/subscribers | memory/leak/lag | Scope/supervision/bounds/24h soak |
| provider unknown outcomes | duplicate external changes | stable identities, possibly-applied, reconciliation |
| stale authority after restore | split brain/stale fence acceptance | witness + fresh epoch + adversarial promotion tests |
| secrets in rich errors/telemetry | credential/content leak | redaction, canary scanner, bounded problem mapping |
| one-language ecosystem temptation | workflow/model streams become authority | DB/UoW invariant and no Effect Cluster/Workflow authority |

## Reconsideration triggers

### Choose Bun/default compiled runtime only if

- all semantics/providers/tests pass without compatibility patches;
- SQLite backup/crash/full-sync is at least as strong;
- signals/workers/subprocesses/telemetry/vault work natively;
- artifacts are materially simpler/smaller;
- Tier-1 soak/package matrices pass.

### Remove SQLite worker only if

A reviewed driver provides genuinely asynchronous/non-blocking behavior or measurements prove main-thread synchronous access meets event-loop/latency/failure gates under busy/backup/load without weakening correctness.

### Add broker/workflow engine only if

Durable DB outbox misses a representative throughput/isolation target and the added system remains downstream—not authority—for commands/events/work.

### Split services only if

A module needs independent trust, availability, scaling or release cadence and the distributed failure/operation cost is measured and accepted. Local mode must remain complete.

### Pause experiment if

- Effect RC upgrades repeatedly invalidate core persistence/transport behavior;
- local package cannot meet agreed reliability/resource budgets;
- cross-engine parity produces recurring uncontained semantic bugs;
- worker/runtime complexity exceeds Go reference advantages without one-language product value;
- owner no longer wants an independent product authority.

## Explicitly unresolved research

- actual Node 24 `node:sqlite` backup/full-fsync behavior under selected patch;
- best audited JCS implementation for exact I-JSON/JCS rules;
- native OS vault portability and code-signing footprint;
- SEA versus runtime archive native asset behavior;
- Effect v4 stable release migration from `rc.108`;
- MCP TypeScript SDK major/version alignment and transport composition;
- W1 event-loop/heap/worker measurements;
- hosted witness architecture and regional DR provider.

Record answers as ADRs with retained proof, not edits hidden in implementation commits.
