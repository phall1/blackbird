# Verification and evidence program

> **Authority:** Experimental sidecar promotion gate  
> **Related:** [External proof reference](references.md) · [Failure/recovery](13-failure-recovery.md) · [Effect tests](effect-v4/07-testing-performance.md)

## Evidence classes

- **Invariant:** zero-tolerance semantic rule; one counterexample blocks promotion.
- **Release target:** numeric gate under a fixed environment/workload.
- **Service objective:** rolling objective only after an operated hosted service exists.
- **Characterization experiment:** required measurement without invented pass threshold.

Reports must use these terms exactly.

## Test pyramid

1. scalar constructors and exhaustive domain examples;
2. model/property/state-machine tests with deterministic IDs and authority time;
3. application orchestration tests against recording/fake ports;
4. canonical codec, JCS and cross-language golden vectors;
5. repository/UoW contract suite against real SQLite and PostgreSQL 18;
6. migration tests from every released schema;
7. HTTP/MCP/CLI/worker-RPC contract tests;
8. outbox/projection/provider failure tests;
9. subprocess abrupt-death tests;
10. packaged clean-machine end-to-end proof and soak.

## Required semantic corpus

For every state-changing operation, fixtures cover:

- valid apply;
- exact command-ID replay;
- exact secondary-key replay with replacement command ID;
- both identities resolving differently (integrity halt);
- changed fingerprint reuse;
- stale/absent/version/reference/authority/authorization conflicts;
- cancellation before commit;
- crash at receipt/state/event/audit/outbox/pre-commit/post-commit/response boundaries;
- current disclosure revoked at replay;
- supported engine and transport combinations;
- payload/size/cardinality boundaries.

## State/property models

Models assert:

- no invalid lifecycle edge;
- versions never wrap/exceed canonical maximum;
- no duplicate semantic outcome from replay/retry;
- recipient/privacy visibility is closed under pagination/search;
- no overlapping exclusive lease grants;
- old epoch/fence is never accepted after rotation;
- delivery and attention dimensions remain independent;
- runtime identity includes endpoint+incarnation+opaque ID;
- provider-owned fields never change without observation;
- projection checkpoint+deltas converge to uninterrupted state.

## Database and crash evidence

### SQLite

Use a real subprocess and filesystem. Inject abrupt termination around all commit stages, response publication, outbox claims and backup. Exercise WAL, busy, disk full, checkpoint, backup cancellation/corruption, unsupported filesystem, worker restart and restore into fresh target.

### PostgreSQL

Use real PostgreSQL 18 (testcontainers/CI service), not a mock. Exercise lock ordering, CAS, deadlocks, serialization retries, pool/network loss, `SKIP LOCKED` claims, missed `NOTIFY`, migrations, backup/PITR rehearsal and stale-writer promotion with a fault-injectable witness.

## Contract verification

- Effect Schema valid/invalid/unknown-field corpus;
- JSON Schema/OpenAPI generated artifact drift check;
- curated MCP tool/resource equivalence;
- worker RPC version/limit/cancellation corpus;
- provider fixture capture plus real supported Phux/Beads compatibility;
- timestamp/UUID/integer/JCS/hash/signature vectors in an independent language;
- unknown event and unsupported known-version policy;
- no Effect/Node-specific persisted values.

## Integrated proof

Adapt the accepted external Blackbird proof slice identified in [references](references.md) into sidecar identities/namespaces. One causally connected run must cover bootstrap, sessions, WorkReference, run, runtime ambiguity/rebind, message/lost response, lease conflict/fence, offline decision, cursor recovery, artifacts/completion, provider transition, projection rebuild, backup/restore/new epoch.

The evidence manifest records:

- source revision, dirty-state declaration and dependency lock digest;
- Node/Effect/TypeScript/native-addon/DB versions;
- platform, hardware, filesystem and power mode;
- binary/archive/image checksums and SBOM;
- fixture/corpus digest and fault schedule;
- command/event/provider transcripts with secrets redacted;
- raw latency/resource samples and estimator;
- test command output and failures;
- residual risks and unsupported claims.

## Performance methodology

- minimum 10,000 steady observations per gated operation/payload stratum;
- minimum 100 independent startup executions;
- nearest-rank p50/p95/p99/max; never pooled across unlike strata;
- report errors, throughput, CPU/RSS/heap/GC/event-loop lag, worker queue, DB/WAL growth and descriptors;
- no target may be met by disabling durability, authorization, journal or outbox;
- cold start requires independently provisioned host/VM state, not renamed files or sleep;
- benchmark corpus includes representative long-lived workspace, not empty DB only.

## Security verification

- challenge purpose/expiry/one-use/replay;
- current revocation races and final CAS;
- wrong audience/channel/authority epoch;
- Bcc/search/count side channels;
- secret canaries through errors/logs/traces/metrics/crashes/bundles;
- malicious Host/Origin/query credential/symlink/path cases;
- import signature/tamper/rollback and forbidden authority records;
- dependency/SBOM/license/provenance/vulnerability review;
- fuzz decoders, canonical codecs, selectors and provider envelopes.

## Promotion gates

### Accepted implementation baseline

The owner/approver signs one manifest containing specification/ADR revisions, resolved kickoff decisions, dependency/runtime pins, authorized roadmap scope, operation-registry/schema/fixture/evidence digests and review disposition. No product implementation precedes it.

### Verified walking slice

The exact integrated proof passes three consecutive clean runs on each SQLite/PostgreSQL × Tier-1 platform cell, with zero retries hidden by the harness and all adversarial findings resolved. Raw evidence is retained for at least two release lines and 180 days, whichever is longer.

### Alpha

Installable local product works end to end in three clean installs per Tier-1 platform; operations/backup rehearsal and supported SDK paths pass. Import is gated only if adopted.

### Beta

Interfaces frozen; security, recovery and packaging each pass three clean runs; the versioned representative workload meets every applicable target; a continuous 24-hour soak has no correctness failure, unbounded resource trend or unexplained restart. One infrastructure-flake rerun is allowed only with retained diagnosis and no product-code change.

### RC

Exact immutable artifact set passes three-run verification, independent recovery rerun, reproducible build/signing/provenance and explicit publication approval.

Blackbird maturity/evidence is never inherited or modified by these gates.
