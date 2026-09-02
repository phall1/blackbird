# Failure, recovery and failover

> **Authority:** Experimental sidecar failure semantics  
> **Related:** [UoW](08-consistency-uow.md) · [Operations](14-operations-observability.md) · [Verification](15-verification.md)

## Outcome taxonomy

| Observation | Safe conclusion | Client/operator action |
|---|---|---|
| transaction rollback known | command not applied | correct/retry as typed |
| commit known, response delivered | applied or replay result authoritative | advance only with returned cursor |
| commit known, response lost | may appear timeout to client | retry exact command/key |
| commit outcome unknown | neither success nor rejection may be claimed | exact replay/receipt resolution |
| provider definitive rejection | effect not accepted as specified | record rejection; policy may retry/new intent |
| provider response lost after possible acceptance | possibly applied | reconcile; no blind non-idempotent replay |
| wake lost | no data conclusion | durable cursor sync |
| runtime watcher lost | health unknown/degraded | inventory/reconcile; do not end binding automatically |

## Failure matrix

| Failure | Required behavior |
|---|---|
| invalid schema/ID | reject before transaction; no write |
| authentication verifier dependency fails | dependency failure; no proof attempt consumed |
| proof cryptographically rejected | bounded security denial transaction; external unauthenticated after known audit commit |
| authorization/version/reference conflict | ordinary rollback; optional separate bounded denial audit |
| cancellation before commit | rollback, exact identity reusable |
| death before commit | WAL/transaction recovery reveals no partial command |
| death after commit before response | complete command visible; replay returns prior result |
| receipt/event/audit/outbox codec failure | complete rollback and integrity alert |
| SQLite busy | bounded wait; no event-loop block; typed retry/overload |
| disk full/I/O error | rollback or indeterminate according to driver evidence; readiness degraded |
| corruption/hash-chain mismatch | fail closed, preserve evidence, restore/repair procedure |
| PostgreSQL serialization/deadlock | bounded whole-command retry with same identities |
| pool/network loss during commit | indeterminate until receipt resolution |
| worker death with claimed job | claim expiry/epoch recovery; stable effect identity |
| provider outage | canonical command remains committed; job retry/park observable |
| poison effect | park/dead-letter; never discard or fake success |
| expired cursor | checkpoint + deltas |
| slow subscriber | bounded close with resumable cursor |
| process clock reversal/jump | database authority-time floor; clock-suspect policy |
| authority transfer/restore | witnessed fencing, fresh epoch before writes |
| stale client fence | FENCE_REJECTED before protected mutation |
| artifact hash/size mismatch | no readable final artifact; failed/abandoned state |
| projection gap | high-water does not advance; no generation swap |

## Authority failover

Single-writer safety is a domain invariant, not a deployment hope.

1. durably storage-fence the prior writer, or establish an equivalent fail-closed witness lease that every authoritative transaction must validate and that the predecessor can no longer renew; process termination or administrative demotion alone is insufficient;
2. compare-and-swap a distinct globally fresh `storage_writer_generation` in the AuthorityWitness;
3. restore/attach the authoritative DB at a verified recovery point in `recovery_pending` read-only admission;
4. validate schema, journal/audit chains, receipt integrity, artifacts, keys and predecessor lineage;
5. durably mint a successor `InstallationAdmissionEpoch` under the promotion transaction so bootstrap/installation administration cannot reuse predecessor admission;
6. for each workspace under an exclusive recovery transaction, durably mint a random successor `WorkspaceAuthorityEpoch`, record the new storage-writer generation, carry revocation state, and invalidate predecessor sessions, lease fences, presentation assertions and worker claims;
7. keep provider-effect admission closed: epoch-aware providers confirm successor epoch; idempotent providers reconcile stable effect IDs; non-idempotent unknown attempts remain `possibly_applied` and blocked;
8. enable only commands whose typed installation/workspace recovery admission and dependencies are satisfied; unreconciled authority-sensitive commands remain blocked;
9. reconcile runtime/provider/outbox state before claiming full readiness.

Domain commands MAY be admitted after workspace activation while a provider gate remains closed only when their effects stay visibly pending and the command does not depend on unreconciled provider truth. If predecessor/storage fencing cannot be authenticated, remain read-only. Epochs are never sorted; a larger-looking token is not newer.

## Backup contract

A successful backup includes:

- database engine/source identity and schema/migration checksums;
- authority and epoch at capture, with event/audit high-water;
- database checksum/snapshot metadata;
- artifact manifest root, object versions, sizes and hashes;
- encryption/signing key references and recovery requirements;
- pending outbox and projection registry metadata;
- build and contract versions.

Creating a file is not successful backup. A periodic restore drill must verify it.

### Local SQLite

Use the supported online backup API; never raw-copy a live WAL database. Pin referenced artifacts during capture. Command latency impact and checkpoint behavior are measured. Failed/cancelled partial output is retained or clearly quarantined, never published as valid.

### Hosted PostgreSQL

Physical/PITR and object-store recovery are operational mechanisms. Domain verification still checks receipts/events/authority epoch and provider ledgers. A promoted stale writer must be fenced before traffic.

## Restore modes

- **Verification-only:** no ordinary listeners, claims, effects or writes; validates a fresh target.
- **Read-only inspection:** authorized queries after validation; no authority mutation.
- **Writable promotion:** requires witness/predecessor evidence and fresh epoch.

No restore overwrites an active source. No binary/schema downgrade is promised.

## External reconciliation

### Runtime

Compare durable binding intent with authenticated endpoint inventory scoped by incarnation. Partial inventory cannot prove absence. A reused terminal ID under a new incarnation cannot alias the old target.

### Tracker

Read current provider object/version. ProviderOperations are confirmed only by causally correlated exact-target observation, rejected by definitive provider response, or remain pending while the associated OutboxAttempt may be `possibly_applied`.

### Notifications

Delivery retry may continue while occurrence is unresolved and generation current. Resolution cancels obsolete queued delivery but does not erase historical attempts/receipts.

### Object store

Verify committed references against versioned objects and hashes. Missing/corrupt object makes artifact unavailable/quarantined and readiness/restore fail according to policy; it is not silently removed.

## Recovery objectives

These are **targets**, not current evidence:

- committed-store-surviving process crash: zero acknowledged-command loss;
- local restart to readiness on representative workspace: p95 ≤ 2 seconds;
- cursor resume: p95 ≤ 1 second;
- healthy worker resumes ready outbox work within 10 seconds;
- reachable runtime reconciliation: p95 ≤ 2 seconds each and ≤ 10 seconds for active reference set;
- local online backup ≤ 60 seconds and restore validation ≤ 5 minutes with artifact corpus;
- hosted HA node/AZ model: RPO 0 for acknowledged commands only after synchronous/fencing proof;
- catastrophic authority/region target: RPO ≤ 5 minutes, RTO ≤ 30 minutes only after monthly restore evidence.

No document may call a target an SLO or guarantee before an operated service and retained measurements exist.
