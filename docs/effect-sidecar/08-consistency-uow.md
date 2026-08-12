# Consistency and unit of work

> **Authority:** Core experimental sidecar invariant  
> **Related:** [Data](07-data-model.md) · [Events/outbox](09-events-outbox-projections.md) · [Failures](13-failure-recovery.md)

## Consistency unit

Every state-changing command owns one bounded database transaction. Application code declares the complete command shape before transaction entry. Storage acquires locks and persists the declaration; domain logic receives only immutable locked state and database-derived authority time.

No HTTP/MCP handler opens a transaction. No domain transition performs Effect, Promise, SQL, time, randomness, logging, filesystem or network I/O.

## Declarative specification

A `CommandSpec` contains:

- tagged installation/workspace scope, requested typed authority/epoch, and admitted witnessed `storage_writer_generation`;
- operation major, command ID, receipt ID and secondary idempotency identity;
- canonical request fingerprint, which excludes request ID, transport deadline/retry/route, and requested authority ID/epoch while retaining semantic scope, actor attribution, expected versions and body;
- authenticated principal, actor-session/service, client, correlation and causation attribution;
- admission, current AuthorityWitness writer generation, policy, lifecycle, reference, version, absence and ceremony guards;
- declared states read and written;
- expected aggregate commit set and fact origin/version/ordinal set;
- preallocated resource/event identifiers;
- bounded audit and effect-intent plans;
- authority-time class and all size/cardinality limits;
- recovery-capsule plan or explicit not-applicable variant.

Undeclared reads, writes, facts, effects or guards are programmer errors and force rollback. Every authority-bearing transaction final-CAS-validates the live witness lease/generation and matching installation/workspace admission epoch. The check is part of commit correctness, not cached readiness; witness loss or mismatch rolls back/fails indeterminate rather than admitting a stale writer.

## Pure decision

```text
LockedSnapshot -> Apply | Replay | Reject
```

This function is synchronous data transformation. In the Effect implementation it MUST NOT return `Effect`, `Promise`, a repository callback, generator, stream or service environment.

- `Apply`: proposed state, facts, audit, receipt semantic result and bounded effect intents.
- `Replay`: prior result after current disclosure authorization; no write.
- `Reject`: typed domain/application rejection; ordinary transaction rolls back.

## Transaction algorithm

```mermaid
sequenceDiagram
  participant T as Transport
  participant A as Application
  participant U as UnitOfWork
  participant D as Domain transition
  participant DB as Database

  T->>A: decoded command + verified auth
  A->>A: proof/policy preparation, IDs, canonical fingerprint
  A->>U: immutable CommandSpec
  U->>DB: begin; lock admission/auth guards
  U->>DB: resolve command + idempotency receipt
  alt matching committed receipt
    U->>A: locked replay snapshot
    A-->>U: Replay after current disclosure authorization
    U->>DB: end read-only
    U-->>T: original semantic result
  else conflicting identity
    U->>DB: rollback
    U-->>T: typed reuse conflict
  else new command
    U->>DB: lock streams/aggregates/ceremonies in canonical order
    U->>DB: derive/advance persisted authority time
    U->>D: immutable locked state + authority time
    D-->>U: Apply or Reject
    U->>DB: validate shape; CAS state and guards
    U->>DB: append events, audit, receipt, outbox atomically
    U->>DB: commit once
    U-->>T: applied or indeterminate
  end
```

## Ordering rules

1. Structural validation, cryptographic verification, prepared policy material, random IDs and signer readiness occur outside the transaction.
2. Current authority/policy/lifecycle conclusions occur from locked state inside.
3. Guards are sorted by closed kind rank, target kind and canonical ID.
4. Authority time advances only after required locks.
5. The domain decision runs after current authorization evidence exists.
6. Final compare-and-swap repeats admission and authorization-generation predicates.
7. Events and effect IDs are materialized before receipt result finalization.
8. Commit happens exactly once.
9. External effects and recovery-capsule signatures happen only after known commit.

## Authority time

Durable expiry and scheduling use:

```text
authority_time = max(database_wall_time, persisted_authority_time_floor + 1 microsecond)
```

The floor advances transactionally for every new authority-bearing write, so accepted instants are strictly monotone even when database wall time stalls or regresses. If clock evidence violates configured bounds, the scope enters clock-suspect behavior and time-sensitive commands fail closed. Client time and Effect `Clock` never decide lease/session/deadline authority.

Read-only replay may compute disclosure time without mutating the floor. A replay cannot extend a lease or session unless the original command explicitly represented that transition.

## Retry and cancellation

- serialization/deadlock/storage transients retry only the entire UoW with identical IDs, fingerprint and proof material;
- the domain callback has no observable effects, so complete retry cannot duplicate one;
- request cancellation before commit requests rollback;
- once commit begins, a bounded independent completion context determines outcome where the driver permits;
- unknown outcome returns `indeterminate`, never rejection;
- client recovery is exact command/idempotency replay.

## Security-only transactions

A closed family exists outside ordinary commands for `initialize_installation`, `rotate_bootstrap_generation`, `resume_bootstrap_generation`, `record_bootstrap_denial`, and `record_command_denial`. Fresh initialization creates non-secret installation/authority/bootstrap-generation metadata, one pending invitation, and event/audit genesis or none; migrations never seed a hidden principal. Process restart rotates the bootstrap generation. Resuming an old-generation invitation requires explicit human-approved binding of old/new generation and invitation. These transactions cannot contain ordinary command receipts, success domain events, or outbox effects.

Authentication/authorization/security denial is recorded through a separate closed security transaction after known ordinary rollback. It may write only bounded denial dedupe/bucket state and security audit entries. It cannot create ordinary receipts, success events, aggregate state or outbox effects.

Cryptographically rejected bootstrap proof has a dedicated security transition that atomically counts/deduplicates the attempt, updates invitation status and appends audit before returning `UNAUTHENTICATED`. Operational verifier failure consumes no attempt.

## Recovery capsules

Every retryable create command MUST declare either a required `RecoveryCapsulePlan` or the closed `not_applicable` variant. When required, the transaction MUST persist the unsigned bounded capsule draft in the same transaction or roll back. It binds command identity, authority, resources, event range, effect identities and receipt-result digest. Signing happens after known commit with the preselected historical key. Signer failure yields committed-but-pending recovery, not command rollback.

## Cross-engine semantic contract

For the same fixture/history, SQLite and PostgreSQL MUST agree on:

- applied/replay/rejected/indeterminate class;
- aggregate state/version;
- typed conflict and safe recovery;
- fact types, origins and relative order;
- receipt identities and semantic digest;
- effect logical identities;
- authority-time comparisons and fence outcomes.

They need not produce identical SQL plans, physical IDs, lock waits or database error text.
