# State machines

> **Authority:** Proposed experimental sidecar semantics adopted from the accepted target unless explicitly marked  
> **Related:** [Domain](03-domain-model.md) · [Use cases](05-use-cases.md) · [Failures](13-failure-recovery.md)

This page is exhaustive for core v1 lifecycle names. A transition not shown is forbidden and returns a typed state conflict without mutation. Expiry is an authority-time command, never a client-clock side effect.

## Authority and identity

```mermaid
stateDiagram-v2
  state Workspace {
    [*] --> ws_active: create
    ws_active --> ws_suspended
    ws_suspended --> ws_active
    ws_active --> ws_archived
    ws_suspended --> ws_archived
  }
  state Principal {
    [*] --> principal_active: register
    principal_active --> principal_suspended
    principal_suspended --> principal_active
    principal_active --> principal_disabled
    principal_suspended --> principal_disabled
  }
  state Device {
    [*] --> device_pending: pairing issue
    [*] --> device_trusted: bootstrap provision
    device_pending --> device_trusted
    device_pending --> device_revoked
    device_trusted --> device_suspended
    device_suspended --> device_trusted
    device_trusted --> device_revoked
    device_suspended --> device_revoked
  }
  state Membership {
    [*] --> member_invited: invite
    [*] --> member_active: owner provision
    member_invited --> member_active
    member_invited --> member_revoked
    member_active --> member_suspended
    member_suspended --> member_active
    member_active --> member_revoked
    member_suspended --> member_revoked
  }
```

Bootstrap Device and owner Membership provisioning are explicit creation transitions producing exactly version 1 and one terminal creation fact for that aggregate; they do not perform two mutations at version 1. `archived`, `disabled`, and each typed `*_revoked` state are terminal. Suspension denies new work without erasing history. Capability/trust changes advance their own revisions and make existing sessions subject to current reauthorization.

```mermaid
stateDiagram-v2
  state Credential {
    [*] --> credential_active
    credential_active --> credential_rotated
    credential_active --> credential_revoked
  }
  state Grant {
    [*] --> grant_active
    grant_active --> grant_revoked
  }
  state Actor {
    [*] --> actor_active
    actor_active --> actor_suspended
    actor_suspended --> actor_active
    actor_active --> actor_retired
    actor_suspended --> actor_retired
  }
  state Delegation {
    [*] --> delegation_proposed
    delegation_proposed --> delegation_active
    delegation_proposed --> delegation_revoked
    delegation_active --> delegation_suspended
    delegation_suspended --> delegation_active
    delegation_active --> delegation_revoked
    delegation_suspended --> delegation_revoked
  }
  state RuntimeEndpoint {
    [*] --> endpoint_proposed
    endpoint_proposed --> endpoint_paired
    endpoint_proposed --> endpoint_revoked
    endpoint_paired --> endpoint_suspended
    endpoint_suspended --> endpoint_paired
    endpoint_paired --> endpoint_revoked
    endpoint_suspended --> endpoint_revoked
  }
```

`credential_rotated`, every typed `*_revoked`, `actor_retired`, and `principal_disabled` are terminal. Credential rotation creates a new active Credential ID while terminalizing the predecessor in one declared commit set. Grant revocation never deletes historical authorization evidence. Only a paired endpoint may submit runtime observations.

## Actor session

```mermaid
stateDiagram-v2
  [*] --> issued: challenge-based issue
  issued --> active: activate proof
  [*] --> active: direct start with equivalent proof
  issued --> expired
  issued --> revoked
  active --> ended: cooperative end
  active --> expired: authority deadline
  active --> revoked: authority action
  ended --> [*]
  expired --> [*]
  revoked --> [*]
```

Transport `session.resume` reauthenticates a connection to a still-active domain session; it does not revive a terminal state. Connection/model/runtime loss does not end a session.

## Objective, work, provider operation and formation

```mermaid
stateDiagram-v2
  state Objective {
    [*] --> objective_draft
    objective_draft --> objective_active
    objective_draft --> objective_abandoned
    objective_active --> objective_satisfied
    objective_active --> objective_abandoned
  }
  state WorkUnit {
    [*] --> work_proposed
    work_proposed --> work_ready
    work_proposed --> work_cancelled
    work_ready --> work_active
    work_ready --> work_cancelled
    work_active --> work_completed
    work_active --> work_cancelled
  }
  state WorkReference {
    [*] --> workref_observed
    workref_observed --> workref_observed: newer provider version
  }
  state ProviderOperation {
    [*] --> providerop_pending
    providerop_pending --> providerop_confirmed: correlated matching observation
    providerop_pending --> providerop_rejected: definitive refusal
  }
```

`satisfied`, `abandoned`, `completed`, `cancelled`, `confirmed`, and `rejected` are terminal. Formation definitions are immutable versioned revisions: defining or revising creates a new revision; it never mutates live process topology.

A matching provider value without operation causation is an independent observation, not proof that a pending operation caused it. Such a ProviderOperation remains pending; its associated OutboxAttempt may be `possibly_applied` until supported reconciliation resolves it.

## Run and participation

```mermaid
stateDiagram-v2
  state Run {
    [*] --> run_planned
    run_planned --> run_starting: start
    run_planned --> run_cancelled
    run_planned --> run_failed
    run_starting --> run_active: start policy satisfied
    run_starting --> run_cancelled
    run_starting --> run_failed
    run_active --> run_completing: request completion accepted
    run_active --> run_cancelled
    run_active --> run_failed
    run_completing --> run_completed: acceptance
    run_completing --> run_active: completion rejected
    run_completing --> run_cancelled
    run_completing --> run_failed
  }
  state Participation {
    [*] --> participation_invited
    participation_invited --> participation_active: join
    participation_invited --> participation_withdrawn
    participation_active --> participation_finished: evidence criteria satisfied
    participation_active --> participation_withdrawn
  }
```

Run `completed/cancelled/failed` and Participation `finished/withdrawn` are terminal. Participations version independently. A live binding never activates or fails a Run implicitly.

**Implemented reference:** current canonical Go Run supports only `planned → starting`, Participation `invited → active`, and initial Binding `requested`. Later states are accepted targets requiring independent sidecar evidence.

## Runtime binding

```mermaid
stateDiagram-v2
  [*] --> requested
  requested --> launching: managed launch
  requested --> reconciling: adopt exact target
  requested --> superseded: explicit replacement before dispatch
  launching --> live: exact target proven
  launching --> reconciling: accepted outcome ambiguous
  launching --> failed: known refusal
  launching --> superseded: deliberate replacement
  reconciling --> live: exact target proven
  reconciling --> orphaned: complete evidence cannot prove target
  reconciling --> failed: known refusal
  reconciling --> superseded: deliberate replacement
  live --> ended: authoritative close
  live --> orphaned: target unprovable
  live --> superseded: deliberate replacement
  orphaned --> superseded: explicit successor
  ended --> [*]
  failed --> [*]
  superseded --> [*]
```

`ended`, `failed`, and `superseded` are terminal. An orphan cannot return live; recovery uses a new Binding ID. Watcher/UI/transport loss changes health only. Runtime identity is endpoint + server incarnation + opaque tagged terminal ID.

## Context checkpoint

A ContextCheckpoint is immutable after creation. It records authorization/policy basis, internally consistent source snapshot, through-cursor, schema/digest, continuations and expiry. Expiry/narrowing/compaction creates a new checkpoint; an old one is never edited or used as a grant.

## Conversation, message and delivery

```mermaid
stateDiagram-v2
  [*] --> open
  open --> closed
  closed --> [*]
```

Message is immutable. Delivery is an independently versioned aggregate. Its dimensions form a monotone product rather than one lifecycle:

```mermaid
stateDiagram-v2
  state "availability" as A {
    [*] --> availability_absent
    availability_absent --> availability_present: record available
  }
  state "read" as R {
    [*] --> read_absent
    read_absent --> read_present: record read
  }
  state "acknowledgement" as K {
    [*] --> ack_absent
    ack_absent --> ack_present: acknowledge
  }
```

Any ordering is legal. Acknowledgement implies neither read nor availability and does not make Delivery terminal.

## Decision and attention

```mermaid
stateDiagram-v2
  state Decision {
    [*] --> decision_open
    decision_open --> decision_resolved
    decision_open --> decision_cancelled
    decision_open --> decision_expired
  }
  state Occurrence {
    [*] --> occurrence_open
    occurrence_open --> occurrence_open: material update / generation +1
    occurrence_open --> occurrence_resolved: source condition resolved
  }
  state AttentionDelivery {
    [*] --> attention_queued
    attention_queued --> attention_delivered: provider accepts
    attention_queued --> attention_cancelled: before acceptance
  }
```

Decision `resolved/cancelled/expired`, Occurrence `resolved`, and Delivery `delivered/cancelled` are terminal. Provider claim/retry/park states belong to OutboxAttempt, not AttentionDelivery.

A Decision snapshots eligible responders and uses **first valid response wins** in v1. Resolution is one exact-version command; concurrent later responses are `DecisionTerminalConflict`. No response replacement or quorum exists in v1. Changing question/options/schema/responders/deadline creates a superseding Decision. Expiry and resolution serialize under exact version and authority time.

Attention shown/seen/dismissed facts form another independent monotone product keyed by occurrence, device, and generation. They do not resolve the source condition.

## Lease

```mermaid
stateDiagram-v2
  [*] --> active: grant and fence
  active --> active: renew expiry only
  active --> released: holder release
  active --> expired: authority time reached
  active --> revoked: administrator policy
  released --> [*]
  expired --> [*]
  revoked --> [*]
```

Renewal preserves the fence. Successor grants increment relevant conflict-key sequences. Acquisition decides expiry under lock; cleanup is not correctness-critical.

A remote `fence.validate` query alone is advisory because validity can change after response. An `integration_enforced`/`sidecar_enforced` mutation boundary MUST couple fence comparison and protected mutation using a provider-native conditional operation, transaction, or lease-token check at mutation time. Otherwise the enforcement class is `advisory`.

## Artifact

```mermaid
stateDiagram-v2
  [*] --> declared
  declared --> available: verified observation commits
  declared --> abandoned
  declared --> failed
  available --> quarantined
  quarantined --> available: authorized release
  abandoned --> [*]
  failed --> [*]
```

Staging and object publication are operational states, not readable Artifact states. Database availability occurs only in a later idempotent verification command after object existence/hash/size/media are proven. Object-published/DB-not-available windows are reconciled by staging manifest and digest.

## Outbox job and attempt

```mermaid
stateDiagram-v2
  [*] --> ready
  ready --> claimed_pre_dispatch
  claimed_pre_dispatch --> dispatched: persist before provider contact
  claimed_pre_dispatch --> ready: claim expires safely
  dispatched --> succeeded: receipt recorded
  dispatched --> ready: proven safe idempotent retry
  dispatched --> possibly_applied: response unknown or claim expires
  possibly_applied --> succeeded: reconciliation confirms
  possibly_applied --> ready: reconciliation proves absent
  ready --> parked: policy exhausted
  possibly_applied --> parked: cannot reconcile
  parked --> ready: explicit authorized retry
```

A previous dispatched attempt may still be running after claim expiry. It is never automatically overlapped for a non-idempotent provider. Claims renew boundedly; durable phase and stable effect identity govern recovery.

## Forbidden implications

- session credential refresh does not extend domain session lifetime;
- live runtime does not activate Run without `run.activate`;
- message ACK does not mark read;
- push/provider acceptance does not resolve attention;
- lease does not grant runtime input;
- run completion does not close tracker work;
- object upload/publication does not make Artifact available;
- provider timeout does not imply rejection;
- process death does not imply DB rollback or provider-effect absence.
