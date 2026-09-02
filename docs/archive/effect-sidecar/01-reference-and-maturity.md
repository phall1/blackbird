# Reference sources and maturity

> **Authority:** Experimental sidecar reference policy  
> **Related:** [Charter](00-charter.md) · [References](references.md) · [Roadmap](effect-v4/08-roadmap-conformance.md)

## Why this page exists

The repository contains accepted Blackbird architecture, partial canonical Go implementation, a separate SQLite daily-coordination path, a legacy Python product, and release-facing documentation. They are not interchangeable sources.

## Source precedence

For sidecar engineering decisions, use this order:

1. accepted sidecar ADRs and an approved acceptance manifest for an exact specification revision;
2. this sidecar specification when its exact revision is Accepted (the current revision is Proposed);
3. explicitly adopted language-neutral invariants from accepted Blackbird ADRs;
4. the accepted Blackbird contract catalog and proof fixtures;
5. current Go behavior for operations actually implemented through canonical boundaries;
6. implementation tests and SQL as evidence of those operations;
7. READMEs and legacy Python behavior only as product-history input.

A lower source cannot override a higher one. Go package layout, DTO repetition, SQL table names, and adjunct shortcuts are not semantic authority.

## Current sidecar maturity

This entire tree is **Proposed**. It authorizes only disposable E0 contract/codec/runtime/storage/packaging probes with isolated temporary data and no user-facing authority. Product handlers, durable user schemas, migrations over user data, installers, public services and release claims are forbidden until an owner-signed acceptance manifest promotes an exact revision and resolves the kickoff decisions in [the decision ledger](effect-v4/09-decisions-risks.md).

## Maturity vocabulary

| Maturity | Meaning |
|---|---|
| Proposed | Under review; permits disposable investigation only. |
| Accepted | Internally consistent and implementation-authorizing. |
| Verified | Exact revision/artifact passed named executable and adversarial evidence. |
| RC | Verified behavior exists in signed supported artifacts and full release matrix passes. |

Issue closure, merged code, a green unit test, or README text does not advance maturity by itself.

## Current reference reality

| Surface | Status | Consequence for sidecar |
|---|---|---|
| Blackbird architecture ADRs 0002–0011 | **Accepted target** | Strong source for intended authority and semantics; not shipped evidence. |
| Blackbird contract catalog/proof slice | **Accepted target** | Adopt selectively under `sidecar.*`; do not claim it already passes. |
| Go strict canonical operation inventory | **Implemented reference, partial** | Canonical API currently reaches bootstrap/identity/session, WorkRef, objective/work, run plan/join/start, context and event sync. It ends at `run.start.v1`. |
| Run activation/completion, full runtime lifecycle, decisions, attention, artifacts, provider transition | **Accepted target** | Must be independently designed/implemented/tested by sidecar. |
| SQLite daily conversations/messages/reservations | **Implemented reference, adjunct** | Useful UX evidence; not canonical cross-engine/UoW parity. |
| PostgreSQL daily coordination | **Not implemented** | Current Go adapter fails closed as unsupported; sidecar must not copy a SQLite-only semantic shortcut. |
| Strict production ingress/proof ceremonies | **Implemented scaffolding, fail-closed** | DTO/domain/storage presence is not a usable end-to-end identity system. |
| OpenCode push bridge | **Implemented reference** | Valuable durable-catch-up/wake-only pattern; remains a projection/client integration. |
| Legacy Python Agent Mail | Separate lineage | Not canonical sidecar or Blackbird semantics. |
| Effect client spike | Client-only evidence | Demonstrates typed decoding/interruption/paging, not server persistence or packaging. |

## Mandatory implementation labels

Backlogs, design reviews, tests and release notes MUST label each capability as:

- `reference_implemented`;
- `target_adopted`;
- `sidecar_implemented`;
- `sidecar_verified`;
- `deferred`;
- `rejected`.

Do not use “parity” without naming the compared operation set, semantic fixture revision, storage engines, transports, and failure cases.

## Adopt, adapt, reject

### Adopt language-neutrally

- distinct workspace/principal/actor/session/run/runtime identities;
- single home authority and opaque authority epoch;
- expected versions and idempotency receipts;
- state + event + audit + outbox atomicity;
- database-derived authority time;
- cursor catch-up and wake-only notifications;
- provider provenance and reconciliation;
- independent delivery/attention facts;
- advisory versus enforced leases and fencing;
- normalized current state plus journal, not maximal event sourcing.

### Adapt deliberately

- operation names become `sidecar.*`;
- contracts are authored with Effect Schema but persist language-neutral JSON;
- Node lifecycle and SQLite worker boundaries replace Go process/concurrency mechanics;
- package boundaries replace Go internal-package enforcement;
- sidecar performance budgets are independently measured.

### Reject as implementation accidents

- opening Blackbird storage;
- reproducing Go file/package size or SQL names;
- treating the local adjunct API as canonical domain design;
- importing current partial state machines as the complete target;
- using Blackbird credentials, cursors, epochs, or signing keys;
- equating a generated SDK type with the domain;
- carrying Effect types into persisted contracts.

## Conformance rule

The sidecar conformance harness compares **semantic histories**, not product branding or byte-identical envelopes. A fixture records:

- preconditions and authenticated authority;
- command semantic fingerprint;
- applied/replay/rejected/indeterminate result;
- aggregate versions and states;
- event types, causation and relative ordering;
- outbox logical identities;
- typed conflicts and recovery instructions.

Black-box comparison against Go is permitted only for currently implemented canonical operations. Accepted target-only cases compare against the accepted model/fixture, not imagined Go output.
