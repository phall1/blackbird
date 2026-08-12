# Roadmap, conformance and optional import

> **Authority:** Experimental execution plan  
> **Related:** [Reference maturity](../01-reference-and-maturity.md) · [Verification](../15-verification.md) · [Decisions](09-decisions-risks.md)

## Stage E0 — foundation and spikes

### E0.1 Contract foundation

- ratify sidecar name/namespace/identity isolation;
- draft/review sidecar ADRs for runtime, authority, domain, persistence and security;
- complete/review the initial [operation registry](../06-operation-registry.md), including every E0/E1 field rather than capability-family prose;
- approve one acceptance manifest with named approver, exact spec/ADR/registry revisions, kickoff pins and authorized E0 proof scope;
- only after that acceptance, implement branded scalars, exact timestamps, JCS/hash vectors and the package/import/generated-contract foundation.

### E0.2 Runtime/storage challenger

Compare pinned Node and Bun candidates on SQLite WAL/full-sync, worker/event loop, backup, kill windows, startup/RSS/artifact and clean installation. Node remains default unless challenger passes all gates and materially simplifies product.

### E0.3 One-command vertical proof

Implement the exact registry entry `sidecar.workspace.create.v1` through direct application, HTTP and MCP so it atomically writes aggregate(s), receipt, events, audit and declared outbox on SQLite/PostgreSQL; prove apply/replay/reuse/stale/revoked/cancel/crash/indeterminate.

**Entry:** the acceptance manifest already authorizes this bounded disposable proof. **Exit:** the walking-slice implementation is eligible for Verified review; no product or permanent MCP exposure claim.

## Stage E1 — current canonical overlap

Complete registry entries first, then implement independent equivalents of currently canonical reference operations:

- bootstrap, principal, pairing, workspace/membership, actor/delegation, session;
- context/event sync;
- WorkReference observe;
- objective/work create/activate;
- run plan-with-bindings, participant join and run start.

Black-box compare against Go only where its strict operation is usable. Where Go production ingress is fail-closed, use accepted fixtures and direct implementation tests; report the limitation.

## Stage E2 — canonical coordination

Implement conversations, immutable messages, To/Cc/Bcc recipient obligations, independent delivery facts and exact/subtree leases/fences through the canonical UoW on both engines. Do not copy SQLite adjunct storage shortcuts.

## Stage E3 — runtime sagas

Runtime endpoint registration/pairing, requested/launching/reconciling/live/orphaned/ended/failed/superseded, direct-client stream boundary, ambiguous launch and incarnation reuse proofs.

## Stage E4 — decisions, attention and artifacts

Typed decisions, occurrences/generations/provider receipts, offline mobile flow, staged/verified artifacts, participant finish, completion request/accept and provider transitions.

## Stage E5 — product/recovery

Search/projection rebuild, local installer/CLI/SDK, backup/restore/epoch rotation, diagnostics, provider compatibility, performance/soak and release packaging.

## Conformance tracks

### Sidecar internal semantic parity

Every operation corpus runs through direct application, HTTP, MCP (where exposed), SQLite and PostgreSQL. Compare state/version/events/effects/errors/recovery, not SQL/transport bytes.

### Blackbird reference mapping

Maintain a versioned mapping:

```text
reference operation/schema/event
  -> adopted | adapted | deferred | rejected
  -> sidecar operation/schema/event
  -> compared implementation revision (if any)
  -> fixture/evidence digest
```

Current Go black-box behavior is an oracle only for implemented canonical cases. Target-only ADR behavior uses accepted model fixtures. Adjunct local coordination is UX/input evidence, not a parity authority.

### Real-provider compatibility

Recorded doubles do not verify actual Phux/Beads/MCP/runtime behavior. Run version-pinned real compatibility after contract tests, retaining capabilities, requests/responses and failure evidence.

## Optional offline import

Import is deferred until independent sidecar semantics pass. If approved:

1. Blackbird remains source authority and unchanged;
2. obtain public offline signed/exported snapshot, never DB access;
3. verify schema, signature, source manifest/digests and authorization;
4. reject secrets, credentials, actor sessions, active leases/fences, pending effects and runtime authority;
5. map importable history/resources to new sidecar IDs with immutable source references;
6. persist one import receipt/audit and deterministic mapping;
7. repeated same export returns same result/no duplicates;
8. changed/tampered export rejects;
9. no live dual-write or reverse sync.

Imported messages/artifacts require explicit privacy/retention approval. Historical terminal locators are inert metadata at most.

## Backlog derivation rule

Each feature issue must include:

- source spec section and adopted status;
- command/query/event/error registry deltas;
- domain transition and invariants;
- SQLite/PostgreSQL migration/repository work;
- HTTP/MCP/SDK exposure;
- adversarial/model/crash/provider tests;
- operation and evidence documentation;
- explicit non-goals and owner decisions.

A feature closes only when its vertical outcome passes supported boundaries; “models added” or “handler compiles” is not completion.

## No compatibility shim phase

The experiment does not need a Blackbird wire/database compatibility layer. If a shared client abstraction is later useful, it lives above two explicit product clients and exposes provenance; neither daemon impersonates the other.
