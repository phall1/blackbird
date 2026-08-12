# Integration contracts

> **Authority:** Experimental sidecar ports; external systems retain their own authority  
> **Related:** [Authority ledger](02-context-authority.md) · [Sequences](12-sequence-diagrams.md) · [Effect adapters](effect-v4/06-transports-integrations.md)

## Port rules

Every integration is behind an application-declared port with:

- explicit provider and protocol version/capabilities;
- authenticated identity and audience;
- bounded request/response schemas decoded from `unknown`;
- stable operation/observation IDs;
- timeout, cancellation, retry and unknown-outcome classifications;
- provenance captured without sensitive payloads;
- contract fixtures and real-provider compatibility tests;
- no imports into the domain package.

Providers are never called inside an authoritative command transaction.

## Runtime provider / Phux

### Authority split

| Sidecar owns | Runtime owns |
|---|---|
| Run and participation | terminal/process existence |
| durable binding identity, intent and history | server incarnation and terminal ID |
| observed binding health/lifecycle projection | terminal bytes, input lease and rendering |
| outbox launch/reconcile intent | actual spawn/adopt/kill/attach behavior |

`RuntimeEndpointRegistration` pairs one service identity and capability manifest. The terminal locator is opaque and scoped to endpoint + negotiated server incarnation. Sidecar correlation metadata contains only sidecar workspace/run/session/binding IDs.

### Launch saga

1. commit requested binding and outbox intent;
2. claim launch effect;
3. negotiate endpoint/incarnation/capability;
4. issue idempotent/correlated create if the provider proves it;
5. if the provider cannot prove idempotent/correlated creation, do not dispatch managed spawn automatically; park for explicit adoption/manual policy or return an incompatible-capability failure;
6. if response is lost after possible acceptance, record reconciliation—not a blind spawn retry;
7. accept live only from exact authenticated observation;
8. orphan/supersede under explicit lifecycle rules.

Terminal bytes flow directly between authorized client and runtime.

## Work providers / Beads

`WorkReference` stores provider, external workspace/object ID, URL, last observed opaque version, observed fields, timestamp, freshness and provenance.

The adapter SHOULD use a supported CLI/API contract with read-only/capability discovery. It MUST NOT access Beads/Dolt tables. Priority, dependencies, readiness, assignment and provider status remain tracker-owned.

A provider transition is a child operation:

1. Sidecar commits requested target and outbox job;
2. adapter sends stable provider operation identity;
3. timeout becomes unknown/pending;
4. later authoritative provider read at a new version confirms only when provider operation identity/receipt or another supported causation proof matches the pending child; a coincidentally matching state caused elsewhere is an independent observation and leaves causality unresolved;
5. definitive refusal rejects; otherwise ProviderOperation remains `pending`, while its latest OutboxAttempt may carry the operational `possibly_applied` posture;
6. only an authenticated observation changes provider projection/operation status.

## Notification provider

The adapter receives a bounded `AttentionDelivery` generation. It returns acceptance/retry/permanent/unknown metadata. APNs/web-push acceptance does not mean device shown/seen or Decision resolved.

Provider-specific tokens live in the secret store. Push payloads minimize content. Device receipts are separately authenticated Sidecar commands.

## Artifact object store

### Upload protocol

- declare expected hash/size/media/quota;
- allocate bounded staging capability;
- stream with bounded memory and cancellation;
- verify ciphertext/plaintext policy, digest and exact byte count;
- publish the content-addressed object idempotently inside object-store authority;
- submit a later authenticated verification observation that atomically moves database Artifact metadata to `available` only after object/hash/size/media proof;
- reconcile the object-published/database-not-available crash window from the durable staging manifest and digest;
- discard/quarantine failed or orphaned staging asynchronously without exposing it as an available Artifact.

Local mode uses a private content-addressed directory. Hosted mode may use S3-compatible multipart/direct upload with signed short-lived capabilities. Canonical identity is digest + verified metadata, not a signed URL.

Backup pins all referenced object versions until manifest publication/abandonment.

## Secret and signing store

Ports include:

- principal/device/workload private key operations;
- credential reference lookup and rotation;
- recovery-capsule signer readiness and signing;
- envelope/object encryption key lookup;
- historical key availability checks.

The transaction receives prepared immutable key references/digests, never a vault client. Actual signing is post-commit.

## Hosted identity and federation (future)

OIDC/PKCE/BFF/DPoP or workload mTLS are ingress adapters producing the same verified authentication evidence. Hosted organization policy is a signed ceiling enforced by workspace home authority. Federation uses commands/events/proposals—not shared SQL or CRDT merge of leases/decisions.

## Desktop and mobile clients

Clients consume product HTTP/SDK and cursor sync. Desktop combines Sidecar projections with direct runtime streams and labels provenance/health. Mobile optimizes for attention and structured decisions, works offline from redacted cache, and confirms accepted commands before claiming completion.

## Blackbird relationship

No live adapter is required or initially allowed. An optional later import/export adapter:

- reads an offline signed Blackbird export through a documented public format;
- never opens Blackbird storage;
- maps into new sidecar IDs while preserving source references;
- is deterministic and repeatable;
- excludes credentials, actor sessions, active leases/fences, pending outbox work and runtime authority;
- never writes to the source.
