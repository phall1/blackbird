# Security and privacy

> **Authority:** Experimental sidecar security baseline; threat-model review required before production  
> **Related:** [Authority](02-context-authority.md) · [Contracts](06-contracts.md) · [Failures](13-failure-recovery.md)

## Security objectives

- authenticate the principal/device/service, not a claimed actor name;
- authorize against current locked policy and revocation state;
- keep one typed current epoch per authority scope plus one witnessed deployment writer generation, and reject stale writers/fences;
- preserve recipient and workspace confidentiality;
- prevent replay from duplicating transitions or disclosing revoked results;
- keep credentials, proofs, message/artifact content and terminal bytes out of telemetry;
- constrain local-loopback threats rather than assuming localhost is trusted.

## Identity and proof

Initial baseline:

- Ed25519 installation, device and workload keys;
- TLS 1.3 for network listeners, including local HTTP where deployed;
- pinned SPKI and TLS-exporter channel binding for pairing/proof assertions;
- short-lived proof-of-possession transport assertions;
- purpose-bound, one-use bootstrap/membership/delegation/device/session ceremonies;
- OS credential vault or explicitly unlocked encrypted keystore;
- current credential/trust/policy/grant revisions bound into authentication evidence.

An actor is selected only through an active delegation and actor session. Service principals have no actor session and may perform only cataloged provider/worker operations.

## Bootstrap

A fresh installation creates one 256-bit invitation with a five-minute target lifetime, delivered only through a controlling TTY or protected inherited channel. Plaintext never enters DB, argv, environment, logs, traces, events or evidence.

Fresh initialization is a security-only transaction that creates non-secret installation/authority metadata, a random bootstrap generation, and exactly one pending invitation (plus declared genesis audit/event or none); migrations never create a hidden principal. Bootstrap success atomically consumes invitation and creates first Principal, trusted Device and installation-owner Grant. Workspace creation is separate.

Each daemon start rotates the bootstrap generation before admitting bootstrap. An invitation from an older generation is unusable unless a human explicitly approves `resume_bootstrap_generation`, which durably binds old generation, new generation and invitation through a protected ceremony. Restart never silently extends invitation lifetime or resets rejected-attempt accounting.

Distinct cryptographically rejected attempts are fingerprinted without retaining proof bytes. Exact duplicates do not increment or add audit entries. Bounded per-subject and per-scope denial buckets prevent audit amplification. Operational verifier failure consumes no attempt.

## Authorization

Effective capability is an intersection:

```text
home authority admission
∩ current workspace policy
∩ principal lifecycle
∩ membership capability ceiling
∩ actor delegation
∩ device trust (when required)
∩ explicit grants
∩ resource constraints
∩ operation-specific rules
```

Prepared authentication evidence is rechecked against locked current versions in the UoW. Result replay reauthorizes disclosure; knowing an idempotency key is not authorization.

## Secret lifecycle

Secrets MUST NOT be stored in:

- command bodies or semantic receipt results;
- events, audit details or outbox metadata;
- process argv/environment;
- URLs/query strings/cookies;
- ordinary logs, traces, metrics or crash bundles;
- import/export bundles without explicit encrypted secret protocol (not in v1).

Logs may retain key reference IDs and safe revisions. Historical recovery signing keys remain available only for the declared recovery window and are never silently substituted.

## Message and attention privacy

- recipient snapshots are immutable and authorization-filtered;
- Bcc identity is visible only to authorized sender/recipient/admin policy;
- pagination/counts occur after visibility filtering to avoid cardinality leaks;
- push payloads contain the minimum routing/attention data and no full content by default;
- provider acceptance is metadata, not permission to expose Decision content;
- mobile cache visibly distinguishes cached, stale and authority-confirmed state;
- no LLM/provider receives message, decision or artifact content without an explicit authorized operation.

## Local threat model

Loopback reduces exposure but is not authentication. Defend against malicious local web pages/processes with:

- explicit Host and Origin policy;
- no credentials in query strings;
- no ambient browser cookie authentication;
- bearer/proof credentials scoped to audience and short lifetimes;
- CSRF-safe non-browser admin surfaces;
- private directories/files and symlink-safe atomic writes;
- rate/payload/queue/storage limits before expensive decoding;
- distinct product/admin listeners and credentials.

Local content at rest initially relies on private file permissions and OS disk encryption unless an explicit encrypted database/object ADR is adopted. This is not E2EE; an unlocked account or privileged operator may access content.

## Provider security

Every provider observation includes registered service identity, endpoint/provider scope, observation ID/version, causation and authenticated channel. A tracker assignee, notification receipt, terminal locator or callback URL never grants capability.

Phux credentials and terminal bytes are excluded from notification/mobile paths. Object-store signed URLs are short-lived, audience-scoped and never persisted as canonical artifact identity.

## Federation baseline (future)

Federation uses signed, audience/scope/epoch-bound commands and events. It synchronizes domain proposals/facts, not databases. Offline peers may propose; the current home authority alone accepts authority-bearing transitions. Key rotation, revocation, replay windows, policy ceilings and witnessed authority transfer must be specified before enablement.

## Telemetry redaction

Forbidden telemetry includes credentials, proofs, handoffs, message/decision/prompt bodies, artifact bytes, terminal bytes, full paths, provider payloads and unbounded URLs. IDs belong in logs/traces when authorized and needed; never as unbounded metric labels. Local remote telemetry export is disabled by default.

Tests seed canary secrets in every ingress and fail if any appears in logs, traces, metrics, evidence, panic output or diagnostic bundles.

## Threat register

| Threat | Required control |
|---|---|
| replayed command | dual receipt identities + fingerprint + current disclosure auth |
| stale writer after restore | witnessed promotion + fresh epoch + stale-fence rejection |
| confused principal/actor | typed identities + active delegation/session |
| Bcc/cardinality leak | pre-pagination authorization filters |
| ambiguous provider result | possibly-applied state and reconciliation |
| native addon/supply chain | exact pins, provenance, SBOM, signed per-platform artifacts |
| malicious local origin | TLS/proof, Host/Origin, no cookies/query credentials |
| audit DoS | bounded dedupe/saturation transactions |
| projection poisoning | typed event versions, inert unknown events, atomic verified rebuild |
| path/symlink escape | normalized logical selector plus no-follow/revalidate in enforcer |
| unlocked host/operator | explicit residual risk; optional encryption/E2EE requires later ADR |
