# Contracts, schemas and compatibility

> **Authority:** Experimental sidecar contract policy; operation semantics adopt selected accepted targets  
> **Related:** [Operation registry](06-operation-registry.md) · [UoW](08-consistency-uow.md) · [Effect codecs](effect-v4/04-schema-codecs.md)

## Contract surfaces

| Surface | Audience | Contract artifact |
|---|---|---|
| Product HTTP | desktop/mobile/SDK | OpenAPI 3.1 + JSON Schema 2020-12 |
| Admin HTTP/local IPC | operator/installer | separate audience and OpenAPI document |
| MCP | agent clients | curated tools/resources/prompts; not automatic OpenAPI reflection |
| SDK | TypeScript and later language clients | generated wire client plus handwritten domain wrapper |
| Provider ports | Phux/tracker/notification/object store | versioned fixtures and capability negotiation |
| Worker RPC | daemon↔SQLite worker | private versioned bounded Schema; no arbitrary callbacks |
| Export/import | offline migration | signed manifest and immutable versioned records |

All sidecar operations use `sidecar.*`; examples below are schematic.

## Command envelope

```json
{
  "schema": "sidecar.command/1",
  "operation": "sidecar.run.plan_with_bindings.v1",
  "request_id": "<bounded transport request id>",
  "command_id": "<uuidv7>",
  "idempotency_key": "<bounded opaque key>",
  "authority_id": "<uuidv7>",
  "authority_epoch": "<opaque equality-only token>",
  "actor_session_id": "<uuidv7-or-null>",
  "client_instance_id": "<uuidv7>",
  "expected_versions": {"run:<uuid>": 3},
  "deadline": "2030-01-02T03:04:05.123000Z",
  "causation_id": null,
  "correlation_id": "<uuidv7>",
  "body": {}
}
```

Authenticated principal/device/service evidence is supplied by the trusted transport boundary, not accepted from command body claims. Public actor commands require an active session; protected provider/worker commands use a narrow service principal and explicit causation without inventing an actor.

## Result dispositions

The semantic result is distinct from transport delivery metadata.

| Disposition | Meaning |
|---|---|
| `applied` | commit is known and a new semantic transition occurred |
| `replay` | prior semantic result disclosed after current authorization; no new write |
| `committed_capsule_pending` | commit known, required post-commit signing unavailable |
| `rejected` | no ordinary command mutation; optional bounded denial audit is separate |
| `indeterminate` | database outcome unknown; retry exact command/key to resolve |

Success contains operation, stable resources/versions, accepted authority/time, event IDs/range and opaque cursor. Request ID is response correlation, not persisted semantic replay content.

## Operation families

Use the external accepted Blackbird contract catalog listed in [references](references.md) only as a semantic checklist. Independent adopted names and skeleton semantics live in the [sidecar operation registry](06-operation-registry.md); its machine-readable successor is required before implementation.

- installation, principal, workspace, membership, actor, delegation, device, session;
- WorkReference, objective, work unit, formation;
- run planning/start/activation/participation/completion;
- runtime endpoint/binding request, launch, observation, reconciliation, supersede;
- conversation, message, delivery facts;
- lease acquire/renew/release and fence validation;
- decision, attention occurrence/delivery/receipt;
- artifact declare/finalize/abandon/attach;
- provider transition request/confirmation/rejection;
- context, event sync, work/run/decision/search queries;
- administrative backup/restore/migration/diagnostics.

The sidecar registry MUST record per command: authority class, scope, expected versions, idempotency fingerprint fields, aggregate read/write set, fact set, effects, limits, errors and transport exposure. A handler without a complete accepted registry entry is forbidden.

## Stable error model

Errors are typed machine contracts, never arbitrary strings.

| Code | Typical meaning | Recovery |
|---|---|---|
| `INVALID_SCHEMA` / `INVALID_ARGUMENT` | malformed or semantically invalid input | correct request |
| `UNAUTHENTICATED` | proof missing/rejected | authenticate; no mutation except bounded security denial path |
| `SESSION_EXPIRED` | domain session or transport proof stale | refresh transport or start a new session as instructed |
| `FORBIDDEN` / `CAPABILITY_REQUIRED` | current policy denies | obtain authority or stop |
| `NOT_FOUND` | disclosable resource absent | re-read/scope check |
| `STALE_VERSION` | expected/current differ | fetch current state and decide again |
| `COMMAND_ID_REUSED` | command ID, different fingerprint | new intent/ID |
| `IDEMPOTENCY_KEY_REUSED` | scoped key, different semantic input | new key for new intent |
| `COMMAND_IN_PROGRESS` | matching receipt currently contended | bounded retry same identity |
| `STATE_CONFLICT` | legal schema, illegal lifecycle/reference | inspect `domain_conflict` |
| `LEASE_CONFLICT` | overlapping incompatible claim | wait/change selector/mode |
| `LEASE_EXPIRED` | terminal lease | acquire a new lease |
| `FENCE_REJECTED` | wrong epoch/key/sequence | stop mutation and re-read grant |
| `CURSOR_INVALID` / `CURSOR_SCOPE_MISMATCH` | forged/wrong stream | obtain scoped checkpoint |
| `CURSOR_EXPIRED` | history retention passed | checkpoint then resume |
| `BACKPRESSURE` | subscriber cannot keep up | reconnect with cursor |
| `DEPENDENCY_UNAVAILABLE` | provider/store/signer unavailable | retry class in safe details |
| `DEADLINE_EXCEEDED` | response absent; result may be unknown | retry exact command identity |
| `INTEGRITY_FAILURE` | hash/schema/storage invariant failed | fail closed, operator intervention |

Safe details never leak another recipient, hidden resource, active lease fence, credential, content, path or provider secret.

## Canonical scalar rules

- IDs are lowercase canonical RFC 9562 UUIDv7 and branded by identity class.
- JSON/JCS integers are exact nonnegative values ≤ `9_007_199_254_740_991` (`2^53-1`); versions begin at one.
- Cryptographic instants use UTC with exactly six fractional digits and `Z`, e.g. `2030-01-02T03:04:05.123000Z`.
- SHA-256 digests are lowercase hex; signatures use explicitly versioned algorithms and unpadded base64url where specified.
- Cursors/tokens are bounded opaque strings. Clients never sort, increment or decode them.
- Hash views contain explicit `null` for defined absent fields. Omission is not a second meaning.
- Typed canonical views are transformed with RFC 8785 JCS. `JSON.stringify` is not canonicalization.
- Non-finite numbers, duplicate decoded keys, invalid Unicode/surrogates, unbounded depth and values outside I-JSON are rejected.

## Domain-separated hashes

```text
SHA-256("sidecar.command-fingerprint/v1\0" || JCS(command_hash_view))
SHA-256("sidecar.authorization-guards/v1\0" || JCS(guard_hash_view))
SHA-256("sidecar.event-digest/v1\0" || JCS(event_hash_view))
SHA-256("sidecar.receipt-result/v1\0" || JCS(receipt_result_core))
SHA-256("sidecar.recovery-capsule/v1\0" || JCS(capsule_draft))
```

Receipt core excludes capsule digest/key/signature so hashing remains acyclic. A capsule may bind the already-computed receipt digest.

## Compatibility policy

- Requests reject unknown fields.
- Responses may add optional fields; clients require known mandatory fields and ignore safe additive fields.
- Known event type with unsupported schema version fails closed.
- Unknown event type is retained as inert `UnknownEvent`; it cannot mutate a projection.
- Operation major versions are literal. Breaking semantic changes require a new major operation/schema and explicit migration/upcaster policy.
- Persisted schemas never contain Effect `Option`, `Duration`, `Cause`, class prototypes, symbols, functions or SDK-native objects.

## Limits

Initial limits follow the adopted target until measured sidecar ADRs amend them:

- message body ≤ 256 KiB UTF-8;
- command envelope/metadata ≤ 1 MiB;
- event payload ≤ 64 KiB;
- receipt semantic core ≤ 2 KiB;
- recovery-capsule draft ≤ 32 KiB;
- effect metadata ≤ 8 KiB;
- artifact metadata ≤ 16 KiB;
- lease request ≤ 256 selectors and 4,096 canonical selector bytes;
- query page ≤ 256 entries;
- bounded nesting/depth defined in generated schemas.
