# Effect transports and integration adapters

> **Authority:** Experimental implementation overlay  
> **Related:** [Neutral contracts](../06-contracts.md) · [Integrations](../11-integrations.md) · [Services](03-services-layers-runtime.md)

## HTTP

Use Effect Platform Node behind an explicit operation registry. Product and admin listeners have separate configuration, audience, auth middleware and OpenAPI artifacts.

Handler pipeline:

1. enforce method/content type/body bytes/deadline/host/origin/rate limits;
2. authenticate channel/proof before sensitive decoding where appropriate;
3. Effect Schema decode from `unknown`, rejecting excess fields;
4. create immutable verified context and call application service;
5. map typed result/problem and enforce matching request/operation;
6. `Cache-Control: no-store`, `nosniff`, trace/correlation headers;
7. never leak Effect `Cause`, stack, provider error or content.

Expected domain failures are HTTP problem documents. Defects become bounded internal problems plus alert.

## MCP

The official TypeScript MCP SDK is isolated in `adapters-mcp`. Its framework/Zod values never enter application/domain.

- curate a small agent surface; do not expose every admin/product operation;
- use Effect Schema for input/output decoding and shared fixtures;
- expected tool failures return structured tool content with stable code/details;
- protocol errors are reserved for malformed MCP protocol use;
- resources expose context/run/decision projections with authorization;
- notifications are wake hints;
- support Streamable HTTP and stdio where product requires;
- stdio writes protocol bytes only to stdout; logs/diagnostics go to structured stderr;
- one MCP session is not principal authentication by itself.

Tool names use independent naming, e.g. `sidecar_start_session`, never `blackbird_*`.

### Streamable HTTP contract

- negotiate and validate the supported MCP protocol version on initialization and subsequent requests;
- POST request `Content-Type` is `application/json`; its `Accept` header negotiates a supported JSON or SSE response according to the pinned protocol/SDK contract—SSE is never an inbound POST body media type;
- GET opens an authorized resumable server stream only for a valid sidecar-issued MCP session and supported `Accept`; DELETE terminates that transport session but never a domain ActorSession;
- issue high-entropy bounded MCP session IDs only after authentication; bind them to principal/device, audience, protocol version and expiry; never accept them as authority by themselves;
- revalidate sidecar authentication, Host, Origin, audience, rate/byte limits and current revocation on **every** GET/POST/DELETE;
- cancellation interrupts request work only until commit ownership transfers; response loss uses exact command/receipt recovery;
- stream resumption uses sidecar opaque event cursors; MCP event IDs/notifications remain wake transport metadata;
- reject unsupported protocol/media/method/session combinations with bounded protocol errors and no authority leakage.

## CLI

Two modes:

- **Online:** authenticated product/admin client of running daemon (`status`, diagnostics, backup request, outbox inspect).
- **Exclusive maintenance:** acquires offline ownership and verifies daemon is stopped/fenced before migration/restore/repair.

The CLI never opens live SQLite beside the daemon. Human output may be styled; `--json` is stable machine output. Secrets never appear in argv/history.

## Subscriptions

Implement SSE or WebSocket as scoped Effect Streams backed by bounded queues. Send head/cursor hints only. On disconnect/reconnect clients call durable sync. Heartbeats contain no authority/content. Overflow closes with typed backpressure and last safe cursor.

## Provider adapter pattern

```ts
// schematic service boundary
interface ProviderPort<Request, Observation, Failure> {
  readonly capabilities: Effect<Capabilities, Failure>
  readonly attempt: (request: Request) => Effect<AttemptResult, Failure>
  readonly reconcile: (identity: StableOperationIdentity) => Effect<Observation, Failure>
}
```

Requests/observations are decoded from unknown and bounded. Provider raw exceptions map to retryable/permanent/unknown/auth/incompatible categories. Stable logical identity is always supplied.

## Runtime provider

Wrap Phux process/network APIs with:

- capability/version negotiation;
- endpoint-specific authentication;
- scoped child-process/socket resources;
- opaque terminal locator preservation;
- inventory completeness marker;
- launch accepted/refused/unknown classification;
- no terminal bytes in Sidecar telemetry/database.

Any direct terminal stream integration belongs in clients, not this adapter.

## Beads/work provider

Use a verified absolute CLI/API endpoint and strict version/capability fixture. Subprocess execution is scoped, timeout/buffer bounded, read-only where observing, and hashes a safe invocation transcript. Provider writes use stable operation identity and later observation confirmation. Never import Dolt/storage packages.

## Notification provider

Per-channel service with bounded concurrency/circuit breaker. Secrets are scoped; payload content minimized. Return provider acceptance metadata only. Effect retries calculate policy, while outbox persists schedule/attempt.

## Object store

Expose streaming upload/download with ≤ configured per-transfer buffer (target 8 MiB), digest/size verification, cancellation and idempotent object-store publication. Publication and database Artifact availability are separate atomic steps joined by a durable staging manifest and later verifier observation; reconciliation repairs object-published/DB-unavailable windows. Signed URLs/capabilities are ephemeral. Local filesystem adapter uses private directories, atomic no-follow operations and content-addressed paths.

## Telemetry integration

Effect OpenTelemetry spans cross transport/auth/application/UoW/outbox/provider boundaries. Inject/propagate only allowed context. A redaction middleware applies before exporters, and tests replace exporter with a canary-scanning collector.

## Client SDK

Generate a Promise/fetch wire client if useful, then provide a handwritten Effect wrapper with:

- typed failure union;
- cancellation/deadline bridging;
- operation/result matching;
- strict response decode;
- cursor page/stream helpers with non-advancing/max-page guards;
- no automatic read/ack side effects.

The existing Effect client spike is reference only; update integer/timestamp/canonical contracts before reuse.
