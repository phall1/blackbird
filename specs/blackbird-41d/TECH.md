# Blackbird as an external provider on the phux highway

Status: **Proposed; implementation requires product and boundary approval.**

2026-09-09 · Planning bead `blackbird-41d` · [Product contract](PRODUCT.md) · [Design study](DESIGN.md)

## 1. Recommendation

Build one end-to-end correspondence capability across Blackbird, phux, Cockpit, and mobile. Use an independently negotiated provider connection through phux, with a fixed local Blackbird adapter. Keep Blackbird in Go. Share a small public protocol and conformance fixtures; keep native presentation and host-specific agent admission in their existing owners.

```text
Cockpit native service                 Mobile native service
          \                            /
           authenticated provider WSS / local UDS
                           |
                phux provider gateway
         admission · routing · bounds · correlation
                           |
             owner-only local Blackbird socket
                           |
                 Blackbird provider API
       grants · operator identity · immutable correspondence
             durable send receipts · resource references
                           |
                existing agent host adapters
                notify / steer / queue policy

Terminal connections run alongside this path, independently.
Beads keeps task authority. Harnesses keep model admission.
```

The release is direct-host, selected-project, single-operator/multiple-device. A host can register one Blackbird binding initially; the envelope names the binding explicitly. The grammar leaves room for additional bindings without implementing a dynamic plugin system.

**The decisive proof:** create a human message on the phone, lose the response after commit, recover its one receipt on reconnect, read that same message on desktop, open an exact referenced terminal, and return to the thread. Ordinary mailbox browsing must leave agent receipts and delivery cursors unchanged throughout.

## 2. Evidence and architectural prerequisites

Code was inspected at Blackbird `0f8cfdd7fadada2c1772bd46b62882cf8187962b` and phux `747dfde0a4d3bda0578baf81bc9c41421859934e`. Private mobile implementation was inspected separately; public specs contain newly authored interface requirements, not copied proprietary source. Its protocol pin differs from the sibling phux checkout; native implementation must coordinate its pin rather than assume parity.

| Current evidence | Consequence |
|---|---|
| Blackbird [admin transport](https://github.com/phall1/blackbird/blob/0f8cfdd7fadada2c1772bd46b62882cf8187962b/internal/transport/http/admin.go#L24-L45) and [thread contracts](https://github.com/phall1/blackbird/blob/0f8cfdd7fadada2c1772bd46b62882cf8187962b/internal/application/coordination/ports_admin.go#L289-L356) are loopback operator reads; thread messages omit recipients and receipt facts. | Reuse projection logic where appropriate, but add a separately authorized provider API. Do not forward the admin token or claim its current DTOs implement the product. |
| [Current message transaction](https://github.com/phall1/blackbird/blob/0f8cfdd7fadada2c1772bd46b62882cf8187962b/internal/storage/sqlite/operations.go#L214-L358) owns append plus deliveries; [peer mail](https://github.com/phall1/blackbird/blob/0f8cfdd7fadada2c1772bd46b62882cf8187962b/internal/storage/sqlite/peermail.go#L17-L45) demonstrates same-transaction outbox writes. | Extend the existing transaction rather than invent a second mailbox. Peer transport deduplication is not a client-send operation ledger. |
| phux [decoder](https://github.com/no-phux/phux/blob/747dfde0a4d3bda0578baf81bc9c41421859934e/crates/phux-protocol/src/wire/decode.rs#L395-L464) rejects unknown frame kinds. | Arbitrary payload capacity is not an extension mechanism. Provider traffic needs separate service dispatch. |
| phux [auth](https://github.com/no-phux/phux/blob/747dfde0a4d3bda0578baf81bc9c41421859934e/crates/phux-server/src/auth.rs#L87-L128) has credential IDs, principals, scopes, and generations, but current established connections retain an admission snapshot. | Per-operation scope and live-revocation checks are new provider work. Terminal pairing grants no mailbox capability. |
| phux [WSS admission](https://github.com/no-phux/phux/blob/747dfde0a4d3bda0578baf81bc9c41421859934e/crates/phux-server/src/transport.rs#L499-L590) authenticates before frames; `phux-dial` separates establishment from application protocol. | Reuse establishment and pinning; add explicit provider path/subprotocol dispatch and a separate connection owner. |
| Cockpit [provider contract](https://github.com/no-phux/phux/blob/747dfde0a4d3bda0578baf81bc9c41421859934e/clients/cockpit/src/providers/contract.zig#L1-L105) models terminals; [native bridge](https://github.com/no-phux/phux/blob/747dfde0a4d3bda0578baf81bc9c41421859934e/clients/cockpit/src/native_extension.zig#L138-L220) separates completions and input modes. | Mailbox service sits beside the terminal provider. Add bounded mailbox result publication and focus ownership. |

### Decisions that must be reconciled before runtime work

- Blackbird [ADR-0001](../../docs/adr/0001-the-phux-boundary.md) and phux ADR-0095 are **Accepted** and categorically forbid daemon connections. Proposed Blackbird [ADR-0002](../../docs/adr/0002-optional-phux-provider.md) permits only the optional provider route. phux needs a matching decision; this draft cannot silently supersede either accepted record.
- phux ADR-0092 remains **Proposed**. Recommend withdrawing its phux-owned task/work coordinator scope while retaining its separate-endpoint principle. This does not transfer Objectives/Runs/task acceptance to Blackbird. Durable work policy remains a separate future design, informed by Beads and host adapters.
- Reconcile Cockpit's product-direction/agent instructions that currently presume phux owns durable-work policy. Keep resource execution and attachment authority in phux.
- phux ADR-0098/workload-auth is spec-only. This release uses the explicitly narrower pinned-bearer profile below; it does not advertise workload proof, cryptographic host-authority continuity across key rotation, or implemented mutual Ed25519 admission.
- Preserve phux ADR-0030's terminal-wire boundary and ADR-0061's compatibility discipline. Existing AgentSession resources remain independent; Blackbird is the first **external** non-terminal provider.

## 3. Module boundaries

| Owner | New responsibility | Explicit boundary |
|---|---|---|
| Blackbird Go daemon | Provider grants, human participants, typed mailbox API, client-operation ledger, explicit resource references, safe read projections | No terminal lifecycle, task scheduler, or model invocation |
| phux Rust server | Optional gateway, service negotiation, device admission, fixed binding lookup, isolated work budget | No persisted message store, send retry queue, mailbox business rules, or generic HTTP proxy |
| Public provider protocol package | Envelope codec, bounds, request correlation, generated/golden schemas and fixtures | No terminal engine or mandatory UI framework |
| Cockpit | Native service owner, Keychain handles, correspondence state, exact navigation | TS receives bounded presentation, never credentials or borrowed socket buffers |
| Mobile | Independent mailbox adapter/projection, secure local drafts, native navigation and privacy | No continuous background delivery promise or config-sync mailbox archive |
| Agent adapters | Display human authors, retain native notify/steer/queue behavior, explicit resource-link production where supported | Mailbox send does not bypass host admission |
| opencode-beads | Existing task claims, reconciliation, acceptance evidence | No new shared Agent schema or automatic claim from correspondence |

Start with one public schema/fixture source in Blackbird (`api/provider/v1/`, proposed), and envelope fixtures owned by phux. Generate or validate Go/Rust/Swift shapes against these fixtures. Extract a shared Rust provider client only when both native integration spikes demonstrate less duplicated correctness work than FFI cost. Cockpit can consume a transport-neutral C ABI handle; mobile may use native WSS and the same fixtures. Requiring both to adopt desktop's terminal C ABI would be unnecessary coupling.

## 4. Identity model

All identifiers are opaque and compared in their owner scope. Display names, paths, host roster UUIDs, PIDs, and current focus are never identity joins.

```text
MailboxRef = (provider_instance_id, project_id)
ThreadRef  = (MailboxRef, conversation_id)
MessageRef = (ThreadRef, message_id)
OperatorRef = (provider_instance_id, operator_id)
ParticipantRef = (MailboxRef, participant_id)
OperationRef = (provider_instance_id, operator_id, operation_id)

BindingRef = (enrolled_host_binding_id, provider_binding_id)
LiveResourceRef = (enrolled_host_binding_id, owner_incarnation,
                   namespace, resource_kind, native_id)
```

- `provider_instance_id` is a persisted Blackbird database identity, independent of daemon startup. Inspect existing installation identity at schema design time and reuse only if it has these exact reset/restore semantics; otherwise add a dedicated row. Restart preserves it; a new or intentionally forked database gets a new identity. Concurrent clones must be explicitly re-identified before enrollment. Backup restore that rewinds operation history requires a new identity and re-enrollment; restoring under an old identity is forbidden by the operator recovery procedure.
- `project_id` reuses the stable coordination workspace ID. The local project key/path is display and lookup metadata; grants store workspace IDs, not a wildcard path prefix. A project recreated at the same path must not inherit a grant.
- The host binding is a persisted UUID authenticated by an **explicitly enrolled TLS leaf pin** in this release. It is not a workload-authority fingerprint. Every reconnect verifies the pin, then the host binding and provider instance. A TLS pin change or provider replacement requires local confirmation/re-enrollment; there is no automatic trust continuity based on a matching URL.
- Transport/server incarnation remains separate. Terminal opening compares the referenced phux server incarnation to the terminal connection's actual HELLO evidence. Initial resource opening supports directly connected, local-to-that-host terminals only. Satellite references remain descriptive until end-to-end owner evidence is supported.
- One operator has independent device credentials. The author is resolved server-side from the grant, never supplied as a trusted display-name assertion. Agent participant IDs retain current actor identity. Human participants use a distinct kind and stable project participant mapping to existing actor-ID-shaped message columns.
- Human authentication sessions are dedicated provider sessions, not `coordination_agent_sessions`; reads do not mint actors or renew agent heartbeats. Human participant enrollment happens only through explicit owner-local setup. Audit session IDs satisfy existing immutable message provenance requirements without masquerading as an agent registration.

## 5. Authorization and enrollment

### Transport profile: `phux-provider/pinned-bearer-v1` (proposed)

This is a single-owner gateway trust model: phux is trusted to assert the admitted device identity to the local Blackbird provider. It is not end-to-end encryption against the host and not a multi-tenant delegated identity system.

1. Owner-local configuration registers a fixed Blackbird socket and provider identity in phux. Blackbird issues a separate bridge credential, stored owner-only by phux; it is never the admin handshake token or an agent registration token.
2. Local enrollment selects an operator, exact existing projects, and read or read-and-send rights. Blackbird creates human participant mappings and grants bound to `(bridge_id, phux_credential_id, credential_generation)` and operator. phux creates a separate provider credential with `provider.blackbird.read` and optionally `provider.blackbird.send`. Neither includes `terminal.control` implicitly.
3. Provisioning stages inactive records and enables them only after both sides agree. A failed setup emits no usable device credential; retry reconciles by enrollment ID. CLI output transfers the provider endpoint, subprotocol, host/provider binding IDs, TLS pin, and device secret through an explicit import/QR workflow. Secrets are not embedded in navigational thread links or ordinary host-roster sync.
4. Native clients store the device credential in a provider-specific device-local Keychain namespace. Non-secret metadata may be stored separately. Missing, locked, expired, revoked, and mismatched identity have distinct error states.
5. Every request is admitted by phux against the **current** credential record/generation/expiry/scope. The gateway supplies an assertion of admitted credential ID/generation over its authenticated local bridge. The client cannot set assertion fields. Blackbird looks up its own current grant and derives the operator/project permission; it never accepts client-authored principal claims or a bridge-only blanket grant.
6. No credential, grant, or operator field is carried in a URL query or logged body. Tokens may be read only by the native service/transport owner. Redirects are refused. Provider reads use no shared cookies or HTTP cache.

The local Blackbird listener is a new owner-only UDS API, explicitly enabled and authenticated even for local calls. Use filesystem permissions plus the bridge credential; do not assume a client-supplied local header is proof of OS ownership. phux's local provider UDS requires the same device credential, rather than making local mailbox use an undocumented bypass. Its framing begins with a bounded credential admission record before provider HELLO. The credential remains local transport metadata, not provider payload.

### Enforcement, revocation, and races

- phux authorizes before binding lookup/forwarding, and Blackbird authorizes before reading or writing a scoped object. Wrong-project identifiers return scope-safe not-found/denied results without revealing another project.
- Each response is rechecked against current gateway authorization before publication. Project-grant changes also increment a durable Blackbird `access_generation` per device binding. An internal bridge-only `access.inspect` returns current generation, granted projects, and operator; it is not part of the remote operation catalog. The gateway calls it before publishing a read response and on its lease tick. A response from an older grant generation is discarded and retried as a fresh authorized read, never relabelled with the new generation. Project removal therefore works even when the gateway credential's broad read scope is unchanged.
- Read authorization linearizes at the final successful provider-grant check. A subsequent revoke cannot retract bytes already authorized for publication. The gateway sends the new access generation or closes the provider connection when it observes a reduction; the client clears removed scopes and fences old in-flight completions by connection and access generation. Once a client has observed access loss, a late response cannot repopulate that scope. A maximum five-second lease tick rechecks both the current gateway credential and Blackbird grants, including on idle connections. If Blackbird cannot revalidate, the service becomes unavailable and no protected response is published; previously observed content is stale, not falsely labelled revoked.
- Blackbird checks its current project grant inside the send transaction, serializing **Blackbird grant revocation** with sends through its write arbiter. A send whose transaction follows that revocation fails; one that commits first may succeed. **Gateway-only revocation** prevents newly authorized forwarding and publication, but a request already dispatched to Blackbird can still commit. Such a client's pending send is Outcome unknown, not Not sent. No distributed transaction between daemons is promised.
- An offline client cannot learn an unseen remote revocation; retained in-memory content is explicitly stale, and authorization must succeed before any new read/send. Revocation/expiry observed authoritatively removes affected content; reduced grants may preserve other project views under the new access generation.
- Grant reductions apply on existing connections. Credential rotation explicitly binds the new generation; overlap is granted deliberately, not inferred. Removing one device does not change the operator's identity or revoke another device.
- An owner-local revoke operation disables both gate and grant; if one side is unavailable, revoking the reachable gate is sufficient to stop new routed requests and setup reports the unreconciled counterpart. Removing a bridge disables every grant under it. There is no remote grant-management operation in the mailbox catalog.

## 6. Provider service transport

**WSS first, plus local UDS.** Proposed WSS path `/providers/v1` and required subprotocol `phux.providers.v1`; allocate/register names during the phux boundary milestone. Use a separate socket connection on the existing TLS listener with service dispatch before terminal decode. Wrong path/subprotocol fails at upgrade and never falls back to terminal dispatch. Existing terminal upgrade behavior and frame goldens remain intact. If sharing the listener cannot preserve that behavior, use an explicit separate provider listener as an implementation decision at the same milestone.

No terminal HELLO, viewport, bootstrap, resource ID, or ATTACH is required. Direct routable WSS is the initial remote path. Existing NAT relay, satellite routing, and QUIC do not automatically carry this service; support for them is deferred. A later QUIC binding can use a distinct ALPN and the identical envelope without altering terminal streams.

### Envelope

One UTF-8 JSON envelope per WSS message; UDS uses `u32` big-endian byte length plus that same envelope. Do not reuse terminal `FrameKind`. Reject duplicate JSON keys, invalid UTF-8, invalid discriminants, nested depth over 32, and integers outside the specified safe range. Unknown optional fields can be ignored; unknown operation or major version is an explicit error. Capabilities are the intersection of implementation and current grants, not authorization in themselves.

```json
{"type":"hello","version":1,"contracts":["blackbird.mailbox/v1"]}
{"type":"hello_ok","version":1,"host_binding_id":"…","max_frame_bytes":1048576}
{"type":"request","request_id":"17","binding_id":"local-blackbird",
 "contract":"blackbird.mailbox/v1","operation":"thread.read",
 "payload":{"project_id":"…","conversation_id":"…","limit":40}}
{"type":"response","request_id":"17","provider_instance_id":"…",
 "result":{"messages":[],"observed_at_us":1789000000000000}}
```

Envelope operations: `hello`, `hello_ok`, `discover`, `request`, `response`, `cancel`, `error`. Discovery is restricted to authorized bindings and returns provider identity, negotiated contract, availability, readable project IDs/display labels, operator identity, actions, and lowered limits. Lack of a binding can be reported without probing a daemon; a configured stopped provider is `unavailable`.

Connection request IDs only correlate attempts. No reuse while pending; results are fenced by connection generation and binding identity. `cancel` ends waiting/cancels reads best-effort; it never certifies mutation rollback. phux never retries a send or queues it durably.

### Default bounds (contract ceilings; implementations may advertise lower)

| Resource | Ceiling / behavior |
|---|---|
| Envelope | 1 MiB encoded, checked before allocation; oversized frame closes service connection |
| Pending requests | 8 per device; 2 concurrent provider calls per device; overload fails promptly |
| Gateway global provider concurrency | 16, isolated from terminal dispatch and SQLite housekeeping |
| Admission / hello | 10 seconds each |
| Read/send forwarding deadline | 15 seconds; send deadline returns outcome-unknown after possible dispatch |
| Outbound queued data | 4 MiB per connection; slow reader disconnects rather than blocking terminals |
| Page | Up to 100 items **and** 512 KiB encoded payload; advance only over returned complete items |
| Message body | Existing 256 KiB UTF-8 stored limit; paged previews plus `message.read` avoid JSON escaping overflow |
| Subject / recipients | Existing 512-byte subject and 256-recipient storage ceiling; first client limits To selection to 32 |
| References | At most 16, at most 2 KiB each |

JSON escaping can exceed frame capacity even for a valid stored body. `message.read` therefore returns bounded UTF-8-safe body chunks, each bound to the immutable message digest and byte offset; default at most 64 KiB unescaped per chunk. Summary/thread pages carry a bounded preview and `body_complete`/full-body handle. Send bodies use a canonical base64-encoded UTF-8 field in the provider contract, bounded before decode and validated after decode, so the existing 256 KiB limit fits within the 1 MiB envelope even for control-heavy text. Clients assemble a full message explicitly; never silently truncate it. Count encoded bytes for every response, not just raw content size.

`error` carries a closed code, safe display reason, optional field errors, and whether retry is appropriate. Minimum codes: `unauthorized`, `forbidden`, `not_found`, `unsupported_contract`, `unsupported_operation`, `provider_identity_changed`, `unavailable`, `overloaded`, `invalid`, `cursor_invalid`, `conversation_closed`, `recipient_unavailable`, `operation_conflict`, `outcome_unknown`. A transport-level failure after dispatch cannot become a definitive `not_sent` result.

## 7. Blackbird mailbox operations

The gateway resolves server-configured `(binding, contract, operation)` to a fixed adapter. Clients cannot supply an HTTP method, destination URL/socket, header, redirect policy, or arbitrary port. Blackbird owns operation schemas and response semantics; phux knows envelope permissions and the fixed adapter allowlist.

| Operation | Contract |
|---|---|
| `participants.list` | Granted project; paged stable participant IDs, human/agent kind, label, local/peer origin and explicit send eligibility. Does not renew agents or infer readiness to work. |
| `conversations.list` | Granted project; keyset page ordered by latest message position then conversation ID; empty conversations use their open position/tie-break. Explicit visible-participant and outstanding-visible-ack filters. |
| `thread.read` | Exact project and conversation; paged immutable message headers/previews, author identity, visible receipt facts and references. Initial view returns latest bounded page; before/after cursors retrieve history. |
| `message.read` | Exact scoped message and digest-bound chunk offset; full content reconstructed without clipping. |
| `message.send` | New conversation with topic or reply in existing conversation, explicit To IDs, body, acknowledgement requirement, optional reply target/references; stable operation ID. |
| `operation.get` | Exact operation ID, current operator and project; returns accepted receipt, recorded rejection, or absent. No access to another operator's intent. |

No read/ack mutation, lease operations, generic events API, global admin API, or remote enrollment is exposed. A “handoff” is an explicit human message addressed to chosen agents with optional context references. It is not a new task/run state machine. A future accepted/declined handoff protocol would require its own product decision and cannot be inferred from acknowledgements.

Recipient eligibility is independent of liveness and participant kind. Existing peer mail creates shadow actors in `coordination_agents`; runtime eligibility must use durable origin metadata rather than parse display names or filter inactive sessions. Add an explicit actor-origin migration: current storage deliberately encodes peers in the reserved `agent@host` namespace (migration 0013), and it does not retain a separate durable relationship for every peer. Migration-time interpretation of that reserved legacy namespace is permitted for backfill; outbox/inbound rows are supporting evidence, not a required surviving join. Validate legacy shape and leave ambiguous historical records ineligible until resolved, rather than guessing a local send target. New local/peer creation writes origin metadata atomically, and outbox retention never deletes it. Preserve peer authors/recipients in history with `send_eligible=false` and a peer-route-unavailable reason. Reject their IDs before accepting a provider send; this release does not enqueue the peer outbox. Ordinary offline local agents remain valid recipients.

Because there is no human acknowledgement operation, every send path that can address a new human participant rejects `acknowledgement_required=true` if any recipient is human, including mixed sets and extended local agent sends. Return a specific validation reason; do not silently clear the flag or satisfy it by browsing. Agent→human replies use ordinary messages without requested acknowledgement. Enrollment does not convert an old agent with existing obligations into a human.

### Pagination and refresh

- Use opaque authenticated cursors bound to provider, project, operation, filters, and append high-water mark; reject scope/version mismatch. No raw SQL offset paging. Cursor signing key persists with provider identity.
- Conversation ordering during a page traversal is computed from messages at or below the captured high-water mark. The traversal does not silently reorder when new messages arrive. Empty-conversation creation requires a comparable durable ordering marker in the new provider projection. Mutable receipt/status values are observed at each request's timestamp, not falsely claimed as one historic snapshot.
- Every response comes from a single SQLite read snapshot with `observed_at_us`. Message identity/position deduplicates appended pages. Receipt changes update those records without modifying immutable content. If a cursor expires or schema changes, discard traversal cursors and reload around the selected message; do not discard a draft.
- First release uses foreground polling, not a new event stream. Refresh the conversation head and selected visible thread window every five seconds while active; refresh immediately on foreground/reconnect and after a known send receipt. A visible-window refresh rereads receipt facts, including old messages; polling only new message positions would miss acknowledgements.
- No overlapping poll per scope. Bound each cycle to the two visible surfaces; pause hidden/background views. Back off connection failures with jitter up to 30 seconds. Manual retry is available. New arrivals update list state and a New messages count without moving focus or the reading anchor.
- Refresh errors preserve the last complete projection as stale. Partial pages from mismatched identities, request generations, or changed selection are discarded. Pagination fetch is user-driven and must not starve refresh/send capacity.
- No existing host-delivery cursor is consumed, acknowledged, or reset. The current coordination event journal is not exposed as a lossless operator subscription. Avoid a second event log until a measured polling limitation warrants one.

### Recipient visibility

Provider project-wide reads intentionally grant all bodies, unlike an agent inbox. To/Cc addresses and associated facts may be projected. Bcc identities/facts are suppressed unless the authenticated operator authored the message; the initial client never sends Bcc. List filters, participant counts, acknowledgement badges, and previews use only visible delivery facts. A hidden Bcc delivery alone must not make a participant-filtered thread match or create a pending-ack badge. The participant directory is an independent project roster and does not expose which messages were Bcc'd to a member.

## 8. Human authorship and reliable writes

### Proposed persistence

Add schema migrations for provider identity, operators, project human-participant mappings, durable actor-origin metadata and legacy peer backfill, bridge/device grants, provider authentication sessions, immutable message references, and the operation ledger. Exact table names are implementation details, but required keys and transaction boundaries are not:

```text
operator project participant: UNIQUE(operator_id, workspace_id)
grant: UNIQUE(bridge_id, credential_id, generation, workspace_id)
operation: PRIMARY KEY(operator_id, operation_id)
           workspace_id, canonical_request_digest, terminal_status,
           conversation_id?, message_id?, rejection_code?, committed_at
reference: (message_id, ordinal), typed reference, author provenance
```

Ledger keys are implicitly scoped to the database's provider identity. Receipts and digest tombstones live for the provider lifetime in this version; do not garbage-collect an operation key and later accept it as a new send. Body storage need not be duplicated in the ledger. A future retention policy must keep conflict detection or introduce explicit operation epochs before deleting keys.

### Send transaction

1. Validate bounded wire shape; resolve the operator and exact workspace from the authenticated grant. Parse the intent into a canonical typed representation. Normalize To IDs by sorting/deduplicating; preserve body bytes exactly. Hash every semantic field, including project, new/reply mode, topic, reply ID, acknowledgement flag, body bytes, and ordered references. Reject unknown mutation fields rather than ignoring future semantics.
2. Enter Blackbird's existing immediate-write transaction. Recheck current grant; look up `(operator, operation_id)`. Same digest returns the original terminal receipt; different digest returns `operation_conflict`. Check this before mutable conversation/recipient validation so a valid replay still returns its original result after a conversation closes.
3. For a new key, validate exact project, open conversation/reply target, human participant, and selected recipients. A definitively refused semantic intent may be recorded as a terminal rejected operation, without creating a conversation/message. Shape/auth failures before ledger admission are explicitly unrecorded and cannot be mistaken for a saved receipt.
4. New-thread creation, one message append, To deliveries, existing coordination events needed by adapters, resource references, and the accepted operation receipt commit atomically. Extend/reuse `sendMessageTx`; never recreate the event and receipt rules in a second writer. No async bridge call or model invocation occurs inside this transaction.
5. Return the canonical conversation ID, message ID, message position, body digest, and saved timestamp only after commit. A rolled-back transaction returns no saved receipt. A lost response does not erase the ledger.

Make human-kind metadata available to current plugin reads and agent delivery rendering, including queries currently joining only `coordination_agents`. Every author/recipient directory and conversation projection must handle both kinds without rewriting existing agent identity or token behavior. Agent→human replies can be addressed to the enrolled human project participant; the human mailbox projection does not register a fake active agent. Existing local send recipient resolution must be extended additively to expose human participants where needed, with unambiguous handles; legacy agent-only clients continue their previous behavior.

### Client recovery state machine

```text
Draft --explicit Send/persist frozen intent--> Submitting
Submitting --accepted ledger receipt-------> Saved (clear that frozen intent)
Submitting --recorded/definitive rejection--> Not sent (retain editable draft)
Submitting --disconnect/timeout/crash-------> Outcome unknown
Outcome unknown --operation.get accepted---> Saved
Outcome unknown --operation.get rejected---> Not sent
Outcome unknown --operation.get absent-----> unresolved; offer retry SAME intent/key
```

`absent` is not proof a concurrent request cannot still commit. Exact-key retry is safe because the write transaction serializes deduplication; a new key is not safe. phux and background reconnect never auto-resubmit. A user-triggered retry reuses the frozen original scope, payload, and key. Concurrent edits are a separate draft and are never cleared by an earlier receipt.

For the original first attempt, a locally proven pre-dispatch refusal can resolve Not sent. After any uncertain attempt, an unrecorded refusal of `operation.get` or a retry—including forbidden, unavailable, malformed request, or gateway-only revocation—does **not** resolve that earlier outcome. Only the accepted ledger receipt, a recorded rejection for the same digest/key, or proof the original intent never left the client resolves it. Access loss hides the content while retaining its frozen identity for later authorized recovery. A provider identity change isolates the old unresolved intent; it is never replayed into the replacement database.

Write the frozen intent to protected local storage before dispatch. If persistence fails, Send fails locally and no request leaves. Persisted pending intents become Outcome unknown after process restart; connect and check status before offering retry. Dismissing/canceling a send only stops waiting. Revalidation after credential rotation resolves the same operator operation IDs under a newly explicit grant; it never changes author identity to the new device.

## 9. Resource references and navigation

Use an explicit bounded typed reference on an immutable message, with source author and optional source-message ID. Schema namespace examples are `phux.terminal/v1`, `opencode.session/v1`, and `blackbird.message/v1`; only the first and last have navigation actions in this release. Namespace strings are a catalog, not executable URI schemes. Unknown namespaces are descriptive/copyable and cannot select a network destination.

Terminal references carry the enrolled host binding, actual owner/server incarnation, resource kind, and native terminal ID. Before activation the client resolves the **exact host** through enrolled metadata, establishes/uses its ordinary authorized terminal connection, verifies incarnation, then resolves the exact terminal. Desktop may activate an existing placement in another window. A lost resource or mismatched incarnation returns unavailable, never “best matching terminal.” Opening checks terminal input/attachment policy independently.

Human composers can explicitly link an inspected live resource whose identity the client knows. Agent adapters may produce references from explicit host session bindings; they must not use plugin-instance-wide mutable “last created terminal” state. Session-scoped targeting is an implementation dependency for agent-generated links, not a prerequisite for read-only mailbox browsing. The initial UI permits only verified direct-host resource selection; unsupported/satellite references remain readable.

Copyable thread references are inert, token-free structured references. Registering OS-wide deep-link handlers, account routing on cold launch, and cross-host automatic connection are deferred. In-app thread/resource round trips are required now; unsupported external links must not imply those routes already exist.

## 10. Native clients and local persistence

### Cockpit

Add a mailbox service next to `src/providers/phux`, not inside the terminal grid provider contract. Preserve the Zig owning-thread rule for native handles and completions. Use an independent bounded request/result path; current snapshot/navigation completion slots must not be overwritten. Socket workers stage bounded data and wake the UI; their notification channel's small message ceiling is not a conversation transport. Large content is chunked/paged behind the native service.

Expose typed summary/thread/composer state through the existing AOT TS/native chrome. Native interaction modes suspend terminal input while editing or navigating a mailbox modal. Test that message text and keyboard shortcuts cannot reach a hidden terminal. The new service requires WSS+pinning support for remote desktop use; the current Unix/TCP terminal worker is not evidence of that capability.

### Mobile

Implement a separate native mailbox service and observable projection. Reuse platform secure storage, privacy covering, foreground transitions, and exact resource navigation principles, not terminal credentials or terminal frame decoding. Public protocol fixtures are shared; private mobile implementation remains private. Evaluate native WSS against the provider C ABI in the early spike; choose the smaller implementation that passes the same conformance suite.

Foreground/resume verifies identity and grants before polling. Background cancels refresh and covers bodies/drafts under app-switcher privacy. No APNs, push registry, or background stream is claimed. Cold app launch can reopen a saved **non-secret selection** only after correct authorization; no full mailbox bodies survive termination in this version.

### Protected device-local drafts and pending intents

- Store content in an app-private encrypted file/database; random content-encryption key lives in the device-only Keychain. On iOS apply complete file protection and exclude content from cloud/config backup; use equivalent owner-only encrypted persistence on desktop.
- Key records by provider, operator, project, conversation (or new-thread local draft ID). Pending intent also stores operation ID, canonical payload/digest, and original grant scope metadata. Device metadata, TS snapshots, diagnostics, and settings sync contain no draft bodies or secrets.
- Keep unsent drafts until explicit send/delete/forget; do not expire unresolved intents silently. Forget provider/account offers local deletion and removes content/key association. Revocation hides content; it remains inaccessible to another operator and cannot send. Local delete is always available. Regrant to the same operator may unlock a retained draft after fresh identity verification.
- Keychain locked/unavailable is not “no draft”; show a recoverable locked state. A corrupt intent is not auto-dispatched or silently replaced. Emit content-free diagnostics and allow local deletion.

## 11. Verification and implementation gates

Each milestone carries concrete tests in Beads. This matrix is the acceptance contract, not a claim that runtime tests have already passed.

| Area | Required evidence |
|---|---|
| Boundary/compatibility | Terminal wire goldens unchanged; old terminal client on new host; provider-only connection without ATTACH; unsupported path/version explicit; disabled/stopped Blackbird leaves terminal interaction usable |
| Authorization | Terminal-only and ungranted provider credentials denied; forged project/operator/assertion denied; Bcc filter/count side channels covered; project removal with unchanged gateway scope; revoke/expire on existing connection; rotation overlap; generation-fenced late response after observed revocation |
| Identity | Two providers reuse conversation ID without collision; restart preserves DB identity; replacement/rewound restore fences intents; TLS pin mismatch fails closed; copied display path cannot select a grant |
| Writes | Concurrent same-key submissions create one message/thread/event set; payload conflict refuses; response loss after COMMIT recovered; absent lookup races original send safely; closed-thread replay returns original receipt; Blackbird grant revocation ordered before send transaction fails; gateway-only revoke after dispatch and unrecorded recovery refusals preserve unknown outcome |
| Reads | Browsing changes no registrations/receipts/leases/host cursors; pagination over large bodies; heavily escaped UTF-8; chunk digest/offset verification; receipt refresh without new message; wrong cursor scope; stable page ordering under new arrivals |
| Agent interoperability | Human authors render correctly in existing adapters; human To recipients resolve without fake agents; acknowledgement-required human/mixed sets rejected on all extended sends; peer shadows cannot become local-send targets, including an outgoing-only peer whose outbox history expired before migration; offline local agents remain eligible; delivery follows host mode; browse never prompts a model; selected session/resource cannot drift between simultaneous host sessions |
| Native lifecycle | Correct thread on both devices; protected drafts survive restart; unknown intents reconcile; changes after Send survive an older receipt; locked keychain; revocation purge; background/foreground stale state; forgotten account fences completions |
| Native interaction | Desktop keyboard focus and no terminal-input leakage; exact resource opening/return anchor; mobile VoiceOver, Dynamic Type, safe areas, 44-point targets, reduced motion and privacy overlay |
| Isolation/load | 10k-message project with page ceilings; slow reader; provider restart; saturated provider concurrency while terminal input remains responsive; all queues and retries bounded |

Project gates at implementation time: Blackbird Go/race suites plus plugin `npm run check`/tests and installed-package smoke when touched; phux protocol/client/server focused tests and updated spec/changelog, then `just cockpit-test` for desktop; mobile pinned `mise`/`just` gates including `just ci`, wire-feature coverage, network chaos and `just a11y-audit` when affected. Record exact source revisions and compiled bridge coverage. The HTML study gets browser interaction/layout checks; it is not native accessibility or runtime-integration evidence.

## 12. Sequencing and decision gates

1. **Ratify boundaries and contract.** Approve PRODUCT.md and proposed ADR; reconcile phux/Cockpit authority docs. Freeze identity, grants, body representation, operation semantics, and transport fixture examples. No implementation bead becomes Ready before this explicit approval gate.
2. **Prove the provider lane.** phux WSS/UDS negotiation, bounded gateway and credential enforcement with a small test provider; a thin client in both native stacks. Demonstrate no terminal dependency and quantify bridge/codec cost before choosing shared Rust FFI versus native mobile codec.
3. **Ship read-only vertical slice.** Blackbird scoped projections, human enrollment/grants, desktop and mobile list/thread states, freshness, pagination, and zero receipt side effects. Use this to review real native UI, long bodies, and accessibility before send complexity.
4. **Add transactional human correspondence.** Blackbird operation ledger and participant interoperability, then protected drafts and recovery UI on both clients. Kill the connection immediately after commit as the milestone's headline demo.
5. **Close the resource round trip.** Exact direct-host references, native navigation, host-adapter session targeting and return position. Full desktop/mobile conformance and fault matrix before enabling broadly.

Only after these pass should a second first-party provider (for example, read-only Beads task context) test what deserves extraction into an extension SDK. Executor is a later provider for external tool discovery/invocation, not a dependency for mail or a substitute for durable identity. Go-to-Rust Blackbird migration has no acceptance benefit in this plan and is not scheduled.

The scope intentionally does not estimate calendar delivery from unimplemented auth/FFI seams. Size relative lanes first: provider authorization and human-write reconciliation are the high-risk/high-effort pieces; read projection and native visual iteration can proceed in parallel after the contract is frozen. Re-estimate with measured results from the two-client transport spike.
