# Use-case catalog

> **Authority:** Experimental sidecar product map derived from accepted targets  
> **Related:** [States](04-state-machines.md) · [Operation registry](06-operation-registry.md) · [Sequences](12-sequence-diagrams.md)

## Roles

| Role | Typical authority |
|---|---|
| Installation owner | initialize local authority; create first workspace |
| Workspace administrator | membership, actor, delegation, integration and policy administration |
| Human operator actor | objectives, runs, acceptance, decisions, provider transitions |
| Agent actor | participate, message, lease, request decisions, attach evidence |
| Service principal | narrowly scoped provider observation, verification, projection or deadline action; never invents an actor session |
| Desktop client | command/query projection and direct runtime-stream composition |
| Mobile client | attention, bounded decision resolution and offline sync |
| Provider adapter | authenticates one external authority and records provenance |
| Operator/SRE | install, migrate, backup, restore, inspect and recover without becoming a work actor |

## Capability inventory

The status column describes reference maturity, not sidecar completion.

| Family | Use case | Reference status | Sidecar acceptance outcome |
|---|---|---|---|
| Installation | Initialize a fresh authority | `reference_implemented` (scaffolding only; production proof path incomplete) | one invitation; one first principal/device/owner grant or none |
| Workspace | Create/suspend/reactivate/archive workspace and initial owner | `reference_implemented` for create; `target_adopted` lifecycle | distinct identity, owner membership and exact legal lifecycle |
| Identity | Register/suspend/reactivate/disable principal | `reference_implemented` for register; `target_adopted` lifecycle | typed principal with bounded credentials and no implicit Actor |
| Membership | Invite/accept/suspend/reactivate/revoke member | `reference_implemented` invite/accept; `target_adopted` lifecycle | purpose-bound handoff, exact version, current capability ceiling |
| Actor | Create/suspend/reactivate/retire persona and delegate principal | `reference_implemented` create/delegate; `target_adopted` lifecycle | actor authorship distinct from authentication |
| Device | Pair/suspend/reactivate/revoke device | `reference_implemented` contracts; fail-closed production handler | proof-bound trust revision and narrow grants |
| Session | Start/end/resume transport binding | `reference_implemented` contracts; fail-closed production proof handler | active domain session or typed recovery posture |
| Context | Get checkpoint and sync deltas | `reference_implemented` | bounded authorized snapshot plus opaque cursor |
| Work | Observe tracker reference and transition native WorkUnit | `reference_implemented` observation; `target_adopted` WorkUnit lifecycle | cached provider provenance plus locally owned responsibility |
| Objective | Create/activate/satisfy/abandon objective | `reference_implemented` create/activate; `target_adopted` terminal lifecycle | local durable intent without tracker-field ownership |
| Formation | Define immutable revision | `target_adopted` | versioned team shape without live topology mutation |
| Run | Plan run with participants/bindings | `reference_implemented` | all initial identities/facts atomically or none |
| Participation | Join/finish/withdraw responsibility | `reference_implemented` join; `target_adopted` finish/withdraw | independent participant version/evidence |
| Runtime | Register/pair/suspend/revoke endpoint; launch/reconcile binding | `target_adopted` beyond requested binding | safe saga, no blind retry after ambiguous spawn |
| Conversation | Open/close durable scope | `reference_implemented` adjunct | canonical session-authorized aggregate on both engines |
| Message | Send/reply with To/Cc/Bcc | `reference_implemented` adjunct To-only | immutable message and all recipient obligations atomically |
| Delivery | available/read/ack independently | `reference_implemented` adjunct | independent monotone per-recipient facts and privacy |
| Lease | exact/subtree shared/exclusive | `reference_implemented` adjunct | atomic overlap decision, authority-time expiry, composite fence |
| Fence | perform protected mutation | `target_adopted` / partial adjunct | fence comparison coupled to mutation or explicitly advisory |
| Decision | request/resolve/cancel/expire | `target_adopted` | typed response and one terminal outcome |
| Attention | queue/deliver/show/see/dismiss/resolve | `target_adopted` | independent occurrence, delivery generation and receipts |
| Artifact | declare/upload/finalize/attach/quarantine | `target_adopted` | no readable partial; verified digest/size/media |
| Completion | request and accept run completion | `target_adopted` | acceptance revision and exact evidence snapshot |
| Provider transition | request/confirm/reject tracker change | `target_adopted` | pending until causally correlated authenticated observation |
| Search | authorized full-text search | `target_adopted` | stable result contract and no visibility leak |
| Projection | rebuild and atomically swap | `target_adopted` | equivalent hashes/high-water before switch |
| Backup | online backup and manifest | `reference_implemented` SQLite | canonical DB + cursor + artifacts + key metadata tied together |
| Restore | sealed verification and promote | `reference_implemented` partial; `target_adopted` full fencing | no writes until authority/dependency gates permit |
| Federation | proposal/accept/sync/authority transfer | `deferred` | signed, audience-bound, one authority; no DB merge |
| Operations | install/status/update/uninstall | `reference_implemented` | independent signed sidecar lifecycle and retained data |

## Principal workflows

### Bootstrap and session

**Preconditions:** fresh migrated database, one short-lived invitation, client device key and protected local channel.  
**Success:** invitation consumed; first principal, trusted device and owner grant commit atomically; workspace/actor/delegation/session follow through distinct commands and ceremonies.  
**Adverse:** duplicate proof, wrong purpose, expiry, fifth invalid proof, response loss, or revoked grant yields the specified replay/rejection without a second identity.

### Conduct a coordinated run

1. observe or create work;
2. create and activate objective/work unit;
3. plan run, participations and requested bindings atomically;
4. participants join;
5. start run;
6. dispatch/reconcile runtime bindings;
7. activate run after start policy;
8. coordinate through messages, leases and decisions;
9. verify/attach artifacts and finish participations;
10. request and accept completion;
11. separately request any tracker transition.

### Recover a disconnected client

A wake hint triggers `events.sync`. If the cursor is invalid/expired/scope-mismatched, the client obtains `context.get`, applies the checkpoint atomically, then resumes deltas from its server-issued cursor. No message or delivery state changes merely because data was fetched.

### Recover a runtime

Watcher loss marks health unknown/degraded. Authenticated inventory under the expected endpoint/incarnation either confirms the target, proves orphaning, or leaves reconciliation pending. An orphaned binding is superseded and a successor is requested. The run, actor, conversation, leases and decisions retain identity.

### Resolve attention offline

The Decision and initial occurrence/delivery exist before notification. Provider delivery can retry while offline. Mobile later authenticates, fetches canonical decision/version, resolves once, and syncs. A source-condition worker separately resolves the occurrence from the Decision event.

## Administrative workflows

- rotate/revoke credentials and invalidate sessions;
- rotate authority epoch during restore/failover;
- inspect/retry/park outbox jobs without fabricating domain facts;
- rebuild projections in shadow tables and verify before swap;
- online backup, artifact pinning and sealed restore validation;
- export a signed offline snapshot;
- import approved non-authority historical data into a separate sidecar workspace;
- generate redacted diagnostic bundles;
- upgrade immutable migrations with previous-release rehearsal.

## Non-use-cases

The following must be rejected as category errors:

- “message the agent” by sending terminal keys;
- infer an actor from tracker assignee, model name, pane or process;
- mark read when a notification provider accepts delivery;
- retry a possibly accepted non-idempotent provider operation blindly;
- use a client wall clock to expire a lease;
- treat SSE/WebSocket delivery as the event journal;
- restore over an active database;
- import active credentials, leases or runtime ownership from Blackbird;
- mutate tracker priority/status by editing the WorkReference projection.
