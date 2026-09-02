# Sidecar operation registry

> **Authority:** Proposed experimental registry skeleton; E0 MUST complete every adopted row before product implementation  
> **Related:** [Contracts](06-contracts.md) · [UoW](08-consistency-uow.md) · [Roadmap](effect-v4/08-roadmap-conformance.md)

This registry is the sidecar's implementation authority once reviewed and promoted to **Accepted**. The Blackbird catalog is reference input, not a substitute. Every adopted operation receives a machine-readable companion record containing full request/result/event schemas and the fields below.

## Required entry shape

```text
OperationEntry
  operation + major
  maturity/status
  authority class and capability
  scope and actor/service attribution
  command and secondary receipt identity variant
  fingerprint inclusions/exclusions
  declared guards and canonical lock keys
  read set / create-absence set / write set
  synchronous transition and commit set
  exact events: type, origin, version, ordinal
  outbox intents and handler contract
  result resource/version/cursor
  operation-specific typed errors and safe details
  limits and recovery-capsule policy
  HTTP/MCP/admin exposure
  SQLite/PostgreSQL invariant mechanism
  fixtures and verification IDs
```

No handler/UoW/migration for an operation may land while these fields remain unspecified.

## E0 proof operation

| Field | Decision |
|---|---|
| Operation | `sidecar.workspace.create.v1` |
| Authority | authenticated installation owner on paired channel |
| Scope | preallocated new Workspace; consult installation provisioning scope |
| Secondary receipt | workspace variant `(workspace_id, principal_id, client_instance_id, operation_major, key)` |
| Fingerprint | includes new workspace/owner membership IDs, principal, alias/discovery locator, policy revision, expected owner/grant revisions; excludes request/deadline/route/requested authority ID+epoch |
| Guards | installation admission epoch/current witnessed writer generation/policy, owner Principal/Grant exact versions, Workspace and owner Membership absent, new workspace stream absent |
| Read set | installation authority/admission, owner Principal/Grant/policy |
| Write set | Workspace v1, owner Membership v1, workspace admission/stream genesis, receipt, audit, events |
| Commit | Workspace + owner Membership + stream/admission or none |
| Events | `sidecar.WorkspaceCreated`, `sidecar.WorkspaceOwnerMembershipProvisioned` with exact origins/ordinals specified in fixture |
| Effects | none required |
| Errors | common set plus authority/reference/absence/policy conflicts |
| Capsule | required retryable-create plan |
| Exposure | disposable E0 direct harness + product HTTP/MCP adapters used only by the vertical proof; permanent MCP exposure remains omitted unless separately adopted |
| DB invariants | unique Workspace/Membership IDs and scoped owner membership; locked installation provisioning guard; no plain check-then-insert |
| Proof | apply/replay/reuse/stale/revoked/crash/commit-loss on both engines |

## Adopted command families

The following names are reserved; each row remains `target_adopted` until its detailed machine record exists.

### Installation and identity

| Operation | Atomic/primary set | Exact accepted facts | Exposure |
|---|---|---|---|
| `sidecar.installation.bootstrap.v1` | invitation + first Principal + initial Credential + trusted Device v1 + owner Grant | `sidecar.InstallationBootstrapped`, `sidecar.PrincipalRegistered`, `sidecar.CredentialCreated`, `sidecar.DeviceBootstrapProvisioned`, `sidecar.InstallationOwnerGrantCreated` | local bootstrap |
| `sidecar.principal.register.v1` | Principal + initial Credential | `sidecar.PrincipalRegistered`, `sidecar.CredentialCreated` | admin |
| `sidecar.workspace.create.v1` | Workspace + active owner Membership v1 | `sidecar.WorkspaceCreated`, `sidecar.WorkspaceOwnerMembershipProvisioned` | product/admin; disposable MCP proof adapter in E0 |
| `sidecar.workspace_member.invite.v1` | Membership + ceremony | `sidecar.WorkspaceMemberInvited` | admin |
| `sidecar.workspace_membership.accept.v1` | Membership + ceremony consume | `sidecar.WorkspaceMembershipAccepted` | restricted pre-session |
| `sidecar.actor.create.v1` | Actor | `sidecar.ActorCreated` | admin |
| `sidecar.actor_delegation.propose.v1` | Delegation + ceremony | `sidecar.ActorDelegationProposed` | admin |
| `sidecar.actor_delegation.activate.v1` | Delegation + handoff | `sidecar.ActorDelegationActivated` | restricted pre-session |
| `sidecar.pairing.challenge.issue.v1` | Device + ceremony | `sidecar.DevicePairingBegan` | product |
| `sidecar.pairing.challenge.redeem.v1` | Device + ceremony consume | `sidecar.DevicePaired` | product |
| `sidecar.session.challenge.issue.v1` | issued ActorSession + ceremony | `sidecar.ActorSessionIssued` | restricted pre-session |
| `sidecar.session.challenge.activate.v1` | ActorSession + ceremony consume | `sidecar.ActorSessionActivated` | restricted pre-session |
| `sidecar.session.start.v1` | directly active ActorSession + equivalent trusted-device/handoff proof | `sidecar.ActorSessionStarted` | HTTP/MCP |
| `sidecar.credential.rotate.v1` | old Credential terminal + new Credential active | `sidecar.CredentialRotated`, `sidecar.CredentialCreated` | admin |
| `sidecar.credential.revoke.v1` | Credential | `sidecar.CredentialRevoked` | admin |
| `sidecar.grant.issue.v1` | Grant | `sidecar.GrantIssued` | admin |
| `sidecar.grant.revoke.v1` | Grant | `sidecar.GrantRevoked` | admin |

Every edge in the authority/identity diagrams maps to a separate `sidecar.<aggregate>.<transition>.v1` registry entry with exact source/target, expected version, guards and `sidecar.<Aggregate><Transition>` fact. This includes workspace suspend/reactivate/archive; principal suspend/reactivate/disable; device suspend/reactivate/revoke; membership suspend/reactivate/revoke; actor suspend/reactivate/retire; delegation suspend/reactivate/revoke; session end/revoke/expire; and runtime-endpoint register/pair/suspend/reactivate/revoke. Authority-time expiry is a protected service command. These rows MUST be expanded into the machine registry before their stage begins; generic patch APIs are forbidden.

### Work and runs

| Operation | Atomic/primary set | Facts |
|---|---|---|
| `sidecar.work_ref.observe.v1` | WorkReference; optionally correlated ProviderOperation | `sidecar.WorkRefObserved`; optional `sidecar.ProviderTransitionConfirmed` |
| `sidecar.objective_and_work.create.v1` | Objective + initial WorkUnit | `sidecar.ObjectiveCreated`, `sidecar.WorkUnitCreated` |
| `sidecar.objective.activate.v1` | Objective | `sidecar.ObjectiveActivated` |
| `sidecar.run.plan_with_bindings.v1` | Run + initial Participations + Bindings | `sidecar.RunPlanned`, `sidecar.ParticipantInvited`*, `sidecar.BindingRequested`* |
| `sidecar.run_participation.join.v1` | Participation | `sidecar.RunParticipantJoined` |
| `sidecar.run.start.v1` | Run | `sidecar.RunStarted` |
| `sidecar.run.activate.v1` | Run | `sidecar.RunActivated` |
| `sidecar.run_participation.finish.v1` | Participation | `sidecar.RunParticipationFinished` |
| `sidecar.run.completion.request.v1` | Run | `sidecar.RunCompletionRequested` |
| `sidecar.run.completion.accept.v1` | Run | `sidecar.RunCompleted` |
| `sidecar.provider.transition.request.v1` | ProviderOperation + outbox | `sidecar.ProviderTransitionRequested` |
| `sidecar.provider.transition.reject_observation.v1` | ProviderOperation from authenticated definitive refusal | `sidecar.ProviderTransitionRejected` |

### Runtime bindings

`request`, `begin_launch`, `reconcile_begin`, `live_observe`, `orphaned_observe`, `ended_observe`, `fail`, and `supersede` are separate operations. Each observation is a protected service command scoped to one paired endpoint/observation/causation; watcher health is not an operation.

### Coordination

| Operation | Commit set/fact rule |
|---|---|
| `sidecar.conversation.open.v1` / `.close.v1` | Conversation lifecycle |
| `sidecar.message.send.v1` | Message plus every To/Cc/Bcc Delivery atomically; `sidecar.MessageSent` + `sidecar.DeliveryRequired` per recipient |
| `sidecar.message.available.record.v1` | Delivery availability only |
| `sidecar.message.read.v1` | Delivery read only |
| `sidecar.message.acknowledge.v1` | Delivery acknowledgement only |
| `sidecar.lease.acquire.v1` | Lease/selectors/counters/fence under overlap arbitration |
| `sidecar.lease.renew.v1` / `.release.v1` | exact holder/version/fence and authority time |
| `sidecar.fence.mutation.v1` | protected integration operation coupling fence check to mutation; no standalone validity guarantee |

### Decisions, attention, artifacts and completion

`decision.request` atomically creates Decision, required Occurrences and generation-one Deliveries. Decision resolve/cancel/expire are separate. Occurrence update/resolve, delivery queue/accepted/cancel and receipt shown/seen/dismissed are separate commands and facts.

Artifact operations are `sidecar.artifact.declare.v1`, `sidecar.artifact.verification.request.v1`, `sidecar.artifact.verification.observe.v1`, `sidecar.artifact.abandon.v1`, `sidecar.artifact.fail_observation.v1`, `sidecar.artifact.attach.v1`, `sidecar.artifact.quarantine.v1`, and `sidecar.artifact.release.v1`. Upload bytes are not commands. Verification-request records staging publication intent/effect only. Verification-observe is the authenticated verifier command that atomically moves database Artifact metadata to `available` or `failed`; it does not claim a cross-system transaction.

## Queries

| Query | Authority | Recovery/error rule |
|---|---|---|
| `sidecar.context.get.v1` | active authorized session | internally consistent checkpoint + through-cursor; scope mismatch fails |
| `sidecar.events.sync.v1` | active session/service projection | opaque cursor; invalid/scope/expired typed errors |
| `sidecar.work.get.v1` | authorized session | provenance/freshness explicit |
| `sidecar.run.get.v1` | eligible participant/operator | joined canonical/projection provenance |
| `sidecar.decision.get.v1` | eligible responder/read grant | no responder/cardinality leak |
| `sidecar.search.v1` | authorized scope | visibility filter before count/page |

Queries never emit events/effects or mutate delivery facts. Wake notifications are not queries/results.

## Completion gate

Before E1 begins, replace this Markdown skeleton with a versioned machine-readable registry plus generated tables that cover every E1 operation field. Before later stages, extend it first. CI checks registry↔Schema↔OpenAPI↔MCP↔migration/test fixture agreement.
