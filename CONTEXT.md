# Blackbird coordination and the proposed phux provider

Vocabulary shared by the existing coordination product and the proposed provider integration in [blackbird-41d](specs/blackbird-41d/PRODUCT.md). Provider-specific terms describe the proposal, not shipped capability.

## Coordination

**Participant**: An identifiable author or recipient of correspondence within a Blackbird project. An agent and a human operator are distinct participant kinds.
_Avoid_: Treating every participant as an agent

**Operator**: The human on whose behalf an authorized client reads or sends correspondence. The operator is distinct from the device used to access it.
_Avoid_: Agent impersonation, device-as-person

**Conversation**: A durable grouping of immutable messages about a shared topic. It can outlive every participating process and client.
_Avoid_: Run, terminal session

**Handoff**: Correspondence asking another participant to take an action, carrying enough context to understand the request. Sending it does not itself assign a task or start execution.
_Avoid_: Automatic delegation, task completion

**Acknowledgement**: A recipient's explicit confirmation of the exact stored message. It is distinct from viewing, transport delivery, and completing requested work.
_Avoid_: Read, success, approval

## Provider integration

**Provider**: An independently authoritative source of a named capability available through the phux environment. Blackbird provides correspondence while retaining ownership of its facts.
_Avoid_: Universal agent runtime

**Provider binding**: A host's explicit association with one provider identity and the capabilities it can expose. A label or network address is not the provider's identity.
_Avoid_: Mailbox, agent identity

**Resource reference**: A namespaced identification of a resource owned elsewhere, with provenance for the association. Knowing a reference neither grants access nor proves that the resource still exists.
_Avoid_: Ownership, authorization, inferred binding

**Live incarnation**: One particular live existence of a resource under its owner. Replacing a process creates a different incarnation even when its human-readable name is reused.
_Avoid_: Persistent work identity

**Observation**: A fact reported by its named source at an identified time. An observation about execution, correspondence, or task state does not establish the others.
_Avoid_: Universal agent status
