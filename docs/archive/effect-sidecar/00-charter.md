# Charter

> **Authority:** Experimental sidecar decision  
> **Related:** [Index](README.md) · [Authority](02-context-authority.md) · [Verification](15-verification.md)

## Mission

Build an independent, local-first coordination plane in TypeScript and Effect v4 that makes durable human-and-agent work coherent across process, client, runtime, provider, and machine failures.

The system records durable intent and outcomes—identities, work, runs, conversations, decisions, leases, artifacts, receipts, and history—while delegating live terminal execution to a runtime provider such as Phux and tracker-owned fields to a configured work provider.

## Product outcomes

A successful system lets a person or agent:

1. establish a trusted workspace and bounded identity;
2. define or reference work;
3. plan and conduct a run with multiple actors;
4. coordinate through durable conversations, decisions, and leases;
5. bind durable work to replaceable live runtimes;
6. attach verifiable evidence and accept completion;
7. disconnect, crash, restore, or move clients without losing meaning;
8. inspect exactly which authority accepted each fact.

## Principles

1. **Local-first is complete.** Core identity, work, messaging, decisions, leases, artifacts, search, history, and runtime coordination work without a hosted account.
2. **One fact has one owner.** Every external field has provenance; projections never silently become authority.
3. **Durable intent and ephemeral execution are distinct.** A run survives terminal loss; terminal bytes never transit this service.
4. **Correctness is established at write time.** Cleanup jobs do not repair accepted invalid state.
5. **The database is authority.** Fibers, streams, wake notifications, caches, and provider callbacks are never sources of truth.
6. **Ordinary use is small.** Session-bound commands hide administrative context while preserving explicit expert surfaces.
7. **Failure is typed.** Unknown provider and database outcomes remain unknown until reconciliation; they are never presented as success.
8. **Architecture remains replaceable.** Domain semantics do not depend on Effect encodings, SQL rows, MCP SDK types, or Node globals.
9. **Operations are product behavior.** Backup, restore, upgrade, diagnostics, redaction, and evidence are designed with features.
10. **Experimental means honest.** No inherited Blackbird evidence, release maturity, or compatibility is claimed.

## Scope

### In scope

- one independently authoritative sidecar workspace;
- local SQLite and hosted PostgreSQL semantic targets;
- normalized state, immutable journal, transactional outbox;
- HTTP/JSON, curated MCP, CLI, and durable cursor sync;
- actors, sessions, objectives, work units, runs, participation and runtime bindings;
- conversations, messages, recipient delivery facts, decisions and attention;
- exact/subtree resource leases and fencing;
- content-addressed artifacts and acceptance evidence;
- Phux-style runtime, tracker, notification, object-store and secret-store ports;
- backup/restore, projection rebuild, failure injection and conformance.

### Explicit non-goals

- replacing or upgrading Blackbird;
- sharing a Blackbird database or credentials;
- proxying terminal byte streams;
- using terminal keystrokes as durable coordination;
- replacing tracker dependency/priority authority;
- general workflow-engine semantics as canonical state;
- full event sourcing of normalized aggregate state;
- required Redis, Kafka, NATS, Celery, Temporal, or cloud account;
- transparent SQLite/PostgreSQL replication;
- arbitrary-glob intersection in the core lease algebra;
- claiming exactly-once external effects;
- end-to-end encrypted multi-party content in the first experiment;
- Windows production support before native proof exists.

## Success definition

The experiment becomes an engineering baseline only when one causally connected proof demonstrates:

- fresh bootstrap through active sessions;
- work/run planning and runtime binding;
- message delivery with independent read/ack facts;
- a fenced lease conflict;
- a structured decision resolved from an offline client;
- runtime loss and successor binding without replacing durable work;
- artifact verification and accepted run completion;
- idempotent lost-response recovery;
- event catch-up after missed wakes;
- projection rebuild;
- backup, sealed restore, new authority epoch, and stale-fence rejection;
- equivalent semantic results on SQLite and PostgreSQL.

Passing this proof makes only the exact sidecar revision and artifact eligible for its own **Verified** label. It says nothing about Blackbird.

## Governance

This revision is Proposed and permits only disposable E0 investigation until an acceptance manifest approves its exact commit. After acceptance, material changes to authority, identity, transaction boundaries, durability, security, wire compatibility, supported runtimes, or release evidence require a sidecar ADR. A code change may not silently supersede this specification.

Open product identity, naming, hosted-service, publication, and release choices remain owner decisions; see [decision ledger](effect-v4/09-decisions-risks.md).
