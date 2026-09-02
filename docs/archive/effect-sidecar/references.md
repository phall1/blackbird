# Reference map

> **Authority:** Citation index; sources retain their own status  
> **Related:** [Reference policy](01-reference-and-maturity.md) · [Index](README.md)

Links are relative to this standalone Blackbird repository unless explicitly identified as external design-source material.

## Standalone Blackbird implementation seams

These are implementation evidence only and may evolve:

- [`internal/domain`](../../../internal/domain/) — typed IDs, states and transitions.
- [`internal/application`](../../../internal/application/) — command/UoW contracts and orchestration.
- [`internal/transport/contracts/operations.go`](../../../internal/transport/contracts/operations.go) — strict canonical operation inventory.
- [`internal/runtime/production.go`](../../../internal/runtime/production.go) — production composition and fail-closed boundaries.
- [`internal/storage/sqlite/migrations`](../../../internal/storage/sqlite/migrations/) — SQLite migrations.
- [`internal/storage/postgres/migrations`](../../../internal/storage/postgres/migrations/) — PostgreSQL migrations.
- [`internal/storage/sqlite/crash_test.go`](../../../internal/storage/sqlite/crash_test.go) — subprocess/WAL crash evidence pattern.
- [`internal/storage/sqlite/backup.go`](../../../internal/storage/sqlite/backup.go) — online backup/restore reference.
- [`internal/integration/beads/beads.go`](../../../internal/integration/beads/beads.go) — narrow provider adapter.
- [`packages/opencode-plugin`](../../../packages/opencode-plugin/) — durable catch-up/wake-only push integration.
- [Repository README](../../../README.md) — released product description; lower semantic authority than contracts/code/evidence.

## External accepted architecture corpus used during authorship

The following files live in the original design/source repository from which standalone Blackbird was extracted. They are intentionally **not copied** into this independent repository. Citations are path-and-title identifiers, not local links. Any later acceptance review MUST pin the source repository URL and commit digest in its manifest before relying on them.

- `MASTERPLAN.md` — product thesis and authority map.
- `docs/architecture/README.md` — architecture/maturity index.
- `docs/architecture/completion-audit.md` and `implementation-readiness.md` — accepted versus verified ledger.
- `docs/architecture/implementation-plan.md` — dependency-ordered increments.
- `docs/architecture/contract-catalog.md` — walking-slice operation/event/error mapping.
- `docs/architecture/proof-slice.md` and `stack-proof.md` — deterministic scenario and stack evidence.
- `docs/architecture/adr/0001b-go-first-principles-stack.md` — Blackbird stack choice and bounded Effect role.
- `docs/architecture/adr/0002-product-constitution.md` — authority/product principles.
- `docs/architecture/adr/0003-domain-identity.md` — aggregates, identities, state machines and commands.
- `docs/architecture/adr/0004-persistence-consistency-recovery.md` — canonical state, receipts, journal/outbox, authority time and failover.
- `docs/architecture/adr/0005-phux-runtime-binding.md` — runtime authority and reconciliation.
- `docs/architecture/adr/0006-session-api-mcp-sdk.md` — session-bound surfaces/cursors/transports.
- `docs/architecture/adr/0007-security-federation.md` — pairing, grants, privacy and threats.
- `docs/architecture/adr/0008-cockpit-mobile-attention.md` — client projection and attention.
- `docs/architecture/adr/0009-operability-verification.md` — workload, evidence and operations.
- `docs/architecture/adr/0010-legacy-extraction-public-launch.md` — lineage/migration/public posture.
- `docs/architecture/adr/0011-application-unit-of-work.md` — declarative orchestration and security transactions.
- `spikes/go-stack/clients/effect/` — client-only Effect proof, not a durable server design.

No external accepted target or proof evidence promotes this sidecar's maturity. If the source revision is unavailable, the sidecar's independently restated rules and registry must stand on their own or acceptance fails.

## Public technical references

- [Effect documentation](https://effect.website/) — APIs must be rechecked at implementation time.
- [Effect v4 experimental documentation](https://effect.plants.sh/) — time-sensitive prerelease source.
- [Node.js v24 documentation](https://nodejs.org/docs/latest-v24.x/api/) — runtime, `node:sqlite`, workers and SEA.
- [Model Context Protocol TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) — transport adapter dependency.
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785).
- [RFC 9562 UUIDs](https://www.rfc-editor.org/rfc/rfc9562).
- [SQLite WAL](https://sqlite.org/wal.html) and [backup API](https://sqlite.org/backup.html).
- [PostgreSQL 18 transaction isolation](https://www.postgresql.org/docs/18/transaction-iso.html), [locking](https://www.postgresql.org/docs/18/explicit-locking.html), and [`SKIP LOCKED`](https://www.postgresql.org/docs/18/sql-select.html).

## Time-stamped dependency observation

At specification authoring time, npm metadata showed Effect v4 packages on aligned `4.0.0-rc.108`, while `effect` npm `latest` remained v3. This is not a permanent version mandate. Implementation start MUST re-query official registries, choose one mutually compatible exact set, record hashes/lockfile, and rerun contract/package spikes before updating the baseline through an explicit sidecar ADR.
