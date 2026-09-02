# Runtime and packaging

> **Authority:** Experimental sidecar decision  
> **Related:** [Overlay](README.md) · [Operations](../14-operations-observability.md) · [Risks](09-decisions-risks.md)

## Reference runtime: Node.js 24 LTS

Pin an exact supported patch because diagnostics, native APIs, `node:sqlite`, worker behavior and SEA details can change across patches. Node is preferred initially for:

- mature worker threads, inspector, heap snapshots and event-loop diagnostics;
- official MCP/library compatibility;
- stable signals, child processes, TLS and filesystem APIs;
- native-module ecosystem and long support window;
- conventional OCI/service-manager operation.

A release does not require system Node. It ships a private runtime alongside bundled application assets.

## Dependency pinning

At implementation kickoff:

1. query official npm metadata/release notes;
2. select one mutually compatible Effect v4 core/platform/sql/telemetry/test set;
3. pin exact versions and TypeScript/Node patch;
4. commit lockfile and package integrity;
5. run API compile, contract, SQLite backup/crash and clean-package probes;
6. record the decision in a sidecar ADR.

The authoring snapshot (`4.0.0-rc.108`) is an experiment baseline, not permission to float `^4` or deploy prerelease code.

## Local artifact

Per platform, publish a signed relocatable archive. The default is bundled ESM application code plus a private Node runtime; production `node_modules` are permitted only for native/runtime modules that cannot be safely bundled and must appear in the manifest. The layout contains `bin/sidecar`, `runtime/node`, `app/daemon.mjs`, `app/cli.mjs`, `app/sqlite-worker.mjs`, `assets/migrations/<engine>/`, `assets/contracts/`, and `manifest.json`; entrypoints resolve workers/assets relative to `import.meta.url` and verified manifest paths, never cwd or build-machine absolutes.

The archive contains:

- private Node runtime;
- bundled application modules/source maps according to security policy;
- native SQLite components required by selected runtime;
- immutable SQL migrations and checksums;
- launcher/service templates;
- public contract manifests;
- licenses, SBOM, build/provenance metadata and checksums.

Installer creates independent XDG paths, service name, ports, credentials and MCP entry. It validates ownership/modes and performs atomic configuration writes. Repeated install converges. Uninstall removes only service definitions/binaries it owns and retains data/config unless separately authorized.

## Node SEA

SEA is a packaging experiment, not the default. It must prove:

- native/addon and migration asset loading from a signed bundle;
- worker-thread startup and module resolution;
- source-map/diagnostics behavior;
- reproducible per-platform builds;
- code-signing/notarization and update behavior;
- no writable temporary extraction vulnerability.

If it adds more platform-specific machinery than a private runtime archive, reject it.

## Bun challenger

Bun compiled executable is attractive for artifact size/startup and built-in SQLite, but must independently pass:

- aligned Effect v4 and MCP compatibility;
- SQL transactions, WAL/full-sync, online backup and corruption behavior;
- workers, signals, subprocesses, TLS, keychain adapters and tracing;
- abrupt-kill and response-loss corpus;
- macOS arm64/Linux amd64/arm64 clean-machine packaging;
- equivalent PostgreSQL and contract fixtures;
- 24-hour resource soak.

Do not maintain Node and Bun production authorities simultaneously without a demonstrated operational reason.

## Hosted artifact

Publish multi-architecture OCI images with explicit `api`, `worker` and `maintenance` roles from one source/artifact provenance. Image runs unprivileged, has read-only root where practical, receives secrets through mounted/runtime providers, and never bundles local credentials.

## Supply chain

Release gates include:

- deterministic lock and dependency review;
- npm provenance/integrity verification;
- native binary hashes and code signatures;
- SBOM and license/source-carry obligations;
- vulnerability scan and explicit disposition;
- reproducible build comparison;
- signed checksums/provenance statement;
- update rollback/recovery rehearsal.

## Platform tiers

Initial claimed tier 1 requires native macOS arm64 and Linux amd64/arm64 evidence. Windows and macOS amd64 are build/package characterization only until migration, locking, backup, sleep/wake, secret-store and runtime integration pass natively.

## Packaging gates

- clean machine with no system Node/SQLite starts and becomes ready after relocating the archive to a different absolute path;
- compressed artifact target ≤ 100 MiB;
- no absolute build paths or secrets;
- migrations/contracts exactly match manifest hashes;
- daemon and updater have safe per-user permissions;
- upgrade from previous release preserves data and pending jobs;
- failed update leaves old runnable artifact or explicit repair state;
- install does not alter Blackbird files, service or client entry.
