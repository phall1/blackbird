# Blackbird

This directory is the isolated production Go module for Blackbird. It is kept
extractable from the Agent Mail excavation tree and never imports the selection
spike or the legacy Python implementation.

The production core currently includes:

- process lifecycle, build identity, and import-boundary enforcement;
- nominal UUIDv7 identities, authority scopes, versions, stable errors, event
  envelopes, and semantic commit-set contracts;
- pure installation, bootstrap, principal, workspace, membership, actor,
  delegation, device, and actor-session transitions; and
- strict bounded public command, result, error, and event wire contracts for
  W0; and
- the in-progress transport-neutral W0 application contract, including closed
  unit-of-work declarations, receipt/replay plans, security-only decisions,
  RFC 8785 result/capsule codecs, and credential-bound identity commits.

These slices have passed their local architecture gates and native macOS/Linux
CI. They do **not** claim that persistence, supported transports, the complete
walking slice, an ADR is Verified, or a release candidate exists. W0.4 is the
application/UnitOfWork boundary; SQLite, PostgreSQL, pairing, HTTP/MCP,
context, and the integrated proof follow in dependency order. W0.4 remains in
progress until its production command/guard/event/audit profiles and complete
recording-UoW orchestration evidence land.

The implementation authority is
[`docs/architecture/implementation-plan.md`](../docs/architecture/implementation-plan.md),
with decisions in [`docs/architecture/adr`](../docs/architecture/adr).

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
go build ./...
```

Build metadata can be supplied with linker flags targeting `main.version`,
`main.commit`, and `main.builtAt`. Unset fields use explicit development
values.
