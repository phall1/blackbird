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

## Local Product Management

The released `blackbird` binary manages its per-user service without requiring
root access:

```sh
blackbird install
blackbird status
blackbird update
blackbird uninstall
```

`install` creates XDG config, data, and state directories, writes an atomic
launchd agent on macOS or systemd user unit on Linux, and safely restarts the
service. It also installs an unattended Homebrew updater that runs every six
hours: a non-`KeepAlive` launchd job on macOS, or a systemd user timer and
oneshot service on Linux. Updater failures are retained in Blackbird's state
logs on macOS and the user journal on Linux. The updater never restarts itself;
the daemon restarts only after the installed formula version changes.

Installation also adds one `blackbird` HTTP MCP entry to detected OpenCode,
Claude Code, and Codex configurations while preserving unrelated settings.
Repeated installs converge the daemon, updater, and client definitions.

`update` runs `brew update` followed by
`brew upgrade phall1/tap/blackbird`; the service is restarted only when the
installed formula version changes. `status` reports both the daemon and updater.
`uninstall` stops the daemon and updater and removes only their definitions. The
database, logs, XDG directories, and MCP client settings are retained.
