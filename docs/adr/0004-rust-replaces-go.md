---
audience: contributors, agents
stability: stable
last-reviewed: 2026-10-08
---

# 0004 — Rust replaces the Go program

**TL;DR.** `blackbird` becomes the Rust binary. The Go module is deleted.
There is no migration from the Go database. The installed Go daemon is not
stopped or overwritten by install.

Status: Accepted
Date: 2026-10-08

## Context

ADR-0003 shipped the eight coordination tools as a Rust kernel beside the Go
daemon. The Go module still carried the install, the loopback service, a
thirteen-step schema history, and a large set of surfaces the live MCP server
no longer publishes: the event journal, telemetry, spend, ledger collectors,
tailnet peer mail, and the work plane.

The owner asked for the Go program to be replaced, and to drop that migration
history rather than port it.

## Decision

- The only `blackbird` binary is the Rust one in `rust/`. HTTP, stdio, and the
  CLI are adapters over `Desk`. No ninth MCP tool.
- The database is a new file, `coordination-v1.sqlite`, created from one
  schema script at `user_version` 1. A file at any other version, or a
  version-0 file that already has tables, is refused and not modified.
- `blackbird daemon` listens on `127.0.0.1:8081` only. `POST /` is stateless
  JSON-RPC. `GET /health` is the health check. Nothing listens on port 8080.
- `blackbird install` copies the binary to `~/.local/libexec/blackbird/` and
  writes a new unit (`io.phux.blackbird-rust` or `blackbird-rust.service`).
  If port 8081 is already taken, install stops and leaves the occupant
  running. It does not replace `com.phall1.blackbird`.
- `name@host`, spend, and tracker reads stay refused.
- Delete `go.mod`, `cmd/`, `internal/`, and the Go CI jobs.

## Consequences

An agent joined to the Go daemon is not joined to the Rust database. It joins
again. Clients configured for `http://127.0.0.1:8081` keep reaching whichever
process is listening there. Install will not take that port away from the Go
daemon.

ADR-0003's kernel and the authority split in ADR-0001 still stand. The
deferral that left the Go daemon as the installed service does not.

## Alternatives

**Port the thirteen migrations.** Rejected. The owner closed that option.
The old file stays where it is, unread.
