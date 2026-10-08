---
audience: contributors, agents
stability: stable
last-reviewed: 2026-10-08
---

# 0003 — A Rust coordination kernel, launched as a phux plugin

**TL;DR.** The eight live coordination tools also exist as a Rust kernel in
`rust/`. phux can launch that binary as an ordinary plugin child process. The
kernel has its own SQLite file, does not dial a phux socket, and does not
replace the Go daemon. ADR-0001's authority split stands. ADR-0002 stays
proposed.

Status: Accepted
Date: 2026-10-08

## Context

The production surface agents actually call is project-scoped identity,
durable mail, and advisory path leases: `blackbird_join`, `blackbird_claim`,
`blackbird_release`, `blackbird_status`, `blackbird_say`, `blackbird_read`,
`blackbird_ack`, and `blackbird_wait`. Around that surface the Go module also
carries install, launchd, admin HTTP, telemetry, beads and ledger adapters,
tailnet peer mail, and a sealed work plane that production MCP no longer
publishes.

phux plugins are executable packages. A `phux-plugin.toml` declares commands,
and phux runs them as argv from the plugin root. There is no in-process plugin
host. That is the same shape as the authority split in ADR-0001: Blackbird
agrees, phux executes, and neither daemon is a client of the other.

ADR-0002's rejected alternative "move Blackbird into phux/Rust" argued that
language unification does not settle authority. That argument still holds. It
does not forbid a Rust implementation that stays a separate process.

## Decision

- Ship a Rust coordination kernel at `rust/` that implements those eight
  tools and nothing else from the Go module.
- Shape it as a phux plugin (`rust/phux-plugin.toml`) plus an integration
  template whose `[launch]` command is `blackbird-rs mcp`. phux starts it as
  a child process. The kernel unsets inherited `PHUX_SOCKET` and websocket
  credentials and never connects to a phux server.
- Give the kernel its own database, `$XDG_STATE_HOME/blackbird-rs/` or
  `BLACKBIRD_RS_DB`. It does not open the Go daemon's file and it does not
  bind `127.0.0.1:8081`.
- Keep the Go daemon as the installed service (`brew install`, `blackbird
  install`, peer mail, telemetry, admin, tracker observations) until a later
  cutover proves the kernel against that contract.
- Refuse `name@host` mail, spend, cost, and tracker reads with a stable
  error instead of answering them as empty success.
- Store only a hash of the registration token. Reject a message body that
  has no recipients, so opening a thread cannot look like a send.

## Consequences

Two databases exist during the transition. An agent pointed at `blackbird-rs
mcp` does not see mail or leases stored by the Go daemon, and the reverse is
also true. Harnesses that need peer mail or the loopback admin API stay on
the Go service. `phux plugin link rust/phux-plugin.toml` adds doctor and
status actions; it does not retarget existing MCP clients.

ADR-0002 is not accepted by this record. The optional provider route is still
a proposal. This decision only chooses where the coordination kernel is
allowed to be implemented.

## Alternatives

**Line-port the Go module into Rust.** Preserves the dead work plane, the
thirteen-migration schema, and the install machinery in a second language
before the plugin boundary is real.

**Replace the Go daemon in the same change.** Breaks the Homebrew service,
every joined agent, and the `127.0.0.1:8081` endpoint those agents already use.

**Link the kernel into the phux process.** phux has no in-process plugin
host, and an in-process desk would collapse the authority split ADR-0001
exists to protect.
