# Changelog

## [0.4.0](https://github.com/phall1/blackbird/compare/v0.3.0...v0.4.0) (2026-08-15)


### Features

* add a first-class command line surface ([c46464c](https://github.com/phall1/blackbird/commit/c46464c7e7a16ed5bdfb2271bab45b1294290f9f))

`blackbird` now has a real command line: grouped `--help`, shell completions,
and `status`, `doctor`, `gc`, `overview`, `projects`, `agents`, `inbox`,
`threads`, `reservations`, `events`, and `logs`, each rendering human output or
`--json` from the same data.

The daemon gained structured logging, `/healthz`, and `/readyz`, and `status`
now handshakes with the running process instead of trusting the supervisor.

Upgrading is safe without action: the installed service definition keeps
working. Run `blackbird install` to move it to the explicit `daemon` command.
A bare `blackbird` with no arguments now prints help instead of starting a
daemon, and no longer creates a database in the current directory.
