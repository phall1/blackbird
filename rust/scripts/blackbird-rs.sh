#!/bin/sh
# Launch the Rust coordination kernel from the plugin root.
# The kernel never dials a phux socket. Inherited pane credentials are dropped
# so a plugin action cannot be aimed at the installed phux server.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
unset PHUX_SOCKET PHUX_PROFILE PHUX_WS_TOKENS PHUX_WS_TLS_CERT PHUX_WS_TLS_KEY PHUX_WS_TLS_CA || true
bin="$root/target/release/blackbird-rs"
if [ ! -x "$bin" ]; then
  bin="$root/target/debug/blackbird-rs"
fi
if [ ! -x "$bin" ]; then
  echo "blackbird-rs is not built. From the blackbird repo: cargo build --manifest-path rust/Cargo.toml" >&2
  exit 1
fi
exec "$bin" "$@"
