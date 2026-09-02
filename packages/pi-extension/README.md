# blackbird-pi

Pi-native **queue-mode** delivery for
[Blackbird](https://github.com/phall1/blackbird). Blackbird remains the always-on
durable mailbox; this extension connects the currently active Pi session to it.
It does not launch or supervise Pi.

```sh
pi install npm:blackbird-pi@0.1.0
```

Start Pi in the repository that should receive messages. The extension
registers the stable agent name `Pi`, catches up Blackbird's durable event
journal, and injects visible messages into the current session. Messages are
queued as follow-ups while Pi is busy. Delivery does not mark Blackbird facts
read or acknowledged.

Blackbird stores delivery progress under the authenticated `pi-extension`
consumer and advances it only after Pi admits the custom message. The local
state under `$XDG_STATE_HOME/blackbird/pi-extension` keeps only the registration
token and host-specific quarantine facts. On first use, the extension imports
the retired companion cursor once into the server consumer and retains its
quarantine state.

Environment overrides:

- `BLACKBIRD_API_URL` defaults to `http://127.0.0.1:8080`.
- `BLACKBIRD_PI_AGENT_NAME` defaults to `Pi`.
- `BLACKBIRD_PI_DISABLED=1` disables the extension.

Use `/blackbird` inside Pi to inspect connection state.
