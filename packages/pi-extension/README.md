# blackbird-pi

Pi-native delivery for [Blackbird](https://github.com/phall1/blackbird).
Blackbird remains the always-on durable mailbox; this extension connects the
currently active Pi session to it. It does not launch or supervise Pi.

```sh
pi install npm:blackbird-pi@0.1.0
```

Start Pi in the repository that should receive messages. The extension
registers the stable agent name `Pi`, catches up Blackbird's durable event
journal, and injects visible messages into the current session. Messages are
queued as follow-ups while Pi is busy. Delivery does not mark Blackbird facts
read or acknowledged.

State is private under `$XDG_STATE_HOME/blackbird/pi-extension`. On first use,
the extension imports the registration token and completed/quarantined delivery
facts from the retired `blackbird-pi` companion state when present.

Environment overrides:

- `BLACKBIRD_API_URL` defaults to `http://127.0.0.1:8080`.
- `BLACKBIRD_PI_AGENT_NAME` defaults to `Pi`.
- `BLACKBIRD_PI_DISABLED=1` disables the extension.

Use `/blackbird` inside Pi to inspect connection state.
