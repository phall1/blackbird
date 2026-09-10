# Specification review and design-study validation

Review date: 2026-09-09 session (completed after 2026-09-10 00:00 UTC).

## Independent architecture review

A fresh-context read-only reviewer inspected the product, technical and design contracts, proposed ADR, and relevant existing storage implementation. Four material findings were raised and resolved; a focused second pass confirmed the remaining peer-migration clarification. These are specification-level dispositions, not runtime correctness claims.

| Finding | Resolution |
|---|---|
| Cross-daemon revocation promised more than the mechanism could enforce | Added per-device access generations, internal grant inspection before publication and on idle ticks, client generation fences, and distinct read/Blackbird-send/gateway-only revocation linearization rules. |
| Human recipients could receive acknowledgement obligations with no action to discharge them | All extended send paths reject acknowledgement-required human or mixed sets. Browsing has no acknowledgement side effect. |
| Remote peer shadow actors could accidentally be treated as offline local send targets | Added durable origin metadata, explicit legacy reserved-namespace backfill, runtime send eligibility, and a fixture for outgoing-only peer history after outbox retention. |
| Access denial during recovery could mislabel an earlier uncertain send as Not sent | An unrecorded refusal never resolves a prior unknown intent. Preserve frozen identity for later authorized status lookup; isolate it on provider replacement. |

No additional material contradictions were reported in the revised specification. Proposed decisions remain subject to user ratification and matching phux/Cockpit boundary updates.

## Browser-study checks

The self-contained HTML was loaded in local headless Chrome using Playwright. Checks passed for:

- Desktop and mobile presentation; conversation selection and mobile Back.
- Draft preservation when switching between conversations in the study.
- Related-resource disclosure, return, and Escape behavior.
- A single simulated operator reply appended to the selected thread.
- Offline send refusal while allowing draft edits; read-only composer disabled.
- Loaded-conversation search, empty results, and outstanding-acknowledgement filter.
- No JavaScript page errors and no external network requests.
- At a 390 × 844 viewport, no horizontal overflow and Send remains within the viewport.

Screenshots were captured in `/private/tmp/opencode/`:

- `blackbird-provider-desktop.png`
- `blackbird-provider-mobile-list.png`
- `blackbird-provider-mobile-thread.png`
- `blackbird-provider-phone.png`

The desktop and phone captures were visually inspected. The first phone capture exposed a study-header height issue; the responsive layout was corrected and the viewport assertion passed on the final run. Native VoiceOver/Dynamic Type, protected storage, real transport, and transactional sending remain implementation acceptance criteria, not capabilities of this fictional study.

## Static checks

- Relative documentation links and whitespace checked across all proposal artifacts.
- ESLint's actual `complexity` rule measured 21 functions/callbacks in the study script. The maximum was **3 before → 3 after** the layout/fixture corrections; `renderThread` changed **1 → 2** to support an explicit participant label. There are no branching hotspots; no runtime production functions changed.
- Beads dependency traversal confirmed both native read lanes depend on the transport and Blackbird read contracts, and all runtime work is transitively behind the explicit product/boundary decision.

To inspect the study manually, open `design-study.html`, select Mobile, open a conversation, inspect Build terminal, return, edit/send a fictional reply, and exercise the State selector. The study needs no server or installed project dependencies.
