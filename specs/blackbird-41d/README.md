# A work environment with durable correspondence

**Recommendation:** make Blackbird the first external provider on the phux highway, and prove the same conversation works naturally in Cockpit and on a phone. Build the provider contract from that concrete experience before generalizing it.

Status: Proposed for product/architecture review. No runtime implementation or release is included in this change.

## Start here

- **[Interactive desktop/mobile study](design-study.html)** — open directly in a browser; self-contained fictional data. Try Mobile, open a conversation, inspect its resource, send a reply, then switch to Connection lost or Read access.
- **[PRODUCT.md](PRODUCT.md)** — user-visible behavior, invariants, and edge cases.
- **[DESIGN.md](DESIGN.md)** — interaction hierarchy, visual direction, desktop/mobile compositions, and accessibility requirements.
- **[TECH.md](TECH.md)** — ownership, transport, identity, grants, API, writes/recovery, native seams, and verification.
- **[Proposed ADR-0002](../../docs/adr/0002-optional-phux-provider.md)** — narrow amendment to the accepted no-daemon-connection rule.
- **[Domain vocabulary](../../CONTEXT.md)** — participant, operator, conversation, provider, and resource reference.
- **[Review and validation](REVIEW.md)** — independent findings, dispositions, and browser-study evidence.

## The product move

The signature experience is **thread → exact resource → same place in the thread**. Correspondence survives the process that prompted it. Desktop gives the operator a readable workbench; mobile makes the same context and decisions reachable without compressing the desktop layout.

The visual direction is warm paper, deep ink, restrained teal, fine separators, and strong typography. The conversation is the center. Status labels correspond to facts rather than generic “agent working” indicators.

## The engineering move

| Component | Owns |
|---|---|
| phux | Connection, authenticated routes, resource addressing/lifecycle, bounded transport |
| Blackbird | Correspondence, participants, project grants, receipts, reliable send identity |
| Cockpit + mobile | Native navigation, presentation, protected local drafts |
| Agent harness | Model admission and notify/steer/queue behavior |
| Beads | Task ownership and acceptance evidence |

The first slice uses a separate provider WSS/UDS connection, a fixed Blackbird adapter, explicitly granted devices/projects, and namespaced references. Existing terminal pairing alone grants no correspondence access. Blackbird remains Go. The gateway carries requests; it does not persist or automatically retry them.

## Implementation sequence

Beads is the source of truth for task state. These references map the proposed architecture to its dependency graph; this document is not a parallel task tracker.

```text
blackbird-41d  specification and design study
       |
blackbird-l5c  ratify product and cross-project boundary
       |
       +-- blackbird-5f0  provider lane + two-client spike
       +-- blackbird-hc9  Blackbird grants + read API
                    |
       +------------+-------------------+
       |            |                   |
  blackbird-43s  blackbird-9ll      blackbird-81c
  Cockpit reads  mobile reads      human writes + ledger
       |            |                   |
       +------------+-------------------+
                    |
              blackbird-5k6  protected composers + recovery
                    |
              blackbird-2c2  exact resource round trips
                    |
              blackbird-e8z  full cross-device acceptance
```

Both read-client tasks depend on the provider lane and Blackbird reads. Human-write backend work depends on the read API; it can progress alongside native read UI after the contract is ratified.

**The first implementation demo should be boringly strong:** the phone sends a message; the response is lost after commit; reconnect finds its one durable receipt; desktop sees the same message; an exact terminal opens and Back restores the reading position.

## Decisions to ratify

1. Permit the optional provider route while preserving execution/coordination/task boundaries. Reconcile phux's matching accepted ADR and proposed coordinator scope.
2. Ship direct-host WSS/local UDS first with explicit pinned-bearer device/project grants. Provider federation, NAT relay service selection, and QUIC are later transport work.
3. Make human authorship, device-local protected drafts, and unknown-send recovery part of the full milestone. Acknowledgement remains agent-only in this release.
4. Use the new correspondence-first native direction, then tune it against real native long-content and accessibility cases.

This approach exercises the highway without requiring a universal Agent model, language migration, generalized extension SDK, or Executor integration first. A second first-party provider should test the reusable extension boundary after this one works.
