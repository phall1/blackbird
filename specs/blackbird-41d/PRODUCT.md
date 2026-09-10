# Blackbird correspondence in the phux workbench

Status: Draft for review · 2026-09-09

Planning bead: `blackbird-41d` · [Technical design](TECH.md) · [Interaction design](DESIGN.md)

## Summary

Cockpit and phux-mobile let an operator inspect the same durable Blackbird correspondence, send an explicitly human-authored handoff, and navigate to related phux resources. Blackbird is the first external non-terminal provider for the phux environment (phux already has AgentSession resources); this release establishes a narrow integration that later providers can help generalize.

## Design reference

No Figma mock exists. The user requested a new, high-quality interaction direction rather than inheriting the current applications' immature UI patterns. [The interactive design study](design-study.html) uses fictional data; it is an experience proposal, not working connectivity or evidence of native implementation.

## Scope

The first release serves one operator's explicitly authorized devices, one directly connected phux host at a time, and selected existing Blackbird projects on that host. Both desktop and mobile are required consumers. Read access ships first; operator-authored correspondence follows before the complete milestone is accepted. Agent execution and model admission continue to belong to the agent host.

Task scheduling, automatic agent creation, mailbox-driven terminal input, multi-hop provider federation, push notifications while iOS is suspended, attachments, arbitrary plugin code, and a general UI-extension SDK are outside this release. Existing Blackbird peer mail remains a separate feature; this surface initially sends to participants in its selected provider/project only.

## Behavior

### Find the right correspondence

1. **An optional capability.** Connecting to a phux host exposes whether Blackbird correspondence is available to this device. Terminal use works when Blackbird is absent, stopped, incompatible, unauthorized, or restarting. Those states have distinct explanations; none appears as an empty mailbox.

2. **Explicit access.** Terminal pairing alone does not grant correspondence access. An operator grants a named device read access, or read-and-send access, to a named set of projects. The grant explains that read access is an operator view of all message bodies in those projects, not impersonation of a selected agent. Recipient-address details remain restricted as defined below. A device cannot enroll or expand its own grant remotely.

3. **Stable selection.** The workbench names the selected host and project. A path, display name, current terminal focus, or most recently created pane never silently chooses another mailbox. Switching projects while a read is pending cannot display the previous project's result in the new selection.

4. **Correspondence first.** The entry view shows a conversation list with subject, latest author, bounded preview, time, and factual status. Selecting a conversation opens its history. Desktop presents list and detail together when space allows; mobile presents a list followed by a full-width thread with an ordinary Back action that preserves list position.

5. **Precise filters.** The default is All conversations in the selected project, newest activity first. Awaiting acknowledgement means at least one required recipient acknowledgement is outstanding; it does not mean the human has been asked to act. A participant filter means correspondence authored by or delivered to that participant. Agent unread counts are explicitly labelled as the agent's facts. Search in the first release is labelled “Search loaded conversations” and never claims to search the entire archive.

6. **No fabricated attention.** Subject text, model prose, process liveness, and heuristics do not create an authoritative “needs your approval” state. A message can request a decision in ordinary text. The interface displays the request without inventing an approval protocol, task status, or completion claim.

7. **Bounded history.** Conversation and message pages can be loaded incrementally. No message body is silently shortened; long messages offer an explicit expansion or full-message read. New arrivals do not move keyboard focus or force a reader to the bottom. A “New messages” control moves there intentionally. Pagination preserves the selected conversation and message anchor.

### Read without impersonating an agent

8. **Browsing has no coordination side effects.** Opening or scrolling a mailbox changes no agent registration, read receipt, acknowledgement, path reservation, host-delivery cursor, task ownership, or model execution. Human viewing is not recorded as an agent reading. The release does not introduce a synced human-unread state.

9. **Authorship and recipients are explicit.** Human-authored messages are labelled as the operator; agent-authored messages retain their agent identity. To/Cc recipients may be displayed under the operator grant. Bcc recipient identities and individual Bcc receipt facts are omitted from project-wide operator reads, except for messages authored by that operator. No picker or filter reveals hidden Bcc membership through a derived conversation match. The operator read grant nevertheless explicitly permits reading all bodies within a granted project.

10. **Honest delivery language.** “Saved to mailbox” means Blackbird durably accepted a send. “Recipient read” and “Acknowledged” require the corresponding Blackbird facts. Saving, opening the thread, and transport success never imply model admission, that an agent is running, or task completion. The initial UI makes no per-message host-admission claim where the adapter cannot prove it.

11. **Freshness is visible.** During reconnection the currently visible in-memory content remains readable with its last observation time and a stale indicator. It is not styled as current. Revocation or an authoritative access denial removes protected content from the view. App termination clears retained read content in this release; it does not promise an offline mailbox archive.

### Send a human handoff

12. **Read-only means read-only.** Read-only devices can inspect correspondence and copy non-secret references. They see an explanation for unavailable send controls. No read command registers an operator or agent.

13. **Explicit send.** A read-and-send device can create a conversation or reply in an existing open conversation. The composer shows the operator author, host, project, and explicitly selected recipients before sending. Recipient selection uses the current participant directory and stable participant identities. The first release supports To recipients only, with a visible option to request acknowledgement for agent-only recipient sets. Requests requiring acknowledgement cannot address a human, because this release has no human acknowledgement action; the same rule applies to agent-originated messages. Existing remote-peer participants remain visible in history but are explicitly unavailable as send targets on this surface. Offline local agents remain eligible. Reply recipients are shown and editable; hidden recipients are never copied into a reply automatically.

14. **Scope-safe drafts.** A draft belongs to one device, operator, provider, project, and optional conversation. Moving to another location keeps that draft in its original scope. Closing and reopening the app restores drafts on the same device after authorization is checked; drafts are not synchronized across devices in this release. Revocation hides them and prevents sending; local deletion remains available.

15. **Recoverable sending.** Pressing Send freezes a single send intent. Double taps and retry after response loss cannot create duplicate messages or conversations. The interface distinguishes Sending, Saved to mailbox, Not sent, and Outcome unknown. On an unknown outcome it offers “Check status” and keeps the exact attempted content; it does not silently create a new send. Changing an uncertain send requires resolving it first or an explicit new-message action warning that the earlier send may already exist.

16. **Offline behavior.** An offline operator may edit a local draft. Sending requires a live authorized connection. Reconnection does not automatically send unsent drafts. A request interrupted after submission may be Outcome unknown, not Not sent. Dismissing a progress indicator does not promise cancellation of a durable send.

17. **Concurrent changes.** A closed conversation, removed recipient, changed grant, or provider identity change is revalidated at send time. A refusal known to resolve the original intent leaves an editable draft with an actionable reason. Losing access during status recovery hides protected content but preserves an earlier unknown-outcome intent; it cannot prove that the earlier send failed. A reply to an old but valid message remains legal when newer messages have arrived; arrival does not silently modify the operator's content or recipients.

18. **Agent response remains native.** After a human send, an already configured host adapter may deliver it under its existing notify/steer/queue behavior. The mailbox UI neither pastes into a terminal nor starts an agent or extra model turn. Replies from the agent appear through ordinary correspondence refresh.

### Navigate to related resources

19. **References are navigation.** A message may carry explicit related-resource references. A reference to a terminal or host session does not establish task ownership, permission, liveness, or that the resource produced the message. Its provenance is visible as “Linked by …”. Message text alone never becomes an executable command or an automatically trusted resource link.

20. **Exact resource opening.** Opening a related phux terminal checks the owning host and exact live incarnation before attachment. If the target is gone or cannot be verified, the interface shows the original reference as unavailable; it does not choose a pane with a matching title, PID, path, or reused numeric ID. Unsupported reference kinds are presented as copyable descriptive references.

21. **Independent permissions.** A mailbox reference can be visible while terminal access is unavailable, and vice versa. Following a reference requires its target's ordinary authorization. Opening a terminal neither sends a message nor grants terminal input authority beyond the existing terminal contract.

### Equal desktop and mobile quality

22. **Focused navigation.** On desktop, the thread is the visual center; related resources appear in a secondary inspector. On mobile, correspondence, thread, composer, and resource detail have deliberate full-width presentations. A narrow device is never a squeezed three-column desktop layout. Returning from a terminal restores the thread and its reading position.

23. **Accessible interactions.** All actions have visible text or accessible labels, status is not conveyed by color alone, and keyboard focus is visible. Desktop supports conventional list navigation, Enter to open, Escape to leave an inspector/composer, and an explicit modified shortcut to send. Mobile supports Dynamic Type, VoiceOver, platform back navigation, and at least 44-point interactive targets. Reduced Motion removes decorative movement.

24. **Background and recovery.** iOS suspension stops active refresh and does not imply the host stopped. Foreground entry rechecks identity and access before refreshing. Expired sessions and revoked grants have distinct recovery actions. No background notification or continuous connectivity is promised by the first release.

25. **Isolation and responsiveness.** A failing or slow provider does not freeze terminal interaction or another host's view. Cancellation of a read stops its work; retry is bounded. The operator can leave the mailbox while it reconnects. Empty project, empty filter, loading, stale, access denied, version mismatch, and unavailable provider are separately designed states.

26. **Incremental compatibility.** Older clients continue their supported terminal behavior with newer hosts. A client shows a capability it understands or explains that an update is needed. A provider update never makes previously unsupported actions implicitly authorized. The same grant and mailbox facts produce equivalent behavior on Cockpit and mobile.
