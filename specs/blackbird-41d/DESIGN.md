# Correspondence, with a place to act

Status: Design proposal · [Product invariants](PRODUCT.md) · [Interactive study](design-study.html)

## The signature interaction

**Read the request. Open its exact resource. Return to the same place in the conversation.**

That round trip is the product's distinguishing interaction. A mailbox with a terminal link is merely a feature list; a thread and its live context that retain their position while the operator moves between them feel like one environment. The underlying ownership stays separate and is expressed with source labels, not infrastructure jargon.

## Information hierarchy

1. **Place:** selected host and project, always visible before an action.
2. **Correspondence:** the conversations relevant to that place, with explicit filters.
3. **The request:** subject and readable thread are the center of attention.
4. **Context:** exact linked resources, participant identity, and receipt facts.
5. **Action:** reply or open a resource; neither is triggered by selection alone.

No global command center, multi-metric status mosaic, inferred agent productivity score, or decorative activity stream. These would compete with the operator's immediate question. The architecture can be broad while the first interaction stays specific.

## Desktop composition

At roomy widths: a 184–224 px environment rail, a 280–340 px conversation list, and a flexible reading canvas. The resource inspector is a deliberate secondary disclosure, not a permanently empty fourth column. At intermediate widths collapse the environment rail to a location control before sacrificing reading width. At narrow widths use the mobile navigation hierarchy.

Conversation rows carry subject, author, timestamp, two lines of preview, and at most one factual status. Selection uses a quiet surface and a fine leading accent. Hover never changes selection or loads protected content on behalf of another project. Keyboard navigation remains in the list until Enter; focus and selection are visibly distinct.

The thread reads like correspondence, not alternating chat bubbles. Author/time form a light metadata line above the message. Long technical text gets a sane reading measure. Message controls appear consistently at the end of the message or in an accessible menu; they do not hide exclusively behind hover.

The reply composer is anchored to the thread and expands when editing. Author and recipients remain legible. Sending collapses it only after durable acceptance. Unknown outcome keeps the frozen message and a Check status action. A subtle inline confirmation is preferable to a celebratory toast.

## Mobile composition

Mobile is a first-class decision surface. The first screen is a calm, searchable conversation list for the selected place. Tapping a row pushes a full-width thread. A compact location label stays in the header. Large body text and platform Dynamic Type take precedence over fitting more rows.

Reply opens a full-height composer with recipients at the top and a thumb-reachable action bar above the keyboard. Interactive dismissal preserves the device-local draft. Unknown sends survive app suspension as frozen intents; a badge on the draft points to status recovery rather than an automatic resend.

Related resources open a bottom sheet for identity and availability, followed by the existing terminal route on explicit Open. Returning restores the thread anchor. The mobile terminal continues to own keyboard and gesture interaction. Mailbox gestures do not override it.

Use native navigation and accessibility semantics in production: Cockpit's existing AOT TypeScript/declarative native chrome with Zig-owned services, and SwiftUI with a separate service adapter in mobile. Do not introduce a second desktop UI framework. The HTML study communicates hierarchy and transitions; its CSS sizes are not a replacement for point-based Dynamic Type and safe-area layout.

## Visual direction

**An instrument for focused work, with the warmth of correspondence.** Paper-tinted reading surfaces, an ink-colored environment rail on desktop, fine separators, deliberate whitespace, and a single restrained teal accent for selection and primary actions. Amber means stale/pending, red means a failed action, and words always carry the meaning as well.

Use the platform's excellent system sans for navigation and reading, with monospace reserved for identifiers and terminal excerpts. Avoid the uniform card-grid look: full-height regions and aligned baselines express structure. No stock icons or invented product logo are needed for the study.

Motion clarifies navigation, not importance: 120–180 ms disclosure transitions, instant text entry, no looping pulses or auto-scrolling content. Reduced Motion removes transitions. Target contrast is WCAG AA; production validation includes large text, VoiceOver, keyboard-only use, and Increased Contrast.

## Status vocabulary

| Label | Evidence and action |
|---|---|
| Saved to mailbox | Durable Blackbird send receipt; continue reading |
| Awaiting acknowledgement | Outstanding required acknowledgement among visible recipient facts |
| Recipient read | A named recipient's stored read fact |
| Acknowledged | A named recipient confirmed the stored body |
| Reconnecting · last updated … | Previously observed content, explicitly stale |
| Outcome unknown | Submitted intent without a resolved receipt; Check status |
| Access removed | Fresh authorization denial; clear protected view |
| Resource unavailable | Exact reference cannot resolve; show identity, offer ordinary host navigation |

Never use “Delivered to agent”, “Working”, “Approved”, or “Done” as substitutes for facts the mailbox cannot establish. A message whose author asks for a decision remains ordinary correspondence; it is not a privileged approval prompt.

## Study interaction coverage

`design-study.html` is self-contained and makes no network calls. It demonstrates conversation selection, loaded-list search/filter, a desktop/mobile presentation toggle, thread/resource round trip, a human-authored reply, and offline/read-only states. The terminal excerpt and all receipt behavior are fictional. Native animations, screen-reader behavior, persistent drafts, actual resource attachment, and uncertain-send recovery are specified above and in PRODUCT.md rather than claimed by this study.

The study is reviewed as a direction, not a final visual system. The first native iteration must include real long message bodies, a 200% text scale, empty/error states, a small iPhone, and a narrow desktop window before spacing and typography are frozen.
