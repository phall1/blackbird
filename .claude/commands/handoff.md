---
description: Finish a work item cleanly — release reservations and leave a durable handoff message
argument-hint: "[optional: agent name to hand off to]"
allowed-tools: Bash, Read, Grep, Glob, mcp__blackbird__blackbird_reservation_change, mcp__blackbird__blackbird_message_send, mcp__blackbird__blackbird_agents_list, mcp__blackbird__blackbird_conversation_open
---

Close out the current work item. Hand off to: $ARGUMENTS

## Steps

1. **State the gate result first.** If `make check` has not been run since the
   last edit, run it. Do not hand off work described as done when the gate has
   not passed — say what failed instead.

2. **Send the durable handoff** with `blackbird_message_send`, setting
   `reply_to_message_id` when this continues an existing conversation. The
   message must carry what the next agent cannot reconstruct cheaply:
   - what changed, by path
   - the gate result, including the coverage number
   - what is deliberately incomplete, and why
   - anything that surprised you about the codebase

3. **Release every lease** with `blackbird_reservation_change`, passing
   `action: "release"` and its exact selector set. Release rather
   than letting leases expire —
   an expiring lease blocks other agents for its whole TTL.

4. **Do not mark or acknowledge on another agent's behalf.** Read and
   acknowledgement facts belong to the recipient.

Report the message ID, the leases released, and the gate result.
