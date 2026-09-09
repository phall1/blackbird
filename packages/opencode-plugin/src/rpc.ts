import { Rpc } from "@opencode/plugin/rpc"
import { z } from "zod"

export const Agent = z.object({
  agent_name: z.string(), active: z.boolean(), unread_deliveries: z.number(), unacked_deliveries: z.number(),
})
export const AgentsPage = z.object({ agents: z.array(Agent), truncated: z.boolean() })
export const Delivery = z.object({
  message_id: z.string(), conversation_id: z.string(), recipient_agent_name: z.string(),
  author_agent_name: z.string().default("Unknown author"), subject: z.string(), read: z.boolean(), acknowledged: z.boolean(),
  acknowledgement_required: z.boolean(), sent_at: z.string(),
})
export const InboxPage = z.object({ pending: z.array(Delivery), truncated: z.boolean() })
export const ThreadMessage = z.object({
  message_id: z.string(), author_agent_name: z.string(), subject: z.string(), body: z.string(),
  sent_at: z.string(), position: z.number(),
})
export const ThreadPage = z.object({ messages: z.array(ThreadMessage), has_more: z.boolean(), next: z.number() })
export const InboxQuery = z.object({ agent: z.string().min(1).max(256).optional(), unread: z.boolean().default(false) })
export const ThreadQuery = z.object({ conversation_id: z.string().min(1).max(256), after: z.number().int().nonnegative().default(0) })
const errors = { unavailable: z.object({ message: z.string() }) }

export const Mail = Rpc.define({
  id: "blackbird.mail",
  events: {},
  methods: {
    agents: { input: z.object({}), output: AgentsPage, errors },
    inbox: { input: InboxQuery, output: InboxPage, errors },
    thread: { input: ThreadQuery, output: ThreadPage, errors },
  },
})
