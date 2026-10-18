import { Effect } from "effect";
import { z } from "zod";
import { type InboxQuery, type ThreadQuery } from "./rpc.js";
export declare function handshakePath(): string;
export declare function createMailReader(projectKey: string, path?: string, fetcher?: typeof fetch): {
    agents: () => Effect.Effect<{
        agents: {
            agent_name: string;
            active: boolean;
            unread_deliveries: number;
            unacked_deliveries: number;
        }[];
        truncated: boolean;
    }, Error, never>;
    inbox: (query: z.infer<typeof InboxQuery>) => Effect.Effect<{
        pending: {
            message_id: string;
            conversation_id: string;
            recipient_agent_name: string;
            author_agent_name: string;
            subject: string;
            read: boolean;
            acknowledged: boolean;
            acknowledgement_required: boolean;
            sent_at: string;
        }[];
        truncated: boolean;
    }, Error, never>;
    thread: (query: z.infer<typeof ThreadQuery>) => Effect.Effect<{
        messages: {
            message_id: string;
            author_agent_name: string;
            subject: string;
            body: string;
            sent_at: string;
            position: number;
        }[];
        has_more: boolean;
        next: number;
    }, Error, never>;
};
//# sourceMappingURL=mail-reader.d.ts.map