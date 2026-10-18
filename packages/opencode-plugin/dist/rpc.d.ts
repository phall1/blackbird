import { z } from "zod";
export declare const Agent: z.ZodObject<{
    agent_name: z.ZodString;
    active: z.ZodBoolean;
    unread_deliveries: z.ZodNumber;
    unacked_deliveries: z.ZodNumber;
}, z.core.$strip>;
export declare const AgentsPage: z.ZodObject<{
    agents: z.ZodArray<z.ZodObject<{
        agent_name: z.ZodString;
        active: z.ZodBoolean;
        unread_deliveries: z.ZodNumber;
        unacked_deliveries: z.ZodNumber;
    }, z.core.$strip>>;
    truncated: z.ZodBoolean;
}, z.core.$strip>;
export declare const Delivery: z.ZodObject<{
    message_id: z.ZodString;
    conversation_id: z.ZodString;
    recipient_agent_name: z.ZodString;
    author_agent_name: z.ZodDefault<z.ZodString>;
    subject: z.ZodString;
    read: z.ZodBoolean;
    acknowledged: z.ZodBoolean;
    acknowledgement_required: z.ZodBoolean;
    sent_at: z.ZodString;
}, z.core.$strip>;
export declare const InboxPage: z.ZodObject<{
    pending: z.ZodArray<z.ZodObject<{
        message_id: z.ZodString;
        conversation_id: z.ZodString;
        recipient_agent_name: z.ZodString;
        author_agent_name: z.ZodDefault<z.ZodString>;
        subject: z.ZodString;
        read: z.ZodBoolean;
        acknowledged: z.ZodBoolean;
        acknowledgement_required: z.ZodBoolean;
        sent_at: z.ZodString;
    }, z.core.$strip>>;
    truncated: z.ZodBoolean;
}, z.core.$strip>;
export declare const ThreadMessage: z.ZodObject<{
    message_id: z.ZodString;
    author_agent_name: z.ZodString;
    subject: z.ZodString;
    body: z.ZodString;
    sent_at: z.ZodString;
    position: z.ZodNumber;
}, z.core.$strip>;
export declare const ThreadPage: z.ZodObject<{
    messages: z.ZodArray<z.ZodObject<{
        message_id: z.ZodString;
        author_agent_name: z.ZodString;
        subject: z.ZodString;
        body: z.ZodString;
        sent_at: z.ZodString;
        position: z.ZodNumber;
    }, z.core.$strip>>;
    has_more: z.ZodBoolean;
    next: z.ZodNumber;
}, z.core.$strip>;
export declare const InboxQuery: z.ZodObject<{
    agent: z.ZodOptional<z.ZodString>;
    unread: z.ZodDefault<z.ZodBoolean>;
}, z.core.$strip>;
export declare const ThreadQuery: z.ZodObject<{
    conversation_id: z.ZodString;
    after: z.ZodDefault<z.ZodNumber>;
}, z.core.$strip>;
export declare const Mail: {
    readonly id: "blackbird.mail";
    readonly events: {};
    readonly methods: {
        readonly agents: {
            readonly input: z.ZodObject<{}, z.core.$strip>;
            readonly output: z.ZodObject<{
                agents: z.ZodArray<z.ZodObject<{
                    agent_name: z.ZodString;
                    active: z.ZodBoolean;
                    unread_deliveries: z.ZodNumber;
                    unacked_deliveries: z.ZodNumber;
                }, z.core.$strip>>;
                truncated: z.ZodBoolean;
            }, z.core.$strip>;
            readonly errors: {
                unavailable: z.ZodObject<{
                    message: z.ZodString;
                }, z.core.$strip>;
            };
        };
        readonly inbox: {
            readonly input: z.ZodObject<{
                agent: z.ZodOptional<z.ZodString>;
                unread: z.ZodDefault<z.ZodBoolean>;
            }, z.core.$strip>;
            readonly output: z.ZodObject<{
                pending: z.ZodArray<z.ZodObject<{
                    message_id: z.ZodString;
                    conversation_id: z.ZodString;
                    recipient_agent_name: z.ZodString;
                    author_agent_name: z.ZodDefault<z.ZodString>;
                    subject: z.ZodString;
                    read: z.ZodBoolean;
                    acknowledged: z.ZodBoolean;
                    acknowledgement_required: z.ZodBoolean;
                    sent_at: z.ZodString;
                }, z.core.$strip>>;
                truncated: z.ZodBoolean;
            }, z.core.$strip>;
            readonly errors: {
                unavailable: z.ZodObject<{
                    message: z.ZodString;
                }, z.core.$strip>;
            };
        };
        readonly thread: {
            readonly input: z.ZodObject<{
                conversation_id: z.ZodString;
                after: z.ZodDefault<z.ZodNumber>;
            }, z.core.$strip>;
            readonly output: z.ZodObject<{
                messages: z.ZodArray<z.ZodObject<{
                    message_id: z.ZodString;
                    author_agent_name: z.ZodString;
                    subject: z.ZodString;
                    body: z.ZodString;
                    sent_at: z.ZodString;
                    position: z.ZodNumber;
                }, z.core.$strip>>;
                has_more: z.ZodBoolean;
                next: z.ZodNumber;
            }, z.core.$strip>;
            readonly errors: {
                unavailable: z.ZodObject<{
                    message: z.ZodString;
                }, z.core.$strip>;
            };
        };
    };
};
//# sourceMappingURL=rpc.d.ts.map