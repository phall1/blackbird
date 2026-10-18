import type { PluginInput, PluginModule, PluginOptions } from "@opencode-ai/plugin";
type MessagePosition = string | number;
export interface BlackbirdMessage {
    readonly message_id: string;
    readonly conversation_id: string;
    readonly subject: string;
    readonly body: string;
    readonly position: MessagePosition;
    readonly author_actor_id?: string;
    readonly sent_at?: string;
}
interface RoutingFixed {
    readonly mode: "fixed";
    readonly sessionID: string;
}
interface RoutingConversation {
    readonly mode: "conversation";
    readonly agent?: string;
}
export interface BlackbirdOptions {
    readonly baseUrl: string;
    readonly projectKey: string;
    readonly agentName: string;
    readonly token?: string;
    readonly stateDir?: string;
    readonly routing?: RoutingFixed | RoutingConversation;
    readonly paths?: {
        readonly register?: string;
        readonly catchUp?: string;
        readonly stream?: string;
        readonly ack?: string;
        readonly message?: string;
    };
    readonly catchUpLimit?: number;
    readonly backoff?: {
        readonly minimumMs?: number;
        readonly maximumMs?: number;
        readonly jitter?: number;
    };
}
/**
 * The narrow slice of OpenCode this plugin needs. It exists so the supervisor
 * can be tested without an OpenCode server, and so an OpenCode API change is a
 * change to one adapter rather than to the delivery loop.
 */
export interface SessionClient {
    create(input: {
        title: string;
        directory: string;
    }): Promise<{
        id: string;
    }>;
    /**
     * Append a Blackbird message to a session's transcript *without* running an
     * agent turn. Resolves only once OpenCode has durably accepted the message —
     * the supervisor marks a message delivered on that promise and must not
     * record delivery for a message OpenCode rejected.
     */
    deliver(input: {
        sessionID: string;
        messageID: string;
        text: string;
        metadata: Record<string, string | number>;
        directory: string;
        agent?: string;
    }): Promise<void>;
}
export declare function createSessionClient(client: PluginInput["client"]): SessionClient;
export interface SupervisorDependencies {
    readonly fetch: typeof globalThis.fetch;
    readonly random: () => number;
    readonly sleep: (milliseconds: number, signal: AbortSignal) => Promise<void>;
}
interface ResolvedOptions {
    readonly baseUrl: URL;
    readonly projectKey: string;
    readonly agentName: string;
    readonly token?: string;
    readonly stateDir: string;
    readonly routing: RoutingFixed | RoutingConversation;
    readonly registerPath: string;
    readonly catchUpPath: string;
    readonly streamPath: string;
    readonly ackPath: string;
    readonly messagePath: string;
    readonly catchUpLimit: number;
    readonly minimumMs: number;
    readonly maximumMs: number;
    readonly jitter: number;
}
export declare function resolveOptions(raw: PluginOptions | BlackbirdOptions, environment?: NodeJS.ProcessEnv): ResolvedOptions;
export declare function deterministicMessageID(blackbirdID: string): string;
export declare function runSupervisor(session: SessionClient, rawOptions: PluginOptions | BlackbirdOptions, signal: AbortSignal, dependencies?: SupervisorDependencies): Promise<void>;
export declare function acquireSupervisor(key: string, start: (signal: AbortSignal) => Promise<void>): () => Promise<void>;
export declare function supervisorKey(options: ResolvedOptions): string;
/**
 * Records one finished assistant message on the observation plane.
 *
 * Exported for tests, and deliberately total: every path that cannot produce a
 * well-formed observation returns rather than throwing, because this runs
 * inside OpenCode's event dispatch and a throw here would surface as a plugin
 * fault during someone's turn.
 */
export declare function recordAssistantMessage(key: string, event: unknown): void;
/**
 * Compatibility port for the older Promise-based V2 adapter. Retained for
 * existing consumers; the package entrypoint now uses the pinned Effect SDK's
 * actual Context and delegates delivery through effect-delivery.ts.
 */
export interface V2Context {
    readonly options: PluginOptions;
    readonly session: {
        create(input: {
            title?: string;
            location?: {
                directory: string;
            };
        }): Promise<{
            id: string;
        }>;
        /**
         * Insert a message into a session's transcript without running an agent
         * turn -- V2's replacement for `prompt({ noReply: true })`. Passing the
         * Blackbird message id as `id` keeps redelivery an upsert, exactly as the
         * v1 path relies on.
         */
        synthetic(input: {
            sessionID: string;
            id?: string;
            text: string;
            metadata?: Record<string, string | number>;
        }): Promise<unknown>;
    };
}
export declare function createV2SessionClient(session: V2Context["session"]): SessionClient;
/**
 * Compatibility export for V1 and the older Promise-based V2 adapter.
 *
 * OpenCode v1 loads `{ id, server }`; the V2 preview validates the default
 * export against `{ id, setup | effect }` and refuses to load a module that has
 * only `server` -- which is how 0.2.x silently stopped loading under
 * `opencode2` after the migration to the stable API. Carrying both hooks costs
 * one small adapter. index.ts now owns the public default Effect export and
 * reuses this export's V1 server hook.
 */
declare const plugin: PluginModule & {
    readonly setup: (context: V2Context) => Promise<() => Promise<void>>;
};
export default plugin;
//# sourceMappingURL=legacy.d.ts.map