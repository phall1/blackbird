export interface TokenClasses {
    uncached_input_tokens: number;
    cache_read_tokens: number;
    cache_write_tokens: number;
    output_tokens: number;
    reasoning_tokens?: number;
}
export interface ModelCallObservation {
    dedupe_key: string;
    harness: "opencode";
    harness_session?: string;
    provider: string;
    model: string;
    operation: "chat";
    usage: TokenClasses;
    outcome: "ok" | "error" | "aborted";
    error_kind?: string;
    started_at: string;
    duration_ms: number;
    raw_usage?: string;
}
export interface OpenCodeTokens {
    input?: unknown;
    output?: unknown;
    reasoning?: unknown;
    cache?: {
        read?: unknown;
        write?: unknown;
    };
}
export declare function normalizeOpenCodeTokens(tokens: OpenCodeTokens | undefined): TokenClasses;
/** OpenCode names an abort explicitly; anything else with an error is a failure. */
export declare function outcomeForMessage(error: unknown): "ok" | "error" | "aborted";
export declare function errorKindForMessage(error: unknown): string | undefined;
/** Bounded so a large payload is truncated here rather than rejected there. */
export declare function boundedRawUsage(value: unknown): string | undefined;
export interface EmitterOptions {
    baseUrl: URL;
    token: string;
    fetch: typeof globalThis.fetch;
    onFailure?: (error: unknown) => void;
}
export declare class TelemetryEmitter {
    #private;
    constructor(options: EmitterOptions);
    record(observation: ModelCallObservation): void;
    flush(): Promise<void>;
    close(): Promise<void>;
}
export declare function publishEmitter(key: string, emitter: TelemetryEmitter): () => void;
export declare function emitterFor(key: string): TelemetryEmitter | undefined;
//# sourceMappingURL=telemetry.d.ts.map