// Blackbird's observation plane (blackbird ADR-0001), OpenCode side.
//
// OpenCode reports per-assistant-message token counts whose `input` already
// excludes cache -- `tokens.cache.read` and `tokens.cache.write` are siblings
// of `input`, not subsets of it -- which is the same disjoint shape Blackbird
// stores. `reasoning` is forwarded as reported and clamped to output, because
// Blackbird treats reasoning as a subset and a provider that disagrees should
// not cost the whole observation.
//
// The raw token object travels with every observation. That is the audit trail
// for this mapping: if the convention above is ever wrong, or OpenCode changes
// it, the stored rows still carry what they were derived from and the plane can
// be recomputed instead of silently holding bad numbers.
//
// Nothing here throws into OpenCode and nothing here is awaited on a turn.
const TELEMETRY_PATH = "api/v1/local/telemetry";
const FLUSH_AT = 32;
const FLUSH_AFTER_MS = 5_000;
const MAX_BUFFERED = 256;
const MAX_PER_REQUEST = 128;
const MAX_RAW_USAGE_BYTES = 4096;
function count(value) {
    return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
}
export function normalizeOpenCodeTokens(tokens) {
    const output = count(tokens?.output);
    const classes = {
        uncached_input_tokens: count(tokens?.input),
        cache_read_tokens: count(tokens?.cache?.read),
        cache_write_tokens: count(tokens?.cache?.write),
        output_tokens: output,
    };
    if (typeof tokens?.reasoning === "number" && Number.isFinite(tokens.reasoning)) {
        classes.reasoning_tokens = Math.min(Math.max(0, Math.floor(tokens.reasoning)), output);
    }
    return classes;
}
/** OpenCode names an abort explicitly; anything else with an error is a failure. */
export function outcomeForMessage(error) {
    if (error === undefined || error === null)
        return "ok";
    const name = typeof error === "object" ? error.name : undefined;
    return typeof name === "string" && name.toLowerCase().includes("abort") ? "aborted" : "error";
}
export function errorKindForMessage(error) {
    if (error === undefined || error === null)
        return undefined;
    const name = typeof error === "object" ? error.name : undefined;
    return typeof name === "string" && name !== "" ? name.slice(0, 128) : "unknown";
}
/** Bounded so a large payload is truncated here rather than rejected there. */
export function boundedRawUsage(value) {
    try {
        const encoded = JSON.stringify(value);
        if (typeof encoded !== "string" || encoded.length === 0)
            return undefined;
        return encoded.length > MAX_RAW_USAGE_BYTES ? undefined : encoded;
    }
    catch {
        return undefined;
    }
}
export class TelemetryEmitter {
    #options;
    #buffer = [];
    #timer;
    #inFlight = Promise.resolve();
    #closed = false;
    constructor(options) {
        this.#options = options;
    }
    record(observation) {
        if (this.#closed)
            return;
        this.#buffer.push(observation);
        if (this.#buffer.length > MAX_BUFFERED) {
            this.#buffer.splice(0, this.#buffer.length - MAX_BUFFERED);
        }
        if (this.#buffer.length >= FLUSH_AT) {
            void this.flush();
            return;
        }
        if (this.#timer === undefined) {
            const timer = setTimeout(() => {
                this.#timer = undefined;
                void this.flush();
            }, FLUSH_AFTER_MS);
            timer.unref();
            this.#timer = timer;
        }
    }
    async flush() {
        if (this.#timer !== undefined) {
            clearTimeout(this.#timer);
            this.#timer = undefined;
        }
        const pending = this.#buffer;
        this.#buffer = [];
        if (pending.length === 0)
            return this.#inFlight;
        this.#inFlight = this.#inFlight.then(async () => {
            for (let index = 0; index < pending.length; index += MAX_PER_REQUEST) {
                await this.#post(pending.slice(index, index + MAX_PER_REQUEST));
            }
        });
        return this.#inFlight;
    }
    async close() {
        await this.flush();
        this.#closed = true;
        await this.#inFlight;
    }
    async #post(batch) {
        try {
            const response = await this.#options.fetch(new URL(TELEMETRY_PATH, this.#options.baseUrl), {
                method: "POST",
                headers: {
                    authorization: `Bearer ${this.#options.token}`,
                    "content-type": "application/json",
                    accept: "application/json",
                },
                body: JSON.stringify({ model_calls: batch }),
            });
            if (!response.ok) {
                this.#options.onFailure?.(new Error(`blackbird: telemetry rejected with HTTP ${String(response.status)}`));
                return;
            }
            const result = (await response.json());
            if (typeof result.rejected === "number" && result.rejected > 0) {
                this.#options.onFailure?.(new Error(`blackbird: ${String(result.rejected)} observation(s) rejected: ${JSON.stringify(result.rejections)}`));
            }
        }
        catch (error) {
            this.#options.onFailure?.(error);
        }
    }
}
// One emitter per supervisor key.
//
// OpenCode reference-counts a shared supervisor across repeated activations, so
// two plugin instances can share one token and one emitter while each still
// receives the `event` hook. That means the same assistant message can be
// recorded twice. It is not corrected here: the observation carries OpenCode's
// own message id as its dedupe key, and the daemon is idempotent on it. Fixing
// it locally would mean tracking instance identity for a problem the wire
// already solves.
const emitters = new Map();
export function publishEmitter(key, emitter) {
    emitters.set(key, emitter);
    return () => {
        if (emitters.get(key) === emitter)
            emitters.delete(key);
        void emitter.close();
    };
}
export function emitterFor(key) {
    return emitters.get(key);
}
//# sourceMappingURL=telemetry.js.map