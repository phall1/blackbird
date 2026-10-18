import { Plugin } from "@opencode/plugin/effect";
import { Effect } from "effect";
export * from "./legacy.js";
declare const _default: {
    server: import("@opencode-ai/plugin").Plugin;
    id: string;
    effect: (context: Plugin.Context) => Effect.Effect<void, never, import("effect/Scope").Scope>;
};
export default _default;
//# sourceMappingURL=index.d.ts.map