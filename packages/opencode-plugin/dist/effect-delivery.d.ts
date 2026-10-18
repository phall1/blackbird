import type { Plugin } from "@opencode/plugin/effect";
import { Effect, Scope } from "effect";
import { runSupervisor, type SessionClient } from "./legacy.js";
export declare function deliveryBridge(session: Plugin.Context["session"]): Effect.Effect<SessionClient, never, Scope.Scope>;
interface SharedDelivery {
    references: number;
    scope: Scope.Closeable;
}
export declare function ownDelivery(key: string, start: Effect.Effect<void, never, Scope.Scope>): Effect.Effect<SharedDelivery, never, Scope.Scope>;
export declare function startDelivery(context: Plugin.Context, run?: typeof runSupervisor): Effect.Effect<void, never, Scope.Scope>;
export {};
//# sourceMappingURL=effect-delivery.d.ts.map