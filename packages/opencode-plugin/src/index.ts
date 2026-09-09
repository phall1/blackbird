import { Plugin } from "@opencode/plugin/effect"
import { Effect } from "effect"
import legacy from "./legacy.js"
import { startDelivery } from "./effect-delivery.js"
import { createMailReader } from "./mail-reader.js"
import { Mail } from "./rpc.js"

export * from "./legacy.js"

export default {
  ...Plugin.define({
    id: "phall1.blackbird",
    effect: (context) => Effect.gen(function* () {
      const path: unknown = context.options["handshakePath"]
      const reader = createMailReader(context.location.directory, typeof path === "string" ? path : undefined)
      yield* context.rpc.register(Mail, {
        agents: (_input, call) => reader.agents().pipe(Effect.mapError((error) => call.error("unavailable", error.message, { message: error.message }))),
        inbox: (input, call) => reader.inbox(input).pipe(Effect.mapError((error) => call.error("unavailable", error.message, { message: error.message }))),
        thread: (input, call) => reader.thread(input).pipe(Effect.mapError((error) => call.error("unavailable", error.message, { message: error.message }))),
      }).pipe(Effect.orDie)
      yield* startDelivery(context)
    }),
  }),
  server: legacy.server,
}
