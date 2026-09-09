import type { Plugin } from "@opencode/plugin/effect"
import { Session } from "@opencode/schema/session"
import { SessionMessage } from "@opencode/schema/session-message"
import { Location } from "@opencode/schema/location"
import { Effect, Exit, Fiber, Queue, Schema, Scope, Semaphore } from "effect"
import { resolveOptions, runSupervisor, supervisorKey, type SessionClient } from "./legacy.js"

// The existing, tested delivery transport is Promise-based. Feed its host
// operations to one scoped fiber rather than starting an Effect runtime from
// inside a callback. Each Promise settles only after the host accepts the work.
export function deliveryBridge(session: Plugin.Context["session"]) {
  return Effect.gen(function* () {
    const queue = yield* Queue.unbounded<Effect.Effect<void>>()
    const pending = new Set<(error: Error) => void>()
    let closed = false
    const request = <A, E>(operation: Effect.Effect<A, E>): Promise<A> =>
      new Promise<A>((resolve, reject: (error: Error) => void) => {
        if (closed) { reject(new Error("Blackbird delivery stopped")); return }
        pending.add(reject)
        Queue.offerUnsafe(queue, operation.pipe(
          // An operation can interrupt itself without interrupting the queue's
          // worker. Await its Exit in a child, still owned by that worker.
          Effect.forkChild,
          Effect.flatMap(Fiber.await),
          Effect.flatMap((exit) => Effect.sync(() => {
            if (Exit.isSuccess(exit)) resolve(exit.value)
            else reject(new Error("OpenCode rejected Blackbird delivery"))
          })),
          Effect.onInterrupt(() => Effect.sync(() => { reject(new Error("Blackbird delivery stopped")) })),
          Effect.ensuring(Effect.sync(() => { pending.delete(reject) })),
        ))
      })
    yield* Effect.addFinalizer(() => Effect.sync(() => {
      closed = true
      for (const reject of pending) reject(new Error("Blackbird delivery stopped"))
      pending.clear()
    }))
    yield* Queue.take(queue).pipe(Effect.flatMap((work) => work), Effect.forever, Effect.forkScoped)
    const client: SessionClient = {
      create: ({ title, directory }) => request(session.create({ title, location: Schema.decodeUnknownSync(Location.Ref)({ directory }) })),
      deliver: ({ sessionID, messageID, text, metadata }) => request(
        session.synthetic({ sessionID: Session.ID.make(sessionID), id: SessionMessage.ID.make(messageID), text, metadata }).pipe(Effect.asVoid),
      ),
    }
    return client
  })
}

interface SharedDelivery { references: number; scope: Scope.Closeable }
const deliveries = new Map<string, SharedDelivery>()
const ownership = Semaphore.makeUnsafe(1)

// A shared scope belongs to all host registrations for this identity. Its worker
// and transport survive the first registration unloading and stop at the last.
export function ownDelivery(key: string, start: Effect.Effect<void, never, Scope.Scope>) {
  const acquire = Effect.gen(function* () {
    const existing = deliveries.get(key)
    if (existing) { existing.references += 1; return existing }
    const scope = yield* Scope.make()
    yield* start.pipe(Scope.provide(scope), Effect.onExit((exit) => {
      if (Exit.isFailure(exit)) return Scope.close(scope, exit)
      return Effect.void
    }))
    const entry = { references: 1, scope }
    deliveries.set(key, entry)
    return entry
  })
  return Effect.acquireRelease(acquire.pipe(ownership.withPermits(1)), (entry) => Effect.gen(function* () {
    entry.references -= 1
    if (entry.references > 0) return
    deliveries.delete(key)
    yield* Scope.close(entry.scope, Exit.void)
  }).pipe(ownership.withPermits(1)))
}

export function startDelivery(context: Plugin.Context, run = runSupervisor) {
  return Effect.gen(function* () {
    // Browser-only installs need no agent identity or delivery registration.
    if (context.options["agentName"] === undefined) return
    const configuredProject: unknown = context.options["projectKey"]
    const options = { ...context.options, projectKey: configuredProject ?? context.location.directory }
    const key = supervisorKey(resolveOptions(options))
    yield* ownDelivery(key, delivery(context, options, run))
  })
}

function delivery(context: Plugin.Context, options: Plugin.Context["options"], run: typeof runSupervisor) {
  return Effect.gen(function* () {
    const client = yield* deliveryBridge(context.session)
    yield* Effect.tryPromise((signal) => run(client, options, signal)).pipe(
      Effect.catch(() => Effect.logWarning("Blackbird delivery stopped; retrying after one second")),
      Effect.andThen(Effect.sleep(1000)),
      Effect.forever,
      Effect.forkScoped,
    )
  })
}
