import type { Plugin } from "@opencode/plugin/effect"
import { Effect, Exit, Scope } from "effect"
import { expect, it, vi } from "vitest"
import plugin from "../src/index.js"
import { deliveryBridge, ownDelivery, startDelivery } from "../src/effect-delivery.js"

it("exposes a lazy Effect plugin and registers browser RPC without registering an agent", async () => {
  const register = vi.fn(() => Effect.void)
  const context = { location: { directory: "/repo" }, options: {}, rpc: { register } } as unknown as Plugin.Context
  const effect = plugin.effect(context)
  expect(register).not.toHaveBeenCalled()
  expect("setup" in plugin).toBe(false)
  expect(typeof plugin.server).toBe("function")
  await Effect.runPromise(Effect.scoped(effect))
  expect(register).toHaveBeenCalledOnce()
})

it("settles delivery only after the host effect accepts it, and propagates host failure", async () => {
  const received: unknown[] = []
  const session = {
    synthetic: (input: unknown) => Effect.sync(() => { received.push(input) }),
  } as unknown as Plugin.Context["session"]
  await Effect.runPromise(Effect.scoped(Effect.gen(function* () {
    const client = yield* deliveryBridge(session)
    yield* Effect.tryPromise({ try: () => client.deliver({ sessionID: "ses_test", messageID: "msg_test", text: "hello", metadata: {}, directory: "/repo" }), catch: (error) => error })
    expect(received).toEqual([{ sessionID: "ses_test", id: "msg_test", text: "hello", metadata: {} }])
  })))
  const rejected = { synthetic: () => Effect.fail(new Error("host unavailable")) } as unknown as Plugin.Context["session"]
  await expect(Effect.runPromise(Effect.scoped(Effect.gen(function* () {
    const client = yield* deliveryBridge(rejected)
    yield* Effect.tryPromise({ try: () => client.deliver({ sessionID: "ses_test", messageID: "msg_test", text: "hello", metadata: {}, directory: "/repo" }), catch: (error) => error })
  })))).rejects.toThrow("rejected Blackbird delivery")
})

it("interrupts in-flight host operations and rejects pending transport promises on unload", async () => {
  let interrupted = false
  let started = false
  const session = { synthetic: () => Effect.sync(() => { started = true }).pipe(Effect.andThen(Effect.never), Effect.onInterrupt(() => Effect.sync(() => { interrupted = true }))) } as unknown as Plugin.Context["session"]
  let delivery: Promise<void> | undefined
  await Effect.runPromise(Effect.scoped(Effect.gen(function* () {
    const client = yield* deliveryBridge(session)
    delivery = client.deliver({ sessionID: "ses_test", messageID: "msg_test", text: "hello", metadata: {}, directory: "/repo" })
    void delivery.catch(() => undefined)
    yield* Effect.promise(() => vi.waitFor(() => expect(started).toBe(true)))
  })))
  await expect(delivery).rejects.toThrow()
  expect(interrupted).toBe(true)
})

it("settles host defects and continues processing subsequent deliveries", async () => {
  let calls = 0
  const session = { synthetic: () => Effect.suspend(() => {
    calls += 1
    return calls === 1 ? Effect.die(new Error("host defect")) : Effect.void
  }) } as unknown as Plugin.Context["session"]
  await Effect.runPromise(Effect.scoped(Effect.gen(function* () {
    const client = yield* deliveryBridge(session)
    const send = () => client.deliver({ sessionID: "ses_test", messageID: "msg_test", text: "hello", metadata: {}, directory: "/repo" })
    yield* Effect.promise(async () => { await expect(send()).rejects.toThrow("rejected") })
    yield* Effect.promise(send)
    expect(calls).toBe(2)
  })))
})

it("shares one delivery scope across activations until the last owner unloads", async () => {
  let starts = 0
  let stops = 0
  const start = Effect.gen(function* () {
    starts += 1
    yield* Effect.addFinalizer(() => Effect.sync(() => { stops += 1 }))
  })
  await Effect.runPromise(Effect.gen(function* () {
    const first = yield* Scope.make()
    const second = yield* Scope.make()
    yield* ownDelivery("test-identity", start).pipe(Scope.provide(first))
    yield* ownDelivery("test-identity", start).pipe(Scope.provide(second))
    expect(starts).toBe(1)
    yield* Scope.close(first, Exit.void)
    expect(stops).toBe(0)
    yield* Scope.close(second, Exit.void)
    expect(stops).toBe(1)
    yield* ownDelivery("test-identity", start).pipe(Effect.scoped)
    expect(starts).toBe(2)
    expect(stops).toBe(2)
  }))
})

it("continues after a host operation interrupts itself", async () => {
  let calls = 0
  const session = { synthetic: () => Effect.suspend(() => {
    calls += 1
    return calls === 1 ? Effect.interrupt : Effect.void
  }) } as unknown as Plugin.Context["session"]
  await Effect.runPromise(Effect.scoped(Effect.gen(function* () {
    const client = yield* deliveryBridge(session)
    const send = () => client.deliver({ sessionID: "ses_test", messageID: "msg_test", text: "hello", metadata: {}, directory: "/repo" })
    yield* Effect.promise(async () => { await expect(send()).rejects.toThrow("rejected") })
    yield* Effect.promise(send)
    expect(calls).toBe(2)
  })))
})

it("automatically restarts an unexpectedly failed supervisor and cancels retries on unload", async () => {
  const context = { location: { directory: "/repo" }, options: { agentName: "restart-test", baseUrl: "http://127.0.0.1:8080" }, session: {} } as unknown as Plugin.Context
  let starts = 0
  let signal: AbortSignal | undefined
  const run = (_client: unknown, _options: unknown, abort: AbortSignal) => {
    starts += 1
    if (starts === 1) return Promise.reject(new Error("temporary state failure"))
    signal = abort
    return new Promise<void>((resolve) => abort.addEventListener("abort", () => resolve(), { once: true }))
  }
  await Effect.runPromise(Effect.scoped(Effect.gen(function* () {
    yield* startDelivery(context, run)
    yield* Effect.promise(() => vi.waitFor(() => expect(starts).toBe(2), { timeout: 2000 }))
  })))
  expect(signal?.aborted).toBe(true)
})
