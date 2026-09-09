import { CliRenderEvents, type Renderable } from "@opentui/core"
import type { Context } from "@opencode/plugin/tui/context"
import { onCleanup } from "solid-js"

// Host panel resizing/focusing can focus an ancestor without changing the
// panel's focused property. Return input to our widget, never steal a dialog.
export function restoreMailboxFocus(renderer: Context["renderer"], root: () => Renderable | undefined, widget: () => string, enabled: () => boolean) {
  let disposed = false
  function focused(node: Renderable | null) {
    if (!node || !ancestor(node, root())) return
    queueMicrotask(() => {
      if (disposed || !enabled() || renderer.currentFocusedRenderable !== node) return
      root()?.findDescendantById(widget())?.focus()
    })
  }
  renderer.on(CliRenderEvents.FOCUSED_RENDERABLE, focused)
  onCleanup(() => { disposed = true; renderer.off(CliRenderEvents.FOCUSED_RENDERABLE, focused) })
}

function ancestor(node: Renderable, child: Renderable | undefined): boolean {
  let parent = child?.parent
  while (parent) {
    if (parent === node) return true
    parent = parent.parent
  }
  return false
}
