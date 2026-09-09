import { execFileSync } from "node:child_process"
import { rmSync } from "node:fs"
import { fileURLToPath } from "node:url"
import solid from "@opentui/solid/bun-plugin"

const root = fileURLToPath(new URL("..", import.meta.url))
rmSync(new URL("../dist", import.meta.url), { recursive: true, force: true })
execFileSync("tsc", ["-p", "tsconfig.build.json"], { cwd: root, stdio: "inherit" })

// The host intentionally skips Solid compilation under node_modules. Ship
// universal-compiled ESM, leaving bare runtime imports for the host to share.
const result = await Bun.build({
  entrypoints: [new URL("../src/tui.tsx", import.meta.url).pathname],
  outdir: new URL("../dist", import.meta.url).pathname,
  target: "bun",
  format: "esm",
  packages: "external",
  plugins: [solid],
})
if (!result.success) throw new AggregateError(result.logs, "Blackbird TUI build failed")
