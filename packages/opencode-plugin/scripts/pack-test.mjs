import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

const workspace = mkdtempSync(join(tmpdir(), "blackbird-opencode-pack-"))
try {
const output = execFileSync("npm", ["pack", "--json", "--pack-destination", workspace], { cwd: new URL("..", import.meta.url), encoding: "utf8" })
const [{ filename }] = JSON.parse(output)
execFileSync("npm", ["init", "--yes"], { cwd: workspace, stdio: "ignore" })
execFileSync("npm", ["install", "--ignore-scripts", join(workspace, filename)], { cwd: workspace, stdio: "inherit" })
const installed = join(workspace, "node_modules", "blackbird-opencode")
const manifest = JSON.parse(readFileSync(join(installed, "package.json"), "utf8"))
if (manifest.name !== "blackbird-opencode") throw new Error("installed tarball has the wrong package name")
const module = await import(join(installed, "dist", "index.js"))
if (module.default?.id !== "phall1.blackbird") throw new Error("installed tarball did not expose the OpenCode plugin")
if (typeof module.default.effect !== "function") throw new Error("installed tarball did not expose Effect setup")
execFileSync("bun", ["--eval", `
  import { Host } from "@opencode/plugin/host";
  const entries = Host.resolve({ directory: process.cwd(), name: "blackbird-opencode" });
  for (const name of ["server", "tui", "rpc"]) {
    if (!entries[name]) throw new Error(name + " entrypoint missing");
    const loaded = await Host.load(entries[name]);
    if (name === "tui" && loaded.default.id !== "phall1.blackbird.tui") throw new Error("TUI failed to load");
    if (name === "rpc" && !loaded.Mail.methods.thread) throw new Error("RPC failed to load");
  }
  console.log("Installed package: V2 server, TUI and RPC loaded through Host");
`], { cwd: workspace, stdio: "inherit" })
if (process.env.BLACKBIRD_PACK_TUI === "1") {
  const root = fileURLToPath(new URL("..", import.meta.url))
  execFileSync(join(root, "node_modules", ".bin", "opencode-drive"), ["run", "scripts/tui-drive.ts"], {
    cwd: root, stdio: "inherit", env: { ...process.env, BLACKBIRD_PLUGIN_DIRECTORY: installed },
  })
}
} finally {
  rmSync(workspace, { recursive: true, force: true })
}
