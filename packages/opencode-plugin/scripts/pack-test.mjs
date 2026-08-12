import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const workspace = mkdtempSync(join(tmpdir(), "blackbird-opencode-pack-"))
const output = execFileSync("npm", ["pack", "--json", "--pack-destination", workspace], { cwd: new URL("..", import.meta.url), encoding: "utf8" })
const [{ filename }] = JSON.parse(output)
execFileSync("npm", ["init", "--yes"], { cwd: workspace, stdio: "ignore" })
execFileSync("npm", ["install", "--ignore-scripts", join(workspace, filename)], { cwd: workspace, stdio: "inherit" })
const installed = join(workspace, "node_modules", "blackbird-opencode")
const manifest = JSON.parse(readFileSync(join(installed, "package.json"), "utf8"))
if (manifest.name !== "blackbird-opencode") throw new Error("installed tarball has the wrong package name")
const module = await import(join(installed, "dist", "index.js"))
if (module.default?.id !== "phall1.blackbird") throw new Error("installed tarball did not expose the OpenCode plugin")
