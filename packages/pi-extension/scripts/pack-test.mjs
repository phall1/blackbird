import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const output = JSON.parse(execFileSync("npm", ["pack", "--json", "--ignore-scripts"], { encoding: "utf8" }))
const tarball = output[0]?.filename
if (!tarball) throw new Error("npm pack did not produce a tarball")
const directory = mkdtempSync(join(tmpdir(), "blackbird-pi-pack-"))
try {
  execFileSync("tar", ["-xzf", tarball, "-C", directory])
  const manifest = JSON.parse(readFileSync(join(directory, "package/package.json"), "utf8"))
  if (manifest.name !== "blackbird-pi" || manifest.pi?.extensions?.[0] !== "./extensions/index.ts") process.exit(1)
  readFileSync(join(directory, "package/extensions/index.ts"), "utf8")
} finally {
  rmSync(directory, { recursive: true, force: true })
  rmSync(tarball, { force: true })
}
