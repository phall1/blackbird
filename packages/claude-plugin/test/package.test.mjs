import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import test from "node:test"

test("declares a Claude channel and session-owned stdio server", async () => {
  const manifest = JSON.parse(await readFile(new URL("../.claude-plugin/plugin.json", import.meta.url)))
  const mcp = JSON.parse(await readFile(new URL("../.mcp.json", import.meta.url)))
  const server = await readFile(new URL("../server.mjs", import.meta.url), "utf8")
  assert.equal(manifest.name, "blackbird")
  assert.deepEqual(mcp.mcpServers.channel.args, ["${CLAUDE_PLUGIN_ROOT}/server.mjs"])
  assert.match(server, /"claude\/channel"/)
  assert.match(server, /name: "accept"/)
})

test("surfaces the daemon's problem document instead of a bare status", async () => {
  const server = await readFile(new URL("../server.mjs", import.meta.url), "utf8")
  // The daemon answers failures with application/problem+json carrying a stable
  // code; throwing only response.status discards what it said.
  assert.match(server, /async function blackbirdFailure\(response, action\)/)
  assert.doesNotMatch(server, /failed with HTTP \$\{response\.status\}`\)/)
  for (const action of ["registration", "catch-up", "message fetch", "stream"]) {
    assert.match(server, new RegExp(`blackbirdFailure\\((response|messageResponse), "${action}"\\)`))
  }
})
