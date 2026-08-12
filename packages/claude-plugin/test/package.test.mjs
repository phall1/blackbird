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
