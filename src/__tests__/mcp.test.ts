// Smoke test for the agent proxy as an MCP server: spawn it over stdio with the SDK's own
// client (real handshake) and confirm it advertises its tools. Uses a dummy
// identity — listing tools triggers no network.

import { describe, it, expect } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

describe('agent proxy MCP server', () => {
  it('starts over stdio and advertises the v1 tool surface', async () => {
    const transport = new StdioClientTransport({
      command: 'npx',
      args: ['tsx', 'src/server.ts'],
      env: {
        ...(process.env as Record<string, string>),
        PROXY_PS_URL: 'http://localhost:2',
        PROXY_AGENT_TOKEN: 'x.y.z',
        PROXY_AGENT_PRIVATE_JWK: JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: 'AAAA', d: 'BBBB' }),
      },
    })
    const client = new Client({ name: 'aauth-proxy-test', version: '0.0.0' })

    try {
      await client.connect(transport)
      const { tools } = await client.listTools()
      const names = tools.map((t) => t.name).sort()
      for (const expected of [
        'add_resource',
        'find_resources',
        'get_operations',
        'invoke',
        'list_operations',
        'list_resources',
        'remove_resource',
      ]) {
        expect(names).toContain(expected)
      }
      const invokeTool = tools.find((t) => t.name === 'invoke')
      expect(invokeTool?.inputSchema?.properties).toHaveProperty('resource')
      expect(invokeTool?.inputSchema?.properties).toHaveProperty('op_id')
    } finally {
      await client.close()
    }
  }, 30_000)
})
