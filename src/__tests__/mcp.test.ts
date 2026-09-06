// Smoke test for the agent proxy as an MCP server: spawn it over stdio with the SDK's own
// client (real handshake) and confirm it advertises its tools. Uses a dummy
// identity — listing tools triggers no network.
//
// serveStdio pins the connection's era on the opening exchange, so both the
// 2025-era `initialize` handshake ('legacy') and the 2026-07-28 `server/discover`
// probe ('auto' → modern) are exercised.

import { describe, it, expect } from 'vitest'
import { Client } from '@modelcontextprotocol/client'
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'

const EXPECTED_TOOLS = [
  'add_resource',
  'find_resources',
  'get_operation_schemas',
  'invoke',
  'list_operations',
  'list_resources',
  'remove_resource',
  'reset_tokens',
]

describe('agent proxy MCP server', () => {
  for (const mode of ['legacy', 'auto'] as const) {
    it(`starts over stdio and advertises the tool surface (versionNegotiation: ${mode})`, async () => {
      const transport = new StdioClientTransport({
        command: 'npx',
        args: ['tsx', 'src/server.ts'],
        env: {
          ...(process.env as Record<string, string>),
          PROXY_PS_URL: 'http://localhost:2',
          PROXY_AGENT_TOKEN: 'x.y.z',
          PROXY_AGENT_PRIVATE_JWK: JSON.stringify({ kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' }),
        },
      })
      const client = new Client(
        { name: 'aauth-proxy-test', version: '0.0.0' },
        { versionNegotiation: { mode } },
      )

      try {
        await client.connect(transport)
        if (mode === 'auto') expect(client.getDiscoverResult()).toBeDefined()
        const { tools } = await client.listTools()
        const names = tools.map((t) => t.name).sort()
        for (const expected of EXPECTED_TOOLS) expect(names).toContain(expected)
        const invokeTool = tools.find((t) => t.name === 'invoke')
        expect(invokeTool?.inputSchema?.properties).toHaveProperty('resource')
        expect(invokeTool?.inputSchema?.properties).toHaveProperty('op_id')
      } finally {
        await client.close()
      }
    }, 30_000)
  }
})
