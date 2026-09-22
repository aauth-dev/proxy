// Coming resources (registry `availability`): find_resources lists them after
// the available ones, tagged `connectable: false` with the reason and the
// interest count, searches them by `upstream`, and connect_resources refuses
// one before touching the host — a gated resource serves valid metadata and
// would otherwise be connected only to answer every call with an access error.

import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

const { McpServer, InMemoryTransport } = await import('@modelcontextprotocol/server')
const { Client } = await import('@modelcontextprotocol/client')
const { buildProxyTools } = await import('../tools.js')
import type { L1Store } from '../store.js'
import type { ProxyConfig } from '../agent.js'
import type { RegistryIndex } from '../registry.js'

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
const AGENT_TOKEN = `${b64({ alg: 'Ed25519', typ: 'aa-agent+jwt' })}.${b64({ iss: 'https://agent.example', ps: 'https://ps.example' })}.sig`

const makeResponse = (status: number, body: unknown, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })

const INDEX: RegistryIndex = {
  updated: '2026-09-15T00:00:00.000Z',
  resources: [
    {
      issuer: 'https://gmail-googleapis-com.proxy.aauth.dev',
      name: 'Gmail AAuth Connector',
      description: 'Gmail fronted with AAuth.',
      access_mode: 'person-token',
      added: '2026-09-15T00:00:00.000Z',
      availability: 'Not yet public — Google has not verified the app.',
      upstream: 'gmail.googleapis.com',
      interest_count: 3,
    },
    {
      issuer: 'https://slack-com.proxy.aauth.dev',
      name: 'Slack AAuth Connector',
      description: 'Slack fronted with AAuth.',
      access_mode: 'person-token',
      added: '2026-09-15T00:00:00.000Z',
      upstream: 'slack.com',
    },
  ],
}

const emptyL1 = (): L1Store => ({
  list: async () => [],
  get: async () => undefined,
  upsert: async () => {},
  remove: async () => false,
  touch: async () => {},
})

const makeCfg = (): ProxyConfig => ({
  psUrl: 'https://ps.example',
  agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
  agentToken: AGENT_TOKEN,
})

async function clientFor(l1: L1Store) {
  const server = new McpServer({ name: 'test', version: '0.0.0' })
  const cfg = makeCfg()
  await buildProxyTools(server, {
    l1,
    registryCache: { read: async () => undefined, write: async () => {} },
    identity: { resolve: async () => ({ kind: 'ready', cfg }), peek: () => cfg },
    connectBudgetMs: 30,
  })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test-client', version: '0.0.0' })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return { client, close: async () => void (await client.close()) }
}

const textOf = (result: unknown): string =>
  ((result as { content: { type: string; text?: string }[] }).content ?? []).map((c) => c.text ?? '').join('\n')

beforeEach(() => {
  vi.resetAllMocks()
  vi.restoreAllMocks()
  mockSignedFetch.mockImplementation(async (url: string) => {
    if (url === 'https://registry.aauth.dev/resources') return makeResponse(200, INDEX)
    throw new Error(`unexpected signed fetch: ${url}`)
  })
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    throw new Error(`unexpected fetch: ${String(input)}`)
  })
})

describe('coming resources', () => {
  it('find_resources lists coming entries last, not connectable, with the reason', async () => {
    const { client, close } = await clientFor(emptyL1())
    try {
      const res = JSON.parse(textOf(await client.callTool({ name: 'find_resources', arguments: {} })))
      expect(res.resources.map((r: { resource: string }) => r.resource)).toEqual([
        'slack-com.proxy.aauth.dev',
        'gmail-googleapis-com.proxy.aauth.dev',
      ])
      const [slack, gmail] = res.resources
      expect(slack).not.toHaveProperty('connectable')
      expect(slack.upstream).toBe('slack.com')
      expect(gmail.connectable).toBe(false)
      expect(gmail.availability).toMatch(/Google has not verified/)
      expect(gmail.interest_count).toBe(3)
      expect(gmail.upstream).toBe('gmail.googleapis.com')
      expect(gmail).not.toHaveProperty('skip_reason')
    } finally {
      await close()
    }
  })

  it('find_resources matches on upstream', async () => {
    const { client, close } = await clientFor(emptyL1())
    try {
      const res = JSON.parse(textOf(await client.callTool({ name: 'find_resources', arguments: { query: 'googleapis' } })))
      expect(res.resources.map((r: { resource: string }) => r.resource)).toEqual(['gmail-googleapis-com.proxy.aauth.dev'])
    } finally {
      await close()
    }
  })

  it('connect_resources refuses a coming resource without touching the host', async () => {
    const { client, close } = await clientFor(emptyL1())
    try {
      const res = JSON.parse(
        textOf(await client.callTool({ name: 'connect_resources', arguments: { items: [{ resource: 'gmail-googleapis-com.proxy.aauth.dev' }] } })),
      )
      const row = res.results[0]
      expect(row.outcome).toBe('error')
      expect(row.detail).toMatch(/^not_available: Not yet public/)
      expect(row.connectable).toBe(false)
      expect(row.upstream).toBe('gmail.googleapis.com')
      expect(row.interest_count).toBe(3)
      // Only the registry was read — the host's well-known was never fetched.
      expect(vi.mocked(globalThis.fetch)).not.toHaveBeenCalled()
      expect(mockSignedFetch.mock.calls.map((c) => c[0])).toEqual(['https://registry.aauth.dev/resources'])
    } finally {
      await close()
    }
  })
})
