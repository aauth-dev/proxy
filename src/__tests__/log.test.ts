// The proxy's event sink (log.ts): a host wires ProxyDeps.log and gets one
// `tool.call` per tool invocation plus the AAuth exchange underneath it —
// `aauth.request` for every signed call, `resource.fetch` for metadata,
// `person_token.hit` for a cache hit. Driven through a real MCP server over an
// in-memory transport so the wrapper around registerTool is what is under test.
//
// The privacy contract is asserted too: identifiers yes, values never.

import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

const { McpServer, InMemoryTransport } = await import('@modelcontextprotocol/server')
const { Client } = await import('@modelcontextprotocol/client')
const { buildProxyTools } = await import('../tools.js')
const { logUrl, toolFields } = await import('../log.js')
import type { L1Entry, L1Store } from '../store.js'
import type { ProxyConfig } from '../agent.js'
import type { ProxyLogFields } from '../log.js'

const PS_METADATA = {
  issuer: 'https://ps.example',
  auth_token_endpoint: 'https://ps.example/token',
  person_token_endpoint: 'https://ps.example/person',
  interaction_endpoint: 'https://ps.example/auth',
  jwks_uri: 'https://ps.example/.well-known/jwks.json',
}

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
const AGENT_TOKEN = `${b64({ alg: 'Ed25519', typ: 'aa-agent+jwt' })}.${b64({ iss: 'https://agent.example', ps: 'https://ps.example' })}.sig`

const makeResponse = (status: number, body: unknown, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })

function entry(host: string): L1Entry {
  return {
    resource: host,
    origin: `https://${host}`,
    issuer: `https://${host}`,
    name: host,
    description: 'test',
    access_mode: 'person-token',
    interaction_endpoint: `https://${host}/connect`,
    connection: {
      endpoint: `https://${host}/connections`,
      upstream_name: 'Google',
      account_description: 'Google account email address',
    },
    picked_vocabs: [{ vocabUri: 'urn:aauth:vocabulary:openapi', docUrl: `https://${host}/openapi.json` }],
    added: '2026-01-01T00:00:00.000Z',
  }
}

function memoryL1(entries: L1Entry[]): L1Store {
  const map = new Map(entries.map((e) => [e.resource, e]))
  return {
    list: async () => [...map.values()],
    get: async (host) => map.get(host),
    upsert: async (e) => void map.set(e.resource, e),
    remove: async (host) => map.delete(host),
    touch: async () => {},
  }
}

const makeCfg = (): ProxyConfig => ({
  psUrl: 'https://ps.example',
  agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
  agentToken: AGENT_TOKEN,
})

async function connectClient(l1: L1Store) {
  const events: { event: string; fields: ProxyLogFields }[] = []
  const server = new McpServer({ name: 'test', version: '0.0.0' })
  const cfg = makeCfg()
  await buildProxyTools(server, {
    l1,
    registryCache: { read: async () => undefined, write: async () => {} },
    identity: { resolve: async () => ({ kind: 'ready', cfg }), peek: () => cfg },
    connectBudgetMs: 30,
    log: (event, fields) => void events.push({ event, fields }),
  })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test-client', version: '0.0.0' })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return { client, cfg, events, close: async () => void (await client.close()) }
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.restoreAllMocks()
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => makeResponse(200, PS_METADATA))
})

describe('proxy log sink', () => {
  it('reports one tool.call per invocation with identifiers and outcome, and copies the sink onto the config', async () => {
    const l1 = memoryL1([entry('gmail.example')])
    const { client, cfg, events, close } = await connectClient(l1)
    try {
      await client.callTool({ name: 'list_resources', arguments: {} })
      const calls = events.filter((e) => e.event === 'tool.call')
      expect(calls).toHaveLength(1)
      expect(calls[0].fields).toMatchObject({ tool: 'list_resources', ok: true })
      expect(typeof calls[0].fields.duration_ms).toBe('number')
      // getConfig ran for list_resources, so the sink is now on the config too.
      expect(cfg.log).toBeDefined()
    } finally {
      await close()
    }
  })

  it('reports the signed AAuth requests underneath connect_resources — url without query, no token, no account value', async () => {
    mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (url === 'https://ps.example/person') return makeResponse(200, { person_token: 'pt_secret', expires_in: 3600 })
      if (url.endsWith('/connections')) {
        return (init?.method ?? 'GET') === 'POST'
          ? makeResponse(200, { resource_token: 'rt_conn' })
          : makeResponse(200, { connections: [] })
      }
      if (url === 'https://ps.example/token') {
        return makeResponse(202, {}, {
          'aauth-requirement': 'requirement=interaction; code="CODE-1"',
          location: 'https://ps.example/pending/CODE-1?secret=1',
        })
      }
      if (url.startsWith('https://ps.example/pending/')) return makeResponse(202, {})
      throw new Error(`unexpected signed fetch: ${url}`)
    })
    const l1 = memoryL1([entry('gmail.example')])
    const { client, events, close } = await connectClient(l1)
    try {
      await client.callTool({
        name: 'connect_resources',
        arguments: { items: [{ resource: 'gmail.example', account: 'person@example.com' }] },
      })

      const call = events.find((e) => e.event === 'tool.call')
      expect(call?.fields).toMatchObject({ tool: 'connect_resources', items: 1, resources: ['gmail.example'] })

      const reqs = events.filter((e) => e.event === 'aauth.request').map((e) => e.fields)
      const urls = reqs.map((r) => r.url as string)
      expect(urls).toContain('https://ps.example/person')
      expect(urls).toContain('https://gmail.example/connections')
      expect(urls).toContain('https://ps.example/token')
      // The poll URL's query string is stripped.
      expect(urls.some((u) => u.startsWith('https://ps.example/pending/CODE-1'))).toBe(true)
      expect(urls.every((u) => !u.includes('?'))).toBe(true)
      // Credential kinds are named; the person-token POST to the resource is signed with the person token.
      expect(reqs.find((r) => r.url === 'https://gmail.example/connections' && r.method === 'POST')?.credential).toBe('person')
      expect(reqs.find((r) => r.url === 'https://ps.example/token')).toMatchObject({ status: 202, requirement: 'interaction' })

      // Nothing sensitive anywhere in the stream.
      const serialized = JSON.stringify(events)
      expect(serialized).not.toContain('pt_secret')
      expect(serialized).not.toContain('rt_conn')
      expect(serialized).not.toContain('person@example.com')
      expect(serialized).not.toContain('secret=1')
    } finally {
      await close()
    }
  })

  it('a non-2xx aauth.request carries the error CODE and nothing else from the body', async () => {
    // The two shapes seen in production: a resource's OAuth-style
    // `{"error":"account_required", …}` and the wallet's
    // `{"error":{"message":"NO_SESSION"}}`. Without the code a 400 was
    // indistinguishable from any other 400 (2026-09-15); the rest of the body
    // (`detail`, `account_description`) stays out — it can echo what was sent.
    mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (url === 'https://ps.example/person') {
        return makeResponse(403, { error: { message: 'NO_SESSION' }, detail: 'session for person@example.com' })
      }
      throw new Error(`unexpected signed fetch: ${url}`)
    })
    const l1 = memoryL1([entry('github.example')])
    const { client, events, close } = await connectClient(l1)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: { items: [{ resource: 'github.example', account: 'octocat' }] },
      })
      const req = events.find((e) => e.event === 'aauth.request' && e.fields.url === 'https://ps.example/person')
      expect(req?.fields).toMatchObject({ status: 403, ok: false, error_code: 'NO_SESSION' })
      expect(req?.fields.error).toBeUndefined() // `error` means the fetch threw; it did not

      // The caller still reads the body itself (logging reads a clone).
      const text = (result as { content: { text?: string }[] }).content.map((c) => c.text ?? '').join('')
      expect(text).toContain('NO_SESSION')

      const serialized = JSON.stringify(events)
      expect(serialized).not.toContain('person@example.com')
      expect(serialized).not.toContain('detail')
    } finally {
      await close()
    }

    // A string `error` (resource proxies): the code is lifted, its neighbours are not.
    mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (url === 'https://ps.example/person') return makeResponse(200, { person_token: 'pt_secret', expires_in: 3600 })
      if (url === 'https://github.example/connections' && init?.method === 'POST') {
        return makeResponse(400, { error: 'account_required', account_description: 'GitHub username', detail: 'octocat' })
      }
      throw new Error(`unexpected signed fetch: ${url}`)
    })
    const second = await connectClient(memoryL1([entry('github.example')]))
    try {
      await second.client.callTool({
        name: 'connect_resources',
        arguments: { items: [{ resource: 'github.example', account: 'octocat' }] },
      })
      const req = second.events.find((e) => e.event === 'aauth.request' && e.fields.url === 'https://github.example/connections')
      expect(req?.fields).toMatchObject({ status: 400, ok: false, error_code: 'account_required' })
      const serialized = JSON.stringify(second.events)
      expect(serialized).not.toContain('GitHub username')
      expect(serialized).not.toContain('octocat')
    } finally {
      await second.close()
    }
  })

  it('logUrl strips the query and toolFields reduces values to presence', () => {
    expect(logUrl('https://r.example/v1/messages?q=from%3Aboss')).toBe('https://r.example/v1/messages')
    expect(toolFields('invoke', {
      resource: 'gmail.example',
      op_id: 'messages.list',
      account: 'person@example.com',
      query: 'q=from:boss',
      body: { to: 'x' },
      path_params: { id: '1' },
    })).toEqual({ tool: 'invoke', resource: 'gmail.example', op_id: 'messages.list', account: true, query: true })
  })
})
