// The MCP vocabulary through the agent: the authorize request names the
// operation in the vocabulary's own entry shape ({ tool } for MCP, still
// { operationId } for OpenAPI), a tools/call answered as SSE comes back as the
// JSON-RPC message, and a resource stored with no picked vocabularies is
// re-read so an MCP-only resource added before the adapter existed recovers.
//
// Real routing and real adapters throughout: only the network is faked —
// global fetch for unsigned requests (well-knowns, vocabulary docs, PS
// metadata), @hellocoop/httpsig for signed ones.

import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { L1Entry, L1Store } from '../store.js'
import type { ProxyConfig } from '../agent.js'

const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

const { invokeAtResource } = await import('../agent.js')
const { McpServer, InMemoryTransport } = await import('@modelcontextprotocol/server')
const { Client } = await import('@modelcontextprotocol/client')
const { buildProxyTools } = await import('../tools.js')
const { createMemoryDocCache } = await import('../resource.js')

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })

const PS_METADATA = {
  issuer: 'https://ps.example',
  auth_token_endpoint: 'https://ps.example/token',
  person_token_endpoint: 'https://ps.example/person',
  jwks_uri: 'https://ps.example/.well-known/jwks.json',
}

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
const AGENT_TOKEN = `${b64({ alg: 'Ed25519', typ: 'aa-agent+jwt' })}.${b64({ iss: 'https://agent.example', ps: 'https://ps.example' })}.sig`

const makeCfg = (): ProxyConfig => ({
  psUrl: 'https://ps.example',
  agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
  agentToken: AGENT_TOKEN,
})

const TOOL = {
  name: 'get_entity',
  description: 'Fetch one resolved entity by id.',
  inputSchema: { type: 'object', properties: { entity_id: { type: 'integer' } } },
}

const OPENAPI = {
  openapi: '3.1.0',
  paths: { '/v1/whoami': { get: { operationId: 'whoami', summary: 'Who am I' } } },
}

/**
 * Unsigned requests: well-knowns, the MCP server's discovery exchange, the
 * OpenAPI doc, PS metadata. Each resource host gets its own URL space.
 */
function routeFetch(wellKnowns: Record<string, unknown>) {
  const hits: string[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input)
    hits.push(url)
    if (url === 'https://ps.example/.well-known/aauth-person.json') return json(PS_METADATA)
    const known = Object.entries(wellKnowns).find(([host]) => url === `https://${host}/.well-known/aauth-resource.json`)
    if (known) return json(known[1])
    if (url.endsWith('/openapi.json')) return json(OPENAPI)
    if (url.endsWith('/mcp')) {
      const msg = JSON.parse(String(init?.body)) as { id?: number; method: string }
      if (msg.method === 'initialize') return json({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-06-18' } })
      if (msg.method === 'notifications/initialized') return new Response(null, { status: 202 })
      if (msg.method === 'tools/list') return json({ jsonrpc: '2.0', id: msg.id, result: { tools: [TOOL] } })
    }
    if (url.includes('.well-known')) return json(PS_METADATA)
    throw new Error(`unexpected fetch ${url}`)
  })
  return hits
}

/** Signed requests: the authorize-first path, then the call itself. */
function routeSignedFetch(call: () => Response) {
  const calls: { url: string; init: { body?: string; method?: string; headers?: Record<string, string> } }[] = []
  mockSignedFetch.mockImplementation(async (url: string, init: { body?: string; method?: string }) => {
    calls.push({ url, init })
    if (url === 'https://ps.example/person') return json({ person_token: 'pt', expires_in: 3600 })
    if (url.endsWith('/authorize')) return json({ resource_token: 'rt' })
    if (url === 'https://ps.example/token') return json({ auth_token: 'at' })
    return call()
  })
  return calls
}

function l1(host: string, vocab: { vocabUri: string; docUrl: string }): L1Entry {
  return {
    resource: host,
    origin: `https://${host}`,
    issuer: `https://${host}`,
    name: host,
    description: 'test',
    access_mode: 'auth-token',
    authorization_endpoint: `https://${host}/authorize`,
    picked_vocabs: [vocab],
    added: '2026-01-01T00:00:00.000Z',
  }
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.restoreAllMocks()
})

describe('authorize-first operation entries', () => {
  it('declares an MCP operation as { tool } and calls tools/call at the endpoint', async () => {
    routeFetch({})
    const calls = routeSignedFetch(() => json({ jsonrpc: '2.0', id: 1, result: { structuredContent: { id: 42 } } }))
    const entry = l1('mcp-a.example', { vocabUri: 'urn:aauth:vocabulary:mcp', docUrl: 'https://mcp-a.example/mcp' })

    const result = await invokeAtResource(makeCfg(), entry, 'get_entity', { body: { entity_id: 42 } })
    expect(result).toEqual({ kind: 'result', status: 200, body: { jsonrpc: '2.0', id: 1, result: { structuredContent: { id: 42 } } } })

    const authz = calls.find((c) => c.url.endsWith('/authorize'))!
    expect(JSON.parse(authz.init.body!)).toEqual({
      r3_operations: { vocabulary: 'urn:aauth:vocabulary:mcp', operations: [{ tool: 'get_entity' }] },
    })
    const call = calls[calls.length - 1]
    expect(call.url).toBe('https://mcp-a.example/mcp')
    expect(call.init.method).toBe('POST')
    expect(JSON.parse(call.init.body!)).toMatchObject({ method: 'tools/call', params: { name: 'get_entity', arguments: { entity_id: 42 } } })
  })

  it('still declares an OpenAPI operation as { operationId }', async () => {
    routeFetch({})
    const calls = routeSignedFetch(() => json({ sub: 'me' }))
    const entry = l1('oas.example', { vocabUri: 'urn:aauth:vocabulary:openapi', docUrl: 'https://oas.example/openapi.json' })

    const result = await invokeAtResource(makeCfg(), entry, 'whoami')
    expect(result).toEqual({ kind: 'result', status: 200, body: { sub: 'me' } })
    const authz = calls.find((c) => c.url.endsWith('/authorize'))!
    expect(JSON.parse(authz.init.body!).r3_operations).toEqual({
      vocabulary: 'urn:aauth:vocabulary:openapi',
      operations: [{ operationId: 'whoami' }],
    })
  })

  it('returns the JSON-RPC message when tools/call is answered as SSE', async () => {
    routeFetch({})
    routeSignedFetch(
      () =>
        new Response(
          `event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress' })}\n\n` +
            `event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'ok' }] } })}\n\n`,
          { status: 200, headers: { 'content-type': 'text/event-stream', 'aauth-budget': 'remaining=9' } },
        ),
    )
    const entry = l1('mcp-b.example', { vocabUri: 'urn:aauth:vocabulary:mcp', docUrl: 'https://mcp-b.example/mcp' })
    const result = await invokeAtResource(makeCfg(), entry, 'get_entity', { body: { entity_id: 1 } })
    expect(result).toEqual({
      kind: 'result',
      status: 200,
      body: { jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'ok' }] } },
      budget: { remaining: 9 },
    })
  })
})

// ── Stale L1 entries ──

function memoryL1(entries: L1Entry[]): L1Store & { map: Map<string, L1Entry> } {
  const map = new Map(entries.map((e) => [e.resource, e]))
  return {
    map,
    list: async () => [...map.values()],
    get: async (host) => map.get(host),
    upsert: async (e) => void map.set(e.resource, e),
    remove: async (host) => map.delete(host),
    touch: async () => {},
  }
}

async function connectClient(store: L1Store) {
  const server = new McpServer({ name: 'test', version: '0.0.0' })
  const cfg = makeCfg()
  await buildProxyTools(server, {
    l1: store,
    registryCache: { read: async () => undefined, write: async () => {} },
    identity: { resolve: async () => ({ kind: 'ready', cfg }), peek: () => cfg },
    docCache: createMemoryDocCache(),
    connectBudgetMs: 30,
  })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test-client', version: '0.0.0' })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return { client, close: async () => void (await client.close()) }
}

const textOf = (result: unknown): string =>
  ((result as { content: { type: string; text?: string }[] }).content ?? []).map((c) => c.text ?? '').join('\n')

/** An entry as a pre-adapter build stored it: the MCP vocabulary was not picked. */
function staleEntry(host: string): L1Entry {
  return {
    resource: host,
    origin: `https://${host}`,
    issuer: `https://${host}`,
    name: host,
    description: 'test',
    access_mode: 'auth-token',
    authorization_endpoint: `https://${host}/authorize`,
    picked_vocabs: [],
    added: '2026-01-01T00:00:00.000Z',
    last_used: '2026-02-01T00:00:00.000Z',
  }
}

const mcpWellKnown = (host: string) => ({
  issuer: `https://${host}`,
  access_mode: 'auth-token',
  authorization_endpoint: `https://${host}/authorize`,
  r3_vocabularies: { 'urn:aauth:vocabulary:mcp': `https://${host}/mcp` },
})

describe('an entry stored with no picked vocabularies is re-read', () => {
  it('list_operations re-reads the well-known and keeps added and last_used', async () => {
    const host = 'stale.example'
    routeFetch({ [host]: mcpWellKnown(host) })
    const store = memoryL1([staleEntry(host)])
    const { client, close } = await connectClient(store)
    try {
      const result = await client.callTool({ name: 'list_operations', arguments: { resource: host } })
      const ops = JSON.parse(textOf(result)) as { opId: string }[]
      expect(ops.map((o) => o.opId)).toEqual(['get_entity'])

      const stored = store.map.get(host)!
      expect(stored.picked_vocabs).toEqual([{ vocabUri: 'urn:aauth:vocabulary:mcp', docUrl: `https://${host}/mcp` }])
      expect(stored.added).toBe('2026-01-01T00:00:00.000Z')
      expect(stored.last_used).toBe('2026-02-01T00:00:00.000Z')
    } finally {
      await close()
    }
  })

  it('connect_resources re-reads a stored entry with no picked vocabularies', async () => {
    const host = 'stale2.example'
    const hits = routeFetch({ [host]: mcpWellKnown(host) })
    const store = memoryL1([staleEntry(host)])
    const { client, close } = await connectClient(store)
    try {
      const result = await client.callTool({ name: 'connect_resources', arguments: { items: [{ resource: host }] } })
      expect(textOf(result)).toContain('urn:aauth:vocabulary:mcp')
      expect(hits).toContain(`https://${host}/.well-known/aauth-resource.json`)
      expect(store.map.get(host)!.picked_vocabs).toHaveLength(1)
    } finally {
      await close()
    }
  })

  it('does not re-read an entry whose metadata is still fresh', async () => {
    const host = 'fresh.example'
    const hits = routeFetch({ [host]: mcpWellKnown(host) })
    const store = memoryL1([{ ...l1(host, { vocabUri: 'urn:aauth:vocabulary:mcp', docUrl: `https://${host}/mcp` }), meta_expires_at: Date.now() + 60_000 }])
    const { client, close } = await connectClient(store)
    try {
      await client.callTool({ name: 'list_operations', arguments: { resource: host } })
      expect(hits).not.toContain(`https://${host}/.well-known/aauth-resource.json`)
    } finally {
      await close()
    }
  })

  // 4.10.0: an entry stored by an earlier version records no lifetime, so it is
  // re-read on its next use, once; after that its own lifetime applies.
  it('re-reads an entry stored before 4.10.0 once, then not again inside its lifetime', async () => {
    const host = 'older.example'
    const hits = routeFetch({ [host]: mcpWellKnown(host) })
    const store = memoryL1([l1(host, { vocabUri: 'urn:aauth:vocabulary:mcp', docUrl: `https://${host}/mcp` })])
    const { client, close } = await connectClient(store)
    const wellKnown = `https://${host}/.well-known/aauth-resource.json`
    try {
      await client.callTool({ name: 'list_operations', arguments: { resource: host } })
      expect(hits.filter((u) => u === wellKnown)).toHaveLength(1)
      expect(store.map.get(host)!.meta_expires_at).toBeGreaterThan(Date.now())
      await client.callTool({ name: 'list_operations', arguments: { resource: host } })
      expect(hits.filter((u) => u === wellKnown)).toHaveLength(1)
    } finally {
      await close()
    }
  })

  it('leaves the entry as it was when the resource still advertises nothing usable', async () => {
    const host = 'empty.example'
    routeFetch({ [host]: { issuer: `https://${host}`, r3_vocabularies: { 'urn:aauth:vocabulary:grpc': `https://${host}/grpc` } } })
    const before = staleEntry(host)
    const store = memoryL1([before])
    const { client, close } = await connectClient(store)
    try {
      const result = await client.callTool({ name: 'list_operations', arguments: { resource: host } })
      expect(JSON.parse(textOf(result))).toEqual([])
      expect(store.map.get(host)).toBe(before)
    } finally {
      await close()
    }
  })
})
