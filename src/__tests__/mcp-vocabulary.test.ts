// The MCP vocabulary adapter (`urn:aauth:vocabulary:mcp`, R3 -02 §MCP
// Vocabulary). Before it existed, a resource advertising only MCP in
// r3_vocabularies (senzing.aauth.dev) was picked with no vocabularies:
// list_operations returned [] and invoke answered "unknown operation".

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MCPAdapter, jsonRpcFromSse, parseSseMessages } from '../vocab/mcp.js'
import type { McpVocabDoc } from '../vocab/mcp.js'
import { fetchResource, toL1Entry } from '../resource.js'

const ENDPOINT = 'https://mcp.example/mcp'

const TOOLS = [
  {
    name: 'search_entities',
    title: 'Search entities',
    description: 'Find resolved entities matching a set of attributes.',
    inputSchema: { type: 'object', properties: { attributes: { type: 'object' } }, required: ['attributes'] },
    outputSchema: { type: 'object', properties: { entities: { type: 'array' } } },
    _meta: { 'aauth.dev/access-mode': 'auth-token', 'aauth.dev/budget': true },
  },
  {
    name: 'get_entity',
    description: 'Fetch one resolved entity by id.',
    inputSchema: { type: 'object', properties: { entity_id: { type: 'integer' } } },
  },
  {
    name: 'why_records',
    annotations: { title: 'Why records' },
    inputSchema: { type: 'object' },
    _meta: { 'aauth.dev/access-mode': 'session-token' },
  },
]

const json = (body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json', ...headers } })

const sse = (events: unknown[], headers: Record<string, string> = {}) =>
  new Response(events.map((e) => `event: message\ndata: ${JSON.stringify(e)}\n\n`).join(''), {
    status: 200,
    headers: { 'content-type': 'text/event-stream', ...headers },
  })

interface Seen {
  method: string
  id?: number
  params?: Record<string, unknown>
  headers: Record<string, string>
}

/**
 * A fake Streamable HTTP MCP server on global fetch. `pages` are the tools/list
 * pages in order; `mode` picks JSON or SSE answers.
 */
function fakeServer(opts: { mode: 'json' | 'sse'; pages?: unknown[][]; sessionId?: string }) {
  const seen: Seen[] = []
  const pages = opts.pages ?? [TOOLS]
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input)
    if (url !== ENDPOINT) throw new Error(`unexpected fetch ${url}`)
    const msg = JSON.parse(String(init?.body)) as { id?: number; method: string; params?: Record<string, unknown> }
    seen.push({ method: msg.method, id: msg.id, params: msg.params, headers: { ...(init?.headers as Record<string, string>) } })
    const reply = (result: unknown, extra: Record<string, string> = {}) => {
      const body = { jsonrpc: '2.0', id: msg.id, result }
      return opts.mode === 'json'
        ? json(body, extra)
        : // A server may put notifications on the stream ahead of the response.
          sse([{ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info' } }, body], extra)
    }
    switch (msg.method) {
      case 'initialize':
        return reply(
          { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'fake', version: '0' } },
          opts.sessionId ? { 'mcp-session-id': opts.sessionId } : {},
        )
      case 'notifications/initialized':
        return new Response(null, { status: 202 })
      case 'tools/list': {
        const cursor = msg.params?.cursor as string | undefined
        const index = cursor ? Number(cursor.replace('page-', '')) : 0
        const next = index + 1 < pages.length ? { nextCursor: `page-${index + 1}` } : {}
        return reply({ tools: pages[index], ...next })
      }
      default:
        throw new Error(`unexpected method ${msg.method}`)
    }
  })
  return seen
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('MCPAdapter.load', () => {
  it('initializes, then lists tools from a JSON server', async () => {
    const seen = fakeServer({ mode: 'json' })
    const doc = await new MCPAdapter().load(ENDPOINT)

    expect(seen.map((s) => s.method)).toEqual(['initialize', 'notifications/initialized', 'tools/list'])
    expect(seen[0].headers.accept).toBe('application/json, text/event-stream')
    expect(seen[0].params).toMatchObject({ protocolVersion: '2025-06-18' })
    // The negotiated version rides every request after initialize.
    expect(seen[2].headers['mcp-protocol-version']).toBe('2025-06-18')
    expect(doc.endpoint).toBe(ENDPOINT)
    expect(doc.protocolVersion).toBe('2025-06-18')
    expect(doc.tools.map((t) => t.name)).toEqual(['search_entities', 'get_entity', 'why_records'])
  })

  it('reads SSE answers, skipping notifications ahead of the response', async () => {
    fakeServer({ mode: 'sse' })
    const doc = await new MCPAdapter().load(ENDPOINT)
    expect(doc.tools.map((t) => t.name)).toEqual(['search_entities', 'get_entity', 'why_records'])
  })

  it('follows nextCursor across pages', async () => {
    const seen = fakeServer({ mode: 'json', pages: [[TOOLS[0]], [TOOLS[1]], [TOOLS[2]]] })
    const doc = await new MCPAdapter().load(ENDPOINT)
    const lists = seen.filter((s) => s.method === 'tools/list')
    expect(lists.map((s) => s.params?.cursor)).toEqual([undefined, 'page-1', 'page-2'])
    expect(doc.tools.map((t) => t.name)).toEqual(['search_entities', 'get_entity', 'why_records'])
  })

  it('carries Mcp-Session-Id once the server issues one', async () => {
    const seen = fakeServer({ mode: 'sse', sessionId: 'sess-123' })
    await new MCPAdapter().load(ENDPOINT)
    expect(seen[0].headers['mcp-session-id']).toBeUndefined()
    expect(seen[1].headers['mcp-session-id']).toBe('sess-123')
    expect(seen[2].headers['mcp-session-id']).toBe('sess-123')
  })

  it('throws when tools/list answers with a JSON-RPC error', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      const msg = JSON.parse(String(init?.body)) as { id?: number; method: string }
      if (msg.method === 'initialize') return json({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-06-18' } })
      if (msg.method === 'notifications/initialized') return new Response(null, { status: 202 })
      return json({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'no tools here' } })
    })
    await expect(new MCPAdapter().load(ENDPOINT)).rejects.toThrow('no tools here')
  })
})

describe('SSE parsing', () => {
  it('joins multi-line data and ignores comments and non-JSON events', () => {
    const text = ': keepalive\n\ndata: {"a":\ndata: 1}\n\ndata: not json\n\nid: 7\ndata: {"b":2}\n'
    expect(parseSseMessages(text)).toEqual([{ a: 1 }, { b: 2 }])
  })

  it('picks the response by id, else the last response', () => {
    const text = [
      { jsonrpc: '2.0', id: 1, result: 'one' },
      { jsonrpc: '2.0', method: 'notifications/progress' },
      { jsonrpc: '2.0', id: 2, result: 'two' },
    ]
      .map((m) => `data: ${JSON.stringify(m)}\n\n`)
      .join('')
    expect(jsonRpcFromSse(text, 1)).toMatchObject({ result: 'one' })
    expect(jsonRpcFromSse(text)).toMatchObject({ result: 'two' })
  })
})

const DOC: McpVocabDoc = { endpoint: ENDPOINT, protocolVersion: '2025-06-18', tools: TOOLS }

describe('MCPAdapter operations', () => {
  const adapter = new MCPAdapter()

  it('lists every tool as sync.request with title and description as the summary', () => {
    expect(adapter.listOperations(DOC)).toEqual([
      {
        opId: 'search_entities',
        kind: 'sync.request',
        summary: 'Search entities: Find resolved entities matching a set of attributes.',
        annotations: { access_mode: 'auth-token', budget: true },
      },
      { opId: 'get_entity', kind: 'sync.request', summary: 'Fetch one resolved entity by id.' },
      // session-token MUST NOT appear in an annotation, so it is dropped.
      { opId: 'why_records', kind: 'sync.request', summary: 'Why records' },
    ])
  })

  it('filters on free text across name, title and description', () => {
    expect(adapter.listOperations(DOC, 'ENTIT').map((o) => o.opId)).toEqual(['search_entities', 'get_entity'])
    expect(adapter.listOperations(DOC, 'resolved').map((o) => o.opId)).toEqual(['search_entities', 'get_entity'])
    expect(adapter.listOperations(DOC, 'why').map((o) => o.opId)).toEqual(['why_records'])
    expect(adapter.listOperations(DOC, 'nothing')).toEqual([])
  })

  it('returns inputSchema as bodySchema and outputSchema as responseSchema', () => {
    const [search, get] = adapter.getOperations(DOC, ['search_entities', 'get_entity', 'missing'])
    expect(search.bodySchema).toEqual(TOOLS[0].inputSchema)
    expect(search.responseSchema).toEqual(TOOLS[0].outputSchema)
    expect(get.bodySchema).toEqual(TOOLS[1].inputSchema)
    expect(get).not.toHaveProperty('responseSchema')
    expect(adapter.getOperations(DOC, ['missing'])).toEqual([])
  })

  it('reads annotations from _meta', () => {
    expect(adapter.annotationsFor(DOC, 'search_entities')).toEqual({ access_mode: 'auth-token', budget: true })
    expect(adapter.annotationsFor(DOC, 'get_entity')).toEqual({})
    expect(adapter.annotationsFor(DOC, 'missing')).toEqual({})
  })

  it('names an operation as { tool }', () => {
    expect(adapter.operationEntry('search_entities')).toEqual({ tool: 'search_entities' })
  })

  it('builds a tools/call POST to the endpoint path', () => {
    const plan = adapter.buildInvocation(DOC, 'get_entity', { body: { entity_id: 42 } })
    expect(plan).toEqual({
      kind: 'sync.request',
      method: 'POST',
      path: '/mcp',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-06-18',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_entity', arguments: { entity_id: 42 } } }),
    })
  })

  it('sends empty arguments when no body is given, and keeps a query on the endpoint', () => {
    const doc = { ...DOC, endpoint: 'https://mcp.example/rpc/mcp?tenant=a' }
    const plan = adapter.buildInvocation(doc, 'get_entity', {})
    if (plan.kind !== 'sync.request') throw new Error('expected sync.request')
    expect(plan.path).toBe('/rpc/mcp')
    expect(plan.query).toBe('tenant=a')
    expect(JSON.parse(plan.body!).params).toEqual({ name: 'get_entity', arguments: {} })
  })

  it('throws on an unknown tool so routing can try the next vocabulary', () => {
    expect(() => adapter.buildInvocation(DOC, 'missing', {})).toThrow('unknown tool missing')
  })

  it('works on a doc that went through a JSON cache round trip', () => {
    const cached = JSON.parse(JSON.stringify(DOC)) as McpVocabDoc
    expect(adapter.listOperations(cached)).toEqual(adapter.listOperations(DOC))
    expect(adapter.getOperations(cached, ['search_entities'])).toEqual(adapter.getOperations(DOC, ['search_entities']))
    expect(adapter.annotationsFor(cached, 'search_entities')).toEqual({ access_mode: 'auth-token', budget: true })
    expect(adapter.buildInvocation(cached, 'get_entity', { body: { entity_id: 1 } })).toEqual(
      adapter.buildInvocation(DOC, 'get_entity', { body: { entity_id: 1 } }),
    )
  })
})

describe('picking the MCP vocabulary', () => {
  const wellKnown = (vocabs: Record<string, string>) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      json({ issuer: 'https://mcp.example', access_mode: 'auth-token', r3_vocabularies: vocabs }),
    )
  }

  it('picks an MCP-only resource', async () => {
    wellKnown({ 'urn:aauth:vocabulary:mcp': ENDPOINT })
    const entry = toL1Entry(await fetchResource('mcp.example'))
    expect(entry.picked_vocabs).toEqual([{ vocabUri: 'urn:aauth:vocabulary:mcp', docUrl: ENDPOINT }])
  })

  it('drops an MCP endpoint on another origin — calls go to the resource origin', async () => {
    wellKnown({ 'urn:aauth:vocabulary:mcp': 'https://elsewhere.example/mcp' })
    const entry = toL1Entry(await fetchResource('mcp.example'))
    expect(entry.picked_vocabs).toEqual([])
  })
})
