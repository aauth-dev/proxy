// get_operation_schemas returns the resource's own guide as `context`,
// read from its `documentation_uri` when that serves text or markdown (an
// llms.txt). An HTML page is skipped, a long guide is cut, and nothing about
// the guide can fail the call.

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { CONTEXT_MAX_BYTES, DOC_TTL_MS, createMemoryDocCache, loadResourceContext, toL1Entry } from '../resource.js'
import type { L1Entry, L1Store } from '../store.js'

const { McpServer, InMemoryTransport } = await import('@modelcontextprotocol/server')
const { Client } = await import('@modelcontextprotocol/client')
const { buildProxyTools } = await import('../tools.js')

const GUIDE_URL = 'https://res.example/llms.txt'
const GUIDE = '# Res\n\n> How to use res.example.\n\nSend every name you know.\n'

function entry(extra: Partial<L1Entry> = {}): L1Entry {
  return {
    resource: 'res.example',
    origin: 'https://res.example',
    issuer: 'https://res.example',
    name: 'Res',
    description: 'test',
    access_mode: 'auth-token',
    picked_vocabs: [{ vocabUri: 'urn:aauth:vocabulary:openapi', docUrl: 'https://res.example/openapi.json' }],
    added: '2026-01-01T00:00:00.000Z',
    documentation_uri: GUIDE_URL,
    ...extra,
  }
}

type Answer = { status?: number; type?: string; body?: string; etag?: string; cacheControl?: string; fail?: boolean }

/** Answers the guide URL in order, recording each request's If-None-Match. */
function serveGuide(answers: Answer[]) {
  const ifNoneMatch: Array<string | null> = []
  let i = 0
  const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input)
    if (url !== GUIDE_URL) throw new Error(`unexpected fetch ${url}`)
    ifNoneMatch.push(new Headers(init?.headers).get('if-none-match'))
    const a = answers[Math.min(i++, answers.length - 1)]
    if (a.fail) throw new Error('unreachable')
    const headers: Record<string, string> = { 'content-type': a.type ?? 'text/markdown; charset=utf-8' }
    if (a.etag) headers.etag = a.etag
    if (a.cacheControl) headers['cache-control'] = a.cacheControl
    const status = a.status ?? 200
    return new Response(status === 304 ? null : (a.body ?? GUIDE), { status, headers })
  })
  return { spy, ifNoneMatch }
}

beforeEach(() => {
  vi.restoreAllMocks()
})

const T0 = 1_000_000

describe('loadResourceContext', () => {
  it('returns a markdown guide with its URL, and serves it from the cache inside its lifetime', async () => {
    const { spy } = serveGuide([{}])
    const cache = createMemoryDocCache()
    expect(await loadResourceContext(entry(), cache, T0)).toEqual({ context: GUIDE, context_url: GUIDE_URL })
    expect(await loadResourceContext(entry(), cache, T0 + DOC_TTL_MS - 1)).toEqual({ context: GUIDE, context_url: GUIDE_URL })
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('accepts text/plain', async () => {
    serveGuide([{ type: 'text/plain' }])
    expect(await loadResourceContext(entry(), createMemoryDocCache(), T0)).toEqual({ context: GUIDE, context_url: GUIDE_URL })
  })

  it('skips an HTML page, and does not fetch it again inside the hour', async () => {
    const { spy } = serveGuide([{ type: 'text/html; charset=utf-8', body: '<html>docs</html>', cacheControl: 'no-store' }])
    const cache = createMemoryDocCache()
    expect(await loadResourceContext(entry(), cache, T0)).toEqual({})
    expect(await loadResourceContext(entry(), cache, T0 + DOC_TTL_MS - 1)).toEqual({})
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('cuts a guide longer than the cap and names the URL', async () => {
    const long = 'é'.repeat(CONTEXT_MAX_BYTES) // two bytes each: the cut lands mid-character
    serveGuide([{ body: long }])
    const { context } = await loadResourceContext(entry(), createMemoryDocCache(), T0)
    expect(context).toBeDefined()
    const [kept, note] = context!.split('\n\n[')
    expect(new TextEncoder().encode(kept).byteLength).toBeLessThanOrEqual(CONTEXT_MAX_BYTES)
    expect(kept).not.toContain('�')
    expect(note).toContain(GUIDE_URL)
  })

  it('returns nothing, and never throws, when the guide cannot be read', async () => {
    serveGuide([{ fail: true }])
    expect(await loadResourceContext(entry(), createMemoryDocCache(), T0)).toEqual({})
    vi.restoreAllMocks()
    serveGuide([{ status: 500 }])
    expect(await loadResourceContext(entry(), createMemoryDocCache(), T0)).toEqual({})
  })

  it('serves the stale copy when the refetch fails', async () => {
    serveGuide([{ cacheControl: 'max-age=60' }, { fail: true }])
    const cache = createMemoryDocCache()
    await loadResourceContext(entry(), cache, T0)
    expect(await loadResourceContext(entry(), cache, T0 + 61_000)).toEqual({ context: GUIDE, context_url: GUIDE_URL })
  })

  it('revalidates an expired copy with its ETag; a 304 keeps it', async () => {
    const { ifNoneMatch } = serveGuide([{ etag: '"v1"', cacheControl: 'max-age=60' }, { status: 304, cacheControl: 'max-age=60' }])
    const cache = createMemoryDocCache()
    await loadResourceContext(entry(), cache, T0)
    expect(await loadResourceContext(entry(), cache, T0 + 61_000)).toEqual({ context: GUIDE, context_url: GUIDE_URL })
    expect(ifNoneMatch).toEqual([null, '"v1"'])
  })

  it('does not fetch without a documentation_uri, with an http one on an https resource, or on another origin', async () => {
    const { spy } = serveGuide([{}])
    expect(await loadResourceContext(entry({ documentation_uri: undefined }), createMemoryDocCache(), T0)).toEqual({})
    expect(await loadResourceContext(entry({ documentation_uri: 'http://res.example/llms.txt' }), createMemoryDocCache(), T0)).toEqual({})
    expect(await loadResourceContext(entry({ documentation_uri: 'https://docs.other.example/llms.txt' }), createMemoryDocCache(), T0)).toEqual({})
    expect(spy).not.toHaveBeenCalled()
  })
})

describe('toL1Entry keeps documentation_uri', () => {
  const fetched = (documentation_uri: string | undefined, origin = 'https://res.example') => ({
    host: 'res.example',
    origin,
    meta: { issuer: origin, ...(documentation_uri ? { documentation_uri } : {}) },
    pickedVocabs: [],
  })

  it('keeps a URL on the resource\'s own origin and drops anything else', () => {
    expect(toL1Entry(fetched(GUIDE_URL)).documentation_uri).toBe(GUIDE_URL)
    expect(toL1Entry(fetched('http://res.example/llms.txt')).documentation_uri).toBeUndefined()
    expect(toL1Entry(fetched('https://docs.res.example/llms.txt')).documentation_uri).toBeUndefined()
    expect(toL1Entry(fetched('https://github.com/res/docs')).documentation_uri).toBeUndefined()
    expect(toL1Entry(fetched('not a url')).documentation_uri).toBeUndefined()
    expect(toL1Entry(fetched(undefined)).documentation_uri).toBeUndefined()
  })

  it('keeps an http URL for a local http resource', () => {
    expect(toL1Entry(fetched('http://localhost:8787/llms.txt', 'http://localhost:8787')).documentation_uri).toBe('http://localhost:8787/llms.txt')
  })
})

// ── The tool ──

const OPENAPI = {
  openapi: '3.1.0',
  paths: { '/v1/search': { post: { operationId: 'search', summary: 'Search', requestBody: { content: { 'application/json': { schema: { type: 'object' } } } } } } },
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

/** The well-known (with or without documentation_uri), the OpenAPI doc and the guide. */
function serveResource(documentationUri: string | undefined) {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input)
    const json = (b: unknown) => new Response(JSON.stringify(b), { headers: { 'content-type': 'application/json' } })
    if (url === 'https://res.example/.well-known/aauth-resource.json') {
      return json({
        issuer: 'https://res.example',
        access_mode: 'auth-token',
        r3_vocabularies: { 'urn:aauth:vocabulary:openapi': 'https://res.example/openapi.json' },
        ...(documentationUri ? { documentation_uri: documentationUri } : {}),
      })
    }
    if (url === 'https://res.example/openapi.json') return json(OPENAPI)
    if (url === GUIDE_URL) return new Response(GUIDE, { headers: { 'content-type': 'text/markdown' } })
    throw new Error(`unexpected fetch ${url}`)
  })
}

async function schemasFor(documentationUri: string | undefined): Promise<Record<string, unknown>> {
  serveResource(documentationUri)
  // No documentation_uri and no lifetime on the stored entry: the tool re-reads the well-known first.
  const store = memoryL1([entry({ documentation_uri: undefined })])
  const server = new McpServer({ name: 'test', version: '0.0.0' })
  const cfg = {
    psUrl: 'https://ps.example',
    agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' },
    agentToken: 'a.b.c',
  } as never
  await buildProxyTools(server, {
    l1: store,
    registryCache: { read: async () => undefined, write: async () => {} },
    identity: { resolve: async () => ({ kind: 'ready', cfg }), peek: () => cfg },
    docCache: createMemoryDocCache(),
  })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test-client', version: '0.0.0' })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  try {
    const result = await client.callTool({ name: 'get_operation_schemas', arguments: { resource: 'res.example', op_ids: ['search'] } })
    const text = (result as { content: { text?: string }[] }).content.map((c) => c.text ?? '').join('')
    return JSON.parse(text) as Record<string, unknown>
  } finally {
    await client.close()
  }
}

describe('get_operation_schemas', () => {
  it('returns the guide once, beside the operations', async () => {
    const out = await schemasFor(GUIDE_URL)
    expect(Object.keys(out)).toEqual(['context', 'context_url', 'operations'])
    expect(out.context).toBe(GUIDE)
    expect(out.context_url).toBe(GUIDE_URL)
    expect((out.operations as { opId: string }[]).map((o) => o.opId)).toEqual(['search'])
  })

  it('returns only the operations when the resource publishes no guide', async () => {
    const out = await schemasFor(undefined)
    expect(Object.keys(out)).toEqual(['operations'])
    expect((out.operations as { opId: string }[]).map((o) => o.opId)).toEqual(['search'])
  })
})
