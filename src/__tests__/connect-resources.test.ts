// connect_resources (4.1.0): the list form, driven through a real MCP server
// over an in-memory transport so the tool handler itself is under test — not
// just the agent.ts functions it calls.
//
// Two regressions are guarded here. The first motivated the tool: with
// connect_resource, item N+1 was only created after the model saw item N's
// answer and called again, and a second call must resume the same PS pendings
// rather than create a second set. The second motivated the live window (D14
// revised): starting every item up front minted a pile of resource-side
// interaction codes that expired before the person reached them (prod,
// 2026-09-12: 29 queued, the tail dead on arrival; prod, 2026-09-15: 27 started
// at once because a bare 202 from the PS was not counted as live). So ONE item
// is live at a time, the rest are accepted as `queued`, and the next starts the
// moment the head lands — in the same call when budget remains.

import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

const { McpServer, InMemoryTransport } = await import('@modelcontextprotocol/server')
const { Client } = await import('@modelcontextprotocol/client')
const { buildProxyTools } = await import('../tools.js')
import type { L1Entry, L1Store } from '../store.js'
import type { ProxyConfig } from '../agent.js'

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

// A FRESH object per server: the default in-flight store is a WeakMap keyed on
// the ProxyConfig identity, so a shared config would carry one test's pendings
// into the next (and, in a real multi-user host, one principal's into another).
const makeCfg = (): ProxyConfig => ({
  psUrl: 'https://ps.example',
  agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
  agentToken: AGENT_TOKEN,
})

/**
 * Routes by URL rather than call order: two items interleave three signed calls
 * each, and an ordered queue would only assert the order this implementation
 * happens to use today.
 */
function routeSignedFetch(opts: { pollStatus?: number; bare202?: boolean } = {}) {
  const posted: string[] = []
  let codeSeq = 0
  mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
    if (url === 'https://ps.example/person') return makeResponse(200, { person_token: 'pt_abc', expires_in: 3600 })
    if (url.endsWith('/connections')) {
      if ((init?.method ?? 'GET') === 'POST') posted.push(url)
      // GET is the connections listing refreshConnections does; POST starts one.
      return (init?.method ?? 'GET') === 'POST'
        ? makeResponse(200, { resource_token: 'rt_conn' })
        : makeResponse(200, { connections: [] })
    }
    if (url === 'https://ps.example/token') {
      codeSeq += 1
      const code = `CODE-${String(codeSeq).padStart(4, '0')}`
      // bare202: the PS is reaching the person by its own channels (an open
      // wallet tab) and advertises no interaction yet — Location only. This is
      // what the wallet answers in production.
      return makeResponse(202, {}, {
        ...(opts.bare202 ? {} : { 'aauth-requirement': `requirement=interaction; code="${code}"` }),
        location: `https://ps.example/pending/${code}`,
      })
    }
    if (url.startsWith('https://ps.example/pending/')) return makeResponse(opts.pollStatus ?? 202, {})
    throw new Error(`unexpected signed fetch: ${url}`)
  })
  return { posted }
}

async function connectClient(l1: L1Store, connectBudgetMs = 30) {
  const server = new McpServer({ name: 'test', version: '0.0.0' })
  const cfg = makeCfg()
  await buildProxyTools(server, {
    l1,
    registryCache: { read: async () => undefined, write: async () => {} },
    identity: { resolve: async () => ({ kind: 'ready', cfg }), peek: () => cfg },
    // A short slice keeps the test fast: only the waiting is cut short.
    connectBudgetMs,
  })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test-client', version: '0.0.0' })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return { client, close: async () => void (await client.close()) }
}

const textOf = (result: unknown): string =>
  ((result as { content: { type: string; text?: string }[] }).content ?? [])
    .map((c) => c.text ?? '')
    .join('\n')

beforeEach(() => {
  vi.resetAllMocks()
  vi.restoreAllMocks()
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => makeResponse(200, PS_METADATA))
})

describe('connect_resources', () => {
  it('starts the head in ONE call and holds the rest queued behind it', async () => {
    const { posted } = routeSignedFetch()
    const l1 = memoryL1([entry('gmail.example'), entry('calendar.example')])
    const { client, close } = await connectClient(l1)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: {
          items: [
            { resource: 'gmail.example', account: 'a@b.co' },
            { resource: 'calendar.example', account: 'a@b.co' },
          ],
        },
      })

      // Only the head's code exists: the second is accepted but not minted
      // until the first lands, so it cannot expire while the person is busy.
      expect(posted).toEqual(['https://gmail.example/connections'])

      const body = textOf(result)
      const summary = JSON.parse(body.slice(0, body.indexOf('\n\n')) || body) as {
        results: { resource: string; outcome: string }[]
        pending: number
        queued: number
      }
      expect(summary.results.map((r) => r.resource)).toEqual(['gmail.example', 'calendar.example'])
      expect(summary.results.map((r) => r.outcome)).toEqual(['still_pending', 'queued'])
      expect(summary.pending).toBe(1)
      expect(summary.queued).toBe(1)

      // Only the head is surfaced, and the person is told what is behind it.
      expect(body).toContain('CODE-0001')
      expect(body).not.toContain('CODE-0002')
      expect(body).toContain('1 more queued behind it')
    } finally {
      await close()
    }
  })

  it('a repeat call resumes the same pendings instead of starting a second set', async () => {
    const { posted } = routeSignedFetch()
    const l1 = memoryL1([entry('gmail.example'), entry('calendar.example')])
    const { client, close } = await connectClient(l1)
    try {
      const args = {
        items: [
          { resource: 'gmail.example', account: 'a@b.co' },
          { resource: 'calendar.example', account: 'a@b.co' },
        ],
      }
      await client.callTool({ name: 'connect_resources', arguments: args })
      expect(posted).toHaveLength(1)

      await client.callTool({ name: 'connect_resources', arguments: args })
      // Still one: the second call polled the live pending. Re-POSTing would
      // orphan the record the person is looking at.
      expect(posted).toHaveLength(1)
    } finally {
      await close()
    }
  })

  it('starts only up to the live window and marks the rest queued', async () => {
    const { posted } = routeSignedFetch()
    const hosts = ['a.example', 'b.example', 'c.example', 'd.example', 'e.example']
    const l1 = memoryL1(hosts.map((h) => entry(h)))
    const { client, close } = await connectClient(l1)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: { items: hosts.map((h) => ({ resource: h, account: 'a@b.co' })) },
      })
      const body = textOf(result)
      const summary = JSON.parse(body.slice(0, body.indexOf('\n\n')) || body) as {
        results: { resource: string; outcome: string }[]
        pending: number
        queued: number
        next?: string
      }

      // One interaction code was minted — the rest were held back, so nothing
      // piles up counting down at once.
      expect(posted).toEqual(['https://a.example/connections'])
      expect(summary.results.map((r) => r.outcome)).toEqual([
        'still_pending',
        'queued',
        'queued',
        'queued',
        'queued',
      ])
      expect(summary.pending).toBe(1)
      expect(summary.queued).toBe(4)
      // Queued items keep the agent calling back to advance the window.
      expect(summary.next).toBeTruthy()
    } finally {
      await close()
    }
  })

  it('a repeat call resumes the live set without minting a second code, and holds queued items', async () => {
    // a goes live, b..e queued. A repeat call must resume a (no re-POST) and
    // must NOT start b..e while the window is full — no code is minted twice
    // and no extra codes are minted for the held items.
    const { posted } = routeSignedFetch()
    const hosts = ['a.example', 'b.example', 'c.example', 'd.example', 'e.example']
    const l1 = memoryL1(hosts.map((h) => entry(h)))
    const { client, close } = await connectClient(l1)
    try {
      const args = { items: hosts.map((h) => ({ resource: h, account: 'a@b.co' })) }
      await client.callTool({ name: 'connect_resources', arguments: args })
      expect(posted).toHaveLength(1)

      await client.callTool({ name: 'connect_resources', arguments: args })
      // Still exactly one POST total: the live one resumed, queued ones held.
      expect(posted).toEqual(['https://a.example/connections'])
    } finally {
      await close()
    }
  })

  it('a bare 202 from the PS (no interaction advertised) still holds the one live slot', async () => {
    // The wallet answers the exchange with 202 + Location and no
    // AAuth-Requirement when it believes it can reach the person itself. That
    // item is just as live as one with an advertised code — not counting it is
    // what let 27 items start at once (prod, 2026-09-15).
    const { posted } = routeSignedFetch({ bare202: true })
    const hosts = ['a.example', 'b.example', 'c.example']
    const l1 = memoryL1(hosts.map((h) => entry(h)))
    const { client, close } = await connectClient(l1)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: { items: hosts.map((h) => ({ resource: h, account: 'a@b.co' })) },
      })
      expect(posted).toEqual(['https://a.example/connections'])
      const summary = JSON.parse(textOf(result)) as { results: { outcome: string }[]; pending: number; queued: number }
      expect(summary.results.map((r) => r.outcome)).toEqual(['still_pending', 'queued', 'queued'])
      expect(summary.pending).toBe(1)
      expect(summary.queued).toBe(2)
    } finally {
      await close()
    }
  })

  it('starts the next queued item in the same call as soon as the head lands', async () => {
    // Every poll answers 200 (the person approves at once), so one call should
    // walk the whole list: land a, start b, land b, ... — no round trip through
    // the model between connections, and never more than one code alive.
    const { posted } = routeSignedFetch({ pollStatus: 200 })
    const hosts = ['a.example', 'b.example', 'c.example', 'd.example', 'e.example']
    const l1 = memoryL1(hosts.map((h) => entry(h)))
    const { client, close } = await connectClient(l1, 5_000)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: { items: hosts.map((h) => ({ resource: h, account: 'a@b.co' })) },
      })
      expect(posted).toEqual(hosts.map((h) => `https://${h}/connections`))
      const summary = JSON.parse(textOf(result)) as { results: { outcome: string }[]; pending: number; queued?: number; next?: string }
      expect(summary.results.map((r) => r.outcome)).toEqual(['connected', 'connected', 'connected', 'connected', 'connected'])
      expect(summary.pending).toBe(0)
      expect(summary.queued).toBeUndefined()
      expect(summary.next).toBeUndefined()
    } finally {
      await close()
    }
  })

  it('an item needing no connection answers ready without calling the PS', async () => {
    const { posted } = routeSignedFetch()
    const bare = { ...entry('whoami.example'), connection: undefined, access_mode: 'agent-token' as const }
    const l1 = memoryL1([bare])
    const { client, close } = await connectClient(l1)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: { items: [{ resource: 'whoami.example' }] },
      })
      const summary = JSON.parse(textOf(result)) as { results: { outcome: string; reason: string }[]; pending: number }
      expect(summary.results[0]).toMatchObject({ outcome: 'ready', reason: 'no_connection_needed' })
      expect(summary.pending).toBe(0)
      expect(posted).toEqual([])
    } finally {
      await close()
    }
  })
})
