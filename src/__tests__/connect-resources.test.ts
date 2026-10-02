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
// at once because a bare 202 from the PS was not counted as live). So TWO items
// are live at a time (one before 5.2.0), the rest are accepted as `queued`, and
// the next starts the moment one lands.
//
// 5.2.0 adds the one-call walk: a client that sends a progressToken is not
// handed back to the model every 30 s, finished items are not asked again, and
// a URL the person must open is handed over once, at once (prod, 2026-09-25: 13
// items, 12 calls, 9 of them connected twice).

import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

const { McpServer, InMemoryTransport } = await import('@modelcontextprotocol/server')
const { serveStdio } = await import('@modelcontextprotocol/server/stdio')
const { Client, UrlElicitationRequiredError } = await import('@modelcontextprotocol/client')
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
function routeSignedFetch(opts: { pollStatus?: number; bare202?: boolean; pendingPolls?: number } = {}) {
  const posted: string[] = []
  const polls = new Map<string, number>()
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
    if (url.startsWith('https://ps.example/pending/')) {
      // pendingPolls: the person approves after this many polls of each code.
      if (opts.pendingPolls !== undefined) {
        const n = (polls.get(url) ?? 0) + 1
        polls.set(url, n)
        return makeResponse(n > opts.pendingPolls ? 200 : 202, {})
      }
      return makeResponse(opts.pollStatus ?? 202, {})
    }
    throw new Error(`unexpected signed fetch: ${url}`)
  })
  return { posted }
}

async function connectClient(
  l1: L1Store,
  connectBudgetMs = 30,
  connectProgressBudgetMs?: number,
  onInteraction?: (url: string, code: string) => void | Promise<void>,
  connectDrainMs?: number,
) {
  const server = new McpServer({ name: 'test', version: '0.0.0' })
  const cfg = makeCfg()
  await buildProxyTools(server, {
    ...(onInteraction ? { onInteraction } : {}),
    l1,
    registryCache: { read: async () => undefined, write: async () => {} },
    identity: { resolve: async () => ({ kind: 'ready', cfg }), peek: () => cfg },
    // A short slice keeps the test fast: only the waiting is cut short.
    connectBudgetMs,
    ...(connectProgressBudgetMs !== undefined ? { connectProgressBudgetMs } : {}),
    ...(connectDrainMs !== undefined ? { connectDrainMs } : {}),
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
  const summaryOf = (result: unknown) => {
    const body = textOf(result)
    return JSON.parse(body.includes('\n\n') ? body.slice(0, body.indexOf('\n\n')) : body) as {
      results: { resource: string; outcome: string }[]
      pending: number
      queued?: number
      next?: string
      awaiting?: { resource: string; url: string }
    }
  }

  it('starts two live in ONE call, holds the rest queued, and hands the head URL over at once', async () => {
    const { posted } = routeSignedFetch()
    const l1 = memoryL1([entry('gmail.example'), entry('calendar.example'), entry('docs.example')])
    const { client, close } = await connectClient(l1)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: {
          items: [
            { resource: 'gmail.example', account: 'a@b.co' },
            { resource: 'calendar.example', account: 'a@b.co' },
            { resource: 'docs.example', account: 'a@b.co' },
          ],
        },
      })

      // Two codes exist: the one the person is looking at and the next one,
      // already waiting at the PS. The third is not minted until a slot frees.
      expect(posted).toEqual(['https://gmail.example/connections', 'https://calendar.example/connections'])

      const summary = summaryOf(result)
      expect(summary.results.map((r) => r.resource)).toEqual(['gmail.example', 'calendar.example', 'docs.example'])
      expect(summary.results.map((r) => r.outcome)).toEqual(['still_pending', 'still_pending', 'queued'])
      expect(summary.pending).toBe(2)
      expect(summary.queued).toBe(1)

      // Only the head is surfaced, and the person is told what is behind it.
      const body = textOf(result)
      expect(body).toContain('CODE-0001')
      expect(body).not.toContain('CODE-0002')
      expect(body).toContain('2 more queued behind it')
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
      expect(posted).toHaveLength(2)

      await client.callTool({ name: 'connect_resources', arguments: args })
      // Still two: the second call polled the live pendings. Re-POSTing would
      // orphan the records the person is looking at.
      expect(posted).toHaveLength(2)
    } finally {
      await close()
    }
  })

  it('a URL handed over once is not handed over again', async () => {
    routeSignedFetch()
    const l1 = memoryL1([entry('gmail.example')])
    const { client, close } = await connectClient(l1)
    try {
      const args = { items: [{ resource: 'gmail.example', account: 'a@b.co' }] }
      const first = textOf(await client.callTool({ name: 'connect_resources', arguments: args }))
      expect(first).toContain('IMPORTANT')
      expect(first).toContain('CODE-0001')

      // The client has shown it; the repeat call waits on it instead of
      // telling the model to display it again. It rides along for reference.
      const second = await client.callTool({ name: 'connect_resources', arguments: args })
      expect(textOf(second)).not.toContain('IMPORTANT')
      const summary = summaryOf(second)
      expect(summary.results.map((r) => r.outcome)).toEqual(['still_pending'])
      expect(summary.awaiting).toEqual({ resource: 'gmail.example', url: 'https://ps.example/auth?code=CODE-0001' })
      expect(summary.next).toBeTruthy()
    } finally {
      await close()
    }
  })

  it('a URL the host handed over natively is not handed over again', async () => {
    // mcp.aauth.dev throws a URL elicitation from onInteraction when the client
    // declares one; the call ends there. The retry must wait on that code, not
    // return it a second time.
    routeSignedFetch()
    const l1 = memoryL1([entry('gmail.example')])
    const { client, close } = await connectClient(l1, 30, undefined, () => {
      throw new Error('elicitation thrown by the host')
    })
    try {
      const args = { items: [{ resource: 'gmail.example', account: 'a@b.co' }] }
      const first = await client.callTool({ name: 'connect_resources', arguments: args })
      expect((first as { isError?: boolean }).isError).toBe(true)

      const second = await client.callTool({ name: 'connect_resources', arguments: args })
      expect(textOf(second)).not.toContain('IMPORTANT')
      expect(summaryOf(second).awaiting?.url).toBe('https://ps.example/auth?code=CODE-0001')
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
      const summary = summaryOf(result)

      // Two interaction codes were minted — the rest were held back, so
      // nothing piles up counting down at once.
      expect(posted).toEqual(['https://a.example/connections', 'https://b.example/connections'])
      expect(summary.results.map((r) => r.outcome)).toEqual([
        'still_pending',
        'still_pending',
        'queued',
        'queued',
        'queued',
      ])
      expect(summary.pending).toBe(2)
      expect(summary.queued).toBe(3)
      // Queued items keep the agent calling back to advance the window.
      expect(summary.next).toBeTruthy()
    } finally {
      await close()
    }
  })

  it('a repeat call resumes the live set without minting a second code, and holds queued items', async () => {
    // a and b go live, c..e queued. A repeat call must resume a and b (no
    // re-POST) and must NOT start c..e while the window is full — no code is
    // minted twice and no extra codes are minted for the held items.
    const { posted } = routeSignedFetch()
    const hosts = ['a.example', 'b.example', 'c.example', 'd.example', 'e.example']
    const l1 = memoryL1(hosts.map((h) => entry(h)))
    const { client, close } = await connectClient(l1)
    try {
      const args = { items: hosts.map((h) => ({ resource: h, account: 'a@b.co' })) }
      await client.callTool({ name: 'connect_resources', arguments: args })
      expect(posted).toHaveLength(2)

      await client.callTool({ name: 'connect_resources', arguments: args })
      // Still exactly two POSTs total: the live ones resumed, queued ones held.
      expect(posted).toEqual(['https://a.example/connections', 'https://b.example/connections'])
    } finally {
      await close()
    }
  })

  it('a bare 202 from the PS (no interaction advertised) still holds a live slot', async () => {
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
      expect(posted).toEqual(['https://a.example/connections', 'https://b.example/connections'])
      const summary = summaryOf(result)
      expect(summary.results.map((r) => r.outcome)).toEqual(['still_pending', 'still_pending', 'queued'])
      expect(summary.pending).toBe(2)
      expect(summary.queued).toBe(1)
    } finally {
      await close()
    }
  })

  it('walks the whole list in one call when the PS reaches the person itself', async () => {
    // Every poll answers 200 (the person approves in the wallet at once), so
    // one call lands a and b, starts c and d as they land, and so on — no
    // round trip through the model between connections.
    const { posted } = routeSignedFetch({ bare202: true, pollStatus: 200 })
    const hosts = ['a.example', 'b.example', 'c.example', 'd.example', 'e.example']
    const l1 = memoryL1(hosts.map((h) => entry(h)))
    const { client, close } = await connectClient(l1, 5_000)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: { items: hosts.map((h) => ({ resource: h, account: 'a@b.co' })) },
      })
      expect(posted).toEqual(hosts.map((h) => `https://${h}/connections`))
      const summary = summaryOf(result)
      expect(summary.results.map((r) => r.outcome)).toEqual(['connected', 'connected', 'connected', 'connected', 'connected'])
      expect(summary.pending).toBe(0)
      expect(summary.queued).toBeUndefined()
      expect(summary.next).toBeUndefined()
    } finally {
      await close()
    }
  })

  it('finished items are not asked again on a repeat call', async () => {
    // The resource's own answer can lag what it stored by a minute (prod,
    // 2026-09-25: POST /connections said not connected 20 s after the grant
    // landed), so a re-POST would start a second connection. A repeat call
    // with the same items answers the finished ones from connectState.
    const { posted } = routeSignedFetch({ bare202: true, pollStatus: 200 })
    const hosts = ['a.example', 'b.example', 'c.example']
    const l1 = memoryL1(hosts.map((h) => entry(h)))
    const { client, close } = await connectClient(l1, 5_000)
    try {
      const args = { items: hosts.map((h) => ({ resource: h, account: 'a@b.co' })) }
      await client.callTool({ name: 'connect_resources', arguments: args })
      expect(posted).toHaveLength(3)

      const again = summaryOf(await client.callTool({ name: 'connect_resources', arguments: args }))
      expect(posted).toHaveLength(3)
      expect(again.results.map((r) => r.outcome)).toEqual(['connected', 'connected', 'connected'])

      // A different account at the same resource is a different item.
      await client.callTool({ name: 'connect_resources', arguments: { items: [{ resource: 'a.example', account: 'c@d.co' }] } })
      expect(posted).toHaveLength(4)
    } finally {
      await close()
    }
  })

  it('with a progressToken, waits past the slice and reports progress as items land', async () => {
    // Each code needs two polls (~1 s apart) before the person approves: past
    // the 30 ms slice, so without a progressToken the call would hand back to
    // the model with `next`. With one, it waits for the whole list.
    const { posted } = routeSignedFetch({ bare202: true, pendingPolls: 1 })
    const hosts = ['a.example', 'b.example', 'c.example']
    const l1 = memoryL1(hosts.map((h) => entry(h)))
    const { client, close } = await connectClient(l1, 30, 20_000)
    try {
      const messages: string[] = []
      const result = await client.callTool(
        { name: 'connect_resources', arguments: { items: hosts.map((h) => ({ resource: h, account: 'a@b.co' })) } },
        { onprogress: (p: { message?: string }) => void messages.push(p.message ?? ''), timeout: 20_000 },
      )
      expect(posted).toEqual(hosts.map((h) => `https://${h}/connections`))
      const summary = summaryOf(result)
      expect(summary.results.map((r) => r.outcome)).toEqual(['connected', 'connected', 'connected'])
      expect(summary.next).toBeUndefined()
      expect(messages.length).toBeGreaterThan(0)
      expect(messages.some((m) => m.includes('3 of 3 finished'))).toBe(true)
    } finally {
      await close()
    }
  }, 20_000)

  it('without a progressToken, the slice still bounds the call', async () => {
    // pollUntilDone may overrun the slice by one 1 s sleep, so the person
    // takes three polls here: still pending when the slice is spent.
    const { posted } = routeSignedFetch({ bare202: true, pendingPolls: 3 })
    const hosts = ['a.example', 'b.example', 'c.example']
    const l1 = memoryL1(hosts.map((h) => entry(h)))
    const { client, close } = await connectClient(l1, 30, 20_000)
    try {
      const summary = summaryOf(
        await client.callTool({ name: 'connect_resources', arguments: { items: hosts.map((h) => ({ resource: h, account: 'a@b.co' })) } }),
      )
      expect(posted).toHaveLength(2)
      expect(summary.results.map((r) => r.outcome)).toEqual(['still_pending', 'still_pending', 'queued'])
      expect(summary.next).toBeTruthy()
    } finally {
      await close()
    }
  })

  it('an item without account at a resource that needs one answers account_required and starts nothing', async () => {
    const { posted } = routeSignedFetch()
    const l1 = memoryL1([entry('gmail.example')])
    const { client, close } = await connectClient(l1)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: { items: [{ resource: 'gmail.example' }] },
      })
      const summary = JSON.parse(textOf(result)) as { results: Record<string, unknown>[]; pending: number }
      expect(summary.results[0]).toMatchObject({
        outcome: 'account_required',
        account_description: 'Google account email address',
      })
      expect(summary.pending).toBe(0)
      expect(posted).toEqual([])
      // Only the registry lookup every item makes; no PS, no resource.
      const called = mockSignedFetch.mock.calls.map(([url]) => String(url))
      expect(called.filter((u) => u !== 'https://registry.aauth.dev/resources')).toEqual([])
    } finally {
      await close()
    }
  })

  it('a resource refusing with account_required answers account_required, not error', async () => {
    // The resource's metadata as cached names no account_description, but the
    // resource itself asks for one: its refusal is what the agent acts on.
    mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (url === 'https://ps.example/person') return makeResponse(200, { person_token: 'pt_abc', expires_in: 3600 })
      if (url === 'https://github.example/connections' && init?.method === 'POST') {
        return makeResponse(400, { error: 'account_required', account_description: 'GitHub username' })
      }
      throw new Error(`unexpected signed fetch: ${url}`)
    })
    const e = entry('github.example')
    const bare = { ...e, connection: { endpoint: e.connection!.endpoint, upstream_name: 'GitHub' } }
    const { client, close } = await connectClient(memoryL1([bare]))
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: { items: [{ resource: 'github.example' }] },
      })
      const summary = JSON.parse(textOf(result)) as { results: Record<string, unknown>[] }
      expect(summary.results[0]).toMatchObject({ outcome: 'account_required', account_description: 'GitHub username' })
      expect(summary.results[0]).not.toHaveProperty('body')
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

  // ── One URL per person server per connect (5.7.0) ──
  //
  // Prod, 2026-09-28: four Google items, the first two both answered
  // `requirement=interaction`. The first call threw a URL elicitation from
  // onInteraction before the second item started; the retry started it and
  // threw a second elicitation — for a code the person's wallet tab already
  // held, since the PS queues every pending interaction per person and drains
  // the queue into the open tab.

  /**
   * A PS as the wallet behaves: the first `interactions` token requests answer
   * `requirement=interaction`, later ones a bare 202 (an open tab is
   * reachable). Each pending URL answers per `poll(code, n)` on its nth poll.
   */
  function scriptedPS(opts: { interactions: number; poll: (code: string, n: number) => Response }) {
    const posted: string[] = []
    const polls = new Map<string, number>()
    let codeSeq = 0
    mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (url === 'https://ps.example/person') return makeResponse(200, { person_token: 'pt_abc', expires_in: 3600 })
      if (url.endsWith('/connections')) {
        if ((init?.method ?? 'GET') === 'POST') {
          posted.push(url)
          return makeResponse(200, { resource_token: 'rt_conn' })
        }
        return makeResponse(200, { connections: [] })
      }
      if (url === 'https://ps.example/token') {
        codeSeq += 1
        const code = `CODE-${String(codeSeq).padStart(4, '0')}`
        return makeResponse(202, {}, {
          ...(codeSeq <= opts.interactions ? { 'aauth-requirement': `requirement=interaction; code="${code}"` } : {}),
          location: `https://ps.example/pending/${code}`,
        })
      }
      if (url.startsWith('https://ps.example/pending/')) {
        const n = (polls.get(url) ?? 0) + 1
        polls.set(url, n)
        return opts.poll(url.slice('https://ps.example/pending/'.length), n)
      }
      throw new Error(`unexpected signed fetch: ${url}`)
    })
    return { posted }
  }

  const deferred = (status: 'pending' | 'interacting', position: number) =>
    makeResponse(202, { status, queue_position: position, queue_depth: 2 })

  /**
   * A client that declares `elicitation.url` and opens every URL it is handed
   * (records it), on either protocol era. `modern` serves the connection the
   * way the stdio bin does (serveStdio picks the era from the opening
   * exchange) and lets the SDK's driver fulfil `input_required` and retry —
   * what Claude Code does.
   */
  async function elicitingClient(
    l1: L1Store,
    era: 'modern' | 'legacy',
    opts: { drainMs?: number; onInteraction?: (url: string, code: string) => void } = {},
  ) {
    const cfg = makeCfg()
    const build = async () => {
      const server = new McpServer({ name: 'test', version: '0.0.0' })
      await buildProxyTools(server, {
        ...(opts.onInteraction ? { onInteraction: opts.onInteraction } : {}),
        l1,
        registryCache: { read: async () => undefined, write: async () => {} },
        identity: { resolve: async () => ({ kind: 'ready', cfg }), peek: () => cfg },
        connectBudgetMs: 30,
        connectProgressBudgetMs: 20_000,
        ...(opts.drainMs !== undefined ? { connectDrainMs: opts.drainMs } : {}),
      })
      return server
    }
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    if (era === 'modern') serveStdio(build, { transport: serverTransport as never })
    else await (await build()).connect(serverTransport)
    const client = new Client(
      { name: 'test-client', version: '0.0.0' },
      { capabilities: { elicitation: { url: {} } }, versionNegotiation: { mode: era === 'modern' ? 'auto' : 'legacy' } } as never,
    )
    const opened: string[] = []
    client.setRequestHandler('elicitation/create' as never, (async (req: { params: { url?: string } }) => {
      opened.push(req.params.url ?? '')
      return { action: 'accept' }
    }) as never)
    await client.connect(clientTransport)
    return { client, opened, close: async () => void (await client.close()) }
  }

  const FOUR = ['gmail.example', 'calendar.example', 'chat.example', 'meet.example']

  it('2026-07-28: four items, the first two interaction — one input_required with one URL, and the retry lands all four', async () => {
    // Gmail and Calendar both need a URL; the person opens Gmail's, the tab
    // holds both codes (`interacting`), and the person approves each in turn.
    // Chat and Meet start as slots free and the PS reaches the open tab.
    const { posted } = scriptedPS({
      interactions: 2,
      poll: (code, n) => {
        if (code === 'CODE-0001') return n < 2 ? deferred('interacting', 1) : makeResponse(200, {})
        if (code === 'CODE-0002') return n < 3 ? deferred('interacting', n < 2 ? 2 : 1) : makeResponse(200, {})
        return makeResponse(200, {})
      },
    })
    const handedOver: string[] = []
    const { client, opened, close } = await elicitingClient(memoryL1(FOUR.map((h) => entry(h))), 'modern', {
      onInteraction: (_url, code) => void handedOver.push(code),
    })
    try {
      const result = await client.callTool(
        { name: 'connect_resources', arguments: { items: FOUR.map((h) => ({ resource: h, account: 'a@b.co' })) } },
        { onprogress: () => {}, timeout: 20_000 },
      )
      // One URL, the head's — Calendar's code rode in the same tab.
      expect(opened).toEqual(['https://ps.example/auth?code=CODE-0001'])
      expect(handedOver).toEqual(['CODE-0001'])
      // Both live slots were filled before the URL went out: two codes in the
      // first call, then one start per item as slots freed.
      expect(posted).toEqual(FOUR.map((h) => `https://${h}/connections`))
      const summary = summaryOf(result)
      expect(summary.results.map((r) => r.outcome)).toEqual(['connected', 'connected', 'connected', 'connected'])
      expect(summary.next).toBeUndefined()
    } finally {
      await close()
    }
  }, 20_000)

  it('2025-era: the same list throws one -32042 with one URL; the retry lands all four', async () => {
    const { posted } = scriptedPS({
      interactions: 2,
      poll: (code, n) => {
        if (code === 'CODE-0001' || code === 'CODE-0002') return n < 2 ? deferred('interacting', 1) : makeResponse(200, {})
        return makeResponse(200, {})
      },
    })
    const { client, close } = await elicitingClient(memoryL1(FOUR.map((h) => entry(h))), 'legacy')
    try {
      const args = { items: FOUR.map((h) => ({ resource: h, account: 'a@b.co' })) }
      const thrown = await client.callTool({ name: 'connect_resources', arguments: args }).catch((e: unknown) => e)
      expect(thrown).toBeInstanceOf(UrlElicitationRequiredError)
      expect((thrown as InstanceType<typeof UrlElicitationRequiredError>).elicitations.map((e) => e.url)).toEqual([
        'https://ps.example/auth?code=CODE-0001',
      ])
      expect(posted).toHaveLength(2)

      const result = await client.callTool({ name: 'connect_resources', arguments: args }, { onprogress: () => {}, timeout: 20_000 })
      expect(summaryOf(result).results.map((r) => r.outcome)).toEqual(['connected', 'connected', 'connected', 'connected'])
    } finally {
      await close()
    }
  }, 20_000)

  // Two items, both `interaction`; the client has no elicitation, so each URL
  // comes back as text and each call is the model's. The first call hands over
  // Gmail's URL and covers Calendar's code.
  const TWO = FOUR.slice(0, 2)
  const twoArgs = { items: TWO.map((h) => ({ resource: h, account: 'a@b.co' })) }

  it('a covered item still `pending` at the head past the drain bound gets its own URL', async () => {
    // The person approved Gmail, but no browser ever took Calendar's code (a
    // record created without presence, a tab that never connected): the PS
    // will not re-advertise it, so the proxy hands its URL over.
    scriptedPS({
      interactions: 2,
      poll: (code, n) => {
        if (code === 'CODE-0001') return n < 2 ? deferred('interacting', 1) : makeResponse(200, {})
        return deferred('pending', 1)
      },
    })
    const { client, close } = await connectClient(memoryL1(TWO.map((h) => entry(h))), 30, 20_000, undefined, 1_500)
    try {
      const first = textOf(await client.callTool({ name: 'connect_resources', arguments: twoArgs }))
      expect(first).toContain('CODE-0001')
      expect(first).not.toContain('CODE-0002')

      const started = Date.now()
      const second = await client.callTool({ name: 'connect_resources', arguments: twoArgs }, { onprogress: () => {}, timeout: 20_000 })
      const body = textOf(second)
      expect(body).toContain('IMPORTANT')
      expect(body).toContain('https://ps.example/auth?code=CODE-0002')
      expect(summaryOf(second).results.map((r) => r.outcome)).toEqual(['connected', 'still_pending'])
      // Not before the bound.
      expect(Date.now() - started).toBeGreaterThanOrEqual(1_500)
    } finally {
      await close()
    }
  }, 20_000)

  it('a covered item a browser holds (`interacting`) gets no URL of its own, however long it waits', async () => {
    scriptedPS({
      interactions: 2,
      poll: (code, n) => {
        if (code === 'CODE-0001') return n < 2 ? deferred('interacting', 1) : makeResponse(200, {})
        return deferred('interacting', 1)
      },
    })
    const { client, close } = await connectClient(memoryL1(TWO.map((h) => entry(h))), 30, 4_000, undefined, 500)
    try {
      await client.callTool({ name: 'connect_resources', arguments: twoArgs })
      const second = await client.callTool({ name: 'connect_resources', arguments: twoArgs }, { onprogress: () => {}, timeout: 20_000 })
      expect(textOf(second)).not.toContain('IMPORTANT')
      const summary = summaryOf(second)
      expect(summary.results.map((r) => r.outcome)).toEqual(['connected', 'still_pending'])
      expect(summary.next).toBeTruthy()
    } finally {
      await close()
    }
  }, 20_000)

  it('a covered code the PS re-advertises gets its own URL at once', async () => {
    // The PS says it cannot reach the person with Calendar's code. That ends
    // Calendar's poll the moment it arrives, bound or no bound.
    scriptedPS({
      interactions: 2,
      poll: (code, n) =>
        code === 'CODE-0001'
          ? n < 2 ? deferred('interacting', 1) : makeResponse(200, {})
          : makeResponse(202, { status: 'pending', requirement: 'interaction', code }, { 'aauth-requirement': `requirement=interaction; code="${code}"` }),
    })
    const { client, close } = await connectClient(memoryL1(TWO.map((h) => entry(h))), 30, 20_000)
    try {
      await client.callTool({ name: 'connect_resources', arguments: twoArgs })
      const second = textOf(await client.callTool({ name: 'connect_resources', arguments: twoArgs }, { onprogress: () => {}, timeout: 20_000 }))
      expect(second).toContain('IMPORTANT')
      expect(second).toContain('https://ps.example/auth?code=CODE-0002')

      // Handed over once: a third call waits on it instead of returning it
      // again, though every poll still advertises it.
      const third = await client.callTool({ name: 'connect_resources', arguments: twoArgs })
      expect(textOf(third)).not.toContain('IMPORTANT')
      expect(summaryOf(third).awaiting?.url).toBe('https://ps.example/auth?code=CODE-0002')
    } finally {
      await close()
    }
  }, 30_000)

  it('an item started while a URL is out is covered by it', async () => {
    // Three items, all `interaction`: Gmail's URL goes out with Calendar
    // covered; when Gmail lands, Chat starts in its slot and is covered by the
    // same URL — the wallet tab takes it from the queue.
    const { posted } = scriptedPS({
      interactions: 3,
      poll: (code, n) => {
        if (code === 'CODE-0001') return n < 2 ? deferred('interacting', 1) : makeResponse(200, {})
        if (code === 'CODE-0002') return n < 3 ? deferred('interacting', 1) : makeResponse(200, {})
        return n < 2 ? deferred('interacting', 1) : makeResponse(200, {})
      },
    })
    const handedOver: string[] = []
    const three = FOUR.slice(0, 3)
    const args = { items: three.map((h) => ({ resource: h, account: 'a@b.co' })) }
    const { client, close } = await connectClient(memoryL1(three.map((h) => entry(h))), 30, 20_000, (_u, code) => void handedOver.push(code))
    try {
      await client.callTool({ name: 'connect_resources', arguments: args })
      const second = await client.callTool({ name: 'connect_resources', arguments: args }, { onprogress: () => {}, timeout: 20_000 })
      expect(textOf(second)).not.toContain('IMPORTANT')
      expect(summaryOf(second).results.map((r) => r.outcome)).toEqual(['connected', 'connected', 'connected'])
      expect(posted).toHaveLength(3)
      expect(handedOver).toEqual(['CODE-0001'])
    } finally {
      await close()
    }
  }, 20_000)
})
