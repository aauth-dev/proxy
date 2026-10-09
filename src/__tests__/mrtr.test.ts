// 5.8.0 (MRTR-PLAN.md): the proxy answers the client only when the person has
// a URL to open or the work is finished.
//
//   Step 1 — a 2025-era client that declared URL elicitation on `initialize`
//            gets the -32042 error even when this server never saw it: the
//            host's `clientCapabilities` remembers. A 2026-07-28 request is
//            answered from its own envelope only.
//   Step 2 — invoke holds a call that sent a progressToken until the pending
//            settles; a declined URL ends the wait.
//   Step 3 — a 2026-07-28 client with no progressToken is held across
//            keepalive rounds (`input_required` with only a requestState), up
//            to MAX_MRTR_ROUNDS.
//
// 2026-07-28 is served the way the stdio bin serves it (serveStdio over an
// in-memory transport, the SDK client's MRTR driver fulfilling and retrying,
// as Claude Code does); the 2025 era by a plain server.connect().

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

const mockRouteOperation = vi.fn()
vi.mock('../resource.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../resource.js')>()
  return { ...real, routeOperation: mockRouteOperation }
})

const { McpServer, InMemoryTransport, createRequestStateCodec } = await import('@modelcontextprotocol/server')
const { serveStdio } = await import('@modelcontextprotocol/server/stdio')
const { Client, UrlElicitationRequiredError } = await import('@modelcontextprotocol/client')
const { buildProxyTools } = await import('../tools.js')
import type { ClientCapabilities, ServerContext } from '@modelcontextprotocol/server'
import type { L1Entry, L1Store } from '../store.js'
import type { ProxyConfig } from '../agent.js'
import type { MrtrState } from '../mrtr.js'

const PS = 'https://ps.example'
const PS_METADATA = {
  issuer: PS,
  auth_token_endpoint: `${PS}/token`,
  person_token_endpoint: `${PS}/person`,
  interaction_endpoint: `${PS}/auth`,
  jwks_uri: `${PS}/.well-known/jwks.json`,
}

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
const AGENT_TOKEN = `${b64({ alg: 'Ed25519', typ: 'aa-agent+jwt' })}.${b64({ iss: 'https://agent.example', ps: PS })}.sig`

const makeResponse = (status: number, body: unknown, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })

// A FRESH config per server: the default in-flight store is keyed on it.
const makeCfg = (): ProxyConfig => ({
  psUrl: PS,
  agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
  agentToken: AGENT_TOKEN,
})

/** A person-token resource (invoke) or one that fronts an upstream account (connect_resources). */
function entry(host: string, connect = false): L1Entry {
  return {
    resource: host,
    origin: `https://${host}`,
    issuer: `https://${host}`,
    name: host,
    description: 'test',
    access_mode: 'person-token',
    ...(connect ? { connection: { endpoint: `https://${host}/connections`, upstream_name: 'Google' } } : {}),
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

/**
 * A PS as Hellō behaves. A person-token request (invoke) or a token exchange
 * (connect_resources) mints a code: `interaction` answers with
 * `requirement=interaction`, else a bare 202 (the PS reaches the person by
 * its own channels). A pending answers per `poll(code, n)` on its nth poll.
 * `personToken` issues person tokens at once, so only the connect's own
 * exchange mints a code.
 */
function fakePS(opts: { interaction?: boolean; personToken?: boolean; latency?: () => Promise<void>; poll: (code: string, n: number) => Response }) {
  const state = { codes: 0, called: 0, polls: 0 }
  const polls = new Map<string, number>()
  const mint = () => {
    state.codes += 1
    const code = `CODE-${state.codes}`
    return makeResponse(202, {}, {
      ...(opts.interaction === false ? {} : { 'aauth-requirement': `requirement=interaction; code="${code}"` }),
      location: `${PS}/pending/${code}`,
    })
  }
  mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
    if (url === `${PS}/person`) return opts.personToken ? makeResponse(200, { person_token: 'pt', expires_in: 3600 }) : mint()
    if (url === `${PS}/token`) return mint()
    if (url.endsWith('/connections')) {
      return (init?.method ?? 'GET') === 'POST' ? makeResponse(200, { resource_token: 'rt' }) : makeResponse(200, { connections: [] })
    }
    if (url.startsWith(`${PS}/pending/`)) {
      await opts.latency?.()
      state.polls += 1
      const n = (polls.get(url) ?? 0) + 1
      polls.set(url, n)
      return opts.poll(url.slice(`${PS}/pending/`.length), n)
    }
    if (url === 'https://gmail.example/whoami') {
      state.called += 1
      return makeResponse(200, { ok: true })
    }
    throw new Error(`unexpected signed fetch: ${url} ${init?.method ?? 'GET'}`)
  })
  return state
}

const approved = () => makeResponse(200, { person_token: 'pt_ok', expires_in: 3600 })
const stillPending = () => makeResponse(202, { status: 'pending' })

type Logged = { event: string } & Record<string, unknown>

const newCodec = () =>
  createRequestStateCodec<MrtrState>({ key: new Uint8Array(32).fill(7), ttlSeconds: 900, bind: (ctx) => ctx.mcpReq.method })

/**
 * A client of either era over an in-memory transport. `capabilities` is what
 * it declares (on initialize for the 2025 era, in every envelope for
 * 2026-07-28); `elicit` answers every URL elicitation it is handed. Every
 * message the server sends is recorded, so a test can read the wire.
 */
async function connect(opts: {
  era: 'modern' | 'legacy'
  l1: L1Store
  capabilities?: ClientCapabilities
  elicit?: 'accept' | 'decline' | 'cancel'
  codec?: ReturnType<typeof newCodec>
  clientCapabilities?: (ctx: ServerContext) => Promise<ClientCapabilities | undefined>
}) {
  const cfg = makeCfg()
  const logged: Logged[] = []
  const build = async () => {
    const server = new McpServer({ name: 'test', version: '0.0.0' }, opts.codec ? { requestState: { verify: opts.codec.verify } } : {})
    await buildProxyTools(server, {
      l1: opts.l1,
      registryCache: { read: async () => undefined, write: async () => {} },
      identity: { resolve: async () => ({ kind: 'ready', cfg }), peek: () => cfg },
      connectBudgetMs: 30,
      log: (event, fields) => void logged.push({ event, ...fields }),
      ...(opts.codec ? { requestStateCodec: opts.codec } : {}),
      ...(opts.clientCapabilities ? { clientCapabilities: opts.clientCapabilities } : {}),
    })
    return server
  }
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const wire: Record<string, unknown>[] = []
  const send = serverTransport.send.bind(serverTransport)
  serverTransport.send = async (message, options) => {
    wire.push(message as unknown as Record<string, unknown>)
    return send(message, options)
  }
  if (opts.era === 'modern') serveStdio(build, { transport: serverTransport as never })
  else await (await build()).connect(serverTransport)
  const client = new Client(
    { name: 'test-client', version: '0.0.0' },
    { capabilities: opts.capabilities ?? {}, versionNegotiation: { mode: opts.era === 'modern' ? 'auto' : 'legacy' } } as never,
  )
  const opened: string[] = []
  if (opts.capabilities?.elicitation) {
    client.setRequestHandler('elicitation/create' as never, (async (req: { params: { url?: string } }) => {
      opened.push(req.params.url ?? '')
      return { action: opts.elicit ?? 'accept' }
    }) as never)
  }
  await client.connect(clientTransport)
  return { client, opened, logged, wire, close: async () => void (await client.close()) }
}

const textOf = (result: unknown): string =>
  ((result as { content?: { type: string; text?: string }[] }).content ?? []).map((c) => c.text ?? '').join('\n')
const summaryOf = (result: unknown) =>
  JSON.parse(textOf(result).split('\n\n')[0]) as { results: { resource: string; outcome: string }[]; next?: string }
const events = (logged: Logged[], name: string) => logged.filter((l) => l.event === name)
const inputRequiredResults = (wire: Record<string, unknown>[]) =>
  wire
    .map((m) => m.result as Record<string, unknown> | undefined)
    .filter((r): r is Record<string, unknown> => r?.resultType === 'input_required')

const URL_CAPS: ClientCapabilities = { elicitation: { url: {} } } as ClientCapabilities
const invokeWhoami = { name: 'invoke', arguments: { resource: 'gmail.example', op_id: 'whoami' } }

beforeEach(() => {
  vi.resetAllMocks()
  vi.restoreAllMocks()
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => makeResponse(200, PS_METADATA))
  mockRouteOperation.mockResolvedValue({
    adapter: { vocabUri: 'urn:aauth:vocabulary:openapi', operationEntry: (id: string) => ({ operationId: id }) },
    plan: { kind: 'sync.request', method: 'GET', path: '/whoami' },
    annotations: {},
    accessMode: 'person-token',
  })
})

afterEach(() => {
  vi.useRealTimers()
})

describe('step 1: capabilities a 2025-era client declared on initialize', () => {
  it('the host-supplied capabilities send a legacy client the -32042 error, URL and code in its message', async () => {
    fakePS({ poll: () => stillPending() })
    // The client's own initialize declared nothing: as a server built per
    // request sees a 2025-era tools/call.
    const { client, logged, close } = await connect({
      era: 'legacy',
      l1: memoryL1([entry('gmail.example')]),
      clientCapabilities: async () => URL_CAPS,
    })
    try {
      const thrown = await client.callTool(invokeWhoami).catch((e: unknown) => e)
      expect(thrown).toBeInstanceOf(UrlElicitationRequiredError)
      const err = thrown as InstanceType<typeof UrlElicitationRequiredError>
      expect(err.code).toBe(-32042)
      expect(err.elicitations.map((e) => e.url)).toEqual([`${PS}/auth?code=CODE-1`])
      expect(err.message).toContain(`${PS}/auth?code=CODE-1`)
      expect(err.message).toContain('code CODE-1')
      expect(events(logged, 'legacy.url_error')).toEqual([
        { event: 'legacy.url_error', tool: 'invoke', hosts: ['gmail.example'], code: 'CODE-1', caps_source: 'initialize' },
      ])
    } finally {
      await close()
    }
  })

  it('a fresh call that resumes the flight logs legacy.followup once', async () => {
    fakePS({ poll: (_c, n) => (n < 2 ? stillPending() : approved()) })
    const { client, logged, close } = await connect({
      era: 'legacy',
      l1: memoryL1([entry('gmail.example')]),
      clientCapabilities: async () => URL_CAPS,
    })
    try {
      await client.callTool(invokeWhoami).catch(() => {})
      const result = await client.callTool(invokeWhoami)
      expect(JSON.parse(textOf(result))).toMatchObject({ status: 200 })
      const followups = events(logged, 'legacy.followup')
      expect(followups).toHaveLength(1)
      expect(followups[0]).toMatchObject({ tool: 'invoke', hosts: ['gmail.example'], same_tool: true })
      expect(followups[0].ms_since_url_error).toBeGreaterThanOrEqual(0)
    } finally {
      await close()
    }
  })

  it('remembered form-only elicitation (Cursor) sends the URL back as text', async () => {
    fakePS({ poll: () => stillPending() })
    const { client, logged, close } = await connect({
      era: 'legacy',
      l1: memoryL1([entry('gmail.example')]),
      clientCapabilities: async () => ({ elicitation: { form: {} } }) as ClientCapabilities,
    })
    try {
      const result = await client.callTool(invokeWhoami)
      expect(textOf(result)).toContain(`${PS}/auth?code=CODE-1`)
      expect(events(logged, 'legacy.url_error')).toEqual([])
    } finally {
      await close()
    }
  })

  it('unknown capabilities (the host answers undefined) send the URL back as text', async () => {
    fakePS({ poll: () => stillPending() })
    const { client, logged, close } = await connect({
      era: 'legacy',
      l1: memoryL1([entry('gmail.example')]),
      clientCapabilities: async () => undefined,
    })
    try {
      const result = await client.callTool(invokeWhoami)
      expect(textOf(result)).toContain(`${PS}/auth?code=CODE-1`)
      expect(events(logged, 'legacy.url_error')).toEqual([])
    } finally {
      await close()
    }
  })

  it('a 2026-07-28 request is answered from its envelope; the host is never asked', async () => {
    fakePS({ poll: () => stillPending() })
    const asked = vi.fn(async () => URL_CAPS)
    const { client, opened, close } = await connect({
      era: 'modern',
      l1: memoryL1([entry('gmail.example')]),
      capabilities: {},
      clientCapabilities: asked,
    })
    try {
      const result = await client.callTool(invokeWhoami)
      expect(textOf(result)).toContain(`${PS}/auth?code=CODE-1`)
      expect(opened).toEqual([])
      expect(asked).not.toHaveBeenCalled()
    } finally {
      await close()
    }
  })
})

describe('step 2: invoke holds the call; a declined URL ends it', () => {
  // The clock is fake, but the work between timers is not: signing, the call
  // log's hashing and the state's HMAC finish on real time. The clock moves
  // one poll interval only after the poll before it has landed — advancing it
  // freely let fake time outrun a slow runner (CI, Node 24) and time the call
  // out before the first progress went out. The PS answers each poll a few
  // real milliseconds late to keep the test honest about that.
  it('holds across a 60 s approval with progress: one URL, one result', async () => {
    const realSetTimeout = globalThis.setTimeout
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] })
    const approveAt = Date.now() + 60_000
    const ps = fakePS({
      latency: () => new Promise((r) => realSetTimeout(r, 5)),
      poll: () => (Date.now() >= approveAt ? approved() : stillPending()),
    })
    const codec = newCodec()
    const { client, opened, logged, wire, close } = await connect({
      era: 'modern',
      l1: memoryL1([entry('gmail.example')]),
      capabilities: URL_CAPS,
      codec,
    })
    try {
      const progress: string[] = []
      const started = Date.now()
      let settled = false
      // The SDK default: a call that hears nothing for 60 s times out. Progress resets it.
      const pending = client
        .callTool(invokeWhoami, { onprogress: (p) => void progress.push(p.message ?? ''), timeout: 60_000, resetTimeoutOnProgress: true })
        .finally(() => void (settled = true))
      // Real time passes until `done` holds or the call settles.
      const until = async (done: () => boolean): Promise<void> => {
        const giveUp = performance.now() + 10_000
        while (!done() && !settled && performance.now() < giveUp) await new Promise((r) => setImmediate(r))
      }
      await until(() => ps.polls >= 1)
      while (!settled) {
        const before = ps.polls
        await vi.advanceTimersByTimeAsync(1_000)
        await until(() => ps.polls > before)
      }
      const result = await pending

      expect(JSON.parse(textOf(result))).toEqual({ status: 200, body: { ok: true } })
      expect(Date.now() - started).toBeGreaterThanOrEqual(60_000)
      // One URL, one code, one call to the resource.
      expect(opened).toEqual([`${PS}/auth?code=CODE-1`])
      expect(ps.codes).toBe(1)
      expect(ps.called).toBe(1)
      // The URL round carried a state; the retry echoed it.
      const rounds = inputRequiredResults(wire)
      expect(rounds).toHaveLength(1)
      expect(typeof rounds[0].requestState).toBe('string')
      expect(events(logged, 'mrtr.retry')).toMatchObject([{ tool: 'invoke', round: 1, input_responses: { connect: 'accept' } }])
      // Held, with progress at least once per slice.
      expect(progress.filter((m) => m.includes('gmail.example')).length).toBeGreaterThanOrEqual(2)
      expect(events(logged, 'hold.start')).toMatchObject([{ tool: 'invoke', hosts: ['gmail.example'], progress_token: true }])
      const [end] = events(logged, 'hold.end')
      expect(end).toMatchObject({ tool: 'invoke', outcome: 'settled' })
      expect(end.slices as number).toBeGreaterThanOrEqual(3)
      expect(end.progress_sent as number).toBeGreaterThanOrEqual(2)
    } finally {
      await close()
    }
  }, 30_000)

  it('a code the PS re-advertises during the hold goes out as a new URL round', async () => {
    // The person let CODE-1 lapse; the PS re-advertises a new code on the
    // same pending, then the person approves.
    const ps = fakePS({
      poll: (code, n) => {
        if (n === 1) return stillPending()
        if (n === 2) return makeResponse(202, {}, { 'aauth-requirement': 'requirement=interaction; code="CODE-9"' })
        return code === 'CODE-1' && n >= 3 ? approved() : stillPending()
      },
    })
    const { client, opened, logged, close } = await connect({
      era: 'modern',
      l1: memoryL1([entry('gmail.example')]),
      capabilities: URL_CAPS,
      codec: newCodec(),
    })
    try {
      const result = await client.callTool(invokeWhoami, { onprogress: () => {}, timeout: 20_000 })
      expect(JSON.parse(textOf(result))).toMatchObject({ status: 200 })
      expect(opened).toEqual([`${PS}/auth?code=CODE-1`, `${PS}/auth?code=CODE-9`])
      expect(ps.codes).toBe(1)
      expect(events(logged, 'mrtr.input_required').map((e) => [e.kind, e.round, e.codes])).toEqual([
        ['url', 1, ['CODE-1']],
        ['url', 2, ['CODE-9']],
      ])
      expect(events(logged, 'hold.end').map((e) => e.outcome)).toEqual(['url', 'settled'])
    } finally {
      await close()
    }
  }, 20_000)

  it('a client that gives up during the hold is logged as call.aborted', async () => {
    fakePS({ poll: () => stillPending() })
    const { client, logged, close } = await connect({
      era: 'modern',
      l1: memoryL1([entry('gmail.example')]),
      capabilities: URL_CAPS,
      codec: newCodec(),
    })
    try {
      const abort = new AbortController()
      const call = client.callTool(invokeWhoami, { onprogress: () => {}, signal: abort.signal }).catch((e: unknown) => e)
      await vi.waitFor(() => expect(events(logged, 'hold.start')).toHaveLength(1))
      abort.abort('gave up')
      await call
      await vi.waitFor(() => expect(events(logged, 'call.aborted')).toHaveLength(1))
      const [aborted] = events(logged, 'call.aborted')
      expect(aborted).toMatchObject({ tool: 'invoke', hosts: ['gmail.example'], progress_sent: 0 })
      expect(aborted.ms_since_start).toBeGreaterThanOrEqual(0)
    } finally {
      await close()
    }
  }, 40_000)

  it('without a progressToken, invoke keeps the bounded slice and answers in text', async () => {
    fakePS({ poll: () => stillPending() })
    const { client, logged, close } = await connect({ era: 'modern', l1: memoryL1([entry('gmail.example')]), capabilities: URL_CAPS })
    try {
      const result = await client.callTool(invokeWhoami)
      expect(textOf(result)).toContain('still in progress')
      expect(events(logged, 'hold.start')).toEqual([])
    } finally {
      await close()
    }
  })

  it('invoke: a declined URL ends the call; the next call starts over', async () => {
    const ps = fakePS({ poll: () => stillPending() })
    const { client, opened, logged, close } = await connect({
      era: 'modern',
      l1: memoryL1([entry('gmail.example')]),
      capabilities: URL_CAPS,
      elicit: 'decline',
      codec: newCodec(),
    })
    try {
      const started = Date.now()
      const result = await client.callTool(invokeWhoami, { onprogress: () => {}, timeout: 20_000 })
      expect(textOf(result)).toBe('The person declined authorization for gmail.example. Do not retry unless they ask.')
      expect(Date.now() - started).toBeLessThan(5_000)
      expect(opened).toHaveLength(1)
      expect(events(logged, 'invoke.declined')).toEqual([
        { event: 'invoke.declined', tool: 'invoke', hosts: ['gmail.example'], action: 'decline', round: 1 },
      ])
      // The flight is gone: asking again mints a new code.
      await client.callTool(invokeWhoami, { onprogress: () => {}, timeout: 20_000 })
      expect(ps.codes).toBe(2)
    } finally {
      await close()
    }
  }, 20_000)

  it('connect_resources: a cancelled URL answers its items `declined` and ends the call', async () => {
    fakePS({ personToken: true, poll: () => makeResponse(202, { status: 'interacting', queue_position: 1 }) })
    const hosts = ['gmail.example', 'calendar.example']
    const { client, logged, close } = await connect({
      era: 'modern',
      l1: memoryL1(hosts.map((h) => entry(h, true))),
      capabilities: URL_CAPS,
      elicit: 'cancel',
      codec: newCodec(),
    })
    try {
      const result = await client.callTool(
        { name: 'connect_resources', arguments: { items: hosts.map((resource) => ({ resource })) } },
        { onprogress: () => {}, timeout: 20_000 },
      )
      // Gmail's URL went out and covered Calendar's code: both end.
      expect(summaryOf(result).results.map((r) => r.outcome)).toEqual(['declined', 'declined'])
      expect(summaryOf(result).next).toBeUndefined()
      expect(events(logged, 'connect.declined')).toEqual([
        { event: 'connect.declined', tool: 'connect_resources', hosts, action: 'cancel', round: 1 },
      ])
    } finally {
      await close()
    }
  }, 20_000)
})

describe('step 3: keepalive rounds for a 2026-07-28 client that sent no progressToken', () => {
  const one = { name: 'connect_resources', arguments: { items: [{ resource: 'gmail.example' }] } }

  it('a keepalive round carries a requestState and no inputRequests; the rounds stop at 8', async () => {
    // The PS reaches the person itself (bare 202) and the person never acts.
    fakePS({ interaction: false, personToken: true, poll: () => stillPending() })
    const { client, logged, wire, close } = await connect({
      era: 'modern',
      l1: memoryL1([entry('gmail.example', true)]),
      codec: newCodec(),
    })
    try {
      const result = await client.callTool(one)
      // Round 9 would be one too many: the call answers `next` in text.
      expect(summaryOf(result).results.map((r) => r.outcome)).toEqual(['still_pending'])
      expect(summaryOf(result).next).toBeTruthy()

      const rounds = inputRequiredResults(wire)
      expect(rounds).toHaveLength(8)
      for (const r of rounds) {
        expect(typeof r.requestState).toBe('string')
        expect(r.inputRequests).toBeUndefined()
      }
      expect(events(logged, 'mrtr.input_required').map((e) => [e.kind, e.round])).toEqual(
        [1, 2, 3, 4, 5, 6, 7, 8].map((n) => ['keepalive', n]),
      )
      expect(events(logged, 'mrtr.retry').map((e) => e.round)).toEqual([1, 2, 3, 4, 5, 6, 7, 8])
      expect(events(logged, 'mrtr.input_required')[0]).toMatchObject({ tool: 'connect_resources', hosts: ['gmail.example'] })
    } finally {
      await close()
    }
  }, 20_000)

  it('no codec: no keepalive, `next` after the slice', async () => {
    fakePS({ interaction: false, personToken: true, poll: () => stillPending() })
    const { client, logged, wire, close } = await connect({ era: 'modern', l1: memoryL1([entry('gmail.example', true)]) })
    try {
      const result = await client.callTool(one)
      expect(summaryOf(result).next).toBeTruthy()
      expect(inputRequiredResults(wire)).toEqual([])
      expect(events(logged, 'mrtr.input_required')).toEqual([])
    } finally {
      await close()
    }
  })

  it('a URL round with no codec carries no requestState', async () => {
    fakePS({ poll: () => stillPending() })
    const { client, wire, close } = await connect({ era: 'modern', l1: memoryL1([entry('gmail.example')]), capabilities: URL_CAPS, elicit: 'decline' })
    try {
      await client.callTool(invokeWhoami)
      const [round] = inputRequiredResults(wire)
      expect(round.inputRequests).toBeDefined()
      expect(round.requestState).toBeUndefined()
    } finally {
      await close()
    }
  })

  it('a fresh call without state resumes the same flight', async () => {
    let approve = false
    const ps = fakePS({ interaction: false, personToken: true, poll: () => (approve ? makeResponse(200, {}) : stillPending()) })
    const { client, logged, close } = await connect({
      era: 'modern',
      l1: memoryL1([entry('gmail.example', true)]),
      codec: newCodec(),
    })
    try {
      const first = await client.callTool(one)
      expect(summaryOf(first).next).toBeTruthy()
      const retries = events(logged, 'mrtr.retry').length
      approve = true
      const second = await client.callTool(one)
      expect(summaryOf(second).results.map((r) => r.outcome)).toEqual(['connected'])
      // Resumed, not started again: one code, and the fresh call echoed no state.
      expect(ps.codes).toBe(1)
      expect(events(logged, 'mrtr.retry')).toHaveLength(retries)
    } finally {
      await close()
    }
  }, 20_000)

  it('a forged or expired state is refused with -32602', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    fakePS({ interaction: false, personToken: true, poll: () => stillPending() })
    const codec = newCodec()
    const { client, close } = await connect({ era: 'modern', l1: memoryL1([entry('gmail.example', true)]), codec })
    try {
      const callWith = (requestState: string) => client.callTool({ ...one, requestState } as never).catch((e: unknown) => e)
      const forged = (await callWith(`v1.${b64({ p: { tool: 'connect_resources', round: 1 }, exp: 9e9 })}.AAAA`)) as { code?: number; message?: string }
      expect(forged.code).toBe(-32602)
      expect(forged.message).toContain('Invalid or expired requestState')

      const now = Date.now()
      const minted = await codec.mint(
        { tool: 'connect_resources', hosts: ['gmail.example'], codes: [], round: 1, started_at: now, at: now },
        { mcpReq: { method: 'tools/call' } } as never,
      )
      vi.setSystemTime(now + 901_000)
      const expired = (await callWith(minted)) as { code?: number }
      expect(expired.code).toBe(-32602)
    } finally {
      await close()
    }
  })
})
