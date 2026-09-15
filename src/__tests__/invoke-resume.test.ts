// invoke resumes a pending authorization instead of starting a new one.
//
// The regression: each retry of `invoke` re-requested the person token, and
// the PS minted a fresh interaction code every time (four codes for one
// approval on 2026-09-14) while the person was looking at the first one.
// invoke now records the interaction as an in-flight record — the same store
// connect_resources uses — and a retry polls that pending for the bounded
// slice, showing the SAME code, until the PS says it is settled.
//
// Driven through a real MCP server over an in-memory transport so the tool
// handler is what is under test.

import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

const mockRouteOperation = vi.fn()
vi.mock('../resource.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../resource.js')>()
  return { ...real, routeOperation: mockRouteOperation }
})

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

/**
 * A PS that behaves like Hellō: every person-token request is a new request and
 * gets a new code, approved or not, and the approved token is delivered once,
 * on the pending URL. The 4.4.0 fake answered a repeat request with 200 after
 * approval, which is what hid the proxy dropping the delivered token.
 * Counting codes is the assertion.
 */
function fakePS() {
  const state = { codes: 0, pending: 202 as 200 | 202 | 410, presented: [] as string[] }
  mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string; signatureKey?: { jwt?: string } }) => {
    if (url === 'https://ps.example/person') {
      state.codes += 1
      const code = `CODE-${state.codes}`
      return makeResponse(202, {}, {
        'aauth-requirement': `requirement=interaction; code="${code}"`,
        location: `https://ps.example/pending/${code}`,
      })
    }
    if (url.startsWith('https://ps.example/pending/')) {
      return makeResponse(state.pending, state.pending === 200 ? { person_token: 'pt_ok', expires_in: 3600 } : {})
    }
    if (url === 'https://gmail.example/whoami') {
      state.presented.push(init?.signatureKey?.jwt ?? '')
      return makeResponse(200, { ok: true })
    }
    throw new Error(`unexpected signed fetch: ${url} ${init?.method ?? 'GET'}`)
  })
  return state
}

async function connectClient(l1: L1Store) {
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
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => makeResponse(200, PS_METADATA))
  mockRouteOperation.mockResolvedValue({
    adapter: { vocabUri: 'urn:aauth:vocabulary:openapi' },
    plan: { kind: 'sync.request', method: 'GET', path: '/whoami' },
    annotations: {},
    accessMode: 'person-token',
  })
})

describe('invoke resumes a pending authorization', () => {
  it('a retry polls the same pending and shows the same code; approval completes the call', async () => {
    const ps = fakePS()
    const { client, close } = await connectClient(memoryL1([entry('gmail.example')]))
    const call = () => client.callTool({ name: 'invoke', arguments: { resource: 'gmail.example', op_id: 'whoami' } })
    try {
      const first = textOf(await call())
      expect(first).toContain('Authorization required')
      expect(first).toContain('CODE-1')
      expect(ps.codes).toBe(1)

      // Retry while the person has not acted: no new person-token request,
      // no new code, the same one shown again.
      const second = textOf(await call())
      expect(second).toContain('still in progress')
      expect(second).toContain('CODE-1')
      expect(second).not.toContain('CODE-2')
      expect(ps.codes).toBe(1)

      // Approval: the pending settles, the person token is issued, the
      // operation runs.
      ps.pending = 200
      const third = await call()
      expect(JSON.parse(textOf(third))).toEqual({ status: 200, body: { ok: true } })
      expect(ps.codes).toBe(1)
      // The token the pending delivered is the one presented, and it is cached:
      // the next call needs no PS round trip at all.
      expect(ps.presented).toEqual(['pt_ok'])
      expect(JSON.parse(textOf(await call()))).toEqual({ status: 200, body: { ok: true } })
      expect(ps.codes).toBe(1)
      expect(ps.presented).toEqual(['pt_ok', 'pt_ok'])
    } finally {
      await close()
    }
  })

  it('a pending the PS has dropped is cleared and a fresh one is started', async () => {
    const ps = fakePS()
    const { client, close } = await connectClient(memoryL1([entry('gmail.example')]))
    const call = () => client.callTool({ name: 'invoke', arguments: { resource: 'gmail.example', op_id: 'whoami' } })
    try {
      expect(textOf(await call())).toContain('CODE-1')
      ps.pending = 410 // gone: declined or expired
      const retry = textOf(await call())
      expect(retry).toContain('CODE-2')
      expect(ps.codes).toBe(2)
    } finally {
      await close()
    }
  })

  it('an auth token delivered on the pending is presented on the retry, not re-requested', async () => {
    // Person token cached already; the resource steps up to an auth token and
    // the exchange needs the person. Hellō delivers the auth token on the
    // pending; a second exchange would mint a second code.
    const state = { codes: 0, exchanges: 0, pending: 202 as 200 | 202, presented: [] as string[] }
    mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string; signatureKey?: { jwt?: string } }) => {
      if (url === 'https://ps.example/person') return makeResponse(200, { person_token: 'pt_ok', expires_in: 3600 })
      if (url === 'https://ps.example/token') {
        state.exchanges += 1
        state.codes += 1
        const code = `AUTH-${state.codes}`
        return makeResponse(202, {}, {
          'aauth-requirement': `requirement=interaction; code="${code}"`,
          location: `https://ps.example/pending/${code}`,
        })
      }
      if (url.startsWith('https://ps.example/pending/')) {
        return makeResponse(state.pending, state.pending === 200 ? { auth_token: 'at_ok', expires_in: 3600 } : {})
      }
      if (url === 'https://gmail.example/whoami') {
        const jwt = init?.signatureKey?.jwt ?? ''
        state.presented.push(jwt)
        if (jwt === 'at_ok') return makeResponse(200, { ok: true })
        return makeResponse(401, {}, { 'aauth-requirement': 'requirement=auth-token; resource-token="rt_1"' })
      }
      throw new Error(`unexpected signed fetch: ${url} ${init?.method ?? 'GET'}`)
    })
    const { client, close } = await connectClient(memoryL1([entry('gmail.example')]))
    const call = () => client.callTool({ name: 'invoke', arguments: { resource: 'gmail.example', op_id: 'whoami' } })
    try {
      expect(textOf(await call())).toContain('AUTH-1')
      state.pending = 200
      expect(JSON.parse(textOf(await call()))).toEqual({ status: 200, body: { ok: true } })
      expect(state.exchanges).toBe(1)
      expect(state.presented).toEqual(['pt_ok', 'at_ok'])
    } finally {
      await close()
    }
  })
})
