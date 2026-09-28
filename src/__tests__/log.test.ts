// The proxy's event sink (log.ts): a host wires ProxyDeps.log and gets one
// `tool.call` per tool invocation plus the AAuth exchange underneath it —
// `aauth.call` for every signed call, `resource.fetch` for metadata,
// `person_token.hit` for a cache hit. Driven through a real MCP server over an
// in-memory transport so the wrapper around registerTool is what is under test.
//
// The privacy contract is asserted too: `aauth.call` carries the call's
// content with tokens as payload only; every other event carries identifiers,
// never values.

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
const AGENT = 'aauth:owl@agent.example'
const AGENT_TOKEN = `${b64({ alg: 'Ed25519', typ: 'aa-agent+jwt' })}.${b64({ iss: 'https://agent.example', sub: AGENT, ps: 'https://ps.example' })}.sig`
// Tokens as they are on the wire: a record holds their payload, never the JWT.
const PERSON_TOKEN = `${b64({ alg: 'Ed25519', typ: 'aa-person+jwt' })}.${b64({ iss: 'https://ps.example', sub: 'pw_1', jti: 'ptk_1' })}.cHRfc2VjcmV0`
const RESOURCE_TOKEN = `${b64({ alg: 'Ed25519', typ: 'aa-resource+jwt' })}.${b64({ iss: 'https://gmail.example', aud: 'https://ps.example' })}.cnRfY29ubg`

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
  // A host's waitUntil: the test awaits every record the proxy deferred.
  const deferred: Promise<unknown>[] = []
  const cfg: ProxyConfig = { ...makeCfg(), waitUntil: (p) => void deferred.push(p) }
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
  const settled = async () => void (await Promise.all(deferred))
  return { client, cfg, events, settled, close: async () => void (await client.close()) }
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

  it('writes an aauth.call record for every signed request under connect_resources — the agent as caller, tokens as payload only', async () => {
    mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (url === 'https://ps.example/person') return makeResponse(200, { person_token: PERSON_TOKEN, expires_in: 3600 })
      if (url.endsWith('/connections')) {
        return (init?.method ?? 'GET') === 'POST'
          ? makeResponse(200, { resource_token: RESOURCE_TOKEN })
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
    const { client, events, settled, close } = await connectClient(l1)
    try {
      // The first call hands the URL over at once; the second waits on it,
      // which is where the poll happens.
      for (let i = 0; i < 2; i++) {
        await client.callTool({
          name: 'connect_resources',
          arguments: { items: [{ resource: 'gmail.example', account: 'person@example.com' }] },
        })
      }
      await settled()
      const call = events.find((e) => e.event === 'tool.call')
      expect(call?.fields).toMatchObject({ tool: 'connect_resources', items: 1, resources: ['gmail.example'] })

      expect(events.some((e) => e.event === 'aauth.request')).toBe(false)
      const records = events.filter((e) => e.event === 'aauth.call').map((e) => e.fields)
      for (const r of records) {
        expect(r).toMatchObject({ event: 'aauth.call', side: 'caller', from: AGENT, from_role: 'agent', agent: AGENT })
        expect(typeof r.call_id).toBe('string')
        expect(typeof r.duration_ms).toBe('number')
      }
      const at = (to: string, path: string, method?: string) =>
        records.find((r) => r.to === to && r.path === path && (!method || r.method === method))
      // The PS: the person token comes back as its payload.
      expect(at('https://ps.example', '/person')).toMatchObject({
        to_role: 'ps',
        status: 200,
        response: { body: { person_token: { type: 'aa-person+jwt', payload: { iss: 'https://ps.example', jti: 'ptk_1' } } } },
      })
      // The resource: the connection request signed with the person token, its resource token as payload.
      expect(at('https://gmail.example', '/connections', 'POST')).toMatchObject({
        to_role: 'resource',
        response: { body: { resource_token: { type: 'aa-resource+jwt', payload: { iss: 'https://gmail.example' } } } },
      })
      // The challenge: AAuth-Requirement parsed, a 202 at info level.
      expect(at('https://ps.example', '/token')).toMatchObject({
        to_role: 'ps',
        status: 202,
        level: 30,
        response: { params: { 'AAuth-Requirement': { requirement: 'interaction', code: 'CODE-1' } } },
      })
      // The poll, with its query: the record is the whole call.
      expect(records.find((r) => r.to === 'https://ps.example' && String(r.path).startsWith('/pending/CODE-1'))).toMatchObject({ query: 'secret=1' })

      // No JWT anywhere, so nothing presentable: not a token, not its signature.
      const serialized = JSON.stringify(events)
      expect(serialized).not.toMatch(/eyJ[A-Za-z0-9_-]{20,}\.eyJ/)
      expect(serialized).not.toContain('cHRfc2VjcmV0')
      expect(serialized).not.toContain('cnRfY29ubg')
      // Every other event keeps to identifiers.
      const others = JSON.stringify(events.filter((e) => e.event !== 'aauth.call'))
      expect(others).not.toContain('person@example.com')
      expect(others).not.toContain('secret=1')
    } finally {
      await close()
    }
  })

  it('a non-2xx call is recorded with its error code at warn level, and the caller still reads the body', async () => {
    // The two shapes seen in production: the wallet's
    // `{"error":{"message":"NO_SESSION"}}` and a resource's OAuth-style
    // `{"error":"account_required", …}`.
    mockSignedFetch.mockImplementation(async (url: string) => {
      if (url === 'https://ps.example/person') {
        return makeResponse(403, { error: { message: 'NO_SESSION' }, detail: 'session for person@example.com' })
      }
      throw new Error(`unexpected signed fetch: ${url}`)
    })
    const l1 = memoryL1([entry('github.example')])
    const { client, events, settled, close } = await connectClient(l1)
    try {
      const result = await client.callTool({
        name: 'connect_resources',
        arguments: { items: [{ resource: 'github.example', account: 'octocat' }] },
      })
      await settled()
      const record = events.find((e) => e.event === 'aauth.call' && e.fields.path === '/person')
      expect(record?.fields).toMatchObject({ status: 403, level: 40, error: 'NO_SESSION', to_role: 'ps' })

      // The caller still reads the body itself (the record reads a clone).
      const text = (result as { content: { text?: string }[] }).content.map((c) => c.text ?? '').join('')
      expect(text).toContain('NO_SESSION')
    } finally {
      await close()
    }

    mockSignedFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (url === 'https://ps.example/person') return makeResponse(200, { person_token: PERSON_TOKEN, expires_in: 3600 })
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
      await second.settled()
      const record = second.events.find((e) => e.event === 'aauth.call' && e.fields.to === 'https://github.example' && e.fields.path === '/connections')
      expect(record?.fields).toMatchObject({ status: 400, level: 40, error: 'account_required', to_role: 'resource' })
      // tool.call and the rest keep to identifiers.
      const others = JSON.stringify(second.events.filter((e) => e.event !== 'aauth.call'))
      expect(others).not.toContain('octocat')
      expect(others).not.toContain('GitHub username')
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
