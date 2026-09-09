// Unit tests for the connection ceremony (ONBOARDING-PLAN.md Track N):
// connectAtResource / pollConnection / listConnections / disconnectAll against
// a mocked signed fetch, the N1 whitelist, N2's `account` on the authorize
// body, and N7's URL composition from published metadata.

import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { L1Entry } from '../store.js'
import type { ProxyConfig } from '../agent.js'

const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

const mockRouteOperation = vi.fn()
vi.mock('../resource.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../resource.js')>()
  return { ...real, routeOperation: mockRouteOperation }
})

const { connectAtResource, disconnectAll, invokeAtResource, listConnections, pollConnection } = await import('../agent.js')
const { fetchResource, toL1Entry } = await import('../resource.js')

function makeResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })
}

const PS_METADATA = {
  issuer: 'https://ps.example',
  auth_token_endpoint: 'https://ps.example/token',
  person_token_endpoint: 'https://ps.example/person',
  interaction_endpoint: 'https://ps.example/auth',
  jwks_uri: 'https://ps.example/.well-known/jwks.json',
}

function agentToken(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'Ed25519', typ: 'aa-agent+jwt' })}.${b64(claims)}.sig`
}
const WITH_PS = agentToken({ iss: 'https://agent.example', ps: 'https://ps.example' })

const CONNECTION = {
  endpoint: 'https://res.example/connections',
  upstream_name: 'Google',
  account_description: 'Google account email address',
  scopes: [{ scope: 'calendar.readonly', default: true, description: 'Read your calendars' }, { scope: 'calendar.events', description: 'Change events' }],
}

function l1(overrides: Partial<L1Entry> = {}): L1Entry {
  return {
    resource: 'res.example',
    origin: 'https://res.example',
    issuer: 'https://res.example',
    name: 'Test Resource',
    description: 'Test',
    access_mode: 'person-token',
    interaction_endpoint: 'https://res.example/connect',
    connection: CONNECTION,
    picked_vocabs: [{ vocabUri: 'urn:aauth:vocabulary:openapi', docUrl: 'https://res.example/openapi.json' }],
    added: '2026-01-01T00:00:00.000Z',
    ...overrides,
  }
}

function config(overrides: Partial<ProxyConfig> = {}): ProxyConfig {
  return {
    psUrl: 'https://ps.example',
    agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
    agentToken: WITH_PS,
    ...overrides,
  }
}

function mockPSWellKnown(): void {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => makeResponse(200, PS_METADATA))
}

const personTokenResponse = () => makeResponse(200, { person_token: 'pt_abc', expires_in: 3600 })
const bodyOf = (call: number): Record<string, unknown> => JSON.parse((mockSignedFetch.mock.calls[call]![1] as { body: string }).body) as Record<string, unknown>
const urlOf = (call: number): string => mockSignedFetch.mock.calls[call]![0] as string
const methodOf = (call: number): string | undefined => (mockSignedFetch.mock.calls[call]![1] as { method?: string }).method

beforeEach(() => {
  vi.resetAllMocks()
  vi.restoreAllMocks()
})

describe('N1 — toL1Entry carries interaction_endpoint and the connection object', () => {
  it('keeps both, and rejects an interaction endpoint on another origin', async () => {
    const meta = { issuer: 'https://res.example', name: 'R', description: 'd', access_mode: 'person-token', r3_vocabularies: {}, interaction_endpoint: 'https://res.example/connect', connection: CONNECTION }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => makeResponse(200, meta))
    const entry = toL1Entry(await fetchResource('res.example'))
    expect(entry.interaction_endpoint).toBe('https://res.example/connect')
    expect(entry.connection).toEqual(CONNECTION)

    // Q2: another origin is fine (an operator hosts the fleet's OAuth start);
    // a non-https endpoint is not.
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => makeResponse(200, { ...meta, interaction_endpoint: 'https://proxy.example/oauth/start/x' }))
    expect((await fetchResource('res.example')).meta.interaction_endpoint).toBe('https://proxy.example/oauth/start/x')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => makeResponse(200, { ...meta, interaction_endpoint: 'http://res.example/connect' }))
    await expect(fetchResource('res.example')).rejects.toThrow(/https/)
  })
})

describe('connectAtResource', () => {
  it('answers ready without calling out when the resource publishes no connection', async () => {
    const out = await connectAtResource(config(), l1({ connection: undefined }))
    expect(out).toEqual({ kind: 'ready', reason: 'no_connection_needed' })
    expect(mockSignedFetch).not.toHaveBeenCalled()
  })

  it('POSTs the collection with a person token, exchanges the token, and completes on a token-less terminal answer (N6)', async () => {
    mockPSWellKnown()
    mockSignedFetch
      .mockResolvedValueOnce(personTokenResponse())
      .mockResolvedValueOnce(makeResponse(200, { resource_token: 'rt_conn' }))
      .mockResolvedValueOnce(makeResponse(200, { status: 'connection_established' }))
    const out = await connectAtResource(config(), l1(), { account: 'dick@hello.coop', scopes: ['calendar.readonly'] })
    expect(out).toEqual({ kind: 'connected', account: 'dick@hello.coop' })
    expect(urlOf(1)).toBe('https://res.example/connections')
    expect(bodyOf(1)).toEqual({ scopes: ['calendar.readonly'], account: 'dick@hello.coop' })
    expect((mockSignedFetch.mock.calls[1]![1] as { signatureKey: { jwt: string } }).signatureKey.jwt).toBe('pt_abc')
    expect(urlOf(2)).toBe('https://ps.example/token')
    expect(bodyOf(2)).toMatchObject({ resource_token: 'rt_conn', presented_token: 'pt_abc', capabilities: ['interaction'] })
  })

  it('already_connected is a status, not an error → ready', async () => {
    mockPSWellKnown()
    mockSignedFetch
      .mockResolvedValueOnce(personTokenResponse())
      .mockResolvedValueOnce(makeResponse(200, { status: 'already_connected', account: 'dick@hello.coop', scopes: ['calendar.readonly'] }))
    const out = await connectAtResource(config(), l1(), { account: 'dick@hello.coop' })
    expect(out).toEqual({ kind: 'ready', reason: 'already_connected', account: 'dick@hello.coop', scopes: ['calendar.readonly'] })
    expect(mockSignedFetch).toHaveBeenCalledTimes(2)
  })

  it('surfaces the resource\'s 400 (account_required) as an error the agent can read', async () => {
    mockPSWellKnown()
    mockSignedFetch
      .mockResolvedValueOnce(personTokenResponse())
      .mockResolvedValueOnce(makeResponse(400, { error: 'account_required', account_description: 'Google account email address' }))
    const out = await connectAtResource(config(), l1())
    expect(out).toEqual({ kind: 'error', status: 400, body: { error: 'account_required', account_description: 'Google account email address' } })
  })

  it('surfaces the PS 202 as an interaction with the URL composed from PS metadata — no relay POST (Q5)', async () => {
    mockPSWellKnown()
    mockSignedFetch
      .mockResolvedValueOnce(personTokenResponse())
      .mockResolvedValueOnce(makeResponse(200, { resource_token: 'rt_conn' }))
      .mockResolvedValueOnce(makeResponse(202, {}, { 'aauth-requirement': 'requirement=interaction; code="ABCD-EFGH"', location: 'https://ps.example/pending/ABCD-EFGH' }))
    const out = await connectAtResource(config(), l1(), { account: 'a@b.co' })
    expect(out).toEqual({
      kind: 'interaction',
      interaction: { url: 'https://ps.example/auth', code: 'ABCD-EFGH', pollUrl: 'https://ps.example/pending/ABCD-EFGH' },
    })
    // person token, POST /connections, exchange — and nothing after.
    expect(mockSignedFetch).toHaveBeenCalledTimes(3)
    expect(urlOf(2)).toBe('https://ps.example/token')
  })
})

describe('pollConnection (B2 slice)', () => {
  it('connected on a token-less 2xx, still_pending on 202 at the budget, error otherwise', async () => {
    const interaction = { url: 'https://ps.example/auth', code: 'ABCD-EFGH', pollUrl: 'https://ps.example/pending/x' }
    mockSignedFetch.mockResolvedValueOnce(makeResponse(200, { status: 'connection_established' }))
    expect(await pollConnection(config(), interaction, 10)).toEqual({ kind: 'connected' })
    mockSignedFetch.mockResolvedValue(makeResponse(202, {}))
    expect(await pollConnection(config(), interaction, 10)).toEqual({ kind: 'still_pending', interaction })
    mockSignedFetch.mockResolvedValueOnce(makeResponse(410, { error: 'expired' }))
    expect(await pollConnection(config(), interaction, 10)).toEqual({ kind: 'error', status: 410, body: { error: 'expired' } })
  })
})

describe('listConnections / disconnectAll', () => {
  it('GETs the collection with the person token and returns the rows', async () => {
    mockPSWellKnown()
    const rows = [{ account: 'a@b.co', scopes: ['calendar.readonly'], connected_at: '2026-09-01T00:00:00Z', status: 'ok' }]
    mockSignedFetch.mockResolvedValueOnce(personTokenResponse()).mockResolvedValueOnce(makeResponse(200, { connections: rows }))
    expect(await listConnections(config(), l1())).toEqual({ kind: 'rows', rows })
    expect(methodOf(1)).toBe('GET')
    expect(urlOf(1)).toBe('https://res.example/connections')
  })

  it('DELETEs each listed account and reports what the resource said happened upstream', async () => {
    mockPSWellKnown()
    mockSignedFetch
      .mockResolvedValueOnce(personTokenResponse())
      .mockResolvedValueOnce(makeResponse(200, { connections: [{ account: 'a@b.co', scopes: [] }, { account: 'c@d.co', scopes: [] }] }))
      .mockResolvedValueOnce(makeResponse(200, { status: 'disconnected', account: 'a@b.co', upstream: 'revoked' }))
      .mockResolvedValueOnce(makeResponse(200, { status: 'disconnected', account: 'c@d.co', upstream: 'not_supported', action_required: 'revoke at Google' }))
    const out = await disconnectAll(config(), l1())
    expect(out).toEqual([
      { account: 'a@b.co', status: 200, upstream: 'revoked' },
      { account: 'c@d.co', status: 200, upstream: 'not_supported', detail: 'revoke at Google' },
    ])
    expect(methodOf(2)).toBe('DELETE')
    expect(urlOf(2)).toBe('https://res.example/connections/a%40b.co')
  })
})

describe('N2 — account on the authorize request', () => {
  it('sends `account` in the /authorize body when the caller names one', async () => {
    mockPSWellKnown()
    mockRouteOperation.mockResolvedValue({
      adapter: { vocabUri: 'urn:aauth:vocabulary:openapi' },
      plan: { kind: 'sync.request', method: 'GET', path: '/x', query: '' },
      annotations: {},
      accessMode: 'auth-token',
    })
    mockSignedFetch
      .mockResolvedValueOnce(personTokenResponse())
      .mockResolvedValueOnce(makeResponse(200, { resource_token: 'rt' }))
      .mockResolvedValueOnce(makeResponse(200, { auth_token: 'at' }))
      .mockResolvedValueOnce(makeResponse(200, { ok: true }))
    const out = await invokeAtResource(config(), l1({ access_mode: 'auth-token', authorization_endpoint: 'https://res.example/authorize' }), 'x', {}, { account: 'a@b.co' })
    expect(out).toEqual({ kind: 'result', status: 200, body: { ok: true } })
    expect(urlOf(1)).toBe('https://res.example/authorize')
    expect(bodyOf(1)).toMatchObject({ account: 'a@b.co', r3_operations: { operations: [{ operationId: 'x' }] } })
  })
})

describe('D2 — a 401 auth-token whose resource token carries interaction_code is the ordinary exchange', () => {
  it('exchanges at the PS and surfaces its 202 with the URL composed from PS metadata', async () => {
    mockPSWellKnown()
    mockRouteOperation.mockResolvedValue({
      adapter: { vocabUri: 'urn:aauth:vocabulary:openapi' },
      plan: { kind: 'sync.request', method: 'GET', path: '/x', query: '' },
      annotations: {},
      accessMode: 'agent-token',
    })
    // The fleet's B3 shape: the vend needed a connect, so the resource
    // challenges with a resource token carrying the pending code. Nothing on
    // the agent side inspects the token; it goes to the PS like any other.
    mockSignedFetch
      .mockResolvedValueOnce(makeResponse(401, { error: 'no_tokens' }, { 'aauth-requirement': 'requirement=auth-token; resource-token="rt.with.interaction_code"' }))
      .mockResolvedValueOnce(makeResponse(202, { status: 'pending' }, { 'aauth-requirement': 'requirement=interaction; code="WXYZ-1234"', location: 'https://ps.example/pending/WXYZ-1234' }))
    const out = await invokeAtResource(config(), l1(), 'x')
    expect(out).toEqual({
      kind: 'interaction',
      interaction: { url: 'https://ps.example/auth', code: 'WXYZ-1234', pollUrl: 'https://ps.example/pending/WXYZ-1234' },
    })
    expect(mockSignedFetch).toHaveBeenCalledTimes(2)
    expect(bodyOf(1)).toMatchObject({ resource_token: 'rt.with.interaction_code' })
  })
})

describe('N7 — a resource 202 with only a code composes the URL from L1', () => {
  it('uses interaction_endpoint when the header carries no url=, and nothing is relayed', async () => {
    mockPSWellKnown()
    mockRouteOperation.mockResolvedValue({
      adapter: { vocabUri: 'urn:aauth:vocabulary:openapi' },
      plan: { kind: 'sync.request', method: 'GET', path: '/x', query: '' },
      annotations: {},
      accessMode: 'agent-token',
    })
    mockSignedFetch.mockResolvedValueOnce(makeResponse(202, {}, { 'aauth-requirement': 'requirement=interaction; code="ABCD-EFGH"', location: 'https://res.example/pending/1' }))
    const out = await invokeAtResource(config(), l1(), 'x')
    expect(out).toEqual({
      kind: 'interaction',
      interaction: { url: 'https://res.example/connect', code: 'ABCD-EFGH', pollUrl: 'https://res.example/pending/1' },
    })
    expect(mockSignedFetch).toHaveBeenCalledTimes(1)
  })
})
