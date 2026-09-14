// Unit tests for invokeAtResource's credential flow: the per-call escalation
// path, person-token acquisition and caching, and the three-way access_mode
// plan. Every test carries a mission, so the mission_s256 claim path is
// exercised even though no PS implements mission_endpoint yet.

import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { L1Entry } from '../store.js'
import type { ProxyConfig } from '../agent.js'

// Mock @hellocoop/httpsig so signedFetch is interceptable.
const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

// Mock routeOperation so we don't need a real vocab doc.
const mockRouteOperation = vi.fn()
vi.mock('../resource.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../resource.js')>()
  return { ...real, routeOperation: mockRouteOperation }
})

// Import after mocks are in place.
const { invokeAtResource } = await import('../agent.js')

function makeResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  })
}

const PS_METADATA = {
  issuer: 'https://ps.example',
  auth_token_endpoint: 'https://ps.example/token',
  person_token_endpoint: 'https://ps.example/person',
  jwks_uri: 'https://ps.example/.well-known/jwks.json',
}

const MISSION = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

// A minimal unsigned aa-agent+jwt. Only the payload is read, and only for `ps`.
function agentToken(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'Ed25519', typ: 'aa-agent+jwt' })}.${b64(claims)}.sig`
}

const WITH_PS = agentToken({ iss: 'https://agent.example', ps: 'https://ps.example' })
const WITHOUT_PS = agentToken({ iss: 'https://agent.example' })

function l1(overrides: Partial<L1Entry> = {}): L1Entry {
  return {
    resource: 'res.example',
    origin: 'https://res.example',
    issuer: 'https://res.example',
    name: 'Test Resource',
    description: 'Test',
    access_mode: 'agent-token',
    picked_vocabs: [
      { vocabUri: 'urn:aauth:vocabulary:openapi', docUrl: 'https://res.example/openapi.json' },
    ],
    added: '2026-01-01T00:00:00.000Z',
    ...overrides,
  }
}

function config(overrides: Partial<ProxyConfig> = {}): ProxyConfig {
  return {
    psUrl: 'https://ps.example',
    agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
    agentToken: WITH_PS,
    missionS256: MISSION,
    ...overrides,
  }
}

/** Route to a plain `sync.request`, optionally carrying an access annotation. */
function routeTo(accessMode: string, annotations: Record<string, unknown> = {}): void {
  mockRouteOperation.mockResolvedValue({
    adapter: { vocabUri: 'urn:aauth:vocabulary:openapi' },
    plan: { kind: 'sync.request', method: 'GET', path: '/whoami', query: 'scope=profile' },
    annotations,
    accessMode,
  })
}

// A fresh Response per call — a Response body can only be read once, and tests
// that invoke twice fetch the PS well-known twice.
function mockPSWellKnown(): ReturnType<typeof vi.spyOn> {
  return vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => makeResponse(200, PS_METADATA)) as never
}

beforeEach(() => {
  vi.resetAllMocks()
  routeTo('agent-token')
})

describe('agent-token per-call escalation', () => {
  it('retries with an auth token when the resource issues a 401 auth-token challenge', async () => {
    const globalFetchSpy = mockPSWellKnown()

    // signedFetch call sequence:
    // 1. resource call → 401 challenge (the per-call proposal reference)
    // 2. PS auth token exchange → auth token
    // 3. resource retry with the auth token → 200
    mockSignedFetch
      .mockResolvedValueOnce(
        makeResponse(401, { error: 'auth_token_required' }, {
          'aauth-requirement': 'requirement=auth-token; resource-token="rt_abc123"',
        }),
      )
      .mockResolvedValueOnce(makeResponse(200, { auth_token: 'auth_tok_xyz' }))
      .mockResolvedValueOnce(makeResponse(200, { sub: 'user@example.com', name: 'Alice' }))

    const result = await invokeAtResource(config(), l1(), 'whoami', { query: 'scope=profile' })

    expect(result).toEqual({
      kind: 'result',
      status: 200,
      body: { sub: 'user@example.com', name: 'Alice' },
    })

    expect(globalFetchSpy).toHaveBeenCalledWith('https://ps.example/.well-known/aauth-person.json')

    // The exchange went to auth_token_endpoint (renamed from token_endpoint in -11).
    const [psUrl, psInit] = mockSignedFetch.mock.calls[1]
    expect(psUrl).toBe('https://ps.example/token')
    const psBody = JSON.parse(psInit.body)
    expect(psBody.resource_token).toBe('rt_abc123')
    expect(psBody.capabilities).toContain('interaction')

    // Content-digest is covered on a PS request carrying a body.
    expect(psInit.components).toContain('content-digest')
    expect(psInit.components).toContain('content-type')
  })

  it('re-authorizes on a budget-exhausted challenge, then surfaces the reason when it repeats', async () => {
    mockPSWellKnown()

    // draft-hardt-aauth-budgets §exhaustion: exhaustion is a plain auth-token
    // challenge with a fresh resource token and reason=budget-exhausted. The
    // loop re-authorizes (always correct), and when the re-acquired auth token
    // exhausts again it stops and surfaces the reason instead of spinning.
    const challenge = (rt: string) =>
      makeResponse(402, { error: 'payment_required' }, {
        'aauth-requirement': `requirement=auth-token; resource-token="${rt}"; reason=budget-exhausted`,
      })
    mockSignedFetch
      .mockResolvedValueOnce(challenge('rt_1'))                          // resource, agent cred
      .mockResolvedValueOnce(makeResponse(200, { auth_token: 'auth_A' })) // PS exchange
      .mockResolvedValueOnce(challenge('rt_2'))                          // resource, auth cred
      .mockResolvedValueOnce(makeResponse(200, { auth_token: 'auth_B' })) // PS exchange
      .mockResolvedValueOnce(challenge('rt_3'))                          // resource, auth cred again → terminal

    const result = await invokeAtResource(config(), l1(), 'whoami', { query: 'scope=profile' })

    expect(result).toEqual({
      kind: 'result',
      status: 402,
      body: { error: 'budget-exhausted', detail: { error: 'payment_required' } },
    })
    // Both fresh resource tokens were taken back to the PS before giving up.
    expect(JSON.parse(mockSignedFetch.mock.calls[1][1].body).resource_token).toBe('rt_1')
    expect(JSON.parse(mockSignedFetch.mock.calls[3][1].body).resource_token).toBe('rt_2')
  })

  it('retries the per-call operation with byte-identical parameters', async () => {
    mockPSWellKnown()
    mockRouteOperation.mockResolvedValue({
      adapter: { vocabUri: 'urn:aauth:vocabulary:openapi' },
      plan: {
        kind: 'sync.request',
        method: 'POST',
        path: '/send',
        headers: { 'content-type': 'application/json' },
        body: '{"to":"mom@example.com"}',
      },
      annotations: { access_mode: 'per-call' },
      accessMode: 'per-call',
    })

    mockSignedFetch
      // person token for the authorize-first path
      .mockResolvedValueOnce(makeResponse(200, { person_token: 'pt_1', expires_in: 3600 }))
      // per-call operations are challenged on invocation, not pre-authorized
      .mockResolvedValueOnce(
        makeResponse(401, {}, {
          'aauth-requirement': 'requirement=auth-token; resource-token="rt_proposal"',
        }),
      )
      .mockResolvedValueOnce(makeResponse(200, { auth_token: 'auth_percall' }))
      .mockResolvedValueOnce(makeResponse(200, { sent: true }))

    const result = await invokeAtResource(
      config(),
      l1({ access_mode: 'per-call' }),
      'sendEmail',
      {},
    )
    expect(result).toEqual({ kind: 'result', status: 200, body: { sent: true } })

    // The challenged call and the retry present exactly the same body — the
    // resource verifies actual parameters against the approved proposal.
    const challenged = mockSignedFetch.mock.calls[1]
    const retried = mockSignedFetch.mock.calls[3]
    expect(retried[0]).toBe(challenged[0])
    expect(retried[1].body).toBe(challenged[1].body)
  })

  it('surfaces an interaction when the PS returns 202 during escalation', async () => {
    mockPSWellKnown()

    mockSignedFetch
      .mockResolvedValueOnce(
        makeResponse(401, { error: 'auth_token_required' }, {
          'aauth-requirement': 'requirement=auth-token; resource-token="rt_def456"',
        }),
      )
      .mockResolvedValueOnce(
        makeResponse(202, {}, {
          'aauth-requirement':
            'requirement=interaction; url="https://ps.example/interact"; code="code_xyz"',
          location: 'https://ps.example/pending/abc',
        }),
      )

    const result = await invokeAtResource(config(), l1(), 'whoami', { query: 'scope=profile' })

    expect(result).toEqual({
      kind: 'interaction',
      interaction: {
        url: 'https://ps.example/interact',
        code: 'code_xyz',
        pollUrl: 'https://ps.example/pending/abc',
      },
    })
  })

  it('returns the 401 as-is when no AAuth-Requirement header is present', async () => {
    mockSignedFetch.mockResolvedValueOnce(makeResponse(401, { error: 'unauthorized' }))

    const result = await invokeAtResource(config(), l1(), 'whoami')

    expect(result).toEqual({ kind: 'result', status: 401, body: { error: 'unauthorized' } })
    expect(mockSignedFetch).toHaveBeenCalledTimes(1)
  })
})

describe('person tokens', () => {
  it('obtains one for the resource, carrying the mission, and presents it', async () => {
    mockPSWellKnown()
    routeTo('person-token')
    mockSignedFetch
      .mockResolvedValueOnce(makeResponse(200, { person_token: 'pt_abc', expires_in: 3600 }))
      .mockResolvedValueOnce(makeResponse(200, { ok: true }))

    const result = await invokeAtResource(
      config(),
      l1({ access_mode: 'person-token' }),
      'whoami',
    )
    expect(result).toEqual({ kind: 'result', status: 200, body: { ok: true } })

    const [ptUrl, ptInit] = mockSignedFetch.mock.calls[0]
    expect(ptUrl).toBe('https://ps.example/person')
    expect(JSON.parse(ptInit.body)).toEqual({
      resource: 'https://res.example',
      capabilities: ['interaction'],
      mission_s256: MISSION,
    })
    // The agent token is presented while requesting the person token …
    expect(ptInit.signatureKey).toEqual({ type: 'jwt', jwt: WITH_PS })
    // … and the person token replaces it on the resource call.
    expect(mockSignedFetch.mock.calls[1][1].signatureKey).toEqual({ type: 'jwt', jwt: 'pt_abc' })
  })

  it('carries the person-identifying hints, but not the exchange-only ones', async () => {
    mockPSWellKnown()
    routeTo('person-token')
    mockSignedFetch
      .mockResolvedValueOnce(makeResponse(200, { person_token: 'pt_abc', expires_in: 3600 }))
      .mockResolvedValueOnce(makeResponse(200, { ok: true }))

    const result = await invokeAtResource(
      config({
        psHints: {
          login_hint: 'sub_123',
          tenant: 'org_1',
          prompt: 'consent',
          upstream_token: 'up_tok',
          subagent_token: 'sub_tok',
          platform: 'cloud',
          capabilities: ['interaction', 'push'],
        },
      }),
      l1({ access_mode: 'person-token' }),
      'whoami',
    )
    expect(result).toEqual({ kind: 'result', status: 200, body: { ok: true } })

    // login_hint is how a PS bound to several accounts knows which one the
    // person token is for; upstream/subagent tokens are endpoint parameters
    // with their own rules, and platform is a consent-display hint for the
    // exchange — none of those are forwarded here.
    expect(JSON.parse(mockSignedFetch.mock.calls[0][1].body)).toEqual({
      resource: 'https://res.example',
      capabilities: ['interaction', 'push'],
      mission_s256: MISSION,
      login_hint: 'sub_123',
      tenant: 'org_1',
      prompt: 'consent',
    })
  })

  it('caches by (resource, mission) and re-uses on a second invoke', async () => {
    mockPSWellKnown()
    routeTo('person-token')
    const cfg = config()
    mockSignedFetch
      .mockResolvedValueOnce(makeResponse(200, { person_token: 'pt_abc', expires_in: 3600 }))
      .mockResolvedValueOnce(makeResponse(200, { ok: 1 }))
      .mockResolvedValueOnce(makeResponse(200, { ok: 2 }))

    await invokeAtResource(cfg, l1({ access_mode: 'person-token' }), 'whoami')
    await invokeAtResource(cfg, l1({ access_mode: 'person-token' }), 'whoami')

    // Three signed calls total: one person-token request, two resource calls.
    expect(mockSignedFetch).toHaveBeenCalledTimes(3)
    expect(mockSignedFetch.mock.calls[2][1].signatureKey).toEqual({ type: 'jwt', jwt: 'pt_abc' })
  })

  it('flushes the whole cache when the agent signing key rotates', async () => {
    mockPSWellKnown()
    routeTo('person-token')
    const store = (await import('../store.js')).createMemoryPersonTokenStore()
    const first = config({ personTokens: store })
    const rotated = config({
      personTokens: store,
      agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'ZZZZ', d: 'YYYY' } as never,
    })

    mockSignedFetch
      .mockResolvedValueOnce(makeResponse(200, { person_token: 'pt_key1', expires_in: 3600 }))
      .mockResolvedValueOnce(makeResponse(200, { ok: 1 }))
      .mockResolvedValueOnce(makeResponse(200, { person_token: 'pt_key2', expires_in: 3600 }))
      .mockResolvedValueOnce(makeResponse(200, { ok: 2 }))

    await invokeAtResource(first, l1({ access_mode: 'person-token' }), 'whoami')
    await invokeAtResource(rotated, l1({ access_mode: 'person-token' }), 'whoami')

    // Every person token binds the same cnf, so the rotation invalidates the
    // cached one and a fresh token is requested.
    expect(mockSignedFetch).toHaveBeenCalledTimes(4)
    expect(mockSignedFetch.mock.calls[3][1].signatureKey).toEqual({ type: 'jwt', jwt: 'pt_key2' })
  })

  it('surfaces the PS 202 deferred interaction on the person token endpoint', async () => {
    mockPSWellKnown()
    routeTo('person-token')
    mockSignedFetch.mockResolvedValueOnce(
      makeResponse(202, { status: 'pending' }, {
        'aauth-requirement':
          'requirement=interaction; url="https://ps.example/interact"; code="P1Q2"',
        location: 'https://ps.example/person/pending/1',
      }),
    )

    const result = await invokeAtResource(config(), l1({ access_mode: 'person-token' }), 'whoami')

    expect(result).toEqual({
      kind: 'interaction',
      interaction: {
        url: 'https://ps.example/interact',
        code: 'P1Q2',
        pollUrl: 'https://ps.example/person/pending/1',
      },
    })
  })

  it('acquires one when a resource challenges with requirement=person-token', async () => {
    mockPSWellKnown()
    mockSignedFetch
      .mockResolvedValueOnce(
        makeResponse(401, {}, { 'aauth-requirement': 'requirement=person-token' }),
      )
      .mockResolvedValueOnce(makeResponse(200, { person_token: 'pt_late', expires_in: 3600 }))
      .mockResolvedValueOnce(makeResponse(200, { ok: true }))

    const result = await invokeAtResource(config(), l1(), 'whoami')
    expect(result).toEqual({ kind: 'result', status: 200, body: { ok: true } })
    expect(mockSignedFetch.mock.calls[1][0]).toBe('https://ps.example/person')
  })
})

describe('authorize-first', () => {
  it('presents the person token at the authorization endpoint with bare operation ids', async () => {
    mockPSWellKnown()
    mockSignedFetch
      .mockResolvedValueOnce(makeResponse(200, { person_token: 'pt_authz', expires_in: 3600 }))
      .mockResolvedValueOnce(makeResponse(200, { resource_token: 'rt_authz' }))
      .mockResolvedValueOnce(makeResponse(200, { auth_token: 'at_authz' }))
      .mockResolvedValueOnce(makeResponse(200, { ok: true }))

    const entry = l1({
      access_mode: 'auth-token',
      authorization_endpoint: 'https://res.example/authorize',
    })
    routeTo('auth-token')

    const result = await invokeAtResource(config(), entry, 'whoami')
    expect(result).toEqual({ kind: 'result', status: 200, body: { ok: true } })

    const [authzUrl, authzInit] = mockSignedFetch.mock.calls[1]
    expect(authzUrl).toBe('https://res.example/authorize')
    // A resource MUST have verified a person token before it issues a resource token.
    expect(authzInit.signatureKey).toEqual({ type: 'jwt', jwt: 'pt_authz' })
    // … and the exchange names that same token as presented_token (-11 step 6).
    expect(JSON.parse(mockSignedFetch.mock.calls[2][1].body)).toMatchObject({ resource_token: 'rt_authz', presented_token: 'pt_authz' })
    // No gateway {service, operationId} entry shape — R3 -02 removed it.
    expect(JSON.parse(authzInit.body)).toEqual({
      r3_operations: {
        vocabulary: 'urn:aauth:vocabulary:openapi',
        operations: [{ operationId: 'whoami' }],
      },
    })
  })

  it('a named account takes the auth-token path even on a person-token read (the account travels in the auth token)', async () => {
    mockPSWellKnown()
    mockSignedFetch
      .mockResolvedValueOnce(makeResponse(200, { person_token: 'pt_acct', expires_in: 3600 }))
      .mockResolvedValueOnce(makeResponse(200, { resource_token: 'rt_acct' }))
      .mockResolvedValueOnce(makeResponse(200, { auth_token: 'at_acct' }))
      .mockResolvedValueOnce(makeResponse(200, { ok: true }))
    const entry = l1({ access_mode: 'person-token', authorization_endpoint: 'https://res.example/authorize' })
    routeTo('person-token')

    const result = await invokeAtResource(config(), entry, 'whoami', {}, { account: 'dick@example.com' })
    expect(result).toEqual({ kind: 'result', status: 200, body: { ok: true } })
    const [authzUrl, authzInit] = mockSignedFetch.mock.calls[1]
    expect(authzUrl).toBe('https://res.example/authorize')
    expect(JSON.parse(authzInit.body)).toMatchObject({ account: 'dick@example.com' })
    // The call itself presents the auth token, not the person token.
    expect(mockSignedFetch.mock.calls[3][1].signatureKey).toEqual({ type: 'jwt', jwt: 'at_acct' })
  })
})

describe('three-way access_mode plan', () => {
  it('skips a recognized mode this agent cannot complete, without calling out', async () => {
    routeTo('auth-token')
    const result = await invokeAtResource(
      config({ agentToken: WITHOUT_PS }),
      l1({ access_mode: 'auth-token' }),
      'whoami',
    )

    expect(result.kind).toBe('skipped')
    if (result.kind !== 'skipped') throw new Error('expected skipped')
    expect(result.mode).toBe('auth-token')
    expect(result.reason).toContain('`ps` claim')
    // Nothing was sent — not to the resource, not to the PS.
    expect(mockSignedFetch).not.toHaveBeenCalled()
  })

  it('treats an unrecognized access_mode as undeclared and reads the runtime requirement', async () => {
    routeTo('urn:example:some-future-mode')
    mockSignedFetch.mockResolvedValueOnce(makeResponse(200, { ok: true }))

    const result = await invokeAtResource(
      config({ agentToken: WITHOUT_PS }),
      l1({ access_mode: 'urn:example:some-future-mode' }),
      'whoami',
    )

    // Never an error: the declaration is advisory.
    expect(result).toEqual({ kind: 'result', status: 200, body: { ok: true } })
    expect(mockSignedFetch.mock.calls[0][1].signatureKey).toEqual({ type: 'jwt', jwt: WITHOUT_PS })
  })

  it('lets an operation annotation lower the requirement below the resource default', async () => {
    // Resource-wide auth-token, but this operation is annotated agent-token —
    // the annotation REPLACES the default, so no PS round trip happens.
    routeTo('agent-token', { access_mode: 'agent-token' })
    mockSignedFetch.mockResolvedValueOnce(makeResponse(200, { ok: true }))

    const result = await invokeAtResource(
      config({ agentToken: WITHOUT_PS }),
      l1({ access_mode: 'auth-token' }),
      'ping',
    )

    expect(result).toEqual({ kind: 'result', status: 200, body: { ok: true } })
    expect(mockSignedFetch).toHaveBeenCalledTimes(1)
  })

  it('skips when an operation annotation raises the requirement above the resource default', async () => {
    routeTo('per-call', { access_mode: 'per-call' })
    const result = await invokeAtResource(
      config({ agentToken: WITHOUT_PS }),
      l1({ access_mode: 'agent-token' }),
      'purchase',
    )

    expect(result.kind).toBe('skipped')
    if (result.kind !== 'skipped') throw new Error('expected skipped')
    expect(result.mode).toBe('per-call')
  })
})

describe('session-token resources', () => {
  it('captures AAuth-Access and presents it in Authorization on the next call', async () => {
    const cfg = config()
    routeTo('session-token')
    mockSignedFetch
      .mockResolvedValueOnce(makeResponse(200, { ok: 1 }, { 'aauth-access': 'sess_abc' }))
      .mockResolvedValueOnce(makeResponse(200, { ok: 2 }))

    const entry = l1({ access_mode: 'session-token' })
    await invokeAtResource(cfg, entry, 'whoami')
    await invokeAtResource(cfg, entry, 'whoami')

    const second = mockSignedFetch.mock.calls[1][1]
    expect(second.headers.authorization).toBe('AAuth sess_abc')
    // The session token must be covered by the signature.
    expect(second.components).toContain('authorization')
  })
})
