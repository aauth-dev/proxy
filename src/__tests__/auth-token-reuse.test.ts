// One auth token per (resource, account, mission): the agent presents the token
// it holds while it grants the operation, grows it to the union when a call
// needs more, starts over from the one operation once it has lapsed, and
// refreshes it inside the refresh margin. The ScopePolicy decides what else to
// declare. Budgets are what make this matter: every auth token a budgeted
// resource's access server issues is an allocation against the person's
// allowance, so one per call exhausts it (senzing.aauth.dev, 2026-09-24: six
// calls, six 100-credit tokens, 11 credits spent, locked out for the hour).

import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { L1Entry } from '../store.js'
import type { ProxyConfig } from '../agent.js'
import type { ScopePolicy } from '../scope.js'
import type { TokenRecord } from '../tokens.js'

const mockSignedFetch = vi.fn()
vi.mock('@hellocoop/httpsig', () => ({ fetch: mockSignedFetch }))

const mockRouteOperation = vi.fn()
const mockListOperations = vi.fn()
vi.mock('../resource.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../resource.js')>()
  return { ...real, routeOperation: mockRouteOperation, listOperationsForResource: mockListOperations }
})

const { invokeAtResource, listTokens } = await import('../agent.js')
const { createMemoryTokenStore } = await import('../tokens.js')

const VOCAB = 'urn:aauth:vocabulary:openapi'
const PS = 'https://ps.example'
const PS_METADATA = {
  issuer: PS,
  auth_token_endpoint: `${PS}/token`,
  person_token_endpoint: `${PS}/person`,
}
const AUTHORIZE = 'https://res.example/authorize'

const now = () => Math.floor(Date.now() / 1000)
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
const jwt = (typ: string, claims: Record<string, unknown>) => `${b64({ alg: 'Ed25519', typ })}.${b64(claims)}.sig`
const payload = (token: string) => JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>

const AGENT_TOKEN = jwt('aa-agent+jwt', { iss: 'https://agent.example', ps: PS })

function l1(overrides: Partial<L1Entry> = {}): L1Entry {
  return {
    resource: 'res.example',
    origin: 'https://res.example',
    issuer: 'https://res.example',
    name: 'Metered',
    description: 'A budgeted resource',
    access_mode: 'auth-token',
    authorization_endpoint: AUTHORIZE,
    picked_vocabs: [{ vocabUri: VOCAB, docUrl: 'https://res.example/openapi.json' }],
    added: '2026-09-24T00:00:00.000Z',
    ...overrides,
  }
}

function config(overrides: Partial<ProxyConfig> = {}): ProxyConfig {
  return {
    psUrl: PS,
    agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
    agentToken: AGENT_TOKEN,
    ...overrides,
  }
}

type Op = Record<string, string>

/**
 * A fake PS + resource, routed by URL so concurrent calls work. The resource
 * serves an operation only to an auth token whose r3_granted names it, and
 * answers every served call with an AAuth-Budget.
 */
function world(opts: { ttl?: number; perCall?: string[]; exhausted?: Set<string>; reason?: string; authorizeStatus?: number } = {}) {
  const ttl = opts.ttl ?? 3000
  const calls: Array<{ url: string; body?: Record<string, unknown>; jwt?: string }> = []
  const opsByResourceToken = new Map<string, Op[]>()
  const spent = new Map<string, number>()
  let n = 0

  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(PS_METADATA))
  mockRouteOperation.mockImplementation(async (_l1: L1Entry, opId: string) => ({
    adapter: { vocabUri: VOCAB, operationEntry: (id: string) => ({ operationId: id }) },
    plan: { kind: 'sync.request', method: 'POST', path: `/v1/${opId}`, body: '{}' },
    annotations: {},
    accessMode: opts.perCall?.includes(opId) ? 'per-call' : 'auth-token',
  }))

  mockSignedFetch.mockImplementation(async (url: string, init: { body?: string; signatureKey?: { jwt?: string } }) => {
    const body = init.body ? (JSON.parse(init.body) as Record<string, unknown>) : undefined
    const presented = init.signatureKey?.jwt
    calls.push({ url, ...(body ? { body } : {}), ...(presented ? { jwt: presented } : {}) })
    n++

    if (url === PS_METADATA.person_token_endpoint) {
      return Response.json({ person_token: jwt('aa-person+jwt', { jti: `pt${n}`, exp: now() + 3600 }), expires_in: 3600 })
    }
    if (url === AUTHORIZE) {
      if (opts.authorizeStatus) return Response.json({ error: 'nope' }, { status: opts.authorizeStatus })
      const rt = `rt${n}`
      opsByResourceToken.set(rt, (body!.r3_operations as { operations: Op[] }).operations)
      return Response.json({ resource_token: rt })
    }
    if (url === PS_METADATA.auth_token_endpoint) {
      const ops = opsByResourceToken.get(body!.resource_token as string) ?? []
      const claims = {
        jti: `at${n}`,
        iat: now(),
        exp: now() + ttl,
        budget: { amount: 100, unit: 'credits', decimals: 0 },
        r3_granted: { vocabulary: VOCAB, operations: ops },
        ...(String(body!.resource_token).startsWith('rt-proposal') ? { proposal: true } : {}),
      }
      return Response.json({ auth_token: jwt('aa-auth+jwt', claims) })
    }
    // The resource.
    const opId = url.split('/v1/')[1]!
    const claims = presented ? payload(presented) : {}
    const granted = (claims.r3_granted as { operations: Op[] } | undefined)?.operations ?? []
    if (!granted.some((o) => o.operationId === opId)) {
      return Response.json({ error: 'operation_not_granted' }, { status: 403 })
    }
    const jti = claims.jti as string
    if (opts.exhausted?.has(jti)) {
      const rt = `rt-step${n}`
      opsByResourceToken.set(rt, granted)
      return Response.json({ error: 'budget_exhausted' }, {
        status: 401,
        headers: { 'aauth-requirement': `requirement=auth-token; resource-token="${rt}"; reason=${opts.reason ?? 'budget-exhausted'}` },
      })
    }
    if (opts.perCall?.includes(opId) && !(claims.proposal as boolean | undefined)) {
      // A per-call write: a proposal for exactly this call.
      const rt = `rt-proposal${n}`
      opsByResourceToken.set(rt, [{ operationId: opId }])
      return Response.json({ error: 'per_call_approval_required' }, {
        status: 401,
        headers: { 'aauth-requirement': `requirement=auth-token; resource-token="${rt}"` },
      })
    }
    const total = (spent.get(jti) ?? 0) + 2
    spent.set(jti, total)
    return Response.json({ ok: opId }, { headers: { 'aauth-budget': `cost=2;remaining=${100 - total};unit="credits";decimals=0` } })
  })

  const at = (url: string) => calls.filter((c) => c.url === url)
  return {
    calls,
    authorizes: () => at(AUTHORIZE).map((c) => (c.body!.r3_operations as { operations: Op[] }).operations.map((o) => o.operationId)),
    exchanges: () => at(PS_METADATA.auth_token_endpoint),
    personTokens: () => at(PS_METADATA.person_token_endpoint),
    resourceCalls: () => calls.filter((c) => c.url.includes('/v1/')),
  }
}

const heldAuth = async (cfg: ProxyConfig): Promise<TokenRecord[]> => (await listTokens(cfg)).filter((t) => t.kind === 'auth')

/** A held auth token record, put straight into the store so its age can be set. */
function heldRecord(o: { exp: number; obtained_at: number; last_used?: number; ops?: string[]; account?: string }): TokenRecord {
  const operations = (o.ops ?? ['search_entities']).map((operationId) => ({ operationId }))
  const granted = { vocabulary: VOCAB, operations }
  return {
    kind: 'auth',
    resource: 'https://res.example',
    ...(o.account ? { account: o.account } : {}),
    value: jwt('aa-auth+jwt', { jti: 'held', exp: o.exp, r3_granted: granted, ...(o.account ? { account: o.account } : {}) }),
    jti: 'held',
    exp: o.exp,
    obtained_at: o.obtained_at,
    ...(o.last_used !== undefined ? { last_used: o.last_used } : {}),
    granted,
  }
}

beforeEach(() => {
  vi.restoreAllMocks()
  vi.resetAllMocks()
})

describe('one auth token per resource / account / mission', () => {
  it('reuses the held token: a repeat call is one request', async () => {
    const w = world()
    const cfg = config()

    for (let i = 0; i < 4; i++) {
      const r = await invokeAtResource(cfg, l1(), 'search_entities')
      expect(r).toMatchObject({ kind: 'result', status: 200 })
    }

    expect(w.personTokens()).toHaveLength(1)
    expect(w.authorizes()).toEqual([['search_entities']])
    expect(w.exchanges()).toHaveLength(1)
    // 3 acquisition requests + 4 resource calls.
    expect(w.calls).toHaveLength(7)
    const tokens = new Set(w.resourceCalls().map((c) => c.jwt))
    expect(tokens.size).toBe(1)
  })

  it('tracks what is left of the budget from AAuth-Budget', async () => {
    world()
    const cfg = config()
    await invokeAtResource(cfg, l1(), 'search_entities')
    await invokeAtResource(cfg, l1(), 'search_entities')

    const [held] = await heldAuth(cfg)
    expect(held!.budget).toEqual({ amount: 100, unit: 'credits', decimals: 0, remaining: 96 })
    expect(held!.last_used).toBeTypeOf('number')
  })

  it('grows to the union when a call needs an operation the held token does not grant', async () => {
    const w = world()
    const cfg = config()

    await invokeAtResource(cfg, l1(), 'search_entities')
    await invokeAtResource(cfg, l1(), 'get_entity')
    await invokeAtResource(cfg, l1(), 'search_entities')
    await invokeAtResource(cfg, l1(), 'get_entity')

    expect(w.authorizes()).toEqual([['search_entities'], ['search_entities', 'get_entity']])
    expect(w.personTokens()).toHaveLength(1)
    // One token held, and it is the grown one.
    const held = await heldAuth(cfg)
    expect(held).toHaveLength(1)
    expect(held[0]!.granted!.operations).toEqual([{ operationId: 'search_entities' }, { operationId: 'get_entity' }])
    // The last two calls presented it without authorizing again.
    const [, , third, fourth] = w.resourceCalls()
    expect(third!.jwt).toBe(held[0]!.value)
    expect(fourth!.jwt).toBe(held[0]!.value)
  })

  it('starts over from the one operation once the held token lapsed idle', async () => {
    const w = world()
    const cfg = config({ tokens: createMemoryTokenStore() })
    const seen: Array<{ reason: string; lapsed?: string[] }> = []
    cfg.scopePolicy = (req) => {
      seen.push({ reason: req.reason, ...(req.lapsed ? { lapsed: req.lapsed.granted?.operations.map((o) => o.operationId) } : {}) })
      return [req.operation]
    }
    // Held for search_entities and get_entity; expired, last used ten minutes ago.
    await cfg.tokens!.put(heldRecord({ exp: now() - 60, obtained_at: now() - 3600, last_used: now() - 600, ops: ['search_entities', 'get_entity'] }))

    await invokeAtResource(cfg, l1(), 'get_entity')

    expect(w.authorizes()).toEqual([['get_entity']])
    // The policy saw what the key last held, for a smarter policy to use.
    expect(seen).toEqual([{ reason: 'initial', lapsed: ['search_entities', 'get_entity'] }])
  })

  it('renews with the whole grant when the held token lapsed while in use', async () => {
    const w = world()
    const cfg = config({ tokens: createMemoryTokenStore() })
    await cfg.tokens!.put(heldRecord({ exp: now() + 10, obtained_at: now() - 3600, last_used: now() - 60, ops: ['search_entities', 'get_entity'] }))

    await invokeAtResource(cfg, l1(), 'search_entities')

    expect(w.authorizes()).toEqual([['search_entities', 'get_entity']])
    const [held] = await heldAuth(cfg)
    expect(held!.jti).not.toBe('held')
  })

  it('keys by account: another account gets its own token', async () => {
    const w = world()
    const cfg = config()
    await invokeAtResource(cfg, l1(), 'search_entities', {}, { account: 'a@example.com' })
    await invokeAtResource(cfg, l1(), 'search_entities', {}, { account: 'b@example.com' })
    await invokeAtResource(cfg, l1(), 'search_entities', {}, { account: 'a@example.com' })

    expect(w.exchanges()).toHaveLength(2)
    expect((await heldAuth(cfg)).map((t) => t.account).sort()).toEqual(['a@example.com', 'b@example.com'])
  })
})

describe('refresh margin', () => {
  it('presents a held auth token inside the margin rather than draw another allocation', async () => {
    const w = world()
    const cfg = config({ tokens: createMemoryTokenStore() })
    const held = heldRecord({ exp: now() + 200, obtained_at: now() - 3000 })
    await cfg.tokens!.put(held)

    await invokeAtResource(cfg, l1(), 'search_entities')

    expect(w.authorizes()).toEqual([])
    expect(w.resourceCalls()[0]!.jwt).toBe(held.value)
  })

  it('does not present a grow that failed', async () => {
    world({ authorizeStatus: 503 })
    const cfg = config({ tokens: createMemoryTokenStore() })
    await cfg.tokens!.put(heldRecord({ exp: now() + 3000, obtained_at: now() }))

    const r = await invokeAtResource(cfg, l1(), 'get_entity')

    expect(r).toMatchObject({ kind: 'result', status: 503 })
  })
})

describe('person token refresh', () => {
  const personHeld = (exp: number, obtainedAt: number): TokenRecord => ({
    kind: 'person',
    resource: 'https://res.example',
    value: jwt('aa-person+jwt', { jti: 'pt-held', exp }),
    jti: 'pt-held',
    exp,
    obtained_at: obtainedAt,
  })

  it('refreshes a person token inside the margin when a new one can live longer', async () => {
    const w = world()
    const cfg = config({ tokens: createMemoryTokenStore(), agentToken: jwt('aa-agent+jwt', { ps: PS, exp: now() + 3600 }) })
    const held = personHeld(now() + 200, now() - 3000)
    await cfg.tokens!.put(held)

    await invokeAtResource(cfg, l1(), 'search_entities')

    expect(w.personTokens()).toHaveLength(1)
    const presented = w.calls.find((c) => c.url === AUTHORIZE)!.jwt
    expect(presented).not.toBe(held.value)
    expect(payload(presented!).jti).toMatch(/^pt/)
  })

  it('presents it when the agent token caps any replacement at the same time', async () => {
    const w = world()
    const cfg = config({ tokens: createMemoryTokenStore(), agentToken: jwt('aa-agent+jwt', { ps: PS, exp: now() + 240 }) })
    const held = personHeld(now() + 200, now() - 3000)
    await cfg.tokens!.put(held)

    await invokeAtResource(cfg, l1(), 'search_entities')

    expect(w.personTokens()).toHaveLength(0)
    expect(w.calls.find((c) => c.url === AUTHORIZE)!.jwt).toBe(held.value)
  })

  it('presents the held one when the refresh fails', async () => {
    const w = world()
    const cfg = config({ tokens: createMemoryTokenStore(), agentToken: jwt('aa-agent+jwt', { ps: PS, exp: now() + 3600 }) })
    const held = personHeld(now() + 200, now() - 3000)
    await cfg.tokens!.put(held)
    const base = mockSignedFetch.getMockImplementation()!
    mockSignedFetch.mockImplementation(async (url: string, init: never) =>
      url === PS_METADATA.person_token_endpoint ? Response.json({ error: 'temporarily_unavailable' }, { status: 503 }) : base(url, init),
    )

    const r = await invokeAtResource(cfg, l1(), 'search_entities')

    expect(r).toMatchObject({ kind: 'result', status: 200 })
    expect(w.calls.find((c) => c.url === AUTHORIZE)!.jwt).toBe(held.value)
  })
})

describe('step-up and per-call', () => {
  it('replaces the held token when the resource steps it up on an exhausted budget', async () => {
    const exhausted = new Set<string>()
    const w = world({ exhausted })
    const cfg = config()

    await invokeAtResource(cfg, l1(), 'search_entities')
    const [first] = await heldAuth(cfg)
    exhausted.add(first!.jti!)

    const r = await invokeAtResource(cfg, l1(), 'search_entities')

    expect(r).toMatchObject({ kind: 'result', status: 200 })
    // The exchange presented the exhausted token, so the chain is linked.
    expect(w.exchanges()[1]!.body!.presented_token).toBe(first!.value)
    const [second] = await heldAuth(cfg)
    expect(second!.jti).not.toBe(first!.jti)
    expect(second!.presented_jti).toBe(first!.jti)
    // No second authorize: the step-up's resource token was enough.
    expect(w.authorizes()).toHaveLength(1)
  })

  // senzing.aauth.dev, 2026-09-25: the resource's step-up token named the
  // wrong presented_jti, the PS refused every renewal, and the spent token
  // stayed held, so every later call drew the same refusal.
  it('drops an exhausted token when the PS refuses its step-up, and the next call starts over', async () => {
    const exhausted = new Set<string>()
    const w = world({ exhausted })
    const cfg = config()
    await invokeAtResource(cfg, l1(), 'search_entities')
    const [first] = await heldAuth(cfg)
    exhausted.add(first!.jti!)
    const base = mockSignedFetch.getMockImplementation()!
    mockSignedFetch.mockImplementation(async (url: string, init: { body?: string }) => {
      if (url === PS_METADATA.auth_token_endpoint && String(JSON.parse(init.body!).resource_token).startsWith('rt-step')) {
        return Response.json({ error: 'invalid_resource_token' }, { status: 400 })
      }
      return base(url, init)
    })

    const refused = await invokeAtResource(cfg, l1(), 'search_entities')
    expect(refused).toMatchObject({ kind: 'result', status: 400 })
    expect(await heldAuth(cfg)).toEqual([])

    const next = await invokeAtResource(cfg, l1(), 'search_entities')
    expect(next).toMatchObject({ kind: 'result', status: 200 })
    expect(w.authorizes()).toHaveLength(2)
    expect(w.resourceCalls().at(-1)!.jwt).not.toBe(first!.value)
  })

  it('keeps a token short only for this call when the PS refuses its step-up', async () => {
    const exhausted = new Set<string>()
    world({ exhausted, reason: 'insufficient-budget' })
    const cfg = config()
    await invokeAtResource(cfg, l1(), 'search_entities')
    const [first] = await heldAuth(cfg)
    exhausted.add(first!.jti!)
    const base = mockSignedFetch.getMockImplementation()!
    mockSignedFetch.mockImplementation(async (url: string, init: { body?: string }) => {
      if (url === PS_METADATA.auth_token_endpoint && String(JSON.parse(init.body!).resource_token).startsWith('rt-step')) {
        return Response.json({ error: 'invalid_resource_token' }, { status: 400 })
      }
      return base(url, init)
    })

    const refused = await invokeAtResource(cfg, l1(), 'search_entities')
    expect(refused).toMatchObject({ kind: 'result', status: 400 })
    expect((await heldAuth(cfg)).map((t) => t.jti)).toEqual([first!.jti])
  })

  it('does not keep a per-call token in place of the held one', async () => {
    const w = world({ perCall: ['add_record'] })
    const cfg = config()

    await invokeAtResource(cfg, l1(), 'search_entities')
    const [classToken] = await heldAuth(cfg)

    // Grows the held token to cover add_record, then the resource asks for a
    // per-call approval of this exact call.
    await invokeAtResource(cfg, l1(), 'add_record')
    const [grown] = await heldAuth(cfg)
    expect(grown!.jti).not.toBe(classToken!.jti)
    expect(grown!.granted!.operations.map((o) => o.operationId)).toEqual(['search_entities', 'add_record'])

    // The proposal-bound token was presented once and not kept.
    expect(w.exchanges()).toHaveLength(3)
    expect((await heldAuth(cfg)).map((t) => t.jti)).toEqual([grown!.jti])
  })

  it('drops the held token when the resource refuses it with requirement=person-token', async () => {
    const w = world()
    const cfg = config()
    await invokeAtResource(cfg, l1(), 'search_entities')
    const [held] = await heldAuth(cfg)

    // The next call's first response refuses the held token.
    const base = mockSignedFetch.getMockImplementation()!
    mockSignedFetch.mockImplementationOnce(async () =>
      Response.json({ error: 'revoked' }, { status: 401, headers: { 'aauth-requirement': 'requirement=person-token' } }),
    )
    mockSignedFetch.mockImplementation(base)

    await invokeAtResource(cfg, l1(), 'search_entities')
    expect((await heldAuth(cfg)).map((t) => t.jti)).not.toContain(held!.jti)
    expect(w.calls.length).toBeGreaterThan(0)
  })
})

describe('step-up races and narrower tokens', () => {
  it('concurrent calls presenting one spent token step it up once', async () => {
    const exhausted = new Set<string>()
    const w = world({ exhausted })
    const cfg = config()
    await invokeAtResource(cfg, l1(), 'search_entities')
    const [first] = await heldAuth(cfg)
    exhausted.add(first!.jti!)

    const results = await Promise.all([1, 2, 3].map(() => invokeAtResource(cfg, l1(), 'search_entities')))

    for (const r of results) expect(r).toMatchObject({ kind: 'result', status: 200 })
    // One initial exchange, one step-up.
    expect(w.exchanges()).toHaveLength(2)
  })

  it('keeps the held token when a step-up returns a narrower one that is not about budget', async () => {
    world()
    const cfg = config({ tokens: createMemoryTokenStore() })
    const held = heldRecord({ exp: now() + 3000, obtained_at: now(), ops: ['search_entities', 'get_entity'] })
    await cfg.tokens!.put(held)
    // The resource answers the held token with a step-up for this one operation.
    const base = mockSignedFetch.getMockImplementation()!
    mockSignedFetch.mockImplementationOnce(async () =>
      Response.json({ error: 'step_up' }, { status: 401, headers: { 'aauth-requirement': 'requirement=auth-token; resource-token="rt-narrow"' } }),
    )
    mockSignedFetch.mockImplementation(async (url: string, init: never) => {
      if (url === PS_METADATA.auth_token_endpoint) {
        return Response.json({ auth_token: jwt('aa-auth+jwt', { jti: 'narrow', exp: now() + 3000, r3_granted: { vocabulary: VOCAB, operations: [{ operationId: 'search_entities' }] } }) })
      }
      return base(url, init)
    })

    const r = await invokeAtResource(cfg, l1(), 'search_entities')

    expect(r).toMatchObject({ kind: 'result', status: 200 })
    expect((await heldAuth(cfg)).map((t) => t.jti)).toEqual(['held'])
  })
})

describe('a token a settled pending delivered', () => {
  const settled = (claims: Record<string, unknown>) =>
    jwt('aa-auth+jwt', { jti: 'settled', exp: now() + 3000, r3_granted: { vocabulary: VOCAB, operations: [{ operationId: 'search_entities' }] }, ...claims })

  it('is held when it is this key\'s token', async () => {
    world()
    const cfg = config()
    await invokeAtResource(cfg, l1(), 'search_entities', {}, { authToken: settled({}) })
    expect((await heldAuth(cfg)).map((t) => t.jti)).toEqual(['settled'])
  })

  it('is presented but not held when it was for another account', async () => {
    const w = world()
    const cfg = config()
    const token = settled({ account: 'a@example.com' })
    await invokeAtResource(cfg, l1(), 'search_entities', {}, { account: 'b@example.com', authToken: token })
    expect(w.resourceCalls()[0]!.jwt).toBe(token)
    expect(await heldAuth(cfg)).toEqual([])
  })

  it('is presented but not held when it does not grant the operation', async () => {
    world()
    const cfg = config()
    await invokeAtResource(cfg, l1(), 'get_entity', {}, { authToken: settled({}) })
    expect((await heldAuth(cfg)).map((t) => t.jti)).not.toContain('settled')
  })
})

describe('scope policy', () => {
  it('adds what the policy returns to the first authorization', async () => {
    const w = world()
    const allReads: ScopePolicy = async (req) =>
      (await req.operations()).filter((o) => o.opId !== 'add_record').map((o) => req.entryFor(o.opId))
    mockListOperations.mockResolvedValue([{ opId: 'search_entities' }, { opId: 'get_entity' }, { opId: 'add_record' }])
    const cfg = config({ scopePolicy: allReads })

    await invokeAtResource(cfg, l1(), 'get_entity')
    await invokeAtResource(cfg, l1(), 'search_entities')

    // The invoked operation first, then the policy's additions, de-duplicated.
    expect(w.authorizes()).toEqual([['get_entity', 'search_entities']])
  })

  it('carries the held operations whatever the policy returns', async () => {
    const w = world()
    const cfg = config({ scopePolicy: () => [] })

    await invokeAtResource(cfg, l1(), 'search_entities')
    await invokeAtResource(cfg, l1(), 'get_entity')

    expect(w.authorizes()).toEqual([['search_entities'], ['search_entities', 'get_entity']])
  })

  it('asks for what the call needs when the policy throws', async () => {
    const w = world()
    const log = vi.fn()
    const cfg = config({ log, scopePolicy: () => { throw new Error('no model') } })

    const r = await invokeAtResource(cfg, l1(), 'search_entities')

    expect(r).toMatchObject({ kind: 'result', status: 200 })
    expect(w.authorizes()).toEqual([['search_entities']])
    expect(log).toHaveBeenCalledWith('scope.policy_error', expect.objectContaining({ error: 'no model' }))
  })
})

describe('concurrency', () => {
  it('two concurrent calls that both miss obtain one token between them', async () => {
    const w = world()
    const cfg = config()

    const results = await Promise.all([
      invokeAtResource(cfg, l1(), 'search_entities'),
      invokeAtResource(cfg, l1(), 'search_entities'),
      invokeAtResource(cfg, l1(), 'search_entities'),
    ])

    for (const r of results) expect(r).toMatchObject({ kind: 'result', status: 200 })
    expect(w.exchanges()).toHaveLength(1)
    expect(w.authorizes()).toEqual([['search_entities']])
  })
})

describe('token log', () => {
  it('reports put and hit, never the token value', async () => {
    world()
    const log = vi.fn()
    const cfg = config({ log })

    await invokeAtResource(cfg, l1(), 'search_entities')
    await invokeAtResource(cfg, l1(), 'search_entities')

    const events = log.mock.calls.map(([e]) => e)
    expect(events).toContain('token.put')
    expect(events).toContain('token.hit')
    const put = log.mock.calls.find(([e, f]) => e === 'token.put' && f.kind === 'auth')![1]
    expect(put).toMatchObject({ kind: 'auth', resource: 'https://res.example', reason: 'initial', operations: ['search_entities'], budget: 100 })
    const [held] = await heldAuth(cfg)
    expect(JSON.stringify(log.mock.calls)).not.toContain(held!.value)
  })
})
