// The token store itself (tokens.ts): one record per key, updates and drops
// guarded by jti so a stale writer cannot clobber the token that replaced it,
// the acquisition lease, the lifetime rules, and the list_resources view.

import { mkdtempSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import {
  authTokenRecord,
  createFsTokenStore,
  createLeaseTable,
  createMemoryTokenStore,
  grantsAtLeast,
  grantsOperation,
  isDueForRefresh,
  isLive,
  NO_LEASE,
  wasInUse,
} from '../tokens.js'
import type { TokenKey, TokenRecord, TokenStore } from '../tokens.js'

const now = () => Math.floor(Date.now() / 1000)
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
const VOCAB = 'urn:aauth:vocabulary:openapi'

const AUTH: TokenKey = { kind: 'auth', resource: 'https://res.example', mission_s256: 'm1' }
const rec = (jti: string, extra: Partial<TokenRecord> = {}): TokenRecord => ({
  ...AUTH,
  value: `tok-${jti}`,
  jti,
  exp: now() + 3000,
  obtained_at: now(),
  ...extra,
})

function storeContract(name: string, make: () => { store: TokenStore; done?: () => void }) {
  describe(name, () => {
    it('holds one record per key: put replaces', async () => {
      const { store, done } = make()
      await store.put(rec('a'))
      await store.put(rec('b'))
      await store.put({ kind: 'person', resource: 'https://res.example', value: 'pt', obtained_at: now() })
      expect((await store.get(AUTH))!.jti).toBe('b')
      expect(await store.list()).toHaveLength(2)
      // Another account, another key.
      expect(await store.get({ ...AUTH, account: 'x' })).toBeUndefined()
      done?.()
    })

    it('updates only the token it was told about', async () => {
      const { store, done } = make()
      await store.put(rec('a', { budget: { amount: 100, unit: 'credits', decimals: 0 } }))
      await store.update(AUTH, 'a', { budget: { amount: 100, unit: 'credits', decimals: 0, remaining: 98 } })
      expect((await store.get(AUTH))!.budget!.remaining).toBe(98)

      // A replacement landed; a late update for the old token is ignored.
      await store.put(rec('b'))
      await store.update(AUTH, 'a', { last_used: 1 })
      expect((await store.get(AUTH))!.last_used).toBeUndefined()
      done?.()
    })

    it('drops only the token it was told about, or whatever the key holds', async () => {
      const { store, done } = make()
      await store.put(rec('b'))
      await store.drop(AUTH, 'a')
      expect(await store.get(AUTH)).toBeDefined()
      await store.drop(AUTH, 'b')
      expect(await store.get(AUTH)).toBeUndefined()
      await store.put(rec('c'))
      await store.drop(AUTH)
      expect(await store.get(AUTH)).toBeUndefined()
      done?.()
    })

    it('flushes everything', async () => {
      const { store, done } = make()
      await store.put(rec('a'))
      await store.put({ kind: 'session', resource: 'https://res.example', value: 's', obtained_at: now() })
      await store.flush()
      expect(await store.list()).toEqual([])
      done?.()
    })
  })
}

storeContract('memory token store', () => ({ store: createMemoryTokenStore() }))
storeContract('filesystem token store', () => {
  const dir = mkdtempSync(join(tmpdir(), 'aauth-tokens-'))
  return { store: createFsTokenStore({ dir }), done: () => rmSync(dir, { recursive: true, force: true }) }
})

describe('filesystem token store', () => {
  it('writes the file readable by its owner only', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'aauth-tokens-'))
    try {
      await createFsTokenStore({ dir }).put(rec('a'))
      expect(statSync(join(dir, 'tokens.json')).mode & 0o777).toBe(0o600)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('acquisition lease', () => {
  it('makes the second acquirer wait for the first to release', async () => {
    const leases = createLeaseTable()
    const order: string[] = []
    const first = await leases.acquire('k')
    const second = leases.acquire('k').then((id) => {
      order.push('second')
      return id
    })
    await new Promise((r) => setTimeout(r, 10))
    order.push('first-releases')
    await leases.release('k', first)
    await leases.release('k', await second)
    expect(order).toEqual(['first-releases', 'second'])
  })

  it('lets the next acquirer in once an unreleased lease lapses', async () => {
    const leases = createLeaseTable(20)
    await leases.acquire('k')
    const started = Date.now()
    await leases.acquire('k')
    expect(Date.now() - started).toBeGreaterThanOrEqual(15)
  })

  it('stops waiting after the wait bound and goes ahead without a lease', async () => {
    const leases = createLeaseTable(10_000, 20)
    await leases.acquire('k')
    expect(await leases.acquire('k')).toBe(NO_LEASE)
  })

  it('ignores a release with a lease id that is not the current one', async () => {
    const leases = createLeaseTable(10_000)
    const id = await leases.acquire('k')
    await leases.release('k', 'someone-else')
    let got = false
    void leases.acquire('k').then(() => (got = true))
    await new Promise((r) => setTimeout(r, 10))
    expect(got).toBe(false)
    await leases.release('k', id)
    await new Promise((r) => setTimeout(r, 0))
    expect(got).toBe(true)
  })
})

describe('lifetime', () => {
  it('a token within 30 s of exp is not live', () => {
    expect(isLive(rec('a', { exp: now() + 29 }))).toBe(false)
    expect(isLive(rec('a', { exp: now() + 31 }))).toBe(true)
    expect(isLive(rec('a', { exp: undefined }))).toBe(true)
  })

  it('is due for refresh inside the five-minute margin, once, and only when a refresh can extend it', () => {
    expect(isDueForRefresh(rec('a', { exp: now() + 299, obtained_at: now() - 3000 }))).toBe(true)
    expect(isDueForRefresh(rec('a', { exp: now() + 301, obtained_at: now() - 3000 }))).toBe(false)
    // Issued with three minutes to live: presented until it expires.
    expect(isDueForRefresh(rec('a', { exp: now() + 180, obtained_at: now() }))).toBe(false)
    // The token above it in the chain expires with it: a refresh buys nothing.
    expect(isDueForRefresh(rec('a', { exp: now() + 200, obtained_at: now() - 3000 }), now() + 240)).toBe(false)
    expect(isDueForRefresh(rec('a', { exp: now() + 200, obtained_at: now() - 3000 }), now() + 3600)).toBe(true)
  })

  it('a lapsed token was in use when it was used in the last five minutes', () => {
    expect(wasInUse(rec('a', { obtained_at: now() - 3600, last_used: now() - 60 }))).toBe(true)
    expect(wasInUse(rec('a', { obtained_at: now() - 3600, last_used: now() - 600 }))).toBe(false)
    expect(wasInUse(rec('a', { obtained_at: now() - 60 }))).toBe(true)
  })

  it('a replacement must grant at least what the held token did', () => {
    const held = rec('a', { granted: { vocabulary: VOCAB, operations: [{ operationId: 'x' }, { operationId: 'y' }] } })
    expect(grantsAtLeast(rec('b', { granted: { vocabulary: VOCAB, operations: [{ operationId: 'y' }, { operationId: 'x' }, { operationId: 'z' }] } }), held)).toBe(true)
    expect(grantsAtLeast(rec('b', { granted: { vocabulary: VOCAB, operations: [{ operationId: 'x' }] } }), held)).toBe(false)
  })
})

describe('auth token claims', () => {
  it('reads the grant, the budget and the lifetime from the token', () => {
    const claims = {
      jti: 'at1',
      iat: 100,
      exp: 4000000000,
      scope: 'senzing',
      budget: { amount: 100, unit: 'credits', decimals: 0 },
      r3_granted: { vocabulary: VOCAB, operations: [{ operationId: 'search_entities' }] },
    }
    const token = `${b64({ typ: 'aa-auth+jwt' })}.${b64(claims)}.sig`
    const r = authTokenRecord(AUTH, token, { agentJkt: 'jkt', presentedJti: 'pt1' })!
    expect(r).toMatchObject({
      ...AUTH,
      value: token,
      agent_jkt: 'jkt',
      jti: 'at1',
      exp: 4000000000,
      presented_jti: 'pt1',
      scope: 'senzing',
      budget: { amount: 100, unit: 'credits', decimals: 0 },
      granted: claims.r3_granted,
    })
    expect(grantsOperation(r, VOCAB, { operationId: 'search_entities' })).toBe(true)
    expect(grantsOperation(r, VOCAB, { operationId: 'get_entity' })).toBe(false)
    expect(grantsOperation(r, 'urn:aauth:vocabulary:mcp', { tool: 'search_entities' })).toBe(false)
  })

  it('does not keep a token it cannot read an expiry from', () => {
    expect(authTokenRecord(AUTH, 'opaque')).toBeUndefined()
    expect(authTokenRecord(AUTH, `${b64({})}.${b64({ jti: 'x' })}.sig`)).toBeUndefined()
  })

  it('a token granting by scope alone is presented and the resource decides', () => {
    expect(grantsOperation(rec('a', { scope: 'senzing' }), VOCAB, { operationId: 'anything' })).toBe(true)
  })
})

describe('list_resources', () => {
  it('shows what each held auth token grants and what is left of it — never the token', async () => {
    const { McpServer, InMemoryTransport } = await import('@modelcontextprotocol/server')
    const { Client } = await import('@modelcontextprotocol/client')
    const { buildProxyTools } = await import('../tools.js')

    const tokens = createMemoryTokenStore()
    await tokens.put(rec('live', {
      account: 'a@example.com',
      value: 'SECRET-TOKEN-VALUE',
      granted: { vocabulary: VOCAB, operations: [{ operationId: 'search_entities' }, { operationId: 'get_entity' }] },
      budget: { amount: 100, unit: 'credits', decimals: 0, remaining: 89 },
    }))
    await tokens.put(rec('lapsed', { exp: now() - 10 }))
    await tokens.put({ kind: 'person', resource: 'https://res.example', value: 'pt', obtained_at: now() })

    const b = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
    const cfg = {
      psUrl: 'https://ps.example',
      agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
      agentToken: `${b({ typ: 'aa-agent+jwt' })}.${b({ ps: 'https://ps.example' })}.sig`,
    }
    const entry = {
      resource: 'res.example',
      origin: 'https://res.example',
      issuer: 'https://res.example',
      name: 'Metered',
      description: 'test',
      access_mode: 'auth-token',
      picked_vocabs: [],
      added: '2026-09-24T00:00:00.000Z',
    }
    const server = new McpServer({ name: 'test', version: '0.0.0' })
    await buildProxyTools(server, {
      l1: { list: async () => [entry], get: async () => entry, upsert: async () => {}, remove: async () => true, touch: async () => {} },
      registryCache: { read: async () => undefined, write: async () => {} },
      identity: { resolve: async () => ({ kind: 'ready', cfg }), peek: () => cfg },
      tokens,
    })
    const [ct, st] = InMemoryTransport.createLinkedPair()
    const client = new Client({ name: 't', version: '0' })
    await Promise.all([server.connect(st), client.connect(ct)])
    try {
      const result = await client.callTool({ name: 'list_resources', arguments: {} })
      const text = (result as { content: { text: string }[] }).content[0]!.text
      const [row] = JSON.parse(text) as Array<{ authorizations: unknown[] }>
      expect(row!.authorizations).toEqual([
        {
          account: 'a@example.com',
          operations: ['search_entities', 'get_entity'],
          budget: { remaining: 89, amount: 100, unit: 'credits' },
          expires_in: expect.any(Number),
        },
      ])
      expect(text).not.toContain('SECRET-TOKEN-VALUE')
    } finally {
      await client.close()
    }
  })
})
