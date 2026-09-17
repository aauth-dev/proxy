// Vocabulary docs expire. Until 4.5.1 a durable DocCache served the first copy
// of a resource's OpenAPI forever, so operations the resource added later never
// reached list_operations (secret.agent.coop's createAccount, 2026-09-15).

import { describe, it, expect, vi } from 'vitest'
import { DOC_TTL_MS, createMemoryDocCache, docLifetimeMs, loadDoc } from '../resource.js'
import type { PickedVocab } from '../resource.js'
import { OpenAPIAdapter } from '../vocab/index.js'
import type { LoadedDoc } from '../vocab/index.js'

function vocab(load: () => Promise<unknown>): PickedVocab {
  return {
    vocabUri: 'urn:aauth:vocabulary:openapi',
    docUrl: 'https://r.example/openapi.json',
    adapter: { load: vi.fn(load) } as unknown as PickedVocab['adapter'],
  }
}

describe('loadDoc', () => {
  it('serves the cached doc inside the TTL and refetches after it', async () => {
    const cache = createMemoryDocCache()
    let version = 1
    const v = vocab(async () => ({ version }))
    const t0 = 1_000_000

    expect(await loadDoc('r.example', v, cache, t0)).toEqual({ version: 1 })
    version = 2
    expect(await loadDoc('r.example', v, cache, t0 + DOC_TTL_MS - 1)).toEqual({ version: 1 })
    expect(await loadDoc('r.example', v, cache, t0 + DOC_TTL_MS)).toEqual({ version: 2 })
    expect(v.adapter.load).toHaveBeenCalledTimes(2)
  })

  it('treats a bare doc written before 4.5.1 as expired', async () => {
    const cache = createMemoryDocCache()
    await cache.set('r.example|urn:aauth:vocabulary:openapi', { version: 'old' })
    const v = vocab(async () => ({ version: 'new' }))
    expect(await loadDoc('r.example', v, cache)).toEqual({ version: 'new' })
  })

  it('serves a stale copy when the refetch fails, and throws with nothing cached', async () => {
    const cache = createMemoryDocCache()
    const t0 = 1_000_000
    await loadDoc('r.example', vocab(async () => ({ version: 1 })), cache, t0)
    const failing = vocab(async () => {
      throw new Error('unreachable')
    })
    expect(await loadDoc('r.example', failing, cache, t0 + DOC_TTL_MS)).toEqual({ version: 1 })
    await expect(loadDoc('other.example', failing, createMemoryDocCache())).rejects.toThrow('unreachable')
  })
})

// 4.9.0: the resource's Cache-Control decides the lifetime inside the hour, and
// an expired copy is revalidated with its ETag (secret-agent-coop plan
// read-send-services section 12b).

type Answer = { doc?: unknown; cacheControl?: string; etag?: string; notModified?: boolean; fail?: boolean }

// An adapter with loadCached: answers in order, recording the If-None-Match of each request.
function cachingVocab(answers: Answer[]) {
  const ifNoneMatch: Array<string | undefined> = []
  let i = 0
  const loadCached = vi.fn(async (_url: string, opts?: { ifNoneMatch?: string }): Promise<LoadedDoc> => {
    ifNoneMatch.push(opts?.ifNoneMatch)
    const a = answers[Math.min(i++, answers.length - 1)]
    if (a.fail) throw new Error('unreachable')
    if (a.notModified) return { notModified: true, cacheControl: a.cacheControl, etag: a.etag }
    return { doc: a.doc, cacheControl: a.cacheControl, etag: a.etag }
  })
  const v: PickedVocab = {
    vocabUri: 'urn:aauth:vocabulary:openapi',
    docUrl: 'https://r.example/openapi.json',
    adapter: { loadCached, load: vi.fn(async () => ({ version: 'plain' })) } as unknown as PickedVocab['adapter'],
  }
  return { v, loadCached, ifNoneMatch }
}

const T0 = 1_000_000
const MIN = 60 * 1000

describe('loadDoc honors Cache-Control', () => {
  it('max-age: served for that long, fetched again after it', async () => {
    const cache = createMemoryDocCache()
    const { v, loadCached } = cachingVocab([
      { doc: { version: 1 }, cacheControl: 'public, max-age=300' },
      { doc: { version: 2 }, cacheControl: 'public, max-age=300' },
    ])
    expect(await loadDoc('r.example', v, cache, T0)).toEqual({ version: 1 })
    expect(await loadDoc('r.example', v, cache, T0 + 5 * MIN - 1)).toEqual({ version: 1 })
    expect(loadCached).toHaveBeenCalledTimes(1)
    expect(await loadDoc('r.example', v, cache, T0 + 5 * MIN)).toEqual({ version: 2 })
    expect(loadCached).toHaveBeenCalledTimes(2)
  })

  it('s-maxage wins over max-age', async () => {
    const cache = createMemoryDocCache()
    const { v, loadCached } = cachingVocab([{ doc: { version: 1 }, cacheControl: 'max-age=600, s-maxage=60' }, { doc: { version: 2 } }])
    await loadDoc('r.example', v, cache, T0)
    expect(await loadDoc('r.example', v, cache, T0 + MIN - 1)).toEqual({ version: 1 })
    expect(await loadDoc('r.example', v, cache, T0 + MIN)).toEqual({ version: 2 })
    expect(loadCached).toHaveBeenCalledTimes(2)
  })

  it('no-store: fetched every time and nothing is kept, not even as a stale fallback', async () => {
    const cache = createMemoryDocCache()
    const { v, loadCached } = cachingVocab([
      { doc: { version: 1 }, cacheControl: 'no-store' },
      { doc: { version: 2 }, cacheControl: 'no-store' },
      { fail: true },
    ])
    expect(await loadDoc('r.example', v, cache, T0)).toEqual({ version: 1 })
    expect(await cache.get('r.example|urn:aauth:vocabulary:openapi')).toBeUndefined()
    expect(await loadDoc('r.example', v, cache, T0 + 1)).toEqual({ version: 2 })
    expect(loadCached).toHaveBeenCalledTimes(2)
    await expect(loadDoc('r.example', v, cache, T0 + 2)).rejects.toThrow('unreachable')
  })

  it('no-store after a cacheable copy drops that copy', async () => {
    const cache = createMemoryDocCache()
    const { v } = cachingVocab([{ doc: { version: 1 }, cacheControl: 'max-age=60' }, { doc: { version: 2 }, cacheControl: 'no-store' }, { fail: true }])
    await loadDoc('r.example', v, cache, T0)
    expect(await loadDoc('r.example', v, cache, T0 + MIN)).toEqual({ version: 2 })
    await expect(loadDoc('r.example', v, cache, T0 + MIN + 1)).rejects.toThrow('unreachable')
  })

  it('no-cache: asked every time, revalidated with the ETag, a stale copy still beats an unreachable resource', async () => {
    const cache = createMemoryDocCache()
    const { v, loadCached, ifNoneMatch } = cachingVocab([
      { doc: { version: 1 }, cacheControl: 'no-cache', etag: '"v1"' },
      { notModified: true, cacheControl: 'no-cache', etag: '"v1"' },
      { fail: true },
    ])
    expect(await loadDoc('r.example', v, cache, T0)).toEqual({ version: 1 })
    expect(await loadDoc('r.example', v, cache, T0 + 1)).toEqual({ version: 1 })
    expect(loadCached).toHaveBeenCalledTimes(2)
    expect(ifNoneMatch).toEqual([undefined, '"v1"'])
    expect(await loadDoc('r.example', v, cache, T0 + 2)).toEqual({ version: 1 })
  })

  it('no header: one hour, as before', async () => {
    const cache = createMemoryDocCache()
    const { v, loadCached } = cachingVocab([{ doc: { version: 1 } }, { doc: { version: 2 } }])
    await loadDoc('r.example', v, cache, T0)
    expect(await loadDoc('r.example', v, cache, T0 + DOC_TTL_MS - 1)).toEqual({ version: 1 })
    expect(await loadDoc('r.example', v, cache, T0 + DOC_TTL_MS)).toEqual({ version: 2 })
    expect(loadCached).toHaveBeenCalledTimes(2)
  })

  it('the one-hour cap: max-age=86400 is served for an hour, no longer', async () => {
    const cache = createMemoryDocCache()
    const { v, loadCached } = cachingVocab([{ doc: { version: 1 }, cacheControl: 'public, max-age=86400' }, { doc: { version: 2 } }])
    await loadDoc('r.example', v, cache, T0)
    expect(await loadDoc('r.example', v, cache, T0 + DOC_TTL_MS - 1)).toEqual({ version: 1 })
    expect(loadCached).toHaveBeenCalledTimes(1)
    expect(await loadDoc('r.example', v, cache, T0 + DOC_TTL_MS)).toEqual({ version: 2 })
  })

  it('304 revalidation: on expiry If-None-Match carries the ETag; a 304 renews the copy without a new body', async () => {
    const cache = createMemoryDocCache()
    const { v, loadCached, ifNoneMatch } = cachingVocab([
      { doc: { version: 1 }, cacheControl: 'public, max-age=300', etag: '"abc"' },
      { notModified: true, cacheControl: 'public, max-age=300', etag: '"abc"' },
      { doc: { version: 2 }, cacheControl: 'public, max-age=300', etag: '"def"' },
    ])
    expect(await loadDoc('r.example', v, cache, T0)).toEqual({ version: 1 })
    // Expired: revalidated, unchanged, renewed for another five minutes.
    expect(await loadDoc('r.example', v, cache, T0 + 5 * MIN)).toEqual({ version: 1 })
    expect(ifNoneMatch).toEqual([undefined, '"abc"'])
    expect(await loadDoc('r.example', v, cache, T0 + 10 * MIN - 1)).toEqual({ version: 1 })
    expect(loadCached).toHaveBeenCalledTimes(2)
    // Expired again, and this time it changed.
    expect(await loadDoc('r.example', v, cache, T0 + 10 * MIN)).toEqual({ version: 2 })
    expect(ifNoneMatch).toEqual([undefined, '"abc"', '"abc"'])
    expect(await loadDoc('r.example', v, cache, T0 + 15 * MIN)).toBeDefined()
    expect(ifNoneMatch.at(-1)).toBe('"def"')
  })

  it('a 304 without Cache-Control keeps the lifetime the copy came with', async () => {
    const cache = createMemoryDocCache()
    const { v, loadCached } = cachingVocab([{ doc: { version: 1 }, cacheControl: 'max-age=120', etag: '"abc"' }, { notModified: true }, { doc: { version: 2 } }])
    await loadDoc('r.example', v, cache, T0)
    await loadDoc('r.example', v, cache, T0 + 2 * MIN)
    expect(await loadDoc('r.example', v, cache, T0 + 4 * MIN - 1)).toEqual({ version: 1 })
    expect(loadCached).toHaveBeenCalledTimes(2)
    expect(await loadDoc('r.example', v, cache, T0 + 4 * MIN)).toEqual({ version: 2 })
  })

  it('no ETag: an expired copy is fetched unconditionally', async () => {
    const cache = createMemoryDocCache()
    const { v, ifNoneMatch } = cachingVocab([{ doc: { version: 1 }, cacheControl: 'max-age=60' }, { doc: { version: 2 }, cacheControl: 'max-age=60' }])
    await loadDoc('r.example', v, cache, T0)
    expect(await loadDoc('r.example', v, cache, T0 + MIN)).toEqual({ version: 2 })
    expect(ifNoneMatch).toEqual([undefined, undefined])
  })

  it('an entry written by 4.5.1–4.8.x (no expiresAt) still expires an hour after fetchedAt', async () => {
    const cache = createMemoryDocCache()
    await cache.set('r.example|urn:aauth:vocabulary:openapi', { aauth_doc_cache: 1, fetchedAt: T0, doc: { version: 'old' } })
    const { v, loadCached } = cachingVocab([{ doc: { version: 'new' }, cacheControl: 'max-age=300' }])
    expect(await loadDoc('r.example', v, cache, T0 + DOC_TTL_MS - 1)).toEqual({ version: 'old' })
    expect(loadCached).not.toHaveBeenCalled()
    expect(await loadDoc('r.example', v, cache, T0 + DOC_TTL_MS)).toEqual({ version: 'new' })
  })

  it('an adapter without loadCached (MCP) is cached for an hour', async () => {
    const cache = createMemoryDocCache()
    let version = 1
    const v = vocab(async () => ({ version }))
    await loadDoc('r.example', v, cache, T0)
    version = 2
    expect(await loadDoc('r.example', v, cache, T0 + DOC_TTL_MS - 1)).toEqual({ version: 1 })
  })
})

describe('docLifetimeMs', () => {
  it('reads the directives that matter and ignores the rest', () => {
    expect(docLifetimeMs(undefined)).toBe(DOC_TTL_MS)
    expect(docLifetimeMs('')).toBe(DOC_TTL_MS)
    expect(docLifetimeMs('public')).toBe(DOC_TTL_MS)
    expect(docLifetimeMs('public, max-age=300')).toBe(300_000)
    expect(docLifetimeMs('MAX-AGE=300')).toBe(300_000)
    expect(docLifetimeMs('max-age="300"')).toBe(300_000)
    expect(docLifetimeMs('max-age=0')).toBe(0)
    expect(docLifetimeMs('max-age=abc')).toBe(DOC_TTL_MS)
    expect(docLifetimeMs('max-age=7200')).toBe(DOC_TTL_MS)
    expect(docLifetimeMs('s-maxage=10, max-age=300')).toBe(10_000)
    expect(docLifetimeMs('no-cache')).toBe(0)
    expect(docLifetimeMs('no-cache, max-age=300')).toBe(0)
    expect(docLifetimeMs('no-store')).toBe('no-store')
    expect(docLifetimeMs('private, no-store, max-age=300')).toBe('no-store')
  })
})

describe('OpenAPIAdapter.loadCached', () => {
  const spec = { openapi: '3.1.0', paths: { '/x': { get: { operationId: 'getX' } } } }
  it('returns the document with the response\'s Cache-Control and ETag, and sends If-None-Match', async () => {
    const seen: Array<string | null> = []
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const inm = new Headers(init?.headers).get('if-none-match')
      seen.push(inm)
      if (inm === '"abc"') return new Response(null, { status: 304, headers: { 'cache-control': 'public, max-age=300', etag: '"abc"' } })
      return new Response(JSON.stringify(spec), { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=300', etag: '"abc"' } })
    })
    try {
      const adapter = new OpenAPIAdapter()
      const first = await adapter.loadCached('https://r.example/openapi.json')
      expect(first).toMatchObject({ cacheControl: 'public, max-age=300', etag: '"abc"' })
      expect(first.notModified ? [] : adapter.listOperations(first.doc).map((o) => o.opId)).toEqual(['getX'])
      expect(await adapter.loadCached('https://r.example/openapi.json', { ifNoneMatch: '"abc"' })).toEqual({ notModified: true, cacheControl: 'public, max-age=300', etag: '"abc"' })
      expect(seen).toEqual([null, '"abc"'])
      // load is unchanged for callers that want only the document.
      expect(adapter.listOperations(await adapter.load('https://r.example/openapi.json')).map((o) => o.opId)).toEqual(['getX'])
    } finally {
      fetchMock.mockRestore()
    }
  })
  it('end to end through loadDoc: one 200, then a 304 on expiry, the operations unchanged', async () => {
    let requests = 0
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      requests++
      if (new Headers(init?.headers).get('if-none-match') === '"abc"') return new Response(null, { status: 304, headers: { etag: '"abc"' } })
      return new Response(JSON.stringify(spec), { status: 200, headers: { 'cache-control': 'public, max-age=300', etag: '"abc"' } })
    })
    try {
      const adapter = new OpenAPIAdapter()
      const v: PickedVocab = { vocabUri: adapter.vocabUri, docUrl: 'https://r.example/openapi.json', adapter }
      const cache = createMemoryDocCache()
      const a = await loadDoc('r.example', v, cache, T0)
      const b = await loadDoc('r.example', v, cache, T0 + 5 * MIN)
      expect(requests).toBe(2)
      expect(b).toBe(a)
      await loadDoc('r.example', v, cache, T0 + 10 * MIN - 1)
      expect(requests).toBe(2)
    } finally {
      fetchMock.mockRestore()
    }
  })
})
