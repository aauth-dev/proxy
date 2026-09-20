// 4.10.0: a stored resource entry is kept current. Until now the well-known
// was read once at connect_resources and never again, so a changed access_mode,
// connection object or vocabulary URL never reached a person already connected.
// The rule is the vocabulary doc cache's (doc-cache.test.ts): the resource's
// Cache-Control decides, at most one hour; an expired entry with an ETag is
// revalidated with If-None-Match.

import { afterEach, describe, expect, it, vi } from 'vitest'
import { DOC_TTL_MS, fetchResourceConditional, refreshResourceEntry, toL1Entry, fetchResource } from '../resource.js'
import type { L1Entry } from '../store.js'

const HOST = 'r.example'
const URL_ = `https://${HOST}/.well-known/aauth-resource.json`
const T0 = 1_700_000_000_000
const MIN = 60_000

type Answer = { meta?: Record<string, unknown>; cacheControl?: string; etag?: string; status?: number; fail?: boolean }

const meta = (over: Record<string, unknown> = {}) => ({
  issuer: `https://${HOST}`,
  name: 'R',
  description: 'first',
  access_mode: 'person-token',
  r3_vocabularies: { 'urn:aauth:vocabulary:openapi': `https://${HOST}/openapi.json` },
  ...over,
})

// Answers in order; records the If-None-Match of each request to the well-known.
function serve(answers: Answer[]) {
  const ifNoneMatch: Array<string | null> = []
  let i = 0
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input) !== URL_) throw new Error(`unexpected fetch ${String(input)}`)
    ifNoneMatch.push(new Headers(init?.headers).get('if-none-match'))
    const a = answers[Math.min(i++, answers.length - 1)]
    if (a.fail) throw new Error('unreachable')
    const headers: Record<string, string> = { 'content-type': 'application/json' }
    if (a.cacheControl) headers['cache-control'] = a.cacheControl
    if (a.etag) headers.etag = a.etag
    if (a.status === 304) return new Response(null, { status: 304, headers })
    return new Response(JSON.stringify(a.meta ?? meta()), { status: a.status ?? 200, headers })
  })
  return { ifNoneMatch, requests: () => i }
}

async function connected(now = T0): Promise<L1Entry> {
  return { ...toL1Entry(await fetchResource(HOST), now), last_used: '2026-02-01T00:00:00.000Z', connections: [{ id: 'c1' } as never] }
}

afterEach(() => vi.restoreAllMocks())

describe('refreshResourceEntry', () => {
  it('max-age: the stored entry is used for that long, then the well-known is read again and the metadata replaced', async () => {
    const s = serve([{ cacheControl: 'public, max-age=300' }, { meta: meta({ description: 'second', access_mode: 'auth-token' }), cacheControl: 'public, max-age=300' }])
    const entry = await connected()
    expect(entry.meta_expires_at).toBe(T0 + 5 * MIN)

    const inside = await refreshResourceEntry(entry, { now: T0 + 5 * MIN - 1 })
    expect(inside).toEqual({ entry, changed: false })
    expect(s.requests()).toBe(1)

    const after = await refreshResourceEntry(entry, { now: T0 + 5 * MIN })
    expect(s.requests()).toBe(2)
    expect(after.changed).toBe(true)
    expect(after.entry).toMatchObject({ description: 'second', access_mode: 'auth-token', meta_expires_at: T0 + 10 * MIN })
  })

  it('keeps what the person has accumulated on the entry: added, last_used, connections', async () => {
    serve([{ cacheControl: 'max-age=60' }, { meta: meta({ description: 'second' }), cacheControl: 'max-age=60' }])
    const entry = await connected()
    const { entry: next } = await refreshResourceEntry(entry, { now: T0 + MIN })
    expect(next.added).toBe(entry.added)
    expect(next.last_used).toBe('2026-02-01T00:00:00.000Z')
    expect(next.connections).toEqual(entry.connections)
  })

  it('a changed vocabulary URL reaches the entry', async () => {
    serve([{ cacheControl: 'max-age=60' }, { meta: meta({ r3_vocabularies: { 'urn:aauth:vocabulary:openapi': `https://${HOST}/v2/openapi.json` } }), cacheControl: 'max-age=60' }])
    const { entry: next } = await refreshResourceEntry(await connected(), { now: T0 + MIN })
    expect(next.picked_vocabs).toEqual([{ vocabUri: 'urn:aauth:vocabulary:openapi', docUrl: `https://${HOST}/v2/openapi.json` }])
  })

  it('304 revalidation: on expiry If-None-Match carries the ETag; a 304 renews the entry without a new body', async () => {
    const s = serve([
      { cacheControl: 'public, max-age=300', etag: '"abc"' },
      { status: 304, cacheControl: 'public, max-age=300', etag: '"abc"' },
      { meta: meta({ description: 'second' }), cacheControl: 'public, max-age=300', etag: '"def"' },
    ])
    const entry = await connected()
    expect(entry.meta_etag).toBe('"abc"')
    const renewed = await refreshResourceEntry(entry, { now: T0 + 5 * MIN })
    expect(s.ifNoneMatch).toEqual([null, '"abc"'])
    expect(renewed.changed).toBe(true)
    expect(renewed.entry).toEqual({ ...entry, meta_expires_at: T0 + 10 * MIN })
    expect((await refreshResourceEntry(renewed.entry, { now: T0 + 10 * MIN - 1 })).changed).toBe(false)
    const replaced = await refreshResourceEntry(renewed.entry, { now: T0 + 10 * MIN })
    expect(replaced.entry).toMatchObject({ description: 'second', meta_etag: '"def"' })
  })

  it('a 304 without Cache-Control keeps the lifetime the entry came with', async () => {
    serve([{ cacheControl: 'max-age=120', etag: '"abc"' }, { status: 304 }])
    const { entry: renewed } = await refreshResourceEntry(await connected(), { now: T0 + 2 * MIN })
    expect(renewed.meta_expires_at).toBe(T0 + 4 * MIN)
  })

  it('no header: one hour; the one-hour cap: max-age=86400 is an hour', async () => {
    serve([{}, { cacheControl: 'max-age=86400' }])
    const plain = await connected()
    expect(plain.meta_expires_at).toBe(T0 + DOC_TTL_MS)
    expect((await refreshResourceEntry(plain, { now: T0 + DOC_TTL_MS - 1 })).changed).toBe(false)
    const { entry: capped } = await refreshResourceEntry(plain, { now: T0 + DOC_TTL_MS })
    expect(capped.meta_expires_at).toBe(T0 + 2 * DOC_TTL_MS)
  })

  it('no-store and no-cache: asked every time; the entry itself is always kept', async () => {
    for (const cacheControl of ['no-store', 'no-cache']) {
      vi.restoreAllMocks()
      const s = serve([{ cacheControl }, { meta: meta({ description: 'second' }), cacheControl }])
      const entry = await connected()
      expect(entry.meta_expires_at, cacheControl).toBe(T0)
      const next = await refreshResourceEntry(entry, { now: T0 })
      expect(s.requests(), cacheControl).toBe(2)
      expect(next.entry.description, cacheControl).toBe('second')
    }
  })

  it('an unreachable resource leaves the stored entry in use', async () => {
    serve([{ cacheControl: 'max-age=60' }, { fail: true }, { status: 500 }])
    const entry = await connected()
    expect(await refreshResourceEntry(entry, { now: T0 + MIN })).toEqual({ entry, changed: false })
    expect(await refreshResourceEntry(entry, { now: T0 + MIN })).toEqual({ entry, changed: false })
  })

  it('an entry stored before 4.10.0 (no meta_expires_at) is read again on its next use', async () => {
    const s = serve([{}, { meta: meta({ description: 'second' }), cacheControl: 'max-age=300' }])
    const { meta_expires_at: _e, meta_max_age_ms: _m, meta_etag: _t, ...old } = await connected()
    const next = await refreshResourceEntry(old, { now: T0 + 1 })
    expect(s.requests()).toBe(2)
    expect(next.entry).toMatchObject({ description: 'second', meta_expires_at: T0 + 1 + 5 * MIN })
  })

  it('a resource that stops advertising a usable vocabulary keeps the one that works, and is asked again after the lifetime', async () => {
    const s = serve([{ cacheControl: 'max-age=60' }, { meta: meta({ r3_vocabularies: { 'urn:aauth:vocabulary:grpc': `https://${HOST}/grpc` } }), cacheControl: 'max-age=60' }])
    const entry = await connected()
    const next = await refreshResourceEntry(entry, { now: T0 + MIN })
    expect(next.entry.picked_vocabs).toEqual(entry.picked_vocabs)
    expect(next.entry.meta_expires_at).toBe(T0 + 2 * MIN)
    expect((await refreshResourceEntry(next.entry, { now: T0 + 2 * MIN - 1 })).changed).toBe(false)
    expect(s.requests()).toBe(2)
  })
})

describe('fetchResourceConditional', () => {
  it('returns the response\'s Cache-Control and ETag, and notModified for a 304 to If-None-Match', async () => {
    serve([{ cacheControl: 'public, max-age=300', etag: '"abc"' }, { status: 304, etag: '"abc"' }])
    const first = await fetchResourceConditional(HOST)
    expect(first).toMatchObject({ host: HOST, cacheControl: 'public, max-age=300', etag: '"abc"' })
    expect(await fetchResourceConditional(HOST, { ifNoneMatch: '"abc"' })).toEqual({ notModified: true, cacheControl: undefined, etag: '"abc"' })
  })
  it('still refuses a redirect and an issuer that is not the origin', async () => {
    serve([{ status: 302 }])
    await expect(fetchResourceConditional(HOST)).rejects.toThrow(/redirect/)
    vi.restoreAllMocks()
    serve([{ meta: meta({ issuer: 'https://elsewhere.example' }) }])
    await expect(fetchResourceConditional(HOST)).rejects.toThrow(/issuer mismatch/)
  })
})
