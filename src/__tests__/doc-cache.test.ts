// Vocabulary docs expire. Until 4.5.1 a durable DocCache served the first copy
// of a resource's OpenAPI forever, so operations the resource added later never
// reached list_operations (secret.agent.coop's createAccount, 2026-09-15).

import { describe, it, expect, vi } from 'vitest'
import { DOC_TTL_MS, createMemoryDocCache, loadDoc } from '../resource.js'
import type { PickedVocab } from '../resource.js'

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
