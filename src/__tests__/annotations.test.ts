// Operation access annotations (R3 -02 §Operation Access Annotations): reading
// them off an OpenAPI Operation Object and an MCP Tool `_meta`, and resolving
// them against the resource-wide access_mode on the way to the LLM.

import { describe, it, expect } from 'vitest'
import {
  effectiveAccessMode,
  OpenAPIAdapter,
  readMcpToolAnnotations,
  readOpenApiAnnotations,
} from '../vocab/index.js'
import { getOperationsForResource, listOperationsForResource } from '../resource.js'
import type { L1Entry } from '../store.js'

const doc = {
  openapi: '3.1.0',
  paths: {
    '/balance': {
      get: {
        operationId: 'getBalance',
        summary: 'Read the account balance',
        'x-aauth-access-mode': 'person-token',
      },
    },
    '/datasets/{id}/purchase': {
      post: {
        operationId: 'purchaseDataset',
        summary: 'Buy a dataset',
        'x-aauth-access-mode': 'per-call',
        'x-aauth-budget': true,
      },
    },
    '/datasets': {
      get: { operationId: 'listDatasets', summary: 'List datasets' },
    },
    '/meter': {
      post: {
        operationId: 'meterUsage',
        summary: 'Report usage',
        'x-aauth-budget': true,
      },
    },
    '/oops': {
      get: {
        operationId: 'misdeclared',
        // MUST NOT appear in an annotation — dropped, resource-wide applies.
        'x-aauth-access-mode': 'session-token',
      },
    },
  },
}

const adapter = new OpenAPIAdapter()
const loaded = { raw: doc as never, ops: undefined as never }

function l1(accessMode: string): L1Entry {
  return {
    resource: 'res.example',
    origin: 'https://res.example',
    issuer: 'https://res.example',
    name: 'Test',
    description: '',
    access_mode: accessMode,
    picked_vocabs: [
      { vocabUri: 'urn:aauth:vocabulary:openapi', docUrl: 'https://res.example/openapi.json' },
    ],
    added: '2026-01-01T00:00:00.000Z',
  }
}

// The doc cache is injectable, so the adapter never has to fetch.
function cacheWith(): { get(k: string): Promise<unknown>; set(k: string, d: unknown): Promise<void> } {
  const parsed = { raw: doc, ops: undefined }
  return {
    async get() {
      // resource.ts re-indexes from `raw` when `ops` isn't a Map.
      return parsed
    },
    async set() {},
  }
}

describe('reading annotations', () => {
  it('reads the OpenAPI specification extensions', () => {
    expect(readOpenApiAnnotations({ 'x-aauth-access-mode': 'per-call', 'x-aauth-budget': true }))
      .toEqual({ access_mode: 'per-call', budget: true })
    expect(readOpenApiAnnotations({ operationId: 'plain' })).toEqual({})
  })

  it('reads the MCP tool _meta keys', () => {
    expect(
      readMcpToolAnnotations({
        _meta: { 'aauth.dev/access-mode': 'per-call', 'aauth.dev/budget': true },
      }),
    ).toEqual({ access_mode: 'per-call', budget: true })
    expect(readMcpToolAnnotations({ _meta: {} })).toEqual({})
    expect(readMcpToolAnnotations(undefined)).toEqual({})
  })

  it('drops session-token, which MUST NOT appear in an annotation', () => {
    expect(readOpenApiAnnotations({ 'x-aauth-access-mode': 'session-token' })).toEqual({})
  })

  it('surfaces annotations through the adapter', () => {
    const ops = adapter.listOperations(loaded)
    const purchase = ops.find((o) => o.opId === 'purchaseDataset')
    expect(purchase?.annotations).toEqual({ access_mode: 'per-call', budget: true })
    // Sparse: unannotated operations carry no annotations field at all.
    expect(ops.find((o) => o.opId === 'listDatasets')?.annotations).toBeUndefined()
    expect(adapter.annotationsFor(loaded, 'getBalance')).toEqual({ access_mode: 'person-token' })
    expect(adapter.annotationsFor(loaded, 'listDatasets')).toEqual({})
  })
})

describe('effectiveAccessMode', () => {
  it('takes the resource-wide mode when the operation is unannotated', () => {
    expect(effectiveAccessMode({}, 'auth-token')).toBe('auth-token')
    expect(effectiveAccessMode(undefined, undefined)).toBe('agent-token')
  })

  it('replaces rather than intersects — an annotation may LOWER the requirement', () => {
    expect(effectiveAccessMode({ access_mode: 'person-token' }, 'auth-token')).toBe('person-token')
  })

  it('raises a budgeted operation to auth-token', () => {
    expect(effectiveAccessMode({ budget: true }, 'agent-token')).toBe('auth-token')
    expect(effectiveAccessMode({ access_mode: 'person-token', budget: true }, 'agent-token')).toBe(
      'auth-token',
    )
    // per-call already outranks the budget implication.
    expect(effectiveAccessMode({ access_mode: 'per-call', budget: true }, 'agent-token')).toBe(
      'per-call',
    )
  })
})

describe('what the LLM sees', () => {
  it('flattens each operation to its effective access_mode and budget', async () => {
    const ops = await listOperationsForResource(l1('auth-token'), undefined, cacheWith())
    const byId = Object.fromEntries(ops.map((o) => [o.opId, o]))

    expect(byId.getBalance.access_mode).toBe('person-token') // annotation lowers it
    expect(byId.listDatasets.access_mode).toBe('auth-token') // sparse → resource-wide
    expect(byId.purchaseDataset.access_mode).toBe('per-call')
    expect(byId.purchaseDataset.budget).toBe(true)
    expect(byId.meterUsage.access_mode).toBe('auth-token') // budget implies auth-token
    expect(byId.misdeclared.access_mode).toBe('auth-token') // session-token dropped

    // The raw annotation object never reaches the LLM — only the resolved value.
    for (const op of ops) expect(op.annotations).toBeUndefined()
    expect(byId.listDatasets.budget).toBeUndefined()
  })

  it('carries the same fields on get_operation_schemas details', async () => {
    const details = await getOperationsForResource(
      l1('agent-token'),
      ['purchaseDataset'],
      cacheWith(),
    )
    expect(details[0].access_mode).toBe('per-call')
    expect(details[0].budget).toBe(true)
    expect(details[0].bodySchema).toBeUndefined()
  })
})
