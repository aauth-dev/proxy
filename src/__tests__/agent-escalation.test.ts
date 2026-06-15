// Unit tests for the per-call auth-token escalation path in invokeAtResource.
// Covers the case where a resource in agent-token mode returns a 401 with an
// AAuth-Requirement header, triggering an exchange at the PS and a retry.

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

const l1: L1Entry = {
  resource: 'res.example',
  origin: 'https://res.example',
  issuer: 'https://res.example',
  name: 'Test Resource',
  description: 'Test',
  access_mode: 'agent-token',
  picked_vocabs: [{ vocabUri: 'urn:aauth:vocabulary:openapi', docUrl: 'https://res.example/openapi.json' }],
  added: '2026-01-01T00:00:00.000Z',
}

const cfg: ProxyConfig = {
  psUrl: 'https://ps.example',
  agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA', d: 'BBBB' } as never,
  agentToken: 'agent.jwt.here',
}

beforeEach(() => {
  vi.resetAllMocks()
  mockRouteOperation.mockResolvedValue({
    adapter: { vocabUri: 'urn:aauth:vocabulary:openapi' },
    plan: { kind: 'sync.request', method: 'GET', path: '/whoami', query: 'scope=profile' },
  })
})

describe('agent-token per-call escalation', () => {
  it('retries with auth token when resource issues a 401 auth-token challenge', async () => {
    // global fetch — PS well-known
    const globalFetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      makeResponse(200, { token_endpoint: 'https://ps.example/token' }),
    )

    // signedFetch call sequence:
    // 1. resource call → 401 challenge
    // 2. PS token exchange → auth token
    // 3. resource retry with auth token → 200
    mockSignedFetch
      .mockResolvedValueOnce(
        makeResponse(401, { error: 'auth_token_required' }, {
          'aauth-requirement': 'requirement=auth-token; resource-token="rt_abc123"',
        }),
      )
      .mockResolvedValueOnce(makeResponse(200, { auth_token: 'auth_tok_xyz' }))
      .mockResolvedValueOnce(makeResponse(200, { sub: 'user@example.com', name: 'Alice' }))

    const result = await invokeAtResource(cfg, l1, 'whoami', { query: 'scope=profile' })

    expect(result).toEqual({ kind: 'result', status: 200, body: { sub: 'user@example.com', name: 'Alice' } })

    // PS well-known was fetched
    expect(globalFetchSpy).toHaveBeenCalledWith('https://ps.example/.well-known/aauth-person.json')

    // PS token exchange carried the resource token
    const [psUrl, psInit] = mockSignedFetch.mock.calls[1]
    expect(psUrl).toBe('https://ps.example/token')
    const psBody = JSON.parse(psInit.body)
    expect(psBody.resource_token).toBe('rt_abc123')
    expect(psBody.capabilities).toContain('interaction')
  })

  it('surfaces an interaction when PS returns 202 during escalation', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      makeResponse(200, { token_endpoint: 'https://ps.example/token' }),
    )

    mockSignedFetch
      .mockResolvedValueOnce(
        makeResponse(401, { error: 'auth_token_required' }, {
          'aauth-requirement': 'requirement=auth-token; resource-token="rt_def456"',
        }),
      )
      .mockResolvedValueOnce(
        makeResponse(202, {}, {
          'aauth-requirement': 'requirement=interaction; url="https://ps.example/interact"; code="code_xyz"',
          location: 'https://ps.example/pending/abc',
        }),
      )

    const result = await invokeAtResource(cfg, l1, 'whoami', { query: 'scope=profile' })

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

    const result = await invokeAtResource(cfg, l1, 'whoami')

    expect(result).toEqual({ kind: 'result', status: 401, body: { error: 'unauthorized' } })
    // No PS call
    expect(mockSignedFetch).toHaveBeenCalledTimes(1)
  })
})
