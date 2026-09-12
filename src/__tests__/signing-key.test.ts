// The agent's signing key is checked before anything signs with it.
//
// It comes from an IdentityProvider, and there are several — the
// filesystem/enclave one here, the Durable-Object-backed one in the hosted
// MCP, and whatever a host writes next. The bundled one normalizes the alg;
// the hosted one did not, and every signed call through mcp.aauth.dev failed
// with `Polymorphic algorithm identifier "EdDSA" is not permitted` until it
// was fixed on its own read path. One provider getting it right is not a
// property of this library.

import { describe, it, expect, vi } from 'vitest'
import { assertAgentSigningKey } from '../jwt'
import { makeAgentPoll } from '../agent'
import type { AgentSigningKey, ProxyConfig } from '../agent'

const ED25519 = { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', d: 'BBBB' }

describe('assertAgentSigningKey', () => {
  it('accepts a fully-specified key', () => {
    expect(() => assertAgentSigningKey(ED25519)).not.toThrow()
    expect(() => assertAgentSigningKey({ kty: 'EC', crv: 'P-256', alg: 'ES256' })).not.toThrow()
  })

  it('refuses the polymorphic EdDSA, and names what produces it', () => {
    expect(() => assertAgentSigningKey({ ...ED25519, alg: 'EdDSA' })).toThrow(/polymorphic/i)
    // The message has to be actionable: which alg to use, and where the bad
    // one comes from. The failure it replaces named neither.
    expect(() => assertAgentSigningKey({ ...ED25519, alg: 'EdDSA' })).toThrow(/"Ed25519"/)
    expect(() => assertAgentSigningKey({ ...ED25519, alg: 'EdDSA' })).toThrow(/workerd/)
  })

  it('refuses a key with no alg at all', () => {
    const { alg: _alg, ...noAlg } = ED25519
    expect(() => assertAgentSigningKey(noAlg)).toThrow(/no "alg"/)
    expect(() => assertAgentSigningKey(noAlg)).toThrow(/Ed25519/)
  })

  it('refuses an alg that contradicts the key material', () => {
    expect(() => assertAgentSigningKey({ ...ED25519, alg: 'ES256' })).toThrow(/key material/)
  })

  it('refuses a missing key rather than signing with undefined', () => {
    expect(() => assertAgentSigningKey(undefined)).toThrow(/missing/)
    expect(() => assertAgentSigningKey(null)).toThrow(/missing/)
  })

  it('leaves an unmapped key type to its own declared alg', () => {
    // No implied alg for RSA here; a declared one is not second-guessed.
    expect(() => assertAgentSigningKey({ kty: 'RSA', alg: 'PS256' })).not.toThrow()
  })
})

// The unit tests above prove the check; this proves it is WIRED. Without a
// call site the guard is decoration, and nothing else in the suite would
// notice it had been removed.
describe('the guard is on the signing path', () => {
  const cfgWith = (alg: string): ProxyConfig => ({
    psUrl: 'https://ps.test',
    agentToken: 'x.y.z',
    agentPrivateJwk: { kty: 'OKP', crv: 'Ed25519', alg, x: 'AAAA', d: 'BBBB' } as unknown as AgentSigningKey,
  })

  it('refuses before any request leaves', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    try {
      // Matched on THIS guard's wording, not on /polymorphic/. httpsig rejects
      // the same key with its own "Polymorphic algorithm identifier" message,
      // so a looser match passes with the guard removed — which is exactly
      // what a mutation run showed.
      await expect(
        makeAgentPoll(cfgWith('EdDSA'))('https://ps.test/aauth/pending/X'),
      ).rejects.toThrow(/identity provider must normalize/)
      // The point of failing at the source: nothing was sent.
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      vi.unstubAllGlobals()
    }
  })
})
