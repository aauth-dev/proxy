// Unverified JWT decoding + RFC 7638 JWK thumbprints.
//
// Decoding only — nothing here verifies a signature. The agent proxy reads its
// own agent token to learn whether it has a `ps` claim (which decides whether
// the person-token / auth-token flows are reachable at all) and reads `exp` off
// tokens it holds. Verification is the recipient's job.
//
// Platform-neutral: base64url by hand and WebCrypto for SHA-256, so the core
// stays workerd-safe (no node:crypto, no Buffer).

export function decodeJwtHeader(jwt: string): Record<string, unknown> {
  return decodeSegment(jwt, 0)
}

export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  return decodeSegment(jwt, 1)
}

function decodeSegment(jwt: string, index: number): Record<string, unknown> {
  const seg = jwt.split('.')[index]
  if (!seg) throw new Error('malformed JWT')
  const b64 = seg.replace(/-/g, '+').replace(/_/g, '/')
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4)
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
}

/** The `ps` claim on an agent token. Absent → the agent has no person server and
 *  cannot obtain a person token, and so cannot complete `person-token`,
 *  `auth-token` or `per-call` access. Malformed tokens read as no PS. */
export function agentTokenPs(agentToken: string): string | undefined {
  try {
    const ps = decodeJwtPayload(agentToken).ps
    return typeof ps === 'string' && ps ? ps : undefined
  } catch {
    return undefined
  }
}

/** Seconds-since-epoch `exp`, or undefined when absent/unparseable. */
export function jwtExp(jwt: string): number | undefined {
  try {
    const exp = decodeJwtPayload(jwt).exp
    return typeof exp === 'number' ? exp : undefined
  } catch {
    return undefined
  }
}

interface ThumbprintableJwk {
  kty?: string
  crv?: string
  x?: string
  y?: string
  n?: string
  e?: string
}

function base64url(bytes: ArrayBuffer): string {
  let s = ''
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * RFC 7638 JWK thumbprint (SHA-256, base64url). Used as the cache key discriminator
 * for person tokens: every person token binds the agent's key through `cnf`, so a
 * change in this value invalidates all of them at once (protocol §Person Token
 * Endpoint).
 */
export async function jwkThumbprint(jwk: ThumbprintableJwk): Promise<string> {
  let canonical: string
  switch (jwk.kty) {
    case 'OKP':
      canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })
      break
    case 'EC':
      canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
      break
    case 'RSA':
      canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })
      break
    default:
      throw new Error(`jwkThumbprint: unsupported kty ${jwk.kty}`)
  }
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return base64url(digest)
}

/**
 * The fully-specified `alg` a JWK's key material implies (RFC 9864).
 * Undefined for key types this library has no mapping for — those are left to
 * whatever `alg` the JWK already carries.
 */
function impliedAlg(jwk: { kty?: string; crv?: string }): string | undefined {
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'Ed25519'
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed448') return 'Ed448'
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') return 'ES256'
  if (jwk.kty === 'EC' && jwk.crv === 'P-384') return 'ES384'
  if (jwk.kty === 'EC' && jwk.crv === 'P-521') return 'ES512'
  return undefined
}

/**
 * Check the agent's signing key before anything signs with it.
 *
 * `@hellocoop/httpsig` 2.x takes the algorithm from the JWK's `alg` and
 * rejects the polymorphic `EdDSA` (RFC 9864). A key that reaches it without a
 * fully-specified `alg` fails deep inside a signed call, as
 * `Polymorphic algorithm identifier "EdDSA" is not permitted` on whatever
 * request happened to be first — a message that names neither the key nor the
 * thing that produced it.
 *
 * The key comes from an `IdentityProvider`, and there are several: the
 * filesystem/enclave one here, the Durable-Object-backed one in the hosted
 * MCP, and whatever a host writes next. They drift. The bundled provider
 * normalizes (`withFullySpecifiedAlg`); the hosted one did not, and every
 * signed call through mcp.aauth.dev failed until it was fixed on its own read
 * path (aauth-mcp #7). One provider getting it right is not a property of this
 * library — checking here is.
 *
 * This REFUSES rather than normalizing, deliberately. Normalizing would hide
 * the provider's bug, and it would only hide half of it: the same raw JWK
 * usually goes into the agent token's `cnf.jwk`, which the verifier extracts,
 * so a silently-fixed signing key buys a signature that verifies against a key
 * the other end rejects. Better to fail at the source, naming it.
 */
export function assertAgentSigningKey(key: unknown): void {
  const jwk = key as { kty?: string; crv?: string; alg?: string } | null | undefined
  if (!jwk || typeof jwk !== 'object') {
    throw new Error('agentPrivateJwk is missing — the identity provider returned no signing key')
  }
  const implied = impliedAlg(jwk)
  if (jwk.alg === undefined) {
    throw new Error(
      `agentPrivateJwk has no "alg" (kty=${String(jwk.kty)} crv=${String(jwk.crv)}). ` +
        `RFC 9864 requires a fully-specified algorithm${implied ? `; this key's material implies "${implied}"` : ''}. ` +
        `Fix the identity provider that produced it.`,
    )
  }
  if (jwk.alg === 'EdDSA') {
    throw new Error(
      `agentPrivateJwk has the polymorphic alg "EdDSA", which RFC 9864 forbids` +
        `${implied ? ` — use "${implied}"` : ''}. ` +
        `workerd's crypto.subtle.exportKey produces this; the identity provider must normalize it.`,
    )
  }
  if (implied && jwk.alg !== implied) {
    throw new Error(
      `agentPrivateJwk says alg "${jwk.alg}" but its key material (kty=${String(jwk.kty)} crv=${String(jwk.crv)}) is "${implied}".`,
    )
  }
}
