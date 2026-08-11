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
