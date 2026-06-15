// @aauth/proxy/local — the Node-only identity adapter for the stdio server.
//
// This is the only place @aauth/local-keys is imported, so the package's core
// entry point stays enclave-free (and bundleable for workerd). Two sources:
//  - env: a software agent token + key (PROXY_AGENT_PRIVATE_JWK / *_KEY_FILE) —
//    tests and simple software-only use.
//  - @aauth/local-keys: the real path — the bootstrapped AP key (Secure Enclave
//    / YubiKey) mints the agent token, binding a fresh software ephemeral key.
//    That ephemeral key (returned as `signingKey`) signs HTTP requests, so
//    the agent proxy's request-signing path is unchanged; only token minting differs.

import { readFileSync } from 'node:fs'
import { createAgentToken, getAgentConfig, listAgentProviders } from '@aauth/local-keys'
import type { AgentSigningKey, ProxyConfig } from './agent.js'
import type { IdentityProvider } from './identity.js'

function required(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`agent proxy: missing required env var ${name}`)
  return value
}

export function loadIdentity(): ProxyConfig {
  const psUrl = required('PROXY_PS_URL')
  const agentToken = required('PROXY_AGENT_TOKEN')

  const jwkJson =
    process.env.PROXY_AGENT_PRIVATE_JWK ??
    readFileSync(process.env.PROXY_AGENT_KEY_FILE ?? '.secrets/proxy-agent-key.json', 'utf8')

  return { psUrl, agentToken, agentPrivateJwk: JSON.parse(jwkJson) }
}

export async function buildConfigFromLocalKeys(
  opts: { agentUrl?: string; psUrl?: string; local?: string } = {},
): Promise<ProxyConfig> {
  const agentUrl = opts.agentUrl ?? process.env.PROXY_AGENT_URL ?? listAgentProviders()[0]
  if (!agentUrl) {
    throw new Error('agent proxy: no agent configured (run @aauth/bootstrap) and no PROXY_AGENT_URL set')
  }

  const psUrl = opts.psUrl ?? process.env.PROXY_PS_URL ?? getAgentConfig(agentUrl)?.personServerUrl
  if (!psUrl) throw new Error(`agent proxy: no Person Server configured for ${agentUrl}; set PROXY_PS_URL`)

  // The AP key (enclave/yubikey) signs the agent token, binding a fresh software
  // ephemeral key returned as signingKey.
  const { signingKey, signatureKey } = await createAgentToken({ agentUrl, local: opts.local })

  return {
    psUrl,
    agentPrivateJwk: signingKey as unknown as AgentSigningKey,
    agentToken: signatureKey.jwt,
  }
}

// Returns true if the JWT's exp claim is within bufferSecs of now (or missing).
function isJwtExpired(jwt: string, bufferSecs = 60): boolean {
  try {
    const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'))
    return typeof payload.exp === 'number' && payload.exp - bufferSecs < Date.now() / 1000
  } catch {
    return false
  }
}

// The stdio server's IdentityProvider. Resolves lazily and caches the result
// so the enclave signs the agent token at most once per session (the env path
// is likewise resolved once). When no agent provider is configured it returns
// `needsBootstrap` without caching, so a mid-session bootstrap is picked up on
// the next call without a restart.
//
// `local` becomes the local-part of the agent id (`aauth:${local}@${domain}`),
// sourced by the caller from the MCP client's declared name so each host on the
// user's machine gets a distinct identifier.
export function createLocalKeysIdentityProvider(): IdentityProvider {
  let cached: ProxyConfig | null = null
  return {
    async resolve({ local }) {
      if (cached) {
        // Static env-var token can't be re-minted — return as-is.
        if (process.env.PROXY_AGENT_PRIVATE_JWK) return { kind: 'ready', cfg: cached }
        // AP-key path: re-mint if the token is close to expiry.
        if (!isJwtExpired(cached.agentToken)) return { kind: 'ready', cfg: cached }
        cached = null
      }
      if (process.env.PROXY_AGENT_PRIVATE_JWK) {
        cached = loadIdentity()
        return { kind: 'ready', cfg: cached }
      }
      const agentUrl = process.env.PROXY_AGENT_URL ?? listAgentProviders()[0]
      if (!agentUrl) return { kind: 'needsBootstrap' }
      cached = await buildConfigFromLocalKeys({ local })
      return { kind: 'ready', cfg: cached }
    },
  }
}
