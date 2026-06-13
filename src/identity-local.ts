// @aauth/praca/local — the Node-only identity adapter for the stdio server.
//
// This is the only place @aauth/local-keys is imported, so the package's core
// entry point stays enclave-free (and bundleable for workerd). Two sources:
//  - env: a software agent token + key (PRACA_AGENT_PRIVATE_JWK / *_KEY_FILE) —
//    tests and simple software-only use.
//  - @aauth/local-keys: the real path — the bootstrapped AP key (Secure Enclave
//    / YubiKey) mints the agent token, binding a fresh software ephemeral key.
//    That ephemeral key (returned as `signingKey`) signs HTTP requests, so
//    praca's request-signing path is unchanged; only token minting differs.

import { readFileSync } from 'node:fs'
import { createAgentToken, getAgentConfig, listAgentProviders } from '@aauth/local-keys'
import type { AgentSigningKey, PracaConfig } from './agent.js'
import type { IdentityProvider } from './identity.js'

function required(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`praca: missing required env var ${name}`)
  return value
}

export function loadIdentity(): PracaConfig {
  const psUrl = required('PRACA_PS_URL')
  const agentToken = required('PRACA_AGENT_TOKEN')

  const jwkJson =
    process.env.PRACA_AGENT_PRIVATE_JWK ??
    readFileSync(process.env.PRACA_AGENT_KEY_FILE ?? '.secrets/praca-agent-key.json', 'utf8')

  return { psUrl, agentToken, agentPrivateJwk: JSON.parse(jwkJson) }
}

export async function buildConfigFromLocalKeys(
  opts: { agentUrl?: string; psUrl?: string; local?: string } = {},
): Promise<PracaConfig> {
  const agentUrl = opts.agentUrl ?? process.env.PRACA_AGENT_URL ?? listAgentProviders()[0]
  if (!agentUrl) {
    throw new Error('praca: no agent configured (run @aauth/bootstrap) and no PRACA_AGENT_URL set')
  }

  const psUrl = opts.psUrl ?? process.env.PRACA_PS_URL ?? getAgentConfig(agentUrl)?.personServerUrl
  if (!psUrl) throw new Error(`praca: no Person Server configured for ${agentUrl}; set PRACA_PS_URL`)

  // The AP key (enclave/yubikey) signs the agent token, binding a fresh software
  // ephemeral key returned as signingKey.
  const { signingKey, signatureKey } = await createAgentToken({ agentUrl, local: opts.local })

  return {
    psUrl,
    agentPrivateJwk: signingKey as unknown as AgentSigningKey,
    agentToken: signatureKey.jwt,
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
  let cached: PracaConfig | null = null
  return {
    async resolve({ local }) {
      if (cached) return { kind: 'ready', cfg: cached }
      if (process.env.PRACA_AGENT_PRIVATE_JWK) {
        cached = loadIdentity()
        return { kind: 'ready', cfg: cached }
      }
      const agentUrl = process.env.PRACA_AGENT_URL ?? listAgentProviders()[0]
      if (!agentUrl) return { kind: 'needsBootstrap' }
      cached = await buildConfigFromLocalKeys({ local })
      return { kind: 'ready', cfg: cached }
    },
  }
}
