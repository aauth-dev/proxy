// Load praca's runtime identity + config.
//
// Two sources:
//  - loadIdentity(): a software agent token + key from env (tests / simple use).
//  - buildConfigFromLocalKeys(): the real path — @aauth/local-keys mints the
//    agent token using the bootstrapped AP key (Secure Enclave / YubiKey), which
//    signs the token binding a fresh *software* ephemeral key. That ephemeral
//    key (returned as `signingKey`) is what signs HTTP requests — so praca's
//    request-signing path is unchanged; only token minting differs.

import { readFileSync } from 'node:fs'
import { createAgentToken, getAgentConfig, listAgentProviders } from '@aauth/local-keys'
import type { PracaConfig, AgentSigningKey } from './agent.js'

function required(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`praca: missing required env var ${name}`)
  return value
}

export function loadIdentity(): PracaConfig {
  const psUrl = required('PRACA_PS_URL')
  const agentToken = required('PRACA_AGENT_TOKEN')

  const jwkJson = process.env.PRACA_AGENT_PRIVATE_JWK
    ?? readFileSync(process.env.PRACA_AGENT_KEY_FILE ?? '.secrets/praca-agent-key.json', 'utf8')

  return { psUrl, agentToken, agentPrivateJwk: JSON.parse(jwkJson) }
}

export type BootstrapStatus =
  | { kind: 'ready'; cfg: PracaConfig }
  | { kind: 'needsBootstrap' }

// Non-throwing entry point for the MCP server: returns `needsBootstrap` when
// no agent provider is configured (instead of throwing at startup) so praca
// can stay up and surface bootstrap guidance to the agent.
//
// `local` becomes the local-part of the agent id (`aauth:${local}@${domain}`).
// Sourced from the MCP client's declared `clientInfo.name` so each host on the
// user's machine gets a distinct identifier. Unsigned — fine here because the
// AP key already gates everything and the user chose what to claim.
export async function loadBootstrapStatus(local?: string): Promise<BootstrapStatus> {
  if (process.env.PRACA_AGENT_PRIVATE_JWK) {
    return { kind: 'ready', cfg: loadIdentity() }
  }
  const agentUrl = process.env.PRACA_AGENT_URL ?? listAgentProviders()[0]
  if (!agentUrl) return { kind: 'needsBootstrap' }
  return { kind: 'ready', cfg: await buildConfigFromLocalKeys({ local }) }
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
