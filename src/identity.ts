// praca's runtime identity port.
//
// An IdentityProvider resolves the PracaConfig (psUrl + agent private JWK +
// agent token) for the current principal. This module is transport- and
// platform-agnostic and MUST NOT import @aauth/local-keys (or any Node-only
// enclave dependency) — that keeps a workerd bundle of @aauth/praca's core
// enclave-free. The stdio server's provider lives in @aauth/praca/local
// (createLocalKeysIdentityProvider); other hosts (e.g. a multi-tenant server)
// supply their own.

import type { PracaConfig } from './agent.js'

export type BootstrapStatus =
  | { kind: 'ready'; cfg: PracaConfig }
  | { kind: 'needsBootstrap' }

export interface IdentityProvider {
  // `local` is a hint for the local-part of the agent id (`aauth:${local}@…`).
  // The stdio provider sources it from the MCP client's name; a provider is
  // free to ignore it and derive identity from its own context.
  resolve(ctx: { local?: string }): Promise<BootstrapStatus>
}
