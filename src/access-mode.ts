// access_mode planning.
//
// `access_mode` is an IANA registry (protocol §Resource Metadata, §AAuth Access
// Mode Value Registry), not a closed list: -11 defines four values, R3 -02 adds
// `per-call`, and extensions may add more. Three outcomes, and only three:
//
//   undeclared    — absent, or a value this agent does not recognize. Call the
//                   resource and read the AAuth-Requirement it returns. NEVER an
//                   error: the declaration is advisory, the runtime requirement
//                   is authoritative.
//   satisfiable   — recognized, and this agent's setup can complete it. Plan
//                   against it and skip the speculative call.
//   unsatisfiable — recognized, and this agent cannot complete it. Skip the
//                   resource (or operation) and say why. An agent whose agent
//                   token carries no `ps` claim cannot obtain a person token,
//                   and so cannot complete person-token, auth-token or per-call
//                   access — it should learn that here, not at a 401.
//
// Mirrors the `@aauth/protocol` surface named in the AAuth -11 package contract
// (planAccessMode / AgentSetup / AccessModePlan / KnownAccessMode). Kept local
// while @aauth/protocol is unpublished; swap the implementation for an import
// when it ships — the types are identical by construction.

export type KnownAccessMode =
  | 'agent-token'
  | 'person-token'
  | 'session-token'
  | 'auth-token'
  | 'per-call'

export const KNOWN_ACCESS_MODES: readonly KnownAccessMode[] = [
  'agent-token',
  'person-token',
  'session-token',
  'auth-token',
  'per-call',
]

export function isKnownAccessMode(v: string | undefined): v is KnownAccessMode {
  return v !== undefined && (KNOWN_ACCESS_MODES as readonly string[]).includes(v)
}

export interface AgentSetup {
  /** false when the agent token carries no `ps` claim. */
  hasPersonServer: boolean
}

export type AccessModePlan =
  | { kind: 'undeclared' }
  | { kind: 'satisfiable'; mode: KnownAccessMode }
  | { kind: 'unsatisfiable'; mode: KnownAccessMode; reason: string }

const NO_PS =
  'this agent token carries no `ps` claim, so the agent has no person server to obtain a person token from'

export function planAccessMode(declared: string | undefined, setup: AgentSetup): AccessModePlan {
  if (!isKnownAccessMode(declared)) return { kind: 'undeclared' }

  switch (declared) {
    // Identity only: every request already carries an agent token.
    case 'agent-token':
      return { kind: 'satisfiable', mode: declared }

    // Resource-managed: the resource runs its own consent flow and hands back a
    // session token via AAuth-Access. No PS involved.
    case 'session-token':
      return { kind: 'satisfiable', mode: declared }

    // All three need a person token, which only a person server issues. A
    // resource MUST have verified a person token before it issues a resource
    // token, so auth-token and per-call are unreachable without one too.
    case 'person-token':
    case 'auth-token':
    case 'per-call':
      return setup.hasPersonServer
        ? { kind: 'satisfiable', mode: declared }
        : {
            kind: 'unsatisfiable',
            mode: declared,
            reason: `access_mode "${declared}" requires a person token, and ${NO_PS}`,
          }
  }
}

/** One-line reason string for a plan, for surfacing to the LLM. */
export function planReason(plan: AccessModePlan): string | undefined {
  return plan.kind === 'unsatisfiable' ? plan.reason : undefined
}
