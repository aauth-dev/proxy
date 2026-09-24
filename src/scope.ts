// How much access to ask for when the agent authorizes at a resource.
//
// The agent holds one auth token per (resource, account, mission) (tokens.ts).
// When it has none, or the one it has does not grant the operation it is about
// to call, it goes to the resource's authorization endpoint and declares
// operations in `r3_operations`. A ScopePolicy decides which.
//
// Whatever the policy returns, the agent also asks for what it needs: the
// operation being invoked and, when it is growing a held token or renewing one
// that lapsed while in use, every operation that token granted. A policy only
// ever ADDS. The default adds nothing: start with the one operation, grow on
// demand, and start over from one once the token has lapsed idle.
//
// The hook is here so the agent can be smarter later without touching the
// flow: every read operation on first use, or a set predicted from what this
// key held before (`lapsed`).

import type { L1Entry } from './store.js'
import type { TokenRecord } from './tokens.js'
import type { OpSummary } from './vocab/types.js'

export interface ScopeRequest {
  resource: L1Entry
  /** The vocabulary the operation is named in (`r3_operations.vocabulary`). */
  vocabulary: string
  /** The operation being invoked, and its entry in the vocabulary's shape. */
  opId: string
  operation: Record<string, string>
  /**
   * initial — no live token is held for this key, and none lapsed while in use.
   * grow    — the held token does not grant this operation.
   * refresh — the token this key held lapsed while in use (tokens.ts
   *           `wasInUse`); it is renewed with everything it granted.
   */
  reason: 'initial' | 'grow' | 'refresh'
  /** On `grow`: the live token being grown. */
  held?: TokenRecord
  /** On `initial` and `refresh`: the expired token this key last held, if the store still has it. */
  lapsed?: TokenRecord
  /** The resource's operations with their effective access modes. Fetched only when called. */
  operations(): Promise<OpSummary[]>
  /** The entry naming `opId` in this vocabulary. */
  entryFor(opId: string): Record<string, string>
}

/** Operations to declare beyond the ones the agent needs. May return the needed ones too; duplicates are removed. */
export type ScopePolicy = (req: ScopeRequest) => Array<Record<string, string>> | Promise<Array<Record<string, string>>>

/** The default: nothing beyond what the call needs. */
export const minimalScope: ScopePolicy = (req) => [req.operation]
