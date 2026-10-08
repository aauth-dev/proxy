// Multi-round-trip state (protocol revision 2026-07-28, MRTR-PLAN.md step 3).
//
// Every `input_required` the proxy returns carries a `requestState` minted
// with the host's codec (the SDK's createRequestStateCodec): URL rounds and
// keepalive rounds alike. The client echoes it on its retry. The flight store
// stays authoritative for what is in flight; the state only counts rounds, so
// the proxy stops before a client's round cap, and dates them for the logs.
//
// The codec signs, it does not encrypt: the client can read the payload. It
// holds hosts and interaction codes the client was already handed, nothing
// more.

import { inputResponse } from '@modelcontextprotocol/server'
import type { RequestStateCodec, ServerContext } from '@modelcontextprotocol/server'

export interface MrtrState {
  /** The tool that minted it. A state echoed on another tool is ignored. */
  tool: string
  /** The hosts the call was waiting on. */
  hosts: string[]
  /** The interaction codes whose URL this round handed over (none on a keepalive round). */
  codes: string[]
  /** 1 for the first `input_required` of a call, then one more per round. */
  round: number
  /** When round 1 was minted (ms since the epoch). */
  started_at: number
  /** When this round was minted. */
  at: number
}

export type MrtrCodec = RequestStateCodec<MrtrState>

// Claude Code's MCP client (and the TS SDK's) gives up after 10 rounds
// (`maxRounds`). Stop two short of it: the call answers in text instead.
export const MAX_MRTR_ROUNDS = 8

const isState = (v: unknown, tool: string): v is MrtrState => {
  if (!v || typeof v !== 'object') return false
  const s = v as Partial<MrtrState>
  return (
    s.tool === tool &&
    typeof s.round === 'number' &&
    typeof s.started_at === 'number' &&
    typeof s.at === 'number' &&
    Array.isArray(s.hosts) &&
    Array.isArray(s.codes)
  )
}

/**
 * The state this request echoed, verified. The host's
 * `ServerOptions.requestState.verify` has already run and the accessor holds
 * the decoded payload. A host that left verify unset hands over the raw
 * string: it is verified here, and a string that fails is treated as absent
 * (nothing it holds decides anything the flight store does not).
 */
export async function readState(ctx: ServerContext, codec: MrtrCodec | undefined, tool: string): Promise<MrtrState | undefined> {
  const raw = ctx.mcpReq.requestState<unknown>()
  if (raw === undefined) return undefined
  if (typeof raw === 'string') {
    if (!codec) return undefined
    const decoded = await codec.verify(raw, ctx).catch(() => undefined)
    return isState(decoded, tool) ? decoded : undefined
  }
  return isState(raw, tool) ? raw : undefined
}

/** `inputResponses` as key → action (`accept`, `decline`, `cancel`), or the response kind when it is not an elicitation. */
export function inputResponseActions(ctx: ServerContext): Record<string, string> | undefined {
  const responses = ctx.mcpReq.inputResponses
  if (!responses) return undefined
  const out: Record<string, string> = {}
  for (const key of Object.keys(responses)) {
    const view = inputResponse(responses, key)
    out[key] = view.kind === 'elicit' ? view.action : view.kind
  }
  return Object.keys(out).length ? out : undefined
}

/**
 * What the person did with the URL handed over under `key`: `decline` or
 * `cancel` ends the wait. An entry the SDK dropped as malformed
 * (`droppedInputResponseKeys`) counts as `accept`: the person may well have
 * opened it, and the flight answers for itself.
 */
export function urlAction(ctx: ServerContext, key: string): 'accept' | 'decline' | 'cancel' | undefined {
  if (ctx.mcpReq.droppedInputResponseKeys?.includes(key)) return 'accept'
  const view = inputResponse(ctx.mcpReq.inputResponses, key)
  return view.kind === 'elicit' ? view.action : undefined
}
