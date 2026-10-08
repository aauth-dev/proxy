// Structured events from inside the proxy, for the host to record.
//
// The proxy is the AAuth side of an MCP tool call: it is what fetches resource
// metadata, obtains person and auth tokens from the Person Server, and signs
// the request to the resource. An MCP host can log the JSON-RPC boundary on its
// own, but nothing outside this package can see the AAuth exchange — so the
// proxy reports it through one optional sink and the host logs both sides.
//
// Events (fields are flat; a host maps them onto its own log shape):
//
//   tool.call         — one per MCP tool invocation the proxy handles.
//                       tool, resource?, op_id?, account? (boolean), items?
//                       (count, connect_resources), resources? (their hosts),
//                       ok, error?, duration_ms
//   aauth.call        — one per signed request the agent makes: to the PS
//                       (token endpoints, polls), the resource (authorization,
//                       the operation itself, connections), or the registry.
//                       The @aauth/call-log record (aauth-dev/monitor
//                       plan/CALL_RECORD.md), whole: side 'caller', call_id
//                       (SHA-256 of the Signature header — the callee's own
//                       record carries the same one), from (the agent), to,
//                       to_role, agent, method, path, query, status,
//                       started_at, duration_ms, signed, request/response
//                       bodies up to 8 KB, response.params (AAuth-Requirement,
//                       Signature-Error, AAuth-Budget parsed), error, level,
//                       msg. Hosts forward it with its fields top-level.
//   resource.fetch    — the resource's /.well-known/aauth-resource.json.
//                       host, status?, ok, duration_ms, error?
//   token.hit         — a held token presented instead of obtaining one (no
//                       PS round trip). kind (person | auth), resource, jti?
//   token.put         — a token kept as the one held for its key, replacing
//                       what the key held. kind, resource?, account? (boolean),
//                       mission? (boolean), reason (initial | grow | refresh |
//                       step-up | settled), jti?, expires_in?, operations?
//                       (the identifiers it grants), budget? (amount)
//   token.drop        — a held token let go. kind, resource?, reason
//                       (refused | replaced | exhausted | resource_deleted |
//                       key_rotated),
//                       jti?, flushed? (the whole
//                       store, on a key rotation)
//   token.refresh_failed — refreshing a held person token failed; the held
//                       token is presented until it expires. kind, resource,
//                       outcome (result | interaction | pending), status?
//   scope.policy_error — the ScopePolicy threw; the call asked for only what it
//                       needs. resource, error
//   invoke.resume     — invoke found an in-flight authorization for the host.
//                       resource, op_id, outcome (still_pending | settled |
//                       gone | abandoned), adopted? (settled: which of
//                       person_token / auth_token / session_token the pending
//                       delivered — names only), status? (gone), age_ms?
//                       (abandoned)
//
// The waits around an authorization (5.8.0, MRTR-PLAN.md). `hosts` are the
// resource hosts the call waits on; `round` is the multi-round-trip round
// (0 before the first `input_required`).
//
//   mrtr.input_required — an `input_required` result goes back. tool, kind
//                       (url | keepalive), round, hosts, codes, ms_since_round_1
//   mrtr.retry        — a request echoes the proxy's requestState. tool,
//                       round (the echoed one), ms_since_previous,
//                       input_responses? (key → accept | decline | cancel)
//   legacy.url_error  — the URL goes to a 2025-era client as -32042. tool,
//                       hosts, code, caps_source (initialize)
//   legacy.followup   — a later call resumes a flight whose URL went out as
//                       -32042. tool, hosts, ms_since_url_error, same_tool
//   hold.start        — a call starts holding on the person. tool, hosts,
//                       progress_token (boolean)
//   hold.end          — tool, hosts, slices (polls), progress_sent, outcome
//                       (invoke: settled | gone | url | timed_out | aborted;
//                       connect_resources: finished | url | deadline |
//                       aborted), duration_ms
//   call.aborted      — the request's abort signal fired during a hold or a
//                       poll: the client stopped listening. tool, hosts,
//                       ms_since_start, progress_sent, last_progress_ms_ago?
//   connect.declined / invoke.declined — the person declined or cancelled
//                       the URL; the wait ends. tool, hosts, action, round
//
// `aauth.call` carries the call's content: bodies up to 8 KB and the query
// (Dick, 2026-09-28: the call log sends bodies if small). A token in it is
// `{ type, payload }` — the claims, never the JWT — and the opaque session
// token rides only in the AAuth-Access and Authorization headers, which no
// record carries. So no event holds a presentable credential.
//
// Every other event carries the shape of a call, not its content: never
// token values, bodies, invoke's path_params / query / body, or the connect
// `account` value. The one thing lifted out of a failure body is its error
// CODE (`account_required`, `NO_SESSION`): without it a 400 from a resource
// is indistinguishable from any other 400 (prod, 2026-09-15). `detail` and
// the like stay out — they can echo what was submitted.

import { loggedHttpsigFetch, type CallLogHost, type HttpsigFetchLike } from '@aauth/call-log'
import { decodeJwtPayload } from './jwt.js'

export type ProxyLogFields = Record<string, unknown>
export type ProxyLog = (event: string, fields: ProxyLogFields) => void

const originOf = (url: string): string | undefined => {
  try {
    return new URL(url).origin
  } catch {
    return undefined
  }
}

/**
 * A signed fetch for a request to `url` that writes its `aauth.call` record
 * to the sink. Without a sink it is `signedFetch` itself. `to_role` is `ps`
 * for the Person Server's origin and `resource` otherwise: the agent calls
 * nothing else (the registry is a resource).
 */
export function callLogged<F>(
  signedFetch: F,
  cfg: { log?: ProxyLog; waitUntil?: (p: Promise<unknown>) => void; agentToken: string; psUrl: string },
  url: string,
): F {
  const log = cfg.log
  if (!log) return signedFetch
  let agent: string | undefined
  try {
    const sub = decodeJwtPayload(cfg.agentToken).sub
    if (typeof sub === 'string') agent = sub
  } catch {
    /* an unreadable agent token names no agent */
  }
  const host: CallLogHost = {
    origin: agent ?? 'agent',
    role: 'agent',
    log: (record) => log('aauth.call', record as unknown as ProxyLogFields),
    defer: cfg.waitUntil,
  }
  const to_role = originOf(url) !== undefined && originOf(url) === originOf(cfg.psUrl) ? 'ps' : 'resource'
  return loggedHttpsigFetch(signedFetch as unknown as HttpsigFetchLike, host, { to_role, agent }) as unknown as F
}

/** origin + pathname only — a query string can carry the person's data. */
export function logUrl(url: string): string {
  try {
    const u = new URL(url)
    return `${u.origin}${u.pathname}`
  } catch {
    return url.split('?')[0]
  }
}

/**
 * The error code of a failure body, and nothing else: a string `error`
 * (`{"error":"account_required",…}` — resources, OAuth-style) or
 * `error.message` (`{"error":{"message":"NO_SESSION"}}` — the wallet). Reads
 * a clone so the caller's own body read is untouched; anything unparseable
 * or unshaped is simply absent.
 */
async function errorCodeOf(res: Response): Promise<string | undefined> {
  try {
    const body = (await res.clone().json()) as unknown
    if (!body || typeof body !== 'object') return undefined
    const err = (body as { error?: unknown }).error
    if (typeof err === 'string') return err.slice(0, 64)
    if (err && typeof err === 'object' && typeof (err as { message?: unknown }).message === 'string') {
      return ((err as { message: string }).message).slice(0, 64)
    }
    return undefined
  } catch {
    return undefined
  }
}

/** Run a fetch-like call, then report it as `event` with status and timing. */
export async function loggedFetch(
  log: ProxyLog | undefined,
  event: string,
  fields: ProxyLogFields,
  run: () => Promise<Response>,
): Promise<Response> {
  if (!log) return run()
  const started = Date.now()
  try {
    const res = await run()
    const requirement = /requirement=([A-Za-z0-9_-]+)/.exec(res.headers.get('aauth-requirement') ?? '')?.[1]
    const errorCode = res.ok ? undefined : await errorCodeOf(res)
    log(event, {
      ...fields,
      status: res.status,
      ok: res.ok,
      ...(requirement ? { requirement } : {}),
      ...(errorCode ? { error_code: errorCode } : {}),
      duration_ms: Date.now() - started,
    })
    return res
  } catch (e) {
    log(event, { ...fields, ok: false, error: (e as Error)?.message ?? String(e), duration_ms: Date.now() - started })
    throw e
  }
}

/**
 * The loggable shape of a tool's arguments: identifiers, never values. `account`
 * and `query` are reduced to presence; invoke's body/path_params/query are not
 * looked at.
 */
export function toolFields(tool: string, args: unknown): ProxyLogFields {
  const a = (args && typeof args === 'object' ? args : {}) as Record<string, unknown>
  const f: ProxyLogFields = { tool }
  if (typeof a.resource === 'string') f.resource = a.resource
  if (typeof a.op_id === 'string') f.op_id = a.op_id
  if (a.account !== undefined) f.account = true
  if (typeof a.query === 'string') f.query = true
  if (Array.isArray(a.items)) {
    f.items = a.items.length
    f.resources = a.items
      .map((i) => (i && typeof i === 'object' ? (i as { resource?: unknown }).resource : undefined))
      .filter((r): r is string => typeof r === 'string')
  }
  return f
}
