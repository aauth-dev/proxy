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
//   aauth.request     — one per signed request the agent makes: to the PS
//                       (token endpoints, polls), the resource (authorization,
//                       the operation itself, connections), or the registry.
//                       credential (agent|person|auth|session), method, url
//                       (origin + path, query stripped), status, ok,
//                       requirement? (AAuth-Requirement on the response),
//                       error_code? (non-2xx: the body's `error` string, or
//                       `error.message` — the code only, never the body),
//                       duration_ms, error? (fetch threw)
//   resource.fetch    — the resource's /.well-known/aauth-resource.json.
//                       host, status?, ok, duration_ms, error?
//   person_token.hit  — a person token served from cache (no PS round trip).
//                       resource
//   invoke.resume     — invoke found an in-flight authorization for the host.
//                       resource, op_id, outcome (still_pending | settled |
//                       gone | abandoned), adopted? (settled: which of
//                       person_token / auth_token / session_token the pending
//                       delivered — names only), status? (gone), age_ms?
//                       (abandoned)
//
// Never carried: token values, request or response bodies, invoke's
// path_params / query / body, or the connect `account` value. Those are the
// person's data or credentials; the sink gets the shape of the call, not its
// content. The one thing lifted out of a failure body is its error CODE
// (`account_required`, `NO_SESSION`): without it a 400 from a resource is
// indistinguishable from any other 400 (prod, 2026-09-15), and a code is the
// shape of the failure, not the person's data. `detail` and the like stay
// out — they can echo what was submitted.

export type ProxyLogFields = Record<string, unknown>
export type ProxyLog = (event: string, fields: ProxyLogFields) => void

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
