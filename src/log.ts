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
//                       duration_ms, error? (fetch threw)
//   resource.fetch    — the resource's /.well-known/aauth-resource.json.
//                       host, status?, ok, duration_ms, error?
//   person_token.hit  — a person token served from cache (no PS round trip).
//                       resource
//
// Never carried: token values, request or response bodies, invoke's
// path_params / query / body, or the connect `account` value. Those are the
// person's data or credentials; the sink gets the shape of the call, not its
// content.

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
    log(event, {
      ...fields,
      status: res.status,
      ok: res.ok,
      ...(requirement ? { requirement } : {}),
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
