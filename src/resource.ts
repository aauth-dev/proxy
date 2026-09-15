// Fetch + validate a resource's well-known doc; pick vocabulary adapters
// the agent proxy supports. The caller (connect_resources) decides what to do with the
// FetchedResource — typically convert to an L1Entry and store.
//
// Mirrors registry/validate.ts:fetchResourceMetadata in spirit: manual
// redirect, basic shape validation, issuer === origin anti-spoof. The SSRF
// guards the registry applies (no localhost, no IPs, no non-default ports)
// are not enforced here because the agent proxy runs on the user's machine, and the
// user explicitly typed the host they want to add.

import { canonicalizeHost } from './host.js'
import { effectiveAccessMode, getAdapter, supportedVocabUris } from './vocab/index.js'
import { loggedFetch } from './log.js'
import type { ProxyLog } from './log.js'
import type { AccessMode, ConnectionMetadata, L1Entry } from './store.js'
import type {
  InvocationPlan,
  InvokeArgs,
  OpDetail,
  OperationAnnotations,
  OpSummary,
  VocabAdapter,
} from './vocab/index.js'

export interface AAuthResourceMeta {
  issuer: string
  client_name?: string
  name?: string
  description?: string
  access_mode?: AccessMode
  logo_uri?: string
  authorization_endpoint?: string
  // One discovery endpoint per vocabulary (R3 -02 §Resource Metadata Extensions,
  // §Operation Identifier Scope).
  r3_vocabularies?: Record<string, string>
  jwks_uri?: string
  interaction_endpoint?: string
  connection?: ConnectionMetadata
}

export interface PickedVocab {
  vocabUri: string
  docUrl: string
  adapter: VocabAdapter
}

export interface FetchedResource {
  host: string
  origin: string
  meta: AAuthResourceMeta
  pickedVocabs: PickedVocab[]
}

export async function fetchResource(hostOrUrl: string, opts: { log?: ProxyLog } = {}): Promise<FetchedResource> {
  const canonical = canonicalizeHost(hostOrUrl)
  if (!canonical) throw new Error(`invalid host: ${hostOrUrl}`)
  const { host, origin } = canonical
  const url = `${origin}/.well-known/aauth-resource.json`

  const res = await loggedFetch(opts.log, 'resource.fetch', { host }, () =>
    fetch(url, {
      redirect: 'manual',
      headers: { accept: 'application/json' },
    }),
  )
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`resource ${host}: unexpected redirect`)
  }
  if (!res.ok) throw new Error(`resource ${host}: well-known ${res.status}`)

  const meta = (await res.json()) as AAuthResourceMeta
  validate(meta, host, origin)

  return {
    host,
    origin,
    meta,
    pickedVocabs: pickVocabs(meta.r3_vocabularies ?? {}),
  }
}

function validate(meta: AAuthResourceMeta, host: string, origin: string): void {
  if (!meta.issuer) throw new Error(`resource ${host}: missing issuer`)
  if (meta.issuer.replace(/\/+$/, '') !== origin) {
    throw new Error(`resource ${host}: issuer mismatch (got ${meta.issuer}, expected ${origin})`)
  }
  // The interaction endpoint is a published property of the resource: where
  // the person is sent with `?code=`. It must be https; it need not share the
  // issuer's origin (ONBOARDING-PLAN-2.md Q2 — an operator hosts the OAuth
  // start for a fleet of resources; the registry may add an origin rule).
  if (meta.interaction_endpoint !== undefined) {
    let https = false
    try {
      https = new URL(meta.interaction_endpoint).protocol === 'https:'
    } catch {
      /* not a URL */
    }
    if (!https) throw new Error(`resource ${host}: interaction_endpoint must be an https URL`)
  }
  // access_mode is NOT validated against a closed list. The value set is an IANA
  // registry (protocol §AAuth Access Mode Value Registry) and the declaration is
  // advisory, so an unrecognized value is not an error — the agent adds the
  // resource, treats the mode as undeclared, and reads the runtime
  // AAuth-Requirement instead (see access-mode.ts).
  //
  // description is enforced at the registry on submit; agent-proxy-side is lenient
  // so direct-URL adds of resources without a description still work.
}

function pickVocabs(advertised: Record<string, string>): PickedVocab[] {
  const out: PickedVocab[] = []
  for (const uri of supportedVocabUris()) {
    const docUrl = advertised[uri]
    if (typeof docUrl !== 'string' || !docUrl) continue
    const adapter = getAdapter(uri)
    if (!adapter) continue
    out.push({ vocabUri: uri, docUrl, adapter })
  }
  return out
}

// ── Vocab doc loading + operation resolution ──
//
// Loaded vocab docs (L3) are cached via the injectable DocCache. The default is
// an in-memory Map for the lifetime of the agent proxy process — cold-start re-fetch
// is the only cost, amortized across a long-lived MCP session (Claude Code's
// typical mode). A host can inject a shared/persistent cache (e.g. R2/KV) so
// cold isolates don't all re-fetch large specs.

// Cache for fetched vocabulary docs (OpenAPI/AsyncAPI specs etc.), keyed by
// host+vocabUri. Async so non-memory backends can implement it.
export interface DocCache {
  get(key: string): Promise<unknown | undefined>
  set(key: string, doc: unknown): Promise<void>
}

export function createMemoryDocCache(): DocCache {
  const m = new Map<string, unknown>()
  return {
    async get(key) {
      return m.get(key)
    },
    async set(key, doc) {
      m.set(key, doc)
    },
  }
}

// Process-wide default so callers that don't inject a cache (e.g. agent.ts's
// invoke path) still share one cache for the process lifetime — unchanged
// behavior from the previous module-level Map.
const defaultDocCache = createMemoryDocCache()

function cacheKey(host: string, vocabUri: string): string {
  return `${host}|${vocabUri}`
}

// How long a fetched vocabulary doc is served before it is fetched again. Until
// 4.5.1 there was no expiry: a host with a durable cache (aauth-mcp's R2) served
// the first copy forever, so an operation a resource added later never appeared
// (secret.agent.coop's createAccount, 2026-09-15).
export const DOC_TTL_MS = 60 * 60 * 1000

// What the cache holds. A bare doc (written before 4.5.1) has no fetchedAt and
// counts as expired.
interface CachedDoc {
  aauth_doc_cache: 1
  fetchedAt: number
  doc: unknown
}

function isCachedDoc(v: unknown): v is CachedDoc {
  return !!v && typeof v === 'object' && (v as CachedDoc).aauth_doc_cache === 1 && typeof (v as CachedDoc).fetchedAt === 'number'
}

export async function loadDoc(host: string, vocab: PickedVocab, cache: DocCache, now = Date.now()): Promise<unknown> {
  const key = cacheKey(host, vocab.vocabUri)
  const cached = await cache.get(key)
  if (isCachedDoc(cached) && now - cached.fetchedAt < DOC_TTL_MS) return cached.doc
  let doc: unknown
  try {
    doc = await vocab.adapter.load(vocab.docUrl)
  } catch (e) {
    // The resource is unreachable right now: a stale copy beats no operations.
    if (isCachedDoc(cached)) return cached.doc
    if (cached !== undefined) return cached
    throw e
  }
  await cache.set(key, { aauth_doc_cache: 1, fetchedAt: now, doc } satisfies CachedDoc)
  return doc
}

function rehydrate(picked: L1Entry['picked_vocabs']): PickedVocab[] {
  const out: PickedVocab[] = []
  for (const v of picked) {
    const adapter = getAdapter(v.vocabUri)
    if (!adapter) continue
    out.push({ vocabUri: v.vocabUri, docUrl: v.docUrl, adapter })
  }
  return out
}

// Resolve an operation's access annotations against the resource-wide
// access_mode and flatten the result onto the summary the LLM reads: `access_mode`
// is always the mode that actually applies to THIS operation, and `budget` appears
// only when the operation draws one down. Advisory throughout — the agent never
// enforces either, and a resource may return any AAuth-Requirement at runtime.
function withEffectiveAccess<T extends OpSummary>(op: T, resourceWide: string | undefined): T {
  const resolved: T = { ...op, access_mode: effectiveAccessMode(op.annotations, resourceWide) }
  if (op.annotations?.budget === true) resolved.budget = true
  delete resolved.annotations
  return resolved
}

export async function listOperationsForResource(
  l1: L1Entry,
  query?: string,
  docCache: DocCache = defaultDocCache,
): Promise<OpSummary[]> {
  const out: OpSummary[] = []
  for (const v of rehydrate(l1.picked_vocabs)) {
    const doc = await loadDoc(l1.resource, v, docCache)
    for (const summary of v.adapter.listOperations(doc, query)) {
      out.push(withEffectiveAccess(summary, l1.access_mode))
    }
  }
  return out
}

export async function getOperationsForResource(
  l1: L1Entry,
  opIds: string[],
  docCache: DocCache = defaultDocCache,
): Promise<OpDetail[]> {
  const out: OpDetail[] = []
  for (const v of rehydrate(l1.picked_vocabs)) {
    const doc = await loadDoc(l1.resource, v, docCache)
    for (const detail of v.adapter.getOperations(doc, opIds)) {
      out.push(withEffectiveAccess(detail, l1.access_mode))
    }
  }
  return out
}

export interface RoutedOperation {
  adapter: VocabAdapter
  plan: InvocationPlan
  /** This operation's own access annotations, {} when it carries none. */
  annotations: OperationAnnotations
  /** The mode that applies to this call: annotation if present, else the resource's. */
  accessMode: string
}

// Resolve an opId on a resource by trying each picked vocab in order. First
// adapter that builds a plan wins. v1 has a single adapter (OpenAPI), so
// "first wins" is unambiguous; the collision-prefix rule for multi-adapter
// resources is an agent-proxy-side concern at list time, not invoke time.
export async function routeOperation(
  l1: L1Entry,
  opId: string,
  args: InvokeArgs,
  docCache: DocCache = defaultDocCache,
): Promise<RoutedOperation> {
  for (const v of rehydrate(l1.picked_vocabs)) {
    const doc = await loadDoc(l1.resource, v, docCache)
    try {
      const plan = v.adapter.buildInvocation(doc, opId, args)
      const annotations = v.adapter.annotationsFor(doc, opId)
      return {
        adapter: v.adapter,
        plan,
        annotations,
        accessMode: effectiveAccessMode(annotations, l1.access_mode),
      }
    } catch {
      // try the next adapter
    }
  }
  throw new Error(`unknown operation ${opId} on resource ${l1.resource}`)
}

// Convert a FetchedResource into the persisted L1 shape.
//
// access_mode default: if the resource advertises an authorization_endpoint
// but no access_mode, infer auth-token (the R3 flow is the only thing
// authorization_endpoint exists for). Absent both, default to agent-token
// (resource accepts agent-signed requests directly — the registry's own mode).
export function toL1Entry(r: FetchedResource): L1Entry {
  const inferredMode: AccessMode =
    r.meta.access_mode ?? (r.meta.authorization_endpoint ? 'auth-token' : 'agent-token')
  return {
    resource: r.host,
    origin: r.origin,
    issuer: r.meta.issuer.replace(/\/+$/, ''),
    name: r.meta.name?.trim() || r.meta.client_name?.trim() || r.host,
    description: r.meta.description ?? '',
    access_mode: inferredMode,
    ...(r.meta.logo_uri ? { logo_uri: r.meta.logo_uri } : {}),
    ...(r.meta.authorization_endpoint
      ? { authorization_endpoint: r.meta.authorization_endpoint }
      : {}),
    // N1: carry the interaction endpoint and the whole connection object.
    // The whitelist used to drop both, which is why nothing connection-
    // related could work until this line.
    ...(typeof r.meta.interaction_endpoint === 'string' ? { interaction_endpoint: r.meta.interaction_endpoint } : {}),
    ...(r.meta.connection && typeof r.meta.connection.endpoint === 'string' ? { connection: r.meta.connection } : {}),
    picked_vocabs: r.pickedVocabs.map((v) => ({ vocabUri: v.vocabUri, docUrl: v.docUrl })),
    added: new Date().toISOString(),
  }
}
