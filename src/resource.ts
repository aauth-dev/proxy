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
  LoadedDoc,
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
  /** The response's Cache-Control and ETag: how long the entry made from this may be used (refreshResourceEntry). */
  cacheControl?: string
  etag?: string
}

/** fetchResourceConditional: the resource, or notModified for a 304 to If-None-Match. */
export type ResourceFetch =
  | ({ notModified?: false } & FetchedResource)
  | { notModified: true; cacheControl?: string; etag?: string }

export async function fetchResource(hostOrUrl: string, opts: { log?: ProxyLog } = {}): Promise<FetchedResource> {
  const fetched = await fetchResourceConditional(hostOrUrl, { log: opts.log })
  if (fetched.notModified) throw new Error(`resource ${hostOrUrl}: 304 to an unconditional request`)
  return fetched
}

// The well-known, with the response's caching headers, and conditional on an
// ETag the stored entry already holds.
export async function fetchResourceConditional(
  hostOrUrl: string,
  opts: { log?: ProxyLog; ifNoneMatch?: string } = {},
): Promise<ResourceFetch> {
  const canonical = canonicalizeHost(hostOrUrl)
  if (!canonical) throw new Error(`invalid host: ${hostOrUrl}`)
  const { host, origin } = canonical
  const url = `${origin}/.well-known/aauth-resource.json`

  const res = await loggedFetch(opts.log, 'resource.fetch', { host }, () =>
    fetch(url, {
      redirect: 'manual',
      headers: { accept: 'application/json', ...(opts.ifNoneMatch ? { 'if-none-match': opts.ifNoneMatch } : {}) },
    }),
  )
  const cacheControl = res.headers.get('cache-control') ?? undefined
  const etag = res.headers.get('etag') ?? undefined
  if (res.status === 304 && opts.ifNoneMatch) return { notModified: true, cacheControl, etag }
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
    pickedVocabs: pickVocabs(meta.r3_vocabularies ?? {}, origin),
    ...(cacheControl !== undefined ? { cacheControl } : {}),
    ...(etag !== undefined ? { etag } : {}),
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

function pickVocabs(advertised: Record<string, string>, origin: string): PickedVocab[] {
  const out: PickedVocab[] = []
  for (const uri of supportedVocabUris()) {
    const docUrl = advertised[uri]
    if (typeof docUrl !== 'string' || !docUrl) continue
    const adapter = getAdapter(uri)
    if (!adapter) continue
    // An MCP endpoint on another origin could only be called as some other
    // resource; drop it rather than sign calls for the wrong audience.
    if (adapter.usableAt && !adapter.usableAt(docUrl, origin)) continue
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

// How long a fetched vocabulary doc is served when the resource says nothing,
// and the most it is ever served for. Until 4.5.1 there was no expiry: a host
// with a durable cache (aauth-mcp's R2) served the first copy forever, so an
// operation a resource added later never appeared (secret.agent.coop's
// createAccount, 2026-09-15). Since 4.9.0 the resource's own Cache-Control
// decides inside that hour, so a resource that sends max-age=300 has a changed
// operation reach agents within five minutes of a deploy (secret-agent-coop
// plan read-send-services section 12).
export const DOC_TTL_MS = 60 * 60 * 1000

// What the cache holds. A bare doc (written before 4.5.1) has no fetchedAt and
// counts as expired. An entry written by 4.5.1–4.8.x has no expiresAt and
// expires DOC_TTL_MS after fetchedAt, as it did then.
interface CachedDoc {
  aauth_doc_cache: 1
  fetchedAt: number
  /** when this copy stops being served without asking the resource again */
  expiresAt?: number
  /** the lifetime that expiresAt came from, reused when a 304 carries no Cache-Control */
  maxAgeMs?: number
  /** the resource's ETag, sent back as If-None-Match once the copy has expired */
  etag?: string
  doc: unknown
}

function isCachedDoc(v: unknown): v is CachedDoc {
  return !!v && typeof v === 'object' && (v as CachedDoc).aauth_doc_cache === 1 && typeof (v as CachedDoc).fetchedAt === 'number'
}

/**
 * How long a response may be served, from its Cache-Control (RFC 9111):
 *   no-store             → 'no-store': do not keep it at all
 *   no-cache             → 0: keep it, but ask every time (a 304 is enough)
 *   s-maxage, max-age    → that many seconds, capped at one hour; s-maxage
 *                          wins, since a host may share this cache
 *   nothing usable       → one hour, as before 4.9.0
 */
export function docLifetimeMs(cacheControl: string | undefined): number | 'no-store' {
  if (!cacheControl) return DOC_TTL_MS
  const directives = new Map<string, string | undefined>()
  for (const part of cacheControl.split(',')) {
    const [name, value] = part.trim().split('=', 2)
    if (name) directives.set(name.toLowerCase(), value?.trim().replace(/^"|"$/g, ''))
  }
  if (directives.has('no-store')) return 'no-store'
  if (directives.has('no-cache')) return 0
  for (const name of ['s-maxage', 'max-age']) {
    const raw = directives.get(name)
    if (raw === undefined || !/^\d+$/.test(raw)) continue
    return Math.min(Number(raw) * 1000, DOC_TTL_MS)
  }
  return DOC_TTL_MS
}

function expiresAtOf(cached: CachedDoc): number {
  return cached.expiresAt ?? cached.fetchedAt + DOC_TTL_MS
}

export async function loadDoc(host: string, vocab: PickedVocab, cache: DocCache, now = Date.now()): Promise<unknown> {
  const key = cacheKey(host, vocab.vocabUri)
  const cached = await cache.get(key)
  // An entry emptied by no-store (below) holds nothing to serve.
  const held = isCachedDoc(cached) && cached.doc !== undefined ? cached : undefined
  if (held && now < expiresAtOf(held)) return held.doc

  let loaded: LoadedDoc
  try {
    // Expired with an ETag: revalidate, so an unchanged doc costs a 304.
    loaded = vocab.adapter.loadCached
      ? await vocab.adapter.loadCached(vocab.docUrl, held?.etag ? { ifNoneMatch: held.etag } : {})
      : { doc: await vocab.adapter.load(vocab.docUrl) }
  } catch (e) {
    // The resource is unreachable right now: a stale copy beats no operations.
    if (held) return held.doc
    // A bare doc written before 4.5.1.
    if (cached !== undefined && !isCachedDoc(cached)) return cached
    throw e
  }

  if (loaded.notModified) {
    // Nothing held to renew: a 304 to a request that carried no ETag. Ask plainly.
    if (!held) return vocab.adapter.load(vocab.docUrl)
    // A 304 renews the copy without a new body. Its Cache-Control replaces the
    // stored one; without one the lifetime the copy came with stands.
    const lifetime = loaded.cacheControl === undefined ? (held.maxAgeMs ?? DOC_TTL_MS) : docLifetimeMs(loaded.cacheControl)
    if (lifetime !== 'no-store') {
      await cache.set(key, { ...held, fetchedAt: now, expiresAt: now + lifetime, maxAgeMs: lifetime, ...(loaded.etag ? { etag: loaded.etag } : {}) } satisfies CachedDoc)
    }
    return held.doc
  }

  const lifetime = docLifetimeMs(loaded.cacheControl)
  // no-store: serve it for this call and keep nothing. The DocCache has no
  // delete, so a copy stored under an earlier policy is overwritten as expired
  // and without the doc it held.
  if (lifetime === 'no-store') {
    if (cached !== undefined) await cache.set(key, { aauth_doc_cache: 1, fetchedAt: 0, expiresAt: 0, doc: undefined } satisfies CachedDoc)
    return loaded.doc
  }
  await cache.set(key, {
    aauth_doc_cache: 1, fetchedAt: now, expiresAt: now + lifetime, maxAgeMs: lifetime, ...(loaded.etag ? { etag: loaded.etag } : {}), doc: loaded.doc,
  } satisfies CachedDoc)
  return loaded.doc
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

// Resolve an opId on a resource by trying each picked vocab in order (the
// adapter table's order: OpenAPI, then MCP). First adapter that builds a plan
// wins. A resource advertising both vocabularies with a colliding identifier
// gets the OpenAPI operation; the collision-prefix rule for multi-adapter
// resources (design.md §OpId namespacing) is not implemented.
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
export function toL1Entry(r: FetchedResource, now = Date.now()): L1Entry {
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
    added: new Date(now).toISOString(),
    ...metaLifetime(r.cacheControl, r.etag, now),
  }
}

// ── Keeping a stored entry current ──
//
// An L1 entry is the person's record of a resource, so it is always kept; what
// expires is the metadata on it. The rule is loadDoc's: the resource's
// Cache-Control decides, at most one hour, and an expired entry with an ETag is
// revalidated with If-None-Match. no-store cannot mean "keep nothing" here, so
// it means what no-cache means: ask every time. Until 4.10.0 the well-known was
// read once at connect_resources and never again, so a changed access_mode,
// connection object or vocabulary URL reached nobody who was already connected.

function metaLifetime(cacheControl: string | undefined, etag: string | undefined, now: number): Pick<L1Entry, 'meta_expires_at' | 'meta_max_age_ms' | 'meta_etag'> {
  const lifetime = docLifetimeMs(cacheControl)
  const ms = lifetime === 'no-store' ? 0 : lifetime
  return { meta_expires_at: now + ms, meta_max_age_ms: ms, ...(etag ? { meta_etag: etag } : {}) }
}

/**
 * The entry to use now: the stored one while it is fresh, otherwise re-read
 * from the well-known. What the person has accumulated on the entry (added,
 * last_used, connections) is kept. `changed` says the caller should store it.
 * A fetch that fails, or a resource that suddenly advertises nothing usable,
 * leaves the entry as it was: a stale entry beats none.
 */
export async function refreshResourceEntry(
  entry: L1Entry,
  opts: { log?: ProxyLog; now?: number } = {},
): Promise<{ entry: L1Entry; changed: boolean }> {
  const now = opts.now ?? Date.now()
  // An entry with no usable vocabulary is re-read whatever its age: that is
  // what a resource added before its vocabulary was supported looks like.
  const fresh = entry.meta_expires_at !== undefined && now < entry.meta_expires_at
  if (fresh && entry.picked_vocabs.length > 0) return { entry, changed: false }

  let fetched: ResourceFetch
  try {
    fetched = await fetchResourceConditional(entry.resource, { log: opts.log, ...(entry.meta_etag ? { ifNoneMatch: entry.meta_etag } : {}) })
  } catch {
    return { entry, changed: false }
  }

  if (fetched.notModified) {
    const lifetime = fetched.cacheControl === undefined ? (entry.meta_max_age_ms ?? DOC_TTL_MS) : docLifetimeMs(fetched.cacheControl)
    const ms = lifetime === 'no-store' ? 0 : lifetime
    return {
      entry: { ...entry, meta_expires_at: now + ms, meta_max_age_ms: ms, ...(fetched.etag ? { meta_etag: fetched.etag } : {}) },
      changed: true,
    }
  }

  const next = toL1Entry(fetched, now)
  if (next.picked_vocabs.length === 0) {
    // The resource advertises nothing this build can use. An entry that never
    // had a vocabulary stays exactly as it was (and is asked again next call);
    // one that has them keeps what works and is asked again after this lifetime.
    if (entry.picked_vocabs.length === 0) return { entry, changed: false }
    return { entry: { ...entry, meta_expires_at: next.meta_expires_at, meta_max_age_ms: next.meta_max_age_ms }, changed: true }
  }
  return {
    entry: {
      ...next,
      added: entry.added,
      ...(entry.last_used ? { last_used: entry.last_used } : {}),
      ...(entry.connections ? { connections: entry.connections } : {}),
    },
    changed: true,
  }
}
