// Fetch + validate a resource's well-known doc; pick vocabulary adapters
// the agent proxy supports. The caller (add_resource) decides what to do with the
// FetchedResource — typically convert to an L1Entry and store.
//
// Mirrors registry/validate.ts:fetchResourceMetadata in spirit: manual
// redirect, basic shape validation, issuer === origin anti-spoof. The SSRF
// guards the registry applies (no localhost, no IPs, no non-default ports)
// are not enforced here because the agent proxy runs on the user's machine, and the
// user explicitly typed the host they want to add.

import { canonicalizeHost } from './host.js'
import { getAdapter, supportedVocabUris } from './vocab/index.js'
import type { AccessMode, L1Entry } from './store.js'
import type {
  InvocationPlan,
  InvokeArgs,
  OpDetail,
  OpSummary,
  VocabAdapter,
} from './vocab/index.js'

export interface AAuthResourceMeta {
  issuer: string
  client_name?: string
  description?: string
  access_mode?: AccessMode
  logo_uri?: string
  authorization_endpoint?: string
  r3_vocabularies?: Record<string, string>
  jwks_uri?: string
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

export async function fetchResource(hostOrUrl: string): Promise<FetchedResource> {
  const canonical = canonicalizeHost(hostOrUrl)
  if (!canonical) throw new Error(`invalid host: ${hostOrUrl}`)
  const { host, origin } = canonical
  const url = `${origin}/.well-known/aauth-resource.json`

  const res = await fetch(url, {
    redirect: 'manual',
    headers: { accept: 'application/json' },
  })
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
  if (
    meta.access_mode !== undefined &&
    !['agent-token', 'aauth-access-token', 'auth-token'].includes(meta.access_mode)
  ) {
    throw new Error(`resource ${host}: invalid access_mode ${meta.access_mode}`)
  }
  // description is enforced at the registry on submit; agent-proxy-side is lenient
  // so direct-URL adds of resources without a description still work.
}

function pickVocabs(advertised: Record<string, string>): PickedVocab[] {
  const out: PickedVocab[] = []
  for (const uri of supportedVocabUris()) {
    const docUrl = advertised[uri]
    if (!docUrl) continue
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

async function loadDoc(host: string, vocab: PickedVocab, cache: DocCache): Promise<unknown> {
  const key = cacheKey(host, vocab.vocabUri)
  let doc = await cache.get(key)
  if (doc === undefined) {
    doc = await vocab.adapter.load(vocab.docUrl)
    await cache.set(key, doc)
  }
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

export async function listOperationsForResource(
  l1: L1Entry,
  query?: string,
  docCache: DocCache = defaultDocCache,
): Promise<OpSummary[]> {
  const out: OpSummary[] = []
  for (const v of rehydrate(l1.picked_vocabs)) {
    const doc = await loadDoc(l1.resource, v, docCache)
    for (const summary of v.adapter.listOperations(doc, query)) {
      out.push(summary)
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
      out.push(detail)
    }
  }
  return out
}

export interface RoutedOperation {
  adapter: VocabAdapter
  plan: InvocationPlan
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
      return { adapter: v.adapter, plan }
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
    name: r.meta.client_name?.trim() || r.host,
    description: r.meta.description ?? '',
    access_mode: inferredMode,
    ...(r.meta.logo_uri ? { logo_uri: r.meta.logo_uri } : {}),
    ...(r.meta.authorization_endpoint
      ? { authorization_endpoint: r.meta.authorization_endpoint }
      : {}),
    picked_vocabs: r.pickedVocabs.map((v) => ({ vocabUri: v.vocabUri, docUrl: v.docUrl })),
    added: new Date().toISOString(),
  }
}
