// Fetch + validate a resource's well-known doc; pick vocabulary adapters
// praca supports. The caller (add_resource) decides what to do with the
// FetchedResource — typically convert to an L1Entry and store.
//
// Mirrors registry/validate.ts:fetchResourceMetadata in spirit: manual
// redirect, basic shape validation, issuer === origin anti-spoof. The SSRF
// guards the registry applies (no localhost, no IPs, no non-default ports)
// are not enforced here because praca runs on the user's machine, and the
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
  // description is enforced at the registry on submit; praca-side is lenient
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
// Loaded vocab docs are cached in memory for the lifetime of the praca process.
// Cold-start re-fetch is the only cost; for a long-lived MCP server (Claude
// Code's typical mode) this is amortized across the whole session. Disk cache
// at ~/.aauth/praca/catalog/{host}/{vocab}.json is a future refinement.

const docCache = new Map<string, unknown>()

function cacheKey(host: string, vocabUri: string): string {
  return `${host}|${vocabUri}`
}

async function loadDoc(host: string, vocab: PickedVocab): Promise<unknown> {
  const key = cacheKey(host, vocab.vocabUri)
  let doc = docCache.get(key)
  if (doc === undefined) {
    doc = await vocab.adapter.load(vocab.docUrl)
    docCache.set(key, doc)
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
): Promise<OpSummary[]> {
  const out: OpSummary[] = []
  for (const v of rehydrate(l1.picked_vocabs)) {
    const doc = await loadDoc(l1.resource, v)
    for (const summary of v.adapter.listOperations(doc, query)) {
      out.push(summary)
    }
  }
  return out
}

export async function getOperationsForResource(
  l1: L1Entry,
  opIds: string[],
): Promise<OpDetail[]> {
  const out: OpDetail[] = []
  for (const v of rehydrate(l1.picked_vocabs)) {
    const doc = await loadDoc(l1.resource, v)
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
// resources is a praca-side concern at list time, not invoke time.
export async function routeOperation(
  l1: L1Entry,
  opId: string,
  args: InvokeArgs,
): Promise<RoutedOperation> {
  for (const v of rehydrate(l1.picked_vocabs)) {
    const doc = await loadDoc(l1.resource, v)
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
// but no access_mode, infer aauth-access-token (the R3 flow is the only thing
// authorization_endpoint exists for). Absent both, default to agent-token
// (resource accepts agent-signed requests directly — the registry's own mode).
export function toL1Entry(r: FetchedResource): L1Entry {
  const inferredMode: AccessMode =
    r.meta.access_mode ?? (r.meta.authorization_endpoint ? 'aauth-access-token' : 'agent-token')
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
