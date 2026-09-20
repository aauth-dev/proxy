// OpenAPI 3.x vocabulary adapter. All ops are `sync.request`.
//
// listOperations supports two query modes:
//   - free-text: matched against opId, summary, tags (case-insensitive substring)
//   - path prefix: query starts with '/'; optional trailing /* — matches path prefix
// Both are bounded; the caller decides on a result cap.

import { readOpenApiAnnotations } from './annotations.js'
import type { OperationAnnotations } from './annotations.js'
import type {
  LoadedDoc,
  InvocationPlan,
  InvokeArgs,
  OpDetail,
  OpSummary,
  VocabAdapter,
} from './types.js'

const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'] as const
type HttpMethod = (typeof HTTP_METHODS)[number]

// Specification extensions (x-*) are permitted on the Operation Object, which is
// where R3 -02 puts the access annotations; the index signature keeps them
// reachable without naming each one.
interface OpenAPIOperation {
  operationId?: string
  summary?: string
  description?: string
  tags?: string[]
  parameters?: unknown[]
  requestBody?: unknown
  responses?: Record<string, unknown>
  [ext: string]: unknown
}

type OpenAPIPathItem = Partial<Record<HttpMethod, OpenAPIOperation>> & {
  parameters?: unknown[]
}

interface OpenAPIDoc {
  openapi?: string
  paths: Record<string, OpenAPIPathItem>
  components?: Record<string, unknown>
}

interface ResolvedOp {
  opId: string
  method: string
  path: string
  summary?: string
  tags?: string[]
  parameters?: unknown[]
  requestBody?: unknown
  responses?: Record<string, unknown>
  annotations: OperationAnnotations
}

export interface OpenAPIVocabDoc {
  raw: OpenAPIDoc
  ops: Map<string, ResolvedOp>
}

function indexOperations(doc: OpenAPIDoc): Map<string, ResolvedOp> {
  const ops = new Map<string, ResolvedOp>()
  for (const [path, item] of Object.entries(doc.paths ?? {})) {
    if (!item) continue
    for (const method of HTTP_METHODS) {
      const op = item[method]
      if (!op?.operationId) continue
      ops.set(op.operationId, {
        opId: op.operationId,
        method: method.toUpperCase(),
        path,
        summary: op.summary ?? op.description,
        tags: op.tags,
        parameters: [...(item.parameters ?? []), ...(op.parameters ?? [])],
        requestBody: op.requestBody,
        responses: op.responses,
        annotations: readOpenApiAnnotations(op),
      })
    }
  }
  return ops
}

// The Accept header for an operation: the media types its success responses
// (2xx, 2XX, default) declare. JSON alone when any of them offers it, since the
// body goes to an LLM; a resource that negotiates on Accept then answers JSON
// instead of its default (raw bytes, say). Nothing declared → no header.
export function acceptFor(responses: Record<string, unknown> | undefined): string | undefined {
  const types: string[] = []
  for (const [code, response] of Object.entries(responses ?? {})) {
    if (!/^(2\d\d|2XX|default)$/i.test(code)) continue
    const content = (response as { content?: unknown } | null)?.content
    if (!content || typeof content !== 'object') continue
    for (const t of Object.keys(content)) if (!types.includes(t)) types.push(t)
  }
  if (types.length === 0) return undefined
  return types.find((t) => /^application\/([\w.-]+\+)?json(\s*;|$)/i.test(t)) ?? types.join(', ')
}

function matches(op: ResolvedOp, query: string): boolean {
  if (!query) return true
  // Path prefix mode: '/foo' or '/foo/*' — match against the op's path.
  if (query.startsWith('/')) {
    const prefix = query.endsWith('/*') ? query.slice(0, -2) : query
    return op.path.toLowerCase().startsWith(prefix.toLowerCase())
  }
  const q = query.toLowerCase()
  return (
    op.opId.toLowerCase().includes(q) ||
    (op.summary?.toLowerCase().includes(q) ?? false) ||
    (op.tags?.some((t) => t.toLowerCase().includes(q)) ?? false)
  )
}

function applyPathParams(path: string, pathParams: Record<string, string> = {}): string {
  return path.replace(/\{(\w+)\}/g, (_m, name: string) =>
    encodeURIComponent(pathParams[name] ?? ''),
  )
}

// Re-index from raw if ops was lost during JSON serialization (R2 cache round-trip
// turns the Map into a plain object that lacks .values()).
function getOps(doc: OpenAPIVocabDoc): Map<string, ResolvedOp> {
  if (doc.ops instanceof Map) return doc.ops
  const ops = indexOperations(doc.raw)
  doc.ops = ops
  return ops
}

// `$ref` inlining. get_operation_schemas is the only place an LLM sees a body
// schema, and a bare `{"$ref": "#/components/schemas/Identifier"}` tells it
// nothing — two testers onboarding to secret.agent.coop had to guess the
// `mailto:` form from prose (2026-09-17, 2026-09-18). Resolve local refs
// against the document's own components and inline what they point at.
//
// A ref already on the stack is a cycle (a tree node whose children are the
// same schema): leave it as the `$ref` it was, so the shape stays finite and
// the LLM still sees the name. Anything non-local (another file, a URL) or
// unresolvable is left alone as well.
const MAX_REF_DEPTH = 12

function resolvePointer(doc: OpenAPIDoc, ref: string): unknown {
  if (!ref.startsWith('#/')) return undefined
  let node: unknown = doc
  for (const raw of ref.slice(2).split('/')) {
    const key = decodeURIComponent(raw.replace(/~1/g, '/').replace(/~0/g, '~'))
    if (!node || typeof node !== 'object') return undefined
    node = (node as Record<string, unknown>)[key]
  }
  return node
}

function inlineRefs(value: unknown, doc: OpenAPIDoc, stack: string[] = []): unknown {
  if (Array.isArray(value)) return value.map((v) => inlineRefs(v, doc, stack))
  if (!value || typeof value !== 'object') return value
  const obj = value as Record<string, unknown>
  const ref = obj.$ref
  if (typeof ref === 'string') {
    if (stack.includes(ref) || stack.length >= MAX_REF_DEPTH) return value
    const target = resolvePointer(doc, ref)
    if (target === undefined) return value
    const inlined = inlineRefs(target, doc, [...stack, ref])
    // A sibling of `$ref` (OpenAPI 3.1 allows `description`, `title`, …)
    // overrides what the target says.
    const { $ref: _dropped, ...siblings } = obj
    return Object.keys(siblings).length > 0 && inlined && typeof inlined === 'object' && !Array.isArray(inlined)
      ? { ...(inlined as Record<string, unknown>), ...inlineRefs(siblings, doc, stack) as Record<string, unknown> }
      : inlined
  }
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(obj)) out[k] = inlineRefs(v, doc, stack)
  return out
}

// Annotations are sparse: emit the field only when the operation carries one, so
// unannotated documents cost nothing extra in the listing the LLM reads.
function annotationsField(op: ResolvedOp): { annotations?: OperationAnnotations } {
  const a = op.annotations ?? {}
  return Object.keys(a).length > 0 ? { annotations: a } : {}
}

export class OpenAPIAdapter implements VocabAdapter<OpenAPIVocabDoc> {
  readonly vocabUri = 'urn:aauth:vocabulary:openapi'

  async load(url: string): Promise<OpenAPIVocabDoc> {
    const loaded = await this.loadCached(url)
    if (loaded.notModified) throw new Error(`openapi load ${url}: 304 to an unconditional request`)
    return loaded.doc
  }

  // The document with the resource's Cache-Control and ETag, so the doc cache
  // can honor them; with ifNoneMatch, a 304 comes back as notModified.
  async loadCached(url: string, opts: { ifNoneMatch?: string } = {}): Promise<LoadedDoc<OpenAPIVocabDoc>> {
    const res = await fetch(url, opts.ifNoneMatch ? { headers: { 'if-none-match': opts.ifNoneMatch } } : undefined)
    const cacheControl = res.headers.get('cache-control') ?? undefined
    const etag = res.headers.get('etag') ?? undefined
    if (res.status === 304 && opts.ifNoneMatch) return { notModified: true, cacheControl, etag }
    if (!res.ok) throw new Error(`openapi load ${url}: ${res.status}`)
    const raw = (await res.json()) as OpenAPIDoc
    return { doc: { raw, ops: indexOperations(raw) }, cacheControl, etag }
  }

  listOperations(doc: OpenAPIVocabDoc, query?: string): OpSummary[] {
    const q = query ?? ''
    const out: OpSummary[] = []
    for (const op of getOps(doc).values()) {
      if (!matches(op, q)) continue
      out.push({
        opId: op.opId,
        kind: 'sync.request',
        summary: op.summary,
        method: op.method,
        path: op.path,
        tags: op.tags,
        ...annotationsField(op),
      })
    }
    return out
  }

  getOperations(doc: OpenAPIVocabDoc, opIds: string[]): OpDetail[] {
    const out: OpDetail[] = []
    const ops = getOps(doc)
    for (const opId of opIds) {
      const op = ops.get(opId)
      if (!op) continue
      out.push({
        opId: op.opId,
        kind: 'sync.request',
        summary: op.summary,
        method: op.method,
        path: op.path,
        tags: op.tags,
        ...annotationsField(op),
        paramsSchema: inlineRefs(op.parameters, doc.raw),
        bodySchema: inlineRefs(op.requestBody, doc.raw),
        responseSchema: inlineRefs(op.responses, doc.raw),
      })
    }
    return out
  }

  annotationsFor(doc: OpenAPIVocabDoc, opId: string): OperationAnnotations {
    return getOps(doc).get(opId)?.annotations ?? {}
  }

  operationEntry(opId: string): Record<string, string> {
    return { operationId: opId }
  }

  buildInvocation(doc: OpenAPIVocabDoc, opId: string, args: InvokeArgs): InvocationPlan {
    const op = getOps(doc).get(opId)
    if (!op) throw new Error(`openapi: unknown operation ${opId}`)
    const path = applyPathParams(op.path, args.pathParams)
    const body = args.body
    const headers: Record<string, string> = {}
    const accept = acceptFor(op.responses)
    if (accept) headers.accept = accept
    if (body !== undefined) headers['content-type'] = args.contentType ?? 'application/json'
    return {
      kind: 'sync.request',
      method: op.method,
      path,
      ...(args.query !== undefined ? { query: args.query } : {}),
      ...(Object.keys(headers).length > 0 ? { headers } : {}),
      ...(body !== undefined ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {}),
    }
  }
}
