// OpenAPI 3.x vocabulary adapter. All ops are `sync.request`.
//
// listOperations supports two query modes:
//   - free-text: matched against opId, summary, tags (case-insensitive substring)
//   - path prefix: query starts with '/'; optional trailing /* — matches path prefix
// Both are bounded; the caller decides on a result cap.

import type {
  InvocationPlan,
  InvokeArgs,
  OpDetail,
  OpSummary,
  VocabAdapter,
} from './types.js'

const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'] as const
type HttpMethod = (typeof HTTP_METHODS)[number]

interface OpenAPIOperation {
  operationId?: string
  summary?: string
  description?: string
  tags?: string[]
  parameters?: unknown[]
  requestBody?: unknown
  responses?: Record<string, unknown>
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
      })
    }
  }
  return ops
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

export class OpenAPIAdapter implements VocabAdapter<OpenAPIVocabDoc> {
  readonly vocabUri = 'urn:aauth:vocabulary:openapi'

  async load(url: string): Promise<OpenAPIVocabDoc> {
    const res = await fetch(url)
    if (!res.ok) throw new Error(`openapi load ${url}: ${res.status}`)
    const raw = (await res.json()) as OpenAPIDoc
    return { raw, ops: indexOperations(raw) }
  }

  listOperations(doc: OpenAPIVocabDoc, query?: string): OpSummary[] {
    const q = query ?? ''
    const out: OpSummary[] = []
    for (const op of doc.ops.values()) {
      if (!matches(op, q)) continue
      out.push({
        opId: op.opId,
        kind: 'sync.request',
        summary: op.summary,
        method: op.method,
        path: op.path,
        tags: op.tags,
      })
    }
    return out
  }

  getOperations(doc: OpenAPIVocabDoc, opIds: string[]): OpDetail[] {
    const out: OpDetail[] = []
    for (const opId of opIds) {
      const op = doc.ops.get(opId)
      if (!op) continue
      out.push({
        opId: op.opId,
        kind: 'sync.request',
        summary: op.summary,
        method: op.method,
        path: op.path,
        tags: op.tags,
        paramsSchema: op.parameters,
        bodySchema: op.requestBody,
        responseSchema: op.responses,
      })
    }
    return out
  }

  buildInvocation(doc: OpenAPIVocabDoc, opId: string, args: InvokeArgs): InvocationPlan {
    const op = doc.ops.get(opId)
    if (!op) throw new Error(`openapi: unknown operation ${opId}`)
    const path = applyPathParams(op.path, args.pathParams)
    const body = args.body
    return {
      kind: 'sync.request',
      method: op.method,
      path,
      ...(args.query !== undefined ? { query: args.query } : {}),
      ...(body !== undefined
        ? {
            headers: { 'content-type': args.contentType ?? 'application/json' },
            body: typeof body === 'string' ? body : JSON.stringify(body),
          }
        : {}),
    }
  }
}
