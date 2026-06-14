// Vocabulary adapter contract. A resource advertises one or more vocabularies
// in `r3_vocabularies` ({ urn → vocab_doc_url }). Each adapter knows how to:
//   - fetch + parse the doc
//   - enumerate operations as bounded summaries (for list_operations)
//   - return full schemas for chosen op_ids (for get_operations)
//   - turn (opId, args) into an InvocationPlan the agent proxy's `invoke` can execute
//
// See design.md §"Vocabularies". The LLM never sees `vocab` — it sees
// `kind` (sync.request | async.send | async.receive) on each OpSummary.

export type OpKind = 'sync.request' | 'async.send' | 'async.receive'

export interface OpSummary {
  opId: string
  kind: OpKind
  summary?: string
  method?: string  // sync.request
  path?: string    // sync.request
  channel?: string // async.*
  tags?: string[]
}

export interface OpDetail extends OpSummary {
  // JSON Schema (or vocab-equivalent) for params, request body, response.
  // Left as-is from the spec for v1; $ref resolution / inlining is a future
  // refinement (the research notes Cloudflare pre-resolves $refs before search
  // because deep indirection hurts LLM accuracy).
  paramsSchema?: unknown
  bodySchema?: unknown
  responseSchema?: unknown
}

export type InvocationPlan =
  | {
      kind: 'sync.request'
      method: string
      path: string
      query?: string
      headers?: Record<string, string>
      body?: string
    }
  | {
      kind: 'async.send'
      channel: string
      message: unknown
      headers?: Record<string, string>
    }
  | {
      kind: 'async.receive'
      channel: string
      filter?: unknown
    }

// Vocab-neutral invoke args the LLM passes. Each adapter interprets these per
// its semantics — OpenAPI uses pathParams/query/body; AsyncAPI publish uses
// `message` (and may ignore the others).
export interface InvokeArgs {
  pathParams?: Record<string, string>
  query?: string
  body?: unknown
  contentType?: string
  message?: unknown
}

export interface VocabAdapter<Doc = unknown> {
  readonly vocabUri: string
  load(url: string): Promise<Doc>
  listOperations(doc: Doc, query?: string): OpSummary[]
  getOperations(doc: Doc, opIds: string[]): OpDetail[]
  buildInvocation(doc: Doc, opId: string, args: InvokeArgs): InvocationPlan
}
