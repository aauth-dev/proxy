// Vocabulary adapter contract. A resource advertises one or more vocabularies
// in `r3_vocabularies` ({ urn → vocab_doc_url }). Each adapter knows how to:
//   - fetch + parse the doc
//   - enumerate operations as bounded summaries (for list_operations)
//   - return full schemas for chosen op_ids (for get_operations)
//   - turn (opId, args) into an InvocationPlan the agent proxy's `invoke` can execute
//   - read each operation's access annotations (R3 -02 §Operation Access
//     Annotations) off the vocabulary document
//
// See design.md §"Vocabularies". The LLM never sees `vocab` — it sees
// `kind` (sync.request | async.send | async.receive) on each OpSummary, plus
// the operation's effective `access_mode` / `budget`.

import type { OperationAnnotations } from './annotations.js'

export type OpKind = 'sync.request' | 'async.send' | 'async.receive'

export interface OpSummary {
  opId: string
  kind: OpKind
  summary?: string
  method?: string  // sync.request
  path?: string    // sync.request
  channel?: string // async.*
  tags?: string[]
  /**
   * The operation's own access annotations, when the vocabulary document carries
   * them. Sparse by design — absent means "takes the resource-wide access_mode".
   * resource.ts resolves these against the L1 entry before the LLM sees them.
   */
  annotations?: OperationAnnotations
  /**
   * The access mode that actually applies to this operation: the annotation when
   * present, the resource-wide `access_mode` otherwise. Filled in by resource.ts,
   * not by adapters. Advisory — the runtime AAuth-Requirement is authoritative.
   */
  access_mode?: string
  /** true when invoking this operation draws down a budget. Omitted when false. */
  budget?: boolean
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
  // The r3_vocabularies discovery value: one doc URL per vocabulary. Operation
  // identifiers are scoped to that one endpoint (R3 -02 §Operation Identifier
  // Scope), so a resource fronting several backends either presents them as one
  // definition or exposes them under separate resource identifiers.
  load(source: string): Promise<Doc>
  listOperations(doc: Doc, query?: string): OpSummary[]
  getOperations(doc: Doc, opIds: string[]): OpDetail[]
  buildInvocation(doc: Doc, opId: string, args: InvokeArgs): InvocationPlan
  /** This operation's access annotations, or {} when it carries none. */
  annotationsFor(doc: Doc, opId: string): OperationAnnotations
}
