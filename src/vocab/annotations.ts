// Operation access annotations (R3 -02 §Operation Access Annotations).
//
// An agent cannot read R3 documents, so R3 alone tells it nothing about what any
// one operation requires. What it CAN read is the vocabulary — the OpenAPI
// document, the MCP tool list — because it has to parse that to make the call at
// all. The annotations state, alongside each operation, which credential it needs
// and whether it draws down a budget.
//
// Encodings (R3 -02 §Vocabulary Encodings):
//
//   OpenAPI  Operation Object   x-aauth-access-mode       x-aauth-budget
//   MCP      Tool `_meta`       aauth.dev/access-mode     aauth.dev/budget
//   AsyncAPI Operation Object   x-aauth-access-mode       x-aauth-budget
//
// Three rules govern how they combine with the resource-wide `access_mode`
// (§Applying Annotations):
//
//   1. Sparse. An operation with no annotation takes the resource's access_mode.
//   2. Replacing, not intersecting. A `person-token` annotation on a resource
//      declaring `auth-token` LOWERS the requirement for that operation.
//   3. Advisory. A resource MAY return any AAuth-Requirement at runtime whatever
//      it published. Annotations let the agent plan; the runtime requirement is
//      authoritative. Nothing here is ever enforced.

export const OPENAPI_ACCESS_MODE_KEY = 'x-aauth-access-mode'
export const OPENAPI_BUDGET_KEY = 'x-aauth-budget'
export const MCP_ACCESS_MODE_KEY = 'aauth.dev/access-mode'
export const MCP_BUDGET_KEY = 'aauth.dev/budget'

export interface OperationAnnotations {
  /** The operation's own access mode, when it carries one. Never `session-token`:
   *  R3 forbids that value in an annotation, and a value we see anyway is dropped. */
  access_mode?: string
  /** true when invoking this operation draws down a budget. */
  budget?: boolean
}

function readAnnotations(
  source: Record<string, unknown> | undefined,
  accessModeKey: string,
  budgetKey: string,
): OperationAnnotations {
  if (!source) return {}
  const out: OperationAnnotations = {}
  const mode = source[accessModeKey]
  // `session-token` MUST NOT appear in an annotation: a resource that manages
  // its own authorization does so for the whole resource and says so in
  // access_mode. Drop it rather than honour it.
  if (typeof mode === 'string' && mode && mode !== 'session-token') out.access_mode = mode
  const budget = source[budgetKey]
  if (typeof budget === 'boolean') out.budget = budget
  return out
}

/** Read the two annotations off an OpenAPI (or AsyncAPI) Operation Object. */
export function readOpenApiAnnotations(op: Record<string, unknown> | undefined): OperationAnnotations {
  return readAnnotations(op, OPENAPI_ACCESS_MODE_KEY, OPENAPI_BUDGET_KEY)
}

/** Read the two annotations off an MCP Tool's `_meta`. */
export function readMcpToolAnnotations(
  tool: { _meta?: Record<string, unknown> } | undefined,
): OperationAnnotations {
  return readAnnotations(tool?._meta, MCP_ACCESS_MODE_KEY, MCP_BUDGET_KEY)
}

/**
 * The access mode that actually applies to one operation.
 *
 * - An annotation replaces the resource-wide default outright (never intersects).
 * - `budget: true` implies at least `auth-token`, because a budget is carried in
 *   the auth token's `budget` claim. Where the access mode annotation is absent,
 *   `budget: true` implies `auth-token` rather than the resource default; a
 *   resource MUST NOT pair `budget: true` with `agent-token` or `person-token`,
 *   and an agent that sees that combination anyway MUST treat it as `auth-token`.
 * - Absent everything, the protocol default is `agent-token`.
 */
export function effectiveAccessMode(
  annotations: OperationAnnotations | undefined,
  resourceWide: string | undefined,
): string {
  const annotated = annotations?.access_mode
  const base = annotated ?? resourceWide ?? 'agent-token'
  if (annotations?.budget === true && (base === 'agent-token' || base === 'person-token')) {
    return 'auth-token'
  }
  return base
}
