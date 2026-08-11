// Vocabulary adapter registry. The agent proxy picks adapters at resource-load time by
// walking `r3_vocabularies` from the well-known doc and selecting every URN
// it has an adapter for.
//
// `urn:aauth:vocabulary:openapi-gateway` was removed in R3 -02 (aauth-dev/AAuth
// issue #72): operation identifiers are scoped to the one discovery endpoint a
// resource advertises per vocabulary (R3 -02 §Operation Identifier Scope), so a
// resource fronting several backend services either presents them as a single
// valid definition or exposes them under separate resource identifiers. There is
// no composite `service:operationId` identity and no `{service, operationId}`
// entry shape any more.

import { OpenAPIAdapter } from './openapi.js'
import type { VocabAdapter } from './types.js'

export * from './types.js'
export * from './annotations.js'
export { OpenAPIAdapter } from './openapi.js'

const ADAPTERS: Record<string, VocabAdapter> = {
  'urn:aauth:vocabulary:openapi': new OpenAPIAdapter(),
  // 'urn:aauth:vocabulary:asyncapi': new AsyncAPIAdapter(),   // Phase 3
  // 'urn:aauth:vocabulary:mcp':      new MCPAdapter(),        // future
  // 'urn:aauth:vocabulary:graphql':  new GraphQLAdapter(),    // future
}

export function getAdapter(vocabUri: string): VocabAdapter | undefined {
  return ADAPTERS[vocabUri]
}

export function supportedVocabUris(): string[] {
  return Object.keys(ADAPTERS)
}
