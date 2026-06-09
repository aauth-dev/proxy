// Vocabulary adapter registry. Praca picks adapters at resource-load time by
// walking `r3_vocabularies` from the well-known doc and selecting every URN
// it has an adapter for.

import { OpenAPIAdapter } from './openapi.js'
import type { VocabAdapter } from './types.js'

export * from './types.js'
export { OpenAPIAdapter } from './openapi.js'

const ADAPTERS: Record<string, VocabAdapter> = {
  'urn:aauth:vocabulary:openapi': new OpenAPIAdapter(),
  // 'urn:aauth:vocabulary:asyncapi': new AsyncAPIAdapter(),   // Phase 3
  // 'urn:aauth:vocabulary:mcp-tools': new MCPToolsAdapter(),  // future
  // 'urn:aauth:vocabulary:graphql':   new GraphQLAdapter(),   // future
}

export function getAdapter(vocabUri: string): VocabAdapter | undefined {
  return ADAPTERS[vocabUri]
}

export function supportedVocabUris(): string[] {
  return Object.keys(ADAPTERS)
}
