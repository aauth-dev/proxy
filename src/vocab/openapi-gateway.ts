// OpenAPI Gateway vocabulary adapter (urn:aauth:vocabulary:openapi-gateway,
// AAuth R3 §OpenAPI Gateway Vocabulary). For resources that front MULTIPLE
// OpenAPI-described services behind a single resource identifier — e.g. a
// Google APIs proxy exposing gmail/calendar/people/… as separate specs.
//
// Discovery: the r3_vocabularies value is not a single URL but an object
// mapping stable service labels → per-service OpenAPI spec URLs. Operation
// identity is the pair (service, operationId); the agent-facing composite id
// is `service:operationId` (unambiguous — ':' appears in no operationId).
// R3 operation entries are { service, operationId } objects.

import { OpenAPIAdapter, type OpenAPIVocabDoc } from './openapi.js'
import type {
  InvocationPlan,
  InvokeArgs,
  OpDetail,
  OpSummary,
  VocabAdapter,
} from './types.js'

export interface GatewayVocabDoc {
  services: Record<string, OpenAPIVocabDoc>
}

// Reuses the plain adapter's per-doc indexing/search/planning; this class only
// adds the service dimension.
const openapi = new OpenAPIAdapter()

function splitId(compositeId: string): { service: string; operationId: string } {
  const i = compositeId.indexOf(':')
  if (i === -1) throw new Error(`openapi-gateway: operation id must be service:operationId, got ${compositeId}`)
  return { service: compositeId.slice(0, i), operationId: compositeId.slice(i + 1) }
}

export class OpenAPIGatewayAdapter implements VocabAdapter<GatewayVocabDoc> {
  readonly vocabUri = 'urn:aauth:vocabulary:openapi-gateway'

  async load(source: string | Record<string, string>): Promise<GatewayVocabDoc> {
    if (typeof source === 'string' || source === null) {
      throw new Error('openapi-gateway: discovery value must be an object mapping service labels to OpenAPI URLs')
    }
    const services: Record<string, OpenAPIVocabDoc> = {}
    await Promise.all(
      Object.entries(source).map(async ([label, url]) => {
        services[label] = await openapi.load(url)
      }),
    )
    return { services }
  }

  listOperations(doc: GatewayVocabDoc, query?: string): OpSummary[] {
    const out: OpSummary[] = []
    for (const [label, serviceDoc] of Object.entries(doc.services)) {
      for (const op of openapi.listOperations(serviceDoc, query)) {
        out.push({ ...op, opId: `${label}:${op.opId}`, tags: [label, ...(op.tags ?? [])] })
      }
    }
    return out
  }

  getOperations(doc: GatewayVocabDoc, opIds: string[]): OpDetail[] {
    const out: OpDetail[] = []
    for (const compositeId of opIds) {
      const { service, operationId } = splitId(compositeId)
      const serviceDoc = doc.services[service]
      if (!serviceDoc) continue
      for (const detail of openapi.getOperations(serviceDoc, [operationId])) {
        out.push({ ...detail, opId: compositeId, tags: [service, ...(detail.tags ?? [])] })
      }
    }
    return out
  }

  buildInvocation(doc: GatewayVocabDoc, compositeId: string, args: InvokeArgs): InvocationPlan {
    const { service, operationId } = splitId(compositeId)
    const serviceDoc = doc.services[service]
    if (!serviceDoc) throw new Error(`openapi-gateway: unknown service ${service}`)
    // Per-service docs publish agent-facing paths relative to the resource
    // origin (the gateway's generated specs label-prefix their paths), so the
    // plain adapter's plan is already correct.
    return openapi.buildInvocation(serviceDoc, operationId, args)
  }

  // R3 operation entries carry the pair, not the composite string.
  formatOperationEntry(compositeId: string): Record<string, unknown> {
    return splitId(compositeId)
  }
}
