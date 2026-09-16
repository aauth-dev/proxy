// MCP vocabulary adapter (`urn:aauth:vocabulary:mcp`, R3 -02 §MCP Vocabulary).
// All ops are `sync.request`.
//
// The discovery endpoint is the MCP server URL. Tools are discovered with MCP
// tool discovery: JSON-RPC 2.0 over HTTP POST (Streamable HTTP) — `initialize`,
// `notifications/initialized`, then `tools/list` following `nextCursor`. A server
// may answer each POST with JSON or with an SSE stream; both are read.
//
// The endpoint is also the call target: `tools/call` is POSTed to it. The agent
// builds the call URL as `${l1.origin}${plan.path}`, so an MCP endpoint on
// another origin cannot be called as this resource — `usableAt` refuses it when
// the vocabulary is picked.
//
// The operation entry is `{ tool }`, not OpenAPI's `{ operationId }`.
//
// Not handled: a server that requires `Mcp-Session-Id` on `tools/call`. The
// session opened for discovery is not carried into invoke — the call is a
// separate signed request, possibly hours later, and the doc it came from is
// cached. Stateless servers (senzing.aauth.dev) need no session.

import { readMcpToolAnnotations } from './annotations.js'
import type { OperationAnnotations } from './annotations.js'
import type { InvocationPlan, InvokeArgs, OpDetail, OpSummary, VocabAdapter } from './types.js'

export const MCP_VOCABULARY = 'urn:aauth:vocabulary:mcp'

// The version this client offers in `initialize`. The server's answer is what
// later requests carry in MCP-Protocol-Version.
export const MCP_CLIENT_PROTOCOL_VERSION = '2025-06-18'

const ACCEPT = 'application/json, text/event-stream'

// Bound on tools/list pages, so a server that keeps handing back a cursor
// cannot hold discovery open.
const MAX_PAGES = 50

export interface McpTool {
  name: string
  title?: string
  description?: string
  inputSchema?: unknown
  outputSchema?: unknown
  annotations?: { title?: string; [k: string]: unknown }
  _meta?: Record<string, unknown>
}

// Plain JSON throughout: loadDoc caches docs as JSON (R2 in aauth-mcp), so no
// Map — lookups walk the array.
export interface McpVocabDoc {
  endpoint: string
  protocolVersion?: string
  tools: McpTool[]
}

interface JsonRpcMessage {
  jsonrpc?: string
  id?: string | number | null
  method?: string
  result?: unknown
  error?: { code?: number; message?: string; data?: unknown }
}

/**
 * Pull the JSON messages out of a `text/event-stream` body. Each event's `data:`
 * lines are joined with newlines (per the SSE format) and parsed; events whose
 * data is not JSON are skipped.
 */
export function parseSseMessages(text: string): unknown[] {
  const out: unknown[] = []
  let data: string[] = []
  const flush = () => {
    if (data.length === 0) return
    try {
      out.push(JSON.parse(data.join('\n')))
    } catch {
      /* not JSON */
    }
    data = []
  }
  for (const raw of text.split(/\r\n|\r|\n/)) {
    if (raw === '') {
      flush()
      continue
    }
    if (raw.startsWith(':')) continue
    const colon = raw.indexOf(':')
    const field = colon === -1 ? raw : raw.slice(0, colon)
    if (field !== 'data') continue
    let value = colon === -1 ? '' : raw.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    data.push(value)
  }
  flush()
  return out
}

/**
 * The JSON-RPC response in an SSE body: the message answering `id` when one is
 * given, else the last message carrying `result` or `error`, else the last
 * message. A server may send notifications on the stream ahead of the response.
 */
export function jsonRpcFromSse(text: string, id?: string | number): unknown {
  const messages = parseSseMessages(text) as JsonRpcMessage[]
  if (messages.length === 0) return undefined
  const isResponse = (m: JsonRpcMessage) => !!m && typeof m === 'object' && ('result' in m || 'error' in m)
  if (id !== undefined) {
    const match = messages.find((m) => isResponse(m) && m.id === id)
    if (match) return match
  }
  for (let i = messages.length - 1; i >= 0; i--) if (isResponse(messages[i])) return messages[i]
  return messages[messages.length - 1]
}

function isSse(res: Response): boolean {
  return (res.headers.get('content-type') ?? '').toLowerCase().includes('text/event-stream')
}

function toolSummary(tool: McpTool): string | undefined {
  const title = tool.title ?? tool.annotations?.title
  if (title && tool.description) return `${title}: ${tool.description}`
  return title ?? tool.description
}

function matches(tool: McpTool, query: string): boolean {
  if (!query) return true
  const q = query.toLowerCase()
  return (
    tool.name.toLowerCase().includes(q) ||
    (tool.title?.toLowerCase().includes(q) ?? false) ||
    (tool.description?.toLowerCase().includes(q) ?? false)
  )
}

function annotationsField(tool: McpTool): { annotations?: OperationAnnotations } {
  const a = readMcpToolAnnotations(tool)
  return Object.keys(a).length > 0 ? { annotations: a } : {}
}

class McpSession {
  private sessionId?: string
  protocolVersion?: string
  private nextId = 1

  constructor(private readonly endpoint: string) {}

  private headers(): Record<string, string> {
    return {
      'content-type': 'application/json',
      accept: ACCEPT,
      ...(this.sessionId ? { 'mcp-session-id': this.sessionId } : {}),
      ...(this.protocolVersion ? { 'mcp-protocol-version': this.protocolVersion } : {}),
    }
  }

  private async post(message: JsonRpcMessage): Promise<Response> {
    const res = await fetch(this.endpoint, { method: 'POST', headers: this.headers(), body: JSON.stringify(message) })
    const sid = res.headers.get('mcp-session-id')
    if (sid) this.sessionId = sid
    return res
  }

  async request(method: string, params?: Record<string, unknown>): Promise<JsonRpcMessage> {
    const id = this.nextId++
    const res = await this.post({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) })
    const text = await res.text()
    let msg: unknown
    if (isSse(res)) {
      msg = jsonRpcFromSse(text, id)
    } else {
      try {
        msg = JSON.parse(text)
      } catch {
        msg = undefined
      }
    }
    if (!msg || typeof msg !== 'object') {
      throw new Error(`mcp ${method} ${this.endpoint}: ${res.status} (no JSON-RPC response)`)
    }
    return msg as JsonRpcMessage
  }

  async notify(method: string): Promise<void> {
    const res = await this.post({ jsonrpc: '2.0', method })
    await res.body?.cancel().catch(() => undefined)
  }
}

export class MCPAdapter implements VocabAdapter<McpVocabDoc> {
  readonly vocabUri = MCP_VOCABULARY

  async load(url: string): Promise<McpVocabDoc> {
    const session = new McpSession(url)

    const init = await session.request('initialize', {
      protocolVersion: MCP_CLIENT_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: '@aauth/proxy', version: '1' },
    })
    // A server that does not implement initialize (a JSON-RPC error rather than a
    // transport failure) may still answer tools/list; go on without a session.
    if (init.result && typeof init.result === 'object') {
      const pv = (init.result as { protocolVersion?: unknown }).protocolVersion
      if (typeof pv === 'string' && pv) session.protocolVersion = pv
      await session.notify('notifications/initialized')
    }

    const tools: McpTool[] = []
    let cursor: string | undefined
    for (let page = 0; page < MAX_PAGES; page++) {
      const res = await session.request('tools/list', cursor ? { cursor } : undefined)
      if (res.error) {
        throw new Error(`mcp tools/list ${url}: ${res.error.message ?? res.error.code ?? 'error'}`)
      }
      const result = (res.result ?? {}) as { tools?: unknown; nextCursor?: unknown }
      if (!Array.isArray(result.tools)) throw new Error(`mcp tools/list ${url}: no tools array`)
      for (const t of result.tools as McpTool[]) {
        if (t && typeof t.name === 'string' && t.name) tools.push(t)
      }
      cursor = typeof result.nextCursor === 'string' && result.nextCursor ? result.nextCursor : undefined
      if (!cursor) break
    }

    return { endpoint: url, ...(session.protocolVersion ? { protocolVersion: session.protocolVersion } : {}), tools }
  }

  usableAt(docUrl: string, origin: string): boolean {
    try {
      return new URL(docUrl).origin === origin
    } catch {
      return false
    }
  }

  listOperations(doc: McpVocabDoc, query?: string): OpSummary[] {
    const q = query ?? ''
    return doc.tools
      .filter((t) => matches(t, q))
      .map((t) => ({ opId: t.name, kind: 'sync.request' as const, summary: toolSummary(t), ...annotationsField(t) }))
  }

  getOperations(doc: McpVocabDoc, opIds: string[]): OpDetail[] {
    const out: OpDetail[] = []
    for (const opId of opIds) {
      const t = doc.tools.find((x) => x.name === opId)
      if (!t) continue
      out.push({
        opId: t.name,
        kind: 'sync.request',
        summary: toolSummary(t),
        ...annotationsField(t),
        // Tool arguments are the invoke `body`.
        bodySchema: t.inputSchema,
        ...(t.outputSchema !== undefined ? { responseSchema: t.outputSchema } : {}),
      })
    }
    return out
  }

  annotationsFor(doc: McpVocabDoc, opId: string): OperationAnnotations {
    return readMcpToolAnnotations(doc.tools.find((t) => t.name === opId))
  }

  operationEntry(opId: string): Record<string, string> {
    return { tool: opId }
  }

  buildInvocation(doc: McpVocabDoc, opId: string, args: InvokeArgs): InvocationPlan {
    if (!doc.tools.some((t) => t.name === opId)) throw new Error(`mcp: unknown tool ${opId}`)
    const url = new URL(doc.endpoint)
    const body = {
      jsonrpc: '2.0',
      // Fixed, not a counter: a per-call retry MUST present exactly the request
      // the proposal was approved for (R3 -02 §Per-Call Proposals), and every
      // invoke is its own single-request exchange.
      id: 1,
      method: 'tools/call',
      params: { name: opId, arguments: args.body ?? {} },
    }
    return {
      kind: 'sync.request',
      method: 'POST',
      path: url.pathname,
      ...(url.search.length > 1 ? { query: url.search.slice(1) } : {}),
      headers: {
        'content-type': 'application/json',
        accept: ACCEPT,
        ...(doc.protocolVersion ? { 'mcp-protocol-version': doc.protocolVersion } : {}),
      },
      body: JSON.stringify(body),
    }
  }
}
