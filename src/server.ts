#!/usr/bin/env node
// praca as an MCP stdio server: the eight-tool v1 discovery surface defined
// in design.md §"Tool surface". Each tool's description embeds the current
// L1 snapshot so the common path needs no extra round-trip.

import { spawn } from 'node:child_process'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { invokeAtResource, type PracaConfig } from './agent.js'
import { loadBootstrapStatus } from './identity.js'
import { canonicalizeHost } from './host.js'
import { fetchRegistry } from './registry.js'
import {
  fetchResource,
  getOperationsForResource,
  listOperationsForResource,
  toL1Entry,
} from './resource.js'
import * as store from './store.js'

// Layer 2 of the interaction-driver hierarchy: when the PS couldn't reach the
// user via its own channels (AAuth#34 interaction_unavailable), praca runs on
// the user's machine and can spawn the OS's default-browser launcher. Best
// effort — silently no-ops on unsupported platforms or when the binary is
// missing. The text fallback (layer 3) is still emitted so a remote MCP or
// headless caller can surface the URL.
function tryOpenBrowser(url: string): void {
  const cmd =
    process.platform === 'darwin'
      ? 'open'
      : process.platform === 'win32'
        ? 'cmd'
        : 'xdg-open'
  const args = process.platform === 'win32' ? ['/c', 'start', '""', url] : [url]
  try {
    const child = spawn(cmd, args, { detached: true, stdio: 'ignore' })
    child.on('error', () => {})
    child.unref()
  } catch {
    // platform / binary missing — text fallback covers it
  }
}

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] })
const json = (v: unknown) => text(JSON.stringify(v, null, 2))

function slugifyClientName(name: string | undefined): string {
  if (!name) return 'mcp-stdio-unknown'
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32)
  return slug || 'mcp-stdio-unknown'
}

const BOOTSTRAP_GUIDANCE = `praca has no AAuth identity on this machine yet.

To set one up, run:

  npx @aauth/bootstrap list

…then follow the setup skill:

  npx @aauth/bootstrap skill setup

That guide walks through generating a keypair (Secure Enclave / YubiKey / software),
binding a Person Server, and publishing the JWKS. When it's done, call this tool again.`

const server = new McpServer({ name: 'praca', version: '0.0.0' })

// Resolved lazily on first tool call so the MCP server starts even when no
// identity is bootstrapped; re-checked when not yet ready so a mid-session
// bootstrap is picked up without a restart.
let cachedCfg: PracaConfig | null = null
async function getConfig(): Promise<{ ok: true; cfg: PracaConfig } | { ok: false }> {
  if (cachedCfg) return { ok: true, cfg: cachedCfg }
  const local = slugifyClientName(server.server.getClientVersion()?.name)
  const status = await loadBootstrapStatus(local)
  if (status.kind === 'needsBootstrap') return { ok: false }
  cachedCfg = status.cfg
  return { ok: true, cfg: cachedCfg }
}

// Snapshot of L1 for tool descriptions, refreshed on each list. Keeps the
// always-loaded context cheap; list_resources is the authoritative fresh view.
function l1Snapshot(): string {
  const entries = store.list()
  if (entries.length === 0) return 'no resources added yet'
  return entries.map((e) => e.resource).join(', ')
}

function describeWithL1(base: string): string {
  return `${base}\n\nCurrently added resources: ${l1Snapshot()}`
}

function requireL1(resource: string): { ok: true; l1: store.L1Entry } | { ok: false; msg: string } {
  const canonical = canonicalizeHost(resource)
  if (!canonical) return { ok: false, msg: `Invalid resource host: ${resource}` }
  const l1 = store.get(canonical.host)
  if (!l1)
    return {
      ok: false,
      msg: `Resource not added: ${canonical.host}. Call add_resource("${canonical.host}") first.`,
    }
  return { ok: true, l1 }
}

// ── Resource lifecycle ──

server.registerTool(
  'find_resources',
  {
    description: describeWithL1(
      'Search the AAuth registry for discoverable resources by free-text query against name/description. Returns each result tagged `added: true` if already in your local resource set.',
    ),
    inputSchema: { query: z.string().optional() },
  },
  async ({ query }) => {
    const c = await getConfig()
    if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
    try {
      const index = await fetchRegistry(c.cfg)
      const q = (query ?? '').trim().toLowerCase()
      const added = new Set(store.list().map((e) => e.resource))
      const filtered = index.resources
        .filter((r) => {
          if (!q) return true
          return (
            r.name.toLowerCase().includes(q) ||
            r.description.toLowerCase().includes(q) ||
            r.issuer.toLowerCase().includes(q)
          )
        })
        .map((r) => {
          const host = canonicalizeHost(r.issuer)?.host ?? r.issuer
          return {
            resource: host,
            name: r.name,
            description: r.description,
            access_mode: r.access_mode,
            added: added.has(host),
            ...(r.logo_uri ? { logo_uri: r.logo_uri } : {}),
          }
        })
      return json(filtered)
    } catch (err) {
      return text(`registry error: ${(err as Error).message}`)
    }
  },
)

server.registerTool(
  'add_resource',
  {
    description: describeWithL1(
      'Add an AAuth resource to your local set. Pass a bare host, host:port, or full URL — praca canonicalizes. Fetches the resource\'s well-known doc, validates, picks supported vocabularies. After adding: agent-token resources are immediately invokable; aauth-access-token/auth-token resources need `connect` or a first `invoke` that surfaces the auth URL.',
    ),
    inputSchema: { resource: z.string() },
  },
  async ({ resource }) => {
    try {
      const fetched = await fetchResource(resource)
      const entry = toL1Entry(fetched)
      store.upsert(entry)
      return json({
        added: entry.resource,
        access_mode: entry.access_mode,
        vocabularies: entry.picked_vocabs.map((v) => v.vocabUri),
        connect_required: entry.access_mode !== 'agent-token',
      })
    } catch (err) {
      return text(`add_resource error: ${(err as Error).message}`)
    }
  },
)

server.registerTool(
  'list_resources',
  {
    description:
      'Return your locally added resources with name, description, access_mode, last_used, and how many vocabularies praca picked. Cheap; safe to call anytime.',
  },
  async () => {
    const entries = store.list().map((e) => ({
      resource: e.resource,
      name: e.name,
      description: e.description,
      access_mode: e.access_mode,
      vocabularies: e.picked_vocabs.map((v) => v.vocabUri),
      added: e.added,
      last_used: e.last_used,
    }))
    return json(entries)
  },
)

server.registerTool(
  'remove_resource',
  {
    description: describeWithL1(
      'Remove a resource from your local set. Praca-local only — does NOT revoke any user grants at the Person Server; re-adding picks up existing grants transparently.',
    ),
    inputSchema: { resource: z.string() },
  },
  async ({ resource }) => {
    const canonical = canonicalizeHost(resource)
    if (!canonical) return text(`invalid host: ${resource}`)
    const removed = store.remove(canonical.host)
    return text(removed ? `removed ${canonical.host}` : `not found: ${canonical.host}`)
  },
)

server.registerTool(
  'connect',
  {
    description: describeWithL1(
      'Pre-authorize a resource — trigger a Person Server consent step if needed. No-op for agent-token resources. For aauth-access-token/auth-token resources, invokes a probe operation to surface the auth URL; returns "already connected" if the auth succeeds.',
    ),
    inputSchema: { resource: z.string() },
  },
  async ({ resource }) => {
    const c = await getConfig()
    if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
    const found = requireL1(resource)
    if (!found.ok) return text(found.msg)
    const { l1 } = found
    if (l1.access_mode === 'agent-token') {
      return text(`${l1.resource}: already connected (agent-token access mode)`)
    }
    const ops = await listOperationsForResource(l1)
    const probe = ops.find((o) => o.kind === 'sync.request' && o.method === 'GET')
    if (!probe) return text(`${l1.resource}: no probe operation available for connect`)
    const result = await invokeAtResource(c.cfg, l1, probe.opId, {})
    if (result.kind === 'interaction') {
      const url = `${result.interaction.url}?code=${result.interaction.code}`
      tryOpenBrowser(url)
      return text(
        `Authorization required. Opening browser; if nothing opens, ask the user to open this URL, then call connect again:\n${url}`,
      )
    }
    if (result.status >= 200 && result.status < 300) {
      store.touch(l1.resource)
      return text(`${l1.resource}: connected.`)
    }
    return text(`${l1.resource}: connect probe returned ${result.status} — ${JSON.stringify(result.body)}`)
  },
)

// ── Operations ──

server.registerTool(
  'list_operations',
  {
    description: describeWithL1(
      'List operations a resource exposes. Optional `query` is either free-text (matched against opId/summary/tags) or an OpenAPI path prefix (e.g. "/crm/v3/objects/contacts/*"). Returns summaries only — schemas are fetched via get_operations to keep token cost flat. Each op carries `kind` (sync.request/async.send/async.receive).',
    ),
    inputSchema: { resource: z.string(), query: z.string().optional() },
  },
  async ({ resource, query }) => {
    const found = requireL1(resource)
    if (!found.ok) return text(found.msg)
    try {
      const ops = await listOperationsForResource(found.l1, query)
      return json(ops)
    } catch (err) {
      return text(`list_operations error: ${(err as Error).message}`)
    }
  },
)

server.registerTool(
  'get_operations',
  {
    description: describeWithL1(
      'Batch fetch full schemas (params, request body, response) for one or more operations on a resource. Separate from list_operations because schemas dominate token cost.',
    ),
    inputSchema: { resource: z.string(), op_ids: z.array(z.string()) },
  },
  async ({ resource, op_ids }) => {
    const found = requireL1(resource)
    if (!found.ok) return text(found.msg)
    try {
      const details = await getOperationsForResource(found.l1, op_ids)
      return json(details)
    } catch (err) {
      return text(`get_operations error: ${(err as Error).message}`)
    }
  },
)

server.registerTool(
  'invoke',
  {
    description: describeWithL1(
      'Invoke an operation on a resource. Pass `path_params`, `query`, `body` (object) as needed. On first call to an unauthorized aauth-access-token resource, returns an auth URL — open it, then call invoke again. async.receive operations return `subscribe_requires_subagent` (v.next).',
    ),
    inputSchema: {
      resource: z.string(),
      op_id: z.string(),
      path_params: z.record(z.string(), z.string()).optional(),
      query: z.string().optional(),
      body: z.record(z.string(), z.unknown()).optional(),
    },
  },
  async ({ resource, op_id, path_params, query, body }) => {
    const c = await getConfig()
    if (!c.ok) return text(BOOTSTRAP_GUIDANCE)
    const found = requireL1(resource)
    if (!found.ok) return text(found.msg)
    try {
      const result = await invokeAtResource(c.cfg, found.l1, op_id, {
        pathParams: path_params,
        query,
        body,
      })
      if (result.kind === 'interaction') {
        const url = `${result.interaction.url}?code=${result.interaction.code}`
        tryOpenBrowser(url)
        return text(
          `Authorization required. Opening browser; if nothing opens, ask the user to open this URL, then call invoke again:\n${url}`,
        )
      }
      if (result.status >= 200 && result.status < 300) store.touch(found.l1.resource)
      return json({ status: result.status, body: result.body })
    } catch (err) {
      return text(`invoke error: ${(err as Error).message}`)
    }
  },
)

await server.connect(new StdioServerTransport())
