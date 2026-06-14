#!/usr/bin/env node
// the agent proxy as an MCP stdio server: wires the transport-agnostic eight-tool surface
// (buildProxyTools) to filesystem-backed state and @aauth/local-keys identity,
// adds an OS-browser interaction launcher, and connects over stdio. The tool
// logic itself lives in tools.ts so an HTTP host can reuse it unchanged.

import { spawn } from 'node:child_process'
import { createWriteStream, mkdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { createLocalKeysIdentityProvider } from './identity-local.js'
import { createFsRegistryCache } from './registry.js'
import { createFsL1Store } from './store.js'
import { buildProxyTools } from './tools.js'

// Layer 2 of the interaction-driver hierarchy: when the PS couldn't reach the
// user via its own channels (AAuth#34 interaction_unavailable), the agent proxy runs on
// the user's machine and can spawn the OS's default-browser launcher. Best
// effort — silently no-ops on unsupported platforms or when the binary is
// missing. The text fallback (layer 3) is still emitted by buildProxyTools so a
// remote MCP or headless caller can surface the URL.
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

function slugifyClientName(name: string | undefined): string {
  if (!name) return 'mcp-stdio-unknown'
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32)
  return slug || 'mcp-stdio-unknown'
}

const { version: PKG_VERSION } = createRequire(import.meta.url)('../package.json') as { version: string }
const server = new McpServer({ name: 'aauth-proxy', version: PKG_VERSION })

// `--log` tees stdio JSON-RPC frames to ~/.aauth/praca/logs/<ISO>.jsonl as
// `{ts, dir, frame}` lines (same shape reloaderoo writes). Opt-in; best-effort —
// silently no-ops if the log directory can't be created or a line isn't JSON.
function setupFrameLog(): void {
  if (!process.argv.includes('--log')) return
  const dir = join(homedir(), '.aauth', 'praca', 'logs')
  let stream: ReturnType<typeof createWriteStream>
  try {
    mkdirSync(dir, { recursive: true })
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').replace(/-\d{3}Z$/, 'Z')
    stream = createWriteStream(join(dir, `${stamp}.jsonl`), { flags: 'a' })
  } catch {
    return
  }
  const emit = (direction: 'client->server' | 'server->client', line: string): void => {
    const t = line.trim()
    if (!t) return
    try {
      stream.write(
        `${JSON.stringify({ ts: new Date().toISOString(), dir: direction, frame: JSON.parse(t) })}\n`,
      )
    } catch {
      // Non-JSON output on this transport would be a protocol bug; drop silently.
    }
  }
  // Tee stdout (server->client). Patch before connect so the initialize reply
  // is captured. Buffer partial lines across writes — the SDK may flush a frame
  // in multiple chunks.
  const origWrite = process.stdout.write.bind(process.stdout)
  let outBuf = ''
  process.stdout.write = ((chunk: unknown, ...rest: unknown[]): boolean => {
    const text =
      typeof chunk === 'string'
        ? chunk
        : Buffer.isBuffer(chunk)
          ? chunk.toString('utf8')
          : String(chunk)
    outBuf += text
    let nl: number
    while ((nl = outBuf.indexOf('\n')) !== -1) {
      emit('server->client', outBuf.slice(0, nl))
      outBuf = outBuf.slice(nl + 1)
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (origWrite as any)(chunk, ...rest)
  }) as typeof process.stdout.write
  // Tee stdin (client->server). Added as a peer listener — Node fans each data
  // event out to all listeners, so the SDK still receives every byte.
  let inBuf = ''
  process.stdin.on('data', (chunk: Buffer) => {
    inBuf += chunk.toString('utf8')
    let nl: number
    while ((nl = inBuf.indexOf('\n')) !== -1) {
      emit('client->server', inBuf.slice(0, nl))
      inBuf = inBuf.slice(nl + 1)
    }
  })
}

setupFrameLog()
await buildProxyTools(server, {
  l1: createFsL1Store(),
  registryCache: createFsRegistryCache(),
  identity: createLocalKeysIdentityProvider(),
  onInteraction: (url, code) => tryOpenBrowser(`${url}?code=${code}`),
  agentLocal: () => slugifyClientName(server.server.getClientVersion()?.name),
})
await server.connect(new StdioServerTransport())
