// Registry client: signed GET registry.aauth.dev/resources with ETag cache.
//
// The registry is an AAuth resource itself (access_mode: agent-token), so
// listing requires the agent proxy's agent token + HTTP signature — the same path used
// for any other agent-token resource. The ETag cache is injected via
// RegistryCache; the stdio server uses the filesystem default
// (createFsRegistryCache), backed by ~/.aauth/proxy/catalog/registry.json.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fetch as signedFetch } from '@hellocoop/httpsig'
import type { ProxyConfig } from './agent.js'
import type { AccessMode } from './store.js'

export interface RegistryEntry {
  issuer: string
  name: string
  description: string
  access_mode: AccessMode
  logo_uri?: string
  added: string
  submitted_by?: { agent: string; ap: string; user?: string }
}

export interface RegistryIndex {
  updated: string
  resources: RegistryEntry[]
}

export interface CachedIndex {
  etag?: string
  fetched: string
  index: RegistryIndex
}

// ETag cache for the registry index. Async so non-filesystem backends (e.g. a
// shared KV namespace) can implement it.
export interface RegistryCache {
  read(): Promise<CachedIndex | undefined>
  write(c: CachedIndex): Promise<void>
}

export function registryUrl(): string {
  return (process.env.PROXY_REGISTRY_URL ?? 'https://registry.aauth.dev').replace(/\/+$/, '')
}

// Filesystem-backed RegistryCache — the default for the stdio server. `dir`
// overrides the state directory (default ~/.aauth/proxy).
export function createFsRegistryCache(opts: { dir?: string } = {}): RegistryCache {
  const cachePath = join(opts.dir ?? join(homedir(), '.aauth', 'proxy'), 'catalog', 'registry.json')
  return {
    async read() {
      if (!existsSync(cachePath)) return undefined
      try {
        return JSON.parse(readFileSync(cachePath, 'utf8')) as CachedIndex
      } catch {
        return undefined
      }
    },
    async write(c) {
      mkdirSync(dirname(cachePath), { recursive: true })
      writeFileSync(cachePath, JSON.stringify(c, null, 2))
    },
  }
}

// Fetch the registry's /resources, signed with the agent token. Honors
// If-None-Match against the cached ETag — on 304 returns the cached index;
// on 200 updates the cache.
export async function fetchRegistry(cfg: ProxyConfig, cache: RegistryCache): Promise<RegistryIndex> {
  const url = `${registryUrl()}/resources`
  const cached = await cache.read()
  const headers: Record<string, string> = { accept: 'application/json' }
  if (cached?.etag) headers['if-none-match'] = cached.etag

  const res = await signedFetch(url, {
    method: 'GET',
    headers,
    signingKey: cfg.agentPrivateJwk,
    signatureKey: { type: 'jwt', jwt: cfg.agentToken },
  })

  if (res.status === 304 && cached) return cached.index
  if (!res.ok) throw new Error(`registry ${url}: ${res.status}`)

  const index = (await res.json()) as RegistryIndex
  const etag = res.headers.get('etag') ?? undefined
  await cache.write({ ...(etag ? { etag } : {}), fetched: new Date().toISOString(), index })
  return index
}
