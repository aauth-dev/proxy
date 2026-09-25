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
import { loggedFetch, logUrl } from './log.js'

export interface RegistryEntry {
  issuer: string
  name: string
  description: string
  access_mode: AccessMode
  logo_uri?: string
  added: string
  submitted_by?: { agent: string; ap: string; user?: string }
  // Present means NOT available (coming): nothing the public can connect to
  // exists at this host yet, and the string says why, in plain language. An
  // entry with `availability` keeps its issuer — the host is its id. A connect
  // to it is still tried: the person may be one the provider lets in.
  availability?: string
  // Host of the API this resource proxies (e.g. api.github.com). Not unique:
  // several resources can front one API. Lets an agent find what fronts an
  // API it knows by name.
  upstream?: string
  // Distinct people who registered interest in a coming resource.
  interest_count?: number
}

// A coming entry: listed and described, not yet public.
export function isComing(r: RegistryEntry): boolean {
  return typeof r.availability === 'string'
}

// Available entries first, coming entries after, each group in the order the
// registry gave them (it sorts by issuer).
export function orderCatalog(resources: RegistryEntry[]): RegistryEntry[] {
  return [...resources.filter((r) => !isComing(r)), ...resources.filter(isComing)]
}

// The registry entry for a host, if the index has one.
export function findEntry(index: RegistryIndex, host: string): RegistryEntry | undefined {
  const want = host.toLowerCase()
  return index.resources.find((r) => {
    try {
      return new URL(r.issuer).host.toLowerCase() === want
    } catch {
      return false
    }
  })
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

  const res = await loggedFetch(cfg.log, 'aauth.request', { credential: 'agent', method: 'GET', url: logUrl(url) }, () =>
    signedFetch(url, {
      method: 'GET',
      headers,
      signingKey: cfg.agentPrivateJwk,
      signatureKey: { type: 'jwt', jwt: cfg.agentToken },
    }),
  )

  if (res.status === 304 && cached) return cached.index
  if (!res.ok) {
    let detail = ''
    try { detail = ` — ${JSON.stringify(await res.json())}` } catch { /* ignore */ }
    throw new Error(`registry ${url}: ${res.status}${detail}`)
  }

  const index = (await res.json()) as RegistryIndex
  const etag = res.headers.get('etag') ?? undefined
  await cache.write({ ...(etag ? { etag } : {}), fetched: new Date().toISOString(), index })
  return index
}
