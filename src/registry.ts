// Registry client: signed GET registry.aauth.dev/resources with ETag cache.
//
// The registry is an AAuth resource itself (access_mode: agent-token), so
// listing requires praca's agent token + HTTP signature — the same path used
// for any other agent-token resource. Cached at ~/.aauth/praca/catalog/registry.json.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fetch as signedFetch } from '@hellocoop/httpsig'
import type { PracaConfig } from './agent.js'
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

interface CachedIndex {
  etag?: string
  fetched: string
  index: RegistryIndex
}

const CACHE_PATH = join(homedir(), '.aauth', 'praca', 'catalog', 'registry.json')

export function registryUrl(): string {
  return (process.env.PRACA_REGISTRY_URL ?? 'https://registry.aauth.dev').replace(/\/+$/, '')
}

function readCache(): CachedIndex | undefined {
  if (!existsSync(CACHE_PATH)) return undefined
  try {
    return JSON.parse(readFileSync(CACHE_PATH, 'utf8')) as CachedIndex
  } catch {
    return undefined
  }
}

function writeCache(c: CachedIndex): void {
  mkdirSync(dirname(CACHE_PATH), { recursive: true })
  writeFileSync(CACHE_PATH, JSON.stringify(c, null, 2))
}

// Cheap synchronous read of the cached index — for find_resources between
// background refreshes. Returns undefined if no cache exists yet.
export function readCachedRegistry(): RegistryIndex | undefined {
  return readCache()?.index
}

// Fetch the registry's /resources, signed with the agent token. Honors
// If-None-Match against the cached ETag — on 304 returns the cached index;
// on 200 updates the cache.
export async function fetchRegistry(cfg: PracaConfig): Promise<RegistryIndex> {
  const url = `${registryUrl()}/resources`
  const cached = readCache()
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
  writeCache({ ...(etag ? { etag } : {}), fetched: new Date().toISOString(), index })
  return index
}
