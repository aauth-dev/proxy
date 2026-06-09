// Host normalization. Praca's canonical resource identifier is the bare
// lowercased host (with port if non-default), e.g. `api-hubapi-com.hello-proxy.net`
// or `localhost:8787` for local dev tunnels. The origin (`https://host` or
// `http://host` for local) is also returned and stored on each L1 entry so the
// scheme survives across praca restarts.
//
// Production AAuth resources are https; we allow http for local dev + the test
// harness.

export interface CanonicalHost {
  host: string
  origin: string
}

export function canonicalizeHost(input: string): CanonicalHost | null {
  let urlStr = input.trim()
  if (!urlStr) return null
  if (!/^https?:\/\//i.test(urlStr)) urlStr = `https://${urlStr}`
  let url: URL
  try {
    url = new URL(urlStr)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  const host = url.host.toLowerCase()
  return { host, origin: `${url.protocol}//${host}` }
}
