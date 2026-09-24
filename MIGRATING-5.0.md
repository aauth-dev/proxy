# Migrating to @aauth/proxy 5.0

5.0.0 replaces the person-token cache and the session-token store with one token store that holds every token the agent holds, and makes the agent keep and reuse its auth tokens: one per (resource, account, mission), grown when a call needs more, renewed with its grant when it lapses while in use, and started over from the one operation when it lapses idle. See `design.md` §Tokens.

## `ProxyConfig`

| 4.x | 5.0 |
|-----|-----|
| `personTokens?: PersonTokenStore` | `tokens?: TokenStore` |
| `sessionTokens?: SessionTokenStore` | `tokens?: TokenStore` |
| — | `scopePolicy?: ScopePolicy` |

Both can also be passed on `ProxyDeps` (`tokens`, `scopePolicy`); `buildProxyTools` copies them onto the resolved config when the identity provider left them unset, as it does `log`.

A host that builds a fresh server per request MUST pass a `tokens` store that outlives the request. The in-memory default is per `ProxyConfig`, so a host that resolves a new config per request gets a new, empty store every time and obtains every token again.

## Exports

| 4.x | 5.0 |
|-----|-----|
| `createMemoryPersonTokenStore` | `createMemoryTokenStore` |
| `createFsPersonTokenStore` (`person-tokens.json`) | `createFsTokenStore` (`tokens.json`) |
| `PersonTokenStore`, `PersonTokenKey`, `SessionTokenStore` | `TokenStore`, `TokenKey`, `TokenRecord`, `TokenKind` |
| `flushPersonTokens(cfg)` | `flushTokens(cfg)` |
| — | `listTokens(cfg)`, `forgetTokens(cfg, resource)`, `minimalScope`, `ScopePolicy`, `ScopeRequest`, `createLeaseTable`, `authTokenRecord`, `grantsOperation`, `grantsAtLeast`, `isLive`, `isDueForRefresh`, `wasInUse` |

## Agent token lifetime

Every person and auth token is capped at the agent token's `exp`. A host that re-mints its agent token only in its last minute hands the proxy short tokens for the last five; re-mint it inside the refresh margin (`REFRESH_MARGIN_SECS`, 300 s). The stdio bin now does.

## `TokenStore`

```ts
interface TokenStore {
  get(key: TokenKey): Promise<TokenRecord | undefined>      // expired records included
  put(record: TokenRecord): Promise<void>                    // replaces the key's record
  update(key: TokenKey, jti: string | undefined, patch: Partial<TokenRecord>): Promise<void>
  drop(key: TokenKey, jti?: string): Promise<void>
  list(): Promise<TokenRecord[]>
  flush(): Promise<void>
  acquire?(key: TokenKey): Promise<string>                   // optional: serialize acquisition per key
  release?(key: TokenKey, lease: string): Promise<void>
}
```

`update` and `drop` with a `jti` act only while the key still holds that token, so a late write for a replaced token is a no-op. Store the record as given; the core reads the fields back.

## Log events

`person_token.hit` is now `token.hit` with `kind: 'person'`; auth-token reuse reports `token.hit` with `kind: 'auth'`. New: `token.put`, `token.drop`, `token.refresh_failed`, `scope.policy_error` (see `log.ts`).

## Tools

`list_resources` gains `authorizations` on a resource where the agent holds an auth token: the operations it grants, its budget (`remaining`, `amount`, `unit`) and `expires_in`. Never the token. `delete_resource` also drops the tokens held for the resource.

## Stdio bin

The `aauth-proxy` bin keeps its tokens in memory, as before: its signing key is minted per process, so no token outlives the process. `createFsTokenStore` is for a host whose key persists; do not share one file between processes that sign with different keys — each would flush the other's tokens as a key rotation.
