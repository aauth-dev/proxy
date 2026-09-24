// Public API for @aauth/proxy (core, workerd-safe — no fs/stdio/local-keys at
// import time). Consumers get the agent flow, the transport-agnostic tool
// factory, the injectable storage/identity ports, and the default filesystem
// adapters. The Node-only @aauth/local-keys identity adapter is exported
// separately from "@aauth/proxy/local".

export {
  connectAtResource,
  disconnectAll,
  flushTokens,
  forgetTokens,
  invokeAtResource,
  invokeAtResourceComplete,
  listConnections,
  listTokens,
  makeAgentPoll,
  obtainPersonToken,
  pollConnection,
  pollUntilDone,
} from './agent.js'
export type {
  AgentSigningKey,
  ConnectArgs,
  ConnectOutcome,
  DisconnectRow,
  Interaction,
  InteractionHandler,
  InvokeArgs,
  InvokeOptions,
  InvokeResult,
  ProxyConfig,
  PSTokenHints,
} from './agent.js'

export { isKnownAccessMode, KNOWN_ACCESS_MODES, planAccessMode, planReason } from './access-mode.js'
export type { AccessModePlan, AgentSetup, KnownAccessMode } from './access-mode.js'

export { agentTokenPs, decodeJwtHeader, decodeJwtPayload, jwkThumbprint, jwtExp } from './jwt.js'

export { buildProxyTools } from './tools.js'
export type { ConnectFlight, ProxyDeps } from './tools.js'

export type { BootstrapStatus, IdentityProvider } from './identity.js'

export type { ProxyLog, ProxyLogFields } from './log.js'

export { canonicalizeHost } from './host.js'
export type { CanonicalHost } from './host.js'

export {
  createMemoryDocCache,
  fetchResource,
  fetchResourceConditional,
  refreshResourceEntry,
  docLifetimeMs,
  getOperationsForResource,
  listOperationsForResource,
  routeOperation,
  toL1Entry,
} from './resource.js'
export type {
  AAuthResourceMeta,
  DocCache,
  FetchedResource,
  ResourceFetch,
  PickedVocab,
  RoutedOperation,
} from './resource.js'

export { createFsRegistryCache, fetchRegistry, registryUrl } from './registry.js'
export type { CachedIndex, RegistryCache, RegistryEntry, RegistryIndex } from './registry.js'

export { createFsL1Store } from './store.js'
export type {
  AccessMode,
  ConnectionMetadata,
  ConnectionRow,
  ConnectionScope,
  L1Entry,
  L1Store,
} from './store.js'

export {
  createFsTokenStore,
  createLeaseTable,
  createMemoryTokenStore,
  authTokenRecord,
  grantsAtLeast,
  grantsOperation,
  isDueForRefresh,
  isLive,
  wasInUse,
  operationName,
  tokenKeyString,
  ACTIVE_WITHIN_SECS,
  EXPIRY_SKEW_SECS,
  LEASE_MS,
  LEASE_WAIT_MS,
  NO_LEASE,
  REFRESH_MARGIN_SECS,
} from './tokens.js'
export type { OperationSet, TokenBudget, TokenKey, TokenKind, TokenRecord, TokenStore } from './tokens.js'

export { minimalScope } from './scope.js'
export type { ScopePolicy, ScopeRequest } from './scope.js'

export * from './vocab/index.js'
