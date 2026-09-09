// Public API for @aauth/proxy (core, workerd-safe — no fs/stdio/local-keys at
// import time). Consumers get the agent flow, the transport-agnostic tool
// factory, the injectable storage/identity ports, and the default filesystem
// adapters. The Node-only @aauth/local-keys identity adapter is exported
// separately from "@aauth/proxy/local".

export {
  connectAtResource,
  disconnectAll,
  flushPersonTokens,
  invokeAtResource,
  invokeAtResourceComplete,
  listConnections,
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
  SessionTokenStore,
} from './agent.js'

export { isKnownAccessMode, KNOWN_ACCESS_MODES, planAccessMode, planReason } from './access-mode.js'
export type { AccessModePlan, AgentSetup, KnownAccessMode } from './access-mode.js'

export { agentTokenPs, decodeJwtHeader, decodeJwtPayload, jwkThumbprint, jwtExp } from './jwt.js'

export { buildProxyTools } from './tools.js'
export type { ConnectFlight, ProxyDeps } from './tools.js'

export type { BootstrapStatus, IdentityProvider } from './identity.js'

export { canonicalizeHost } from './host.js'
export type { CanonicalHost } from './host.js'

export {
  createMemoryDocCache,
  fetchResource,
  getOperationsForResource,
  listOperationsForResource,
  routeOperation,
  toL1Entry,
} from './resource.js'
export type {
  AAuthResourceMeta,
  DocCache,
  FetchedResource,
  PickedVocab,
  RoutedOperation,
} from './resource.js'

export { createFsRegistryCache, fetchRegistry, registryUrl } from './registry.js'
export type { CachedIndex, RegistryCache, RegistryEntry, RegistryIndex } from './registry.js'

export {
  createFsL1Store,
  createFsPersonTokenStore,
  createMemoryPersonTokenStore,
} from './store.js'
export type {
  AccessMode,
  ConnectionMetadata,
  ConnectionRow,
  ConnectionScope,
  L1Entry,
  L1Store,
  PersonTokenKey,
  PersonTokenStore,
} from './store.js'

export * from './vocab/index.js'
