// Public API for @aauth/praca (core, workerd-safe — no fs/stdio/local-keys at
// import time). Consumers get the agent flow, the transport-agnostic tool
// factory, the injectable storage/identity ports, and the default filesystem
// adapters. The Node-only @aauth/local-keys identity adapter is exported
// separately from "@aauth/praca/local".

export { invokeAtResource, invokeAtResourceComplete } from './agent.js'
export type {
  AgentSigningKey,
  Interaction,
  InteractionHandler,
  InvokeArgs,
  InvokeResult,
  PracaConfig,
} from './agent.js'

export { buildPracaTools } from './tools.js'
export type { PracaDeps } from './tools.js'

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

export { createFsL1Store } from './store.js'
export type { AccessMode, L1Entry, L1Store } from './store.js'

export * from './vocab/index.js'
